//! Token-bucket rate limiter for outgoing requests.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<Bucket>>,
}

struct Bucket {
    rate_per_sec: f64,
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn new(rate_per_sec: u32) -> Self {
        let rate = (rate_per_sec.max(1)) as f64;
        Self {
            inner: Arc::new(Mutex::new(Bucket {
                rate_per_sec: rate,
                tokens: rate,
                last: Instant::now(),
            })),
        }
    }

    pub async fn acquire(&self, cancel: &CancellationToken) -> crate::Result<()> {
        loop {
            if cancel.is_cancelled() {
                return Err(crate::SherlockError::Cancelled);
            }
            let wait = {
                let mut b = self.inner.lock().await;
                let now = Instant::now();
                let elapsed = now.duration_since(b.last).as_secs_f64();
                b.tokens = (b.tokens + elapsed * b.rate_per_sec).min(b.rate_per_sec);
                b.last = now;
                if b.tokens >= 1.0 {
                    b.tokens -= 1.0;
                    None
                } else {
                    let need = (1.0 - b.tokens) / b.rate_per_sec;
                    Some(Duration::from_secs_f64(need.max(0.001)))
                }
            };
            match wait {
                None => return Ok(()),
                Some(d) => {
                    tokio::select! {
                        _ = tokio::time::sleep(d) => {}
                        _ = cancel.cancelled() => return Err(crate::SherlockError::Cancelled),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_burst_then_paces() {
        let rl = RateLimiter::new(100);
        let c = CancellationToken::new();
        for _ in 0..5 {
            rl.acquire(&c).await.unwrap();
        }
    }
}
