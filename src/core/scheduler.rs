use crate::core::rate_limit::RateLimiter;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

/// Bounded task scheduler for discovery / passive / active / verification queues.
pub struct Scheduler {
    pub discovery: Semaphore,
    pub analysis: Semaphore,
    pub verification: Semaphore,
    pub cancel: CancellationToken,
    pub rate: RateLimiter,
}

impl Scheduler {
    pub fn new(concurrency: u32, rate: u32, cancel: CancellationToken) -> Self {
        let n = concurrency.max(1) as usize;
        Self {
            discovery: Semaphore::new(n),
            analysis: Semaphore::new(n),
            verification: Semaphore::new((n / 2).max(1)),
            cancel,
            rate: RateLimiter::new(rate),
        }
    }
}
