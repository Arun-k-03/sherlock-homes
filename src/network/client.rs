use crate::core::error::{Result, SherlockError};
use crate::core::rate_limit::RateLimiter;
use crate::core::scope::ScopeGuard;
use crate::evidence::redact_text;
use crate::network::response::RecordedResponse;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Clone)]
pub struct HttpEngine {
    client: reqwest::Client,
    extra_headers: HashMap<String, String>,
    max_bytes: usize,
    max_redirects: u32,
}

#[derive(Debug, Clone)]
pub struct Fetched {
    pub response: RecordedResponse,
    pub request_headers_redacted: String,
}

impl HttpEngine {
    pub fn new(
        timeout_secs: u64,
        max_bytes: usize,
        max_redirects: u32,
        user_agent: &str,
        extra_headers: HashMap<String, String>,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(timeout_secs.max(1)))
            .user_agent(user_agent)
            .tls_built_in_root_certs(true)
            .build()
            .map_err(|e| SherlockError::Network(e.to_string()))?;
        Ok(Self {
            client,
            extra_headers,
            max_bytes,
            max_redirects,
        })
    }

    pub async fn get(
        &self,
        url: &Url,
        scope: &ScopeGuard,
        rate: &RateLimiter,
        cancel: &CancellationToken,
    ) -> Result<Fetched> {
        self.execute("GET", url, None, None, scope, rate, cancel)
            .await
    }

    pub async fn execute(
        &self,
        method: &str,
        url: &Url,
        headers: Option<&HashMap<String, String>>,
        body: Option<&str>,
        scope: &ScopeGuard,
        rate: &RateLimiter,
        cancel: &CancellationToken,
    ) -> Result<Fetched> {
        scope.allows_url(url)?;
        rate.acquire(cancel).await?;
        if cancel.is_cancelled() {
            return Err(SherlockError::Cancelled);
        }

        let mut current = url.clone();
        let mut redirects = Vec::new();
        let mut hops = 0;
        loop {
            scope.allows_url(&current)?;
            let mut req = self.client.request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
                current.as_str(),
            );
            for (k, v) in &self.extra_headers {
                req = req.header(k, v);
            }
            if let Some(h) = headers {
                for (k, v) in h {
                    req = req.header(k, v);
                }
            }
            if let Some(b) = body {
                req = req.body(b.to_string());
            }

            let started = Instant::now();
            let resp = tokio::select! {
                r = req.send() => r.map_err(|e| SherlockError::Network(e.to_string()))?,
                _ = cancel.cancelled() => return Err(SherlockError::Cancelled),
            };
            let status = resp.status().as_u16();
            let mut hdrs = HashMap::new();
            for (k, v) in resp.headers().iter() {
                hdrs.insert(k.to_string(), v.to_str().unwrap_or("[binary]").to_string());
            }
            let content_type = hdrs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.clone());
            let location = hdrs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.clone());

            if (300..400).contains(&status) && hops < self.max_redirects {
                if let Some(loc) = location {
                    let next = current
                        .join(&loc)
                        .map_err(|e| SherlockError::Network(e.to_string()))?;
                    redirects.push(next.to_string());
                    current = next;
                    hops += 1;
                    continue;
                }
            }

            let bytes = resp
                .bytes()
                .await
                .map_err(|e| SherlockError::Network(e.to_string()))?;
            let truncated = if bytes.len() > self.max_bytes {
                bytes.slice(..self.max_bytes)
            } else {
                bytes
            };
            let body_vec = truncated.to_vec();
            let mut hasher = Sha256::new();
            hasher.update(&body_vec);
            let body_hash = hex::encode(hasher.finalize());
            let body_text = if looks_textual(content_type.as_deref(), &body_vec) {
                Some(String::from_utf8_lossy(&body_vec).into_owned())
            } else {
                None
            };
            let elapsed_ms = started.elapsed().as_millis();
            let req_headers = redact_text(&format_headers(&self.extra_headers));
            return Ok(Fetched {
                response: RecordedResponse {
                    url: url.to_string(),
                    final_url: current.to_string(),
                    status,
                    headers: hdrs,
                    content_type,
                    body: body_vec,
                    body_text,
                    body_hash,
                    elapsed_ms,
                    redirects,
                },
                request_headers_redacted: req_headers,
            });
        }
    }
}

fn format_headers(h: &HashMap<String, String>) -> String {
    h.iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn looks_textual(ct: Option<&str>, body: &[u8]) -> bool {
    if let Some(c) = ct {
        let c = c.to_ascii_lowercase();
        if c.contains("json")
            || c.contains("html")
            || c.contains("xml")
            || c.contains("javascript")
            || c.contains("text/")
        {
            return true;
        }
        if c.contains("octet-stream") || c.contains("image/") || c.contains("video/") {
            return false;
        }
    }
    let sample = &body[..body.len().min(512)];
    let nuls = sample.iter().filter(|b| **b == 0).count();
    nuls < 4
}
