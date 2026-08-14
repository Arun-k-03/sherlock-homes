pub mod authorization;
pub mod cors;
pub mod disclosure;
pub mod passive;
pub mod redirects;
pub mod secrets;
pub mod xss;

use crate::core::types::{CandidateFinding, Endpoint};
use crate::network::client::HttpEngine;
use crate::network::response::RecordedResponse;
use async_trait::async_trait;

pub struct DetectorContext<'a> {
    pub case_id: &'a str,
    pub pages: &'a [RecordedResponse],
    pub http: &'a HttpEngine,
    pub scope: &'a crate::core::scope::ScopeGuard,
    pub rate: &'a crate::core::rate_limit::RateLimiter,
    pub cancel: &'a tokio_util::sync::CancellationToken,
    pub mode: crate::core::config::ScanMode,
}

#[async_trait]
pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn supports(&self, endpoint: &Endpoint) -> bool;
    async fn analyze(
        &self,
        ctx: &DetectorContext<'_>,
        endpoint: &Endpoint,
    ) -> crate::Result<Vec<CandidateFinding>>;
}

pub fn all_detectors() -> Vec<Box<dyn Detector>> {
    let mut v: Vec<Box<dyn Detector>> = Vec::new();
    v.extend(passive::detectors());
    v.extend(disclosure::detectors());
    v.extend(cors::detectors());
    v.extend(redirects::detectors());
    v.extend(xss::detectors());
    v.extend(authorization::detectors());
    v
}

pub fn fingerprint(
    host: &str,
    method: &str,
    path: &str,
    param: Option<&str>,
    class: &str,
) -> String {
    crate::correlation::fingerprint::compute(host, method, path, param, class)
}
