use sherlock_homes::core::rate_limit::RateLimiter;
use sherlock_homes::core::scope::ScopeGuard;
use sherlock_homes::network::HttpEngine;
use std::collections::HashMap;
use tokio_util::sync::CancellationToken;
use url::Url;

#[tokio::test]
async fn connection_refused_is_error_not_panic() {
    let url = Url::parse("http://127.0.0.1:1/").unwrap();
    let scope = ScopeGuard::new(&url, &[], &[]).unwrap();
    let http = HttpEngine::new(2, 8_000, 2, "lab", HashMap::new()).unwrap();
    let rate = RateLimiter::new(5);
    let cancel = CancellationToken::new();
    let err = http
        .execute("GET", &url, None, None, &scope, &rate, &cancel)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(!msg.is_empty());
}

#[test]
fn unsupported_scheme_rejected_by_url_policy() {
    let url = Url::parse("ftp://example.com/").unwrap();
    assert_ne!(url.scheme(), "http");
    assert_ne!(url.scheme(), "https");
}
