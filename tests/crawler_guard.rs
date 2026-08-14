use sherlock_homes::core::events::EventBus;
use sherlock_homes::core::rate_limit::RateLimiter;
use sherlock_homes::core::scope::ScopeGuard;
use sherlock_homes::discovery::crawler::{crawl, CrawlLimits};
use sherlock_homes::network::HttpEngine;
use std::collections::HashMap;
use tokio_util::sync::CancellationToken;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn does_not_follow_git_object_fanout() {
    let server = MockServer::start().await;
    let mut listing = String::from("<html>");
    for i in 0..40 {
        listing.push_str(&format!("<a href=\"/.git/objects/ab/{i:040x}\">o</a>"));
    }
    listing.push_str("<a href=\"/safe\">ok</a></html>");
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string(listing),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/safe"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string("<html>safe</html>"),
        )
        .mount(&server)
        .await;

    let url = Url::parse(&server.uri()).unwrap();
    let scope = ScopeGuard::new(&url, &[], &[]).unwrap();
    let http = HttpEngine::new(10, 500_000, 4, "lab", HashMap::new()).unwrap();
    let rate = RateLimiter::new(80);
    let cancel = CancellationToken::new();
    let events = EventBus::new(256);
    let limits = CrawlLimits {
        max_depth: 3,
        max_pages: 50,
        max_requests: 50,
        max_queue: 200,
        max_children_per_parent: 80,
    };
    let crawled = crawl(
        &url, &http, &scope, &rate, &cancel, &events, "SH-G", &limits,
    )
    .await
    .unwrap();
    assert!(crawled.pages.len() <= 5);
    assert!(!crawled
        .endpoints
        .iter()
        .any(|e| e.normalized_path.contains("/.git/objects")));
}

#[tokio::test]
async fn request_budget_stops_safely() {
    let server = MockServer::start().await;
    let mut listing = String::from("<html>");
    for i in 0..30 {
        listing.push_str(&format!("<a href=\"/p{i}\">p</a>"));
        Mock::given(method("GET"))
            .and(path(format!("/p{i}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html>p</html>"),
            )
            .mount(&server)
            .await;
    }
    listing.push_str("</html>");
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string(listing),
        )
        .mount(&server)
        .await;

    let url = Url::parse(&server.uri()).unwrap();
    let scope = ScopeGuard::new(&url, &[], &[]).unwrap();
    let http = HttpEngine::new(10, 500_000, 4, "lab", HashMap::new()).unwrap();
    let rate = RateLimiter::new(80);
    let cancel = CancellationToken::new();
    let events = EventBus::new(512);
    let limits = CrawlLimits {
        max_depth: 2,
        max_pages: 50,
        max_requests: 50,
        max_queue: 5,
        max_children_per_parent: 80,
    };
    let crawled = crawl(
        &url, &http, &scope, &rate, &cancel, &events, "SH-B", &limits,
    )
    .await
    .unwrap();
    assert!(
        crawled.pages.len() <= 50,
        "crawler must remain bounded, got {} pages",
        crawled.pages.len()
    );
}
