use sherlock_homes::core::config::ScanMode;
use sherlock_homes::core::rate_limit::RateLimiter;
use sherlock_homes::core::scope::ScopeGuard;
use sherlock_homes::database::Database;
use sherlock_homes::detectors::{all_detectors, DetectorContext};
use sherlock_homes::discovery::crawler::crawl;
use sherlock_homes::discovery::normalize_path;
use sherlock_homes::evidence::redact_text;
use sherlock_homes::ids::CaseId;
use sherlock_homes::network::HttpEngine;
use sherlock_homes::reports::{write_reports, ReportFormat};
use std::collections::HashMap;
use tokio_util::sync::CancellationToken;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn crawl_and_passive_and_reports() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .insert_header("server", "fixture")
                .set_body_raw(
                    r#"<html><title>T</title><a href="/login">x</a></html>"#,
                    "text/html",
                ),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string("<html>login</html>"),
        )
        .mount(&server)
        .await;

    let url = Url::parse(&server.uri()).unwrap();
    let scope = ScopeGuard::new(&url, &[], &[]).unwrap();
    let http = HttpEngine::new(10, 1_000_000, 4, "sherlock-test", HashMap::new()).unwrap();
    let rate = RateLimiter::new(50);
    let cancel = CancellationToken::new();
    let events = sherlock_homes::core::events::EventBus::new(64);
    let limits = sherlock_homes::discovery::CrawlLimits {
        max_depth: 2,
        ..Default::default()
    };
    let crawled = crawl(
        &url, &http, &scope, &rate, &cancel, &events, "SH-TEST", &limits,
    )
    .await
    .unwrap();
    assert!(!crawled.pages.is_empty());
    assert!(crawled
        .endpoints
        .iter()
        .any(|e| e.normalized_path == "/" || e.normalized_path == "/login"));

    let db = Database::open_in_memory().unwrap();
    let id = CaseId("SH-260814-IT01".into());
    db.create_case(&id, &server.uri(), "safe").unwrap();
    let pages: Vec<_> = crawled.pages.iter().map(|p| p.response.clone()).collect();
    let dets = all_detectors();
    for ep in &crawled.endpoints {
        let ctx = DetectorContext {
            case_id: &id.0,
            pages: &pages,
            http: &http,
            scope: &scope,
            rate: &rate,
            cancel: &cancel,
            mode: ScanMode::Passive,
        };
        for d in &dets {
            if d.supports(ep) {
                let found = d.analyze(&ctx, ep).await.unwrap();
                for c in found {
                    db.upsert_finding(&id.0, &c).unwrap();
                }
            }
        }
    }
    assert!(!db.list_findings(&id.0).unwrap().is_empty());

    let dir = tempfile::tempdir().unwrap();
    let written = write_reports(
        &db,
        &id.0,
        &[
            ReportFormat::Json,
            ReportFormat::Html,
            ReportFormat::Markdown,
            ReportFormat::Csv,
            ReportFormat::Sarif,
            ReportFormat::Pdf,
            ReportFormat::Jsonl,
        ],
        dir.path(),
    )
    .unwrap();
    assert_eq!(written.len(), 7);
    for (_, p) in written {
        assert!(p.exists());
        assert!(p.metadata().unwrap().len() > 10);
    }
}

#[test]
fn helpers() {
    assert_eq!(normalize_path("/api/users/9"), "/api/users/{id}");
    assert!(redact_text("Authorization: Bearer secret-token-value").contains("[REDACTED]"));
}
