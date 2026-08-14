//! Local detector accuracy lab. No Internet. WireMock only.

use serde::Deserialize;
use sherlock_homes::core::config::ScanMode;
use sherlock_homes::core::rate_limit::RateLimiter;
use sherlock_homes::core::scope::ScopeGuard;
use sherlock_homes::detectors::{all_detectors, DetectorContext};
use sherlock_homes::discovery::endpoints::from_url;
use sherlock_homes::network::HttpEngine;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Debug, Deserialize)]
struct Expectation {
    route: String,
    kind: String,
    expected: Vec<String>,
}

#[tokio::test]
async fn detector_accuracy_against_local_lab() {
    let server = MockServer::start().await;
    mount_lab(&server).await;

    let raw = include_str!("lab/ground-truth.json");
    let cases: Vec<Expectation> = serde_json::from_str(raw).unwrap();

    let base = Url::parse(&server.uri()).unwrap();
    let scope = ScopeGuard::new(&base, &[], &[]).unwrap();
    let http = HttpEngine::new(10, 1_000_000, 4, "sherlock-lab", HashMap::new()).unwrap();
    let rate = RateLimiter::new(50);
    let cancel = CancellationToken::new();
    let dets = all_detectors();

    #[derive(Default, serde::Serialize)]
    struct Row {
        detector_id: String,
        tp: u32,
        tn: u32,
        fp: u32,
        fn_: u32,
        precision: Option<f64>,
        recall: Option<f64>,
        false_positive_rate: Option<f64>,
        false_negative_rate: Option<f64>,
    }

    let mut stats: HashMap<String, Row> = HashMap::new();
    let mut details = Vec::new();

    for case in &cases {
        let url = base.join(&case.route).unwrap();
        let fetched = http
            .execute("GET", &url, None, None, &scope, &rate, &cancel)
            .await
            .unwrap();
        let page_url = Url::parse(&fetched.response.final_url).unwrap_or(url.clone());
        let ep = from_url("GET", &page_url);
        let pages = vec![fetched.response.clone()];
        let ctx = DetectorContext {
            case_id: "SH-LAB",
            pages: &pages,
            http: &http,
            scope: &scope,
            rate: &rate,
            cancel: &cancel,
            mode: ScanMode::Passive,
        };
        let mut found = HashSet::new();
        for d in &dets {
            if !d.supports(&ep) {
                continue;
            }
            for c in d.analyze(&ctx, &ep).await.unwrap() {
                found.insert(c.detector_id);
            }
        }

        for class in &case.expected {
            let row = stats.entry(class.clone()).or_insert_with(|| Row {
                detector_id: class.clone(),
                ..Default::default()
            });
            let hit = found.contains(class);
            match case.kind.as_str() {
                "positive" => {
                    if hit {
                        row.tp += 1;
                    } else {
                        row.fn_ += 1;
                    }
                }
                "negative" => {
                    if hit {
                        row.fp += 1;
                    } else {
                        row.tn += 1;
                    }
                }
                _ => panic!("unknown kind {}", case.kind),
            }
        }
        details.push(serde_json::json!({
            "route": case.route,
            "kind": case.kind,
            "expected": case.expected,
            "observed": found,
        }));
    }

    for row in stats.values_mut() {
        let tp = row.tp as f64;
        let fp = row.fp as f64;
        let fn_ = row.fn_ as f64;
        let tn = row.tn as f64;
        if tp + fp > 0.0 {
            row.precision = Some(tp / (tp + fp));
        }
        if tp + fn_ > 0.0 {
            row.recall = Some(tp / (tp + fn_));
        }
        if fp + tn > 0.0 {
            row.false_positive_rate = Some(fp / (fp + tn));
        }
        if fn_ + tp > 0.0 {
            row.false_negative_rate = Some(fn_ / (fn_ + tp));
        }
    }

    let mut rows: Vec<_> = stats.into_values().collect();
    rows.sort_by(|a, b| a.detector_id.cmp(&b.detector_id));
    let report = serde_json::json!({
        "lab": "localhost wiremock fixtures",
        "internet": false,
        "detectors": rows,
        "cases": details,
    });
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/detector-benchmark.json");
    if let Some(parent) = out.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&out, serde_json::to_string_pretty(&report).unwrap()).unwrap();

    let cases = report["cases"].as_array().cloned().unwrap_or_default();
    let fp_secret = cases
        .iter()
        .find(|c| c["route"] == "/secrets/false-positive");
    if let Some(c) = fp_secret {
        let observed = c["observed"].as_array().cloned().unwrap_or_default();
        assert!(
            !observed
                .iter()
                .any(|v| v.as_str() == Some("secret_exposure")),
            "minified apiKey alias must not produce secret_exposure"
        );
    }
    let vuln_headers = cases.iter().find(|c| c["route"] == "/headers/vulnerable");
    if let Some(c) = vuln_headers {
        let observed = c["observed"].as_array().cloned().unwrap_or_default();
        assert!(
            observed.iter().any(|v| v.as_str() == Some("missing_csp"))
                || observed.iter().any(|v| v.as_str() == Some("missing_xcto")),
            "vulnerable headers fixture should yield at least one header finding, observed={observed:?}"
        );
    }
}

async fn mount_lab(server: &MockServer) {
    html(
        server,
        "/headers/vulnerable",
        200,
        "<html><title>v</title><body>ok</body></html>",
        &[],
    )
    .await;
    html(
        server,
        "/headers/secure",
        200,
        "<html><title>s</title><body>ok</body></html>",
        &[
            ("content-security-policy", "default-src 'self'"),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "no-referrer"),
            ("strict-transport-security", "max-age=31536000"),
        ],
    )
    .await;
    html(server, "/headers/404", 404, "<html>missing</html>", &[]).await;
    Mock::given(method("GET"))
        .and(path("/headers/image"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "image/png")
                .set_body_raw(b"\x89PNG".to_vec(), "image/png"),
        )
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/cookies/vulnerable"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .insert_header("set-cookie", "session=labonly")
                .set_body_string("<html>c</html>"),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/cookies/secure"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .insert_header("set-cookie", "session=labonly; HttpOnly; SameSite=Lax")
                .set_body_string("<html>c</html>"),
        )
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/cors/vulnerable"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .insert_header("access-control-allow-origin", "*")
                .set_body_string("{\"ok\":true}"),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/cors/secure"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .insert_header("access-control-allow-origin", "https://app.example")
                .set_body_string("{\"ok\":true}"),
        )
        .mount(server)
        .await;

    html(
        server,
        "/debug/vulnerable",
        500,
        "Traceback (most recent call last):\n  File \"app.py\", line 1",
        &[],
    )
    .await;
    html(server, "/debug/secure", 200, "<html>healthy</html>", &[]).await;

    Mock::given(method("GET"))
        .and(path("/sourcemap/vulnerable"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/javascript")
                .set_body_string("console.log(1);\n//# sourceMappingURL=app.js.map\n"),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sourcemap/secure"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/javascript")
                .set_body_string("console.log(1);\n"),
        )
        .mount(server)
        .await;

    html(
        server,
        "/secrets/vulnerable",
        200,
        "<pre>-----BEGIN RSA PRIVATE KEY-----\nMIIEFAKE_PRIVATE_KEY_FOR_SHERLOCK_LAB_ONLY\n-----END RSA PRIVATE KEY-----</pre>",
        &[],
    )
    .await;
    html(
        server,
        "/secrets/secure",
        200,
        "<html>const apiKey = process.env.API_KEY;</html>",
        &[],
    )
    .await;
    html(
        server,
        "/secrets/false-positive",
        200,
        "<script>apiKey:a}=t.config,c=await</script>",
        &[],
    )
    .await;
}

async fn html(server: &MockServer, route: &str, status: u16, body: &str, extra: &[(&str, &str)]) {
    let mut t = ResponseTemplate::new(status)
        .insert_header("content-type", "text/html")
        .set_body_string(body);
    for (k, v) in extra {
        t = t.insert_header(*k, *v);
    }
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(t)
        .mount(server)
        .await;
}
