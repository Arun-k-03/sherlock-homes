//! JavaScript discovery: distinguish confirmed request destinations from
//! untrusted string literals that must not become crawl targets.

use once_cell::sync::Lazy;
use regex::Regex;
use url::Url;

static FETCH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:fetch|axios\.(?:get|post|put|delete)|XMLHttpRequest)\s*\(\s*['"]([^'"]+)['"]"#,
    )
    .expect("re")
});
static PATH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)['"](/(?:api|v\d+)[^'"]{0,80})['"]"#).expect("re"));
static SOURCEMAP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"sourceMappingURL=([^\s]+)"#).expect("re"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsReference {
    pub raw: String,
    pub kind: JsRefKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsRefKind {
    ConfirmedRequest,
    StringLiteral,
}

pub fn extract_confirmed_request_urls(base: &Url, js: &str) -> Vec<String> {
    let mut out = Vec::new();
    for cap in FETCH.captures_iter(js) {
        let Some(m) = cap.get(1) else { continue };
        let raw = m.as_str();
        if looks_like_rpc_or_sdk_path(raw) {
            continue;
        }
        if let Ok(u) = join_if_http(base, raw) {
            out.push(u);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Bare JS strings that look like API paths. Do **not** treat these as crawl targets.
pub fn extract_string_api_candidates(js: &str) -> Vec<String> {
    let mut out = Vec::new();
    for cap in PATH.captures_iter(js) {
        if let Some(m) = cap.get(1) {
            out.push(m.as_str().to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Backward-compatible helper used by tests: confirmed fetch destinations only.
pub fn extract_api_paths(base: &Url, js: &str) -> Vec<String> {
    extract_confirmed_request_urls(base, js)
}

pub fn source_map_refs(js: &str) -> Vec<String> {
    SOURCEMAP
        .captures_iter(js)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

fn join_if_http(base: &Url, raw: &str) -> Result<String, ()> {
    let u = if raw.starts_with("http://") || raw.starts_with("https://") {
        Url::parse(raw).map_err(|_| ())?
    } else if raw.starts_with('/') {
        base.join(raw).map_err(|_| ())?
    } else {
        return Err(());
    };
    if u.scheme() == "http" || u.scheme() == "https" {
        Ok(u.to_string())
    } else {
        Err(())
    }
}

/// Firebase-style and similar RPC paths (`/v1/accounts:signInWithPassword`) are
/// not same-origin HTML resources even when they look like absolute paths.
pub fn looks_like_rpc_or_sdk_path(path: &str) -> bool {
    let p = path.split('?').next().unwrap_or(path);
    if p.contains("://") {
        return false;
    }
    p.contains(':') && !p.starts_with("http")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_fetch() {
        let base = Url::parse("https://example.com/").unwrap();
        let urls = extract_api_paths(&base, r#"fetch("/api/orders")"#);
        assert!(urls.iter().any(|u| u.contains("/api/orders")));
    }

    #[test]
    fn firebase_style_strings_are_not_same_origin_crawl_targets() {
        let base = Url::parse("https://app.example.com/assets/app.js").unwrap();
        let js = r#"
            const x = "/v1/accounts:delete";
            const y = "/v1/accounts:lookup";
            const z = "/v1/accounts:signInWithPassword";
            const t = "/v1/token";
            const r = "/v2/recaptchaConfig";
            fetch("/api/profile");
        "#;
        let crawl = extract_confirmed_request_urls(&base, js);
        assert!(crawl.iter().any(|u| u.ends_with("/api/profile")));
        assert!(!crawl.iter().any(|u| u.contains("accounts:delete")));
        assert!(!crawl.iter().any(|u| u.contains("signInWithPassword")));
        assert!(!crawl.iter().any(|u| u.contains("recaptchaConfig")));
        let refs = extract_string_api_candidates(js);
        assert!(refs.iter().any(|s| s.contains("accounts:delete")));
        assert!(refs.iter().any(|s| s == "/v1/token"));
    }

    #[test]
    fn rpc_path_helper() {
        assert!(looks_like_rpc_or_sdk_path("/v1/accounts:delete"));
        assert!(!looks_like_rpc_or_sdk_path("/api/profile"));
        assert!(!looks_like_rpc_or_sdk_path("https://example.com/v1/x"));
    }
}
