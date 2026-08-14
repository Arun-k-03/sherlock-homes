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

pub fn extract_api_paths(base: &Url, js: &str) -> Vec<String> {
    let mut out = Vec::new();
    for cap in FETCH.captures_iter(js) {
        if let Some(m) = cap.get(1) {
            if let Ok(u) = base.join(m.as_str()) {
                if u.scheme() == "http" || u.scheme() == "https" {
                    out.push(u.to_string());
                }
            }
        }
    }
    for cap in PATH.captures_iter(js) {
        if let Some(m) = cap.get(1) {
            if let Ok(u) = base.join(m.as_str()) {
                out.push(u.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

pub fn source_map_refs(js: &str) -> Vec<String> {
    SOURCEMAP
        .captures_iter(js)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect()
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
}
