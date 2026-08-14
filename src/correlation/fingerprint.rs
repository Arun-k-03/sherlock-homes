use crate::core::types::CandidateFinding;

pub fn compute(host: &str, method: &str, path: &str, param: Option<&str>, class: &str) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        host.to_ascii_lowercase(),
        method.to_ascii_uppercase(),
        path,
        param.unwrap_or("-"),
        class
    )
}

/// Vulnerability classes that are a host-wide control (or banner), not a
/// single-endpoint bug. Correlation stores one finding plus affected paths.
pub fn is_host_aggregated(class: &str) -> bool {
    matches!(
        class,
        "missing_csp"
            | "missing_hsts"
            | "missing_xcto"
            | "x_frame_options"
            | "missing_referrer_policy"
            | "server_banner"
            | "cors_misconfig"
            | "cookie_flags"
    )
}

pub fn host_of(c: &CandidateFinding) -> String {
    if !c.host.is_empty() {
        return c.host.to_ascii_lowercase();
    }
    c.fingerprint
        .split('|')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn aggregation_extra(c: &CandidateFinding) -> String {
    match c.detector_id.as_str() {
        "server_banner" => {
            let line = c
                .evidence_summary
                .lines()
                .next()
                .unwrap_or(&c.evidence_summary)
                .trim();
            if let Some((kind, value)) = line.split_once(':') {
                let token = value.split_whitespace().next().unwrap_or("").trim();
                format!(
                    "{}:{}",
                    kind.trim().to_ascii_lowercase(),
                    token.to_ascii_lowercase()
                )
            } else {
                line.to_ascii_lowercase()
            }
        }
        "cookie_flags" => c
            .evidence_summary
            .split_whitespace()
            .next()
            .unwrap_or("cookie")
            .to_ascii_lowercase(),
        _ => String::new(),
    }
}

pub fn correlate_key(c: &CandidateFinding) -> String {
    let host = host_of(c);
    let class = c.detector_id.as_str();
    if is_host_aggregated(class) {
        format!("{}|HOST|{}|{}", host, class, aggregation_extra(c))
    } else {
        compute(&host, &c.method, &c.endpoint, c.parameter.as_deref(), class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable() {
        let a = compute("Example.com", "get", "/x", Some("q"), "xss");
        let b = compute("example.com", "GET", "/x", Some("q"), "xss");
        assert_eq!(a, b);
    }

    #[test]
    fn host_level_csp_ignores_path() {
        let a = CandidateFinding {
            detector_id: "missing_csp".into(),
            method: "GET".into(),
            endpoint: "/".into(),
            fingerprint: "example.com|GET|/|-|missing_csp".into(),
            ..Default::default()
        };
        let b = CandidateFinding {
            detector_id: "missing_csp".into(),
            method: "GET".into(),
            endpoint: "/login.html".into(),
            fingerprint: "example.com|GET|/login.html|-|missing_csp".into(),
            ..Default::default()
        };
        assert_eq!(correlate_key(&a), correlate_key(&b));
    }
}
