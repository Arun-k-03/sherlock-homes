//! Secret exposure detection: keywords are hints, not evidence.
//! A finding requires an assigned literal (or a known credential format).
//! Prefer false negatives over HIGH/CONFIRMED false positives.

use crate::core::types::{CandidateFinding, Confidence, Endpoint, Severity};
use crate::detectors::fingerprint;
use once_cell::sync::Lazy;
use regex::Regex;

const MAX_SCAN_BYTES: usize = 1_048_576;
const MAX_HITS: usize = 12;
const GENERIC_MIN_LEN: usize = 16;

static AWS_ACCESS_KEY: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("re"));
static GITHUB_PAT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b").expect("re")
});
static SLACK_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").expect("re"));
static JWT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b").expect("re")
});
static PEM_BEGIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----").expect("re")
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretKind {
    Generic,
    AwsAccessKeyId,
    GitHubToken,
    SlackToken,
    Jwt,
    PrivateKeyPem,
}

impl SecretKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::AwsAccessKeyId => "aws_access_key_id",
            Self::GitHubToken => "github_token",
            Self::SlackToken => "slack_token",
            Self::Jwt => "jwt",
            Self::PrivateKeyPem => "private_key_pem",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecretHit {
    pub kind: SecretKind,
    pub key_name: Option<String>,
    pub redacted_value: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub reason: String,
}

pub fn findings_for(endpoint: &Endpoint, body: &str) -> Vec<CandidateFinding> {
    scan_body(body)
        .into_iter()
        .map(|hit| to_finding(endpoint, &hit))
        .collect()
}

pub fn scan_body(body: &str) -> Vec<SecretHit> {
    let text = if body.len() > MAX_SCAN_BYTES {
        &body[..MAX_SCAN_BYTES]
    } else {
        body
    };
    let mut hits = Vec::new();
    collect_assignment_hits(text, &mut hits);
    collect_format_hits(text, &mut hits);
    dedup_hits(hits)
}

fn to_finding(endpoint: &Endpoint, hit: &SecretHit) -> CandidateFinding {
    let key = hit.key_name.as_deref().unwrap_or("literal");
    let title = match hit.kind {
        SecretKind::PrivateKeyPem => "Private key material in response body",
        SecretKind::GitHubToken => "GitHub token-shaped literal in response body",
        SecretKind::SlackToken => "Slack token-shaped literal in response body",
        SecretKind::AwsAccessKeyId => "AWS access key identifier in response body",
        SecretKind::Jwt => "JWT-shaped token in response body",
        SecretKind::Generic => "Suspicious credential-like literal in response body",
    };
    let description = format!(
        "A {} credential candidate was observed near '{}'. {} This is not proof of a live secret; rotate only after confirming the value is a real credential. Client-side platform identifiers are often intentional.",
        hit.kind.as_str(),
        key,
        hit.reason
    );
    CandidateFinding {
        detector_id: "secret_exposure".into(),
        detector_name: "Potential secret exposure".into(),
        title: title.into(),
        description,
        severity: hit.severity,
        confidence: hit.confidence,
        cwe: Some("CWE-798".into()),
        owasp: Some("A07:2021 Identification and Authentication Failures".into()),
        method: endpoint.method.clone(),
        endpoint: endpoint.normalized_path.clone(),
        parameter: Some(hit.kind.as_str().into()),
        evidence_summary: format!(
            "key={} kind={} value={} ({})",
            key,
            hit.kind.as_str(),
            hit.redacted_value,
            hit.reason
        ),
        fingerprint: fingerprint(
            &endpoint.host,
            &endpoint.method,
            &endpoint.normalized_path,
            Some(hit.kind.as_str()),
            "secret_exposure",
        ),
        source_engine: "sherlock-core".into(),
        host: endpoint.host.clone(),
        ..Default::default()
    }
}

fn collect_assignment_hits(text: &str, hits: &mut Vec<SecretHit>) {
    let mut i = 0;
    let bytes = text.as_bytes();
    while i < bytes.len() && hits.len() < MAX_HITS {
        match bytes[i] {
            b'"' | b'\'' | b'`' => {
                let quote = bytes[i];
                let start = i + 1;
                if let Some(end) = close_quote(text, start, quote) {
                    let inner = &text[start..end];
                    let after = skip_ws(text, end + 1);
                    if is_secret_key_name(inner) {
                        if let Some(hit) = hit_from_assignment(text, after, Some(inner)) {
                            hits.push(hit);
                        }
                    }
                    i = end + 1;
                    continue;
                }
                i += 1;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                i = text[i..]
                    .find('\n')
                    .map(|n| i + n + 1)
                    .unwrap_or(bytes.len());
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i = text[i + 2..]
                    .find("*/")
                    .map(|n| i + n + 4)
                    .unwrap_or(bytes.len());
            }
            c if is_ident_start(c) => {
                let (ident, next) = read_ident(text, i);
                if is_secret_key_name(ident) {
                    if let Some(hit) = hit_from_assignment(text, next, Some(ident)) {
                        hits.push(hit);
                    }
                }
                i = next;
            }
            _ => i += 1,
        }
    }
}

fn collect_format_hits(text: &str, hits: &mut Vec<SecretHit>) {
    if PEM_BEGIN.is_match(text) {
        hits.push(score_known(
            SecretKind::PrivateKeyPem,
            None,
            "BEGIN PRIVATE KEY",
        ));
    }
    for m in AWS_ACCESS_KEY.find_iter(text) {
        if is_public_example_credential(m.as_str()) {
            continue;
        }
        hits.push(score_known(SecretKind::AwsAccessKeyId, None, m.as_str()));
    }
    for m in GITHUB_PAT.find_iter(text) {
        hits.push(score_known(SecretKind::GitHubToken, None, m.as_str()));
    }
    for m in SLACK_TOKEN.find_iter(text) {
        hits.push(score_known(SecretKind::SlackToken, None, m.as_str()));
    }
    for m in JWT.find_iter(text) {
        hits.push(score_known(SecretKind::Jwt, None, m.as_str()));
    }
}

fn hit_from_assignment(text: &str, from: usize, key: Option<&str>) -> Option<SecretHit> {
    let i = skip_ws(text, from);
    let bytes = text.as_bytes();
    if i >= bytes.len() {
        return None;
    }
    if bytes[i] != b':' && bytes[i] != b'=' {
        return None;
    }
    let rhs_at = skip_ws(text, i + 1);
    match parse_rhs(text, rhs_at)? {
        Rhs::Reference | Rhs::None => None,
        Rhs::Literal(value) => score_literal(key, &value),
    }
}

#[derive(Debug)]
enum Rhs {
    Literal(String),
    Reference,
    None,
}

fn parse_rhs(text: &str, i: usize) -> Option<Rhs> {
    let bytes = text.as_bytes();
    if i >= bytes.len() {
        return Some(Rhs::None);
    }
    match bytes[i] {
        q @ (b'"' | b'\'' | b'`') => {
            let start = i + 1;
            let end = close_quote(text, start, q)?;
            let inner = &text[start..end];
            if q == b'`' && inner.contains("${") {
                return Some(Rhs::Reference);
            }
            Some(Rhs::Literal(inner.to_string()))
        }
        c if is_ident_start(c) => {
            let _ = read_member_expr(text, i);
            Some(Rhs::Reference)
        }
        _ => Some(Rhs::None),
    }
}

fn score_literal(key: Option<&str>, value: &str) -> Option<SecretHit> {
    if is_placeholder(value) || is_weak_literal(value) || is_public_example_credential(value) {
        return None;
    }
    if let Some(kind) = classify_format(value) {
        return Some(score_known(kind, key, value));
    }
    if value.len() < GENERIC_MIN_LEN {
        return None;
    }
    let entropy = shannon_entropy(value);
    if entropy < 3.3 {
        return None;
    }
    if !has_mixed_charset(value) {
        return None;
    }
    Some(SecretHit {
        kind: SecretKind::Generic,
        key_name: key.map(|s| s.to_string()),
        redacted_value: mask_secret(value),
        severity: Severity::Medium,
        confidence: Confidence::Potential,
        reason: format!("quoted literal length={} entropy={entropy:.2}", value.len()),
    })
}

fn score_known(kind: SecretKind, key: Option<&str>, value: &str) -> SecretHit {
    let (severity, confidence, reason) = match kind {
        SecretKind::PrivateKeyPem => (
            Severity::High,
            Confidence::HighConfidence,
            "PEM private-key block (BEGIN/END) is strong evidence of key material".into(),
        ),
        SecretKind::GitHubToken | SecretKind::SlackToken => (
            Severity::High,
            Confidence::Likely,
            "value matches a known private token format".into(),
        ),
        SecretKind::AwsAccessKeyId => (
            Severity::Medium,
            Confidence::Likely,
            "AWS access key id (AKIA…) is an identifier, not the secret key".into(),
        ),
        SecretKind::Jwt => (
            Severity::Medium,
            Confidence::Potential,
            "JWT-shaped literal; frontend session tokens are not automatically private secrets"
                .into(),
        ),
        SecretKind::Generic => (
            Severity::Medium,
            Confidence::Potential,
            "generic high-entropy literal".into(),
        ),
    };
    SecretHit {
        kind,
        key_name: key.map(|s| s.to_string()),
        redacted_value: mask_secret(value),
        severity,
        confidence,
        reason,
    }
}

fn classify_format(value: &str) -> Option<SecretKind> {
    if PEM_BEGIN.is_match(value) || value.contains("PRIVATE KEY-----") {
        return Some(SecretKind::PrivateKeyPem);
    }
    if AWS_ACCESS_KEY.is_match(value) {
        return Some(SecretKind::AwsAccessKeyId);
    }
    if GITHUB_PAT.is_match(value) {
        return Some(SecretKind::GitHubToken);
    }
    if SLACK_TOKEN.is_match(value) {
        return Some(SecretKind::SlackToken);
    }
    if JWT.is_match(value) {
        return Some(SecretKind::Jwt);
    }
    None
}

fn is_secret_key_name(ident: &str) -> bool {
    let n: String = ident
        .chars()
        .filter(|c| *c != '_' && *c != '-')
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(
        n.as_str(),
        "apikey"
            | "secret"
            | "secretkey"
            | "clientsecret"
            | "token"
            | "password"
            | "accesstoken"
            | "authorization"
            | "privatekey"
            | "authtoken"
            | "bearertoken"
            | "authkey"
    )
}

fn is_public_example_credential(value: &str) -> bool {
    let u = value.to_ascii_uppercase();
    u.contains("EXAMPLE") || u.contains("GUIDES") || value.contains("xxxx")
}

fn is_placeholder(value: &str) -> bool {
    let v = value.trim();
    let n = v.to_ascii_lowercase();
    let compact: String = n.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    matches!(
        n.as_str(),
        "foo"
            | "bar"
            | "baz"
            | "test"
            | "testing"
            | "example"
            | "sample"
            | "dummy"
            | "changeme"
            | "password"
            | "secret"
            | "undefined"
            | "null"
            | "none"
            | "nil"
            | "todo"
            | "true"
            | "false"
            | "xxx"
            | "xxxx"
            | "xxxxxxxx"
            | "123456"
            | "12345678"
            | "your_api_key"
            | "your-api-key"
            | "api_key_here"
            | "insert_key"
            | "placeholder"
            | "replace_me"
    ) || compact == "yourapikey"
        || compact == "apikeyhere"
        || n.contains("your_api_key")
        || n.contains("api_key_here")
        || n.contains("changeme")
        || n.starts_with('<') && n.ends_with('>')
        || v.starts_with("${")
        || v.starts_with("process.env")
}

fn is_weak_literal(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return true;
    }
    if v.starts_with("http://") || v.starts_with("https://") || v.starts_with('/') {
        return true;
    }
    if v.chars().all(|c| c == 'x' || c == 'X' || c == '*') {
        return true;
    }
    if v.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    if looks_like_reference(v) {
        return true;
    }
    false
}

fn looks_like_reference(value: &str) -> bool {
    if value.starts_with("process.env")
        || value.starts_with("window.")
        || value.starts_with("this.")
    {
        return true;
    }
    let bytes = value.as_bytes();
    if bytes.is_empty() || !is_ident_start(bytes[0]) {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$' || c == '.')
        && value.contains('.')
}

fn shannon_entropy(s: &str) -> f64 {
    let mut freq = [0u32; 256];
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    for b in bytes {
        freq[*b as usize] += 1;
    }
    let n = bytes.len() as f64;
    freq.iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = f64::from(*c) / n;
            -p * p.log2()
        })
        .sum()
}

fn has_mixed_charset(s: &str) -> bool {
    let letters = s.chars().any(|c| c.is_ascii_alphabetic());
    let digits = s.chars().any(|c| c.is_ascii_digit());
    letters && digits
}

pub fn mask_secret(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if value.contains("PRIVATE KEY") {
        return "-----BEGIN PRIVATE KEY----- [REDACTED]".into();
    }
    if chars.len() <= 8 {
        let prefix: String = chars.iter().take(2).collect();
        return format!("{prefix}****");
    }
    let prefix: String = chars.iter().take(4).collect();
    let suffix: String = chars[chars.len() - 3..].iter().collect();
    let star_n = (chars.len() - 7).clamp(3, 16);
    format!("{prefix}{}{suffix}", "*".repeat(star_n))
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'$'
}

fn is_ident_continue(b: u8) -> bool {
    is_ident_start(b) || b.is_ascii_digit()
}

fn read_ident(text: &str, i: usize) -> (&str, usize) {
    let bytes = text.as_bytes();
    let mut j = i + 1;
    while j < bytes.len() && is_ident_continue(bytes[j]) {
        j += 1;
    }
    (&text[i..j], j)
}

fn read_member_expr(text: &str, i: usize) -> (&str, usize) {
    let bytes = text.as_bytes();
    let (_, mut j) = read_ident(text, i);
    loop {
        let k = skip_ws(text, j);
        if k < bytes.len() && bytes[k] == b'.' {
            let k2 = skip_ws(text, k + 1);
            if k2 < bytes.len() && is_ident_start(bytes[k2]) {
                let (_, n) = read_ident(text, k2);
                j = n;
                continue;
            }
        }
        break;
    }
    (&text[i..j], j)
}

fn skip_ws(text: &str, mut i: usize) -> usize {
    let bytes = text.as_bytes();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn close_quote(text: &str, start: usize, quote: u8) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == quote {
            return Some(i);
        }
        if quote != b'`' && (bytes[i] == b'\n' || bytes[i] == b'\r') {
            return None;
        }
        i += 1;
    }
    None
}

fn dedup_hits(hits: Vec<SecretHit>) -> Vec<SecretHit> {
    let mut out = Vec::new();
    for hit in hits {
        if out
            .iter()
            .any(|h: &SecretHit| h.kind == hit.kind && h.redacted_value == hit.redacted_value)
        {
            continue;
        }
        out.push(hit);
        if out.len() >= MAX_HITS {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_endpoint() -> Endpoint {
        Endpoint {
            method: "GET".into(),
            url: "https://example.test/assets/index-Bemi_9WV.js".into(),
            host: "example.test".into(),
            normalized_path: "/assets/index-Bemi_9WV.js".into(),
            content_type: Some("application/javascript".into()),
            parameters: vec![],
            auth_hint: None,
        }
    }

    fn kinds(body: &str) -> Vec<SecretKind> {
        scan_body(body).into_iter().map(|h| h.kind).collect()
    }

    fn any_high_or_confirmed(body: &str) -> bool {
        scan_body(body)
            .into_iter()
            .any(|h| h.severity == Severity::High || h.confidence >= Confidence::HighConfidence)
    }

    #[test]
    fn regression_minified_apikey_alias_is_not_a_finding() {
        let body = "apiKey:a}=t.config,c=await";
        let hits = scan_body(body);
        assert!(
            hits.is_empty(),
            "minified alias must not be a secret: {hits:?}"
        );
        assert!(!any_high_or_confirmed(body));
        let findings = findings_for(&sample_endpoint(), body);
        assert!(findings.is_empty());
    }

    #[test]
    fn false_positive_fixtures_produce_zero_confirmed_or_high() {
        let fixtures = [
            "apiKey:a}=t.config,c=await",
            "const {apiKey:a}=config",
            "const token = config.token",
            "const apiKey = process.env.API_KEY",
            r#"const apiKey = "YOUR_API_KEY""#,
            r#"tokenEndpoint="/v1/token""#,
            r#"passwordField="password""#,
            "apiKey:t.config",
            "apiKey:e.apiKey",
            "{apiKey:a}",
            "const{apiKey:a}=t.config",
            "apiKey:config.apiKey",
            r#"const { apiKey: a } = config"#,
        ];
        for body in fixtures {
            let hits = scan_body(body);
            assert!(
                hits.iter()
                    .all(|h| h.confidence != Confidence::Confirmed && h.severity != Severity::High),
                "fixture produced HIGH/CONFIRMED: {body:?} -> {hits:?}"
            );
            assert!(
                hits.is_empty(),
                "benign fixture should yield no findings: {body:?} -> {hits:?}"
            );
        }
    }

    #[test]
    fn keyword_only_rejected() {
        assert!(scan_body("the apiKey is configured later").is_empty());
        assert!(scan_body("password authorization token secret").is_empty());
    }

    #[test]
    fn identifier_assignment_rejected() {
        assert!(scan_body("const token = config.token").is_empty());
        assert!(scan_body("apiKey:t.config").is_empty());
    }

    #[test]
    fn environment_reference_rejected() {
        assert!(scan_body("const apiKey = process.env.API_KEY").is_empty());
    }

    #[test]
    fn placeholder_rejected() {
        assert!(scan_body(r#"const apiKey = "YOUR_API_KEY""#).is_empty());
        assert!(scan_body(r#"secret = "changeme""#).is_empty());
        assert!(scan_body(r#"token = "xxxxxxxx""#).is_empty());
        assert!(scan_body(r#"password = "123456""#).is_empty());
        assert!(scan_body(r#"apiKey = "undefined""#).is_empty());
        assert!(scan_body(r#"apiKey = "null""#).is_empty());
        assert!(scan_body(r#"apiKey = "example""#).is_empty());
        assert!(scan_body(r#"apiKey = "foo""#).is_empty());
    }

    #[test]
    fn short_value_rejected() {
        assert!(scan_body(r#"apiKey = "shortval""#).is_empty());
        assert!(scan_body("apiKey:a").is_empty());
    }

    #[test]
    fn high_entropy_literal_is_potential_not_confirmed() {
        let body = r#"const apiKey = "n8q2mK9vL4xR7wP1sT6yH3bC5zQ8""#;
        let hits = scan_body(body);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, SecretKind::Generic);
        assert_eq!(hits[0].confidence, Confidence::Potential);
        assert_ne!(hits[0].severity, Severity::High);
        assert_ne!(hits[0].confidence, Confidence::Confirmed);
        assert!(!hits[0]
            .redacted_value
            .contains("n8q2mK9vL4xR7wP1sT6yH3bC5zQ8"));
        assert!(hits[0].redacted_value.starts_with("n8q2"));
    }

    #[test]
    fn json_quoted_key_with_literal() {
        let body = r#"{"apiKey":"n8q2mK9vL4xR7wP1sT6yH3bC5zQ8"}"#;
        assert_eq!(kinds(body), vec![SecretKind::Generic]);
    }

    #[test]
    fn known_synthetic_github_token_is_candidate() {
        let body = r#"const token = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#;
        let hits = scan_body(body);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, SecretKind::GitHubToken);
        assert_eq!(hits[0].confidence, Confidence::Likely);
        assert_ne!(hits[0].confidence, Confidence::Confirmed);
        assert!(!hits[0]
            .redacted_value
            .contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn pem_fixture_is_strong_candidate() {
        let body = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK9SYNTHETICNOTAREALKEYMATERIALXX\n-----END RSA PRIVATE KEY-----";
        let hits = scan_body(body);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, SecretKind::PrivateKeyPem);
        assert!(hits[0].confidence >= Confidence::HighConfidence);
        assert_eq!(hits[0].severity, Severity::High);
        assert!(!hits[0].redacted_value.contains("MIIBOgIBAAJBAK9"));
    }

    #[test]
    fn aws_access_key_id_is_not_automatic_high_confirmed() {
        let body = "AKIAB1C2D3E4F5G6H7I8";
        let hits = scan_body(body);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, SecretKind::AwsAccessKeyId);
        assert_ne!(hits[0].confidence, Confidence::Confirmed);
        assert_ne!(hits[0].severity, Severity::High);
    }

    #[test]
    fn findings_never_embed_full_generic_secret() {
        let secret = "n8q2mK9vL4xR7wP1sT6yH3bC5zQ8";
        let body = format!(r#"api_key='{secret}'"#);
        let findings = findings_for(&sample_endpoint(), &body);
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].evidence_summary.contains(secret));
        assert!(!findings[0].description.contains(secret));
        assert_eq!(findings[0].confidence, Confidence::Potential);
    }

    #[test]
    fn mask_keeps_prefix_and_suffix() {
        let masked = mask_secret("abcd1234567890XYZ");
        assert!(masked.starts_with("abcd"));
        assert!(masked.ends_with("XYZ"));
        assert!(masked.contains('*'));
        assert!(!masked.contains("1234567890"));
    }
}
