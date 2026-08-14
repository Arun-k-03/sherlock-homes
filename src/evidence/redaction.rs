//! Redact secrets from displayed or exported HTTP evidence.

use once_cell::sync::Lazy;
use regex::Regex;

static AUTH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(authorization:\s*bearer\s+)[^\s]+").expect("re"));
static BASIC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(authorization:\s*basic\s+)[^\s]+").expect("re"));
static COOKIE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)((?:cookie|set-cookie):\s*[^;=\s]+=)[^;\r\n]+").expect("re"));
static API_KEY_HDR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)((?:x-api-key|api-key|x-auth-token):\s*)[^\s]+").expect("re"));
static JWT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").expect("re")
});
static AWS: Lazy<Regex> = Lazy::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").expect("re"));

static PEM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----")
        .expect("re")
});

pub fn redact_text(input: &str) -> String {
    let mut s = AUTH.replace_all(input, "$1[REDACTED]").into_owned();
    s = BASIC.replace_all(&s, "$1[REDACTED]").into_owned();
    s = COOKIE.replace_all(&s, "$1[REDACTED]").into_owned();
    s = API_KEY_HDR.replace_all(&s, "$1[REDACTED]").into_owned();
    s = JWT.replace_all(&s, "[REDACTED_JWT]").into_owned();
    s = AWS.replace_all(&s, "[REDACTED_AWS_KEY]").into_owned();
    s = PEM
        .replace_all(
            &s,
            "-----BEGIN PRIVATE KEY----- [REDACTED] -----END PRIVATE KEY-----",
        )
        .into_owned();
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_bearer() {
        let out = redact_text("Authorization: Bearer abc.def.ghi extra");
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("abc.def.ghi"));
    }

    #[test]
    fn redacts_cookie() {
        let out = redact_text("Cookie: session=supersecret; theme=dark");
        assert!(out.contains("session=[REDACTED]"));
        assert!(!out.contains("supersecret"));
    }
}
