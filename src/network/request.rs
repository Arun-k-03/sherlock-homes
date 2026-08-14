use crate::evidence::redact_text;

pub fn format_request_line(method: &str, url: &str) -> String {
    redact_text(&format!("{method} {url}"))
}
