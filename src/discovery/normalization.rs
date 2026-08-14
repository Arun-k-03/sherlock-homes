use once_cell::sync::Lazy;
use regex::Regex;

static UUID: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").expect("re")
});
static HEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^[0-9a-f]{32,}$").expect("re"));
static NUM: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\d+$").expect("re"));

pub fn normalize_segment(seg: &str) -> String {
    if UUID.is_match(seg) || NUM.is_match(seg) || HEX.is_match(seg) {
        "{id}".into()
    } else {
        seg.to_string()
    }
}

pub fn normalize_path(path: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    let mut out = String::new();
    for seg in path.split('/') {
        if seg.is_empty() {
            continue;
        }
        out.push('/');
        out.push_str(&normalize_segment(seg));
    }
    if out.is_empty() {
        "/".into()
    } else {
        out
    }
}

pub fn infer_type(sample: &str) -> String {
    if UUID.is_match(sample) {
        "uuid".into()
    } else if NUM.is_match(sample) {
        "integer".into()
    } else if sample.contains('@') {
        "email".into()
    } else {
        "string".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_ids() {
        assert_eq!(normalize_path("/api/users/100"), "/api/users/{id}");
        assert_eq!(normalize_path("/api/users/101"), "/api/users/{id}");
        assert_eq!(
            normalize_path("/items/550e8400-e29b-41d4-a716-446655440000"),
            "/items/{id}"
        );
    }
}
