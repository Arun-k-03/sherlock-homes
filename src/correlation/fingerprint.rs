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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable() {
        let a = compute("Example.com", "get", "/x", Some("q"), "xss");
        let b = compute("example.com", "GET", "/x", Some("q"), "xss");
        assert_eq!(a, b);
    }
}
