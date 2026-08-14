use std::collections::HashMap;

pub fn parse_set_cookie(headers: &HashMap<String, String>) -> Vec<CookieMeta> {
    let mut out = Vec::new();
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("set-cookie") {
            out.push(CookieMeta::parse(v));
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct CookieMeta {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
}

impl CookieMeta {
    pub fn parse(raw: &str) -> Self {
        let mut parts = raw.split(';');
        let nv = parts.next().unwrap_or("");
        let name = nv.split('=').next().unwrap_or("").trim().to_string();
        let mut secure = false;
        let mut http_only = false;
        let mut same_site = None;
        for p in parts {
            let p = p.trim();
            if p.eq_ignore_ascii_case("secure") {
                secure = true;
            } else if p.eq_ignore_ascii_case("httponly") {
                http_only = true;
            } else if let Some(rest) = p.strip_prefix("samesite=").or_else(|| {
                p.to_ascii_lowercase()
                    .starts_with("samesite=")
                    .then(|| p.split_once('=').map(|x| x.1).unwrap_or(""))
            }) {
                same_site = Some(rest.to_string());
            } else if p.to_ascii_lowercase().starts_with("samesite=") {
                same_site = p.split_once('=').map(|x| x.1.to_string());
            }
        }
        Self {
            name,
            secure,
            http_only,
            same_site,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_flags() {
        let c = CookieMeta::parse("sid=abc; Secure; HttpOnly; SameSite=Lax");
        assert!(c.secure && c.http_only);
        assert_eq!(c.same_site.as_deref(), Some("Lax"));
    }
}
