//! Scope Guard — every outgoing active request must pass this check.

use crate::core::error::{Result, SherlockError};
use std::collections::HashSet;
use url::Url;

#[derive(Debug, Clone)]
pub struct ScopeGuard {
    allowed_hosts: HashSet<String>,
    exclude_patterns: Vec<Pattern>,
}

#[derive(Debug, Clone)]
struct Pattern {
    raw: String,
}

impl Pattern {
    fn matches(&self, path: &str) -> bool {
        wildcard_match(&self.raw, path)
    }
}

/// `*` matches any path segment run; `**` not required for v1.
fn wildcard_match(pattern: &str, path: &str) -> bool {
    let pat = if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("/{pattern}")
    };
    let text = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    glob_match(&pat, &text)
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    fn rec(p: &[char], t: &[char]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some('*'), _) => rec(&p[1..], t) || (!t.is_empty() && rec(p, &t[1..])),
            (Some(&pc), Some(&tc)) if pc == tc => rec(&p[1..], &t[1..]),
            _ => false,
        }
    }
    rec(&p, &t)
}

impl ScopeGuard {
    pub fn new(target: &Url, extra_allows: &[String], excludes: &[String]) -> Result<Self> {
        let mut allowed_hosts = HashSet::new();
        let host = target
            .host_str()
            .ok_or_else(|| SherlockError::InvalidTarget("target has no host".into()))?
            .to_ascii_lowercase();
        allowed_hosts.insert(host);
        for a in extra_allows {
            allowed_hosts.insert(
                a.trim()
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .split('/')
                    .next()
                    .unwrap_or(a)
                    .to_ascii_lowercase(),
            );
        }
        let exclude_patterns = excludes
            .iter()
            .map(|raw| Pattern { raw: raw.clone() })
            .collect();
        Ok(Self {
            allowed_hosts,
            exclude_patterns,
        })
    }

    pub fn allows_url(&self, url: &Url) -> Result<()> {
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(SherlockError::Scope(format!(
                "scheme '{scheme}' is not allowed"
            )));
        }
        let host = url
            .host_str()
            .ok_or_else(|| SherlockError::Scope("URL has no host".into()))?
            .to_ascii_lowercase();
        if !self.allowed_hosts.contains(&host) {
            return Err(SherlockError::Scope(format!(
                "host '{host}' is outside the authorized scene"
            )));
        }
        let path = url.path();
        for pat in &self.exclude_patterns {
            if pat.matches(path) {
                return Err(SherlockError::Scope(format!(
                    "path '{path}' is excluded by '{}'",
                    pat.raw
                )));
            }
        }
        Ok(())
    }

    pub fn allows_str(&self, url: &str) -> Result<()> {
        let parsed = Url::parse(url).map_err(|_| SherlockError::InvalidTarget(url.into()))?;
        self.allows_url(&parsed)
    }

    pub fn allowed_hosts(&self) -> impl Iterator<Item = &String> {
        self.allowed_hosts.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_foreign_host() {
        let target = Url::parse("https://example.com").unwrap();
        let g = ScopeGuard::new(&target, &[], &[]).unwrap();
        assert!(g.allows_str("https://example.com/a").is_ok());
        assert!(g.allows_str("https://evil.example/a").is_err());
    }

    #[test]
    fn extra_allow() {
        let target = Url::parse("https://example.com").unwrap();
        let g = ScopeGuard::new(&target, &["api.example.com".into()], &[]).unwrap();
        assert!(g.allows_str("https://api.example.com/v1").is_ok());
    }

    #[test]
    fn exclude_glob() {
        let target = Url::parse("https://example.com").unwrap();
        let g = ScopeGuard::new(&target, &[], &["/logout".into(), "/delete/*".into()]).unwrap();
        assert!(g.allows_str("https://example.com/logout").is_err());
        assert!(g.allows_str("https://example.com/delete/1").is_err());
        assert!(g.allows_str("https://example.com/ok").is_ok());
    }

    #[test]
    fn blocks_non_http() {
        let target = Url::parse("https://example.com").unwrap();
        let g = ScopeGuard::new(&target, &[], &[]).unwrap();
        assert!(g.allows_str("ftp://example.com/a").is_err());
    }
}
