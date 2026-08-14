use scraper::{Html, Selector};
use url::Url;

#[derive(Debug, Clone)]
pub struct ParsedPage {
    pub title: Option<String>,
    pub links: Vec<String>,
    pub scripts: Vec<String>,
    pub forms: Vec<FormInfo>,
}

#[derive(Debug, Clone)]
pub struct FormInfo {
    pub action: String,
    pub method: String,
    pub inputs: Vec<(String, String)>,
}

pub fn parse_html(base: &Url, html: &str) -> ParsedPage {
    let doc = Html::parse_document(html);
    let title = Selector::parse("title").ok().and_then(|s| {
        doc.select(&s)
            .next()
            .map(|n| n.text().collect::<String>().trim().to_string())
    });
    let mut links = Vec::new();
    if let Ok(sel) = Selector::parse("a[href]") {
        for n in doc.select(&sel) {
            if let Some(h) = n.value().attr("href") {
                if let Ok(u) = base.join(h) {
                    if u.scheme() == "http" || u.scheme() == "https" {
                        links.push(strip_fragment(u));
                    }
                }
            }
        }
    }
    let mut scripts = Vec::new();
    if let Ok(sel) = Selector::parse("script[src]") {
        for n in doc.select(&sel) {
            if let Some(h) = n.value().attr("src") {
                if let Ok(u) = base.join(h) {
                    scripts.push(strip_fragment(u));
                }
            }
        }
    }
    let forms = crate::discovery::forms::extract(base, &doc);
    ParsedPage {
        title,
        links,
        scripts,
        forms,
    }
}

fn strip_fragment(mut u: Url) -> String {
    u.set_fragment(None);
    u.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_links() {
        let base = Url::parse("https://example.com/").unwrap();
        let p = parse_html(
            &base,
            r#"<html><a href="/login">l</a><script src="/app.js"></script></html>"#,
        );
        assert!(p.links.iter().any(|l| l.contains("/login")));
        assert!(p.scripts.iter().any(|l| l.contains("/app.js")));
    }
}
