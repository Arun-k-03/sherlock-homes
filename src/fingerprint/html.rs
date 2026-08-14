use scraper::{Html, Selector};

pub fn generator(html: &str) -> Option<String> {
    let doc = Html::parse_document(html);
    let sel = Selector::parse(r#"meta[name="generator"]"#).ok()?;
    doc.select(&sel)
        .next()
        .and_then(|n| n.value().attr("content").map(|s| s.to_string()))
}
