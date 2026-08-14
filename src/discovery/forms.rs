use crate::discovery::parser::FormInfo;
use scraper::{Html, Selector};
use url::Url;

pub fn extract(base: &Url, doc: &Html) -> Vec<FormInfo> {
    let mut out = Vec::new();
    let Ok(sel) = Selector::parse("form") else {
        return out;
    };
    let Ok(input_sel) = Selector::parse("input, textarea, select") else {
        return out;
    };
    for form in doc.select(&sel) {
        let action = form.value().attr("action").unwrap_or("");
        let method = form
            .value()
            .attr("method")
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let action_url = base.join(action).map(|u| u.to_string()).unwrap_or_default();
        let mut inputs = Vec::new();
        for inp in form.select(&input_sel) {
            let name = inp.value().attr("name").unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            let typ = inp.value().attr("type").unwrap_or("text").to_string();
            inputs.push((name, typ));
        }
        out.push(FormInfo {
            action: action_url,
            method,
            inputs,
        });
    }
    out
}
