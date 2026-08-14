use crate::network::response::RecordedResponse;

#[derive(Debug, Clone)]
pub struct TechHit {
    pub name: String,
    pub evidence: String,
}

pub fn fingerprint(resp: &RecordedResponse) -> Vec<TechHit> {
    let mut hits = Vec::new();
    for (k, v) in crate::fingerprint::headers::interesting_headers(resp) {
        hits.push(TechHit {
            name: format!("{k}: {v}"),
            evidence: format!("HTTP header {k}"),
        });
    }
    if let Some(text) = &resp.body_text {
        if let Some(g) = crate::fingerprint::html::generator(text) {
            hits.push(TechHit {
                name: g,
                evidence: "meta generator".into(),
            });
        }
        if text.contains("wp-content") {
            hits.push(TechHit {
                name: "WordPress".into(),
                evidence: "wp-content path".into(),
            });
        }
        if text.contains("__NEXT_DATA__") {
            hits.push(TechHit {
                name: "Next.js".into(),
                evidence: "__NEXT_DATA__".into(),
            });
        }
        if text.contains("csrfmiddlewaretoken") {
            hits.push(TechHit {
                name: "Django".into(),
                evidence: "csrfmiddlewaretoken".into(),
            });
        }
    }
    if resp
        .header("x-powered-by")
        .map(|v| v.to_ascii_lowercase().contains("express"))
        .unwrap_or(false)
    {
        hits.push(TechHit {
            name: "Express".into(),
            evidence: "X-Powered-By".into(),
        });
    }
    hits
}
