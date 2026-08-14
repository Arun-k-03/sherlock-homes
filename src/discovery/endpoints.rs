use crate::core::types::{Endpoint, ParamLocation, Parameter};
use crate::discovery::normalization::{infer_type, normalize_path};
use url::Url;

pub fn from_url(method: &str, url: &Url) -> Endpoint {
    let mut parameters = Vec::new();
    for (k, v) in url.query_pairs() {
        parameters.push(Parameter {
            name: k.to_string(),
            location: ParamLocation::Query,
            sample: Some(v.to_string()),
            inferred_type: infer_type(&v),
        });
    }
    let path = url.path();
    for seg in path.split('/') {
        if crate::discovery::normalization::normalize_segment(seg) == "{id}" && !seg.is_empty() {
            parameters.push(Parameter {
                name: "id".into(),
                location: ParamLocation::Path,
                sample: Some(seg.to_string()),
                inferred_type: infer_type(seg),
            });
        }
    }
    Endpoint {
        method: method.to_uppercase(),
        url: url.to_string(),
        host: url.host_str().unwrap_or("").to_string(),
        normalized_path: normalize_path(path),
        content_type: None,
        parameters,
        auth_hint: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_params() {
        let u = Url::parse("https://example.com/search?q=phone").unwrap();
        let ep = from_url("GET", &u);
        assert_eq!(ep.normalized_path, "/search");
        assert!(ep.parameters.iter().any(|p| p.name == "q"));
    }
}
