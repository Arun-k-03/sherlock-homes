use crate::network::response::RecordedResponse;

pub fn interesting_headers(resp: &RecordedResponse) -> Vec<(String, String)> {
    let names = [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-generator",
        "via",
        "x-drupal-cache",
        "x-shopify-stage",
    ];
    names
        .iter()
        .filter_map(|n| resp.header(n).map(|v| ((*n).to_string(), v.to_string())))
        .collect()
}
