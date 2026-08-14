use crate::network::response::RecordedResponse;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub status_diff: i32,
    pub length_diff: i64,
    pub body_similarity: f64,
    pub header_diff: bool,
    pub redirect_diff: bool,
    pub timing_diff_ms: i128,
    pub reflection: bool,
}

/// A changed response is evidence, never an automatic verdict of VULNERABLE.
pub fn compare(base: &RecordedResponse, test: &RecordedResponse) -> DiffResult {
    let sim = similarity(base.body.as_slice(), test.body.as_slice());
    let header_diff = base.headers != test.headers;
    let redirect_diff = base.redirects != test.redirects;
    DiffResult {
        status_diff: test.status as i32 - base.status as i32,
        length_diff: test.body.len() as i64 - base.body.len() as i64,
        body_similarity: sim,
        header_diff,
        redirect_diff,
        timing_diff_ms: test.elapsed_ms as i128 - base.elapsed_ms as i128,
        reflection: false,
    }
}

fn similarity(a: &[u8], b: &[u8]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let n = a.len().max(b.len()) as f64;
    let mut same = 0usize;
    for i in 0..a.len().min(b.len()) {
        if a[i] == b[i] {
            same += 1;
        }
    }
    same as f64 / n
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn resp(status: u16, body: &str) -> RecordedResponse {
        RecordedResponse {
            url: "https://t".into(),
            final_url: "https://t".into(),
            status,
            headers: HashMap::new(),
            content_type: Some("text/html".into()),
            body: body.as_bytes().to_vec(),
            body_text: Some(body.into()),
            body_hash: "x".into(),
            elapsed_ms: 1,
            redirects: vec![],
        }
    }

    #[test]
    fn identical_is_one() {
        let a = resp(200, "hello");
        let d = compare(&a, &a);
        assert_eq!(d.status_diff, 0);
        assert!((d.body_similarity - 1.0).abs() < f64::EPSILON);
    }
}
