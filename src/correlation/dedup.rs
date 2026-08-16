use crate::core::types::CandidateFinding;
use crate::correlation::fingerprint::{correlate_key, host_of};
use std::collections::HashMap;

pub fn merge(candidates: Vec<CandidateFinding>) -> Vec<CandidateFinding> {
    let mut map: HashMap<String, CandidateFinding> = HashMap::new();
    for c in candidates {
        let key = correlate_key(&c);
        map.entry(key.clone())
            .and_modify(|existing| merge_into(existing, &c))
            .or_insert_with(|| normalize_new(c, key));
    }
    map.into_values().collect()
}

pub fn prepare(c: &CandidateFinding) -> CandidateFinding {
    let mut prepared = c.clone();
    prepared.fingerprint = correlate_key(c);
    prepared.host = host_of(c);
    let label = c.observation_label();
    if !label.trim().is_empty() && !prepared.affected_endpoints.iter().any(|e| e == &label) {
        prepared.affected_endpoints.push(label);
    }
    prepared
}

fn normalize_new(mut c: CandidateFinding, key: String) -> CandidateFinding {
    c.host = host_of(&c);
    c.fingerprint = key;
    let label = c.observation_label();
    if c.affected_endpoints.is_empty() {
        c.affected_endpoints.push(label);
    }
    c
}

fn merge_into(existing: &mut CandidateFinding, incoming: &CandidateFinding) {
    let label = incoming.observation_label();
    if !label.trim().is_empty() && !existing.affected_endpoints.iter().any(|e| e == &label) {
        existing.affected_endpoints.push(label);
    }
    for ep in &incoming.affected_endpoints {
        if !ep.trim().is_empty() && !existing.affected_endpoints.iter().any(|e| e == ep) {
            existing.affected_endpoints.push(ep.clone());
        }
    }
    if !existing.source_engine.contains(&incoming.source_engine) {
        existing.source_engine = format!("{}, {}", existing.source_engine, incoming.source_engine);
    }
    if incoming.confidence > existing.confidence {
        existing.confidence = incoming.confidence;
    }
    existing.evidence_summary =
        append_unique_evidence(&existing.evidence_summary, &incoming.evidence_summary);
    let n = existing.affected_endpoints.len();
    if n > 1 && !existing.description.contains("Affected endpoints:") {
        existing.description =
            format!("{}\n\nAffected endpoints: {n}", existing.description.trim());
    } else if n > 1 {
        existing.description = rewrite_affected_count(&existing.description, n);
    }
}

pub fn append_unique_evidence(existing: &str, incoming: &str) -> String {
    let incoming = incoming.trim();
    if incoming.is_empty() {
        return existing.to_string();
    }
    if existing.contains(incoming) {
        return existing.to_string();
    }
    if existing.trim().is_empty() {
        return incoming.to_string();
    }
    format!("{}\n---\n{incoming}", existing.trim())
}

fn rewrite_affected_count(description: &str, n: usize) -> String {
    if let Some(idx) = description.rfind("Affected endpoints:") {
        format!("{}Affected endpoints: {n}", &description[..idx])
    } else {
        format!("{}\n\nAffected endpoints: {n}", description.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{Confidence, Severity};

    fn csp(path: &str) -> CandidateFinding {
        CandidateFinding {
            detector_id: "missing_csp".into(),
            detector_name: "CSP".into(),
            title: "Missing Content-Security-Policy".into(),
            description: "CSP header is absent.".into(),
            severity: Severity::Low,
            confidence: Confidence::Confirmed,
            method: "GET".into(),
            endpoint: path.into(),
            fingerprint: format!("example.com|GET|{path}|-|missing_csp"),
            source_engine: "sherlock-core".into(),
            host: "example.com".into(),
            evidence_summary: "Content-Security-Policy absent".into(),
            ..Default::default()
        }
    }

    #[test]
    fn merges_csp_across_paths() {
        let merged = merge(vec![csp("/"), csp("/login.html"), csp("/search")]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].affected_endpoints.len(), 3);
        assert!(merged[0].fingerprint.contains("|HOST|missing_csp|"));
    }
}
