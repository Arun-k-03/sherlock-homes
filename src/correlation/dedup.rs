use crate::core::types::CandidateFinding;
use std::collections::HashMap;

pub fn merge(candidates: Vec<CandidateFinding>) -> Vec<CandidateFinding> {
    let mut map: HashMap<String, CandidateFinding> = HashMap::new();
    for c in candidates {
        map.entry(c.fingerprint.clone())
            .and_modify(|e| {
                if !e.source_engine.contains(&c.source_engine) {
                    e.source_engine = format!("{}, {}", e.source_engine, c.source_engine);
                }
                if c.confidence > e.confidence {
                    e.confidence = c.confidence;
                    e.evidence_summary = format!(
                        "{}\n---\n[{}] {}",
                        e.evidence_summary, c.source_engine, c.evidence_summary
                    );
                }
            })
            .or_insert(c);
    }
    map.into_values().collect()
}
