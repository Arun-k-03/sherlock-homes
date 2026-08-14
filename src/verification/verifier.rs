use crate::core::types::{CandidateFinding, Confidence};
use crate::correlation::confidence;

/// Promote or reject candidates. A delta alone never confirms a vulnerability.
pub fn verdict(c: &CandidateFinding, repeatable: bool, independent_sources: usize) -> Confidence {
    if c.confidence == Confidence::Rejected {
        return Confidence::Rejected;
    }
    let verified = matches!(
        c.confidence,
        Confidence::Confirmed | Confidence::HighConfidence
    );
    confidence::combine(independent_sources.max(1), verified, repeatable)
}
