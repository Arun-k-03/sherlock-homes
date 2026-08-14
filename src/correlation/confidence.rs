use crate::core::types::Confidence;

/// Confidence is qualitative, not a precise probability.
pub fn combine(sources: usize, verified: bool, repeatable: bool) -> Confidence {
    if verified && repeatable {
        Confidence::Confirmed
    } else if verified {
        Confidence::HighConfidence
    } else if sources >= 2 {
        Confidence::Likely
    } else {
        Confidence::Potential
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_repeatable_is_confirmed() {
        assert_eq!(combine(1, true, true), Confidence::Confirmed);
    }
}
