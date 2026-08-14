use crate::core::config::ScanMode;
use crate::core::types::{CandidateFinding, Confidence, Endpoint, ParamLocation, Severity};
use crate::detectors::{fingerprint, Detector, DetectorContext};
use crate::verification::differential::compare;
use async_trait::async_trait;
use url::Url;

pub fn detectors() -> Vec<Box<dyn Detector>> {
    vec![Box::new(AuthzCompare)]
}

/// Architecture for BOLA/IDOR-style comparison when two identifiers appear in the path/query.
/// Does not attempt credential stuffing. Only swaps observed IDs already on the authorized scene.
struct AuthzCompare;

#[async_trait]
impl Detector for AuthzCompare {
    fn id(&self) -> &'static str {
        "authz_inconsistency"
    }
    fn name(&self) -> &'static str {
        "Authorization boundary comparison"
    }
    fn supports(&self, endpoint: &Endpoint) -> bool {
        endpoint
            .parameters
            .iter()
            .any(|p| p.location == ParamLocation::Path && p.inferred_type == "integer")
    }
    async fn analyze(
        &self,
        ctx: &DetectorContext<'_>,
        endpoint: &Endpoint,
    ) -> crate::Result<Vec<CandidateFinding>> {
        if matches!(ctx.mode, ScanMode::Passive) {
            return Ok(vec![]);
        }
        let Some(p) = endpoint
            .parameters
            .iter()
            .find(|p| p.location == ParamLocation::Path)
        else {
            return Ok(vec![]);
        };
        let Some(sample) = p.sample.as_deref() else {
            return Ok(vec![]);
        };
        let Ok(orig) = Url::parse(&endpoint.url) else {
            return Ok(vec![]);
        };
        let baseline = match ctx.http.get(&orig, ctx.scope, ctx.rate, ctx.cancel).await {
            Ok(f) => f.response,
            Err(_) => return Ok(vec![]),
        };
        if baseline.status == 401 || baseline.status == 403 {
            return Ok(vec![]);
        }
        let alt = if sample == "1" { "2" } else { "1" };
        let swapped = orig.to_string().replacen(sample, alt, 1);
        let Ok(alt_url) = Url::parse(&swapped) else {
            return Ok(vec![]);
        };
        if ctx.scope.allows_url(&alt_url).is_err() {
            return Ok(vec![]);
        }
        let other = match ctx
            .http
            .get(&alt_url, ctx.scope, ctx.rate, ctx.cancel)
            .await
        {
            Ok(f) => f.response,
            Err(_) => return Ok(vec![]),
        };
        let diff = compare(&baseline, &other);
        // Evidence of inconsistency: both succeeded with different bodies.
        // This is a SUSPECT, not confirmed BOLA — confirmation needs two identities.
        if baseline.status == 200
            && other.status == 200
            && diff.body_similarity < 0.92
            && diff.length_diff.abs() > 32
        {
            return Ok(vec![CandidateFinding {
                detector_id: "authz_inconsistency".into(),
                detector_name: self.name().into(),
                title: "Potential access control inconsistency".into(),
                description: format!(
                    "GET {} and a neighboring identifier both returned HTTP 200 with substantially different bodies. This is a suspect for object-level authorization issues and requires a second test identity to confirm.",
                    endpoint.normalized_path
                ),
                severity: Severity::Medium,
                confidence: Confidence::Potential,
                cwe: Some("CWE-639".into()),
                owasp: Some("A01:2021 Broken Access Control".into()),
                method: endpoint.method.clone(),
                endpoint: endpoint.normalized_path.clone(),
                parameter: Some(p.name.clone()),
                evidence_summary: format!(
                    "status {} vs {}, length delta {}, similarity {:.2}",
                    baseline.status, other.status, diff.length_diff, diff.body_similarity
                ),
                fingerprint: fingerprint(
                    &endpoint.host,
                    &endpoint.method,
                    &endpoint.normalized_path,
                    Some(&p.name),
                    "authz_inconsistency",
                ),
                source_engine: "sherlock-core".into(),
            }]);
        }
        Ok(vec![])
    }
}
