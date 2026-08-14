use crate::core::error::Result;
use crate::core::types::Endpoint;

pub async fn run_if_present(_target: &str) -> Result<Vec<Endpoint>> {
    if which::which("katana").is_err() {
        return Ok(vec![]);
    }
    Ok(vec![])
}
