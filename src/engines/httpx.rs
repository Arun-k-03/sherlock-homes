use crate::core::error::Result;

pub async fn run_if_present(_target: &str) -> Result<()> {
    let _ = which::which("httpx");
    Ok(())
}
