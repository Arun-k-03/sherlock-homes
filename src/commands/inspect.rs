use crate::core::config::AppConfig;
use crate::core::rate_limit::RateLimiter;
use crate::core::scope::ScopeGuard;
use crate::network::HttpEngine;
use crate::ui::Renderer;
use std::collections::HashMap;
use tokio_util::sync::CancellationToken;
use url::Url;

pub async fn run(
    cfg: &AppConfig,
    target: &str,
    _auth: Option<&str>,
    renderer: &mut Renderer,
    cancel: CancellationToken,
) -> crate::Result<()> {
    renderer.banner();
    let mut t = target.to_string();
    if !t.contains("://") {
        t = format!("https://{t}");
    }
    let url = Url::parse(&t)?;
    let scope = ScopeGuard::new(&url, &[], &[])?;
    let http = HttpEngine::new(
        cfg.scan.timeout_seconds,
        cfg.scan.max_response_bytes,
        cfg.scan.max_redirects,
        &cfg.scan.user_agent,
        HashMap::new(),
    )?;
    let rate = RateLimiter::new(cfg.scan.rate);
    let fetched = http.get(&url, &scope, &rate, &cancel).await?;
    println!("URL: {}", fetched.response.final_url);
    println!("Status: {}", fetched.response.status);
    println!("Content-Type: {:?}", fetched.response.content_type);
    println!("Body hash: {}", fetched.response.body_hash);
    println!("Elapsed: {} ms", fetched.response.elapsed_ms);
    println!("\nHeaders:");
    for (k, v) in &fetched.response.headers {
        println!("  {}: {}", k, crate::evidence::redact_text(v));
    }
    println!("\nTechnologies:");
    for t in crate::fingerprint::fingerprint(&fetched.response) {
        println!("  - {} ({})", t.name, t.evidence);
    }
    Ok(())
}
