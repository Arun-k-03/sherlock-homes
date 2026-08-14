use crate::cli::ScanArgs;
use crate::core::config::{AppConfig, ScanMode};
use crate::core::events::{EventBus, EventKind, ScanEvent};
use crate::core::rate_limit::RateLimiter;
use crate::core::scope::ScopeGuard;
use crate::core::types::{CandidateFinding, Confidence, Severity};
use crate::correlation::dedup;
use crate::database::Database;
use crate::detectors::{all_detectors, DetectorContext};
use crate::discovery::crawler;
use crate::evidence::redact_text;
use crate::ids::CaseId;
use crate::network::HttpEngine;
use crate::ui::renderer::{RenderMode, Renderer};
use std::collections::HashMap;
use tokio_util::sync::CancellationToken;
use url::Url;

pub struct ScanOptions {
    pub target: String,
    pub mode: ScanMode,
    pub depth: u32,
    pub rate: u32,
    pub concurrency: u32,
    pub timeout: u64,
    pub allow: Vec<String>,
    pub exclude: Vec<String>,
    pub crawl_only: bool,
    pub hunt: bool,
    pub auth: Option<String>,
    pub resume: Option<String>,
    pub authorize_full: bool,
}

impl ScanOptions {
    pub fn from_args(args: &ScanArgs, cfg: &AppConfig) -> Self {
        Self {
            target: args.target.clone(),
            mode: args.mode.unwrap_or(cfg.scan.mode),
            depth: args.depth.unwrap_or(cfg.scan.depth),
            rate: args.rate.unwrap_or(cfg.scan.rate),
            concurrency: args.concurrency.unwrap_or(cfg.scan.concurrency),
            timeout: args.timeout.unwrap_or(cfg.scan.timeout_seconds),
            allow: args.allow.clone(),
            exclude: args.exclude.clone(),
            crawl_only: false,
            hunt: false,
            auth: args.auth.clone(),
            resume: args.resume.clone(),
            authorize_full: args.i_authorize_full,
        }
    }
}

pub async fn run_scan(
    db: &Database,
    cfg: &AppConfig,
    opts: ScanOptions,
    renderer: &mut Renderer,
    cancel: CancellationToken,
) -> crate::Result<CaseId> {
    if opts.mode == ScanMode::Full && !opts.authorize_full {
        return Err(crate::SherlockError::Authorization(
            "full mode requires --i-authorize-full (still non-destructive; scope-controlled)"
                .into(),
        ));
    }

    let mut target = opts.target.clone();
    if !target.contains("://") {
        target = format!("https://{target}");
    }
    let url = Url::parse(&target).map_err(|_| {
        crate::SherlockError::InvalidTarget(format!("cannot parse target '{target}'"))
    })?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(crate::SherlockError::InvalidTarget(
            "only http and https schemes are allowed".into(),
        ));
    }

    let case_id = if let Some(r) = &opts.resume {
        CaseId(r.clone())
    } else {
        CaseId::generate()
    };
    if opts.resume.is_some() {
        if db.get_case(&case_id.0)?.is_none() {
            return Err(crate::SherlockError::CaseNotFound(case_id.0));
        }
        db.set_case_status(&case_id.0, "running")?;
    } else {
        db.create_case(&case_id, url.as_str(), opts.mode_str())?;
    }

    let events = EventBus::new(4096);
    let mut rx = events.subscribe();
    let case_for_ui = case_id.0.clone();
    // Drain events on this task interleaved — we'll emit then poll.

    renderer.handle(&ScanEvent::new(
        EventKind::CaseOpened,
        &case_id.0,
        format!(
            "Case     {}\nTarget   {}\nMode     {}",
            case_id.0,
            url,
            opts.mode_str().to_uppercase()
        ),
    ));

    let scope = ScopeGuard::new(&url, &opts.allow, &opts.exclude)?;
    events.emit(ScanEvent::new(
        EventKind::TargetValidated,
        &case_id.0,
        url.to_string(),
    ));

    let host = url.host_str().unwrap_or("").to_string();
    let ip = tokio::net::lookup_host(format!(
        "{}:{}",
        host,
        url.port_or_known_default().unwrap_or(443)
    ))
    .await
    .ok()
    .and_then(|mut it| it.next())
    .map(|a| a.ip().to_string());
    if let Some(ref ip) = ip {
        db.insert_host(&case_id.0, &host, Some(ip))?;
        events.emit(ScanEvent::new(
            EventKind::HostResolved,
            &case_id.0,
            format!("{host} -> {ip}"),
        ));
    } else {
        db.insert_host(&case_id.0, &host, None)?;
        events.emit(ScanEvent::new(
            EventKind::Warning,
            &case_id.0,
            format!("DNS lookup failed for {host}; continuing with hostname"),
        ));
    }

    let mut extra = HashMap::new();
    if let Some(name) = &opts.auth {
        if let Some((headers, cookies)) = db.auth_get(name)? {
            if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&headers) {
                extra.extend(map);
            }
            if !cookies.is_empty() && cookies != "{}" {
                extra.insert("Cookie".into(), cookies);
            }
        }
    }

    let http = HttpEngine::new(
        opts.timeout,
        cfg.scan.max_response_bytes,
        cfg.scan.max_redirects,
        &cfg.scan.user_agent,
        extra,
    )?;
    let rate = RateLimiter::new(opts.rate);
    let depth = if opts.hunt { 0 } else { opts.depth };

    events.emit(
        ScanEvent::new(EventKind::PhaseProgress, &case_id.0, "discovery")
            .with_phase("discovery", 10),
    );

    if renderer.mode != RenderMode::Machine && cfg.ui.animations {
        crate::ui::animations::lens_sweep(52, 12, 40, &cancel).await;
    }

    let crawl = crawler::crawl(
        &url, depth, &http, &scope, &rate, &cancel, &events, &case_id.0,
    )
    .await?;

    let mut pages: Vec<_> = crawl.pages.iter().map(|p| p.response.clone()).collect();
    let mut endpoints = crawl.endpoints;

    if !opts.hunt && !opts.crawl_only && opts.mode != ScanMode::Passive {
        let probes = crawler::probe_sensitive(&url, &http, &scope, &rate, &cancel).await;
        for (path, resp) in probes {
            let u = url.join(&path).unwrap_or_else(|_| url.clone());
            let ep = crate::discovery::endpoints::from_url("GET", &u);
            endpoints.push(ep);
            pages.push(resp);
        }
    }

    for p in &crawl.pages {
        let excerpt = redact_text(&p.response.text().chars().take(400).collect::<String>());
        let hdrs = p
            .response
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n");
        let _ = db.insert_http_pair(
            &case_id.0,
            "GET",
            &p.response.final_url,
            &p.request_headers_redacted,
            "",
            p.response.status,
            &redact_text(&hdrs),
            &p.response.body_hash,
            p.response.body.len(),
            p.response.content_type.as_deref(),
            p.response.elapsed_ms,
            &excerpt,
        );
        let title = p.response.body_text.as_ref().and_then(|t| {
            t.split("<title>")
                .nth(1)
                .and_then(|s| s.split("</title>").next())
                .map(|s| s.trim().to_string())
        });
        let _ = db.insert_page(
            &case_id.0,
            &p.response.final_url,
            p.response.status,
            p.response.content_type.as_deref(),
            &p.response.body_hash,
            title.as_deref(),
        );
        for tech in crate::fingerprint::fingerprint(&p.response) {
            let _ = db.insert_tech(&case_id.0, &tech.name, &tech.evidence);
        }
    }

    for ep in &endpoints {
        let _ = db.insert_endpoint(&case_id.0, ep);
        renderer.handle(
            &ScanEvent::new(EventKind::EndpointDiscovered, &case_id.0, ep.key())
                .with_endpoint(&ep.method, &ep.normalized_path),
        );
    }

    events.emit(
        ScanEvent::new(EventKind::PhaseProgress, &case_id.0, "observation")
            .with_phase("discovery", 100)
            .with_phase("observation", 100),
    );
    renderer.handle(
        &ScanEvent::new(EventKind::PhaseProgress, &case_id.0, "observation")
            .with_phase("observation", 100),
    );

    if opts.crawl_only {
        finish(&case_id, db, renderer)?;
        return Ok(case_id);
    }

    let mut candidates: Vec<CandidateFinding> = Vec::new();
    if let Ok(ext) = crate::engines::nuclei::run_if_present(url.as_str(), &cancel).await {
        candidates.extend(ext);
    }
    let detectors = all_detectors();
    let total = endpoints.len().max(1);
    for (i, ep) in endpoints.iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        let pct = ((i * 100) / total) as u8;
        renderer.handle(
            &ScanEvent::new(EventKind::PhaseProgress, &case_id.0, "investigation")
                .with_phase("investigation", pct),
        );
        let dctx = DetectorContext {
            case_id: &case_id.0,
            pages: &pages,
            http: &http,
            scope: &scope,
            rate: &rate,
            cancel: &cancel,
            mode: opts.mode,
        };
        for det in &detectors {
            if !det.supports(ep) {
                continue;
            }
            match det.analyze(&dctx, ep).await {
                Ok(found) => {
                    for c in found {
                        renderer.handle(&ScanEvent {
                            kind: EventKind::CandidateFound,
                            case_id: case_id.0.clone(),
                            timestamp: chrono::Utc::now(),
                            message: c.title.clone(),
                            method: Some(c.method.clone()),
                            path: Some(c.endpoint.clone()),
                            parameter: c.parameter.clone(),
                            severity: Some(c.severity.as_str().into()),
                            phase: None,
                            progress: None,
                            extra: None,
                        });
                        let _ = db.insert_candidate(&case_id.0, &c);
                        candidates.push(c);
                    }
                }
                Err(crate::SherlockError::Cancelled) => break,
                Err(e) => tracing::debug!("detector {} skipped: {e}", det.id()),
            }
        }
    }

    renderer.handle(
        &ScanEvent::new(EventKind::PhaseProgress, &case_id.0, "verification")
            .with_phase("investigation", 100)
            .with_phase("verification", 40),
    );

    let merged = dedup::merge(candidates);
    for c in merged {
        if cancel.is_cancelled() {
            break;
        }
        if c.confidence == Confidence::Rejected {
            continue;
        }
        renderer.handle(&ScanEvent::new(
            EventKind::VerificationStarted,
            &case_id.0,
            c.title.clone(),
        ));
        let fid = db.upsert_finding(&case_id.0, &c)?;
        let _ = db.add_evidence(
            &case_id.0,
            &fid,
            "http",
            "",
            "",
            &redact_text(&c.evidence_summary),
        );
        if c.confidence >= Confidence::HighConfidence {
            renderer.handle(&ScanEvent::new(
                EventKind::FindingConfirmed,
                &case_id.0,
                format!(
                    "{}\nFinding: {}\nSeverity: {}\nConfidence: {}",
                    fid,
                    c.title,
                    c.severity.label(),
                    c.confidence.label()
                ),
            ));
            renderer.finding_line(c.severity, c.confidence, &c.title, &c.method, &c.endpoint);
        }
    }

    renderer.handle(
        &ScanEvent::new(EventKind::PhaseProgress, &case_id.0, "done")
            .with_phase("verification", 100),
    );

    let resume = serde_json::json!({
        "target": url.to_string(),
        "mode": opts.mode_str(),
        "depth": depth,
        "endpoints": endpoints.len(),
    });
    db.set_resume_state(&case_id.0, &resume.to_string())?;

    if cancel.is_cancelled() {
        db.set_case_status(&case_id.0, "paused")?;
        eprintln!(
            "Interrupted. Resume with: sherlock case resume {}",
            case_id.0
        );
    } else {
        finish(&case_id, db, renderer)?;
    }

    while let Ok(ev) = rx.try_recv() {
        let _ = db.record_event(
            &case_for_ui,
            &format!("{:?}", ev.kind),
            &serde_json::to_string(&ev).unwrap_or_default(),
        );
    }
    Ok(case_id)
}

impl ScanOptions {
    fn mode_str(&self) -> &'static str {
        match self.mode {
            ScanMode::Passive => "passive",
            ScanMode::Safe => "safe",
            ScanMode::Full => "full",
            ScanMode::Api => "api",
        }
    }
}

fn finish(case_id: &CaseId, db: &Database, renderer: &mut Renderer) -> crate::Result<()> {
    db.set_case_status(&case_id.0, "closed")?;
    renderer.handle(&ScanEvent::new(
        EventKind::CaseClosed,
        &case_id.0,
        case_id.0.clone(),
    ));
    Ok(())
}

pub fn severity_counts(
    findings: &[crate::evidence::model::StoredFinding],
) -> (u32, u32, u32, u32, u32) {
    let mut c = (0, 0, 0, 0, 0);
    for f in findings {
        match f.severity {
            Severity::Critical => c.0 += 1,
            Severity::High => c.1 += 1,
            Severity::Medium => c.2 += 1,
            Severity::Low => c.3 += 1,
            Severity::Informational => c.4 += 1,
        }
    }
    c
}
