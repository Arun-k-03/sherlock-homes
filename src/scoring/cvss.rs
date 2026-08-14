//! CVSS 4.0-inspired scoring. Values are computed from explicit metrics only.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssVector {
    pub version: String,
    pub vector: String,
    pub score: Option<f64>,
}

/// Very small CVSS 4.0 Base-like calculator using a documented subset of metrics.
/// Returns None if metrics are incomplete — we never invent scores.
#[derive(Debug, Clone)]
pub struct CvssMetrics {
    pub av: Av,
    pub ac: Ac,
    pub at: At,
    pub pr: Pr,
    pub ui: Ui,
    pub vc: Impact,
    pub vi: Impact,
    pub va: Impact,
}

#[derive(Debug, Clone, Copy)]
pub enum Av {
    Network,
    Adjacent,
    Local,
    Physical,
}
#[derive(Debug, Clone, Copy)]
pub enum Ac {
    Low,
    High,
}
#[derive(Debug, Clone, Copy)]
pub enum At {
    None,
    Present,
}
#[derive(Debug, Clone, Copy)]
pub enum Pr {
    None,
    Low,
    High,
}
#[derive(Debug, Clone, Copy)]
pub enum Ui {
    None,
    Passive,
    Active,
}
#[derive(Debug, Clone, Copy)]
pub enum Impact {
    High,
    Low,
    None,
}

fn av_w(v: Av) -> f64 {
    match v {
        Av::Network => 0.0,
        Av::Adjacent => 0.1,
        Av::Local => 0.2,
        Av::Physical => 0.3,
    }
}
fn ac_w(v: Ac) -> f64 {
    match v {
        Ac::Low => 0.0,
        Ac::High => 0.1,
    }
}
fn pr_w(v: Pr) -> f64 {
    match v {
        Pr::None => 0.0,
        Pr::Low => 0.1,
        Pr::High => 0.2,
    }
}
fn ui_w(v: Ui) -> f64 {
    match v {
        Ui::None => 0.0,
        Ui::Passive => 0.05,
        Ui::Active => 0.15,
    }
}
fn imp(v: Impact) -> f64 {
    match v {
        Impact::High => 0.56,
        Impact::Low => 0.22,
        Impact::None => 0.0,
    }
}

pub fn score_from_metrics(m: &CvssMetrics) -> CvssVector {
    let isc = 1.0 - ((1.0 - imp(m.vc)) * (1.0 - imp(m.vi)) * (1.0 - imp(m.va)));
    let mut score = isc * 10.0;
    score *= 1.0 - av_w(m.av);
    score *= 1.0 - ac_w(m.ac);
    score *= 1.0 - pr_w(m.pr);
    score *= 1.0 - ui_w(m.ui);
    if matches!(m.at, At::Present) {
        score *= 0.9;
    }
    score = (score * 10.0).round() / 10.0;
    score = score.clamp(0.0, 10.0);
    let vector = format!(
        "CVSS:4.0/AV:{}/AC:{}/AT:{}/PR:{}/UI:{}/VC:{}/VI:{}/VA:{}",
        av_s(m.av),
        ac_s(m.ac),
        at_s(m.at),
        pr_s(m.pr),
        ui_s(m.ui),
        imp_s(m.vc),
        imp_s(m.vi),
        imp_s(m.va),
    );
    CvssVector {
        version: "4.0".into(),
        vector,
        score: Some(score),
    }
}

fn av_s(v: Av) -> &'static str {
    match v {
        Av::Network => "N",
        Av::Adjacent => "A",
        Av::Local => "L",
        Av::Physical => "P",
    }
}
fn ac_s(v: Ac) -> &'static str {
    match v {
        Ac::Low => "L",
        Ac::High => "H",
    }
}
fn at_s(v: At) -> &'static str {
    match v {
        At::None => "N",
        At::Present => "P",
    }
}
fn pr_s(v: Pr) -> &'static str {
    match v {
        Pr::None => "N",
        Pr::Low => "L",
        Pr::High => "H",
    }
}
fn ui_s(v: Ui) -> &'static str {
    match v {
        Ui::None => "N",
        Ui::Passive => "P",
        Ui::Active => "A",
    }
}
fn imp_s(v: Impact) -> &'static str {
    match v {
        Impact::High => "H",
        Impact::Low => "L",
        Impact::None => "N",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_high_impact_is_elevated() {
        let v = score_from_metrics(&CvssMetrics {
            av: Av::Network,
            ac: Ac::Low,
            at: At::None,
            pr: Pr::None,
            ui: Ui::None,
            vc: Impact::High,
            vi: Impact::Low,
            va: Impact::None,
        });
        assert!(v.score.unwrap() >= 6.0);
        assert!(v.vector.starts_with("CVSS:4.0/"));
    }
}
