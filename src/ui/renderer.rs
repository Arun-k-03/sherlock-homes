use crate::core::events::{EventKind, ScanEvent};
use crate::core::types::{Confidence, Severity};
use crate::ui::ascii;
use crate::ui::cinematic::CinematicTui;
use crate::ui::theme::{color_level, ColorLevel};
use crossterm::style::{Color, ResetColor, SetForegroundColor};
use crossterm::{execute, style::Print};
use std::io::{stdout, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderMode {
    Minimal,
    Classic,
    Cinematic,
    Machine,
}

pub struct Renderer {
    pub mode: RenderMode,
    pub color: bool,
    pub ascii_only: bool,
    pub animations: bool,
    pub used_cinematic: bool,
    pub counters: Counters,
    pub phases: Phases,
    cinematic: Option<CinematicTui>,
}

#[derive(Debug, Default, Clone)]
pub struct Counters {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
    pub requests: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Phases {
    pub discovery: u8,
    pub observation: u8,
    pub investigation: u8,
    pub verification: u8,
}

impl Renderer {
    pub fn new(mode: RenderMode, color: bool, ascii_only: bool) -> Self {
        Self {
            mode,
            color,
            ascii_only,
            animations: true,
            used_cinematic: false,
            counters: Counters::default(),
            phases: Phases::default(),
            cinematic: None,
        }
    }

    pub fn arm_cinematic(&mut self, animations: bool) {
        self.animations = animations;
    }

    pub fn banner(&self) {
        if self.mode == RenderMode::Machine || self.mode == RenderMode::Cinematic {
            return;
        }
        let compact = self.mode == RenderMode::Minimal;
        gold(self.color, ascii::banner(self.ascii_only, compact));
        println!();
    }

    pub fn handle(&mut self, ev: &ScanEvent) {
        match ev.kind {
            EventKind::RequestSent => self.counters.requests += 1,
            EventKind::FindingConfirmed | EventKind::PassiveFinding => {
                if let Some(s) = &ev.severity {
                    match s.as_str() {
                        "critical" => self.counters.critical += 1,
                        "high" => self.counters.high += 1,
                        "medium" => self.counters.medium += 1,
                        "low" => self.counters.low += 1,
                        _ => self.counters.info += 1,
                    }
                }
            }
            EventKind::PhaseProgress => {
                if let (Some(p), Some(n)) = (&ev.phase, ev.progress) {
                    match p.as_str() {
                        "discovery" => self.phases.discovery = n,
                        "observation" => self.phases.observation = n,
                        "investigation" => self.phases.investigation = n,
                        "verification" => self.phases.verification = n,
                        _ => {}
                    }
                }
            }
            EventKind::DiscoveryCompleted => {
                self.phases.discovery = 100;
                self.phases.observation = 100;
            }
            EventKind::CaseClosed => {
                if self.phases.discovery > 0 {
                    self.phases.discovery = 100;
                }
                if self.phases.observation > 0 {
                    self.phases.observation = 100;
                }
                if self.phases.investigation > 0 {
                    self.phases.investigation = 100;
                }
                if self.phases.verification > 0 {
                    self.phases.verification = 100;
                }
            }
            _ => {}
        }

        match self.mode {
            RenderMode::Machine => {}
            RenderMode::Minimal => crate::ui::minimal::event(ev),
            RenderMode::Classic => crate::ui::classic::event(ev, self.color),
            RenderMode::Cinematic => self.handle_cinematic(ev),
        }
    }

    fn handle_cinematic(&mut self, ev: &ScanEvent) {
        if self.cinematic.is_none() {
            match CinematicTui::enter(self.ascii_only, self.color, self.animations) {
                Ok(ui) => {
                    self.cinematic = Some(ui);
                    self.used_cinematic = true;
                }
                Err(_) => {
                    self.mode = RenderMode::Classic;
                    crate::ui::classic::event(ev, self.color);
                    return;
                }
            }
        }
        if let Some(ui) = &mut self.cinematic {
            if !ev.case_id.is_empty() && ui.state.scan_mode.is_empty() {
                ui.state.scan_mode = "SAFE".into();
            }
            ui.apply(ev);
            let _ = ui.draw();
            if ev.kind == EventKind::CaseClosed {
                ui.shutdown();
            }
        }
    }

    pub fn leave_cinematic(&mut self) {
        if let Some(ui) = &mut self.cinematic {
            ui.shutdown();
        }
    }

    pub fn print_case_footer(&self, case_id: &str) {
        println!("Case file: {case_id}");
        if self.used_cinematic || self.mode == RenderMode::Cinematic {
            println!("Report:");
            println!("sherlock report {case_id} --format pdf,html");
        }
    }

    pub fn finding_line(
        &self,
        sev: Severity,
        conf: Confidence,
        title: &str,
        method: &str,
        path: &str,
    ) {
        match self.mode {
            RenderMode::Machine | RenderMode::Cinematic => {}
            RenderMode::Minimal => {
                println!(
                    "[{}] {title}\n{method} {path}\nConfidence: {}",
                    sev.label(),
                    conf.label()
                );
            }
            RenderMode::Classic => {
                println!();
                gold(self.color, "SUSPECT IDENTIFIED");
                println!("Technical Finding:");
                println!("  {title}");
                println!("Endpoint:");
                println!("  {method} {path}");
                println!("Confidence:");
                println!("  {}", conf.label());
            }
        }
    }
}

pub fn gold(color: bool, text: &str) {
    if color && color_level() != ColorLevel::None {
        let mut out = stdout();
        let _ = execute!(
            out,
            SetForegroundColor(Color::Yellow),
            Print(text),
            ResetColor
        );
        let _ = writeln!(out);
    } else {
        println!("{text}");
    }
}
