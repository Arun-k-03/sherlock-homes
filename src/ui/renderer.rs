use crate::core::events::{EventKind, ScanEvent};
use crate::core::types::{Confidence, Severity};
use crate::ui::ascii;
use crate::ui::terminal;
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
    pub counters: Counters,
    clues: Vec<String>,
    pub phases: Phases,
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
        let mode = match mode {
            RenderMode::Cinematic if terminal::too_small_for_cinematic() => RenderMode::Classic,
            other => other,
        };
        Self {
            mode,
            color,
            ascii_only,
            counters: Counters::default(),
            clues: Vec::new(),
            phases: Phases::default(),
        }
    }

    pub fn banner(&self) {
        if self.mode == RenderMode::Machine {
            return;
        }
        let compact = self.mode == RenderMode::Minimal;
        gold(self.color, ascii::banner(self.ascii_only, compact));
        println!();
    }

    pub fn handle(&mut self, ev: &ScanEvent) {
        match ev.kind {
            EventKind::RequestSent | EventKind::ResponseReceived => self.counters.requests += 1,
            EventKind::FindingConfirmed | EventKind::PassiveFinding | EventKind::CandidateFound => {
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
            _ => {}
        }
        let ts = ev.timestamp.format("%H:%M:%S");
        let line = format!("{ts} {}", ev.message);
        self.clues.push(line);
        if self.clues.len() > 8 {
            self.clues.remove(0);
        }
        match self.mode {
            RenderMode::Machine => {}
            RenderMode::Minimal => crate::ui::minimal::event(ev),
            RenderMode::Classic => crate::ui::classic::event(ev, self.color),
            RenderMode::Cinematic => crate::ui::cinematic::draw(
                ev,
                &self.counters,
                &self.clues,
                &self.phases,
                self.color,
            ),
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
            RenderMode::Machine => {}
            RenderMode::Minimal => {
                println!(
                    "[{}] {title}\n{method} {path}\nConfidence: {}",
                    sev.label(),
                    conf.label()
                );
            }
            _ => {
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

pub fn bar(pct: u8, width: usize) -> String {
    let filled = ((pct as usize) * width) / 100;
    let mut s = String::new();
    for i in 0..width {
        if i < filled {
            s.push('#');
        } else {
            s.push('-');
        }
    }
    format!("{s} {pct:3}%")
}
