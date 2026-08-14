use crate::core::events::ScanEvent;
use crate::ui::renderer::{bar, gold, Counters};
use crossterm::{cursor, execute, terminal};
use std::io::{stdout, Write};

#[derive(Clone)]
pub struct PhaseView {
    pub discovery: u8,
    pub observation: u8,
    pub investigation: u8,
    pub verification: u8,
}

impl From<&super::renderer::Renderer> for PhaseView {
    fn from(_: &super::renderer::Renderer) -> Self {
        Self {
            discovery: 0,
            observation: 0,
            investigation: 0,
            verification: 0,
        }
    }
}

pub fn draw(
    ev: &ScanEvent,
    counters: &Counters,
    clues: &[String],
    phases: &super::renderer::Phases,
    color: bool,
) {
    let mut out = stdout();
    let _ = execute!(
        out,
        cursor::MoveTo(0, 0),
        terminal::Clear(terminal::ClearType::FromCursorDown)
    );
    let case = &ev.case_id;
    println!("+==================================================================+");
    gold(
        color,
        &format!("| SHERLOCK HOMES                         CASE {case:<16}|"),
    );
    println!("| CYBER INVESTIGATION ENGINE             SAFE INVESTIGATION      |");
    println!("+==================================================================+");
    println!("| PHASE                                                            |");
    println!("| Discovery      {} |", bar(phases.discovery, 20));
    println!("| Observation    {} |", bar(phases.observation, 20));
    println!("| Investigation  {} |", bar(phases.investigation, 20));
    println!("| Verification   {} |", bar(phases.verification, 20));
    println!("+==================================================================+");
    println!("| LIVE CLUES                                                       |");
    for c in clues
        .iter()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let trunc: String = c.chars().take(62).collect();
        println!("| {trunc:<64} |");
    }
    println!("+==================================================================+");
    println!(
        "| CRITICAL {}   HIGH {}   MEDIUM {}   LOW {}   REQUESTS {} |",
        counters.critical, counters.high, counters.medium, counters.low, counters.requests
    );
    println!("+==================================================================+");
    let _ = out.flush();
}

// expose Phases from renderer - we'll make it pub
