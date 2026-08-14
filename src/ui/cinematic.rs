//! Cinematic TUI: one dashboard, redrawn in place via ratatui.

use crate::core::events::{EventKind, ScanEvent};
use crate::ui::terminal::TerminalGuard;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph};
use ratatui::Terminal;
use std::collections::VecDeque;
use std::io::{stdout, Stdout};
use std::time::Duration;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub const CINEMATIC_MIN_WIDTH: u16 = 40;
pub const CINEMATIC_MIN_HEIGHT: u16 = 12;
pub const CINEMATIC_FULL_WIDTH: u16 = 72;
pub const CINEMATIC_FULL_HEIGHT: u16 = 24;
const DEFAULT_EVENT_CAP: usize = 8;

#[derive(Debug, Clone)]
pub struct CinematicState {
    pub case_id: String,
    pub target: String,
    pub scan_mode: String,
    pub discovery_progress: u8,
    pub observation_progress: u8,
    pub investigation_progress: u8,
    pub verification_progress: u8,
    pub discovery_started: bool,
    pub observation_started: bool,
    pub investigation_started: bool,
    pub verification_started: bool,
    pub endpoints_discovered: u32,
    pub parameters_discovered: u32,
    pub requests_sent: u32,
    pub responses_received: u32,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
    pub current_activity: String,
    pub recent_events: VecDeque<String>,
    pub scan_complete: bool,
    pub lens_step: u32,
    pub event_cap: usize,
}

impl Default for CinematicState {
    fn default() -> Self {
        Self {
            case_id: String::new(),
            target: String::new(),
            scan_mode: "SAFE".into(),
            discovery_progress: 0,
            observation_progress: 0,
            investigation_progress: 0,
            verification_progress: 0,
            discovery_started: false,
            observation_started: false,
            investigation_started: false,
            verification_started: false,
            endpoints_discovered: 0,
            parameters_discovered: 0,
            requests_sent: 0,
            responses_received: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            current_activity: "Opening the case...".into(),
            recent_events: VecDeque::new(),
            scan_complete: false,
            lens_step: 0,
            event_cap: DEFAULT_EVENT_CAP,
        }
    }
}

impl CinematicState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_event_capacity(&mut self, cap: usize) {
        self.event_cap = cap.max(1);
        while self.recent_events.len() > self.event_cap {
            self.recent_events.pop_front();
        }
    }

    pub fn apply(&mut self, ev: &ScanEvent) {
        if !ev.case_id.is_empty() {
            self.case_id = ev.case_id.clone();
        }
        match ev.kind {
            EventKind::CaseOpened => {
                let msg = normalize_event_text(&ev.message);
                if matches!(
                    msg.to_ascii_uppercase().as_str(),
                    "SAFE" | "PASSIVE" | "FULL" | "API"
                ) {
                    self.scan_mode = msg.to_ascii_uppercase();
                } else if self.target.is_empty() {
                    self.target = msg;
                }
                self.current_activity = "Case opened".into();
            }
            EventKind::TargetValidated => {
                self.target = normalize_event_text(&ev.message);
                self.current_activity = "Scene validated".into();
            }
            EventKind::HostResolved => {
                self.current_activity =
                    format!("Host resolved: {}", normalize_event_text(&ev.message));
            }
            EventKind::DiscoveryStarted => {
                self.discovery_started = true;
                self.discovery_progress = 0;
                self.current_activity = "Discovery started".into();
            }
            EventKind::DiscoveryCompleted => {
                self.discovery_started = true;
                self.observation_started = true;
                self.discovery_progress = 100;
                self.observation_progress = 100;
                self.current_activity = "Discovery complete".into();
            }
            EventKind::PageDiscovered => {
                self.discovery_started = true;
                self.bump_discovery();
                self.tick_lens();
                self.current_activity =
                    format!("Page {}", ev.path.as_deref().unwrap_or(&ev.message));
            }
            EventKind::EndpointDiscovered => {
                self.discovery_started = true;
                self.endpoints_discovered = self.endpoints_discovered.saturating_add(1);
                self.bump_discovery();
                self.current_activity = format!(
                    "Clue {}",
                    crate::core::events::format_endpoint_label(
                        ev.method.as_deref(),
                        ev.path.as_deref(),
                        &ev.message
                    )
                );
            }
            EventKind::ParameterDiscovered => {
                self.parameters_discovered = self.parameters_discovered.saturating_add(1);
            }
            EventKind::RequestSent => {
                self.requests_sent = self.requests_sent.saturating_add(1);
                self.tick_lens();
                self.current_activity = format!(
                    "Trace {}",
                    crate::core::events::format_endpoint_label(
                        ev.method.as_deref(),
                        ev.path.as_deref(),
                        &ev.message
                    )
                );
            }
            EventKind::ResponseReceived => {
                self.responses_received = self.responses_received.saturating_add(1);
            }
            EventKind::PhaseProgress => {
                if let (Some(phase), Some(n)) = (ev.phase.as_deref(), ev.progress) {
                    match phase {
                        "discovery" => {
                            self.discovery_started = true;
                            self.discovery_progress = n;
                        }
                        "observation" => {
                            self.observation_started = true;
                            self.observation_progress = n;
                        }
                        "investigation" => {
                            self.investigation_started = true;
                            self.investigation_progress = n;
                        }
                        "verification" => {
                            self.verification_started = true;
                            self.verification_progress = n;
                        }
                        _ => {}
                    }
                }
                return;
            }
            EventKind::CandidateFound | EventKind::PassiveFinding => {
                self.current_activity = format!("Suspect: {}", normalize_event_text(&ev.message));
            }
            EventKind::VerificationStarted | EventKind::Deduction => {
                self.verification_started = true;
                if self.verification_progress < 40 {
                    self.verification_progress = 40;
                }
                self.current_activity = "Verifying evidence...".into();
            }
            EventKind::FindingConfirmed => {
                self.count_severity(ev.severity.as_deref());
                self.current_activity =
                    format!("Finding {}", ev.finding_id.as_deref().unwrap_or(""));
            }
            EventKind::FindingRejected => {
                self.current_activity = "Suspect cleared".into();
            }
            EventKind::Warning => {
                self.current_activity = normalize_event_text(&ev.message);
            }
            EventKind::CaseClosed => {
                self.scan_complete = true;
                self.finalize_phases();
                self.current_activity = "Case closed".into();
            }
            _ => {}
        }
        let line = format_clue_line(ev);
        self.push_clue(line);
    }

    fn bump_discovery(&mut self) {
        if self.scan_complete {
            return;
        }
        if self.discovery_progress < 90 {
            self.discovery_progress = (self.discovery_progress.saturating_add(4)).min(90);
        }
    }

    fn tick_lens(&mut self) {
        self.lens_step = self.lens_step.wrapping_add(1);
    }

    fn count_severity(&mut self, sev: Option<&str>) {
        match sev.unwrap_or("informational") {
            "critical" => self.critical = self.critical.saturating_add(1),
            "high" => self.high = self.high.saturating_add(1),
            "medium" => self.medium = self.medium.saturating_add(1),
            "low" => self.low = self.low.saturating_add(1),
            _ => self.info = self.info.saturating_add(1),
        }
    }

    pub fn finalize_phases(&mut self) {
        if self.discovery_started {
            self.discovery_progress = 100;
        }
        if self.observation_started || self.discovery_started {
            self.observation_started = true;
            self.observation_progress = 100;
        }
        if self.investigation_started {
            self.investigation_progress = 100;
        }
        if self.verification_started || self.investigation_started {
            self.verification_started = true;
            self.verification_progress = 100;
        }
        if self.discovery_started && self.investigation_started {
            self.discovery_progress = 100;
            self.observation_progress = 100;
            self.investigation_progress = 100;
            self.verification_progress = 100;
        }
    }

    fn push_clue(&mut self, line: String) {
        if line.is_empty() {
            return;
        }
        self.recent_events.push_back(line);
        while self.recent_events.len() > self.event_cap {
            self.recent_events.pop_front();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutMetrics {
    pub compact: bool,
    pub too_small: bool,
    pub clue_capacity: usize,
    pub inner_text_width: usize,
}

pub fn layout_metrics(width: u16, height: u16) -> LayoutMetrics {
    let too_small = width < CINEMATIC_MIN_WIDTH || height < CINEMATIC_MIN_HEIGHT;
    let compact = width < CINEMATIC_FULL_WIDTH || height < CINEMATIC_FULL_HEIGHT;
    LayoutMetrics {
        compact,
        too_small,
        clue_capacity: clue_capacity(height, compact),
        inner_text_width: width.saturating_sub(4) as usize,
    }
}

pub fn clue_capacity(height: u16, compact: bool) -> usize {
    let reserved = if compact { 14 } else { 20 };
    height.saturating_sub(reserved).max(2) as usize
}

pub fn normalize_event_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_space = false;
    for c in input.chars() {
        let mapped = match c {
            '\r' | '\n' | '\t' => ' ',
            c if c.is_control() => continue,
            c => c,
        };
        if mapped.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            prev_space = false;
            out.push(mapped);
        }
    }
    out.trim().to_string()
}

pub fn truncate_to_width(s: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if s.width() <= width {
        return s.to_string();
    }
    let mut acc = 0usize;
    let mut out = String::new();
    for c in s.chars() {
        let w = c.width().unwrap_or(1);
        if acc + w > width {
            break;
        }
        acc += w;
        out.push(c);
    }
    out
}

pub fn format_clue_line(ev: &ScanEvent) -> String {
    let ts = ev.timestamp.format("%H:%M:%S");
    let kind = clue_kind_label(ev.kind);
    let body = match ev.kind {
        EventKind::FindingConfirmed => {
            let id = ev.finding_id.as_deref().unwrap_or("-");
            let title = normalize_event_text(&ev.message);
            let sev = ev
                .severity
                .as_deref()
                .unwrap_or("info")
                .to_ascii_uppercase();
            format!("{id}  {title}  {sev}")
        }
        EventKind::CandidateFound | EventKind::PassiveFinding => {
            let title = normalize_event_text(&ev.message);
            let sev = ev
                .severity
                .as_deref()
                .unwrap_or("info")
                .to_ascii_uppercase();
            format!("{title}  {sev}")
        }
        EventKind::EndpointDiscovered | EventKind::PageDiscovered | EventKind::RequestSent => {
            crate::core::events::format_endpoint_label(
                ev.method.as_deref(),
                ev.path.as_deref(),
                &ev.message,
            )
        }
        EventKind::PhaseProgress => String::new(),
        _ => normalize_event_text(&ev.message),
    };
    let line = if body.is_empty() {
        format!("{ts}  {kind}")
    } else {
        format!("{ts}  {kind}  {body}")
    };
    normalize_event_text(&line)
}

fn clue_kind_label(kind: EventKind) -> &'static str {
    match kind {
        EventKind::FindingConfirmed => "FINDING",
        EventKind::CandidateFound | EventKind::PassiveFinding => "SUSPECT",
        EventKind::EndpointDiscovered => "CLUE",
        EventKind::PageDiscovered => "PAGE",
        EventKind::RequestSent => "TRACE",
        EventKind::ResponseReceived => "EVIDENCE",
        EventKind::VerificationStarted | EventKind::Deduction => "VERIFY",
        EventKind::Warning => "WARN",
        EventKind::CaseOpened => "CASE",
        EventKind::CaseClosed => "CLOSED",
        EventKind::DiscoveryStarted => "DISCOVER",
        EventKind::DiscoveryCompleted => "MAPPED",
        EventKind::HostResolved => "HOST",
        EventKind::TargetValidated => "SCENE",
        EventKind::ParameterDiscovered => "PARAM",
        _ => "NOTE",
    }
}

pub fn phase_label(pct: u8, complete: bool) -> String {
    if complete && pct >= 100 {
        "DONE".into()
    } else {
        format!("{pct:3}%")
    }
}

pub fn lens_line(step: u32, width: usize) -> String {
    let w = width.clamp(12, 64);
    let span = w.saturating_sub(3);
    if span == 0 {
        return "[o]".into();
    }
    let pos = (step as usize) % span;
    let glyph = match step % 11 {
        10 => "[!]",
        x if x % 4 == 0 => "[O]",
        _ => "[o]",
    };
    let mut line = String::new();
    for x in 0..span {
        if x == pos {
            line.push_str(glyph);
        } else {
            line.push('-');
        }
    }
    line.push('>');
    line
}

pub struct CinematicTui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    pub state: CinematicState,
    guard: TerminalGuard,
    ascii_only: bool,
    color: bool,
    animations: bool,
    restored: bool,
}

impl CinematicTui {
    pub fn enter(ascii_only: bool, color: bool, animations: bool) -> std::io::Result<Self> {
        let guard = TerminalGuard::enter_cinematic()?;
        let backend = CrosstermBackend::new(stdout());
        let mut terminal = Terminal::new(backend)?;
        terminal.clear()?;
        Ok(Self {
            terminal,
            state: CinematicState::new(),
            guard,
            ascii_only,
            color,
            animations,
            restored: false,
        })
    }

    pub fn apply(&mut self, ev: &ScanEvent) {
        self.poll_terminal();
        let (w, h) = self
            .terminal
            .size()
            .map(|s| (s.width, s.height))
            .unwrap_or((80, 24));
        let metrics = layout_metrics(w, h);
        self.state.set_event_capacity(metrics.clue_capacity);
        self.state.apply(ev);
    }

    pub fn draw(&mut self) -> std::io::Result<()> {
        self.poll_terminal();
        let ascii = self.ascii_only;
        let color = self.color;
        let animations = self.animations;
        let state = self.state.clone();
        self.terminal.draw(|f| {
            render_dashboard(f, &state, ascii, color, animations);
        })?;
        Ok(())
    }

    fn poll_terminal(&mut self) {
        while event::poll(Duration::from_millis(0)).unwrap_or(false) {
            match event::read() {
                Ok(Event::Resize(_, _)) => {}
                Ok(Event::Key(k))
                    if k.code == KeyCode::Char('c')
                        && k.modifiers.contains(KeyModifiers::CONTROL) => {}
                _ => {}
            }
        }
    }

    pub fn shutdown(&mut self) {
        if self.restored {
            return;
        }
        let _ = self.draw();
        let _ = self.terminal.show_cursor();
        self.guard.restore();
        self.restored = true;
    }
}

impl Drop for CinematicTui {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn render_dashboard(
    f: &mut ratatui::Frame<'_>,
    state: &CinematicState,
    ascii_only: bool,
    color: bool,
    animations: bool,
) {
    let area = f.area();
    let metrics = layout_metrics(area.width, area.height);
    if metrics.too_small {
        let msg = Paragraph::new("Terminal too small for cinematic view.");
        f.render_widget(msg, area);
        return;
    }

    let gold = if color {
        Style::default()
            .fg(Color::Rgb(201, 162, 39))
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::BOLD)
    };
    let borders = border_set(ascii_only);

    let chunks = if metrics.compact {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),
                Constraint::Length(5),
                Constraint::Min(4),
                Constraint::Length(3),
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),
                Constraint::Length(3),
                Constraint::Length(6),
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(3),
            ])
            .split(area)
    };

    let header_block = Block::default()
        .borders(Borders::ALL)
        .border_set(borders)
        .title(" SHERLOCK HOMES ")
        .title_style(gold)
        .style(Style::default());
    let mode = if state.scan_mode.is_empty() {
        "SAFE"
    } else {
        state.scan_mode.as_str()
    };
    let header_text = vec![
        Line::from(Span::styled("CYBER INVESTIGATION ENGINE", gold)),
        Line::from(format!(
            "CASE {:<16}  {} INVESTIGATION",
            truncate_to_width(&state.case_id, 16),
            mode
        )),
    ];
    f.render_widget(Paragraph::new(header_text).block(header_block), chunks[0]);

    if metrics.compact {
        render_phases(f, chunks[1], state, ascii_only, color, borders, gold);
        render_clues(f, chunks[2], state, metrics.inner_text_width, borders, gold);
        render_footer(f, chunks[3], state, borders, gold);
        return;
    }

    let target_block = Block::default()
        .borders(Borders::ALL)
        .border_set(borders)
        .title(" TARGET ");
    let target = truncate_to_width(&state.target, metrics.inner_text_width);
    f.render_widget(Paragraph::new(target).block(target_block), chunks[1]);

    render_phases(f, chunks[2], state, ascii_only, color, borders, gold);

    let lens_block = Block::default()
        .borders(Borders::ALL)
        .border_set(borders)
        .title(" LENS ");
    let lens = if animations {
        lens_line(state.lens_step, metrics.inner_text_width.saturating_sub(2))
    } else {
        "[o]-------------------->".into()
    };
    f.render_widget(Paragraph::new(lens).block(lens_block), chunks[3]);

    render_clues(f, chunks[4], state, metrics.inner_text_width, borders, gold);
    render_footer(f, chunks[5], state, borders, gold);
}

fn render_phases(
    f: &mut ratatui::Frame<'_>,
    area: Rect,
    state: &CinematicState,
    _ascii_only: bool,
    color: bool,
    borders: border::Set,
    gold: Style,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(borders)
        .title(" PHASE ")
        .title_style(gold);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);
    let teal = if color {
        Style::default().fg(Color::Rgb(70, 130, 130))
    } else {
        Style::default()
    };
    let done = state.scan_complete;
    draw_phase(
        f,
        rows[0],
        "Discovery",
        state.discovery_progress,
        done && state.discovery_started,
        teal,
    );
    draw_phase(
        f,
        rows[1],
        "Observation",
        state.observation_progress,
        done && (state.observation_started || state.discovery_started),
        teal,
    );
    draw_phase(
        f,
        rows[2],
        "Investigation",
        state.investigation_progress,
        done && state.investigation_started,
        teal,
    );
    draw_phase(
        f,
        rows[3],
        "Verification",
        state.verification_progress,
        done && (state.verification_started || state.investigation_started),
        teal,
    );
}

fn draw_phase(
    f: &mut ratatui::Frame<'_>,
    area: Rect,
    name: &str,
    pct: u8,
    done: bool,
    style: Style,
) {
    let label = format!("{name:<14} {}", phase_label(pct, done));
    let gauge = Gauge::default()
        .gauge_style(style)
        .percent(u16::from(pct.min(100)))
        .label(label);
    f.render_widget(gauge, area);
}

fn render_clues(
    f: &mut ratatui::Frame<'_>,
    area: Rect,
    state: &CinematicState,
    inner_width: usize,
    borders: border::Set,
    gold: Style,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(borders)
        .title(" LIVE CLUES ")
        .title_style(gold);
    let lines: Vec<Line> = state
        .recent_events
        .iter()
        .map(|e| Line::from(truncate_to_width(e, inner_width)))
        .collect();
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_footer(
    f: &mut ratatui::Frame<'_>,
    area: Rect,
    state: &CinematicState,
    borders: border::Set,
    gold: Style,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(borders)
        .title_style(gold);
    let text = format!(
        "CRITICAL {}   HIGH {}   MEDIUM {}   LOW {}   INFO {}   REQUESTS {}",
        state.critical, state.high, state.medium, state.low, state.info, state.requests_sent
    );
    f.render_widget(Paragraph::new(text).block(block), area);
}

fn border_set(ascii_only: bool) -> border::Set {
    if ascii_only {
        border::Set {
            top_left: "+",
            top_right: "+",
            bottom_left: "+",
            bottom_right: "+",
            vertical_left: "|",
            vertical_right: "|",
            horizontal_top: "-",
            horizontal_bottom: "-",
        }
    } else {
        border::PLAIN
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ev(kind: EventKind, msg: &str) -> ScanEvent {
        let mut e = ScanEvent::new(kind, "SH-260814-A7F2", msg);
        e.timestamp = chrono::Utc
            .with_ymd_and_hms(2026, 8, 14, 8, 25, 46)
            .unwrap();
        e
    }

    #[test]
    fn multiline_event_normalization() {
        let raw = "SH-F-0018\nFinding: Server banner disclosure\nSeverity:\tLOW";
        let n = normalize_event_text(raw);
        assert!(!n.contains('\n'));
        assert!(!n.contains('\t'));
        assert!(!n.contains('\r'));
        assert!(!n.contains("  "));
        assert_eq!(
            n,
            "SH-F-0018 Finding: Server banner disclosure Severity: LOW"
        );
    }

    #[test]
    fn width_truncation() {
        let s = "abcdefghij";
        assert_eq!(truncate_to_width(s, 4), "abcd");
        assert_eq!(truncate_to_width(s, 80), s);
        assert_eq!(truncate_to_width(s, 0), "");
    }

    #[test]
    fn finding_clue_is_single_line() {
        let mut e = ev(EventKind::FindingConfirmed, "Server banner disclosure");
        e.finding_id = Some("SH-F-0018".into());
        e.severity = Some("low".into());
        let line = format_clue_line(&e);
        assert_eq!(line.matches('\n').count(), 0);
        assert!(line.contains("FINDING"));
        assert!(line.contains("SH-F-0018"));
        assert!(line.contains("Server banner disclosure"));
        assert!(line.contains("LOW"));
        assert!(line.starts_with("08:25:46"));
    }

    #[test]
    fn request_counter_from_request_sent_only() {
        let mut s = CinematicState::new();
        s.apply(&ev(EventKind::ResponseReceived, "200"));
        assert_eq!(s.requests_sent, 0);
        assert_eq!(s.responses_received, 1);
        s.apply(&ev(EventKind::RequestSent, "GET /").with_endpoint("GET", "/"));
        s.apply(&ev(EventKind::RequestSent, "GET /login").with_endpoint("GET", "/login"));
        assert_eq!(s.requests_sent, 2);
        assert_eq!(s.responses_received, 1);
    }

    #[test]
    fn clue_line_does_not_repeat_http_method() {
        let mut e = ev(EventKind::EndpointDiscovered, "GET /search");
        e.method = Some("GET".into());
        e.path = None;
        let line = format_clue_line(&e);
        assert!(line.contains("GET /search"));
        assert!(!line.contains("GET GET"));
        let mut e2 = ev(EventKind::EndpointDiscovered, "POST /api/login");
        e2.method = Some("GET".into());
        e2.path = Some("POST /api/login".into());
        let line2 = format_clue_line(&e2);
        assert!(line2.contains("POST /api/login"));
        assert!(!line2.contains("GET POST"));
    }

    #[test]
    fn phase_transitions_and_case_closed() {
        let mut s = CinematicState::new();
        s.apply(&ev(EventKind::DiscoveryStarted, "start"));
        assert_eq!(s.discovery_progress, 0);
        s.apply(&ev(EventKind::EndpointDiscovered, "GET /").with_endpoint("GET", "/"));
        assert!(s.discovery_progress > 0 && s.discovery_progress < 100);
        s.apply(&ev(EventKind::DiscoveryCompleted, "done"));
        assert_eq!(s.discovery_progress, 100);
        assert_eq!(s.observation_progress, 100);
        s.apply(&ev(EventKind::PhaseProgress, "investigation").with_phase("investigation", 85));
        assert_eq!(s.investigation_progress, 85);
        s.apply(&ev(EventKind::CaseClosed, "SH-260814-A7F2"));
        assert!(s.scan_complete);
        assert_eq!(s.discovery_progress, 100);
        assert_eq!(s.observation_progress, 100);
        assert_eq!(s.investigation_progress, 100);
        assert_eq!(s.verification_progress, 100);
        assert_eq!(phase_label(s.discovery_progress, true), "DONE");
    }

    #[test]
    fn recent_event_buffer_is_bounded() {
        let mut s = CinematicState::new();
        s.set_event_capacity(3);
        for i in 0..10 {
            s.apply(&ev(EventKind::Clue, &format!("event-{i}")));
        }
        assert_eq!(s.recent_events.len(), 3);
        assert!(s.recent_events.front().unwrap().contains("event-7"));
        assert!(s.recent_events.back().unwrap().contains("event-9"));
    }

    #[test]
    fn resize_safe_layout_metrics() {
        let full = layout_metrics(100, 40);
        assert!(!full.compact);
        assert!(!full.too_small);
        assert!(full.clue_capacity >= 5);

        let compact = layout_metrics(60, 20);
        assert!(compact.compact);
        assert!(!compact.too_small);

        let tiny = layout_metrics(20, 8);
        assert!(tiny.too_small);

        let a = clue_capacity(40, false);
        let b = clue_capacity(24, false);
        assert!(a >= b);
    }
}
