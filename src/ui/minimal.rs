use crate::core::events::{format_endpoint_label, EventKind, ScanEvent};

pub fn event(ev: &ScanEvent) {
    match ev.kind {
        EventKind::EndpointDiscovered => {
            println!(
                "[CLUE] {}",
                format_endpoint_label(ev.method.as_deref(), ev.path.as_deref(), &ev.message)
            );
        }
        EventKind::CandidateFound | EventKind::PassiveFinding => {
            println!(
                "[{}] {}",
                ev.severity.as_deref().unwrap_or("INFO").to_uppercase(),
                ev.message
            );
        }
        EventKind::FindingConfirmed => println!("[EVIDENCE CONFIRMED] {}", ev.message),
        EventKind::CaseOpened => println!("[CASE OPENED] {}", ev.message),
        EventKind::CaseClosed => println!("[CASE CLOSED] {}", ev.message),
        EventKind::Warning => eprintln!("[WARN] {}", ev.message),
        EventKind::RequestSent
        | EventKind::ResponseReceived
        | EventKind::PageDiscovered
        | EventKind::PhaseProgress => {}
        _ => {
            if !ev.message.is_empty() {
                println!("[*] {}", ev.message);
            }
        }
    }
}
