use crate::core::events::{EventKind, ScanEvent};

pub fn event(ev: &ScanEvent) {
    match ev.kind {
        EventKind::EndpointDiscovered => {
            println!(
                "[CLUE] {} {}",
                ev.method.as_deref().unwrap_or("GET"),
                ev.path.as_deref().unwrap_or(&ev.message)
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
        _ => {
            if !ev.message.is_empty() {
                println!("[*] {}", ev.message);
            }
        }
    }
}
