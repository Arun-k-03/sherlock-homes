use crate::core::events::{EventKind, ScanEvent};
use crate::ui::renderer::gold;

pub fn event(ev: &ScanEvent, color: bool) {
    match ev.kind {
        EventKind::CaseOpened => {
            gold(color, "[CASE OPENED]");
            println!("{}", ev.message);
        }
        EventKind::TargetValidated => println!("[+] Scene validated: {}", ev.message),
        EventKind::HostResolved => println!("[+] Host resolved: {}", ev.message),
        EventKind::PageDiscovered => println!("[+] Page: {}", ev.message),
        EventKind::EndpointDiscovered => {
            println!(
                "[CLUE] {}",
                crate::core::events::format_endpoint_label(
                    ev.method.as_deref(),
                    ev.path.as_deref(),
                    &ev.message
                )
            );
        }
        EventKind::ParameterDiscovered => println!("    PARAM  {}", ev.message),
        EventKind::CandidateFound => {
            gold(color, "[SUSPECT]");
            println!("{}", ev.message);
        }
        EventKind::PassiveFinding => println!("[SUSPECT] {}", ev.message),
        EventKind::VerificationStarted => println!("[?] Verifying evidence..."),
        EventKind::FindingConfirmed => {
            gold(color, "[EVIDENCE CONFIRMED]");
            println!("{}", ev.message);
        }
        EventKind::FindingRejected => println!("[-] Suspect cleared: {}", ev.message),
        EventKind::CaseClosed => gold(color, "[CASE CLOSED]"),
        EventKind::Deduction => println!("[?] Deducing... {}", ev.message),
        EventKind::Clue => println!("[CLUE] {}", ev.message),
        EventKind::Warning => eprintln!("[!] {}", ev.message),
        _ => {}
    }
}
