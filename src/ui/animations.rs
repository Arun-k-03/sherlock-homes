use crossterm::{cursor, execute, style::Print, terminal};
use std::io::{stdout, Write};
use std::time::Duration;

pub fn enabled(no_animation: bool, reduced: bool, machine: bool) -> bool {
    if machine || no_animation {
        return false;
    }
    if reduced {
        return false;
    }
    true
}

pub async fn lens_sweep(
    width: usize,
    frames: u32,
    delay_ms: u64,
    cancel: &tokio_util::sync::CancellationToken,
) {
    let w = width.clamp(20, 70);
    let mut out = stdout();
    let _ = execute!(out, cursor::Hide);
    for i in 0..=frames {
        if cancel.is_cancelled() {
            break;
        }
        let pos = ((i as usize) * (w.saturating_sub(6))) / frames.max(1) as usize;
        let ch = if i == frames {
            "[!]"
        } else if i % 7 == 0 {
            "[O]"
        } else {
            "[o]"
        };
        let mut line = String::from("    ");
        for x in 0..w {
            if x == pos {
                line.push_str(ch);
            } else {
                line.push('-');
            }
        }
        line.push('>');
        let _ = execute!(
            out,
            cursor::SavePosition,
            terminal::Clear(terminal::ClearType::CurrentLine),
            Print(&line),
            cursor::RestorePosition
        );
        let _ = out.flush();
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
            _ = cancel.cancelled() => break,
        }
    }
    let _ = execute!(
        out,
        terminal::Clear(terminal::ClearType::CurrentLine),
        cursor::Show
    );
    let _ = writeln!(out);
}

pub async fn packet_trace(
    frames: u32,
    delay_ms: u64,
    cancel: &tokio_util::sync::CancellationToken,
) {
    let mut out = stdout();
    let width = 54usize;
    let _ = execute!(out, cursor::Hide);
    for i in 0..=frames {
        if cancel.is_cancelled() {
            break;
        }
        let pos = ((i as usize) * (width.saturating_sub(4))) / frames.max(1) as usize;
        let mut line = String::from("|");
        for x in 0..width {
            if x == pos {
                line.push_str("[>]");
            } else {
                line.push('-');
            }
        }
        line.push('|');
        let _ = execute!(
            out,
            cursor::SavePosition,
            terminal::Clear(terminal::ClearType::CurrentLine),
            Print(&line),
            cursor::RestorePosition
        );
        let _ = out.flush();
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
            _ = cancel.cancelled() => break,
        }
    }
    let _ = execute!(
        out,
        terminal::Clear(terminal::ClearType::CurrentLine),
        cursor::Show
    );
    let _ = writeln!(out);
}

pub async fn deduction_dots(cancel: &tokio_util::sync::CancellationToken) {
    let mut out = stdout();
    for n in 1..=3 {
        if cancel.is_cancelled() {
            break;
        }
        let msg = format!("    DEDUCING {}", ".".repeat(n));
        let _ = execute!(
            out,
            cursor::SavePosition,
            terminal::Clear(terminal::ClearType::CurrentLine),
            Print(&msg),
            cursor::RestorePosition
        );
        let _ = out.flush();
        tokio::time::sleep(Duration::from_millis(180)).await;
    }
    let _ = execute!(out, terminal::Clear(terminal::ClearType::CurrentLine));
    let _ = writeln!(out, "    [!] ANOMALY DETECTED");
}

pub fn verdict_box(serious: bool) {
    if serious {
        println!(
            r#"
##########################################################
#                                                        #
#                 EVIDENCE CONFIRMED                     #
#                                                        #
##########################################################
"#
        );
    } else {
        println!(
            r#"
+--------------------+
| VERDICT REACHED    |
+--------------------+
"#
        );
    }
}

pub fn magnifying_glass() -> &'static str {
    r#"
           .------------.
         .'              '.
        /        +         \
       |                    |
        \                  /
         '.              .'
           '------------'
                \
                 \
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_mode_disables() {
        assert!(!enabled(false, false, true));
        assert!(enabled(false, false, false));
    }
}
