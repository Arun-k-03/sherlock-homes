use crossterm::{cursor, execute, terminal};
use std::io::{stdout, Write};

/// Restores cursor and terminal on drop / panic unwind.
pub struct TerminalGuard {
    raw: bool,
    hidden: bool,
}

impl TerminalGuard {
    pub fn enter(hide_cursor: bool) -> std::io::Result<Self> {
        let mut g = Self {
            raw: false,
            hidden: false,
        };
        if hide_cursor {
            execute!(stdout(), cursor::Hide)?;
            g.hidden = true;
        }
        Ok(g)
    }

    pub fn restore(&mut self) {
        let mut out = stdout();
        if self.hidden {
            let _ = execute!(out, cursor::Show);
            self.hidden = false;
        }
        if self.raw {
            let _ = terminal::disable_raw_mode();
            self.raw = false;
        }
        let _ = out.flush();
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

pub fn size() -> (u16, u16) {
    terminal::size().unwrap_or((80, 24))
}

pub fn too_small_for_cinematic() -> bool {
    let (w, h) = size();
    w < 72 || h < 24
}
