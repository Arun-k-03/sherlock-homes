use crossterm::{cursor, execute, terminal};
use std::io::{stdout, Write};

/// Restores cursor, raw mode, and alternate screen on drop / panic unwind.
pub struct TerminalGuard {
    raw: bool,
    hidden: bool,
    alt: bool,
}

impl TerminalGuard {
    pub fn enter(hide_cursor: bool) -> std::io::Result<Self> {
        let mut g = Self {
            raw: false,
            hidden: false,
            alt: false,
        };
        if hide_cursor {
            execute!(stdout(), cursor::Hide)?;
            g.hidden = true;
        }
        Ok(g)
    }

    /// Cinematic TUI lifecycle: raw mode, alternate screen, hidden cursor, one clear.
    pub fn enter_cinematic() -> std::io::Result<Self> {
        terminal::enable_raw_mode()?;
        execute!(
            stdout(),
            terminal::EnterAlternateScreen,
            cursor::Hide,
            terminal::Clear(terminal::ClearType::All)
        )?;
        stdout().flush()?;
        Ok(Self {
            raw: true,
            hidden: true,
            alt: true,
        })
    }

    pub fn restore(&mut self) {
        let mut out = stdout();
        if self.hidden {
            let _ = execute!(out, cursor::Show);
            self.hidden = false;
        }
        if self.alt {
            let _ = execute!(out, terminal::LeaveAlternateScreen);
            self.alt = false;
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
    w < 40 || h < 12
}
