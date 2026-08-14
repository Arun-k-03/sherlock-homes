use crossterm::style::Color;

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub gold: Color,
    pub white: Color,
    pub gray: Color,
    pub teal: Color,
    pub emerald: Color,
    pub amber: Color,
    pub orange: Color,
    pub crimson: Color,
}

impl Theme {
    pub fn victorian() -> Self {
        Self {
            gold: Color::Rgb {
                r: 201,
                g: 162,
                b: 39,
            },
            white: Color::Rgb {
                r: 245,
                g: 240,
                b: 230,
            },
            gray: Color::Rgb {
                r: 120,
                g: 118,
                b: 110,
            },
            teal: Color::Rgb {
                r: 70,
                g: 130,
                b: 130,
            },
            emerald: Color::Rgb {
                r: 46,
                g: 139,
                b: 87,
            },
            amber: Color::Rgb {
                r: 201,
                g: 148,
                b: 50,
            },
            orange: Color::Rgb {
                r: 196,
                g: 90,
                b: 40,
            },
            crimson: Color::Rgb {
                r: 153,
                g: 27,
                b: 27,
            },
        }
    }

    pub fn ansi16() -> Self {
        Self {
            gold: Color::Yellow,
            white: Color::White,
            gray: Color::DarkGrey,
            teal: Color::Cyan,
            emerald: Color::Green,
            amber: Color::Yellow,
            orange: Color::Red,
            crimson: Color::DarkRed,
        }
    }
}

pub fn color_level() -> ColorLevel {
    if std::env::var("NO_COLOR").is_ok() {
        return ColorLevel::None;
    }
    if std::env::var("TERM").unwrap_or_default() == "dumb" {
        return ColorLevel::None;
    }
    if std::env::var("COLORTERM")
        .map(|v| v.contains("truecolor") || v.contains("24bit"))
        .unwrap_or(false)
    {
        return ColorLevel::True;
    }
    ColorLevel::Ansi256
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorLevel {
    None,
    Ansi16,
    Ansi256,
    True,
}

impl ColorLevel {
    pub fn theme(self) -> Option<Theme> {
        match self {
            Self::None => None,
            Self::Ansi16 => Some(Theme::ansi16()),
            Self::Ansi256 | Self::True => Some(Theme::victorian()),
        }
    }
}
