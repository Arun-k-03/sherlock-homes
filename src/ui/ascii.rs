//! Original Sherlock Homes banner. ASCII-first; Unicode never required.

pub const BANNER: &str = r#"
  +==============================================================+
  |                    S H E R L O C K   H O M E S               |
  |               CYBER INVESTIGATION ENGINE                     |
  +==============================================================+
                         .----------------.
                       .'        +         '.
                      /       .-' '-.        \
                     |       /  ( )  \        |
                      \      \   _   /       /
                       '.     '-._.-'      .'
                         '--------|--------'
                                  |
                                  |
                           [  LENS  ]
              EVERY REQUEST LEAVES A CLUE
"#;

pub const BANNER_MINIMAL: &str =
    "SHERLOCK HOMES  |  CYBER INVESTIGATION ENGINE\nEVERY REQUEST LEAVES A CLUE.";

pub fn banner(ascii_only: bool, compact: bool) -> &'static str {
    let _ = ascii_only;
    if compact {
        BANNER_MINIMAL
    } else {
        BANNER
    }
}
