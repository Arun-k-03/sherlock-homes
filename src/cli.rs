use crate::core::config::{ScanMode, UiMode};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "sherlock",
    author,
    version,
    about = "Sherlock Homes — Cyber Investigation Engine\nEVERY REQUEST LEAVES A CLUE.",
    long_about = "Sherlock Homes is a CLI/TUI web-application vulnerability assessment engine.\nScan only systems you own or are explicitly authorized to test.\nDefault mode is SAFE. Automated scanners cannot guarantee 100% detection."
)]
pub struct Cli {
    /// Quiet: no banners/animations; diagnostics on stderr
    #[arg(long, global = true)]
    pub quiet: bool,

    /// Disable animations
    #[arg(long, global = true)]
    pub no_animation: bool,

    /// Reduced motion
    #[arg(long, global = true)]
    pub reduced_motion: bool,

    /// ASCII-only output
    #[arg(long, global = true)]
    pub ascii_only: bool,

    /// Disable color
    #[arg(long, global = true)]
    pub no_color: bool,

    /// UI presentation
    #[arg(long, global = true, value_enum)]
    pub ui: Option<UiMode>,

    /// Machine-readable output format for commands that support it
    #[arg(long, global = true)]
    pub format: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Open a case and investigate a target (Scene)
    Scan(ScanArgs),
    /// Focused hunt against a single URL without deep crawl
    Hunt(ScanArgs),
    /// Map the attack surface (crawl only)
    Crawl(ScanArgs),
    /// Inspect a single URL: headers, cookies, technologies
    Inspect {
        target: String,
        #[arg(long)]
        auth: Option<String>,
    },
    /// List stored investigations (Case Files)
    Cases {
        #[arg(long)]
        json: bool,
    },
    /// Show or resume a case
    Case {
        #[command(subcommand)]
        action: Option<CaseCmd>,
        id: Option<String>,
    },
    /// List discovered endpoints (Clues)
    Clues { case_id: String },
    /// List candidate findings (Suspects)
    Suspects { case_id: String },
    /// List confirmed/likely findings
    Findings { case_id: String },
    /// Show evidence for a finding
    Evidence { finding_id: String },
    /// Show the case verdict
    Verdict { case_id: String },
    /// Generate investigation reports
    Report(ReportArgs),
    /// Manage authentication profiles
    Auth {
        #[command(subcommand)]
        action: AuthCmd,
    },
    /// Show optional engine status
    Engines,
    /// System diagnostics
    Doctor {
        /// Inspect Evidence Vault schema and migration status
        #[arg(long)]
        database: bool,
    },
    /// Configuration
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// Print version
    Version,
    /// Generate shell completions
    Completion { shell: clap_complete::Shell },
}

#[derive(Debug, Subcommand)]
pub enum CaseCmd {
    Resume { case_id: String },
    Show { case_id: String },
}

#[derive(Debug, Subcommand)]
pub enum AuthCmd {
    Add { name: String },
    List,
    Remove { name: String },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    Show,
    Path,
    Reset,
}

#[derive(Debug, Clone, clap::Args)]
pub struct ScanArgs {
    /// Target URL (the Scene)
    pub target: String,
    /// Scan mode (default: safe)
    #[arg(long, value_enum)]
    pub mode: Option<ScanMode>,
    /// Crawl depth
    #[arg(long)]
    pub depth: Option<u32>,
    /// Requests per second
    #[arg(long)]
    pub rate: Option<u32>,
    /// Concurrent requests
    #[arg(long)]
    pub concurrency: Option<u32>,
    /// Request timeout seconds
    #[arg(long)]
    pub timeout: Option<u64>,
    /// Additional allowed hosts
    #[arg(long = "allow")]
    pub allow: Vec<String>,
    /// Excluded path patterns
    #[arg(long = "exclude")]
    pub exclude: Vec<String>,
    /// Auth profile name
    #[arg(long)]
    pub auth: Option<String>,
    /// Acknowledge full-mode extra checks
    #[arg(long)]
    pub i_authorize_full: bool,
    /// Resume an existing case
    #[arg(long)]
    pub resume: Option<String>,
}

#[derive(Debug, Clone, clap::Args)]
pub struct ReportArgs {
    pub case_id: String,
    /// Comma-separated: pdf,html,json,jsonl,sarif,markdown,csv
    #[arg(long)]
    pub format: Option<String>,
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Jsonl,
    Sarif,
}

impl Cli {
    pub fn wants_machine_stdout(&self) -> bool {
        if self.quiet {
            return true;
        }
        if let Some(fmt) = &self.format {
            let f = fmt.to_ascii_lowercase();
            return f == "json" || f == "jsonl" || f == "sarif";
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn version_and_help_parse() {
        assert!(Cli::try_parse_from(["sherlock", "version"]).is_ok());
        assert!(Cli::try_parse_from(["sherlock", "doctor"]).is_ok());
        assert!(Cli::try_parse_from(["sherlock", "scan", "--help"]).is_err());
    }

    #[test]
    fn invalid_subcommand_fails() {
        assert!(Cli::try_parse_from(["sherlock", "explode-the-lab"]).is_err());
    }

    #[test]
    fn findings_accepts_global_format_flag() {
        let cli = Cli::try_parse_from(["sherlock", "findings", "SH-1", "--format", "pdf"]).unwrap();
        assert_eq!(cli.format.as_deref(), Some("pdf"));
        match cli.command {
            Some(Commands::Findings { case_id }) => assert_eq!(case_id, "SH-1"),
            _ => panic!("expected findings"),
        }
    }
}
