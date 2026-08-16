pub mod auth;
pub mod cases;
pub mod config;
pub mod crawl;
pub mod doctor;
pub mod engines;
pub mod evidence;
pub mod findings;
pub mod hunt;
pub mod inspect;
pub mod report;
pub mod scan;

use crate::cli::{AuthCmd, CaseCmd, Cli, Commands, ConfigCmd};
use crate::core::config::AppConfig;
use crate::core::config::UiMode;
use crate::database::Database;
use crate::platform::db_path;
use crate::ui::renderer::{RenderMode, Renderer};
use clap::CommandFactory;
use tokio_util::sync::CancellationToken;

pub async fn dispatch(cli: Cli, cancel: CancellationToken) -> crate::Result<()> {
    let cfg = AppConfig::load()?;
    let machine = cli.wants_machine_stdout();
    let ui_mode = cli.ui.unwrap_or(cfg.ui.mode);
    let color = cfg.ui.color && !cli.no_color && !machine && std::env::var_os("NO_COLOR").is_none();
    let ascii_only = cfg.ui.ascii_only || cli.ascii_only;
    let render_mode = if machine {
        RenderMode::Machine
    } else {
        match ui_mode {
            UiMode::Minimal => RenderMode::Minimal,
            UiMode::Classic => RenderMode::Classic,
            UiMode::Cinematic => RenderMode::Cinematic,
        }
    };
    let mut renderer = Renderer::new(render_mode, color, ascii_only);

    match cli.command {
        None => {
            if !machine {
                renderer.banner();
            }
            let mut cmd = Cli::command();
            cmd.print_help()?;
            println!();
            Ok(())
        }
        Some(Commands::Version) => {
            println!("sherlock {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(Commands::Completion { shell }) => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "sherlock", &mut std::io::stdout());
            Ok(())
        }
        Some(Commands::Doctor { database }) => doctor::run(&cfg, machine, database),
        Some(Commands::Engines) => engines::run(&cfg),
        Some(Commands::Config { action }) => match action {
            ConfigCmd::Show => config::show(&cfg),
            ConfigCmd::Path => config::path(),
            ConfigCmd::Reset => config::reset(),
        },
        Some(Commands::Scan(args)) => {
            let db = Database::open(&db_path()?)?;
            if !machine {
                renderer.banner();
            }
            scan::run(&db, &cfg, args, &mut renderer, cancel).await
        }
        Some(Commands::Hunt(args)) => {
            let db = Database::open(&db_path()?)?;
            if !machine {
                renderer.banner();
            }
            hunt::run(&db, &cfg, args, &mut renderer, cancel).await
        }
        Some(Commands::Crawl(args)) => {
            let db = Database::open(&db_path()?)?;
            if !machine {
                renderer.banner();
            }
            crawl::run(&db, &cfg, args, &mut renderer, cancel).await
        }
        Some(Commands::Inspect { target, auth }) => {
            inspect::run(&cfg, &target, auth.as_deref(), &mut renderer, cancel).await
        }
        Some(Commands::Cases { json }) => {
            let db = Database::open(&db_path()?)?;
            cases::list(&db, json)
        }
        Some(Commands::Case { action, id }) => {
            let db = Database::open(&db_path()?)?;
            match action {
                Some(CaseCmd::Resume { case_id }) => {
                    cases::resume(&db, &cfg, &case_id, &mut renderer, cancel).await
                }
                Some(CaseCmd::Show { case_id }) => cases::show(&db, &case_id),
                None => {
                    let id = id.ok_or_else(|| {
                        crate::SherlockError::InvalidId("case id required".into())
                    })?;
                    cases::show(&db, &id)
                }
            }
        }
        Some(Commands::Findings { case_id }) => {
            reject_document_format("findings", cli.format.as_deref())?;
            let db = Database::open(&db_path()?)?;
            findings::list(&db, &case_id, cli.format.as_deref())
        }
        Some(Commands::Clues { case_id }) => {
            reject_document_format("clues", cli.format.as_deref())?;
            let db = Database::open(&db_path()?)?;
            cases::clues(&db, &case_id)
        }
        Some(Commands::Suspects { case_id }) => {
            reject_document_format("suspects", cli.format.as_deref())?;
            let db = Database::open(&db_path()?)?;
            findings::suspects(&db, &case_id)
        }
        Some(Commands::Evidence { finding_id }) => {
            reject_document_format("evidence", cli.format.as_deref())?;
            let db = Database::open(&db_path()?)?;
            evidence::show(&db, &finding_id)
        }
        Some(Commands::Verdict { case_id }) => {
            reject_document_format("verdict", cli.format.as_deref())?;
            let db = Database::open(&db_path()?)?;
            findings::verdict(&db, &case_id)
        }
        Some(Commands::Report(args)) => {
            let db = Database::open(&db_path()?)?;
            report::run(&db, &cfg, args)
        }
        Some(Commands::Auth { action }) => {
            let db = Database::open(&db_path()?)?;
            match action {
                AuthCmd::Add { name } => auth::add(&db, &name),
                AuthCmd::List => auth::list(&db),
                AuthCmd::Remove { name } => auth::remove(&db, &name),
            }
        }
    }
}

fn reject_document_format(command: &str, format: Option<&str>) -> crate::Result<()> {
    let Some(fmt) = format else {
        return Ok(());
    };
    let f = fmt.to_ascii_lowercase();
    if matches!(f.as_str(), "pdf" | "html" | "markdown" | "md" | "csv") {
        return Err(crate::SherlockError::Report(format!(
            "`sherlock {command}` does not write {fmt} documents. Use: sherlock report CASE --format {fmt}"
        )));
    }
    Ok(())
}
