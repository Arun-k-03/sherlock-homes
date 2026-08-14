use clap::Parser;
use sherlock_homes::cli::Cli;
use sherlock_homes::commands;
use sherlock_homes::ui::TerminalGuard;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sherlock_homes=info".parse().unwrap()),
        )
        .with_writer(std::io::stderr)
        .init();

    let _guard = TerminalGuard::enter(false).ok();
    let cancel = CancellationToken::new();
    let cancel_c = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        cancel_c.cancel();
        eprintln!("\nStopping new tasks. Flushing the Evidence Vault...");
    });

    let cli = Cli::parse();
    if let Err(e) = commands::dispatch(cli, cancel).await {
        if matches!(e, sherlock_homes::SherlockError::Cancelled) {
            std::process::exit(130);
        }
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
