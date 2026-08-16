use crate::cli::ScanArgs;
use crate::core::config::AppConfig;
use crate::core::scanner::{run_scan, ScanOptions};
use crate::database::Database;
use crate::ui::Renderer;
use tokio_util::sync::CancellationToken;

pub async fn run(
    db: &Database,
    cfg: &AppConfig,
    args: ScanArgs,
    renderer: &mut Renderer,
    cancel: CancellationToken,
) -> crate::Result<()> {
    let opts = ScanOptions::from_args(&args, cfg);
    let id = run_scan(db, cfg, opts, renderer, cancel).await?;
    renderer.print_case_footer(&id.0);
    Ok(())
}
