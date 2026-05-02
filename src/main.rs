use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use constitute_logging::{LoggingEngine, api};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(about = "CAAC-aligned blind structured logging service")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7480")]
    bind: SocketAddr,
    #[arg(long, default_value = "./data")]
    data_dir: PathBuf,
    #[arg(long, env = "CONSTITUTE_STORAGE_URL")]
    storage_url: Option<String>,
    #[arg(long, default_value = "gateway-local-logs")]
    archive_container_id: String,
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&args.log_level))
        .init();
    let engine = LoggingEngine::open(&args.data_dir, args.archive_container_id)?;
    let app = api::router(engine, args.storage_url);
    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("bind logging service on {}", args.bind))?;
    tracing::info!(bind = %args.bind, "constitute-logging listening");
    axum::serve(listener, app).await?;
    Ok(())
}
