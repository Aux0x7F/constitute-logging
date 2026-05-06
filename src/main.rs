use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use constitute_logging::{LoggingEngine, LoggingServiceIdentity, api};
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
    #[arg(long)]
    hosted_manifest: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&args.log_level))
        .init();
    let engine = LoggingEngine::open(&args.data_dir, args.archive_container_id)?;
    let identity = LoggingServiceIdentity::load_or_create(&args.data_dir)?;
    let bind = args.bind.to_string();
    persist_hosted_service_manifest(
        args.hosted_manifest
            .clone()
            .unwrap_or_else(|| args.data_dir.join("hosted-service.json")),
        &identity,
        &bind,
    )?;
    let app = api::router(engine, args.storage_url, identity);
    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("bind logging service on {}", args.bind))?;
    tracing::info!(bind = %args.bind, "constitute-logging listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn persist_hosted_service_manifest(
    path: PathBuf,
    identity: &LoggingServiceIdentity,
    bind: &str,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create hosted-service manifest dir {}", parent.display()))?;
    }
    let manifest = serde_json::json!({
        "service": "logging",
        "servicePk": identity.service_pk,
        "deviceLabel": "Constitute Logging",
        "serviceVersion": env!("CARGO_PKG_VERSION"),
        "apiBaseUrl": "",
        "apiBind": bind,
        "healthUrl": "/health",
        "appUrl": "/constitute-logging-ui/",
        "capabilities": [
            "log_observation",
            "safe_fact_index",
            "live_watch",
            "timeline",
            "storage_archive",
            "encrypted_detail_refs"
        ],
        "projectionChannels": [
            "logging.events",
            "logging.health",
            "logging.dashboard"
        ],
        "invocationKinds": [
            "service.describe.request",
            "service.describe.response",
            "service.projection.request",
            "service.projection.response",
            "service.watch.request",
            "service.watch.event",
            "service.close"
        ]
    });
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("move hosted-service manifest into place {}", path.display()))?;
    Ok(())
}
