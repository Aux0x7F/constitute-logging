// domain-owned-vocabulary: logging.dashboard.observe logging.health.observe logging.surface logging.surface.observe
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use constitute_logging::{LoggingEngine, LoggingServiceIdentity, api, edge_client};
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
    #[arg(long, env = "CONSTITUTE_SWARM_EDGE_ENDPOINT")]
    swarm_edge_endpoint: Option<String>,
    #[arg(long, default_value = "zone_lab", env = "CONSTITUTE_SWARM_ZONE_ID")]
    swarm_zone_id: String,
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
    if let Some(gateway_endpoint) = args.swarm_edge_endpoint.clone() {
        let edge_state = api::ApiState {
            engine: engine.clone(),
            storage_url: args.storage_url.clone(),
            service_identity: identity.clone(),
            http: reqwest::Client::new(),
            caac_fixture_mode: false,
        };
        let edge_config = edge_client::SwarmEdgeClientConfig {
            gateway_endpoint,
            member_ref: identity.service_pk.clone(),
            service_pk: identity.service_pk.clone(),
            service_sk_hex: identity.service_sk_hex.clone(),
            zone_id: args.swarm_zone_id.clone(),
        };
        tokio::spawn(async move {
            if let Err(err) = edge_client::run_swarm_edge_client(edge_state, edge_config).await {
                tracing::warn!(error = %err, "logging swarm edge client stopped");
            }
        });
    }
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
    let service_pk = identity.service_pk.as_str();
    let service_ref = format!("service:logging:{service_pk}");
    let manifest = serde_json::json!({
        "service": "logging",
        "servicePk": service_pk,
        "deviceLabel": "Constitute Logging",
        "serviceVersion": env!("CARGO_PKG_VERSION"),
        "apiBaseUrl": "",
        "apiBind": bind,
        "healthUrl": "/health",
        "appUrl": "/constitute-logging-ui/",
        "aliases": ["Logging", "Constitute Logging"],
        "surfaceChannel": "logging.surface",
        "summary": "Structured safe event observation and retention state.",
        "nodes": ["events", "health", "dashboard", "settings"],
        "capabilities": [
            constitute_protocol::CAPABILITY_PROJECTION_OBSERVE,
            constitute_protocol::CAPABILITY_LOGGING_EVENTS_INGEST,
            constitute_protocol::CAPABILITY_LOGGING_EVENTS_OBSERVE,
            "logging.health.observe",
            "logging.dashboard.observe",
            "logging.surface.observe"
        ],
        "channels": [
            "logging.surface",
            constitute_protocol::PROJECTION_CHANNEL_LOGGING_EVENTS,
            constitute_protocol::PROJECTION_CHANNEL_LOGGING_HEALTH,
            constitute_protocol::PROJECTION_CHANNEL_LOGGING_DASHBOARD
        ],
        "swarmEdge": {
            "memberRef": service_pk,
            "serviceRef": service_ref.clone(),
            "servicePk": service_pk,
            "promiseRefs": [
                service_ref,
                service_pk
            ],
            "role": "edgeMember",
            "transport": "gateway.swarm.edge.websocket"
        }
    });
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("move hosted-service manifest into place {}", path.display()))?;
    Ok(())
}
