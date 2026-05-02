use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use reqwest::Client;
use serde_json::json;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::engine::{LoggingEngine, now_seconds};
use crate::types::{
    EventSearchQuery, ProducerEventsRequest, ProducerEventsResponse, RegisterProducerRequest,
    StorageMaterializeRequest, StorageMaterializedIndexEntry,
};

#[derive(Clone)]
pub struct ApiState {
    pub engine: LoggingEngine,
    pub storage_url: Option<String>,
    pub http: Client,
}

#[derive(Debug)]
struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(json!({ "error": self.0.to_string() }));
        (StatusCode::BAD_REQUEST, body).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        Self(value)
    }
}

pub fn router(engine: LoggingEngine, storage_url: Option<String>) -> Router {
    let state = ApiState {
        engine,
        storage_url,
        http: Client::new(),
    };
    Router::new()
        .route("/health", get(health))
        .route("/hosted-service.json", get(hosted_service_manifest))
        .route("/v1/producers", post(register_producer))
        .route(
            "/v1/producers/{producer_id}/events",
            post(ingest_producer_events),
        )
        .route("/v1/producers/{producer_id}/poll", post(poll_producer))
        .route("/v1/events/search", get(search_events))
        .route("/v1/events/{event_id}", get(get_event))
        .route("/v1/timeline", get(search_events))
        .route("/v1/watch", get(watch))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn hosted_service_manifest() -> impl IntoResponse {
    Json(json!({
        "service": "logging",
        "deviceLabel": "Constitute Logging",
        "serviceVersion": env!("CARGO_PKG_VERSION"),
        "apiBaseUrl": "",
        "healthUrl": "/health",
        "appUrl": "/constitute-logging-ui/",
        "capabilities": [
            "log_observation",
            "safe_fact_index",
            "live_watch",
            "timeline",
            "storage_archive",
            "encrypted_detail_refs"
        ]
    }))
}

async fn health(State(state): State<ApiState>) -> Result<impl IntoResponse, ApiError> {
    let storage_status = if state.storage_url.is_some() {
        "configured"
    } else {
        "not_configured"
    };
    Ok(Json(state.engine.health(storage_status)?))
}

async fn register_producer(
    State(state): State<ApiState>,
    Json(request): Json<RegisterProducerRequest>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.register_producer(request)?))
}

async fn ingest_producer_events(
    State(state): State<ApiState>,
    Path(producer_id): Path<String>,
    Json(request): Json<ProducerEventsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let events = request.events.clone();
    let response = state.engine.ingest_events(&producer_id, request)?;
    archive_events(&state, &producer_id, &events).await;
    Ok(Json(response))
}

async fn poll_producer(
    State(state): State<ApiState>,
    Path(producer_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let producer = state.engine.producer(&producer_id)?;
    if producer.base_url.trim().is_empty() {
        return Err(anyhow::anyhow!("producer has no base url").into());
    }
    let url = format!(
        "{}/v1/logging/events?after={}",
        producer.base_url.trim_end_matches('/'),
        urlencoding::encode(&producer.cursor)
    );
    let response = state
        .http
        .get(url)
        .send()
        .await
        .map_err(anyhow::Error::from)?
        .error_for_status()
        .map_err(anyhow::Error::from)?
        .json::<ProducerEventsResponse>()
        .await
        .map_err(anyhow::Error::from)?;
    let events = response.events.clone();
    let ingest = state.engine.ingest_events(
        &producer_id,
        ProducerEventsRequest {
            cursor: response.next_cursor,
            events,
        },
    )?;
    archive_events(&state, &producer_id, &response.events).await;
    Ok(Json(ingest))
}

async fn search_events(
    State(state): State<ApiState>,
    Query(query): Query<EventSearchQuery>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.search(query)?))
}

async fn get_event(
    State(state): State<ApiState>,
    Path(event_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.engine.get_event(&event_id)?))
}

async fn watch(State(state): State<ApiState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| watch_socket(socket, state.engine))
}

async fn watch_socket(mut socket: WebSocket, engine: LoggingEngine) {
    let mut rx = engine.subscribe();
    while let Ok(event) = rx.recv().await {
        match serde_json::to_string(&event) {
            Ok(text) => {
                if socket.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

async fn archive_events(
    state: &ApiState,
    producer_id: &str,
    events: &[constitute_protocol::LogEventEnvelope],
) {
    let Some(storage_url) = &state.storage_url else {
        return;
    };
    if events.is_empty() {
        return;
    }
    let entries = events
        .iter()
        .map(|event| StorageMaterializedIndexEntry {
            entry_id: event.event_id.clone(),
            container_id: state.engine.archive_container_id(),
            record_type: "logEvent".to_string(),
            subject: event
                .subject
                .as_ref()
                .and_then(|subject| subject.id.clone().or_else(|| subject.display.clone()))
                .unwrap_or_else(|| event.producer.service.clone()),
            priority: enum_value(&event.severity),
            tags: event.tags.clone(),
            facts: json!({
                "producerId": producer_id,
                "service": event.producer.service,
                "component": event.producer.component,
                "category": enum_value(&event.category),
                "severity": enum_value(&event.severity),
                "outcome": enum_value(&event.outcome),
                "safeFacts": event.safe_facts,
            }),
            detail_ref: event.detail_ref.clone(),
            created_at: event.occurred_at,
        })
        .collect::<Vec<_>>();
    let url = format!(
        "{}/v1/local-index/materialize",
        storage_url.trim_end_matches('/')
    );
    if let Err(err) = state
        .http
        .post(url)
        .json(&StorageMaterializeRequest { entries })
        .send()
        .await
    {
        tracing::warn!(error = %err, at = now_seconds(), "logging storage materialization failed");
    }
}

fn enum_value(value: &impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_default()
}
