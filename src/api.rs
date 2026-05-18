use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use constitute_protocol::{
    CAPABILITY_PROJECTION_DELTA_APPLY, CAPABILITY_PROJECTION_OBSERVE, CaacEnvelope, ConsumerFloor,
    EncryptedDetailRef, LOG_EVIDENCE_DETAIL_CUSTODY_ENCRYPTED_DETAIL_REF,
    LOG_EVIDENCE_PROFILE_EVENT_MEDIA_PATH, LOG_EVIDENCE_PROFILE_EVENT_RUNTIME_DIAGNOSTIC,
    LOG_EVIDENCE_PROFILE_EVENT_SECURITY_AUDIT, LOG_EVIDENCE_PROFILE_EVENT_SERVICE_EVENT,
    LOG_EVIDENCE_PROFILE_EVENT_STORAGE_ACCESS, LOG_EVIDENCE_PROFILE_KIND, LogCategory,
    LogEventEnvelope, LogEvidenceProfile, LogOutcome, LogSeverity, MaterializationBudget,
    MaterializationSchemaPosture, ProjectionDeltaOp, ProjectionDeltaOpKind, ProjectionPathSegment,
    RECORD_CONSUMER_FLOOR, RECORD_MATERIALIZATION_BUDGET, SWARM_FRAME_VERSION, StoragePinIntent,
    SwarmFrame, SwarmFrameBody, SwarmFrameKind, SwarmProjectionDelta, SwarmProjectionSnapshot,
    SwarmRecordRef, ZoneScope, open_envelope, seal_envelope, sha256_hex, swarm_frame_id,
    validate_consumer_floor, validate_log_evidence_profile, validate_materialization_budget,
    validate_projection_delta, validate_projection_snapshot, validate_storage_pin_intent,
    validate_swarm_frame,
};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::engine::{LoggingEngine, now_seconds};
use crate::identity::LoggingServiceIdentity;
use crate::types::{
    EventSearchQuery, ProducerEventsRequest, ProducerEventsResponse, RegisterProducerRequest,
    StorageMaterializeRequest, StorageMaterializedIndexEntry,
};

pub(crate) const LOGGING_CHANNELS: [&str; 4] = [
    "logging.surface",
    "logging.events",
    "logging.health",
    "logging.dashboard",
];

pub(crate) const LOGGING_EDGE_CAPABILITIES: [&str; 6] = [
    CAPABILITY_PROJECTION_OBSERVE,
    "logging.events.ingest",
    "logging.events.observe",
    "logging.health.observe",
    "logging.dashboard.observe",
    "logging.surface.observe",
];

#[derive(Clone)]
pub struct ApiState {
    pub engine: LoggingEngine,
    pub storage_url: Option<String>,
    pub service_identity: LoggingServiceIdentity,
    pub http: Client,
    pub caac_fixture_mode: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProjectionAdapterRequest {
    #[serde(default)]
    request_id: String,
    #[serde(default)]
    frame: Value,
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

pub fn router(
    engine: LoggingEngine,
    storage_url: Option<String>,
    service_identity: LoggingServiceIdentity,
) -> Router {
    let state = ApiState {
        engine,
        storage_url,
        service_identity,
        http: Client::new(),
        caac_fixture_mode: false,
    };
    Router::new()
        .route("/health", get(health))
        .route("/hosted-service.json", get(hosted_service_manifest))
        .route(
            "/operator/logging/projection-adapter",
            post(projection_adapter),
        )
        .route("/operator/logging/v1/producers", post(register_producer))
        .route(
            "/operator/logging/v1/producers/{producer_id}/events",
            post(ingest_producer_events),
        )
        .route(
            "/operator/logging/v1/producers/{producer_id}/poll",
            post(poll_producer),
        )
        .route("/operator/logging/v1/events/search", get(search_events))
        .route("/operator/logging/v1/events/{event_id}", get(get_event))
        .route("/operator/logging/v1/timeline", get(search_events))
        .route("/operator/logging/v1/watch", get(watch))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn hosted_service_manifest(State(state): State<ApiState>) -> impl IntoResponse {
    let service_pk = state.service_identity.service_pk.as_str();
    let service_ref = format!("service:logging:{service_pk}");
    Json(json!({
        "service": "logging",
        "servicePk": service_pk,
        "deviceLabel": "Constitute Logging",
        "serviceVersion": env!("CARGO_PKG_VERSION"),
        "apiBaseUrl": "",
        "healthUrl": "/health",
        "appUrl": "/constitute-logging-ui/",
        "aliases": ["Logging", "Constitute Logging"],
        "surfaceChannel": "logging.surface",
        "summary": "Structured safe event observation and retention state.",
        "nodes": ["events", "health", "dashboard", "settings"],
        "capabilities": LOGGING_EDGE_CAPABILITIES,
        "channels": [
            {
                "channelId": "logging.surface",
                "recordKinds": ["projection.delta"],
                "capabilities": ["logging.surface.observe"]
            },
            {
                "channelId": "logging.events",
                "recordKinds": ["logging.event", "projection.delta"],
                "capabilities": ["logging.events.ingest", "logging.events.observe"]
            },
            {
                "channelId": "logging.health",
                "recordKinds": ["projection.delta"],
                "capabilities": ["logging.health.observe"]
            },
            {
                "channelId": "logging.dashboard",
                "recordKinds": ["projection.delta"],
                "capabilities": ["logging.dashboard.observe"]
            }
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
            "transport": "gateway.swarm.edge.websocket",
            "channels": LOGGING_CHANNELS,
            "capabilities": LOGGING_EDGE_CAPABILITIES
        },
        "transportHints": {
            "edgeStream": "gateway.swarm.edge.websocket",
            "operatorProjectionAdapter": "/operator/logging/projection-adapter"
        }
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

async fn ingest_edge_frame_at(
    state: &ApiState,
    frame: SwarmFrame,
    now: u64,
) -> Result<Value, ApiError> {
    validate_swarm_frame(&frame, now).map_err(anyhow::Error::from)?;
    if frame.kind != SwarmFrameKind::RecordPublish {
        return Err(anyhow::anyhow!("logging edge only accepts record.publish frames").into());
    }
    let channel_id = frame
        .channel_id
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_string();
    if channel_id != "logging.events" {
        return Err(anyhow::anyhow!("logging edge frame targets unsupported channel").into());
    }
    if frame
        .record_ref
        .as_ref()
        .map(|record| record.kind.as_str())
        .is_some_and(|kind| kind != "logging.event")
    {
        return Err(anyhow::anyhow!("logging edge frame record kind must be logging.event").into());
    }
    let payload = sealed_frame_payload(state, &frame, now)?;
    let record = logging_event_record_from_payload(&payload);
    let event: LogEventEnvelope = serde_json::from_value(record).map_err(anyhow::Error::from)?;
    let producer_id = logging_event_producer_id(&payload)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(event.producer.service.as_str())
        .trim()
        .to_string();
    let request = ProducerEventsRequest {
        cursor: event.event_id.clone(),
        events: vec![event.clone()],
    };
    let ingest = state.engine.ingest_events(&producer_id, request)?;
    let archive_pin_intents = archive_pin_intents_for_event(state, &event).map_err(ApiError)?;
    let request_id = frame
        .correlation_id
        .clone()
        .unwrap_or_else(|| frame.frame_id.clone());
    let projection_payload = json!({
        "requestId": request_id,
        "channelId": "logging.events",
        "baseRevision": projection_base_revision(&payload),
        "limit": 2500,
        "filters": payload.get("filters").cloned().unwrap_or_else(|| json!({}))
    });
    let projection = logging_events_projection(
        state,
        &projection_payload,
        request_id.clone(),
        now_seconds(),
    )?;
    Ok(json!({
        "status": "accepted",
        "frameId": frame.frame_id,
        "channelId": "logging.events",
        "accepted": ingest.accepted,
        "duplicate": ingest.duplicate,
        "cursor": ingest.cursor,
        "archivePinIntents": archive_pin_intents,
        "projectionDelta": projection.get("projectionDelta").cloned().unwrap_or_else(|| json!({})),
        "safeProjectionDelta": true
    }))
}

fn logging_event_record_from_payload(payload: &Value) -> Value {
    if let Some(inner) = payload.get("payload").filter(|value| value.is_object()) {
        let inner_record_kind = inner
            .get("recordKind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if inner_record_kind == "logging.event" {
            if let Some(record) = inner.get("record").filter(|value| value.is_object()) {
                return record.clone();
            }
            if let Some(event) = inner.get("event").filter(|value| value.is_object()) {
                return event.clone();
            }
        }
        if let Some(record) = inner
            .get("record")
            .filter(|value| looks_like_logging_event(value))
        {
            return record.clone();
        }
        if let Some(event) = inner
            .get("event")
            .filter(|value| looks_like_logging_event(value))
        {
            return event.clone();
        }
    }
    payload
        .get("record")
        .or_else(|| payload.get("event"))
        .cloned()
        .unwrap_or_else(|| payload.clone())
}

fn logging_event_producer_id(payload: &Value) -> Option<&str> {
    payload
        .get("producerId")
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .get("payload")
                .and_then(|inner| inner.get("producerId"))
                .and_then(Value::as_str)
        })
}

fn looks_like_logging_event(value: &Value) -> bool {
    value.is_object()
        && value.get("schemaVersion").is_some()
        && value.get("eventId").is_some()
        && value.get("producer").is_some()
        && value.get("occurredAt").is_some()
}

async fn observe_edge_frame_at(
    state: &ApiState,
    frame: &SwarmFrame,
    now: u64,
) -> Result<Value, ApiError> {
    validate_swarm_frame(frame, now).map_err(anyhow::Error::from)?;
    if frame.kind != SwarmFrameKind::ChannelObserve {
        return Err(anyhow::anyhow!("logging edge only observes channel.observe frames").into());
    }
    let channel_id = frame
        .channel_id
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_string();
    if !LOGGING_CHANNELS.contains(&channel_id.as_str()) {
        return Err(anyhow::anyhow!("logging edge projection channel is unsupported").into());
    }
    let claims = sealed_frame_payload(state, frame, now)?;
    let payload = claims
        .get("payload")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or_else(|| claims.clone());
    let request_id = payload
        .get("requestId")
        .or_else(|| claims.get("requestId"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or(frame.correlation_id.as_deref())
        .unwrap_or(frame.frame_id.as_str())
        .trim()
        .to_string();
    let host_gateway_pk = payload
        .get("hostGatewayPk")
        .or_else(|| claims.get("hostGatewayPk"))
        .or_else(|| {
            claims
                .get("authority")
                .and_then(|authority| authority.get("gatewayPk"))
        })
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let now_seconds = now_seconds();
    match channel_id.as_str() {
        "logging.surface" => {
            logging_surface_projection(state, &host_gateway_pk, request_id, now_seconds)
        }
        "logging.events" => logging_events_projection(state, &payload, request_id, now_seconds),
        "logging.health" => logging_health_projection(
            state,
            request_id,
            projection_base_revision(&payload),
            now_seconds,
        ),
        "logging.dashboard" => {
            logging_dashboard_projection(state, &payload, request_id, now_seconds)
        }
        _ => Err(anyhow::anyhow!("unsupported logging projection channel").into()),
    }
}

pub async fn process_gateway_frame(
    state: &ApiState,
    frame: SwarmFrame,
    now: u64,
) -> anyhow::Result<Vec<SwarmFrame>> {
    let source_frame = frame.clone();
    if is_route_observation_frame(&source_frame) {
        return Ok(Vec::new());
    }
    if source_frame.kind == SwarmFrameKind::ChannelObserve {
        let projection = observe_edge_frame_at(state, &source_frame, now)
            .await
            .map_err(|err| err.0)?;
        return Ok(vec![projection_snapshot_response_frame(
            state,
            &source_frame,
            projection,
            now,
        )?]);
    }
    let response = ingest_edge_frame_at(state, frame, now)
        .await
        .map_err(|err| err.0)?;
    let mut frames = Vec::new();
    let Some(delta) = response
        .get("projectionDelta")
        .filter(|value| value.is_object())
    else {
        return Ok(frames);
    };
    frames.push(projection_delta_response_frame(
        state,
        &source_frame,
        delta.clone(),
        now,
    )?);
    if let Some(intents) = response.get("archivePinIntents").and_then(Value::as_array) {
        for intent_value in intents {
            let intent: StoragePinIntent = serde_json::from_value(intent_value.clone())?;
            frames.push(storage_pin_intent_frame(state, &source_frame, intent, now)?);
        }
    }
    Ok(frames)
}

fn is_route_observation_frame(frame: &SwarmFrame) -> bool {
    frame.kind == SwarmFrameKind::RecordPublish
        && frame.channel_id.as_deref() == Some("swarm.route")
        && frame.record_ref.as_ref().map(|record| record.kind.as_str()) == Some("route.observation")
}

fn projection_delta_response_frame(
    state: &ApiState,
    source_frame: &SwarmFrame,
    delta: Value,
    now: u64,
) -> anyhow::Result<SwarmFrame> {
    let projection_id = delta
        .get("projectionId")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("logging:projection:logging.events");
    let channel_id = source_frame
        .channel_id
        .clone()
        .unwrap_or_else(|| "logging.events".to_string());
    let mut frame = SwarmFrame {
        version: SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: SwarmFrameKind::ProjectionDelta,
        issuer: format!("service:logging:{}", state.service_identity.service_pk),
        audience: json!({ "actorRef": source_frame.issuer }),
        zone_scope: source_frame.zone_scope.clone().or_else(default_zone_scope),
        issued_at: now,
        expires_at: Some(now + 60_000),
        nonce: format!("logging-projection-delta-{now}-{}", source_frame.frame_id),
        correlation_id: Some(source_frame.frame_id.clone()),
        channel_id: Some(channel_id),
        record_ref: Some(SwarmRecordRef {
            kind: "projection.delta".to_string(),
            id: projection_id.to_string(),
            revision: delta.get("revision").and_then(Value::as_u64),
        }),
        capability: Some(CAPABILITY_PROJECTION_DELTA_APPLY.to_string()),
        body: SwarmFrameBody {
            encoding: "caac".to_string(),
            envelope: seal_frame_payload(
                &state.service_identity,
                source_frame,
                "projection.delta",
                json!({
                    "recordKind": "projection.delta",
                    "delta": delta,
                }),
                now,
            ),
            public_bootstrap: false,
            payload: None,
            signature: None,
        },
        ack: None,
    };
    frame.frame_id = swarm_frame_id(&frame)?;
    Ok(frame)
}

fn projection_snapshot_response_frame(
    state: &ApiState,
    source_frame: &SwarmFrame,
    projection: Value,
    now: u64,
) -> anyhow::Result<SwarmFrame> {
    let snapshot = projection_snapshot_for_record(&projection, now).map_err(|err| err.0)?;
    let mut frame = SwarmFrame {
        version: SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: SwarmFrameKind::ProjectionSnapshot,
        issuer: format!("service:logging:{}", state.service_identity.service_pk),
        audience: json!({ "actorRef": source_frame.issuer }),
        zone_scope: source_frame.zone_scope.clone().or_else(default_zone_scope),
        issued_at: now,
        expires_at: Some(now + 60_000),
        nonce: format!(
            "logging-projection-snapshot-{now}-{}",
            source_frame.frame_id
        ),
        correlation_id: Some(source_frame.frame_id.clone()),
        channel_id: source_frame.channel_id.clone(),
        record_ref: Some(SwarmRecordRef {
            kind: "projection.snapshot".to_string(),
            id: snapshot.projection_id.clone(),
            revision: Some(snapshot.revision),
        }),
        capability: Some(CAPABILITY_PROJECTION_OBSERVE.to_string()),
        body: SwarmFrameBody {
            encoding: "caac".to_string(),
            envelope: seal_frame_payload(
                &state.service_identity,
                source_frame,
                "projection.snapshot",
                json!({
                    "recordKind": "projection.snapshot",
                    "snapshot": snapshot,
                }),
                now,
            ),
            public_bootstrap: false,
            payload: None,
            signature: None,
        },
        ack: None,
    };
    frame.frame_id = swarm_frame_id(&frame)?;
    Ok(frame)
}

fn storage_pin_intent_frame(
    state: &ApiState,
    source_frame: &SwarmFrame,
    intent: StoragePinIntent,
    now: u64,
) -> anyhow::Result<SwarmFrame> {
    validate_storage_pin_intent(&intent)?;
    let mut frame = SwarmFrame {
        version: SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: SwarmFrameKind::StoragePinIntent,
        issuer: format!("service:logging:{}", state.service_identity.service_pk),
        audience: json!({ "capability": "storage.pin" }),
        zone_scope: source_frame.zone_scope.clone().or_else(default_zone_scope),
        issued_at: now,
        expires_at: Some(now + 60_000),
        nonce: format!("logging-storage-pin-{now}-{}", intent.intent_id),
        correlation_id: Some(source_frame.frame_id.clone()),
        channel_id: Some("storage.pin.intent".to_string()),
        record_ref: Some(SwarmRecordRef {
            kind: "storage.pin.intent".to_string(),
            id: intent.intent_id.clone(),
            revision: Some(1),
        }),
        capability: Some("storage.pin".to_string()),
        body: SwarmFrameBody {
            encoding: "caac".to_string(),
            envelope: seal_frame_record(
                &state.service_identity,
                source_frame,
                "storage.pin.intent",
                serde_json::to_value(intent).unwrap_or_else(|_| json!({})),
                now,
            ),
            public_bootstrap: false,
            payload: None,
            signature: None,
        },
        ack: None,
    };
    frame.frame_id = swarm_frame_id(&frame)?;
    Ok(frame)
}

fn default_zone_scope() -> Option<ZoneScope> {
    Some(ZoneScope {
        zone_id: "zone_lab".to_string(),
        privacy: Some("rawIds".to_string()),
        ttl: Some(30),
        max_hops: Some(2),
    })
}

fn sealed_frame_payload(state: &ApiState, frame: &SwarmFrame, now: u64) -> Result<Value, ApiError> {
    if frame.body.encoding != "caac" {
        return Err(anyhow::anyhow!("logging edge requires sealed CAAC frame body").into());
    }
    let envelope = frame
        .body
        .envelope
        .as_ref()
        .filter(|value| value.is_object())
        .ok_or_else(|| anyhow::anyhow!("logging edge frame missing sealed envelope"))?;
    if !state.caac_fixture_mode {
        reject_placeholder_caac(frame, envelope)?;
        let caac: CaacEnvelope = serde_json::from_value(envelope.clone())
            .map_err(|_| anyhow::anyhow!("logging edge requires opened CAAC envelope"))?;
        return open_envelope(&caac, &state.service_identity.service_sk_hex, now, None)
            .map_err(|err| anyhow::anyhow!("logging edge CAAC open failed: {err}").into());
    }
    for key in ["sealedPayload", "payload", "record"] {
        if let Some(value) = envelope.get(key).filter(|value| value.is_object()) {
            return if key == "record" {
                Ok(json!({ "record": value }))
            } else {
                Ok(value.clone())
            };
        }
    }
    Ok(envelope.clone())
}

fn seal_frame_record(
    service_identity: &LoggingServiceIdentity,
    source_frame: &SwarmFrame,
    kind: &str,
    record: Value,
    now: u64,
) -> Option<Value> {
    seal_frame_payload(
        service_identity,
        source_frame,
        kind,
        json!({ "record": record }),
        now,
    )
}

fn seal_frame_payload(
    service_identity: &LoggingServiceIdentity,
    source_frame: &SwarmFrame,
    kind: &str,
    payload: Value,
    now: u64,
) -> Option<Value> {
    let recipient_pk = frame_recipient_pk(source_frame, &service_identity.service_pk);
    seal_envelope(
        kind,
        &payload,
        &service_identity.service_sk_hex,
        &[recipient_pk],
        now,
        now + 60_000,
    )
    .ok()
    .and_then(|envelope| serde_json::to_value(envelope).ok())
}

fn reject_placeholder_caac(frame: &SwarmFrame, envelope: &Value) -> Result<(), ApiError> {
    if frame
        .body
        .signature
        .as_deref()
        .is_some_and(is_placeholder_token)
        || envelope
            .get("shape")
            .and_then(Value::as_str)
            .is_some_and(is_placeholder_token)
        || envelope.get("sealedPayload").is_some()
    {
        return Err(
            anyhow::anyhow!("logging edge rejects placeholder CAAC outside fixture mode").into(),
        );
    }
    if let Some(signature) = envelope.get("signature").and_then(Value::as_str)
        && is_placeholder_token(signature)
    {
        return Err(
            anyhow::anyhow!("logging edge rejects placeholder CAAC outside fixture mode").into(),
        );
    }
    Ok(())
}

fn is_placeholder_token(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("placeholder") || lowered.contains("fixture")
}

fn frame_recipient_pk(frame: &SwarmFrame, fallback_pk: &str) -> String {
    if is_hex_pk(&frame.issuer) {
        frame.issuer.clone()
    } else {
        fallback_pk.to_string()
    }
}

fn is_hex_pk(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn projection_adapter(
    State(state): State<ApiState>,
    Json(request): Json<ProjectionAdapterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let frame = request.frame;
    let kind = frame
        .get("kind")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .trim();
    if kind != "service.projection.request" {
        return Err(anyhow::anyhow!("unsupported projection adapter frame kind").into());
    }
    let recipient = frame
        .get("recipientServicePk")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .trim();
    if !recipient.is_empty() && recipient != state.service_identity.service_pk.trim() {
        return Err(anyhow::anyhow!("projection adapter recipient mismatch").into());
    }
    let host_gateway_pk = frame
        .get("hostGatewayPk")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .trim()
        .to_string();
    let payload = frame
        .get("sealedPayload")
        .cloned()
        .filter(|value| value.is_object())
        .ok_or_else(|| anyhow::anyhow!("service projection request missing payload"))?;
    let channel_id = payload
        .get("channelId")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .trim()
        .to_string();
    let request_id = payload
        .get("requestId")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(request.request_id.as_str())
        .trim()
        .to_string();
    let now = now_seconds();
    let projection = match channel_id.as_str() {
        "logging.surface" => logging_surface_projection(&state, &host_gateway_pk, request_id, now)?,
        "logging.events" => logging_events_projection(&state, &payload, request_id, now)?,
        "logging.health" => {
            logging_health_projection(&state, request_id, projection_base_revision(&payload), now)?
        }
        "logging.dashboard" => logging_dashboard_projection(&state, &payload, request_id, now)?,
        _ => return Err(anyhow::anyhow!("unsupported logging projection channel").into()),
    };
    Ok(Json(json!({
        "frame": {
            "kind": "service.projection.response",
            "requestId": projection.get("requestId").cloned().unwrap_or_else(|| json!("")),
            "service": "logging",
            "servicePk": state.service_identity.service_pk,
        },
        "projection": projection,
    })))
}

fn logging_surface_projection(
    state: &ApiState,
    host_gateway_pk: &str,
    request_id: String,
    now: u64,
) -> Result<Value, ApiError> {
    let health = state.engine.health(if state.storage_url.is_some() {
        "configured"
    } else {
        "not_configured"
    })?;
    let surface = json!({
        "surfaceId": "logging.surface",
        "schemaVersion": 1,
        "service": "logging",
        "servicePk": state.service_identity.service_pk,
        "hostGatewayPk": host_gateway_pk,
        "aliases": ["Logging", "Constitute Logging"],
        "summary": "Structured safe event observation and retention state.",
        "healthNode": "health",
        "updatedAt": now,
        "nodes": [
            {
                "nodeId": "logging.events",
                "path": "events",
                "label": "Events",
                "description": "Policy-materialized safe event stream.",
                "backingChannel": "logging.events",
                "fields": [
                    {
                        "fieldId": "events",
                        "label": "Events",
                        "valueKind": "array",
                        "capabilities": ["read", "observe"]
                    },
                    {
                        "fieldId": "policy",
                        "label": "Policy",
                        "valueKind": "object",
                        "capabilities": ["read", "observe", "set"]
                    }
                ]
            },
            {
                "nodeId": "logging.health",
                "path": "health",
                "label": "Health",
                "description": "Logging service health and storage attachment state.",
                "backingChannel": "logging.health",
                "fields": [
                    {
                        "fieldId": "status",
                        "label": "Status",
                        "valueKind": "string",
                        "capabilities": ["read", "observe"]
                    },
                    {
                        "fieldId": "storageStatus",
                        "label": "Storage",
                        "valueKind": "string",
                        "capabilities": ["read", "observe"]
                    }
                ]
            },
            {
                "nodeId": "logging.dashboard",
                "path": "dashboard",
                "label": "Dashboard",
                "description": "Reduced severity counts, critical shortlist, and coverage.",
                "backingChannel": "logging.dashboard",
                "fields": [
                    {
                        "fieldId": "severityCounts",
                        "label": "Severity Counts",
                        "valueKind": "object",
                        "capabilities": ["read", "observe"]
                    },
                    {
                        "fieldId": "coverage",
                        "label": "Coverage",
                        "valueKind": "object",
                        "capabilities": ["read", "observe"]
                    }
                ]
            },
            {
                "nodeId": "logging.settings",
                "path": "settings",
                "label": "Settings",
                "description": "Requested sync/retention policy knobs.",
                "backingChannel": "logging.events",
                "fields": [
                    {
                        "fieldId": "rollingWindowHours",
                        "label": "Rolling Window Hours",
                        "valueKind": "number",
                        "capabilities": ["read", "observe", "set"]
                    },
                    {
                        "fieldId": "maxVerbosityClass",
                        "label": "Max Verbosity",
                        "valueKind": "string",
                        "capabilities": ["read", "observe", "set"],
                        "schema": { "enum": ["normal", "verbose", "noise"] }
                    }
                ]
            }
        ],
        "diagnostics": []
    });
    Ok(json!({
        "requestId": request_id,
        "channelId": "logging.surface",
        "service": "logging",
        "servicePk": state.service_identity.service_pk,
        "producer": {
            "service": "logging",
            "component": "surface"
        },
        "cursor": {
            "value": format!("surface-{now}"),
            "updatedAt": now
        },
        "freshness": {
            "state": "fresh",
            "updatedAt": now,
            "staleAfter": now + 60
        },
        "scope": {},
        "payloadSchema": "constitute.service.surface.v1",
        "payload": {
            "surface": surface
        },
        "safeFacts": {
            "status": health.status,
            "nodeCount": 4,
            "surfaceChannel": "logging.surface"
        },
        "encryptedDetailRefs": [],
        "diagnostics": []
    }))
    .and_then(|projection| attach_projection_delta(projection, 0, now))
}

fn logging_events_projection(
    state: &ApiState,
    payload: &Value,
    request_id: String,
    now: u64,
) -> Result<Value, ApiError> {
    let base_revision = projection_base_revision(payload);
    let filters = payload
        .get("filters")
        .cloned()
        .filter(|value| value.is_object())
        .unwrap_or_else(|| json!({}));
    let policy = projection_policy(payload, "logging.events", now);
    let mut query: EventSearchQuery = serde_json::from_value(filters.clone()).unwrap_or_default();
    apply_policy_to_query(&policy, &mut query, now);
    let limit = payload
        .get("limit")
        .and_then(|value| value.as_u64())
        .or_else(|| {
            policy
                .get("syncDepthTarget")
                .and_then(|target| target.get("targetCount"))
                .and_then(|value| value.as_u64())
        })
        .map(|value| value.clamp(1, 5000) as usize)
        .or(query.limit)
        .unwrap_or(2500);
    let mut response_query = query.clone();
    response_query.limit = Some(5000);
    let response = state.engine.search(response_query)?;
    let mut scored_events = scored_policy_events(&response.events, &policy);
    scored_events.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .importance_score
            .cmp(&left_score.importance_score)
            .then_with(|| right.occurred_at.cmp(&left.occurred_at))
    });
    let target_count = scored_events.len() as u64;
    let policy_event_refs = scored_events
        .iter()
        .map(|(_, event)| *event)
        .collect::<Vec<_>>();
    let events = scored_events
        .iter()
        .take(limit)
        .map(|(score, event)| annotated_event_value_with_score(event, score))
        .collect::<Vec<_>>();
    let materialized_count = events.len() as u64;
    let oldest_observed = policy_event_refs
        .iter()
        .map(|event| event.occurred_at)
        .min();
    let newest_observed = policy_event_refs
        .iter()
        .map(|event| event.received_at.unwrap_or(event.occurred_at))
        .max();
    let completion_ratio = completion_ratio(materialized_count, target_count);
    let sync_state = if completion_ratio >= 1.0 {
        "completeEnough"
    } else {
        "syncing"
    };
    let cursor = scored_events
        .first()
        .map(|(_, event)| event.event_id.clone())
        .unwrap_or_else(|| format!("empty-{now}"));
    let replay_posture = logging_projection_replay_posture(
        state,
        "logging.events",
        &policy_event_refs,
        materialized_count,
        target_count,
        limit as u64,
        now,
    )?;
    let materialization_budget = logging_projection_materialization_budget(
        state,
        "logging.events",
        &replay_posture,
        materialized_count,
        target_count,
        limit as u64,
        now,
    )?;
    let projection = json!({
        "requestId": request_id,
        "channelId": "logging.events",
        "service": "logging",
        "servicePk": state.service_identity.service_pk,
        "producer": {
            "service": "logging",
            "component": "projection"
        },
        "cursor": {
            "value": cursor,
            "updatedAt": now
        },
        "freshness": {
            "state": "fresh",
            "updatedAt": now,
            "staleAfter": now + 30
        },
        "scope": policy,
        "payloadSchema": "constitute.logging.events.v1",
        "payload": {
            "events": events,
            "policy": policy,
            "coverage": {
                "materializedCount": materialized_count,
                "targetCount": target_count,
                "completionRatio": completion_ratio,
                "completeSeverityBands": complete_severity_bands(&policy_event_refs, materialized_count, target_count),
                "oldestObservedAt": oldest_observed,
                "newestObservedAt": newest_observed,
                "syncState": sync_state
            },
            "replayPosture": replay_posture,
            "materializationBudget": materialization_budget
        },
        "replayPosture": replay_posture,
        "materializationBudget": materialization_budget,
        "safeFacts": {
            "eventCount": materialized_count,
            "targetCount": target_count,
            "completionRatio": completion_ratio,
            "syncState": sync_state,
            "replayState": replay_posture.get("state").cloned().unwrap_or_else(|| json!("unknown")),
            "privacyTier": "safeProjection"
        },
        "encryptedDetailRefs": [],
        "diagnostics": []
    });
    attach_projection_delta(projection, base_revision, now)
}

fn logging_health_projection(
    state: &ApiState,
    request_id: String,
    base_revision: u64,
    now: u64,
) -> Result<Value, ApiError> {
    let storage_status = if state.storage_url.is_some() {
        "configured"
    } else {
        "not_configured"
    };
    let health = state.engine.health(storage_status)?;
    let projection = json!({
        "requestId": request_id,
        "channelId": "logging.health",
        "service": "logging",
        "servicePk": state.service_identity.service_pk,
        "producer": {
            "service": "logging",
            "component": "health"
        },
        "cursor": {
            "value": format!("health-{now}"),
            "updatedAt": now
        },
        "freshness": {
            "state": "fresh",
            "updatedAt": now,
            "staleAfter": now + 30
        },
        "scope": {},
        "payloadSchema": "constitute.logging.health.v1",
        "payload": {
            "health": health
        },
        "safeFacts": {
            "status": health.status,
            "eventCount": health.events,
            "producerCount": health.producers,
            "storageStatus": health.storage_status
        },
        "encryptedDetailRefs": [],
        "diagnostics": []
    });
    attach_projection_delta(projection, base_revision, now)
}

fn logging_dashboard_projection(
    state: &ApiState,
    payload: &Value,
    request_id: String,
    now: u64,
) -> Result<Value, ApiError> {
    let base_revision = projection_base_revision(payload);
    let policy = projection_policy(payload, "logging.dashboard", now);
    let mut query = EventSearchQuery::default();
    apply_policy_to_query(&policy, &mut query, now);
    query.limit = Some(5000);
    let response = state.engine.search(query)?;
    let scored_events = scored_policy_events(&response.events, &policy);
    let target_count = scored_events.len() as u64;
    let policy_event_refs = scored_events
        .iter()
        .map(|(_, event)| *event)
        .collect::<Vec<_>>();
    let mut critical_count = 0u64;
    let mut error_count = 0u64;
    let mut warning_count = 0u64;
    let mut info_count = 0u64;
    let mut materialized_count = 0u64;
    let mut shortlist = Vec::new();
    for (score, event) in scored_events.iter() {
        materialized_count += 1;
        match event.severity {
            LogSeverity::Critical => critical_count += 1,
            LogSeverity::Error => error_count += 1,
            LogSeverity::Warning => warning_count += 1,
            _ => info_count += 1,
        }
        if shortlist.len() < 8
            && matches!(
                event.severity,
                LogSeverity::Critical | LogSeverity::Error | LogSeverity::Warning
            )
        {
            shortlist.push(annotated_event_value_with_score(event, score));
        }
    }
    let health = state.engine.health(if state.storage_url.is_some() {
        "configured"
    } else {
        "not_configured"
    })?;
    let evidence_profile = security_evidence_profile(state, now)?;
    let security_budget = logging_security_evidence_materialization_budget(state, now)?;
    let replay_posture = logging_projection_replay_posture(
        state,
        "logging.dashboard",
        &policy_event_refs,
        materialized_count,
        target_count,
        5000,
        now,
    )?;
    let materialization_budget = logging_projection_materialization_budget(
        state,
        "logging.dashboard",
        &replay_posture,
        materialized_count,
        target_count,
        5000,
        now,
    )?;
    let coverage = json!({
        "materializedCount": materialized_count,
        "targetCount": target_count,
        "completionRatio": completion_ratio(materialized_count, target_count),
        "completeSeverityBands": complete_severity_bands(&policy_event_refs, materialized_count, target_count),
        "oldestObservedAt": policy_event_refs.iter().map(|event| event.occurred_at).min(),
        "newestObservedAt": policy_event_refs.iter().map(|event| event.occurred_at).max(),
        "syncState": if materialized_count >= target_count { "completeEnough" } else { "syncing" }
    });
    let projection = json!({
        "requestId": request_id,
        "channelId": "logging.dashboard",
        "service": "logging",
        "servicePk": state.service_identity.service_pk,
        "producer": {
            "service": "logging",
            "component": "dashboard"
        },
        "cursor": {
            "value": format!("dashboard-{now}"),
            "updatedAt": now
        },
        "freshness": {
            "state": "fresh",
            "updatedAt": now,
            "staleAfter": now + 30
        },
        "scope": policy,
        "payloadSchema": "constitute.logging.dashboard.v1",
        "payload": {
            "severityCounts": {
                "critical": critical_count,
                "error": error_count,
                "warning": warning_count,
                "info": info_count
            },
            "criticalShortlist": shortlist,
            "coverage": coverage,
            "storage": {
                "status": health.storage_status,
                "archiveContainerId": health.archive_container_id
            },
            "evidenceProfiles": [serde_json::to_value(evidence_profile).map_err(anyhow::Error::from)?],
            "evidenceMaterializationBudgets": [serde_json::to_value(security_budget).map_err(anyhow::Error::from)?],
            "replayPosture": replay_posture,
            "materializationBudget": materialization_budget
        },
        "replayPosture": replay_posture,
        "materializationBudget": materialization_budget,
        "safeFacts": {
            "critical": critical_count,
            "error": error_count,
            "warning": warning_count,
            "info": info_count,
            "targetCount": target_count,
            "securityEvidenceProfiles": 1,
            "securityMaterializationBudgets": 1,
            "replayState": replay_posture.get("state").cloned().unwrap_or_else(|| json!("unknown"))
        },
        "encryptedDetailRefs": [],
        "diagnostics": []
    });
    attach_projection_delta(projection, base_revision, now)
}

fn logging_projection_consumer_floor(
    channel_id: &str,
    source_events: &[&LogEventEnvelope],
    materialized_count: u64,
    target_count: u64,
    materialization_id: &str,
    now: u64,
) -> Result<ConsumerFloor, ApiError> {
    let lagging = target_count > materialized_count;
    let cursor = source_events
        .first()
        .map(|event| event.event_id.clone())
        .unwrap_or_else(|| format!("empty-{channel_id}-{now}"));
    let event_time_floor = source_events.iter().map(|event| event.occurred_at).min();
    let observed_time_floor = source_events
        .iter()
        .map(|event| event.received_at.unwrap_or(event.occurred_at))
        .max()
        .or(event_time_floor);
    let floor = ConsumerFloor {
        kind: Some(RECORD_CONSUMER_FLOOR.to_string()),
        floor_id: format!("floor:{materialization_id}"),
        consumer_ref: "runtime.projection.store".to_string(),
        subscription_id: None,
        materialization_id: Some(materialization_id.to_string()),
        subject_ref: Some(channel_id.to_string()),
        cursor: Some(cursor),
        ack_floor: Some(materialized_count.to_string()),
        witness_floor: Some(target_count.to_string()),
        compaction_floor: Some(target_count.saturating_sub(materialized_count).to_string()),
        event_time_floor,
        observed_time_floor,
        lag_state: if lagging { "lagging" } else { "caughtUp" }.to_string(),
        reason: lagging
            .then(|| "materialized projection is behind available event evidence".to_string()),
        redelivery: json!({ "mode": "projection-repair", "duplicatePolicy": "eventId" }),
        replay: json!({ "mode": "boundedProjection", "channelId": channel_id }),
        evidence_refs: Vec::new(),
        sampled_at: now,
        expires_at: Some(now + 60),
    };
    validate_consumer_floor(&floor).map_err(anyhow::Error::from)?;
    Ok(floor)
}

fn logging_projection_replay_posture(
    state: &ApiState,
    channel_id: &str,
    source_events: &[&LogEventEnvelope],
    materialized_count: u64,
    target_count: u64,
    limit: u64,
    now: u64,
) -> Result<Value, ApiError> {
    let materialization_id = format!("logging.service.{channel_id}.projection");
    let floor = logging_projection_consumer_floor(
        channel_id,
        source_events,
        materialized_count,
        target_count,
        &materialization_id,
        now,
    )?;
    let safe_fact_key_count = source_events
        .iter()
        .flat_map(|event| {
            event
                .safe_facts
                .as_object()
                .map(|map| map.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        })
        .collect::<HashSet<_>>()
        .len() as u64;
    let label_value_count = source_events
        .iter()
        .flat_map(|event| event.tags.iter().cloned())
        .collect::<HashSet<_>>()
        .len() as u64;
    let schema_versions = source_events
        .iter()
        .map(|event| event.schema_version.to_string())
        .collect::<HashSet<_>>();
    let encrypted_refs = source_events
        .iter()
        .map(|event| {
            event.encrypted_detail_refs.len() as u64 + u64::from(event.detail_ref.is_some())
        })
        .sum::<u64>();
    let pressure = target_count > limit || safe_fact_key_count > 64 || label_value_count > 250;
    Ok(json!({
        "state": if target_count > materialized_count { "lagging" } else { "caughtUp" },
        "sourceAuthority": format!("service:logging:{}", state.service_identity.service_pk),
        "consumerFloor": floor,
        "bitemporal": {
            "eventTimeFloor": floor.event_time_floor,
            "observedTimeFloor": floor.observed_time_floor
        },
        "schema": {
            "state": if schema_versions.len() <= 1 { "current" } else { "compatible" },
            "versions": schema_versions.into_iter().collect::<Vec<_>>()
        },
        "cardinality": {
            "state": if pressure { "pressure" } else { "withinBudget" },
            "sourceCount": source_events.len(),
            "materializedCount": materialized_count,
            "targetCount": target_count,
            "safeFactKeyCount": safe_fact_key_count,
            "labelValueCount": label_value_count,
            "highCardinalityOverflow": "encryptedDetailRef"
        },
        "privacy": {
            "tiers": ["safeFacts", "safeProjection", "encryptedDetail"],
            "encryptedDetailRefs": encrypted_refs,
            "safeFactsOnly": false
        },
        "sampling": {
            "state": if pressure { "adaptive" } else { "fullWithinWindow" },
            "limit": limit,
            "policy": "severityThenTime"
        }
    }))
}

fn logging_projection_materialization_budget(
    state: &ApiState,
    channel_id: &str,
    replay_posture: &Value,
    materialized_count: u64,
    target_count: u64,
    limit: u64,
    now: u64,
) -> Result<MaterializationBudget, ApiError> {
    let materialization_id = format!("logging.service.{channel_id}.projection");
    let pressure = replay_posture
        .get("cardinality")
        .and_then(|cardinality| cardinality.get("state"))
        .and_then(Value::as_str)
        == Some("pressure");
    let floor: ConsumerFloor = serde_json::from_value(
        replay_posture
            .get("consumerFloor")
            .cloned()
            .unwrap_or_else(|| json!({})),
    )
    .map_err(anyhow::Error::from)?;
    let budget = MaterializationBudget {
        kind: Some(RECORD_MATERIALIZATION_BUDGET.to_string()),
        budget_id: materialization_id,
        source_authority: format!("service:logging:{}", state.service_identity.service_pk),
        consumer_ref: "runtime.projection.store".to_string(),
        subscriber_ref: None,
        payload_class: "projection".to_string(),
        copy_role: "projection".to_string(),
        transfer_mode: "clone".to_string(),
        privacy_tier: Some("safeProjection".to_string()),
        state: if pressure { "pressure" } else { "withinBudget" }.to_string(),
        limits: json!({
            "channelId": channel_id,
            "materializedCount": materialized_count,
            "targetCount": target_count,
            "maxEvents": limit,
            "maxSafeFactKeys": 64,
            "maxLabelValues": 250
        }),
        snapshot_policy: json!({ "mode": "safeProjection", "owner": "logging.service" }),
        delta_policy: json!({ "mode": "projection.delta", "baseRevision": "required" }),
        coalescing: json!({ "key": "eventId", "duplicatePolicy": "replaceLatest" }),
        cardinality: replay_posture
            .get("cardinality")
            .cloned()
            .unwrap_or_else(|| json!({})),
        schema: Some(MaterializationSchemaPosture {
            state: replay_posture
                .get("schema")
                .and_then(|schema| schema.get("state"))
                .and_then(Value::as_str)
                .unwrap_or("current")
                .to_string(),
            version: Some("constitute.logging.projection.v1".to_string()),
            reason: None,
            migration_refs: Vec::new(),
        }),
        consumer_floor: Some(floor),
        reference_refs: Vec::new(),
        blocked_reasons: if pressure {
            vec!["loggingProjectionMaterializationPressure".to_string()]
        } else {
            Vec::new()
        },
        evidence_refs: Vec::new(),
        retention_class: Some("ephemeral.logging-projection".to_string()),
        issued_at: now,
        release_after: Some(now + 60),
        expires_at: Some(now + 5 * 60),
    };
    validate_materialization_budget(&budget).map_err(anyhow::Error::from)?;
    Ok(budget)
}

fn logging_security_evidence_materialization_budget(
    state: &ApiState,
    now: u64,
) -> Result<MaterializationBudget, ApiError> {
    let materialization_id = "logging.security.default.90d".to_string();
    let floor = ConsumerFloor {
        kind: Some(RECORD_CONSUMER_FLOOR.to_string()),
        floor_id: format!("floor:{materialization_id}"),
        consumer_ref: "constitute-security".to_string(),
        subscription_id: None,
        materialization_id: Some(materialization_id.clone()),
        subject_ref: Some("logging.events.encryptedDetail".to_string()),
        cursor: Some(state.engine.archive_container_id()),
        ack_floor: Some("storage-container-ref".to_string()),
        witness_floor: Some("security-profile".to_string()),
        compaction_floor: Some("retention-window:90d".to_string()),
        event_time_floor: None,
        observed_time_floor: Some(now),
        lag_state: "unknown".to_string(),
        reason: None,
        redelivery: json!({ "mode": "authorized-read", "duplicatePolicy": "objectRef" }),
        replay: json!({ "mode": "security-query", "retentionWindow": "90d" }),
        evidence_refs: vec!["logging.security.default".to_string()],
        sampled_at: now,
        expires_at: Some(now + 24 * 60 * 60),
    };
    validate_consumer_floor(&floor).map_err(anyhow::Error::from)?;
    let budget = MaterializationBudget {
        kind: Some(RECORD_MATERIALIZATION_BUDGET.to_string()),
        budget_id: materialization_id,
        source_authority: format!("service:logging:{}", state.service_identity.service_pk),
        consumer_ref: "constitute-security".to_string(),
        subscriber_ref: None,
        payload_class: "retainedRaw".to_string(),
        copy_role: "retention".to_string(),
        transfer_mode: "referenceOnly".to_string(),
        privacy_tier: Some("encryptedDetail".to_string()),
        state: "withinBudget".to_string(),
        limits: json!({
            "retentionWindow": "90d",
            "detailCustody": "encryptedDetailRef",
            "safeIndexRefs": ["logging.events.safeIndex", "logging.dashboard.securitySummary"]
        }),
        snapshot_policy: json!({ "mode": "encrypted-detail-refs-only" }),
        delta_policy: json!({ "mode": "storage-pin-intent" }),
        coalescing: json!({ "key": "encryptedDetailRef" }),
        cardinality: json!({ "rawDetail": "byObjectRef", "safeFacts": "indexedSummary" }),
        schema: Some(MaterializationSchemaPosture {
            state: "current".to_string(),
            version: Some("logging.security.evidence.v1".to_string()),
            reason: None,
            migration_refs: Vec::new(),
        }),
        consumer_floor: Some(floor),
        reference_refs: vec![state.engine.archive_container_id()],
        blocked_reasons: Vec::new(),
        evidence_refs: vec!["logging.security.default".to_string()],
        retention_class: Some("long.security-evidence".to_string()),
        issued_at: now,
        release_after: Some(now + 90 * 24 * 60 * 60),
        expires_at: Some(now + 90 * 24 * 60 * 60),
    };
    validate_materialization_budget(&budget).map_err(anyhow::Error::from)?;
    Ok(budget)
}

fn security_evidence_profile(state: &ApiState, now: u64) -> Result<LogEvidenceProfile, ApiError> {
    let profile = LogEvidenceProfile {
        kind: Some(LOG_EVIDENCE_PROFILE_KIND.to_string()),
        profile_id: "logging.security.default".to_string(),
        consumer_ref: "constitute-security".to_string(),
        event_classes: vec![
            LOG_EVIDENCE_PROFILE_EVENT_SECURITY_AUDIT.to_string(),
            LOG_EVIDENCE_PROFILE_EVENT_RUNTIME_DIAGNOSTIC.to_string(),
            LOG_EVIDENCE_PROFILE_EVENT_SERVICE_EVENT.to_string(),
            LOG_EVIDENCE_PROFILE_EVENT_STORAGE_ACCESS.to_string(),
            LOG_EVIDENCE_PROFILE_EVENT_MEDIA_PATH.to_string(),
        ],
        retention_window: "90d".to_string(),
        safe_index_refs: vec![
            "logging.events.safeIndex".to_string(),
            "logging.dashboard.securitySummary".to_string(),
        ],
        detail_custody: LOG_EVIDENCE_DETAIL_CUSTODY_ENCRYPTED_DETAIL_REF.to_string(),
        encrypted_detail_required: true,
        access_grant_refs: vec!["grant:logging.security.default".to_string()],
        storage_container_refs: vec![state.engine.archive_container_id()],
        materialization_budget_ref: Some("logging.security.default.90d".to_string()),
        issued_at: now,
        expires_at: Some(now + 90 * 24 * 60 * 60),
    };
    validate_log_evidence_profile(&profile).map_err(anyhow::Error::from)?;
    Ok(profile)
}

fn projection_base_revision(payload: &Value) -> u64 {
    payload
        .get("baseRevision")
        .or_else(|| payload.get("currentRevision"))
        .and_then(|value| value.as_u64())
        .unwrap_or(0)
}

fn attach_projection_delta(
    mut projection: Value,
    base_revision: u64,
    now: u64,
) -> Result<Value, ApiError> {
    let delta = projection_delta_for_record(&projection, base_revision, now)?;
    if let Value::Object(map) = &mut projection {
        map.insert("revision".to_string(), json!(delta.revision));
        map.insert("projectionId".to_string(), json!(delta.projection_id));
        map.insert("policyId".to_string(), json!(delta.policy_id));
        map.insert(
            "projectionDelta".to_string(),
            serde_json::to_value(delta).map_err(anyhow::Error::from)?,
        );
    }
    Ok(projection)
}

fn projection_snapshot_for_record(
    projection: &Value,
    now: u64,
) -> Result<SwarmProjectionSnapshot, ApiError> {
    let channel_id = projection
        .get("channelId")
        .and_then(Value::as_str)
        .unwrap_or("logging.unknown");
    let projection_id = projection
        .get("projectionId")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("logging:projection:{channel_id}"));
    let policy_id = projection
        .get("policyId")
        .or_else(|| {
            projection
                .get("scope")
                .and_then(|scope| scope.get("policyId"))
        })
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{channel_id}.current"));
    let revision = projection
        .get("revision")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let snapshot = SwarmProjectionSnapshot {
        projection_id,
        policy_id,
        revision,
        state: projection.clone(),
        coverage: projection
            .get("payload")
            .and_then(|payload| payload.get("coverage"))
            .cloned()
            .unwrap_or_else(|| json!({})),
        freshness: projection
            .get("freshness")
            .cloned()
            .unwrap_or_else(|| json!({})),
        source_refs: projection
            .get("servicePk")
            .and_then(Value::as_str)
            .map(|service_pk| vec![format!("service:{service_pk}")])
            .unwrap_or_default(),
        issued_at: now,
    };
    validate_projection_snapshot(&snapshot).map_err(anyhow::Error::from)?;
    Ok(snapshot)
}

fn projection_delta_for_record(
    projection: &Value,
    base_revision: u64,
    now: u64,
) -> Result<SwarmProjectionDelta, ApiError> {
    let channel_id = projection
        .get("channelId")
        .and_then(|value| value.as_str())
        .unwrap_or("logging.unknown");
    let projection_id = format!("logging:projection:{channel_id}");
    let policy_id = projection
        .get("scope")
        .and_then(|scope| scope.get("policyId"))
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{channel_id}.current"));
    let revision = base_revision.saturating_add(1);
    let mut ops = Vec::new();
    for key in [
        "channelId",
        "service",
        "servicePk",
        "producer",
        "cursor",
        "freshness",
        "scope",
        "payloadSchema",
        "payload",
        "safeFacts",
        "encryptedDetailRefs",
        "diagnostics",
    ] {
        if let Some(value) = projection.get(key) {
            ops.push(ProjectionDeltaOp {
                op: ProjectionDeltaOpKind::Set,
                path: vec![ProjectionPathSegment::Key(key.to_string())],
                value: Some(value.clone()),
            });
        }
    }
    let delta = SwarmProjectionDelta {
        projection_id,
        policy_id,
        base_revision,
        revision,
        ops,
        affected_records: projection_affected_records(projection),
        coverage: projection
            .get("payload")
            .and_then(|payload| payload.get("coverage"))
            .cloned()
            .unwrap_or_else(|| json!({})),
        freshness: projection
            .get("freshness")
            .cloned()
            .unwrap_or_else(|| json!({})),
        source_refs: projection
            .get("servicePk")
            .and_then(|value| value.as_str())
            .map(|service_pk| vec![format!("service:{service_pk}")])
            .unwrap_or_default(),
        issued_at: now,
    };
    validate_projection_delta(&delta, base_revision).map_err(anyhow::Error::from)?;
    Ok(delta)
}

fn projection_affected_records(projection: &Value) -> Vec<Value> {
    let channel_id = projection
        .get("channelId")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if channel_id == "logging.events" {
        return projection
            .get("payload")
            .and_then(|payload| payload.get("events"))
            .and_then(|events| events.as_array())
            .map(|events| {
                events
                    .iter()
                    .filter_map(|event| {
                        event
                            .get("eventId")
                            .and_then(|value| value.as_str())
                            .map(|event_id| {
                                json!({
                                    "recordKind": "logging.event",
                                    "recordId": event_id
                                })
                            })
                    })
                    .collect()
            })
            .unwrap_or_default();
    }
    vec![json!({
        "recordKind": "logging.projection",
        "recordId": channel_id
    })]
}

fn projection_policy(payload: &Value, channel_id: &str, _now: u64) -> Value {
    let mut policy = payload
        .get("policy")
        .cloned()
        .filter(|value| value.is_object())
        .unwrap_or_else(|| json!({}));
    if !policy.is_object() {
        policy = json!({});
    }
    let map = policy.as_object_mut().expect("policy object");
    map.entry("policyId".to_string())
        .or_insert_with(|| json!("logging.default.72h.low"));
    map.insert("channelId".to_string(), json!(channel_id));
    map.entry("service".to_string())
        .or_insert_with(|| json!("logging"));
    map.entry("scope".to_string())
        .or_insert_with(|| json!({ "range": "rolling", "hours": 72 }));
    map.entry("rollingWindowHours".to_string())
        .or_insert_with(|| json!(72));
    map.entry("maxVerbosityClass".to_string())
        .or_insert_with(|| json!("verbose"));
    map.entry("minSeverity".to_string())
        .or_insert_with(|| json!("debug"));
    map.entry("excludedVerbosityClasses".to_string())
        .or_insert_with(|| json!(["noise"]));
    map.entry("syncDepthTarget".to_string())
        .or_insert_with(|| json!({ "mode": "policyComplete", "targetCount": 2500 }));
    map.entry("retentionTarget".to_string()).or_insert_with(|| {
        json!({
            "critical": "forever",
            "errorWarning": "90d",
            "normalInfo": "48h",
            "verboseNoise": "12h"
        })
    });
    policy
}

fn apply_policy_to_query(policy: &Value, query: &mut EventSearchQuery, now: u64) {
    if query.from.is_none() {
        let hours = policy
            .get("rollingWindowHours")
            .and_then(|value| value.as_u64())
            .unwrap_or(24);
        query.from = Some(now.saturating_sub(hours.saturating_mul(60 * 60)));
    }
    if query.limit.is_none() {
        query.limit = policy
            .get("syncDepthTarget")
            .and_then(|target| target.get("targetCount"))
            .and_then(|value| value.as_u64())
            .map(|value| value.clamp(1, 5000) as usize);
    }
}

#[derive(Clone, Copy, Debug)]
struct EventProjectionScore {
    importance_score: i64,
    routine_score: i64,
    frequency: usize,
    verbosity_class: &'static str,
    retention_class: &'static str,
}

fn scored_policy_events<'a>(
    events: &'a [LogEventEnvelope],
    policy: &Value,
) -> Vec<(EventProjectionScore, &'a LogEventEnvelope)> {
    let frequency = event_frequency_map(events);
    events
        .iter()
        .filter_map(|event| {
            let count = frequency
                .get(&event_frequency_key(event))
                .copied()
                .unwrap_or(1);
            let score = event_projection_score(event, count);
            if policy_allows_event_score(policy, event, &score) {
                Some((score, event))
            } else {
                None
            }
        })
        .collect()
}

fn event_frequency_map(events: &[LogEventEnvelope]) -> HashMap<String, usize> {
    let mut frequency = HashMap::new();
    for event in events {
        *frequency.entry(event_frequency_key(event)).or_insert(0) += 1;
    }
    frequency
}

fn event_frequency_key(event: &LogEventEnvelope) -> String {
    let subject = event
        .subject
        .as_ref()
        .map(|subject| {
            format!(
                "{}:{}:{}",
                subject.kind,
                subject.id.as_deref().unwrap_or_default(),
                subject.display.as_deref().unwrap_or_default()
            )
        })
        .unwrap_or_default();
    let resource = event
        .resource
        .as_ref()
        .map(|resource| {
            format!(
                "{}:{}:{}",
                resource.kind,
                resource.id.as_deref().unwrap_or_default(),
                resource.display.as_deref().unwrap_or_default()
            )
        })
        .unwrap_or_default();
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        category_key(&event.category),
        outcome_key(&event.outcome),
        event.producer.service,
        event.producer.component,
        subject,
        resource,
        event.tags.join(",")
    )
}

fn category_key(category: &LogCategory) -> &'static str {
    match category {
        LogCategory::System => "system",
        LogCategory::HostedService => "hostedService",
        LogCategory::GatewayControl => "gatewayControl",
        LogCategory::CameraDevice => "cameraDevice",
        LogCategory::MediaProjection => "mediaProjection",
        LogCategory::Recording => "recording",
        LogCategory::Worker => "worker",
        LogCategory::Storage => "storage",
        LogCategory::Logging => "logging",
        _ => "gatewayControl",
    }
}

fn outcome_key(outcome: &LogOutcome) -> &'static str {
    match outcome {
        LogOutcome::Observed => "observed",
        LogOutcome::Succeeded => "succeeded",
        LogOutcome::Failed => "failed",
        LogOutcome::Denied => "denied",
        LogOutcome::Degraded => "degraded",
        LogOutcome::Recovered => "recovered",
    }
}

fn annotated_event_value_with_score(
    event: &LogEventEnvelope,
    score: &EventProjectionScore,
) -> Value {
    let mut value = serde_json::to_value(event).unwrap_or_else(|_| json!({}));
    if let Value::Object(root) = &mut value {
        let safe_facts = root
            .entry("safeFacts".to_string())
            .or_insert_with(|| json!({}));
        if let Value::Object(map) = safe_facts {
            map.insert("verbosityClass".to_string(), json!(score.verbosity_class));
            map.insert("retentionClass".to_string(), json!(score.retention_class));
            map.insert("importanceScore".to_string(), json!(score.importance_score));
            map.insert("routineScore".to_string(), json!(score.routine_score));
            map.insert("frequencyClass".to_string(), json!(score.frequency));
        }
    }
    value
}

fn policy_allows_event_score(
    policy: &Value,
    event: &LogEventEnvelope,
    score: &EventProjectionScore,
) -> bool {
    let verbosity = score.verbosity_class;
    let excluded = policy
        .get("excludedVerbosityClasses")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if excluded.iter().any(|value| *value == verbosity) {
        return false;
    }
    let max_verbosity = policy
        .get("maxVerbosityClass")
        .and_then(|value| value.as_str())
        .unwrap_or("normal");
    if verbosity_rank(verbosity) > verbosity_rank(max_verbosity) {
        return false;
    }
    let min_severity = policy
        .get("minSeverity")
        .and_then(|value| value.as_str())
        .unwrap_or("info");
    severity_rank(&event.severity) >= severity_rank_str(min_severity)
}

fn event_projection_score(event: &LogEventEnvelope, frequency: usize) -> EventProjectionScore {
    let mut score = match event.severity {
        LogSeverity::Critical => 100,
        LogSeverity::Error => 90,
        LogSeverity::Warning => 70,
        LogSeverity::Notice => 45,
        LogSeverity::Info => 35,
        LogSeverity::Debug => 10,
    };
    if matches!(event.outcome, LogOutcome::Failed | LogOutcome::Denied) {
        score += 20;
    }
    if matches!(event.outcome, LogOutcome::Degraded) {
        score += 10;
    }
    if matches!(
        event.category,
        LogCategory::GatewayControl
            | LogCategory::Storage
            | LogCategory::Logging
            | LogCategory::Worker
    ) {
        score += 5;
    }

    let routine_score = event_routine_score(event, frequency);
    score = (score - routine_score).clamp(0, 120);
    if routine_score >= 70 {
        score = score.min(15);
    }
    let verbosity_class = verbosity_class_for_score(event, routine_score);
    EventProjectionScore {
        importance_score: score,
        routine_score,
        frequency,
        verbosity_class,
        retention_class: retention_class_for_event_score(event, verbosity_class),
    }
}

fn event_routine_score(event: &LogEventEnvelope, frequency: usize) -> i64 {
    if matches!(
        event.severity,
        LogSeverity::Critical | LogSeverity::Error | LogSeverity::Warning
    ) || matches!(
        event.outcome,
        LogOutcome::Failed | LogOutcome::Denied | LogOutcome::Degraded
    ) {
        return 0;
    }

    let mut score = 0i64;
    if matches!(event.category, LogCategory::HostedService) {
        score += 10;
    }
    if event.producer.service == "gateway" {
        score += 15;
    }
    if event.producer.component == "managed" {
        score += 15;
    }
    if event
        .subject
        .as_ref()
        .map(|subject| subject.kind == "service")
        .unwrap_or(false)
    {
        score += 5;
    }
    score += match frequency {
        0 | 1 => 0,
        2..=4 => 10,
        5..=9 => 20,
        10..=24 => 35,
        _ => 50,
    };
    score.clamp(0, 100)
}

fn verbosity_class_for_score(event: &LogEventEnvelope, routine_score: i64) -> &'static str {
    if matches!(
        event.severity,
        LogSeverity::Critical | LogSeverity::Error | LogSeverity::Warning
    ) {
        return "critical";
    }
    if matches!(event.severity, LogSeverity::Debug) {
        return "verbose";
    }
    if matches!(
        event.outcome,
        LogOutcome::Failed | LogOutcome::Denied | LogOutcome::Degraded
    ) {
        return "normal";
    }
    if routine_score >= 70 {
        return "noise";
    }
    if routine_score >= 35 {
        return "verbose";
    }
    "normal"
}

fn retention_class_for_event_score(event: &LogEventEnvelope, verbosity: &str) -> &'static str {
    match event.severity {
        LogSeverity::Critical => "forever",
        LogSeverity::Error => "long",
        LogSeverity::Warning => "rolling",
        LogSeverity::Debug => "ephemeral",
        _ if verbosity == "noise" => "ephemeral",
        _ if verbosity == "verbose" => "rolling",
        _ => "short",
    }
}

fn verbosity_rank(value: &str) -> u8 {
    match value {
        "critical" => 0,
        "normal" => 1,
        "verbose" => 2,
        "noise" => 3,
        _ => 3,
    }
}

fn severity_rank(value: &LogSeverity) -> u8 {
    match value {
        LogSeverity::Debug => 0,
        LogSeverity::Info => 1,
        LogSeverity::Notice => 2,
        LogSeverity::Warning => 3,
        LogSeverity::Error => 4,
        LogSeverity::Critical => 5,
    }
}

fn severity_rank_str(value: &str) -> u8 {
    match value {
        "debug" => 0,
        "info" => 1,
        "notice" => 2,
        "warning" | "warn" => 3,
        "error" => 4,
        "critical" => 5,
        _ => 1,
    }
}

fn completion_ratio(materialized_count: u64, target_count: u64) -> f64 {
    if target_count == 0 {
        return 1.0;
    }
    ((materialized_count as f64) / (target_count as f64)).clamp(0.0, 1.0)
}

fn complete_severity_bands(
    events: &[&LogEventEnvelope],
    materialized_count: u64,
    target_count: u64,
) -> Vec<&'static str> {
    if materialized_count >= target_count {
        return vec!["critical", "error", "warning", "info"];
    }
    let mut bands = Vec::new();
    if events
        .iter()
        .any(|event| matches!(event.severity, LogSeverity::Critical))
    {
        bands.push("critical");
    }
    if events
        .iter()
        .any(|event| matches!(event.severity, LogSeverity::Error))
    {
        bands.push("error");
    }
    if events
        .iter()
        .any(|event| matches!(event.severity, LogSeverity::Warning))
    {
        bands.push("warning");
    }
    bands
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
    archive_events(&state, &producer_id, &events);
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
    archive_events(&state, &producer_id, &response.events);
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

fn archive_events(
    state: &ApiState,
    producer_id: &str,
    events: &[constitute_protocol::LogEventEnvelope],
) {
    if events.is_empty() {
        return;
    }
    let request = match storage_materialize_request_for_events(state, producer_id, events) {
        Ok(request) => request,
        Err(err) => {
            tracing::warn!(error = %err, at = now_seconds(), "logging storage archive request build failed");
            return;
        }
    };
    tracing::info!(
        entries = request.entries.len(),
        pin_intents = request.pin_intents.len(),
        at = now_seconds(),
        "logging archive retention recorded as storage intent payloads; direct storage operator POST is disabled"
    );
}

fn storage_materialize_request_for_events(
    state: &ApiState,
    producer_id: &str,
    events: &[constitute_protocol::LogEventEnvelope],
) -> anyhow::Result<StorageMaterializeRequest> {
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
            detail_ref: event
                .detail_ref
                .clone()
                .or_else(|| event.encrypted_detail_refs.first().cloned()),
            encrypted_detail_refs: encrypted_detail_refs_for_event(event),
            created_at: event.occurred_at,
        })
        .collect::<Vec<_>>();
    let mut pin_intents = Vec::new();
    for event in events {
        pin_intents.extend(archive_pin_intents_for_event(state, event)?);
    }
    Ok(StorageMaterializeRequest {
        entries,
        pin_intents,
    })
}

fn encrypted_detail_refs_for_event(
    event: &constitute_protocol::LogEventEnvelope,
) -> Vec<EncryptedDetailRef> {
    let mut refs = Vec::new();
    let mut seen = HashSet::new();
    let mut push_ref = |detail_ref: &EncryptedDetailRef| {
        let key = format!(
            "{}|{}|{}",
            detail_ref.object_id, detail_ref.container_id, detail_ref.manifest_hash
        );
        if seen.insert(key) {
            refs.push(detail_ref.clone());
        }
    };
    if let Some(detail_ref) = &event.detail_ref {
        push_ref(detail_ref);
    }
    for detail_ref in &event.encrypted_detail_refs {
        push_ref(detail_ref);
    }
    refs
}

fn archive_pin_intents_for_event(
    state: &ApiState,
    event: &constitute_protocol::LogEventEnvelope,
) -> anyhow::Result<Vec<StoragePinIntent>> {
    encrypted_detail_refs_for_event(event)
        .iter()
        .map(|detail_ref| archive_pin_intent_for_detail_ref(state, event, detail_ref))
        .collect()
}

fn archive_pin_intent_for_detail_ref(
    state: &ApiState,
    event: &constitute_protocol::LogEventEnvelope,
    detail_ref: &EncryptedDetailRef,
) -> anyhow::Result<StoragePinIntent> {
    let retention = archive_retention_for_event(event);
    let intent = StoragePinIntent {
        intent_id: format!(
            "logging-archive-pin-{}",
            sha256_hex(format!(
                "{}|{}|{}",
                event.event_id, detail_ref.object_id, detail_ref.manifest_hash
            ))
        ),
        object_refs: vec![detail_ref.object_id.clone()],
        manifest_hash: detail_ref.manifest_hash.clone(),
        desired_replicas: if matches!(event.severity, LogSeverity::Critical | LogSeverity::Error) {
            2
        } else {
            1
        },
        retention,
        authority_refs: vec![format!("service:{}", state.service_identity.service_pk)],
        expires_at: archive_pin_expires_at(event),
    };
    validate_storage_pin_intent(&intent)?;
    Ok(intent)
}

fn archive_retention_for_event(event: &constitute_protocol::LogEventEnvelope) -> String {
    match event.severity {
        LogSeverity::Critical => "forever",
        LogSeverity::Error => "long",
        LogSeverity::Warning | LogSeverity::Notice => "rolling",
        LogSeverity::Debug => "ephemeral",
        LogSeverity::Info => "short",
    }
    .to_string()
}

fn archive_pin_expires_at(event: &constitute_protocol::LogEventEnvelope) -> Option<u64> {
    match event.severity {
        LogSeverity::Critical => None,
        LogSeverity::Error => Some(event.occurred_at.saturating_add(90 * 24 * 60 * 60)),
        LogSeverity::Warning | LogSeverity::Notice => {
            Some(event.occurred_at.saturating_add(30 * 24 * 60 * 60))
        }
        LogSeverity::Info => Some(event.occurred_at.saturating_add(7 * 24 * 60 * 60)),
        LogSeverity::Debug => Some(event.occurred_at.saturating_add(24 * 60 * 60)),
    }
}

fn enum_value(value: &impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProducerEventsRequest, RegisterProducerRequest};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use constitute_protocol::{
        EncryptedDetailRef, LOG_SCHEMA_VERSION, LogCategory, LogCorrelationRef, LogOutcome,
        LogProducerRef, LogRedactionClass, LogSeverity, LogSubjectRef, SWARM_FRAME_VERSION,
        StoragePinProjectionStatus, SwarmFrame, SwarmFrameBody, SwarmFrameKind, SwarmRecordRef,
        ZoneScope, log_event_id, pubkey_from_sk_hex, storage_pin_projection_from_records,
        swarm_frame_id,
    };
    use tower::ServiceExt;

    fn event_at(occurred_at: u64, subject: &str) -> constitute_protocol::LogEventEnvelope {
        let mut event = constitute_protocol::LogEventEnvelope {
            schema_version: LOG_SCHEMA_VERSION,
            event_id: String::new(),
            occurred_at,
            received_at: None,
            producer: LogProducerRef {
                service: "logging-test".to_string(),
                component: "projection".to_string(),
                instance_id: Some("gateway-1".to_string()),
                gateway_pk: None,
                service_pk: None,
            },
            category: LogCategory::Logging,
            severity: LogSeverity::Info,
            outcome: LogOutcome::Observed,
            subject: Some(LogSubjectRef {
                kind: "service".to_string(),
                id: Some(subject.to_string()),
                display: Some(subject.to_string()),
            }),
            resource: None,
            correlation: None,
            tags: vec!["projection-test".to_string()],
            safe_facts: json!({ "subject": subject, "occurredAt": occurred_at }),
            detail_ref: None,
            encrypted_detail_refs: Vec::new(),
            redaction: vec![LogRedactionClass::Safe],
        };
        event.event_id = log_event_id(&event).expect("event id");
        event
    }

    fn routine_gateway_signal_at(
        occurred_at: u64,
        subject: &str,
    ) -> constitute_protocol::LogEventEnvelope {
        let mut event = event_at(occurred_at, subject);
        event.producer.service = "gateway".to_string();
        event.producer.component = "managed".to_string();
        event.category = LogCategory::GatewayControl;
        event.severity = LogSeverity::Info;
        event.outcome = LogOutcome::Observed;
        event.tags = vec!["gateway".to_string(), "projection_signal".to_string()];
        event.safe_facts = json!({
            "subject": subject,
            "occurredAt": occurred_at,
            "signalType": "projection"
        });
        event.event_id = log_event_id(&event).expect("event id");
        event
    }

    struct TestState {
        state: ApiState,
        _dir: tempfile::TempDir,
    }

    impl std::ops::Deref for TestState {
        type Target = ApiState;

        fn deref(&self) -> &Self::Target {
            &self.state
        }
    }

    fn test_state() -> TestState {
        let dir = tempfile::tempdir().expect("tempdir");
        let engine = LoggingEngine::open(dir.path(), "test-archive").expect("engine");
        TestState {
            state: ApiState {
                engine,
                storage_url: None,
                service_identity: LoggingServiceIdentity {
                    service_pk: pubkey_from_sk_hex(&"1".repeat(64)).expect("service pk"),
                    service_sk_hex: "1".repeat(64),
                },
                http: Client::new(),
                caac_fixture_mode: true,
            },
            _dir: dir,
        }
    }

    fn product_state() -> TestState {
        let mut state = test_state();
        state.state.caac_fixture_mode = false;
        state.state.service_identity.service_pk =
            pubkey_from_sk_hex(&state.state.service_identity.service_sk_hex).expect("service pk");
        state
    }

    fn logging_event_frame(event: constitute_protocol::LogEventEnvelope) -> SwarmFrame {
        let now = 1_700_000_000_000;
        let mut frame = SwarmFrame {
            version: SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind: SwarmFrameKind::RecordPublish,
            issuer: "runtime:browser-test".to_string(),
            audience: json!({ "service": "logging" }),
            zone_scope: Some(ZoneScope {
                zone_id: "zone_lab".to_string(),
                privacy: Some("rawIds".to_string()),
                ttl: Some(30),
                max_hops: Some(2),
            }),
            issued_at: now,
            expires_at: None,
            nonce: "nonce-logging-edge-event".to_string(),
            correlation_id: Some("corr-logging-edge-event".to_string()),
            channel_id: Some("logging.events".to_string()),
            record_ref: Some(SwarmRecordRef {
                kind: "logging.event".to_string(),
                id: event.event_id.clone(),
                revision: Some(1),
            }),
            capability: Some("logging.events.ingest".to_string()),
            body: SwarmFrameBody {
                encoding: "caac".to_string(),
                envelope: Some(json!({
                    "envelopeId": "env-logging-edge-event",
                    "shape": "sealed-frame-placeholder",
                    "sealed": true,
                    "sealedPayload": {
                        "producerId": "edge-producer",
                        "baseRevision": 2,
                        "record": event
                    }
                })),
                public_bootstrap: false,
                payload: None,
                signature: Some("fixture-signature-placeholder".to_string()),
            },
            ack: None,
        };
        frame.frame_id = swarm_frame_id(&frame).expect("frame id");
        frame
    }

    fn logging_projection_observe_frame(channel_id: &str) -> SwarmFrame {
        let now = 1_700_000_000_000;
        let mut frame = SwarmFrame {
            version: SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind: SwarmFrameKind::ChannelObserve,
            issuer: "runtime:browser-test".to_string(),
            audience: json!({ "service": "logging" }),
            zone_scope: Some(ZoneScope {
                zone_id: "zone_lab".to_string(),
                privacy: Some("rawIds".to_string()),
                ttl: Some(30),
                max_hops: Some(2),
            }),
            issued_at: now,
            expires_at: Some(now + 60_000),
            nonce: format!("nonce-logging-observe-{channel_id}"),
            correlation_id: Some(format!("corr-logging-observe-{channel_id}")),
            channel_id: Some(channel_id.to_string()),
            record_ref: Some(SwarmRecordRef {
                kind: "projection.snapshot".to_string(),
                id: channel_id.to_string(),
                revision: None,
            }),
            capability: Some(CAPABILITY_PROJECTION_OBSERVE.to_string()),
            body: SwarmFrameBody {
                encoding: "caac".to_string(),
                envelope: Some(json!({
                    "envelopeId": format!("env-logging-observe-{channel_id}"),
                    "shape": "sealed-frame-placeholder",
                    "sealed": true,
                    "sealedPayload": {
                        "requestId": format!("projection-{channel_id}"),
                        "channelId": channel_id,
                        "baseRevision": 0,
                        "limit": 25,
                        "filters": {}
                    }
                })),
                public_bootstrap: false,
                payload: None,
                signature: Some("fixture-signature-placeholder".to_string()),
            },
            ack: None,
        };
        frame.frame_id = swarm_frame_id(&frame).expect("frame id");
        frame
    }

    fn product_logging_event_frame(event: constitute_protocol::LogEventEnvelope) -> SwarmFrame {
        const ISSUER_TEST_SK: &str =
            "2222222222222222222222222222222222222222222222222222222222222222";
        let now = 1_700_000_000_000;
        let envelope = seal_envelope(
            "logging.event",
            &json!({
                "producerId": "edge-producer",
                "baseRevision": 2,
                "record": event
            }),
            ISSUER_TEST_SK,
            &[pubkey_from_sk_hex(&"1".repeat(64)).expect("service pk")],
            now,
            now + 60_000,
        )
        .expect("seal");
        let mut frame = SwarmFrame {
            version: SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind: SwarmFrameKind::RecordPublish,
            issuer: pubkey_from_sk_hex(ISSUER_TEST_SK).expect("issuer pk"),
            audience: json!({ "service": "logging" }),
            zone_scope: Some(ZoneScope {
                zone_id: "zone_lab".to_string(),
                privacy: Some("rawIds".to_string()),
                ttl: Some(30),
                max_hops: Some(2),
            }),
            issued_at: now,
            expires_at: Some(now + 60_000),
            nonce: "nonce-logging-real-caac-event".to_string(),
            correlation_id: Some("corr-logging-real-caac-event".to_string()),
            channel_id: Some("logging.events".to_string()),
            record_ref: Some(SwarmRecordRef {
                kind: "logging.event".to_string(),
                id: "edge-event".to_string(),
                revision: Some(1),
            }),
            capability: Some("logging.events.ingest".to_string()),
            body: SwarmFrameBody {
                encoding: "caac".to_string(),
                envelope: Some(serde_json::to_value(envelope).expect("envelope json")),
                public_bootstrap: false,
                payload: None,
                signature: None,
            },
            ack: None,
        };
        frame.frame_id = swarm_frame_id(&frame).expect("frame id");
        frame
    }

    fn product_runtime_diagnostic_log_frame(
        event: constitute_protocol::LogEventEnvelope,
    ) -> SwarmFrame {
        const ISSUER_TEST_SK: &str =
            "2222222222222222222222222222222222222222222222222222222222222222";
        let now = 1_700_000_000_000;
        let envelope = seal_envelope(
            "logging.event",
            &json!({
                "method": "runtime.diagnostics.log",
                "signalType": "intent",
                "activation": {
                    "kind": "runtime.activation.request",
                    "activationId": "diag-runtime-event",
                    "nodeRef": "runtime.diagnostics",
                    "capabilityRef": "logging.events.ingest"
                },
                "record": {
                    "kind": "runtime.activation.request",
                    "activationId": "diag-runtime-event",
                    "nodeRef": "runtime.diagnostics",
                    "capabilityRef": "logging.events.ingest"
                },
                "payload": {
                    "recordKind": "logging.event",
                    "producerId": "runtime",
                    "record": event
                }
            }),
            ISSUER_TEST_SK,
            &[pubkey_from_sk_hex(&"1".repeat(64)).expect("service pk")],
            now,
            now + 60_000,
        )
        .expect("seal");
        let mut frame = SwarmFrame {
            version: SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind: SwarmFrameKind::RecordPublish,
            issuer: pubkey_from_sk_hex(ISSUER_TEST_SK).expect("issuer pk"),
            audience: json!({ "service": "logging" }),
            zone_scope: Some(ZoneScope {
                zone_id: "zone_lab".to_string(),
                privacy: Some("rawIds".to_string()),
                ttl: Some(30),
                max_hops: Some(2),
            }),
            issued_at: now,
            expires_at: Some(now + 60_000),
            nonce: "nonce-runtime-diagnostic-log".to_string(),
            correlation_id: Some("runtime-diagnostic-correlation".to_string()),
            channel_id: Some("logging.events".to_string()),
            record_ref: Some(SwarmRecordRef {
                kind: "logging.event".to_string(),
                id: event.event_id.clone(),
                revision: Some(1),
            }),
            capability: Some("logging.events.ingest".to_string()),
            body: SwarmFrameBody {
                encoding: "caac".to_string(),
                envelope: Some(serde_json::to_value(envelope).expect("envelope json")),
                public_bootstrap: false,
                payload: None,
                signature: None,
            },
            ack: None,
        };
        frame.frame_id = swarm_frame_id(&frame).expect("frame id");
        frame
    }

    #[tokio::test]
    async fn logging_edge_frame_ingests_event_and_returns_projection_delta() {
        let state = test_state();
        let event = event_at(1_700_000_000, "edge-event");
        let frame = logging_event_frame(event.clone());
        let response = ingest_edge_frame_at(&state.state, frame, 1_700_000_000_000)
            .await
            .expect("edge frame ingest");

        assert_eq!(response["status"], "accepted");
        assert_eq!(response["accepted"], 1);
        assert_eq!(response["channelId"], "logging.events");
        let delta: SwarmProjectionDelta =
            serde_json::from_value(response["projectionDelta"].clone()).expect("delta");
        validate_projection_delta(&delta, 2).expect("valid edge projection delta");
        assert_eq!(delta.projection_id, "logging:projection:logging.events");

        let found = state
            .engine
            .search(EventSearchQuery {
                q: Some("edge-event".to_string()),
                ..Default::default()
            })
            .expect("search");
        assert_eq!(found.events.len(), 1);
        assert_eq!(found.events[0].event_id, event.event_id);
    }

    #[tokio::test]
    async fn logging_edge_rejects_placeholder_caac_outside_fixture_mode() {
        let state = product_state();
        let event = event_at(1_700_000_000, "placeholder-rejected");
        let frame = logging_event_frame(event);
        let err = ingest_edge_frame_at(&state.state, frame, 1_700_000_000_000)
            .await
            .expect_err("placeholder must reject");

        assert!(err.0.to_string().contains("placeholder CAAC"));
    }

    #[tokio::test]
    async fn logging_edge_opens_real_caac_before_reading_event_payload() {
        let state = product_state();
        let event = event_at(1_700_000_000, "real-caac-event");
        let frame = product_logging_event_frame(event.clone());
        let response = ingest_edge_frame_at(&state.state, frame, 1_700_000_000_000)
            .await
            .expect("edge frame ingest");

        assert_eq!(response["status"], "accepted");
        assert_eq!(response["accepted"], 1);
        let found = state
            .engine
            .search(EventSearchQuery {
                q: Some("real-caac-event".to_string()),
                ..Default::default()
            })
            .expect("search");
        assert_eq!(found.events.len(), 1);
        assert_eq!(found.events[0].event_id, event.event_id);
    }

    #[tokio::test]
    async fn logging_edge_opens_runtime_diagnostic_payload_record() {
        let state = product_state();
        let mut event = event_at(1_700_000_000, "runtime-diagnostic-event");
        event.producer.service = "runtime".to_string();
        event.producer.component = "browser-runtime".to_string();
        event.category = LogCategory::Worker;
        event.correlation = Some(LogCorrelationRef {
            correlation_id: "diag-runtime".to_string(),
            causation_id: None,
            trace_id: None,
        });
        event.safe_facts = json!({
            "kind": "route.observation",
            "capabilityRef": "logging.events.ingest",
            "channelRef": "logging.events",
            "correlationId": "diag-runtime"
        });
        event.event_id = log_event_id(&event).expect("event id");
        let frame = product_runtime_diagnostic_log_frame(event.clone());
        let response = ingest_edge_frame_at(&state.state, frame, 1_700_000_000_000)
            .await
            .expect("runtime diagnostic edge frame ingest");

        assert_eq!(response["status"], "accepted");
        assert_eq!(response["accepted"], 1);
        let found = state
            .engine
            .search(EventSearchQuery {
                q: Some("runtime-diagnostic-event".to_string()),
                ..Default::default()
            })
            .expect("search");
        assert_eq!(found.events.len(), 1);
        assert_eq!(found.events[0].event_id, event.event_id);
        assert_eq!(
            found.events[0].safe_facts["capabilityRef"],
            "logging.events.ingest"
        );
    }

    #[tokio::test]
    async fn logging_gateway_stream_frame_ingests_without_http_and_emits_projection_frame() {
        let state = test_state();
        let event = event_at(1_700_000_000, "stream-edge-event");
        let frame = logging_event_frame(event.clone());
        let emitted = process_gateway_frame(&state.state, frame, 1_700_000_000_000)
            .await
            .expect("stream frame");

        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].kind, SwarmFrameKind::ProjectionDelta);
        assert_eq!(emitted[0].channel_id.as_deref(), Some("logging.events"));
        assert_eq!(
            emitted[0]
                .record_ref
                .as_ref()
                .map(|record| record.kind.as_str()),
            Some("projection.delta")
        );
        validate_swarm_frame(&emitted[0], 1_700_000_000_001).expect("valid emitted frame");

        let found = state
            .engine
            .search(EventSearchQuery {
                q: Some("stream-edge-event".to_string()),
                ..Default::default()
            })
            .expect("search");
        assert_eq!(found.events.len(), 1);
        assert_eq!(found.events[0].event_id, event.event_id);
    }

    #[tokio::test]
    async fn logging_gateway_ignores_route_observation_frames() {
        let state = test_state();
        let event = event_at(1_700_000_000, "route-observation");
        let mut frame = logging_event_frame(event);
        frame.channel_id = Some("swarm.route".to_string());
        frame.record_ref = Some(SwarmRecordRef {
            kind: "route.observation".to_string(),
            id: "route-observation".to_string(),
            revision: Some(1),
        });
        frame.frame_id = swarm_frame_id(&frame).expect("frame id");

        let emitted = process_gateway_frame(&state.state, frame, 1_700_000_000_000)
            .await
            .expect("route observation ignored");

        assert!(emitted.is_empty());
        let found = state
            .engine
            .search(EventSearchQuery {
                q: Some("route-observation".to_string()),
                ..Default::default()
            })
            .expect("search");
        assert!(found.events.is_empty());
    }

    #[tokio::test]
    async fn logging_gateway_projection_observe_emits_snapshot_frame() {
        let state = test_state();
        let event = event_at(1_700_000_000, "observe-snapshot-event");
        let ingest_frame = logging_event_frame(event.clone());
        ingest_edge_frame_at(&state.state, ingest_frame, 1_700_000_000_000)
            .await
            .expect("seed event");

        let observe_frame = logging_projection_observe_frame("logging.dashboard");
        let emitted = process_gateway_frame(&state.state, observe_frame, 1_700_000_000_100)
            .await
            .expect("projection observe frame");

        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].kind, SwarmFrameKind::ProjectionSnapshot);
        assert_eq!(emitted[0].channel_id.as_deref(), Some("logging.dashboard"));
        assert_eq!(
            emitted[0]
                .record_ref
                .as_ref()
                .map(|record| record.kind.as_str()),
            Some("projection.snapshot")
        );
        validate_swarm_frame(&emitted[0], 1_700_000_000_101).expect("valid snapshot frame");
    }

    #[tokio::test]
    async fn logging_gateway_stream_frame_emits_storage_pin_intent_for_archived_detail() {
        let state = test_state();
        let mut event = event_at(1_700_000_000, "stream-archive-event");
        event.detail_ref = Some(EncryptedDetailRef {
            object_id: "object-encrypted-detail-edge".to_string(),
            container_id: "gateway-logs".to_string(),
            key_ref: "gateway-logs:key".to_string(),
            manifest_hash: "sha256:edge-detail-manifest".to_string(),
            summary_tags: vec!["logging".to_string(), "archive".to_string()],
        });
        event.encrypted_detail_refs = vec![EncryptedDetailRef {
            object_id: "object-encrypted-detail-secondary".to_string(),
            container_id: "gateway-logs".to_string(),
            key_ref: "gateway-logs:key-secondary".to_string(),
            manifest_hash: "sha256:edge-detail-secondary-manifest".to_string(),
            summary_tags: vec!["logging".to_string(), "debug-detail".to_string()],
        }];
        event.event_id = log_event_id(&event).expect("event id");
        let frame = logging_event_frame(event);
        let emitted = process_gateway_frame(&state.state, frame, 1_700_000_000_000)
            .await
            .expect("stream frame");

        assert_eq!(emitted.len(), 3);
        assert_eq!(emitted[0].kind, SwarmFrameKind::ProjectionDelta);
        assert_eq!(emitted[1].kind, SwarmFrameKind::StoragePinIntent);
        assert_eq!(emitted[1].channel_id.as_deref(), Some("storage.pin.intent"));
        assert_eq!(
            emitted[1]
                .record_ref
                .as_ref()
                .map(|record| record.kind.as_str()),
            Some("storage.pin.intent")
        );
        validate_swarm_frame(&emitted[1], 1_700_000_000_001).expect("valid storage pin frame");
        assert_eq!(emitted[2].kind, SwarmFrameKind::StoragePinIntent);
        validate_swarm_frame(&emitted[2], 1_700_000_000_001)
            .expect("valid secondary storage pin frame");
    }

    #[tokio::test]
    async fn legacy_logging_product_routes_are_not_mounted() {
        let state = test_state();
        let app = router(state.engine.clone(), None, state.service_identity.clone());
        let retired_projection_adapter = format!("/{}-{}", "service", "exchange");
        let retired_local_edge_adapter = format!("/{}{}", "swarm", "/edge");
        for (method, path) in [
            ("POST", retired_projection_adapter.as_str()),
            ("POST", retired_local_edge_adapter.as_str()),
            ("GET", "/v1/watch"),
            ("GET", "/v1/events/search"),
            ("GET", "/v1/timeline"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
        }
    }

    #[test]
    fn events_projection_is_service_owned_projection_record() {
        let state = test_state();
        let projection = logging_events_projection(
            &state,
            &json!({
                "requestId": "projection-test",
                "channelId": "logging.events",
                "limit": 10,
                "filters": {}
            }),
            "projection-test".to_string(),
            1_700_000_000,
        )
        .expect("projection");
        assert_eq!(projection["channelId"], "logging.events");
        assert_eq!(projection["service"], "logging");
        assert_eq!(projection["servicePk"], state.service_identity.service_pk);
        assert!(
            projection["payload"]["events"]
                .as_array()
                .expect("events")
                .is_empty()
        );
        assert_eq!(projection["safeFacts"]["eventCount"], 0);
        assert_eq!(
            projection["materializationBudget"]["kind"],
            "materialization.budget"
        );
        assert_eq!(
            projection["materializationBudget"]["payloadClass"],
            "projection"
        );
        assert_eq!(
            projection["materializationBudget"]["privacyTier"],
            "safeProjection"
        );
        assert_eq!(
            projection["materializationBudget"]["consumerFloor"]["kind"],
            "consumer.floor"
        );
        assert_eq!(projection["replayPosture"]["schema"]["state"], "current");
        assert_eq!(
            projection["replayPosture"]["privacy"]["tiers"][2],
            "encryptedDetail"
        );
        let budget: MaterializationBudget =
            serde_json::from_value(projection["materializationBudget"].clone()).expect("budget");
        validate_materialization_budget(&budget).expect("valid service projection budget");
    }

    #[test]
    fn logging_projection_records_include_protocol_valid_deltas() {
        let state = test_state();
        let events = logging_events_projection(
            &state,
            &json!({
                "requestId": "projection-delta-events",
                "channelId": "logging.events",
                "baseRevision": 7,
                "filters": {}
            }),
            "projection-delta-events".to_string(),
            1_700_000_000,
        )
        .expect("events projection");
        let delta: SwarmProjectionDelta =
            serde_json::from_value(events["projectionDelta"].clone()).expect("events delta");
        validate_projection_delta(&delta, 7).expect("valid events delta");
        assert_eq!(delta.projection_id, "logging:projection:logging.events");
        assert_eq!(delta.revision, 8);
        assert!(delta.ops.iter().any(|op| {
            op.path == vec![ProjectionPathSegment::Key("payload".to_string())] && op.value.is_some()
        }));

        let health =
            logging_health_projection(&state, "projection-health".to_string(), 0, 1_700_000_000)
                .expect("health projection");
        let health_delta: SwarmProjectionDelta =
            serde_json::from_value(health["projectionDelta"].clone()).expect("health delta");
        validate_projection_delta(&health_delta, 0).expect("valid health delta");

        let dashboard = logging_dashboard_projection(
            &state,
            &json!({
                "requestId": "projection-dashboard",
                "channelId": "logging.dashboard",
                "baseRevision": 3
            }),
            "projection-dashboard".to_string(),
            1_700_000_000,
        )
        .expect("dashboard projection");
        let dashboard_delta: SwarmProjectionDelta =
            serde_json::from_value(dashboard["projectionDelta"].clone()).expect("dashboard delta");
        validate_projection_delta(&dashboard_delta, 3).expect("valid dashboard delta");
    }

    #[test]
    fn ingest_rejects_unsafe_safe_facts() {
        let state = test_state();
        state
            .engine
            .register_producer(RegisterProducerRequest {
                producer_id: "gateway".to_string(),
                label: "Gateway".to_string(),
                base_url: String::new(),
                cursor: String::new(),
            })
            .expect("producer");
        let mut event = event_at(1_700_000_000, "unsafe");
        event.safe_facts = json!({
            "service": "logging-test",
            "rawBody": "must not be indexed"
        });
        event.event_id = log_event_id(&event).expect("event id");
        let err = state
            .engine
            .ingest_events(
                "gateway",
                ProducerEventsRequest {
                    cursor: String::new(),
                    events: vec![event],
                },
            )
            .expect_err("unsafe safe facts reject");
        assert!(err.to_string().contains("unsafe log safe fact key"));
        let found = state
            .engine
            .search(EventSearchQuery::default())
            .expect("search");
        assert!(found.events.is_empty());
    }

    #[test]
    fn surface_projection_declares_human_navigable_nodes() {
        let state = test_state();
        let projection = logging_surface_projection(
            &state,
            "gateway-pk",
            "surface-test".to_string(),
            1_700_000_000,
        )
        .expect("surface projection");
        assert_eq!(projection["channelId"], "logging.surface");
        assert_eq!(
            projection["payload"]["surface"]["surfaceId"],
            "logging.surface"
        );
        assert_eq!(
            projection["payload"]["surface"]["hostGatewayPk"],
            "gateway-pk"
        );
        let nodes = projection["payload"]["surface"]["nodes"]
            .as_array()
            .expect("surface nodes");
        assert!(nodes.iter().any(|node| node["path"] == "events"));
        assert!(nodes.iter().any(|node| node["path"] == "health"));
        assert!(nodes.iter().any(|node| node["path"] == "dashboard"));
        assert!(nodes.iter().any(|node| node["path"] == "settings"));
        let settings = nodes
            .iter()
            .find(|node| node["path"] == "settings")
            .expect("settings");
        assert!(
            settings["fields"]
                .as_array()
                .expect("fields")
                .iter()
                .any(|field| field["capabilities"]
                    .as_array()
                    .expect("capabilities")
                    .iter()
                    .any(|capability| capability == "set"))
        );
    }

    #[test]
    fn events_projection_materializes_policy_coverage_without_paging_terms() {
        let state = test_state();
        state
            .engine
            .register_producer(RegisterProducerRequest {
                producer_id: "gateway".to_string(),
                label: "Gateway".to_string(),
                base_url: String::new(),
                cursor: String::new(),
            })
            .expect("producer");
        let events = (0..650)
            .map(|index| event_at(1_700_000_000 - index, &format!("event-{index}")))
            .collect::<Vec<_>>();
        state
            .engine
            .ingest_events(
                "gateway",
                ProducerEventsRequest {
                    cursor: String::new(),
                    events,
                },
            )
            .expect("ingest");

        let first = logging_events_projection(
            &state,
            &json!({
                "requestId": "projection-first",
                "channelId": "logging.events",
                "filters": {},
                "policy": {
                    "policyId": "logging.default.72h.low",
                    "channelId": "logging.events",
                    "service": "logging",
                    "rollingWindowHours": 72,
                    "maxVerbosityClass": "normal",
                    "minSeverity": "debug",
                    "excludedVerbosityClasses": ["noise"],
                    "syncDepthTarget": { "mode": "policyComplete", "targetCount": 2500 },
                    "retentionTarget": { "normalInfo": "48h" }
                }
            }),
            "projection-first".to_string(),
            1_700_000_000,
        )
        .expect("first projection");
        let first_events = first["payload"]["events"].as_array().expect("first events");
        assert_eq!(first_events.len(), 650);
        assert_eq!(first["payload"]["coverage"]["materializedCount"], 650);
        assert_eq!(first["payload"]["coverage"]["targetCount"], 650);
        assert_eq!(first["payload"]["coverage"]["completionRatio"], 1.0);
        assert_eq!(first["payload"]["coverage"]["syncState"], "completeEnough");
        assert!(first["payload"]["coverage"]["requestedLimit"].is_null());
        assert!(first_events[0]["safeFacts"]["verbosityClass"].is_string());
    }

    #[test]
    fn events_projection_low_verbosity_filters_repetitive_routine_control_plane_noise() {
        let state = test_state();
        state
            .engine
            .register_producer(RegisterProducerRequest {
                producer_id: "gateway".to_string(),
                label: "Gateway".to_string(),
                base_url: String::new(),
                cursor: String::new(),
            })
            .expect("producer");
        let mut events = (0..20)
            .map(|index| routine_gateway_signal_at(1_700_000_000 - index, "constitute-logging-ui"))
            .collect::<Vec<_>>();
        events.push(event_at(1_700_000_010, "normal-work"));
        let mut warning = routine_gateway_signal_at(1_700_000_011, "nvr");
        warning.severity = LogSeverity::Warning;
        warning.event_id = log_event_id(&warning).expect("event id");
        events.push(warning);
        state
            .engine
            .ingest_events(
                "gateway",
                ProducerEventsRequest {
                    cursor: String::new(),
                    events,
                },
            )
            .expect("ingest");

        let projection = logging_events_projection(
            &state,
            &json!({
                "requestId": "projection-noise",
                "channelId": "logging.events",
                "filters": {},
                "policy": {
                    "policyId": "logging.default.72h.low",
                    "channelId": "logging.events",
                    "service": "logging",
                    "rollingWindowHours": 72,
                    "maxVerbosityClass": "normal",
                    "minSeverity": "debug",
                    "excludedVerbosityClasses": ["noise"],
                    "syncDepthTarget": { "mode": "policyComplete", "targetCount": 2500 },
                    "retentionTarget": { "normalInfo": "48h" }
                }
            }),
            "projection-noise".to_string(),
            1_700_000_020,
        )
        .expect("projection");
        let returned = projection["payload"]["events"].as_array().expect("events");
        assert_eq!(returned.len(), 2);
        assert!(
            returned
                .iter()
                .any(|event| event["subject"]["display"] == "normal-work")
        );
        assert!(returned.iter().any(|event| event["severity"] == "warning"));
        assert!(
            !returned
                .iter()
                .any(|event| event["subject"]["display"] == "constitute-logging-ui")
        );
        assert_eq!(projection["payload"]["coverage"]["targetCount"], 2);
    }

    #[test]
    fn health_projection_is_service_owned_projection_record() {
        let state = test_state();
        let projection =
            logging_health_projection(&state, "projection-health".to_string(), 0, 1_700_000_000)
                .expect("projection");
        assert_eq!(projection["channelId"], "logging.health");
        assert_eq!(projection["service"], "logging");
        assert_eq!(projection["payload"]["health"]["status"], "ok");
        assert_eq!(projection["safeFacts"]["storageStatus"], "not_configured");
    }

    #[test]
    fn dashboard_projection_reports_policy_severity_counts() {
        let state = test_state();
        state
            .engine
            .register_producer(RegisterProducerRequest {
                producer_id: "gateway".to_string(),
                label: "Gateway".to_string(),
                base_url: String::new(),
                cursor: String::new(),
            })
            .expect("producer");
        let mut critical = event_at(1_700_000_000, "critical");
        critical.severity = LogSeverity::Critical;
        critical.event_id = log_event_id(&critical).expect("event id");
        let events = vec![critical, event_at(1_700_000_001, "normal")];
        state
            .engine
            .ingest_events(
                "gateway",
                ProducerEventsRequest {
                    cursor: String::new(),
                    events,
                },
            )
            .expect("ingest");
        let projection = logging_dashboard_projection(
            &state,
            &json!({
                "requestId": "projection-dashboard",
                "channelId": "logging.dashboard"
            }),
            "projection-dashboard".to_string(),
            1_700_000_010,
        )
        .expect("projection");
        assert_eq!(projection["channelId"], "logging.dashboard");
        assert_eq!(projection["payload"]["severityCounts"]["critical"], 1);
        assert_eq!(
            projection["payload"]["criticalShortlist"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(projection["payload"]["storage"]["status"], "not_configured");
        let profile = &projection["payload"]["evidenceProfiles"][0];
        assert_eq!(profile["kind"], "logging.evidence.profile");
        assert_eq!(profile["consumerRef"], "constitute-security");
        assert_eq!(profile["detailCustody"], "encryptedDetailRef");
        assert_eq!(
            profile["storageContainerRefs"][0],
            state.engine.archive_container_id()
        );
        assert_eq!(projection["safeFacts"]["securityEvidenceProfiles"], 1);
        assert_eq!(projection["safeFacts"]["securityMaterializationBudgets"], 1);
        assert_eq!(
            projection["materializationBudget"]["kind"],
            "materialization.budget"
        );
        assert_eq!(
            projection["replayPosture"]["consumerFloor"]["kind"],
            "consumer.floor"
        );
        let budget: MaterializationBudget =
            serde_json::from_value(projection["materializationBudget"].clone()).expect("budget");
        validate_materialization_budget(&budget).expect("valid dashboard projection budget");
        let security_budget: MaterializationBudget = serde_json::from_value(
            projection["payload"]["evidenceMaterializationBudgets"][0].clone(),
        )
        .expect("security budget");
        validate_materialization_budget(&security_budget).expect("valid security budget");
        assert_eq!(security_budget.payload_class, "retainedRaw");
        assert_eq!(
            security_budget.privacy_tier.as_deref(),
            Some("encryptedDetail")
        );
    }

    #[test]
    fn archive_pin_intent_uses_protocol_record_without_raw_event_bytes() {
        let state = test_state();
        let mut event = event_at(1_700_000_000, "archive");
        event.detail_ref = Some(EncryptedDetailRef {
            object_id: "object-encrypted-detail-1".to_string(),
            container_id: "gateway-logs".to_string(),
            key_ref: "gateway-logs:key".to_string(),
            manifest_hash: "sha256:encrypted-detail-manifest".to_string(),
            summary_tags: vec!["logging".to_string(), "archive".to_string()],
        });
        event.encrypted_detail_refs = vec![EncryptedDetailRef {
            object_id: "object-encrypted-detail-2".to_string(),
            container_id: "gateway-logs".to_string(),
            key_ref: "gateway-logs:key-secondary".to_string(),
            manifest_hash: "sha256:encrypted-detail-manifest-2".to_string(),
            summary_tags: vec!["logging".to_string(), "debug-detail".to_string()],
        }];
        event.event_id = log_event_id(&event).expect("event id");
        let request =
            storage_materialize_request_for_events(&state, "gateway", &[event]).expect("request");
        assert_eq!(request.entries.len(), 1);
        assert_eq!(request.entries[0].encrypted_detail_refs.len(), 2);
        assert_eq!(request.pin_intents.len(), 2);
        let intent = &request.pin_intents[0];
        validate_storage_pin_intent(intent).expect("valid pin intent");
        assert_eq!(intent.object_refs, vec!["object-encrypted-detail-1"]);
        assert_eq!(intent.manifest_hash, "sha256:encrypted-detail-manifest");
        let secondary_intent = &request.pin_intents[1];
        validate_storage_pin_intent(secondary_intent).expect("valid secondary pin intent");
        assert_eq!(
            secondary_intent.object_refs,
            vec!["object-encrypted-detail-2"]
        );
        assert_eq!(
            secondary_intent.manifest_hash,
            "sha256:encrypted-detail-manifest-2"
        );
        let pin_projection = storage_pin_projection_from_records(intent, &[], 1_700_000_000)
            .expect("pin projection");
        assert_eq!(pin_projection.status, StoragePinProjectionStatus::Pending);
        assert_eq!(pin_projection.missing_replicas, intent.desired_replicas);

        let serialized = serde_json::to_string(&request).expect("json");
        assert!(!serialized.contains("raw event body"));
        assert!(!serialized.contains("mediaBytes"));
        assert!(!serialized.contains("blobBytes"));
    }
}
