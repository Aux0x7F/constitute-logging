use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use constitute_protocol::{LogCategory, LogEventEnvelope, LogOutcome, LogSeverity};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;
use std::collections::HashMap;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::engine::{LoggingEngine, now_seconds};
use crate::identity::LoggingServiceIdentity;
use crate::types::{
    EventSearchQuery, ProducerEventsRequest, ProducerEventsResponse, RegisterProducerRequest,
    StorageMaterializeRequest, StorageMaterializedIndexEntry,
};

#[derive(Clone)]
pub struct ApiState {
    pub engine: LoggingEngine,
    pub storage_url: Option<String>,
    pub service_identity: LoggingServiceIdentity,
    pub http: Client,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceExchangeAdapterRequest {
    #[serde(default)]
    service_capability: String,
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
    };
    Router::new()
        .route("/health", get(health))
        .route("/hosted-service.json", get(hosted_service_manifest))
        .route("/service-exchange", post(service_exchange))
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

async fn hosted_service_manifest(State(state): State<ApiState>) -> impl IntoResponse {
    Json(json!({
        "service": "logging",
        "servicePk": state.service_identity.service_pk,
        "deviceLabel": "Constitute Logging",
        "serviceVersion": env!("CARGO_PKG_VERSION"),
        "apiBaseUrl": "",
        "healthUrl": "/health",
        "appUrl": "/constitute-logging-ui/",
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
        ],
        "transportHints": {
            "frameEndpoint": "/service-exchange"
        },
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

async fn service_exchange(
    State(state): State<ApiState>,
    Json(request): Json<ServiceExchangeAdapterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let frame = request.frame;
    let kind = frame
        .get("kind")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .trim();
    if kind != "service.projection.request" {
        return Err(anyhow::anyhow!("unsupported service exchange frame kind").into());
    }
    let recipient = frame
        .get("recipientServicePk")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .trim();
    if !recipient.is_empty() && recipient != state.service_identity.service_pk.trim() {
        return Err(anyhow::anyhow!("service exchange recipient mismatch").into());
    }
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
        "logging.events" => logging_events_projection(&state, &payload, request_id, now)?,
        "logging.health" => logging_health_projection(&state, request_id, now)?,
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
        "serviceCapabilityAccepted": !request.service_capability.trim().is_empty(),
    })))
}

fn logging_events_projection(
    state: &ApiState,
    payload: &Value,
    request_id: String,
    now: u64,
) -> Result<Value, ApiError> {
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
        .map(|event| event.occurred_at)
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
    Ok(json!({
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
            }
        },
        "safeFacts": {
            "eventCount": materialized_count,
            "targetCount": target_count,
            "completionRatio": completion_ratio,
            "syncState": sync_state
        },
        "encryptedDetailRefs": [],
        "diagnostics": []
    }))
}

fn logging_health_projection(
    state: &ApiState,
    request_id: String,
    now: u64,
) -> Result<Value, ApiError> {
    let storage_status = if state.storage_url.is_some() {
        "configured"
    } else {
        "not_configured"
    };
    let health = state.engine.health(storage_status)?;
    Ok(json!({
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
    }))
}

fn logging_dashboard_projection(
    state: &ApiState,
    payload: &Value,
    request_id: String,
    now: u64,
) -> Result<Value, ApiError> {
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
    let coverage = json!({
        "materializedCount": materialized_count,
        "targetCount": target_count,
        "completionRatio": completion_ratio(materialized_count, target_count),
        "completeSeverityBands": complete_severity_bands(&policy_event_refs, materialized_count, target_count),
        "oldestObservedAt": policy_event_refs.iter().map(|event| event.occurred_at).min(),
        "newestObservedAt": policy_event_refs.iter().map(|event| event.occurred_at).max(),
        "syncState": if materialized_count >= target_count { "completeEnough" } else { "syncing" }
    });
    Ok(json!({
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
            }
        },
        "safeFacts": {
            "critical": critical_count,
            "error": error_count,
            "warning": warning_count,
            "info": info_count,
            "targetCount": target_count
        },
        "encryptedDetailRefs": [],
        "diagnostics": []
    }))
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
        .or_insert_with(|| json!("normal"));
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
        LogCategory::ServiceAccess => "serviceAccess",
        LogCategory::ServiceSignal => "serviceSignal",
        LogCategory::HostedService => "hostedService",
        LogCategory::GatewayControl => "gatewayControl",
        LogCategory::CameraDevice => "cameraDevice",
        LogCategory::MediaProjection => "mediaProjection",
        LogCategory::Recording => "recording",
        LogCategory::Worker => "worker",
        LogCategory::Storage => "storage",
        LogCategory::Logging => "logging",
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
    if matches!(
        event.category,
        LogCategory::ServiceAccess | LogCategory::ServiceSignal
    ) {
        score += 35;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProducerEventsRequest, RegisterProducerRequest};
    use constitute_protocol::{
        LOG_SCHEMA_VERSION, LogCategory, LogOutcome, LogProducerRef, LogRedactionClass,
        LogSeverity, LogSubjectRef, log_event_id,
    };

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
        event.category = LogCategory::ServiceSignal;
        event.severity = LogSeverity::Info;
        event.outcome = LogOutcome::Observed;
        event.tags = vec!["gateway".to_string(), "service_signal".to_string()];
        event.safe_facts = json!({
            "subject": subject,
            "occurredAt": occurred_at,
            "signalType": "service_projection"
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
                    service_pk: "f".repeat(64),
                    service_sk_hex: "1".repeat(64),
                },
                http: Client::new(),
            },
            _dir: dir,
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
        assert_eq!(
            projection["servicePk"],
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        assert!(
            projection["payload"]["events"]
                .as_array()
                .expect("events")
                .is_empty()
        );
        assert_eq!(projection["safeFacts"]["eventCount"], 0);
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
            logging_health_projection(&state, "projection-health".to_string(), 1_700_000_000)
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
    }
}
