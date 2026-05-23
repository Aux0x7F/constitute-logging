// domain-owned-vocabulary: logging.edge.reject swarm.edge.claims
use anyhow::{Context, Result};
use constitute_fabric::{HostFabricMemberContributionSpec, build_host_fabric_member_contribution};
use constitute_protocol::{
    CAPABILITY_SWARM_EDGE_ATTACH, CARRIER_EDGE_ADAPTER_WEB_SOCKET, CARRIER_EDGE_BACKPRESSURE_CLEAR,
    CARRIER_EDGE_SESSION_OPEN, CarrierEdgeSessionEvidence, FABRIC_MEMBER_CONTRIBUTION_RUNNING,
    FABRIC_MEMBER_ROLE_LOGGING_PROCESSOR, HostFabricMemberContribution,
    RECORD_CARRIER_EDGE_SESSION_EVIDENCE, SWARM_EDGE_WIRE_ACCEPT, SWARM_EDGE_WIRE_HELLO,
    SWARM_EDGE_WIRE_RESUME, SWARM_FRAME_VERSION, SWARM_WIRE_FRAME, SwarmAck, SwarmEdgeAccept,
    SwarmEdgeHello, SwarmFrame, SwarmFrameBody, SwarmFrameKind, ZoneScope, seal_envelope,
    swarm_frame_id, validate_carrier_edge_session_evidence,
    validate_host_fabric_member_contribution, validate_swarm_edge_hello, validate_swarm_frame,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use crate::api::{self, ApiState, LOGGING_CHANNELS, LOGGING_EDGE_CAPABILITIES};
use crate::engine::now_millis;

#[derive(Clone, Debug)]
pub struct SwarmEdgeClientConfig {
    pub gateway_endpoint: String,
    pub member_ref: String,
    pub service_pk: String,
    pub service_sk_hex: String,
    pub zone_id: String,
}

#[derive(Clone, Debug, Default)]
pub struct SwarmEdgeClientState {
    pub session_id: Option<String>,
    pub carrier_edge_session_evidence: Option<CarrierEdgeSessionEvidence>,
    pub last_acked_frame_id: Option<String>,
    pub rejects: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum GatewayWireMessage {
    #[serde(rename = "swarm.edge.accept")]
    Accept { accept: SwarmEdgeAccept },
    #[serde(rename = "swarm.edge.resume")]
    Resume { accept: SwarmEdgeAccept },
    #[serde(rename = "swarm.frame")]
    Frame { frame: SwarmFrame },
    #[serde(other)]
    Unsupported,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum ServiceWireMessage<'a> {
    #[serde(rename = "swarm.edge.hello")]
    Hello { hello: &'a SwarmEdgeHello },
    #[serde(rename = "swarm.frame")]
    Frame { frame: &'a SwarmFrame },
}

pub fn build_hello(config: &SwarmEdgeClientConfig, now: u64) -> SwarmEdgeHello {
    let service_ref = format!("service:logging:{}", config.service_pk.trim());
    let fabric_contribution = logging_host_fabric_contribution(config, &service_ref, now)
        .expect("logging host-fabric contribution builds");
    let fabric_contribution_ref = fabric_contribution.contribution_id.clone();
    validate_host_fabric_member_contribution(&fabric_contribution)
        .expect("logging host-fabric contribution is valid");
    let promise_refs = vec![
        service_ref.clone(),
        config.service_pk.trim().to_string(),
        fabric_contribution_ref.clone(),
    ];
    SwarmEdgeHello {
        member_kind: "service".to_string(),
        member_ref: config.member_ref.clone(),
        zone_scope: ZoneScope {
            zone_id: config.zone_id.clone(),
            privacy: Some("rawIds".to_string()),
            ttl: Some(30),
            max_hops: Some(2),
        },
        supported_versions: vec![SWARM_FRAME_VERSION as u32],
        last_acked_frame_id: None,
        last_projection_revisions: json!({}),
        capability_refs: std::iter::once(CAPABILITY_SWARM_EDGE_ATTACH.to_string())
            .chain(
                LOGGING_EDGE_CAPABILITIES
                    .iter()
                    .map(|value| value.to_string()),
            )
            .collect(),
        channel_refs: LOGGING_CHANNELS
            .iter()
            .map(|value| value.to_string())
            .collect(),
        promise_refs: promise_refs.clone(),
        nonce: format!("logging-edge-hello-{now}"),
        issued_at: now,
        expires_at: Some(now + 60_000),
        sealed_claims: SwarmFrameBody {
            encoding: "caac".to_string(),
            envelope: constitute_protocol::seal_envelope(
                "swarm.edge.claims",
                &json!({
                    "service": "logging",
                    "memberRef": config.member_ref.clone(),
                    "serviceRef": service_ref,
                    "servicePk": config.service_pk.clone(),
                    "hostFabricMemberContributionRef": fabric_contribution_ref,
                    "hostFabricMemberContribution": fabric_contribution,
                    "capabilityRefs": LOGGING_EDGE_CAPABILITIES,
                    "channelRefs": LOGGING_CHANNELS,
                    "promiseRefs": promise_refs,
                }),
                &config.service_sk_hex,
                std::slice::from_ref(&config.service_pk),
                now,
                now + 60_000,
            )
            .ok()
            .and_then(|envelope| serde_json::to_value(envelope).ok()),
            public_bootstrap: false,
            payload: None,
            signature: None,
        },
    }
}

fn logging_host_fabric_contribution(
    config: &SwarmEdgeClientConfig,
    service_ref: &str,
    now: u64,
) -> Result<HostFabricMemberContribution> {
    let zone_ref = format!("discovery:{}", config.zone_id.trim());
    let fabric_ref = format!("host-fabric:{}", config.zone_id.trim());
    let evidence_ref = format!("swarm.edge.hello:logging:{now}");
    let contribution = build_host_fabric_member_contribution(HostFabricMemberContributionSpec {
        contribution_id: format!("hostFabric:logging:{}", config.service_pk.trim()),
        fabric_ref,
        host_ref: zone_ref.clone(),
        member_ref: config.member_ref.clone(),
        participant_ref: config.member_ref.clone(),
        role: FABRIC_MEMBER_ROLE_LOGGING_PROCESSOR.to_string(),
        role_ref: format!("role:{FABRIC_MEMBER_ROLE_LOGGING_PROCESSOR}"),
        state: FABRIC_MEMBER_CONTRIBUTION_RUNNING.to_string(),
        contract_ref: service_ref.to_string(),
        subject_ref: service_ref.to_string(),
        module_refs: vec![
            "module:logging-edge-client".to_string(),
            "module:logging-processor".to_string(),
            service_ref.to_string(),
        ],
        source_refs: vec![format!("source:logging:{}", config.service_pk.trim())],
        capability_refs: LOGGING_EDGE_CAPABILITIES
            .iter()
            .map(|value| value.to_string())
            .collect(),
        grant_refs: Vec::new(),
        input_refs: LOGGING_CHANNELS
            .iter()
            .map(|value| value.to_string())
            .collect(),
        output_refs: vec![service_ref.to_string()],
        evidence_refs: vec![evidence_ref],
        lifecycle_plan_refs: Vec::new(),
        release_refs: Vec::new(),
        resource_posture: None,
        blocked_reasons: Vec::new(),
        safe_facts: json!({
            "service": "logging",
            "role": FABRIC_MEMBER_ROLE_LOGGING_PROCESSOR,
            "zoneRef": zone_ref,
        }),
        observed_at: now,
        expires_at: Some(now + 60_000),
    })?;
    validate_host_fabric_member_contribution(&contribution)
        .expect("logging host-fabric contribution is valid");
    Ok(contribution)
}

pub fn validate_hello(hello: &SwarmEdgeHello) -> Result<()> {
    validate_swarm_edge_hello(hello).map_err(Into::into)
}

pub async fn run_swarm_edge_client(state: ApiState, config: SwarmEdgeClientConfig) -> Result<()> {
    loop {
        match run_swarm_edge_client_once(&state, &config).await {
            Ok(()) => tracing::warn!(
                endpoint = %config.gateway_endpoint,
                "logging gateway edge stream closed"
            ),
            Err(err) => tracing::warn!(
                endpoint = %config.gateway_endpoint,
                error = %err,
                "logging gateway edge stream failed"
            ),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn run_swarm_edge_client_once(
    state: &ApiState,
    config: &SwarmEdgeClientConfig,
) -> Result<()> {
    let (ws, _) = connect_async(&config.gateway_endpoint)
        .await
        .with_context(|| format!("connect logging edge client to {}", config.gateway_endpoint))?;
    let (mut sink, mut stream) = ws.split();
    let mut client_state = SwarmEdgeClientState::default();
    let hello = build_hello(&config, now_millis());
    validate_hello(&hello)?;
    let hello_text = serde_json::to_string(&ServiceWireMessage::Hello { hello: &hello })?;
    timeout(
        Duration::from_millis(LOGGING_EDGE_WRITE_TIMEOUT_MS),
        sink.send(Message::Text(hello_text)),
    )
    .await
    .context("timed out sending logging edge hello")??;

    let (frame_tx, mut frame_rx) =
        mpsc::channel::<(SwarmFrame, u64)>(LOGGING_EDGE_FRAME_WORK_QUEUE);
    let (out_tx, mut out_rx) = mpsc::channel::<SwarmFrame>(LOGGING_EDGE_RESPONSE_QUEUE);
    let worker_state = (*state).clone();
    let worker_out = out_tx.clone();
    let frame_worker = tokio::spawn(async move {
        while let Some((frame, now)) = frame_rx.recv().await {
            let frame_id = frame.frame_id.clone();
            match timeout(
                Duration::from_millis(LOGGING_EDGE_FRAME_WORK_TIMEOUT_MS),
                process_gateway_work_frame(&worker_state, frame, now),
            )
            .await
            {
                Ok(frames) => {
                    for frame in frames {
                        if worker_out.send(frame).await.is_err() {
                            return;
                        }
                    }
                }
                Err(_) => {
                    tracing::warn!(
                        frame_id = %frame_id,
                        timeout_ms = LOGGING_EDGE_FRAME_WORK_TIMEOUT_MS,
                        "logging edge worker timed out before service response"
                    );
                }
            }
        }
    });

    let (writer_done_tx, mut writer_done_rx) = oneshot::channel::<()>();
    let frame_writer = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            let frame_id = frame.frame_id.clone();
            let text = match serde_json::to_string(&ServiceWireMessage::Frame { frame: &frame }) {
                Ok(text) => text,
                Err(err) => {
                    tracing::warn!(
                        frame_id = %frame_id,
                        error = %err,
                        "failed to encode logging edge outbound frame"
                    );
                    continue;
                }
            };
            match timeout(
                Duration::from_millis(LOGGING_EDGE_WRITE_TIMEOUT_MS),
                sink.send(Message::Text(text)),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    tracing::warn!(
                        frame_id = %frame_id,
                        error = %err,
                        "failed to send logging edge outbound frame"
                    );
                    break;
                }
                Err(_) => {
                    tracing::warn!(
                        frame_id = %frame_id,
                        timeout_ms = LOGGING_EDGE_WRITE_TIMEOUT_MS,
                        "timed out sending logging edge outbound frame"
                    );
                    break;
                }
            }
        }
        let _ = writer_done_tx.send(());
    });

    loop {
        tokio::select! {
            _ = &mut writer_done_rx => {
                break;
            }
            message = stream.next() => {
                let Some(message) = message else {
                    break;
                };
                let message = message?;
                let Message::Text(text) = message else {
                    continue;
                };
                handle_gateway_text_for_queue(
                    state,
                    &mut client_state,
                    &text,
                    now_millis(),
                    &frame_tx,
                    &out_tx,
                )
                .await?;
            }
        }
    }
    drop(frame_tx);
    drop(out_tx);
    let _ = frame_worker.await;
    let _ = frame_writer.await;
    Ok(())
}

pub async fn handle_gateway_text(
    state: &ApiState,
    client_state: &mut SwarmEdgeClientState,
    text: &str,
    now: u64,
) -> Result<Vec<SwarmFrame>> {
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "logging edge ignored malformed gateway wire json"
            );
            return Ok(Vec::new());
        }
    };
    if wire_kind(&value) == Some(FRAME_WIRE_KIND) {
        let message = match serde_json::from_value::<GatewayWireMessage>(value.clone()) {
            Ok(message) => message,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "logging edge rejected malformed gateway frame wire message"
                );
                return Ok(malformed_wire_reject_frame(
                    state,
                    &value,
                    now,
                    "logging_frame_rejected",
                    &err.to_string(),
                )
                .into_iter()
                .collect());
            }
        };
        return match message {
            GatewayWireMessage::Frame { frame } => {
                handle_gateway_frame(state, client_state, frame, now).await
            }
            _ => Ok(Vec::new()),
        };
    }

    let message: GatewayWireMessage = match serde_json::from_value(value) {
        Ok(message) => message,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "logging edge ignored malformed gateway control wire message"
            );
            return Ok(Vec::new());
        }
    };
    match message {
        GatewayWireMessage::Accept { accept } | GatewayWireMessage::Resume { accept } => {
            note_carrier_edge_accept(client_state, &accept, now)?;
            Ok(Vec::new())
        }
        GatewayWireMessage::Frame { frame } => {
            handle_gateway_frame(state, client_state, frame, now).await
        }
        GatewayWireMessage::Unsupported => Ok(Vec::new()),
    }
}

async fn handle_gateway_text_for_queue(
    state: &ApiState,
    client_state: &mut SwarmEdgeClientState,
    text: &str,
    now: u64,
    frame_tx: &mpsc::Sender<(SwarmFrame, u64)>,
    out_tx: &mpsc::Sender<SwarmFrame>,
) -> Result<()> {
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "logging edge ignored malformed gateway wire json"
            );
            return Ok(());
        }
    };

    if wire_kind(&value) == Some(FRAME_WIRE_KIND) {
        let message = match serde_json::from_value::<GatewayWireMessage>(value.clone()) {
            Ok(message) => message,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "logging edge rejected malformed gateway frame wire message"
                );
                if let Some(frame) = malformed_wire_reject_frame(
                    state,
                    &value,
                    now,
                    "logging_frame_rejected",
                    &err.to_string(),
                ) {
                    try_send_logging_edge_response(out_tx, frame);
                }
                return Ok(());
            }
        };
        if let GatewayWireMessage::Frame { frame } = message {
            admit_logging_gateway_frame(state, client_state, frame, now, frame_tx, out_tx);
        }
        return Ok(());
    }

    let message: GatewayWireMessage = match serde_json::from_value(value) {
        Ok(message) => message,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "logging edge ignored malformed gateway control wire message"
            );
            return Ok(());
        }
    };
    match message {
        GatewayWireMessage::Accept { accept } | GatewayWireMessage::Resume { accept } => {
            note_carrier_edge_accept(client_state, &accept, now)?;
        }
        GatewayWireMessage::Frame { frame } => {
            admit_logging_gateway_frame(state, client_state, frame, now, frame_tx, out_tx);
        }
        GatewayWireMessage::Unsupported => {}
    }
    Ok(())
}

fn admit_logging_gateway_frame(
    state: &ApiState,
    client_state: &mut SwarmEdgeClientState,
    frame: SwarmFrame,
    now: u64,
    frame_tx: &mpsc::Sender<(SwarmFrame, u64)>,
    out_tx: &mpsc::Sender<SwarmFrame>,
) {
    if handle_ack_reject(client_state, &frame) {
        return;
    }
    let frame_id = frame.frame_id.clone();
    match frame_tx.try_send((frame, now)) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full((frame, _)))
        | Err(mpsc::error::TrySendError::Closed((frame, _))) => {
            tracing::warn!(
                frame_id = %frame_id,
                "logging edge frame work queue saturated; rejecting gateway frame before service processing"
            );
            if let Some(reject_frame) = logging_reject_frame(
                state,
                &frame,
                now,
                "logging_edge_overloaded",
                "logging edge work queue saturated before service processing",
            ) {
                try_send_logging_edge_response(out_tx, reject_frame);
            }
        }
    }
}

fn try_send_logging_edge_response(out_tx: &mpsc::Sender<SwarmFrame>, frame: SwarmFrame) {
    let frame_id = frame.frame_id.clone();
    if let Err(err) = out_tx.try_send(frame) {
        tracing::warn!(
            frame_id = %frame_id,
            error = %err,
            "logging edge response queue saturated"
        );
    }
}

pub fn logging_carrier_edge_session_evidence(
    accept: &SwarmEdgeAccept,
    now: u64,
) -> Result<CarrierEdgeSessionEvidence> {
    let member_ref = accept.member_ref.trim();
    let session_id = accept.session_id.trim();
    let service_ref = accept
        .promise_refs
        .iter()
        .map(|reference| reference.trim())
        .find(|reference| reference.starts_with("service:"))
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("service:logging:{member_ref}"));
    let record = CarrierEdgeSessionEvidence {
        kind: Some(RECORD_CARRIER_EDGE_SESSION_EVIDENCE.to_string()),
        evidence_id: format!(
            "carrier-edge-evidence:logging:{}:{}",
            slug(&service_ref),
            slug(session_id)
        ),
        selection_ref: format!("carrier-select:{}:gateway-edge", slug(&service_ref)),
        edge_session_ref: format!("edge-session:{session_id}"),
        adapter_ref: "adapter:gateway-association:websocket".to_string(),
        adapter_kind: CARRIER_EDGE_ADAPTER_WEB_SOCKET.to_string(),
        participant_ref: service_ref.clone(),
        peer_ref: None,
        state: CARRIER_EDGE_SESSION_OPEN.to_string(),
        connection_state: Some("connected".to_string()),
        backpressure_state: Some(CARRIER_EDGE_BACKPRESSURE_CLEAR.to_string()),
        retry_posture: json!({ "state": "notRequired", "retryAfterMs": null }),
        release_posture: json!({ "state": "held", "expiresAt": accept.expires_at }),
        safe_facts: json!({
            "service": "logging",
            "memberKind": accept.member_kind,
            "capabilityCount": accept.capability_refs.len(),
            "channelCount": accept.channel_refs.len(),
            "promiseCount": accept.promise_refs.len(),
            "source": "swarmEdgeAccept"
        }),
        evidence_refs: vec![format!("session:{session_id}"), service_ref],
        blocked_reasons: vec![],
        observed_at: now,
        expires_at: accept.expires_at,
    };
    validate_carrier_edge_session_evidence(&record)?;
    Ok(record)
}

fn note_carrier_edge_accept(
    client_state: &mut SwarmEdgeClientState,
    accept: &SwarmEdgeAccept,
    now: u64,
) -> Result<()> {
    let evidence = logging_carrier_edge_session_evidence(accept, now)?;
    tracing::info!(
        session_id = %accept.session_id,
        adapter_ref = %evidence.adapter_ref,
        carrier_state = %evidence.state,
        "logging carrier edge session open"
    );
    client_state.session_id = Some(accept.session_id.clone());
    client_state.carrier_edge_session_evidence = Some(evidence);
    Ok(())
}

async fn process_gateway_work_frame(
    state: &ApiState,
    frame: SwarmFrame,
    now: u64,
) -> Vec<SwarmFrame> {
    match api::process_gateway_frame(state, frame.clone(), now).await {
        Ok(frames) => frames,
        Err(err) => {
            tracing::warn!(
                frame_id = %frame.frame_id,
                kind = ?frame.kind,
                channel_id = ?frame.channel_id,
                error = %err,
                "logging edge rejected gateway frame without dropping stream"
            );
            logging_reject_frame(
                state,
                &frame,
                now,
                "logging_frame_rejected",
                &err.to_string(),
            )
            .into_iter()
            .collect()
        }
    }
}

pub async fn handle_gateway_frame(
    state: &ApiState,
    client_state: &mut SwarmEdgeClientState,
    frame: SwarmFrame,
    now: u64,
) -> Result<Vec<SwarmFrame>> {
    if handle_ack_reject(client_state, &frame) {
        return Ok(Vec::new());
    }
    match api::process_gateway_frame(state, frame.clone(), now).await {
        Ok(frames) => Ok(frames),
        Err(err) => {
            tracing::warn!(
                frame_id = %frame.frame_id,
                kind = ?frame.kind,
                channel_id = ?frame.channel_id,
                error = %err,
                "logging edge rejected gateway frame without dropping stream"
            );
            Ok(logging_reject_frame(
                state,
                &frame,
                now,
                "logging_frame_rejected",
                &err.to_string(),
            )
            .into_iter()
            .collect())
        }
    }
}

fn handle_ack_reject(client_state: &mut SwarmEdgeClientState, frame: &SwarmFrame) -> bool {
    match frame.kind {
        SwarmFrameKind::Ack => {
            client_state.last_acked_frame_id = frame
                .ack
                .as_ref()
                .and_then(|ack| ack.acked_frame_id.clone())
                .or_else(|| frame.correlation_id.clone());
            true
        }
        SwarmFrameKind::Reject => {
            let reason = frame
                .ack
                .as_ref()
                .and_then(|ack| ack.reason_code.clone())
                .unwrap_or_else(|| "rejected".to_string());
            client_state.rejects.push(reason);
            true
        }
        _ => false,
    }
}

pub fn wire_kind(value: &Value) -> Option<&str> {
    value.get("type").and_then(Value::as_str)
}

fn slug(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

pub const HELLO_WIRE_KIND: &str = SWARM_EDGE_WIRE_HELLO;
pub const ACCEPT_WIRE_KIND: &str = SWARM_EDGE_WIRE_ACCEPT;
pub const RESUME_WIRE_KIND: &str = SWARM_EDGE_WIRE_RESUME;
pub const FRAME_WIRE_KIND: &str = SWARM_WIRE_FRAME;

const REJECT_TTL_MS: u64 = 60_000;
const LOGGING_EDGE_FRAME_WORK_QUEUE: usize = 256;
const LOGGING_EDGE_RESPONSE_QUEUE: usize = 256;
const LOGGING_EDGE_FRAME_WORK_TIMEOUT_MS: u64 = 5_000;
const LOGGING_EDGE_WRITE_TIMEOUT_MS: u64 = 2_000;

fn logging_reject_frame(
    state: &ApiState,
    source_frame: &SwarmFrame,
    now: u64,
    reason_code: &str,
    detail: &str,
) -> Option<SwarmFrame> {
    let recipients = response_recipients(state, Some(source_frame.issuer.as_str()));
    if recipients.is_empty() {
        tracing::warn!(
            frame_id = %source_frame.frame_id,
            "logging edge could not reject frame because no response recipient was recoverable"
        );
        return None;
    }
    let envelope = seal_envelope(
        "logging.edge.reject",
        &json!({
            "reasonCode": reason_code,
            "detail": detail,
            "sourceFrameId": source_frame.frame_id,
        }),
        &state.service_identity.service_sk_hex,
        &recipients,
        now,
        now.saturating_add(REJECT_TTL_MS),
    )
    .ok()?;
    let mut frame = SwarmFrame {
        version: SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: SwarmFrameKind::Reject,
        issuer: format!("service:logging:{}", state.service_identity.service_pk),
        audience: json!({
            "actorRef": source_frame.issuer,
            "serviceRef": format!("service:logging:{}", state.service_identity.service_pk),
        }),
        zone_scope: source_frame.zone_scope.clone(),
        issued_at: now,
        expires_at: Some(now.saturating_add(REJECT_TTL_MS)),
        nonce: format!("logging-reject-{now}-{}", source_frame.frame_id),
        correlation_id: Some(source_frame.frame_id.clone()),
        channel_id: source_frame.channel_id.clone(),
        record_ref: None,
        capability: None,
        body: SwarmFrameBody {
            encoding: "caac".to_string(),
            envelope: Some(serde_json::to_value(envelope).ok()?),
            public_bootstrap: false,
            payload: None,
            signature: None,
        },
        ack: Some(SwarmAck {
            acked_frame_id: None,
            retry_after_ms: None,
            gap_after_frame_ids: vec![],
            reason_code: Some(reason_code.to_string()),
        }),
    };
    frame.frame_id = swarm_frame_id(&frame).ok()?;
    validate_swarm_frame(&frame, now).ok()?;
    Some(frame)
}

fn malformed_wire_reject_frame(
    state: &ApiState,
    wire: &Value,
    now: u64,
    reason_code: &str,
    detail: &str,
) -> Option<SwarmFrame> {
    let frame_value = wire.get("frame")?;
    let source_frame_id = frame_value
        .get("frameId")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("malformed-frame");
    let source_issuer = frame_value
        .get("issuer")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let recipients = response_recipients(state, Some(source_issuer));
    if recipients.is_empty() {
        return None;
    }
    let source_kind = frame_value.get("kind").cloned().unwrap_or(Value::Null);
    let envelope = seal_envelope(
        "logging.edge.reject",
        &json!({
            "reasonCode": reason_code,
            "detail": detail,
            "sourceFrameId": source_frame_id,
            "sourceKind": source_kind,
        }),
        &state.service_identity.service_sk_hex,
        &recipients,
        now,
        now.saturating_add(REJECT_TTL_MS),
    )
    .ok()?;
    let zone_scope = frame_value
        .get("zoneScope")
        .and_then(|value| serde_json::from_value::<ZoneScope>(value.clone()).ok());
    let mut frame = SwarmFrame {
        version: SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: SwarmFrameKind::Reject,
        issuer: format!("service:logging:{}", state.service_identity.service_pk),
        audience: json!({
            "actorRef": source_issuer,
            "serviceRef": format!("service:logging:{}", state.service_identity.service_pk),
        }),
        zone_scope,
        issued_at: now,
        expires_at: Some(now.saturating_add(REJECT_TTL_MS)),
        nonce: format!("logging-reject-{now}-{source_frame_id}"),
        correlation_id: Some(source_frame_id.to_string()),
        channel_id: frame_value
            .get("channelId")
            .and_then(Value::as_str)
            .map(|value| value.to_string()),
        record_ref: None,
        capability: None,
        body: SwarmFrameBody {
            encoding: "caac".to_string(),
            envelope: Some(serde_json::to_value(envelope).ok()?),
            public_bootstrap: false,
            payload: None,
            signature: None,
        },
        ack: Some(SwarmAck {
            acked_frame_id: None,
            retry_after_ms: None,
            gap_after_frame_ids: vec![],
            reason_code: Some(reason_code.to_string()),
        }),
    };
    frame.frame_id = swarm_frame_id(&frame).ok()?;
    validate_swarm_frame(&frame, now).ok()?;
    Some(frame)
}

fn response_recipients(state: &ApiState, issuer: Option<&str>) -> Vec<String> {
    let mut recipients = Vec::new();
    if let Some(issuer) = issuer {
        push_recipient(&mut recipients, issuer.trim());
        if let Some((_, suffix)) = issuer.rsplit_once(':') {
            push_recipient(&mut recipients, suffix.trim());
        }
    }
    if recipients.is_empty() {
        push_recipient(&mut recipients, state.service_identity.service_pk.trim());
    }
    recipients
}

fn push_recipient(recipients: &mut Vec<String>, value: &str) {
    if is_hex_pubkey(value) && !recipients.iter().any(|item| item == value) {
        recipients.push(value.to_string());
    }
}

fn is_hex_pubkey(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use constitute_protocol::{CAPABILITY_PROJECTION_OBSERVE, SwarmAck, pubkey_from_sk_hex};
    use reqwest::Client;

    use crate::engine::LoggingEngine;
    use crate::identity::LoggingServiceIdentity;

    fn test_state() -> (tempfile::TempDir, ApiState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let service_sk_hex = "1".repeat(64);
        let service_pk = pubkey_from_sk_hex(&service_sk_hex).expect("service pk");
        let engine = LoggingEngine::open(dir.path(), "test-archive").expect("engine");
        (
            dir,
            ApiState {
                engine,
                storage_url: None,
                service_identity: LoggingServiceIdentity {
                    service_pk,
                    service_sk_hex,
                },
                http: Client::new(),
                caac_fixture_mode: true,
            },
        )
    }

    #[test]
    fn logging_edge_client_builds_valid_hello_wire_record() {
        let service_pk = pubkey_from_sk_hex(&"1".repeat(64)).expect("service pk");
        let config = SwarmEdgeClientConfig {
            gateway_endpoint: "ws://127.0.0.1:7000/swarm.edge".to_string(),
            member_ref: service_pk.clone(),
            service_pk: service_pk.clone(),
            service_sk_hex: "1".repeat(64),
            zone_id: "zone_lab".to_string(),
        };
        let hello = build_hello(&config, 1_700_000_000_000);

        validate_hello(&hello).expect("valid hello");
        assert_eq!(hello.member_kind, "service");
        assert_eq!(hello.member_ref, service_pk);
        assert!(
            hello
                .supported_versions
                .contains(&(SWARM_FRAME_VERSION as u32))
        );
        assert!(
            hello
                .capability_refs
                .contains(&CAPABILITY_SWARM_EDGE_ATTACH.to_string())
        );
        assert!(
            hello
                .capability_refs
                .contains(&CAPABILITY_PROJECTION_OBSERVE.to_string())
        );
        assert!(
            hello
                .channel_refs
                .contains(&constitute_protocol::PROJECTION_CHANNEL_LOGGING_EVENTS.to_string())
        );
        assert!(
            hello
                .promise_refs
                .contains(&format!("service:logging:{service_pk}"))
        );
        assert!(hello.promise_refs.contains(&service_pk));
        assert!(
            hello
                .promise_refs
                .contains(&format!("hostFabric:logging:{service_pk}"))
        );

        let wire =
            serde_json::to_value(ServiceWireMessage::Hello { hello: &hello }).expect("wire json");
        assert_eq!(wire_kind(&wire), Some(HELLO_WIRE_KIND));
    }

    #[test]
    fn logging_edge_client_materializes_carrier_evidence_from_accept() {
        let service_pk = pubkey_from_sk_hex(&"1".repeat(64)).expect("service pk");
        let config = SwarmEdgeClientConfig {
            gateway_endpoint: "ws://127.0.0.1:7000/swarm.edge".to_string(),
            member_ref: service_pk.clone(),
            service_pk: service_pk.clone(),
            service_sk_hex: "1".repeat(64),
            zone_id: "zone_lab".to_string(),
        };
        let hello = build_hello(&config, 1_700_000_000_000);
        let accept = SwarmEdgeAccept {
            session_id: "edge-logging-1".to_string(),
            member_kind: hello.member_kind.clone(),
            member_ref: hello.member_ref.clone(),
            zone_scope: hello.zone_scope.clone(),
            accepted_version: SWARM_FRAME_VERSION as u32,
            last_acked_frame_id: None,
            last_projection_revisions: json!({}),
            capability_refs: hello.capability_refs.clone(),
            channel_refs: hello.channel_refs.clone(),
            promise_refs: hello.promise_refs.clone(),
            nonce: "accept-logging".to_string(),
            issued_at: 1_700_000_000_010,
            expires_at: Some(1_700_000_060_000),
            sealed_claims: hello.sealed_claims.clone(),
        };
        let evidence = logging_carrier_edge_session_evidence(&accept, 1_700_000_000_011)
            .expect("carrier evidence");
        validate_carrier_edge_session_evidence(&evidence).expect("valid carrier evidence");
        assert_eq!(
            evidence.adapter_ref,
            "adapter:gateway-association:websocket"
        );
        assert_eq!(
            evidence.participant_ref,
            format!("service:logging:{service_pk}")
        );
        assert_eq!(evidence.state, CARRIER_EDGE_SESSION_OPEN);
    }

    #[test]
    fn logging_edge_client_tracks_ack_and_reject_frames() {
        let mut state = SwarmEdgeClientState::default();
        let ack = SwarmFrame {
            version: SWARM_FRAME_VERSION,
            frame_id: "ack-frame".to_string(),
            kind: SwarmFrameKind::Ack,
            issuer: "gateway".to_string(),
            audience: json!({}),
            zone_scope: None,
            issued_at: 1_700_000_000_000,
            expires_at: None,
            nonce: "ack-nonce".to_string(),
            correlation_id: Some("sent-frame".to_string()),
            channel_id: None,
            record_ref: None,
            capability: None,
            body: SwarmFrameBody {
                encoding: "caac".to_string(),
                envelope: Some(json!({ "envelopeId": "ack" })),
                public_bootstrap: false,
                payload: None,
                signature: None,
            },
            ack: Some(SwarmAck {
                acked_frame_id: Some("sent-frame".to_string()),
                retry_after_ms: None,
                gap_after_frame_ids: vec![],
                reason_code: None,
            }),
        };
        assert!(handle_ack_reject(&mut state, &ack));
        assert_eq!(state.last_acked_frame_id.as_deref(), Some("sent-frame"));

        let mut reject = ack;
        reject.kind = SwarmFrameKind::Reject;
        reject.ack.as_mut().expect("ack").acked_frame_id = None;
        reject.ack.as_mut().expect("ack").reason_code = Some("invalid_frame".to_string());
        assert!(handle_ack_reject(&mut state, &reject));
        assert_eq!(state.rejects, vec!["invalid_frame".to_string()]);
    }

    #[tokio::test]
    async fn logging_edge_reader_rejects_when_work_queue_is_saturated() {
        let (_dir, state) = test_state();
        let mut client_state = SwarmEdgeClientState::default();
        let now: u64 = 1_700_000_000_000;
        let issuer = pubkey_from_sk_hex(&"2".repeat(64)).expect("issuer pk");
        let frame = SwarmFrame {
            version: SWARM_FRAME_VERSION,
            frame_id: "logging-overload-source".to_string(),
            kind: SwarmFrameKind::RecordPublish,
            issuer,
            audience: json!({ "service": "logging" }),
            zone_scope: Some(ZoneScope {
                zone_id: "zone_lab".to_string(),
                privacy: Some("rawIds".to_string()),
                ttl: Some(30),
                max_hops: Some(2),
            }),
            issued_at: now,
            expires_at: Some(now + 60_000),
            nonce: "logging-overload-source-nonce".to_string(),
            correlation_id: None,
            channel_id: Some(constitute_protocol::PROJECTION_CHANNEL_LOGGING_EVENTS.to_string()),
            record_ref: None,
            capability: None,
            body: SwarmFrameBody {
                encoding: "caac".to_string(),
                envelope: Some(json!({ "envelopeId": "logging-overload" })),
                public_bootstrap: false,
                payload: None,
                signature: None,
            },
            ack: None,
        };
        let (frame_tx, mut frame_rx) = mpsc::channel::<(SwarmFrame, u64)>(1);
        let (out_tx, mut out_rx) = mpsc::channel::<SwarmFrame>(1);
        frame_tx
            .try_send((frame.clone(), now))
            .expect("fill work queue");

        admit_logging_gateway_frame(&state, &mut client_state, frame, now, &frame_tx, &out_tx);

        assert!(frame_rx.try_recv().is_ok());
        let reject = out_rx.try_recv().expect("overload reject");
        assert_eq!(reject.kind, SwarmFrameKind::Reject);
        assert_eq!(
            reject.correlation_id.as_deref(),
            Some("logging-overload-source")
        );
        assert_eq!(
            reject
                .ack
                .as_ref()
                .and_then(|ack| ack.reason_code.as_deref()),
            Some("logging_edge_overloaded")
        );
        validate_swarm_frame(&reject, now.saturating_add(1)).expect("valid overload reject");
    }

    #[tokio::test]
    async fn malformed_frame_wire_returns_reject_without_dropping_edge_session() {
        let (_dir, state) = test_state();
        let mut client_state = SwarmEdgeClientState::default();
        let now: u64 = 1_700_000_000_000;
        let issuer = pubkey_from_sk_hex(&"2".repeat(64)).expect("issuer pk");
        let wire = json!({
            "type": FRAME_WIRE_KIND,
            "frame": {
                "version": SWARM_FRAME_VERSION,
                "frameId": "legacy-service-signal",
                "kind": "serviceSignal",
                "issuer": issuer,
                "audience": { "service": "logging" },
                "zoneScope": {
                    "zoneId": "zone_lab",
                    "privacy": "rawIds",
                    "ttl": 30,
                    "maxHops": 2
                },
                "issuedAt": now,
                "expiresAt": now + 60_000,
                "nonce": "legacy-service-signal-nonce",
                "channelId": constitute_protocol::PROJECTION_CHANNEL_LOGGING_DASHBOARD,
                "body": {
                    "encoding": "caac",
                    "envelope": { "envelopeId": "legacy" },
                    "publicBootstrap": false
                }
            }
        });

        let responses = handle_gateway_text(
            &state,
            &mut client_state,
            &wire.to_string(),
            now.saturating_add(1),
        )
        .await
        .expect("malformed frame is handled at edge boundary");

        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].kind, SwarmFrameKind::Reject);
        assert_eq!(
            responses[0].correlation_id.as_deref(),
            Some("legacy-service-signal")
        );
        assert_eq!(
            responses[0]
                .ack
                .as_ref()
                .and_then(|ack| ack.reason_code.as_deref()),
            Some("logging_frame_rejected")
        );
        validate_swarm_frame(&responses[0], now.saturating_add(2)).expect("valid reject frame");
    }
}
