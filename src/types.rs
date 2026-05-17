use constitute_protocol::{EncryptedDetailRef, LogEventEnvelope, StoragePinIntent};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterProducerRequest {
    pub producer_id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub cursor: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProducerRecord {
    pub producer_id: String,
    pub label: String,
    pub base_url: String,
    pub cursor: String,
    pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProducerEventsRequest {
    #[serde(default)]
    pub cursor: String,
    pub events: Vec<LogEventEnvelope>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProducerEventsResponse {
    pub producer_id: String,
    pub next_cursor: String,
    pub events: Vec<LogEventEnvelope>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestResponse {
    pub producer_id: String,
    pub accepted: usize,
    pub duplicate: usize,
    pub cursor: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventSearchQuery {
    pub service: Option<String>,
    pub component: Option<String>,
    pub category: Option<String>,
    pub severity: Option<String>,
    pub outcome: Option<String>,
    pub subject: Option<String>,
    pub resource: Option<String>,
    pub tag: Option<String>,
    pub correlation_id: Option<String>,
    pub q: Option<String>,
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventSearchResponse {
    pub events: Vec<LogEventEnvelope>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoggingHealth {
    pub status: String,
    pub events: u64,
    pub producers: u64,
    pub storage_status: String,
    pub archive_container_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoggingWatchEvent {
    pub event_id: String,
    pub kind: String,
    pub at: u64,
    pub producer_id: String,
    pub severity: String,
    pub category: String,
    #[serde(default)]
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageMaterializedIndexEntry {
    pub entry_id: String,
    pub container_id: String,
    pub record_type: String,
    pub subject: String,
    pub priority: String,
    pub tags: Vec<String>,
    pub facts: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_ref: Option<EncryptedDetailRef>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageMaterializeRequest {
    pub entries: Vec<StorageMaterializedIndexEntry>,
    #[serde(default)]
    pub pin_intents: Vec<StoragePinIntent>,
}
