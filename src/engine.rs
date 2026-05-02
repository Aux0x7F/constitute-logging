use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use constitute_protocol::{LogEventEnvelope, validate_log_event};
use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::broadcast;

use crate::types::{
    EventSearchQuery, EventSearchResponse, IngestResponse, LoggingHealth, LoggingWatchEvent,
    ProducerEventsRequest, ProducerRecord, RegisterProducerRequest,
};

#[derive(Clone)]
pub struct LoggingEngine {
    inner: Arc<LoggingEngineInner>,
}

struct LoggingEngineInner {
    db: Mutex<Connection>,
    watch_tx: broadcast::Sender<LoggingWatchEvent>,
    archive_container_id: String,
}

impl LoggingEngine {
    pub fn open(root: impl AsRef<Path>, archive_container_id: impl Into<String>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).context("create logging data dir")?;
        let db = Connection::open(root.join("logging.sqlite3")).context("open logging sqlite")?;
        init_schema(&db)?;
        let (watch_tx, _) = broadcast::channel(512);
        Ok(Self {
            inner: Arc::new(LoggingEngineInner {
                db: Mutex::new(db),
                watch_tx,
                archive_container_id: archive_container_id.into(),
            }),
        })
    }

    pub fn archive_container_id(&self) -> String {
        self.inner.archive_container_id.clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LoggingWatchEvent> {
        self.inner.watch_tx.subscribe()
    }

    pub fn health(&self, storage_status: impl Into<String>) -> Result<LoggingHealth> {
        let db = self.lock_db()?;
        Ok(LoggingHealth {
            status: "ok".to_string(),
            events: count_table(&db, "events")?,
            producers: count_table(&db, "producers")?,
            storage_status: storage_status.into(),
            archive_container_id: self.archive_container_id(),
        })
    }

    pub fn register_producer(&self, request: RegisterProducerRequest) -> Result<ProducerRecord> {
        if request.producer_id.trim().is_empty() {
            return Err(anyhow!("producer id is required"));
        }
        let record = ProducerRecord {
            producer_id: request.producer_id.trim().to_string(),
            label: request.label,
            base_url: request.base_url,
            cursor: request.cursor,
            updated_at: now_seconds(),
        };
        let db = self.lock_db()?;
        db.execute(
            "insert or replace into producers (producer_id, label, base_url, cursor, updated_at) values (?1, ?2, ?3, ?4, ?5)",
            params![
                record.producer_id,
                record.label,
                record.base_url,
                record.cursor,
                record.updated_at
            ],
        )?;
        Ok(record)
    }

    pub fn producer(&self, producer_id: &str) -> Result<ProducerRecord> {
        let db = self.lock_db()?;
        db.query_row(
            "select producer_id, label, base_url, cursor, updated_at from producers where producer_id = ?1",
            params![producer_id],
            |row| {
                Ok(ProducerRecord {
                    producer_id: row.get(0)?,
                    label: row.get(1)?,
                    base_url: row.get(2)?,
                    cursor: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| anyhow!("producer not found"))
    }

    pub fn ingest_events(
        &self,
        producer_id: &str,
        request: ProducerEventsRequest,
    ) -> Result<IngestResponse> {
        let mut accepted = 0usize;
        let mut duplicate = 0usize;
        let mut cursor = request.cursor;
        for mut event in request.events {
            if event.received_at.is_none() {
                event.received_at = Some(now_seconds());
            }
            validate_log_event(&event)?;
            if self.insert_event(producer_id, &event)? {
                accepted += 1;
                cursor = event.event_id.clone();
                self.emit(producer_id, &event);
            } else {
                duplicate += 1;
            }
        }
        self.update_cursor(producer_id, &cursor)?;
        Ok(IngestResponse {
            producer_id: producer_id.to_string(),
            accepted,
            duplicate,
            cursor,
        })
    }

    pub fn get_event(&self, event_id: &str) -> Result<LogEventEnvelope> {
        let db = self.lock_db()?;
        let event_json: String = db
            .query_row(
                "select event_json from events where event_id = ?1",
                params![event_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| anyhow!("log event not found"))?;
        Ok(serde_json::from_str(&event_json)?)
    }

    pub fn search(&self, query: EventSearchQuery) -> Result<EventSearchResponse> {
        let limit = query.limit.unwrap_or(100).clamp(1, 1000);
        let db = self.lock_db()?;
        let mut stmt = db.prepare("select event_json from events order by occurred_at desc")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut events = Vec::new();
        for row in rows {
            let event: LogEventEnvelope = serde_json::from_str(&row?)?;
            if matches_query(&event, &query) {
                events.push(event);
                if events.len() >= limit {
                    break;
                }
            }
        }
        Ok(EventSearchResponse { events })
    }

    fn insert_event(&self, producer_id: &str, event: &LogEventEnvelope) -> Result<bool> {
        let db = self.lock_db()?;
        let subject = event
            .subject
            .as_ref()
            .and_then(|subject| subject.id.clone().or_else(|| subject.display.clone()))
            .unwrap_or_default();
        let resource = event
            .resource
            .as_ref()
            .and_then(|resource| resource.id.clone().or_else(|| resource.display.clone()))
            .unwrap_or_default();
        let correlation_id = event
            .correlation
            .as_ref()
            .map(|correlation| correlation.correlation_id.clone())
            .unwrap_or_default();
        let changed = db.execute(
            "insert or ignore into events (
                event_id, producer_id, occurred_at, received_at, service, component, category,
                severity, outcome, subject, resource, correlation_id, tags_json, safe_facts_json,
                detail_ref_json, event_json
            ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                event.event_id,
                producer_id,
                event.occurred_at,
                event.received_at.unwrap_or_default(),
                event.producer.service,
                event.producer.component,
                serde_json::to_string(&event.category)?,
                serde_json::to_string(&event.severity)?,
                serde_json::to_string(&event.outcome)?,
                subject,
                resource,
                correlation_id,
                serde_json::to_string(&event.tags)?,
                serde_json::to_string(&event.safe_facts)?,
                serde_json::to_string(&event.detail_ref)?,
                serde_json::to_string(event)?,
            ],
        )?;
        Ok(changed > 0)
    }

    fn update_cursor(&self, producer_id: &str, cursor: &str) -> Result<()> {
        let db = self.lock_db()?;
        db.execute(
            "update producers set cursor = ?1, updated_at = ?2 where producer_id = ?3",
            params![cursor, now_seconds(), producer_id],
        )?;
        Ok(())
    }

    fn emit(&self, producer_id: &str, event: &LogEventEnvelope) {
        let _ = self.inner.watch_tx.send(LoggingWatchEvent {
            event_id: event.event_id.clone(),
            kind: "log.event".to_string(),
            at: event.received_at.unwrap_or(event.occurred_at),
            producer_id: producer_id.to_string(),
            severity: enum_value(&event.severity),
            category: enum_value(&event.category),
            message: event
                .subject
                .as_ref()
                .and_then(|subject| subject.display.clone())
                .unwrap_or_else(|| event.producer.service.clone()),
        });
    }

    fn lock_db(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.inner
            .db
            .lock()
            .map_err(|_| anyhow!("logging sqlite lock poisoned"))
    }
}

fn matches_query(event: &LogEventEnvelope, query: &EventSearchQuery) -> bool {
    if let Some(from) = query.from
        && event.occurred_at < from
    {
        return false;
    }
    if let Some(to) = query.to
        && event.occurred_at > to
    {
        return false;
    }
    if !matches_opt(&event.producer.service, &query.service) {
        return false;
    }
    if !matches_opt(&event.producer.component, &query.component) {
        return false;
    }
    if !matches_opt(&enum_value(&event.category), &query.category) {
        return false;
    }
    if !matches_opt(&enum_value(&event.severity), &query.severity) {
        return false;
    }
    if !matches_opt(&enum_value(&event.outcome), &query.outcome) {
        return false;
    }
    if let Some(subject) = &query.subject {
        let hay = event
            .subject
            .as_ref()
            .map(|subject| {
                format!(
                    "{} {} {}",
                    subject.kind,
                    subject.id.clone().unwrap_or_default(),
                    subject.display.clone().unwrap_or_default()
                )
            })
            .unwrap_or_default();
        if !hay.contains(subject) {
            return false;
        }
    }
    if let Some(resource) = &query.resource {
        let hay = event
            .resource
            .as_ref()
            .map(|resource| {
                format!(
                    "{} {} {}",
                    resource.kind,
                    resource.id.clone().unwrap_or_default(),
                    resource.display.clone().unwrap_or_default()
                )
            })
            .unwrap_or_default();
        if !hay.contains(resource) {
            return false;
        }
    }
    if let Some(tag) = &query.tag
        && !event.tags.iter().any(|item| item == tag)
    {
        return false;
    }
    if let Some(correlation_id) = &query.correlation_id {
        if event
            .correlation
            .as_ref()
            .map(|correlation| &correlation.correlation_id)
            != Some(correlation_id)
        {
            return false;
        }
    }
    if let Some(q) = &query.q {
        let hay = serde_json::to_string(event).unwrap_or_default();
        if !hay.to_ascii_lowercase().contains(&q.to_ascii_lowercase()) {
            return false;
        }
    }
    true
}

fn matches_opt(value: &str, expected: &Option<String>) -> bool {
    expected
        .as_ref()
        .map(|expected| value.eq_ignore_ascii_case(expected))
        .unwrap_or(true)
}

fn enum_value(value: &impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_default()
}

fn init_schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        r#"
        create table if not exists producers (
            producer_id text primary key,
            label text not null,
            base_url text not null,
            cursor text not null,
            updated_at integer not null
        );
        create table if not exists events (
            event_id text primary key,
            producer_id text not null,
            occurred_at integer not null,
            received_at integer not null,
            service text not null,
            component text not null,
            category text not null,
            severity text not null,
            outcome text not null,
            subject text not null,
            resource text not null,
            correlation_id text not null,
            tags_json text not null,
            safe_facts_json text not null,
            detail_ref_json text not null,
            event_json text not null
        );
        create index if not exists idx_events_time on events (occurred_at desc);
        create index if not exists idx_events_service on events (service);
        create index if not exists idx_events_category on events (category);
        create index if not exists idx_events_severity on events (severity);
        create index if not exists idx_events_correlation on events (correlation_id);
        "#,
    )?;
    Ok(())
}

fn count_table(db: &Connection, table: &str) -> Result<u64> {
    let sql = format!("select count(*) from {table}");
    Ok(db.query_row(&sql, [], |row| row.get::<_, u64>(0))?)
}

pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use constitute_protocol::{
        LOG_SCHEMA_VERSION, LogCategory, LogCorrelationRef, LogOutcome, LogProducerRef,
        LogRedactionClass, LogSeverity, LogSubjectRef, log_event_id,
    };
    use serde_json::json;

    fn event(service: &str) -> LogEventEnvelope {
        let mut event = LogEventEnvelope {
            schema_version: LOG_SCHEMA_VERSION,
            event_id: String::new(),
            occurred_at: 1_700_000_000,
            received_at: None,
            producer: LogProducerRef {
                service: "gateway".to_string(),
                component: "managed".to_string(),
                instance_id: Some("gateway-1".to_string()),
                gateway_pk: None,
                service_pk: None,
            },
            category: LogCategory::ServiceAccess,
            severity: LogSeverity::Info,
            outcome: LogOutcome::Succeeded,
            subject: Some(LogSubjectRef {
                kind: "service".to_string(),
                id: Some(service.to_string()),
                display: Some("Security Cameras".to_string()),
            }),
            resource: None,
            correlation: Some(LogCorrelationRef {
                correlation_id: "corr-1".to_string(),
                causation_id: None,
                trace_id: None,
            }),
            tags: vec!["service-access".to_string()],
            safe_facts: json!({ "service": service, "operation": "request" }),
            detail_ref: None,
            redaction: vec![LogRedactionClass::Safe],
        };
        event.event_id = log_event_id(&event).expect("event id");
        event
    }

    #[test]
    fn ingests_and_searches_events() {
        let dir = tempfile::tempdir().expect("tempdir");
        let engine = LoggingEngine::open(dir.path(), "gateway-logs").expect("engine");
        engine
            .register_producer(RegisterProducerRequest {
                producer_id: "gateway".to_string(),
                label: "Gateway".to_string(),
                base_url: String::new(),
                cursor: String::new(),
            })
            .expect("producer");
        let response = engine
            .ingest_events(
                "gateway",
                ProducerEventsRequest {
                    cursor: String::new(),
                    events: vec![event("nvr")],
                },
            )
            .expect("ingest");
        assert_eq!(response.accepted, 1);
        let found = engine
            .search(EventSearchQuery {
                service: Some("gateway".to_string()),
                tag: Some("service-access".to_string()),
                ..Default::default()
            })
            .expect("search");
        assert_eq!(found.events.len(), 1);
    }

    #[test]
    fn deduplicates_event_ids() {
        let dir = tempfile::tempdir().expect("tempdir");
        let engine = LoggingEngine::open(dir.path(), "gateway-logs").expect("engine");
        let event = event("nvr");
        let response = engine
            .ingest_events(
                "gateway",
                ProducerEventsRequest {
                    cursor: String::new(),
                    events: vec![event.clone(), event],
                },
            )
            .expect("ingest");
        assert_eq!(response.accepted, 1);
        assert_eq!(response.duplicate, 1);
    }
}
