# constitute-logging

`constitute-logging` is the blind structured logging service for Constitution hosts.

It observes service-owned log surfaces, validates and deduplicates protocol log records, indexes safe facts, writes durable encrypted archives through `constitute-storage`, and serves hot query/watch projections.

It does not decrypt sensitive detail. Producers encrypt sensitive detail before logging sees it; client/device wallets or future explicitly authorized analyzer services handle decrypt/view.

## V1 Surface

- `GET /health`
- `GET /hosted-service.json`
- `POST /v1/producers`
- `POST /v1/producers/{producer_id}/events`
- `GET /v1/events/search`
- `GET /v1/events/{event_id}`
- `GET /v1/timeline`
- `GET /v1/watch`

## Boundaries

- Producers own plaintext context and safe-fact formulation.
- Storage owns transactional encrypted archive/index/pin durability.
- Logging owns observation, validation, dedupe, safe-fact indexing, hot query, timeline, watch, and storage submission.
- Notifications, detection, cybersecurity, and physical-security workflows are downstream consumers.
