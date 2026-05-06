# constitute-logging Architecture

`constitute-logging` is a gateway-hosted observability capability.

## Owns

- Cursor-based observation of producer-owned logging surfaces.
- Protocol log envelope validation.
- Event deduplication by event id.
- Safe-fact normalization and indexing.
- Service-owned virtual event/dashboard projections.
- Semantic sync priority and coverage reporting.
- Semantic retention policy for log records and encrypted detail refs.
- Watch stream for service-side observers.
- Durable archive submission to `constitute-storage`.
- Hosted-service manifest and health projection.

## Does Not Own

- Plaintext diagnostic detail.
- Key wallets or long-lived secret custody.
- Producer safe-fact formulation.
- Generic storage object/pin/prune mechanics.
- Detection, alerting, cybersecurity, or physical-security interpretation.
- Host/service lifecycle execution or remediation.
- UI rendering.
- Browser account/runtime projection storage.
- Browser-facing service access orchestration.

## Producer Contract

Producers expose durable cursor-based event surfaces.
Each event is a `constitute-protocol` log envelope with:

- searchable safe facts
- producer/service/resource references
- category, severity, outcome, and correlation data
- optional encrypted detail ref

Sensitive payloads, credentials, CAAC request bodies, service capability values, decrypted request bodies, raw secret material, credential-bearing URLs, and worker argv secrets are never safe facts.

## Projection And Sync Contract

`logging.events` is a virtual materialized projection, not a newest-N query.
Logging owns the projection semantics and the sync plan for a requested policy.
Runtime asks for a policy scope; Logging decides which events satisfy that scope and which records are most valuable to synchronize first.

Default policy:
- rolling 72h
- low verbosity
- no hard severity floor
- critical/error/warn prioritized first by service-side scoring
- normal info included while current volume is small
- repetitive expected info events classified as `noise` and excluded unless enabled

Importance is a service-side feature score, not a UI filter. The score combines severity, outcome, category, producer/component role, subject/resource shape, and frequency of similar records within the current policy candidate set. Routine high-frequency control-plane observations fall to `verbose` or `noise`; failures, degraded states, warnings, errors, and criticals stay visible even when they share the same producer shape.

`logging.dashboard` is a reduced projection for operator summary facts such as severity counts, critical/error shortlist, current degraded producers/services, sync coverage, and storage/archive status.

## Storage Contract

Logging archives per gateway by default.
Storage receives encrypted archive objects, encrypted index shards, availability refs, and pin offers.
Storage does not observe services directly, does not decrypt log detail, and does not understand log severity or verbosity.
Logging translates semantic retention policy into storage pin/lease behavior.

Cybersecurity may request security evidence retention through Logging policy, but Logging remains the generic event truth/archive capability. Host-security inputs such as fail2ban, AppArmor/SELinux, auth/sudo/audit, firewall posture, exposed ports, service hardening drift, and suspicious service behavior are log sources/facts here; cybersecurity interpretation belongs to `constitute-cybersec`, and privileged remediation belongs to `constitute-service-manager`.

## Browser Access Boundary

`constitute-logging` owns service projection exchange for Logging data.

First-party browser apps consume logging through account-runtime projections:
- `logging.events`
- `logging.health`

When projections are missing or stale, account/runtime requests service-owned CAAC projection exchange. Gateway routes and attests the exchange but does not query Logging-specific APIs or reshape payloads.

Browser apps, Gateway adapters, and future CLI clients must not use raw logging service URLs as their architecture. Temporary HTTP/WebSocket endpoints may exist only as internal or smoke-test transport scaffolding below the protocol boundary.
