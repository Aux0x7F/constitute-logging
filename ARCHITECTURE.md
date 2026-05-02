# constitute-logging Architecture

`constitute-logging` is a gateway-hosted observability capability.

## Owns

- Cursor-based observation of producer-owned logging surfaces.
- Protocol log envelope validation.
- Event deduplication by event id.
- Safe-fact normalization and indexing.
- Hot local query and timeline projections.
- Watch stream for live operator views.
- Durable archive submission to `constitute-storage`.
- Hosted-service manifest and health projection.

## Does Not Own

- Plaintext diagnostic detail.
- Key wallets or long-lived secret custody.
- Producer safe-fact formulation.
- Storage object/pin/prune policy.
- Detection, alerting, cybersecurity, or physical-security interpretation.
- UI rendering.

## Producer Contract

Producers expose durable cursor-based event surfaces.
Each event is a `constitute-protocol` log envelope with:

- searchable safe facts
- producer/service/resource references
- category, severity, outcome, and correlation data
- optional encrypted detail ref

Sensitive payloads, credentials, CAAC request bodies, service capability values, decrypted request bodies, raw secret material, credential-bearing URLs, and worker argv secrets are never safe facts.

## Storage Contract

Logging archives per gateway by default.
Storage receives encrypted archive objects, encrypted index shards, availability refs, and pin offers.
Storage does not observe services directly and does not decrypt log detail.
