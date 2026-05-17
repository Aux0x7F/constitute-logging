# constitute-logging

`constitute-logging` is the blind structured event-evidence capability for
Constitution hosts and services.

It accepts opened CAAC swarm edge event records, indexes safe facts, emits safe
projection deltas, preserves encrypted detail refs, and emits archive
pin-intent records for Storage fulfillment. It owns logging event grammar,
correlation, query, and projection semantics without becoming the owner of
detection policy or decrypted event-detail access.

Product coordination uses the gateway-owned `swarm.edge` WebSocket stream. Raw
HTTP query, watch, and projection adapter routes are operator-only under
`/operator/logging/...`.
