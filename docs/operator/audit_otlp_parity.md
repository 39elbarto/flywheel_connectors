# Audit-chain OTLP Parity Export — Operator Reference

Bead: `flywheel_connectors-angoc.7.2` (Phase M.5)

The audit chain is the canonical, tamper-evident record of every
capability decision the host makes. For external observability, every
audit-chain append also emits a parallel OTLP span under the
`fcp.audit.entry` namespace so dashboards, alerting, and forensics
pipelines can subscribe via standard OpenTelemetry tooling without
reading the on-disk audit chain directly.

This document pins:
- the OTLP span schema (attributes, name, kind, status mapping),
- the parity guarantees the export MUST honor,
- the backpressure / dropped-span semantics,
- the redaction posture,
- the consuming e2e test contract.

## Span schema

For every audit-chain append, the host emits exactly one OTLP span
with the following shape:

| Field | Value |
|---|---|
| span name | `fcp.audit.entry` |
| span kind | `INTERNAL` |
| status | `OK` when `entry.decision = "accepted"`; `ERROR` otherwise. Error message = `entry.reason_code` |
| start time | `entry.hlc.physical_ms * 1_000_000` (UTC nanoseconds from HLC physical component) |
| end time | start time + a fixed 1-microsecond synthetic duration (audit append is instantaneous; the span is a point event) |

Attributes (all under namespace `fcp.audit.entry.*`):

| Attribute | Type | Source | Required |
|---|---|---|---|
| `fcp.audit.entry.entry_id` | string | `entry.id` (BLAKE3-256 hex prefix, 32 chars) | yes |
| `fcp.audit.entry.hlc` | string | compact HLC key formatted as `{l}.{c}` where `l = entry.hlc.physical_ms * 1_000_000` and `c = entry.hlc.logical` | yes |
| `fcp.audit.entry.hlc.l` | integer | HLC physical component encoded for OTLP as UTC nanoseconds (`entry.hlc.physical_ms * 1_000_000`) | yes |
| `fcp.audit.entry.hlc.c` | integer | HLC logical counter (`entry.hlc.logical`) | yes |
| `fcp.audit.entry.hlc.node_id` | string | stable node id that produced `entry.hlc` | yes |
| `fcp.audit.entry.zone` | string | `entry.zone` (e.g. `z:work`) | yes |
| `fcp.audit.entry.decision` | string | one of `accepted`, `rejected_predicate`, `rejected_revocation`, `rejected_expired` | yes |
| `fcp.audit.entry.reason_code` | string | structured reason enum (e.g. `RevokedBeforeUse`, `QuorumNotMet`, `Expired`) | yes |
| `fcp.audit.entry.quorum_height` | integer | `entry.quorum_height` when audit chain uses BLS-aggregated quorum signing; 0 otherwise | yes |
| `fcp.audit.entry.sig_kinds_present` | string array | non-empty subset of `{ed25519, ml_dsa_65, bls_aggregate, stark}` indicating which proof kinds are attached to this entry | yes |
| `fcp.audit.entry.seq` | integer | `entry.seq` — monotonically increasing chain position | yes |
| `fcp.audit.entry.prev_hash_prefix` | string | first 16 hex chars of `entry.prev_hash` for chain-linkage tracing without leaking the full hash | yes |

## Parity guarantee

For every audit chain entry `e` written to disk, the host MUST emit
exactly one OTLP span `s` such that, for the 9 cardinal fields
(`entry_id`, `hlc`, `hlc.l`, `hlc.c`, `hlc.node_id`, `zone`,
`decision`, `reason_code`, `seq`), each span attribute matches the
source field or HLC-derived value pinned in the table above:

```
s.attributes[fcp.audit.entry.<field>] == e.<field>
```

The conformance test
`crates/fcp-e2e/tests/audit_otlp_parity_e2e.rs::test_span_fields_byte_equivalent_to_audit`
appends 1000 entries with known fields and asserts byte-equivalent
recovery via a local OTLP collector.

## Append never blocks on OTLP

The audit chain is the canonical record. OTLP is downstream
observability. Therefore: the host MUST emit OTLP spans on a
fire-and-forget queue. If the queue is full or the collector is
unreachable, the host:

1. Records the audit entry on-disk (the canonical record never
   blocks).
2. Drops the span and increments `fcp.audit.otlp_dropped_total`
   counter.
3. Logs a structured `WARN` line: `{ "event": "otlp_drop",
   "entry_id": "<id>", "reason": "queue_full" | "collector_unreachable",
   "dropped_count_total": <N>, "last_attempt_ms": <ms> }`.

The `test_otlp_collector_down_does_not_block_append` e2e test
asserts this guarantee with a stopped collector and a 60-second
unreachability window.

## Recovery when collector returns

When the collector becomes reachable again, the host:

1. Resumes emitting new audit-chain spans normally.
2. Does NOT backfill the dropped spans. The audit chain on disk is
   the canonical record; OTLP catch-up from disk is a separate
   pipeline (cron-driven export, not part of this bead).
3. Emits a `INFO` line: `{ "event": "otlp_resume",
   "dropped_during_outage": <N>, "outage_secs": <N> }`.

The `test_collector_drop_recovers_when_restored` e2e test asserts
this with a collector down for 60 seconds then up.

## Redaction posture

The audit chain SHALL NOT contain raw secret payloads (the host
runtime ensures this via `SecretTaintTracker` from `angoc.10.2`).
The OTLP span exports ONLY the 12 cardinal fields above; it does NOT
copy the full audit-entry body. Therefore:

- No secret bytes can reach OTLP via this path.
- The `entry_id` is the BLAKE3 hash of the canonical body — it is an
  opaque identifier, not a secret carrier.
- `prev_hash_prefix` is 16 hex chars (8 bytes); insufficient to
  pre-image the full 32-byte hash.

The `test_no_secret_leak_in_spans` e2e test injects a known
SecretTaintTracker secret into the entry payload and asserts no
secret bytes appear in any span attribute.

## Backpressure budget

The OTLP queue has a configured maximum depth (default 10000 spans).
When the depth crosses 80%, the host emits a `WARN` line and drops
new spans rather than blocking. Operators tune the depth via
`OTLP_FCP_AUDIT_QUEUE_DEPTH` env var.

When the depth crosses 100% AND stays there for 5 consecutive seconds,
the host emits a `ERROR` line escalating to operator attention —
typically a sign of a chronically unreachable collector.

## Operator commands

| Command | Effect |
|---|---|
| `fwc audit otlp status --json` | reports `{ "queue_depth": N, "queue_capacity": M, "dropped_total": K, "last_export_ts": "..." }` |
| `fwc audit otlp drain` | flushes the queue synchronously (operator-initiated, used during clean shutdown) |
| `fwc doctor --probe audit_otlp` | runs the full parity self-check: writes a synthetic audit entry, asserts a corresponding span lands at the configured collector within 5 seconds |

## OTLP semantics

Spans use OpenTelemetry semantic conventions where applicable:

- Resource attributes: `service.name = "fcp-host"`,
  `service.version = <fcp-host build version>`,
  `service.instance.id = <host instance id>`.
- The exporter respects the standard `OTEL_EXPORTER_OTLP_*` env vars
  for endpoint, headers, and compression.
- Sampling: ALL audit-chain spans MUST be sampled (no head sampling).
  Audit is forensic, not load-shed. The decision to drop is per
  the backpressure rules above, not per the OTel sampler.

## Cross-references

- `crates/fcp-audit/src/otlp_export.rs` — backing implementation
  (deferred to `angoc.7.2.1`)
- `crates/fcp-e2e/tests/audit_otlp_parity_e2e.rs` — 4 e2e tests
  (deferred to `angoc.7.2.1`)
- `crates/fwc/schemas/audit_otlp_span.schema.json` — JSON schema
  for the span body (this commit)
- `crates/fwc/tests/fixtures/audit_otlp_parity/golden_accepted_span.json` —
  golden fixture (this commit)
- `docs/operator/capability_replay.md` (Phase M.2) — uses the same
  `entry_id` namespace so the two surfaces correlate

## Deferred Rust implementation

Filed as `angoc.7.2.1`. The runtime work needs:

1. A fire-and-forget OTLP exporter wired into `fcp-audit::append`.
2. Resource-attribute population from the host runtime context.
3. The 4 e2e tests with a local OTLP collector (the `tonic`/`opentelemetry`
   crate stack provides a test collector, but the integration touches
   `fcp-host` startup which is currently entangled with PQ-hardening-
   track changes).

The spec doc + schema + golden fixture committed here give the
runtime team a concrete contract; the e2e tests in the bead body
translate directly to fixture cases once dispatch lands.
