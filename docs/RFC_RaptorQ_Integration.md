# ASUPERSYNC RaptorQ Architecture Contract (P7)

> Status: Normative migration contract
> Owner bead: `flywheel_connectors-235t.20`
> Program epic: `flywheel_connectors-235t`
> Downstream beads: `235t.21`, `235t.22`, `235t.23`, `235t.24`, `235t.25`

---

## 1. Purpose

Define one canonical architecture contract for the RaptorQ pipeline during ASUPERSYNC migration so all downstream implementation beads preserve the same symbol, decode, repair, and replay semantics.

This contract is the P7 baseline from `docs/ASUPERSYNC_Capability_Matrix.md`.

---

## 2. Scope and Boundaries

This contract covers runtime behavior across four crate surfaces:

| Surface | Current Primary Modules | Contract Responsibility |
|---|---|---|
| RaptorQ core | `crates/fcp-raptorq/src/config.rs`, `encode.rs`, `decode.rs`, `chunk.rs` | Symbol policy, chunking policy, decode admission bounds |
| Mesh transport/admission | `crates/fcp-mesh/src/admission.rs`, `symbol_request.rs`, `degraded.rs` | Peer budgets, anti-amplification, bounded repair transport |
| Store + repair orchestration | `crates/fcp-store/src/symbol_store.rs`, `coverage.rs`, `repair.rs` | Coverage accounting, repair eligibility, deterministic scheduling |
| CLI repair workflow | `crates/fcp-cli/src/repair/mod.rs`, `types.rs` | Stable operator-facing status schema and exit semantics |

Non-goal: this bead does not implement full runtime cutover in all crates; it defines the normative contract that downstream beads must implement.

---

## 3. Normative Inputs

All behavior in this contract is constrained by:

- `docs/ADR_ASUPERSYNC_Runtime_Baseline.md`
- `docs/ASUPERSYNC_Capability_Matrix.md`
- `docs/ASUPERSYNC_Feature_Parity_Baseline.md`
- `docs/ASUPERSYNC_Logging_Forensics_Standard.md`
- `FCP_Specification_V2.md`

For Wave D (`235t.20`-`235t.25`), parity contracts `PAR-RAPTORQ-001`, `PAR-RAPTORQ-002`, `PAR-RAPTORQ-003`, and `PAR-RUNTIME-003` are mandatory.

---

## 4. Symbol Sizing and Chunking Policy

### 4.1 Path and MTU policy

Symbol sizing MUST be derived from `RaptorQPreset` + MTU safety guardrails:

- `DEFAULT_MAX_DATAGRAM_BYTES = 1200`
- `DEFAULT_SYMBOLS_PER_FRAME = 1`
- Symbol size is clamped via `RaptorQConfig::mtu_safe_symbol_size` / `bound_symbol_size`.

Path presets currently supported:

- `Lan` (default preset)
- `Derp` (default preset)

Both start with `preferred_symbol_size=1024` and `repair_ratio_bps=500`, then clamp to MTU-safe limits.

### 4.2 Object and chunk policy

`RaptorQConfig` defaults are normative until explicitly changed by a future contract revision:

- `symbol_size = 1024`
- `repair_ratio_bps = 500` (5%)
- `max_object_size = 64 MiB`
- `decode_timeout = 30s`
- `max_chunk_threshold = 256 KiB`
- `chunk_size = 64 KiB`

Objects above `max_chunk_threshold` MUST use `ChunkedObjectManifest` and be reconstructed chunk-wise, not as a monolithic decode operation.

### 4.3 Symbol count formulas

For payload length `L` and symbol size `S`:

- `K = ceil(L / S)` source symbols
- `repair = floor(K * repair_ratio_bps / 10000)`
- `total = K + repair`

Downstream beads MUST avoid ad hoc symbol math; they must use these shared config helpers.

---

## 5. Decode Admission Safety Bounds

Decode safety bounds MUST be explicit and fail-closed.

### 5.1 Core decode admission (`fcp-raptorq`)

`DecodeAdmissionController::new(config)` currently defines:

- `max_concurrent = 16`
- `max_memory_per_decode = config.max_object_size`
- `timeout = config.decode_timeout`
- `max_symbols_buffered = config.total_symbols(config.max_object_size) + 1000`

A decode permit MUST reject work when any bound is exceeded:

- timeout -> `DecodeError::Timeout`
- symbol cap -> `DecodeError::SymbolBufferExceeded`
- memory cap -> `DecodeError::MemoryLimitExceeded`
- concurrency cap -> `DecodeError::AdmissionDenied`

### 5.2 Mesh peer decode budgets (`fcp-mesh`)

Admission policy and peer budgets MUST additionally enforce per-peer runtime limits:

- `DEFAULT_MAX_INFLIGHT_DECODES = 32`
- `DEFAULT_MAX_DECODE_CPU_MS_PER_MIN = 5000`
- Symbol and byte budgets from `AdmissionPolicy` and `PeerBudget`

RaptorQ decode and repair flows MUST pass through both layers: per-decode admission in `fcp-raptorq` and per-peer admission in `fcp-mesh`.

---

## 6. Epoch Buffering and Replay Strategy

Epoch replay behavior MUST be deterministic and testable.

### 6.1 Buffer identity and ordering

Buffer/replay identity is bound by `(zone_id, epoch_id, object_id)`.

Replay order MUST be stable:

1. ascending `epoch_id`
2. ascending `object_id` (byte-order)
3. ascending `esi` within each object

### 6.2 Completion and timeout rules

- Epoch/object decode is complete only when decoder returns payload.
- Incomplete decodes exceeding `decode_timeout` fail closed and emit structured failure logs.
- Partial symbols may remain staged for targeted repair requests while within timeout and retention windows.

### 6.3 Degraded control-plane fallback

When FCPC is unavailable, `fcp-mesh::degraded` uses FCPS `CONTROL_PLANE` symbol transport. This path MUST preserve the same decode admission and replay ordering guarantees as normal flows.

---

## 7. Deterministic Repair Scheduling Semantics

Repair orchestration MUST be bounded, convergent, and deterministic.

### 7.1 Eligibility and priority

`RepairController` eligibility is derived from `CoverageEvaluation` + `ObjectPlacementPolicy`:

- `Unavailable` -> always repair
- `Degraded` -> repair on diversity deficit or coverage deficit above threshold
- `Healthy` -> no repair

Priority ranges:

- Unavailable: `1000 + deficit/100`
- Degraded with diversity deficit: `200 + 10*diversity_deficit + deficit/100`
- Degraded without diversity deficit: `100 + deficit/100`
- Healthy: `0`

### 7.2 Queue ordering contract

Repair queue ordering MUST be deterministic:

- primary sort: descending `priority`
- tie-break: ascending `object_id`

Queue semantics:

- deduplicate by `object_id`
- bounded dequeue by rate limiter + concurrent permits

### 7.3 Fairness and bounds

- `max_repairs_per_minute` token bucket controls dequeue rate.
- `max_concurrent_repairs` controls parallelism.
- `max_symbols_per_repair` bounds per-repair transfer pressure.
- `TargetedRepairRequest` SHOULD prefer missing ESIs and source-diversity-improving peers.

---

## 8. CLI Repair Contract

`fcp repair status` must remain machine-consumable and operator-safe:

- Stable JSON schema via `RepairReport` types
- Exit semantics:
  - `0`: healthy
  - `1`: critical/unavailable
  - `2`: degraded

Current implementation still contains simulation placeholders in `crates/fcp-cli/src/repair/mod.rs`; bead `235t.24` MUST replace placeholders with real mesh/store-backed data without breaking schema or exit-code semantics.

---

## 9. Observability and Forensics Contract

All failure paths in decode/repair/replay MUST emit structured logs compatible with:

- `docs/ASUPERSYNC_Logging_Forensics_Standard.md`
- `docs/testing/e2e_log_schema.md`

Minimum required fields include run/scenario correlation, operation phase, bounded-resource reason codes, and deterministic replay artifact pointers.

---

## 10. Downstream Bead Integration Requirements

| Bead | Must Consume From This Contract |
|---|---|
| `235t.21` (`fcp-raptorq` migration) | Sections 4, 5, 6 |
| `235t.22` (`fcp-store` migration) | Sections 4, 7 |
| `235t.23` (`fcp-mesh` degraded + repair loop) | Sections 5, 6, 7 |
| `235t.24` (`fcp-cli` async repair flows) | Sections 4, 8, 9 |
| `235t.25` (vectors + adversarial suite) | Sections 4, 5, 6, 7, 9 |

Each downstream bead must link this document in completion evidence and demonstrate parity against Wave D contracts.

---

## 11. Acceptance Checklist for `235t.20`

- Architecture contract is explicit for symbol sizing, decode admission, epoch buffering/replay, and deterministic repair semantics.
- Contract is linked in ASUPERSYNC baseline docs.
- Deterministic repair scheduling behavior is encoded in implementation/tests.

