# STUDY: Google Discovery Service Resolution Baseline

> **Status**: Source-backed baseline  
> **Date**: 2026-03-06  
> **Owner Bead**: `flywheel_connectors-lszk.45.1.2.1`  
> **Program Track**: `flywheel_connectors-lszk.45`

---

## 1) Scope

Define the service-resolution layer that sits in front of pinned Discovery ingestion for Google-family connectors:

1. a deliberately tiny curated alias registry,
2. a first-class explicit `service:version` path for non-curated APIs,
3. deterministic naming and cache identity conventions for pinned snapshots,
4. hard separation between service resolution and operation/method catalog generation.

This baseline is intended to unblock `flywheel_connectors-lszk.45.1.2` and keep downstream migration beads aligned with the accepted ADR.

---

## 2) Local Evidence Snapshot

### 2.1 Runtime connectors are currently pinned to explicit Google API versions

- Gmail defaults to `https://gmail.googleapis.com/gmail/v1` in [connectors/gmail/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/gmail/src/connector.rs:23) and [connectors/gmail/src/client.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/gmail/src/client.rs:20).
- Google Calendar defaults to `https://www.googleapis.com/calendar/v3` in [connectors/google-calendar/src/client.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/google-calendar/src/client.rs:17).
- Google AI defaults to `https://generativelanguage.googleapis.com/v1beta` in [connectors/google-ai/src/client.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/google-ai/src/client.rs:23).

Conclusion: explicit API-version selection already exists in practice, but it is connector-local and not modeled as a shared service-resolution substrate.

### 2.2 Connector IDs and operation IDs are service-scoped and stable

- Gmail connector ID is `gmail` in [connectors/gmail/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/gmail/src/connector.rs:140), with operation IDs under `gmail.*` in [connectors/gmail/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/gmail/src/connector.rs:509).
- Google Calendar connector ID is `google-calendar` in [connectors/google-calendar/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/google-calendar/src/connector.rs:116), with operation IDs under `gcal.*` in [connectors/google-calendar/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/google-calendar/src/connector.rs:390).
- Google AI connector ID is `google-ai` in [connectors/google-ai/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/google-ai/src/connector.rs:131), with operation IDs under `google-ai.*` in [connectors/google-ai/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/google-ai/src/connector.rs:379).

Conclusion: naming already demonstrates a stable service boundary; the missing layer is deterministic service selection before Discovery snapshot generation.

### 2.3 Project policy already requires pinned Discovery snapshots and stable interfaces

- The accepted ADR requires pinned snapshot updates and rejects runtime Discovery mutation in [docs/ADR_GOOGLE_Discovery_Snapshot_Baseline.md](/Users/jemanuel/projects/flywheel_connectors/docs/ADR_GOOGLE_Discovery_Snapshot_Baseline.md:52).
- Manifest validation enforces deterministic `interface_hash` behavior in [crates/fcp-manifest/src/lib.rs](/Users/jemanuel/projects/flywheel_connectors/crates/fcp-manifest/src/lib.rs:180).
- Core introspection contract is explicit and typed in [crates/fcp-core/src/protocol.rs](/Users/jemanuel/projects/flywheel_connectors/crates/fcp-core/src/protocol.rs:1589).

Conclusion: service resolution must feed deterministic generation inputs; it must not be an implicit runtime concern.

---

## 3) Service-Resolution Contract

### 3.1 Inputs

Service resolution accepts exactly one user-facing selector shape:

1. friendly alias (`gmail`, `calendar`, `gcal`, `google-ai`, etc.), or
2. explicit `service:version` (for example `gmail:v1`, `calendar:v3`, `generativelanguage:v1beta`).

Resolution output is always a canonical pair:

- `api_name` (Discovery service name),
- `api_version` (Discovery version string).

### 3.2 Tiny Curated Alias Registry (Normative)

The alias registry is intentionally tiny and maps only high-value friendly names to canonical `(api_name, api_version)` pairs.

Required properties:

1. Alias entries MUST be static, reviewed, and versioned in git.
2. Alias entries MUST NOT include method catalogs, schemas, or operation definitions.
3. Alias resolution MUST be deterministic and side-effect free.
4. Unknown aliases MUST fail with explicit diagnostics (no fuzzy fallback).

### 3.3 Explicit `service:version` Path (Normative)

When a selector is not in the curated alias map, callers can provide explicit `service:version`.

Required properties:

1. This path MUST bypass alias lookup except for normalization.
2. This path MUST be supported for snapshot generation and evaluation workflows.
3. This path MUST preserve deterministic artifact identity using the exact canonicalized pair.
4. This path MUST remain available even if the alias table stays small.

This keeps onboarding and experimentation unblocked without forcing a giant pre-curated registry.

### 3.4 Alias Resolution Is Not Method Catalog Hardcoding (Normative)

Service resolution chooses only API identity (`api_name`, `api_version`).

It MUST NOT:

1. embed operation lists,
2. encode method-specific policies,
3. decide introspection shape,
4. bypass snapshot normalization/generation/override stages.

Method catalogs are produced later from pinned Discovery snapshots plus explicit handwritten overlays per the ADR baseline.

---

## 4) Deterministic Naming and Cache Identity

### 4.1 Canonicalization Rules

Define one canonical identity tuple:

- `service_identity = "<api_name>:<api_version>"`

Canonicalization requirements:

1. trim leading/trailing whitespace,
2. lowercase `api_name` and `api_version`,
3. reject empty components,
4. reject selectors missing a version delimiter for explicit mode.

### 4.2 Snapshot Identity

A pinned snapshot identifier MUST include:

1. canonical `service_identity`,
2. source content digest (Discovery JSON canonical bytes),
3. snapshot schema/tooling version.

Recommended composite key shape:

- `google-discovery/<api_name>/<api_version>/<source_digest>`

This ensures two generation runs with identical inputs resolve to the same snapshot identity.

### 4.3 Cache Key and Artifact Path Stability

Cache and artifact paths MUST be derived from canonical identity, not input alias text.

Implications:

1. `gmail` and `gmail:v1` converge to identical snapshot/cache keys.
2. `calendar` and `gcal` converge only if both aliases map to the same canonical pair.
3. Alias-table edits that change mapped versions intentionally change snapshot identity and are review-visible.

---

## 5) Control-Flow Mapping (Preserved, With FCP Shift)

Preserved upstream flow:

1. identify service,
2. resolve version,
3. fetch/cache Discovery,
4. build surface,
5. authenticate,
6. execute.

FCP adaptation mandated by ADR:

1. stages 1-4 run in generation/snapshot pipelines,
2. runtime connectors consume generated/pinned artifacts,
3. runtime connectors still handle stages 5-6 (auth + execution) for actual requests.

This preserves the useful decomposition while preventing runtime surface mutation.

---

## 6) Acceptance Checklist for This Bead

- Friendly aliases are supported through a deliberately small curated registry.
- Explicit `service:version` is supported for pinned snapshot generation/evaluation.
- Deterministic naming/cache conventions are defined around canonical `api_name:api_version`.
- Alias resolution is explicitly separated from operation/method catalog hardcoding.

