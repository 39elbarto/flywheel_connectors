# STUDY: Google Gmail/Calendar Baseline Audit

> **Status**: Source-backed baseline  
> **Date**: 2026-03-06  
> **Owner Bead**: `flywheel_connectors-lszk.45.2.7`  
> **Program Track**: `flywheel_connectors-lszk.45`

---

## 1) Scope

Freeze the current local baseline for Gmail and Google Calendar, record exactly where generic Google logic is duplicated today, and define the target split between:

1. shared Google substrate work,
2. service-owned handwritten logic,
3. case-by-case migration decisions.

This document is intended to block ambiguity for:

- `flywheel_connectors-lszk.45.2.1` (Gmail migration),
- `flywheel_connectors-lszk.45.2.2` (Calendar migration),
- `flywheel_connectors-lszk.45.2.6` (migration acceptance suite).

---

## 2) Local Evidence Snapshot

### 2.1 Manual operation catalogs exist in both manifests

- Gmail declares operation entries directly in manifest TOML (for example `gmail.send_message`, `gmail.get_message`, `gmail.list_messages`) in [connectors/gmail/manifest.toml](/Users/jemanuel/projects/flywheel_connectors/connectors/gmail/manifest.toml:34).
- Google Calendar similarly declares operation entries directly in [connectors/google-calendar/manifest.toml](/Users/jemanuel/projects/flywheel_connectors/connectors/google-calendar/manifest.toml:34).

### 2.2 Manual introspection catalogs exist in both connector implementations

- Gmail builds `Introspection { operations: vec![ ... op_info(...) ... ] }` in [connectors/gmail/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/gmail/src/connector.rs:504).
- Google Calendar builds its own `Introspection` operation list in [connectors/google-calendar/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/google-calendar/src/connector.rs:390).

### 2.3 Gmail operation drift between manifest and introspection

Observed from local source extraction:

- Manifest-only: `gmail.create_draft`, `gmail.modify_labels`, `gmail.search_messages`
- Introspection-only: `gmail.get_draft`, `gmail.get_thread`, `gmail.modify_message`, `gmail.send_draft`, `gmail.sync_history`

This is concrete duplication/drift risk between two handwritten catalogs in:

- [connectors/gmail/manifest.toml](/Users/jemanuel/projects/flywheel_connectors/connectors/gmail/manifest.toml:34)
- [connectors/gmail/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/gmail/src/connector.rs:504)

### 2.4 Gmail carries service-specific auth/config + refresh-token exchange

- Multi-source auth selection (`token` vs `credential_id` vs `oauth_refresh`) with exactly-one enforcement in [connectors/gmail/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/gmail/src/connector.rs:157).
- Gmail-specific parsing helpers for scopes/cursor/auth fields (`parse_required_scopes`, `parse_history_cursor_path`, `parse_credential_id`, `parse_oauth_refresh`) in [connectors/gmail/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/gmail/src/connector.rs:1142).
- Refresh-token HTTP exchange and scope reconciliation in `exchange_refresh_token` at [connectors/gmail/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/gmail/src/connector.rs:1362).

### 2.5 Gmail also carries service-specific history cursor and lease sequencing logic

- Stateful incremental history sync with persisted cursor, anti-regression checks, and lease fencing in `invoke_sync_history` at [connectors/gmail/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/gmail/src/connector.rs:939).

### 2.6 Calendar has separate auth parser and its own manual invoke/introspection surface

- Calendar-specific strict auth parsing (`token`/`credential_id`) in [connectors/google-calendar/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/google-calendar/src/connector.rs:27).
- Calendar-specific operation dispatch match in [connectors/google-calendar/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/connectors/google-calendar/src/connector.rs:835).
- Calendar operation catalogs are currently aligned between manifest and introspection (unlike Gmail), but still duplicated across two handwritten surfaces.

---

## 3) Destination Representation Already Exists (Gap Is Upstream Substrate)

The destination-side representation for connector operation surfaces and invocation contracts already exists in core/CLI.

- Core connector interface already models `introspect()` + `invoke()` in [crates/fcp-core/src/connector.rs](/Users/jemanuel/projects/flywheel_connectors/crates/fcp-core/src/connector.rs:22).
- Wire-level invoke request/response are already defined in [crates/fcp-core/src/protocol.rs](/Users/jemanuel/projects/flywheel_connectors/crates/fcp-core/src/protocol.rs:347) and [crates/fcp-core/src/protocol.rs](/Users/jemanuel/projects/flywheel_connectors/crates/fcp-core/src/protocol.rs:505).
- Core introspection/operation types already exist in [crates/fcp-core/src/protocol.rs](/Users/jemanuel/projects/flywheel_connectors/crates/fcp-core/src/protocol.rs:1589).
- CLI-side consumer descriptors already exist in [crates/fcp-cli/src/connector/types.rs](/Users/jemanuel/projects/flywheel_connectors/crates/fcp-cli/src/connector/types.rs:214).

Conclusion: migration risk is not lack of destination type/system modeling. The main gap is shared Google ingestion/auth/executor/generation substrate and how handwritten overlays are layered on top.

---

## 4) Convergence Map (3-Way Split)

| Must Become Shared Google Substrate | Must Remain Service-Owned Handwritten Logic | Needs Deliberate Case-by-Case Review |
|---|---|---|
| Discovery snapshot ingestion + normalization + pinning pipeline | Gmail history cursor semantics (`historyId` progression, dedup, lease fencing) | Which Gmail/Calendar helper flows are generated vs handwritten overlays |
| Canonical operation catalog generation from pinned snapshot | Gmail mailbox/domain behavior specifics (thread/message/draft semantics) | Naming normalization for operation IDs where current manifest/introspection differ |
| Shared Google auth source matrix and validation rules | Calendar freebusy and recurring-instance behavior semantics | Compatibility strategy for historical operation IDs during migration |
| Shared token materialization interfaces (including refresh-token path) | Service-specific error shaping where API semantics differ materially | Which fields stay strict/preserve shape vs normalized cross-service schemas |
| Shared REST executor (timeouts/retries/error mapping/pagination/upload primitives) | Service-specific state models and domain invariants | Where to centralize vs keep per-service AI hint wording |
| Shared policy/capability mapping scaffolding for generated operations | Service-specific tests for domain edge behavior | Cross-service policy defaults for risky ops (approval mode defaults) |
| Shared drift detection between snapshot, manifest, and introspection | | |

---

## 5) Practical Migration Guidance From This Baseline

1. Eliminate duplicated operation catalog authoring first (single generated source -> manifest/introspection outputs).
2. Preserve Gmail’s stateful `sync_history` behavior as explicit service-owned logic while lifting generic auth/execution substrate.
3. Keep Calendar as the cleaner migration proving path, but do not treat current parity as proof that duplicated catalogs are acceptable long term.
4. Add acceptance checks that compare generated manifest/introspection surfaces and fail on drift.

---

## 6) Helper Overlay Policy + Initial Workflow Shortlist

Handwritten workflow helpers now have an explicit machine-readable policy contract in:

- [crates/fcp-google-discovery/data/google_policy_matrix.v1.json](/Users/jemanuel/projects/flywheel_connectors/crates/fcp-google-discovery/data/google_policy_matrix.v1.json)
  (`helper_overlay_policy`)
- Owner bead: `flywheel_connectors-lszk.45.1.5.2`

Required rule: helpers are thin overlays above generated operations only. A helper is allowed only when it is multi-step, requires stateful workflow semantics that single generated calls cannot express, and adds explicit safety controls (approval/budget/confirmation) mapped to existing generated capability checks.

Initial high-value shortlist recorded in that policy object:

- `gmail.sync_history_checkpointed`
- `gmail.triage_and_reply`
- `calendar.find_slot_then_schedule`
- `calendar.safe_reschedule`
- `bigquery.budget_guarded_query`

Everything else should default to generated operation surfaces until explicitly justified.

---

## 7) Blocking Checklist for Downstream Beads

- `flywheel_connectors-lszk.45.2.1` MUST reference this audit before changing Gmail operation surfaces.
- `flywheel_connectors-lszk.45.2.2` MUST reference this audit before centralizing Calendar auth/catalog code.
- `flywheel_connectors-lszk.45.2.6` MUST include explicit manifest↔introspection parity assertions and intentional-delta reporting.
