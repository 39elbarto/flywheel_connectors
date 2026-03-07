# Google Connector Platform Reference

> **Status**: Source-backed developer/operator reference  
> **Date**: 2026-03-07  
> **Owner Bead**: `flywheel_connectors-lszk.45.1.9`  
> **Program Track**: `flywheel_connectors-lszk.45`

---

## 1. Purpose

This document explains how the shared Google connector platform works in the
current tree, how operators should think about provisioning and policy, and how
developers should add or migrate Google-family connectors without reintroducing
hand-maintained drift.

It is a practical synthesis of the current implementation in
[`crates/fcp-google-discovery`](../crates/fcp-google-discovery/src/lib.rs),
the accepted snapshot ADR in
[`docs/ADR_GOOGLE_Discovery_Snapshot_Baseline.md`](./ADR_GOOGLE_Discovery_Snapshot_Baseline.md),
the service-resolution baseline in
[`docs/STUDY_GOOGLE_Discovery_Service_Resolution.md`](./STUDY_GOOGLE_Discovery_Service_Resolution.md),
the security/policy baseline in
[`docs/STUDY_GOOGLE_Security_Policy_Mapping.md`](./STUDY_GOOGLE_Security_Policy_Mapping.md),
and the Gmail/Calendar migration audit in
[`docs/STUDY_GOOGLE_Gmail_Calendar_Baseline_Audit.md`](./STUDY_GOOGLE_Gmail_Calendar_Baseline_Audit.md).

---

## 2. Platform Model

The shared Google platform is centered on one rule: Google Discovery is the
upstream schema source, but it is not allowed to mutate a shipped connector's
runtime-visible surface.

The intended flow is:

1. Resolve a Google service identity (`alias` or `service:version`).
2. Fetch and normalize a pinned Discovery snapshot.
3. Load machine-readable policy for capabilities, zones, risk, and provisioning.
4. Generate connector-facing artifacts from the pinned snapshot plus policy.
5. Layer narrow handwritten overrides above generated outputs where FCP safety
   or service semantics require them.
6. Ship a stable binary + manifest pair with a fixed interface.

The ADR makes the boundary explicit: runtime connectors must not fetch live
Discovery and add or remove operations on the fly.

---

## 3. Shared Substrate Modules

The shared implementation lives in
[`crates/fcp-google-discovery`](../crates/fcp-google-discovery/src/lib.rs).

### 3.1 Service resolution and pinned snapshots

- [`src/lib.rs`](../crates/fcp-google-discovery/src/lib.rs) defines
  `DiscoveryServiceId`, `ServiceAliasRegistry`, `DiscoveryFetcher`, normalized
  snapshot types, and deterministic snapshot storage keys.
- The alias registry is deliberately small and reviewed in git. Current curated
  aliases include `gmail`, `calendar`, `gcal`, `youtube`, `bigquery`, `drive`,
  `docs`, `sheets`, `google-ai`, and `generativelanguage`.
- Explicit `service:version` selectors stay available for non-curated APIs and
  evaluation workflows.
- Snapshot identity is deterministic:
  `google-discovery/<api_name>/<api_version>/<source_digest>`.

### 3.2 Shared Google auth

- [`src/auth.rs`](../crates/fcp-google-discovery/src/auth.rs) defines the
  allowed auth-source matrix and the strict source-selection chain.
- Runtime-safe sources are:
  `access_token`, `credential_id`, and `oauth_refresh`.
- Provisioning-only sources include:
  `credentials_file`, `default_credentials`, and
  `application_default_credentials`.
- Encrypted connector-owned local credential stores are rejected because they
  violate the FCP secret-residency model.
- The module also materializes runtime auth and enforces required-scope checks.

### 3.3 Shared REST execution

- [`src/executor.rs`](../crates/fcp-google-discovery/src/executor.rs)
  centralizes request validation, URL-template expansion, schema validation,
  pagination token extraction, upload modes, and Google error normalization.
- Connector code should use this layer for generic Google HTTP mechanics rather
  than rebuilding request shaping and error mapping per service.

### 3.4 Shared policy catalog

- [`src/policy.rs`](../crates/fcp-google-discovery/src/policy.rs) loads the
  embedded catalog from
  [`data/google_policy_matrix.v1.json`](../crates/fcp-google-discovery/data/google_policy_matrix.v1.json).
- The catalog contains:
  service-level policy profiles, operation classification rules, recommended
  zones, host allowlists, helper-overlay policy, and provisioning policy.
- Current service entries in the embedded catalog include:
  `gmail`, `calendar`, `youtube`, `bigquery`, and `generativelanguage`.

### 3.5 Shared generation

- [`src/generator.rs`](../crates/fcp-google-discovery/src/generator.rs)
  generates four synchronized outputs from one pinned snapshot plus policy:
  `Introspection`, MCP tool descriptors, agent skill artifacts, and manifest
  operation fragments.
- This is the key anti-drift mechanism: one normalized method catalog drives
  every generated consumer-facing surface.

### 3.6 Shared provisioning

- [`src/provisioning.rs`](../crates/fcp-google-discovery/src/provisioning.rs)
  turns the policy catalog into concrete FCP provisioning recipes and setup
  descriptors.
- Current provisioning surfaces declared in the catalog are:
  `gmail`, `calendar`, and `workspace_events`.
- Provisioning bundles carry:
  default scopes, escalation triggers, required API enablement,
  consent-restriction rules, allowed `gcloud` automation boundaries, fallback
  steps, and runtime materialization expectations.

---

## 4. Operator Guidance

### 4.1 Treat Google connector surfaces as pinned artifacts

Operators should assume that a connector release is bound to a reviewed
Discovery snapshot and a reviewed policy catalog, not to whatever Google
publishes today. If the Google API shape changes upstream, the correct response
is a snapshot/generation update and a new release, not live runtime mutation.

### 4.2 Provisioning is narrow by default

The policy catalog is opinionated about least-privilege setup:

- `gmail` defaults to `https://www.googleapis.com/auth/gmail.readonly`
- `calendar` defaults to `https://www.googleapis.com/auth/calendar.readonly`
- `workspace_events` defaults to
  `https://www.googleapis.com/auth/chat.messages.readonly`

Escalations above those defaults must come through declared trigger paths in the
provisioning bundle, not ad hoc scope inflation in connector config.

### 4.3 Runtime credentials should be materialized into runtime-safe forms

Provisioning may inspect broader auth sources, but steady-state connector
runtime should converge on runtime-safe materialization such as
`credential_id`, in-memory `access_token`, or allowed refresh-token exchange.
Operators should avoid designs that depend on connector-local credential files
or connector-owned secret stores.

### 4.4 Zones and host allowlists come from policy, not connector guesswork

The embedded policy catalog already records recommended zone placement and host
allowlists for each Google service. Current examples include:

- `gmail` -> `z:private`, `z:work`
- `calendar` -> `z:private`, `z:work`
- `youtube` -> `z:community`, `z:work`
- `bigquery` -> `z:project:analytics`, `z:work`
- `generativelanguage` -> `z:project:ml`, `z:work`

That policy should be treated as the default control plane for deployment,
approval posture, and network allowlisting.

### 4.5 `gcloud` is a setup accelerator, not a policy bypass

Provisioning recipes can use `gcloud` where it reduces operator friction, but
the policy catalog also defines what must not be bypassed and what the fallback
procedure is when `gcloud` is unavailable. This keeps setup automation aligned
with consent restrictions and runtime-auth separation.

---

## 5. Current Adoption State

The shared platform is real, but adoption is uneven across Google-family
connectors in the current tree.

| Connector | Current state | Evidence |
|---|---|---|
| `google-calendar` | Uses shared service selection, shared Google auth selection/materialization, and provisioning bundle driven scope resolution. | [`connectors/google-calendar/src/connector.rs`](../connectors/google-calendar/src/connector.rs) |
| `youtube` | Uses shared service selection and shared Google auth selection, while still supporting an API-key path for service-specific ergonomics. | [`connectors/youtube/src/connector.rs`](../connectors/youtube/src/connector.rs) |
| `gmail` | Still owns substantial handwritten Google plumbing plus Gmail-specific stateful logic. Migration target is to lift generic Google mechanics while preserving history cursor, lease sequencing, and high-risk mail workflows as explicit service-owned logic. | [`connectors/gmail/src/connector.rs`](../connectors/gmail/src/connector.rs), [`docs/STUDY_GOOGLE_Gmail_Calendar_Baseline_Audit.md`](./STUDY_GOOGLE_Gmail_Calendar_Baseline_Audit.md) |
| `google-ai` | Not yet on the shared auth/provisioning path; still uses connector-local auth parsing. | [`connectors/google-ai/src/connector.rs`](../connectors/google-ai/src/connector.rs) |
| `bigquery` | Not yet migrated to the shared Google substrate; still uses connector-local auth/config parsing. | [`connectors/bigquery/src/connector.rs`](../connectors/bigquery/src/connector.rs) |

This matters operationally: not every Google-family connector currently inherits
the same setup UX, policy surface, or drift resistance. The platform reference
describes the target architecture and the parts already implemented today, not a
claim of full migration completeness.

---

## 6. Generation and Override Rules

Generated outputs should be the default for method catalogs, schemas,
capabilities, and AI-facing tool metadata. Handwritten overlays are allowed, but
only under explicit constraints.

The helper-overlay policy in
[`data/google_policy_matrix.v1.json`](../crates/fcp-google-discovery/data/google_policy_matrix.v1.json)
requires helpers to be thin overlays above generated operations and only when
they add something raw Discovery cannot safely express.

Current approved workflow shortlist:

- `gmail.sync_history_checkpointed`
- `gmail.triage_and_reply`
- `calendar.find_slot_then_schedule`
- `calendar.safe_reschedule`
- `bigquery.budget_guarded_query`

That is the default review stance:

- Generated operation surfaces first.
- Handwritten overlay only for multi-step, stateful, or safety-sensitive flows.
- Service-specific invariants remain explicit rather than being buried in generic
  metadata.

---

## 7. What Must Stay Service-Owned

The Gmail/Calendar migration audit already defines the most important split.
Generic Google plumbing should migrate into shared layers, but service-owned
logic must stay explicit when it carries domain invariants or state semantics.

Examples that should remain service-owned:

- Gmail history cursor progression and gap handling
- lease sequencing and cursor fencing during Gmail history sync
- Gmail helper flows that combine context gathering, drafting, and send safety
- Calendar-specific recurrence, attendee, and freebusy semantics
- any service-specific error shaping where generic Google transport errors are
  insufficient

The migration test for correctness is not "how much code moved into the shared
crate." The test is whether generic mechanics were centralized without erasing
service semantics or safety boundaries.

---

## 8. How To Add a New Google Connector

For a new Google-family connector, follow this sequence:

1. Define the canonical service identity through the alias registry or explicit
   `service:version` path.
2. Fetch and pin the Discovery snapshot. Do not plan around live runtime
   Discovery mutation.
3. Add or extend policy-catalog coverage for the service:
   capability mapping, risk/safety tier, recommended zones, host allowlist,
   provisioning surface, and helper-overlay rules if needed.
4. Generate artifacts from the snapshot plus policy:
   introspection, MCP tools, agent skills, and manifest fragments.
5. Only then add service-owned handwritten code for the pieces the generic
   substrate cannot own:
   domain invariants, stateful workflows, or high-value helper overlays.
6. Use shared auth selection/materialization and shared executor plumbing rather
   than cloning transport/auth logic into the connector.
7. Add drift and parity tests so generated manifest/introspection outputs stay
   synchronized and intentional deltas are visible.

The anti-pattern is writing a mostly manual connector first and promising to
"factor it later." That is exactly how manifest, introspection, and policy drift
re-enters the tree.

---

## 9. References for Future Work

- Architecture contract:
  [`docs/ADR_GOOGLE_Discovery_Snapshot_Baseline.md`](./ADR_GOOGLE_Discovery_Snapshot_Baseline.md)
- Service resolution baseline:
  [`docs/STUDY_GOOGLE_Discovery_Service_Resolution.md`](./STUDY_GOOGLE_Discovery_Service_Resolution.md)
- Security and policy baseline:
  [`docs/STUDY_GOOGLE_Security_Policy_Mapping.md`](./STUDY_GOOGLE_Security_Policy_Mapping.md)
- Gmail/Calendar migration audit:
  [`docs/STUDY_GOOGLE_Gmail_Calendar_Baseline_Audit.md`](./STUDY_GOOGLE_Gmail_Calendar_Baseline_Audit.md)
- Shared substrate crate:
  [`crates/fcp-google-discovery/src/lib.rs`](../crates/fcp-google-discovery/src/lib.rs)
