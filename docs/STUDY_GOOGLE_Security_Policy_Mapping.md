# STUDY: Google Security and Policy Mapping Baseline

> **Status**: Source-backed baseline  
> **Date**: 2026-03-07  
> **Owner Beads**: `flywheel_connectors-lszk.45.1.6`, `flywheel_connectors-lszk.45.1.8.1`  
> **Program Track**: `flywheel_connectors-lszk.45`

---

## 1) Purpose

Define the normative translation layer between Google Discovery methods and FCP enforcement metadata:

- capability IDs,
- risk levels,
- safety tiers,
- approval modes,
- recommended deployment zones,
- service host allowlists,
- service-specific exceptions/carve-outs,
- and provisioning/setup policy for scope posture, escalation triggers, runtime-vs-provisioning auth separation, and `gcloud`-assisted bootstrap boundaries.

This mapping is the policy substrate used by future Google generator work. Discovery says what methods exist; this policy map says how safe they are in FCP and what control envelope they must run under.

---

## 2) Machine-Readable Artifact (Generator Input)

Canonical generator-consumable artifact:

- `crates/fcp-google-discovery/data/google_policy_matrix.v1.json`

Typed loader and classifier API:

- `crates/fcp-google-discovery/src/policy.rs`

Provisioning/setup policy lives in the same artifact under the top-level
`provisioning_policy` section so scope escalation and runtime-auth separation
stay versioned with the method-policy map.

Key behavior implemented in the typed loader:

1. Deterministic parsing/validation of service profiles and method rules.
2. Rule matching precedence: exact > prefix wildcard (`foo.*`) > catch-all (`*`).
3. Fail-closed fallback support via per-service `*` rules (`google.review_required` + `forbidden`).
4. Alias-aware selector resolution support through `ServiceAliasRegistry`.
5. Deterministic validation of per-surface provisioning rules, including narrow default scopes, explicit escalation triggers, and `gcloud` automation boundaries.

---

## 3) Initial Service Coverage

This baseline covers first migration and expansion services:

- Gmail (`gmail:v1`)
- Google Calendar (`calendar:v3`)
- YouTube Data API (`youtube:v3`)
- BigQuery (`bigquery:v2`)
- Google AI / Generative Language (`generativelanguage:v1beta` and `v1`)

---

## 4) Service Policy Summary

| Service | Default Zones | Host Allowlist | Typical Read Class | Typical Mutating Class | Destructive Class |
|---|---|---|---|---|---|
| Gmail | `z:private`, `z:work` | `gmail.googleapis.com`, `www.googleapis.com` | `gmail.read` + `safe` + `none` | `gmail.write` + `risky` + `policy` | `gmail.send`/`gmail.delete` + `dangerous` + `interactive` |
| Calendar | `z:private`, `z:work` | `www.googleapis.com` | `gcal.read` + `safe` + `none` | `gcal.write` + `risky` + `policy` | `gcal.delete`/ACL destructive ops + `dangerous` + `interactive` |
| YouTube | `z:community`, `z:work` | `youtube.googleapis.com`, `www.googleapis.com` | `youtube.read` + `safe` + `none` | `youtube.write` + `risky` + `policy` | `youtube.delete` + `dangerous` + `interactive` |
| BigQuery | `z:work`, `z:project:analytics` | `bigquery.googleapis.com` | `bigquery.*.read` + `safe` + `none` | `bigquery.*.write` + `risky` + `policy` | delete/cancel admin ops + `dangerous` + `interactive` |
| Google AI | `z:work`, `z:project:ml` | `generativelanguage.googleapis.com` | models/embed/read + `safe` + `none` | cache writes + `risky` + `policy` | file delete + `dangerous` + `interactive` |

---

## 5) Carve-Outs and Exceptions

### Gmail

- `users.history.*` remains semantically tied to service-owned cursor/lease behavior.
- `users.settings.*` is policy-gated because forwarding/filter changes can alter data-routing posture.

### Calendar

- Recurrence/timezone semantics remain service-owned logic above generic policy rows.
- ACL and calendar-list mutations remain explicitly policy-gated/destructive where applicable.

### YouTube

- Uploads and moderation/admin-style operations are not safe-by-default and remain policy/interactively gated.
- Quota-heavy or externally visible mutations should never auto-classify as `safe`.

### BigQuery

- `jobs.query` is high-impact (cost + data exposure potential) and is policy-gated by default.
- Delete/cancel style operations remain interactive by default.

### Google AI

- Model inference is often side-effect free, but downstream actioning from model output must still be host-policy governed.
- API-key auth may apply; absence of OAuth scopes does not imply absence of policy controls.

---

## 6) Provisioning / Setup Policy Baseline

The Google foundation baseline now includes a typed provisioning policy in
`crates/fcp-google-discovery/data/google_policy_matrix.v1.json`
(`provisioning_policy`) with first-class profiles for:

- Gmail
- Google Calendar
- Google Workspace Events + Pub/Sub bootstrap

This section is intentionally architectural, not polish. The setup UX needs to
encode hard Google constraints that materially affect connector behavior:

1. **Narrow-by-default scopes**: start from the smallest scope bundle that
   supports the selected workflow and only widen on explicit feature selection.
2. **Explicit escalation triggers**: send, mutation, admin, or app-auth flows
   must map to named escalation paths rather than silently broadening consent.
3. **Runtime/provisioning auth separation**: ADC, local credentials files, and
   `gcloud`-authenticated bootstrap are setup-time inputs only; runtime still
   materializes `credential_id` handles or in-memory tokens through the shared
   auth substrate.
4. **`gcloud` boundary clarity**: `gcloud` may automate project/API/Pub/Sub
   bootstrap when it genuinely reduces friction, but it must never bypass
   consent, restricted-scope verification, admin approval, or org policy.
5. **Deterministic fallback**: when `gcloud` is unavailable, the system must
   emit equivalent manual steps instead of relaxing scope or auth policy.

Workspace Events needs extra attention because the subscription lifecycle is not
just OAuth consent. The Pub/Sub topic, delivery IAM, and same-project
constraints are part of the provisioning contract and therefore belong in the
typed policy artifact rather than ad hoc setup notes.

Implementation note for `flywheel_connectors-lszk.45.1.8`: the shared planner in
`crates/fcp-google-discovery/src/provisioning.rs` consumes this policy baseline
and emits concrete `ProvisioningRecipe` / `SetupDescriptor` bundles so downstream
connectors can reuse one deterministic setup contract instead of hand-rolling
surface-specific provisioning logic.

## 7) Generator Contract

When deriving operation descriptors from Discovery snapshots:

1. Classify each method with the policy catalog for its service.
2. Emit capability/risk/safety/approval from the matched rule.
3. Carry service host allowlist defaults into generated network constraints.
4. If only catch-all rule matches (`*` + `forbidden`), require explicit human policy review before enabling the operation.

This keeps generated surfaces deterministic and fail-closed while still allowing service-specific overlays.
