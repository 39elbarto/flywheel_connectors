# Google Sheets Connector V3 Contract

> **Status**: PROVEN runtime contract documented with simulation and retry drift called out
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/google_sheets_connector_verification.sh`
> **Sheets API upstream**: https://developers.google.com/sheets/api/reference/rest
> **Values resource upstream**: https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets.values
> **Values update upstream**: https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets.values/update
> **Values append upstream**: https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets.values/append

## Purpose

This document fixes the operator-facing contract for `fcp.google_sheets`. The connector exposes a bounded practical spreadsheet workflow: metadata and value reads, value writes, idempotent append, confirmed clear, spreadsheet creation, sheet copy, and an allowlisted structural batch editor.

The connector is intentionally not a raw Google API tunnel. It validates request kinds, ranges, IDs, field masks, nesting, cell counts, request counts, and payload sizes before any provider call.

## Current Runtime Snapshot

The current crate exposes these operations:

- `sheets.get_spreadsheet`
- `sheets.get_values`
- `sheets.batch_get_values`
- `sheets.update_values`
- `sheets.batch_update_values`
- `sheets.append_values`
- `sheets.clear_values`
- `sheets.create_spreadsheet`
- `sheets.copy_sheet`
- `sheets.batch_update_spreadsheet`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-google-sheets`.
- Runtime `BaseConnector` ID is `google-sheets`.
- Configuration accepts Google auth either at the top level or under `auth`.
- Configuration requires exactly one Google auth source accepted by `GoogleAuthSelection`: direct bearer token, `credential_id`, or OAuth refresh material accepted by the shared layer.
- Direct bearer-token mode sends the Google Authorization header through `reqwest`.
- `credential_id` mode is secretless and reports `configured_pending_token_materialization`.
- Default base URL is `https://sheets.googleapis.com/v4`.
- Public base URLs must use HTTPS, must target exact host `sheets.googleapis.com`, and must not contain userinfo, query strings, or fragments.
- `localhost`, `127.0.0.1`, and `::1` are accepted with HTTP or HTTPS for deterministic loopback tests.
- Runtime request timeout is 30 seconds.
- Spreadsheet IDs are inserted into URL path segments only after local path-segment validation.
- Path-segment validation rejects empty strings, slashes, backslashes, `..`, query strings, fragments, encoded slash/backslash/query/fragment markers, and literal percent characters.
- Range expressions are percent-encoded with `percent_encoding::NON_ALPHANUMERIC` before being placed in the URL path.
- `sheets.update_values` writes with `valueInputOption=USER_ENTERED`.
- `sheets.append_values` writes with `valueInputOption=USER_ENTERED` and `insertDataOption=INSERT_ROWS`.
- Value writes require a bounded two-dimensional `values` array; batch reads and writes accept at most 100 ranges and 50,000 cells.
- `sheets.append_values` requires an 8–128 character idempotency key. A successful retry with the same key and payload is served from the connector-session receipt cache; reusing the key for different data is rejected.
- `sheets.clear_values` requires `confirm_clear=true`, performs a read-only value preflight, clears the range, and reads it back.
- Structural batches accept only documented request types. Delete/clear request types additionally require `confirm_destructive=true`; every structural batch captures metadata before and after the atomic provider update.
- Runtime handshake installs a `CapabilityVerifier`.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- Runtime `invoke` requires `capability_token`, computes `google-sheets:spreadsheet:{spreadsheet_id}`, and verifies a bound token before provider execution.
- `health()`, `doctor()`, and `self_check()` are local configuration checks only. They do not probe Google Sheets.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest connector ID is `fcp.google_sheets`, while runtime `BaseConnector` ID is `google-sheets`.
- Runtime `handle_simulate` is permissive. It returns `would_execute = true` for any supplied operation string and does not validate operation inventory, configured state, handshake state, input, capability, or capability token.
- `SheetsClient` stores an `HttpRetryConfig`, but the current HTTP helpers call `reqwest` directly and do not execute the shared retry loop.
- Runtime `handle_shutdown` shuts down the client runtime and sets `client = None`, but it does not clear verifier, session, configured flag, or handshaken flag.
- The dedicated tracked verification shell script is `scripts/e2e/google_sheets_connector_verification.sh`.

A follow-up parity bead should make `simulate` enforce the same operation/input/capability rules as `invoke`, wire the stored retry config or remove it, and reset lifecycle state consistently on shutdown.

## First-Slice Scope

The current Google Sheets README slice documents the existing runtime surface:

- Google bearer-token, credential-reference, and OAuth refresh auth selection through the shared Google layer
- Sheets API base URL policy and loopback test allowance
- spreadsheet metadata reads, range reads, range updates, row appends, and value clears
- bound capability-token verification during `invoke`
- current permissive simulation behavior
- provider error mapping, range/path encoding, redaction posture, and health behavior
- lifecycle, doctor, health, self-check, introspection, simulation, invoke, and shutdown surfaces
- deterministic WireMock tests and direct proof commands
- the tracked pre-promotion verifier bundle that ties gauntlet, manifest, Cargo, local non-mock JSONL, redaction, and replay evidence together

## Auth And Scope Boundary

- Authentication mechanisms: Google bearer token, host credential reference, or OAuth refresh material through the shared Google auth layer.
- Home zone: `z:private`.
- Allowed source zones: `z:owner` and `z:private`.
- Allowed target zone: `z:private`.
- Forbidden zones: `z:public` and `z:work`.
- Runtime and manifest capability surface:
  - `sheets.read` gates spreadsheet metadata and value reads.
  - `sheets.values.write` gates update, batch update, append, and confirmed clear.
  - `sheets.structure.write` gates spreadsheet creation, sheet copy, and validated structural batches.
- The connector does not persist spreadsheet IDs, sheet names, cell values, formulas, access tokens, credential IDs, provider payloads, or provider error bodies beyond process memory.
- Sheets data can contain private tab names, formulas, business metrics, customer data, and hidden structure. Treat all live reads and writes as private-zone data.

## Network And Runtime Invariants

- Production host: `sheets.googleapis.com`.
- Production API prefix: `/v4`.
- Production port: `443`.
- TLS and SNI are required by the manifest for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback base URLs are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints use `10_000 ms` connect timeout and `30_000 ms` total timeout.
- Manifest maximum response bytes are `1_048_576`, `5_242_880`, or `10_485_760` depending on operation size.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `30_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.
- Runtime handshake event caps report no streaming and no replay.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `sheets.read` | Read spreadsheet metadata and cell ranges. |
| `sheets.values.write` | Update, batch update, append, and confirmed clear of cell values. |
| `sheets.structure.write` | Create spreadsheets, copy tabs, and apply validated structural updates. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `sheets.get_spreadsheet` | `GET /v4/spreadsheets/{spreadsheet_id}` | `sheets.read` | `Safe` | `Low` | `Strict` | Reads spreadsheet metadata and sheet list. |
| `sheets.get_values` | `GET /v4/spreadsheets/{spreadsheet_id}/values/{range}` | `sheets.read` | `Safe` | `Low` | `Strict` | Reads cell values from an A1 notation range. |
| `sheets.batch_get_values` | `GET /v4/spreadsheets/{spreadsheet_id}/values:batchGet` | `sheets.read` | `Safe` | `Low` | `Strict` | Reads up to 100 ranges with explicit render choices. |
| `sheets.update_values` | `PUT /v4/spreadsheets/{spreadsheet_id}/values/{range}` | `sheets.values.write` | `Risky` | `Medium` | `BestEffort` | Writes a bounded two-dimensional array. |
| `sheets.batch_update_values` | `POST /v4/spreadsheets/{spreadsheet_id}/values:batchUpdate` | `sheets.values.write` | `Risky` | `Medium` | `BestEffort` | Atomically writes values or formulas to up to 100 ranges. |
| `sheets.append_values` | `POST /v4/spreadsheets/{spreadsheet_id}/values/{range}:append` | `sheets.values.write` | `Risky` | `Medium` | `BestEffort` | Appends once per connector-session idempotency key. |
| `sheets.clear_values` | `GET`, `POST :clear`, `GET` | `sheets.values.write` | `Dangerous` | `High` | `Strict` | Requires confirmation and returns preflight plus readback. |
| `sheets.create_spreadsheet` | `POST /v4/spreadsheets` | `sheets.structure.write` | `Risky` | `Medium` | `None` | Creates a spreadsheet with bounded initial tabs. |
| `sheets.copy_sheet` | `POST /v4/spreadsheets/{id}/sheets/{sheet_id}:copyTo` | `sheets.structure.write` | `Risky` | `Medium` | `None` | Copies a tab to a bound destination spreadsheet. |
| `sheets.batch_update_spreadsheet` | `GET`, `POST :batchUpdate`, `GET` | `sheets.structure.write` | `Dangerous` | `High` | `BestEffort` | Applies an atomic allowlisted batch with preflight and readback. |

## Resource URIs

Runtime capability-token verification binds all supported operations to this resource URI shape:

| Operation family | Resource URI |
|------------------|--------------|
| spreadsheet metadata, range reads, updates, appends, clears | `google-sheets:spreadsheet:{spreadsheet_id}` |

## Explicit Non-Goals

The current implementation does not include:

- raw HTTP requests, unrestricted discovery-method passthrough, or structural request types outside the allowlist
- Drive file export, Drive placement, file permissions, sharing, or revision history
- formula analysis, CSV import/export, durable cross-restart append receipts, sync-token storage, or connector-local credential vaulting
- OAuth consent setup, Sheets API enablement, service-account/domain-wide delegation provisioning, or Google Workspace tenant onboarding

These are excluded on purpose:

- Spreadsheet data often mixes private, financial, customer, and operational records.
- Range writes are easy to make destructive, especially with `USER_ENTERED` interpretation.
- Structural spreadsheet editing is a larger API surface than this values-focused connector slice.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration and local client state
- operation metadata with capability, risk, safety tier, idempotency, schemas, and AI hints
- bound capability-token verification during `invoke`
- resource URI binding by spreadsheet ID
- current permissive simulation behavior
- local-only readiness for configured state
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, base URL policy, loopback allowance, introspection, and shutdown behavior
- spreadsheet metadata, get values, update values, append values, and clear values through deterministic HTTP fixtures
- range encoding and spreadsheet ID path-segment validation
- invoke rejection for missing config, missing token, unknown operation, missing fields, and wrong capability
- provider 401, 403, 404, 429, retryable transport/server classes, malformed JSON, invalid range, and FCP error mapping

## Source Notes

- `connectors/google-sheets/src/connector.rs` defines configuration parsing, base URL policy, lifecycle handlers, introspection, simulation, resource URI binding, capability-token verification, and invoke dispatch.
- `connectors/google-sheets/src/client.rs` defines Sheets paths, Google auth header application, timeout, request metrics, path-segment validation, range encoding, and provider error mapping.
- `connectors/google-sheets/src/types.rs` defines spreadsheet, range, update, append, and provider error shapes.
- `connectors/google-sheets/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/google-sheets/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, and rate-limit pools.
- `connectors/google-sheets/tests/connector_suite_happy_path.rs` covers deterministic runtime behavior and connector-suite expectations.

## Verification Bundle

The dedicated tracked `scripts/e2e/google_sheets_connector_verification.sh` bundle is the closeout surface for this connector, alongside the crate-local test suite and direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for Sheets API paths
- auth, endpoint policy, provider error, lifecycle, simulation, and introspection tests
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Google account or Workspace test tenant with Sheets API access enabled for live verification.
- Prefer credential-reference mode when host policy should own Google secret material.
- Use loopback WireMock fixtures for routine proof.

**Dedicated environment**:

- Keep test spreadsheets separate from personal and production spreadsheets.
- Use small, explicit A1 ranges for smoke tests.
- Use disposable tabs or dedicated fixture spreadsheets for writes and clears.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, spreadsheet IDs when sensitive, tab names, range names, cell values, formulas, provider payloads, provider error bodies, and endpoint URLs when they reveal tenant topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, retry decisions, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide exactly one Google auth source.
- If live checks fail with a credential reference, materialize host credentials before invoking provider operations.
- If range operations fail, verify A1 notation and the spreadsheet ID, not the individual sheet ID.
- If writes appear wrong, remember `USER_ENTERED` lets Google interpret values as formulas, dates, or numbers.
- If an append call is retried during the same connector session, reuse the exact same idempotency key and payload. A new key intentionally creates a new append.

**Rerun commands**:

- `scripts/e2e/google_sheets_connector_verification.sh`
- `CARGO_TARGET_DIR=/home/ubuntu/.cache/fcp-google-sheets cargo check -p fcp-google-sheets --all-targets`
- `CARGO_TARGET_DIR=/home/ubuntu/.cache/fcp-google-sheets cargo test -p fcp-google-sheets --tests -- --nocapture`
- `CARGO_TARGET_DIR=/home/ubuntu/.cache/fcp-google-sheets cargo clippy -p fcp-google-sheets --all-targets --no-deps -- -D warnings`
- `ubs connectors/google-sheets/README.md`
