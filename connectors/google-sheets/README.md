# Google Sheets Connector V3 Contract

> **Status**: runtime contract documented; simulation and retry drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Sheets API upstream**: https://developers.google.com/sheets/api/reference/rest
> **Values resource upstream**: https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets.values
> **Values update upstream**: https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets.values/update
> **Values append upstream**: https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets.values/append

## Purpose

This document fixes the operator-facing contract for `fcp.google_sheets`. The connector exposes the Google Sheets API surface implemented in this crate: spreadsheet metadata lookup, range reads, range updates, row appends, and value clearing.

The connector is intentionally a bounded Sheets bridge. It is not a full spreadsheet editor, chart client, pivot-table client, batchUpdate structural editor, Drive permission manager, formula auditor, export client, or long-running spreadsheet warehouse.

## Current Runtime Snapshot

The current crate exposes these operations:

- `sheets.get_spreadsheet`
- `sheets.get_values`
- `sheets.update_values`
- `sheets.append_values`
- `sheets.clear_values`

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
- `sheets.update_values` and `sheets.append_values` require a two-dimensional `values` array.
- Runtime handshake installs a `CapabilityVerifier`.
- Runtime `invoke` requires `capability_token`, computes `google-sheets:spreadsheet:{spreadsheet_id}`, and verifies a bound token before provider execution.
- `health()`, `doctor()`, and `self_check()` are local configuration checks only. They do not probe Google Sheets.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest connector ID is `fcp.google_sheets`, while runtime `BaseConnector` ID is `google-sheets`.
- Runtime handshake returns placeholder manifest hash `sha256:google-sheets-connector-v1` even though the manifest carries a concrete `interface_hash`.
- Runtime `handle_simulate` is permissive. It returns `would_execute = true` for any supplied operation string and does not validate operation inventory, configured state, handshake state, input, capability, or capability token.
- `SheetsClient` stores an `HttpRetryConfig`, but the current HTTP helpers call `reqwest` directly and do not execute the shared retry loop.
- Runtime `handle_shutdown` shuts down the client runtime and sets `client = None`, but it does not clear verifier, session, configured flag, or handshaken flag.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should make `simulate` enforce the same operation/input/capability rules as `invoke`, wire the stored retry config or remove it, replace the placeholder handshake hash, and reset lifecycle state consistently on shutdown.

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

## Auth And Scope Boundary

- Authentication mechanisms: Google bearer token, host credential reference, or OAuth refresh material through the shared Google auth layer.
- Home zone: `z:private`.
- Allowed source zones: `z:owner` and `z:private`.
- Allowed target zone: `z:private`.
- Forbidden zones: `z:public` and `z:work`.
- Runtime capability surface:
  - `sheets.read` gates spreadsheet metadata and value reads.
  - `sheets.write` gates update, append, and clear.
- Manifest capability surface uses `sheets.read` and `sheets.write` as optional capabilities.
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
| `sheets.write` | Update, append, and clear cell values. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `sheets.get_spreadsheet` | `GET /v4/spreadsheets/{spreadsheet_id}` | `sheets.read` | `Safe` | `Low` | `Strict` | Reads spreadsheet metadata and sheet list. |
| `sheets.get_values` | `GET /v4/spreadsheets/{spreadsheet_id}/values/{range}` | `sheets.read` | `Safe` | `Low` | `Strict` | Reads cell values from an A1 notation range. |
| `sheets.update_values` | `PUT /v4/spreadsheets/{spreadsheet_id}/values/{range}?valueInputOption=USER_ENTERED` | `sheets.write` | `Risky` | `Medium` | `BestEffort` | Writes a two-dimensional array to a range. |
| `sheets.append_values` | `POST /v4/spreadsheets/{spreadsheet_id}/values/{range}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS` | `sheets.write` | `Risky` | `Medium` | `None` | Appends rows to the detected table below a range. |
| `sheets.clear_values` | `POST /v4/spreadsheets/{spreadsheet_id}/values/{range}:clear` | `sheets.write` | `Dangerous` | `High` | `Strict` | Clears values in a range while leaving formatting. |

## Resource URIs

Runtime capability-token verification binds all supported operations to this resource URI shape:

| Operation family | Resource URI |
|------------------|--------------|
| spreadsheet metadata, range reads, updates, appends, clears | `google-sheets:spreadsheet:{spreadsheet_id}` |

## Explicit Non-Goals

The current implementation does not include:

- spreadsheet creation, sheet creation/deletion, formatting, charts, filters, pivot tables, protected ranges, named ranges, or batchUpdate structural edits
- Drive file export, Drive placement, file permissions, sharing, or revision history
- formula analysis, formula execution controls, CSV import/export, durable caches, sync-token storage, or connector-local credential vaulting
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

There is no dedicated tracked `scripts/e2e/google_sheets_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

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
- If `sheets.append_values` duplicates rows, the operation is intentionally not idempotent.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-sheets-readme cargo check -p fcp-google-sheets --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-sheets-readme cargo test -p fcp-google-sheets --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-sheets-readme cargo clippy -p fcp-google-sheets --all-targets --no-deps -- -D warnings`
- `ubs connectors/google-sheets/README.md`
