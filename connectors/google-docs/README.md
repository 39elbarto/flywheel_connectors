# Google Docs Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Docs API upstream**: https://developers.google.com/docs/api/reference/rest/v1/documents
> **Documents create upstream**: https://developers.google.com/docs/api/reference/rest/v1/documents/create
> **Documents get upstream**: https://developers.google.com/docs/api/reference/rest/v1/documents/get
> **Documents batchUpdate upstream**: https://developers.google.com/docs/api/reference/rest/v1/documents/batchUpdate

## Purpose

This document fixes the operator-facing contract for `fcp.google_docs`. The connector exposes the Google Docs API surface implemented in this crate: document lookup, document creation, and batch document updates.

The connector is intentionally a bounded Docs bridge. It is not a full Google Drive client, export client, comment client, suggestion review client, permission manager, template system, Workspace provisioning tool, or long-running document warehouse.

## Current Runtime Snapshot

The current crate exposes these operations:

- `docs.get`
- `docs.create`
- `docs.batch_update`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-google-docs`.
- Runtime `BaseConnector` ID is `google-docs`.
- Configuration accepts Google auth either at the top level or under `auth`.
- Configuration requires exactly one Google auth source accepted by `GoogleAuthSelection`: direct bearer token, `credential_id`, or `oauth_refresh`.
- Direct bearer-token mode sends the Google Authorization header through `GoogleRestExecutor`.
- `credential_id` mode is secretless and reports `configured_pending_token_materialization`.
- Default base URL is `https://docs.googleapis.com/v1`.
- Public base URLs must use HTTPS, must target exact host `docs.googleapis.com`, and must not contain userinfo, query strings, or fragments.
- `localhost`, `127.0.0.1`, and `::1` are accepted with HTTP or HTTPS for deterministic loopback tests.
- Runtime request timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 2`, `initial_delay_ms = 500`, `max_delay_ms = 30000`, and jitter enabled.
- Document IDs are inserted into URL path segments only after local path-segment validation.
- Path-segment validation rejects empty strings, slashes, backslashes, `..`, query strings, fragments, encoded slash/backslash/query/fragment markers, and literal percent characters.
- `docs.create` posts only a title field to the provider.
- `docs.batch_update` requires a non-empty JSON array in `requests` and passes that array through to Google.
- Runtime handshake installs a `CapabilityVerifier`.
- `invoke` requires `capability_token`, validates input, computes resource URIs, and verifies a bound capability token before provider execution.
- `simulate` validates operation inventory, input shape, configured/handshaken state, and bound capability token before returning an allowed result.
- `health()`, `doctor()`, and `self_check()` are local configuration checks only. They do not probe the Google Docs API.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest connector ID is `fcp.google_docs`, while runtime `BaseConnector` ID is `google-docs`.
- Runtime handshake returns placeholder manifest hash `sha256:google-docs-connector-v1`.
- Manifest `interface_hash` is `blake3-256:fcp.interface.v2:google_docs_v1`, which is a named placeholder-style string rather than a concrete digest.
- Runtime `handle_shutdown` shuts down the client runtime and sets `client = None`, but it leaves verifier, session, and other lifecycle state in place.
- `doctor()` and `self_check()` report configured/local readiness only, not provider reachability or credential validity.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should align connector ID spelling, replace placeholder manifest/interface proofs, add provider-backed readiness when desired, reset lifecycle state consistently on shutdown, and decide whether Docs-specific Drive export, placement, permission, comment, or suggestion surfaces belong in this connector.

## First-Slice Scope

The current Google Docs README slice documents the existing runtime surface:

- Google bearer-token, credential-reference, and OAuth refresh auth selection
- Docs API base URL policy and loopback test allowance
- document get, create, and batch update operations
- bound capability-token verification during both `invoke` and `simulate`
- provider error mapping, retry behavior, redaction posture, and health behavior
- lifecycle, doctor, health, self-check, introspection, simulation, invoke, and shutdown surfaces
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Google bearer token, host credential reference, or OAuth refresh material through the shared Google auth layer.
- Home zone: `z:private`.
- Allowed source zones: `z:owner` and `z:private`.
- Allowed target zone: `z:private`.
- Forbidden zone: `z:public`.
- Runtime capability surface:
  - `docs.read` gates document lookup.
  - `docs.write` gates document creation and batch update.
- Manifest capability surface uses `docs.read` and `docs.write` as optional capabilities.
- The connector does not persist documents, document bodies, titles, access tokens, credential IDs, provider payloads, or provider error bodies beyond process memory.
- Google Docs documents can contain private text, comments rendered in structural payloads, named styles, embedded objects, and linked Drive metadata. Treat all live reads and writes as private-zone data.

## Network And Runtime Invariants

- Production host: `docs.googleapis.com`.
- Production API prefix: `/v1`.
- Production port: `443`.
- TLS and SNI are required by the manifest for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback base URLs are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints use `10_000 ms` connect timeout and `30_000 ms` total timeout.
- Manifest maximum response bytes are `1_048_576` for create and `5_242_880` for get and batch update.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `30_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.
- The connector does not implement streaming events or replay.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `docs.read` | Read Google Docs documents visible to the authenticated principal. |
| `docs.write` | Create documents and apply batch update requests. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `docs.get` | `GET /v1/documents/{document_id}` | `docs.read` | `Safe` | `Low` | `Strict` | Reads one Google Docs document by ID. |
| `docs.create` | `POST /v1/documents` | `docs.write` | `Risky` | `Medium` | `None` | Creates a new document for the authenticated principal. |
| `docs.batch_update` | `POST /v1/documents/{document_id}:batchUpdate` | `docs.write` | `Risky` | `High` | `BestEffort` | Applies ordered structural edits to an existing document. |

## Resource URIs

Runtime capability-token verification binds operations to these resource URI shapes:

| Operation | Resource URI |
|-----------|--------------|
| `docs.get` | `google-docs:document:{document_id}` |
| `docs.create` | `google-docs:documents` |
| `docs.batch_update` | `google-docs:document:{document_id}` |

## Explicit Non-Goals

The current implementation does not include:

- Drive file export, media download, file placement, file metadata, or permission management
- comments, replies, suggestion review, named range management, structural diffing, template filling, or document merge workflows
- OAuth consent setup, Docs API enablement, service-account/domain-wide delegation provisioning, or Google Workspace tenant onboarding
- durable document caches, revision history, audit export, long-running pagination jobs, or connector-local credential vaulting
- streaming document changes, push notifications, or webhook receiving

These are excluded on purpose:

- Docs payloads are high-sensitivity user content.
- Batch update requests are order-sensitive and index-sensitive.
- Drive file lifecycle and permission behavior belongs behind a separate Drive contract unless explicitly unified.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration and local client state
- operation metadata with capability, risk, safety tier, idempotency, schemas, and AI hints
- bound capability-token verification during `invoke`
- simulation denial for unknown operation, unconfigured connector, missing handshake, invalid input, and bound capability-token mismatch
- local-only readiness for configured state
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, base URL policy, loopback allowance, introspection, simulation, and shutdown behavior
- document get, create, and batch update through deterministic HTTP fixtures
- invoke rejection for unknown operation, missing token, missing input, wrong capability, and pre-provider capability verification
- provider 401, 403, 404, 429, retryable transport/server classes, malformed JSON, and FCP error mapping
- path-segment validation for traversal and double-encoded separators

## Source Notes

- `connectors/google-docs/src/connector.rs` defines configuration parsing, base URL policy, lifecycle handlers, introspection, simulation, capability-token verification, resource URI binding, and invoke dispatch.
- `connectors/google-docs/src/client.rs` defines Docs paths, Google auth application, retry dispatch, timeout, request metrics, path-segment validation, and provider error mapping.
- `connectors/google-docs/src/types.rs` defines document and batch update request/response shapes.
- `connectors/google-docs/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/google-docs/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, and rate-limit pools.
- `connectors/google-docs/tests/connector_suite_happy_path.rs` covers deterministic runtime behavior and connector-suite expectations.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/google_docs_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for Docs API paths
- auth, endpoint policy, provider error, lifecycle, simulation, and introspection tests
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Google account or Workspace test tenant with Docs API access enabled for live verification.
- Prefer credential-reference mode when host policy should own Google secret material.
- Use loopback WireMock fixtures for routine proof.

**Dedicated environment**:

- Keep test documents separate from personal and production documents.
- Use disposable document IDs for batch update proof.
- Keep batch update request arrays small and deterministic in smoke tests.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, document IDs when sensitive, titles, document body content, embedded object IDs, provider payloads, provider error bodies, and endpoint URLs when they reveal tenant topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, retry decisions, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide exactly one Google auth source.
- If live checks fail with a credential reference, materialize host credentials before invoking provider operations.
- If `docs.get` fails, verify the ID is a Google Docs document and the authenticated principal can read it.
- If `docs.batch_update` fails validation, pass a non-empty `requests` array and avoid relying on stale document indexes.
- If provider returns 403, treat it as an auth/permission failure rather than a retryable transport error.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-docs-readme cargo check -p fcp-google-docs --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-docs-readme cargo test -p fcp-google-docs --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-docs-readme cargo clippy -p fcp-google-docs --all-targets --no-deps -- -D warnings`
- `ubs connectors/google-docs/README.md`
