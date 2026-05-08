# Dropbox Connector V3 Contract

> **Status**: runtime contract documented with known handler/manifest drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://www.dropbox.com/developers/documentation/http/documentation
> **OAuth upstream**: https://www.dropbox.com/developers/reference/oauth-guide

## Purpose

This document fixes the operator-facing contract for `fcp.dropbox`. The connector exposes the Dropbox file-metadata and account surface implemented in this crate: folder listing, pagination, metadata reads, folder creation, delete, move, copy, search, current-account reads, and space-usage reads.

The connector is intentionally a small Dropbox API v2 bridge. It is not a full Dropbox SDK, sync engine, content upload/download client, shared-link manager, webhook receiver, team administration client, Paper client, backup tool, or OAuth refresh-token manager.

## Current Runtime Snapshot

The current runtime exposes these operations:

- `dropbox.files.list`
- `dropbox.files.list_continue`
- `dropbox.files.get_metadata`
- `dropbox.files.create_folder`
- `dropbox.files.delete`
- `dropbox.files.move`
- `dropbox.files.copy`
- `dropbox.files.search`
- `dropbox.account.get_space_usage`
- `dropbox.account.get_current`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of:
  - `access_token`
  - `credential_id`
- `access_token` is trimmed and must be non-empty.
- `credential_id` must be a valid UUID and is treated as secretless egress-proxy metadata.
- Default metadata API base URL is `https://api.dropboxapi.com/2`.
- Default content API URL is `https://content.dropboxapi.com/2`.
- `base_url` and `content_url` validation rejects userinfo, query strings, and fragments before request construction.
- Endpoint policy allows HTTPS `api.dropboxapi.com`, HTTPS `content.dropboxapi.com`, and loopback hosts for deterministic tests.
- Bearer-token mode sends `Authorization: Bearer <token>`.
- Credential-id mode sends `X-FCP-Credential-Id: <uuid>`.
- HTTP client timeout is `30 seconds`.
- The client stores a retry configuration with `max_retries = 2`, but the current `post` helper calls `reqwest` directly and does not run the shared retry loop.
- All currently exposed Dropbox API calls use `POST` with JSON bodies through the metadata API base URL.
- `content_url` is configured and validated, but no currently exposed runtime operation uses Dropbox file-content endpoints.
- Provider 401, 403, 404, 409 path/not-found, 429, and other failures map to FCP errors.
- `health` is local readiness only and considers the connector healthy only when configured and a `session_id` was supplied during handshake.
- `self_check` is local provisioning validation only; it does not probe the Dropbox API.
- `credential_id` mode makes `self_check` degraded with `credential_injection_required`.
- `introspect` exposes no streaming support.

## Known Contract Gaps

The current implementation has several intentional truthfulness notes:

- The connector uses a legacy `handle_*` method surface rather than the full typed `FcpConnector` trait implementation used by newer connectors.
- `BaseConnector` is initialized with connector ID `dropbox`, while the manifest and handshake payload use `fcp.dropbox`.
- `invoke` checks generic configured/handshaken readiness, but it does not verify a bound capability token for the requested operation.
- `simulate` only checks whether an operation ID is known; it does not validate readiness, input schema, approval state, or capability tokens.
- `manifest.toml` declares only `dropbox.files.list`, `dropbox.files.get_metadata`, `dropbox.files.delete`, and `dropbox.sharing.list`.
- Runtime exposes `dropbox.files.list_continue`, `dropbox.files.create_folder`, `dropbox.files.move`, `dropbox.files.copy`, `dropbox.files.search`, `dropbox.account.get_space_usage`, and `dropbox.account.get_current`, which are not declared in the manifest operation catalog.
- The manifest declares `dropbox.sharing.list`, and the client has a `list_shared_links` helper, but runtime introspection and invoke dispatch do not expose `dropbox.sharing.list`.
- Runtime handshake and introspection use `dropbox.account.read`, but the manifest optional capability list does not include `dropbox.account.read`.
- The manifest marks `dropbox.files.delete` as interactive, but runtime `OperationInfo` currently sets `requires_approval` to `None` for all operations.
- The manifest mentions OAuth2 access and refresh token storage. The runtime accepts an access token or credential reference; it does not manage refresh tokens after configuration.
- The runtime configures `content_url`, but the current operation set does not implement file upload, file download, or media download despite the manifest optional `media.download` capability.
- Retryability is represented in `DropboxError`, but the live HTTP helper does not currently use the configured retry loop.

Operators should treat this README as the current truthfulness snapshot. A follow-up should align the handler surface, connector ID, manifest operation catalog, account capability metadata, sharing operation exposure, capability-token enforcement, approval metadata, refresh-token behavior, and retry dispatch before this connector is described as a fully modern FCP connector.

## First-Slice Scope

The current Dropbox README slice documents the existing runtime surface:

- access-token and credential-id configuration
- Dropbox API v2 base URL and content URL policy
- folder listing and cursor continuation
- metadata reads
- folder creation
- file/folder delete, move, and copy
- search
- current-account and space-usage reads
- OAuth2 Authorization Code PKCE provisioning recipe metadata
- lifecycle, doctor, health, self-check, introspection, simulation, and shutdown surfaces
- deterministic WireMock tests for provider request paths and provider error mapping

## Auth And Scope Boundary

- Authentication mechanisms: Dropbox OAuth2 access token or host credential reference.
- The provisioning recipe describes OAuth2 Authorization Code PKCE with scopes:
  - `files.metadata.read`
  - `files.metadata.write`
  - `files.content.read`
  - `files.content.write`
  - `account_info.read`
- Runtime configuration accepts only `access_token` or `credential_id`; it does not implement an interactive OAuth callback server or refresh-token lifecycle.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Capability surface:
  - `dropbox.files.read` gates folder listing, pagination, metadata reads, and search.
  - `dropbox.files.write` gates folder creation, move, and copy.
  - `dropbox.files.delete` gates delete.
  - `dropbox.account.read` gates current-account and space-usage reads in runtime metadata.
  - `dropbox.sharing.read` is present in the manifest but not currently exposed by runtime invocation.
- The connector does not persist Dropbox responses, paths, cursor strings, account IDs, email addresses, access tokens, credential IDs beyond configuration metadata, provider payloads, or provider error bodies.

## Network And Runtime Invariants

- Production metadata host: `api.dropboxapi.com`.
- Production content host: `content.dropboxapi.com`.
- Production API prefix: `/2`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback overrides are test-only.
- Runtime request timeout is `30 seconds`.
- Manifest network constraints set `10_000 ms` connect timeout and `30_000 ms` total timeout.
- Maximum response bytes are `10_485_760` for listing/sharing reads and `1_048_576` for metadata/delete responses.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open listeners and does not implement subscriptions.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `dropbox.files.list` | `POST /files/list_folder` | `dropbox.files.read` | `Safe` | `Low` | `Strict` | Reads files and folders at one Dropbox path. |
| `dropbox.files.list_continue` | `POST /files/list_folder/continue` | `dropbox.files.read` | `Safe` | `Low` | `Strict` | Continues a prior folder listing with a cursor. |
| `dropbox.files.get_metadata` | `POST /files/get_metadata` | `dropbox.files.read` | `Safe` | `Low` | `Strict` | Reads metadata for one file or folder path. |
| `dropbox.files.create_folder` | `POST /files/create_folder_v2` | `dropbox.files.write` | `Risky` | `Medium` | `None` | Creates provider-visible folder state. |
| `dropbox.files.delete` | `POST /files/delete_v2` | `dropbox.files.delete` | `Dangerous` | `High` | `None` | Deletes a file or folder from the active Dropbox namespace. |
| `dropbox.files.move` | `POST /files/move_v2` | `dropbox.files.write` | `Risky` | `Medium` | `None` | Moves a file or folder and changes provider-visible paths. |
| `dropbox.files.copy` | `POST /files/copy_v2` | `dropbox.files.write` | `Risky` | `Medium` | `None` | Copies a file or folder and creates provider-visible state. |
| `dropbox.files.search` | `POST /files/search_v2` | `dropbox.files.read` | `Safe` | `Low` | `Strict` | Searches visible Dropbox files by query. |
| `dropbox.account.get_space_usage` | `POST /users/get_space_usage` | `dropbox.account.read` | `Safe` | `Low` | `Strict` | Reads account storage usage and allocation. |
| `dropbox.account.get_current` | `POST /users/get_current_account` | `dropbox.account.read` | `Safe` | `Low` | `Strict` | Reads current authenticated account metadata. |

## Explicit Non-Goals

The current implementation does not include:

- OAuth callback handling, token exchange execution, token refresh, or multi-user token storage
- file upload, file download, temporary links, file locks, revisions, restore, thumbnails, previews, exports, or media download
- shared-link listing through runtime invocation despite the manifest entry and client helper
- team folders, team spaces, team admin, member management, groups, namespaces, or enterprise audit APIs
- webhook/event subscriptions or longpolling
- sync, delta reconciliation, offline cache, conflict resolution, or local filesystem mirroring
- Paper, Sign, Transfer, Capture, DocSend, or Dropbox Dash APIs
- connector-local credential vaulting

These are excluded on purpose:

- Runtime invocation is currently a small handler-style bridge and should stay narrow until capability enforcement is upgraded.
- File/folder delete, move, copy, and create-folder operations mutate remote storage state and need explicit operation contracts.
- Broader Dropbox coverage needs separate provider fixtures, content-endpoint handling, account/team permission modeling, and refresh-token behavior.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration and handshake state
- request and error counters
- auth mode as bearer token or credential ID
- credential-injection requirement for credential-id mode
- base URL policy and loopback verification allowance
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- simulation allow/deny based only on known operation ID
- self-check degradation for unconfigured, missing client, invalid network policy, or credential-injection mode

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle health, doctor, self-check, introspection, simulate, and shutdown behavior
- bearer-token auth header propagation and credential-id header propagation
- folder listing, cursor continuation, metadata reads, folder creation, delete, move, copy, search, space usage, and current-account WireMock requests
- missing required input fields
- provider 401, 403, path/not-found, 429, and 500-class error mapping
- unknown operation and simulation behavior
- request/error counters
- configuration validation, credential-id validation, base URL policy, content URL policy, query/fragment/userinfo rejection, and loopback allowances

## Source Notes

- `connectors/dropbox/src/connector.rs` defines configuration parsing, base URL policy, lifecycle handlers, diagnostics, simulation, operation metadata, provisioning recipe, and invoke dispatch.
- `connectors/dropbox/src/client.rs` defines request construction, auth headers, timeout setup, Dropbox API paths, response parsing, and provider error parsing.
- `connectors/dropbox/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/dropbox/src/types.rs` defines Dropbox API error response shapes.
- `connectors/dropbox/manifest.toml` defines the partial operation catalog, network constraints, sandbox boundary, zone policy, rate limits, and AI hints.
- `connectors/dropbox/tests/integration.rs` covers deterministic HTTP behavior and handler lifecycle behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/dropbox_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation contract tests
- deterministic WireMock coverage for the ten runtime operations
- auth, base URL, content URL, input validation, provider error, lifecycle, introspection, simulation, and shutdown tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a disposable Dropbox app and test account for live verification.
- Prefer a short-lived OAuth2 access token scoped only to test data.
- Use WireMock loopback fixtures for routine proof.
- Use credential-id mode only when the host or egress proxy is ready to inject Dropbox auth.

**Dedicated environment**:

- Keep live folder creation, delete, move, and copy checks confined to disposable folders.
- Never run delete, move, or copy checks against production Dropbox data.
- Use synthetic paths and fixture account data in logs and transcripts.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, cursor strings, account IDs, email addresses, file paths when sensitive, provider payloads, provider error bodies, and local paths.
- Verification output should use operation IDs, endpoint shapes, host classes, status/error classes, retry decisions, and synthetic Dropbox resource identifiers.

**Common remediation**:

- If configuration fails, provide exactly one of `access_token` or `credential_id`.
- If endpoint policy rejects a URL, use `https://api.dropboxapi.com/2`, `https://content.dropboxapi.com/2`, or a loopback test origin.
- If credential-id mode self-check reports `credential_injection_required`, use direct access-token mode or wire the egress proxy injection path.
- If invocation fails with readiness errors, configure and handshake with a non-empty `session_id` before invoking.
- If Dropbox returns path errors, confirm that root listing uses the empty string rather than `/`.
- If repeated 500 or 429 errors appear, remember that the current direct HTTP helper does not run the configured retry loop.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-dropbox-readme cargo check -p fcp-dropbox --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-dropbox-readme cargo test -p fcp-dropbox --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-dropbox-readme cargo clippy -p fcp-dropbox --all-targets --no-deps -- -D warnings`
- `ubs connectors/dropbox/README.md`
