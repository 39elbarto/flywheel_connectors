# Figma Connector V3 Contract

> **Status**: runtime contract documented with endpoint-policy and capability-pool drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Figma REST API upstream**: https://developers.figma.com/docs/rest-api/
> **Figma auth upstream**: https://developers.figma.com/docs/rest-api/authentication/
> **Figma scopes upstream**: https://developers.figma.com/docs/rest-api/scopes/
> **Figma comments upstream**: https://developers.figma.com/docs/rest-api/comments-endpoints/
> **Figma webhooks upstream**: https://developers.figma.com/docs/rest-api/webhooks/

## Purpose

This document fixes the operator-facing contract for `fcp.figma`. The connector exposes the Figma REST API and local design-analysis surface implemented in this crate: teams, projects, files, nodes, components, styles, image export URLs, versions, comments, webhook management, design-token extraction, component bundling, and design-audit macros.

The connector is intentionally a bounded Figma bridge. It is not a full Figma platform SDK, OAuth app manager, Plugin API runtime, Widget API runtime, MCP client, image downloader, webhook receiver, organization admin client, activity-log client, or durable design-system warehouse.

## Current Runtime Snapshot

The current crate exposes these operations:

- `figma.list_team_projects`
- `figma.list_project_files`
- `figma.get_file_meta`
- `figma.get_file`
- `figma.get_file_nodes`
- `figma.get_file_components`
- `figma.get_file_styles`
- `figma.export_images`
- `figma.list_file_versions`
- `figma.list_comments`
- `figma.post_comment`
- `figma.delete_comment`
- `figma.list_webhooks`
- `figma.create_webhook`
- `figma.delete_webhook`
- `figma.styles.list`
- `figma.tokens.export`
- `figma.macro.export_component_bundle`
- `figma.macro.design_audit`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-figma`.
- Runtime `BaseConnector` ID is `figma`.
- Configuration accepts exactly one of:
  - `token`
  - `credential_id`
- `token` mode sends `X-FIGMA-TOKEN: <token>`.
- `credential_id` must be a valid UUID and sends `X-FCP-Credential-ID: <uuid>`.
- Default base URL is `https://api.figma.com/v1`.
- Runtime configuration accepts a caller-supplied `base_url` string without scheme, host, userinfo, query string, or fragment validation.
- Runtime HTTP timeout is `60 seconds` at the reqwest client layer and `30 seconds` at the connector runtime request context layer.
- Runtime retry policy uses the shared retry loop with `max_retries = 2`; client fields also retain legacy `max_retries = 3`, `initial_delay_ms = 1000`, and `max_delay_ms = 60000`.
- Rate-limit handling honors `Retry-After` when Figma returns HTTP 429 and otherwise uses a 60-second retry hint.
- Provider response/error bodies are truncated to 2048 bytes before surfacing API errors.
- Webhook operations use the Figma v2 API by appending `../v2/webhooks` paths relative to the configured `/v1` base URL.
- `health` is local configured/client state only and reports metrics from `BaseConnector`.
- `doctor` checks local configuration, client initialization, base URL, auth mode, network constraint label, and credential-injection mode.
- `self_check` calls `GET /me` for direct-token mode, and returns `credential_injection_required` for credential-id mode.
- Runtime handshake installs a `CapabilityVerifier`.
- `invoke` requires a serialized `capability_token`, resolves the required operation capability, and verifies a bound capability token before provider execution.
- `simulate` validates configured state, handshaken state, known operation, and bound capability token before returning an allow/deny response.
- Runtime introspection exposes 19 operations and no event resource types.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest connector ID is `fcp.figma`, while runtime `BaseConnector` ID is `figma`.
- Runtime handshake returns placeholder manifest hash `sha256:figma-connector-v1`.
- Manifest and runtime default to `https://api.figma.com/v1`, while official Figma REST docs describe the common base URL as `https://api.figma.com` with endpoint paths under `/v1`.
- Official Figma docs also describe Figma for Government as `https://api.figma-gov.com`; runtime custom `base_url` could point there, but the manifest host policy only names `api.figma.com` and related image/CDN hosts.
- Runtime configuration does not enforce the manifest network constraints or reject unsafe/custom origins.
- Manifest network constraints deny localhost, private ranges, tailnet ranges, and IP literals for live operations, while runtime tests and configuration accept loopback/custom origins as plain strings.
- Runtime `doctor` always marks `network_constraints` as pass and labels egress as `api.figma.com (via {base_url})` without validating the active host.
- Manifest optional capabilities include `media.download`, but runtime `figma.export_images` returns provider download URLs and does not download image bytes.
- Manifest defines a `figma.export` rate-limit pool and maps `figma.export_images` to it, but `figma.export` is not in the optional capability list and runtime capability verification uses `figma.read` for image export.
- Runtime `OperationInfo` currently sets `requires_approval` to `None` for all operations, regardless of manifest approval metadata.
- Runtime schema constraints are only partially enforced before provider dispatch. Required string fields are checked, token export format is checked, and macro caps are clamped, but many enum/range/schema constraints are left to Figma or local helper behavior.
- `handle_shutdown` is local status only. It does not clear config, client, verifier, session, configured flags, or handshaken flags, and it does not call `FigmaClient::shutdown()`.
- Manifest `event_caps` and handshake event caps advertise streaming, but runtime introspection has no events and this connector does not receive or verify inbound Figma webhooks.

A follow-up parity bead should align connector ID spelling, replace placeholder manifest proofs, add base URL policy enforcement, reconcile `figma.export` and `media.download`, decide how Figma Government is represented in policy, add approval metadata to runtime introspection, tighten input validation, and reset lifecycle state consistently on shutdown.

## First-Slice Scope

The current Figma README slice documents the existing runtime surface:

- token and credential-id configuration
- Figma REST v1 and webhook v2 path behavior
- file, node, component, style, image export, version, comment, and webhook operations
- local design token extraction, token export, component bundle, and design audit macros
- bound capability-token verification during both `invoke` and `simulate`
- provider error mapping, retry behavior, redaction posture, doctor behavior, and health behavior
- lifecycle, doctor, health, self-check, introspection, simulation, invoke, and shutdown surfaces
- deterministic WireMock tests and helper unit tests

## Auth And Scope Boundary

- Authentication mechanisms: Figma token or host credential reference.
- Runtime does not implement OAuth authorization, OAuth refresh, plan access token administration, personal access token creation, OAuth app publishing, or connector-local credential vaulting.
- Official Figma docs support OAuth apps, plan access tokens for organization-level automation, and personal access tokens. Runtime accepts only an already-materialized token or credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability surface:
  - `figma.read` gates teams, projects, files, nodes, components, styles, image export URLs, versions, comments, webhooks listing, design tokens, component bundles, and design audits.
  - `figma.write` gates comment creation.
  - `figma.delete` gates comment deletion and webhook deletion.
  - `figma.webhook` gates webhook creation.
- Manifest capability surface also lists `media.download`, but current runtime does not perform image download.
- The connector does not persist files, nodes, comments, webhooks, tokens, styles, exported token output, audit findings, access tokens, credential IDs beyond configuration metadata, provider payloads, or provider error bodies.
- Figma files, comments, versions, components, styles, and generated design tokens can contain private product and customer data. Treat all live reads and writes as work-zone data.

## Network And Runtime Invariants

- Default runtime host: `api.figma.com`.
- Default runtime API prefix: `/v1`.
- Webhook runtime path prefix: `../v2/webhooks` relative to the configured base URL.
- Official common base URL: `https://api.figma.com`.
- Official Figma for Government base URL: `https://api.figma-gov.com`.
- Runtime request construction appends endpoint paths to `base_url`.
- Runtime base URL is not policy-validated before request construction.
- Runtime reqwest timeout: `60 seconds`.
- Runtime request-context timeout: `30 seconds`.
- Runtime retry policy is based on `HttpRetryConfig { max_retries = 2, ..default }`.
- Manifest live-operation network policy requires TLS/SNI and denies localhost, private ranges, tailnet ranges, and IP literals.
- Manifest allows Figma image export/CDN hosts for `figma.export_images`, but runtime only returns image URLs and leaves actual download outside the connector.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets and does not implement webhook receiving.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `figma.read` | Read Figma teams, projects, files, nodes, components, styles, versions, comments, webhooks, and derived design-analysis output. |
| `figma.write` | Create comments on files. |
| `figma.delete` | Delete comments and webhook subscriptions. |
| `figma.webhook` | Create webhook subscriptions. |
| `media.download` | Manifest-only optional capability in this checkout; runtime only returns image URLs. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `figma.list_team_projects` | `GET /v1/teams/{team_id}/projects` | `figma.read` | `Safe` | `Low` | `Strict` | Reads project inventory for a team. |
| `figma.list_project_files` | `GET /v1/projects/{project_id}/files` | `figma.read` | `Safe` | `Low` | `Strict` | Reads file inventory for a project. |
| `figma.get_file_meta` | `GET /v1/files/{file_key}?depth=1` | `figma.read` | `Safe` | `Low` | `Strict` | Reads lightweight file metadata using shallow file retrieval. |
| `figma.get_file` | `GET /v1/files/{file_key}` | `figma.read` | `Safe` | `Low` | `Strict` | Reads a full or partial Figma file document tree. |
| `figma.get_file_nodes` | `GET /v1/files/{file_key}/nodes` | `figma.read` | `Safe` | `Low` | `Strict` | Reads specific node subtrees. |
| `figma.get_file_components` | `GET /v1/files/{file_key}/components` | `figma.read` | `Safe` | `Low` | `Strict` | Reads published component metadata for a file. |
| `figma.get_file_styles` | `GET /v1/files/{file_key}/styles` | `figma.read` | `Safe` | `Low` | `Strict` | Reads published style metadata for a file. |
| `figma.export_images` | `GET /v1/images/{file_key}` | `figma.read` | `Safe` | `Low` | `Strict` | Returns time-limited image URLs for caller-supplied node IDs and format. |
| `figma.list_file_versions` | `GET /v1/files/{file_key}/versions` | `figma.read` | `Safe` | `Low` | `Strict` | Reads version history metadata. |
| `figma.list_comments` | `GET /v1/files/{file_key}/comments` | `figma.read` | `Safe` | `Low` | `Strict` | Reads comments and optional markdown-formatted comment text. |
| `figma.post_comment` | `POST /v1/files/{file_key}/comments` | `figma.write` | `Safe` | `Low` | `None` | Creates a visible comment or reply in a Figma file. |
| `figma.delete_comment` | `DELETE /v1/files/{file_key}/comments/{comment_id}` | `figma.delete` | `Risky` | `Medium` | `Strict` | Deletes a comment when provider permissions allow it. |
| `figma.list_webhooks` | `GET /v2/webhooks/{team_id}` | `figma.read` | `Safe` | `Low` | `Strict` | Reads webhook subscriptions for a team. |
| `figma.create_webhook` | `POST /v2/webhooks` | `figma.webhook` | `Risky` | `Medium` | `None` | Creates provider-visible webhook subscription state. |
| `figma.delete_webhook` | `DELETE /v2/webhooks/{webhook_id}` | `figma.delete` | `Risky` | `Medium` | `Strict` | Removes provider webhook subscription state. |
| `figma.styles.list` | `GET /v1/files/{file_key}/styles` plus local transform | `figma.read` | `Safe` | `Low` | `Strict` | Converts published styles into normalized design-token entries. |
| `figma.tokens.export` | `GET /v1/files/{file_key}/styles` plus local transform | `figma.read` | `Safe` | `Low` | `Strict` | Emits normalized token output as JSON or CSS custom properties. |
| `figma.macro.export_component_bundle` | `GET /components` and optional `GET /styles` | `figma.read` | `Safe` | `Low` | `Strict` | Produces a bounded component bundle, optionally with tokens. |
| `figma.macro.design_audit` | `GET /files`, `GET /components`, `GET /styles` plus local checks | `figma.read` | `Safe` | `Low` | `Strict` | Runs bounded local checks for naming, styles, structure, and tokens. |

## Explicit Non-Goals

The current implementation does not include:

- OAuth authorization, OAuth token refresh, app publishing, plan access token management, or personal access token generation
- Plugin API, Widget API, Embed API, MCP Server, Dev Mode integration, or browser/UI automation
- image byte download, image caching, image checksum verification, or storage of exported assets
- variable endpoints, dev resources, activity logs, analytics, organization admin APIs, discovery APIs, or text events
- comment reactions, file branch management, file publishing, library analytics, or permission management
- webhook receiving, passcode verification for inbound payloads, retry handling for inbound events, or event replay
- durable indexing of files, nodes, styles, comments, versions, webhooks, or audit results

These are excluded on purpose:

- Figma file trees and comments can expose sensitive design, product, and customer context.
- Image export returns time-limited URLs, and downloading those bytes requires a separate media/download policy boundary.
- Webhook creation changes provider state, while receiving and verifying webhook payloads requires an inbound listener that this connector does not expose.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration and local client state
- request and error metrics
- auth mode as token or credential ID
- base URL string, without strong runtime policy validation
- credential-injection requirement for credential-id mode
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- bound capability-token verification during `invoke`
- simulation denial for unknown operation, unconfigured connector, missing handshake, invalid bound capability token, and operation/capability mismatch
- provider-backed self-check through `GET /me` for direct-token mode

The deterministic integration evidence is anchored on connector-local tests covering:

- happy-path WireMock requests for files, nodes, components, styles, images, versions, comments, webhooks, teams, projects, file metadata, design tokens, component bundle, and design audit behavior
- provider 401, 403, 404, 429, and 500-class error mapping
- retry behavior for rate-limit responses with and without `Retry-After`
- FCP2 default-deny behavior for missing handshake, missing capability token, wrong capability, unknown operation, and simulate mismatch
- lifecycle health, handshake, introspection, shutdown, risk levels, doctor, and self-check behavior
- configuration validation for token, credential-id, both auth modes, no auth, custom base URLs, and credential-id diagnostics
- input validation for required fields and helper tests for token normalization, CSS export, component bundle serialization, and design-audit findings

## Source Notes

- `connectors/figma/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, introspection, simulation, capability-token verification, invoke dispatch, design-token transforms, component bundling, and design-audit logic.
- `connectors/figma/src/client.rs` defines Figma REST request construction, auth headers, retry dispatch, timeout setup, API paths, webhook v2 path construction, response parsing, and provider error handling.
- `connectors/figma/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/figma/src/types.rs` defines Figma teams, projects, files, nodes, components, styles, comments, webhooks, image exports, versions, design tokens, component bundles, and design-audit response shapes.
- `connectors/figma/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, rate limits, and AI hints.
- `connectors/figma/tests/integration.rs` covers deterministic HTTP behavior and FCP2 capability behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/figma_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for Figma REST paths
- auth, retry, provider error, lifecycle, simulation, introspection, and bound capability-token tests
- design-token extraction, token export, component bundle, and audit helper tests
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use WireMock fixtures for routine verification.
- Use a disposable Figma team/project/file for live checks.
- Prefer credential-id mode only when the host or egress proxy is ready to inject Figma auth.

**Dedicated environment**:

- Keep live comments, webhook subscriptions, and export checks confined to disposable Figma files or teams.
- Never create or delete webhooks against production teams without explicit operator approval.
- Use synthetic file keys, node IDs, project IDs, team IDs, comment bodies, webhook endpoints, and passcodes in logs and transcripts.

**Redaction rules**:

- Redact tokens, credential IDs where needed, file keys, team IDs, project IDs, node IDs, comment bodies, webhook endpoints, webhook passcodes, design content, provider payloads, provider error bodies, and local paths.
- Verification output should use operation IDs, endpoint shapes, host classes, status/error classes, retry decisions, and synthetic Figma resource identifiers.

**Common remediation**:

- If configuration fails, provide exactly one of `token` or `credential_id`.
- If credential-id mode self-check reports `credential_injection_required`, use direct token mode or wire the egress proxy injection path.
- If invocation fails with capability errors, complete handshake first and pass a bound token whose operation and capability match the requested operation.
- If live provider calls fail with 403, verify Figma token scopes such as file content, comments, metadata, and webhook access according to the official scope table.
- If webhook calls fail, verify that the token and user have permissions for the target team/project/file context and that the endpoint is externally reachable for live webhook delivery.
- If image export returns URLs but no bytes, remember that this connector does not download the generated assets.
- If a custom base URL behaves unexpectedly, inspect the constructed path, especially webhook paths using `../v2/webhooks`.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-figma-readme cargo check -p fcp-figma --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-figma-readme cargo test -p fcp-figma --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-figma-readme cargo clippy -p fcp-figma --all-targets --no-deps -- -D warnings`
- `ubs connectors/figma/README.md`
