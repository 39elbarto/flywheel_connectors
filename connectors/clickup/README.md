# ClickUp Connector V3 Contract

> **Status**: runtime contract documented with known handler/manifest drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://developer.clickup.com/reference
> **Authentication upstream**: https://developer.clickup.com/docs/authentication

## Purpose

This document fixes the operator-facing contract for `fcp.clickup`. The connector exposes the ClickUp project-management surface implemented in this crate: workspace spaces, space lists, list tasks, task creation, and task deletion.

The connector is intentionally a small ClickUp API v2 bridge. It is not a full ClickUp SDK, OAuth app workflow, webhook receiver, Docs API client, custom-field editor, attachment client, time-tracking client, automation client, or workspace administration surface.

## Current Runtime Snapshot

The current runtime exposes these operations:

- `clickup.spaces.list`
- `clickup.lists.list`
- `clickup.tasks.list`
- `clickup.tasks.create`
- `clickup.tasks.delete`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of:
  - `api_token`
  - `credential_id`
- `api_token` is trimmed and must be non-empty.
- `credential_id` must be a valid UUID and is treated as secretless egress-proxy metadata.
- Default base URL is `https://api.clickup.com/api/v2`.
- API-token mode allows only HTTPS `api.clickup.com` plus loopback verification hosts.
- Credential-id mode allows any HTTPS host plus loopback verification hosts, because the host or egress proxy can inject credentials.
- Base URL validation rejects userinfo, query strings, and fragments before request construction.
- Personal API-token mode sends `Authorization: <token>` with no `Bearer` prefix, matching ClickUp's personal-token API behavior.
- Credential-id mode sends `X-FCP-Credential-Id: <uuid>`.
- HTTP client timeout is `30 seconds`.
- The client stores a retry configuration with `max_retries = 2`, but the current `get`, `post`, and `delete` helpers call `reqwest` directly and do not run the shared retry loop.
- Path segments are rejected if they are empty, contain path separators, query/fragment delimiters, percent signs, control characters, or traversal values.
- `clickup.tasks.create` currently sends only `{ "name": <name> }`; extra caller fields such as assignee, status, priority, dates, tags, and custom fields are ignored.
- Provider 401, 403, 404, 429, and other failures map to FCP external or invalid-request errors.
- `health` is local readiness only and considers the connector healthy only when configured and a `session_id` was supplied during handshake.
- `self_check` is local provisioning validation only; it does not probe the ClickUp API.
- `introspect` exposes no streaming support.

## Known Contract Gaps

The current implementation has several intentional truthfulness notes:

- The connector uses a legacy `handle_*` method surface rather than the full typed `FcpConnector` trait implementation used by newer connectors.
- `BaseConnector` is initialized with connector ID `clickup`, while the manifest and handshake payload use `fcp.clickup`.
- `invoke` checks generic configured/handshaken readiness, but it does not verify a bound capability token for the requested operation.
- `simulate` only checks whether an operation ID is known; it does not validate readiness, input schema, approval state, or capability tokens.
- The manifest marks `clickup.tasks.create` as policy-approved and `clickup.tasks.delete` as interactive, but runtime `OperationInfo` currently sets `requires_approval` to `None` for all operations.
- The manifest declares `storage.state` and says the connector stores a personal API token. The runtime keeps the active config and client in process memory; the provisioning recipe is the path that asks the host to store `api_token` under `connector:fcp.clickup`.
- Retryability is represented in `ClickUpError`, but the live HTTP helpers do not currently use the configured retry loop.

Operators should treat this README as the current truthfulness snapshot. A follow-up should align the handler surface, connector ID, capability-token enforcement, approval metadata, and retry dispatch before this connector is described as a fully modern FCP connector.

## First-Slice Scope

The current ClickUp README slice documents the existing runtime surface:

- personal API token and credential-id configuration
- ClickUp API v2 base URL policy
- workspace/team space listing
- space list listing
- task listing
- task creation with task name only
- task deletion
- lifecycle, doctor, health, self-check, introspection, simulation, and shutdown surfaces
- deterministic WireMock tests for provider request paths and provider error mapping

## Auth And Scope Boundary

- Authentication mechanisms: ClickUp personal API token or host credential reference.
- OAuth is documented by ClickUp upstream, but this connector does not implement OAuth app creation, authorization-code exchange, token refresh, or per-user token storage.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Capability surface:
  - `clickup.spaces.read` gates workspace/team space listing.
  - `clickup.lists.read` gates space list listing.
  - `clickup.tasks.read` gates task listing.
  - `clickup.tasks.write` gates task creation in metadata.
  - `clickup.tasks.delete` gates task deletion in metadata.
- The connector does not persist ClickUp responses, workspace IDs, space IDs, list IDs, task IDs, task names, task descriptions, custom fields, API tokens, credential IDs beyond configuration metadata, provider payloads, or provider error bodies.

## Network And Runtime Invariants

- Production host: `api.clickup.com`.
- Production API prefix: `/api/v2`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback overrides are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints set `10_000 ms` connect timeout and `30_000 ms` total timeout.
- Maximum response bytes are `10_485_760` for read/list operations and `1_048_576` for task creation/deletion.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open listeners and does not implement subscriptions.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `clickup.spaces.list` | `GET /team/{team_id}/space` | `clickup.spaces.read` | `Safe` | `Low` | `Strict` | Reads spaces visible in one ClickUp workspace/team. |
| `clickup.lists.list` | `GET /space/{space_id}/list` | `clickup.lists.read` | `Safe` | `Low` | `Strict` | Reads lists in one space before task operations. |
| `clickup.tasks.list` | `GET /list/{list_id}/task` | `clickup.tasks.read` | `Safe` | `Low` | `Strict` | Reads task summaries in one list. |
| `clickup.tasks.create` | `POST /list/{list_id}/task` | `clickup.tasks.write` | `Risky` | `Medium` | `None` | Creates provider-visible task state. |
| `clickup.tasks.delete` | `DELETE /task/{task_id}` | `clickup.tasks.delete` | `Dangerous` | `High` | `None` | Permanently deletes a ClickUp task instead of closing it. |

## Explicit Non-Goals

The current implementation does not include:

- OAuth authorization-code flow, OAuth app setup, token refresh, or multi-user token storage
- workspace/team discovery beyond `clickup.spaces.list`
- folders, comments, docs, attachments, views, goals, time tracking, automations, or webhooks
- task update, close/reopen, move, assign, tag, priority, date, relationship, or custom-field operations
- pagination controls for task/list/space enumeration
- ClickUp v3 APIs or ClickUp MCP server integration
- live provider self-check against ClickUp
- FCP subscription-based streaming
- connector-local credential vaulting

These are excluded on purpose:

- Runtime invocation is currently a small handler-style bridge and should stay narrow until capability enforcement is upgraded.
- Task deletion is the only destructive operation in this slice and should use dedicated approval policy once runtime metadata is aligned.
- Broader ClickUp coverage needs separate operation contracts, pagination behavior, and provider fixtures.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration and handshake state
- request and error counters
- auth mode as API token or credential ID
- credential-injection requirement for credential-id mode
- base URL policy and loopback verification allowance
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- simulation allow/deny based only on known operation ID
- self-check degradation for unconfigured, missing client, invalid network policy, or credential-injection mode

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle health, doctor, self-check, introspection, and shutdown
- personal-token auth header propagation
- spaces, lists, tasks list, task create, and task delete WireMock requests
- missing required input fields
- provider 401, 403, 404, 429, and 500-class error mapping
- unknown operation and simulation behavior
- request/error counters
- configuration validation, credential-id validation, base URL policy, and path segment rejection
- manifest and runtime checks for the dedicated `clickup.tasks.delete` capability

## Source Notes

- `connectors/clickup/src/connector.rs` defines configuration parsing, base URL policy, lifecycle handlers, diagnostics, simulation, operation metadata, provisioning recipe, and invoke dispatch.
- `connectors/clickup/src/client.rs` defines request construction, auth headers, path-segment rejection, timeout setup, ClickUp API paths, and provider error parsing.
- `connectors/clickup/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/clickup/src/types.rs` defines normalized ClickUp space, list, task, and error response types.
- `connectors/clickup/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, rate limits, and AI hints.
- `connectors/clickup/tests/integration.rs` covers deterministic HTTP behavior and handler lifecycle behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/clickup_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation contract tests
- deterministic WireMock coverage for the five runtime operations
- auth, base URL, input validation, provider error, lifecycle, introspection, and simulation tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a disposable ClickUp workspace/team for live verification.
- Prefer a personal API token generated specifically for the verification account.
- Use WireMock loopback fixtures for routine proof.
- Use credential-id mode only when the host or egress proxy is ready to inject ClickUp auth.

**Dedicated environment**:

- Keep live task creation confined to a disposable list.
- Never run task deletion against production project-management data.
- Use synthetic task names and fixture IDs in logs and transcripts.

**Redaction rules**:

- Redact API tokens, credential IDs where needed, workspace/team IDs, space IDs, list IDs, task IDs, task names when sensitive, task descriptions, provider payloads, provider error bodies, and local paths.
- Verification output should use operation IDs, endpoint shapes, host classes, status/error classes, retry decisions, and synthetic ClickUp resource identifiers.

**Common remediation**:

- If configuration fails, provide exactly one of `api_token` or `credential_id`.
- If API-token configuration rejects a custom base URL, use `https://api.clickup.com/api/v2` or a loopback test origin.
- If credential-id mode self-check reports `credential_injection_required`, use direct API-token mode or wire the egress proxy injection path.
- If invocation fails with readiness errors, configure and handshake with a non-empty `session_id` before invoking.
- If ClickUp returns 404, list spaces and lists again to confirm the workspace/team, space, list, and task IDs are still current.
- If repeated 500 or 429 errors appear, remember that the current direct HTTP helpers do not run the configured retry loop.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-clickup-readme cargo check -p fcp-clickup --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-clickup-readme cargo test -p fcp-clickup --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-clickup-readme cargo clippy -p fcp-clickup --all-targets --no-deps -- -D warnings`
- `ubs connectors/clickup/README.md`
