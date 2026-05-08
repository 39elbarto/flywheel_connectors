# Todoist Connector V3 Contract

> **Status**: runtime contract documented; approval/capability drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Todoist API reference**: https://developer.todoist.com/api/v1/
> **Todoist REST v2 reference entry point**: https://developer.todoist.com/rest/v2/

## Purpose

This document fixes the operator-facing contract for `fcp.todoist`. The connector currently exposes a bounded Todoist task-management surface implemented in this crate: project listing, task listing, task creation, task completion, and task deletion.

The connector is intentionally a small Todoist bridge. It is not a full Todoist SDK, project editor, label client, comment client, section client, upload client, automation engine, webhook receiver, sync client, or general Todoist API proxy.

## Current Runtime Snapshot

The current crate exposes these invoke operations:

- `todoist.projects.list`
- `todoist.tasks.list`
- `todoist.tasks.create`
- `todoist.tasks.complete`
- `todoist.tasks.delete`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-todoist`.
- Runtime `BaseConnector` ID is `todoist`.
- Manifest connector ID and handshake connector ID are `fcp.todoist`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:962e4e8aa8eb1ceb5b8de98a98f7ab1f313a8c63a5475e922c561973bb3b2233`.
- Configuration requires exactly one of `api_token` or `credential_id`.
- `api_token` is trimmed and rejected when missing or blank.
- `credential_id` must be a string and a valid UUID.
- Supplying both `api_token` and `credential_id` is rejected.
- Default `base_url` is `https://api.todoist.com/rest/v2`.
- Non-string `base_url` values are ignored and the default endpoint is used.
- Client construction trims trailing slashes from `base_url`.
- The HTTP client timeout is 30 seconds.
- User agent is `fcp-todoist/0.1.0 (FCP connector)`.
- Direct token mode sends `Authorization: Bearer`.
- Credential-reference mode sends `X-FCP-Credential-Id` and expects host or egress-proxy injection.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime `invoke` checks configured plus handshaken state through `base.check_ready()`.
- Runtime `invoke` does not verify `capability_token`.
- Runtime does not verify approval tokens for task create, complete, or delete.
- Runtime `simulate` only checks whether `operation_id` exists in the local operation inventory.
- `handle_configure()` creates a new client, clears `session_id`, clears the base handshaken flag, stores config, and sets configured.
- `handle_handshake()` requires configuration, accepts an optional `session_id`, sets the base handshaken flag, and returns the Todoist capability strings.
- `health()` reports healthy only when configuration exists and `session_id.is_some()`.
- `doctor()` checks local configuration, client initialization, and session presence only; it does not call Todoist.
- `self_check()` validates local base URL policy and client presence; it does not make a live Todoist probe.
- `self_check()` is degraded in credential-reference mode because the host must inject credentials.
- `handle_shutdown()` shuts down the client runtime, clears client/config and base lifecycle flags, but does not clear request/error counters.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Manifest marks `todoist.tasks.create` and `todoist.tasks.complete` as policy-approved and `todoist.tasks.delete` as interactive approval. Runtime `OperationInfo` sets `requires_approval = None`, and invoke checks no approval token.
- Runtime operation metadata advertises `todoist.projects.read`, `todoist.tasks.read`, `todoist.tasks.write`, and `todoist.tasks.delete`, but runtime does not verify bound capability tokens.
- Manifest network constraints allow only `api.todoist.com` on port 443 and deny local hosts. Runtime base URL policy allows `localhost`, `127.0.0.1`, and `::1` for tests and only runs that policy during `self_check()`, not during configure or invoke.
- Runtime base URL policy checks scheme and host but does not reject userinfo, query strings, fragments, custom ports, or non-default paths.
- Runtime stores a `HttpRetryConfig`, but direct reqwest calls do not run through a connector retry loop.
- Manifest rate-limit pools are documented intent; runtime relies on provider responses and maps 429 into a rate-limit error.
- Manifest state model is singleton-writer and says it stores an API token. Runtime stores token/config/session/client state only in process memory.
- Manifest connector description mentions labels, but runtime exposes no label operations.
- Todoist upstream documentation currently publishes an `api/v1` reference while this implementation still defaults to `rest/v2`; this README documents the code in this checkout, not a completed API-version migration.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should add bound capability-token verification, add approval-token verification for task mutations, decide whether `rest/v2` remains the intended upstream base path, align manifest labels wording with runtime support, tighten runtime base URL policy or document local-test overrides, wire runtime retries or remove dead retry metadata, and add a tracked verification bundle.

## First-Slice Scope

The current Todoist README slice documents the existing runtime surface:

- API-token and credential-reference configuration
- Todoist project and task operation paths
- task create, complete, and delete mutation behavior
- local base URL policy, timeout, auth header, rate-limit, and error mapping behavior
- lifecycle, health, doctor, self-check, simulation, introspection, and shutdown behavior
- runtime/manifest drift around capability enforcement, approvals, network policy, retries, and persistence
- deterministic connector tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms:
  - direct Todoist API token
  - host-injected `credential_id`
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability metadata:
  - `todoist.projects.read`
  - `todoist.tasks.read`
  - `todoist.tasks.write`
  - `todoist.tasks.delete`
- Handshake returns capability strings but does not install a verifier.
- Invoke does not reject missing, malformed, wrong-operation, wrong-resource, or wrong-capability tokens.
- Task mutation operations do not verify approval tokens at runtime.
- The connector does not persist API tokens, credential IDs, task data, project data, request counters, provider errors, or session IDs outside process memory.
- Todoist tasks and projects can contain private or work data. Treat live output according to the configured Todoist account and workspace zone.

## Network And Runtime Invariants

- Default endpoint: `https://api.todoist.com/rest/v2`.
- Direct token mode sends `Authorization: Bearer {token}`.
- Credential-reference mode sends `X-FCP-Credential-Id: {uuid}`.
- GET, POST, and DELETE requests send `Accept: application/json`.
- JSON write requests are sent with reqwest JSON bodies.
- Empty successful responses are normalized to `{}`.
- Todoist plain-text and JSON error bodies are both accepted.
- HTTP 401 maps to unauthorized.
- HTTP 403 maps to forbidden.
- HTTP 404 maps to not found with provider detail.
- HTTP 429 maps to rate limited, using `Retry-After` when present and otherwise defaulting to 60 seconds.
- Other non-success statuses map to provider API errors.
- Task ID path segments reject blank input, slash, backslash, `..`, NUL, encoded slash `%2f`, and encoded backslash `%5c`.
- Request counters increment before dispatch.
- Error counters increment only for typed Todoist operation errors.
- No native listener, webhook receiver, durable queue, sync cursor, or background polling loop is started by this connector.

## Operation Inventory

| Operation | Runtime Todoist path | Capability metadata | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------------|---------------------|------------|-----------|-------------|----------------|
| `todoist.projects.list` | `GET /projects` | `todoist.projects.read` | `Safe` | `Low` | `Strict` | none |
| `todoist.tasks.list` | `GET /tasks`, optional `project_id` query | `todoist.tasks.read` | `Safe` | `Low` | `Strict` | none |
| `todoist.tasks.create` | `POST /tasks` | `todoist.tasks.write` | `Risky` | `Medium` | `None` | `content`; optional `project_id`, `due_string` |
| `todoist.tasks.complete` | `POST /tasks/{task_id}/close` | `todoist.tasks.write` | `Risky` | `Medium` | `Strict` | `task_id` |
| `todoist.tasks.delete` | `DELETE /tasks/{task_id}` | `todoist.tasks.delete` | `Dangerous` | `High` | `Strict` | `task_id` |

## Explicit Non-Goals

The current implementation does not include:

- Todoist OAuth, app installation, token refresh, account discovery, workspace provisioning, or credential vaulting
- project create/update/delete, section APIs, label APIs, comment APIs, reminder APIs, upload APIs, sync APIs, activity APIs, or templates
- webhooks, event subscriptions, push delivery, polling loops, durable sync cursors, or replay storage
- automatic retry loops, connector-local rate-limit pools, batching, pagination helpers, or result caching
- host-side credential injection implementation for `credential_id` mode
- capability-token verification, approval-token verification, per-project resource binding, or per-task policy storage
- durable task/project persistence, audit logging, payload redaction, or Todoist data classification

These are excluded on purpose:

- Task creation, completion, and deletion mutate live personal or work task state.
- A general Todoist API proxy would bypass the connector's typed capability model.
- Credential-reference mode depends on host policy and should not be confused with provider readiness.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, `introspect()`, and `shutdown()` are part of the public closeout contract. They surface:

- configured/unconfigured state, client presence, session presence, request counters, and error counters
- local endpoint policy and credential-injection readiness metadata
- degraded readiness for missing configuration and credential-reference mode
- typed introspection with operations, schemas, capability IDs, risk levels, safety tiers, idempotency, and agent hints
- simulation allow/deny for known versus unknown operation IDs only
- typed provider/FCP error mapping for missing input, invalid path segments, auth failures, 404s, 429s, transport failures, JSON errors, and provider API errors

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, reconfigure handshake invalidation, health, doctor, self-check, introspection, simulate, shutdown, and counters
- direct token and credential-reference configuration validation
- project list, task list with project filter, task create, complete, and delete
- auth header behavior, local mock endpoints, empty successful bodies, provider error classes, and rate-limit handling
- operation metadata, safety tiers, risk levels, idempotency, and capability strings
- base URL policy, path-segment sanitization, provisioning recipe shape, and redaction behavior

## Source Notes

- `connectors/todoist/src/connector.rs` defines configuration parsing, lifecycle handlers, operation catalog, provisioning recipe, endpoint policy, introspection, simulation, and invoke dispatch.
- `connectors/todoist/src/client.rs` defines Todoist HTTP transport, auth headers, base URL, timeout, path sanitization, method paths, error parsing, rate-limit mapping, and client shutdown.
- `connectors/todoist/src/types.rs` defines Todoist API envelope and error response shapes.
- `connectors/todoist/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/todoist/manifest.toml` defines the manifest operation catalog, network constraints, sandbox boundary, zone policy, approval intent, rate-limit intent, and state intent.
- `connectors/todoist/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/todoist/README.md
ubs connectors/todoist/README.md
LC_ALL=C rg -n '[^ -~]' connectors/todoist/README.md
rg -n '\bmaster\b' connectors/todoist/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-todoist
rch exec -- cargo check -p fcp-todoist --all-targets
rch exec -- cargo clippy -p fcp-todoist --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Use a dedicated Todoist test account or project for verification.
- Prefer direct API-token mode for local deterministic tests; pair `credential_id` mode with a host or egress proxy that injects provider auth.
- Treat task create, complete, and delete as high-review mutations until capability and approval verification are implemented.
- Do not rely on `self_check()` as proof that the Todoist token is valid; it does not call the provider.
- Do not rely on `simulate()` as an authorization check; it only validates operation existence.
- Do not rely on shutdown to erase request/error counters.
