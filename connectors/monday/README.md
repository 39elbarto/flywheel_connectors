# Monday.com Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **monday.com API upstream**: https://developer.monday.com/api-reference/docs/getting-started
> **monday.com authentication upstream**: https://developer.monday.com/api-reference/docs/authentication
> **monday.com boards upstream**: https://developer.monday.com/api-reference/reference/boards
> **monday.com items upstream**: https://developer.monday.com/api-reference/reference/items
> **monday.com updates upstream**: https://developer.monday.com/api-reference/reference/updates
> **monday.com versioning upstream**: https://developer.monday.com/api-reference/docs/api-versioning

## Purpose

This document fixes the operator-facing contract for `fcp.monday`. The connector exposes the monday.com GraphQL API surface implemented in this crate: board listing and lookup, item listing/creation/deletion, and item update listing/creation.

The connector is intentionally a bounded work-management bridge. It is not a full monday.com administration client, board designer, column-value editor, subitem manager, automation manager, docs client, webhook listener, OAuth app installer, or account provisioning tool.

## Current Runtime Snapshot

The current crate exposes these operations:

- `monday.boards.list`
- `monday.boards.get`
- `monday.items.list`
- `monday.items.create`
- `monday.items.delete`
- `monday.updates.list`
- `monday.updates.create`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-monday`.
- Runtime `BaseConnector` ID is `monday`.
- Manifest and reported connector ID are `fcp.monday`.
- Manifest version is `0.1.0`.
- Manifest format is `wasi`.
- Configuration requires exactly one auth source:
  - `api_token`
  - `credential_id`
- Direct API-token mode sends `Authorization: <token>` with no `Bearer` prefix.
- `credential_id` mode sends `X-FCP-Credential-Id` and expects host egress policy to inject real secret material.
- `credential_id` must be a valid UUID.
- Default runtime base URL is `https://api.monday.com/v2`.
- The client trims trailing slashes from `base_url`.
- Configure rejects `base_url` values with URL userinfo, query strings, fragments, parse failures, or missing hosts where applicable.
- Direct API-token mode accepts only HTTPS `api.monday.com` or loopback test hosts.
- Credential-id mode accepts any HTTPS host or loopback test host after URL hygiene checks.
- Runtime request timeout is 30 seconds.
- Runtime request-context timeout is 30 seconds.
- Runtime stores `HttpRetryConfig { max_retries = 2 }`, but `query()` sends one request and does not use a retry loop.
- Runtime sends GraphQL requests as `POST {base_url}` with JSON body `{ "query": "..." }`.
- Runtime sends `Content-Type: application/json` and `Accept: application/json`.
- Runtime does not send an `API-Version` header.
- Runtime parses HTTP 200 GraphQL `errors` as terminal GraphQL errors.
- Runtime treats a successful response without `data` as a GraphQL error.
- `health()` and `doctor()` consider a handshake complete only when a `session_id` was provided.
- A handshake without `session_id` marks the base connector handshaken but still reports degraded health and a failed non-critical doctor handshake check.
- `self_check()` performs local provisioning readiness only. It does not call monday.com.
- Direct API-token mode reports `ok` if local configuration and URL policy pass.
- `credential_id` mode reports degraded `credential_injection_required` and skips a live probe.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime `invoke` checks `BaseConnector::check_ready()` and operation ID, but does not require or verify an FCP capability token.
- Runtime `simulate` parses both typed `SimulateRequest` and legacy `operation_id` style input, checks known operation, required input fields, configured/client state, and `session_id`.
- Runtime `simulate` does not verify capability tokens or approval tokens.
- `handle_shutdown()` shuts down the client runtime, clears client/config/base flags, and returns an empty object.
- `handle_shutdown()` does not clear the stored `session_id`.

## Runtime GraphQL Adapter

The runtime uses these GraphQL request shapes:

| Operation | Runtime query shape | Required input | Output handling |
|-----------|---------------------|----------------|-----------------|
| `monday.boards.list` | `boards(limit: {limit}) { id name state board_kind }` | none | Returns `{ "boards": data.boards }`, defaulting missing boards to `[]`. |
| `monday.boards.get` | `boards(ids: [{board_id}]) { id name description state }` | `board_id` | Returns the first board as `{ "board": ... }`, or `null` if no board is returned. |
| `monday.items.list` | `boards(ids: [{board_id}]) { items_page(limit: 50) { items { id name state column_values { id text value } } } }` | `board_id` | Returns `{ "items": first_board.items_page.items }`, defaulting to `[]`. |
| `monday.items.create` | `create_item(board_id, item_name, column_values?) { id name }` | `board_id`, `item_name` | Returns `{ "id": create_item.id }`, or `null` if the field is absent. |
| `monday.items.delete` | `delete_item(item_id) { id }` | `item_id` | Returns `{}` and discards the provider's deleted item ID. |
| `monday.updates.list` | `items(ids: [{item_id}]) { updates { id text_body creator { name } created_at } }` | `item_id` | Returns `{ "updates": first_item.updates }`, defaulting to `[]`. |
| `monday.updates.create` | `create_update(item_id, body) { id text_body }` | `item_id`, `body` | Returns the provider's `create_update` object, or `{}` if absent. |

Input validation is intentionally narrow:

- Required values must be JSON strings.
- Board IDs and item IDs are validated in the client as non-empty ASCII digit strings before being embedded in GraphQL.
- `boards.list.limit` defaults to `25` and is inserted directly as a `u64`; runtime does not enforce the manifest maximum of `100`.
- `items.list` always requests the first `50` items and does not expose cursor pagination.
- `column_values` is accepted as JSON, converted with `to_string()`, then string-escaped into the GraphQL mutation.
- `item_name` and update `body` are string-escaped with `serde_json::to_string()` before GraphQL embedding.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Manifest defines only four operations: `monday.boards.list`, `monday.items.create`, `monday.items.delete`, and `monday.items.list`.
- Runtime introspection and invoke define seven operations, adding `monday.boards.get`, `monday.updates.list`, and `monday.updates.create`.
- Runtime handshake advertises `monday.updates.read` and `monday.updates.write`, but the manifest optional capabilities omit those update capabilities.
- Manifest rate-limit pools do not include `monday.boards.get`, `monday.updates.list`, or `monday.updates.create`.
- Manifest marks `monday.items.create` with policy approval and `monday.items.delete` with interactive approval; runtime operation metadata sets `requires_approval = None` for all operations and runtime checks no approval token.
- Runtime does not verify capability tokens or bind operations to resource URIs.
- Runtime direct API-token mode enforces `api.monday.com`, while credential-id mode permits custom HTTPS hosts for egress-proxy injection.
- Runtime request helper stores retry config but does not apply it.
- Runtime does not send an `API-Version` header. Current upstream versioning docs list `2026-04` as the current version, with `2026-01` maintenance and `2026-07` release-candidate versions.
- Runtime `boards.list` schema says `limit` maximum `100`, but runtime does not cap the value.
- Runtime `items.list` uses `items_page(limit: 50)` and does not expose monday.com's cursor pagination.
- Runtime `items.delete` discards the provider's deleted item ID.
- Runtime `boards.get` maps no returned board to `null`, not an FCP not-found error.
- Runtime E2E suite adapter advertises only board-list introspection and forwards invoke payloads without proving connector-level capability-token verification.
- Runtime `health` and `doctor` treat missing `session_id` as not handshaken even though `handle_handshake()` sets the base connector handshaken flag.
- Runtime shutdown clears base lifecycle flags but leaves `session_id` populated.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should align manifest and runtime operation catalogs, add update capabilities and rate-limit pools to the manifest or remove runtime update operations, enforce approval tokens for mutation operations, wire capability-token verification into invoke, decide whether custom credential-id hosts are acceptable in production, apply or remove retry configuration, send an explicit API version header, expose pagination where needed, and clear `session_id` during shutdown.

## First-Slice Scope

The current Monday.com README slice documents the existing runtime surface:

- API-token and credential-id configuration
- GraphQL request construction and input validation
- provider host policy, timeout, provider error mapping, and retry drift
- board, item, and update operations
- lifecycle, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- runtime/manifest drift around operations, capabilities, approval policy, API versioning, simulation, and capability-token verification
- deterministic WireMock integration tests and the connector-suite happy path

## Auth And Zone Boundary

- Authentication mechanisms: monday.com API token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime handshake advertises:
  - `monday.boards.read`
  - `monday.items.read`
  - `monday.items.write`
  - `monday.updates.read`
  - `monday.updates.write`
- Manifest required capabilities are `network.dns`, `network.egress`, `network.tls.sni`, and `storage.state`.
- Manifest optional capabilities are `monday.boards.read`, `monday.items.write`, and `monday.items.read`.
- The connector does not persist API tokens, credential IDs beyond configuration metadata, board data, item data, update text, provider payloads, provider error bodies, request counters, or error counters outside process memory.
- monday.com payloads can include work boards, private project names, item names, column values, comments, creator names, timestamps, and operational state. Treat live output as work-zone operational data unless a stricter zone is configured by the host.

## Network And Runtime Invariants

- Default runtime base URL: `https://api.monday.com/v2`.
- Runtime direct requests POST to `base_url` exactly after trailing slash trimming.
- Runtime direct API-token mode accepts HTTPS `api.monday.com` and loopback test hosts only.
- Runtime credential-id mode accepts any HTTPS host plus loopback test hosts after URL hygiene checks.
- Runtime readiness policy accepts loopback hosts for tests with either HTTP or HTTPS.
- Runtime request timeout: `30 seconds`.
- Runtime retry policy is configured but not applied by the current request helper.
- Runtime HTTP error mapping covers 401, 403, 404, 429 with `Retry-After`, and other API statuses.
- Runtime GraphQL error mapping collects 200-response error messages and returns a non-retryable GraphQL error.
- Manifest operation network policy requires TLS/SNI, allows `api.monday.com` on port `443`, denies localhost, private ranges, tailnet ranges, and IP literals, and caps response sizes at `1048576` or `10485760` bytes by operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `monday.boards.read` | List boards and read one board by numeric ID. |
| `monday.items.read` | List items on one board. |
| `monday.items.write` | Create or delete items. |
| `monday.updates.read` | List updates/comments on one item. |
| `monday.updates.write` | Create an update/comment on one item. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `monday.boards.list` | GraphQL `boards(limit)` | `monday.boards.read` | `Safe` | `Low` | `Strict` | Lists boards visible to the token, defaulting missing boards to an empty array. |
| `monday.boards.get` | GraphQL `boards(ids)` | `monday.boards.read` | `Safe` | `Low` | `Strict` | Reads one board by numeric ID and returns `null` when no board is returned. |
| `monday.items.list` | GraphQL `boards(ids).items_page(limit: 50)` | `monday.items.read` | `Safe` | `Low` | `Strict` | Lists the first page of items and selected column values on one board. |
| `monday.items.create` | GraphQL `create_item` mutation | `monday.items.write` | `Risky` | `Medium` | `None` | Creates one item on a board and returns the new item ID. |
| `monday.items.delete` | GraphQL `delete_item` mutation | `monday.items.write` | `Dangerous` | `High` | `Strict` | Deletes one item by numeric ID and returns an empty object. |
| `monday.updates.list` | GraphQL `items(ids).updates` | `monday.updates.read` | `Safe` | `Low` | `Strict` | Lists updates/comments on one item. |
| `monday.updates.create` | GraphQL `create_update` mutation | `monday.updates.write` | `Risky` | `Medium` | `None` | Posts one update/comment to an item and returns provider update fields. |

## Resource URIs

Runtime capability-token verification is absent for Monday.com in this checkout, so there are no effective resource URI bindings. The practical authorization binding is configuration plus base readiness plus operation name.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| Boards | `monday://account/{account_id}/boards/{board_id}` |
| Items | `monday://account/{account_id}/boards/{board_id}/items/{item_id}` |
| Updates | `monday://account/{account_id}/items/{item_id}/updates` |

## Explicit Non-Goals

The current implementation does not include:

- board create/update/delete, workspace/folder management, group management, column schema reads/writes, column value mutation, item updates beyond create/delete, subitems, docs, files, automations, users, teams, accounts, assets, or notifications
- cursor pagination beyond the first `items_page`, advanced filters, item search, GraphQL variables, persisted queries, complexity accounting, or API-version selection
- OAuth app installation, token refresh, API-token rotation, webhook ingestion, webhook signature verification, or durable event replay
- durable storage of board, item, update, or provider response data

These are excluded on purpose:

- Item creation, deletion, and update posting are side-effecting work-management actions and need explicit approval/runtime verification before broader mutation is safe.
- monday.com GraphQL schemas are versioned. Runtime behavior should pin an API version before relying on new fields or multi-level board semantics.
- Cursor pagination, column values, and subitem behavior need operation-specific contracts rather than ad hoc GraphQL expansion.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, handshake, request, and error counter state
- auth mode and provider URL readiness through self-check provisioning details
- credential-injection requirement for credential-id mode
- direct API-token self-check based on local readiness only, not a live monday.com API probe
- operation metadata with capability, risk, safety tier, idempotency, schemas, and hints
- simulation allow/deny for known operations, required input, configured/client state, and handshake state
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, configured-but-not-handshaken health, introspection, simulation, doctor, self-check, shutdown, and counters
- API-token and credential-id configuration
- URL hygiene, direct-token host policy, credential-id host policy, and loopback fixtures
- WireMock fixtures for board listing/get, item listing/create/delete, and update listing/create
- missing required input fields and unknown operation rejection
- provider 401, 403, 404, 429, 500, GraphQL error, empty body, and malformed JSON classes
- numeric ID injection protection, string escaping, column-values handling, auth redaction, provisioning readiness, operation inventory, and connector-suite happy/error paths

## Source Notes

- `connectors/monday/src/connector.rs` defines configuration parsing, URL hygiene, lifecycle handlers, diagnostics, provisioning recipe, introspection, simulation, invoke dispatch, operation metadata, base URL policy, and readiness reporting.
- `connectors/monday/src/client.rs` defines monday.com GraphQL request construction, auth headers, timeout settings, query strings, ID validation, response parsing, and provider error handling.
- `connectors/monday/src/types.rs` defines provider API and GraphQL response shapes.
- `connectors/monday/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/monday/manifest.toml` defines the manifest operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit pools.
- `connectors/monday/tests/integration.rs` contains deterministic HTTP behavior and connector-level behavior.
- `connectors/monday/tests/connector_suite_happy_path.rs` contains the FCP connector-suite adapter and board-list happy/error proof.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/monday/README.md
ubs connectors/monday/README.md
LC_ALL=C rg -n '[^ -~]' connectors/monday/README.md
rg -n '\bmaster\b' connectors/monday/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-monday
rch exec -- cargo check -p fcp-monday --all-targets
rch exec -- cargo clippy -p fcp-monday --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Prefer `credential_id` for production so host policy owns secret injection.
- Use direct API tokens only in local deterministic tests or explicitly scoped environments.
- Use numeric string IDs for `board_id` and `item_id`; names and slugs are rejected before GraphQL dispatch.
- Treat `monday.items.create`, `monday.items.delete`, and `monday.updates.create` as high-review operations even though runtime approval checks are absent.
- Do not rely on capability-token or approval-token enforcement until runtime verification is implemented.
- Do not assume pagination beyond the first item page.
- Pin an `API-Version` header in follow-up source work before depending on current-version monday.com schema behavior.
- If self-check reports `credential_injection_required`, use direct API-token mode or wire host-side injection.
- If self-check reports `network_constraints_invalid`, use `https://api.monday.com/v2` or a loopback test server.
