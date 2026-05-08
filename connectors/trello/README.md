# Trello Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Trello REST API introduction**: https://developer.atlassian.com/cloud/trello/guides/rest-api/api-introduction/
> **Trello cards API**: https://developer.atlassian.com/cloud/trello/rest/api-group-cards/
> **Trello boards API**: https://developer.atlassian.com/cloud/trello/rest/api-group-boards/
> **Trello lists API**: https://developer.atlassian.com/cloud/trello/rest/api-group-lists/

## Purpose

This document fixes the operator-facing contract for `fcp.trello`. The connector currently exposes a bounded Trello project-management surface implemented in this crate: board listing and reads, list listing, card listing/reading/creation/update/deletion, board label listing, and board member listing.

The connector is intentionally a small Trello board/card bridge. It is not a full Trello SDK, Power-Up runtime, webhook client, organization admin client, Butler automation client, attachment manager, checklist client, custom-field client, search client, or general Trello REST API proxy.

## Current Runtime Snapshot

The current crate exposes these invoke operations:

- `trello.boards.list`
- `trello.boards.get`
- `trello.lists.list`
- `trello.cards.list`
- `trello.cards.get`
- `trello.cards.create`
- `trello.cards.update`
- `trello.cards.delete`
- `trello.labels.list`
- `trello.members.list`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-trello`.
- Runtime `BaseConnector` ID is `trello`.
- Manifest connector ID and handshake connector ID are `fcp.trello`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:579b1d9f03d85653ce50a70efee7741523937a11d3d37ccc751f795daf53903a`.
- Configuration requires either `api_key` plus `token`, or `credential_id`.
- `api_key` and `token` are trimmed and both are required for direct auth.
- `credential_id` must be a string and a valid UUID.
- Supplying direct credentials and `credential_id` together is rejected.
- Default `base_url` is `https://api.trello.com/1`.
- Non-string `base_url` values are ignored and the default endpoint is used.
- Client construction trims trailing slashes from `base_url`.
- The HTTP client timeout is 30 seconds.
- User agent is `fcp-trello/0.1.0 (FCP connector)`.
- Direct key/token mode sends `key` and `token` as reqwest query parameters.
- Credential-reference mode sends `X-FCP-Credential-Id` and expects host or egress-proxy injection.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime `invoke` checks configured plus handshaken state through `base.check_ready()`.
- Runtime `invoke` does not verify `capability_token`.
- Runtime does not verify approval tokens for card create, update, or delete.
- Runtime `simulate` only checks whether `operation_id` exists in the local operation inventory.
- `handle_configure()` creates a new client, stores config, and sets configured.
- `handle_configure()` does not clear an existing session ID or base handshaken state.
- `handle_handshake()` requires configuration, accepts an optional `session_id`, sets the base handshaken flag, and returns Trello capability strings.
- `health()` reports healthy only when configuration exists and `session_id.is_some()`.
- `doctor()` checks local configuration, client initialization, and session presence only; it does not call Trello.
- `self_check()` validates local base URL policy and client presence; it does not make a live Trello probe.
- `self_check()` is degraded in credential-reference mode because the host must inject credentials.
- `handle_shutdown()` shuts down the client runtime, clears client/config and base lifecycle flags, but does not clear `session_id` or request/error counters.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Manifest declares five operations: `trello.boards.list`, `trello.cards.create`, `trello.cards.delete`, `trello.cards.list`, and `trello.lists.get`.
- Runtime exposes ten operations and uses `trello.lists.list`, not manifest operation ID `trello.lists.get`.
- Runtime exposes `trello.boards.get`, `trello.cards.get`, `trello.cards.update`, `trello.labels.list`, and `trello.members.list`, none of which are declared by the manifest.
- Runtime handshake and operation metadata include `trello.labels.read` and `trello.members.read`, but manifest optional capabilities do not include those capabilities.
- Manifest `trello.cards.list` schema requires `board_id` and has optional `list_id`; runtime requires `list_id` and calls `/lists/{list_id}/cards`.
- Manifest marks `trello.cards.create` as policy-approved and `trello.cards.delete` as interactive approval. Runtime `OperationInfo` sets `requires_approval = None`, and invoke checks no approval token.
- Runtime operation metadata advertises Trello capability IDs, but runtime does not verify bound capability tokens.
- Manifest network constraints allow only `api.trello.com` on port 443 and deny local hosts. Runtime base URL policy allows `localhost`, `127.0.0.1`, and `::1` for tests and only runs that policy during `self_check()`, not during configure or invoke.
- Runtime base URL policy checks scheme and host but does not reject userinfo, query strings, fragments, custom ports, or non-default paths.
- Runtime path-segment validation rejects blank input, slash, backslash, NUL, `.`, and `..`, but unlike Todoist it does not reject encoded slashes such as `%2f`.
- Runtime stores a `HttpRetryConfig`, but direct reqwest calls do not run through a connector retry loop.
- Manifest rate-limit pools are documented intent; runtime relies on provider responses and maps 429 into a rate-limit error.
- Manifest state model is singleton-writer and mentions board membership cache. Runtime stores config/session/client state only in process memory and has no durable board cache.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should align manifest and runtime operation IDs, add missing manifest operations and capabilities or narrow runtime exports, fix `trello.cards.list` input semantics, add bound capability-token verification, add approval-token verification for card mutations, tighten runtime base URL and path policies or document local-test overrides, wire runtime retries or remove dead retry metadata, and add a tracked verification bundle.

## First-Slice Scope

The current Trello README slice documents the existing runtime surface:

- API-key/token and credential-reference configuration
- Trello board, list, card, label, and member operation paths
- card create, update, delete mutation behavior
- local base URL policy, timeout, auth query/header behavior, rate-limit, and error mapping behavior
- lifecycle, health, doctor, self-check, simulation, introspection, and shutdown behavior
- runtime/manifest drift around operation inventory, capability enforcement, approvals, network policy, retries, and persistence
- deterministic connector tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms:
  - direct Trello API key plus token
  - host-injected `credential_id`
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability metadata:
  - `trello.boards.read`
  - `trello.cards.read`
  - `trello.cards.write`
  - `trello.cards.delete`
  - `trello.labels.read`
  - `trello.members.read`
- Handshake returns capability strings but does not install a verifier.
- Invoke does not reject missing, malformed, wrong-operation, wrong-resource, or wrong-capability tokens.
- Card mutation operations do not verify approval tokens at runtime.
- The connector does not persist API keys, tokens, credential IDs, board data, card data, label data, member data, request counters, provider errors, or session IDs outside process memory.
- Trello boards and cards can contain private or work data. Treat live output according to the board workspace and account policy.

## Network And Runtime Invariants

- Default endpoint: `https://api.trello.com/1`.
- Direct key/token mode sends `key={api_key}` and `token={token}` as reqwest query parameters.
- Credential-reference mode sends `X-FCP-Credential-Id: {uuid}`.
- GET, POST, PUT, and DELETE requests send `Accept: application/json`.
- JSON write requests are sent with reqwest JSON bodies.
- Empty successful responses are normalized to `{}`.
- Trello JSON error bodies with `message` are parsed; otherwise the raw body or status text is used.
- HTTP 401 maps to unauthorized.
- HTTP 403 maps to forbidden.
- HTTP 404 maps to not found with provider detail.
- HTTP 429 maps to rate limited, using `Retry-After` when present and otherwise defaulting to 10 seconds.
- Other non-success statuses map to provider API errors.
- Request path segments are sanitized before board/list/card/member path use.
- Request counters increment before dispatch.
- Error counters increment only for typed Trello operation errors.
- No native listener, webhook receiver, durable queue, search index, or background polling loop is started by this connector.

## Operation Inventory

| Operation | Runtime Trello path/behavior | Capability metadata | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|------------------------------|---------------------|------------|-----------|-------------|----------------|
| `trello.boards.list` | `GET /members/{member}/boards`, default member `me` | `trello.boards.read` | `Safe` | `Low` | `Strict` | none; optional `member` |
| `trello.boards.get` | `GET /boards/{board_id}` | `trello.boards.read` | `Safe` | `Low` | `Strict` | `board_id` |
| `trello.lists.list` | `GET /boards/{board_id}/lists` | `trello.boards.read` | `Safe` | `Low` | `Strict` | `board_id` |
| `trello.cards.list` | `GET /lists/{list_id}/cards` | `trello.cards.read` | `Safe` | `Low` | `Strict` | `list_id` |
| `trello.cards.get` | `GET /cards/{card_id}` | `trello.cards.read` | `Safe` | `Low` | `Strict` | `card_id` |
| `trello.cards.create` | `POST /cards` | `trello.cards.write` | `Risky` | `Medium` | `None` | `idList`, `name`; optional `desc`, `due` |
| `trello.cards.update` | `PUT /cards/{card_id}` | `trello.cards.write` | `Risky` | `Medium` | `Strict` | `card_id`; optional `name`, `desc`, `closed`, `idList`, `due` |
| `trello.cards.delete` | `DELETE /cards/{card_id}` | `trello.cards.delete` | `Dangerous` | `High` | `None` | `card_id` |
| `trello.labels.list` | `GET /boards/{board_id}/labels` | `trello.labels.read` | `Safe` | `Low` | `Strict` | `board_id` |
| `trello.members.list` | `GET /boards/{board_id}/members` | `trello.members.read` | `Safe` | `Low` | `Strict` | `board_id` |

## Explicit Non-Goals

The current implementation does not include:

- Trello OAuth app installation, API-key provisioning, token refresh, account discovery, workspace provisioning, or credential vaulting
- board create/update/delete, list create/update/archive, label create/update/delete, member management, checklist APIs, attachment APIs, custom fields, comments, actions, notifications, search, or organizations
- webhooks, event subscriptions, push delivery, polling loops, durable sync cursors, or replay storage
- automatic retry loops, connector-local rate-limit pools, batching, pagination helpers, or result caching
- host-side credential injection implementation for `credential_id` mode
- capability-token verification, approval-token verification, per-board resource binding, per-card policy storage, or mutation review enforcement
- durable board/card/label/member persistence, audit logging, payload redaction, or Trello data classification

These are excluded on purpose:

- Card creation, update, and deletion mutate live collaboration state.
- A general Trello REST API proxy would bypass the connector's typed capability model.
- Trello key/token credentials often grant broad board access and must remain visibly bounded.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, `introspect()`, and `shutdown()` are part of the public closeout contract. They surface:

- configured/unconfigured state, client presence, session presence, request counters, and error counters
- local endpoint policy and credential-injection readiness metadata
- degraded readiness for missing configuration and credential-reference mode
- typed introspection with operations, schemas, capability IDs, risk levels, safety tiers, idempotency, and agent hints
- simulation allow/deny for known versus unknown operation IDs only
- typed provider/FCP error mapping for missing input, invalid path segments, auth failures, 404s, 429s, transport failures, JSON errors, and provider API errors

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, doctor, self-check, introspection, simulate, shutdown, and counters
- direct API-key/token and credential-reference configuration validation
- board list/get, list list, card list/get/create/update/delete, label list, and member list
- auth query parameter behavior, local mock endpoints, empty successful bodies, provider error classes, and rate-limit handling
- operation metadata, safety tiers, risk levels, idempotency, and capability strings
- base URL policy, path-segment sanitization, provisioning recipe shape, and redaction behavior

## Source Notes

- `connectors/trello/src/connector.rs` defines configuration parsing, lifecycle handlers, operation catalog, provisioning recipe, endpoint policy, introspection, simulation, and invoke dispatch.
- `connectors/trello/src/client.rs` defines Trello HTTP transport, auth query/header behavior, base URL, timeout, path sanitization, method paths, error parsing, rate-limit mapping, and client shutdown.
- `connectors/trello/src/types.rs` defines Trello API envelope and error response shapes.
- `connectors/trello/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/trello/manifest.toml` defines the manifest operation catalog, network constraints, sandbox boundary, zone policy, approval intent, rate-limit intent, and state intent.
- `connectors/trello/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/trello/README.md
ubs connectors/trello/README.md
LC_ALL=C rg -n '[^ -~]' connectors/trello/README.md
rg -n '\bmaster\b' connectors/trello/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-trello
rch exec -- cargo check -p fcp-trello --all-targets
rch exec -- cargo clippy -p fcp-trello --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Use a dedicated Trello test workspace, board, list, and card for verification.
- Prefer direct API-key/token mode for local deterministic tests; pair `credential_id` mode with a host or egress proxy that injects provider auth.
- Treat card create, update, and delete as high-review mutations until capability and approval verification are implemented.
- Do not rely on `self_check()` as proof that the Trello key/token are valid; it does not call the provider.
- Do not rely on `simulate()` as an authorization check; it only validates operation existence.
- Do not rely on shutdown to erase session ID or request/error counters.
