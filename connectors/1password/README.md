# 1Password Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://developer.1password.com/docs/connect/api-reference/

## Purpose

This document fixes the operator-facing contract for `fcp.1password`. The connector exposes the current 1Password Connect Server surface implemented in this crate: vault listing, item listing, item retrieval, item creation, and item deletion.

The connector is intentionally a bounded Connect Server bridge. It is not a 1Password account-management client, browser extension bridge, SCIM service, Events API consumer, or general secret vault. Any value returned by `1password.items.get` can include secret material and must be treated as sensitive.

## Current Runtime Snapshot

The current crate exposes these operations:

- `1password.vaults.list`
- `1password.items.list`
- `1password.items.get`
- `1password.items.create`
- `1password.items.delete`

Important runtime truths the contract preserves:

- Configuration requires exactly one of `access_token` or `credential_id`.
- `access_token` mode sends bearer auth.
- `credential_id` mode sends `X-FCP-Credential-Id`.
- Credential IDs must be valid UUIDs.
- Default base URL is `https://localhost:8080`, matching a local/operator-managed 1Password Connect Server.
- `base_url` may be overridden and is passed to the client after trailing slash trimming.
- The runtime currently does not enforce a production host allow-list on `base_url`; the manifest still defines the intended sandbox egress policy.
- The HTTP client uses a 30 second timeout and user agent `fcp-onepassword/0.1.0 (FCP connector)`.
- `1password.vaults.list` calls `GET /v1/vaults`.
- `1password.items.list` calls `GET /v1/vaults/{vault_id}/items`.
- `1password.items.get` calls `GET /v1/vaults/{vault_id}/items/{item_id}`.
- `1password.items.create` calls `POST /v1/vaults/{vault_id}/items`.
- `1password.items.delete` calls `DELETE /v1/vaults/{vault_id}/items/{item_id}` and returns `{ "deleted": true }` on success.
- Required string fields are presence/type checked, but path segments are not sanitized in this runtime slice.
- Create payloads pass through caller `category`, `title`, optional `fields`, and optional `tags`; fields and tags default to empty arrays.
- 401, 403, 404, 429 with `Retry-After`, and generic API errors are mapped into connector error classes.
- `health` is local connector state, not a live provider probe.
- `self_check` reports local provisioning readiness and does not call the provider.

## First-Slice Scope

The first 1Password README slice documents the existing runtime surface:

- vault listing through `GET /v1/vaults`
- item listing through `GET /v1/vaults/{vault_id}/items`
- item retrieval through `GET /v1/vaults/{vault_id}/items/{item_id}`
- item creation through `POST /v1/vaults/{vault_id}/items`
- item deletion through `DELETE /v1/vaults/{vault_id}/items/{item_id}`
- direct access-token auth and host credential reference auth
- local Connect Server default base URL
- runtime/manifest network-policy mismatch that operators must account for before live deployment
- required-field validation for vault, item, category, and title inputs
- provider auth, permission, not-found, rate-limit, server, JSON, and HTTP error mapping
- lifecycle, introspection, simulation, doctor, self-check, provisioning-readiness, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: 1Password Connect Server access token or host credential reference.
- Home zone: `z:private`.
- Allowed source zones: `z:owner` and `z:private`.
- Allowed target zone: `z:private`.
- Forbidden zones: `z:public`, `z:community`, and `z:work`.
- Capability surface:
  - `1password.vaults.read` gates vault listing.
  - `1password.items.read` gates item listing and item retrieval.
  - `1password.items.write` gates item creation and item deletion.
- The connector does not persist vaults, items, field values, tags, access tokens, or credential IDs.
- The manifest declares `storage.state`, but the current runtime keeps configuration in memory for the connector process.
- Credential-id mode forwards a host credential reference header; host-side credential materialization remains outside this connector.

## Network And Runtime Invariants

- Runtime default base URL: `https://localhost:8080`.
- Connect Server path root: `/v1`.
- Runtime request timeout: `30_000 ms`.
- Manifest operation host allow-list: `*.1password.com` and `*.b5dev.com`.
- Manifest operation port allow-list: `443`.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals.
- Runtime tests use loopback WireMock origins.
- Because the runtime default is a local Connect Server URL while the manifest egress policy is public-host focused, live sandbox deployment requires an explicit network-policy decision before treating this connector as production-ready.
- Manifest network constraints set total timeout `30_000 ms`.
- Maximum response bytes are `1_048_576` for vault, get, create, and delete operations, and `10_485_760` for item listing.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `120_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `1password.vaults.read` | List vaults accessible to the configured Connect Server token. |
| `1password.items.read` | List items and retrieve item field values. |
| `1password.items.write` | Create and delete vault items. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `1password.vaults.list` | `GET /v1/vaults` | `1password.vaults.read` | `Safe` | `Low` | `Strict` | Lists accessible vault metadata. |
| `1password.items.list` | `GET /v1/vaults/{vault_id}/items` | `1password.items.read` | `Safe` | `Low` | `Strict` | Lists item metadata without requiring full secret fields. |
| `1password.items.get` | `GET /v1/vaults/{vault_id}/items/{item_id}` | `1password.items.read` | `Risky` | `Medium` | `Strict` | Reads one item including field values that can contain secrets. |
| `1password.items.create` | `POST /v1/vaults/{vault_id}/items` | `1password.items.write` | `Risky` | `Medium` | `None` | Creates new secret material or metadata in a vault. |
| `1password.items.delete` | `DELETE /v1/vaults/{vault_id}/items/{item_id}` | `1password.items.write` | `Dangerous` | `High` | `Strict` | Deletes an item and can break dependent systems. |

## Explicit Non-Goals

The current implementation does not include:

- 1Password account, user, group, team, SCIM, Events API, or audit log operations
- document upload/download despite the manifest description mentioning documents
- vault creation, vault mutation, item update, item restore, item archive, item file attachment, item sharing, or item version history
- 1Password CLI integration or browser extension integration
- connector-local secret vaulting or durable secret caching
- path-segment sanitization for vault IDs and item IDs
- host credential injection implementation inside the connector
- FCP subscription-based streaming
- automatic Connect Server provisioning

These are excluded on purpose:

- The useful first slice is a narrow Connect Server bridge for bounded vault and item access.
- Item retrieval can expose secrets, so read and write operations use private-zone capability boundaries rather than public or work-zone access.
- Deletion is intentionally dangerous and interactive-policy gated in the manifest.
- The runtime/manifest network mismatch needs a follow-up policy decision before broad live deployment.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, `introspect()`, and `provisioning_readiness()` are part of the public closeout contract. They surface:

- configuration, handshake state, local health status, request counters, and error counters
- auth mode as bearer token, credential ID, or unconfigured
- base URL used by the runtime
- client initialization and handshake readiness
- five operation metadata entries derived from runtime operation info
- provisioning recipe steps for auth-mode selection, access-token prompt, secret storage, and base URL prompt

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- lifecycle health, handshake, shutdown, self-check, doctor, and introspection
- bearer auth header behavior
- vault listing, empty vault listing, item listing, item retrieval, item creation, and item deletion
- missing required fields for read, create, and delete operations
- 401, 403, 404, 429, and 500 provider error paths
- unknown-operation and simulation behavior
- request/error counters
- configuration parsing, token trimming, credential ID validation, and auth redaction
- operation metadata, schema, risk, safety, idempotency, and capability invariants

## Source Notes

- `connectors/1password/src/connector.rs` defines configuration parsing, lifecycle handlers, provisioning readiness, operation dispatch, required-field validation, operation metadata, and provisioning recipe metadata.
- `connectors/1password/src/client.rs` defines Connect Server REST calls, bearer/credential headers, default base URL, request timeout, response parsing, and provider error mapping.
- `connectors/1password/src/error.rs` maps provider and runtime failures into FCP-facing errors.
- `connectors/1password/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, rate-limit pools, and operation AI hints.
- `connectors/1password/tests/integration.rs` covers deterministic WireMock operation behavior, lifecycle diagnostics, error handling, simulation, and counters.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/1password_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock Connect Server coverage
- auth, base URL, vault, item, create, delete, provider-error, lifecycle, simulation, provisioning, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a 1Password Connect Server access token for direct live verification.
- Use `credential_id` only when an egress proxy can materialize the secret at request time.
- Use WireMock loopback fixtures for routine proof.
- Decide whether live deployment targets local Connect Server, hosted Connect Server, or a policy-controlled proxy before enabling sandbox egress.

**Dedicated environment**:

- Use a test vault and synthetic items for live runs.
- Keep production vault IDs, item IDs, item titles, field labels, field values, and tags out of routine logs.
- Keep item update, document operations, Events API, SCIM, and account management out of this connector until separate beads define those contracts.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, vault IDs when sensitive, item IDs when sensitive, item titles when sensitive, field values, tags, provider payloads, and provider error bodies.
- Verification output should use operation names, endpoint paths, auth mode, host class, result counts, status/error classes, retry decisions, and local readiness status.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one of `access_token` or `credential_id`.
- If configuration fails, make sure `credential_id` is a UUID and that `access_token` is not supplied at the same time.
- If `doctor` reports the handshake check as degraded, call `handshake` after configuration.
- If provider calls fail with 401 or 403, check the Connect Server token and vault grants.
- If item list succeeds but item get fails, confirm the item ID and read permissions for that vault.
- If create/delete is rejected by policy, confirm the caller has `1password.items.write` and the operation approval policy is satisfied.
- If live egress fails from a sandbox, reconcile the local Connect Server default with the manifest network constraints before widening the connector.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-onepassword-e2e cargo check -p fcp-onepassword --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-onepassword-e2e cargo test -p fcp-onepassword --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-onepassword-e2e cargo clippy -p fcp-onepassword --all-targets --no-deps -- -D warnings`
