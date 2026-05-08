# Bitwarden Connector V3 Contract

> **Status**: runtime contract documented; endpoint-policy drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://bitwarden.com/help/bitwarden-apis/
> **CLI upstream**: https://bitwarden.com/help/cli/#serve

## Purpose

This document fixes the operator-facing contract for `fcp.bitwarden`. The connector exposes a focused Bitwarden vault-management surface for collection listing, item listing, item retrieval, item creation, and item deletion.

The connector is intentionally a private-zone vault bridge. It is not a full Bitwarden organization admin client, event-log client, policy client, attachment bridge, Send bridge, directory-sync client, or account-recovery tool.

## Current Runtime Snapshot

The current crate exposes these operations:

- `bitwarden.collections.list`
- `bitwarden.items.list`
- `bitwarden.items.get`
- `bitwarden.items.create`
- `bitwarden.items.delete`

Important runtime truths the contract preserves:

- Configuration requires exactly one of `access_token` or `credential_id`.
- `access_token` mode sends `Authorization: Bearer ...`.
- `credential_id` mode sends `X-FCP-Credential-Id: ...`.
- `credential_id` must be a valid UUID.
- Access tokens are trimmed and redacted in debug output.
- Default base URL is `https://api.bitwarden.com`.
- The implemented request paths are Vault Management API / `bw serve` style paths: `/collections`, `/list/object/items`, `/object/item`, and `/object/item/{item_id}`.
- The client strips trailing slashes from `base_url` but does not fully parse or normalize it during configure.
- Doctor and self-check perform a live `collections.list` call when configured.
- Doctor base URL policy accepts HTTPS known Bitwarden cloud hosts, HTTPS self-hosted domains containing `bitwarden`, and loopback test origins.
- Runtime loopback origins are accepted by diagnostics for deterministic tests.
- The HTTP client timeout is `30 seconds`.
- The connector constructs a shared retry config with a maximum of two retries; current request helpers call reqwest directly.
- Upstream 401, 403, 404, 429 with `Retry-After`, OAuth-style error bodies, and generic provider failures are mapped into FCP auth, permission, not-found, rate-limit, or external errors.

## Endpoint Policy Drift In This Checkout

The runtime and manifest describe different operational assumptions:

- The runtime paths match Bitwarden Vault Management API / `bw serve` behavior, and the official Bitwarden docs state that this API requires the CLI `serve` command to start a local HTTP server.
- The manifest network constraints allow `*.bitwarden.com` and `*.bitwarden.eu`, require TLS/SNI, and deny localhost, private ranges, tailnet ranges, and IP literals for live operations.
- The runtime diagnostics still allow loopback for deterministic tests, while live manifest policy would deny loopback unless routed through a host-approved proxy or a future manifest update.
- The default `https://api.bitwarden.com` value is the current code default, but the implemented `/collections` and `/object/item` path shapes should be treated as Vault Management API compatible, not as a broad Bitwarden Public API claim.

This README documents the runtime truth while keeping the endpoint-policy drift visible. A follow-up manifest/runtime parity bead should reconcile whether this connector's production target is a host-proxied `bw serve` endpoint, a self-hosted Vault Management API endpoint, or a different Bitwarden API surface.

## First-Slice Scope

The current Bitwarden README slice documents the existing runtime surface:

- direct bearer-token and host credential-reference configuration
- Vault Management API style item and collection paths
- collection listing through `GET /collections`
- item listing through `GET /list/object/items`
- optional `collection_id` and `folder_id` filters on item listing
- item retrieval through `GET /object/item/{item_id}`
- item creation through `POST /object/item`
- item deletion through `DELETE /object/item/{item_id}`
- provider error mapping, retry metadata, and redaction posture
- lifecycle, introspection, simulation, doctor, self-check, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: bearer token or host credential reference.
- Home zone: `z:private`.
- Allowed source zones: `z:owner` and `z:private`.
- Allowed target zone: `z:private`.
- Forbidden zones: `z:public`, `z:community`, and `z:work`.
- Capability surface:
  - `bitwarden.collections.read` gates collection listing.
  - `bitwarden.items.read` gates item listing and item retrieval.
  - `bitwarden.items.write` gates item creation and item deletion.
- The connector does not persist vault items, collection lists, folders, passwords, TOTP seeds, access tokens, credential IDs, provider payloads, or provider error bodies beyond process memory.
- `bitwarden.items.get` can return secret fields and is intentionally marked risky.
- `bitwarden.items.delete` is policy-gated as dangerous because this connector does not expose restore or trash-management operations.

## Network And Runtime Invariants

- Code default base URL: `https://api.bitwarden.com`.
- Implemented path family: Vault Management API / `bw serve` style paths.
- Manifest live host family: `*.bitwarden.com` and `*.bitwarden.eu`.
- Diagnostic accepted hosts: `api.bitwarden.com`, `api.bitwarden.eu`, `vault.bitwarden.com`, `vault.bitwarden.eu`, domains containing `bitwarden`, and loopback test origins.
- Production port: `443` under the current manifest.
- TLS and SNI are required by the manifest for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback diagnostics are test-only unless the host policy deliberately proxies and permits that route.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints set total timeout `30_000 ms`.
- Maximum response bytes are `1_048_576` for collection list, item get, create, and delete; item list allows `10_485_760`.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `120_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `bitwarden.collections.read` | List visible vault collections. |
| `bitwarden.items.read` | List item metadata and retrieve one item, including secret fields. |
| `bitwarden.items.write` | Create or delete vault items. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `bitwarden.collections.list` | `GET /collections` | `bitwarden.collections.read` | `Safe` | `Low` | `Strict` | Read-only collection inventory. |
| `bitwarden.items.list` | `GET /list/object/items` | `bitwarden.items.read` | `Safe` | `Low` | `Strict` | Read-only item listing with optional collection and folder filters. |
| `bitwarden.items.get` | `GET /object/item/{item_id}` | `bitwarden.items.read` | `Risky` | `Medium` | `Strict` | Retrieves one item and can include passwords, TOTP seeds, and notes. |
| `bitwarden.items.create` | `POST /object/item` | `bitwarden.items.write` | `Risky` | `Medium` | `None` | Creates a provider-visible vault item. |
| `bitwarden.items.delete` | `DELETE /object/item/{item_id}` | `bitwarden.items.write` | `Dangerous` | `High` | `Strict` | Destructive item operation with no restore path exposed by this connector. |

## Explicit Non-Goals

The current implementation does not include:

- Bitwarden Public API organization management for members, groups, policies, collections, event logs, or organization API keys
- login/unlock/session-key management, `bw serve` process management, or CLI orchestration
- folder listing, folder creation, collection creation, collection updates, or item movement between collections
- item update/edit, restore, trash listing, permanent-delete toggles, attachment upload/download, Send, emergency access, or account recovery
- TOTP generation, password generation, password health, breach reports, or URI matching
- sync status, vault lock state, multi-account switching, or offline export/import
- FCP subscription-based streaming
- connector-local credential vaulting

These are excluded on purpose:

- The useful first slice is a narrow private-zone item/collection bridge.
- Secret-bearing item retrieval and item deletion need explicit capability and policy boundaries.
- Managing `bw serve` lifecycle or full organization administration requires a separate security contract.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration and handshake state
- request and error counters
- configured auth mode and base URL
- base URL diagnostic status
- live collection-list auth/connectivity validation when configured
- degraded self-check for unconfigured state or failed collection-list probe
- five operation descriptors with capability, risk, safety tier, idempotency, schemas, and AI hints
- simulation denial for unsupported operation IDs

The deterministic integration evidence is anchored on connector-local tests covering:

- access-token and credential-id configuration
- rejection for missing auth, duplicate auth methods, empty tokens, non-string credential IDs, and invalid UUIDs
- lifecycle health, handshake-before-configure failure, shutdown, doctor, self-check, introspection, simulation, and counters
- bearer auth header propagation
- collection listing, item listing, filtered item listing, item retrieval, item creation, and item deletion loopback requests
- required-field validation for `item_id`, `type`, and `name`
- provider 401, 403, 404, 429 with `Retry-After`, 500, and OAuth-style error bodies
- manifest operation inventory, rate-limit pools, and network constraints

## Source Notes

- `connectors/bitwarden/src/connector.rs` defines configuration parsing, auth mode selection, lifecycle handlers, diagnostics, live self-check behavior, introspection, simulation, and invoke dispatch.
- `connectors/bitwarden/src/client.rs` defines Vault Management API style paths, bearer and credential-reference headers, timeout, retry metadata, request helpers, and provider error mapping.
- `connectors/bitwarden/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/bitwarden/src/types.rs` defines provider error response parsing.
- `connectors/bitwarden/manifest.toml` defines operation schemas, network constraints, sandbox boundary, zone policy, rate limits, and AI hints.
- `connectors/bitwarden/tests/integration.rs` covers deterministic HTTP behavior and manifest/runtime contract checks.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/bitwarden_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime operation agreement
- deterministic WireMock coverage for all five operations
- auth, base URL diagnostics, provider error, lifecycle, simulation, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a disposable Bitwarden vault or test organization for live mutation checks.
- Prefer a host-approved Vault Management API endpoint or proxy that matches the manifest/network policy before live use.
- Use WireMock loopback fixtures for routine proof.
- Treat `credential_id` as a host egress-proxy reference, not a Bitwarden credential itself.

**Dedicated environment**:

- Keep live created items synthetic and non-sensitive.
- Do not run delete checks against production vault items.
- Do not log item payloads from `bitwarden.items.get`.
- Do not expose a local `bw serve` endpoint broadly; Bitwarden warns that unbound network exposure can let other machines make API requests.

**Redaction rules**:

- Redact bearer tokens, credential IDs where needed, item IDs when sensitive, collection IDs when sensitive, folder IDs when sensitive, item names, usernames, passwords, TOTP seeds, notes, provider payloads, provider error bodies, and endpoint URLs when they reveal vault topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, retry decisions, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide exactly one of `access_token` or `credential_id`.
- If credential-id configuration fails, pass a valid UUID.
- If live checks fail against `https://api.bitwarden.com`, verify whether the target actually exposes the Vault Management API path family expected by this connector.
- If manifest policy denies loopback `bw serve`, route through an approved host-side proxy or file a manifest/runtime parity follow-up instead of bypassing policy.
- If item creation fails validation, include integer `type` and string `name`.
- If item retrieval or deletion fails validation, pass an item ID rather than a name, URL, or provider object.
- If delete is denied by policy, verify explicit approval for `bitwarden.items.write` and the dangerous operation tier.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-bitwarden-readme cargo check -p fcp-bitwarden --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-bitwarden-readme cargo test -p fcp-bitwarden --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-bitwarden-readme cargo clippy -p fcp-bitwarden --all-targets --no-deps -- -D warnings`
