# Zapier Connector V3 Contract

> **Status**: runtime contract documented; legacy API drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Zapier API overview**: https://docs.zapier.com/platform/reference
> **Powered by Zapier API**: https://docs.zapier.com/platform/reference/api
> **Zapier MCP docs**: https://docs.zapier.com/mcp
> **Legacy AI Actions/NLA host used by runtime**: https://nla.zapier.com/

## Purpose

This document fixes the operator-facing contract for `fcp.zapier`. The connector currently targets the legacy Zapier NLA/AI Actions exposed-action surface implemented in this crate: list exposed actions and execute one exposed action by ID.

The connector is intentionally a bounded automation trigger bridge. It is not a complete Zapier Platform client, Zap editor, Zap history browser, connection manager, app-integration builder, current Powered by Zapier v2 workflow client, MCP server client, task log scraper, webhook receiver, or general Zapier API proxy.

## Current Runtime Snapshot

The current crate exposes these operations:

- `zapier.zaps.list`
- `zapier.zaps.execute`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-zapier`.
- Runtime `BaseConnector` ID is `fcp.zapier`.
- Manifest and reported connector ID are `fcp.zapier`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000`.
- Configuration requires exactly one auth source: direct `api_key` or `credential_id`.
- Direct API-key mode trims surrounding whitespace and rejects empty keys.
- Direct API-key mode sends `Authorization: Bearer {api_key}`.
- `credential_id` mode sends `X-FCP-Credential-Id` and expects host egress policy to inject real secret material.
- `credential_id` must be a valid UUID.
- Default base URL is `https://api.zapier.com/v1`.
- `base_url` policy allows only `https://api.zapier.com`, `https://nla.zapier.com`, `localhost`, or `127.0.0.1`.
- Localhost and `127.0.0.1` are allowed for tests even over HTTP.
- `::1` is not accepted as a local test host.
- The client trims trailing slashes from `base_url`.
- Reqwest client timeout is 60 seconds.
- Shared request context timeout is 60 seconds.
- The client stores a default retry config but current GET/POST helpers send one request directly and do not wrap requests in the shared retry loop.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime `invoke` does not accept or verify `capability_token`.
- Runtime does not install a `CapabilityVerifier`.
- Runtime does not verify approval tokens for `zapier.zaps.execute`.
- `simulate` only checks whether `operation_id` is present in the local operation inventory.
- `handle_configure()` clears any prior session ID and handshaken flag before replacing the client/config.
- `handle_handshake()` requires prior configuration, accepts an optional `session_id`, and marks the connector handshaken even when no session ID is provided.
- `health()` reports healthy only after configure plus handshake; configured but unhandshaken is degraded.
- `doctor()` checks configuration, client initialization, and handshake state.
- `self_check()` is a local readiness check; it does not call Zapier.
- `handle_shutdown()` clears client/config/session and base configured/handshaken flags, but request/error counters remain in memory.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Current Zapier docs emphasize Zapier Platform APIs, Powered by Zapier API, Zapier MCP, and v2 action/action-run style surfaces. Runtime uses legacy NLA/AI Actions paths under `/exposed/` and `/exposed/{action_id}/execute/`.
- Runtime operation names use `zaps`, but the implemented HTTP surface lists and executes exposed NLA actions, not full Zap definitions.
- Manifest and runtime operation IDs are aligned, but the interface hash is still the all-zero placeholder.
- Manifest marks `zapier.zaps.execute` as policy-approved. Runtime operation metadata sets `requires_approval = None`, and invoke checks no approval token.
- Runtime `zapier.zaps.execute` schema says `params` is required in operation metadata and manifest, but invoke treats `params` as optional and defaults it to `{}`.
- Runtime inserts `instructions: null` into execute payloads when the caller does not provide `instructions`.
- Runtime validates `action_id` as a single ASCII alphanumeric, dash, or underscore path component up to 128 bytes. This rejects dots, slashes, percent encoding, whitespace, query/fragment delimiters, and non-ASCII.
- Manifest network constraints deny localhost and private ranges. Runtime allows localhost and `127.0.0.1` for tests at configure time.
- Manifest says NLA API key state is stored under singleton-writer state. Runtime keeps configuration in process memory and does not persist connector state itself.
- Runtime `self_check()` validates local config and URL policy only; it does not prove the API key, credential injection, action inventory, or Zapier account access.
- Manifest rate-limit pools are documented intent only; runtime does not enforce connector-local rate limits.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should decide whether this connector remains a legacy AI Actions/NLA bridge or migrates to the current Powered by Zapier API/MCP surfaces, replace the placeholder interface hash, align operation names with exposed actions, add capability-token and approval-token verification, align required input semantics for `params`, enforce or document test-only URL exceptions, add live readiness where desired, and add a tracked verification bundle.

## First-Slice Scope

The current Zapier README slice documents the existing runtime surface:

- direct API-key and host credential-reference configuration
- endpoint policy for Zapier hosts and local test hosts
- exposed-action listing and execution over legacy `/exposed/` paths
- action ID path-injection hardening
- local health, doctor, self-check, simulation, introspection, and shutdown behavior
- runtime/manifest drift around approvals, capability enforcement, legacy API shape, and state persistence
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Zapier API key or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability metadata:
  - `zapier.zaps.read`
  - `zapier.zaps.write`
- The connector does not verify capability tokens, operation grants, principal identity, zone, or approval tokens at invoke time.
- The connector does not persist API keys, credential secret material, action payloads, action results, provider error bodies, request counters, or action inventory outside process memory.
- Exposed actions can send messages, mutate SaaS records, trigger workflows, or move data between services. Treat live output and parameters as work-zone or private-zone data based on the connected Zapier account and exposed action.

## Network And Runtime Invariants

- Default endpoint: `https://api.zapier.com/v1`.
- Runtime list request: `GET {base_url}/exposed/`.
- Runtime execute request: `POST {base_url}/exposed/{action_id}/execute/`.
- Runtime sends `Accept: application/json`.
- Runtime sends bearer auth in direct API-key mode.
- Runtime sends `X-FCP-Credential-Id` in credential-reference mode.
- Runtime user agent is `fcp-zapier/0.1.0 (FCP connector)`.
- Runtime reqwest timeout: `60 seconds`.
- Runtime request context timeout: `60 seconds`.
- Runtime does not apply the stored retry config around GET/POST calls.
- Provider HTTP 401, 403, 404, 429, and other API errors map to typed connector/FCP errors.
- `Retry-After` on 429 is converted to milliseconds; missing values default to 60000 ms.
- Provider error bodies are truncated to 2048 bytes before extracting `error` or `detail`.
- Manifest connect timeout is `10000 ms`, operation total timeout is `30000 ms` or `60000 ms`, and maximum response bytes are `1048576` or `10485760` by operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, no exec, and no inbound listener capability.
- The connector does not open inbound sockets, receive Zapier webhooks, manage Zapier connections, or edit Zaps.

## Operation Inventory

| Operation | Runtime request | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|-----------------|------------|------------|-----------|-------------|----------------|
| `zapier.zaps.list` | `GET /exposed/` | `zapier.zaps.read` | `Safe` | `Low` | `Strict` | none |
| `zapier.zaps.execute` | `POST /exposed/{action_id}/execute/` | `zapier.zaps.write` | `Risky` | `Medium` | `None` | `action_id`; `params` optional at runtime despite schema |

## Explicit Non-Goals

The current implementation does not include:

- current Powered by Zapier v2 action catalog, action-run creation, action-run status polling, or account/service discovery
- Zapier MCP server integration
- Zap listing/editing through the Zapier editor or full Zap definition APIs
- connection creation, OAuth authorization, account linking, app installation, or app integration management
- task history, run logs, retries, replay, billing/task quota inspection, or Zap error inspection
- webhook receive endpoints, webhook verification, event replay, durable queueing, or idempotency keys
- approval-token verification, capability-token verification, zone-aware policy checks, or per-action allowlists
- durable storage for exposed action inventories, parameter schemas, or execution results

These are excluded on purpose:

- Exposed Zapier actions can trigger arbitrary third-party side effects.
- The legacy NLA/AI Actions surface is narrow and should not silently expand into a general Zapier automation proxy.
- Current Zapier Platform, Powered by Zapier, and MCP surfaces have different API shapes and deserve separate manifest-aligned runtime contracts.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, handshake, request counter, and error counter state
- local URL policy and credential-injection readiness
- degraded self-check for unconfigured and `credential_id` modes
- typed introspection with two operations, schemas, capability IDs, risk levels, safety tiers, idempotency, and hints
- simulation allow/deny for known versus unknown operation IDs only
- provider/FCP error mapping for auth failures, forbidden responses, missing actions, rate limits, API errors, JSON errors, and transport errors

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, doctor, self-check, introspection, simulation, shutdown, and counters
- list exposed actions from top-level arrays and `{ "zaps": [...] }` objects
- execute exposed action with explicit params, empty params, and omitted params
- unknown-operation and missing-operation rejection
- provider 401, 403, 404, 429, 500, 502, and empty-error-body behavior
- direct API-key versus credential-ID configuration
- endpoint policy hard rejection for non-Zapier hosts and HTTP downgrade outside local tests
- action ID path-injection rejection for slashes, dots, query/fragment characters, percent encoding, whitespace, oversized IDs, and non-ASCII
- provisioning recipe shape for manual API-key entry

## Source Notes

- `connectors/zapier/src/connector.rs` defines configuration parsing, endpoint policy, provisioning recipe, lifecycle handlers, local introspection, simulation, and invoke dispatch.
- `connectors/zapier/src/client.rs` defines Zapier auth headers, endpoint paths, timeout, action ID validation, and provider error mapping.
- `connectors/zapier/src/types.rs` defines legacy Zap/NLA action and error response shapes.
- `connectors/zapier/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/zapier/manifest.toml` defines the manifest operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit intent.
- `connectors/zapier/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/zapier/README.md
ubs connectors/zapier/README.md
LC_ALL=C rg -n '[^ -~]' connectors/zapier/README.md
rg -n '\bmaster\b' connectors/zapier/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-zapier
rch exec -- cargo check -p fcp-zapier --all-targets
rch exec -- cargo clippy -p fcp-zapier --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Treat this connector as a legacy NLA/AI Actions exposed-action bridge, not as a current Powered by Zapier v2 or MCP integration.
- Use least-privilege Zapier credentials and expose only actions intended for automated execution.
- Keep direct API-key mode pointed at `https://api.zapier.com/v1` or `https://nla.zapier.com` unless running deterministic localhost tests.
- Do not rely on `self_check()` as a live Zapier account or API-key probe; it only validates local readiness.
- Treat `zapier.zaps.execute` as a high-review operation until capability-token and approval-token verification are implemented.
- Keep action IDs as simple ASCII IDs and put all dynamic data in `params`; the runtime rejects path-like action IDs by design.
