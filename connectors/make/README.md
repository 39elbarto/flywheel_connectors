# Make Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Make API upstream**: https://developers.make.com/api-documentation/api-reference/scenarios
> **Make API docs**: https://www.make.com/en/api/documentation

## Purpose

This document fixes the operator-facing contract for `fcp.make`. The connector exposes the Make API surface implemented in this crate: scenarios and recent scenario executions.

The connector is intentionally a bounded automation bridge. It is not a full Make administration client, scenario editor, connection manager, webhook manager, organization/team manager, data store client, custom app manager, OAuth installer, or Make Bridge client.

## Current Runtime Snapshot

The current crate exposes these operations:

- `make.scenarios.list`
- `make.scenarios.run`
- `make.executions.list`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-make`.
- Runtime `BaseConnector` ID is `make`.
- Manifest and reported connector ID are `fcp.make`.
- Manifest interface hash is currently all zeroes: `blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000`.
- Configuration requires exactly one auth source: direct `api_token` or `credential_id`.
- Direct token mode sends `Authorization: Token {api_token}`.
- `credential_id` mode sends `X-FCP-Credential-Id` and expects host egress policy to inject real secret material.
- Default base URL is `https://us1.make.com/api/v2`.
- Custom `base_url` is accepted during configure without URL hygiene checks.
- `self_check` readiness policy accepts `make.com`, `*.make.com`, `integromat.com`, `*.integromat.com`, and loopback hosts.
- `self_check` readiness policy rejects non-loopback HTTP and unknown hosts.
- Runtime request timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 3`.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime does not install a `CapabilityVerifier` and does not verify `capability_token`.
- Runtime does not verify approval tokens for scenario runs.
- `simulate` only checks whether `operation_id` is present in the local operation inventory.
- `handle_configure()` does not clear a prior handshake.
- `handle_shutdown()` clears config/client/base flags but leaves `session_id` in memory.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest interface hash is a placeholder all-zero hash.
- Manifest marks `make.scenarios.run` with `requires_approval = "policy"`, but runtime introspection sets `requires_approval = None` and runtime checks no approval token.
- Runtime does not verify capability tokens or bind operations to resource URIs.
- Manifest state hint says API token and team ID are stored; runtime keeps configuration in memory, has no `team_id` field, and does not persist connector state.
- Manifest operation hints mention a connector-level team ID, but runtime does not parse or use a team ID.
- Configure accepts arbitrary `base_url` strings. Host/scheme policy is only surfaced by `self_check`.
- Make URL policy does not reject userinfo, query strings, or fragments.
- Runtime introspection returns only `connector_id`, `version`, and `operations`, not the fuller `Introspection` shape with events, resource types, auth caps, or event caps.
- `handle_configure()` can leave the connector handshaken after reconfiguration because it does not reset the base handshaken flag.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should replace the placeholder interface hash, implement capability-token and approval-token verification, add or remove team ID semantics, harden `base_url` parsing to reject userinfo/query/fragment, reset handshake state on reconfigure, and add a tracked verification bundle.

## First-Slice Scope

The current Make README slice documents the existing runtime surface:

- direct API-token and host credential-reference configuration
- Make/Integromat base URL behavior
- provider host policy, timeout, retry, and provider error mapping
- scenario listing, scenario run, and execution listing operations
- simplified handshake and local readiness behavior
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Make API token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `make.scenarios.read` gates scenario listing metadata, but runtime does not enforce capability tokens.
  - `make.scenarios.write` gates scenario run metadata, but runtime does not enforce capability tokens.
  - `make.executions.read` gates recent execution listing metadata, but runtime does not enforce capability tokens.
- The connector does not persist API tokens, credential secret material, scenario data, execution data, scenario inputs, or provider error bodies outside process memory.
- Make payloads can include automation topology, scenario names, execution history, statuses, timestamps, and processed operational data. Treat live output as work-zone operational data.

## Network And Runtime Invariants

- Default Make API host: `us1.make.com`.
- Default API path prefix: `/api/v2`.
- Runtime readiness policy also accepts legacy Integromat hosts.
- Production port: `443`.
- TLS and SNI are required by the manifest for provider operations.
- Manifest network policy allows `*.make.com` and denies localhost, private ranges, tailnet ranges, and IP literals for live provider operations.
- Runtime readiness policy accepts loopback hosts for deterministic tests.
- Runtime readiness policy rejects non-loopback HTTP and unknown hosts.
- Runtime request timeout: `30 seconds`.
- Runtime retry policy: three attempts using the shared retry loop.
- Provider 401, 403, 404, 429, and other API errors map to typed connector/FCP errors.
- `Retry-After` on 429 is converted to milliseconds; missing values default to 60000 ms.
- Manifest connect timeout is `10000 ms`, total timeout is `30000 ms`, and maximum response bytes are `1048576` or `10485760` by operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, no exec, and no inbound listener capability.
- The connector does not open inbound sockets or receive Make webhooks.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `make.scenarios.read` | List scenarios in the configured API scope. |
| `make.scenarios.write` | Trigger a scenario run. |
| `make.executions.read` | List recent executions for a scenario. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `make.scenarios.list` | `GET /scenarios` | `make.scenarios.read` | `Safe` | `Low` | `Strict` | Lists scenarios and returns `scenarios`, defaulting missing scenarios to an empty array. |
| `make.scenarios.run` | `POST /scenarios/{scenario_id}/run` | `make.scenarios.write` | `Risky` | `Medium` | `None` | Triggers one scenario run and returns `execution_id` from `executionId` or `execution_id`. |
| `make.executions.list` | `GET /scenarios/{scenario_id}/executions` | `make.executions.read` | `Safe` | `Low` | `Strict` | Lists recent executions for one scenario and returns `executions`, defaulting missing executions to an empty array. |

## Resource URIs

Runtime capability-token verification is absent for Make in this checkout, so there are no effective resource URI bindings. The practical authorization binding is configuration plus base readiness plus operation name.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| Scenarios | `make://{region}/scenarios/{scenario_id}` |
| Executions | `make://{region}/scenarios/{scenario_id}/executions` |

## Explicit Non-Goals

The current implementation does not include:

- scenario create/update/delete, scenario interface management, blueprint export/import, scheduling changes, or scenario activation controls
- connection management, custom apps, webhooks, data stores, teams, organizations, folders, templates, or users
- execution detail retrieval, execution cancellation, logs, bundles, incomplete execution recovery, or run replay
- OAuth installation flow, token refresh, API-token rotation, webhook ingestion, or durable event replay
- durable storage of scenario or execution data

These are excluded on purpose:

- Scenario runs are side-effecting automation and need explicit approval/runtime verification before broader mutation is safe.
- Scenario editing needs stronger schema modeling than the current pass-through JSON operation surface.
- Webhook signature verification belongs at the host ingress boundary before connector invocation.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, handshake, request, and error counter state
- provider URL readiness and credential-injection warning state
- degraded self-check for unconfigured and `credential_id` modes
- direct API-token self-check based on local readiness only, not a live Make API probe
- operation metadata with capability, risk, safety tier, idempotency, schemas, and hints
- simulation allow/deny for known versus unknown operation IDs
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, configured-but-not-handshaken health, introspection, simulation, doctor, self-check, shutdown, and counters
- scenario listing, scenario run, and execution listing through deterministic HTTP fixtures
- invoke rejection for unknown operation, missing handshake, and missing required inputs
- provider 401, 403, 404, 429, and 500 classes
- auth header shape, auth redaction, custom URL handling, provisioning readiness, and base URL policy

## Source Notes

- `connectors/make/src/connector.rs` defines configuration parsing, URL readiness policy, lifecycle handlers, introspection, simulation, and invoke dispatch.
- `connectors/make/src/client.rs` defines Make API paths, auth headers, retry dispatch, timeout, default base URL, and provider error mapping.
- `connectors/make/src/types.rs` defines scenario, execution, and API error shapes.
- `connectors/make/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/make/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit intent.
- `connectors/make/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/make/README.md
ubs connectors/make/README.md
LC_ALL=C rg -n '[^ -~]' connectors/make/README.md
rg -n '\bmaster\b' connectors/make/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-make
rch exec -- cargo check -p fcp-make --all-targets
rch exec -- cargo clippy -p fcp-make --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Prefer `credential_id` for production so host policy owns secret injection.
- Use direct `api_token` only in local deterministic tests or explicitly scoped environments.
- Treat `make.scenarios.run` as a high-review operation even though runtime approval checks are absent.
- Do not rely on capability-token or approval-token enforcement until runtime verification is implemented.
- Do not assume team scoping exists in this runtime until `team_id` is actually parsed and enforced.
- Do not use a custom `base_url` with userinfo, query strings, or fragments even though the current runtime does not reject all of them.
