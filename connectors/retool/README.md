# Retool Connector V3 Contract

> **Status**: runtime contract documented with workflow-only and approval-token drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Retool Workflows upstream**: https://docs.retool.com/workflows

## Purpose

This document fixes the operator-facing contract for `fcp.retool`. Despite the manifest description mentioning apps, workflows, and queries, the current implementation is a small Retool Workflows client. It lists workflows and triggers a workflow run through the configured Retool API base URL.

The connector is intentionally a bounded Retool workflow trigger bridge. It is not a Retool app builder, query editor, resource-management client, user-management client, permission-management client, audit-log exporter, workflow authoring runtime, webhook receiver, or connector-local credential vault.

## Current Runtime Snapshot

The current crate exposes these operations:

- `retool.workflows.list`
- `retool.workflows.run`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-retool`.
- Runtime `BaseConnector` ID is `retool`.
- Manifest and handshake connector ID are `fcp.retool`.
- Connector version is `0.1.0`.
- Configuration requires `api_token`.
- `api_token` must be a non-empty string and is trimmed.
- Optional `subdomain` selects `https://{subdomain}.retool.com/api/v1`.
- Without `subdomain` or `base_url`, runtime uses `https://app.retool.com/api/v1`.
- Optional `base_url` overrides `subdomain`.
- Runtime auth sends `Authorization: Bearer <api_token>`.
- Runtime reqwest timeout is `30 seconds`.
- Runtime request context timeout is `30 seconds`.
- Runtime contains an `HttpRetryConfig` with `max_retries = 2`, but current request methods send requests directly and do not use a retry loop.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime `invoke` checks only connector readiness, operation identity, local required-field extraction, and client initialization before dispatch.
- Runtime does not verify `capability_token`.
- Runtime does not verify approval tokens for `retool.workflows.run`.
- `simulate` checks only whether `operation_id` is known. It does not validate readiness, input shape, caller authority, capability, approval state, or rate limits.
- `handle_shutdown()` shuts down the client runtime, clears client/config state, and resets configured/handshaken flags.
- `handle_shutdown()` does not clear the stored `session_id` string.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Manifest description says "Retool (apps, workflows, queries)", but runtime exposes only workflow list and workflow run.
- Manifest operation `retool.workflows.run` is policy-gated. Runtime introspection exposes it with no `requires_approval` field and invoke checks no approval token.
- Runtime accepts an arbitrary configured `base_url` during configure and creates the client before self-check applies endpoint policy.
- Runtime base URL policy accepts `https://retool.com`, `https://*.retool.com`, and loopback HTTP(S) for deterministic tests. Manifest live-operation policy allows `api.retool.com` and `*.retool.com` on port 443 and denies localhost.
- Runtime `self_check` performs local configuration, endpoint-policy, and client checks only. It does not call Retool.
- Runtime `doctor` performs local configuration, client, and handshake checks only. It does not call Retool.
- Runtime inserts `workflow_id` directly into `/workflows/{workflow_id}/run` after checking that it is a string. It does not enforce a path-safe workflow ID pattern.
- Runtime `workflows.list` has no pagination or filtering inputs. It returns the provider response body as received.
- Runtime stores API token and endpoint metadata in memory only. It does not persist the manifest-advertised API token or org subdomain to connector state.
- Manifest `interface_hash` is all zeros.
- There is no tracked verification shell script for this connector.

A follow-up parity bead should install bound capability-token verification, enforce approval-token semantics for workflow runs, validate or encode `workflow_id` as a path segment, decide whether app/query surfaces belong in this connector, align endpoint policy between manifest and runtime, and replace the zero interface hash.

## First-Slice Scope

The current Retool README slice documents the existing runtime surface:

- direct API-token configuration
- optional subdomain and base URL selection
- workflow list and workflow run operations
- retry, timeout, provider error, readiness, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- runtime/manifest drift around scope, approvals, capability-token verification, endpoint policy, path validation, state persistence, pagination, and interface hash
- deterministic WireMock tests and direct proof commands

## Auth And Zone Boundary

- Authentication mechanism: Retool API bearer token.
- Runtime does not implement Retool SSO, OAuth app authorization, API token creation, API token rotation, user impersonation, SCIM, service-account enrollment, or connector-local credential vaulting.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Capability families:
  - `retool.workflows.read`
  - `retool.workflows.write`
- Workflow lists, workflow inputs, and workflow outputs can expose production system names, internal automation design, customer data, credentials passed into workflows, and business-sensitive results. Do not log API tokens, workflow inputs, workflow outputs, raw provider error bodies, or workflow names from private instances in shared artifacts.

## Network And Runtime Invariants

- Default runtime base URL template: `https://{subdomain}.retool.com/api/v1`.
- Default subdomain when none is configured: `app`.
- Runtime HTTP endpoints:
  - `GET /workflows`
  - `POST /workflows/{workflow_id}/run`
- Runtime sends `Authorization: Bearer <api_token>`.
- Runtime sends workflow-run bodies as JSON. If `input.data` is absent, it sends `{}`.
- Runtime maps successful empty bodies to `{}`.
- Runtime maps 401 to unauthorized, 403 to forbidden, 404 to not found, 429 to rate limited using `Retry-After` with a 60 second default, and other non-success responses to provider API errors.
- Runtime base URL policy allows Retool HTTPS hosts and loopback hosts for deterministic tests.
- Manifest live-operation policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and allows `api.retool.com` plus `*.retool.com` on port 443.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, read-only `/usr` and `/lib`, writable `$CONNECTOR_STATE`, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `retool.workflows.list` | `GET /workflows` | `retool.workflows.read` | `Safe` | `Low` | `Strict` | None. |
| `retool.workflows.run` | `POST /workflows/{workflow_id}/run` | `retool.workflows.write` | `Risky` | `Medium` | `None` | `workflow_id`; optional `data`. |

## Explicit Non-Goals

The current implementation does not include:

- Retool app creation, app export/import, UI editing, query editing, resource management, permission management, user management, SCIM, audit logs, or organization settings
- Retool workflow authoring, workflow deployment, workflow scheduling, workflow version management, workflow enable/disable controls, webhook creation, webhook verification, or inbound webhook serving
- arbitrary Retool API endpoint passthrough
- pagination, filtering, sorting, or status filtering for workflow lists
- connector-local storage of API tokens, org metadata, workflow definitions, workflow inputs, workflow outputs, run IDs, counters, or provider errors outside process memory
- direct FCP capability-token or approval-token verification at connector invoke time

These are excluded on purpose:

- Triggering a workflow can mutate external systems, send messages, move money, update databases, or call production APIs depending on the workflow definition.
- Workflow outputs can include secrets and customer data.
- Retool's app/query/resource surface needs separate permission and audit handling before it should share this connector contract.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration, endpoint, client, and handshake state
- in-memory request/error counters
- known operation metadata, capability IDs, risk levels, safety tiers, and idempotency
- known versus unknown operation simulation
- provider error mapping for unauthorized, forbidden, not found, rate-limit, API, JSON, and transport failures

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle health, configure, handshake, shutdown, doctor, self-check, introspection, and counters
- workflow list success, empty list, and pagination-shaped provider payloads
- workflow run success with and without a body
- missing, null, and non-string `workflow_id` rejection
- provider 401, 403, 404, 429, 500, and 502 responses
- unknown-operation and simulation behavior
- subdomain configuration, base URL override, shutdown/reconfigure behavior, and base URL policy checks

## Source Notes

- `connectors/retool/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, introspection, simulation, invoke dispatch, operation IDs, provisioning readiness, and base URL policy.
- `connectors/retool/src/client.rs` defines Retool HTTP request construction, auth headers, endpoint paths, timeout configuration, and provider error mapping.
- `connectors/retool/src/types.rs` defines workflow request/response helper shapes.
- `connectors/retool/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/retool/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, rate-limit pools, state claim, and AI hints.
- `connectors/retool/tests/integration.rs` covers deterministic HTTP behavior, lifecycle behavior, operation dispatch, error mapping, and diagnostics.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/retool/README.md
ubs connectors/retool/README.md
LC_ALL=C rg -n '[^ -~]' connectors/retool/README.md
rg -n '\bmaster\b' connectors/retool/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-retool
rch exec -- cargo check -p fcp-retool --all-targets
rch exec -- cargo clippy -p fcp-retool --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Treat `retool.workflows.run` as approval-gated until runtime approval enforcement lands.
- Keep `base_url` on a Retool-owned HTTPS host for live use; loopback is a deterministic-test allowance, not a production endpoint policy.
- Do not treat this connector as an app/query/resource API surface until those operations exist in source and tests.
- Use `retool.workflows.list` to discover workflows before triggering a run, and confirm disabled/draft workflow behavior with the configured Retool instance rather than assuming list entries are runnable.
