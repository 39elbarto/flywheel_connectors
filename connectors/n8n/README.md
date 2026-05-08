# n8n Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **n8n public REST API**: https://docs.n8n.io/api/
> **n8n API reference**: https://docs.n8n.io/api/api-reference/

## Purpose

This document fixes the operator-facing contract for `fcp.n8n`. The connector currently targets the n8n public REST API surface implemented in this crate: workflow listing, workflow lookup, workflow activation state changes, execution listing, and execution lookup.

The connector is intentionally a bounded self-hosted n8n administration bridge. It is not a workflow authoring client, credential manager, project manager, variable manager, audit client, webhook trigger runtime, event subscription client, n8n CLI replacement, or general HTTP proxy.

## Current Runtime Snapshot

The current crate exposes these operations:

- `n8n.workflows.list`
- `n8n.workflows.get`
- `n8n.workflows.activate`
- `n8n.executions.list`
- `n8n.executions.get`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-n8n`.
- Runtime `BaseConnector` ID is `n8n`.
- Manifest and reported connector ID are `fcp.n8n`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000`.
- Configuration requires exactly one auth source: direct `api_key` or `credential_id`.
- Direct API-key mode sends `X-N8N-API-KEY`.
- `credential_id` mode sends `X-FCP-Credential-Id` and expects host egress policy to inject real secret material.
- `credential_id` must be a valid UUID.
- `base_url` is required because n8n is self-hosted.
- `base_url` is trimmed but not otherwise validated by `configure`.
- The client trims trailing slashes from `base_url`.
- Runtime endpoint shape is `{base_url}/workflows`, `{base_url}/workflows/{id}`, `{base_url}/executions`, and `{base_url}/executions/{id}`.
- Runtime request timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 2`.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime does not install a `CapabilityVerifier` and does not verify `capability_token`.
- Runtime does not verify approval tokens for `n8n.workflows.activate`.
- `simulate` only checks whether `operation_id` is present in the local operation inventory.
- `handle_configure()` does not clear a prior session ID and does not reset the base handshaken flag.
- `handle_handshake()` accepts an optional `session_id`, sets the base handshaken flag, and returns capability IDs.
- `health()` and `doctor()` consider a handshake complete only when `session_id` is present.
- `handle_shutdown()` shuts down the client runtime and clears config/client/base flags, but leaves `session_id` in memory.
- `self_check()` is a local readiness check only; it does not issue a live n8n API probe.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest marks `n8n.workflows.activate` as `requires_approval = "policy"`, while runtime operation metadata sets `requires_approval = None` and invoke checks no approval token.
- Manifest network constraints allow `localhost.localdomain:5678`; runtime readiness accepts any HTTPS host and loopback HTTP for local tests.
- Runtime configure does not enforce the URL readiness policy, so a bad `base_url` can configure and fail later in `self_check` or invoke.
- Runtime readiness rejects non-loopback HTTP and missing hosts, but does not reject userinfo, query strings, fragments, redirects, or path shapes that are not n8n API roots.
- Manifest says API key and instance URL are stored under singleton-writer state. Runtime keeps config in process memory and does not persist connector state itself.
- Manifest format is `wasi`; this crate is a Rust package with `fcp-n8n` binary and library surfaces.
- Runtime `introspect()` returns only `connector_id`, `version`, and operations, not the full `Introspection` shape with events, resource types, auth caps, or event caps.
- `handle_handshake()` can set the base handshaken flag even when no `session_id` was provided, while health/doctor still report not handshaken.
- `handle_shutdown()` can leave `session_id` present, so health/doctor semantics can be misleading after shutdown.
- Manifest rate-limit pools are documented intent only; runtime does not enforce connector-local rate limits.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should add capability-token and approval-token verification, align manifest/runtime approval and network policy, reset session and handshake state on reconfigure and shutdown, harden URL validation, decide whether to support more n8n public API resources, and add a tracked verification bundle.

## First-Slice Scope

The current n8n README slice documents the existing runtime surface:

- direct n8n API key and host credential-reference configuration
- required self-hosted API base URL behavior
- local URL readiness, timeout, retry, and provider error mapping
- workflow read and activation operations
- execution read operations
- simplified handshake, self-check, introspection, and simulation behavior
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: n8n API key or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `n8n.workflows.read` gates workflow list/get metadata, but runtime does not enforce capability tokens.
  - `n8n.workflows.write` gates workflow activation metadata, but runtime does not enforce capability or approval tokens.
  - `n8n.executions.read` gates execution list/get metadata, but runtime does not enforce capability tokens.
- The connector does not persist API keys, credential secret material, workflow definitions, execution payloads, provider error bodies, or API responses outside process memory.
- Workflow and execution data can contain secrets, credentials metadata, prompts, private business data, or tool output. Treat live output as work-zone data unless a stricter zone policy is implemented.

## Network And Runtime Invariants

- Runtime endpoint shape:
  - `GET {base_url}/workflows`
  - `GET {base_url}/workflows/{id}`
  - `PATCH {base_url}/workflows/{id}` with JSON body `{ "active": bool }`
  - `GET {base_url}/executions`
  - `GET {base_url}/executions/{id}`
- Runtime sends `Accept: application/json`.
- Runtime sends `X-N8N-API-KEY` in direct API-key mode.
- Runtime sends `X-FCP-Credential-Id` in credential-reference mode.
- Runtime user agent is `fcp-n8n/0.1.0 (FCP connector)`.
- Runtime host policy accepts any HTTPS host and loopback HTTP/HTTPS for `localhost`, `127.0.0.1`, `::1`, and `[::1]`.
- Runtime readiness policy rejects non-loopback HTTP, unparsable URLs, and URLs without a host.
- Runtime configure does not enforce the readiness policy.
- Runtime request timeout: `30 seconds`.
- Runtime retry policy: `max_retries = 2` using the shared retry loop.
- Provider HTTP 401, 403, 404, 429, and other API errors map to typed connector/FCP errors.
- `Retry-After` on 429 is converted to milliseconds; missing values default to 60000 ms.
- Manifest connect timeout is `5000 ms`, operation total timeout is `15000 ms`, and maximum response bytes are `1048576` or `10485760` by operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, no exec, and no inbound listener capability.
- The connector does not open inbound sockets, receive n8n webhooks, run workflows locally, or connect to n8n's internal database.

## Operation Inventory

| Operation | HTTP request | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|--------------|------------|------------|-----------|-------------|----------------|
| `n8n.workflows.list` | `GET /workflows` | `n8n.workflows.read` | `Safe` | `Low` | `Strict` | none |
| `n8n.workflows.get` | `GET /workflows/{id}` | `n8n.workflows.read` | `Safe` | `Low` | `Strict` | `id` string |
| `n8n.workflows.activate` | `PATCH /workflows/{id}` | `n8n.workflows.write` | `Risky` | `Medium` | `None` | `id` string and `active` bool |
| `n8n.executions.list` | `GET /executions` | `n8n.executions.read` | `Safe` | `Low` | `Strict` | none |
| `n8n.executions.get` | `GET /executions/{id}` | `n8n.executions.read` | `Safe` | `Low` | `Strict` | `id` string |

## Explicit Non-Goals

The current implementation does not include:

- workflow create, update, delete, import, export, clone, test-run, tag, project, variable, credential, user, audit, or source-control operations
- pagination, filtering, sorting, or query parameter support for workflow or execution list calls
- activation approval-token verification despite the manifest policy marker
- execution retry, stop, delete, log streaming, custom-data filtering, or execution-data redaction management
- API-key provisioning automation beyond the local provisioning recipe prompts
- OAuth installation, API-key rotation, credential validation beyond local configuration shape, or live self-check probe
- n8n CLI behavior, server CLI behavior, embedded n8n runtime, webhook receiver, scheduler, or trigger execution

These are excluded on purpose:

- Activating a workflow can start cron, webhook, polling, or other production triggers and needs explicit approval/runtime verification before broader mutation is safe.
- Workflow and execution payloads may contain sensitive data and need a clearer read policy before adding broad export or debugging surfaces.
- n8n has a large public API; this connector should grow only through manifest-aligned, capability-gated slices.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, session ID, request, and error counter state
- local URL readiness and credential-injection warning state
- degraded self-check for unconfigured and `credential_id` modes
- operation metadata with capability, risk, safety tier, idempotency, schemas, and hints
- simulation allow/deny for known versus unknown operation IDs only
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, doctor, self-check, introspection, simulation, shutdown, and counters
- all five n8n API operations through deterministic HTTP fixtures
- invoke rejection for unknown operation and missing required inputs
- provider 401, 403, 404, 429, and 500 classes
- API-key and credential-ID auth modes, auth redaction, default/custom URL behavior, provisioning readiness, and base URL policy
- reconfigure behavior and request/error counter behavior

## Source Notes

- `connectors/n8n/src/connector.rs` defines configuration parsing, lifecycle handlers, URL readiness policy, provisioning recipe, introspection, simulation, and invoke dispatch.
- `connectors/n8n/src/client.rs` defines auth headers, endpoint paths, timeout, retry config, URL trimming, and provider error mapping.
- `connectors/n8n/src/types.rs` defines API error response shapes.
- `connectors/n8n/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/n8n/manifest.toml` defines the manifest operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit intent.
- `connectors/n8n/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/n8n/README.md
ubs connectors/n8n/README.md
LC_ALL=C rg -n '[^ -~]' connectors/n8n/README.md
rg -n '\bmaster\b' connectors/n8n/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-n8n
rch exec -- cargo check -p fcp-n8n --all-targets
rch exec -- cargo clippy -p fcp-n8n --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Configure a real n8n public API root, commonly shaped like `https://n8n.example.com/api/v1`.
- Use a host credential reference when possible; direct API-key mode keeps the key in process memory.
- Treat workflow activation as a high-review operation until approval-token verification is implemented.
- Do not rely on capability-token enforcement until runtime verification is implemented.
- Use `self_check()` to catch obvious URL policy problems, but do not treat it as a live n8n health probe.
- Expect list operations to return the provider's default page, not a complete synchronized inventory.
