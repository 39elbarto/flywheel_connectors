# n8n Connector Security Contract

> **Status**: packet 1 security gates implemented; production provider egress and workflow lifecycle remain fail-closed
> **Bead**: `flywheel_connectors-nqm81.2`
> **Verification script**: none tracked; use the commands below
> **n8n public REST API**: https://docs.n8n.io/api/
> **n8n API reference**: https://docs.n8n.io/api/api-reference/

## Purpose

This document fixes the operator-facing contract for `fcp.n8n`. The connector exposes workflow and execution reads, plus a capability- and approval-gated workflow lifecycle operation that is intentionally unavailable until a mediated write path is delivered.

The connector is intentionally a bounded self-hosted n8n administration bridge. It is not a workflow authoring client, credential manager, project manager, variable manager, audit client, webhook trigger runtime, event subscription client, n8n CLI replacement, or general HTTP proxy.

## Current Runtime Snapshot

The current crate exposes these operations:

- `n8n.workflows.list`
- `n8n.workflows.get`
- `n8n.workflows.activate`
- `n8n.executions.list`
- `n8n.executions.get`

Important runtime truths:

- Package and binary name are `fcp-n8n`.
- Runtime `BaseConnector` ID is `n8n`.
- Manifest and reported connector ID are `fcp.n8n`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000`.
- Configuration requires exactly one auth source: direct `api_key` or `credential_id`.
- Direct API-key mode is usable only against loopback test fixtures. Production provider egress fails before DNS or HTTP until host-mediated enforcement is available.
- `credential_id` is only a host-managed reference. The direct client neither injects the secret nor sends the reference as a provider header; every provider call fails closed until host mediation is available.
- `credential_id` must be a valid UUID.
- `base_url` is required and canonicalized to the `/api/v1` root.
- Runtime endpoint shape is `{base_url}/workflows`, `{base_url}/workflows/{id}`, `{base_url}/executions`, and `{base_url}/executions/{id}`.
- Runtime request timeout is 30 seconds; each direct client provider call is single-attempt and has no automatic retry.
- Runtime `invoke` requires the canonical `operation` field.
- A host-key-backed `CapabilityVerifier` validates the bound capability token before provider dispatch.
- Activation additionally requires exactly one semantically matching execution approval; malformed entries fail closed. The host remains authoritative for approval signature verification.
- Reconfigure and shutdown clear client, verifier, zone, session, configured, and handshaken state.
- `self_check()` performs its read-only probe only on the loopback test path; production direct egress fails before provider traffic.

## Declarative Versus Mechanical Enforcement

The manifest declares DNS, TLS SNI, host/port, private-range, redirect, timeout,
and response-size policy for the host egress layer. The direct `reqwest` path does
not mechanically enforce DNS resolution, private-range checks, or response-size
limits. It is therefore unavailable for non-loopback provider traffic. No local
proxy or substitute network policy is installed in this packet.

The connector does mechanically enforce configuration shape, canonical API-root
validation, capability-token binding, approval semantic matching, safe path
segments, and lifecycle/session reset. These checks do not replace host egress
mediation.

## Scope

This packet documents and verifies:

- direct n8n API key and host credential-reference configuration
- required self-hosted API base URL behavior
- local URL readiness, timeout, single-attempt provider calls, and error mapping
- workflow reads and the activation approval boundary
- execution read operations
- handshake, self-check, introspection, simulation, and reset behavior
- deterministic WireMock tests and direct proof commands

## Auth, Capabilities, And Approvals

- Authentication configuration accepts exactly one of an API key or a host credential reference.
- Provisioning asks for the instance URL and credential reference only. It does not prompt for, store, or serialize a raw API key.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `n8n.workflows.read` gates workflow list/get provider calls.
  - `n8n.workflows.write` gates the activation approval boundary; a valid request is then denied before provider traffic in this packet.
  - `n8n.executions.read` gates execution list/get provider calls.
- Capability tokens must bind to the current connector instance and exact resource URI. The host verifier checks the token signature; the connector performs the bound semantic check.
- Activation approval must be an exact single execution approval for connector, canonical `operation`, zone, resource, workflow state, and normalized constraints. A host-bound `input_hash` is compatible; a `request_object_id` is not. Malformed approval entries fail closed.
- The connector does not persist API keys, credential secret material, workflow definitions, execution payloads, provider error bodies, or API responses outside process memory.
- Workflow and execution data can contain secrets, credentials metadata, prompts, private business data, or tool output. Treat live output as work-zone data unless a stricter zone policy is implemented.

## Network And Runtime Invariants

- Runtime endpoint shape:
  - `GET {base_url}/workflows`
  - `GET {base_url}/workflows/{id}`
  - `GET {base_url}/executions`
  - `GET {base_url}/executions/{id}`
- `n8n.workflows.activate` emits no provider request in this packet. Its capability and approval checks run first, then the operation fails closed with a deferred-lifecycle error. The mediated write path is owned by the lifecycle/egress follow-up beads.
- Runtime sends `Accept: application/json`.
- Loopback test requests with API-key mode send `X-N8N-API-KEY`.
- Credential-reference mode sends no credential header from this client.
- Runtime user agent is `fcp-n8n/0.1.0 (FCP connector)`.
- Direct provider I/O is allowed only for loopback test hosts (`localhost`, `127.0.0.1`, or IPv6 loopback) with API-key mode. Production HTTPS configurations fail before DNS or HTTP and require host-mediated egress enforcement.
- Credential references fail before any provider traffic until a host-mediated secret-injection contract is present.
- Runtime request timeout: `30 seconds`.
- Direct client calls are single-attempt; no automatic retry loop is installed.
- Provider HTTP 401, 403, 404, 429, and other API errors map to typed connector/FCP errors.
- `Retry-After` on 429 is surfaced as a delay hint in the typed error; it does not trigger an automatic retry.
- Manifest connect timeout, total timeout, DNS, private-range, redirect, SNI, and response-size entries are host-policy declarations, not claims about the direct client path.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, no exec, and no inbound listener capability.
- The connector does not open inbound sockets, receive n8n webhooks, run workflows locally, or connect to n8n's internal database.

## Operation Inventory

| Operation | HTTP request | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|--------------|------------|------------|-----------|-------------|----------------|
| `n8n.workflows.list` | `GET /workflows` | `n8n.workflows.read` | `Safe` | `Low` | `Strict` | none |
| `n8n.workflows.get` | `GET /workflows/{id}` | `n8n.workflows.read` | `Safe` | `Low` | `Strict` | `id` string |
| `n8n.workflows.activate` | no provider request; lifecycle deferred | `n8n.workflows.write` | `Risky` | `Medium` | `None` | `id` string and `active` bool plus one matching approval |
| `n8n.executions.list` | `GET /executions` | `n8n.executions.read` | `Safe` | `Low` | `Strict` | none |
| `n8n.executions.get` | `GET /executions/{id}` | `n8n.executions.read` | `Safe` | `Low` | `Strict` | `workflow_id` and `id` strings |

## Explicit Non-Goals

The current implementation does not include:

- workflow create, update, delete, import, export, clone, test-run, tag, project, variable, credential, user, audit, or source-control operations
- pagination, filtering, sorting, or query parameter support for workflow or execution list calls
- activation provider lifecycle; capability and approval gates are present, but the provider write path is deferred
- execution retry, stop, delete, log streaming, custom-data filtering, or execution-data redaction management
- API-key provisioning, secret injection, or host egress enforcement
- OAuth installation, API-key rotation, credential validation beyond local configuration shape, or live self-check probe
- n8n CLI behavior, server CLI behavior, embedded n8n runtime, webhook receiver, scheduler, or trigger execution

These are excluded on purpose:

- Activating a workflow can start cron, webhook, polling, or other production triggers. This packet therefore denies the operation even after its capability and approval checks pass.
- Workflow and execution payloads may contain sensitive data and need a clearer read policy before adding broad export or debugging surfaces.
- n8n has a large public API; this connector should grow only through manifest-aligned, capability-gated slices.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, session ID, request, and error counter state
- local URL readiness and host-mediation warning state
- failed self-check for production direct egress and credential-reference modes, without provider traffic
- operation metadata with capability, risk, safety tier, idempotency, schemas, and hints
- simulation allow/deny for known versus unknown `operation` values
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, doctor, self-check, introspection, simulation, shutdown, and counters
- all read operations through deterministic HTTP fixtures, plus activation zero-traffic denial
- invoke rejection for unknown operation and missing required inputs
- provider 401, 403, 404, 429, and 500 classes
- API-key and credential-reference modes, auth redaction, zero-traffic egress denial, provisioning readiness, and base URL policy
- reconfigure behavior and request/error counter behavior

## Source Notes

- `connectors/n8n/src/connector.rs` defines configuration parsing, lifecycle handlers, URL readiness policy, provisioning recipe, introspection, simulation, and invoke dispatch.
- `connectors/n8n/src/client.rs` defines auth headers, endpoint paths, timeout, URL trimming, and provider error mapping.
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

For source or behavior changes, run the connector proof lane:

```bash
cargo test -p fcp-n8n --all-targets
cargo check -p fcp-n8n --all-targets
cargo clippy -p fcp-n8n --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Operator Guidance

- Configure an n8n public API root, commonly shaped like `https://n8n.example.com/api/v1`.
- Use a host credential reference for the eventual mediated path; this connector cannot inject it and fails closed until that path exists.
- Direct API-key mode is for loopback fixtures only in this packet; production egress requires host mediation.
- Treat workflow activation as deferred: capability and approval checks are enforced, but no provider lifecycle request is emitted.
- Use `self_check()` as a safe readiness/probe report. Production and credential-reference modes report failure before provider traffic.
- Expect list operations to return the provider's default page, not a complete synchronized inventory.
