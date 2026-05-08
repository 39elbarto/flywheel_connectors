# Pulumi Connector V3 Contract

> **Status**: runtime contract documented; Pulumi Cloud REST drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Pulumi Cloud REST API upstream**: https://www.pulumi.com/docs/reference/cloud-rest-api/
> **Pulumi API basics upstream**: https://www.pulumi.com/docs/reference/cloud-rest-api/api-basics/
> **Pulumi stacks upstream**: https://www.pulumi.com/docs/reference/cloud-rest-api/stacks/
> **Pulumi stack updates upstream**: https://www.pulumi.com/docs/reference/cloud-rest-api/stack-updates/

## Purpose

This document fixes the operator-facing contract for `fcp.pulumi`. The connector exposes the Pulumi Cloud stack and update surface implemented in this crate: stack listing, stack lookup, stack creation, stack deletion, stack export, and update/deployment listing through a small REST client.

The connector is intentionally a bounded Pulumi Cloud bridge. It is not a Pulumi program runner, preview executor, update/deploy trigger, organization administration client, policy-pack manager, ESC environment client, Pulumi Deployments orchestrator, webhook listener, durable state backend, or Pulumi SDK wrapper.

## Current Runtime Snapshot

The current crate exposes these operations:

- `pulumi.stacks.list`
- `pulumi.stacks.get`
- `pulumi.stacks.create`
- `pulumi.stacks.delete`
- `pulumi.stacks.export`
- `pulumi.deployments.list`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-pulumi`.
- Manifest ID is `fcp.pulumi`.
- `BaseConnector` runtime ID is `pulumi`.
- Manifest version is `0.1.0`.
- Manifest format is `wasi`.
- Configuration requires exactly one auth source:
  - `access_token`
  - `credential_id`
- Direct token mode trims whitespace and sends `Authorization: Bearer <token>`.
- `credential_id` mode sends `X-FCP-Credential-Id` and expects host egress policy to inject real secret material.
- `credential_id` must be a valid UUID.
- Default runtime API URL is `https://api.pulumi.com/api`.
- Custom `base_url` is accepted at configure time without URL policy enforcement.
- `self_check()` applies the URL policy after configure.
- Runtime request timeout is 30 seconds.
- Runtime request-context timeout is 30 seconds.
- The client uses the shared retry loop config with `max_retries = 2`, although the low-level request helpers send one request each in the current implementation.
- `health()` reports configured and session-ID state. It does not call Pulumi.
- `doctor()` checks local configuration, client initialization, and whether a session ID was provided. It does not call Pulumi.
- `self_check()` checks local readiness only. Direct-token mode does not perform a live Pulumi probe.
- `credential_id` self-check reports degraded `credential_injection_required` and skips any live probe.
- Runtime `invoke` uses the JSON field `operation_id`, not `operation`.
- Runtime `invoke` does not require or verify a capability token.
- Runtime `simulate` only checks whether the `operation_id` is known.
- Runtime `simulate` does not check configuration, handshake, input shape, approval policy, or capability tokens.
- Runtime `shutdown()` calls client shutdown, clears config and client state, and clears the base configured/handshaken flags.
- Runtime `shutdown()` does not clear the stored `session_id`.

## Runtime API Adapter

The runtime uses these request shapes:

| Operation | Runtime request | Required input | Output handling |
|-----------|-----------------|----------------|-----------------|
| `pulumi.stacks.list` | `GET /stacks` with optional `organization` and `project` query parameters | none | Returns the provider JSON body unchanged. |
| `pulumi.stacks.get` | `GET /stacks/{organization}/{project}/{stack}` | `organization`, `project`, `stack` | Returns the provider JSON body unchanged. |
| `pulumi.stacks.create` | `POST /stacks/{organization}/{project}` with `{ "stackName": stack }` | `organization`, `project`, `stack` | Returns the provider JSON body unchanged. |
| `pulumi.stacks.delete` | `DELETE /stacks/{organization}/{project}/{stack}` | `organization`, `project`, `stack` | Empty success bodies become `{}`. Other success bodies are returned unchanged. |
| `pulumi.stacks.export` | `GET /stacks/{organization}/{project}/{stack}/export` | `organization`, `project`, `stack` | Returns the provider JSON body unchanged. |
| `pulumi.deployments.list` | `GET /stacks/{organization}/{project}/{stack}/updates` | `organization`, `project`, `stack` | Returns the provider JSON body unchanged. |

Identifier handling is deliberately restrictive for path segments:

- `organization`, `project`, and `stack` are trimmed before path use.
- Empty path segments are rejected.
- Slashes, backslashes, `..`, `%2f`, and `%5c` are rejected.
- The sanitized value is inserted into the path without percent encoding.
- Optional `organization` and `project` query values for `pulumi.stacks.list` are forwarded as query parameters and are not path-sanitized.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Current Pulumi REST API documentation describes API-key requests with `Authorization: token <api-token>`. Runtime sends `Authorization: Bearer <token>`.
- Current Pulumi REST API documentation scopes stack list to the user stacks endpoint. Runtime calls `/api/stacks` through the default base URL, not `/api/user/stacks`.
- Manifest network constraints allow only `api.pulumi.com` on port `443`, deny localhost, deny private ranges, require TLS/SNI, and cap redirects at three. Runtime configure accepts any string as `base_url` that `reqwest` can build against; URL policy is only surfaced later through self-check.
- Runtime URL self-check accepts `api.pulumi.com`, `pulumi.com`, any `*.pulumi.com`, and loopback test hosts. The manifest allows only `api.pulumi.com`.
- Manifest declares `storage.state` and says state stores the access token and org/project context. Runtime keeps config in memory and does not persist token, credential ID, organization, project, stack, counters, or provider payloads.
- Manifest operation approval modes mark stack create as policy and stack delete as interactive. Runtime does not enforce approval tokens.
- Runtime introspection reports no `requires_approval` metadata for any operation.
- Manifest rate-limit pools exist for read, write, and deployment-read operations. Runtime introspection reports no rate-limit metadata and the client does not enforce those manifest pools.
- Manifest network response caps vary by operation. Runtime does not enforce those response byte caps before parsing JSON.
- Handshake returns all three Pulumi capabilities unconditionally after configure. It does not filter requested capabilities.
- Handshake does not parse a full `HandshakeRequest`, does not install a `CapabilityVerifier`, and does not return a manifest hash.
- Health treats a configured connector without a `session_id` as degraded even though the base handshaken flag is set.
- Direct-token `self_check()` reports local readiness without a live Pulumi API probe.
- `credential_id` mode creates a client that forwards `X-FCP-Credential-Id`; there is no local materialization or live connectivity test in this connector.
- Provider 401, 403, 404, and 429 are mapped as `FcpError::External` with status codes, not specialized unauthorized/resource/rate-limit FCP variants.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should align the Pulumi auth header with the provider contract, confirm the intended stack-list endpoint, enforce production URL policy at configure or before invoke, add capability-token verification, expose approval and rate-limit metadata, decide whether `self_check()` should perform a live read-only probe, and reconcile the manifest state model with in-memory runtime behavior.

## First-Slice Scope

The current Pulumi README slice documents the existing runtime surface:

- access-token and credential-id configuration
- base URL handling and self-check policy
- stack read/write/export/delete operations
- deployment/update listing
- lifecycle, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- provider error mapping, retry classification, timeout behavior, and path-segment validation
- runtime/manifest/provider-doc drift around authentication, endpoint paths, approvals, rate limits, network policy, state persistence, and capability-token verification
- deterministic WireMock integration tests

## Auth And Zone Boundary

- Authentication mechanisms: direct Pulumi access token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability families:
  - `pulumi.stacks.read`
  - `pulumi.stacks.write`
  - `pulumi.deployments.read`
- Manifest required capabilities are `network.dns`, `network.egress`, `network.tls.sni`, and `storage.state`.
- Manifest forbids `system.exec`, `network.listen`, `media.upload`, and `media.download`.
- The connector does not intentionally persist access tokens, credential IDs, Pulumi stack bodies, state exports, update records, request counters, or error counters outside process memory.
- Pulumi stack export payloads can contain deployment checkpoints, stack outputs, configuration, and provider metadata. Treat live output as work-zone sensitive data unless the host supplies a stricter zone policy.

## Network And Runtime Invariants

- Default runtime API URL: `https://api.pulumi.com/api`.
- Direct runtime request headers include `Accept: application/json`.
- Direct token requests use `Authorization: Bearer <token>`.
- `credential_id` requests use `X-FCP-Credential-Id: <uuid>`.
- Runtime client timeout is 30 seconds.
- Runtime request-context timeout is 30 seconds.
- Runtime self-check production host policy accepts `https://api.pulumi.com`, `https://pulumi.com`, and `https://*.pulumi.com`.
- Loopback URLs are accepted by self-check policy for deterministic tests.
- Manifest operation network policy allows `api.pulumi.com` on port `443`, requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, caps redirects at three, and caps response sizes by operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets.
- Provider 401 and 403 are terminal authentication or authorization failures.
- Provider 404 is a terminal not-found failure.
- Provider 429 is retryable and honors `Retry-After` seconds, defaulting to 60 seconds when absent.
- Provider 5xx responses are classified as retryable API errors.
- JSON parse errors are internal failures.

## Capability Families

| Capability | Purpose |
|------------|---------|
| `pulumi.stacks.read` | List, inspect, and export Pulumi stack metadata or state. |
| `pulumi.stacks.write` | Create or delete Pulumi stacks. |
| `pulumi.deployments.read` | List recent Pulumi updates/deployments for a stack. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `pulumi.stacks.list` | `GET /stacks` | `pulumi.stacks.read` | `Safe` | `Low` | `Strict` | Reads stack inventory with optional org/project filters. |
| `pulumi.stacks.get` | `GET /stacks/{organization}/{project}/{stack}` | `pulumi.stacks.read` | `Safe` | `Low` | `Strict` | Reads one stack and its provider-returned metadata. |
| `pulumi.stacks.create` | `POST /stacks/{organization}/{project}` | `pulumi.stacks.write` | `Risky` | `Medium` | `Strict` | Creates a new Pulumi stack record. |
| `pulumi.stacks.delete` | `DELETE /stacks/{organization}/{project}/{stack}` | `pulumi.stacks.write` | `Dangerous` | `High` | `Strict` | Removes a stack and can destroy historical state. |
| `pulumi.stacks.export` | `GET /stacks/{organization}/{project}/{stack}/export` | `pulumi.stacks.read` | `Safe` | `Low` | `Strict` | Reads a deployment checkpoint/state export. |
| `pulumi.deployments.list` | `GET /stacks/{organization}/{project}/{stack}/updates` | `pulumi.deployments.read` | `Safe` | `Low` | `Strict` | Reads recent updates/deployment history for a stack. |

## Resource URIs

Runtime invoke currently does not verify capability tokens, so no resource binding is enforced locally. The effective authorization boundary is host-side admission plus operation dispatch.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| Stack metadata | `pulumi://stack/{organization}/{project}/{stack}` |
| Stack export | `pulumi://stack/{organization}/{project}/{stack}/export` |
| Stack collection | `pulumi://organization/{organization}/project/{project}/stacks` |
| Deployment history | `pulumi://stack/{organization}/{project}/{stack}/updates` |

## Explicit Non-Goals

The current implementation does not include:

- Running `pulumi up`, `pulumi preview`, `pulumi destroy`, or any local CLI command
- Pulumi program packaging or code execution
- Pulumi Deployments job creation, cancellation, or log streaming
- Organization, team, role, or policy-pack administration
- ESC environment management
- Webhook subscriptions or inbound event delivery
- Durable sync, replay, or checkpoint storage
- Stack config secret editing
- Provider-specific resource graph normalization
- Cross-account or cross-zone stack aggregation
- Real Pulumi Cloud integration tests

## Test And Verification Contract

The tracked tests use deterministic WireMock servers. They cover:

- configure, handshake, health, doctor, self-check, introspect, simulate, and shutdown paths
- access-token configuration
- credential-ID configuration validation
- stack list/get/create/delete/export operations
- deployment/update listing
- missing required input fields
- unknown operation handling
- path-segment rejection for traversal-like values
- Authorization header behavior for direct-token requests
- provider 401, 403, 404, 429, and 500 responses
- request and error counter updates

Before committing README-only changes for this connector, run:

```bash
git diff --check -- connectors/pulumi/README.md
LC_ALL=C rg -n '[^ -~]' connectors/pulumi/README.md
rg -n '\bmaster\b' connectors/pulumi/README.md
ubs connectors/pulumi/README.md
```

No Cargo/rch lane is required for README-only edits. Any runtime or test change must use the workspace verification lanes described in the root `AGENTS.md`.
