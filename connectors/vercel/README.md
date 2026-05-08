# Vercel Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Vercel REST API upstream**: https://vercel.com/docs/rest-api/reference
> **Deployments upstream**: https://vercel.com/docs/rest-api/reference/endpoints/deployments
> **Projects upstream**: https://vercel.com/docs/rest-api/reference/endpoints/projects
> **Environment Variables upstream**: https://vercel.com/docs/rest-api/reference/endpoints/environment-variables

## Purpose

This document fixes the operator-facing contract for `fcp.vercel`. The connector exposes the Vercel REST API surface implemented in this crate: deployments, projects, project domains, environment variables, and local connector health.

The connector is intentionally a bounded Vercel project operations bridge. It is not a Vercel CLI replacement, git provider integration, build log streamer, webhook receiver, billing client, team administration client, analytics client, or general hosting control plane.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `vercel.health`
- `vercel.deployments.list`
- `vercel.deployments.get`
- `vercel.deployments.create`
- `vercel.deployments.delete`
- `vercel.projects.list`
- `vercel.projects.get`
- `vercel.projects.create`
- `vercel.projects.delete`
- `vercel.domains.list`
- `vercel.domains.add`
- `vercel.domains.remove`
- `vercel.env.list`
- `vercel.env.create`
- `vercel.env.delete`

Important runtime truths the contract preserves:

- Runtime connector ID is `fcp.vercel`.
- `base_url` defaults to `https://api.vercel.com`.
- Authentication accepts either direct access-token mode or secretless credential-reference mode.
- Direct access-token mode sends `Authorization: Bearer <token>`.
- Credential-reference mode sends `X-FCP-Credential-ID` and reports a degraded self-check status until a host-side credential injector proves live provider access.
- Scope accepts at most one of `team_id` or `team_slug`; runtime requests add either `teamId` or `slug` query parameters.
- `request_timeout_ms` must be greater than zero.
- `base_url` must be an absolute `http` or `https` URL, but runtime validation does not require the production Vercel host.
- Path segments for deployment IDs, project IDs, project names, domains, and env var IDs reject blank values, path separators, `..`, and encoded slash or backslash forms.
- `vercel.health` performs a lightweight client health probe by listing one project.
- Handshake installs a `CapabilityVerifier`.
- `invoke` requires configured and handshaken state, maps each operation to a required Vercel capability, verifies a bound capability token, and then calls the client.
- `simulate` currently returns allowed for any request and does not validate configuration, input shape, capability tokens, provider reachability, or operation-specific policy.
- `subscribe` and `unsubscribe` return `StreamingNotSupported`.
- `shutdown` clears the client, configuration, verifier, and configured/handshaken base state.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest operation keys are unprefixed names such as `deployments_list`, while runtime introspection exposes dotted operation IDs such as `vercel.deployments.list`.
- Manifest network constraints are intended for Vercel's production API, but runtime `base_url` accepts any `http` or `https` host for tests and local fixtures.
- `doctor()` warns when the base URL does not start with `https://`, but configuration accepts remote plaintext HTTP URLs.
- Handshake grants every requested capability rather than filtering to the manifest capability set.
- `simulate` is permissive and not policy-aware.
- Credential-reference mode is transport-level only in this crate; it depends on the host or egress layer to inject the real Vercel token.
- The runtime does not implement webhook ingestion, deployment event streaming, build-log streaming, domain verification flows, or pagination persistence.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should align manifest operation IDs with runtime introspection, enforce production host and HTTPS policy outside deterministic tests, filter handshake grants, make simulation capability-aware, and decide how credential-reference injection should be proven in `self_check`.

## First-Slice Scope

The current Vercel README slice documents the implemented runtime surface:

- access-token and credential-reference authentication modes
- optional team scoping through `team_id` or `team_slug`
- deployments list, get, create, and delete operations
- projects list, get, create, and delete operations
- project domain list, add, and remove operations
- project environment variable list, create, and delete operations
- local lifecycle, health, doctor, self-check, introspection, simulation, invoke, subscribe, unsubscribe, and shutdown behavior
- bound capability-token verification during invoke
- provider error mapping for auth, not found, validation, rate limit, retryable server errors, timeout, JSON, and configuration failures
- deterministic WireMock integration evidence

## Auth And Scope Boundary

- Authentication mechanism: Vercel access token or host-resolved credential reference.
- Direct token header: `Authorization: Bearer <token>`.
- Credential-reference header: `X-FCP-Credential-ID: <credential_id>`.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zones: `z:work` and `z:project:*`.
- Runtime capability surface:
  - `vercel.projects.read` gates project reads.
  - `vercel.projects.write` gates project creates and deletes.
  - `vercel.deployments.read` gates deployment reads.
  - `vercel.deployments.write` gates deployment creates and deletes.
  - `vercel.domains.read` gates project-domain reads.
  - `vercel.domains.write` gates project-domain mutations.
  - `vercel.env.read` gates environment-variable reads.
  - `vercel.env.write` gates environment-variable mutations.
- The connector does not persist Vercel tokens, credential IDs, project metadata, deployment payloads, domains, environment-variable values, provider responses, or provider error bodies beyond process memory.
- Environment variable names and values, deployment aliases, git metadata, framework settings, domain names, project IDs, and team identifiers can expose private work infrastructure. Treat live request and response data as work-zone sensitive.

## Network And Runtime Invariants

- Production host: `api.vercel.com`.
- Default production base URL: `https://api.vercel.com`.
- Runtime path families:
  - `GET /v6/deployments`
  - `GET /v13/deployments/{deployment_id}`
  - `POST /v13/deployments`
  - `DELETE /v13/deployments/{deployment_id}`
  - `GET /v9/projects`
  - `GET /v9/projects/{project_id_or_name}`
  - `POST /v10/projects`
  - `DELETE /v9/projects/{project_id_or_name}`
  - `GET /v9/projects/{project_id_or_name}/domains`
  - `POST /v10/projects/{project_id_or_name}/domains`
  - `DELETE /v10/projects/{project_id_or_name}/domains/{domain}`
  - `GET /v9/projects/{project_id_or_name}/env`
  - `POST /v10/projects/{project_id_or_name}/env`
  - `DELETE /v9/projects/{project_id_or_name}/env/{env_id}`
- Team scoping is added as `teamId=<team_id>` or `slug=<team_slug>` when configured.
- Project, deployment, domain, and env-var path segments are sanitized before request construction.
- The connector does not open inbound sockets and does not implement replay or streaming.
- Sandbox profile is strict, with no exec and no privileged system access.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `vercel.projects.read` | List and inspect Vercel projects. |
| `vercel.projects.write` | Create and delete Vercel projects. |
| `vercel.deployments.read` | List and inspect deployments. |
| `vercel.deployments.write` | Create and delete deployments. |
| `vercel.domains.read` | List project domain bindings. |
| `vercel.domains.write` | Add and remove project domain bindings. |
| `vercel.env.read` | List project environment variables. |
| `vercel.env.write` | Create and delete project environment variables. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `vercel.health` | project probe | `vercel.projects.read` | `Safe` | `Low` | `Strict` | Verifies client/provider reachability with a minimal project list. |
| `vercel.deployments.list` | `GET /v6/deployments` | `vercel.deployments.read` | `Safe` | `Low` | `Strict` | Reads deployment summaries. |
| `vercel.deployments.get` | `GET /v13/deployments/{id}` | `vercel.deployments.read` | `Safe` | `Low` | `Strict` | Reads one deployment record. |
| `vercel.deployments.create` | `POST /v13/deployments` | `vercel.deployments.write` | `Risky` | `Medium` | `None` | Creates a new deployment and can trigger user-visible hosting changes. |
| `vercel.deployments.delete` | `DELETE /v13/deployments/{id}` | `vercel.deployments.write` | `Dangerous` | `High` | `BestEffort` | Removes deployment state from Vercel. |
| `vercel.projects.list` | `GET /v9/projects` | `vercel.projects.read` | `Safe` | `Low` | `Strict` | Reads project summaries. |
| `vercel.projects.get` | `GET /v9/projects/{id_or_name}` | `vercel.projects.read` | `Safe` | `Low` | `Strict` | Reads one project record. |
| `vercel.projects.create` | `POST /v10/projects` | `vercel.projects.write` | `Risky` | `Medium` | `None` | Creates provider project state. |
| `vercel.projects.delete` | `DELETE /v9/projects/{id_or_name}` | `vercel.projects.write` | `Dangerous` | `High` | `BestEffort` | Deletes provider project state. |
| `vercel.domains.list` | `GET /v9/projects/{project}/domains` | `vercel.domains.read` | `Safe` | `Low` | `Strict` | Reads project domain bindings. |
| `vercel.domains.add` | `POST /v10/projects/{project}/domains` | `vercel.domains.write` | `Risky` | `Medium` | `BestEffort` | Adds a domain binding that can affect public routing. |
| `vercel.domains.remove` | `DELETE /v10/projects/{project}/domains/{domain}` | `vercel.domains.write` | `Dangerous` | `High` | `BestEffort` | Removes a domain binding. |
| `vercel.env.list` | `GET /v9/projects/{project}/env` | `vercel.env.read` | `Safe` | `Medium` | `Strict` | Reads environment-variable metadata and may expose sensitive names. |
| `vercel.env.create` | `POST /v10/projects/{project}/env` | `vercel.env.write` | `Dangerous` | `High` | `None` | Writes configuration that can affect future builds and runtime behavior. |
| `vercel.env.delete` | `DELETE /v9/projects/{project}/env/{env_id}` | `vercel.env.write` | `Dangerous` | `High` | `BestEffort` | Deletes provider environment-variable state. |

## Explicit Non-Goals

The current implementation does not include:

- Vercel login flows, browser OAuth, token creation, or credential vaulting
- GitHub, GitLab, Bitbucket, or Git provider installation flows
- Vercel CLI parity, local development servers, build-log tailing, deployment event streaming, webhook receipt, or serverless function log streaming
- analytics, billing, usage, team membership, access groups, project transfer, firewall, edge config, integrations, marketplace, or account administration APIs
- persistent pagination cursors, local project caches, environment snapshots, rollback orchestration, or deployment promotion workflows
- automatic DNS verification, nameserver changes, or certificate troubleshooting

These are excluded on purpose:

- Project and environment-variable operations can affect production deployments.
- Environment-variable values and deployment metadata are sensitive work data.
- Git-provider and team administration flows need separate consent and credential boundaries.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, `introspect()`, `invoke()`, `subscribe()`, `unsubscribe()`, and `shutdown()` are part of the public closeout contract. They surface:

- configured state, auth mode, team scope, base URL, request timeout, and manifest hash
- operation metadata with capability, risk, safety tier, idempotency, schemas, and AI hints
- bound capability-token verification during `invoke`
- current permissive simulation behavior
- current credential-reference degraded self-check behavior
- non-streaming posture through `StreamingNotSupported`

The deterministic integration evidence is anchored on connector-local tests covering:

- manifest/runtime schema parity for all runtime operations
- access-token and credential-reference request headers
- team scoping query parameters
- deployment, project, domain, and environment-variable request paths
- provider error mapping for unauthorized, not found, validation, rate limit, retryable server error, timeout, and malformed JSON cases
- path-segment sanitization for project, deployment, domain, and environment-variable IDs
- lifecycle behavior for configure, handshake, health, doctor, self-check, introspect, invoke, simulate, and shutdown

## Source Notes

- `connectors/vercel/src/connector.rs` defines lifecycle handlers, operation metadata, capability-token verification, simulation, health, self-check, and invoke dispatch.
- `connectors/vercel/src/client.rs` defines Vercel client construction, auth headers, team scoping, health probe, and provider error conversion.
- `connectors/vercel/src/client/deployments.rs` defines deployment list, get, create, and delete paths.
- `connectors/vercel/src/client/projects.rs` defines project list, get, create, and delete paths.
- `connectors/vercel/src/client/domains.rs` defines project-domain list, add, and remove paths.
- `connectors/vercel/src/client/env_vars.rs` defines project environment-variable list, create, and delete paths.
- `connectors/vercel/src/types.rs` defines configuration, auth mode, team scope, request and response types, and validation.
- `connectors/vercel/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/vercel/manifest.toml` defines the manifest operation catalog, capability catalog, network constraints, sandbox boundary, and zone policy.
- `connectors/vercel/tests/integration.rs` covers deterministic HTTP behavior and runtime lifecycle coverage.

## Verification

README-only changes do not require Cargo or `rch` verification. Before committing this file, run:

```bash
git diff --check -- connectors/vercel/README.md
LC_ALL=C grep -n '[^[:print:][:space:]]' connectors/vercel/README.md
rg -n "$(printf '\\x6d\\x61\\x73\\x74\\x65\\x72')" connectors/vercel/README.md
ubs connectors/vercel/README.md
```

For code changes in this connector, use the workspace-required proof lane from the root `AGENTS.md`:

```bash
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
rch exec -- cargo fmt --check
```
