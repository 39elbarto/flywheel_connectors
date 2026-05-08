# Docker Hub Connector V3 Contract

> **Status**: runtime contract documented; upstream endpoint drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://docs.docker.com/reference/api/hub/latest/
> **Repository upstream**: https://docs.docker.com/docker-hub/repos/
> **Tag upstream**: https://docs.docker.com/docker-hub/repos/manage/hub-images/tags/
> **Changelog upstream**: https://docs.docker.com/reference/api/hub/changelog/
> **Deprecated endpoint upstream**: https://docs.docker.com/reference/api/hub/deprecated/

## Purpose

This document fixes the operator-facing contract for `fcp.dockerhub`. The connector exposes a focused Docker Hub API surface for repositories, tags, organizations, and credential health.

The connector is intentionally a bounded container-registry bridge. It is not a Docker Engine client, OCI Distribution API client, Docker Desktop client, organization administration client, billing client, access-token management client, vulnerability-insight client, webhook client, or image push/pull transport.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `dockerhub.repos.list`
- `dockerhub.repos.get`
- `dockerhub.repos.create`
- `dockerhub.repos.delete`
- `dockerhub.tags.list`
- `dockerhub.tags.get`
- `dockerhub.tags.delete`
- `dockerhub.orgs.list`
- `dockerhub.health`

Important runtime truths the contract preserves:

- Configuration uses tagged auth modes:
  - `{"mode":"token","access_token":"..."}` for bearer-token auth.
  - `{"mode":"credentials","username":"...","password":"..."}` for legacy username/password login.
- Token mode sends the configured access token as a bearer token.
- Credentials mode performs best-effort `POST /v2/users/login` and then uses the returned bearer token when available.
- Empty token or empty password means credential material is missing and readiness reports `requires_credential_injection`.
- Default base URL is `https://hub.docker.com`.
- Configuration accepts optional `base_url`, `retry`, `request_timeout_ms`, and `namespace`.
- The configured `namespace` is currently diagnostic/default metadata only; invoke paths still require explicit `namespace` input for namespace-scoped operations.
- Production base URL policy requires HTTPS and exact host `hub.docker.com`.
- `localhost`, `127.0.0.1`, and `.localhost` are accepted for deterministic loopback tests.
- Path segments reject empty strings, whitespace-only strings, `/`, `\`, `..`, `%2f`, and `%5c`.
- Debug output redacts access tokens, passwords, login response tokens, and client auth material.
- Runtime request timeout default is `30 seconds`.
- HTTP 429 honors numeric or HTTP-date `Retry-After`; missing retry metadata defaults to `30 seconds`.
- Provider 401, 403, 404, 429, malformed JSON, cancellation, and retryable 5xx or transport failures are mapped into typed connector/FCP errors.
- Handshake declares no FCP streaming support.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest operation table keys use schema names such as `repos_list`, `tags_get`, and `health`; runtime operation IDs use dotted names such as `dockerhub.repos.list`.
- Manifest optional capabilities are empty even though runtime gates operations with `dockerhub.repos.read`, `dockerhub.repos.write`, and `dockerhub.orgs.read`.
- The manifest homepage points at a Docker Hub API URL shape that is no longer the clearest current docs entrypoint; the current official API reference is under `https://docs.docker.com/reference/api/hub/latest/`.
- Runtime request paths still use legacy `/v2/repositories/{namespace}/...` shapes.
- Current Docker Hub API docs and changelog identify namespace-scoped replacements under `/v2/namespaces/{namespace}/repositories/...` and list deprecations for legacy `/v2/repositories/...` routes.

A follow-up parity bead should migrate runtime paths and manifest schemas together if Docker's deprecation window requires it.

## First-Slice Scope

The current Docker Hub README slice documents the existing runtime surface:

- token and credentials auth modes
- production and loopback base URL policy
- repository listing through `GET /v2/repositories/{namespace}/`
- repository retrieval through `GET /v2/repositories/{namespace}/{name}/`
- repository creation through `POST /v2/repositories/{namespace}/`
- repository deletion through `DELETE /v2/repositories/{namespace}/{name}/`
- tag listing through `GET /v2/repositories/{namespace}/{name}/tags/`
- tag retrieval through `GET /v2/repositories/{namespace}/{name}/tags/{tag}/`
- tag deletion through `DELETE /v2/repositories/{namespace}/{name}/tags/{tag}/`
- organization listing through `GET /v2/user/orgs/`
- credential health through `GET /v2/user`
- provider error mapping, retry metadata, and redaction posture
- lifecycle, introspection, simulation, doctor, self-check, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: Docker Hub personal access token or legacy username/password.
- Home zone: `z:work`.
- Allowed source zones: `z:work` and `z:private`.
- Allowed target zone: `z:work`.
- Capability surface:
  - `dockerhub.repos.read` gates repository reads, tag reads, and credential health.
  - `dockerhub.repos.write` gates repository creation, repository deletion, and tag deletion.
  - `dockerhub.orgs.read` gates organization listing.
- Runtime invoke and simulate verify bound capability tokens when a verifier is present.
- The connector does not persist repositories, tags, organizations, access tokens, passwords, session tokens, provider payloads, or provider error bodies beyond process memory.
- Repository deletion is critical and tag deletion is high risk because both remove provider-visible registry state.

## Network And Runtime Invariants

- Default production base URL: `https://hub.docker.com`.
- Production host: `hub.docker.com`.
- Production port: `443`.
- TLS is required by the manifest for live traffic.
- Manifest network policy denies localhost and private ranges for live operations.
- Runtime loopback origins are test-only.
- Runtime request timeout default: `30 seconds`.
- Manifest network constraints set `max_redirects = 0` for all declared operations.
- The manifest denies `system.exec` and `system.privileged`.
- Runtime pagination accepts Docker Hub paginated objects with `results` and also tolerates array responses in tests.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `dockerhub.repos.read` | Read repositories, tags, and credential health. |
| `dockerhub.repos.write` | Create repositories and delete repositories or tags. |
| `dockerhub.orgs.read` | List organizations visible to the authenticated account. |

## Operation Inventory

| Operation | Manifest key | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|--------------|----------------|------------|------------|-----------|-------------|-----------|
| `dockerhub.repos.list` | `repos_list` | `GET /v2/repositories/{namespace}/` | `dockerhub.repos.read` | `Safe` | `Low` | `None` | Read-only repository inventory. |
| `dockerhub.repos.get` | `repos_get` | `GET /v2/repositories/{namespace}/{name}/` | `dockerhub.repos.read` | `Safe` | `Low` | `None` | Read-only repository detail lookup. |
| `dockerhub.repos.create` | `repos_create` | `POST /v2/repositories/{namespace}/` | `dockerhub.repos.write` | `Risky` | `Medium` | `Strict` | Creates provider-visible repository state. |
| `dockerhub.repos.delete` | `repos_delete` | `DELETE /v2/repositories/{namespace}/{name}/` | `dockerhub.repos.write` | `Dangerous` | `Critical` | `Strict` | Permanently removes a repository; requires interactive approval in runtime metadata. |
| `dockerhub.tags.list` | `tags_list` | `GET /v2/repositories/{namespace}/{name}/tags/` | `dockerhub.repos.read` | `Safe` | `Low` | `None` | Read-only tag inventory. |
| `dockerhub.tags.get` | `tags_get` | `GET /v2/repositories/{namespace}/{name}/tags/{tag}/` | `dockerhub.repos.read` | `Safe` | `Low` | `None` | Read-only tag detail lookup. |
| `dockerhub.tags.delete` | `tags_delete` | `DELETE /v2/repositories/{namespace}/{name}/tags/{tag}/` | `dockerhub.repos.write` | `Dangerous` | `High` | `Strict` | Removes a provider-visible tag; requires interactive approval in runtime metadata. |
| `dockerhub.orgs.list` | `orgs_list` | `GET /v2/user/orgs/` | `dockerhub.orgs.read` | `Safe` | `Low` | `None` | Read-only organization inventory. |
| `dockerhub.health` | `health` | `GET /v2/user` | `dockerhub.repos.read` | `Safe` | `Low` | `Strict` | Verifies credentials and returns authenticated user metadata. |

## Explicit Non-Goals

The current implementation does not include:

- Docker Engine, Docker Registry v2 blob/manifest transport, image push, image pull, image build, or image signing
- namespace-scoped replacement endpoint migration for all legacy `/v2/repositories/...` calls
- repository update, repository immutable tag settings, repository groups, webhooks, automated builds, vulnerability insights, Scout, usage, billing, teams, roles, or permissions APIs
- personal access token management, organization access token management, audit logs, SSO, SCIM, or organization member management
- namespace defaulting during invoke despite the optional config field
- credential refresh storage, long-lived local cache, or connector-managed Docker CLI login
- FCP subscription-based streaming

These are excluded on purpose:

- The first slice keeps read-only registry inventory separate from registry mutation and deletion.
- Repository and tag deletion need explicit capability and interactive approval boundaries.
- Docker's newer namespace-scoped Hub API routes should be adopted as a deliberate runtime and manifest parity change.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration and handshake state
- runtime and client readiness
- configured auth mode, credential-material status, base URL, and allowed hosts
- base URL policy failures before live requests
- degraded readiness when credentials are omitted for host-side injection
- live `GET /v2/user` provider validation during self-check when configured and credential material is present
- nine operation descriptors with capability, risk, safety tier, idempotency, approval metadata, schemas, and AI hints
- simulation denial for unsupported operation IDs or missing capability verifier state

The deterministic integration evidence is anchored on connector-local tests covering:

- success paths for repository list/get/create, tag list/get, and organization list
- destructive request shape for repository deletion and tag deletion
- typed auth, not-found, rate-limit, malformed JSON, retry, and cancellation errors
- manifest operation schemas for all nine manifest operation keys
- runtime risk and interactive-approval metadata for repository and tag deletion
- debug redaction for token, password, login response, and client auth material
- base URL policy for production, HTTP rejection, localhost loopback, and unknown-host rejection
- credential-material readiness for token and secretless modes
- path-segment rejection for traversal-like namespace, repository, and tag values

## Source Notes

- `connectors/dockerhub/src/connector.rs` defines configuration parsing, readiness, lifecycle handlers, runtime operation metadata, capability verification, simulation, and invoke dispatch.
- `connectors/dockerhub/src/client.rs` defines Docker Hub auth, login, request paths, pagination, retry handling, path-segment guards, timeout behavior, and provider error mapping.
- `connectors/dockerhub/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/dockerhub/src/types.rs` defines auth, provider payload, pagination, repository, tag, organization, and login response types.
- `connectors/dockerhub/manifest.toml` defines manifest operation schemas, network constraints, zone policy, and AI hints.
- `connectors/dockerhub/tests/integration.rs` covers deterministic HTTP behavior and manifest/runtime contract checks.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/dockerhub_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and capability metadata
- deterministic WireMock coverage for live HTTP request shapes
- auth, base URL policy, provider error, lifecycle, simulation, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a disposable Docker Hub namespace or test organization for live mutation checks.
- Prefer a Docker Hub personal access token over legacy username/password configuration.
- Use WireMock loopback fixtures for routine proof.
- Keep repository and tag names synthetic in live tests.

**Dedicated environment**:

- Do not delete production repositories or tags through this connector.
- Treat private repository names, tag digests, organization names, and user metadata as sensitive.
- Verify whether the account can access the namespace before invoking create or delete operations.
- Track Docker Hub API deprecation notes before relying on legacy runtime endpoints for long-lived automation.

**Redaction rules**:

- Redact personal access tokens, passwords, session tokens, repository names when private, namespace names when sensitive, tag names when sensitive, digests when sensitive, organization names when sensitive, provider payloads, provider error bodies, and endpoint URLs when they reveal account topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, retry decisions, and payload-shape summaries.

**Common remediation**:

- If configuration fails, use `mode = "token"` with a non-empty `access_token`, or `mode = "credentials"` with `username` and `password`.
- If readiness reports credential injection required, inject credential material at runtime or use a non-empty token/password for local proof.
- If production URL policy fails, use `https://hub.docker.com`.
- If invoke rejects an operation despite configured `namespace`, include `namespace` in the operation input.
- If path validation fails, pass plain namespace, repository, or tag segments, not URLs or `namespace/repository` strings.
- If Docker returns 404, verify namespace ownership, repository name, tag name, and endpoint deprecation status.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-dockerhub-readme cargo check -p fcp-dockerhub --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-dockerhub-readme cargo test -p fcp-dockerhub --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-dockerhub-readme cargo clippy -p fcp-dockerhub --all-targets --no-deps -- -D warnings`
