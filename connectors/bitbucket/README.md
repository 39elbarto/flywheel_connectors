# Bitbucket Connector V3 Contract

> **Status**: manifest/runtime contract documented with known drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://developer.atlassian.com/cloud/bitbucket/rest/intro/

## Purpose

This document fixes the operator-facing contract for `fcp.bitbucket`. The connector exposes Bitbucket Cloud workspace, repository, pull request, branch, commit, issue, and pipeline metadata surfaces, plus pull request creation.

The connector is intentionally a Bitbucket Cloud REST v2 bridge. It is not a git transport, clone/fetch/push implementation, Bitbucket Server/Data Center client, webhook receiver, package registry client, or full repository administration surface.

## Current Runtime Snapshot

The current runtime introspection exposes these operations:

- `bitbucket.user.get`
- `bitbucket.workspaces.list`
- `bitbucket.repositories.list`
- `bitbucket.repositories.get`
- `bitbucket.pull_requests.list`
- `bitbucket.pull_requests.get`
- `bitbucket.pull_requests.create`
- `bitbucket.branches.list`
- `bitbucket.commits.list`
- `bitbucket.pipelines.list`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of:
  - `access_token`
  - `username` plus `app_password`
  - `credential_id`
- `credential_id` must be a valid UUID and is treated as secretless egress-proxy metadata.
- Default base URL is `https://api.bitbucket.org/2.0`.
- Runtime base URL hygiene rejects userinfo, query strings, fragments, and unparseable URLs.
- Runtime endpoint policy accepts HTTPS `api.bitbucket.org` or `bitbucket.org`; localhost, `127.0.0.1`, and `::1` are accepted for deterministic tests.
- Access-token mode sends `Authorization: Bearer ...`.
- App-password mode sends HTTP Basic auth with `username:app_password`.
- Credential-id mode sends `X-FCP-Credential-Id: ...` and self-check reports `credential_injection_required`.
- HTTP client timeout is `30 seconds`.
- The connector retries through the shared connector runtime with a maximum of two retries.
- Path segments for workspace, repo slug, pull request ID, and related identifiers are percent-encoded before URL construction.
- `bitbucket.pull_requests.create` defaults `destination_branch` to `main` when omitted.
- Invocation and simulation require a bound capability token after handshake.
- Upstream 401, 403, 404, 429, and other provider failures are mapped into FCP auth, permission, not-found, rate-limit, or external errors.

## Known Contract Gap

The current manifest does not fully match the runtime introspection surface.

- `manifest.toml` declares `bitbucket.repos.list`, while runtime exposes `bitbucket.repositories.list` and `bitbucket.repositories.get`.
- Runtime exposes `bitbucket.user.get`, `bitbucket.workspaces.list`, `bitbucket.pull_requests.get`, `bitbucket.branches.list`, and `bitbucket.commits.list`, but those operations are not declared in the manifest.
- Runtime uses capabilities such as `bitbucket.repositories.read`, `bitbucket.user.read`, `bitbucket.workspaces.read`, `bitbucket.branches.read`, and `bitbucket.commits.read`; the manifest currently declares only `bitbucket.repos.read`, `bitbucket.pull_requests.*`, `bitbucket.issues.read`, and `bitbucket.pipelines.read`.
- The manifest declares `bitbucket.issues.list`, but the current runtime invoke dispatch does not include an issues operation.

Operators should treat this README as a truthfulness snapshot, not as proof that the Bitbucket manifest is already complete. A follow-up should align manifest operations, capability IDs, and runtime introspection before this connector is considered manifest-complete.

## First-Slice Scope

The current Bitbucket README slice documents the existing runtime surface:

- access token, app password, and credential-id configuration
- Bitbucket Cloud REST v2 base URL policy
- bound capability-token enforcement
- user and workspace metadata
- repository list and get
- pull request list, get, and create
- branch, commit, and pipeline list
- provider error mapping, retry behavior, and redaction posture
- lifecycle, introspection, simulation, doctor, self-check, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: OAuth2 access token, app password, or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Runtime capability surface:
  - `bitbucket.user.read` gates authenticated-user lookup.
  - `bitbucket.workspaces.read` gates workspace listing.
  - `bitbucket.repositories.read` gates repository listing and lookup.
  - `bitbucket.pull_requests.read` gates pull request listing and lookup.
  - `bitbucket.pull_requests.write` gates pull request creation.
  - `bitbucket.branches.read` gates branch listing.
  - `bitbucket.commits.read` gates commit listing.
  - `bitbucket.pipelines.read` gates pipeline listing.
- The connector does not persist repository payloads, branch names, commit messages, pull request bodies, access tokens, app passwords, credential IDs beyond configuration metadata, provider payloads, or provider error bodies.

## Network And Runtime Invariants

- Production host: `api.bitbucket.org`.
- Production API prefix: `/2.0`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback overrides are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints set total timeout `30_000 ms`.
- Maximum response bytes are `10_485_760` for list/read operations and `1_048_576` for pull request creation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `bitbucket.user.get` | `GET /user` | `bitbucket.user.read` | `Safe` | `Low` | `Strict` | Read-only identity check for the authenticated principal. |
| `bitbucket.workspaces.list` | `GET /workspaces` | `bitbucket.workspaces.read` | `Safe` | `Low` | `Strict` | Read-only workspace discovery for follow-on repository calls. |
| `bitbucket.repositories.list` | `GET /repositories/{workspace}` | `bitbucket.repositories.read` | `Safe` | `Low` | `Strict` | Read-only repository inventory for a workspace. |
| `bitbucket.repositories.get` | `GET /repositories/{workspace}/{repo_slug}` | `bitbucket.repositories.read` | `Safe` | `Low` | `Strict` | Read-only repository metadata lookup. |
| `bitbucket.pull_requests.list` | `GET /repositories/{workspace}/{repo_slug}/pullrequests` | `bitbucket.pull_requests.read` | `Safe` | `Low` | `Strict` | Read-only pull request inventory. |
| `bitbucket.pull_requests.get` | `GET /repositories/{workspace}/{repo_slug}/pullrequests/{pr_id}` | `bitbucket.pull_requests.read` | `Safe` | `Low` | `Strict` | Read-only pull request detail lookup. |
| `bitbucket.pull_requests.create` | `POST /repositories/{workspace}/{repo_slug}/pullrequests` | `bitbucket.pull_requests.write` | `Risky` | `Medium` | `None` | Creates provider-visible review state and should be policy-gated. |
| `bitbucket.branches.list` | `GET /repositories/{workspace}/{repo_slug}/refs/branches` | `bitbucket.branches.read` | `Safe` | `Low` | `Strict` | Read-only branch inventory. |
| `bitbucket.commits.list` | `GET /repositories/{workspace}/{repo_slug}/commits` | `bitbucket.commits.read` | `Safe` | `Low` | `Strict` | Read-only commit history inventory. |
| `bitbucket.pipelines.list` | `GET /repositories/{workspace}/{repo_slug}/pipelines` | `bitbucket.pipelines.read` | `Safe` | `Low` | `Strict` | Read-only CI/CD pipeline history. |

## Explicit Non-Goals

The current implementation does not include:

- git clone, fetch, push, merge, rebase, or repository checkout behavior
- branch creation, branch deletion, commit creation, file content editing, or source browsing
- pull request merge, decline, approve, comment, reviewer, task, or build-status operations
- issue list at runtime despite the manifest entry
- Bitbucket Server or Data Center APIs
- webhooks, pipeline triggering, artifact/log download, deployment management, or repository administration
- connector-local OAuth token refresh or provider key management
- FCP subscription-based streaming
- connector-local credential vaulting

These are excluded on purpose:

- Runtime invocation is capability-token bound and should expose only narrow provider actions.
- Pull request creation is the only write operation in this slice.
- Runtime/manifest drift should be corrected directly before adding broader operations.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration and handshake state
- auth mode, base URL, credential-injection state, request counters, and error counters
- configured capability verifier state
- self-check degradation for unconfigured and credential-id configurations
- simulation denial for missing operation IDs, unknown operation IDs, invalid input, missing tokens, and capability-token denial
- runtime introspection metadata for the 10 operations listed above

The deterministic integration evidence is anchored on connector-local tests covering:

- access-token configuration, auth header propagation, and lifecycle behavior
- handshake key/zone setup for bound capability verification
- capability-token success and denial paths
- user, workspace, repository, pull request, branch, commit, and pipeline loopback requests
- pull request create request body construction and `main` destination default
- path segment percent-encoding
- provider 401, 403, 404, 429, malformed JSON, and retryability behavior
- simulation, health, doctor, self-check, introspection, counters, and shutdown behavior

## Source Notes

- `connectors/bitbucket/src/connector.rs` defines configuration parsing, base URL policy, capability-token verification, lifecycle handlers, diagnostics, simulation, introspection, and invoke dispatch.
- `connectors/bitbucket/src/client.rs` defines REST v2 request paths, auth headers, path-segment encoding, timeout, retry config, and provider error mapping.
- `connectors/bitbucket/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/bitbucket/manifest.toml` defines the current partial operation catalog, network constraints, sandbox boundary, zone policy, rate limits, and AI hints.
- `connectors/bitbucket/tests/integration.rs` covers deterministic HTTP behavior and runtime capability enforcement.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/bitbucket_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime introspection operation checks
- deterministic WireMock coverage for runtime operations
- auth, base URL, input validation, capability-token, provider error, lifecycle, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a test Bitbucket Cloud workspace and repository for live provider verification.
- Prefer app-password or access-token credentials scoped only to the operations under test.
- Use WireMock loopback fixtures for routine proof.

**Dedicated environment**:

- Keep live pull request creation confined to disposable branches in disposable repositories.
- Do not expect runtime issue listing until the manifest/runtime gap is fixed.
- Do not expect Bitbucket Server/Data Center behavior from this connector.

**Redaction rules**:

- Redact access tokens, app passwords, credential IDs where needed, workspace and repository names when sensitive, branch names when sensitive, commit messages, pull request titles/bodies, provider payloads, provider error bodies, and local paths.
- Verification output should use operation IDs, endpoint shapes, host classes, status/error classes, retry decisions, resource URI shapes, and hashed or synthetic repository identifiers.

**Common remediation**:

- If configuration fails, provide exactly one supported auth mode.
- If app-password configuration fails, provide both `username` and `app_password`.
- If credential-id mode self-check reports `credential_injection_required`, use direct credentials or wire the egress proxy injection path.
- If base URL validation fails, use `https://api.bitbucket.org/2.0` or a loopback test origin.
- If invocation fails with capability denial, check that the capability token was issued for the exact operation and resource URI shape.
- If pull request creation targets the wrong branch, pass `destination_branch` explicitly instead of relying on the `main` default.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-bitbucket-readme cargo check -p fcp-bitbucket --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-bitbucket-readme cargo test -p fcp-bitbucket --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-bitbucket-readme cargo clippy -p fcp-bitbucket --all-targets --no-deps -- -D warnings`
