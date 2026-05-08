# GitLab Connector V3 Contract

> **Status**: runtime contract documented; base-url policy drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://docs.gitlab.com/api/rest/
> **Auth upstream**: https://docs.gitlab.com/api/rest/authentication/
> **Resources upstream**: https://docs.gitlab.com/api/api_resources/
> **Issues upstream**: https://docs.gitlab.com/api/issues/
> **Merge requests upstream**: https://docs.gitlab.com/api/merge_requests/
> **Pipelines upstream**: https://docs.gitlab.com/api/pipelines/

## Purpose

This document fixes the operator-facing contract for `fcp.gitlab`. The connector exposes a focused GitLab REST API surface for project discovery, issue reads and creation, merge request reads, and pipeline reads.

The connector is intentionally a bounded GitLab work-zone bridge. It is not a full GitLab administration client, repository file client, commit client, branch client, group client, package client, registry client, CI trigger client, merge client, or runner manager.

## Current Runtime Snapshot

The current crate exposes these operations:

- `gitlab.projects.list`
- `gitlab.issues.list`
- `gitlab.issues.create`
- `gitlab.merge_requests.list`
- `gitlab.pipelines.list`

Important runtime truths the contract preserves:

- Configuration requires exactly one auth mode: `private_token` or `credential_id`.
- `private_token` mode sends the `PRIVATE-TOKEN` header.
- `credential_id` mode sends `X-FCP-Credential-Id`.
- `credential_id` must be a valid UUID.
- Empty or whitespace private tokens fail configuration.
- Supplying both auth modes or no auth mode fails configuration.
- Default base URL is `https://gitlab.com/api/v4`.
- Base URLs are parsed and canonicalized by trimming trailing slashes.
- Project IDs can be numeric IDs or namespace paths; runtime percent-encodes the project ID as one URL path segment.
- Runtime validates `per_page` as an unsigned integer between 1 and 100.
- Runtime validates required `project_id` for project-scoped reads and required `title` for issue creation.
- Runtime validates `description` as a string when present.
- Private tokens are redacted in debug output and log labels.
- HTTP client timeout is `30 seconds`.
- A retry config with two maximum retries is constructed, but current request helpers call reqwest directly rather than using the shared retry loop.
- Provider 401, 403, 404, 429 with `Retry-After`, malformed JSON, and generic API failures are mapped into typed connector/FCP errors.
- Handshake creates a capability verifier from `host_public_key`, optional `zone`, and this connector instance ID.
- `invoke` and `simulate` verify bound capability tokens against operation, capability, and resource URI constraints.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- The manifest host allowlist is only `gitlab.com`; runtime private-token policy accepts `gitlab.com`, `*.gitlab.com`, and loopback test hosts.
- Credential-id configuration accepts any HTTPS host or loopback host, but readiness still reports network policy using the stricter GitLab.com allowlist.
- Runtime supports namespace-path project IDs by percent-encoding `/`, while the manifest text still nudges operators toward numeric project IDs.
- Runtime `OperationInfo` sets `requires_approval = None` for `gitlab.issues.create`, while the manifest marks issue creation as `requires_approval = "policy"`.
- The client has a retry config field but currently does not route requests through `RetryLoop`.

A follow-up parity bead should reconcile self-managed GitLab policy, manifest host constraints, approval metadata, and retry-loop use.

## First-Slice Scope

The current GitLab README slice documents the existing runtime surface:

- personal access token and host credential-reference configuration
- production and loopback base URL policy
- project listing through `GET /projects`
- issue listing through `GET /projects/{project_id}/issues`
- issue creation through `POST /projects/{project_id}/issues`
- merge request listing through `GET /projects/{project_id}/merge_requests`
- pipeline listing through `GET /projects/{project_id}/pipelines`
- provider error mapping, redaction posture, capability-token enforcement, and current retry gap
- lifecycle, introspection, simulation, doctor, self-check, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: GitLab personal access token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Capability surface:
  - `gitlab.projects.read` gates project listing.
  - `gitlab.issues.read` gates issue listing.
  - `gitlab.issues.write` gates issue creation.
  - `gitlab.merge_requests.read` gates merge request listing.
  - `gitlab.pipelines.read` gates pipeline listing.
- Runtime invoke and simulate require a bound capability token after handshake.
- Resource URIs are operation-specific, such as `gitlab:projects`, `gitlab:project:{project_id}:issues`, `gitlab:project:{project_id}:merge_requests`, and `gitlab:project:{project_id}:pipelines`.
- The connector does not persist projects, issues, merge requests, pipelines, private tokens, credential IDs, provider payloads, or provider error bodies beyond process memory.
- Issue creation is provider-visible collaboration state and should be policy gated by the host.

## Network And Runtime Invariants

- Default production base URL: `https://gitlab.com/api/v4`.
- GitLab REST API paths start under `/api/v4`.
- Production port: `443`.
- Manifest host allowlist is `gitlab.com`.
- Runtime private-token policy additionally accepts `*.gitlab.com`.
- Runtime credential-id policy permits any HTTPS host, which can represent a host-approved self-managed GitLab route.
- Runtime loopback origins are test-only.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints set total timeout `30_000 ms`.
- Maximum response bytes are `1_048_576` for issue creation and `10_485_760` for read/list operations.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `gitlab.projects.read` | List projects visible to the authenticated principal. |
| `gitlab.issues.read` | List issues in one project. |
| `gitlab.issues.write` | Create issues in one project. |
| `gitlab.merge_requests.read` | List merge requests in one project. |
| `gitlab.pipelines.read` | List CI/CD pipelines in one project. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `gitlab.projects.list` | `GET /projects` | `gitlab.projects.read` | `Safe` | `Low` | `Strict` | Read-only inventory of projects visible to the token. |
| `gitlab.issues.list` | `GET /projects/{project_id}/issues` | `gitlab.issues.read` | `Safe` | `Low` | `Strict` | Read-only issue list for one project. |
| `gitlab.issues.create` | `POST /projects/{project_id}/issues` | `gitlab.issues.write` | `Risky` | `Medium` | `None` | Creates provider-visible collaboration state. |
| `gitlab.merge_requests.list` | `GET /projects/{project_id}/merge_requests` | `gitlab.merge_requests.read` | `Safe` | `Low` | `Strict` | Read-only merge request list for one project. |
| `gitlab.pipelines.list` | `GET /projects/{project_id}/pipelines` | `gitlab.pipelines.read` | `Safe` | `Low` | `Strict` | Read-only CI/CD pipeline list for one project. |

## Explicit Non-Goals

The current implementation does not include:

- groups, users, memberships, repositories, files, commits, branches, tags, releases, packages, container registry, environments, deployments, runners, jobs, variables, snippets, milestones, labels, discussions, notes, todos, epics, wikis, or audit events
- issue updates, closes, comments, assignees, labels, due dates, weights, confidential issues, or attachments
- merge request creation, update, approval, merge, rebase, close, notes, diffs, or review discussions
- pipeline creation, retry, cancel, bridge/job details, variables, schedules, or trigger tokens
- GitLab OAuth flow, token rotation, token introspection, or token provisioning beyond the recipe metadata
- durable project membership cache despite manifest state wording
- connector-local credential vaulting or FCP subscription-based streaming

These are excluded on purpose:

- The first slice keeps read-only project/workflow visibility separate from issue mutation.
- Bound capability verification is present and should remain the enforcement surface for future operations.
- Self-managed GitLab support needs an explicit host-policy decision before broadening live network claims.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration and handshake state
- request and error counters
- auth mode, token/credential-reference status, base URL, and network policy status
- host public key and zone handling during handshake
- degraded self-check for unconfigured state or credential-injection mode
- failure for invalid base URL policy or missing client state
- five operation descriptors with capability, risk, safety tier, idempotency, schemas, and AI hints
- simulation denial for unsupported operation IDs, missing configuration, missing handshake, missing/invalid capability token, wrong capability, and input validation failures
- shutdown state reset

The deterministic integration evidence is anchored on connector-local tests covering:

- private-token and credential-id configuration
- missing auth, duplicate auth, empty token, whitespace token, invalid credential ID, and custom base URL handling
- handshake public-key parsing, health, doctor, self-check, introspection, simulation, counters, reconfigure, and shutdown
- bound capability-token success and denial cases
- project list, issue list/create, merge request list, and pipeline list loopback requests
- namespace-path project ID encoding
- validation for `per_page`, `project_id`, `title`, and `description`
- provider 401, 403, 404, 429 with `Retry-After`, 500, empty arrays, and malformed JSON behavior
- base URL policy for GitLab.com, subdomains, loopback, unknown hosts, and HTTP rejection

## Source Notes

- `connectors/gitlab/src/connector.rs` defines configuration parsing, lifecycle handlers, provisioning readiness, capability verifier setup, input validation, resource URI derivation, operation metadata, simulation, and invoke dispatch.
- `connectors/gitlab/src/client.rs` defines GitLab auth headers, default base URL, path-segment percent encoding, timeout, endpoint paths, error mapping, and redacted debug behavior.
- `connectors/gitlab/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/gitlab/src/types.rs` defines provider error response parsing.
- `connectors/gitlab/manifest.toml` defines operation schemas, network constraints, sandbox boundary, zone policy, rate limits, and AI hints.
- `connectors/gitlab/tests/integration.rs` covers deterministic HTTP behavior and manifest/runtime contract checks.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/gitlab_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and capability metadata
- deterministic WireMock coverage for all five operations
- auth, base URL policy, provider error, lifecycle, capability verification, simulation, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a disposable GitLab project for live issue-creation checks.
- Prefer a personal access token scoped to the smallest useful API permissions.
- Use `credential_id` only when the host-side egress layer owns credential injection and self-managed host approval.
- Use WireMock loopback fixtures for routine proof.

**Dedicated environment**:

- Keep live issue titles/descriptions synthetic.
- Do not create issues in production projects without explicit approval.
- Use numeric project IDs or correctly URL-encoded namespace paths.
- Keep `per_page` bounded at 100 or below.

**Redaction rules**:

- Redact private tokens, credential IDs where needed, project paths when private, issue titles/descriptions when sensitive, merge request titles, pipeline refs, provider payloads, provider error bodies, and endpoint URLs when they reveal organization topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, capability-denial summaries, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide exactly one of `private_token` or `credential_id`.
- If private-token base URL validation fails, use `https://gitlab.com/api/v4`, an HTTPS `*.gitlab.com` endpoint, or loopback for tests.
- If self-managed GitLab is needed, route it through credential-id mode and reconcile readiness/manifest policy before live use.
- If invoke fails with missing capability token, complete handshake with `host_public_key` and supply a bound token for the requested operation.
- If `per_page` validation fails, pass an integer from 1 through 100.
- If project-scoped operations fail with 404, verify project ID/path encoding and token visibility.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-gitlab-readme cargo check -p fcp-gitlab --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-gitlab-readme cargo test -p fcp-gitlab --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-gitlab-readme cargo clippy -p fcp-gitlab --all-targets --no-deps -- -D warnings`
