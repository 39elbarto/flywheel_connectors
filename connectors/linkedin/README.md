# LinkedIn Connector V3 Contract

> **Status**: runtime contract documented with legacy v2/ugcPosts and manifest-operation drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **LinkedIn OAuth upstream**: https://learn.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow
> **LinkedIn protocol upstream**: https://learn.microsoft.com/en-us/linkedin/shared/api-guide/concepts/protocol-version
> **LinkedIn profile upstream**: https://learn.microsoft.com/en-us/linkedin/shared/integrations/people/profile-api
> **LinkedIn posts upstream**: https://learn.microsoft.com/en-us/linkedin/marketing/community-management/shares/posts-api
> **LinkedIn legacy UGC upstream**: https://learn.microsoft.com/en-us/linkedin/compliance/integrations/shares/ugc-post-api
> **LinkedIn organization upstream**: https://learn.microsoft.com/en-us/linkedin/marketing/community-management/organizations/organization-lookup-api

## Purpose

This document fixes the operator-facing contract for `fcp.linkedin`. The connector exposes the LinkedIn surfaces implemented in this crate: profile reads, person lookup by ID, connection listing, organization lookup, organization follower statistics, UGC post create/get/delete, organization share statistics, and company search.

The connector is intentionally a bounded LinkedIn REST bridge. It is not a full LinkedIn Marketing API SDK, current `/rest/posts` client, ads client, learning client, lead-gen client, OAuth app manager, compliance archive client, webhook listener, media uploader, or durable social publishing workflow.

## Current Runtime Snapshot

The current crate exposes these operations:

- `linkedin.profile.get`
- `linkedin.profile.get_by_id`
- `linkedin.connections.list`
- `linkedin.company.get`
- `linkedin.company.followers`
- `linkedin.posts.create`
- `linkedin.posts.delete`
- `linkedin.posts.get`
- `linkedin.analytics.shares`
- `linkedin.search.companies`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-linkedin`.
- Runtime `BaseConnector` ID is `linkedin`.
- Manifest connector ID is `fcp.linkedin`.
- Runtime handshake returns connector ID `fcp.linkedin` and version `0.1.0`.
- Configuration requires exactly one auth source:
  - `access_token`
  - `credential_id`
- `credential_id` must be a valid UUID.
- `access_token` mode sends `Authorization: Bearer <token>`.
- `credential_id` mode sends `X-FCP-Credential-Id: <uuid>`.
- Default base URL is `https://api.linkedin.com/v2`.
- Runtime request helpers add `X-Restli-Protocol-Version: 2.0.0`.
- Runtime does not add a `Linkedin-Version` header.
- Runtime reqwest timeout is `30 seconds`.
- Runtime request-context timeout is configured to `30 seconds`, but normal GET/POST/DELETE helpers do not use a retry loop.
- Runtime stores `HttpRetryConfig { max_retries = 3 }`, but it is not currently applied to requests.
- Runtime `handle_response` returns `{}` for empty success bodies such as 204 deletes.
- HTTP 401 maps to unauthorized, 403 maps to forbidden, 404 maps to not-found, 429 maps to rate-limited with `Retry-After`, and other statuses map to provider API errors.
- `health` reports configured state plus `session_id.is_some()` as the handshake indicator.
- `doctor` checks local configuration, client initialization, and `session_id.is_some()`.
- `self_check` performs only local provisioning readiness; direct-token mode does not call LinkedIn.
- `handle_shutdown` shuts down the client runtime, clears client/config, and resets configured and handshaken flags.
- `invoke` expects `operation_id` and optional `input`.
- `invoke` checks `BaseConnector::check_ready()` and operation ID, but does not require or verify an FCP capability token in this checkout.
- `simulate` only checks whether an `operation_id` is known.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Runtime uses the legacy `/v2/ugcPosts` endpoint for create/get/delete, while current Microsoft docs say the Posts API replaces `ugcPosts` and uses `/rest/posts` plus both `X-Restli-Protocol-Version: 2.0.0` and `Linkedin-Version: YYYYMM` headers.
- Runtime organization calls use `/v2/organizations/{id}` and `/v2/organizationalEntityFollowerStatistics`, while current organization docs emphasize versioned `/rest/organizations`, `/rest/organization`, `/rest/networkSizes`, and `Linkedin-Version` headers for current Marketing APIs.
- Runtime profile calls use `/v2/me` and `/v2/people/(id:{person_id})`, which match the older Profile API shape and are restricted by LinkedIn approval and member privacy rules.
- Runtime search uses `/search/blended`, which is not present in the manifest operation catalog and should be treated as a legacy/restricted surface until verified.
- Manifest optional capabilities list only `linkedin.posts.write`, `linkedin.posts.read`, and `linkedin.profile.read`; runtime handshake and introspection also advertise `linkedin.connections.read`, `linkedin.company.read`, `linkedin.analytics.read`, and `linkedin.search.read`.
- Manifest defines `linkedin.posts.list`; runtime does not implement it and instead implements `linkedin.posts.get`.
- Manifest `linkedin.posts.create` input requires `commentary`; runtime requires `text`.
- Manifest `linkedin.posts.delete` input requires `post_id`; runtime requires `post_urn`.
- Runtime operation metadata sets `requires_approval = None`, while the manifest marks create as policy-gated and delete as interactive.
- Runtime `configure` accepts any `base_url` string that the client can store; endpoint policy is reported later by `self_check`.
- Runtime `doctor` does not include auth-mode, endpoint-policy, or credential-injection diagnostics.
- Runtime health treats a handshake without `session_id` as degraded even though `BaseConnector` handshaken state is set.
- Runtime direct HTTP requests do not currently use the stored retry configuration.
- Runtime does not verify bound capability tokens for reads, social writes, analytics reads, or destructive deletes.

A follow-up parity bead should migrate or explicitly freeze the LinkedIn surface: either update to current versioned `/rest` APIs with `Linkedin-Version`, or document legacy `/v2` compatibility as an intentional target. It should also reconcile manifest operation IDs and schemas, add missing capability families, enforce endpoint policy during configure, wire retry policy into HTTP helpers, make health/doctor and BaseConnector handshake semantics agree, and add bound capability-token verification.

## First-Slice Scope

The current LinkedIn README slice documents the existing runtime surface:

- access-token and credential-id configuration
- legacy Rest.li v2 profile, person, connection, organization, UGC post, analytics, and search paths
- lifecycle, local readiness, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- runtime/manifest drift around current LinkedIn API versions, operation IDs, input fields, capability families, approval metadata, endpoint policy, retry, and capability-token verification
- mock-only WireMock integration tests

## Auth And Zone Boundary

- Authentication mechanisms: LinkedIn OAuth access token or host credential reference.
- Official LinkedIn docs describe 3-legged OAuth for member authorization and authenticated API calls with bearer tokens.
- Runtime does not implement OAuth authorization redirects, code exchange, token refresh, token revocation, client-secret handling, product access requests, scope discovery, or connector-local credential vaulting.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime handshake advertises:
  - `linkedin.profile.read`
  - `linkedin.connections.read`
  - `linkedin.company.read`
  - `linkedin.posts.read`
  - `linkedin.posts.write`
  - `linkedin.analytics.read`
  - `linkedin.search.read`
- Manifest optional capabilities omit several runtime-advertised read families.
- The connector does not persist profiles, connections, organizations, follower statistics, posts, analytics, search results, access tokens, credential IDs beyond configuration metadata, provider payloads, provider error bodies, or publication logs.
- LinkedIn data can include personal profile data, connections, company administration context, social post content, and engagement analytics. Treat live reads and writes as work-zone data.

## Network And Runtime Invariants

- Default runtime host: `api.linkedin.com`.
- Default runtime base path: `/v2`.
- Runtime request construction appends operation paths to `base_url`.
- Runtime adds `X-Restli-Protocol-Version: 2.0.0` to GET, POST, and DELETE requests.
- Runtime does not add the current `Linkedin-Version` header required by many versioned `/rest` Marketing API docs.
- Runtime self-check endpoint policy accepts `https://api.linkedin.com` and local loopback test hosts.
- Runtime production policy rejects non-HTTPS and unknown hosts, but this policy is not enforced during configure.
- Manifest live-operation network policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and allows only `api.linkedin.com` on port 443.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets and does not implement webhooks.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `linkedin.profile.read` | Read the authenticated profile or a profile by person ID. |
| `linkedin.connections.read` | Runtime-only connection listing capability in this checkout. |
| `linkedin.company.read` | Runtime-only organization lookup and follower statistics capability in this checkout. |
| `linkedin.posts.read` | Read one UGC post by URN. |
| `linkedin.posts.write` | Create or delete UGC posts. |
| `linkedin.analytics.read` | Runtime-only organization share statistics capability in this checkout. |
| `linkedin.search.read` | Runtime-only company search capability in this checkout. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `linkedin.profile.get` | `GET /me` | `linkedin.profile.read` | `Safe` | `Low` | `Strict` | Reads the authenticated member profile. |
| `linkedin.profile.get_by_id` | `GET /people/(id:{person_id})` | `linkedin.profile.read` | `Safe` | `Low` | `Strict` | Reads another member profile by person ID when the token and API access permit it. |
| `linkedin.connections.list` | `GET /connections?q=viewer&start=0&count=50` | `linkedin.connections.read` | `Safe` | `Low` | `Strict` | Reads a bounded connection list through a legacy runtime path. |
| `linkedin.company.get` | `GET /organizations/{company_id}` | `linkedin.company.read` | `Safe` | `Low` | `Strict` | Reads one organization by ID through the runtime v2 path. |
| `linkedin.company.followers` | `GET /organizationalEntityFollowerStatistics?...` | `linkedin.company.read` | `Safe` | `Low` | `Strict` | Reads follower statistics for one organization URN constructed from the company ID. |
| `linkedin.posts.create` | `POST /ugcPosts` | `linkedin.posts.write` | `Risky` | `High` | `None` | Creates a UGC post using `author`, `text`, and optional visibility. |
| `linkedin.posts.delete` | `DELETE /ugcPosts/{encoded post_urn}` | `linkedin.posts.write` | `Dangerous` | `High` | `None` in runtime, `Strict` in manifest | Deletes one UGC post by URN. |
| `linkedin.posts.get` | `GET /ugcPosts/{encoded post_urn}` | `linkedin.posts.read` | `Safe` | `Low` | `Strict` | Reads one UGC post by URN. |
| `linkedin.analytics.shares` | `GET /organizationalEntityShareStatistics?...` | `linkedin.analytics.read` | `Safe` | `Low` | `Strict` | Reads share statistics for an organizational entity. |
| `linkedin.search.companies` | `GET /search/blended?...types=List(COMPANY)` | `linkedin.search.read` | `Safe` | `Low` | `Strict` | Searches companies by keyword through a legacy runtime path. |

## Explicit Non-Goals

The current implementation does not include:

- OAuth authorization code flow, token exchange, token refresh, token revocation, product-access workflows, or scope discovery
- current `/rest/posts` create/get/delete/update, `Linkedin-Version` selection, image/video/document upload, article posts, comments, reactions, social metadata, or batch post retrieval
- ads, campaign management, lead forms, learning, events, pages administration, organization access control, organization ACL discovery, or compliance archive workflows
- webhook listeners, event subscriptions, durable post scheduling, publication approval queues, or social content storage
- direct FCP capability-token verification at connector invoke time

These are excluded on purpose:

- LinkedIn APIs are heavily permissioned and product-gated.
- Social posts mutate public or semi-public identity surfaces and need mechanical approval and audit boundaries.
- Current LinkedIn Marketing APIs are versioned by header, so broad expansion needs explicit version pinning.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration and local client state
- request and error counters
- auth mode as access token or credential ID through self-check provisioning details
- endpoint policy status through self-check provisioning details
- credential-injection requirement for credential-id mode
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- provider error mapping for auth failures, forbidden access, not-found, rate-limit, server errors, invalid input, and JSON errors

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle health, configure, handshake, shutdown, doctor, self-check, introspection, and simulate
- `X-Restli-Protocol-Version` and bearer auth headers
- WireMock profile, person, connection, company, follower, post create/delete/get, analytics, and search paths
- missing required input fields
- provider 401, 403, 404, 429, and 500-class error behavior
- request/error counters
- auth redaction, credential-id handling, base URL policy, provisioning recipe shape, and operation inventory assertions

## Source Notes

- `connectors/linkedin/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, provisioning recipe, introspection, simulation, invoke dispatch, operation metadata, base URL policy, and readiness reporting.
- `connectors/linkedin/src/client.rs` defines LinkedIn HTTP request construction, auth headers, Rest.li protocol header use, response parsing, and provider error handling.
- `connectors/linkedin/src/types.rs` defines profile, organization, post, analytics, search, connection, and provider-error shapes.
- `connectors/linkedin/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/linkedin/manifest.toml` defines the partial operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit pools.
- `connectors/linkedin/tests/integration.rs` covers deterministic HTTP behavior and connector-level behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/linkedin_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for LinkedIn REST paths
- auth, provider error, lifecycle, simulation, introspection, self-check, and doctor coverage
- legacy endpoint and input-shape behavior
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use WireMock fixtures for routine verification.
- Use a disposable LinkedIn developer application and approved product scopes for live proof.
- Treat live mutation proof as a manual approval exercise until capability tokens and current `/rest/posts` parity are implemented.

**Dedicated environment**:

- Keep live posts synthetic and clearly labeled as tests.
- Use member or organization URNs deliberately.
- Use current Microsoft docs to choose the right API generation before implementing new LinkedIn behavior.
- Prefer current `/rest` APIs and `Linkedin-Version` for new work unless a bead explicitly targets legacy `/v2` parity.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, member IDs when sensitive, connection data, profile fields, organization IDs when sensitive, post text, analytics payloads, provider error bodies, and request URLs containing custom test hosts.
- Verification output should use operation IDs, endpoint shapes, HTTP status classes, retry decisions, synthetic URNs, and synthetic company IDs.

**Common remediation**:

- If configuration fails, provide exactly one of `access_token` or `credential_id`.
- If self-check reports `network_constraints_invalid`, use `https://api.linkedin.com/v2` or a loopback test host.
- If self-check reports `credential_injection_required`, use direct token mode or wire host-side injection.
- If live `/ugcPosts` calls fail, verify whether the target product still permits legacy UGC APIs or migrate the operation to `/rest/posts`.
- If current Marketing API calls fail with missing version errors, add the required `Linkedin-Version` header in the implementation rather than changing only tests.
- If post creation rejects input, remember runtime requires `text`, while the manifest currently documents `commentary`.
- If post deletion rejects input, remember runtime requires `post_urn`, while the manifest currently documents `post_id`.
- If `simulate` allows an operation but policy should deny it, remember that current simulation only checks operation ID.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-linkedin-readme cargo check -p fcp-linkedin --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-linkedin-readme cargo test -p fcp-linkedin --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-linkedin-readme cargo clippy -p fcp-linkedin --all-targets --no-deps -- -D warnings`
- `ubs connectors/linkedin/README.md`
