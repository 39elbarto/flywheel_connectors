# Mixpanel Connector V3 Contract

> **Status**: runtime contract documented; provider endpoint drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Mixpanel Query API upstream**: https://developer.mixpanel.com/reference/query-api-overview
> **Mixpanel Insights upstream**: https://developer.mixpanel.com/reference/insights-query
> **Mixpanel funnels list upstream**: https://developer.mixpanel.com/reference/funnels-list-saved
> **Mixpanel service accounts upstream**: https://developer.mixpanel.com/reference/service-accounts-api

## Purpose

This document fixes the operator-facing contract for `fcp.mixpanel`. The connector exposes the Mixpanel analytics surface implemented in this crate: event-like query dispatch, saved funnel listing, and saved Insights report query dispatch.

The connector is intentionally a bounded analytics-read bridge. It is not a full Mixpanel ingestion client, export client, cohort manager, user-profile manager, report authoring tool, service-account administration client, webhook listener, or dashboard synchronizer.

## Current Runtime Snapshot

The current crate exposes these operations:

- `mixpanel.events.query`
- `mixpanel.funnels.list`
- `mixpanel.insights.query`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-mixpanel`.
- Runtime `BaseConnector` ID is `mixpanel`.
- Manifest and reported connector ID are `fcp.mixpanel`.
- Manifest version is `0.1.0`.
- Manifest format is `wasi`.
- Configuration requires `project_id` plus exactly one auth source:
  - `username` and `secret`
  - `credential_id`
- `project_id` may be a string or unsigned integer during configure.
- Direct service-account mode sends HTTP Basic auth as `base64(username:secret)`.
- `credential_id` mode sends `X-FCP-Credential-Id` and expects host egress policy to inject real secret material.
- `credential_id` must be a valid UUID.
- Default runtime base URL is `https://mixpanel.com/api/2.0`.
- The client trims trailing slashes from `base_url`.
- Configure accepts custom `base_url` values without applying the runtime host policy.
- Runtime host policy is evaluated by `self_check`, not by configure.
- Runtime host policy accepts `mixpanel.com`, `data.mixpanel.com`, `eu.mixpanel.com`, any `*.mixpanel.com`, and loopback hosts for tests.
- Runtime host policy rejects non-loopback HTTP, missing hosts, invalid URLs, and unknown hosts.
- Runtime request timeout is 60 seconds.
- Runtime request-context timeout is 60 seconds.
- The client uses the shared retry loop with `max_retries = 2`.
- `Retry-After` on 429 is converted from seconds to milliseconds; missing values default to 60000 ms.
- `health()` and `doctor()` consider a handshake complete only when a `session_id` was provided.
- A handshake without `session_id` marks the base connector handshaken but still reports degraded health and a failed non-critical doctor handshake check.
- `self_check()` performs local provisioning readiness only. It does not call Mixpanel.
- Direct service-account mode reports `ok` if local configuration and URL policy pass.
- `credential_id` mode reports degraded `credential_injection_required` and skips a live probe.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime `invoke` checks `BaseConnector::check_ready()` and operation ID, but does not require or verify an FCP capability token.
- Runtime `simulate` only checks whether the operation ID is known.
- `handle_shutdown()` shuts down the client runtime, clears client/config/base flags, and returns an empty object.
- `handle_shutdown()` does not clear the stored `session_id`.

## Runtime API Adapter

The runtime uses these request shapes:

| Operation | Runtime request | Required input | Output handling |
|-----------|-----------------|----------------|-----------------|
| `mixpanel.events.query` | `POST {base_url}/insights` with JSON body containing numeric `project_id`, `from_date`, `to_date`, and optional `event` | `from_date`, `to_date` | Returns `{ "data": response.data }`, or `null` if `data` is absent. |
| `mixpanel.funnels.list` | `GET {base_url}/funnels/list?project_id={project_id}` | none | Wraps an array response as `{ "funnels": [...] }`, or uses `response.funnels`, or returns an empty array. |
| `mixpanel.insights.query` | `POST {base_url}/insights` with JSON body containing numeric `project_id` and `bookmark_id` | `bookmark_id` | Returns `{ "data": response.data }`, or `null` if `data` is absent. |

Input validation is intentionally narrow:

- `from_date`, `to_date`, and `bookmark_id` must be JSON strings.
- `event` is optional and must be a JSON string when present.
- The runtime does not validate date format beyond requiring strings.
- `project_id` is parsed as `u64` for POST request bodies; non-numeric configured strings become `0`.
- `project_id` is sanitized for the funnels query string path segment and rejects empty values, slashes, backslashes, `..`, `%2f`, and `%5c`.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Current Mixpanel docs describe saved Insights query as `GET /api/query/insights` with query parameters including integer `project_id` and `bookmark_id`; the runtime sends `POST {base_url}/insights` with a JSON body.
- Current Mixpanel docs describe saved funnels listing as `GET /api/query/funnels/list`; the runtime sends `GET {base_url}/funnels/list?project_id=...` using the default base URL `https://mixpanel.com/api/2.0`.
- The manifest description for `mixpanel.events.query` says "JQL or Insights API"; runtime sends the same `/insights` POST shape used by `mixpanel.insights.query`, not JQL or Mixpanel segmentation query.
- Current Mixpanel segmentation docs describe event queries under `/api/query/segmentation`; runtime does not call that endpoint.
- Manifest network constraints deny localhost and IP literals, while runtime self-check accepts loopback hosts for deterministic tests.
- Configure accepts arbitrary custom `base_url` strings that parse into the client. Unknown hosts are surfaced by `self_check`, not rejected by configure.
- Runtime direct service-account self-check does not verify that credentials are accepted by Mixpanel.
- Runtime operation metadata sets `requires_approval = None` for all operations.
- Runtime does not verify capability tokens or bind operations to resource URIs.
- Runtime `simulate` does not check configured state, handshake state, input shape, URL policy, auth mode, approval policy, or capability tokens.
- Runtime `health` and `doctor` treat missing `session_id` as not handshaken even though `handle_handshake()` sets the base connector handshaken flag.
- Runtime shutdown clears base lifecycle flags but leaves `session_id` populated.
- The provisioning recipe captures service-account username/secret material but does not capture `project_id`; the host must still supply `project_id` during configure.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should reconcile the runtime endpoint shapes with the current Mixpanel Query API, decide whether event query should use segmentation/JQL or stay saved-report based, enforce provider URL policy during configure, validate numeric `project_id` consistently, clear `session_id` during shutdown, align simulation with invoke policy, and add capability-token verification if this connector is promoted beyond local deterministic proof.

## First-Slice Scope

The current Mixpanel README slice documents the existing runtime surface:

- service-account and credential-id configuration
- project ID handling
- endpoint policy, timeout, retry, and provider error mapping
- event, funnel, and Insights operations
- lifecycle, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- runtime/manifest/provider-doc drift around endpoint paths, URL policy, lifecycle state, simulation, and capability-token verification
- deterministic WireMock integration tests

## Auth And Zone Boundary

- Authentication mechanisms: Mixpanel service account or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime handshake advertises:
  - `mixpanel.events.read`
  - `mixpanel.funnels.read`
  - `mixpanel.insights.read`
- Manifest required capabilities are `network.dns`, `network.egress`, `network.tls.sni`, and `storage.state`.
- The connector does not persist service-account secrets, credential IDs beyond configuration metadata, project data, report data, provider payloads, provider error bodies, request counters, or error counters outside process memory.
- Mixpanel payloads can include user behavior analytics, funnel names, report data, event names, segmentation results, and product telemetry. Treat live output as work-zone operational data unless a stricter zone is configured by the host.

## Network And Runtime Invariants

- Default runtime base URL: `https://mixpanel.com/api/2.0`.
- Runtime direct requests append fixed paths to `base_url`.
- Runtime request timeout: `60 seconds`.
- Runtime retry policy: two retries using the shared retry loop.
- Runtime readiness policy accepts only HTTPS Mixpanel hosts unless the host is loopback.
- Runtime readiness policy accepts loopback hosts for tests with either HTTP or HTTPS.
- Runtime readiness policy accepts wildcard Mixpanel subdomains.
- Manifest operation network policy requires TLS/SNI, allows Mixpanel hosts on port `443`, denies localhost, private ranges, tailnet ranges, and IP literals, and caps response sizes at `10485760` or `52428800` bytes by operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `mixpanel.events.read` | Query the runtime's event-like Insights request for a date range. |
| `mixpanel.funnels.read` | List saved funnel definitions. |
| `mixpanel.insights.read` | Query a saved Insights report by bookmark ID. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `mixpanel.events.query` | `POST /insights` | `mixpanel.events.read` | `Safe` | `Low` | `Strict` | Performs the runtime's event-style saved-report request and returns the `data` member. |
| `mixpanel.funnels.list` | `GET /funnels/list?project_id=...` | `mixpanel.funnels.read` | `Safe` | `Low` | `Strict` | Lists saved funnels and normalizes array or wrapped responses to `funnels`. |
| `mixpanel.insights.query` | `POST /insights` | `mixpanel.insights.read` | `Safe` | `Low` | `Strict` | Performs the runtime's saved Insights request and returns the `data` member. |

## Resource URIs

Runtime capability-token verification is absent for Mixpanel in this checkout, so there are no effective resource URI bindings. The practical authorization binding is configuration plus base readiness plus operation name.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| Project reports | `mixpanel://project/{project_id}/reports/{bookmark_id}` |
| Funnels | `mixpanel://project/{project_id}/funnels` |
| Events | `mixpanel://project/{project_id}/events/{event_name}` |

## Explicit Non-Goals

The current implementation does not include:

- event ingestion, event export, JQL execution, cohort reads/writes, profile reads/writes, group analytics, annotations, dashboards, report creation, or funnel conversion querying
- service-account creation, rotation, project assignment, or organization administration
- OAuth setup, project secret legacy auth, SCIM provisioning, webhook ingestion, or durable event replay
- pagination helpers, workspace selection, region selection beyond custom `base_url`, or API-version negotiation
- durable storage of analytics data, credentials, query results, or provider responses

These are excluded on purpose:

- Product analytics can expose customer behavior and sensitive product usage. Reads need narrow zone and resource policy before broadening.
- Mixpanel has multiple API families with different base URLs and auth expectations. Endpoint parity should be explicit before live production use.
- Provider report APIs can have rate and concurrency limits; deterministic tests should stay on WireMock fixtures.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, handshake, request, and error counter state
- auth mode and project ID readiness through self-check provisioning details
- provider URL readiness through self-check provisioning details
- credential-injection requirement for credential-id mode
- direct service-account self-check based on local readiness only, not a live Mixpanel API probe
- operation metadata with capability, risk, safety tier, idempotency, schemas, and hints
- simulation allow/deny for known versus unknown operation IDs
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, configured-but-not-handshaken health, introspection, simulation, doctor, self-check, shutdown, and counters
- service-account and credential-id configuration
- WireMock fixtures for event query, funnel listing, and Insights query
- missing required input fields and unknown operation rejection
- provider 401, 403, 404, 429, 500, and empty-response classes
- auth redaction, custom URL handling, provisioning readiness, base URL policy, project ID sanitization, retry behavior, and operation inventory

## Source Notes

- `connectors/mixpanel/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, provisioning recipe, introspection, simulation, invoke dispatch, operation metadata, base URL policy, and readiness reporting.
- `connectors/mixpanel/src/client.rs` defines Mixpanel HTTP request construction, auth headers, retry dispatch, timeout settings, endpoint paths, project ID handling, response parsing, and provider error handling.
- `connectors/mixpanel/src/types.rs` defines provider API response shapes.
- `connectors/mixpanel/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/mixpanel/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit pools.
- `connectors/mixpanel/tests/integration.rs` contains deterministic HTTP behavior and connector-level behavior.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/mixpanel/README.md
ubs connectors/mixpanel/README.md
LC_ALL=C rg -n '[^ -~]' connectors/mixpanel/README.md
rg -n '\bmaster\b' connectors/mixpanel/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-mixpanel
rch exec -- cargo check -p fcp-mixpanel --all-targets
rch exec -- cargo clippy -p fcp-mixpanel --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Prefer `credential_id` for production so host policy owns secret injection.
- Use direct service-account credentials only in local deterministic tests or explicitly scoped environments.
- Always provide a numeric `project_id` until runtime validation is tightened; non-numeric strings become `0` in POST bodies.
- Do not treat `mixpanel.events.query` as a complete Mixpanel segmentation or JQL client.
- Verify the live endpoint shape against Mixpanel before using this connector outside WireMock fixtures.
- Do not rely on capability-token or approval-token enforcement until runtime verification is implemented.
- If self-check reports `credential_injection_required`, use direct service-account mode or wire host-side injection.
- If self-check reports `network_constraints_invalid`, use an HTTPS Mixpanel host or a loopback test server.
