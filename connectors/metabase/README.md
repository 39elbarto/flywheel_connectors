# Metabase Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Metabase API upstream**: https://www.metabase.com/docs/latest/api

## Purpose

This document fixes the operator-facing contract for `fcp.metabase`. The connector exposes the Metabase API surface implemented in this crate: dashboards, saved questions, and saved-question execution.

The connector is intentionally a bounded business-intelligence bridge. It is not a full Metabase administration client, dashboard renderer, SQL editor, database manager, collection manager, permissions manager, alerting client, embedding client, OAuth installer, or event subscription surface.

## Current Runtime Snapshot

The current crate exposes these operations:

- `metabase.dashboards.list`
- `metabase.questions.list`
- `metabase.questions.run`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-metabase`.
- Runtime `BaseConnector` ID is `metabase`.
- Manifest and reported connector ID are `fcp.metabase`.
- Manifest interface hash is currently all zeroes: `blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000`.
- Configuration requires `base_url` because Metabase is self-hosted.
- Configuration requires exactly one auth source: direct `session_token` or `credential_id`.
- Direct session-token mode sends `X-Metabase-Session: {session_token}`.
- `credential_id` mode is parsed and retained as a host-side reference, but live invoke/simulate reject it because this connector slice does not implement host credential injection.
- The client deliberately sends no upstream auth header in `credential_id` mode.
- `base_url` is trimmed only by removing trailing slashes in the client.
- `base_url` is not validated by `configure`; readiness policy is surfaced through `self_check`.
- `self_check` accepts HTTPS for non-local hosts and HTTP for `localhost`, `127.0.0.1`, and `::1`.
- Runtime request timeout is 30 seconds.
- The client is configured with shared retry settings using `max_retries = 2`.
- Runtime `invoke` accepts either `operation_id` or `operation`.
- Runtime does not install a `CapabilityVerifier` and does not verify `capability_token`.
- Runtime has no approval-token checks because all implemented operations are read-scoped metadata/query operations.
- `simulate` checks known operation, configured state, handshake state, and direct session-token support.
- `handle_configure()` clears the prior session ID and resets the base handshaken flag.
- `handle_shutdown()` shuts down the client runtime, clears config/client/session/base flags, and returns an empty object.
- `self_check()` is a local readiness check only; it does not issue a live Metabase probe.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest interface hash is a placeholder all-zero hash.
- Manifest state hint says the session token and instance URL are stored. Runtime keeps configuration in memory and does not persist connector state.
- Manifest network constraints list `*.metabase.com` and `localhost.localdomain`; runtime readiness accepts any HTTPS host and loopback HTTP.
- Runtime `credential_id` mode is configured and visible in doctor/self-check, but live invoke and simulate reject it until host-side credential injection exists.
- Runtime does not verify capability tokens or bind operations to resource URIs.
- Runtime `base_url` policy does not reject URL userinfo, query strings, or fragments.
- Runtime operation `metabase.questions.run` sends an empty POST body to `/card/{card_id}/query`; it does not accept Metabase parameter values in this slice.
- Runtime introspection has no event catalog, resource types, auth capabilities, or event capabilities.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should replace the placeholder interface hash, implement capability-token verification, either implement host credential injection or remove the unusable `credential_id` live path, harden `base_url` parsing to reject userinfo/query/fragment, add parameter support for saved-question execution, align runtime and manifest host policy, and add a tracked verification bundle.

## First-Slice Scope

The current Metabase README slice documents the existing runtime surface:

- direct session-token and parsed host credential-reference configuration
- self-hosted base URL behavior
- provider host policy, timeout, retry settings, and provider error mapping
- dashboard listing, saved-question listing, and saved-question execution operations
- simplified handshake and local readiness behavior
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Metabase session token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `metabase.dashboards.read` gates dashboard listing metadata, but runtime does not enforce capability tokens.
  - `metabase.questions.read` gates saved-question listing and execution metadata, but runtime does not enforce capability tokens.
- The connector does not persist session tokens, credential secret material, dashboard data, saved-question data, query results, or provider error bodies outside process memory.
- Metabase payloads can include dashboard names, collection structure, saved-question names, database/schema metadata, query result rows, and operational analytics. Treat live output as work-zone data unless a stricter zone boundary is implemented.

## Network And Runtime Invariants

- Runtime endpoint shape: `{base_url}/dashboard`, `{base_url}/card`, and `{base_url}/card/{card_id}/query`.
- Production endpoints should use HTTPS.
- Runtime readiness policy accepts any HTTPS host because Metabase is self-hosted.
- Runtime readiness policy accepts HTTP only for `localhost`, `127.0.0.1`, and `::1`.
- Runtime readiness policy rejects parse failures and missing hosts.
- Runtime configure does not enforce the readiness policy.
- Runtime request timeout: `30 seconds`.
- Runtime retry setting: `max_retries = 2`.
- Provider HTTP 401, 403, 404, 429, and other API errors map to typed connector/FCP errors.
- `Retry-After` on 429 is converted to milliseconds; missing values default to 60000 ms.
- Manifest connect timeout is `10000 ms`, total timeout is `30000 ms` for list operations and `120000 ms` for question execution, and maximum response bytes are `10485760` or `52428800` by operation.
- Sandbox profile is `strict`, with `512 MB` memory, `50%` CPU, no exec, and no inbound listener capability.
- The connector does not open inbound sockets, receive Metabase webhooks, or hold durable query caches.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `metabase.dashboards.read` | List dashboard metadata. |
| `metabase.questions.read` | List saved questions and run one saved question. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `metabase.dashboards.list` | `GET /dashboard` | `metabase.dashboards.read` | `Safe` | `Low` | `Strict` | Lists dashboards and returns `dashboards`, accepting either a provider array or an object field. |
| `metabase.questions.list` | `GET /card` | `metabase.questions.read` | `Safe` | `Low` | `Strict` | Lists saved questions/cards and returns `questions`, accepting either a provider array or an object field. |
| `metabase.questions.run` | `POST /card/{card_id}/query` | `metabase.questions.read` | `Safe` | `Low` | `Strict` | Runs one saved question with an empty body and returns provider `data` plus status when present. |

## Credential Modes

Direct session-token mode is the only live request mode in this checkout:

- configure requires a non-empty trimmed `session_token`
- the client sends `X-Metabase-Session`
- health reports `live_requests_supported = true` after configure
- self-check can return ok when local URL readiness passes

`credential_id` mode is a parsed but not live-complete path:

- configure requires a valid UUID string
- the client never leaks that value upstream as an auth header
- doctor reports a noncritical `host_credential_injection` check
- self-check returns degraded with `credential_injection_required`
- invoke returns FCP-1003
- simulate denies with FCP-1003 after configured and handshaken state is present

Production users should not expect `credential_id` live requests to work until host-side credential injection is implemented for this connector.

## Resource URIs

Runtime capability-token verification is absent for Metabase in this checkout, so there are no effective resource URI bindings. The practical authorization binding is configuration plus base readiness plus operation name.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| Instance | `metabase://{instance}` |
| Dashboards | `metabase://{instance}/dashboards/{dashboard_id}` |
| Questions | `metabase://{instance}/questions/{card_id}` |
| Query results | `metabase://{instance}/questions/{card_id}/result` |

## Explicit Non-Goals

The current implementation does not include:

- dashboard detail retrieval, dashboard cards, dashboard creation/editing, dashboard parameters, or dashboard subscriptions
- saved-question create/update/delete, native SQL editing, parameterized run bodies, query cancellation, or result exports
- database, schema, table, field, collection, user, group, permissions, settings, alert, pulse, or embedding APIs
- OAuth installation flow, token refresh, session-token rotation, webhook ingestion, audit events, or durable event replay
- durable storage of dashboards, saved questions, query results, or credentials

These are excluded on purpose:

- Saved-question execution can expose sensitive business data and needs explicit capability/resource binding before broader query surfaces are safe.
- Parameterized runs need typed parameter validation before accepting arbitrary provider payloads.
- Administration and permission APIs belong in separate high-review slices.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, handshake, live-request support, request, and error counter state
- local URL readiness only, not a live Metabase probe
- degraded self-check for unconfigured and `credential_id` modes
- operation metadata with capability, risk, safety tier, idempotency, schemas, and hints
- simulation allow/deny for known versus unknown operation IDs, missing config, missing handshake, and unsupported `credential_id` live mode
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, doctor, self-check, introspection, simulation, shutdown, and counters
- dashboard listing, saved-question listing, and saved-question execution through deterministic HTTP fixtures
- operation alias handling through `operation_id` and `operation`
- invoke rejection for unknown operation, missing required inputs, missing handshake, and unsupported `credential_id` mode
- provider 401, 403, 404, 429, and 500 classes
- auth redaction, session-token header shape, credential ID non-leakage, custom URL handling, provisioning readiness, and base URL policy

## Source Notes

- `connectors/metabase/src/connector.rs` defines configuration parsing, lifecycle handlers, URL readiness policy, credential-mode gates, introspection, simulation, and invoke dispatch.
- `connectors/metabase/src/client.rs` defines Metabase API paths, session-token header shape, credential ID non-leakage, timeout, and provider error mapping.
- `connectors/metabase/src/types.rs` defines dashboard, question, and API error shapes.
- `connectors/metabase/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/metabase/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit intent.
- `connectors/metabase/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/metabase/README.md
ubs connectors/metabase/README.md
LC_ALL=C rg -n '[^ -~]' connectors/metabase/README.md
rg -n '\bmaster\b' connectors/metabase/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-metabase
rch exec -- cargo check -p fcp-metabase --all-targets
rch exec -- cargo clippy -p fcp-metabase --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Use direct `session_token` for current live testing because `credential_id` mode is not live-complete.
- Treat `base_url` as sensitive configuration. The runtime policy is intentionally permissive for self-hosted deployments.
- Avoid `base_url` values with userinfo, query strings, or fragments even though current runtime does not reject all of them.
- Treat `metabase.questions.run` output as potentially sensitive business data.
- Do not rely on capability-token enforcement until runtime verification is implemented.
- Do not interpret this connector as a dashboard renderer, SQL authoring surface, or Metabase administration client.
