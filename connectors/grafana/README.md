# Grafana Connector V3 Contract

> **Status**: runtime contract documented; capability-enforcement drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Grafana HTTP API upstream**: https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/
> **Grafana legacy HTTP API upstream**: https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/api-legacy/
> **Grafana data source API upstream**: https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/data_source/
> **Grafana annotations API upstream**: https://grafana.com/docs/grafana/latest/developers/http_api/annotations/
> **Grafana alerting provisioning API upstream**: https://grafana.com/docs/grafana/latest/developers/http_api/alerting_provisioning/

## Purpose

This document fixes the operator-facing contract for `fcp.grafana`. The connector exposes the Grafana HTTP API surface implemented in this crate: dashboard search, dashboard lookup, dashboard save, dashboard delete, datasource listing, datasource query, alert rule listing, alert rule creation, and annotation creation.

The connector is intentionally a bounded Grafana bridge. It is not a full Grafana administrator, user/team/org manager, folder permission manager, alert notification-policy manager, datasource provisioning client, reporting client, or dashboard migration tool.

## Current Runtime Snapshot

The current crate exposes these operations:

- `grafana.dashboards.list`
- `grafana.dashboards.get`
- `grafana.dashboards.create`
- `grafana.dashboards.delete`
- `grafana.datasources.list`
- `grafana.datasources.query`
- `grafana.alerts.list`
- `grafana.alerts.create`
- `grafana.annotations.create`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-grafana`.
- Runtime `BaseConnector` ID is `grafana`.
- Runtime handshake response reports connector ID `fcp.grafana`.
- Configuration requires exactly one of `auth_token` or `credential_id`.
- `auth_token` is trimmed and sent as a bearer token.
- `credential_id` must be a valid UUID and is sent as `X-FCP-Credential-Id` for host egress credential injection.
- Default base URL is `https://grafana.com/api`.
- Public base URLs must use HTTPS, must not contain userinfo, query strings, or fragments, and must target either exact host `grafana.com` or a non-empty `.grafana.net` subdomain.
- `localhost` and `127.0.0.1` are accepted with HTTP or HTTPS for deterministic loopback tests.
- Runtime request timeout is 30 seconds.
- Runtime HTTP requests use the shared retry loop with `max_retries = 3`.
- Path segments such as dashboard UIDs are percent-encoded before being placed in URLs.
- Dashboard search query and tag values are percent-encoded before being placed in query strings.
- Runtime `invoke` expects an `operation_id` field, not the `operation` field used by the newer token-verifying connectors in this workspace.
- Runtime `invoke` does not require `capability_token` and does not verify operation-scoped capability grants.
- Runtime `simulate` only checks whether `operation_id` appears in the local operation list.
- Runtime `self_check()` reports provisioning readiness only. It does not probe Grafana.
- Runtime `shutdown()` clears client, config, configured flag, and base handshaken flag.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest connector ID is `fcp.grafana`, while runtime `BaseConnector` ID is `grafana`.
- Runtime handshake is not the standard FCP capability-token handshake. It accepts an optional `session_id`, returns a capability list, and does not install a `CapabilityVerifier`.
- Runtime `invoke` does not parse or verify `capability_token`; host policy must not treat invoke as capability-verified until the follow-up fix lands.
- Runtime `simulate` does not check configured state, handshake state, inputs, risk, approval, or capability tokens.
- Manifest operation entries carry `requires_approval`, but runtime introspection currently returns operations with `requires_approval = None`.
- Manifest network constraints allow `*.grafana.net` and `*.grafana.com`, while runtime `validate_base_url` allows exact `grafana.com` and `.grafana.net` subdomains only. The separate provisioning readiness helper accepts `.grafana.com`, so configure-time and readiness-time host checks disagree.
- Runtime uses legacy `/api` endpoints. Current Grafana documentation marks legacy `/api` routes as deprecated in favor of `/apis`, while still accessible.
- Runtime `handle_shutdown` does not clear `session_id`, so `handle_health()` can still report `handshaken = true` from the stored session string after shutdown even though the base handshaken flag was cleared.
- The invoke match contains a duplicate `grafana.alerts.create` arm with no behavioral difference.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should implement standard capability-token verification, align `operation_id` versus `operation`, align configure/readiness/manifest host policy, surface approval metadata consistently, migrate or explicitly freeze legacy endpoint use, clear session state on shutdown, and remove duplicate dispatch arms.

## First-Slice Scope

The current Grafana README slice documents the existing runtime surface:

- bearer-token and secretless credential-reference auth selection
- Grafana base URL policy and loopback test allowance
- dashboard list/get/create/delete, datasource list/query, alert list/create, and annotation create operations
- current invoke-time capability enforcement gap
- provider error mapping, retry behavior, redaction posture, and provisioning readiness behavior
- lifecycle, doctor, health, self-check, introspection, simulation, invoke, and shutdown surfaces
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Grafana API key/service-account token via `auth_token`, or secretless credential reference via `credential_id`.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Manifest capability surface:
  - `grafana.dashboards.read` gates dashboard list/get.
  - `grafana.dashboards.write` gates dashboard create/update/delete.
  - `grafana.datasources.read` gates datasource list/query.
  - `grafana.alerts.read` gates alert rule listing.
  - `grafana.alerts.write` gates alert rule creation.
  - `grafana.annotations.write` gates annotation creation.
- Current runtime invoke path does not enforce those capabilities. Host policy must gate access before invoking this connector.
- The connector does not persist dashboards, datasource results, alert definitions, annotation text, bearer tokens, credential IDs, provider payloads, or provider error bodies beyond process memory.
- Grafana data can contain production topology, metrics, logs, secrets embedded in dashboard JSON, alert routing hints, and incident timelines. Treat all live reads and writes as work-zone data.

## Network And Runtime Invariants

- Default base URL: `https://grafana.com/api`.
- Supported runtime production host classes: exact `grafana.com` and non-empty `.grafana.net` subdomains.
- Manifest host classes: `*.grafana.net` and `*.grafana.com`.
- Runtime loopback hosts: `localhost` and `127.0.0.1`.
- Production port: `443`.
- TLS and SNI are required by the manifest for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback base URLs are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints use `10_000 ms` connect timeout.
- Manifest total timeout is `30_000 ms` for most operations and `120_000 ms` for datasource query.
- Manifest maximum response bytes are `1_048_576`, `5_242_880`, or `52_428_800` depending on operation size.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `grafana.dashboards.read` | Search and read dashboard JSON and metadata. |
| `grafana.dashboards.write` | Save or delete dashboards. |
| `grafana.datasources.read` | List datasources and query datasource backends. |
| `grafana.alerts.read` | List alert rules. |
| `grafana.alerts.write` | Create alert rules. |
| `grafana.annotations.write` | Create Grafana annotations. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `grafana.dashboards.list` | `GET /api/search?type=dash-db` | `grafana.dashboards.read` | `Safe` | `Low` | `Strict` | Searches dashboard metadata by query, tag, and limit. |
| `grafana.dashboards.get` | `GET /api/dashboards/uid/{uid}` | `grafana.dashboards.read` | `Safe` | `Low` | `Strict` | Reads dashboard JSON and metadata by UID. |
| `grafana.dashboards.create` | `POST /api/dashboards/db` | `grafana.dashboards.write` | `Risky` | `Medium` | `Strict` | Creates or updates a dashboard JSON model. |
| `grafana.dashboards.delete` | `DELETE /api/dashboards/uid/{uid}` | `grafana.dashboards.write` | `Dangerous` | `High` | `Strict` | Deletes a dashboard by UID. |
| `grafana.datasources.list` | `GET /api/datasources` | `grafana.datasources.read` | `Safe` | `Low` | `Strict` | Lists configured datasources. |
| `grafana.datasources.query` | `POST /api/ds/query` | `grafana.datasources.read` | `Safe` | `Low` | `Strict` | Queries a datasource backend with the provided expression and optional time range. |
| `grafana.alerts.list` | `GET /api/ruler/grafana/api/v1/rules` | `grafana.alerts.read` | `Safe` | `Low` | `Strict` | Lists Grafana alert rules, optionally filtered by state and limit. |
| `grafana.alerts.create` | `POST /api/ruler/grafana/api/v1/rules` | `grafana.alerts.write` | `Risky` | `Medium` | `None` | Creates an alert rule. |
| `grafana.annotations.create` | `POST /api/annotations` | `grafana.annotations.write` | `Safe` | `Low` | `None` | Creates a global or dashboard-scoped annotation. |

## Legacy API Boundary

This runtime currently uses Grafana legacy `/api` endpoints:

- `/search`
- `/dashboards/uid/{uid}`
- `/dashboards/db`
- `/datasources`
- `/ds/query`
- `/ruler/grafana/api/v1/rules`
- `/annotations`

Grafana's current documentation says legacy `/api` routes remain accessible, but are deprecated in favor of newer `/apis` routes. This README documents the current runtime contract rather than silently upgrading endpoints.

## Explicit Non-Goals

The current implementation does not include:

- user, team, organization, service-account, folder, folder-permission, dashboard-permission, playlist, snapshot, report, or SSO management
- datasource create/update/delete, datasource health checks, secure field updates, or datasource permission management
- alert notification policies, contact points, mute timings, silences, alert deletes, or alert rule updates
- dashboard version history, folder moves, library panels, dashboard import/export validation, or provisioned-dashboard reconciliation
- durable metric caches, query pagination, result streaming, or connector-local credential vaulting

These are excluded on purpose:

- Grafana dashboards and datasource queries often expose production topology and incident data.
- Grafana writes can delete dashboards or alter alerting behavior.
- Legacy endpoint migration needs an explicit compatibility decision rather than an invisible README-level rewrite.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration state, handshake/session state, request count, and error count
- provisioning readiness with auth mode, base URL, and network allow-list status
- operation metadata with capability, risk, safety tier, idempotency, schemas, and AI hints
- current lack of invoke-time capability-token verification
- local-only self-check behavior
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- configuration auth-mode validation, base URL validation, loopback allowance, userinfo rejection, host allow-list behavior, and provisioning readiness
- dashboard list/get/create/delete, datasource list/query, alert list/create, and annotation create behavior
- retryable HTTP/429/5xx behavior, JSON errors, 401, 403, 404, and FCP error mapping
- operation catalog shape, risk/safety/idempotency values, and provisioning recipe shape

## Source Notes

- `connectors/grafana/src/connector.rs` defines configuration parsing, base URL policy, lifecycle handlers, doctor/health/self-check, introspection, simulation, invoke dispatch, provisioning readiness, and operation metadata.
- `connectors/grafana/src/client.rs` defines Grafana paths, bearer and credential-reference auth, retry dispatch, timeout, path/query encoding, response decoding, and provider error mapping.
- `connectors/grafana/src/types.rs` defines provider error response shapes.
- `connectors/grafana/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/grafana/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit pools.
- `connectors/grafana/tests/integration.rs` covers deterministic HTTP behavior and runtime invoke coverage.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/grafana_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for Grafana HTTP API paths
- auth, endpoint policy, provider error, lifecycle, simulation, and introspection tests
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a disposable Grafana Cloud stack or loopback fixture for live verification.
- Prefer `credential_id` mode when host policy should own Grafana secret material.
- Use service-account tokens with the narrowest Grafana permissions available.

**Dedicated environment**:

- Keep test dashboards, alert rules, datasources, and annotations separate from production observability assets.
- Export dashboard JSON before delete or overwrite operations.
- Use read-only datasource queries for smoke tests and bound time windows.

**Redaction rules**:

- Redact bearer tokens, credential IDs where needed, dashboard UIDs, dashboard JSON when it embeds sensitive labels or queries, datasource UIDs, query strings, alert rule bodies, annotation text, provider payloads, provider error bodies, and endpoint URLs when they reveal tenant topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, retry decisions, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide exactly one of `auth_token` or `credential_id`.
- If a Grafana Cloud `.grafana.com` subdomain is needed, note that manifest/readiness allow it but current configure-time validation rejects it.
- If invoke is used in production, gate capability and approval in the host until runtime token verification is implemented.
- If dashboard save fails, check `overwrite`, dashboard UID, folder UID, and dashboard version.
- If datasource query returns unexpected data, verify datasource UID, query language, and `from_ts`/`to_ts` range.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-grafana-readme cargo check -p fcp-grafana --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-grafana-readme cargo test -p fcp-grafana --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-grafana-readme cargo clippy -p fcp-grafana --all-targets --no-deps -- -D warnings`
- `ubs connectors/grafana/README.md`
