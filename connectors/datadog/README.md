# Datadog Connector V3 Contract

> **Status**: runtime contract documented; manifest/provider drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://docs.datadoghq.com/api/latest/using-the-api/
> **Events upstream**: https://docs.datadoghq.com/api/latest/events/
> **Logs upstream**: https://docs.datadoghq.com/api/latest/logs/
> **Metrics upstream**: https://docs.datadoghq.com/api/latest/metrics/
> **Monitors upstream**: https://docs.datadoghq.com/api/latest/monitors/

## Purpose

This document fixes the operator-facing contract for `fcp.datadog`. The connector exposes a focused Datadog REST API surface for observability events, log search, metrics query and submission, and monitor listing, creation, and deletion.

The connector is intentionally a bounded work-zone observability bridge. It is not a full Datadog administration client, dashboard client, incident client, tracing client, SLO client, synthetics client, user-management client, billing client, or archive/export client.

## Current Runtime Snapshot

The current crate exposes these operations:

- `datadog.events.create`
- `datadog.events.list`
- `datadog.logs.search`
- `datadog.metrics.query`
- `datadog.metrics.submit`
- `datadog.monitors.create`
- `datadog.monitors.delete`
- `datadog.monitors.list`

Important runtime truths the contract preserves:

- Configuration requires exactly one auth mode: either `api_key` plus `app_key`, or `credential_id`.
- `api_key` and `app_key` mode sends `DD-API-KEY` and `DD-APPLICATION-KEY`.
- `credential_id` mode sends `X-FCP-Credential-Id`.
- `credential_id` must be a valid UUID.
- Supplying both auth modes, a partial API/app key pair, non-string `credential_id`, or invalid UUID fails configuration.
- Default base URL is `https://api.datadoghq.com/api/v1`.
- Region selection accepts `us`, `us1`, `us3`, `us5`, `eu`, `eu1`, and `ap1`; unknown regions fall back to the default US1 endpoint.
- Explicit `base_url` overrides `region`.
- Production base URLs must use HTTPS and one of the exact runtime hosts: `api.datadoghq.com`, `api.us3.datadoghq.com`, `api.us5.datadoghq.com`, `api.ap1.datadoghq.com`, or `api.datadoghq.eu`.
- `localhost` and `127.0.0.1` are accepted for deterministic loopback tests.
- Runtime endpoint validation rejects substring-host tricks such as `datadoghq.com.evil.example`.
- Debug output and redacted labels avoid logging API keys, application keys, or credential material.
- HTTP request timeout is `30 seconds`.
- Requests run through the shared retry loop; HTTP 429 honors Datadog rate-limit reset metadata when available.
- Provider 401, 403, 404, 429, malformed JSON, and retryable 5xx or transport failures are mapped into FCP auth, permission, not-found, rate-limit, external, or retryable errors.
- Handshake declares no FCP streaming support.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Runtime `datadog.monitors.delete` requires the dedicated capability `datadog.monitors.delete`.
- The manifest operation and rate-limit pool still route `datadog.monitors.delete` through `datadog.monitors.write`.
- The manifest optional capabilities omit `datadog.monitors.delete`, while runtime handshake advertises it.
- Runtime `datadog.events.create` is `RiskLevel::Medium`; the manifest still labels it `risk_level = "low"`.
- Runtime endpoints are v1-shaped under `/api/v1`. Current Datadog docs include newer event-management and logs endpoints, including v2 event intake and v2 log search, while this connector still uses `/events` and `/logs-queries/list` on the configured v1 base URL.

A follow-up parity bead should reconcile manifest capabilities, risk metadata, and any provider endpoint migration before broadening this connector.

## First-Slice Scope

The current Datadog README slice documents the existing runtime surface:

- API/app key and host credential-reference configuration
- exact production and loopback base URL policy
- event creation through `POST /events`
- event listing through `GET /events`
- log search through `POST /logs-queries/list`
- metrics query through `GET /query`
- metrics submission through `POST /series`
- monitor creation through `POST /monitor`
- monitor deletion through `DELETE /monitor/{monitor_id}`
- monitor listing through `GET /monitor`
- provider error mapping, retry metadata, and redaction posture
- lifecycle, introspection, simulation, doctor, self-check, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: Datadog API/app key pair or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `datadog.events.write` gates event creation.
  - `datadog.events.read` gates event listing.
  - `datadog.logs.read` gates log search.
  - `datadog.metrics.read` gates metrics query.
  - `datadog.metrics.write` gates metrics submission.
  - `datadog.monitors.read` gates monitor listing.
  - `datadog.monitors.write` gates monitor creation.
  - `datadog.monitors.delete` gates monitor deletion at runtime.
- The connector does not persist logs, metrics, events, monitors, API keys, application keys, credential IDs, provider payloads, or provider error bodies beyond process memory.
- Metrics submission, monitor creation, and monitor deletion are policy-sensitive because they mutate provider-visible observability state.
- Log search can return sensitive application and user data, even though it is read-only.

## Network And Runtime Invariants

- Default production base URL: `https://api.datadoghq.com/api/v1`.
- Supported production region bases:
  - US1: `https://api.datadoghq.com/api/v1`
  - US3: `https://api.us3.datadoghq.com/api/v1`
  - US5: `https://api.us5.datadoghq.com/api/v1`
  - EU1: `https://api.datadoghq.eu/api/v1`
  - AP1: `https://api.ap1.datadoghq.com/api/v1`
- Production port: `443`.
- TLS and SNI are required by the manifest for live traffic.
- Manifest host allowlist is `*.datadoghq.com` and `*.datadoghq.eu`.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback base URLs are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints set total timeout `30_000 ms` for event create, metrics submit, and monitor operations.
- Manifest network constraints set total timeout `60_000 ms` for log search and metrics query.
- Maximum response bytes are `1_048_576` for write-like operations, `10_485_760` for event and monitor list operations, and `52_428_800` for log search and metrics query.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `datadog.events.write` | Post provider-visible events. |
| `datadog.events.read` | List events in a time range. |
| `datadog.logs.read` | Search logs. |
| `datadog.metrics.read` | Query time-series metrics. |
| `datadog.metrics.write` | Submit custom metrics. |
| `datadog.monitors.read` | List monitors. |
| `datadog.monitors.write` | Create monitors. |
| `datadog.monitors.delete` | Delete monitors at runtime. |

## Operation Inventory

| Operation | Endpoint shape | Runtime capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|--------------------|------------|-----------|-------------|-----------|
| `datadog.events.create` | `POST /events` | `datadog.events.write` | `Safe` | `Medium` | `None` | Creates a provider-visible event such as a deployment marker. |
| `datadog.events.list` | `GET /events?start=...&end=...` | `datadog.events.read` | `Safe` | `Low` | `Strict` | Read-only event inventory for a bounded time range. |
| `datadog.logs.search` | `POST /logs-queries/list` | `datadog.logs.read` | `Safe` | `Low` | `Strict` | Read-only log search that can expose sensitive application data. |
| `datadog.metrics.query` | `GET /query` | `datadog.metrics.read` | `Safe` | `Low` | `Strict` | Read-only time-series query. |
| `datadog.metrics.submit` | `POST /series` | `datadog.metrics.write` | `Risky` | `Medium` | `None` | Writes custom metrics that affect dashboards, monitors, and billing. |
| `datadog.monitors.create` | `POST /monitor` | `datadog.monitors.write` | `Risky` | `Medium` | `None` | Creates alerting state. |
| `datadog.monitors.delete` | `DELETE /monitor/{monitor_id}` | `datadog.monitors.delete` | `Dangerous` | `High` | `Strict` | Destructive monitor operation with a dedicated runtime capability. |
| `datadog.monitors.list` | `GET /monitor` | `datadog.monitors.read` | `Safe` | `Low` | `Strict` | Read-only monitor inventory. |

## Explicit Non-Goals

The current implementation does not include:

- dashboard, notebook, SLO, incident, on-call, service catalog, synthetics, APM, trace, RUM, error-tracking, CI visibility, usage, or billing APIs
- monitor update, mute, unmute, validate, can-delete, group search, configuration policy, notification rule, or template APIs
- metrics metadata updates, metric tag configuration, metric volumes, metric assets, or v2 metrics intake migration
- log archive, log index, log pipeline, log-based metric, or live tail APIs
- event v2 intake migration, event search v2, or event correlation helpers
- OAuth app flow, API key provisioning, app key provisioning, or Datadog organization/user management
- connector-local credential vaulting, durable provider cache, or streaming subscription support

These are excluded on purpose:

- The first slice keeps read-only diagnostics, write-like telemetry changes, and destructive monitor deletion separated by explicit capabilities.
- Datadog logs and metrics can contain sensitive operational data and cost-sensitive payloads.
- Provider endpoint migrations should be handled as a dedicated parity task, not hidden in documentation.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration and handshake state
- request and error counters
- configured auth mode and base URL
- provisioning readiness, region inference, and credential-reference status
- operation descriptors with capability, risk, safety tier, idempotency, schemas, and AI hints
- simulation denial for unsupported operation IDs
- handshake invalidation after reconfigure
- shutdown state reset

The deterministic integration evidence is anchored on connector-local tests covering:

- API/app key configuration, credential-id configuration, duplicate auth rejection, partial auth rejection, and invalid credential IDs
- region mapping and base URL validation, including hostile substring hosts and loopback tests
- lifecycle health, doctor, self-check, handshake-before-configure failure, reconfigure, shutdown, introspection, and simulation
- Datadog auth header propagation on loopback HTTP requests
- event create/list, log search, metrics query/submit, monitor create/delete/list operations
- required-field validation for `start`, `end`, `query`, `from_ts`, `to_ts`, `series`, and `monitor_id`
- provider 401, 403, 404, 429, 500, malformed JSON, and retry behavior
- dedicated runtime capability for `datadog.monitors.delete`
- manifest operation inventory, rate-limit pools, and network constraints

## Source Notes

- `connectors/datadog/src/connector.rs` defines configuration parsing, lifecycle handlers, provisioning readiness, introspection, simulation, operation metadata, and invoke dispatch.
- `connectors/datadog/src/client.rs` defines Datadog auth headers, region base URLs, retry loop use, endpoint paths, timeout, provider error handling, and redacted debug behavior.
- `connectors/datadog/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/datadog/src/types.rs` defines provider error response parsing.
- `connectors/datadog/manifest.toml` defines operation schemas, network constraints, sandbox boundary, zone policy, rate limits, and AI hints.
- `connectors/datadog/tests/integration.rs` covers deterministic HTTP behavior and manifest/runtime contract checks.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/datadog_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and capability metadata
- deterministic WireMock coverage for the eight operations
- auth, URL policy, provider error, lifecycle, simulation, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a dedicated Datadog test organization or sandbox account for live provider verification.
- Use API and application keys scoped to the smallest useful permission set.
- Prefer `credential_id` when the host should inject credentials at egress time.
- Use WireMock loopback fixtures for routine proof.

**Dedicated environment**:

- Keep live metric names, event titles, tags, and monitor names synthetic.
- Do not run log searches across production indexes unless the query, time range, and output handling are approved.
- Do not delete monitors from production accounts through this connector.
- Check composite monitor references and muting alternatives before any delete approval.

**Redaction rules**:

- Redact API keys, application keys, credential IDs where needed, event text, event tags when sensitive, log queries, log rows, metric names when sensitive, monitor names, monitor queries, notification targets, provider payloads, provider error bodies, and endpoint URLs when they reveal account topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, retry decisions, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide either both `api_key` and `app_key`, or a valid UUID `credential_id`, but not both.
- If requests hit the wrong site, use an explicit `region` or validated `base_url`.
- If a production URL is rejected, use an exact supported Datadog API host with HTTPS.
- If `datadog.monitors.delete` is denied, request the dedicated runtime capability instead of relying on `datadog.monitors.write`.
- If log search returns no data, verify the query syntax, index access, and time window.
- If metrics submission fails, verify timestamp bounds and metric payload shape.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-datadog-readme cargo check -p fcp-datadog --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-datadog-readme cargo test -p fcp-datadog --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-datadog-readme cargo clippy -p fcp-datadog --all-targets --no-deps -- -D warnings`
