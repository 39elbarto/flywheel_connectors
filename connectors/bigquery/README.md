# BigQuery Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://cloud.google.com/bigquery/docs/reference/rest
> **Query upstream**: https://cloud.google.com/bigquery/docs/reference/rest/v2/jobs/query

## Purpose

This document fixes the operator-facing contract for `fcp.bigquery`. The connector exposes a focused Google BigQuery REST API surface for dataset discovery, table discovery, job listing, and synchronous SQL query execution.

The connector is intentionally a bounded analytics bridge. It is not a full BigQuery administration client, load-job client, streaming-insert client, model/routine/row-access-policy client, reservation client, or data-transfer service.

## Current Runtime Snapshot

The current crate exposes these operations:

- `bigquery.datasets.list`
- `bigquery.tables.list`
- `bigquery.jobs.list`
- `bigquery.jobs.query`

Important runtime truths the contract preserves:

- Configuration requires a non-empty `access_token`.
- Configuration accepts optional `project_id` and optional `base_url`.
- If `project_id` is configured, operation input can omit `project_id`; otherwise introspection marks `project_id` as required for project-scoped operations.
- Default base URL is `https://bigquery.googleapis.com/bigquery/v2`.
- Production base URL must target HTTPS `bigquery.googleapis.com`.
- `localhost`, `127.0.0.1`, and `::1` are accepted for deterministic loopback tests.
- Runtime endpoint validation rejects empty URLs, unparseable URLs, missing hosts, non-BigQuery non-loopback hosts, and non-HTTPS non-loopback endpoints.
- All live requests send `Authorization: Bearer ...` and `Accept: application/json`.
- `BigQueryAuth` debug output and redacted labels avoid logging the bearer token.
- HTTP client timeout is `30 seconds`.
- The connector constructs a shared retry config with a maximum of two retries; current request helpers call reqwest directly.
- Dynamic path segments reject empty values, `/`, `\`, `..`, `%2f`, `%5c`, and `%2e` so project and dataset IDs cannot alter URL routing.
- `bigquery.jobs.query` sends `query` and `useLegacySql` in the JSON body.
- Upstream 401, 403, 404, 429 with `Retry-After`, and other provider failures are mapped into FCP auth, permission, not-found, rate-limit, or external errors.

## First-Slice Scope

The current BigQuery README slice documents the existing runtime surface:

- bearer access-token configuration
- optional default project ID
- production and loopback base URL policy
- dataset listing through `GET /projects/{project_id}/datasets`
- table listing through `GET /projects/{project_id}/datasets/{dataset_id}/tables`
- recent job listing through `GET /projects/{project_id}/jobs`
- synchronous query execution through `POST /projects/{project_id}/queries`
- provider error mapping, retry metadata, and redaction posture
- lifecycle, introspection, simulation, doctor, self-check, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanism: Google OAuth2 bearer access token supplied at configure time.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Capability surface:
  - `bigquery.datasets.read` gates dataset listing.
  - `bigquery.tables.read` gates table listing.
  - `bigquery.jobs.read` gates job listing.
  - `bigquery.jobs.write` gates synchronous query execution.
- The connector does not persist datasets, tables, rows, query text, job metadata, access tokens, provider payloads, or provider error bodies beyond process memory.
- Query execution is capability and policy gated because it can read sensitive data and incur provider cost.

## Network And Runtime Invariants

- Production base URL: `https://bigquery.googleapis.com/bigquery/v2`.
- Production host: `bigquery.googleapis.com`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback overrides are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints set total timeout `30_000 ms` for list operations and `300_000 ms` for query execution.
- Maximum response bytes are `10_485_760` for list operations and `104_857_600` for query execution.
- Sandbox profile is `strict`, with `512 MB` memory, `75%` CPU, `600_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `bigquery.datasets.read` | List datasets visible to the configured token. |
| `bigquery.tables.read` | List tables in a dataset. |
| `bigquery.jobs.read` | List recent jobs started in a project. |
| `bigquery.jobs.write` | Run a synchronous SQL query. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `bigquery.datasets.list` | `GET /projects/{project_id}/datasets` | `bigquery.datasets.read` | `Safe` | `Low` | `Strict` | Read-only dataset inventory for a project. |
| `bigquery.tables.list` | `GET /projects/{project_id}/datasets/{dataset_id}/tables` | `bigquery.tables.read` | `Safe` | `Low` | `Strict` | Read-only table inventory for one dataset. |
| `bigquery.jobs.list` | `GET /projects/{project_id}/jobs` | `bigquery.jobs.read` | `Safe` | `Low` | `Strict` | Read-only recent-job inventory. |
| `bigquery.jobs.query` | `POST /projects/{project_id}/queries` | `bigquery.jobs.write` | `Risky` | `High` | `None` | Executes SQL and can expose data or incur query cost. |

## Explicit Non-Goals

The current implementation does not include:

- project listing or service-account inspection
- dataset create, update, patch, delete, or undelete
- table get, create, update, patch, delete, data listing, or `insertAll`
- asynchronous job insert, cancel, get, delete, or `getQueryResults`
- load jobs, extract jobs, copy jobs, streaming inserts, Storage API, or BigQuery Data Transfer Service
- model, routine, row-access-policy, reservation, connection, IAM, or Analytics Hub APIs
- OAuth authorization-code flow, token refresh, service-account key handling, or Workload Identity setup
- local query result cache, durable row storage, or result pagination helpers
- FCP subscription-based streaming
- connector-local credential vaulting

These are excluded on purpose:

- The first slice keeps read-only inventory and risky query execution separate.
- Query execution needs explicit policy because it can read sensitive datasets and generate billable work.
- Broader BigQuery administration and ingestion surfaces require separate capability and redaction contracts.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration and handshake state
- request and error counters
- default project ID readiness
- effective base URL and local network-policy validation
- self-check degradation for unconfigured state and invalid base URL policy
- client initialization state
- four operation descriptors with capability, risk, safety tier, idempotency, schemas, and AI hints
- simulation denial for unsupported operation IDs

The deterministic integration evidence is anchored on connector-local tests covering:

- configuration with and without a default project ID
- handshake-before-configure failure and shutdown behavior
- health, doctor, self-check, introspection, simulation, and counters
- bearer auth header propagation
- dataset listing, table listing, job listing, and query loopback requests
- Standard SQL and legacy SQL query body behavior
- required-field validation for `project_id`, `dataset_id`, and `query`
- path-segment rejection for traversal-like identifiers
- provider 401, 403, 404, 429 with `Retry-After`, and 500 errors
- manifest operation inventory, rate-limit pools, and network constraints

## Source Notes

- `connectors/bigquery/src/connector.rs` defines configuration parsing, lifecycle handlers, provisioning readiness, diagnostics, introspection, simulation, and invoke dispatch.
- `connectors/bigquery/src/client.rs` defines BigQuery REST paths, bearer auth, timeout, retry metadata, base URL policy, path-segment guards, request bodies, and provider error mapping.
- `connectors/bigquery/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/bigquery/src/types.rs` defines provider error response parsing.
- `connectors/bigquery/manifest.toml` defines operation schemas, network constraints, sandbox boundary, zone policy, rate limits, and AI hints.
- `connectors/bigquery/tests/integration.rs` covers deterministic HTTP behavior and manifest/runtime contract checks.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/bigquery_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime operation agreement
- deterministic WireMock coverage for all four operations
- auth, URL policy, input validation, provider error, lifecycle, simulation, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a test Google Cloud project with the BigQuery API enabled for live provider verification.
- Use a bearer token scoped tightly to the test operations.
- Use a disposable dataset and query target for live mutation/cost-sensitive checks.
- Use WireMock loopback fixtures for routine proof.

**Dedicated environment**:

- Keep live SQL synthetic and bounded with explicit `LIMIT` clauses when possible.
- Do not run broad scans against production datasets.
- Verify which project pays for the query before invoking `bigquery.jobs.query`.
- Treat dataset IDs, table IDs, query text, row values, job IDs, and provider errors as sensitive analytics data.

**Redaction rules**:

- Redact bearer tokens, project IDs when sensitive, dataset IDs when sensitive, table IDs when sensitive, query text, row values, job IDs, provider payloads, and provider error bodies.
- Verification output should use operation IDs, endpoint shapes, host class, auth mode, status/error classes, retry decisions, row counts, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide a non-empty `access_token`.
- If operation input reports missing `project_id`, configure a default project ID or include `project_id` in the operation input.
- If table listing fails validation, pass a dataset ID, not a fully qualified `project.dataset` string.
- If URL policy fails, use `https://bigquery.googleapis.com/bigquery/v2` or a loopback test origin.
- If query execution is denied by policy, verify approval for `bigquery.jobs.write` and the high-risk operation tier.
- If BigQuery returns 403, confirm both token scopes and BigQuery IAM roles on the project and dataset.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-bigquery-readme cargo check -p fcp-bigquery --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-bigquery-readme cargo test -p fcp-bigquery --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-bigquery-readme cargo clippy -p fcp-bigquery --all-targets --no-deps -- -D warnings`
