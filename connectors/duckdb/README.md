# DuckDB Connector V3 Contract

> **Status**: runtime contract documented with major manifest/runtime drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **DuckDB upstream**: https://duckdb.org/docs/current/
> **MotherDuck upstream**: https://motherduck.com/docs/

## Purpose

This document fixes the operator-facing contract for `fcp.duckdb`. The current runtime is a MotherDuck HTTP API bridge for SQL execution, database metadata, table metadata, schema listing, query-status lookup, and database shares.

The connector is not currently an embedded local DuckDB engine wrapper despite the manifest and provisioning recipe language. It does not open local `.duckdb` files, load DuckDB extensions, run an embedded SQL engine in-process, expose Arrow/Parquet import/export, or enforce read-only SQL locally.

## Current Runtime Snapshot

The current runtime exposes these operations:

- `duckdb.query.execute`
- `duckdb.databases.list`
- `duckdb.databases.get`
- `duckdb.tables.list`
- `duckdb.tables.get`
- `duckdb.schemas.list`
- `duckdb.queries.status`
- `duckdb.shares.list`
- `duckdb.shares.create`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of:
  - `service_token`
  - `credential_id`
- `service_token` is trimmed and must be non-empty.
- `credential_id` must be a valid UUID and is treated as secretless egress-proxy metadata.
- Optional `database` supplies the default database for `duckdb.query.execute` when the invoke input omits `database`.
- Default base URL is `https://app.motherduck.com/api/v0`.
- `base_url` is trimmed for trailing slashes by the client, but runtime configuration does not validate scheme, host, userinfo, query strings, fragments, or path prefix.
- Service-token mode sends `Authorization: Bearer <token>`.
- Credential-id mode sends `X-FCP-Credential-Id: <uuid>`.
- HTTP client timeout is `30 seconds`.
- The client stores a retry configuration with `max_retries = 2`, but the current `get` and `post` helpers call `reqwest` directly and do not run the shared retry loop.
- Path segments for database names, table names, and query IDs reject `/`, `\\`, `..`, `%2f`, and `%5c`.
- `duckdb.query.execute` sends caller SQL directly to `POST /sql` and does not parse or restrict write/DDL statements.
- Provider 401, 403, 404, 429, and other failures map to FCP errors.
- `health` is local readiness only and considers the connector healthy only when configured and a `session_id` was supplied during handshake.
- `self_check` is local provisioning validation only; it does not probe MotherDuck.
- `credential_id` mode makes `self_check` degraded with `credential_injection_required`.
- `introspect` exposes no streaming support.

## Known Contract Gaps

The current implementation has several significant truthfulness notes:

- The connector uses a legacy `handle_*` method surface rather than the full typed `FcpConnector` trait implementation used by newer connectors.
- `BaseConnector` is initialized with connector ID `duckdb`, while the manifest and handshake payload use `fcp.duckdb`.
- `invoke` checks generic configured/handshaken readiness, but it does not verify a bound capability token for the requested operation.
- `simulate` only checks whether an operation ID is known; it does not validate readiness, input schema, approval state, SQL safety, or capability tokens.
- `manifest.toml` describes embedded DuckDB local-file behavior, forbids network capabilities, and uses `none.invalid` network constraints.
- Runtime is a networked MotherDuck HTTP client and requires either a service token or credential reference.
- The provisioning recipe asks for a local DuckDB database file path and stores `database_path`; runtime configuration does not consume `database_path`.
- `manifest.toml` declares only `duckdb.execute`, `duckdb.query`, and `duckdb.tables.list`, while runtime exposes nine operation IDs under `duckdb.*`.
- Manifest capabilities are `duckdb.execute.write`, `duckdb.query.read`, and `duckdb.tables.read`; runtime introspection and handshake use broader `duckdb.read` and `duckdb.write`.
- The manifest marks write execution as interactive and dangerous, while runtime `OperationInfo` sets `requires_approval` to `None` and marks `duckdb.query.execute` as high-risk/risky.
- The manifest implies read-only `duckdb.query`, but the runtime exposes only `duckdb.query.execute` and does not enforce SQL read-only behavior.
- The client has no production host allowlist for `base_url`; test and custom origins are accepted as-is.
- Retryability is represented in `DuckDbError`, but the live HTTP helpers do not currently use the configured retry loop.

Operators should treat this README as the current truthfulness snapshot. A follow-up should decide whether this connector is a local embedded DuckDB connector or a MotherDuck connector, then align the manifest, provisioning recipe, network policy, operation IDs, capabilities, approval metadata, SQL safety, base URL policy, and retry dispatch.

## First-Slice Scope

The current DuckDB README slice documents the existing runtime surface:

- service-token and credential-id configuration
- MotherDuck HTTP base URL behavior
- optional default database forwarding
- SQL execution through `/sql`
- database list/get
- table list/get
- schema listing
- query-status lookup
- share list/create
- lifecycle, doctor, health, self-check, introspection, simulation, and shutdown surfaces
- deterministic WireMock tests for provider request paths and provider error mapping

## Auth And Scope Boundary

- Authentication mechanisms: MotherDuck service token or host credential reference.
- Runtime does not implement OAuth, browser login, database-file prompts, local credentials, or token refresh.
- Home zone in manifest: `z:private`.
- Allowed source zones in manifest: `z:owner` and `z:private`.
- Allowed target zone in manifest: `z:private`.
- Forbidden zones in manifest: `z:public`, `z:community`, and `z:work`.
- Runtime handshake capabilities:
  - `duckdb.read`
  - `duckdb.write`
- Runtime operation capabilities:
  - `duckdb.read` gates database, table, schema, query-status, and share reads.
  - `duckdb.write` gates SQL execution and share creation.
- Manifest capabilities:
  - `duckdb.query.read`
  - `duckdb.tables.read`
  - `duckdb.execute.write`
- The connector does not persist MotherDuck responses, SQL text, database names, table names, schema names, query IDs, share names, service tokens, credential IDs beyond configuration metadata, provider payloads, or provider error bodies.

## Network And Runtime Invariants

- Runtime default host: `app.motherduck.com`.
- Runtime default API prefix: `/api/v0`.
- Runtime port for the default URL: `443`.
- Runtime client timeout: `30 seconds`.
- Runtime request construction appends endpoint paths to `base_url`.
- Runtime path-segment sanitation is applied to database, table, and query-id path segments, not to `base_url`.
- Manifest network policy forbids network DNS, egress, and TLS capabilities, which does not match the current MotherDuck HTTP runtime.
- Manifest sandbox profile is `strict`, with `512 MB` memory, `50%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open listeners and does not implement subscriptions.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `duckdb.query.execute` | `POST /sql` | `duckdb.write` | `Risky` | `High` | `None` | Sends arbitrary SQL to MotherDuck and may mutate remote state. |
| `duckdb.databases.list` | `GET /databases` | `duckdb.read` | `Safe` | `Low` | `Strict` | Reads database inventory. |
| `duckdb.databases.get` | `GET /databases/{database}` | `duckdb.read` | `Safe` | `Low` | `Strict` | Reads metadata for one database. |
| `duckdb.tables.list` | `GET /databases/{database}/tables` | `duckdb.read` | `Safe` | `Low` | `Strict` | Reads table inventory for one database. |
| `duckdb.tables.get` | `GET /databases/{database}/tables/{table}` | `duckdb.read` | `Safe` | `Low` | `Strict` | Reads metadata for one table. |
| `duckdb.schemas.list` | `GET /databases/{database}/schemas` | `duckdb.read` | `Safe` | `Low` | `Strict` | Reads schema inventory for one database. |
| `duckdb.queries.status` | `GET /queries/{query_id}` | `duckdb.read` | `Safe` | `Low` | `Strict` | Reads status for a previously submitted query. |
| `duckdb.shares.list` | `GET /shares` | `duckdb.read` | `Safe` | `Low` | `Strict` | Reads database-share inventory. |
| `duckdb.shares.create` | `POST /shares` | `duckdb.write` | `Risky` | `Medium` | `None` | Creates provider-visible share state. |

## Explicit Non-Goals

The current implementation does not include:

- embedded DuckDB process execution
- local `.duckdb` file opening or filesystem path validation
- local SQL parser or read-only enforcement
- prepared statements, parameters, transactions, copy/import/export, Parquet/CSV/Arrow APIs, extension management, or local secrets
- database create/drop, table create/drop, schema create/drop, or view/materialized-view management as dedicated operations
- query cancellation, streaming results, pagination, or result-size enforcement
- share deletion, share grants, recipient management, or sharing policy checks
- OAuth, browser login, token refresh, or connector-local credential vaulting

These are excluded on purpose:

- Runtime invocation is currently a small handler-style MotherDuck bridge and should stay narrow until capability enforcement and SQL safety are upgraded.
- Arbitrary SQL execution can mutate data and should not be presented as a safe read-query path.
- Broader DuckDB or MotherDuck coverage needs a clear product boundary and separate operation contracts.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration and handshake state
- request and error counters
- auth mode as service token or credential ID
- credential-injection requirement for credential-id mode
- default database configuration status
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- simulation allow/deny based only on known operation ID
- self-check degradation for unconfigured, missing client, or credential-injection mode

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle health, doctor, self-check, introspection, simulate, and shutdown behavior
- bearer-token auth header propagation
- SQL execution, database list/get, table list/get, schema list, query status, share list/create WireMock requests
- missing required input fields
- provider 401, 403, 404, 429, and 500-class error mapping
- unknown operation and simulation behavior
- request/error counters
- configuration validation, credential-id validation, default database behavior, path-segment sanitation, and provisioning recipe shape

## Source Notes

- `connectors/duckdb/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, simulation, operation metadata, provisioning recipe, and invoke dispatch.
- `connectors/duckdb/src/client.rs` defines MotherDuck HTTP request construction, auth headers, timeout setup, path-segment sanitation, API paths, response parsing, and provider error parsing.
- `connectors/duckdb/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/duckdb/src/types.rs` defines MotherDuck-style query, database, table, schema, share, query-status, and error response shapes.
- `connectors/duckdb/manifest.toml` defines the currently stale local-file operation catalog, network constraints, sandbox boundary, zone policy, rate limits, and AI hints.
- `connectors/duckdb/tests/integration.rs` covers deterministic HTTP behavior and handler lifecycle behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/duckdb_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation contract tests
- deterministic WireMock coverage for the nine runtime operations
- auth, path sanitation, input validation, provider error, lifecycle, introspection, simulation, and shutdown tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a disposable MotherDuck account or WireMock fixtures for verification.
- Prefer a service token scoped to test data.
- Use credential-id mode only when the host or egress proxy is ready to inject MotherDuck auth.

**Dedicated environment**:

- Keep live SQL execution confined to disposable databases.
- Never run arbitrary SQL, DDL, DML, share creation, or destructive statements against production data.
- Use synthetic database names, table names, query IDs, share names, and SQL text in logs and transcripts.

**Redaction rules**:

- Redact service tokens, credential IDs where needed, SQL text when sensitive, database names, table names, query IDs, share names, provider payloads, provider error bodies, and local paths.
- Verification output should use operation IDs, endpoint shapes, host classes, status/error classes, retry decisions, and synthetic MotherDuck resource identifiers.

**Common remediation**:

- If configuration fails, provide exactly one of `service_token` or `credential_id`.
- If credential-id mode self-check reports `credential_injection_required`, use direct service-token mode or wire the egress proxy injection path.
- If invocation fails with readiness errors, configure and handshake with a non-empty `session_id` before invoking.
- If path-segment validation rejects a database, table, or query ID, remove path separators, traversal sequences, and encoded slashes.
- If repeated 500 or 429 errors appear, remember that the current direct HTTP helper does not run the configured retry loop.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-duckdb-readme cargo check -p fcp-duckdb --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-duckdb-readme cargo test -p fcp-duckdb --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-duckdb-readme cargo clippy -p fcp-duckdb --all-targets --no-deps -- -D warnings`
- `ubs connectors/duckdb/README.md`
