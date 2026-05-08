# Snowflake Connector V3 Contract

> **Status**: runtime contract documented; Snowflake SQL API drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Snowflake SQL API upstream**: https://docs.snowflake.com/en/developer-guide/sql-api/index
> **Snowflake SQL API endpoints upstream**: https://docs.snowflake.com/en/developer-guide/sql-api/about-endpoints
> **Snowflake SQL API reference upstream**: https://docs.snowflake.com/en/developer-guide/sql-api/reference

## Purpose

This document fixes the operator-facing contract for `fcp.snowflake`. The connector exposes the Snowflake data-warehouse surface implemented in this crate: database listing, warehouse listing, SQL statement submission, DDL/DML submission, and table listing through `SHOW TABLES`.

The connector is intentionally a bounded Snowflake SQL bridge. It is not a Snowflake Native App client, Snowpark runtime, account administration client, grants/role management tool, task/stream orchestrator, warehouse lifecycle manager, data-loading pipeline, query-status poller, result-pagination engine, OAuth refresh daemon, or Snowflake SDK wrapper.

## Current Runtime Snapshot

The current crate exposes these operations:

- `snowflake.databases.list`
- `snowflake.warehouses.list`
- `snowflake.sql.query`
- `snowflake.sql.execute`
- `snowflake.tables.list`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-snowflake`.
- Manifest ID is `fcp.snowflake`.
- `BaseConnector` runtime ID is `snowflake`.
- Manifest version is `0.1.0`.
- Manifest format is `wasi`.
- Configuration requires `account_identifier`.
- Configuration requires exactly one auth source:
  - `access_token`
  - `credential_id`
- Direct token mode sends `Authorization: Bearer <token>`.
- `credential_id` must be a valid UUID.
- `credential_id` mode configures a placeholder client but runtime `invoke` is disabled until host egress credential injection is wired.
- Default configure-time `base_url` is `https://{account_identifier}.snowflakecomputing.com`.
- The low-level client default, if no base URL were passed, would be `https://{account_identifier}.snowflakecomputing.com/api/v2`, but `handle_configure()` always passes the resolved `base_url`.
- Runtime request timeout is 60 seconds at the reqwest client layer.
- Runtime request-context timeout is 30 seconds.
- The client stores a retry config with `max_retries = 2`, but the low-level GET/POST helpers send a single request in the current implementation.
- `warehouse`, `database`, and `schema` may be configured as defaults and overridden per SQL operation.
- `health()` reports configured/session-ID state and counters. It does not call Snowflake.
- `doctor()` checks local configuration, client initialization, and handshake session ID. It does not call Snowflake.
- `self_check()` reports local provisioning readiness only. It does not perform a live Snowflake probe.
- Runtime `invoke` uses the JSON field `operation_id`, not `operation`.
- Runtime `invoke` does not require or verify a capability token.
- Runtime `simulate` only checks whether the `operation_id` is known.
- Runtime `simulate` does not check configuration, handshake, input shape, approval policy, SQL safety, or capability tokens.
- Runtime `shutdown()` clears config and client state and clears the base configured/handshaken flags.
- Runtime `shutdown()` does not clear the stored `session_id`.

## Runtime API Adapter

The runtime uses these request shapes under `{base_url}`:

| Operation | Runtime request | Required input | Output handling |
|-----------|-----------------|----------------|-----------------|
| `snowflake.databases.list` | `GET /databases` | none | Wraps provider response as `{ "databases": ... }`. |
| `snowflake.warehouses.list` | `GET /warehouses` | none | Wraps provider response as `{ "warehouses": ... }`. |
| `snowflake.sql.query` | `POST /statements` | `statement` | Sends `statement`, `timeout`, and optional/default `warehouse`, `database`, `schema`; returns `data`, `metadata`, and `statement_handle`. |
| `snowflake.sql.execute` | `POST /statements` | `statement` | Sends the same SQL body shape; returns `status` from provider `message` or `executed`, plus `statement_handle`. |
| `snowflake.tables.list` | `POST /statements` via `SHOW TABLES` | `database` | Builds `SHOW TABLES IN DATABASE {database}` or `SHOW TABLES IN SCHEMA {database}.{schema}` and returns provider `data` as `tables`. |

SQL context handling:

- SQL statement bodies include `timeout: 60`.
- `warehouse`, `database`, and `schema` are copied directly into SQL API JSON fields for SQL query and execute operations.
- `tables.list` validates `database` and optional `schema` as Snowflake identifiers before building the `SHOW TABLES` statement.
- Identifier validation permits ASCII letters, ASCII digits, underscore, dot, and dollar sign.
- Identifiers must start with an ASCII letter or underscore.
- Leading dots, trailing dots, and consecutive dots are rejected.
- Raw SQL statements are not parsed, restricted, or rewritten.
- `snowflake.sql.query` and `snowflake.sql.execute` currently share the same request path and transport behavior; the risk distinction is metadata and caller intent, not local SQL parsing.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Current Snowflake SQL API documentation describes the SQL API as a REST API for query execution and deployment-management SQL, with statement submission, status checks, and cancellation.
- Snowflake documents the SQL API base as `https://account_identifier.snowflakecomputing.com/api`, with `/api/v2/statements/`, `/api/v2/statements/{statementHandle}`, and `/api/v2/statements/{statementHandle}/cancel` endpoints.
- Runtime default configure-time `base_url` omits `/api` or `/api/v2`, so default production calls become `/databases`, `/warehouses`, and `/statements` under the account host.
- The client has an internal no-base-url default with `/api/v2`, but `handle_configure()` does not use that branch.
- The connector exposes `GET /databases` and `GET /warehouses` directly. These are not Snowflake SQL API statement endpoints; a follow-up should decide whether to target Snowflake REST object APIs under `/api/v2` or implement database/warehouse listing through SQL statements.
- Runtime does not implement statement status polling or cancel endpoints.
- Runtime does not retrieve paginated or chunked result sets after the initial statement response.
- Provisioning recipe is named `snowflake.password_auth` and asks for an access token or password, but the runtime only has a Bearer-token transport. It does not implement Snowflake password login.
- Snowflake SQL API authentication documentation points to OAuth or key-pair authentication. The runtime accepts a pre-issued token or host credential reference and does not mint, refresh, or sign tokens.
- Manifest operation approval modes mark `snowflake.sql.execute` as interactive. Runtime does not enforce approval tokens.
- Runtime introspection reports no `requires_approval` metadata for any operation.
- Manifest rate-limit pools exist for SQL read/write, warehouse read, and database read operations. Runtime introspection reports no rate-limit metadata and the client does not enforce those pools.
- Manifest response caps vary by operation. Runtime does not enforce those response byte caps before parsing JSON.
- Handshake returns all four Snowflake capabilities unconditionally after configure. It does not filter requested capabilities.
- Handshake does not parse a full `HandshakeRequest`, does not install a `CapabilityVerifier`, and does not return a manifest hash.
- `self_check()` reports local readiness without a live read-only Snowflake API probe.
- Runtime `simulate` is only a known-operation check.
- Provider 401, 403, 404, and 429 are mapped through connector-specific errors and then into FCP errors, but no capability-token denial path is involved.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should normalize the default base URL to the intended Snowflake API root, decide the authoritative API surface for databases and warehouses, implement status/result polling for SQL statements, reconcile provisioning with real Snowflake auth modes, add capability-token verification, expose approval and rate-limit metadata, and add live self-check behavior.

## First-Slice Scope

The current Snowflake README slice documents the existing runtime surface:

- account identifier, access-token, and credential-ID configuration
- base URL behavior and Snowflake API path drift
- database, warehouse, SQL query, SQL execute, and table listing operations
- lifecycle, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- provider error mapping, timeout behavior, SQL context handling, and identifier validation
- runtime/manifest/provider-doc drift around endpoint paths, auth, approval, rate limits, response caps, statement polling, result pagination, and capability-token verification
- deterministic WireMock integration tests

## Auth And Zone Boundary

- Authentication mechanisms: direct Snowflake access token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability families:
  - `snowflake.databases.read`
  - `snowflake.warehouses.read`
  - `snowflake.sql.read`
  - `snowflake.sql.write`
- Manifest required capabilities are `network.dns`, `network.egress`, `network.tls.sni`, and `storage.state`.
- Manifest forbids `system.exec`, `network.listen`, `media.upload`, and `media.download`.
- The connector does not intentionally persist access tokens, credential IDs beyond configuration metadata, SQL statements, query results, request counters, or error counters outside process memory.
- Snowflake payloads can contain warehouse metadata, database names, table names, query results, customer records, and operational schema details. Treat live output as work-zone sensitive data unless the host supplies a stricter zone policy.

## Network And Runtime Invariants

- Default configure-time endpoint: `https://{account_identifier}.snowflakecomputing.com`.
- Direct-token requests use `Authorization: Bearer <token>`.
- `credential_id` mode is accepted during configure but blocked at invoke until egress injection is wired.
- Runtime configure accepts `https` hosts ending in `.snowflakecomputing.com` and loopback hosts for tests.
- Runtime configure rejects non-local `http` and unknown hosts during self-check policy evaluation.
- Runtime request timeout is 60 seconds at the HTTP client layer.
- Runtime request-context timeout is 30 seconds.
- Manifest operation network policy allows `*.snowflakecomputing.com` on port `443`, requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, caps redirects at three, and caps response sizes by operation.
- Sandbox profile is `strict`, with `512 MB` memory, `75%` CPU, `600000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets.
- Provider 401 and 403 are terminal authentication or authorization failures.
- Provider 404 is a terminal not-found failure.
- Provider 429 is retryable and honors `Retry-After` seconds, defaulting to 60 seconds when absent.
- Other non-success provider responses are external API errors.
- JSON parse errors are internal failures.

## Capability Families

| Capability | Purpose |
|------------|---------|
| `snowflake.databases.read` | Read database and table inventory. |
| `snowflake.warehouses.read` | Read warehouse inventory. |
| `snowflake.sql.read` | Submit caller-provided SQL intended as read-only query work. |
| `snowflake.sql.write` | Submit caller-provided SQL intended as DDL/DML work. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `snowflake.databases.list` | `GET /databases` | `snowflake.databases.read` | `Safe` | `Low` | `Strict` | Reads database inventory. |
| `snowflake.warehouses.list` | `GET /warehouses` | `snowflake.warehouses.read` | `Safe` | `Low` | `Strict` | Reads warehouse inventory. |
| `snowflake.sql.query` | `POST /statements` | `snowflake.sql.read` | `Risky` | `Medium` | `Strict` | Submits arbitrary caller SQL expected to be read-oriented. |
| `snowflake.sql.execute` | `POST /statements` | `snowflake.sql.write` | `Dangerous` | `High` | `None` | Submits arbitrary caller SQL expected to mutate schema or data. |
| `snowflake.tables.list` | `POST /statements` | `snowflake.databases.read` | `Safe` | `Low` | `Strict` | Runs generated `SHOW TABLES` SQL after identifier validation. |

## Resource URIs

Runtime invoke currently does not verify capability tokens, so no resource binding is enforced locally. The effective authorization boundary is host-side admission plus operation dispatch.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| Databases | `snowflake://database/{database}` |
| Schemas | `snowflake://database/{database}/schema/{schema}` |
| Tables | `snowflake://database/{database}/schema/{schema}/table/{table}` |
| Warehouses | `snowflake://warehouse/{warehouse}` |
| SQL statements | `snowflake://statement/{statement_handle}` |

## Explicit Non-Goals

The current implementation does not include:

- Snowflake password login
- OAuth authorization-code flow or token refresh
- Key-pair JWT signing
- Statement status polling
- Statement cancellation
- Result pagination or partition retrieval
- Warehouse start/stop/resume/suspend controls
- Role, grant, user, or organization administration
- COPY INTO, staged file upload, or bulk ingestion helpers
- Snowpark, Native Apps, tasks, streams, alerts, or dynamic tables
- SQL parser enforcement for read-only queries
- Capability-token or approval-token enforcement

## Verification

README-only changes do not require Cargo or `rch` compilation. For this connector contract, use:

```bash
git diff --check -- connectors/snowflake/README.md
LC_ALL=C rg -n '[^ -~]' connectors/snowflake/README.md
rg -n '\bmaster\b' connectors/snowflake/README.md
ubs connectors/snowflake/README.md
```
