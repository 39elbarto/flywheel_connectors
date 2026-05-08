# MySQL Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/mysql_connector_verification.sh`
> **MySQL Reference Manual**: https://dev.mysql.com/doc/refman/en/
> **MySQL EXPLAIN upstream**: https://dev.mysql.com/doc/refman/en/explain.html

## Purpose

This document fixes the operator-facing contract for `fcp.mysql`. The connector exposes the MySQL/MariaDB HTTP proxy surface implemented in this crate: read queries, mutation statements, explain plans, schema metadata, and proxy health.

The connector is intentionally a bounded database-proxy bridge. It is not a native MySQL wire-protocol driver, connection pool, migration tool, DDL authoring surface, replication client, backup/restore client, binlog reader, stored-procedure framework, or general SQL administration console.

## Current Runtime Snapshot

The current crate exposes these operations:

- `mysql.query`
- `mysql.execute`
- `mysql.explain`
- `mysql.schema.tables`
- `mysql.schema.columns`
- `mysql.schema.indexes`
- `mysql.health`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-mysql`.
- Runtime `BaseConnector` ID is `fcp.mysql`.
- Manifest and reported connector ID are `fcp.mysql`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:b24518e1e14afe702ce373f3659a9845de7242f64e88a68f23849ac5fe1788a5`.
- Manifest format is `native`, but the runtime client is an HTTP REST-proxy client.
- Configuration requires exactly one auth source: direct `api_key` or `credential_id`.
- Direct API-key mode sends bearer auth.
- `credential_id` mode sends `X-FCP-Credential-Id` to the proxy.
- `health()` and `self_check()` degrade in `credential_id` mode because host-side credential injection cannot be proven locally.
- Runtime invoke does not reject `credential_id` mode; it sends the credential ID header to the configured proxy endpoint.
- Default base URL is the placeholder `https://db.example.com`.
- Configuration accepts an optional `base_url`; the client trims trailing slashes.
- Runtime URL policy requires absolute HTTP(S), rejects query strings, rejects fragments, rejects embedded credentials, requires HTTPS for non-local endpoints, and allows local HTTP for `localhost`, `127.0.0.1`, and `*.localhost`.
- Runtime URL policy accepts any non-local HTTPS host; the manifest expects the installer to substitute an operator-pinned proxy host.
- Runtime request timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 2`.
- Runtime `invoke` uses `operation`, not `operation_id`.
- Runtime does not call `base.check_ready()` before invoke.
- Runtime does not install a `CapabilityVerifier` and does not verify `capability_token`.
- Runtime does not verify approval tokens for `mysql.execute`.
- `simulate` requires `operation` and only checks configured state plus known operation.
- `handle_configure()` does not set the base configured flag and does not reset the local handshake flag.
- `handle_handshake()` sets a local boolean and returns no capabilities array.
- `handle_shutdown()` shuts down the client runtime but does not clear config, client, or local handshake state.
- `health()` and `self_check()` perform a live `GET /health` probe in direct API-key mode.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- The manifest declares a native connector, but the runtime talks to an HTTP proxy, not MySQL's native protocol.
- Manifest host constraints use `operator-configured` on port `443`; runtime URL policy accepts any HTTPS host and local HTTP test endpoints.
- Manifest declares `network.tls.sni` as required; runtime permits local HTTP for tests.
- Runtime `invoke` uses `operation`; most newer connector slices use `operation_id`.
- Runtime `invoke` can run without a handshake and without the base readiness flags because it only requires an initialized client.
- Runtime does not verify capability tokens or approval tokens.
- Runtime metadata marks `mysql.execute` as `requires_approval = Interactive`, and the manifest matches, but runtime checks no approval token.
- Runtime input schema exposes `timeout_ms` for `mysql.query`, but the client does not pass `timeout_ms` to the proxy.
- Runtime `handle_shutdown()` does not clear config/client/handshake state, so shutdown is not a reset.
- Runtime `credential_id` mode is visible and invokable, but self-check/health cannot prove it until the host or proxy performs credential injection.
- Runtime introspection returns an operations array plus verification script metadata, not the full `Introspection` shape with events, resource types, auth caps, or event caps.

A follow-up parity bead should decide whether this remains an HTTP proxy connector or moves to a native MySQL protocol implementation, align base readiness and handshake behavior, implement capability-token and approval-token verification, pass or remove `timeout_ms`, harden credential-injection semantics, and make shutdown clear runtime state or document it as a soft runtime stop.

## First-Slice Scope

The current MySQL README slice documents the existing runtime surface:

- direct API-token and host credential-reference configuration
- operator-configured HTTP proxy endpoint behavior
- live proxy health checks
- query, execute, explain, schema, and health operations
- table identifier validation for schema metadata paths
- tracked verification script and deterministic WireMock tests

## Auth And Scope Boundary

- Authentication mechanisms: proxy API key or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability surface:
  - `mysql.read` gates query, explain, schema, and health metadata, but runtime does not enforce capability tokens.
  - `mysql.write` gates execute metadata, but runtime does not enforce capability or approval tokens.
- The connector does not persist API keys, credential secret material, SQL text, parameter values, rows, schema metadata, health payloads, or provider error bodies outside process memory.
- SQL and result payloads can include sensitive business data. Treat live output as work-zone or private-zone data based on the configured proxy/database.

## Network And Runtime Invariants

- Default proxy base URL: `https://db.example.com`.
- Runtime endpoint shapes:
  - `POST /query`
  - `POST /execute`
  - `POST /explain`
  - `GET /schema/tables`
  - `GET /schema/columns/{table}`
  - `GET /schema/indexes/{table}`
  - `GET /health`
- Runtime sends JSON bodies for query, execute, and explain.
- Direct API-key mode uses bearer auth.
- Credential-reference mode sends `X-FCP-Credential-Id`.
- Runtime request timeout: `30 seconds`.
- Runtime retry policy: `max_retries = 2` using the shared retry loop.
- Provider HTTP 401, 403, 409, 429, and other API errors map to typed connector/FCP errors.
- `Retry-After` on 429 is converted to milliseconds; missing values default to 1000 ms.
- Manifest connect timeout is `10000 ms`, operation total timeout is `30000 ms`, and maximum response bytes are `10485760` for each operation.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, no exec, and no inbound listener capability.
- The connector does not open inbound sockets and does not connect to MySQL over TCP itself.

## Operation Inventory

| Operation | Proxy endpoint | Capability | SafetyTier | RiskLevel | Idempotency | Runtime notes |
|-----------|----------------|------------|------------|-----------|-------------|---------------|
| `mysql.query` | `POST /query` | `mysql.read` | `Safe` | `Low` | `Strict` | Sends `sql` and positional `params`; schema advertises `timeout_ms`, but runtime ignores it. |
| `mysql.execute` | `POST /execute` | `mysql.write` | `Risky` | `High` | `None` | Sends mutation SQL and params; metadata requires interactive approval, but runtime checks no approval token. |
| `mysql.explain` | `POST /explain` | `mysql.read` | `Safe` | `Low` | `Strict` | Sends SQL to the proxy's explain endpoint. MySQL documents EXPLAIN as an execution-plan inspection statement. |
| `mysql.schema.tables` | `GET /schema/tables` | `mysql.read` | `Safe` | `Low` | `Strict` | Lists table metadata exposed by the proxy. |
| `mysql.schema.columns` | `GET /schema/columns/{table}` | `mysql.read` | `Safe` | `Low` | `Strict` | Validates table identifier before path construction. |
| `mysql.schema.indexes` | `GET /schema/indexes/{table}` | `mysql.read` | `Safe` | `Low` | `Strict` | Validates table identifier before path construction. |
| `mysql.health` | `GET /health` | `mysql.read` | `Safe` | `Low` | `Strict` | Returns a wrapped live proxy health probe. |

## SQL And Identifier Guardrails

The runtime relies on the operator-configured proxy for SQL policy. Local guardrails are intentionally narrow:

- `mysql.query`, `mysql.execute`, and `mysql.explain` require a string `sql` field.
- `params` defaults to an empty array when missing.
- The runtime does not parse SQL to prove that `mysql.query` is read-only.
- The runtime does not block DDL through `mysql.execute`.
- `mysql.schema.columns` and `mysql.schema.indexes` validate the `table` path component.
- Table identifiers must start with a letter or underscore.
- Table identifiers may contain ASCII letters, digits, underscores, and dots.
- Leading dots, trailing dots, and consecutive dots are rejected.

Proxy-side policy must enforce the real boundary between read, write, schema, health, staging, and production databases.

## Resource URIs

Runtime capability-token verification is absent for MySQL in this checkout, so there are no effective resource URI bindings. The practical authorization binding is configuration plus proxy policy plus operation name.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| Proxy/database | `mysql://{proxy-id}/{database}` |
| Table | `mysql://{proxy-id}/{database}/{table}` |
| Query | `mysql://{proxy-id}/{database}/query/{query-class}` |
| Health | `mysql://{proxy-id}/health` |

## Explicit Non-Goals

The current implementation does not include:

- native MySQL protocol, TLS negotiation to a database server, connection pooling, prepared statement lifecycle, transactions, or savepoints
- DDL management, migrations, users, grants, replication, binlog streaming, backups, restores, or stored procedure authoring
- SQL AST validation, read-only proof, row-level policy, query cost estimation, or parameter type checking
- durable query history, result caching, schema cache, audit event persistence, or webhook/event ingestion
- OAuth installation flow, token refresh, credential rotation, or local credential injection

These are excluded on purpose:

- `mysql.execute` can mutate or delete rows and must remain a high-review operation until approval verification exists.
- A proxy is the current security boundary. Native database access would need a separate connection, credential, and query-policy design.
- Production verification should use a disposable staging database and proxy, never a live production database.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, handshake boolean, request counter, error counter, network policy, auth mode, operator guidance, verification script, and artifact-root hints
- live `/health` probe success or failure in direct API-key mode
- degraded self-check for unconfigured, invalid network policy, client-uninitialized, and `credential_id` modes
- operation metadata with capability, risk, safety tier, idempotency, schemas, hints, and approval metadata
- simulation `would_succeed` for configured plus known operation
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- unconfigured health and doctor guidance
- manifest per-operation network constraints
- secretless credential-injection evidence
- invalid network policy rejection
- live proxy self-check against WireMock
- query, execute, schema table listing, and introspection approval evidence
- client auth redaction, default/custom URL behavior, retry config, table identifier validation, and error conversion

The tracked verification script `scripts/e2e/mysql_connector_verification.sh` collects manifest, cargo check, format, doctor, self-check, integration, and clippy logs under `artifacts/e2e/mysql_connector/<timestamp>`.

## Source Notes

- `connectors/mysql/src/connector.rs` defines configuration parsing, lifecycle handlers, URL readiness policy, operator guidance, live self-check, introspection, simulation, and invoke dispatch.
- `connectors/mysql/src/client.rs` defines proxy paths, auth headers, retry dispatch, timeout, table identifier validation, and provider error mapping.
- `connectors/mysql/src/types.rs` defines proxy table, column, index, query, and API error shapes.
- `connectors/mysql/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/mysql/manifest.toml` defines the operation catalog, operator-configured network constraints, sandbox boundary, zone policy, and rate-limit intent.
- `connectors/mysql/tests/integration.rs` contains the runtime contract proof surface.
- `scripts/e2e/mysql_connector_verification.sh` is the tracked broader proof script for source or behavior changes.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/mysql/README.md
ubs connectors/mysql/README.md
LC_ALL=C rg -n '[^ -~]' connectors/mysql/README.md
rg -n '\bmaster\b' connectors/mysql/README.md
```

For source or behavior changes, run the tracked connector proof lane:

```bash
scripts/e2e/mysql_connector_verification.sh
```

Or run the focused commands through `rch`:

```bash
rch exec -- cargo test -p fcp-mysql
rch exec -- cargo check -p fcp-mysql --all-targets
rch exec -- cargo clippy -p fcp-mysql --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Use a dedicated HTTPS proxy host and disposable staging database for verification.
- Treat `https://db.example.com` as a placeholder, not a usable default.
- Prefer direct `api_key` for current live proof because `credential_id` mode cannot pass local health proof without host injection.
- Treat `mysql.execute` as a high-review operation even though runtime approval checks are absent.
- Do not rely on capability-token or approval-token enforcement until runtime verification is implemented.
- Do not interpret this connector as a native MySQL client or migration tool.
