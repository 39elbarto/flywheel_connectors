# MongoDB Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **MongoDB REST API hub**: https://www.mongodb.com/docs/api/
> **Atlas Data API v1 upstream**: https://www.mongodb.com/docs/api/doc/atlas-data-api-v1/group/endpoint-action

## Purpose

This document fixes the operator-facing contract for `fcp.mongodb`. The connector currently targets the MongoDB Atlas Data API action surface implemented in this crate: document find, insert, update, delete, and aggregation.

The connector is intentionally a bounded Atlas Data API bridge. It is not a MongoDB wire-protocol driver, Atlas Admin API client, database/collection administration client, change stream listener, backup/restore tool, index manager, transaction coordinator, or general MongoDB shell surface.

MongoDB's current REST API hub marks the Atlas Data API v1 surface as deprecated and lists App Services/Data API end-of-life notices. This README documents the runtime that exists in this checkout; it is not an endorsement that the upstream API is a long-term target.

## Current Runtime Snapshot

The current crate exposes these operations:

- `mongodb.find_one`
- `mongodb.find`
- `mongodb.insert_one`
- `mongodb.insert_many`
- `mongodb.update_one`
- `mongodb.update_many`
- `mongodb.delete_one`
- `mongodb.delete_many`
- `mongodb.aggregate`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-mongodb`.
- Runtime `BaseConnector` ID is `mongodb`.
- Manifest and reported connector ID are `fcp.mongodb`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:774e98368d9f1013d860cbdf2e902c2a54b8f8db5badb3da0d4f777fbb551879`.
- Configuration requires exactly one auth source: direct `api_key` or `credential_id`.
- Direct API-key mode sends the Atlas Data API `apiKey` header.
- `credential_id` mode sends `X-FCP-Credential-Id` and expects host egress policy to inject real secret material.
- `self_check` degrades in `credential_id` mode because host injection cannot be proven locally.
- Runtime invoke does not reject `credential_id` mode; it sends the credential ID header to the configured endpoint.
- Default base URL is the placeholder `https://data.mongodb-api.com/app/data-xxxxx/endpoint/data/v1`.
- Configuration accepts an optional `base_url` string and optional `data_source`; `data_source` defaults to `Cluster0`.
- The client trims trailing slashes from `base_url`.
- `base_url` is not validated by `configure`; readiness policy is surfaced through `self_check`.
- Runtime host policy accepts HTTPS hosts ending in `.mongodb.net`, `.mongodb.com`, or exactly `data.mongodb-api.com`, plus loopback hosts for tests.
- Runtime host policy rejects non-loopback HTTP and unknown hosts, but does not reject URL userinfo, query strings, or fragments.
- Runtime request timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 2`.
- All Atlas Data API operations are sent as HTTP `POST` requests to `{base_url}/action/{action}`.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime does not install a `CapabilityVerifier` and does not verify `capability_token`.
- Runtime does not verify approval tokens for insert, update, delete, or aggregate operations.
- `simulate` only checks whether `operation_id` is present in the local operation inventory.
- `handle_configure()` does not clear a prior session ID and does not reset the base handshaken flag.
- `handle_shutdown()` shuts down the client runtime and clears config/client/base flags, but leaves `session_id` in memory.
- `self_check()` is a local readiness check only; it does not issue a live Atlas Data API probe.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Upstream Atlas Data API v1 is now documented by MongoDB as deprecated; the runtime still targets the Data API action endpoints.
- Manifest advertises `mongodb.documents.find`, `mongodb.documents.insert`, `mongodb.documents.delete`, `mongodb.databases.list`, `mongodb.collections.list`, and `mongodb.aggregate`; runtime exposes nine different operation IDs.
- Manifest advertises database and collection listing operations, but runtime does not implement `mongodb.databases.list` or `mongodb.collections.list`.
- Runtime implements `find_one`, `insert_one`, `insert_many`, `update_one`, `update_many`, `delete_one`, and `delete_many` operations that are not individually represented in the manifest.
- Manifest capabilities are `mongodb.documents.read`, `mongodb.databases.read`, and `mongodb.documents.write`; runtime operation metadata uses `mongodb.read` and `mongodb.write`.
- Handshake returns operation IDs in its `capabilities` array instead of capability IDs.
- Manifest marks `mongodb.aggregate` as risky and policy-approved; runtime marks it safe/low and checks no approval token.
- Manifest marks delete as interactive approval and idempotent; runtime delete operations are dangerous/high with no idempotency and no approval check.
- Manifest state hint says connection string and database context are stored. Runtime keeps configuration in memory and uses Data API `base_url` plus `data_source`, not a MongoDB connection string.
- Manifest network constraints allow only `*.mongodb.net`, while runtime readiness also accepts `*.mongodb.com`, exact `data.mongodb-api.com`, and loopback hosts.
- Runtime URL readiness can accept paths that are not Atlas Data API endpoints, such as generic MongoDB web/API hosts, then append `/action/*`.
- Runtime introspection returns only `connector_id`, `version`, and operations, not the full `Introspection` shape with events, resource types, auth caps, or event caps.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should decide whether this connector remains on the deprecated Atlas Data API, align operation IDs and capability IDs across manifest/handshake/runtime, remove unimplemented database and collection list operations or implement them, add capability-token and approval-token verification, harden URL policy, reset handshake/session state consistently, and add a tracked verification bundle.

## First-Slice Scope

The current MongoDB README slice documents the existing runtime surface:

- direct Atlas Data API key and host credential-reference configuration
- Data API base URL and `data_source` behavior
- local host policy, timeout, retry, and provider error mapping
- document find/insert/update/delete and aggregation operations
- simplified handshake, self-check, introspection, and simulation behavior
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Atlas Data API key or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `mongodb.read` gates find and aggregate metadata, but runtime does not enforce capability tokens.
  - `mongodb.write` gates insert, update, and delete metadata, but runtime does not enforce capability or approval tokens.
- Manifest capability surface:
  - `mongodb.documents.read`
  - `mongodb.databases.read`
  - `mongodb.documents.write`
- The connector does not persist API keys, credential secret material, documents, filters, update expressions, aggregation pipelines, results, or provider error bodies outside process memory.
- MongoDB payloads can contain arbitrary application records. Treat live output as work-zone or private-zone data based on the configured Atlas app and collection.

## Network And Runtime Invariants

- Default Atlas Data API base URL: `https://data.mongodb-api.com/app/data-xxxxx/endpoint/data/v1`.
- Runtime endpoint shape: `{base_url}/action/{findOne|find|insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany|aggregate}`.
- Runtime sends `Content-Type: application/json` and `Accept: application/json`.
- Runtime host policy accepts HTTPS `*.mongodb.net`, HTTPS `*.mongodb.com`, exact HTTPS `data.mongodb-api.com`, and loopback HTTP/HTTPS for deterministic tests.
- Runtime readiness policy rejects non-loopback HTTP and unknown hosts.
- Runtime configure does not enforce the readiness policy.
- Runtime request timeout: `30 seconds`.
- Runtime retry policy: `max_retries = 2` using the shared retry loop.
- Provider HTTP 401, 403, 404, 429, and other API errors map to typed connector/FCP errors.
- `Retry-After` on 429 is converted to milliseconds; missing values default to 60000 ms.
- Manifest connect timeout is `10000 ms`, operation total timeout is `30000 ms`, `60000 ms`, or `120000 ms`, and maximum response bytes range from `1048576` to `52428800` by operation.
- Sandbox profile is `strict`, with `512 MB` memory, `75%` CPU, no exec, and no inbound listener capability.
- The connector does not open inbound sockets, maintain change streams, or connect to MongoDB over the native driver protocol.

## Operation Inventory

| Operation | Endpoint action | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|-----------------|------------|------------|-----------|-------------|----------------|
| `mongodb.find_one` | `findOne` | `mongodb.read` | `Safe` | `Low` | `Strict` | `database`, `collection`; optional `filter`. |
| `mongodb.find` | `find` | `mongodb.read` | `Safe` | `Low` | `Strict` | `database`, `collection`; optional `filter`, `limit`, `sort`, `projection`. |
| `mongodb.insert_one` | `insertOne` | `mongodb.write` | `Risky` | `Medium` | `None` | `database`, `collection`, `document`. |
| `mongodb.insert_many` | `insertMany` | `mongodb.write` | `Risky` | `Medium` | `None` | `database`, `collection`, `documents`. |
| `mongodb.update_one` | `updateOne` | `mongodb.write` | `Risky` | `Medium` | `None` | `database`, `collection`, `filter`, `update`. |
| `mongodb.update_many` | `updateMany` | `mongodb.write` | `Risky` | `Medium` | `None` | `database`, `collection`, `filter`, `update`. |
| `mongodb.delete_one` | `deleteOne` | `mongodb.write` | `Dangerous` | `High` | `None` | `database`, `collection`, `filter`. |
| `mongodb.delete_many` | `deleteMany` | `mongodb.write` | `Dangerous` | `High` | `None` | `database`, `collection`, `filter`. |
| `mongodb.aggregate` | `aggregate` | `mongodb.read` | `Safe` | `Low` | `Strict` | `database`, `collection`, `pipeline`. |

## Explicit Non-Goals

The current implementation does not include:

- native MongoDB driver connections, SRV/TLS driver negotiation, transactions, sessions, read preferences, or write concerns
- database listing, collection listing, collection creation/drop, index management, validation rules, users, roles, backups, or Atlas project administration
- change streams, triggers, webhooks, event replay, durable cursor state, or aggregation result persistence
- OAuth installation flow, API-key rotation, credential validation beyond local configuration shape, or live self-check probe
- document schema validation, query sanitization, aggregation stage policy, or `$where`/server-side JavaScript filtering

These are excluded on purpose:

- Insert, update, and delete operations can mutate or destroy arbitrary application data and need explicit approval/runtime verification before broader mutation is safe.
- The deprecated upstream Data API should be revisited before adding large feature surface.
- Native MongoDB access belongs in a different connector architecture than this HTTP Data API bridge.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, session ID, request, and error counter state
- local URL readiness and credential-injection warning state
- degraded self-check for unconfigured and `credential_id` modes
- operation metadata with capability, risk, safety tier, idempotency, schemas, and hints
- simulation allow/deny for known versus unknown operation IDs only
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, doctor, self-check, introspection, simulation, shutdown, and counters
- all nine Data API action operations through deterministic HTTP fixtures
- invoke rejection for unknown operation and missing required inputs
- provider 401, 403, 404, 429, and 500 classes
- all requests using POST
- auth redaction, credential ID mode metadata, default/custom URL behavior, provisioning readiness, and base URL policy

## Source Notes

- `connectors/mongodb/src/connector.rs` defines configuration parsing, lifecycle handlers, URL readiness policy, provisioning readiness, introspection, simulation, and invoke dispatch.
- `connectors/mongodb/src/client.rs` defines Atlas Data API action paths, auth headers, retry dispatch, timeout, default base URL, and provider error mapping.
- `connectors/mongodb/src/types.rs` defines document, insert/update/delete, aggregation, and API error shapes.
- `connectors/mongodb/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/mongodb/manifest.toml` defines the manifest operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit intent.
- `connectors/mongodb/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/mongodb/README.md
ubs connectors/mongodb/README.md
LC_ALL=C rg -n '[^ -~]' connectors/mongodb/README.md
rg -n '\bmaster\b' connectors/mongodb/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-mongodb
rch exec -- cargo check -p fcp-mongodb --all-targets
rch exec -- cargo clippy -p fcp-mongodb --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Treat the Atlas Data API v1 dependency as a migration risk because MongoDB now lists that API as deprecated.
- Always configure a real Atlas Data API app endpoint; the default `data-xxxxx` URL is a placeholder.
- Keep `data_source` explicit in production instead of relying on `Cluster0`.
- Treat update and delete operations as high-review operations even though runtime approval checks are absent.
- Do not rely on capability-token or approval-token enforcement until runtime verification is implemented.
- Do not interpret this connector as a native MongoDB driver or Atlas administration surface.
