# Elasticsearch Connector V3 Contract

> **Status**: runtime contract documented with known handler/approval drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://www.elastic.co/docs/api/doc/elasticsearch/
> **Authentication upstream**: https://www.elastic.co/docs/api/doc/elasticsearch/authentication

## Purpose

This document fixes the operator-facing contract for `fcp.elasticsearch`. The connector exposes the Elasticsearch REST surface implemented in this crate: document search, single-document lookup, single-document indexing, bulk operations, index listing, index deletion, and cluster health.

The connector is intentionally a bounded Elasticsearch API bridge. It is not a full Elastic client, Kibana client, ingest-pipeline manager, index-template manager, snapshot/restore tool, security administration surface, data-stream lifecycle tool, scroll/search-after implementation, or vector-search abstraction.

## Current Runtime Snapshot

The current runtime exposes these operations:

- `elasticsearch.search`
- `elasticsearch.get_document`
- `elasticsearch.index_document`
- `elasticsearch.bulk`
- `elasticsearch.indices.list`
- `elasticsearch.indices.delete`
- `elasticsearch.cluster.health`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of:
  - `api_key`
  - `credential_id`
- `api_key` is trimmed and must be non-empty.
- `credential_id` must be a valid UUID and is treated as secretless egress-proxy metadata.
- Default base URL is `https://localhost:9200`, but production base URL policy only accepts HTTPS hosts ending in `.elastic-cloud.com` or `.found.io`.
- Loopback hosts `localhost`, `127.0.0.1`, and `::1` are accepted with `http` or `https` for deterministic tests.
- Runtime base URL policy does not reject userinfo, query strings, or fragments before request construction.
- API-key mode sends `Authorization: ApiKey <api_key>`.
- Credential-id mode sends `X-FCP-Credential-Id: <uuid>`.
- HTTP client timeout is `30 seconds`.
- The client uses the shared retry loop for JSON requests and NDJSON bulk requests.
- Retryable classes include transport failures, HTTP 429, and 5xx API responses.
- Provider 401, 403, 404, 429, and other failures map to FCP errors.
- Provider error bodies are truncated to 2048 bytes before parsing/surfacing.
- Path segments for index names, document IDs, and index-list patterns reject empty values, `/`, `\\`, `..`, `%2f`, and `%5c`.
- `health` is local readiness only and considers the connector healthy only when configured and a `session_id` was supplied during handshake.
- `self_check` is local provisioning validation only; it does not call Elasticsearch.
- `introspect` exposes no streaming support.

## Known Contract Gaps

The runtime, manifest, and policy metadata are not fully aligned in this checkout:

- The connector uses a legacy `handle_*` method surface rather than the full typed `FcpConnector` trait implementation used by newer connectors.
- `BaseConnector` is initialized with connector ID `elasticsearch`, while the manifest and handshake payload use `fcp.elasticsearch`.
- `invoke` checks generic configured/handshaken readiness, but it does not verify a bound capability token for the requested operation.
- `simulate` only checks whether an operation ID is known; it does not validate readiness, input schema, approval state, resource constraints, or capability tokens.
- Manifest marks `elasticsearch.bulk` and `elasticsearch.index_document` as policy-approved and `elasticsearch.indices.delete` as interactive, but runtime `OperationInfo` currently sets `requires_approval` to `None` for all operations.
- Runtime base URL policy rejects ordinary self-managed HTTPS Elasticsearch hosts unless they are loopback, `.elastic-cloud.com`, or `.found.io`.
- Runtime base URL policy allows loopback by default, while manifest network constraints deny localhost for live operations.
- Runtime base URL policy does not reject query strings, fragments, or userinfo before concatenating endpoint paths.
- The provisioning recipe prompts for auth mode, API key, and base URL but only includes a `store_api_key` step; it does not include a store step for base URL or a credential-id path.
- `elasticsearch.indices.write` is included in handshake and manifest optional capabilities, but no runtime operation uses it separately from `elasticsearch.indices.delete`.
- The manifest state migration hint mentions scroll IDs for paginated searches, but runtime does not implement scroll, search-after, or stored pagination state.

Operators should treat this README as the current truthfulness snapshot. A follow-up should align the handler surface, connector ID, capability-token enforcement, approval metadata, base URL hygiene, provisioning recipe, and pagination/search state story before this connector is described as a fully modern FCP connector.

## First-Slice Scope

The current Elasticsearch README slice documents the existing runtime surface:

- API-key and credential-id configuration
- Elastic Cloud and loopback base URL policy
- search
- get document by ID
- index document with caller ID or auto-generated ID
- bulk NDJSON dispatch
- index listing through `_cat/indices`
- index deletion
- cluster health
- lifecycle, doctor, health, self-check, introspection, simulation, and shutdown surfaces
- deterministic WireMock tests for provider request paths and provider error mapping

## Auth And Scope Boundary

- Authentication mechanisms: Elasticsearch API key or host credential reference.
- Runtime does not implement username/password, bearer tokens, service-account tokens, OAuth, SAML, or API-key creation.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Capability surface:
  - `elasticsearch.search.read` gates search and get-document operations.
  - `elasticsearch.index.write` gates single-document indexing and bulk operations.
  - `elasticsearch.indices.read` gates index listing.
  - `elasticsearch.indices.delete` gates index deletion.
  - `elasticsearch.cluster.read` gates cluster health.
  - `elasticsearch.indices.write` is advertised but not used by a current runtime operation.
- The connector does not persist Elasticsearch responses, search queries, indexed documents, bulk payloads, index names, document IDs, API keys, credential IDs beyond configuration metadata, provider payloads, or provider error bodies.

## Network And Runtime Invariants

- Production host policy: `*.elastic-cloud.com` or `*.found.io`.
- Production schemes: `https` only.
- Production ports in manifest: `443` and `9243`.
- Loopback test hosts: `localhost`, `127.0.0.1`, and `::1`.
- Runtime request timeout: `30 seconds`.
- Runtime request construction appends endpoint paths to `base_url`.
- Runtime retry policy is based on `HttpRetryConfig { max_retries = 2, ..default }`.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Manifest network constraints set `10_000 ms` connect timeout and either `30_000 ms`, `60_000 ms`, or `120_000 ms` total timeout depending on operation.
- Maximum response bytes are `52_428_800` for search and bulk, `10_485_760` for document reads and index listing, and `1_048_576` for document writes, index deletion, and cluster health.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open listeners and does not implement subscriptions.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `elasticsearch.search` | `POST /{index}/_search` | `elasticsearch.search.read` | `Safe` | `Low` | `Strict` | Reads matching documents with optional query, size, from, and sort body fields. |
| `elasticsearch.get_document` | `GET /{index}/_doc/{id}` | `elasticsearch.search.read` | `Safe` | `Low` | `Strict` | Reads one document by ID. |
| `elasticsearch.index_document` | `PUT /{index}/_doc/{id}` or `POST /{index}/_doc` | `elasticsearch.index.write` | `Risky` | `Medium` | `Strict` | Creates or replaces one document, or asks Elasticsearch to assign an ID. |
| `elasticsearch.bulk` | `POST /_bulk` | `elasticsearch.index.write` | `Risky` | `Medium` | `None` | Sends caller-supplied NDJSON bulk action/source lines and may mutate or delete documents. |
| `elasticsearch.indices.list` | `GET /_cat/indices/{pattern}?format=json` | `elasticsearch.indices.read` | `Safe` | `Low` | `Strict` | Reads index metadata for a pattern, defaulting to `*`. |
| `elasticsearch.indices.delete` | `DELETE /{index}` | `elasticsearch.indices.delete` | `Dangerous` | `High` | `Strict` | Deletes an index and all documents in it. |
| `elasticsearch.cluster.health` | `GET /_cluster/health` | `elasticsearch.cluster.read` | `Safe` | `Low` | `Strict` | Reads cluster health status. |

## Explicit Non-Goals

The current implementation does not include:

- username/password auth, service-account token auth, API-key creation, role/user/security APIs, or Kibana APIs
- index create/update, mappings, settings, aliases, templates, data streams, ILM, SLM, snapshots, transforms, ingest pipelines, or reindex
- delete document, update document, update-by-query, delete-by-query, mget, msearch, count, explain, terms enum, async search, scroll, search-after, PIT, or pagination state
- vector search helpers, retriever abstractions, semantic search wrappers, or rank/eval APIs
- bulk request validation beyond JSON serialization into NDJSON lines
- connector-local credential vaulting
- webhook/event subscriptions or streaming

These are excluded on purpose:

- Runtime invocation is currently a small handler-style bridge and should stay narrow until capability enforcement is upgraded.
- Index deletion and bulk operations can destroy or rewrite large volumes of data and must remain explicit operations.
- Broader Elasticsearch coverage needs separate provider fixtures, permission modeling, pagination contracts, and payload validation.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration and handshake state
- request and error counters
- auth mode as API key or credential ID
- base URL policy and loopback verification allowance
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- simulation allow/deny based only on known operation ID
- self-check status and provisioning details without a live Elasticsearch probe

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle health, doctor, self-check, introspection, simulate, and shutdown behavior
- API-key auth header propagation
- search, get document, index document, bulk, index list, index delete, and cluster health WireMock requests
- missing required input fields
- provider 401, 403, 404, 429, and 500-class error mapping
- unknown operation and simulation behavior
- request/error counters
- configuration validation, credential-id validation, trusted-host policy, loopback allowance, and path-segment sanitation

## Source Notes

- `connectors/elasticsearch/src/connector.rs` defines configuration parsing, base URL policy, lifecycle handlers, diagnostics, simulation, operation metadata, provisioning recipe, and invoke dispatch.
- `connectors/elasticsearch/src/client.rs` defines request construction, auth headers, path-segment sanitation, timeout setup, retry dispatch, Elasticsearch API paths, NDJSON bulk dispatch, response parsing, and provider error parsing.
- `connectors/elasticsearch/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/elasticsearch/src/types.rs` defines Elasticsearch search, document, index, cluster-health, bulk, delete-index, and error response shapes.
- `connectors/elasticsearch/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, rate limits, and AI hints.
- `connectors/elasticsearch/tests/integration.rs` covers deterministic HTTP behavior and handler lifecycle behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/elasticsearch_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation contract tests
- deterministic WireMock coverage for the seven runtime operations
- auth, base URL policy, path sanitation, input validation, provider error, lifecycle, introspection, simulation, and shutdown tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a disposable Elastic Cloud deployment or WireMock fixtures for verification.
- Prefer an API key scoped only to test indices.
- Use credential-id mode only when the host or egress proxy is ready to inject Elasticsearch auth.

**Dedicated environment**:

- Keep live indexing, bulk, and delete-index checks confined to disposable indices.
- Never run index deletion or bulk deletion/update checks against production clusters.
- Use synthetic index names, document IDs, and document bodies in logs and transcripts.

**Redaction rules**:

- Redact API keys, credential IDs where needed, search queries when sensitive, document bodies, index names when sensitive, document IDs, provider payloads, provider error bodies, and local paths.
- Verification output should use operation IDs, endpoint shapes, host classes, status/error classes, retry decisions, and synthetic Elasticsearch resource identifiers.

**Common remediation**:

- If configuration fails, provide exactly one of `api_key` or `credential_id`.
- If base URL policy rejects a live cluster, use an Elastic Cloud endpoint ending in `.elastic-cloud.com` or `.found.io`, or a loopback fixture endpoint.
- If invocation fails with readiness errors, configure and handshake with a non-empty `session_id` before invoking.
- If path-segment validation rejects an index, document ID, or pattern, remove path separators, traversal sequences, and encoded slashes.
- If `_cat/indices` returns too much data, supply a narrower `pattern`.
- If provider 429 or 5xx errors appear, the runtime retry loop should retry according to the configured policy; inspect final surfaced status after retries are exhausted.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-elasticsearch-readme cargo check -p fcp-elasticsearch --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-elasticsearch-readme cargo test -p fcp-elasticsearch --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-elasticsearch-readme cargo clippy -p fcp-elasticsearch --all-targets --no-deps -- -D warnings`
- `ubs connectors/elasticsearch/README.md`
