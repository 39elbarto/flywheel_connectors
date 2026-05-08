# Qdrant Connector V3 Contract

> **Status**: runtime contract documented; Qdrant endpoint-policy drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Qdrant interfaces upstream**: https://qdrant.tech/documentation/interfaces/
> **Qdrant cluster access upstream**: https://qdrant.tech/documentation/cloud/cluster-access/
> **Qdrant security upstream**: https://qdrant.tech/documentation/guides/security/
> **Qdrant collections upstream**: https://qdrant.tech/documentation/concepts/collections/
> **Qdrant points upstream**: https://qdrant.tech/documentation/manage-data/points/
> **Qdrant search upstream**: https://qdrant.tech/documentation/search/search/
> **Qdrant Cloud management API upstream**: https://qdrant.tech/documentation/cloud-api/

## Purpose

This document fixes the operator-facing contract for `fcp.qdrant`. The connector exposes the Qdrant database REST surface implemented in this crate: collection listing, collection inspection, collection creation/deletion, vector search/query, point retrieval, scroll, count, upsert, and point deletion.

The connector is intentionally a bounded Qdrant database bridge. It is not a Qdrant Cloud account/project/cluster management client, embedding model service, vectorization pipeline, schema migration engine, snapshot/restore orchestrator, distributed query planner, webhook listener, gRPC adapter, or Qdrant SDK wrapper.

## Current Runtime Snapshot

The current stdio runtime exposes these operations:

- `qdrant.list_collections`
- `qdrant.collection_info`
- `qdrant.create_collection`
- `qdrant.delete_collection`
- `qdrant.search`
- `qdrant.query_points`
- `qdrant.batch_query_points`
- `qdrant.get_points`
- `qdrant.scroll`
- `qdrant.count`
- `qdrant.upsert_points`
- `qdrant.delete_points`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-qdrant`.
- Manifest ID is `fcp.qdrant`.
- `BaseConnector` runtime ID is `qdrant`.
- Manifest version is `0.1.0`.
- Manifest format is `wasi`.
- Configuration requires `cluster_url`.
- Configuration requires exactly one auth source:
  - `api_key`
  - `credential_id`
- Direct API-key mode sends the `api-key` header.
- `credential_id` must be a valid UUID.
- `credential_id` mode stores config but does not create a `QdrantClient`; direct API calls require token materialization outside the current runtime.
- Runtime `cluster_url` must be an absolute `http` or `https` URL with a host, root path, no userinfo, no query, and no fragment.
- Runtime configure trims a trailing slash from `cluster_url`.
- Runtime configure does not enforce the manifest host allowlist.
- Runtime request timeout is 30 seconds.
- Runtime request-context timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 2`.
- `health()` reports client/config state and request metrics. It does not require handshake state.
- `doctor()` performs local config checks and, in direct API-key mode, a live read-only `list_collections` probe.
- `self_check()` performs a live read-only `list_collections` probe only when a direct API-key client exists.
- Runtime `invoke` uses the JSON field `operation`, not `operation_id`.
- Runtime `invoke` requires a deserializable, bound `CapabilityToken`.
- Runtime `invoke` verifies the bound capability token against operation capability and operation ID.
- Runtime `simulate` validates operation, input shape, configured client state, handshake verifier state, and bound capability token.
- Runtime `simulate` does not call Qdrant.
- Runtime `shutdown()` calls client shutdown and returns `{ "status": "shutdown" }`.
- Runtime `shutdown()` does not clear config, client, verifier, session, or base lifecycle state.
- The `FcpConnector` trait `introspect()` implementation exposes only `qdrant.list_collections`; the stdio `handle_introspect()` response exposes all 12 operations.

## Runtime API Adapter

The runtime uses these request shapes:

| Operation | Runtime request | Required input | Output handling |
|-----------|-----------------|----------------|-----------------|
| `qdrant.list_collections` | `GET /collections` | none | Reads `result.collections`, defaulting to an empty list. |
| `qdrant.collection_info` | `GET /collections/{collection_name}` | `collection_name` | Reads `result`, defaulting to `{}`. |
| `qdrant.create_collection` | `PUT /collections/{collection_name}` | `collection_name`, `vectors` | Forwards vector/config fields and returns `status` plus a local receipt. |
| `qdrant.delete_collection` | `DELETE /collections/{collection_name}` | `collection_name` | Returns `status` plus a local receipt. |
| `qdrant.search` | `POST /collections/{collection_name}/points/search` | `collection_name` at invoke time | Forwards optional vector search fields and returns `result` array. |
| `qdrant.query_points` | `POST /collections/{collection_name}/points/query` | `collection_name`, `query` | Forwards query controls and returns either `result` array or `result.points`. |
| `qdrant.batch_query_points` | `POST /collections/{collection_name}/points/query/batch` with `{ "searches": queries }` | `collection_name`, `queries` array | Returns `result` array. |
| `qdrant.get_points` | `POST /collections/{collection_name}/points` | `collection_name` at invoke time | Forwards optional `ids`, `with_payload`, and `with_vectors`; returns `result` array. |
| `qdrant.scroll` | `POST /collections/{collection_name}/points/scroll` | `collection_name` | Returns `result` object, defaulting to empty points and null next offset. |
| `qdrant.count` | `POST /collections/{collection_name}/points/count` | `collection_name` | Returns `count`, defaulting to `0`. |
| `qdrant.upsert_points` | `PUT /collections/{collection_name}/points` | `collection_name`, `points` | Sends `{ "points": points }` and returns `status` plus a local receipt. |
| `qdrant.delete_points` | `POST /collections/{collection_name}/points/delete` | `collection_name` | Forwards optional `points` and `filter`; returns `status` plus a local receipt. |

Collection path handling is deliberately restrictive:

- Empty or whitespace-only collection names are rejected.
- Slashes, backslashes, null bytes, `.`, and `..` are rejected.
- Accepted collection names are inserted into request paths without percent encoding.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Current Qdrant documentation separates database REST/gRPC endpoints from the Qdrant Cloud management API. Runtime targets the database REST API, not the Cloud management API.
- Manifest network constraints allow only `*.cloud.qdrant.io` on ports `443`, `6333`, and `6334`, deny localhost, deny private ranges, require TLS/SNI, and cap redirects at three. Runtime configure accepts any root `http` or `https` URL with a host.
- Runtime doctor accepts HTTPS or local test hosts. Runtime configure also accepts non-local HTTP URLs; doctor later marks them failed.
- `credential_id` mode cannot issue direct Qdrant API requests in the current runtime because no HTTP client is created. Health reports degraded pending materialization, and self-check reports `not_configured`.
- Handshake grants every requested capability without filtering against the manifest optional capability list.
- Handshake returns the hardcoded manifest hash `sha256:qdrant-connector-v1`, not the manifest interface hash.
- Runtime introspection reports no `requires_approval` metadata for write or delete operations.
- Manifest operation approval modes mark create/upsert as policy and delete operations as interactive. Runtime invokes do not enforce approval tokens.
- Manifest rate-limit pools exist for collections-read, collections-write, points-read, and points-write operations. Runtime introspection reports no rate-limit metadata and the client does not enforce those manifest pools.
- Manifest response caps vary by operation. Runtime does not enforce those response byte caps before parsing JSON.
- `simulate` requires `vector` and `limit` for `qdrant.search`, but `invoke` requires only `collection_name` and may send an empty search body.
- `simulate` requires `ids` for `qdrant.get_points`, but `invoke` requires only `collection_name` and may send an empty request body.
- `qdrant.delete_points` allows a request with neither `points` nor `filter`; a follow-up should require one selector before sending a destructive provider call.
- Invoke without a verifier returns `NotConfigured` instead of `NotHandshaken`.
- The `FcpConnector` trait `introspect()` and stdio `handle_introspect()` operation catalogs are inconsistent.
- Shutdown does not clear runtime lifecycle state.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should enforce production endpoint policy before invoke, complete credential-ID materialization, filter granted capabilities during handshake, expose approval and rate-limit metadata, require selectors for destructive point deletion, align invoke validation with simulate and manifest schemas, fix trait/stdio introspection parity, and decide whether shutdown should clear lifecycle state.

## First-Slice Scope

The current Qdrant README slice documents the existing runtime surface:

- API-key and credential-ID configuration
- database REST endpoint handling
- collection read/write/delete operations
- point read/write/delete operations
- vector search, query, batch query, scroll, and count behavior
- lifecycle, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- provider error mapping, retry behavior, timeout behavior, redaction, and collection path validation
- runtime/manifest/provider-doc drift around endpoint policy, credential materialization, approvals, rate limits, input validation, introspection, and shutdown
- deterministic WireMock integration tests plus optional real Qdrant testcontainer coverage

## Auth And Zone Boundary

- Authentication mechanisms: direct Qdrant API key or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability families:
  - `qdrant.collections.read`
  - `qdrant.collections.write`
  - `qdrant.points.read`
  - `qdrant.points.write`
- Manifest required capabilities are `network.dns`, `network.egress`, and `network.tls.sni`.
- Manifest forbids `system.exec`, `network.listen`, `media.upload`, and `media.download`.
- The connector does not intentionally persist API keys, credential IDs beyond configuration metadata, vector payloads, provider responses, provider errors, request metrics, receipts, or query results outside process memory.
- Qdrant payloads can contain private embeddings, document chunks, metadata, search results, tenant IDs, and operational collection details. Treat live output as work-zone sensitive data unless the host supplies a stricter zone policy.

## Network And Runtime Invariants

- Runtime requires caller-provided `cluster_url`; there is no default Qdrant endpoint.
- Direct API-key requests use the `api-key` header.
- Runtime configure accepts `http` or `https` URLs with root path only.
- Runtime doctor accepts HTTPS or loopback test hosts.
- Runtime client timeout is 30 seconds.
- Runtime request-context timeout is 30 seconds.
- Manifest operation network policy allows `*.cloud.qdrant.io` on ports `443`, `6333`, and `6334`, requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, caps redirects at three, and caps response sizes by operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets.
- Provider 401 and 403 map to unauthorized.
- Provider 404 maps to resource not found.
- Provider 429 maps to rate limited and honors `Retry-After` seconds, defaulting to 60 seconds when absent.
- Provider 5xx responses are retryable external errors.
- Timeout and connect failures are retryable.
- Other provider errors are terminal external API errors with redacted messages.

## Capability Families

| Capability | Purpose |
|------------|---------|
| `qdrant.collections.read` | List collections and inspect collection metadata. |
| `qdrant.collections.write` | Create or delete collections. |
| `qdrant.points.read` | Search, query, retrieve, scroll, and count points. |
| `qdrant.points.write` | Upsert or delete points. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `qdrant.list_collections` | `GET /collections` | `qdrant.collections.read` | `Safe` | `Low` | `Strict` | Reads collection inventory. |
| `qdrant.collection_info` | `GET /collections/{collection_name}` | `qdrant.collections.read` | `Safe` | `Low` | `Strict` | Reads collection config and statistics. |
| `qdrant.create_collection` | `PUT /collections/{collection_name}` | `qdrant.collections.write` | `Risky` | `Medium` | `None` | Creates collection schema/storage. |
| `qdrant.delete_collection` | `DELETE /collections/{collection_name}` | `qdrant.collections.write` | `Dangerous` | `High` | `Strict` | Deletes a collection and all points. |
| `qdrant.search` | `POST /collections/{collection_name}/points/search` | `qdrant.points.read` | `Safe` | `Low` | `Strict` | Runs vector similarity search. |
| `qdrant.query_points` | `POST /collections/{collection_name}/points/query` | `qdrant.points.read` | `Safe` | `Low` | `Strict` | Runs the query API with optional ranking/filter controls. |
| `qdrant.batch_query_points` | `POST /collections/{collection_name}/points/query/batch` | `qdrant.points.read` | `Safe` | `Low` | `Strict` | Batches independent vector queries. |
| `qdrant.get_points` | `POST /collections/{collection_name}/points` | `qdrant.points.read` | `Safe` | `Low` | `Strict` | Retrieves points by IDs when IDs are supplied. |
| `qdrant.scroll` | `POST /collections/{collection_name}/points/scroll` | `qdrant.points.read` | `Safe` | `Low` | `Strict` | Iterates points with optional filter and pagination. |
| `qdrant.count` | `POST /collections/{collection_name}/points/count` | `qdrant.points.read` | `Safe` | `Low` | `Strict` | Counts points with optional filter. |
| `qdrant.upsert_points` | `PUT /collections/{collection_name}/points` | `qdrant.points.write` | `Risky` | `Medium` | `Strict` | Inserts or updates vector points. |
| `qdrant.delete_points` | `POST /collections/{collection_name}/points/delete` | `qdrant.points.write` | `Dangerous` | `High` | `Strict` | Deletes points by ID list or filter when supplied. |

## Resource URIs

Runtime capability-token verification currently checks capability and operation ID, but passes an empty resource binding list to the verifier. The effective local authorization binding is capability plus operation, not a collection or point URI.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| Collections | `qdrant://collection/{collection_name}` |
| Point search/query | `qdrant://collection/{collection_name}/points/query` |
| Point IDs | `qdrant://collection/{collection_name}/points/{point_id}` |
| Point collection mutation | `qdrant://collection/{collection_name}/points` |

## Explicit Non-Goals

The current implementation does not include:

- Qdrant Cloud account, project, or cluster management
- Qdrant snapshot create/restore
- gRPC transport
- Embedding generation or document chunking
- Schema migration planning
- Tenant-aware routing
- Collection alias management
- Shard, replica, optimizer, or quantization policy orchestration beyond forwarding create-collection fields
- Payload index management
- Streaming subscriptions or inbound event delivery
- Durable sync, replay, or cache storage
- Cross-collection federation

## Test And Verification Contract

The tracked tests use deterministic WireMock servers by default. They cover:

- configure, handshake, health, doctor, self-check, introspect, simulate, invoke, and shutdown paths
- direct API-key mode
- credential-ID validation and degraded materialization behavior
- all 12 stdio operations
- capability-token success and denial paths
- simulate success and denial paths
- missing required fields for stricter simulate paths
- provider 401, 403, 404, 429, and 500 responses
- JSON parse failures
- redaction of sensitive tokens in error messages
- request metrics
- operation receipts for mutating calls

The optional `integration-testcontainer` feature adds real Qdrant coverage through Docker/testcontainers for collection lifecycle, upsert/count, cosine search, scroll pagination, and deleted-collection 404 behavior.

Before committing README-only changes for this connector, run:

```bash
git diff --check -- connectors/qdrant/README.md
LC_ALL=C rg -n '[^ -~]' connectors/qdrant/README.md
rg -n '\bmaster\b' connectors/qdrant/README.md
ubs connectors/qdrant/README.md
```

No Cargo/rch lane is required for README-only edits. Any runtime or test change must use the workspace verification lanes described in the root `AGENTS.md`.
