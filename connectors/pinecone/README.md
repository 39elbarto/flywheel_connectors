# Pinecone Connector V3 Contract

> **Status**: runtime contract documented with data-plane and API-version drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Pinecone control-plane upstream**: https://docs.pinecone.io/reference/api/2025-10/control-plane/list_indexes
> **Pinecone data-plane upstream**: https://docs.pinecone.io/reference/api/2026-04/data-plane/upsert
> **Pinecone target-index guidance**: https://docs.pinecone.io/guides/manage-data/target-an-index

## Purpose

This document fixes the operator-facing contract for `fcp.pinecone`. The connector exposes the Pinecone surfaces implemented in this crate: index listing, index description, index creation and deletion, index statistics, vector query, vector fetch, vector upsert, and vector deletion.

The connector is intentionally a bounded vector-database bridge. It is not a full Pinecone SDK, integrated-embedding client, imports/backups client, namespace manager, API-key administrator, inference API client, rerank client, embedding client, project/organization administration client, or durable vector-ingestion daemon.

## Current Runtime Snapshot

The current crate exposes these operations:

- `pinecone.list_indexes`
- `pinecone.describe_index`
- `pinecone.describe_index_stats`
- `pinecone.create_index`
- `pinecone.delete_index`
- `pinecone.query`
- `pinecone.fetch`
- `pinecone.upsert`
- `pinecone.delete`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-pinecone`.
- Runtime `BaseConnector` ID is `fcp.pinecone`.
- Manifest connector ID is `fcp.pinecone`.
- Connector version is `0.1.0`.
- Configuration requires exactly one auth source:
  - `api_key`
  - `credential_id`
- `credential_id` must be a valid UUID.
- Direct API-key mode sends `Api-Key: <key>`.
- `credential_id` mode sends `X-FCP-Credential-ID` and expects host or egress-proxy credential injection.
- Default control-plane URL is `https://api.pinecone.io`.
- Optional `control_plane_url` replaces the control-plane base for tests or custom routing.
- Optional `data_plane_url` is required for vector data-plane operations in this runtime.
- Runtime does not automatically cache the `host` returned by `describe_index`.
- Runtime request timeout is `30 seconds`.
- Runtime retry config sets `max_retries = 2` through the shared retry loop.
- `health` reports local configured state and request metrics; it does not prove live provider reachability.
- `doctor` checks local configuration, client initialization, configured control-plane URL, auth mode, and credential-injection status.
- `self_check` performs `list_indexes` in direct-key mode.
- `self_check` degrades in `credential_id` mode because egress-proxy injection cannot be proven locally.
- `handshake` constructs a `CapabilityVerifier`, records a generated session ID, and returns a manifest-content SHA-256 hash.
- Runtime `invoke` uses `operation`, not `operation_id`.
- Runtime `invoke` requires `capability_token` and verifies a bound FCP capability token before dispatch.
- Runtime operation metadata sets all `requires_approval` fields to `None`; manifest marks create/upsert as policy-gated and delete/delete-index as interactive.
- `simulate` deserializes `SimulateRequest` and returns allowed without checking operation ID, configured state, handshake state, capability tokens, or approval policy.
- `handle_shutdown()` shuts down the client runtime, clears client/config/verifier/session state, and resets configured/handshaken flags.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Current Pinecone control-plane examples include a required `X-Pinecone-Api-Version` header such as `2025-10`. Current data-plane examples include a required `X-Pinecone-Api-Version` header such as `2026-04`. Runtime does not send this header.
- Current Pinecone docs recommend targeting data operations by the index host in production. Runtime supports this only when `data_plane_url` is provided during configuration; it does not discover or cache the host from `describe_index`.
- Runtime requires `index_name` in data-plane operation inputs, but then ignores it after selecting the configured `data_plane_url`.
- Manifest `pinecone.upsert` hints say batch up to 100 vectors and 2 MB, while current Pinecone docs recommend up to 1000 vectors for the shown `vectors/upsert` reference surface. Runtime does not enforce either bound.
- Manifest network constraints allow `*.pinecone.io`; runtime accepts arbitrary configured control-plane and data-plane URLs with no host policy at configure time.
- Manifest marks `pinecone.delete` and `pinecone.delete_index` as interactive approval operations, but runtime checks no approval token after capability-token verification.
- Runtime `simulate` is permissive and does not mirror invoke's operation/capability verification.
- Runtime direct API-key redaction reveals the first up-to-eight characters of the key in diagnostic labels.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should add Pinecone API-version headers, decide how to manage and cache index hosts, make data-plane inputs and routing coherent, enforce configured endpoint policy, align batch-size guidance, make simulation mirror invoke authority, and add approval-token checks for destructive or costly write operations.

## First-Slice Scope

The current Pinecone README slice documents the existing runtime surface:

- direct API-key and host credential-reference configuration
- control-plane and data-plane URL behavior
- index list/describe/create/delete and vector stats/query/fetch/upsert/delete operations
- retry, timeout, provider error, readiness, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- runtime/manifest drift around API-version headers, endpoint policy, index-host targeting, approval metadata, and simulation
- deterministic WireMock tests and direct proof commands

## Auth And Zone Boundary

- Authentication mechanisms: Pinecone API key or host credential reference.
- Official Pinecone docs require the `Api-Key` header for API calls.
- Runtime does not implement API-key creation, permissions management, service accounts, project/organization administration, OAuth, token rotation, or connector-local credential vaulting.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `pinecone.indexes.read`
  - `pinecone.indexes.write`
  - `pinecone.vectors.read`
  - `pinecone.vectors.write`
- The connector does not persist API keys, credential IDs beyond configuration metadata, vectors, metadata filters, query vectors, query results, provider payloads, provider error bodies, or usage records outside process memory.
- Pinecone vectors and metadata can embed private documents, code, customer records, and internal retrieval context. Treat live query/fetch/upsert/delete payloads as work-zone or private-zone data based on the configured index.

## Network And Runtime Invariants

- Default control-plane host: `api.pinecone.io`.
- Control-plane endpoints:
  - `GET /indexes`
  - `GET /indexes/{index_name}`
  - `POST /indexes`
  - `DELETE /indexes/{index_name}`
- Data-plane endpoints are appended to `data_plane_url`:
  - `POST /describe_index_stats`
  - `POST /query`
  - `GET /vectors/fetch`
  - `POST /vectors/upsert`
  - `POST /vectors/delete`
- Runtime request timeout: `30 seconds`.
- Runtime retry policy: `max_retries = 2`.
- Runtime retries transport timeouts/connect errors, 429 responses with `Retry-After`, and 5xx responses.
- Runtime treats 401, 403, 404, malformed JSON, and non-success non-retry status classes as terminal errors.
- Runtime path segment sanitization rejects empty index names, slashes, backslashes, NUL, `.`, and `..`.
- Runtime data-plane operations fail with a configuration error when `data_plane_url` is absent.
- Manifest live-operation policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and allows `*.pinecone.io` on port 443.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, read-only `/usr` and `/lib`, writable `$CONNECTOR_STATE`, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `pinecone.indexes.read` | List indexes, describe one index, and read index stats metadata. |
| `pinecone.indexes.write` | Create or delete an index. |
| `pinecone.vectors.read` | Query or fetch vectors. |
| `pinecone.vectors.write` | Upsert or delete vectors. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `pinecone.list_indexes` | `GET /indexes` | `pinecone.indexes.read` | `Safe` | `Low` | `Strict` | None. |
| `pinecone.describe_index` | `GET /indexes/{index_name}` | `pinecone.indexes.read` | `Safe` | `Low` | `Strict` | `index_name`. |
| `pinecone.describe_index_stats` | `POST /describe_index_stats` | `pinecone.indexes.read` | `Safe` | `Low` | `Strict` | `index_name`; optional `filter`. |
| `pinecone.create_index` | `POST /indexes` | `pinecone.indexes.write` | `Risky` | `Medium` | `BestEffort` | `name`, `dimension`; optional `metric`, `spec`. |
| `pinecone.delete_index` | `DELETE /indexes/{index_name}` | `pinecone.indexes.write` | `Dangerous` | `High` | `Strict` | `index_name`. |
| `pinecone.query` | `POST /query` | `pinecone.vectors.read` | `Safe` | `Low` | `Strict` | `index_name`, `top_k`; optional `vector` or `id`, `namespace`, `filter`, `include_metadata`, `include_values`. |
| `pinecone.fetch` | `GET /vectors/fetch` | `pinecone.vectors.read` | `Safe` | `Low` | `Strict` | `index_name`, array `ids`; optional `namespace`. |
| `pinecone.upsert` | `POST /vectors/upsert` | `pinecone.vectors.write` | `Risky` | `Medium` | `Strict` | `index_name`, array `vectors`; optional `namespace`. |
| `pinecone.delete` | `POST /vectors/delete` | `pinecone.vectors.write` | `Dangerous` | `High` | `Strict` | `index_name`; optional `ids`, `delete_all`, `namespace`, `filter`. |

## Explicit Non-Goals

The current implementation does not include:

- integrated embedding records API, text upsert/search, inference embedding, reranking, model listings, or hosted model invocation
- imports, backups, restore, namespace management, collection migration, API-key management, service accounts, project administration, or billing/cost controls
- automatic index host discovery, host cache invalidation, private endpoint management, or production target-context management
- vector chunking, local embedding generation, document loaders, metadata schema management, retrieval pipelines, or durable ingestion state
- approval-token verification for destructive operations

These are excluded on purpose:

- Vector writes and deletes can alter or destroy retrieval state used by production agents.
- Query and fetch results can expose embedded private text or metadata.
- Index creation and deletion affect cost, capacity, availability, and data durability.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration, client, session, verifier, request, and error state
- auth mode as direct API key or credential ID
- credential-injection requirement for credential-id mode
- live list-indexes self-check for direct-key mode
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- bound capability-token verification during invoke
- provider error mapping for unauthorized, forbidden, not-found, rate-limit, retryable server errors, JSON errors, and transport errors

The deterministic integration evidence is anchored on connector-local tests covering:

- control-plane parsing for list, describe, create, and delete index operations
- data-plane parsing for stats, query, fetch, upsert, and delete operations
- provider error taxonomy, rate-limit retry, server retry, redaction, and data-plane missing-URL errors
- connector-level invoke paths with generated capability tokens
- rejection of mismatched capability tokens
- auth exclusivity, credential-id parsing, custom URLs, health, doctor, self-check, shutdown, introspection, and manifest operation inventory

## Source Notes

- `connectors/pinecone/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, handshake, capability verification, introspection, simulation, invoke dispatch, operation IDs, and field validation.
- `connectors/pinecone/src/client.rs` defines Pinecone HTTP request construction, auth headers, control/data-plane routing, retry/timeout behavior, path segment sanitization, and provider error mapping.
- `connectors/pinecone/src/types.rs` defines index, stats, vector, query, fetch, upsert, and provider error envelope shapes.
- `connectors/pinecone/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/pinecone/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, rate-limit pools, and AI hints.
- `connectors/pinecone/tests/integration.rs` covers deterministic HTTP behavior and connector-level behavior.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/pinecone/README.md
ubs connectors/pinecone/README.md
LC_ALL=C rg -n '[^ -~]' connectors/pinecone/README.md
rg -n '\bmaster\b' connectors/pinecone/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-pinecone
rch exec -- cargo check -p fcp-pinecone --all-targets
rch exec -- cargo clippy -p fcp-pinecone --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Use WireMock fixtures for routine verification.
- Use disposable indexes and synthetic vectors for live mutation proof.
- Configure `data_plane_url` to the target index host before vector stats/query/fetch/upsert/delete operations.
- Do not rely on `index_name` to select a data-plane host in this runtime.
- Treat `delete_all`, metadata-filter deletes, and index deletion as high-review operations even though runtime approval checks are absent.
- Do not rely on simulation as an authorization signal; invoke is the path that verifies bound capability tokens.
- Re-check Pinecone API-version header requirements before using this runtime against live Pinecone APIs.
- Redact API keys, credential IDs where needed, vector values when sensitive, metadata fields, query filters, index names when private, provider payloads, and provider error bodies in shared logs.
