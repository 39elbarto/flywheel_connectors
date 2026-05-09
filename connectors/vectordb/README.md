# VectorDB Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Pinecone docs**: https://docs.pinecone.io/
> **Qdrant collections docs**: https://qdrant.tech/documentation/manage-data/collections/
> **Qdrant points API**: https://api.qdrant.tech/api-reference/points/upsert-points

## Purpose

This document fixes the operator-facing contract for `fcp.vectordb`. The connector currently exposes a provider-selectable vector database surface implemented in this crate: collection listing/description/creation/deletion plus vector query, fetch, upsert, delete, and metadata update.

The connector is intentionally a bounded vector-store control surface. It is not a full Pinecone SDK, Qdrant SDK, embedding service, reranker, hybrid-search planner, durable ingestion pipeline, cross-provider migration tool, or arbitrary vector database proxy.

## Current Runtime Snapshot

The current crate exposes these invoke operations:

- `vectordb.list_collections`
- `vectordb.describe_collection`
- `vectordb.create_collection`
- `vectordb.delete_collection`
- `vectordb.query_vectors`
- `vectordb.fetch_vectors`
- `vectordb.upsert_vectors`
- `vectordb.delete_vectors`
- `vectordb.update_vector_metadata`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-vectordb`.
- Runtime `BaseConnector` ID is `vectordb`.
- Manifest connector ID is `fcp.vectordb`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:58a82020b8b361edebf04f34ce0aa970dc1d6f9945bc4daeb210f6e9420c2f62`.
- Runtime handshake returns `manifest_hash = "sha256:vectordb-connector-v1"`, not the manifest interface hash.
- Configuration is deserialized as `VectorDbConfig` and requires `provider`, `endpoint`, and `credential_id`.
- Supported providers are `pinecone` and `qdrant`.
- `endpoint` must be nonempty and must not include `http://` or `https://`.
- `credential_id` must be a valid credential UUID.
- `use_tls` defaults to `true`.
- `namespace` is optional.
- `connect_timeout_ms` defaults to `10000` and must be 1..=300000.
- `request_timeout_ms` defaults to `60000` and must be 1..=600000.
- Pinecone requires TLS at config validation time.
- Qdrant may run without TLS.
- Runtime endpoint allowlist is a warning during configure, not a configure failure.
- Pinecone endpoint allowlist is `*.pinecone.io`.
- Qdrant endpoint allowlist is `*.qdrant.io` and `*.qdrant.tech`.
- Runtime `invoke` uses `operation`, not `operation_id`.
- Runtime `invoke` requires a serialized `capability_token`.
- Runtime installs a `CapabilityVerifier` during canonical handshake and verifies bound capability tokens for invoke.
- Runtime bound-token verification uses the operation ID and an empty resource URI list.
- Runtime does not verify approval tokens for policy or interactive operations.
- Runtime operations are currently synthetic/local validation handlers. They do not call Pinecone, Qdrant, or any other provider.
- `handle_configure()` stores config, sets configured, and creates a `ConnectorRuntime`.
- `handle_configure()` does not clear an existing verifier, session ID, or base handshaken state.
- `handle_handshake()` accepts a canonical `HandshakeRequest`, installs a verifier, creates a session ID, and grants requested capabilities without checking configuration.
- `health()` reports healthy when config exists; it does not require handshake, endpoint allowlist success, or provider connectivity.
- `doctor()` performs local config, endpoint-pattern, TLS, credential-ID, and assumed-connectivity checks; it does not make a provider probe.
- `self_check()` requires config, session ID, endpoint allowlist success, and provider TLS rules; it does not make a provider probe.
- `shutdown()` only shuts down the runtime reference; there is no JSON-RPC `shutdown` branch in `src/main.rs`.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Manifest operation IDs are unprefixed (`create_collection`, `query_vectors`, and so on), while runtime invoke and introspection use `vectordb.*` operation IDs.
- Manifest and runtime both document provider network constraints, but runtime operations do not open HTTP or gRPC connections.
- `list_collections` and `describe_collection` declare no-egress sentinels because their current runtime handlers return local synthetic data instead of provider results.
- Manifest marks `create_collection`, `upsert_vectors`, and `delete_vectors` as policy-approved and `delete_collection` as interactive approval. Runtime `OperationInfo` includes approval metadata, but invoke checks no approval token.
- Runtime verifies bound capability tokens for invoke, but it does not bind tokens to collection, namespace, vector IDs, endpoint, or provider resources.
- Runtime `simulate()` deserializes only canonical `SimulateRequest`, checks configured state and operation existence, and does not verify capability tokens or input schemas.
- Manifest network constraints deny localhost and private ranges. Runtime config accepts Qdrant endpoints such as `localhost:6333`; `self_check()` later fails endpoint allowlist for that endpoint.
- Runtime endpoint allowlist suffix matching treats any host ending in `.pinecone.io`, `.qdrant.io`, or `.qdrant.tech` as allowed after lowercasing and stripping a port. It does not parse a URL, reject userinfo, reject path/query/fragment text, or canonicalize hostnames.
- Runtime stores `retry_config.max_retries = 2`, but direct invoke paths do not use a retry loop.
- Manifest rate-limit pools are documented intent; runtime has no connector-local rate-limit enforcement.
- Manifest state model is singleton-writer. Runtime stores configuration, verifier, session, metrics, and runtime handle only in process memory.
- `vectordb.list_collections` returns an empty list.
- `vectordb.describe_collection` returns synthetic metadata with dimension `1536`, metric `cosine`, status `ready`, vector count `0`, and current timestamp.
- `vectordb.create_collection`, `delete_collection`, `upsert_vectors`, `delete_vectors`, and `update_vector_metadata` validate input and return synthetic success shapes.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should align manifest and runtime operation IDs, decide whether this connector is a mock contract harness or must call real Pinecone/Qdrant APIs, add approval-token verification, add collection/namespace/vector resource binding to capability checks, tighten endpoint parsing, reconcile localhost test support with manifest network policy, wire or remove retry/rate-limit metadata, and add a tracked verification bundle.

## First-Slice Scope

The current VectorDB README slice documents the existing runtime surface:

- Pinecone/Qdrant provider selection and credential-reference configuration
- collection and vector operation catalog
- bound capability-token verification for invoke
- synthetic provider behavior and local input validation
- endpoint allowlist and TLS readiness checks
- lifecycle, health, doctor, self-check, simulation, introspection, and runtime shutdown behavior
- runtime/manifest drift around operation IDs, provider calls, approvals, network policy, retries, rate limits, and persistence
- deterministic connector tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanism: host-injected `credential_id` only.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability surface:
  - `vectordb.collections.read`
  - `vectordb.collections.write`
  - `vectordb.collections.delete`
  - `vectordb.vectors.read`
  - `vectordb.vectors.write`
  - `vectordb.vectors.delete`
- Invoke rejects missing, malformed, wrong-operation, wrong-instance, wrong-zone, or wrong-capability tokens.
- Invoke does not verify approval tokens.
- The connector does not persist credential IDs, collection metadata, vector values, vector IDs, query vectors, filters, provider responses, or runtime metrics outside process memory.
- Vector metadata and retrieval payloads can contain private, work, or regulated data. Treat live output according to the configured provider and collection namespace.

## Runtime And Provider Invariants

- `provider` must be `pinecone` or `qdrant`.
- `endpoint` is configured without protocol.
- `VectorDbConfig::url()` derives `https://{endpoint}` when `use_tls = true` and `http://{endpoint}` when false.
- Pinecone default port metadata is 443.
- Qdrant default port metadata is 6333.
- Collection names for create must match `^[a-z][a-z0-9_-]*$`.
- Collection create `dimension` must be 1..=10000.
- Collection create `metric` may be `cosine`, `euclidean`, or `dotproduct`.
- Collection delete requires `confirm = true`.
- Query vectors require a nonempty numeric `vector`.
- Query `top_k` defaults to 10 and must be 1..=10000.
- Fetch IDs must be a nonempty string array with at most 1000 entries.
- Upsert batches must contain 1..=1000 vector objects.
- Upsert vector IDs must be 1..=512 characters.
- Upsert vector values must be a nonempty numeric array.
- Upsert vector `metadata` and `sparse_values` must be objects when present.
- Delete vectors requires `ids`, `filter`, or `delete_all = true`.
- Metadata update requires `collection`, `id`, and object `metadata`.
- Request/error metrics are recorded through `BaseConnector::record_request`.
- No provider socket, background queue, native listener, embedding call, rerank call, or durable ingestion loop is started by this connector.

## Operation Inventory

| Operation | Runtime behavior | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|------------------|------------|------------|-----------|-------------|----------------|
| `vectordb.list_collections` | Validate optional namespace and return empty `collections` | `vectordb.collections.read` | `Safe` | `Low` | `None` | none |
| `vectordb.describe_collection` | Return synthetic metadata for a collection | `vectordb.collections.read` | `Safe` | `Low` | `None` | `collection` |
| `vectordb.create_collection` | Validate collection schema and return synthetic created status | `vectordb.collections.write` | `Risky` | `Medium` | `BestEffort` | `collection`, `dimension` |
| `vectordb.delete_collection` | Require `confirm = true` and return synthetic deletion | `vectordb.collections.delete` | `Dangerous` | `High` | `BestEffort` | `collection`, `confirm` |
| `vectordb.query_vectors` | Validate query vector/top_k/filter shape and return empty matches | `vectordb.vectors.read` | `Safe` | `Low` | `None` | `collection`, `vector` |
| `vectordb.fetch_vectors` | Validate IDs and return placeholder vectors keyed by ID | `vectordb.vectors.read` | `Safe` | `Low` | `None` | `collection`, `ids` |
| `vectordb.upsert_vectors` | Validate batch/vector shape and return `upserted_count` | `vectordb.vectors.write` | `Risky` | `Medium` | `BestEffort` | `collection`, `vectors` |
| `vectordb.delete_vectors` | Validate delete criteria and return count for explicit IDs | `vectordb.vectors.delete` | `Risky` | `Medium` | `BestEffort` | `collection` plus `ids`, `filter`, or `delete_all` |
| `vectordb.update_vector_metadata` | Validate metadata object and return `updated = true` | `vectordb.vectors.write` | `Safe` | `Low` | `BestEffort` | `collection`, `id`, `metadata` |

## Explicit Non-Goals

The current implementation does not include:

- actual Pinecone or Qdrant HTTP/gRPC calls
- provider-specific auth header injection, API-key handling, or host egress-proxy implementation
- vector dimensionality discovery from a real collection
- real collection/index creation, deletion, listing, metadata reads, query, fetch, upsert, delete, or metadata mutation
- embedding generation, sparse encoding, text search, reranking, namespace provisioning, import jobs, backups, snapshots, or provider migration
- pagination, streaming result cursors, durable ingestion checkpoints, retry loops, rate-limit pools, or cache storage
- approval-token verification or resource-bound capability checks
- native listeners, webhooks, or provider event subscriptions

These are excluded on purpose:

- Vector stores often contain private documents, retrieval metadata, and derived embeddings.
- Collection deletion and vector deletion can irreversibly remove retrieval state.
- A provider-generic vector API must not hide whether it is a validation harness or a real provider client.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configured/unconfigured state, provider, request/error metrics, endpoint pattern readiness, TLS readiness, and redacted credential ID prefix
- degraded readiness for missing config or missing handshake
- failed self-check for endpoint mismatch or TLS mismatch
- typed introspection with operations, schemas, capability IDs, risk levels, safety tiers, idempotency, and approval metadata
- simulation would-succeed/failure state for configured and known-operation checks only
- FCP error mapping for malformed config, missing operation, missing capability token, bad capability token, capability mismatch, missing fields, bounds violations, and unsupported operations

The deterministic integration evidence is anchored on connector-local tests covering:

- configuration, provider display/default ports/TLS requirements, endpoint allowlists, timeout bounds, serde round trips, health, doctor, self-check, simulate, handshake, metrics, and main dispatch
- all nine operations, required fields, payload bounds, collection-name policy, query bounds, vector batch bounds, delete criteria, and metadata validation
- capability-token enforcement per operation, wrong-capability denial, redaction, idempotency, risk levels, safety tiers, and introspection completeness
- logged evidence for schema completeness, error taxonomy, capability gating, redaction, retry/idempotency classification, payload bounds, lifecycle, and deterministic introspection

## Source Notes

- `connectors/vectordb/src/lib.rs` defines lifecycle handlers, operation catalog, capability verification, synthetic invoke behavior, simulation, introspection, and runtime metrics.
- `connectors/vectordb/src/config.rs` defines provider selection, endpoint/TLS/timeout validation, endpoint allowlists, doctor result types, and config tests.
- `connectors/vectordb/src/main.rs` defines JSON-RPC dispatch for configure, handshake, health, doctor, self_check, simulate, introspect, and invoke.
- `connectors/vectordb/manifest.toml` defines the manifest operation catalog, network constraints, sandbox boundary, zone policy, approval intent, rate-limit intent, and state intent.
- `connectors/vectordb/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/vectordb/README.md
ubs connectors/vectordb/README.md
LC_ALL=C rg -n '[^ -~]' connectors/vectordb/README.md
rg -n '\bmaster\b' connectors/vectordb/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-vectordb
rch exec -- cargo check -p fcp-vectordb --all-targets
rch exec -- cargo clippy -p fcp-vectordb --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Treat this connector as a local validation/capability contract until provider calls are implemented.
- Use Qdrant local endpoints only for deterministic tests; production readiness requires endpoint policy alignment.
- Treat collection create/delete, vector upsert/delete, and metadata mutation as high-review operations until approval verification is implemented.
- Do not rely on `health()` as provider readiness; it only checks configured state.
- Do not rely on `simulate()` as authorization proof; it does not verify capability tokens.
- Do not rely on manifest rate-limit pools as runtime enforcement.
