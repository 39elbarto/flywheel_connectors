# Algolia Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://www.algolia.com/doc/rest-api/search

## Purpose

This document fixes the operator-facing contract for `fcp.algolia`. The connector exposes a narrow Algolia Search API surface for index listing, index search, record lookup, and record deletion.

The connector is intentionally an Algolia Search bridge, not a full Algolia administration client. It does not configure index settings, browse every record, manage API keys, create or update records, run analytics, or expose personalization and recommendation surfaces.

## Current Runtime Snapshot

The current crate exposes these operations:

- `algolia.indices.list`
- `algolia.search`
- `algolia.records.get`
- `algolia.records.delete`

Important runtime truths the contract preserves:

- Configuration requires `application_id` and `api_key`.
- Optional `base_url` overrides are accepted only after URL hygiene checks reject userinfo, query strings, fragments, and unparseable URLs.
- Default base URL is `https://{application_id}.algolia.net/1`.
- Runtime endpoint policy accepts HTTPS hosts under `algolia.net` or `algolianet.com`; localhost, `127.0.0.1`, and `::1` are accepted for deterministic tests.
- All live requests send `X-Algolia-Application-Id` and `X-Algolia-API-Key`.
- `AlgoliaAuth` debug output and redacted labels avoid logging the API key.
- HTTP client timeout is `30 seconds`.
- The connector retries through the shared connector runtime with a maximum of two retries.
- `algolia.search` calls `POST /indexes/{index_name}/query`.
- `algolia.indices.list` calls `GET /indexes`.
- `algolia.records.get` calls `GET /indexes/{index_name}/{object_id}`.
- `algolia.records.delete` calls `DELETE /indexes/{index_name}/{object_id}`.
- `index_name` and `object_id` are required strings where used.
- Search input requires `index_name` and `query`; optional `hits_per_page` is forwarded when present.
- Upstream 401, 403, 404, 429, and other provider failures are mapped into FCP external/auth/rate-limit errors.

## First-Slice Scope

The current Algolia README slice documents the existing runtime surface:

- direct Application ID plus API key configuration
- Search API base URL construction and custom base URL hygiene
- index listing
- index search
- record lookup by object ID
- record deletion by object ID
- provider error mapping, retry behavior, and redaction posture
- lifecycle, introspection, simulation, doctor, self-check, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanism: Algolia Application ID plus API key.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Capability surface:
  - `algolia.indices.read` gates index listing.
  - `algolia.search.read` gates search.
  - `algolia.records.read` gates direct record reads.
  - `algolia.records.delete` gates direct record deletion.
- The manifest also declares optional `algolia.records.write`, but the current runtime does not expose a write/create/update operation.
- The connector does not persist queries, records, index names, object IDs, API keys, provider payloads, or provider error bodies.

## Network And Runtime Invariants

- Default production host shape: `{application_id}.algolia.net`.
- Production alternate host family: `*.algolianet.com`.
- Production API prefix: `/1`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback overrides are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints set total timeout `10_000 ms` for search, record get, and record delete; index listing allows `15_000 ms`.
- Maximum response bytes are `10_485_760` for search and index listing, and `1_048_576` for record get and delete.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `algolia.indices.read` | List Algolia indices visible to the configured key. |
| `algolia.search.read` | Search records in a named index. |
| `algolia.records.read` | Fetch one record by index name and object ID. |
| `algolia.records.delete` | Delete one record by index name and object ID. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `algolia.indices.list` | `GET /indexes` | `algolia.indices.read` | `Safe` | `Low` | `Strict` | Read-only index inventory for routing search and record operations. |
| `algolia.search` | `POST /indexes/{index_name}/query` | `algolia.search.read` | `Safe` | `Low` | `Strict` | Read-only search over caller-supplied query text. |
| `algolia.records.get` | `GET /indexes/{index_name}/{object_id}` | `algolia.records.read` | `Safe` | `Low` | `Strict` | Read-only direct record lookup. |
| `algolia.records.delete` | `DELETE /indexes/{index_name}/{object_id}` | `algolia.records.delete` | `Dangerous` | `High` | `Strict` | Destructive record deletion; manifest marks it for interactive approval. |

## Explicit Non-Goals

The current implementation does not include:

- index creation, deletion, settings updates, synonyms, rules, replicas, or analytics
- record create, update, partial update, batch write, or browse-all operations
- secured API key generation or provider key management
- Personalization, Recommend, Query Suggestions, or DocSearch-specific APIs
- webhooks, background indexing, crawler orchestration, or connector-side search UI
- FCP subscription-based streaming
- connector-local credential vaulting

These are excluded on purpose:

- The useful first slice keeps read and destructive boundaries explicit.
- Record deletion needs a dedicated high-risk capability and manifest approval posture.
- Broader Algolia administration surfaces need separate capability contracts before exposure.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration and handshake state
- request and error counters
- generated effective base URL
- network policy acceptance for the configured base URL
- API client initialization state
- four operation descriptors with capability, risk, safety tier, and idempotency metadata
- simulation denial for unsupported operation IDs

The deterministic integration evidence is anchored on connector-local tests covering:

- configuration requirements for `application_id`, `api_key`, and clean `base_url`
- base URL policy acceptance and rejection
- auth header propagation
- search, indices list, record get, and record delete loopback requests
- provider 401, 403, 404, 429, malformed JSON, and retryability behavior
- manifest operation inventory, rate-limit pools, and network constraints
- lifecycle, health, doctor, self-check, simulation, and shutdown behavior

## Source Notes

- `connectors/algolia/src/connector.rs` defines configuration parsing, base URL hygiene, lifecycle handlers, diagnostics, introspection, simulation, and invoke dispatch.
- `connectors/algolia/src/client.rs` defines the Search API request paths, auth headers, timeout, retry config, URL construction, and provider error mapping.
- `connectors/algolia/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/algolia/manifest.toml` defines operation schemas, network constraints, sandbox boundary, zone policy, rate limits, and AI hints.
- `connectors/algolia/tests/integration.rs` covers deterministic HTTP behavior and manifest/runtime contract checks.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/algolia_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime operation agreement
- deterministic WireMock coverage for all four operations
- auth, URL policy, input validation, provider error, lifecycle, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a test Algolia application and API key for live provider verification.
- Use a key scoped tightly to the operations being tested.
- Use WireMock loopback fixtures for routine proof.

**Dedicated environment**:

- Keep live searches synthetic and non-sensitive.
- Keep destructive delete verification confined to disposable test indices and disposable records.
- Do not use a search-only API key for `algolia.records.get` or `algolia.records.delete` if the upstream key lacks the required ACL.

**Redaction rules**:

- Redact API keys, provider error bodies, private index names, sensitive object IDs, query text, record payloads, and search hits.
- Verification output should use operation IDs, endpoint shapes, host classes, result counts, status/error classes, retry decisions, and redacted auth labels.

**Common remediation**:

- If configuration fails, provide non-empty `application_id` and `api_key`.
- If base URL validation fails, remove userinfo, query strings, and fragments, then use an HTTPS Algolia host or a loopback test origin.
- If `self_check` reports invalid network constraints, use the default generated Algolia URL or a manifest-allowed production host.
- If search fails validation, provide `index_name` and `query`, and keep `hits_per_page` numeric.
- If direct record lookup or delete fails, verify the API key ACL and confirm the target index is not a read-only replica.
- If the upstream returns 429, respect retry-after behavior where present and let caller-owned retry scheduling decide when to reissue.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-algolia-readme cargo check -p fcp-algolia --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-algolia-readme cargo test -p fcp-algolia --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-algolia-readme cargo clippy -p fcp-algolia --all-targets --no-deps -- -D warnings`
