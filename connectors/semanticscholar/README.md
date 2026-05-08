# Semantic Scholar Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://api.semanticscholar.org/api-docs/graph

## Purpose

This document fixes the operator-facing contract for `fcp.semanticscholar`. The connector exposes the Semantic Scholar Academic Graph read surface implemented in this crate: paper search, paper detail, citation and reference traversal, recommendations, author detail, and author papers.

The connector is intentionally a read-only academic graph bridge. It does not download datasets, retrieve PDFs, scrape article pages, mutate Semantic Scholar account state, or store scholarly metadata locally.

## Current Runtime Snapshot

The current crate exposes these operations:

- `semanticscholar.paper.search`
- `semanticscholar.paper.get`
- `semanticscholar.paper.citations`
- `semanticscholar.paper.references`
- `semanticscholar.paper.recommendations`
- `semanticscholar.author.get`
- `semanticscholar.author.papers`

Important runtime truths the contract preserves:

- Configuration accepts one of `api_key`, `credential_id`, or no auth.
- Configuration rejects simultaneous `api_key` and `credential_id`.
- API-key mode sends `x-api-key: ...`.
- Credential-id mode sends `X-FCP-Credential-Id: ...`.
- Credential IDs must be valid UUIDs.
- No-auth mode is supported for public Semantic Scholar access and reports degraded self-check status after a successful probe because public rate limits are lower.
- Default base URL is `https://api.semanticscholar.org/graph/v1`.
- Production base URLs must use HTTPS and host `api.semanticscholar.org`.
- Loopback base URLs are accepted only for deterministic tests.
- Base URLs are trimmed and trailing slashes are removed.
- Default HTTP timeout is `30_000 ms`.
- Health probing calls `/paper/search?query=transformers&fields=paperId&limit=1&offset=0`.
- Paper and author path IDs are rejected when empty, slash-bearing, backslash-bearing, path-traversing, or encoded slash/backslash-bearing.
- `semanticscholar.paper.search` calls `GET /paper/search`.
- Paper-search `limit` defaults to 10 and is bounded to 1 through 100.
- Paper-search `offset` must be non-negative.
- `semanticscholar.paper.get` calls `GET /paper/{paper_id}`.
- `semanticscholar.paper.citations` calls `GET /paper/{paper_id}/citations`.
- `semanticscholar.paper.references` calls `GET /paper/{paper_id}/references`.
- Citation and reference list `limit` values are bounded to 1 through 1000.
- `semanticscholar.paper.recommendations` calls `GET /paper/{paper_id}/recommendations`.
- Recommendation `limit` values are bounded to 1 through 500.
- `semanticscholar.author.get` calls `GET /author/{author_id}`.
- `semanticscholar.author.papers` calls `GET /author/{author_id}/papers`.
- Author paper list `limit` values are bounded to 1 through 1000.
- Default field lists are supplied per operation when callers omit `fields`.
- 401, 403, 404, 429, and generic API errors are mapped into connector error classes.

## First-Slice Scope

The first Semantic Scholar README slice documents the existing runtime surface:

- paper search through `GET /paper/search`
- paper detail through `GET /paper/{paper_id}`
- paper citations through `GET /paper/{paper_id}/citations`
- paper references through `GET /paper/{paper_id}/references`
- paper recommendations through `GET /paper/{paper_id}/recommendations`
- author detail through `GET /author/{author_id}`
- author papers through `GET /author/{author_id}/papers`
- API-key, host credential reference, and public no-auth modes
- production and loopback base URL policy
- paper ID, author ID, fields, limit, and offset validation
- provider timeout, unauthorized, forbidden, not-found, rate-limit, and generic API error mapping
- lifecycle, introspection, simulation, doctor, self-check, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: Semantic Scholar API key, host credential reference, or public no-auth access.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden source zones: `z:public` and `z:community`.
- Capability surface:
  - `semanticscholar.papers.read` gates paper search, paper detail, citations, references, and recommendations.
  - `semanticscholar.authors.read` gates author detail and author papers.
- The connector does not persist queries, paper IDs, author IDs, titles, abstracts, citation graphs, recommendation results, API keys, or credential IDs.
- Credential-id mode forwards the credential reference header; host-side credential materialization remains outside this connector.

## Network And Runtime Invariants

- Production host: `api.semanticscholar.org`.
- Production path root: `/graph/v1`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback overrides are test-only.
- Runtime default request timeout: `30_000 ms`.
- Manifest paper and author detail operations set total timeout `30_000 ms`.
- Manifest graph-list operations set total timeout `60_000 ms`.
- Maximum response bytes are `1_048_576` for detail operations and `10_485_760` for list operations.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `120_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support.
- Manifest rate-limit pools define 100 requests per 60 seconds with burst 10 for paper and author surfaces.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `semanticscholar.papers.read` | Read papers, paper search results, citations, references, and recommendations. |
| `semanticscholar.authors.read` | Read author profiles and author paper lists. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `semanticscholar.paper.search` | `GET /paper/search` | `semanticscholar.papers.read` | `Safe` | `Low` | `Strict` | Read-only search over caller-supplied academic query text. |
| `semanticscholar.paper.get` | `GET /paper/{paper_id}` | `semanticscholar.papers.read` | `Safe` | `Low` | `Strict` | Reads one paper metadata record. |
| `semanticscholar.paper.citations` | `GET /paper/{paper_id}/citations` | `semanticscholar.papers.read` | `Safe` | `Low` | `Strict` | Reads papers citing the target paper. |
| `semanticscholar.paper.references` | `GET /paper/{paper_id}/references` | `semanticscholar.papers.read` | `Safe` | `Low` | `Strict` | Reads papers referenced by the target paper. |
| `semanticscholar.paper.recommendations` | `GET /paper/{paper_id}/recommendations` | `semanticscholar.papers.read` | `Safe` | `Low` | `Strict` | Reads provider-generated paper recommendations for one paper ID. |
| `semanticscholar.author.get` | `GET /author/{author_id}` | `semanticscholar.authors.read` | `Safe` | `Low` | `Strict` | Reads one author metadata record. |
| `semanticscholar.author.papers` | `GET /author/{author_id}/papers` | `semanticscholar.authors.read` | `Safe` | `Low` | `Strict` | Reads paper metadata associated with one author. |

## Explicit Non-Goals

The current implementation does not include:

- Semantic Scholar datasets API downloads or local graph mirroring
- PDF retrieval, full-text extraction, or article page scraping
- bulk lookup endpoints outside the implemented operation catalog
- author search, venue search, corpus statistics, recommendations by positive/negative seed sets, or account/key management
- graph persistence, citation-cache storage, deduplication, ranking feedback, or local embeddings
- public-zone invocation
- FCP subscription-based streaming
- connector-local credential vaulting

These are excluded on purpose:

- The useful first slice is the read-only Academic Graph path used by agents for paper and author lookup.
- Dataset-scale sync and local graph storage need separate storage, freshness, and provenance contracts.
- Paper abstracts, titles, author metadata, and citation neighborhoods can expose sensitive research interests, so verification should avoid logging private live queries or broad result payloads.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, auth mode, base URL, request counters, and error counters
- base URL policy status and credential-injection status
- API-key status, including degraded public-mode reporting when no key is configured
- manifest-backed operation metadata, input schemas, and output schemas
- simulation support for shape validation without provider dispatch

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- API-key, credential-id, and no-auth header behavior
- lifecycle, health, self-check, doctor, and invalid-network diagnostics
- all seven operation dispatch paths
- paper ID and author ID path-injection rejection
- limit and offset validation
- default field lists and caller-supplied field forwarding
- 401, 403, 404, 429 with retry metadata, 500-class, and timeout/error mapping
- manifest-backed introspection metadata
- request and error counters

## Source Notes

- `connectors/semanticscholar/src/connector.rs` defines configuration parsing, auth mode selection, base URL policy, operation validation, lifecycle handlers, diagnostics, simulation, and manifest-backed introspection.
- `connectors/semanticscholar/src/client.rs` defines Academic Graph REST calls, headers, field defaults, retry/timeout settings, path-segment validation, health probe, and provider error mapping.
- `connectors/semanticscholar/src/types.rs` defines request argument parsing and normalized response types.
- `connectors/semanticscholar/manifest.toml` defines the operation catalog, rate-limit pools, network constraints, sandbox boundary, zone policy, and operation AI hints.
- `connectors/semanticscholar/tests/integration.rs` covers deterministic operation calls, auth headers, lifecycle behavior, validation, provider errors, simulation, diagnostics, and metadata parity.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/semanticscholar_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock Academic Graph coverage
- auth, base URL, paper, citation, reference, recommendation, author, limit, offset, error, lifecycle, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Semantic Scholar API key for live provider verification when practical.
- Public no-auth mode is supported but should be treated as lower-throughput and less reliable for live proof.
- Use WireMock loopback fixtures for routine proof.
- Keep live paper and author queries synthetic when possible.

**Dedicated environment**:

- Use a test Semantic Scholar API key for live runs.
- Keep private research topics, unpublished paper IDs, and sensitive author queries out of routine logs.
- Keep dataset downloads, PDF retrieval, bulk graph mirroring, and local embedding storage out of this connector until separate beads define those contracts.

**Redaction rules**:

- Redact API keys, credential IDs where needed, private query text, sensitive paper IDs, sensitive author IDs, abstracts, titles when sensitive, provider payloads, and provider error bodies.
- Verification output should use operation names, endpoint paths, auth mode, host classes, result counts, status/error classes, retry decisions, and limit/offset values.

**Common remediation**:

- If `health` reports `unconfigured`, configure with `api_key`, `credential_id`, or explicitly accept public no-auth mode.
- If configuration fails, make sure `api_key` and `credential_id` are not both present and that credential IDs are UUIDs.
- If base URL validation fails, use `https://api.semanticscholar.org/graph/v1` or a loopback test origin.
- If path validation fails, pass only the paper or author ID, not a full provider URL.
- If paper-search validation fails, check for a missing query, invalid `limit`, or negative `offset`.
- If graph-list validation fails, check the operation-specific `limit` cap: 1000 for citations, references, and author papers; 500 for recommendations.
- If public-mode self-check is degraded, provide an API key for higher-throughput live verification.
- If the upstream returns 429, respect provider rate limits and avoid broad live retry loops in tests.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-semanticscholar-e2e cargo check -p fcp-semanticscholar --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-semanticscholar-e2e cargo test -p fcp-semanticscholar --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-semanticscholar-e2e cargo clippy -p fcp-semanticscholar --all-targets --no-deps -- -D warnings`
