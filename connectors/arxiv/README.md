# arXiv Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://info.arxiv.org/help/api/user-manual.html
> **Secondary upstream**: https://api.semanticscholar.org/api-docs/graph

## Purpose

This document fixes the operator-facing contract for `fcp.arxiv`. The connector exposes the current arXiv and Semantic Scholar read surfaces implemented in this crate: paper search, paper metadata, PDF/source retrieval, citation and reference traversal, author lookup, category lookup, and polling-backed new-paper monitoring.

The connector is intentionally a read-only academic research bridge. It is not a PDF indexing pipeline, local citation database, durable monitor service, production crawler, or account-management client.

## Current Runtime Snapshot

The current crate exposes these operations:

- `arxiv.search_papers`
- `arxiv.search_semantic`
- `arxiv.get_paper`
- `arxiv.get_full_text`
- `arxiv.download_pdf`
- `arxiv.get_citations`
- `arxiv.get_references`
- `arxiv.extract_references`
- `arxiv.get_author`
- `arxiv.list_categories`
- `arxiv.get_new_papers`
- `arxiv.monitor_category`
- `arxiv.monitor_query`

Important runtime truths the contract preserves:

- Configuration is open-access by default and does not require an arXiv credential.
- `arxiv_base_url` defaults to `https://export.arxiv.org`.
- `scholar_base_url` defaults to `https://api.semanticscholar.org/graph/v1`.
- `scholar_api_key` is optional and, when present, is sent as `x-api-key`.
- `rate_limit_rps` defaults to `3.0`; `self_check` degrades when it is outside `0 < rps <= 10`.
- Production `arxiv_base_url` must use HTTPS and host `export.arxiv.org`; loopback HTTP/HTTPS origins are accepted for tests.
- Production `scholar_base_url` must use HTTPS and host `api.semanticscholar.org` or `scholar.google.com`; loopback origins are accepted for tests.
- Base URLs must not include userinfo, query strings, or fragments.
- The HTTP client has a 60 second reqwest timeout and user agent `fcp-arxiv/0.1.0 (FCP connector)`.
- A shared retry config with `max_retries = 2` is constructed, but current direct request helpers do not route provider calls through the retry loop.
- arXiv API calls request Atom XML from `/api/query` and parse entries plus `opensearch:totalResults`.
- PDF download calls `GET /pdf/{arxiv_id}.pdf` and returns base64 content plus `size_bytes`.
- Full-text retrieval calls `GET /e-print/{arxiv_id}` and decodes returned bytes as lossy UTF-8 source text.
- Semantic search, citations, references, and author lookup use Semantic Scholar Academic Graph endpoints.
- `arxiv.list_categories` is local static data and does not call either provider.
- Required string fields are presence/type checked, but arXiv IDs are not path-segment sanitized in this slice.
- Numeric limits are passed through from caller inputs; the manifest declares intended bounds, but runtime validation is light.
- Monitor operations are polling-backed single invocations returning `papers` and `cursor_ts`; the connector does not persist cursors.
- `health` is local connector state, not a live provider probe.
- `self_check` reports local provisioning readiness and does not call arXiv or Semantic Scholar.

## First-Slice Scope

The first arXiv README slice documents the existing runtime surface:

- arXiv Atom search through `GET /api/query?search_query=...`
- arXiv metadata lookup through `GET /api/query?id_list=...`
- PDF download through `GET /pdf/{arxiv_id}.pdf`
- source/full-text retrieval through `GET /e-print/{arxiv_id}`
- Semantic Scholar paper relevance search through `/paper/search`
- Semantic Scholar citations and references through `/paper/ARXIV:{arxiv_id}/citations` and `/references`
- Semantic Scholar author search through `/author/search`
- local category catalog lookup
- polling-backed category and query monitors
- optional Semantic Scholar API-key forwarding
- base URL, rate-limit, lifecycle, doctor, self-check, introspection, simulation, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: none for arXiv, optional Semantic Scholar API key for graph operations.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zones: `z:work` and `z:private`.
- Forbidden zones: `z:public` and `z:community`.
- Capability surface:
  - `arxiv.search` gates keyword and semantic search.
  - `arxiv.read` gates metadata, source, and PDF retrieval.
  - `arxiv.citations` gates references, extracted references, and citing-paper lookup.
  - `arxiv.authors` gates author lookup.
  - `arxiv.categories` gates category listing and new-paper listing.
  - `arxiv.monitor` gates polling-backed category and query monitors.
- The connector does not persist papers, PDFs, source text, category cursors, API keys, or result caches beyond process memory.
- Any returned abstracts, titles, author names, research topics, and citation neighborhoods can reveal sensitive research interests and should be handled as non-public work data.

## Network And Runtime Invariants

- Primary arXiv host: `export.arxiv.org`.
- arXiv API path root: `/api/query`.
- arXiv PDF/source paths: `/pdf/{id}.pdf` and `/e-print/{id}`.
- Secondary Semantic Scholar host: `api.semanticscholar.org`.
- Semantic Scholar path root: `/graph/v1`.
- Production port: `443`.
- TLS and SNI are required for live provider traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback origins are test-only.
- Runtime request timeout: `60_000 ms` at the reqwest client layer, with a connector runtime timeout configured to `30_000 ms`.
- Manifest search operations set total timeout `30_000 ms`; content and citation operations can set `60_000 ms` or `120_000 ms`.
- Maximum response bytes are `10_485_760` for metadata/search/list operations and `52_428_800` for PDF/source operations.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- The manifest advertises streaming event caps, but the current runtime monitor surface is request/response polling, not an FCP subscription listener.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `arxiv.search` | Search arXiv and Semantic Scholar paper indexes. |
| `arxiv.read` | Read paper metadata, PDF bytes, and source/full-text data. |
| `arxiv.citations` | Traverse Semantic Scholar citation and reference edges. |
| `arxiv.authors` | Search Semantic Scholar author profiles and publication lists. |
| `arxiv.categories` | List arXiv categories and recent category papers. |
| `arxiv.monitor` | Poll categories or queries for new matching papers. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `arxiv.search_papers` | `GET /api/query?search_query=...` | `arxiv.search` | `Safe` | `Low` | `Strict` | Read-only arXiv Atom search. |
| `arxiv.search_semantic` | `GET /paper/search` | `arxiv.search` | `Safe` | `Low` | `Strict` | Read-only Semantic Scholar relevance search. |
| `arxiv.get_paper` | `GET /api/query?id_list=...` | `arxiv.read` | `Safe` | `Low` | `Strict` | Reads one arXiv metadata record. |
| `arxiv.get_full_text` | `GET /e-print/{arxiv_id}` | `arxiv.read` | `Safe` | `Low` | `Strict` | Fetches TeX/source bytes and returns lossy text. |
| `arxiv.download_pdf` | `GET /pdf/{arxiv_id}.pdf` | `arxiv.read` | `Safe` | `Low` | `Strict` | Downloads a bounded PDF as base64. |
| `arxiv.get_citations` | `GET /paper/ARXIV:{id}/citations` | `arxiv.citations` | `Safe` | `Low` | `Strict` | Reads papers citing the target paper. |
| `arxiv.get_references` | `GET /paper/ARXIV:{id}/references` | `arxiv.citations` | `Safe` | `Low` | `Strict` | Reads papers referenced by the target paper. |
| `arxiv.extract_references` | Semantic Scholar references, normalized locally | `arxiv.citations` | `Safe` | `Low` | `Strict` | Formats reference entries into a simplified shape. |
| `arxiv.get_author` | `GET /author/search` | `arxiv.authors` | `Safe` | `Low` | `Strict` | Reads the first matching author profile and papers. |
| `arxiv.list_categories` | local catalog | `arxiv.categories` | `Safe` | `Low` | `Strict` | Lists connector-local category metadata. |
| `arxiv.get_new_papers` | `GET /api/query?search_query=cat:...` | `arxiv.categories` | `Safe` | `Low` | `Strict` | Reads recent papers in one category. |
| `arxiv.monitor_category` | polling-backed category search | `arxiv.monitor` | `Safe` | `Low` | `Strict` | Returns new papers and a cursor timestamp. |
| `arxiv.monitor_query` | polling-backed query search | `arxiv.monitor` | `Safe` | `Low` | `Strict` | Returns query matches and a cursor timestamp. |

## Explicit Non-Goals

The current implementation does not include:

- durable monitor cursor storage
- provider-side subscription streams or webhook listeners
- local PDF indexing, citation graph persistence, embeddings, or search index storage
- arXiv submission, moderation, account, or author-profile mutation APIs
- Semantic Scholar dataset downloads or local graph mirroring
- PDF parsing beyond base64 download and lossy e-print byte decoding
- full arXiv ID path sanitization
- connector-local credential vaulting
- public-zone invocation

These are excluded on purpose:

- The useful first slice is a bounded research lookup bridge, not a crawler.
- arXiv has explicit rate-limit expectations, so monitor operations remain polling-backed and bounded.
- Citation graph and PDF indexing need separate storage, freshness, provenance, and redaction contracts.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, base URLs, rate-limit settings, request counters, and error counters
- Semantic Scholar API-key presence without exposing the key
- base URL policy status and local client readiness
- operation metadata, schemas, capability IDs, risk levels, safety tiers, and idempotency
- simulation denial for unknown operations, missing readiness, and malformed required inputs

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- lifecycle health, handshake, reconfigure, shutdown, doctor, self-check, and introspection
- arXiv search, empty search, paper lookup, PDF download, source retrieval, new-paper listing, and monitors
- Semantic Scholar semantic search, citations, references, parsed references, and author lookup
- category lookup and filtering
- required-field validation and simulation for all operations
- 429 and 500-class arXiv errors
- 404, 429 with `Retry-After`, and 500-class Semantic Scholar errors
- unknown-operation behavior and request/error counters
- base URL policy, API-key redaction, URL encoding, XML parsing, and type helpers

## Source Notes

- `connectors/arxiv/src/connector.rs` defines configuration parsing, base URL policy, lifecycle handlers, operation dispatch, diagnostics, simulation, operation metadata, and provisioning recipe metadata.
- `connectors/arxiv/src/client.rs` defines arXiv and Semantic Scholar REST calls, optional Semantic Scholar auth, default URLs, request timeouts, response parsing, and provider error mapping.
- `connectors/arxiv/src/xml_parser.rs` parses Atom entries, total result counts, links, authors, categories, DOI, comments, and journal references.
- `connectors/arxiv/src/types.rs` defines normalized paper, category, and provider error data types.
- `connectors/arxiv/manifest.toml` defines the operation catalog, event caps, network constraints, sandbox boundary, zone policy, rate-limit pools, and operation AI hints.
- `connectors/arxiv/tests/integration.rs` and `connectors/arxiv/tests/connector_suite_happy_path.rs` cover deterministic provider behavior and FCP suite integration.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/arxiv_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock arXiv and Semantic Scholar coverage
- auth, base URL, paper search, paper detail, PDF/source, citations, references, author, category, monitor, lifecycle, simulation, and error tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- No arXiv credential is required for metadata, PDF, source, category, or monitor operations.
- Use a Semantic Scholar API key for graph operations when live rate limits matter.
- Use WireMock loopback fixtures for routine proof.
- Keep live research queries synthetic when possible.

**Dedicated environment**:

- Use low-volume test queries and known public arXiv IDs.
- Respect arXiv rate limits; do not bulk-download PDFs or sources through this connector.
- Keep production research topics, unpublished paper IDs, private author searches, and broad citation traversals out of routine logs.

**Redaction rules**:

- Redact Semantic Scholar API keys, private query text, sensitive arXiv IDs, sensitive author names, abstracts, titles when sensitive, PDF/source payloads, provider payloads, and provider error bodies.
- Verification output should use operation names, endpoint classes, result counts, status/error classes, cursor timestamps, and local readiness status.

**Common remediation**:

- If `health` reports `unconfigured`, call `configure`.
- If `doctor` reports handshake degradation, call `handshake` after configuration.
- If `self_check` reports invalid network constraints, remove userinfo, query strings, fragments, unsupported hosts, or non-HTTPS production URLs.
- If Semantic Scholar graph calls rate limit, configure a `scholar_api_key` and lower caller concurrency.
- If search results look empty, confirm arXiv query syntax and category codes through `arxiv.list_categories`.
- If monitor calls repeat old papers, persist the returned `cursor_ts` in the host and pass it back as `since_ts`.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-arxiv-e2e cargo check -p fcp-arxiv --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-arxiv-e2e cargo test -p fcp-arxiv --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-arxiv-e2e cargo clippy -p fcp-arxiv --all-targets --no-deps -- -D warnings`
