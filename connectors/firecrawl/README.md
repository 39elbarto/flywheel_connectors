# Firecrawl Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://docs.firecrawl.dev/api-reference/v2-introduction

## Purpose

This document fixes the operator-facing contract for `fcp.firecrawl`. The connector exposes the current Firecrawl v2 web-data surface implemented in this crate: search, single-page scrape, crawl job start, and crawl job status.

The connector is intentionally a public web-data bridge, not a browser session controller or private-network fetcher. It validates Firecrawl API configuration, blocks private/internal target URLs before network dispatch, and keeps API keys and page content out of connector state.

## Current Runtime Snapshot

The current crate exposes these operations:

- `firecrawl.search`
- `firecrawl.scrape`
- `firecrawl.crawl.start`
- `firecrawl.crawl.status`

Important runtime truths the contract preserves:

- Configuration requires `api_key`.
- API-key mode sends `Authorization: Bearer ...`.
- Default base URL is `https://api.firecrawl.dev`.
- Base URL overrides must be absolute HTTP/HTTPS URLs without userinfo, query, or fragment components.
- Non-loopback base URLs must use HTTPS and host `api.firecrawl.dev`.
- Loopback HTTP/HTTPS base URLs are accepted only for deterministic tests.
- Base URL normalization rejects legacy `/v1` and strips a trailing `/v2`, because the client appends `/v2/...` routes itself.
- Default `request_timeout_ms` is `30_000`.
- Retry behavior is configured through the shared `HttpRetryConfig` surface.
- `firecrawl.search` calls `POST /v2/search`.
- Search query is required, trimmed, and capped at 500 characters.
- Search `limit` must be positive and is capped to 100.
- Search `sources` are limited to `web`, `images`, and `news`.
- Search `categories` are limited to `github`, `research`, and `pdf`.
- Search `enterprise` options are limited to `anon` and `zdr`.
- `scrape_results = true` maps to Firecrawl `scrapeOptions` with markdown output.
- `firecrawl.scrape` calls `POST /v2/scrape`.
- Scrape defaults `formats` to `["markdown"]`.
- Scrape target URL must be absolute HTTP/HTTPS, must not include userinfo, and must not target localhost, private/link-local/unspecified IPs, or metadata hosts.
- Scrape `proxy` is limited to `auto`, `basic`, and `stealth`.
- `firecrawl.crawl.start` calls `POST /v2/crawl`.
- Crawl start maps `max_depth` to Firecrawl `maxDiscoveryDepth`.
- Crawl target URL uses the same private/internal target blocking as scrape.
- `firecrawl.crawl.status` calls `GET /v2/crawl/{crawl_id}`.
- Crawl IDs must be non-empty and must not contain path traversal or encoded slash/backslash characters.
- `firecrawl.health` is not a provider operation; readiness is local connector state.

## First-Slice Scope

The first Firecrawl README slice documents the existing runtime surface:

- web search through `POST /v2/search`
- single URL scrape through `POST /v2/scrape`
- crawl job start through `POST /v2/crawl`
- crawl job status through `GET /v2/crawl/{crawl_id}`
- bearer API-key auth
- production and loopback base URL validation
- target URL SSRF guardrails for scrape and crawl start
- search source/category/enterprise option validation
- scrape format, tag, wait, timeout, cache, and proxy option validation
- crawl include/exclude path, depth, limit, and external-link option validation
- provider error, rate-limit, retry, and timeout mapping
- lifecycle, introspection, simulation, doctor, self-check, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanism: Firecrawl API key / `FIRECRAWL_API_KEY` equivalent.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Capability surface:
  - `firecrawl.search` gates search.
  - `firecrawl.scrape` gates single-page scrape.
  - `firecrawl.crawl` gates crawl start and crawl status.
- The connector does not persist queries, target URLs, scraped page content, crawl IDs, crawl results, API keys, provider payloads, or provider errors.
- There is no credential-id mode in this connector slice.

## Network And Runtime Invariants

- Production host: `api.firecrawl.dev`.
- Production path root: `/v2`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for provider API calls.
- Runtime loopback provider API overrides are test-only.
- Runtime default `request_timeout_ms`: `30_000`.
- Manifest operation network constraints set total timeout `60_000 ms`.
- Maximum response bytes are `10_485_760`.
- Sandbox profile is `strict`, with `96 MB` memory, `25%` CPU, `60_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support.
- Target URL validation blocks local, private, link-local, unspecified, metadata, and userinfo-bearing URLs before Firecrawl is called.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `firecrawl.search` | Search the web through Firecrawl v2. |
| `firecrawl.scrape` | Scrape one public HTTP(S) URL through Firecrawl v2. |
| `firecrawl.crawl` | Start and inspect Firecrawl crawl jobs. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `firecrawl.search` | `POST /v2/search` | `firecrawl.search` | `Safe` | `Low` | `Strict` | Read-only search with optional markdown scraping of result pages. |
| `firecrawl.scrape` | `POST /v2/scrape` | `firecrawl.scrape` | `Safe` | `Low` | `Strict` | Fetches and extracts one public target URL through Firecrawl. |
| `firecrawl.crawl.start` | `POST /v2/crawl` | `firecrawl.crawl` | `Safe` | `Medium` | `BestEffort` | Starts a multi-page crawl job that can consume credits and remote crawl resources. |
| `firecrawl.crawl.status` | `GET /v2/crawl/{crawl_id}` | `firecrawl.crawl` | `Safe` | `Low` | `Strict` | Reads crawl job status and returned page data. |

## Explicit Non-Goals

The current implementation does not include:

- Firecrawl map, extract, parse, agent, browser session, active crawl, cancel crawl, crawl errors, batch scrape, or account endpoints
- webhook registration or callback handling
- Firecrawl self-hosted private endpoint support
- browser interaction, screenshots, actions, or managed live-view sessions as first-class FCP operations
- target URL fetching outside Firecrawl's provider API
- public-zone invocation
- FCP subscription-based streaming
- automatic crawl cancellation on local timeout
- durable storage of queries, page content, target URLs, crawl IDs, crawl results, provider payloads, or provider errors
- connector-local credential vaulting

These are excluded on purpose:

- The useful first slice covers the core search/scrape/crawl loop while keeping target URL policy narrow.
- Firecrawl's broader v2 API surface needs separate capability contracts before exposure.
- Crawl start can consume credits and remote work, so it remains a medium-risk operation even though it is safe from an FCP approval perspective.
- Private-network and metadata-service URLs must fail closed locally before a provider call can be made.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, client/runtime initialization, and live surface status
- manifest-backed operation metadata, including input and output schemas
- implemented flag in introspection entries
- local readiness without submitting a live Firecrawl job
- simulation denial because Firecrawl does not support dry-run mode

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- bearer auth header behavior
- `/v2/search`, `/v2/scrape`, `/v2/crawl`, and `/v2/crawl/{id}` path construction
- base URL normalization from `/v2` test roots
- search limit capping, source/category/enterprise validation, and markdown scrape option mapping
- scrape body serialization and default markdown format
- crawl start body serialization, `max_depth` to `maxDiscoveryDepth`, include/exclude paths, and external-link option mapping
- crawl ID path-injection rejection
- private/internal target blocking before any provider request is sent
- response deserialization for search, scrape, crawl start, and crawl status
- manifest metadata and introspection parity

## Source Notes

- `connectors/firecrawl/src/connector.rs` defines configuration parsing, base URL policy, target URL validation, operation dispatch, lifecycle handlers, diagnostics, and manifest-backed introspection.
- `connectors/firecrawl/src/client.rs` defines Firecrawl v2 REST calls, bearer auth, retry loop behavior, response handling, rate-limit mapping, and crawl ID path validation.
- `connectors/firecrawl/src/types.rs` defines request/response serialization for search, scrape, crawl start, and crawl status.
- `connectors/firecrawl/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and operation AI hints.
- `connectors/firecrawl/tests/connector_suite_happy_path.rs` covers deterministic search, scrape, crawl start, and private-target blocking behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/firecrawl_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock Firecrawl v2 coverage
- auth, base URL, search, scrape, crawl, target URL blocking, crawl ID, retry/error, lifecycle, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Firecrawl API key for live provider verification.
- Use WireMock loopback fixtures for routine proof.
- Use live calls only when the operator intentionally accepts provider cost and page-content handling.
- Keep target URLs public, absolute HTTP(S), and free of userinfo.

**Dedicated environment**:

- Use a test Firecrawl account for live runs.
- Keep search queries and target URLs synthetic when possible.
- Keep batch scrape, map, extract, parse, agent, browser, active crawl, cancellation, and account operations out of this connector until separate beads define those contracts.

**Redaction rules**:

- Redact API keys, private query text, target URLs when sensitive, markdown/html/raw page content, screenshots, crawl IDs where correlation is sensitive, provider payloads, and provider error bodies.
- Verification output should use operation names, endpoint paths, target host classes, result counts, status/error classes, retry decisions, crawl status, credit counts when non-sensitive, and block reasons.

**Common remediation**:

- If `health` reports `unconfigured`, configure with `api_key`.
- If `health` reports `degraded`, check client/runtime initialization and complete handshake.
- If base URL validation fails, use `https://api.firecrawl.dev` or a loopback test origin without `/v1`.
- If search validation fails, check query length, positive `limit`, `sources`, `categories`, `enterprise`, and country code.
- If scrape or crawl target validation fails, remove userinfo and avoid localhost, private IPs, link-local IPs, unspecified IPs, and metadata hosts.
- If crawl status validation fails, pass only the crawl ID returned by `firecrawl.crawl.start`, not a full provider URL.
- If a provider returns 429 or 5xx, rely on the configured retry policy and avoid broad live retry loops in tests.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-firecrawl-e2e cargo check -p fcp-firecrawl --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-firecrawl-e2e cargo test -p fcp-firecrawl --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-firecrawl-e2e cargo clippy -p fcp-firecrawl --all-targets --no-deps -- -D warnings`
