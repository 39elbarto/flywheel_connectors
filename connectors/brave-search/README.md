# Brave Search Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://api-dashboard.search.brave.com/app/documentation/web-search/get-started

## Purpose

This document fixes the operator-facing contract for `fcp.brave-search`. The connector exposes Brave Search web results and Brave LLM Context search as read-only grounding operations.

The connector is intentionally a search bridge, not a browser, crawler, scraper, summarizer, or long-term retrieval store. It normalizes upstream results into FCP external-content wrappers so downstream agents can treat titles, descriptions, page content, and source snippets as untrusted web input.

## Current Runtime Snapshot

The current crate exposes these operations:

- `brave-search.web.search`
- `brave-search.llm-context.search`

Important runtime truths the contract preserves:

- Configuration requires exactly one of `api_key` or `credential_id`.
- API-key mode sends `X-Subscription-Token: ...`.
- Credential-id mode is accepted at configuration time but cannot perform live requests in this connector slice.
- Default base URL is `https://api.search.brave.com`.
- Production base URLs must use HTTPS and host `api.search.brave.com` or `search.brave.com`.
- Loopback HTTP/HTTPS base URLs are accepted only for deterministic tests.
- Base URL paths are preserved and the connector appends the operation endpoint.
- Default `request_timeout_ms` is `30_000`.
- `brave-search.web.search` calls `GET /res/v1/web/search`.
- `brave-search.llm-context.search` calls `GET /res/v1/llm/context`.
- `query` is required for both operations.
- `count` defaults to 5 and is clamped to 1 through 10.
- Unsupported country values normalize to `ALL`.
- `language` is accepted as an alias for `search_lang`.
- Search language aliases normalize `ja` to `jp`, Chinese simplified variants to `zh-hans`, and Chinese traditional variants to `zh-hant`.
- `ui_lang` is accepted only for web search and must use a language-region shape such as `en-US`.
- `freshness` is mutually exclusive with explicit `date_after` and `date_before` filters.
- Explicit date ranges must be ordered with `date_after` before `date_before`.
- LLM Context `date_before` is valid only when paired with `date_after`.
- Web-search output includes `query`, provider `brave`, mode `web`, count, external-content metadata, and normalized results.
- LLM-context output includes `query`, provider `brave`, mode `llm-context`, count, external-content metadata, normalized results, and sources.
- Upstream 429 and server errors are surfaced as retryable external errors.
- Upstream 401 is surfaced as a non-retryable auth/configuration error.

## First-Slice Scope

The first Brave Search README slice documents the existing runtime surface:

- web search through `GET /res/v1/web/search`
- LLM Context search through `GET /res/v1/llm/context`
- direct subscription-token auth
- host credential reference configuration with explicit live-request limitation
- production host allow-listing and loopback test overrides
- query, count, country, search language, UI language, safesearch, freshness, and date-range validation
- external-content wrapping of titles, descriptions, page content, result text, and source snippets
- provider timeout, malformed JSON, auth, rate-limit, and retryable upstream error mapping
- lifecycle, introspection, simulation, doctor, self-check, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: Brave Search API key or host credential reference.
- Home zone: `z:public`.
- Allowed source zones: `z:public` and `z:work`.
- Allowed target zones: `z:public` and `z:work`.
- Capability surface:
  - `brave-search.web` gates web search.
  - `brave-search.llm-context` gates LLM Context search.
- The connector does not persist queries, result URLs, source URLs, result text, LLM context payloads, API keys, or credential IDs.
- Credential-id mode is configuration metadata only in this slice; host-side credential injection is not implemented by the connector runtime.

## Network And Runtime Invariants

- Production host: `api.search.brave.com`.
- Production web-search path: `/res/v1/web/search`.
- Production LLM-context path: `/res/v1/llm/context`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback overrides are test-only.
- Runtime default `request_timeout_ms`: `30_000`.
- Manifest network constraints set total timeout `60_000 ms`.
- Maximum response bytes are `10_485_760`.
- Sandbox profile is `strict`, with `96 MB` memory, `25%` CPU, `30_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `brave-search.web` | Execute read-only Brave Web Search queries. |
| `brave-search.llm-context` | Execute read-only Brave LLM Context queries for AI grounding. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `brave-search.web.search` | `GET /res/v1/web/search` | `brave-search.web` | `Safe` | `Low` | `Strict` | Read-only web search over caller-supplied query and search filters. |
| `brave-search.llm-context.search` | `GET /res/v1/llm/context` | `brave-search.llm-context` | `Safe` | `Low` | `Strict` | Read-only LLM-grounding search that returns provider-ranked context and sources. |

## Explicit Non-Goals

The current implementation does not include:

- Brave image, video, news, suggest, spellcheck, answers, local POI, local descriptions, rich data, or Goggles-specific operations
- POST-mode LLM Context requests
- web page fetching outside Brave's API response
- browser automation, crawling, scraping, or click-through behavior
- search result persistence, vector storage, ranking feedback, deduplication, or answer synthesis
- provider account, subscription, or key management
- FCP subscription-based streaming
- connector-local credential vaulting

These are excluded on purpose:

- The useful first slice is a narrow read-only search bridge with explicit web and LLM-context capability boundaries.
- Brave's broader Search API surfaces need separate capability contracts before exposure.
- Search results and LLM context can contain untrusted web text, so the runtime wraps extracted fields instead of presenting them as trusted connector-authored content.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, auth mode, base URL, request counters, and error counters
- credential-injection warnings when `credential_id` is configured
- web-search and LLM-context operation metadata derived from the embedded manifest
- self-check degradation for unconfigured or credential-id-only configurations
- simulation denial for credential-id live requests

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- subscription-token auth header behavior
- `/res/v1/web/search` and `/res/v1/llm/context` path construction
- proxy base URL path preservation
- web-search happy path and LLM-context normalized output
- external-content wrapping for untrusted results and sources
- count clamping, country normalization, language normalization, UI-language validation, and date/freshness validation
- 401, 429 with `Retry-After`, timeout, malformed JSON, and retryability mapping
- manifest-backed introspection metadata
- lifecycle, health, doctor, simulation, and shutdown behavior

## Source Notes

- `connectors/brave-search/src/connector.rs` defines configuration parsing, auth handling, base URL policy, operation validation, result normalization, lifecycle handlers, diagnostics, and manifest-backed introspection.
- `connectors/brave-search/src/error.rs` defines error classes used by provider, validation, auth, timeout, and retry mapping.
- `connectors/brave-search/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and operation AI hints.
- `connectors/brave-search/tests/integration.rs` covers deterministic web search, LLM-context output, validation, provider errors, timeout behavior, introspection, and lifecycle behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/brave_search_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock coverage for web and LLM-context search
- auth, base URL, query, count, language, UI-language, date, freshness, error, lifecycle, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Brave Search API key for live provider verification.
- Do not expect `credential_id` mode to perform live requests until a host egress injection layer is wired for this connector.
- Prefer synthetic queries for deterministic verification.
- Use WireMock loopback fixtures for routine proof.

**Dedicated environment**:

- Use a test Brave Search subscription for live runs.
- Keep live queries short and non-sensitive.
- Keep image, video, news, answers, suggest, spellcheck, POI, rich data, and Goggles-specific behavior out of this connector until separate beads define those contracts.

**Redaction rules**:

- Redact API keys, credential IDs where needed, private query text, result URLs when sensitive, page titles when sensitive, descriptions, LLM context chunks, source text, provider payloads, and provider error bodies.
- Verification output should use operation names, endpoint paths, host classes, result counts, language/filter shapes, status/error classes, retry decisions, and wrapper presence.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one of `api_key` or `credential_id`.
- If `health` reports `degraded` under `credential_id`, switch to API-key mode or add host egress credential injection before live requests.
- If base URL validation fails, use `https://api.search.brave.com` or a loopback test origin.
- If web-search validation fails, check for an empty query, invalid `ui_lang`, unsupported `search_lang`, invalid safesearch, or mutually exclusive freshness/date filters.
- If LLM-context validation fails, remove `ui_lang` and make sure `date_before` is paired with `date_after`.
- If the upstream returns 429, respect `Retry-After` where present and let caller-owned retry scheduling decide when to reissue.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-brave-search-e2e cargo check -p fcp-brave-search --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-brave-search-e2e cargo test -p fcp-brave-search --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-brave-search-e2e cargo clippy -p fcp-brave-search --all-targets --no-deps -- -D warnings`
