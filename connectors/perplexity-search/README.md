# Perplexity Search Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/perplexity_search_manifest_operations_verification.sh`
> **Primary upstream**: https://docs.perplexity.ai/

## Purpose

This document fixes the operator-facing contract for `fcp.perplexity-search`. The connector exposes grounded answer synthesis through Perplexity/OpenRouter chat completions and native structured Perplexity search through separate capabilities. Returned answer text, citations, and web result records remain external untrusted content.

## Current Runtime Snapshot

The current crate exposes these operations:

- `perplexity-search.query`
- `perplexity-search.search`

Important runtime truths the contract preserves:

- Configuration accepts `api_key`, optional `base_url`, retry policy, `request_timeout_ms`, and optional `default_model`.
- If an API key starts with `sk-or-`, default routing switches to OpenRouter with `perplexity/sonar-pro`; otherwise the default base URL is `https://api.perplexity.ai` with model `sonar`.
- Custom base URLs are allowed only after URL validation rejects userinfo, query strings, fragments, non-HTTP(S) schemes, and sensitive non-loopback IP ranges.
- `perplexity-search.query` uses `/chat/completions` and can route through direct Perplexity or OpenRouter.
- `perplexity-search.search` uses native `/search` and is rejected when the configured transport is OpenRouter.
- Invocation requires a bound capability token verified against the connector instance.
- The runtime is non-streaming and reports streaming/replay disabled in event capabilities.

## First-Slice Scope

The first Perplexity Search slice is intentionally narrow:

- run grounded answer-synthesis queries through chat completions
- run native structured Perplexity Search API queries
- validate recency, date, domain, country, language, token, and sampling options before provider calls
- wrap title and snippet text from native search results as untrusted web content
- expose manifest-derived introspection for the operation catalog
- expose lifecycle, health, self-check, simulate, invoke, and shutdown surfaces through the `FcpConnector` trait

## Auth And Scope Boundary

- Authentication mechanism: bearer API key.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Capability surface:
  - `perplexity-search.query` gates answer-synthesis chat-completion calls.
  - `perplexity-search.search` gates native structured search calls.
- Capability tokens are verified with instance binding during invoke and simulate.
- Secretless empty-key configuration degrades self-check with `credential_injection_required`; live provider calls need API-key material.

## Network And Runtime Invariants

- Production hosts for answer synthesis: `api.perplexity.ai` and `openrouter.ai`.
- Production host for native structured search: `api.perplexity.ai`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and broad redirects for live operations.
- Loopback HTTP is available only through explicit custom base URLs for deterministic tests.
- Default request timeout: `30_000 ms`.
- Maximum response bytes: `10_485_760`.
- Runtime advertises no replay, subscription, or streaming event support.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `perplexity-search.query` | Execute grounded answer synthesis through chat completions. |
| `perplexity-search.search` | Execute native structured Perplexity web search. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `perplexity-search.query` | `POST /chat/completions` | `perplexity-search.query` | `Safe` | `Medium` | `None` | Read-oriented grounded answer synthesis can spend tokens and return generated external content. |
| `perplexity-search.search` | `POST /search` | `perplexity-search.search` | `Safe` | `Medium` | `None` | Read-oriented structured search returns untrusted web result metadata. |

## Explicit Non-Goals

The first implementation slice does not include:

- streaming chat completions
- native search through OpenRouter
- model administration or account management
- webhook ingest or provider-side push events
- cross-account aggregation
- persistence of query, citation, or result payloads

These are excluded on purpose:

- The connector is a bounded request-response research surface, not a general LLM account manager.
- Native structured search has a different provider endpoint and capability from chat completions.
- Search and answer payloads contain untrusted external content and must remain explicit in outputs.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration and client readiness
- base URL, transport, default model, and API-key presence
- manifest hash returned during handshake
- bound capability-token enforcement for invocation and simulation
- retryable versus failed self-check outcomes
- operation catalog from the embedded manifest

The deterministic integration evidence is anchored on no-live-provider HTTP loopback runs covering:

- chat-completions happy path
- native search happy path
- capability-token binding for operation invocation
- manifest/runtime/schema unit contract tests
- cross-connector manifest operation audit evidence for `fcp.perplexity-search`

## Source Notes

- `connectors/perplexity-search/src/connector.rs` defines configuration routing, transport selection, capability verification, operation validation, lifecycle methods, and manifest-derived introspection.
- `connectors/perplexity-search/src/client.rs` defines authenticated HTTP POSTs, retry behavior, redaction of auth material from errors, and `/chat/completions` plus `/search` request paths.
- `connectors/perplexity-search/src/types.rs` defines API-key auth and request/response payloads for chat completions and native search.
- `connectors/perplexity-search/manifest.toml` defines the two-operation catalog, network constraints, and no-listener/no-exec capability posture.
- `connectors/perplexity-search/tests/connector_suite_happy_path.rs` covers deterministic loopback behavior through the shared connector-suite harness.

## Verification Bundle

The closeout bundle is anchored on `scripts/e2e/perplexity_search_manifest_operations_verification.sh`. It writes a redaction-safe JSONL log to the path supplied as its first argument, or to `/tmp/fcp-perplexity-search-manifest-ops-<timestamp>.jsonl` by default.

The bundle captures:

- manifest/runtime/schema unit contract tests
- deterministic no-live-provider HTTP connector-suite coverage
- cross-connector manifest operation audit evidence for `fcp.perplexity-search`
- a JSONL record asserting 2 manifest operations and 2 runtime introspection operations

## Operator Guidance

**Prerequisites**:

- Use a Perplexity API key for direct mode or an OpenRouter key for chat-completions routing.
- Use loopback HTTP only for deterministic test fixtures.
- Request the correct capability for the operation being invoked.

**Dedicated environment**:

- Prefer a test key or loopback fixture for replayable evidence.
- Do not send sensitive internal data in query or system prompt text.

**Redaction rules**:

- Redact API keys, `Authorization` headers, request bodies, system prompts, query text, model responses, citations, usage payloads, provider result URLs, snippets, and provider error bodies.
- Treat answer text, citations, titles, snippets, and returned URLs as untrusted external content.

**Common remediation**:

- If health reports degraded or self-check reports `not_configured`, configure the connector before probing.
- If self-check reports `credential_injection_required`, provide an API key or route through a future host credential-injection path.
- If self-check reports `self_check_retryable`, retry after provider recovery or increase timeout/retry settings.
- If native search rejects OpenRouter transport, use `perplexity-search.query` or switch to direct Perplexity API routing.
- If date filters fail, use `YYYY-MM-DD` dates and do not combine date filters with `freshness` or `search_recency_filter`.
- If domain filtering fails, use either all allow entries or all deny entries prefixed with `-`; do not mix both.

**Rerun commands**:

- `CARGO_TARGET_DIR=/tmp/fcp-perplexity-search-manifest-ops-target scripts/e2e/perplexity_search_manifest_operations_verification.sh`
- `rch exec -- cargo test -p fcp-perplexity-search manifest --lib -- --nocapture`
- `rch exec -- cargo test -p fcp-perplexity-search --test connector_suite_happy_path -- --nocapture`
- `rch exec -- cargo run -p fcp-conformance --bin fcp-manifest-ops-audit -- --repo-root . --allow-findings --log-jsonl /tmp/fcp-perplexity-search-manifest-ops.jsonl`
