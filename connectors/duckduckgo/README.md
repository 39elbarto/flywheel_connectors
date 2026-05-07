# DuckDuckGo Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/duckduckgo_manifest_operations_verification.sh`
> **Primary upstream**: https://duckduckgo.com/

## Purpose

This document fixes the operator-facing contract for `fcp.duckduckgo`. The connector is a no-key, read-only search adapter for DuckDuckGo HTML search, vertical JSON search, autocomplete, and provider health probing. Returned search content is treated as untrusted external content, and the connector intentionally avoids logging raw query text.

## Current Runtime Snapshot

The current crate exposes these operations:

- `duckduckgo.search.text`
- `duckduckgo.search.images`
- `duckduckgo.search.news`
- `duckduckgo.search.suggestions`
- `duckduckgo.health`

Important runtime truths the contract preserves:

- The connector has no API-key, OAuth, or credential-injection mode.
- Configuration accepts `html_base_url`, `api_base_url`, `instant_base_url`, optional shared `base_url`, `request_timeout_ms`, `default_region`, `default_safe_search`, and `user_agent`.
- Production hosts are `html.duckduckgo.com`, `lite.duckduckgo.com`, `duckduckgo.com`, and `api.duckduckgo.com`.
- Localhost HTTP overrides are accepted only for deterministic tests.
- Query text is hashed in normalized outputs and must not be logged in evidence.
- Search result URLs, snippets, image metadata, article records, and suggestions are external untrusted content.
- The runtime is non-streaming and has no listener surface.

## First-Slice Scope

The first DuckDuckGo slice is intentionally narrow:

- run no-key HTML web search
- run image search through the vqd-backed vertical endpoint
- run news search through the vqd-backed vertical endpoint
- fetch autocomplete suggestions
- probe the Instant Answer endpoint for health
- expose manifest-derived introspection for the operation catalog

## Auth And Scope Boundary

- Authentication mechanism: none.
- Home zone: `z:public`.
- Allowed source and target zones: `z:public` and `z:work`.
- Capability surface:
  - `duckduckgo.search.read` gates all search and health operations.
- The connector does not store user credentials and does not perform cross-account aggregation.

## Network And Runtime Invariants

- Production hosts: `html.duckduckgo.com`, `lite.duckduckgo.com`, `duckduckgo.com`, `api.duckduckgo.com`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and broad redirects for live operations.
- Localhost overrides are test-only.
- Default request timeout: `15_000 ms`.
- Maximum response bytes: `5_242_880` for search result operations and `1_048_576` for suggestions and health.
- Runtime advertises no replay, subscription, or streaming event support.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `duckduckgo.search.read` | Run no-key search, vertical search, suggestions, and health probes. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `duckduckgo.search.text` | `POST /html/` on `html.duckduckgo.com` or `lite.duckduckgo.com` | `duckduckgo.search.read` | `Safe` | `Low` | `Strict` | Read-only HTML search returning normalized untrusted web results. |
| `duckduckgo.search.images` | `GET /i.js` with vqd token on `duckduckgo.com` | `duckduckgo.search.read` | `Safe` | `Low` | `Strict` | Read-only image vertical search returning normalized untrusted image records. |
| `duckduckgo.search.news` | `GET /news.js` with vqd token on `duckduckgo.com` | `duckduckgo.search.read` | `Safe` | `Low` | `Strict` | Read-only news vertical search returning normalized untrusted article records. |
| `duckduckgo.search.suggestions` | `GET /ac/` on `duckduckgo.com` | `duckduckgo.search.read` | `Safe` | `Low` | `Strict` | Read-only autocomplete suggestions for a caller-supplied query. |
| `duckduckgo.health` | `GET /` on `api.duckduckgo.com` | `duckduckgo.search.read` | `Safe` | `Low` | `Strict` | No-key provider health probe through the Instant Answer endpoint. |

## Explicit Non-Goals

The first implementation slice does not include:

- credentialed DuckDuckGo surfaces
- ad account, browser, or privacy-product administration
- webhook ingest, subscriptions, or provider-side push events
- crawling or content extraction beyond returned result records
- raw query logging in diagnostics or replay artifacts

These are excluded on purpose:

- The useful connector boundary is no-key search and health probing.
- Search results are external content, so the connector must keep the trust boundary visible.
- Adding unrelated DuckDuckGo products would blur the operator contract.

## Readiness And Verification Surface

`doctor()`, `health()`, and `self_check()` are part of the public closeout contract. They surface:

- configuration, client, and handshake state
- no-auth posture
- privacy logging invariant
- configured base URLs and default search options
- request and error counters
- Instant Answer health probe status

The deterministic integration evidence is anchored on no-live-provider loopback runs covering:

- lifecycle health, configure, handshake, shutdown, doctor, and self-check behavior
- no-auth privacy boundary advertisement
- manifest operation count and network-host conformance
- text, image, news, suggestions, and health operation catalog parity

## Source Notes

- `connectors/duckduckgo/src/connector.rs` defines configuration validation, request construction, result normalization, privacy-preserving output shape, lifecycle methods, and manifest-derived introspection.
- `connectors/duckduckgo/manifest.toml` defines the operation catalog, per-operation network constraints, sandbox boundary, and no-listener/no-exec capability posture.
- `connectors/duckduckgo/tests/integration.rs` covers deterministic loopback behavior for the connector runtime.
- `connectors/duckduckgo/tests/conformance.rs` verifies manifest shape and per-operation host scoping.

## Verification Bundle

The closeout bundle is anchored on `scripts/e2e/duckduckgo_manifest_operations_verification.sh`. It writes a redaction-safe JSONL log to the path supplied as its first argument, or to `/tmp/fcp-duckduckgo-manifest-ops-<timestamp>.jsonl` by default.

The bundle captures:

- manifest/runtime/schema unit contract tests
- deterministic no-live-provider loopback integration coverage
- manifest conformance tests
- cross-connector manifest operation audit evidence for `fcp.duckduckgo`
- a JSONL record asserting 5 manifest operations and 5 runtime introspection operations

## Operator Guidance

**Prerequisites**:

- No provider credentials are required.
- Use localhost overrides only for deterministic tests.
- Keep `max_results` within the manifest/runtime bounds and use a valid DuckDuckGo region code such as `us-en` or `wt-wt`.

**Dedicated environment**:

- A disposable provider account is not needed because this connector is no-auth and read-only.
- Prefer loopback mock tests when capturing replayable evidence.

**Redaction rules**:

- Do not log raw query text.
- Redact full result URLs, snippets, image captions, image URLs, news article text, and suggestion text from shared evidence unless the artifact is intentionally public.
- Treat returned provider content as untrusted external input.

**Common remediation**:

- If `health` reports `unconfigured`, call `configure` with valid base URLs or rely on defaults, then run `handshake`.
- If `self_check` reports `not_configured`, configure the connector before probing provider health.
- If `self_check` reports `upstream_probe_failed`, retry after provider recovery or switch to deterministic loopback verification.
- If configuration rejects a base URL, use HTTPS production hosts or localhost HTTP for tests only.
- If image or news search fails because no vqd token is returned, retry through the deterministic fixture or reduce dependence on live vertical endpoints.

**Rerun commands**:

- `CARGO_TARGET_DIR=/tmp/fcp-duckduckgo-manifest-ops-target scripts/e2e/duckduckgo_manifest_operations_verification.sh`
- `rch exec -- cargo test -p fcp-duckduckgo manifest --lib -- --nocapture`
- `rch exec -- cargo test -p fcp-duckduckgo --test integration lifecycle_advertises_no_auth_privacy_boundary -- --nocapture`
- `rch exec -- cargo test -p fcp-duckduckgo --test conformance manifest -- --nocapture`
- `rch exec -- cargo run -p fcp-conformance --bin fcp-manifest-ops-audit -- --repo-root . --allow-findings --log-jsonl /tmp/fcp-duckduckgo-manifest-ops.jsonl`
