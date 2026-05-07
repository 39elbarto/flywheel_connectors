# Tavily Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/tavily_manifest_operations_verification.sh`
> **Primary upstream**: https://docs.tavily.com/

## Purpose

This document fixes the operator-facing contract for `fcp.tavily`. The connector is a native, read-only Tavily web search adapter. The current slice covers search only; Tavily extract, crawl, and map workflows are intentionally deferred until the connector surface is broader.

## Current Runtime Snapshot

The current crate exposes this operation:

- `tavily.search`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `api_key` or `credential_id`, plus optional `base_url` and `request_timeout_ms`.
- `api_key` mode sends `Authorization: Bearer <token>` and `X-Client-Source: fcp`.
- `credential_id` mode is accepted for configuration metadata but live invocation is blocked until host-side credential injection exists for this connector slice.
- The production base URL is `https://api.tavily.com`; hosts under `tavily.com` are accepted by policy.
- Localhost HTTP overrides are accepted only for deterministic tests.
- Search input is validated and normalized before POSTing to `/search`.
- `max_results` is floored when fractional and clamped to the connector's `1..20` bound.
- The runtime is non-streaming and has no listener surface.

## First-Slice Scope

The first Tavily slice is intentionally narrow:

- execute read-only Tavily web search
- pass through supported Tavily search options for topic, depth, result count, domains, answer/raw/image toggles, day window, and time range
- expose manifest-derived introspection for the operation catalog
- expose lifecycle, health, doctor, self-check, simulate, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanism: bearer API key, with a configuration-only credential-id mode.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Capability surface:
  - `tavily.search` gates the single search operation.
- The connector does not ingest webhooks, store credentials, subscribe to provider events, or fan out across accounts.

## Network And Runtime Invariants

- Production host policy: `tavily.com` and `*.tavily.com`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and broad redirects for live operations.
- Localhost overrides are test-only.
- Default request timeout: `60_000 ms`.
- Maximum response bytes: `10_485_760`.
- Runtime advertises no replay, subscription, or streaming event support.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `tavily.search` | Execute read-only Tavily web search. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `tavily.search` | `POST /search` | `tavily.search` | `Safe` | `Low` | `Strict` | Read-only search request returning Tavily answer and result records. |

## Explicit Non-Goals

The first implementation slice does not include:

- Tavily extract workflows
- Tavily crawl workflows
- Tavily map workflows
- webhook ingest or provider-side push events
- streaming search results
- host-side credential injection for live `credential_id` invocation

These are excluded on purpose:

- The current manifest and runtime intentionally advertise one operation.
- Search is read-only and testable through deterministic HTTP loopback fixtures.
- Expanding into extraction or crawling needs a separate capability and verification story.

## Readiness And Verification Surface

`doctor()`, `health()`, and `self_check()` are part of the public closeout contract. They surface:

- configuration, client, and handshake state
- auth mode and whether live requests are supported
- credential-id degradation when host-side credential injection is required
- configured base URL
- request and error counters
- upstream probe result for `/search`
- the search-only surface boundary

The deterministic integration evidence is anchored on no-live-provider HTTP loopback runs covering:

- connector-suite happy path through configure, handshake, health, invoke, simulate, and shutdown
- API-key header propagation with `Authorization` and `X-Client-Source`
- manifest/runtime/schema unit contract tests
- cross-connector manifest operation audit evidence for `fcp.tavily`

## Source Notes

- `connectors/tavily/src/connector.rs` defines configuration validation, auth header construction, search input normalization, lifecycle methods, and manifest-derived introspection.
- `connectors/tavily/manifest.toml` defines the single operation, network constraints, sandbox boundary, and no-listener/no-exec capability posture.
- `connectors/tavily/tests/connector_suite_happy_path.rs` covers deterministic loopback behavior through the shared connector-suite harness.

## Verification Bundle

The closeout bundle is anchored on `scripts/e2e/tavily_manifest_operations_verification.sh`. It writes a redaction-safe JSONL log to the path supplied as its first argument, or to `/tmp/fcp-tavily-manifest-ops-<timestamp>.jsonl` by default.

The bundle captures:

- manifest/runtime/schema unit contract tests
- deterministic no-live-provider HTTP connector-suite coverage
- cross-connector manifest operation audit evidence for `fcp.tavily`
- a JSONL record asserting 1 manifest operation and 1 runtime introspection operation

## Operator Guidance

**Prerequisites**:

- Use a Tavily API key for live provider verification.
- Use localhost loopback for deterministic test evidence.
- Treat `credential_id` as configuration metadata only until this connector slice gets host-side credential injection support.

**Dedicated environment**:

- Prefer a test Tavily project or the loopback fixture for repeatable evidence.
- Do not send sensitive internal data as search query text.

**Redaction rules**:

- Redact API keys, `Authorization` headers, credential IDs, request bodies, raw query text, provider payloads, and provider error bodies.
- Treat returned URLs, snippets, answer text, raw content, and image metadata as untrusted external content.

**Common remediation**:

- If `health` reports `unconfigured`, call `configure` with either `api_key` or `credential_id`, then run `handshake`.
- If `self_check` reports `not_configured`, configure the connector before probing `/search`.
- If `self_check` reports `credential_injection_required`, use API-key mode or wait for host-side credential injection support.
- If `self_check` reports `upstream_probe_failed`, verify the API key, provider availability, base URL, and timeout, then rerun the proof lane.
- If configuration rejects a base URL, use an HTTPS Tavily host or localhost HTTP for tests only.
- If invocation rejects options, keep `topic`, `search_depth`, and `time_range` inside manifest enum values and keep `days` positive.

**Rerun commands**:

- `CARGO_TARGET_DIR=/tmp/fcp-tavily-manifest-ops-target scripts/e2e/tavily_manifest_operations_verification.sh`
- `rch exec -- cargo test -p fcp-tavily manifest --lib -- --nocapture`
- `rch exec -- cargo test -p fcp-tavily --test connector_suite_happy_path -- --nocapture`
- `rch exec -- cargo run -p fcp-conformance --bin fcp-manifest-ops-audit -- --repo-root . --allow-findings --log-jsonl /tmp/fcp-tavily-manifest-ops.jsonl`
