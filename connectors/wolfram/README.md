# Wolfram Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/wolfram_manifest_operations_verification.sh`
> **Primary upstream**: https://products.wolframalpha.com/api/

## Purpose

This document fixes the operator-facing contract for `fcp.wolfram`. The connector exposes read-only computational knowledge queries through the Wolfram Alpha API: full pod/subpod query results, short text answers, and spoken-word answers. Query strings and provider results are treated as sensitive operational data.

## Current Runtime Snapshot

The current crate exposes these operations:

- `wolfram.query`
- `wolfram.short_answer`
- `wolfram.spoken_result`

Important runtime truths the contract preserves:

- Configuration requires a `credential_id`, optional `base_url`, optional `allow_mock_base_url`, and `timeout_ms`.
- The default base URL normalizes to `https://api.wolframalpha.com`.
- Loopback mock URLs require `allow_mock_base_url=true`, an explicit port, and debug/test builds.
- Live invoke still requires an explicit `app_id` input; credential injection is not wired for this connector yet.
- `input` and `query` are aliases for the Wolfram query string.
- All three operations share capability `wolfram.query`.
- Invocation verifies a bound capability token when a verifier and token are present.
- The runtime is non-streaming and reports event streaming/replay disabled in handshake response.

## First-Slice Scope

The first Wolfram slice is intentionally narrow:

- run a full `/v2/query` computational query returning pods, subpods, and assumptions
- run `/v1/result` for short text answers
- run `/v1/spoken` for spoken-word answers
- validate production and loopback mock base URL policy before client use
- expose manifest-derived JSON and typed core introspection for the operation catalog
- expose health, doctor, self-check, simulate, invoke, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanism: explicit Wolfram AppID in operation input.
- Configuration carries a `credential_id`, but runtime credential injection is not wired for invocation yet.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Capability surface:
  - `wolfram.query` gates full query, short answer, and spoken result operations.
- The connector does not persist AppIDs, query strings, or provider results.

## Network And Runtime Invariants

- Production host: `api.wolframalpha.com`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and broad redirects for live operations.
- Loopback mocks are test-only and require explicit `allow_mock_base_url=true`.
- Default timeout: `30_000 ms`.
- Maximum response bytes: `10_485_760` for full query and `65_536` for short/spoken text endpoints.
- Runtime advertises no replay, subscription, or streaming event support.
- HTTP retry budget retries 429, 408, 5xx, and transient connect/timeout failures; terminal 4xx errors are not retried.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `wolfram.query` | Execute computational query, short-answer, and spoken-result requests. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `wolfram.query` | `GET /v2/query` | `wolfram.query` | `Safe` | `Low` | `Strict` | Read-only computational query returning structured pods and assumptions. |
| `wolfram.short_answer` | `GET /v1/result` | `wolfram.query` | `Safe` | `Low` | `Strict` | Read-only compact text answer for a computational query. |
| `wolfram.spoken_result` | `GET /v1/spoken` | `wolfram.query` | `Safe` | `Low` | `Strict` | Read-only spoken-word text answer for a computational query. |

## Explicit Non-Goals

The first implementation slice does not include:

- AppID credential injection at invoke time
- Wolfram Cloud account administration
- notebook, image, file, or computation upload workflows
- webhook ingest or provider-side push events
- streaming result delivery
- storage of query history or result payloads

These are excluded on purpose:

- The current connector is a bounded request-response computational lookup surface.
- The credential story is intentionally explicit until host injection is implemented.
- Provider result payloads can include sensitive or misleading interpretations and should not become connector state.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, client, runtime, and handshake state
- base URL policy validation
- credential ID redaction in doctor output
- manifest-derived operation metadata
- capability-token verification for invoke when a verifier/token is present
- runtime request/error metrics

The deterministic integration evidence is anchored on no-live-provider HTTP loopback runs covering:

- base URL policy and mock seam behavior
- manifest/runtime/schema provider contract tests
- connector-suite happy path coverage
- manifest interface hash verification through `fwc`
- cross-connector manifest operation audit evidence for `fcp.wolfram`

## Source Notes

- `connectors/wolfram/src/connector.rs` defines lifecycle handling, capability checks, operation dispatch, self-check/doctor output, and manifest-derived introspection.
- `connectors/wolfram/src/client.rs` defines Wolfram API request construction, endpoint-specific response parsing, retry behavior, and health probing.
- `connectors/wolfram/src/types.rs` defines configuration and base URL policy validation.
- `connectors/wolfram/manifest.toml` defines the three-operation catalog, network constraints, and no-listener/no-exec capability posture.
- `connectors/wolfram/tests/provider_contract.rs` covers manifest/runtime/schema contract behavior.
- `connectors/wolfram/tests/connector_suite_happy_path.rs` covers deterministic no-live-provider HTTP loopback behavior.

## Verification Bundle

The closeout bundle is anchored on `scripts/e2e/wolfram_manifest_operations_verification.sh`. It writes a redaction-safe JSONL log to the path supplied as its first argument, or to `/tmp/fcp-wolfram-manifest-ops-<timestamp>.jsonl` by default.

The bundle captures:

- focused formatting, compiler, and clippy checks
- inline unit tests
- manifest/runtime/schema provider-contract tests
- deterministic no-live-provider connector-suite coverage
- manifest interface hash verification through `fwc`
- cross-connector manifest operation audit evidence for `fcp.wolfram`
- a JSONL record asserting 3 manifest operations and 3 runtime introspection operations

## Operator Guidance

**Prerequisites**:

- Use a Wolfram Alpha AppID for live provider calls.
- Pass `app_id` explicitly with each operation until credential injection is implemented.
- Use loopback mock endpoints only with `allow_mock_base_url=true` in debug/test builds.

**Dedicated environment**:

- Prefer a test AppID or loopback fixture for replayable evidence.
- Do not send confidential prompts or proprietary formulas to live Wolfram unless that exposure is acceptable.

**Redaction rules**:

- Redact AppIDs, credential IDs, query strings, request bodies, pod/subpod plaintext, image URLs, assumptions, short/spoken answers, provider payloads, and provider error bodies.
- Treat returned pod text and assumptions as sensitive external content.

**Common remediation**:

- If `health` reports `not_configured`, call `configure` before invoking operations.
- If `self_check` reports `not_handshaken`, complete handshake before self-check.
- If `self_check` reports `base_url_mismatch`, use `https://api.wolframalpha.com` or an explicit loopback mock URL with `allow_mock_base_url=true`.
- If invoke reports missing `app_id`, pass the Wolfram AppID explicitly in operation input.
- If capability verification fails, request `wolfram.query` for the bound connector instance and operation.
- If provider calls are rate-limited or return transient 5xx errors, retry inside the bounded retry budget or rerun after upstream recovery.

**Rerun commands**:

- `FCP_WOLFRAM_USE_RCH=1 CARGO_TARGET_DIR=/tmp/fcp-wolfram-manifest-ops-target scripts/e2e/wolfram_manifest_operations_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-wolfram-manifest-ops-target CARGO_INCREMENTAL=0 cargo fmt --check -p fcp-wolfram`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-wolfram-manifest-ops-target CARGO_INCREMENTAL=0 cargo check -p fcp-wolfram --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-wolfram-manifest-ops-target CARGO_INCREMENTAL=0 cargo clippy -p fcp-wolfram --all-targets --no-deps -- -D warnings`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-wolfram-manifest-ops-target CARGO_INCREMENTAL=0 cargo test -p fcp-wolfram --lib -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-wolfram-manifest-ops-target CARGO_INCREMENTAL=0 cargo test -p fcp-wolfram --test provider_contract -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-wolfram-manifest-ops-target CARGO_INCREMENTAL=0 cargo test -p fcp-wolfram --test connector_suite_happy_path -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-wolfram-manifest-ops-target CARGO_INCREMENTAL=0 cargo run -p fwc -- manifest fix connectors/wolfram/manifest.toml --check --json`
