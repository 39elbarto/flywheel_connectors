# Deepgram Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/deepgram_manifest_operations_verification.sh`
> **Primary upstream**: https://developers.deepgram.com/

## Purpose

This document fixes the operator-facing contract for `fcp.deepgram`. The connector covers prerecorded transcription plus finite realtime transcription sessions through Deepgram Listen. It is not a host-supervised indefinite stream subscription runtime; that long-running surface is deferred until the host owns stream lifecycle, fan-in, fan-out, and cancellation.

## Current Runtime Snapshot

The current crate exposes these operations:

- `deepgram.listen.transcribe`
- `deepgram.listen.stream`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `api_key` or `credential_id`, plus optional `base_url` and `request_timeout_ms`.
- `api_key` mode sends `Authorization: Token <key>`.
- `credential_id` mode is accepted for configuration metadata but live invocation is blocked until host-side credential injection exists for this connector slice.
- Production base URL is `https://api.deepgram.com`; `developers.deepgram.com` is also allowed by policy.
- Localhost HTTP overrides are accepted only for deterministic tests.
- Prerecorded transcription validates `audio_url` and optional declared media size before sending `/v1/listen`.
- Finite realtime transcription converts HTTPS base URLs to WSS and sends bounded audio chunks over `/v1/listen`.
- The runtime advertises `streaming_supported=true` with `streaming_session_mode=finite`.

## First-Slice Scope

The first Deepgram slice is intentionally narrow:

- create prerecorded transcription requests from an audio URL
- run finite realtime transcription sessions from base64 audio input or chunk arrays
- support bounded streaming options for model, encoding, sample rate, endpointing, interim results, connect timeout, session timeout, event limit, reconnect attempts, and reconnect delay
- report provider request IDs, partials, finals, metadata, transcript text, and streaming stats for finite sessions
- expose manifest-derived introspection for the operation catalog and a deferred long-running stream descriptor

## Auth And Scope Boundary

- Authentication mechanism: Deepgram API key, with a configuration-only credential-id mode.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Capability surface:
  - `deepgram.listen` gates prerecorded transcription.
  - `deepgram.listen.streaming` gates finite realtime transcription.
- The connector does not persist audio bytes or transcripts.
- The connector does not implement host-side credential injection for live provider calls yet.

## Network And Runtime Invariants

- Production hosts: `api.deepgram.com` and `developers.deepgram.com`.
- Production port: `443`.
- TLS and SNI are required for live HTTP and WebSocket traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and broad redirects for live operations.
- Localhost overrides are test-only.
- Default prerecorded request timeout: `60_000 ms`.
- Finite streaming timeout bound: up to `300_000 ms`.
- Maximum response bytes: `10_485_760`.
- Maximum streaming audio chunk bytes: `262_144`.
- Maximum streaming audio total bytes: `2_097_152`.
- Runtime advertises finite streaming only; host-supervised indefinite streaming is deferred.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `deepgram.listen` | Create prerecorded transcription requests. |
| `deepgram.listen.streaming` | Run finite realtime transcription WebSocket sessions. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `deepgram.listen.transcribe` | `POST /v1/listen` | `deepgram.listen` | `Safe` | `Low` | `Strict` | Read-oriented transcription over caller-provided media URL. |
| `deepgram.listen.stream` | `WS /v1/listen` | `deepgram.listen.streaming` | `Safe` | `Low` | `None` | Finite realtime transcription depends on session events and audio chunk ordering. |

## Explicit Non-Goals

The first implementation slice does not include:

- host-supervised indefinite audio streaming
- persistent transcript storage
- audio upload hosting
- webhook ingest or provider-side push events
- credential vaulting or live credential injection
- model management, billing, or project administration

These are excluded on purpose:

- Connector-local invoke can safely handle finite sessions but cannot supervise indefinite streams across host restarts.
- Audio and transcript payloads are sensitive and should stay out of persistent connector state.
- Long-running stream subscriptions need host-owned lifecycle and cancellation semantics.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, client, and handshake state
- auth mode and whether live requests are supported
- credential-id degradation when host-side credential injection is required
- configured base URL
- request and error counters
- upstream `/v1/projects` probe result
- finite streaming boundary and deferred long-running operation details

The deterministic integration evidence is anchored on no-live-provider HTTP and WebSocket loopback runs covering:

- prerecorded transcription request handling
- finite realtime WebSocket frame handling
- manifest/runtime/schema contract tests
- connector-suite happy path coverage
- manifest interface-hash verification

## Source Notes

- `connectors/deepgram/src/connector.rs` defines auth/config validation, HTTP transcription, finite WebSocket transcription, deferred long-running stream metadata, lifecycle methods, and manifest-derived introspection.
- `connectors/deepgram/manifest.toml` defines the two-operation catalog, HTTP/WebSocket network constraints, sandbox boundary, and no-listener/no-exec capability posture.
- `connectors/deepgram/tests/provider_contract.rs` covers manifest/runtime/schema contract behavior.
- `connectors/deepgram/tests/connector_suite_happy_path.rs` covers deterministic no-live-provider HTTP and WebSocket loopback behavior.

## Verification Bundle

The closeout bundle is anchored on `scripts/e2e/deepgram_manifest_operations_verification.sh`. It writes a redaction-safe JSONL log to the path supplied as its first argument, or to `/tmp/fcp-deepgram-manifest-ops-<timestamp>.jsonl` by default.

The bundle captures:

- manifest/runtime/schema provider-contract tests
- deterministic no-live-provider HTTP/WebSocket connector-suite coverage
- manifest interface hash verification through `fwc`
- a JSONL record asserting 2 manifest operations and 2 runtime introspection operations

## Operator Guidance

**Prerequisites**:

- Use a Deepgram API key for live provider verification.
- Use loopback HTTP/WebSocket fixtures for replayable evidence.
- Keep prerecorded `audio_url` values HTTPS in live mode, with localhost HTTP only for tests.

**Dedicated environment**:

- Prefer a test Deepgram project or deterministic loopback fixture for proof.
- Do not use production customer audio for repeatable verification.

**Redaction rules**:

- Redact API keys, `Authorization` headers, credential IDs, audio URLs, request bodies, audio bytes, transcripts, partial/final events, metadata payloads, provider request IDs, provider payloads, and provider error bodies.
- Treat transcripts and provider metadata as sensitive external content.

**Common remediation**:

- If `health` reports `unconfigured`, call `configure` with either `api_key` or `credential_id`, then run `handshake`.
- If `self_check` reports `not_configured`, configure the connector before probing `/v1/projects`.
- If `self_check` reports `credential_injection_required`, use API-key mode or wait for host-side credential injection support.
- If `self_check` reports `upstream_probe_failed`, verify the API key, base URL, timeout, and provider availability.
- If streaming fails before metadata arrives, lower `max_events` only for tests or inspect provider close/error frames.
- If audio input is rejected, keep chunks under the per-chunk and total-byte limits and provide exactly one supported base64 input shape.

**Rerun commands**:

- `FCP_DEEPGRAM_USE_RCH=1 CARGO_TARGET_DIR=/tmp/fcp-deepgram-manifest-ops-target scripts/e2e/deepgram_manifest_operations_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-deepgram-manifest-ops-target CARGO_INCREMENTAL=0 cargo test -p fcp-deepgram deepgram_manifest --test provider_contract -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-deepgram-manifest-ops-target CARGO_INCREMENTAL=0 cargo test -p fcp-deepgram --test connector_suite_happy_path -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-deepgram-manifest-ops-target CARGO_INCREMENTAL=0 cargo run -p fwc -- manifest fix connectors/deepgram/manifest.toml --check --json`
