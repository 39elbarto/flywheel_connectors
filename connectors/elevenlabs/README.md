# ElevenLabs Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/elevenlabs_manifest_operations_verification.sh`
> **Primary upstream**: https://elevenlabs.io/docs

## Purpose

This document fixes the operator-facing contract for `fcp.elevenlabs`. The connector exposes ElevenLabs voice discovery, finite request-response text-to-speech, bounded HTTP chunked text-to-speech streaming, and finite Scribe realtime transcription.

The connector is not a host-supervised indefinite audio stream runtime. Long-running Scribe sessions and WebSocket input-stream TTS are deferred until the host owns stream lifecycle, fan-in, fan-out, shutdown, and restart supervision.

## Current Runtime Snapshot

The current crate exposes these operations:

- `elevenlabs.voices.list`
- `elevenlabs.tts.generate`
- `elevenlabs.tts.stream`
- `elevenlabs.scribe.realtime.transcribe`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `api_key` or `credential_id`, plus optional `base_url` and `request_timeout_ms`.
- `api_key` mode sends the `xi-api-key` header.
- `credential_id` mode is accepted for configuration metadata but live invocation is blocked until host-side credential injection exists for this connector slice.
- Production base URL is `https://api.elevenlabs.io/v1`.
- Localhost HTTP overrides are accepted only for deterministic loopback tests.
- Request-response TTS returns a single base64 audio object.
- HTTP chunked TTS streaming returns bounded base64 audio chunks, chunk sizes, total byte count, and provenance metadata.
- Finite Scribe realtime transcription converts HTTPS base URLs to WSS and runs a bounded WebSocket session with caller-supplied audio bytes.
- Runtime introspection advertises two deferred host-owned surfaces: long-running Scribe transcription and WebSocket input-stream TTS.

## First-Slice Scope

The first ElevenLabs slice is intentionally narrow:

- list voices through `/voices`
- synthesize one finite TTS response for a complete text input
- synthesize bounded HTTP chunked TTS output with explicit chunk and byte ceilings
- run finite Scribe realtime transcription sessions from one base64 audio payload or bounded base64 chunk arrays
- expose manifest-derived runtime introspection for all four connector-local operations
- advertise host-required follow-up surfaces without pretending connector-local invoke can supervise them

## Auth And Scope Boundary

- Authentication mechanism: ElevenLabs API key, with a configuration-only credential-id mode.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Capability surface:
  - `elevenlabs.voices` gates voice discovery.
  - `elevenlabs.tts` gates finite request-response TTS.
  - `elevenlabs.tts.streaming` gates bounded HTTP chunked TTS streaming.
  - `elevenlabs.stt.streaming` gates finite Scribe realtime transcription.
- The connector does not persist text prompts, voice settings, audio bytes, transcripts, provider configs, or provider responses.
- The connector does not implement host-side credential injection for live provider calls yet.

## Network And Runtime Invariants

- Production host family: `elevenlabs.io` and `*.elevenlabs.io`.
- Production port: `443`.
- TLS and SNI are required for live HTTP and WebSocket traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and unsafe host forms for live operations.
- Localhost HTTP overrides are test-only.
- Default HTTP request timeout: `60_000 ms`.
- Voice listing response ceiling: `2_097_152` bytes.
- Request-response TTS response ceiling: `33_554_432` bytes.
- Bounded TTS stream response ceiling and default `max_audio_bytes`: `8_388_608` bytes.
- Maximum TTS stream audio bytes: `16_777_216`.
- Default TTS stream chunks: `1_024`; maximum: `4_096`.
- Finite Scribe realtime timeout bound: up to `300_000 ms`.
- Maximum realtime audio chunk bytes: `262_144`.
- Maximum realtime audio total bytes: `2_097_152`.
- Maximum realtime events: `1_024`.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `elevenlabs.voices` | Discover voice identifiers before synthesis. |
| `elevenlabs.tts` | Generate one finite audio object from complete text. |
| `elevenlabs.tts.streaming` | Generate bounded HTTP chunked audio with byte and chunk ceilings. |
| `elevenlabs.stt.streaming` | Run finite Scribe realtime transcription sessions. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `elevenlabs.voices.list` | `GET /voices` | `elevenlabs.voices` | `Safe` | `Low` | `Strict` | Read-only voice catalog discovery. |
| `elevenlabs.tts.generate` | `POST /text-to-speech/{voice_id}` | `elevenlabs.tts` | `Safe` | `Medium` | `None` | Synthesis output depends on text, model, voice, and settings. |
| `elevenlabs.tts.stream` | `POST /text-to-speech/{voice_id}/stream` | `elevenlabs.tts.streaming` | `Safe` | `Medium` | `None` | Chunked synthesis depends on provider streaming behavior and connector byte ceilings. |
| `elevenlabs.scribe.realtime.transcribe` | `WS /v1/speech-to-text/realtime` | `elevenlabs.stt.streaming` | `Safe` | `Low` | `None` | Finite transcription depends on frame ordering, session events, and reconnect behavior. |

## Explicit Non-Goals

The first implementation slice does not include:

- host-supervised indefinite Scribe sessions
- WebSocket input-stream TTS for partial text fan-in
- persistent text, voice, audio, transcript, or provider-config storage
- voice creation, cloning, editing, deletion, or library management
- dubbing, sound effects, history, billing, project administration, or account management
- credential vaulting or live credential injection

These are excluded on purpose:

- Connector-local invoke can safely handle finite request-response and bounded streaming sessions, but it cannot supervise indefinite fan-in/fan-out across host restarts.
- Text prompts, generated audio, transcripts, previous text, and provider configs are sensitive and must stay out of connector-local persistent state.
- Long-running streams need host-owned cancellation, restart, and policy-gated broadcast semantics.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, client, and handshake state
- auth mode and whether live requests are supported
- credential-id degradation when host-side credential injection is required
- configured base URL
- request and error counters
- upstream `/voices` probe result
- finite streaming session mode
- manifest-derived operation metadata, schemas, AI hints, safety, idempotency, and network constraints
- deferred host-owned operation descriptors for long-running Scribe and WebSocket input-stream TTS

The deterministic integration evidence is anchored on no-live-provider loopback runs covering:

- `/voices` connector-suite happy path
- bounded HTTP chunked TTS response handling
- finite Scribe realtime WebSocket frame handling
- manifest/runtime/schema contract tests
- redaction-safe manifest operation audit JSONL evidence

## Source Notes

- `connectors/elevenlabs/src/connector.rs` defines auth/config validation, HTTP request construction, request-response TTS, bounded chunked TTS, finite Scribe realtime transcription, lifecycle methods, simulation behavior, deferred host-owned operation metadata, and manifest-derived introspection.
- `connectors/elevenlabs/manifest.toml` defines the four-operation catalog, HTTP/WebSocket network constraints, sandbox boundary, and no-listener/no-exec capability posture.
- `connectors/elevenlabs/tests/provider_contract.rs` covers manifest/runtime/schema contract behavior, provider metadata, and deferred operation descriptors.
- `connectors/elevenlabs/tests/connector_suite_happy_path.rs` covers deterministic no-live-provider HTTP and WebSocket loopback behavior.

## Verification Bundle

The closeout bundle is anchored on `scripts/e2e/elevenlabs_manifest_operations_verification.sh`. The script writes a redaction-safe JSONL log to the path supplied as its first argument, or to `/tmp/fcp-elevenlabs-manifest-ops-<timestamp>.jsonl` by default.

The script currently invokes Cargo directly. In shared agent sessions, use `rch` for the equivalent Cargo proof commands:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-elevenlabs-manifest-ops-target CARGO_INCREMENTAL=0 cargo test -p fcp-elevenlabs elevenlabs_manifest --test provider_contract -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-elevenlabs-manifest-ops-target CARGO_INCREMENTAL=0 cargo test -p fcp-elevenlabs --test connector_suite_happy_path -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-elevenlabs-manifest-ops-target CARGO_INCREMENTAL=0 cargo run -p fcp-conformance --bin fcp-manifest-ops-audit -- --repo-root . --allow-findings --log-jsonl /tmp/fcp-elevenlabs-manifest-ops.jsonl`

The bundle captures:

- manifest/runtime/schema provider-contract tests
- deterministic no-live-provider HTTP and WebSocket connector-suite coverage
- redaction-safe cross-connector manifest operation audit evidence
- a JSONL record asserting 4 manifest operations and 4 runtime introspection operations

## Operator Guidance

**Prerequisites**:

- Use an ElevenLabs API key for live provider verification.
- Use loopback HTTP/WebSocket fixtures for replayable evidence.
- Keep live base URLs on HTTPS ElevenLabs hosts; localhost HTTP is for tests only.

**Dedicated environment**:

- Prefer a test ElevenLabs account or deterministic loopback fixture for proof.
- Do not use production customer text, voices, audio, previous text, or transcripts for repeatable verification.

**Redaction rules**:

- Redact API keys, `xi-api-key` headers, credential IDs, voice IDs from private accounts, text prompts, voice settings, pronunciation dictionary locators, generated audio, audio chunks, transcripts, previous text, provider configs, provider payloads, and provider error bodies.
- Treat TTS outputs and transcripts as sensitive derived external content.

**Common remediation**:

- If `health` reports `unconfigured`, call `configure` with either `api_key` or `credential_id`, then run `handshake`.
- If `self_check` reports `not_configured`, configure the connector before probing `/voices`.
- If `self_check` reports `credential_injection_required`, use API-key mode or wait for host-side credential injection support.
- If `self_check` reports `upstream_probe_failed`, verify the API key, base URL, timeout, and provider availability.
- If TTS input is rejected, provide non-empty `voice_id` and `text`, keep `model_id` inside the advertised enum, and keep `voice_settings` values within schema bounds.
- If chunked TTS fails, lower `max_audio_bytes` or `max_chunks` only for tests, and confirm the provider returned at least one non-empty audio chunk.
- If realtime transcription input is rejected, provide exactly one supported base64 input shape and keep audio format, sample rate, event, chunk, and reconnect bounds inside schema limits.

**Rerun commands**:

- Isolated non-shared runner only: `scripts/e2e/elevenlabs_manifest_operations_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-elevenlabs-manifest-ops-target CARGO_INCREMENTAL=0 cargo test -p fcp-elevenlabs elevenlabs_manifest --test provider_contract -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-elevenlabs-manifest-ops-target CARGO_INCREMENTAL=0 cargo test -p fcp-elevenlabs --test connector_suite_happy_path -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-elevenlabs-manifest-ops-target CARGO_INCREMENTAL=0 cargo run -p fcp-conformance --bin fcp-manifest-ops-audit -- --repo-root . --allow-findings --log-jsonl /tmp/fcp-elevenlabs-manifest-ops.jsonl`
