# Mistral Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/mistral_manifest_operations_verification.sh`
> **Primary upstream**: https://docs.mistral.ai/

## Purpose

This document fixes the operator-facing contract for `fcp.mistral`. The connector exposes bounded Mistral chat completions, embeddings, file transcription, finite realtime transcription, and model discovery through one work-zone connector instance.

The connector is not an unbounded chat-stream or microphone subscription runtime. Its realtime transcription surface is a finite WebSocket session driven by caller-supplied audio bytes.

## Current Runtime Snapshot

The current crate exposes these operations:

- `mistral.chat.completions`
- `mistral.embeddings.create`
- `mistral.audio.transcriptions`
- `mistral.audio.realtime.transcribe`
- `mistral.models.list`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `api_key` or `credential_id`, plus optional `base_url` and `request_timeout_ms`.
- `api_key` mode sends a bearer token to Mistral.
- `credential_id` mode is accepted for configuration metadata but live invocation is blocked until host-side credential injection exists for this connector slice.
- Production base URL is `https://api.mistral.ai/v1`.
- Localhost HTTP overrides are accepted only for deterministic loopback tests.
- Chat completions reject `stream=true`; this slice exposes non-streaming request-response chat only.
- File transcription accepts base64 audio bytes and sends a multipart request to `/audio/transcriptions`.
- Realtime transcription converts HTTPS base URLs to WSS and runs a bounded session on `/v1/audio/transcriptions/realtime`.
- The runtime advertises `streaming_supported=true`, but the streaming mode is finite and connector-local.

## First-Slice Scope

The first Mistral slice is intentionally narrow:

- create non-streaming chat completions from caller-supplied message arrays
- create embeddings for a string or batch input
- transcribe one uploaded audio payload from base64 bytes
- run finite realtime transcription sessions from one base64 audio payload or bounded base64 chunk arrays
- list available models through `/models`
- expose manifest-derived runtime introspection for all five operations

## Auth And Scope Boundary

- Authentication mechanism: Mistral API key, with a configuration-only credential-id mode.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Capability surface:
  - `mistral.chat` gates chat completions.
  - `mistral.embeddings` gates embedding creation.
  - `mistral.audio` gates file transcription and finite realtime transcription.
  - `mistral.models` gates model discovery.
- The connector does not persist prompts, embeddings input, audio bytes, transcripts, model output, or provider responses.
- The connector does not implement host-side credential injection for live provider calls yet.

## Network And Runtime Invariants

- Production host family: `mistral.ai` and `*.mistral.ai`.
- Production port: `443`.
- TLS and SNI are required for live HTTP and WebSocket traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and unsafe host forms for live operations.
- Localhost HTTP overrides are test-only.
- Default HTTP request timeout: `60_000 ms`.
- HTTP operation response ceiling: `10_485_760` bytes, except model listing at `2_097_152` bytes.
- Finite realtime timeout bound: up to `300_000 ms`.
- Maximum realtime audio chunk bytes: `262_144`.
- Maximum realtime audio total bytes: `2_097_152`.
- Maximum realtime events: `1_024`.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `mistral.chat` | Create bounded non-streaming chat completions. |
| `mistral.embeddings` | Create embeddings for text or text batches. |
| `mistral.audio` | Run file transcription and finite realtime transcription. |
| `mistral.models` | List model identifiers visible to the account. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `mistral.chat.completions` | `POST /chat/completions` | `mistral.chat` | `Safe` | `Medium` | `None` | Model output depends on prompt, tool, and sampling input and is not replay-stable. |
| `mistral.embeddings.create` | `POST /embeddings` | `mistral.embeddings` | `Safe` | `Low` | `Strict` | Embedding generation is read-like for a fixed input and model. |
| `mistral.audio.transcriptions` | `POST /audio/transcriptions` | `mistral.audio` | `Safe` | `Low` | `None` | Transcription output can vary by provider model and audio interpretation. |
| `mistral.audio.realtime.transcribe` | `WS /v1/audio/transcriptions/realtime` | `mistral.audio` | `Safe` | `Low` | `None` | Finite WebSocket sessions depend on frame ordering, events, and reconnect behavior. |
| `mistral.models.list` | `GET /models` | `mistral.models` | `Safe` | `Low` | `Strict` | Read-only model catalog discovery. |

## Explicit Non-Goals

The first implementation slice does not include:

- streaming chat completions
- indefinite microphone or audio subscriptions
- provider-hosted file upload management
- persistent prompt, transcript, embedding, or completion storage
- tool execution beyond forwarding provider-supported tool fields in chat requests
- credential vaulting or live credential injection
- account administration, billing, fine-tuning, batch jobs, or safety policy management

These are excluded on purpose:

- Connector-local invoke can safely handle bounded request-response and finite WebSocket sessions, but it cannot supervise indefinite streams across host restarts.
- Prompt, audio, transcript, and embedding payloads are sensitive and must stay out of connector-local persistent state.
- Live credential injection needs a host-owned credential boundary before `credential_id` can be used for provider requests.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, client, and handshake state
- auth mode and whether live requests are supported
- credential-id degradation when host-side credential injection is required
- configured base URL
- request and error counters
- upstream `/models` probe result
- stream=true rejection for chat completions
- manifest-derived operation metadata, schemas, AI hints, safety, idempotency, and network constraints

The deterministic integration evidence is anchored on no-live-provider loopback runs covering:

- `/models` connector-suite happy and provider-error paths
- finite realtime WebSocket frame handling
- manifest/runtime/schema contract tests
- redaction-safe manifest operation audit JSONL evidence

## Source Notes

- `connectors/mistral/src/connector.rs` defines auth/config validation, HTTP request construction, file transcription, finite realtime transcription, lifecycle methods, simulation behavior, and manifest-derived introspection.
- `connectors/mistral/manifest.toml` defines the five-operation catalog, HTTP/WebSocket network constraints, sandbox boundary, and no-listener/no-exec capability posture.
- `connectors/mistral/tests/provider_contract.rs` covers manifest/runtime/schema contract behavior and provider metadata.
- `connectors/mistral/tests/connector_suite_happy_path.rs` covers deterministic HTTP and WebSocket loopback behavior.

## Verification Bundle

The closeout bundle is anchored on `scripts/e2e/mistral_manifest_operations_verification.sh`. The script writes a redaction-safe JSONL log to the path supplied as its first argument, or to `/tmp/fcp-mistral-manifest-ops-<timestamp>.jsonl` by default.

The script currently invokes Cargo directly. In shared agent sessions, use `rch` for the equivalent Cargo proof commands:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-mistral-manifest-ops-target CARGO_INCREMENTAL=0 cargo test -p fcp-mistral mistral_manifest --test provider_contract -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-mistral-manifest-ops-target CARGO_INCREMENTAL=0 cargo test -p fcp-mistral --test connector_suite_happy_path -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-mistral-manifest-ops-target CARGO_INCREMENTAL=0 cargo run -p fcp-conformance --bin fcp-manifest-ops-audit -- --repo-root . --allow-findings --log-jsonl /tmp/fcp-mistral-manifest-ops.jsonl`

The bundle captures:

- manifest/runtime/schema provider-contract tests
- deterministic no-live-provider HTTP and WebSocket connector-suite coverage
- redaction-safe cross-connector manifest operation audit evidence
- a JSONL record asserting 5 manifest operations and 5 runtime introspection operations

## Operator Guidance

**Prerequisites**:

- Use a Mistral API key for live provider verification.
- Use loopback HTTP/WebSocket fixtures for replayable evidence.
- Keep live base URLs on HTTPS Mistral hosts; localhost HTTP is for tests only.

**Dedicated environment**:

- Prefer a test Mistral account or deterministic loopback fixture for proof.
- Do not use production customer prompts, audio, transcripts, or embedding content for repeatable verification.

**Redaction rules**:

- Redact API keys, bearer headers, credential IDs, prompts, message arrays, tool payloads, embedding input, audio bytes, transcripts, model output, provider request IDs, provider payloads, and provider error bodies.
- Treat chat completions, embeddings, and transcripts as sensitive derived external content.

**Common remediation**:

- If `health` reports `unconfigured`, call `configure` with either `api_key` or `credential_id`, then run `handshake`.
- If `self_check` reports `not_configured`, configure the connector before probing `/models`.
- If `self_check` reports `credential_injection_required`, use API-key mode or wait for host-side credential injection support.
- If `self_check` reports `upstream_probe_failed`, verify the API key, base URL, timeout, and provider availability.
- If chat simulation rejects a request, remove `stream=true` and keep the request on the non-streaming chat completion surface.
- If realtime audio input is rejected, provide exactly one supported base64 input shape and keep chunk and total sizes within connector limits.

**Rerun commands**:

- Isolated non-shared runner only: `scripts/e2e/mistral_manifest_operations_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-mistral-manifest-ops-target CARGO_INCREMENTAL=0 cargo test -p fcp-mistral mistral_manifest --test provider_contract -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-mistral-manifest-ops-target CARGO_INCREMENTAL=0 cargo test -p fcp-mistral --test connector_suite_happy_path -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-mistral-manifest-ops-target CARGO_INCREMENTAL=0 cargo run -p fcp-conformance --bin fcp-manifest-ops-audit -- --repo-root . --allow-findings --log-jsonl /tmp/fcp-mistral-manifest-ops.jsonl`
