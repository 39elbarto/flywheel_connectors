# Whisper Connector V3 Contract

> **Status**: runtime contract documented; OpenAI API/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **OpenAI speech-to-text guide**: https://developers.openai.com/api/docs/guides/speech-to-text
> **OpenAI whisper-1 model page**: https://developers.openai.com/api/docs/models/whisper-1

## Purpose

This document fixes the operator-facing contract for `fcp.whisper`. The connector currently exposes an OpenAI-compatible speech-to-text surface implemented in this crate: transcription, translation to English, language detection, verbose transcription, model listing, provider health, in-process usage counters, and supported format listing.

The connector is intentionally a bounded audio transcription bridge. It is not a local Whisper runtime, realtime transcription client, diarization client, speaker-recognition engine, audio recorder, file storage service, audio chunker, subtitle editor, billing client, or arbitrary OpenAI API proxy.

## Current Runtime Snapshot

The current crate exposes these invoke operations:

- `whisper.transcribe`
- `whisper.translate`
- `whisper.detect_language`
- `whisper.transcribe_verbose`
- `whisper.list_models`
- `whisper.health`
- `whisper.usage`
- `whisper.formats`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-whisper`.
- Runtime `BaseConnector` ID is `whisper`.
- Manifest connector ID and handshake connector ID are `fcp.whisper`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000`.
- Configuration requires exactly one of `api_key` or `credential_id`.
- `api_key` is trimmed and rejected when missing or blank.
- `credential_id` must be a string and a valid UUID.
- Supplying both `api_key` and `credential_id` is rejected.
- Default `base_url` is `https://api.openai.com/v1`.
- Non-string `base_url` values are ignored and the default endpoint is used.
- Runtime does not validate `base_url` against the manifest network constraints.
- Default request timeout is 120 seconds.
- Optional `request_timeout_ms` must be a positive integer and at most 120000.
- Client construction trims trailing slashes from `base_url`.
- User agent is `fcp-whisper/0.1.0 (FCP connector)`.
- Direct API-key mode sends `Authorization: Bearer`.
- Credential-reference mode sends `X-FCP-Credential-Id` and expects host or egress-proxy injection.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime `invoke` checks configured plus handshaken state through `base.check_ready()`.
- Runtime `invoke` does not verify `capability_token`.
- Canonical `simulate()` does verify a bound capability token when a canonical `SimulateRequest` is supplied.
- Legacy `simulate()` only checks whether `operation_id` maps to a known capability.
- `handle_configure()` creates a new client, stores config, and sets configured.
- `handle_configure()` does not clear an existing verifier, session ID, or base handshaken state.
- `handle_handshake()` requires configuration. It installs a verifier only when params parse as a canonical `HandshakeRequest`; legacy `session_id` handshake sets only session/base flags.
- Handshake returns operation-name strings in `capabilities`, not the manifest capability IDs.
- `health()` reports healthy only when configuration exists and `session_id.is_some()`.
- `doctor()` checks local configuration, client initialization, and session presence only; it does not call OpenAI.
- `self_check()` returns `ok` when configured and `degraded` when unconfigured; it does not validate endpoint, auth, model, or provider reachability.
- `handle_shutdown()` clears client, config, verifier, and base lifecycle flags, but does not clear `session_id` or request/error counters.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- OpenAI's current speech-to-text guide describes file-upload transcription/translation endpoints and current model choices. Runtime sends JSON bodies containing `audio_base64` and/or `audio_url` to `/audio/transcriptions` and `/audio/translations`.
- Runtime accepts `audio_url`, but OpenAI's hosted audio endpoints are file-upload oriented. This may only work with an OpenAI-compatible proxy that accepts JSON audio references.
- Runtime allows any string `base_url`; manifest network constraints allow only `api.openai.com` on port 443.
- Runtime `SUPPORTED_FORMATS` includes `flac` and `ogg`, while the current OpenAI speech-to-text guide lists `mp3`, `mp4`, `mpeg`, `mpga`, `m4a`, `wav`, and `webm` for file uploads.
- Runtime `list_models` is hardcoded and does not call `/models`.
- Runtime hardcoded `list_models` includes `whisper-large-v3`, while the OpenAI hosted model page centers the hosted `whisper-1` model and newer speech-to-text models are documented separately.
- Runtime `health` calls `/models` and reports provider reachability, but lifecycle `doctor()` and `self_check()` do not.
- Runtime stores a `HttpRetryConfig`, but direct reqwest calls do not run through a connector retry loop.
- Manifest rate-limit blocks are documented intent; runtime has no connector-local rate-limit enforcement.
- Runtime canonical simulate verifies bound capability tokens, but invoke does not verify capability tokens.
- Runtime does not bind canonical simulate tokens to audio source, model, file, account, or endpoint resource URIs.
- Manifest state model is stateless and forbids `storage.state`; runtime keeps config, client, verifier, session, request counters, and error counters in process memory only.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should decide whether this connector targets OpenAI's hosted multipart API or a JSON OpenAI-compatible proxy, align supported formats and model listing with the chosen target, validate `base_url` against manifest policy or document proxy support, add invoke-time bound capability verification, add resource binding where useful, wire or remove retry/rate-limit metadata, make self-check/doctor readiness meaningful, and add a tracked verification bundle.

## First-Slice Scope

The current Whisper README slice documents the existing runtime surface:

- API-key and credential-reference configuration
- OpenAI-compatible transcription and translation request paths
- language detection and verbose transcription behavior
- model, health, usage, and format helper operations
- legacy and canonical simulation behavior
- lifecycle, health, doctor, self-check, introspection, and shutdown behavior
- runtime/manifest drift around OpenAI transport shape, model/format claims, endpoint policy, capability enforcement, retries, rate limits, and persistence
- deterministic connector tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms:
  - direct API key
  - host-injected `credential_id`
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability metadata:
  - `whisper.transcription`
  - `whisper.translation`
  - `whisper.info`
- Handshake can install a verifier for canonical simulate, but invoke does not use it.
- Invoke does not reject missing, malformed, wrong-operation, wrong-resource, or wrong-capability tokens.
- No operation requires approval tokens at runtime or in the manifest.
- The connector does not persist API keys, credential IDs, audio bytes, audio URLs, transcript text, detected languages, provider errors, request counters, or session IDs outside process memory.
- Audio and transcript payloads can contain private, work, credential, health, or regulated data. Treat live output according to the source audio and account policy.

## Network And Runtime Invariants

- Default endpoint: `https://api.openai.com/v1`.
- Transcription path: `POST /audio/transcriptions`.
- Translation path: `POST /audio/translations`.
- Provider health path: `GET /models`.
- Direct key mode sends `Authorization: Bearer {api_key}`.
- Credential-reference mode sends `X-FCP-Credential-Id: {uuid}`.
- Requests send `Accept: application/json`.
- Runtime transcription/translation sends JSON bodies, not multipart file uploads.
- `whisper.transcribe` defaults `model` to `whisper-1` and `response_format` to `json`.
- `whisper.translate` defaults `model` to `whisper-1` and returns English text.
- `whisper.detect_language` calls transcription with `response_format = "verbose_json"`.
- `whisper.transcribe_verbose` calls transcription with `response_format = "verbose_json"` and `timestamp_granularities = ["word", "segment"]`.
- Audio input validation requires nonempty `audio_base64` or nonempty `audio_url`.
- Base64 input size is estimated as `len * 3 / 4` and must be at most 25 MB.
- Runtime does not validate file extension, MIME type, URL scheme, response format, language code, model ID, or temperature bounds before sending provider calls.
- Empty successful responses are normalized to `{}`.
- OpenAI-style JSON error bodies are parsed for `error.message`.
- HTTP 401 maps to auth failure.
- HTTP 429 maps to rate limited, using `Retry-After` when present and otherwise defaulting to 60 seconds.
- Other non-success statuses map to provider API errors.
- Request counters increment before dispatch.
- Error counters increment only for typed Whisper operation errors.
- No local model process, realtime stream, file store, native listener, background queue, or chunking worker is started by this connector.

## Operation Inventory

| Operation | Runtime behavior | Capability metadata | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|------------------|---------------------|------------|-----------|-------------|----------------|
| `whisper.transcribe` | JSON `POST /audio/transcriptions`; returns text/language/duration/segments | `whisper.transcription` | `Safe` | `Low` | `Strict` | `audio_base64` or `audio_url` |
| `whisper.translate` | JSON `POST /audio/translations`; returns English text/source language/duration | `whisper.translation` | `Safe` | `Low` | `Strict` | `audio_base64` or `audio_url` |
| `whisper.detect_language` | JSON transcription with `verbose_json`; returns language/confidence | `whisper.transcription` | `Safe` | `Low` | `Strict` | `audio_base64` or `audio_url` |
| `whisper.transcribe_verbose` | JSON transcription with verbose format and word/segment granularity | `whisper.transcription` | `Safe` | `Low` | `Strict` | `audio_base64` or `audio_url` |
| `whisper.list_models` | Return hardcoded Whisper model metadata | `whisper.info` | `Safe` | `Low` | `Strict` | none |
| `whisper.health` | Call `/models` and return reachability status | `whisper.info` | `Safe` | `Low` | `Strict` | none |
| `whisper.usage` | Return in-process request/error counters | `whisper.info` | `Safe` | `Low` | `Strict` | none |
| `whisper.formats` | Return hardcoded format list and 25 MB cap | `whisper.info` | `Safe` | `Low` | `Strict` | none |

## Supported Formats Reported By Runtime

`whisper.formats` reports:

- `mp3`
- `mp4`
- `mpeg`
- `mpga`
- `m4a`
- `wav`
- `webm`
- `flac`
- `ogg`

The current OpenAI hosted file-upload guide lists a narrower hosted input set. Treat this runtime list as the connector's local allow/metadata surface, not proof that every configured backend accepts every format.

## Explicit Non-Goals

The current implementation does not include:

- local Whisper model loading, GPU inference, model download, model selection beyond request fields, or offline transcription
- OpenAI Realtime transcription, streaming deltas, microphone capture, call transcription, or live media sessions
- multipart file upload assembly, file fetching for `audio_url`, chunking, compression, sample-rate conversion, silence trimming, or subtitle editing
- diarization, speaker identification, voice activity detection, forced alignment, profanity filtering, PII redaction, or transcript post-processing
- OpenAI billing/usage API calls, per-model usage accounting, pricing lookup, or dashboard integration
- retry loops, rate-limit pools, transcript caching, durable audit logs, or audio/transcript storage
- invoke-time capability-token verification, approval-token verification, or per-audio resource binding

These are excluded on purpose:

- Audio often contains sensitive speech, names, credentials, or regulated data.
- Hosted audio transcription APIs have provider-specific payload and model constraints.
- A general OpenAI proxy would bypass the connector's typed capability model.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, `introspect()`, and `shutdown()` are part of the public closeout contract. They surface:

- configured/unconfigured state, session presence, client presence, request counters, and error counters
- local-only self-check state with no provider probe
- provider reachability only through invoke operation `whisper.health`
- typed introspection with operations, schemas, capability IDs, risk levels, safety tiers, idempotency, and agent hints
- legacy simulation allow/deny for known operation IDs
- canonical simulation with bound capability-token verification
- typed provider/FCP error mapping for missing input, oversized base64 audio, auth failures, 429s, transport failures, JSON errors, malformed responses, and provider API errors

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, canonical handshake, secret redaction, loopback speech fixtures, capability-token denial for wrong zone/instance, simulate behavior, and shutdown
- transcribe, translate, detect language, verbose transcription, model listing, health, usage, and formats
- provider error taxonomy for audio validation, auth, rate limit, provider errors, network failure, timeout, and malformed shapes
- structured JSONL evidence logs that redact API keys, audio bytes, audio URLs, transcripts, provider bodies, speaker names, email-like sentinels, and local paths
- manifest/runtime conformance for operation count, operation IDs, schemas, capabilities, risk levels, safety tiers, idempotency, AI hints, network constraints, and error taxonomy

## Source Notes

- `connectors/whisper/src/connector.rs` defines configuration parsing, lifecycle handlers, operation catalog, simulation paths, audio input validation, introspection, and invoke dispatch.
- `connectors/whisper/src/client.rs` defines OpenAI-compatible HTTP transport, auth headers, base URL, timeout, request paths, error parsing, rate-limit mapping, and client shutdown.
- `connectors/whisper/src/types.rs` defines OpenAI-style API error response shapes.
- `connectors/whisper/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/whisper/manifest.toml` defines the manifest operation catalog, OpenAI network constraints, sandbox boundary, zone policy, rate-limit intent, and stateless intent.
- `connectors/whisper/tests/integration.rs` and `connectors/whisper/tests/conformance_contract.rs` contain the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/whisper/README.md
ubs connectors/whisper/README.md
LC_ALL=C rg -n '[^ -~]' connectors/whisper/README.md
rg -n '\bmaster\b' connectors/whisper/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-whisper
rch exec -- cargo check -p fcp-whisper --all-targets
rch exec -- cargo clippy -p fcp-whisper --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Use a dedicated non-production OpenAI-compatible endpoint and short synthetic audio fixture for verification.
- Treat `audio_url` as backend-specific; the runtime forwards it as JSON and does not fetch it.
- Treat `whisper.list_models` and `whisper.formats` as local metadata, not live provider truth.
- Prefer `whisper.health` over lifecycle `self_check()` when you need provider reachability.
- Do not rely on invoke for capability enforcement until it uses the installed verifier.
- Do not rely on shutdown to erase session ID or request/error counters.
