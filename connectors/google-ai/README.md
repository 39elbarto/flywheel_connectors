# Google AI Connector V3 Contract

> **Status**: runtime contract documented; simulation and manifest drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Generate upstream**: https://ai.google.dev/api/generate-content
> **Embeddings upstream**: https://ai.google.dev/api/embeddings
> **Tokens upstream**: https://ai.google.dev/api/tokens
> **Models upstream**: https://ai.google.dev/api/models
> **Tuning upstream**: https://ai.google.dev/api/tuning
> **Live upstream**: https://ai.google.dev/api/live

## Purpose

This document fixes the operator-facing contract for `fcp.google-ai`. The connector exposes the Google AI Gemini API surface implemented in this crate: content generation, aggregate stream-generation responses, embeddings, token counting, model discovery, tuned-model control-plane operations, local usage counters, and constrained Google Live browser-session token creation.

The connector is intentionally a bounded Gemini API bridge. It is not a full Google GenAI SDK, Vertex AI client, file upload client, Code Assist client, Imagen/VeO media client, chat-memory system, browser runtime, model registry, safety policy engine, or realtime session runner for production browser traffic.

## Current Runtime Snapshot

The current crate exposes these operations:

- `google-ai.generate_content`
- `google-ai.generate_content_stream`
- `google-ai.live.create_browser_session`
- `google-ai.embed_content`
- `google-ai.batch_embed_contents`
- `google-ai.count_tokens`
- `google-ai.list_models`
- `google-ai.get_model`
- `google-ai.tuning.create`
- `google-ai.tuning.list`
- `google-ai.tuning.get`
- `google-ai.tuning.get_operation`
- `google-ai.tuning.cancel`
- `google-ai.get_usage`

Important runtime truths the contract preserves:

- Configuration requires exactly one auth mode: `api_key` or `credential_id`.
- `api_key` mode appends the key as the `key` query parameter to each request URL.
- `credential_id` mode sends `X-FCP-Credential-ID` so the host or egress proxy can inject key material.
- `credential_id` must be a valid UUID.
- Default base URL is `https://generativelanguage.googleapis.com/v1beta`.
- Public base URLs must use HTTPS, exact host `generativelanguage.googleapis.com`, no userinfo, no query string, and no fragment.
- `localhost`, `127.0.0.1`, and `::1` are accepted for deterministic tests with HTTP or HTTPS.
- Runtime request timeout is 30 seconds.
- Requests run through the shared retry loop with two retries.
- 401 and 403 are terminal auth failures; 404 is terminal not-found; 429 is retryable and honors `Retry-After`; 5xx and retryable transport failures are retryable.
- Usage counters are in-memory per connector instance and track request success/error counts plus prompt and candidate token counts when provider responses include usage metadata.
- Handshake installs a `CapabilityVerifier`.
- `invoke` resolves the runtime operation capability from introspection and verifies a bound capability token before dispatch.
- Generation responses add provenance with `source = google-ai`, model, untrusted integrity, tool-call detection, and chunk count.
- Live browser-session creation returns a short-lived `clientSecret` and redaction-safe provenance; the `clientSecret` is not safe to log.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest connector ID is `fcp.google-ai`, while runtime `BaseConnector` and requests use `google-ai`.
- Runtime handshake returns placeholder manifest hash `sha256:google-ai-connector-v1`.
- Runtime `simulate` returns allowed for any operation ID; it does not validate configured state, handshake state, operation inventory, input schema, capability token, or approval policy.
- Runtime `handle_shutdown` shuts down the client runtime but does not clear config, client, verifier, session, or configured/handshaken flags.
- Runtime `google-ai.generate_content_stream` calls the provider stream endpoint but parses the full HTTP response as a JSON array or single object, merges chunks, and returns one aggregate JSON response to FCP callers.
- Runtime `google-ai.tuning.create` and `google-ai.tuning.cancel` require `ApprovalMode::ElevationToken`; the manifest currently labels them as `requires_approval = "interactive"`.
- Runtime `google-ai.live.create_browser_session` supports `prefix_padding_ms` and `silence_duration_ms` fields in introspection, while the manifest lists other Live VAD fields but omits those two names.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should align connector IDs, manifest hash, simulate behavior, shutdown semantics, approval metadata, and Live schema field names before describing this connector as policy-complete.

## First-Slice Scope

The current Google AI README slice documents the existing runtime surface:

- API-key and secretless credential-reference configuration
- Gemini REST base URL policy
- non-streaming content generation and aggregate stream-generation responses
- single and batch embeddings
- token counting
- model listing and model lookup
- tuned-model create/list/get/operation/cancel control-plane operations
- local usage counters
- constrained Live browser-session token creation
- bound capability-token verification for invoke
- provider error mapping, retry behavior, provenance, redaction posture, and readiness surfaces
- deterministic WireMock and loopback realtime tests plus direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Google AI API key or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `google-ai.generate` gates text generation and aggregate stream generation.
  - `google-ai.live_voice` gates Live browser-session token creation.
  - `google-ai.embed` gates single and batch embeddings.
  - `google-ai.models` gates token counting and model discovery.
  - `google-ai.tuning` gates tuned-model control-plane operations.
  - `google-ai.usage` gates local usage counter reads.
- The connector does not persist prompts, completions, embeddings, API keys, credential IDs, tuned-model payloads, Live client secrets, provider payloads, or provider error bodies beyond process memory.
- Generation and embedding operations can expose user prompts and retrieved content to Google AI.
- Tuning operations are high-impact because they can start paid training jobs and create persistent provider-side tuned models.
- Live browser-session tokens are short-lived but sensitive bearer-like material and must not be logged.

## Network And Runtime Invariants

- Production host: `generativelanguage.googleapis.com`.
- Default production API prefix: `/v1beta`.
- Live browser-session token creation can switch the base path to `v1alpha` for `auth_tokens`.
- Production port: `443`.
- TLS and SNI are required by the manifest for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback base URLs are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest timeouts vary by operation:
  - `15_000 ms` for token counting, model lookup/listing, Live token creation, tuning lookup/listing/cancel, and usage.
  - `30_000 ms` for embedding and tuning creation.
  - `60_000 ms` for batch embedding.
  - `120_000 ms` for non-stream generation.
  - `300_000 ms` for stream-generation responses.
- Maximum response bytes range from `262_144` for Live token creation to `52_428_800` for stream-generation responses.
- Sandbox profile is `strict`, with `512 MB` memory, `75%` CPU, `300_000 ms` wall-clock timeout, no exec, no ptrace, no state storage, and no media upload.
- Handshake advertises streaming event capability, but FCP invoke for `generate_content_stream` returns an aggregate response.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `google-ai.generate` | Generate text or aggregate stream-generation chunks. |
| `google-ai.live_voice` | Mint constrained Google Live browser-session tokens. |
| `google-ai.embed` | Create single or batch embeddings. |
| `google-ai.models` | Count tokens and inspect model metadata. |
| `google-ai.tuning` | Create, list, inspect, poll, or cancel tuned-model resources. |
| `google-ai.usage` | Read connector-local usage counters. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `google-ai.generate_content` | `POST /v1beta/{model}:generateContent` | `google-ai.generate` | `Safe` | `Medium` | `None` | Sends prompts/tools to a Gemini model and returns one response. |
| `google-ai.generate_content_stream` | `POST /v1beta/{model}:streamGenerateContent` | `google-ai.generate` | `Safe` | `Medium` | `None` | Calls the stream endpoint but returns merged chunks as one JSON object. |
| `google-ai.live.create_browser_session` | `POST /v1alpha/auth_tokens` | `google-ai.live_voice` | `Safe` | `High` | `None` | Mints a short-lived constrained token for Google Live browser audio. |
| `google-ai.embed_content` | `POST /v1beta/models/{model}:embedContent` | `google-ai.embed` | `Safe` | `Low` | `Strict` | Generates one embedding. |
| `google-ai.batch_embed_contents` | `POST /v1beta/models/{model}:batchEmbedContents` | `google-ai.embed` | `Safe` | `Low` | `Strict` | Generates multiple embeddings in one request. |
| `google-ai.count_tokens` | `POST /v1beta/{model}:countTokens` | `google-ai.models` | `Safe` | `Low` | `Strict` | Counts tokens for a generation-shaped payload. |
| `google-ai.list_models` | `GET /v1beta/models` | `google-ai.models` | `Safe` | `Low` | `Strict` | Lists Gemini models visible to the configured credential. |
| `google-ai.get_model` | `GET /v1beta/{model}` | `google-ai.models` | `Safe` | `Low` | `Strict` | Reads metadata for one model or tuned model resource. |
| `google-ai.tuning.create` | `POST /v1beta/tunedModels` | `google-ai.tuning` | `Dangerous` | `High` | `None` | Starts a tuned-model training job. |
| `google-ai.tuning.list` | `GET /v1beta/tunedModels` | `google-ai.tuning` | `Safe` | `Low` | `Strict` | Lists tuned models. |
| `google-ai.tuning.get` | `GET /v1beta/{tuned_model}` | `google-ai.tuning` | `Safe` | `Low` | `Strict` | Reads metadata for one tuned model. |
| `google-ai.tuning.get_operation` | `GET /v1beta/{operation}` | `google-ai.tuning` | `Safe` | `Low` | `Strict` | Polls one long-running tuning operation. |
| `google-ai.tuning.cancel` | `POST /v1beta/{operation}:cancel` | `google-ai.tuning` | `Dangerous` | `High` | `BestEffort` | Requests cancellation of a tuning operation. |
| `google-ai.get_usage` | local counters | `google-ai.usage` | `Safe` | `Low` | `Strict` | Returns per-instance in-memory usage counters. |

## Explicit Non-Goals

The current implementation does not include:

- Vertex AI endpoints, OAuth service-account flows, Application Default Credentials, or Google Cloud regional model routing
- file upload, file retrieval, cached content APIs, image/video generation, speech synthesis outside Live, or multimodal media upload handling
- true incremental FCP streaming output for `generate_content_stream`
- production browser orchestration, WebRTC, microphone capture, speaker playback, or durable Live session management
- model deletion, tuned-model update/delete, operation list, permission management, dataset import/export, or training cost estimation
- safety-policy enforcement beyond passing provider request fields through
- tool execution, function-call side-effect execution, or host tool sandboxing inside this connector
- durable prompt/completion cache, embedding store, transcript store, or usage ledger

These are excluded on purpose:

- Prompt, completion, embedding, and Live audio flows can carry sensitive data.
- Tuning has provider-side cost and persistent side effects.
- Realtime browser operation needs a separate runtime and redaction contract beyond token minting.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, client state, auth mode, base URL, host policy, secretless credential-injection state, and request metrics
- operation metadata with capability, risk, safety tier, idempotency, schemas, and AI hints
- self-check through `list_models(pageSize = 1)` when credential material is configured
- degraded self-check for secretless credential references
- bound capability-token verification during invoke
- provenance on generation, stream aggregation, Live token creation, and tuning operations
- local usage counters through `google-ai.get_usage`
- current simulation behavior, which is permissive even for unknown operations

The deterministic integration evidence is anchored on connector-local tests covering:

- streaming JSON array parsing and single-object fallback
- provider error taxonomy, rate limits, 401s, 5xx, serialization errors, and FCP error mapping
- redaction of API keys and Live credentials
- usage metrics accumulation
- bound capability-token verification and wrong-capability rejection
- missing capability-token and unknown-operation invoke errors
- all 14 operation IDs in introspection
- tuning create/cancel/get/list/get-operation flows
- Live browser-session token contract and redaction-safe provenance
- realtime loopback coverage for WebSocket lifecycle, audio frames, tool calls, resume, malformed frames, and JSONL redaction
- manifest/runtime operation inventory checks

## Source Notes

- `connectors/google-ai/src/connector.rs` defines configuration parsing, base URL policy, lifecycle handlers, operation metadata, capability-token verification, simulation, and invoke dispatch.
- `connectors/google-ai/src/client.rs` defines Gemini REST paths, API-key query auth, credential-reference header auth, retry dispatch, timeout, usage accounting, health check, model/tuning helpers, and provider error handling.
- `connectors/google-ai/src/realtime.rs` defines deterministic Google Live realtime loopback execution and JSONL evidence helpers.
- `connectors/google-ai/src/types.rs` defines Gemini generation, embedding, model, tuning, usage, and Live browser-session types.
- `connectors/google-ai/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/google-ai/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and AI hints.
- `connectors/google-ai/tests/integration.rs` covers deterministic HTTP, capability-token, operation, usage, and realtime loopback behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/google_ai_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and metadata
- deterministic WireMock coverage for generation, embeddings, models, and tuning
- realtime loopback WebSocket coverage without live Google API calls
- auth, endpoint policy, provider error, lifecycle, simulation, and introspection tests
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a dedicated Google AI API key or host credential reference for live verification.
- Use disposable prompts, outputs, embeddings, and tuned-model IDs.
- Prefer credential-reference mode when host policy should own API-key material.
- Use WireMock and loopback realtime fixtures for routine proof.

**Dedicated environment**:

- Keep prompts, tool declarations, tuning examples, tuned-model names, and Live instructions synthetic.
- Do not tune models with production data through routine verification.
- Do not log Live `clientSecret`, prompts, completions, embeddings, function calls, or realtime transcripts.
- Treat provider-generated tool calls as untrusted suggestions until host policy executes or rejects them.

**Redaction rules**:

- Redact API keys, credential IDs where needed, prompts, completions, system instructions, tool declarations when sensitive, tool calls, tool responses, embeddings, model names when private, tuned-model IDs, training examples, Live client secrets, audio frames, transcripts, provider payloads, provider error bodies, and endpoint URLs when they reveal account topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, retry decisions, token-count summaries, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide exactly one of `api_key` or UUID `credential_id`.
- If base URL validation fails, use `https://generativelanguage.googleapis.com/v1beta` or a loopback verification URL.
- If self-check is degraded with `credential_injection_required`, inject host credentials before running live probes.
- If generation is denied, request `google-ai.generate` and pass a bound token for the target connector instance.
- If tuning is denied, request `google-ai.tuning` plus the required host approval token.
- If stream-generation callers expect token-by-token delivery, use a follow-up FCP streaming implementation rather than relying on the current aggregate response.
- If Live browser sessions fail, verify `v1alpha`, token expiration bounds, model support, and that `clientSecret` is treated as short-lived sensitive material.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-ai-readme cargo check -p fcp-google-ai --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-ai-readme cargo test -p fcp-google-ai --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-ai-readme cargo clippy -p fcp-google-ai --all-targets --no-deps -- -D warnings`
