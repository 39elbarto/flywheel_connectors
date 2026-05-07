# Together AI Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/together_connector_verification.sh`
> **Primary upstream**: https://docs.together.ai/

## Purpose

This document fixes the operator-facing contract for `fcp.together`. The connector exposes Together AI through OpenAI-compatible chat, SSE chat streaming, embeddings, model listing, health probing, and a minimal legacy completions path.

The connector is text-focused. Image generation is explicitly deferred to media-generation connectors.

## Current Runtime Snapshot

The current crate exposes these operations:

- `together.chat.completions`
- `together.chat.completions_stream`
- `together.embeddings.create`
- `together.models.list`
- `together.health`
- `together.completions.legacy`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `api_key` or `credential_id`, plus optional `base_url`, default model settings, request timeout, model-cache TTL, and rate-limit wait policy.
- API-key mode sends a bearer token to Together.
- Credential-id mode emits an `x-fcp-credential-id` header and requires host-side egress credential injection for live traffic.
- Default base URL is `https://api.together.ai/v1`.
- Loopback HTTP base URLs are accepted for deterministic tests.
- Default chat model is `openai/gpt-oss-20b`.
- Default embedding model is `intfloat/multilingual-e5-large-instruct`.
- Together model IDs must include a namespace and model segment, for example `openai/gpt-oss-20b`.
- SSE chat streaming returns redaction-safe chunk metadata and assembled text from a bounded invoke call; FCP subscribe is not implemented.
- The legacy completions operation exists only for older callers that cannot send chat messages.

## First-Slice Scope

The first Together slice is intentionally narrow:

- create non-streaming chat completions from caller-supplied message arrays
- create SSE chat completions and return assembled content plus chunk metadata
- forward supported Together provider extensions such as `reasoning_effort` and `safety_model`
- create text embeddings
- list and cache Together model IDs
- run a bounded health probe using model listing
- support minimal legacy `/v1/completions`
- enforce capability-token checks for invoke paths
- emit redaction-safe loopback and optional live JSONL evidence

## Auth And Scope Boundary

- Authentication mechanism: Together API key, with host-injected credential-id mode.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `together.chat` gates chat, SSE chat, and legacy completions.
  - `together.embeddings` gates embedding creation.
  - `together.models.read` gates model discovery.
  - `together.health.read` gates the health probe.
- The connector does not persist prompts, completions, streamed chunks, embedding input, vectors, model catalogs, or provider responses.
- Credential-id mode is a host-egress contract, not direct proof that live Together will accept the request without an injection layer.

## Network And Runtime Invariants

- Production host: `api.together.ai`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and unsafe host forms for live operations.
- Localhost HTTP overrides are test-only.
- Default request timeout: `60_000 ms`.
- Model-list and health timeout bounds are shorter: health uses `5_000 ms`, models list uses `30_000 ms`.
- SSE chat streaming may run up to `300_000 ms`.
- Maximum response bytes are `10_485_760`.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `180_000 ms` wall-clock timeout, no exec, and no ptrace.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `together.chat` | Create chat, SSE chat, and legacy text completions. |
| `together.embeddings` | Create Together-hosted text embeddings. |
| `together.models.read` | List Together model identifiers. |
| `together.health.read` | Run a bounded model-list readiness probe. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `together.chat.completions` | `POST /v1/chat/completions` | `together.chat` | `Safe` | `Medium` | `None` | Model output depends on prompt, tools, sampling input, reasoning effort, and safety model. |
| `together.chat.completions_stream` | `POST /v1/chat/completions` with SSE | `together.chat` | `Safe` | `Medium` | `None` | Streaming output depends on event ordering and provider deltas. |
| `together.embeddings.create` | `POST /v1/embeddings` | `together.embeddings` | `Safe` | `Low` | `Strict` | Embedding generation is read-like for a fixed input and model. |
| `together.models.list` | `GET /v1/models` | `together.models.read` | `Safe` | `Low` | `Strict` | Read-only model catalog discovery with in-memory cache support. |
| `together.health` | `GET /v1/models` bounded probe | `together.health.read` | `Safe` | `Low` | `Strict` | Health probe confirms Together reachability and model-list path. |
| `together.completions.legacy` | `POST /v1/completions` | `together.chat` | `Safe` | `Medium` | `None` | Compatibility path for older callers that cannot send chat messages. |

## Explicit Non-Goals

The first implementation slice does not include:

- image generation or image editing
- audio, video, speech, file, fine-tuning, batch, or dataset APIs
- FCP subscription-based streaming
- persistent prompt, completion, stream, embedding, or model-cache storage
- direct credential vaulting
- public-zone invocation
- expansion of legacy completions beyond minimal compatibility

These are excluded on purpose:

- The useful first slice is text inference and embeddings through Together's OpenAI-compatible surface.
- Image generation has different safety and artifact-handling requirements and belongs in a dedicated media connector.
- Legacy completions remain available only to bridge old callers; new work should use chat completions.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake, auth mode, base URL, default models, request counters, and error counters
- redacted auth labels rather than bearer tokens
- base URL policy for `api.together.ai/v1` and loopback-compatible paths
- explicit image-generation deferral
- model-list probe health metadata
- operation schemas, safety, risk, idempotency, and AI hints

The deterministic integration evidence is anchored on WireMock loopback runs covering:

- chat completion
- SSE chat streaming
- embeddings
- model listing and cache use
- health probe
- provider error redaction
- rate-limit retry policy
- cancellation before dispatch
- FCP trait invoke capability-token validation
- shutdown cleanup
- redaction-safe JSONL evidence

## Source Notes

- `connectors/together/src/client.rs` defines Together base URL policy, auth headers, direct model-listing behavior, rate-limit handling, and model cache behavior.
- `connectors/together/src/connector.rs` defines lifecycle, capability verification, operation dispatch, introspection, health/doctor behavior, and legacy completions routing.
- `connectors/together/src/types.rs` defines chat, embedding, legacy prompt, model ID, reasoning-effort, safety-model, and request validation.
- `connectors/together/manifest.toml` defines the six-operation catalog, network constraints, sandbox boundary, and no-listener/no-exec posture.
- `connectors/together/tests/conformance.rs` checks manifest and runtime operation surface alignment.
- `connectors/together/tests/provider_contract.rs` checks provider registry metadata and redaction behavior.
- `connectors/together/tests/integration.rs` covers loopback chat, streaming, embeddings, model listing, health, redaction, rate limits, cancellation, trait invoke, and JSONL evidence.
- `connectors/together/tests/live_verification.rs` emits structured skip records unless `TOGETHER_API_KEY` is present.

## Verification Bundle

The closeout bundle is anchored on `scripts/e2e/together_connector_verification.sh`. It writes artifacts under `artifacts/e2e/together/<run_id>` by default and offloads Cargo work through `rch`.

The bundle captures:

- manifest check through `fwc` or `rch exec -- cargo run -p fwc`
- `rch exec -- cargo check -p fcp-together --all-targets`
- `rch exec -- cargo fmt --package fcp-together --check`
- WireMock JSONL loopback coverage
- optional live smoke coverage gated by `TOGETHER_API_KEY`
- JSONL extraction for fixture and live records
- `rch exec -- cargo clippy -p fcp-together --all-targets --no-deps -- -D warnings`
- replay script and environment metadata

## Operator Guidance

**Prerequisites**:

- Use a Together API key in `TOGETHER_API_KEY` for live provider verification.
- Use WireMock loopback fixtures for deterministic proof.
- Use `TOGETHER_LIVE_CHAT_MODEL` and `TOGETHER_LIVE_EMBEDDING_MODEL` only when live model defaults need to differ from the connector defaults.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a test Together account for live runs and keep live prompts intentionally small.

**Redaction rules**:

- Redact API keys, bearer headers, credential IDs, prompts, completions, streamed text chunks, tool-call arguments, safety-model context, embedding input, vectors, raw model IDs when sensitive, provider payloads, and provider error bodies.
- The verification JSONL records use counts, byte lengths, status values, cleanup state, retry decisions, and model ID hashes.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one of `api_key` or `credential_id`, then run handshake.
- If `self_check` reports `credential_injection_required`, run behind the host egress injection layer or switch to API-key mode for direct live probes.
- If base URL validation fails, use `https://api.together.ai/v1` or a localhost loopback URL for tests.
- If a model is rejected, use a namespace/model identifier such as `openai/gpt-oss-20b`.
- If `reasoning_effort` is rejected, use `low`, `medium`, or `high`.
- If embeddings are rejected, use non-empty input and an embedding model such as `intfloat/multilingual-e5-large-instruct`.
- If a caller can send chat messages, prefer `together.chat.completions` over `together.completions.legacy`.

**Rerun commands**:

- `FCP_TOGETHER_TARGET_DIR=/tmp/fcp-together-e2e scripts/e2e/together_connector_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-together-e2e cargo check -p fcp-together --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-together-e2e cargo test -p fcp-together --test integration together_loopback_e2e_jsonl_matrix -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-together-e2e cargo test -p fcp-together --test live_verification together_live_smoke_or_structured_skip_jsonl -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-together-e2e cargo clippy -p fcp-together --all-targets --no-deps -- -D warnings`
