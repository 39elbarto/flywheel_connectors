# Qwen Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/qwen_connector_verification.sh`
> **Primary upstream**: https://www.alibabacloud.com/help/en/model-studio/

## Purpose

This document fixes the operator-facing contract for `fcp.qwen`. The connector exposes Alibaba Qwen through DashScope OpenAI-compatible chat, SSE chat streaming, embeddings, model listing, and a bounded health probe.

The connector is scoped to DashScope compatible mode. It intentionally does not call DashScope-native `/api/v1/services` endpoints.

## Current Runtime Snapshot

The current crate exposes these operations:

- `qwen.chat.completions`
- `qwen.chat.completions_stream`
- `qwen.embeddings.create`
- `qwen.models.list`
- `qwen.health`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `api_key` or `credential_id`, plus optional `base_url`, default model settings, request timeout, model-cache TTL, and rate-limit wait policy.
- API-key mode sends a bearer token to DashScope compatible mode.
- Credential-id mode emits an `x-fcp-credential-id` header and requires host-side egress credential injection for live traffic.
- Default base URL is `https://dashscope-intl.aliyuncs.com/compatible-mode/v1`.
- The Beijing base URL `https://dashscope.aliyuncs.com/compatible-mode/v1` is also supported.
- Loopback HTTP base URLs are accepted for deterministic tests.
- Text chat defaults to `qwen-plus`.
- Multimodal `image_url` chat defaults to `qwen-vl-plus` when no model is supplied.
- Embeddings default to `text-embedding-v4`.
- SSE chat streaming returns redaction-safe chunk metadata and assembled text from a bounded invoke call; FCP subscribe is not implemented.

## First-Slice Scope

The first Qwen slice is intentionally narrow:

- create non-streaming chat completions from caller-supplied message arrays
- create SSE chat completions and return assembled content plus chunk metadata
- support Qwen-VL and QVQ image inputs through standard OpenAI `image_url` content blocks
- create text embeddings
- list and cache compatible-mode model IDs
- run a bounded health probe using model listing
- enforce capability-token checks for invoke paths
- emit redaction-safe loopback and optional live JSONL evidence

## Auth And Scope Boundary

- Authentication mechanism: DashScope API key, with host-injected credential-id mode.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `qwen.chat` gates chat and SSE chat operations.
  - `qwen.embeddings` gates embedding creation.
  - `qwen.models.read` gates model discovery.
  - `qwen.health.read` gates the health probe.
- The connector does not persist prompts, image URLs, completions, streamed chunks, embedding input, vectors, model catalogs, or provider responses.
- Credential-id mode is a host-egress contract, not direct proof that live DashScope will accept the request without an injection layer.

## Network And Runtime Invariants

- Production hosts: `dashscope-intl.aliyuncs.com` and `dashscope.aliyuncs.com`.
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
| `qwen.chat` | Create text, Qwen-VL, and SSE chat completions. |
| `qwen.embeddings` | Create DashScope text embeddings. |
| `qwen.models.read` | List compatible-mode model IDs. |
| `qwen.health.read` | Run a bounded model-list readiness probe. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `qwen.chat.completions` | `POST /chat/completions` | `qwen.chat` | `Safe` | `Medium` | `None` | Model output depends on prompt, tool, image, and sampling input. |
| `qwen.chat.completions_stream` | `POST /chat/completions` with SSE | `qwen.chat` | `Safe` | `Medium` | `None` | Streaming output depends on event ordering and provider deltas. |
| `qwen.embeddings.create` | `POST /embeddings` | `qwen.embeddings` | `Safe` | `Low` | `Strict` | Embedding generation is read-like for a fixed input and model. |
| `qwen.models.list` | `GET /models` | `qwen.models.read` | `Safe` | `Low` | `Strict` | Read-only model catalog discovery with in-memory cache support. |
| `qwen.health` | `GET /models` bounded probe | `qwen.health.read` | `Safe` | `Low` | `Strict` | Health probe confirms compatible-mode reachability and model-list path. |

## Explicit Non-Goals

The first implementation slice does not include:

- DashScope-native `/api/v1/services` endpoints
- image generation, video generation, speech APIs, file upload APIs, or fine-tuning
- FCP subscription-based streaming
- persistent prompt, image, completion, stream, embedding, or model-cache storage
- direct credential vaulting
- public-zone invocation

These are excluded on purpose:

- The useful first slice is OpenAI-compatible Qwen inference with clear safety and redaction boundaries.
- Native DashScope services have different request shapes and should not be smuggled through this connector.
- Qwen-VL support is limited to HTTPS `image_url` blocks in chat messages and rejects text-only models for image input.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake, auth mode, base URL, default models, request counters, and error counters
- redacted auth labels rather than bearer tokens
- base URL policy for international, Beijing, and loopback-compatible paths
- Qwen-VL input-shape guidance
- explicit denial of DashScope-native endpoint coverage
- model-list probe health metadata
- operation schemas, safety, risk, idempotency, and AI hints

The deterministic integration evidence is anchored on WireMock loopback runs covering:

- text chat
- Qwen-VL image URL chat
- SSE chat streaming
- embeddings
- model listing and cache use
- health probe
- provider error redaction
- rate-limit wait policy
- cancellation before dispatch
- shutdown cleanup
- redaction-safe JSONL evidence

## Source Notes

- `connectors/qwen/src/client.rs` defines DashScope compatible-mode base URLs, auth headers, error mapping, model cache behavior, and provider identity.
- `connectors/qwen/src/connector.rs` defines lifecycle, capability verification, operation dispatch, introspection, and health/doctor behavior.
- `connectors/qwen/src/types.rs` defines chat, image URL, embedding, model ID, and request validation.
- `connectors/qwen/manifest.toml` defines the five-operation catalog, network constraints, sandbox boundary, and no-listener/no-exec posture.
- `connectors/qwen/tests/conformance.rs` checks manifest and runtime operation surface alignment.
- `connectors/qwen/tests/integration.rs` covers loopback chat, streaming, embeddings, model listing, health, redaction, rate limits, cancellation, and JSONL evidence.
- `connectors/qwen/tests/live_verification.rs` emits structured skip records unless `DASHSCOPE_API_KEY` is present.

## Verification Bundle

The closeout bundle is anchored on `scripts/e2e/qwen_connector_verification.sh`. It writes artifacts under `artifacts/e2e/qwen/<run_id>` by default and offloads Cargo work through `rch`.

The bundle captures:

- manifest check through `fwc` or `rch exec -- cargo run -p fwc`
- `rch exec -- cargo check -p fcp-qwen --all-targets`
- `rch exec -- cargo fmt --package fcp-qwen --check`
- WireMock JSONL loopback coverage
- optional live smoke coverage gated by `DASHSCOPE_API_KEY`
- JSONL extraction for fixture and live records
- `rch exec -- cargo clippy -p fcp-qwen --all-targets --no-deps -- -D warnings`
- replay script and environment metadata

## Operator Guidance

**Prerequisites**:

- Use a DashScope API key in `DASHSCOPE_API_KEY` for live provider verification.
- Use WireMock loopback fixtures for deterministic proof.
- Use `QWEN_LIVE_CHAT_MODEL`, `QWEN_LIVE_VISION_MODEL`, and `QWEN_LIVE_EMBEDDING_MODEL` only when live model defaults need to differ from the connector defaults.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a test DashScope account for live runs and keep live prompts intentionally small.

**Redaction rules**:

- Redact API keys, bearer headers, credential IDs, prompts, completions, streamed text chunks, image URLs, embedding input, vectors, raw model IDs when sensitive, provider payloads, and provider error bodies.
- The verification JSONL records use counts, byte lengths, status values, cleanup state, retry decisions, and model ID hashes.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one of `api_key` or `credential_id`, then run handshake.
- If `self_check` reports `credential_injection_required`, run behind the host egress injection layer or switch to API-key mode for direct live probes.
- If base URL validation fails, use one of the two DashScope compatible-mode base URLs or a localhost loopback URL for tests.
- If Qwen-VL input is rejected, use HTTPS `image_url` blocks and a `qwen-vl`, `qwen3-vl`, or `qvq` model.
- If embeddings are rejected, use non-empty input and an embedding model such as `text-embedding-v4`.
- If streamed output looks empty, inspect SSE finish metadata and provider deltas before assuming transport failure.

**Rerun commands**:

- `FCP_QWEN_TARGET_DIR=/tmp/fcp-qwen-e2e scripts/e2e/qwen_connector_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-qwen-e2e cargo check -p fcp-qwen --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-qwen-e2e cargo test -p fcp-qwen --test integration qwen_loopback_e2e_jsonl_matrix -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-qwen-e2e cargo test -p fcp-qwen --test live_verification qwen_live_smoke_or_structured_skip_jsonl -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-qwen-e2e cargo clippy -p fcp-qwen --all-targets --no-deps -- -D warnings`
