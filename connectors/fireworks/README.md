# Fireworks Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://docs.fireworks.ai/

## Purpose

This document fixes the operator-facing contract for `fcp.fireworks`. The connector exposes Fireworks AI's OpenAI-compatible text and embedding inference surface: chat completions, SSE chat streaming, embeddings, model listing, health probing, and a legacy completions operation for older OpenAI-compatible callers.

The connector is text and embedding focused. Fireworks workflow image generation and media-generation surfaces are intentionally deferred to media connectors instead of being hidden behind this runtime.

## Current Runtime Snapshot

The current crate exposes these operations:

- `fireworks.chat.completions`
- `fireworks.chat.completions_stream`
- `fireworks.embeddings.create`
- `fireworks.models.list`
- `fireworks.health`
- `fireworks.completions.legacy`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `api_key` or `credential_id`.
- API-key mode sends `Authorization: Bearer ...`.
- Credential-id mode sends `x-fcp-credential-id` and requires host-side egress credential injection for live traffic.
- Default base URL is `https://api.fireworks.ai/inference/v1`.
- Base URL overrides must use path `/inference/v1`, must not include username, password, query, or fragment components, and may only target `api.fireworks.ai` or loopback test hosts.
- Loopback HTTP/HTTPS base URLs are accepted only for deterministic tests.
- Default chat model is `accounts/fireworks/models/llama-v3p1-8b-instruct`.
- Default embedding model is `nomic-ai/nomic-embed-text-v1.5`.
- Default `request_timeout_ms` is `60_000`.
- Default `model_cache_ttl_seconds` is `3600`.
- `wait_on_rate_limit_ms` switches rate-limit behavior from fail-fast to bounded wait/retry.
- Fireworks model IDs must be either `accounts/<account>/models/<model>` or `namespace/model`, with no whitespace.
- Chat validation accepts Fireworks extensions such as `reasoning_effort` and `context_length_exceeded_behavior`.
- `fireworks.models.list` uses a Fireworks-aware in-memory model cache and supports `{"refresh": true}` to invalidate it.
- FCP subscribe is not implemented; streaming is exposed as the bounded invoke operation `fireworks.chat.completions_stream`.

## First-Slice Scope

The first Fireworks README slice documents the existing runtime surface:

- non-streaming chat completions through `POST /inference/v1/chat/completions`
- SSE chat completions through the same endpoint with `stream: true`
- embeddings through `POST /inference/v1/embeddings`
- model discovery through `GET /inference/v1/models`
- a health operation backed by a short model-list probe
- legacy prompt completions through the OpenAI-compatible completions surface
- local validation for model ID shapes, empty message or embedding input, invalid reasoning/context behavior, invalid auth material, and invalid base URLs
- rate-limit retry behavior for configured bounded waits
- redaction-safe doctor, error, and JSONL evidence output
- bound capability-token verification before dispatch
- explicit deferral of image generation

## Auth And Scope Boundary

- Authentication mechanisms: Fireworks API key or host-injected credential ID.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `fireworks.chat` gates chat, streaming chat, and legacy completions.
  - `fireworks.embeddings` gates embedding creation.
  - `fireworks.models.read` gates model listing.
  - `fireworks.health.read` gates the health probe.
- The connector does not persist prompts, completions, streamed chunks, embedding inputs, embedding vectors, model catalogs, provider payloads, or provider responses.
- Credential-id mode is a host-egress contract, not proof that live Fireworks will accept a request without an injection layer.

## Network And Runtime Invariants

- Production host: `api.fireworks.ai`.
- Production path root: `/inference/v1`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and unsafe host forms for live operations.
- Localhost HTTP/HTTPS overrides are test-only.
- Runtime default `request_timeout_ms`: `60_000`.
- Manifest chat, embeddings, and legacy-completions network constraints set total timeout `60_000 ms`.
- Manifest streaming network constraints set total timeout `300_000 ms`.
- Manifest model-list network constraints set total timeout `30_000 ms`.
- Manifest health network constraints set total timeout `5_000 ms`.
- Maximum response bytes are `10_485_760`.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `180_000 ms` wall-clock timeout, no exec, and no ptrace.
- Event capability metadata declares streaming support, no replay, no acknowledgement requirement, and a minimum buffer of 0 events.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `fireworks.chat` | Send chat, streaming chat, and legacy prompt-completion requests. |
| `fireworks.embeddings` | Create Fireworks text embeddings. |
| `fireworks.models.read` | List available Fireworks model IDs with cache reuse. |
| `fireworks.health.read` | Probe provider reachability through a bounded model-list request. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `fireworks.chat.completions` | `POST /inference/v1/chat/completions` | `fireworks.chat` | `Safe` | `Medium` | `None` | Model output depends on prompt, tools, sampling options, context behavior, and model ID. |
| `fireworks.chat.completions_stream` | `POST /inference/v1/chat/completions` with SSE | `fireworks.chat` | `Safe` | `Medium` | `None` | Stream output depends on event ordering, content deltas, tool-call deltas, and finish metadata. |
| `fireworks.embeddings.create` | `POST /inference/v1/embeddings` | `fireworks.embeddings` | `Safe` | `Low` | `Strict` | Embeddings are deterministic enough for strict idempotency but still expose sensitive input text and vectors. |
| `fireworks.models.list` | `GET /inference/v1/models` | `fireworks.models.read` | `Safe` | `Low` | `Strict` | Read-only model catalog discovery with in-memory caching. |
| `fireworks.health` | `GET /inference/v1/models` bounded probe | `fireworks.health.read` | `Safe` | `Low` | `Strict` | Read-only readiness probe for credentials and network path. |
| `fireworks.completions.legacy` | `POST /inference/v1/completions` | `fireworks.chat` | `Safe` | `Medium` | `None` | Minimal prompt-completion compatibility for older callers that cannot send chat messages. |

## Explicit Non-Goals

The current implementation does not include:

- Fireworks workflow image generation
- image, audio, video, file, batch, fine-tuning, realtime, or deployment-management APIs
- model upload, dedicated deployment provisioning, or account administration
- FCP subscription-based streaming
- connector-local credential vaulting
- public-zone invocation
- durable storage of prompts, completions, embedding input, embedding vectors, model catalogs, streamed deltas, or provider errors

These are excluded on purpose:

- The useful first slice is direct Fireworks text and embedding inference with clear capability gates.
- Image generation is a separate operational surface and is documented as deferred by `doctor()`.
- Provider credentials and host egress injection stay outside the connector-local storage boundary.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, auth mode, base URL, default chat model, default embedding model, request counters, and error counters
- redacted auth labels rather than raw API keys
- base URL policy for `api.fireworks.ai/inference/v1` and loopback-compatible test origins
- credential-injection status for secretless mode
- image-generation deferral status
- operation schemas, safety, risk, idempotency, and AI hints
- simulate-time operation support
- capability-token checks against bound resources before dispatch

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- API-key and credential-id auth header behavior
- base URL normalization and rejection, including username/password, query, and fragment rejection
- Fireworks model ID validation
- chat request builder validation for Fireworks extensions
- embedding request builder validation
- non-streaming chat completion dispatch and redacted doctor output
- SSE chunk assembly without prompt echoing
- embedding response summarization without vector leakage in summary fields
- Fireworks array-shaped model-list parsing and cache reuse
- health reuse of the shared model-list path
- bounded rate-limit retry behavior
- provider error mapping with sensitive body redaction
- cancellation before network dispatch
- FCP trait invoke, capability-token validation, shutdown behavior, and JSONL fixture evidence
- live skip/pass behavior gated by `FIREWORKS_API_KEY`

## Source Notes

- `connectors/fireworks/src/client.rs` defines auth headers, base URL normalization, user agent, OpenAI-compatible dispatch, direct model-list fetching, Fireworks model-list parsing, model-cache invalidation, and rate-limit retry handling.
- `connectors/fireworks/src/connector.rs` defines configuration validation, lifecycle handlers, operation dispatch, capability verification, introspection, simulation, health, doctor, self-check, and shutdown behavior.
- `connectors/fireworks/src/types.rs` defines chat, embeddings, and legacy-completions input parsing plus local validation for model IDs, reasoning effort, context behavior, embedding batches, and prompt input.
- `connectors/fireworks/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and image-generation deferral guidance.
- `connectors/fireworks/tests/conformance.rs` checks manifest operation coverage, network policy, image-generation deferral, and runtime introspection parity.
- `connectors/fireworks/tests/integration.rs` covers deterministic loopback behavior, error mapping, rate-limit retry, redaction, cancellation, JSONL evidence, and FCP trait behavior.
- `connectors/fireworks/tests/provider_contract.rs` checks provider-contract advertisement, redaction, auth methods, model defaults, base URLs, and import side-effect posture.
- `connectors/fireworks/tests/live_verification.rs` emits live skip/pass JSONL when `FIREWORKS_API_KEY` is absent or present.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/fireworks_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock integration coverage
- provider-contract coverage
- live provider smoke tests gated by `FIREWORKS_API_KEY`
- base URL, auth, model validation, embeddings, rate-limit, cancellation, and redaction tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use `FIREWORKS_API_KEY` only for live provider verification.
- Use `credential_id` only behind a host egress injection layer.
- Use WireMock loopback fixtures for deterministic proof.
- Set `FIREWORKS_LIVE_CHAT_MODEL` or `FIREWORKS_LIVE_EMBEDDING_MODEL` only when the default live models are not appropriate for a live smoke run.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a test Fireworks account for live runs and keep live prompts intentionally small.
- Keep image, deployment-management, fine-tuning, and account-admin expectations out of this connector.

**Redaction rules**:

- Redact API keys, credential IDs where needed, prompts, completions, streamed chunks, tool-call arguments, embedding input, embedding vectors, model-list response bodies, provider payloads, and provider error bodies.
- Verification output should use counts, byte lengths, operation IDs, hashed model IDs where needed, status values, error classes, and cleanup state.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one of `api_key` or `credential_id`.
- If `health` reports `degraded`, complete handshake before invoking operations that require bound capability tokens.
- If `self_check` reports `credential_injection_required`, run behind the host egress injection layer or switch to direct API-key mode for live probes.
- If base URL validation fails, use `https://api.fireworks.ai/inference/v1` or a loopback `/inference/v1` origin for tests.
- If a model is rejected, use `accounts/<account>/models/<model>` or `namespace/model` with no whitespace.
- If `reasoning_effort` is rejected, use `none`, `low`, `medium`, `high`, or `max`.
- If `context_length_exceeded_behavior` is rejected, use `truncate` or `error`.
- If embeddings input is rejected, remove empty strings and keep batches at or below 1,000 entries.
- If image generation is requested, route it to a media-generation connector instead.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fireworks-e2e cargo check -p fcp-fireworks --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fireworks-e2e cargo test -p fcp-fireworks --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fireworks-e2e cargo test -p fcp-fireworks --test live_verification -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fireworks-e2e cargo clippy -p fcp-fireworks --all-targets --no-deps -- -D warnings`
