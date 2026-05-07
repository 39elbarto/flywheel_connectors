# GLM Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://docs.z.ai/api-reference/

## Purpose

This document fixes the operator-facing contract for `fcp.glm`. The connector exposes first-party GLM/Zhipu AI text and embedding inference through the BigModel-compatible chat, SSE streaming, embeddings, static model catalog, and health operations.

The connector is request-response and streaming oriented, but it is not a full Z.AI platform runtime. It does not expose tokenizer, OCR, file, tool, account, or deployment-management APIs.

## Current Runtime Snapshot

The current crate exposes these operations:

- `glm.chat.completions`
- `glm.chat.completions_stream`
- `glm.embeddings.create`
- `glm.models.list`
- `glm.health`

Important runtime truths the contract preserves:

- Configuration accepts exactly one GLM auth mode:
  - direct bearer `api_key`
  - combined JWT credential `jwt_api_key` with documented `<api_key_id>.<signing-material>` shape
  - split JWT fields `api_key_id` plus `api_key_signing_material`
  - host-injected `credential_id`
- Direct bearer and generated JWT modes send `Authorization: Bearer ...`.
- Credential-id mode sends `x-fcp-credential-id` and requires host-side egress credential injection for live traffic.
- JWT mode signs HS256 tokens with `sign_type = "SIGN"` and caches them until near expiry.
- Default `jwt_ttl_seconds` is `60`.
- Default base URL is `https://open.bigmodel.cn/api/paas/v4`.
- Runtime also accepts `/api/coding/paas/v4` for coding-plan use and loopback test hosts.
- Base URL overrides must not include query or fragment components.
- Default chat model is `glm-5.1`.
- Default embedding model is `embedding-3`.
- Default `request_timeout_ms` is `180_000`.
- Default `model_cache_ttl_seconds` is `3600`.
- `wait_on_rate_limit_ms` switches rate-limit behavior from fail-fast to bounded wait/retry.
- `glm.models.list` returns a conservative documented static catalog rather than calling a provider `/models` endpoint.
- Chat input rejects empty messages, duplicate `max_tokens` plus `max_completion_tokens`, and zero `n` before network dispatch.
- Embedding input rejects empty strings, empty batches, empty batch entries, and zero `dimensions` before network dispatch.
- FCP subscribe is not implemented; streaming is exposed as the bounded invoke operation `glm.chat.completions_stream`.

## First-Slice Scope

The first GLM README slice documents the existing runtime surface:

- non-streaming chat completions through `POST /api/paas/v4/chat/completions`
- SSE chat completions through the same endpoint with `stream: true`
- embeddings through `POST /api/paas/v4/embeddings`
- static documented model catalog listing
- a health operation that reports catalog count without sending prompts
- direct bearer auth, combined JWT auth, split JWT auth, and host credential reference auth
- JWT generation, caching, and golden-vector coverage
- GLM-specific provider error mapping, including documented rate-limit code handling
- local validation for invalid chat and embedding fields
- bound capability-token verification before dispatch

## Auth And Scope Boundary

- Authentication mechanisms: GLM bearer API key, GLM JWT material, or host-injected credential ID.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, `z:work`, and `z:project:*`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `glm.chat` gates chat and streaming chat completions.
  - `glm.embeddings` gates embedding creation.
  - `glm.models.read` gates static model catalog listing.
  - `glm.health.read` gates the health probe.
- The connector does not persist prompts, completions, streamed chunks, embedding inputs, embedding vectors, model catalogs, JWTs, signing material, provider payloads, or provider responses.
- Credential-id mode is a host-egress contract, not proof that live GLM will accept a request without an injection layer.

## Network And Runtime Invariants

- Production host allowed by current runtime: `open.bigmodel.cn`.
- Production path root: `/api/paas/v4`.
- Coding-plan path accepted by current runtime: `/api/coding/paas/v4`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and unsafe host forms for live operations.
- Localhost HTTP/HTTPS overrides are test-only.
- Runtime default `request_timeout_ms`: `180_000`.
- Manifest chat, streaming, and embeddings network constraints set total timeout `180_000 ms`.
- Manifest model-list network constraints set total timeout `30_000 ms`.
- Manifest health network constraints set total timeout `5_000 ms`.
- Maximum response bytes are `10_485_760`.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `180_000 ms` wall-clock timeout, no exec, and no ptrace.
- Event capability metadata declares streaming support, no replay, no acknowledgement requirement, and a minimum buffer of 0 events.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `glm.chat` | Send non-streaming and streaming GLM chat-completion requests. |
| `glm.embeddings` | Create GLM text embeddings. |
| `glm.models.read` | List the connector's conservative documented model catalog. |
| `glm.health.read` | Report readiness and model catalog count without sending prompts. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `glm.chat.completions` | `POST /api/paas/v4/chat/completions` | `glm.chat` | `Safe` | `Medium` | `None` | Model output depends on prompt, tools, sampling options, and model ID. |
| `glm.chat.completions_stream` | `POST /api/paas/v4/chat/completions` with SSE | `glm.chat` | `Safe` | `Medium` | `None` | Stream output depends on event ordering, content deltas, tool-call deltas, and finish metadata. |
| `glm.embeddings.create` | `POST /api/paas/v4/embeddings` | `glm.embeddings` | `Safe` | `Low` | `Strict` | Embeddings expose sensitive source text and vectors but are deterministic enough for strict idempotency. |
| `glm.models.list` | Local static catalog | `glm.models.read` | `Safe` | `Low` | `Strict` | Current public docs do not advertise `/models`; runtime returns a conservative documented catalog. |
| `glm.health` | Local readiness and catalog count | `glm.health.read` | `Safe` | `Low` | `Strict` | Prompt-free readiness metadata for configured connector state and documented models. |

## Explicit Non-Goals

The current implementation does not include:

- provider `/models` network calls
- tokenizer, OCR, file, audio, video, search, account, billing, batch, fine-tuning, or deployment-management APIs
- automatic migration to Z.AI's newer hostname
- FCP subscription-based streaming
- connector-local credential vaulting
- public-zone invocation
- durable storage of prompts, completions, embeddings, JWTs, signing material, streamed deltas, or provider errors

These are excluded on purpose:

- The useful first slice is direct GLM chat and embeddings with explicit auth-mode coverage.
- Model listing is intentionally static until a stable provider model-list endpoint is available in the contract this connector targets.
- Provider credentials, JWT signing material, and host egress injection stay outside durable connector-local storage.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, auth mode, base URL, default chat model, default embedding model, request counters, and error counters
- redacted auth labels rather than raw API keys, JWTs, signing material, or credential values
- base URL policy for `open.bigmodel.cn/api/paas/v4`, coding-plan path handling, and loopback-compatible test origins
- credential-injection status for host credential reference mode
- operation schemas, safety, risk, idempotency, and AI hints
- simulate-time operation support
- capability-token checks against bound resources before dispatch

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- direct bearer auth header behavior
- base URL normalization and rejection
- JWT generation golden vector and combined-key splitting
- JWT cache reuse and refresh near expiry
- chat completion dispatch and redacted doctor output
- SSE chunk assembly without prompt echoing
- embedding dispatch through the documented embedding surface
- static model catalog and prompt-free health behavior
- GLM rate-limit error-code mapping
- invalid chat and embedding fields failing locally before network dispatch
- FCP trait invoke, capability-token validation, and shutdown behavior
- manifest identity, archetype, capability, and sandbox coverage

## Source Notes

- `connectors/glm/src/client.rs` defines auth header application, JWT generation and caching, base URL normalization, GLM error mapping, OpenAI-compatible request dispatch, static model catalog, and model-cache no-op behavior.
- `connectors/glm/src/connector.rs` defines configuration validation, auth-mode selection, lifecycle handlers, operation dispatch, capability verification, introspection, simulation, health, doctor, self-check, and shutdown behavior.
- `connectors/glm/src/types.rs` defines chat and embeddings input parsing plus local validation for duplicate token budgets, zero `n`, empty embedding input, empty embedding batches, and zero dimensions.
- `connectors/glm/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and JWT-capable auth posture.
- `connectors/glm/tests/conformance.rs` checks manifest identity, archetypes, capabilities, and sandbox posture.
- `connectors/glm/tests/integration.rs` covers deterministic loopback behavior, JWT behavior, error mapping, local validation, redaction, and FCP trait behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/glm_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock integration coverage
- JWT auth, base URL, chat, streaming, embeddings, static catalog, error mapping, and redaction tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use direct `api_key` mode for simple bearer-token live probes.
- Use `jwt_api_key` when the operator has GLM's combined `<api_key_id>.<signing-material>` credential.
- Use split `api_key_id` plus `api_key_signing_material` when credential material is stored separately.
- Use `credential_id` only behind a host egress injection layer.
- Use WireMock loopback fixtures for deterministic proof.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a test GLM/Z.AI account for live runs and keep live prompts intentionally small.
- Keep tokenizer, OCR, file, account, and deployment-management expectations out of this connector.

**Redaction rules**:

- Redact API keys, JWTs, JWT signing material, credential IDs where needed, prompts, completions, streamed chunks, tool-call arguments, embedding input, embedding vectors, provider payloads, and provider error bodies.
- Verification output should use counts, byte lengths, operation IDs, model IDs when non-sensitive, status values, error classes, and cleanup state.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one GLM auth mode.
- If `health` reports `degraded`, complete handshake before invoking operations that require bound capability tokens.
- If `self_check` reports `credential_injection_required`, run behind the host egress injection layer or switch to direct bearer/JWT mode for live probes.
- If auth configuration fails with `Provide exactly one GLM auth mode`, remove extra credential fields.
- If split JWT auth fails, provide both `api_key_id` and `api_key_signing_material`.
- If combined JWT auth fails, use the `<api_key_id>.<signing-material>` shape.
- If base URL validation fails, use `https://open.bigmodel.cn/api/paas/v4`, `https://open.bigmodel.cn/api/coding/paas/v4`, or a loopback origin with one of those paths for tests.
- If chat input rejects token budgets, keep only one of `max_tokens` or `max_completion_tokens`.
- If embedding input is rejected, remove empty strings and set `dimensions` to a positive value.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-glm-e2e cargo check -p fcp-glm --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-glm-e2e cargo test -p fcp-glm --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-glm-e2e cargo clippy -p fcp-glm --all-targets --no-deps -- -D warnings`
