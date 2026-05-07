# Moonshot Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://platform.kimi.ai/docs/api/overview

## Purpose

This document fixes the operator-facing contract for `fcp.moonshot`. The connector exposes Moonshot/Kimi's OpenAI-compatible long-context inference surface: chat completions, SSE chat streaming, model listing, and a bounded health probe.

The connector is intentionally chat-focused. Current first-party Kimi API documentation centers the Chat Completions API and model listing; `moonshot.embeddings.create` is declared only so introspection can honestly report that embeddings are not supported by this connector slice.

## Current Runtime Snapshot

The current crate exposes these operations:

- `moonshot.chat.completions`
- `moonshot.chat.completions_stream`
- `moonshot.models.list`
- `moonshot.health`
- `moonshot.embeddings.create`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `api_key` or `credential_id`.
- API-key mode sends `Authorization: Bearer ...`.
- Credential-id mode sends `x-fcp-credential-id` and requires host-side egress credential injection for live traffic.
- Default base URL is `https://api.moonshot.ai/v1`.
- Base URL overrides must use path `/v1`, must not include username, password, query, or fragment components, and may only target `api.moonshot.ai`, `api.moonshot.cn`, or loopback test hosts.
- Non-loopback base URLs must use HTTPS.
- Loopback HTTP/HTTPS base URLs are accepted only for deterministic tests.
- Default model is `kimi-k2.6`.
- Default context-window guard is model-aware and falls back to `256_000` tokens.
- Default `request_timeout_ms` is `300_000`.
- Default `model_cache_ttl_seconds` is `3600`.
- `wait_on_rate_limit_ms` switches rate-limit behavior from fail-fast to bounded wait/retry.
- Chat input rejects empty messages, simultaneous `max_tokens` and `max_completion_tokens`, non-1 `n` values, empty or control-character model IDs, and caller-supplied token estimates that exceed the selected context window.
- `max_completion_tokens` and `thinking` are forwarded through provider extensions; when `max_completion_tokens` is supplied, legacy `max_tokens` is not sent.
- `moonshot.models.list` uses `GET /v1/models` and supports `{"refresh": true}` to invalidate the in-memory cache.
- FCP subscribe is not implemented; streaming is exposed as the bounded invoke operation `moonshot.chat.completions_stream`.
- `moonshot.embeddings.create` fails locally before provider dispatch.

## First-Slice Scope

The first Moonshot README slice documents the existing runtime surface:

- non-streaming chat completions through `POST /v1/chat/completions`
- SSE chat completions through the same endpoint with `stream: true`
- model discovery through `GET /v1/models`
- a health operation backed by a short model-list probe
- direct bearer auth and host credential reference auth
- explicit `.ai`, `.cn`, and loopback-only base URL policy
- local validation for invalid auth material, base URLs, chat fields, model IDs, and context-window estimates
- model-aware context-window classes for `8k`, `32k`, `128k`, `256k`, and custom values
- bounded rate-limit retry behavior
- redaction-safe doctor, self-check, health, and provider error output
- bound capability-token verification before dispatch
- an explicit not-supported embeddings operation for introspection honesty

## Auth And Scope Boundary

- Authentication mechanisms: Moonshot API key or host-injected credential ID.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, `z:work`, and `z:project:*`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `moonshot.chat` gates chat and streaming chat completions.
  - `moonshot.models.read` gates model listing.
  - `moonshot.health.read` gates the health probe.
  - `moonshot.embeddings` is associated only with the not-supported embeddings declaration.
- The connector does not persist prompts, completions, streamed chunks, tool-call arguments, thinking payloads, model catalogs, provider payloads, provider responses, API keys, or credential IDs.
- Credential-id mode is a host-egress contract, not proof that live Moonshot will accept a request without an injection layer.

## Network And Runtime Invariants

- Default production host: `api.moonshot.ai`.
- Alternate production host accepted by runtime: `api.moonshot.cn`.
- Path root: `/v1`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and unsafe host forms for live operations.
- Runtime loopback overrides are test-only and still require path `/v1`.
- Runtime default `request_timeout_ms`: `300_000`.
- Manifest chat and streaming network constraints set total timeout `300_000 ms`.
- Manifest model-list and embeddings metadata constraints set total timeout `30_000 ms`.
- Manifest health network constraints set total timeout `5_000 ms`.
- Maximum response bytes are `10_485_760`.
- Sandbox profile is `strict`, with `192 MB` memory, `25%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- Event capability metadata declares streaming support, no replay, no acknowledgement requirement, and a minimum buffer of 0 events.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `moonshot.chat` | Send non-streaming and streaming Moonshot/Kimi chat-completion requests. |
| `moonshot.models.read` | List available Kimi model IDs with cache reuse. |
| `moonshot.health.read` | Probe configured Moonshot reachability through a bounded model-list request. |
| `moonshot.embeddings` | Report the intentionally unavailable embeddings surface. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `moonshot.chat.completions` | `POST /v1/chat/completions` | `moonshot.chat` | `Safe` | `Medium` | `None` | Model output depends on prompt, tool definitions, thinking mode, sampling options, and model ID. |
| `moonshot.chat.completions_stream` | `POST /v1/chat/completions` with SSE | `moonshot.chat` | `Safe` | `Medium` | `None` | Stream output depends on event ordering, reasoning deltas, content deltas, tool-call deltas, and finish metadata. |
| `moonshot.models.list` | `GET /v1/models` | `moonshot.models.read` | `Safe` | `Low` | `Strict` | Read-only model catalog discovery with in-memory caching. |
| `moonshot.health` | `GET /v1/models` bounded probe | `moonshot.health.read` | `Safe` | `Low` | `Strict` | Read-only readiness probe for credentials and network path. |
| `moonshot.embeddings.create` | Local not-supported response | `moonshot.embeddings` | `Safe` | `Low` | `None` | Declared for honest introspection; invocation fails before provider dispatch. |

## Explicit Non-Goals

The current implementation does not include:

- invokable Moonshot/Kimi embeddings
- file, batch, fine-tuning, admin, or billing APIs
- OpenAI-compatible legacy `/v1/completions`
- OpenAI-compatible `/v1/responses`
- provider-side token counting or context estimation
- automatic prompt truncation
- FCP subscription-based streaming
- connector-local credential vaulting
- public-zone invocation
- durable storage of prompts, completions, model catalogs, streamed deltas, thinking payloads, or provider errors
- proxying unsupported embeddings through another provider

These are excluded on purpose:

- The useful first slice is direct Kimi chat and streaming with explicit context-limit checks.
- The connector refuses over-window requests when the caller supplies token estimates instead of silently truncating private long-context inputs.
- Unsupported embeddings are represented explicitly so operators do not infer a hidden fallback.
- Provider credentials and host egress injection stay outside the connector-local storage boundary.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, auth mode, base URL, default model, context-window class, request counters, and error counters
- redacted API-key labels rather than raw API keys
- base URL policy for `api.moonshot.ai/v1`, `api.moonshot.cn/v1`, and loopback-compatible test origins
- credential-injection status for host credential reference mode
- operation schemas, safety, risk, idempotency, and AI hints
- simulate-time operation support, including the embeddings not-supported explanation
- capability-token checks against bound resources before dispatch

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- API-key and credential-id header behavior
- base URL normalization for `.ai`, `.cn`, loopback, invalid paths, userinfo, query, and fragment rejection
- chat completion dispatch and redacted provider errors
- SSE chunk assembly with reasoning delta counts and tool-call delta counts
- model-list caching and health reuse of the shared client
- bounded rate-limit retry behavior
- local rejection of unsupported or unsafe chat inputs
- context-window classes and over-window refusal
- embeddings failing locally before network dispatch
- FCP trait invoke, capability-token validation, introspection, simulation, and shutdown behavior
- live-provider smoke coverage with structured skip when credentials are absent

## Source Notes

- `connectors/moonshot/src/client.rs` defines auth headers, base URL normalization, user agent, OpenAI-compatible request dispatch, model listing, and model-cache invalidation.
- `connectors/moonshot/src/connector.rs` defines configuration validation, lifecycle handlers, operation dispatch, capability verification, introspection, simulation, health, doctor, self-check, and shutdown behavior.
- `connectors/moonshot/src/types.rs` defines chat input parsing, context-window classes, `max_completion_tokens` forwarding, `thinking` forwarding, and local context-limit validation.
- `connectors/moonshot/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and not-supported embeddings declaration.
- `connectors/moonshot/tests/conformance.rs` checks manifest operation coverage, operation metadata, and introspection parity.
- `connectors/moonshot/tests/integration.rs` covers deterministic loopback behavior, streaming, error mapping, rate-limit retry, context-window validation, redaction, unsupported embeddings, and FCP trait behavior.
- `connectors/moonshot/tests/live_verification.rs` and `connectors/moonshot/tests/provider_contract.rs` provide optional live/contract evidence around the current Kimi API.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/moonshot_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock integration coverage
- optional live-provider smoke with structured skip if credentials are absent
- base URL, auth, chat, streaming, model-list, health, context-window, rate-limit, redaction, and not-supported embeddings tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Moonshot API key only for live provider verification.
- Use `credential_id` only behind a host egress injection layer.
- Choose the `.ai` or `.cn` API platform intentionally; the connector accepts both hosts but does not treat credentials as interchangeable.
- Provide `estimated_input_tokens` when the caller already has a token estimate and needs deterministic refusal rather than truncation.
- Use WireMock loopback fixtures for deterministic proof.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a test Moonshot account for live runs and keep live prompts intentionally small.
- Keep embeddings, files, batches, fine-tuning, billing, and admin expectations out of this connector.

**Redaction rules**:

- Redact API keys, credential IDs where needed, prompts, completions, streamed chunks, tool-call arguments, thinking payloads, model-list response bodies, provider payloads, and provider error bodies.
- Verification output should use counts, byte lengths, token estimates, context-window classes, operation IDs, model IDs when non-sensitive, status values, error classes, and cleanup state.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one of `api_key` or `credential_id`.
- If `health` reports `degraded`, complete handshake before invoking operations that require bound capability tokens.
- If `self_check` reports `credential_injection_required`, run behind the host egress injection layer or switch to direct API-key mode for live probes.
- If base URL validation fails, use `https://api.moonshot.ai/v1`, `https://api.moonshot.cn/v1`, or a loopback `/v1` origin for tests.
- If chat input is rejected for token limits, lower the estimated input, lower requested output tokens, select a model with a larger known context window, or pass an explicit `context_window_tokens` value.
- If both `max_tokens` and `max_completion_tokens` are supplied, remove one; new Kimi work should prefer `max_completion_tokens`.
- If `moonshot.embeddings.create` is requested, route the request to a connector that actually supports embeddings.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-moonshot-e2e cargo check -p fcp-moonshot --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-moonshot-e2e cargo test -p fcp-moonshot --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-moonshot-e2e cargo clippy -p fcp-moonshot --all-targets --no-deps -- -D warnings`
