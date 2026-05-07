# LM Studio Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://lmstudio.ai/docs/developer/openai-compat

## Purpose

This document fixes the operator-facing contract for `fcp.lm_studio`. The connector exposes LM Studio's local or operator-allowlisted OpenAI-compatible inference surface: chat completions, SSE chat streaming, embeddings, model listing, and a bounded health probe.

The connector is intentionally a local-service bridge, not a full LM Studio platform runtime. It does not expose native LM Studio model load, download, unload, stateful chat, REST-v0 management, MCP, Anthropic-compatible, Responses, or legacy Completions APIs.

## Current Runtime Snapshot

The current crate exposes these operations:

- `lm_studio.chat.completions`
- `lm_studio.chat.completions_stream`
- `lm_studio.embeddings.create`
- `lm_studio.models.list`
- `lm_studio.health`

Important runtime truths the contract preserves:

- Configuration accepts optional unauthenticated mode, `api_key`, or `credential_id`.
- `api_key` and `credential_id` are mutually exclusive; absent auth is valid because local LM Studio may be unauthenticated.
- API-key mode sends `Authorization: Bearer ...`.
- Credential-id mode sends `x-fcp-credential-id` and requires host-side egress credential injection for live checks.
- Default base URL is `http://localhost:1234/v1`.
- Base URL path must be exactly `/v1`; query and fragment components are rejected.
- Base URL scheme must be `http` or `https`.
- Loopback hosts are allowed by default.
- Non-loopback hosts must be listed exactly in `allowed_hosts`, with at most 64 bare hostname or IP-literal entries.
- `tailnet_only = true` rejects localhost and loopback base URLs.
- Runtime classifies configured endpoints as `loopback`, `tailnet_dns`, `tailnet_ip`, `private_ip`, or `operator_allowed_host`.
- Default chat model is `local-model`.
- Default embedding model is `local-embedding-model`.
- Default `request_timeout_ms` is `300_000`.
- Default `model_cache_ttl_seconds` is `300`.
- `wait_on_rate_limit_ms` switches rate-limit behavior from fail-fast to bounded wait/retry.
- Chat input rejects empty messages, zero `n`, `n > 128`, empty model IDs, overlong model IDs, whitespace in model IDs, and model IDs containing CR, LF, or NUL.
- Embedding input rejects empty strings, empty batches, batches larger than 1,000 entries, empty batch entries, and zero `dimensions`.
- `lm_studio.models.list` uses `GET /v1/models` and supports `{"refresh": true}` to invalidate the in-memory cache.
- FCP subscribe is not implemented; streaming is exposed as the bounded invoke operation `lm_studio.chat.completions_stream`.
- The connector never loads, downloads, unloads, or auto-evicts LM Studio models.

## First-Slice Scope

The first LM Studio README slice documents the existing runtime surface:

- non-streaming chat completions through `POST /v1/chat/completions`
- SSE chat completions through the same endpoint with `stream: true`
- embeddings through `POST /v1/embeddings`
- model discovery through `GET /v1/models`
- a health operation backed by a short model-list probe
- optional no-auth, direct bearer auth, and host credential reference auth
- explicit loopback and operator-allowlisted tailnet/private host policy
- local validation for invalid auth material, base URLs, model IDs, chat fields, and embedding fields
- bounded rate-limit retry behavior
- redaction-safe doctor, self-check, health, and JSONL proof output
- bound capability-token verification before dispatch

## Auth And Scope Boundary

- Authentication mechanisms: no auth, LM Studio API token / proxy bearer token, or host-injected credential ID.
- Home zone: `z:owner`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zones: `z:owner`, `z:private`, and `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `lm_studio.chat` gates chat and streaming chat completions.
  - `lm_studio.embeddings` gates embedding creation.
  - `lm_studio.models.read` gates model listing.
  - `lm_studio.health.read` gates the health probe.
- The connector does not persist prompts, completions, streamed chunks, embedding inputs, embedding vectors, model catalogs, API keys, credential IDs, provider payloads, or provider responses.
- Credential-id mode is a host-egress contract, not proof that a local LM Studio server will accept a request without an injection layer.

## Network And Runtime Invariants

- Default local host: `localhost`.
- Default local port: `1234`.
- Default path root: `/v1`.
- Compatibility hosts: loopback by default, or exact operator entries in `allowed_hosts`.
- Compatibility path: `/v1` only.
- HTTP is valid for loopback and operator-allowlisted local-service endpoints.
- HTTPS is valid for operator-allowlisted tailnet/private hosts and proxies.
- Manifest policy intentionally allows localhost, private ranges, tailnet ranges, and IP literals for this local-service connector.
- Manifest policy disables redirects with `max_redirects = 0`.
- Runtime default `request_timeout_ms`: `300_000`.
- Manifest chat, streaming, and embeddings network constraints set total timeout `300_000 ms`.
- Manifest model-list network constraints set total timeout `30_000 ms`.
- Manifest health network constraints set total timeout `5_000 ms`.
- Maximum response bytes are `10_485_760`.
- Sandbox profile is `moderate`, with `128 MB` memory, `25%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `lm_studio.chat` | Send non-streaming and streaming local LM Studio chat-completion requests. |
| `lm_studio.embeddings` | Create local LM Studio text embeddings. |
| `lm_studio.models.read` | List models visible to the configured LM Studio server. |
| `lm_studio.health.read` | Probe configured LM Studio reachability through a bounded model-list request. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `lm_studio.chat.completions` | `POST /v1/chat/completions` | `lm_studio.chat` | `Safe` | `Medium` | `None` | Local model output depends on prompt, tools, sampling options, model ID, and loaded model state. |
| `lm_studio.chat.completions_stream` | `POST /v1/chat/completions` with SSE | `lm_studio.chat` | `Safe` | `Medium` | `None` | Stream output depends on event ordering, model chunking, and finish metadata. |
| `lm_studio.embeddings.create` | `POST /v1/embeddings` | `lm_studio.embeddings` | `Safe` | `Low` | `Strict` | Embeddings expose sensitive source text and vectors but are deterministic enough for strict idempotency. |
| `lm_studio.models.list` | `GET /v1/models` | `lm_studio.models.read` | `Safe` | `Low` | `Strict` | Read-only model catalog discovery with in-memory caching. |
| `lm_studio.health` | `GET /v1/models` bounded probe | `lm_studio.health.read` | `Safe` | `Low` | `Strict` | Read-only readiness probe for configuration, model visibility, and network path. |

## Explicit Non-Goals

The current implementation does not include:

- LM Studio native REST-v0 stateful chat APIs
- LM Studio model load, download, unload, eviction, or lifecycle management
- LM Studio MCP server orchestration
- LM Studio Anthropic-compatible Messages API
- OpenAI-compatible `/v1/responses`
- OpenAI-compatible legacy `/v1/completions`
- public-zone invocation
- automatic model loading when `models.list` does not include a requested model
- durable storage of prompts, completions, embeddings, model catalogs, streamed deltas, or provider errors

These are excluded on purpose:

- The useful first slice is local or tailnet-hosted inference against already-loaded LM Studio models.
- Model lifecycle remains an operator concern; the connector does not mutate the local LM Studio runtime.
- Local-service networking is explicit and operator-allowlisted instead of silently sending prompts to arbitrary hosts.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, auth mode, base URL class, default models, request counters, and error counters
- redacted auth labels rather than raw API keys or credential values
- base URL policy for loopback, tailnet DNS, tailnet IP, private IP, and operator-allowlisted hosts
- credential-injection status for host credential reference mode
- operation schemas, safety, risk, idempotency, and AI hints
- simulate-time operation support
- capability-token checks against bound resources before dispatch

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- no-auth, API-key, and credential-id header behavior
- base URL normalization, tailnet-only rejection of loopback, and exact allowed-host policy
- chat, streaming chat, embeddings, model listing, and health dispatch
- in-memory model-list cache behavior
- rate-limit wait/retry behavior
- cancellation and shutdown behavior
- doctor redaction for prompts and embedding input
- local JSONL matrix output that logs hashes, counts, status values, and base URL class instead of sensitive text
- structured skip behavior for optional live local LM Studio smoke runs
- FCP trait invoke and bound capability-token validation

## Source Notes

- `connectors/lm-studio/src/client.rs` defines auth headers, local-service base URL normalization, endpoint classification, OpenAI-compatible dispatch, embeddings, and model listing.
- `connectors/lm-studio/src/connector.rs` defines configuration validation, lifecycle handlers, operation dispatch, capability verification, introspection, simulation, health, doctor, self-check, and shutdown behavior.
- `connectors/lm-studio/src/types.rs` defines chat and embeddings input parsing plus local validation for model IDs, chat counts, and embedding payloads.
- `connectors/lm-studio/src/error.rs` maps OpenAI-compatible client and streaming errors into FCP errors with sensitive text redaction.
- `connectors/lm-studio/manifest.toml` defines the operation catalog, local-service network constraints, sandbox boundary, and zone policy.
- `connectors/lm-studio/tests/integration.rs` covers deterministic loopback behavior, local-smoke skip behavior, JSONL evidence, redaction, rate-limit retry, shutdown, and FCP trait behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/lm_studio_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock integration coverage
- optional local LM Studio smoke with structured skip if the server is not listening or the model is not loaded
- base URL, auth, tailnet-only, allowed-host, chat, streaming, embeddings, model-list, health, rate-limit, cancellation, and redaction tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Start the LM Studio API server from the Developer tab or with `lms server start`.
- Load the model you want to use before invoking this connector.
- Use `api_key` only when LM Studio authentication is enabled or when a proxy in front of LM Studio requires a bearer token.
- Use `credential_id` only behind a host egress injection layer.
- Configure `allowed_hosts` for every non-loopback base URL.
- Use `tailnet_only = true` when the deployment must reject local loopback and force a tailnet or operator-allowlisted host.

**Dedicated environment**:

- Prefer WireMock loopback evidence for routine verification.
- Use a test LM Studio model and a dedicated local server for live local smoke runs.
- Keep native LM Studio model-management expectations out of this connector.

**Redaction rules**:

- Redact API keys, credential IDs where needed, prompts, completions, streamed chunks, tool-call arguments, embedding input, embedding vectors, full base URLs, provider payloads, and provider error bodies.
- Verification output should use base URL class, model ID hashes, byte counts, token counts, stream chunk counts, model counts, status values, error classes, and cleanup state.

**Common remediation**:

- If `health` reports `unconfigured`, call configure with either no auth, `api_key`, or `credential_id`, plus a valid `/v1` base URL if the default server is not used.
- If configuration fails with `Provide at most one of api_key or credential_id`, remove one auth mode.
- If base URL validation fails, use `http://localhost:1234/v1` or a `/v1` URL whose host is exactly listed in `allowed_hosts`.
- If `tailnet_only` rejects the default URL, provide a non-loopback base URL and include its host in `allowed_hosts`.
- If a requested model is absent, load it in LM Studio first; this connector does not load or download models.
- If `self_check` reports `credential_injection_required`, run behind the host egress injection layer or switch to direct no-auth/API-key mode.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-lm-studio-e2e cargo check -p fcp-lm-studio --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-lm-studio-e2e cargo test -p fcp-lm-studio --test integration -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-lm-studio-e2e cargo clippy -p fcp-lm-studio --all-targets --no-deps -- -D warnings`
