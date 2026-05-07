# Ollama Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://docs.ollama.com/api/openai-compatibility

## Purpose

This document fixes the operator-facing contract for `fcp.ollama`. The connector exposes Ollama's local or operator-allowlisted OpenAI-compatible inference surface: chat completions, SSE chat streaming, embeddings, model listing, and a bounded health probe.

The connector is intentionally mesh-sovereign and local-service oriented. It does not expose Ollama-native `/api/*` model-management endpoints, image generation, Responses, legacy Completions, cloud account APIs, or automatic model pulling.

## Current Runtime Snapshot

The current crate exposes these operations:

- `ollama.chat.completions`
- `ollama.chat.completions_stream`
- `ollama.embeddings.create`
- `ollama.models.list`
- `ollama.health`

Important runtime truths the contract preserves:

- Configuration accepts optional unauthenticated mode, `api_key`, or `credential_id`.
- `api_key` and `credential_id` are mutually exclusive; absent auth is valid because local Ollama is unauthenticated by default.
- API-key mode sends `Authorization: Bearer ...` for reverse proxies or secured tailnet deployments.
- Credential-id mode sends `x-fcp-credential-id` and requires host-side egress credential injection for live checks.
- Default base URL is `http://localhost:11434/v1`.
- Base URL path must be exactly `/v1`; query and fragment components are rejected.
- Base URL scheme must be `http` or `https`.
- Loopback hosts are allowed by default.
- Non-loopback hosts must be listed exactly in `allowed_hosts`, with at most 64 bare hostname or IP-literal entries.
- `tailnet_only = true` rejects localhost and loopback base URLs.
- Runtime classifies configured endpoints as `loopback`, `tailnet_dns`, `tailnet_ip`, `private_ip`, or `operator_allowed_host`.
- Default chat model is `llama3.2`.
- Default embedding model is `nomic-embed-text`.
- Default `request_timeout_ms` is `300_000`.
- Default `model_cache_ttl_seconds` is `300`.
- `wait_on_rate_limit_ms` switches rate-limit behavior from fail-fast to bounded wait/retry.
- Chat input rejects empty messages, zero `n`, `n > 128`, empty model IDs, overlong model IDs, whitespace in model IDs, and model IDs containing CR, LF, or NUL.
- Ollama chat input preserves OpenAI-compatible fields plus Ollama-specific `format` and `keep_alive` by forwarding them through provider extensions.
- Embedding input rejects empty strings, empty batches, batches larger than 1,000 entries, empty batch entries, and zero `dimensions`.
- `ollama.models.list` uses `GET /v1/models` and supports `{"refresh": true}` to invalidate the in-memory cache.
- FCP subscribe is not implemented; streaming is exposed as the bounded invoke operation `ollama.chat.completions_stream`.
- The connector never calls `/api/pull`, `/api/tags`, `/api/generate`, `/api/chat`, or any other Ollama-native endpoint.

## First-Slice Scope

The first Ollama README slice documents the existing runtime surface:

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

- Authentication mechanisms: no auth, optional Ollama proxy bearer token, or host-injected credential ID.
- Home zone: `z:owner`.
- Allowed source zones: `z:owner`, `z:private`, `z:work`, and `z:project:*`.
- Allowed target zones: `z:owner`, `z:private`, `z:work`, and `z:project:*`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `ollama.chat` gates chat and streaming chat completions.
  - `ollama.embeddings` gates embedding creation.
  - `ollama.models.read` gates model listing.
  - `ollama.health.read` gates the health probe.
- The connector does not persist prompts, completions, streamed chunks, embedding inputs, embedding vectors, model catalogs, API keys, credential IDs, provider payloads, or provider responses.
- Credential-id mode is a host-egress contract, not proof that a local Ollama server will accept a request without an injection layer.

## Network And Runtime Invariants

- Default local host: `localhost`.
- Default local port: `11434`.
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
- Sandbox profile is `local-services`, with `128 MB` memory, `25%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `ollama.chat` | Send non-streaming and streaming local Ollama chat-completion requests. |
| `ollama.embeddings` | Create local Ollama text embeddings. |
| `ollama.models.read` | List installed Ollama model IDs through the OpenAI-compatible endpoint. |
| `ollama.health.read` | Probe configured Ollama reachability through a bounded model-list request. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `ollama.chat.completions` | `POST /v1/chat/completions` | `ollama.chat` | `Safe` | `Medium` | `None` | Local model output depends on prompt, tools, sampling options, model ID, and installed model state. |
| `ollama.chat.completions_stream` | `POST /v1/chat/completions` with SSE | `ollama.chat` | `Safe` | `Medium` | `None` | Stream output depends on event ordering, model chunking, and finish metadata. |
| `ollama.embeddings.create` | `POST /v1/embeddings` | `ollama.embeddings` | `Safe` | `Low` | `Strict` | Embeddings expose sensitive source text and vectors but are deterministic enough for strict idempotency. |
| `ollama.models.list` | `GET /v1/models` | `ollama.models.read` | `Safe` | `Low` | `Strict` | Read-only installed-model discovery with in-memory caching. |
| `ollama.health` | `GET /v1/models` bounded probe | `ollama.health.read` | `Safe` | `Low` | `Strict` | Read-only readiness probe for configuration, model visibility, and network path. |

## Explicit Non-Goals

The current implementation does not include:

- Ollama-native `/api/generate`, `/api/chat`, `/api/tags`, `/api/show`, `/api/pull`, `/api/create`, `/api/copy`, `/api/delete`, `/api/ps`, or `/api/embed`
- OpenAI-compatible `/v1/responses`
- OpenAI-compatible legacy `/v1/completions`
- OpenAI-compatible image generation
- automatic model pulling, copying, creation, deletion, or context-size mutation
- cloud account, registry, or library management
- public-zone invocation
- durable storage of prompts, completions, embeddings, model catalogs, streamed deltas, or provider errors

These are excluded on purpose:

- The useful first slice is local or tailnet-hosted inference against already-installed Ollama models.
- Model lifecycle remains an operator concern; the connector cannot change the local Ollama model inventory.
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
- structured skip behavior for optional live local Ollama smoke runs
- FCP trait invoke and bound capability-token validation

## Source Notes

- `connectors/ollama/src/client.rs` defines auth headers, local-service base URL normalization, endpoint classification, OpenAI-compatible dispatch, embeddings, and model listing.
- `connectors/ollama/src/connector.rs` defines configuration validation, lifecycle handlers, operation dispatch, capability verification, introspection, simulation, health, doctor, self-check, and shutdown behavior.
- `connectors/ollama/src/types.rs` defines chat and embeddings input parsing plus local validation for model IDs, chat counts, embedding payloads, and Ollama-specific `format` / `keep_alive` forwarding.
- `connectors/ollama/src/error.rs` maps OpenAI-compatible client and streaming errors into FCP errors with sensitive text redaction.
- `connectors/ollama/manifest.toml` defines the operation catalog, local-service network constraints, sandbox boundary, zone policy, and privacy metadata.
- `connectors/ollama/tests/integration.rs` covers deterministic loopback behavior, local-smoke skip behavior, JSONL evidence, redaction, rate-limit retry, shutdown, and FCP trait behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/ollama_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock integration coverage
- optional local Ollama smoke with structured skip if the server is not listening or the model is not installed
- base URL, auth, tailnet-only, allowed-host, chat, streaming, embeddings, model-list, health, rate-limit, cancellation, and redaction tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Install and start Ollama before live local smoke runs.
- Pull every chat and embedding model you expect to use before invoking this connector.
- Use `api_key` only when a reverse proxy or secured tailnet deployment requires a bearer token; default local Ollama ignores bearer auth.
- Use `credential_id` only behind a host egress injection layer.
- Configure `allowed_hosts` for every non-loopback base URL.
- Use `tailnet_only = true` when the deployment must reject local loopback and force a tailnet or operator-allowlisted host.

**Dedicated environment**:

- Prefer WireMock loopback evidence for routine verification.
- Use a tiny test model for optional live local smoke runs.
- Keep model pulling, copying, deletion, context-size changes, and native Ollama management expectations out of this connector.

**Redaction rules**:

- Redact API keys, credential IDs where needed, prompts, completions, streamed chunks, tool-call arguments, embedding input, embedding vectors, full base URLs, provider payloads, and provider error bodies.
- Verification output should use base URL class, model ID hashes, byte counts, token counts, stream chunk counts, model counts, status values, error classes, and cleanup state.

**Common remediation**:

- If `health` reports `unconfigured`, call configure with either no auth, `api_key`, or `credential_id`, plus a valid `/v1` base URL if the default server is not used.
- If configuration fails with `Provide at most one of api_key or credential_id`, remove one auth mode.
- If base URL validation fails, use `http://localhost:11434/v1` or a `/v1` URL whose host is exactly listed in `allowed_hosts`.
- If `tailnet_only` rejects the default URL, provide a non-loopback base URL and include its host in `allowed_hosts`.
- If a requested model is absent, run `ollama pull` outside the connector; this connector does not pull or create models.
- If context size must change, create the Ollama model outside the connector and call the API with the updated model name.
- If `self_check` reports `credential_injection_required`, run behind the host egress injection layer or switch to direct no-auth/API-key mode.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-ollama-e2e cargo check -p fcp-ollama --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-ollama-e2e cargo test -p fcp-ollama --test integration -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-ollama-e2e cargo clippy -p fcp-ollama --all-targets --no-deps -- -D warnings`
