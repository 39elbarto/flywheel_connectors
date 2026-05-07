# NVIDIA NIM Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://docs.nvidia.com/nim/large-language-models/latest/reference/api-reference.html

## Purpose

This document fixes the operator-facing contract for `fcp.nvidia_nim`. The connector exposes NVIDIA-hosted and operator self-hosted NIM inference through OpenAI-compatible chat completions, SSE chat streaming, embeddings, model listing, and an explicit NeMo Retriever reranking operation.

The connector is intentionally an invocation bridge, not a NIM deployment manager. It does not launch containers, configure GPU serving, manage model profiles, call NIM management endpoints, or expose every endpoint that a running NIM may provide.

## Current Runtime Snapshot

The current crate exposes these operations:

- `nvidia_nim.chat.completions`
- `nvidia_nim.chat.completions_stream`
- `nvidia_nim.embeddings.create`
- `nvidia_nim.rerank`
- `nvidia_nim.models.list`
- `nvidia_nim.health`

Important runtime truths the contract preserves:

- Configuration accepts `deployment_mode = "hosted"` by default, or `deployment_mode = "self_hosted"` with accepted spellings `self_hosted`, `self-hosted`, and `selfhosted`.
- Hosted mode requires exactly one of `api_key` or `credential_id`.
- Self-hosted mode may use no auth, `api_key`, or `credential_id`; `api_key` and `credential_id` are mutually exclusive.
- API-key mode sends `Authorization: Bearer ...`.
- Credential-id mode sends `x-fcp-credential-id` and requires host-side egress credential injection for live checks.
- Default hosted inference base URL is `https://integrate.api.nvidia.com/v1`.
- Default hosted rerank base URL is `https://ai.api.nvidia.com/v1`, with rerank path `/retrieval/nvidia/reranking`.
- Default self-hosted rerank base URL is the configured inference base URL, with rerank path `/ranking`.
- All base URLs must use path `/v1` and must not include query or fragment components.
- Hosted endpoints must use HTTPS and the exact NVIDIA hosts for their purpose.
- Self-hosted endpoints may use loopback by default or exact operator entries in `allowed_hosts`.
- `tailnet_only = true` rejects localhost and loopback self-hosted base URLs.
- Private and tailnet IP literals require both an exact `allowed_hosts` entry and `allow_private_hosts = true`.
- Runtime classifies configured endpoints as `hosted_api`, `hosted_retrieval`, `loopback`, `tailnet_dns`, `tailnet_ip`, `private_ip`, or `operator_allowed_host`.
- Default chat model is `meta/llama-3.1-8b-instruct`.
- Default embedding model is `nvidia/nv-embedqa-e5-v5`.
- Default rerank model is `nv-rerank-qa-mistral-4b:1`.
- Default `request_timeout_ms` is `180_000`.
- Default `model_cache_ttl_seconds` is `300`.
- `wait_on_rate_limit_ms` switches rate-limit behavior from fail-fast to bounded wait/retry.
- Chat input rejects empty messages, zero `n`, `n > 128`, empty model IDs, overlong model IDs, whitespace in model IDs, and model IDs containing CR, LF, or NUL.
- Chat `nvext` is forwarded through provider extensions.
- Embedding input rejects empty strings, empty batches, batches larger than 1,000 entries, empty batch entries, and zero `dimensions`.
- Rerank input requires a query plus 1 to 512 passages, trims text, rejects empty text, rejects text longer than 9,728 bytes, accepts `truncate` values `START`, `END`, and `NONE`, and accepts image fields only as bounded `data:image/...` URLs.
- `nvidia_nim.models.list` uses `GET /v1/models` and supports `{"refresh": true}` to invalidate the in-memory cache.
- FCP subscribe is not implemented; streaming is exposed as the bounded invoke operation `nvidia_nim.chat.completions_stream`.

## First-Slice Scope

The first NVIDIA NIM README slice documents the existing runtime surface:

- non-streaming chat completions through `POST /v1/chat/completions`
- SSE chat completions through the same endpoint with `stream: true`
- embeddings through `POST /v1/embeddings`
- hosted retrieval reranking through `/retrieval/nvidia/reranking`
- self-hosted reranking through `/v1/ranking`
- model discovery through `GET /v1/models`
- a health operation backed by a short model-list probe
- hosted API-key and credential-reference auth
- optional self-hosted no-auth operation
- explicit hosted, loopback, tailnet DNS, tailnet IP, private IP, and operator-allowlisted URL policy
- local validation for invalid auth material, allowed hosts, model IDs, chat fields, embedding fields, and rerank fields
- bounded rate-limit retry behavior for OpenAI-compatible and rerank paths
- redaction-safe doctor, self-check, health, provider error, and JSONL proof output
- bound capability-token verification before dispatch

## Auth And Scope Boundary

- Authentication mechanisms: no auth for self-hosted mode, NVIDIA API key / proxy bearer token, or host-injected credential ID.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zones: `z:owner`, `z:private`, and `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `nvidia_nim.chat` gates chat and streaming chat completions.
  - `nvidia_nim.embeddings` gates embedding creation.
  - `nvidia_nim.rerank` gates reranking.
  - `nvidia_nim.models.read` gates model listing.
  - `nvidia_nim.health.read` gates the health probe.
- The connector does not persist prompts, completions, streamed chunks, tool-call arguments, `nvext` payloads, embedding inputs, embedding vectors, rerank query text, passage text, image data URLs, model catalogs, provider payloads, provider responses, API keys, or credential IDs.
- Credential-id mode is a host-egress contract, not proof that live NVIDIA NIM will accept a request without an injection layer.

## Network And Runtime Invariants

- Hosted inference host: `integrate.api.nvidia.com`.
- Hosted retrieval rerank host: `ai.api.nvidia.com`.
- Hosted inference path root: `/v1`.
- Hosted rerank request path: `/v1/retrieval/nvidia/reranking`.
- Self-hosted inference path root: `/v1`.
- Self-hosted rerank request path: `/v1/ranking`.
- Production port: `443`; manifest policy also lists `80` and `8000` for self-hosted/operator deployments.
- Hosted traffic requires HTTPS and exact NVIDIA hosts.
- Self-hosted HTTP and HTTPS are valid only for loopback or exact operator-allowlisted hosts.
- Manifest hosted network policy denies localhost, private ranges, tailnet ranges, IP literals, and redirects.
- Runtime self-hosted policy explicitly allows loopback and operator-approved tailnet/private hosts when configuration opts in.
- Runtime default `request_timeout_ms`: `180_000`.
- Manifest chat, streaming, embeddings, and rerank network constraints set total timeout `180_000 ms`.
- Manifest model-list network constraints set total timeout `30_000 ms`.
- Manifest health network constraints set total timeout `5_000 ms`.
- Maximum response bytes are `10_485_760`.
- Sandbox profile is `moderate`, with `128 MB` memory, `25%` CPU, `180_000 ms` wall-clock timeout, no exec, and no ptrace.
- Event capability metadata declares streaming support, no replay, no acknowledgement requirement, and a minimum buffer of 0 events.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `nvidia_nim.chat` | Send non-streaming and streaming NIM chat-completion requests. |
| `nvidia_nim.embeddings` | Create embeddings through a configured NIM embedding model. |
| `nvidia_nim.rerank` | Rerank retrieved passages through hosted retrieval or self-hosted NeMo Retriever. |
| `nvidia_nim.models.read` | List models visible to the configured NIM inference endpoint. |
| `nvidia_nim.health.read` | Probe configured NIM reachability through a bounded model-list request. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `nvidia_nim.chat.completions` | `POST /v1/chat/completions` | `nvidia_nim.chat` | `Safe` | `Medium` | `None` | Model output depends on prompt, tools, sampling options, `nvext`, model ID, and deployment state. |
| `nvidia_nim.chat.completions_stream` | `POST /v1/chat/completions` with SSE | `nvidia_nim.chat` | `Safe` | `Medium` | `None` | Stream output depends on event ordering, model chunking, provider deltas, and finish metadata. |
| `nvidia_nim.embeddings.create` | `POST /v1/embeddings` | `nvidia_nim.embeddings` | `Safe` | `Low` | `Strict` | Embeddings expose sensitive source text and vectors but are deterministic enough for strict idempotency. |
| `nvidia_nim.rerank` | Hosted `/retrieval/nvidia/reranking` or self-hosted `/v1/ranking` | `nvidia_nim.rerank` | `Safe` | `Low` | `Strict` | Ranking exposes sensitive query and passage text but should be repeatable for a fixed model and payload. |
| `nvidia_nim.models.list` | `GET /v1/models` | `nvidia_nim.models.read` | `Safe` | `Low` | `Strict` | Read-only model catalog discovery with in-memory caching. |
| `nvidia_nim.health` | `GET /v1/models` bounded probe | `nvidia_nim.health.read` | `Safe` | `Low` | `Strict` | Read-only readiness probe for configuration and network path. |

## Explicit Non-Goals

The current implementation does not include:

- NIM container launch, shutdown, model-profile selection, GPU scheduling, or deployment lifecycle management
- NIM management endpoints such as readiness/liveness endpoints beyond the connector's model-list health probe
- OpenAI-compatible `/v1/completions`
- OpenAI-compatible `/v1/responses`
- Anthropic-compatible `/v1/messages`
- tokenize, detokenize, chat-template render, or count-token endpoints
- training, fine-tuning, model upload, or model registry management
- automatic model loading when `models.list` does not include a requested model
- FCP subscription-based streaming
- connector-local credential vaulting
- public-zone invocation
- durable storage of prompts, completions, embeddings, rerank payloads, streamed deltas, model catalogs, or provider errors

These are excluded on purpose:

- The useful first slice is an invocation bridge to an already-hosted NVIDIA or operator NIM boundary.
- Model serving, GPU placement, and NIM container lifecycle remain operator concerns.
- Self-hosted network access is explicit and allowlisted instead of silently sending prompts to arbitrary hosts.
- Rerank endpoints differ between NVIDIA-hosted retrieval and self-hosted NeMo Retriever; the connector keeps that routing visible in configuration and health output.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, auth mode, deployment mode, endpoint classes, rerank endpoint name, default models, request counters, and error counters
- redacted API-key labels rather than raw API keys
- base URL policy for hosted API, hosted retrieval, loopback, tailnet DNS, tailnet IP, private IP, and operator-allowlisted hosts
- credential-injection status for host credential reference mode
- operation schemas, safety, risk, idempotency, and AI hints
- simulate-time operation support
- capability-token checks against bound model, embedding-model, rerank-model, and model-list resources before dispatch

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- no-auth, API-key, and credential-id header behavior
- hosted and self-hosted deployment-mode parsing
- hosted HTTPS exact-host policy
- self-hosted loopback, tailnet-only, allowed-host, private-IP, and tailnet-IP policy
- chat, streaming chat, embeddings, rerank, model listing, and health dispatch
- hosted and self-hosted rerank endpoint selection
- in-memory model-list cache behavior
- rate-limit wait/retry behavior for OpenAI-compatible and rerank paths
- cancellation and shutdown behavior
- doctor redaction for prompts, embedding input, rerank queries, passages, and image data URLs
- local JSONL matrix output that logs hashes, counts, status values, endpoint classes, and cleanup state instead of sensitive text
- structured skip behavior for optional hosted smoke runs
- FCP trait invoke and bound capability-token validation

## Source Notes

- `connectors/nvidia-nim/src/client.rs` defines auth headers, deployment-mode parsing, base URL normalization, endpoint classification, OpenAI-compatible dispatch, embeddings, model listing, rerank dispatch, and provider error redaction.
- `connectors/nvidia-nim/src/connector.rs` defines configuration validation, lifecycle handlers, operation dispatch, capability verification, introspection, simulation, health, doctor, self-check, and shutdown behavior.
- `connectors/nvidia-nim/src/types.rs` defines chat, embeddings, and rerank input parsing plus local validation for model IDs, chat counts, embedding payloads, rerank text, image data URLs, and truncate values.
- `connectors/nvidia-nim/manifest.toml` defines the operation catalog, hosted/self-hosted network constraints, sandbox boundary, zone policy, and operation AI hints.
- `connectors/nvidia-nim/tests/integration.rs` covers deterministic loopback behavior, hosted-smoke skip behavior, JSONL evidence, redaction, rate-limit retry, shutdown, endpoint classification, URL policy, and FCP trait behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/nvidia_nim_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock integration coverage
- optional hosted NVIDIA smoke with structured skip if credentials are absent
- base URL, deployment mode, auth, allowed-host, chat, streaming, embeddings, rerank, model-list, health, rate-limit, cancellation, and redaction tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use an NVIDIA-hosted API key only for hosted live provider verification.
- Use `credential_id` only behind a host egress injection layer.
- Use `deployment_mode = "self_hosted"` for local or operator-managed NIM containers.
- Configure `allowed_hosts` for every non-loopback self-hosted base URL.
- Set `allow_private_hosts = true` when using private or tailnet IP literals intentionally.
- Set `tailnet_only = true` when the deployment must reject local loopback and force a tailnet/operator endpoint.
- Ensure the configured NIM actually serves the model family requested by chat, embeddings, or rerank calls.

**Dedicated environment**:

- Prefer WireMock loopback evidence for routine verification.
- Use a test NVIDIA account for hosted smoke runs and keep live prompts intentionally small.
- Use a dedicated self-hosted NIM container or tailnet endpoint for local proof.
- Keep NIM deployment, model-management, tokenizer, Responses, Messages, and legacy Completions expectations out of this connector.

**Redaction rules**:

- Redact API keys, credential IDs where needed, prompts, completions, streamed chunks, tool-call arguments, `nvext` payloads, embedding input, embedding vectors, rerank query text, rerank passage text, image data URLs, full base URLs, provider payloads, and provider error bodies.
- Verification output should use endpoint class, rerank endpoint name, model ID hashes, byte counts, token counts, stream chunk counts, embedding counts, passage counts, ranking counts, status values, error classes, and cleanup state.

**Common remediation**:

- If hosted configuration fails with `Hosted NVIDIA NIM requires api_key or credential_id`, add exactly one hosted auth mode.
- If self-hosted configuration fails with `Provide at most one of api_key or credential_id`, remove one auth mode.
- If base URL validation fails in hosted mode, use `https://integrate.api.nvidia.com/v1` for inference and `https://ai.api.nvidia.com/v1` for hosted rerank.
- If base URL validation fails in self-hosted mode, use a `/v1` URL on loopback or a host exactly listed in `allowed_hosts`.
- If `tailnet_only` rejects the default URL, provide a non-loopback self-hosted base URL and include its host in `allowed_hosts`.
- If a private or tailnet IP literal is rejected, add the exact IP to `allowed_hosts` and set `allow_private_hosts = true`.
- If a requested model is absent, load or expose that model in the hosted/self-hosted NIM deployment first; this connector does not load or download models.
- If rerank calls hit the wrong path, verify `deployment_mode`; hosted rerank uses the NVIDIA retrieval endpoint, while self-hosted rerank uses `/v1/ranking`.
- If `self_check` reports `credential_injection_required`, run behind the host egress injection layer or switch to direct no-auth/API-key mode as appropriate for the deployment.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-nvidia-nim-e2e cargo check -p fcp-nvidia-nim --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-nvidia-nim-e2e cargo test -p fcp-nvidia-nim --test integration -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-nvidia-nim-e2e cargo clippy -p fcp-nvidia-nim --all-targets --no-deps -- -D warnings`
