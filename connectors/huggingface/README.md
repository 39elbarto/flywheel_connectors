# Hugging Face Connector V3 Contract

> **Status**: incubating runtime contract documented with inference-endpoint and credential-injection drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Hugging Face Inference Providers upstream**: https://huggingface.co/docs/inference-providers/index
> **Text generation upstream**: https://huggingface.co/docs/inference-providers/tasks/text-generation
> **Summarization upstream**: https://huggingface.co/docs/api-inference/en/tasks/summarization
> **Hub API upstream**: https://huggingface.co/docs/hub/api

## Purpose

This document fixes the operator-facing contract for `fcp.huggingface`. The connector exposes the Hugging Face surfaces implemented in this crate: bounded text generation, bounded summarization, Hub model listing, and Hub model metadata lookup.

The connector is intentionally a small inference and model-catalog bridge. It is not a full Hugging Face Hub client, repository manager, dataset client, Space runtime client, router-backed Inference Providers SDK, streaming chat client, fine-tuning client, model uploader, organization admin client, or durable model registry.

## Current Runtime Snapshot

The current crate exposes these operations:

- `huggingface.inference.text_generation`
- `huggingface.inference.summarization`
- `huggingface.models.list`
- `huggingface.models.info`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-huggingface`.
- Runtime connector ID is `fcp.huggingface`.
- Manifest connector ID is `fcp.huggingface`.
- Runtime connector version is `0.2.0`.
- Configuration accepts:
  - `api_token`
  - `credential_id`
  - neither auth source, for anonymous/public-model attempts
- `api_token` and `credential_id` are mutually exclusive.
- `credential_id` must be a valid UUID when present.
- Direct-token mode sends `Authorization: Bearer <token>`.
- Default inference URL is `https://api-inference.huggingface.co`.
- Default Hub URL is `https://huggingface.co/api`.
- Runtime request timeout defaults to `30000 ms`.
- Runtime uses the shared retry loop for inference, model-list, model-info, and `whoami` requests.
- Text generation defaults to model `gpt2` when `model_id` is omitted.
- Summarization defaults to model `facebook/bart-large-cnn` when `model_id` is omitted.
- Model listing defaults to `limit = 25` and rejects limits over `100`.
- Model IDs are locally rejected when empty, path-traversal-shaped, percent-encoded slash/backslash-shaped, or containing more than one slash.
- Inference requests post JSON to `{inference_url}/models/{model_id}`.
- Model listing calls `GET {hub_url}/models` with optional `search`, `pipeline_tag`, and `limit`.
- Model metadata calls `GET {hub_url}/models/{model_id}`.
- `self_check` calls `/whoami-v2` for direct-token mode after stripping a trailing `/api` from `hub_url`.
- HTTP 401 and 403 map to unauthorized, 404 maps to not-found, 429 maps to rate-limited, model-loading 503 responses are retryable, and other 5xx responses are retryable.
- `health` reports `ready` only for configured direct-token mode; configured credential-id and anonymous modes report `degraded`.
- `doctor` checks configuration, handshake, client initialization, runtime initialization, and auth source.
- `handle_shutdown` clears client, runtime, config, configured state, and handshaken state.
- `invoke` only checks connector ready state and operation ID. It does not require or verify an FCP capability token in this checkout.
- `simulate` checks known operation ID plus configured state. It does not check handshake state, approval policy, or capability tokens.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Runtime uses the legacy-style `api-inference.huggingface.co/models/{model_id}` endpoint shape, while current Hugging Face docs emphasize Inference Providers and router-backed endpoints such as `router.huggingface.co`.
- Runtime accepts `credential_id`, reports credential-injection readiness, and includes it in the provider contract test, but `HuggingfaceClient` stores only `api_token` and never sends an `X-FCP-Credential-Id` header. Credential-id mode cannot perform live requests unless a surrounding proxy rewrites requests without connector help.
- Runtime custom `inference_url` and `hub_url` validation accepts any absolute `http` or `https` URL without query or fragment. The manifest pins live egress to `api-inference.huggingface.co` and `huggingface.co`, denies localhost/private/tailnet/IP literals, and requires canonical host checks.
- Runtime `introspect` marks inference operations with `safety_tier = "safe"`, while the manifest marks text generation and summarization as `risky`.
- Runtime `invoke` does not verify bound capability tokens for either inference or model-catalog operations.
- Runtime `simulate` can allow a configured operation without checking the handshake or caller authority.
- Runtime summarization manifest input schema includes `do_sample`, but the invoke path currently forwards only `max_length` and `min_length`.
- Runtime model-list output includes the connector-local `catalog` and `limit` wrapper, not just the raw Hub list.
- Runtime direct requests may work anonymously for public endpoints, but self-check still uses `whoami-v2` and will degrade without a usable token.

A follow-up parity bead should either migrate to the current Inference Providers router contract or clearly preserve the legacy Inference API surface, implement real credential-id header/proxy behavior, enforce manifest host policy at configure time, align runtime safety metadata with the manifest, verify bound capability tokens, and remove or implement unsupported summarization schema fields.

## First-Slice Scope

The current Hugging Face README slice documents the existing runtime surface:

- direct token, credential-id, and anonymous configuration modes
- text generation and summarization request shapes
- Hub model list and model-info operations
- default model selection and model-list bounding
- retry, timeout, provider error, readiness, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- runtime/manifest drift around endpoint policy, credential injection, capability-token verification, and inference safety metadata
- mock-only provider contract tests

## Auth And Zone Boundary

- Authentication mechanisms: Hugging Face user access token, host credential reference, or anonymous public-model access.
- Official Hugging Face docs describe bearer-token authentication for Inference Providers requests and Hub API access.
- Runtime does not implement token creation, token rotation, OAuth login, model access approval, provider selection policy, billing controls, organization administration, or connector-local credential vaulting.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Runtime handshake advertises:
  - `huggingface.inference`
  - `huggingface.models`
- The connector does not persist prompts, generated text, summaries, model metadata, tokens, credential IDs beyond configuration metadata, provider payloads, provider error bodies, model catalog caches, or usage records.
- Prompts and summaries can include sensitive source text, customer data, private code, or private research context. Treat live inference input and output as work-zone data.

## Network And Runtime Invariants

- Default inference host: `api-inference.huggingface.co`.
- Default Hub host: `huggingface.co`.
- Default Hub API prefix: `/api`.
- Runtime request construction appends `/models/{model_id}` or `/models` to the configured base URLs.
- Runtime reqwest timeout is configured from `request_timeout_ms`.
- Runtime request contexts use the same configured timeout.
- Runtime base URL normalization strips trailing slashes and rejects query strings and fragments.
- Runtime permits HTTP base URLs, including loopback test fixtures.
- Manifest live-operation policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and allows only the default Hugging Face hosts.
- Sandbox profile is `strict`, with `96 MB` memory, `25%` CPU, `60000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets and does not implement streaming responses.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `huggingface.inference` | Run text generation and summarization against a selected model. |
| `huggingface.models` | List Hub models and read one model's metadata. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `huggingface.inference.text_generation` | `POST {inference_url}/models/{model_id}` | `huggingface.inference` | `Risky` in manifest, `safe` in runtime introspection | `Medium` | `None` | Sends caller prompt text to a model and returns generated text. |
| `huggingface.inference.summarization` | `POST {inference_url}/models/{model_id}` | `huggingface.inference` | `Risky` in manifest, `safe` in runtime introspection | `Medium` | `None` | Sends caller text to a summarization model and returns summaries. |
| `huggingface.models.list` | `GET {hub_url}/models` | `huggingface.models` | `Safe` | `Low` | `Strict` | Reads bounded Hub model catalog entries with optional filters. |
| `huggingface.models.info` | `GET {hub_url}/models/{model_id}` | `huggingface.models` | `Safe` | `Low` | `Strict` | Reads metadata for one caller-selected Hub model. |

## Explicit Non-Goals

The current implementation does not include:

- Inference Providers router support, chat completions, provider selection, streaming tokens, structured outputs, tools, or OpenAI-compatible routes
- model upload, repository creation, dataset access, Space management, comments, discussions, likes, follows, billing, or organization administration
- token creation, token exchange, OAuth login, model access approval workflows, or credential rotation
- image, audio, video, embedding, reranking, classification, or speech tasks
- persistent model catalog cache, usage accounting, request transcripts, or response storage
- direct FCP capability-token verification at connector invoke time

These are excluded on purpose:

- Inference inputs can contain private text and source code.
- Provider selection and billing policy need explicit operator controls before broader inference expansion.
- Model generation is non-idempotent and can produce unsafe or non-deterministic output, so expansion needs stronger approval and audit boundaries.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration, client, runtime, and handshake state
- auth mode as API token, credential ID, or anonymous
- credential-injection requirement for credential-id mode
- provider-backed token validation through `whoami-v2` for direct-token mode
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- model defaults and the bounded model-list catalog behavior
- retry, rate-limit, model-loading, not-found, unauthorized, timeout, and JSON parse error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- provider contract advertisement, default models, auth modes, base URLs, and secret redaction
- WireMock model-list filters, text-generation request shape, model-info auth failure, not-found mapping, rate-limit retry, malformed catalog JSON, timeout cancellation, self-check, and shutdown behavior
- lifecycle health, configure defaults, invalid credential IDs, mixed auth rejection, base URL query rejection, handshake requirements, unknown operations, missing inputs, model-list limit bounds, and simulate behavior

## Source Notes

- `connectors/huggingface/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, introspection, simulation, invoke dispatch, operation IDs, default models, and model-list bounds.
- `connectors/huggingface/src/client.rs` defines Hugging Face HTTP request construction, auth headers, base URL normalization, model ID sanitization, retry dispatch, whoami checks, and response parsing.
- `connectors/huggingface/src/types.rs` defines inference request/response shapes, model metadata, model-list query fields, and provider error envelopes.
- `connectors/huggingface/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/huggingface/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and AI hints.
- `connectors/huggingface/tests/provider_contract.rs` covers provider-contract and loopback behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/huggingface_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for Hugging Face HTTP paths
- auth, provider error, retry, timeout, lifecycle, simulation, introspection, doctor, and self-check coverage
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use WireMock fixtures for routine verification.
- Use a disposable Hugging Face token for live direct-token checks.
- Prefer direct token mode until credential-id injection is actually wired through the HTTP client or egress layer.

**Dedicated environment**:

- Keep live prompts synthetic and non-sensitive.
- Pin `model_id` explicitly when reproducibility matters.
- Use `huggingface.models.info` before invoking unfamiliar gated or large models.
- Keep `limit` small for catalog listing.

**Redaction rules**:

- Redact API tokens, credential IDs where needed, prompts, generated text when sensitive, summaries, private model IDs, gated-model names, provider payloads, provider error bodies, and request URLs containing custom test hosts.
- Verification output should use operation IDs, endpoint classes, model ID hashes, HTTP status classes, retry decisions, and synthetic prompt text.

**Common remediation**:

- If configuration rejects auth, provide only one of `api_token` or `credential_id`.
- If self-check reports `credential_injection_required`, use direct token mode or implement host-side injection.
- If self-check reports `token_validation_failed` in anonymous mode, remember that anonymous public-model calls may still work but `whoami-v2` cannot validate a token.
- If model listing rejects input, keep `limit` between `1` and `100`.
- If inference rejects a model ID, use either `model` or `org/model` shape without encoded separators.
- If provider returns model-loading 503, let the retry loop consume the `estimated_time` hint or retry later.
- If `simulate` allows an operation but policy should deny it, remember that current simulation only checks configured state and operation ID.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-huggingface-readme cargo check -p fcp-huggingface --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-huggingface-readme cargo test -p fcp-huggingface --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-huggingface-readme cargo clippy -p fcp-huggingface --all-targets --no-deps -- -D warnings`
- `ubs connectors/huggingface/README.md`
