# OpenRouter Connector V3 Contract

> **Status**: runtime contract documented; manifest/introspection/API drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **OpenRouter API overview upstream**: https://openrouter.ai/docs/api-reference/overview
> **OpenRouter chat completions upstream**: https://openrouter.ai/docs/api-reference/chat-completion
> **OpenRouter models upstream**: https://openrouter.ai/docs/api/api-reference/models/get-models
> **OpenRouter video generation upstream**: https://openrouter.ai/docs/guides/overview/multimodal/video-generation
> **OpenRouter video submit upstream**: https://openrouter.ai/docs/api/api-reference/video-generation/create-videos
> **OpenRouter video polling upstream**: https://openrouter.ai/docs/api/api-reference/video-generation/get-videos

## Purpose

This document fixes the operator-facing contract for `fcp.openrouter`. The connector exposes the OpenRouter API surface currently implemented in this crate: non-streaming chat completions, model catalog reads, and bounded video generation with job polling and generated-asset download.

The connector is intentionally a bounded OpenRouter request-response bridge. It is not a full OpenAI-compatible SDK, streaming relay, Responses API adapter, embeddings client, image-generation wrapper, provider-key manager, model-router policy engine, video-to-video tool, persistent generation tracker, usage analytics collector, or durable media store.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `openrouter.chat.completions`
- `openrouter.models.list`
- `openrouter.videos.generate`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-openrouter`.
- Manifest ID is `fcp.openrouter`.
- `BaseConnector` runtime ID is `fcp.openrouter`.
- Runtime connector version is `0.1.0`.
- Manifest format is `native`.
- Manifest schema version is `2.1`.
- Configuration requires exactly one auth source:
  - `api_key`
  - `credential_id`
- Direct API-key mode sends `Authorization: Bearer <api_key>`.
- `credential_id` mode is accepted at configure time but no host credential-injection path is implemented in this slice.
- Runtime `invoke()` rejects all supported operations in `credential_id` mode.
- Runtime `simulate()` returns blocked for supported operations in `credential_id` mode.
- Default base URL is `https://openrouter.ai/api/v1`.
- Custom `base_url` must use HTTPS and host `openrouter.ai`, except HTTP loopback is accepted for tests.
- Custom `base_url` must not include userinfo, query string, or fragment.
- Optional `app_name` becomes the `X-Title` provider header.
- Optional `app_url` becomes the `HTTP-Referer` provider header.
- Default request timeout is 60000 ms.
- Runtime `handle_configure()` creates the HTTP client, stores config, and marks the base configured.
- Runtime `handle_handshake()` is a local JSON handshake, not a typed FCP `HandshakeRequest`.
- Runtime `handle_handshake()` requires prior configuration, accepts an optional `session_id`, defaults to `openrouter-local-session`, and returns the static capabilities `openrouter.chat`, `openrouter.models`, and `openrouter.video`.
- Runtime `handle_handshake()` does not install a `CapabilityVerifier`, does not return a manifest hash, and does not validate requested capabilities.
- Runtime `handle_health()` reports local configured/handshaken state, whether live requests are supported, request/error counters, and base URL. It does not call OpenRouter.
- Runtime `handle_doctor()` checks local configuration, client initialization, credential-injection readiness, handshake state, and documented surface boundary. It does not call OpenRouter.
- Runtime `handle_self_check()` calls `GET /models` in direct API-key mode.
- Runtime `handle_self_check()` reports degraded in `credential_id` mode because host credential injection is not implemented.
- Runtime `handle_invoke()` accepts `operation_id` or `operation` plus optional `input`.
- Runtime `handle_invoke()` does not require or verify a capability token.
- Runtime `handle_simulate()` only checks known operation, `credential_id` blocking, and `stream=true` blocking for chat.
- Runtime `handle_shutdown()` clears client, config, session, and configured/handshaken flags.
- Runtime events and resource types are empty.
- Streaming is not supported.

## Runtime API Adapter

The runtime uses these request shapes under `{base_url}`:

| Operation | Capability | Required input | Runtime behavior |
|-----------|------------|----------------|------------------|
| `openrouter.chat.completions` | `openrouter.chat` | `messages` | `POST /chat/completions`; returns normalized first-choice content plus raw provider payload. |
| `openrouter.models.list` | `openrouter.models` | none | `GET /models`; returns provider model catalog JSON. |
| `openrouter.videos.generate` | `openrouter.video` | `prompt` | `POST /videos`; polls returned job URL until terminal completion, then downloads the generated video and returns base64. |

Chat behavior:

- `messages` must be a non-empty array.
- `model` defaults to `openai/gpt-4.1-mini`.
- `stream=true` is rejected.
- Runtime forwards only this subset of optional chat fields: `max_tokens`, `temperature`, `top_p`, `response_format`, `tools`, and `tool_choice`.
- Runtime does not forward provider-routing fields, transforms, web-search plugins, reasoning parameters, `models`, `modalities`, `metadata`, or streaming-only debug options.
- Runtime output is a normalized object with `id`, `model`, `content`, `finish_reason`, `usage`, and `raw`.

Video behavior:

- `model` defaults to `google/veo-3.1-fast`.
- `prompt` must be a non-empty string.
- `duration_seconds` is normalized to one of 4, 6, or 8 seconds.
- Optional `resolution`, `aspect_ratio`, `size`, `audio`, `callback_url`, and `seed` are forwarded to OpenRouter using the current runtime mapping.
- `provider_options.callback_url` and `provider_options.seed` override the top-level callback URL and seed when present.
- `input_images` accepts up to four objects using `url`, `data_url`, or `base64`.
- Image roles are mapped into `frame_images` for first/last frames and `input_references` for reference images or extras.
- Non-empty `input_videos` is rejected.
- `poll_interval_ms` defaults to 5000, is capped at 60000, and may be 0.
- `max_poll_attempts` defaults to 120 and is clamped to 1 through 120.
- `max_download_bytes` defaults to 128 MiB and is enforced before and after reading the generated video body.
- If OpenRouter returns `unsigned_urls`, the runtime downloads the first non-empty URL.
- If no unsigned URL is present, runtime falls back to `videos/{job_id}/content?index=0`.
- Provider auth headers are included only for same-origin polling or download URLs.
- Cross-origin polling or unsigned download URLs are fetched without provider auth headers.
- Download URLs must use HTTPS, except localhost URLs are allowed only when the configured base URL is also localhost.
- Output embeds the downloaded video as base64 with MIME type, byte length, and a stable file name.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- OpenRouter documents that chat completions support both streaming and non-streaming modes. Runtime intentionally rejects `stream=true`.
- OpenRouter documents a broad OpenAI-compatible request schema. Runtime forwards only a narrow chat subset.
- OpenRouter documents models, generation metadata, image/audio/video inputs, and many routing features. Runtime exposes only `/models`, `/chat/completions`, and `/videos`.
- The manifest declares no durable state and no event surface. Runtime matches that.
- The manifest declares network constraints for `openrouter.ai`, but runtime also permits localhost base URLs for tests.
- Runtime accepts `credential_id`, but all live operations are blocked in that mode because host-side credential injection is not implemented in this connector slice.
- Runtime `handle_handshake()` does not parse a full `HandshakeRequest`, does not install a `CapabilityVerifier`, and does not return a manifest hash.
- Runtime `handle_invoke()` does not require capability tokens or approval tokens.
- Runtime `handle_simulate()` does not validate full input schema, configured state, handshake state, provider quota, model availability, billing status, moderation policy, or asset size beyond its lightweight local checks.
- Runtime request/error counters increment only through `handle_invoke()`.
- Runtime video generation downloads the completed asset into memory and returns base64, so large generated videos are bounded only by `max_download_bytes` and process memory.
- Runtime polling can occupy a request for up to `poll_interval_ms * max_poll_attempts`; defaults are 5000 ms and 120 attempts.
- No dedicated tracked verification shell script exists for this connector.

A follow-up parity bead should add typed FCP handshake and capability verification, implement or remove `credential_id` mode, decide whether streaming chat should be supported through an event surface, widen chat parameter forwarding where safe, add provider-scope/billing/model availability diagnostics, expose generation metadata reads if needed, and avoid returning large video assets inline when the host has a better blob path.

## First-Slice Scope

The current OpenRouter README slice documents the existing runtime surface:

- API-key and current credential-ID configuration
- Non-streaming chat completions, model listing, and bounded video generation operations
- Local health, doctor, live self-check, introspection, simulate, invoke, and shutdown behavior
- Header handling for `Authorization`, `X-Title`, and `HTTP-Referer`
- Video polling, cross-origin credential stripping, generated-asset size caps, and base64 return behavior
- Runtime/manifest/provider-doc drift around streaming, broad request schemas, credential injection, typed FCP handshake, capability tokens, and large media handling
- Existing integration-test orientation through provider contracts, connector suite tests, manifest schema checks, and WireMock-backed OpenRouter flows

## Auth And Zone Boundary

- Authentication mechanisms: direct OpenRouter API key or currently-blocked host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability families:
  - `openrouter.chat`
  - `openrouter.models`
  - `openrouter.video`
- Manifest required capabilities are `network.dns`, `network.egress`, and `network.tls.sni`.
- Manifest forbids `system.exec` and `network.listen`.
- The connector does not intentionally persist API keys, credential IDs beyond configuration metadata, prompts, completions, model catalogs, video jobs, generated videos, request counters, or error counters outside process memory.
- OpenRouter payloads can contain prompts, messages, tool schemas, model outputs, usage data, provider metadata, image references, callback URLs, seeds, and generated videos. Treat live input and output as private or work-zone sensitive unless the host supplies a stricter zone policy.

## Explicit Non-Goals

- No streaming chat delivery.
- No Responses API surface.
- No embeddings endpoint.
- No provider-key management.
- No automatic model routing policy.
- No OpenRouter generation metadata operation.
- No video-to-video generation.
- No durable video storage.
- No external blob upload for generated videos.
- No downstream data-use enforcement.
- No cross-zone model invocation.

## Verification

README-only changes do not require Cargo or `rch` verification. Before committing this file, run:

```bash
git diff --check -- connectors/openrouter/README.md
LC_ALL=C rg -n '[^ -~]' connectors/openrouter/README.md
rg -n '\bmaster\b' connectors/openrouter/README.md
ubs connectors/openrouter/README.md
```

For code changes in this connector, use the workspace-required proof lane from the root `AGENTS.md`:

```bash
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
rch exec -- cargo fmt --check
```
