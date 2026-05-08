# Anthropic Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://docs.anthropic.com/

## Purpose

This document fixes the operator-facing contract for `fcp.anthropic`. The connector exposes Anthropic Claude through the Messages API, a simple single-turn chat wrapper, SSE message streaming, local usage accounting, auth-method introspection, OAuth refresh status reporting, and model normalization.

The connector is built around Claude Messages. It does not expose Anthropic Files, Batches, Admin, or workspace-management APIs.

## Current Runtime Snapshot

The current crate exposes these operations:

- `anthropic.chat`
- `anthropic.message`
- `anthropic.message.stream`
- `anthropic.get_usage`
- `anthropic.auth.list_methods`
- `anthropic.auth.refresh_oauth`
- `anthropic.models.normalize`

Important runtime truths the contract preserves:

- Configuration accepts exactly one auth method: `api_key`, `auth_token`, `bearer_token`, `claude_code_oauth_token`, `oauth_token`, `setup_token`, or `credential_id`.
- `credential_id` must parse as a UUID and requires host-side egress credential injection for live traffic.
- API-key mode sends `x-api-key`.
- Bearer-token mode sends `Authorization: Bearer ...` for provider-mediated or gateway deployments.
- Claude Code OAuth and setup-token modes are Claude Code runtime credentials, not direct default Anthropic API credentials; configuration rejects them against `https://api.anthropic.com` and only allows them behind a localhost verification or host-managed provider boundary.
- Claude Code OAuth and setup-token modes automatically add `claude-code-20250219` and `oauth-2025-04-20` beta headers when they are configured behind that boundary.
- Default base URL is `https://api.anthropic.com`.
- Loopback HTTP base URLs are accepted only for deterministic tests.
- Default API version is `2023-06-01`, overridable by config `api_version` or `FCP_ANTHROPIC_API_VERSION`.
- Default model is `claude-sonnet-4-6`.
- Supported models are limited to the crate-local canonical list and aliases normalized by `Model::normalize`.
- Thinking content is never returned verbatim in `content_blocks`; it is represented as `{"type":"thinking","redacted":true}`.
- FCP subscribe is not implemented; streaming is exposed through `anthropic.message.stream`.

## First-Slice Scope

The first Anthropic README slice documents the existing runtime surface:

- single-turn `anthropic.chat` requests
- multi-message `anthropic.message` requests with system content, tools, cache control, service tier, thinking, output config, and per-request beta headers
- SSE `anthropic.message.stream` requests with text, thinking, tool-use, usage, and stop-reason aggregation
- local token and cost counters through `anthropic.get_usage`
- auth method listing and OAuth refreshability reporting
- model alias normalization and 1M-context guardrails
- bound capability-token verification before dispatch
- redaction-safe diagnostics and live skip/pass test behavior

## Auth And Scope Boundary

- Authentication mechanisms: Anthropic API key, bearer token, Claude Code OAuth token, setup token, or host-injected credential ID.
- Direct Anthropic API calls use `api_key` or `credential_id`; Claude Code OAuth and setup-token credentials must be routed through a host-managed Claude CLI/provider boundary or a localhost verification fixture.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `anthropic.chat` gates simple chat requests.
  - `anthropic.message` gates structured non-streaming Messages API requests.
  - `anthropic.message.stream` gates streaming Messages API requests.
  - `anthropic.get_usage` gates local usage/cost counters.
  - `anthropic.auth` gates auth method and OAuth refresh status operations.
  - `anthropic.models` gates model normalization.
- The connector does not persist prompts, completions, thinking content, streamed chunks, tool inputs, usage snapshots, provider payloads, or provider responses.
- Credential-id mode is a host-egress contract, not direct proof that live Anthropic will accept the request without an injection layer.

## Network And Runtime Invariants

- Production host: `api.anthropic.com`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and unsafe host forms for live operations.
- Base URL overrides must be origins without path, query, or fragment.
- Localhost HTTP overrides are test-only.
- Request connect timeout: `10_000 ms`.
- Total operation timeout: `120_000 ms`.
- Maximum response bytes are `10_485_760`.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120_000 ms` wall-clock timeout, read-only `/usr` and `/lib`, no exec, and no ptrace.
- Event capability metadata declares streaming support, no replay, and a minimum buffer of 10 events.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `anthropic.chat` | Send a simple one-turn chat request. |
| `anthropic.message` | Send structured multi-message Claude requests with optional tools and advanced options. |
| `anthropic.message.stream` | Stream a structured Claude response through SSE and return an assembled result. |
| `anthropic.get_usage` | Read local request, token, and cost counters. |
| `anthropic.auth` | Inspect configured auth mode and refreshability metadata. |
| `anthropic.models` | Normalize Claude model aliases to canonical API IDs. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `anthropic.chat` | `POST /v1/messages` | `anthropic.chat` | `Safe` | `Medium` | `None` | Model output depends on prompt, model, system content, and advanced generation options. |
| `anthropic.message` | `POST /v1/messages` | `anthropic.message` | `Safe` | `Medium` | `None` | Structured conversation output depends on message history, tools, thinking, cache, and service-tier input. |
| `anthropic.message.stream` | `POST /v1/messages` with SSE | `anthropic.message.stream` | `Safe` | `Medium` | `None` | Stream output depends on event ordering, content-block deltas, and provider stop metadata. |
| `anthropic.get_usage` | Local counters | `anthropic.get_usage` | `Safe` | `Low` | `Strict` | Read-only local accounting for this connector instance. |
| `anthropic.auth.list_methods` | Local metadata | `anthropic.auth` | `Safe` | `Low` | `Strict` | Read-only auth capability discovery. |
| `anthropic.auth.refresh_oauth` | Local metadata | `anthropic.auth` | `Safe` | `Low` | `Strict` | Reports whether the active auth mode is host-refreshable. |
| `anthropic.models.normalize` | Local normalization | `anthropic.models` | `Safe` | `Low` | `Strict` | Deterministic alias-to-model mapping. |

## Explicit Non-Goals

The current implementation does not include:

- Anthropic Files, Batches, Admin, workspace, or organization APIs
- persistent conversation storage
- FCP subscription-based streaming
- direct credential vaulting or OAuth refresh
- direct use of Claude Code subscription/setup tokens against `https://api.anthropic.com`
- public-zone invocation
- connector-local storage of prompts, thinking traces, streamed deltas, or tool inputs
- automatic 1M-context beta header injection for retired beta paths

These are excluded on purpose:

- The useful first slice is Claude Messages with clear FCP capability boundaries.
- Host credential flows own OAuth and credential refresh behavior.
- Thinking output can expose sensitive intermediate work, so the connector redacts it from structured content blocks.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, auth mode, base URL, API version, request counters, error counters, and cost totals
- redacted auth labels rather than raw API keys or bearer tokens
- base URL policy for `api.anthropic.com` and loopback-compatible origins
- credential-injection status for secretless mode
- operation schemas, safety, risk, idempotency, and AI hints
- simulate-time capability-token checks against bound resources

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- simple chat and multi-turn message invokes
- system prompts
- SSE chunk parsing, ping keepalives, and mid-stream error events
- tool use and streamed tool-input JSON deltas
- 401, 429, 529, 500, and context-length error mapping
- usage and cost accounting
- default-deny capability-token behavior
- lifecycle behavior for configure, handshake, health, doctor, self-check, introspection, simulate, and shutdown
- live verification skip/pass behavior gated by `ANTHROPIC_API_KEY`

## Source Notes

- `connectors/anthropic/src/client.rs` defines auth headers, API-version resolution, retry behavior, usage counters, health checks, Messages API calls, and SSE parsing.
- `connectors/anthropic/src/connector.rs` defines configuration validation, capability verification, operation dispatch, thinking redaction, introspection, simulation, and lifecycle behavior.
- `connectors/anthropic/src/types.rs` defines Claude model IDs, alias normalization, pricing, 1M-context support, Messages request/response types, content blocks, tools, cache control, service tier, thinking, and stream events.
- `connectors/anthropic/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, event capability metadata, and no-listener/no-storage/no-exec posture.
- `connectors/anthropic/tests/conformance_contract.rs` checks contract-level operation metadata.
- `connectors/anthropic/tests/provider_contract.rs` checks provider/auth behavior.
- `connectors/anthropic/tests/v3_lifecycle.rs` checks lifecycle expectations.
- `connectors/anthropic/tests/integration.rs` covers deterministic loopback and error behavior.
- `connectors/anthropic/tests/live_verification.rs` emits live skip/pass results when `ANTHROPIC_API_KEY` is absent or present.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/anthropic_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock integration coverage
- live provider smoke tests gated by `ANTHROPIC_API_KEY`
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use `ANTHROPIC_API_KEY` only for live provider verification.
- Use WireMock loopback fixtures for deterministic proof.
- Use `FCP_ANTHROPIC_API_VERSION` only when the operator intentionally needs a non-default version header.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a test Anthropic account for live runs and keep live prompts intentionally small.
- Treat Claude Code OAuth and setup-token auth as host-mediated credentials.

**Redaction rules**:

- Redact API keys, bearer tokens, setup tokens, credential IDs where needed, prompts, completions, thinking blocks, streamed text chunks, tool inputs, provider payloads, and provider error bodies.
- Verification output should use counts, byte lengths, operation IDs, status values, error classes, model IDs when non-sensitive, and cleanup state.

**Common remediation**:

- If `health` reports `not_configured`, configure with exactly one auth method and then run handshake.
- If `self_check` reports `credential_injection_required`, run behind the host egress injection layer or switch to a direct live-test key.
- If `claude_code_oauth_token`, `oauth_token`, or `setup_token` is rejected against the default API origin, use `api_key` or `credential_id` for direct Anthropic API calls, or route the Claude Code credential through a host-managed Claude CLI/provider boundary.
- If base URL validation fails, use `https://api.anthropic.com` or a localhost origin for tests.
- If a model is rejected, run `anthropic.models.normalize` or choose one of the supported canonical IDs.
- If `enable_1m_context` fails, switch to `claude-opus-4-7`, `claude-opus-4-6`, or `claude-sonnet-4-6`.
- If thinking and forced tool choice conflict, remove forced `tool_choice` or disable thinking for that request.
- If a streamed response looks incomplete, inspect SSE event ordering and `stop_reason` before changing aggregation logic.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-anthropic-e2e cargo check -p fcp-anthropic --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-anthropic-e2e cargo test -p fcp-anthropic --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-anthropic-e2e cargo test -p fcp-anthropic --test live_verification -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-anthropic-e2e cargo clippy -p fcp-anthropic --all-targets --no-deps -- -D warnings`
