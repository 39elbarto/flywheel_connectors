# Fal Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://docs.fal.ai/model-endpoints/queue/

## Purpose

This document fixes the operator-facing contract for `fcp.fal`. The connector exposes Fal's queue-based media-generation surface: enqueue a model route, poll queue status, fetch completed result JSON, cancel queued/running jobs, and optionally perform bounded connector-side waiting.

The connector is intentionally a queue control plane, not a media proxy. It returns provider JSON, request IDs, provider operation URLs, and redaction-safe media summaries; it never downloads or proxies generated image or video bytes.

## Current Runtime Snapshot

The current crate exposes these operations:

- `fal.media.submit`
- `fal.job.status`
- `fal.job.result`
- `fal.job.cancel`
- `fal.job.wait_until_complete`
- `fal.health`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `api_key` / `fal_key` or `credential_id`.
- API-key mode sends `Authorization: Key ...`.
- Credential-id mode sends `x-fcp-credential-id` and requires host-side egress credential injection for live traffic.
- Default queue base URL is `https://queue.fal.run`.
- `queue_base_url` and `base_url` are aliases for the same queue origin configuration.
- Queue base URL overrides must be absolute URLs without query or fragment components.
- Non-loopback queue base URLs must use HTTPS and host `queue.fal.run`.
- Loopback HTTP/HTTPS queue base URLs are accepted only for deterministic tests.
- Default `request_timeout_ms` is `60_000`, capped at `600_000`.
- Default `default_poll_interval_ms` is `500`, capped at `30_000`.
- Default `timeout_ms` for `fal.job.wait_until_complete` is `300_000`, capped at `600_000`.
- Default `max_retries` is 2 and is capped at 10.
- Default `retry_backoff_ms` is `250`, capped at `30_000`.
- `fal.media.submit` requires `model_route`; the payload is `params` or `input`, and must be a JSON object.
- `webhook_url` is optional, must be HTTPS, and is sent as `fal_webhook`.
- `no_retry = true` sends `x-fal-no-retry: 1`.
- `model_route` is normalized by trimming leading/trailing slashes and rejects traversal, repeated slashes, query/fragment markers, encoded slashes, backslashes, empty segments, and invalid segment characters.
- Job operations accept provider URLs (`status_url`, `response_url`, `cancel_url`) only when the URL shares the configured queue origin and targets a `/requests/...` endpoint with the expected suffix.
- Job operations can also build URLs from `model_route` plus `request_id`.
- `request_id` accepts only non-empty ASCII alphanumeric, dash, underscore, and dot characters, capped at 160 characters.
- `fal.job.wait_until_complete` polls status until `COMPLETED`, then fetches result JSON; it fails on `FAILED` or provider error payloads and times out without canceling the remote job.
- `fal.health` is local readiness metadata and does not perform a paid live generation request.

## First-Slice Scope

The first Fal README slice documents the existing runtime surface:

- queue submission through `POST https://queue.fal.run/{model_route}`
- queue status through `GET .../requests/{request_id}/status`
- queue result through `GET .../requests/{request_id}/response` or a provider response URL
- queue cancellation through `PUT .../requests/{request_id}/cancel`
- bounded wait convenience around status then result
- local health metadata that does not submit work
- direct `Key` auth and host credential reference auth
- queue-origin validation for provider operation URLs
- model route, request ID, webhook, timeout, retry, and payload-shape validation
- redaction-safe output summaries with URL hashes, URL hosts, content types, counts, and byte totals
- provider error, rate-limit, timeout, and retry mapping
- lifecycle, introspection, simulation, doctor, and self-check surfaces

## Auth And Scope Boundary

- Authentication mechanisms: Fal API key / `FAL_KEY` equivalent, or host-injected credential ID.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `fal.media.generate` gates queue submission.
  - `fal.jobs` gates status, result, cancel, and bounded wait operations.
  - `fal.health.read` gates local readiness metadata.
- The connector does not persist prompts, raw params, media URLs, provider result bodies, generated media bytes, API keys, or credential IDs.
- Credential-id mode is a host-egress contract, not proof that live Fal will accept a request without an injection layer.

## Network And Runtime Invariants

- Production queue host: `queue.fal.run`.
- Production queue scheme: HTTPS.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and redirects for live operations.
- Runtime loopback overrides are test-only.
- Runtime default `request_timeout_ms`: `60_000`.
- Manifest submit network constraints set total timeout `60_000 ms`.
- Manifest status, cancel, and health network constraints set total timeout `30_000 ms`, `30_000 ms`, and `5_000 ms` respectively.
- Manifest result and wait network constraints allow `33_554_432` response bytes for provider result JSON.
- Maximum generation request body size is `20 MiB`.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support and no binary proxying.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `fal.media.generate` | Enqueue a Fal model-route media generation request. |
| `fal.jobs` | Poll status, fetch result JSON, cancel jobs, and perform bounded wait/result convenience. |
| `fal.health.read` | Return connector readiness metadata without live generation. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `fal.media.submit` | `POST /{model_route}` | `fal.media.generate` | `Safe` | `Medium` | `None` | Enqueues paid/compute-bound media generation whose result depends on model route and opaque model-specific params. |
| `fal.job.status` | `GET /{model_route}/requests/{request_id}/status` or provider `status_url` | `fal.jobs` | `Safe` | `Low` | `Strict` | Read-only queue state, optionally with logs that may expose prompt fragments. |
| `fal.job.result` | `GET /{model_route}/requests/{request_id}/response` or provider `response_url` | `fal.jobs` | `Safe` | `Low` | `Strict` | Fetches completed provider JSON and summarizes media outputs without downloading binary bytes. |
| `fal.job.cancel` | `PUT /{model_route}/requests/{request_id}/cancel` or provider `cancel_url` | `fal.jobs` | `Safe` | `Low` | `None` | Mutates remote queue state and may race with already-started or already-completed work. |
| `fal.job.wait_until_complete` | Status polling followed by result fetch | `fal.jobs` | `Safe` | `Medium` | `None` | Repeatedly polls remote state and returns result JSON only after completion. |
| `fal.health` | Local readiness metadata | `fal.health.read` | `Safe` | `Low` | `Strict` | Confirms connector configuration without performing live generation. |

## Explicit Non-Goals

The current implementation does not include:

- synchronous `https://fal.run` execution
- WebSocket queue status streaming
- FCP subscription-based streaming
- endpoint schema discovery or per-model parameter validation beyond JSON-object payload shape
- binary image/video download, upload, caching, transcoding, or proxying
- provider file storage management
- public-zone invocation
- automatic cancel on local wait timeout
- durable storage of request IDs, prompts, params, logs, media URLs, output summaries, or provider payloads
- connector-local credential vaulting

These are excluded on purpose:

- The useful first slice is a safe queue-control connector that lets operators manage long-running media jobs without keeping open connections.
- Fal owns per-model input schema validation; this connector validates FCP and queue-safety boundaries.
- Local timeout should not silently cancel paid provider work; callers must invoke `fal.job.cancel` explicitly.
- Generated media remains behind Fal/provider URLs and is summarized with hashes and counts for audit.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, auth mode, queue base URL, request counters, error counters, and binary-proxying status
- redacted API-key labels rather than raw API keys
- host credential reference status
- supported operations, capability IDs, risk, safety, idempotency, and AI hints
- local readiness without a paid live generation probe
- redaction checks for prompts, raw request bodies, API keys, and signed output URLs

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- `Key` auth header behavior and credential redaction
- queue submit, status, result, cancel, and wait flows
- provider operation URL origin and suffix validation
- route traversal and encoded slash rejection
- HTTPS-only webhook validation
- rate-limit, timeout, not-found, and provider error mapping
- redacted media summaries that hash URLs and expose only counts, hosts, content types, and byte totals
- lifecycle, introspection, simulation, self-check, doctor, and shutdown behavior
- JSONL evidence records with live generation skipped unless explicitly gated

## Source Notes

- `connectors/fal/src/connector.rs` defines auth headers, queue base URL normalization, route/request validation, queue operations, retry/error mapping, lifecycle handlers, redacted media summaries, and diagnostics.
- `connectors/fal/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and operation AI hints.
- `connectors/fal/tests/integration.rs` covers deterministic queue lifecycle behavior, validation, redaction, rate-limit, timeout, and FCP lifecycle behavior.
- `connectors/fal/tests/conformance.rs` covers basic lifecycle conformance.
- `connectors/fal/tests/e2e_jsonl.rs` emits redaction-safe JSONL fixture records and a structured live-skip record.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/fal_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock queue coverage
- JSONL evidence coverage with structured live-generation skip
- auth, base URL, model-route, operation URL, webhook, timeout, retry, queue status, result, cancel, and redaction tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Fal API key only for live provider verification.
- Use `credential_id` only behind a host egress injection layer.
- Choose a model route explicitly, such as `fal-ai/flux/schnell`; model-specific params are validated by Fal.
- Use WireMock loopback fixtures for deterministic proof.
- Use live generation only when the operator intentionally accepts provider cost and artifact handling.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a test Fal account for live runs and keep prompts and payloads intentionally small.
- Keep synchronous execution, WebSocket streaming, binary media transport, file storage, and per-model schema expectations out of this connector.

**Redaction rules**:

- Redact API keys, credential IDs where needed, prompts, raw params, request bodies, logs, request IDs where correlation is sensitive, status URLs, response URLs, cancel URLs, signed media URLs, provider payloads, and provider error bodies.
- Verification output should use model route when non-sensitive, request ID hashes, URL host hashes, output counts, content types, byte totals, status transitions, error classes, retry decisions, and cleanup state.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one of `api_key` / `fal_key` or `credential_id`.
- If `health` reports `degraded`, complete handshake before invoking operations.
- If queue base URL validation fails, use `https://queue.fal.run` or a loopback test origin.
- If `model_route` validation fails, pass a route like `fal-ai/flux/schnell` without query strings, fragments, empty segments, traversal, or encoded slashes.
- If status/result/cancel URL validation fails, use provider URLs returned by this connector or pass `model_route` plus `request_id`.
- If wait times out, check status separately or explicitly call `fal.job.cancel`; timeout does not cancel the remote job.
- If result output includes URLs, use `output_summary` for logs and avoid logging provider payloads.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fal-e2e cargo check -p fcp-fal --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fal-e2e cargo test -p fcp-fal --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fal-e2e cargo clippy -p fcp-fal --all-targets --no-deps -- -D warnings`
