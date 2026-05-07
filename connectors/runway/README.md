# Runway Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://docs.dev.runwayml.com/api

## Purpose

This document fixes the operator-facing contract for `fcp.runway`. The connector exposes Runway's asynchronous image/video generation task surface: submit video and image generation jobs, inspect task status, cancel tasks, wait with a bounded poll loop, and perform a low-cost organization health probe.

The connector is intentionally a task-control bridge, not a media proxy. It returns task IDs, provider payloads, and redaction-safe output summaries; it never downloads or proxies generated image or video bytes.

## Current Runtime Snapshot

The current crate exposes these operations:

- `runway.video.image_to_video`
- `runway.video.text_to_video`
- `runway.video.video_to_video`
- `runway.image.text_to_image`
- `runway.job.status`
- `runway.job.cancel`
- `runway.job.wait_until_complete`
- `runway.health`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `api_key` / `runway_api_key` or `credential_id`.
- API-key mode sends `Authorization: Bearer ...`.
- Credential-id mode sends `x-fcp-credential-id` and requires host-side egress credential injection for live traffic.
- Default base URL is `https://api.dev.runwayml.com/v1`.
- Base URL overrides must use path `/v1`, must not include query or fragment components, and may only target `api.dev.runwayml.com` or loopback test hosts.
- Non-loopback base URLs must use HTTPS.
- Loopback HTTP/HTTPS base URLs are accepted only for deterministic tests.
- Every provider request sends `X-Runway-Version: 2024-11-06`.
- Configured `api_version` or `x_runway_version` must be exactly `2024-11-06`.
- Default `request_timeout_ms` is `60_000`, capped at `1_800_000`.
- Default `default_poll_interval_ms` is `5_000`, capped at `60_000`.
- Default `timeout_ms` for `runway.job.wait_until_complete` is `600_000`, capped at `1_800_000`.
- Default `max_retries` is 2 and is capped at 10.
- Default `retry_backoff_ms` is `500`, capped at `30_000`.
- Submit operations accept either direct top-level fields or `params` / `body`.
- `runway.video.image_to_video` requires `model`, `promptText`, and `promptImage`.
- `runway.video.text_to_video` and `runway.image.text_to_image` require `model` and `promptText`.
- `runway.video.video_to_video` requires `model` and `videoUri`.
- Generation request bodies are limited to `20 MiB`.
- `task_id` and `id` are accepted for task operations; task IDs are capped at 128 characters and allow only ASCII alphanumeric, dash, and underscore.
- `runway.job.cancel` treats provider 404 as `not_found_ignored`.
- `runway.job.wait_until_complete` polls until `SUCCEEDED`; it fails on `FAILED`, `CANCELED`, or `CANCELLED`, and times out without canceling the remote task.
- `runway.health` performs a live `GET /v1/organization` probe and reports whether credit balance and usage tier fields are present.

## First-Slice Scope

The first Runway README slice documents the existing runtime surface:

- image-to-video task submission through `POST /v1/image_to_video`
- text-to-video task submission through `POST /v1/text_to_video`
- video-to-video task submission through `POST /v1/video_to_video`
- text-to-image task submission through `POST /v1/text_to_image`
- task status through `GET /v1/tasks/{id}`
- task cancel through `DELETE /v1/tasks/{id}`
- bounded wait convenience around task polling
- organization readiness through `GET /v1/organization`
- direct bearer auth and host credential reference auth
- exact `X-Runway-Version: 2024-11-06` request semantics
- base URL, API version, task ID, timeout, retry, and payload-shape validation
- redaction-safe output summaries with URL hashes, URL hosts, content types, output counts, and byte totals
- provider error, rate-limit, timeout, and retry mapping
- lifecycle, introspection, simulation, doctor, and self-check surfaces

## Auth And Scope Boundary

- Authentication mechanisms: Runway API key / `RUNWAY_API_KEY` equivalent, or host-injected credential ID.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `runway.video.generate` gates image-to-video, text-to-video, and video-to-video task submission.
  - `runway.image.generate` gates text-to-image task submission.
  - `runway.jobs` gates task status, cancel, and bounded wait operations.
  - `runway.health.read` gates the organization readiness probe.
- The connector does not persist prompts, input URLs, provider output URLs, provider response bodies, generated media bytes, API keys, or credential IDs.
- Credential-id mode is a host-egress contract, not proof that live Runway will accept a request without an injection layer.

## Network And Runtime Invariants

- Production host: `api.dev.runwayml.com`.
- Production path root: `/v1`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and redirects for live operations.
- Runtime loopback overrides are test-only.
- Runtime default `request_timeout_ms`: `60_000`.
- Manifest submit operation network constraints set total timeout `60_000 ms`.
- Manifest task status, cancel, and health constraints set total timeout `30_000 ms`, `30_000 ms`, and `30_000 ms` respectively.
- Manifest bounded wait constraints set total timeout `300_000 ms`.
- Maximum response bytes are `1_048_576`.
- Maximum generation request body size is `20 MiB`.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support and no binary proxying.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `runway.video.generate` | Submit Runway video generation and transformation tasks. |
| `runway.image.generate` | Submit Runway text-to-image generation tasks. |
| `runway.jobs` | Poll task status, cancel tasks, and perform bounded wait convenience. |
| `runway.health.read` | Probe Runway organization metadata without submitting generation work. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `runway.video.image_to_video` | `POST /v1/image_to_video` | `runway.video.generate` | `Safe` | `Medium` | `None` | Enqueues paid/compute-bound video generation from prompt text and prompt image input. |
| `runway.video.text_to_video` | `POST /v1/text_to_video` | `runway.video.generate` | `Safe` | `Medium` | `None` | Enqueues paid/compute-bound video generation from prompt text. |
| `runway.video.video_to_video` | `POST /v1/video_to_video` | `runway.video.generate` | `Safe` | `Medium` | `None` | Enqueues paid/compute-bound video transformation from an input video URI. |
| `runway.image.text_to_image` | `POST /v1/text_to_image` | `runway.image.generate` | `Safe` | `Medium` | `None` | Enqueues paid/compute-bound image generation from prompt text. |
| `runway.job.status` | `GET /v1/tasks/{id}` | `runway.jobs` | `Safe` | `Low` | `Strict` | Read-only task state and redaction-safe output metadata. |
| `runway.job.cancel` | `DELETE /v1/tasks/{id}` | `runway.jobs` | `Safe` | `Low` | `None` | Mutates remote task state; 404 is treated as idempotently safe local cleanup. |
| `runway.job.wait_until_complete` | Repeated `GET /v1/tasks/{id}` | `runway.jobs` | `Safe` | `Medium` | `None` | Repeatedly polls remote state and returns output metadata only after terminal success. |
| `runway.health` | `GET /v1/organization` | `runway.health.read` | `Safe` | `Low` | `Strict` | Read-only account/readiness probe without generation work. |

## Explicit Non-Goals

The current implementation does not include:

- binary image/video download, upload, caching, transcoding, or proxying
- Runway asset/library management
- model discovery, model pricing, account billing management, or credit mutation
- audio, avatar, lip-sync, or non-modeled Runway endpoints beyond the current operation catalog
- task webhooks or callback receivers
- FCP subscription-based streaming
- automatic cancel on local wait timeout
- public-zone invocation
- durable storage of task IDs, prompts, input URLs, output URLs, output summaries, provider payloads, or provider errors
- connector-local credential vaulting

These are excluded on purpose:

- The useful first slice is task submission and lifecycle control for the current Runway API version.
- Local timeout should not silently cancel paid provider work; callers must invoke `runway.job.cancel` explicitly.
- Generated media remains behind Runway/provider URLs and is summarized with hashes and counts for audit.
- API-version pinning keeps the connector from drifting silently when Runway changes endpoint semantics.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, auth mode, base URL, API version, request counters, error counters, and binary-proxying status
- redacted API-key labels rather than raw API keys
- host credential reference status
- required `X-Runway-Version: 2024-11-06`
- supported operations, capability IDs, risk, safety, idempotency, and AI hints
- prompt, input URL, output URL, API-key, and provider-response redaction checks
- the fact that `self_check` is configuration-only unless `runway.health` or a gated e2e script performs a live probe

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- bearer auth and `x-runway-version` header behavior
- image-to-video, text-to-video, video-to-video, and text-to-image submit bodies
- status, wait, cancel, and health lifecycle behavior
- cancel 404 handling as `not_found_ignored`
- rate-limit, timeout, provider failure, and provider error mapping
- bad API version rejection
- local required-field validation for submit operations
- redacted task output summaries that hash signed URLs and expose only counts, hosts, content types, and byte totals
- lifecycle, introspection, simulation, self-check, doctor, and shutdown behavior
- manifest operation/network conformance and JSONL evidence records with live generation skipped unless explicitly gated

## Source Notes

- `connectors/runway/src/connector.rs` defines auth headers, API-version enforcement, base URL normalization, task operations, retry/error mapping, lifecycle handlers, redacted output summaries, and diagnostics.
- `connectors/runway/manifest.toml` defines the operation catalog, API-version hints, network constraints, sandbox boundary, zone policy, and operation AI hints.
- `connectors/runway/tests/integration.rs` covers deterministic task lifecycle behavior, validation, redaction, rate-limit, timeout, cancel 404 handling, and FCP lifecycle behavior.
- `connectors/runway/tests/conformance.rs` checks manifest operation coverage, network policy, API-version documentation, and introspection parity.
- `connectors/runway/tests/e2e_jsonl.rs` emits redaction-safe JSONL fixture records and a structured live-skip record.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/runway_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock task coverage
- JSONL evidence coverage with structured live-generation skip
- auth, base URL, API version, generation required fields, task status, task cancel, wait behavior, health, rate-limit, timeout, failure, and redaction tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Runway API key only for live provider verification.
- Use `credential_id` only behind a host egress injection layer.
- Use API version `2024-11-06`; the connector rejects any other configured version.
- Use WireMock loopback fixtures for deterministic proof.
- Use live generation only when the operator intentionally accepts provider cost and artifact handling.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a test Runway account for live runs and keep prompts, input URLs, and generated durations intentionally small.
- Keep binary media transport, asset management, webhooks, and non-catalog Runway endpoints out of this connector.

**Redaction rules**:

- Redact API keys, credential IDs where needed, prompts, prompt images, input video URIs, reference URIs, output URLs, signed URLs, task IDs where correlation is sensitive, provider payloads, provider failure details, and provider error bodies.
- Verification output should use model IDs when non-sensitive, task ID hashes, URL host hashes, output counts, content types, byte totals, credit counts when non-sensitive, status transitions, error classes, retry decisions, and cleanup state.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one of `api_key` / `runway_api_key` or `credential_id`.
- If `health` reports `degraded`, complete handshake before invoking operations.
- If base URL validation fails, use `https://api.dev.runwayml.com/v1` or a loopback `/v1` test origin.
- If API version validation fails, set `api_version` or `x_runway_version` to `2024-11-06`.
- If submit validation fails, provide the required fields for the selected operation and keep the body under `20 MiB`.
- If wait times out, check status separately or explicitly call `runway.job.cancel`; timeout does not cancel the remote task.
- If a provider task returns `FAILED`, treat the failure as terminal and do not auto-retry without operator intent.
- If task output includes URLs, use `output_summary` for logs and avoid logging provider payloads.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-runway-e2e cargo check -p fcp-runway --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-runway-e2e cargo test -p fcp-runway --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-runway-e2e cargo clippy -p fcp-runway --all-targets --no-deps -- -D warnings`
