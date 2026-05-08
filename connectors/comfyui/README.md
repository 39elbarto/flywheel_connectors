# ComfyUI Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://docs.comfy.org/development/comfyui-server/comms_routes

## Purpose

This document fixes the operator-facing contract for `fcp.comfyui`. The connector exposes a self-hosted ComfyUI REST workflow control surface: submit workflow JSON, poll history, build `/view` output URL metadata, cancel queued or running work, perform bounded connector-side waiting, and run a server readiness probe.

The connector is intentionally a workflow control plane, not an image proxy or workflow editor. It returns prompt IDs, status metadata, and ComfyUI `/view` URLs; it never downloads generated images or logs workflow JSON.

## Current Runtime Snapshot

The current crate exposes these operations:

- `comfyui.workflow.submit`
- `comfyui.workflow.status`
- `comfyui.workflow.result`
- `comfyui.workflow.cancel`
- `comfyui.workflow.wait_until_complete`
- `comfyui.health`

Important runtime truths the contract preserves:

- Default base URL is `http://localhost:8188`.
- Loopback ComfyUI endpoints are allowed by default.
- Non-loopback hosts must be listed in `allowed_hosts`.
- Tailnet endpoints require `allow_tailnet_ranges = true`.
- Private IP endpoints require `allow_private_ranges = true`.
- `tailnet_only = true` requires a `.ts.net` host or Tailscale IP and rejects loopback.
- Base URLs must use HTTP or HTTPS, must have an empty or `/` path, and must not include query or fragment components.
- Authentication accepts at most one of `api_key`, `authorization_header`, or `credential_id`.
- No auth is valid because default local ComfyUI deployments are often unauthenticated.
- `api_key` is converted to `Authorization: Bearer ...`.
- `authorization_header` is sent as provided after header-value validation.
- `credential_id` sends `x-fcp-credential-id` and requires host-side egress credential injection for protected deployments.
- Default `request_timeout_ms` is `300_000`.
- Default `wait_timeout_ms` is `600_000`.
- Default `poll_interval_ms` is `1_000`.
- Default `client_id` is `fcp-comfyui`.
- `workflow` is the preferred submit field; `prompt` is accepted as an alias.
- Workflow JSON must be an object and must serialize to 1 byte through 16 MiB.
- `prompt_id` and `client_id` reject CR, LF, NUL, path separators, URL separators, and unsafe query characters.
- `comfyui.workflow.status` is complete once `/history/{prompt_id}` contains the prompt ID.
- `comfyui.workflow.result` builds `/view` URLs from ComfyUI history output metadata and does not fetch image bytes.
- `comfyui.workflow.cancel` posts queue deletion and optionally calls `/interrupt` for active work.
- `comfyui.workflow.wait_until_complete` polls history until complete or timeout, then returns result metadata.
- `comfyui.health` probes `GET /system_stats`.

## First-Slice Scope

The first ComfyUI README slice documents the existing runtime surface:

- workflow submission through `POST /prompt`
- workflow status through `GET /history/{prompt_id}`
- result metadata through ComfyUI history output parsing and `/view` URL construction
- queued-work cancellation through `POST /queue`
- optional active-run interruption through `POST /interrupt`
- bounded wait convenience around history polling
- readiness through `GET /system_stats`
- unauthenticated, bearer-header, custom authorization-header, and host credential reference modes
- loopback, allowed host, private-range, and tailnet-range endpoint policy
- workflow JSON, prompt ID, client ID, timeout, poll interval, auth, and output component validation
- lifecycle, introspection, simulation, doctor, self-check, deterministic JSONL, and live-health skip surfaces

## Auth And Scope Boundary

- Authentication mechanisms: none, bearer API key, explicit authorization header, or host-injected credential ID.
- Home zone: `z:owner`.
- Allowed source zones: `z:owner`, `z:private`, `z:work`, and `z:project:default`.
- Allowed target zones: `z:owner`, `z:private`, `z:work`, and `z:project:default`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `comfyui.workflow.run` gates submit and cancel.
  - `comfyui.workflow.read` gates status, result, and bounded wait.
  - `comfyui.health.read` gates readiness probing.
- The connector does not persist workflow JSON, prompt text, seeds, input URLs, output URLs, generated image bytes, auth headers, API keys, or credential IDs.
- Credential-id mode is a host-egress contract, not proof that a protected ComfyUI endpoint will accept a request without an injection layer.

## Network And Runtime Invariants

- Default local host: `localhost`.
- Default local port: `8188`.
- Production/self-hosted path root: `/`.
- Loopback HTTP is valid for local ComfyUI because upstream defaults to a local server.
- Non-loopback HTTP/HTTPS endpoints require explicit operator allow-listing.
- Manifest network policy deliberately permits localhost, private ranges, tailnet ranges, and IP literals because this connector targets operator-managed self-hosted ComfyUI servers.
- Runtime configuration still enforces non-loopback `allowed_hosts` and explicit private/tailnet opt-in flags.
- Runtime default `request_timeout_ms`: `300_000`.
- Runtime default `wait_timeout_ms`: `600_000`.
- Runtime default `poll_interval_ms`: `1_000`.
- Manifest workflow operation network constraints set total timeout `600_000 ms`.
- Manifest health constraints set total timeout `10_000 ms`.
- Maximum response bytes are `10_485_760`.
- Maximum workflow JSON body size is `16 MiB`.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `600_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support and no binary proxying.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `comfyui.workflow.run` | Submit workflows and request queue cancellation or active-run interruption. |
| `comfyui.workflow.read` | Poll status, inspect result metadata, and perform bounded wait convenience. |
| `comfyui.health.read` | Probe ComfyUI server readiness through `/system_stats`. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `comfyui.workflow.submit` | `POST /prompt` | `comfyui.workflow.run` | `Safe` | `Medium` | `None` | Enqueues operator-authored generation work and may consume local GPU/CPU resources. |
| `comfyui.workflow.status` | `GET /history/{prompt_id}` | `comfyui.workflow.read` | `Safe` | `Low` | `Strict` | Read-only history lookup; completion is whether history contains the prompt ID. |
| `comfyui.workflow.result` | `GET /history/{prompt_id}` plus `/view` URL construction | `comfyui.workflow.read` | `Safe` | `Low` | `Strict` | Returns output metadata and local `/view` URLs without proxying generated image bytes. |
| `comfyui.workflow.cancel` | `POST /queue`, optional `POST /interrupt` | `comfyui.workflow.run` | `Safe` | `Medium` | `BestEffort` | Mutates queue/active execution state and can interrupt currently running work when explicitly requested. |
| `comfyui.workflow.wait_until_complete` | Repeated `GET /history/{prompt_id}` followed by result metadata | `comfyui.workflow.read` | `Safe` | `Low` | `Strict` | Bounded polling convenience for callers that want connector-side wait behavior. |
| `comfyui.health` | `GET /system_stats` | `comfyui.health.read` | `Safe` | `Low` | `Strict` | Bounded readiness check against the configured ComfyUI server. |

## Explicit Non-Goals

The current implementation does not include:

- ComfyUI WebSocket progress streaming
- workflow graph validation, node schema discovery, or custom-node compatibility checks
- workflow editing, prompt templating, seed management, or parameter expansion
- binary image download, upload, caching, transcoding, or proxying
- model installation, extension installation, memory freeing, user data management, or queue listing beyond the current cancel path
- public-zone invocation
- automatic cancel on local wait timeout
- durable storage of prompt IDs, workflow JSON, prompt text, seeds, input URLs, output URLs, generated images, or provider payloads
- connector-local credential vaulting

These are excluded on purpose:

- The useful first slice is a safe self-hosted workflow control connector around the stable core REST routes.
- ComfyUI owns workflow graph validation; this connector validates FCP and endpoint-safety boundaries.
- Local timeout should not silently interrupt local GPU work; callers must invoke `comfyui.workflow.cancel` explicitly.
- Generated media remains behind the operator's ComfyUI `/view` route and is treated as metadata from the connector's perspective.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, auth mode, base URL class, allowed host count, private/tailnet flags, request counters, and error counters
- redacted authorization labels rather than raw secrets
- host credential reference status
- supported operations, capability IDs, risk, safety, idempotency, resource URIs, and AI hints
- loopback/allowed-host policy diagnostics
- workflow and output URL redaction expectations
- bounded live health evidence when `COMFYUI_BASE_URL` is explicitly provided

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- loopback base URL defaults and non-loopback allow-listing
- tailnet-only, private range, and tailnet range policy
- auth-header, API-key, credential-id, and unauthenticated modes
- workflow JSON validation and submit body construction
- prompt ID and client ID validation
- status, result, cancel, wait, and health lifecycle behavior
- history parsing and `/view` URL construction without binary image proxying
- output component validation for filename, subfolder, and type
- doctor redaction checks
- deterministic JSONL evidence records and structured live-health skip records
- manifest operation/network conformance and introspection parity

## Source Notes

- `connectors/comfyui/src/connector.rs` defines configuration parsing, auth mode selection, endpoint policy, operation dispatch, bounded wait, capability resources, lifecycle handlers, diagnostics, and operation metadata.
- `connectors/comfyui/src/client.rs` defines REST calls for `/prompt`, `/history/{prompt_id}`, `/queue`, `/interrupt`, and `/system_stats`, base URL validation, auth headers, and provider error mapping.
- `connectors/comfyui/src/types.rs` defines workflow, prompt ID, wait, history, artifact, and `/view` URL validation.
- `connectors/comfyui/manifest.toml` defines the operation catalog, self-hosted network exception, sandbox boundary, zone policy, and operation AI hints.
- `connectors/comfyui/tests/integration.rs` covers deterministic workflow lifecycle behavior, validation, JSONL evidence, redaction, and FCP lifecycle behavior.
- `connectors/comfyui/tests/conformance.rs` covers manifest operation coverage, network policy, and introspection parity.
- `connectors/comfyui/tests/live_verification.rs` emits a structured live health result or skip record gated by `COMFYUI_BASE_URL`.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/comfyui_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock workflow coverage
- JSONL evidence coverage with structured live-health skip
- auth, endpoint policy, workflow submission, history parsing, result URL construction, cancel, wait, health, self-check, doctor, and redaction tests
- optional live health verification gated by environment variables
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use loopback ComfyUI for routine local verification.
- Add non-loopback hosts to `allowed_hosts` explicitly.
- Set `allow_private_ranges = true` for private IP endpoints and `allow_tailnet_ranges = true` for tailnet endpoints.
- Use `tailnet_only = true` only when the configured endpoint is a `.ts.net` host or Tailscale IP.
- Use `credential_id` only behind a host egress injection layer.
- Use WireMock loopback fixtures for deterministic proof.
- Use live workflow submission only when the operator intentionally accepts local GPU/CPU cost and artifact handling.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a small synthetic ComfyUI workflow fixture for live runs.
- Keep WebSocket progress, binary media transport, workflow editing, model installation, and custom-node management out of this connector until they have separate beads and capability contracts.

**Redaction rules**:

- Redact auth headers, API keys, credential IDs where needed, workflow JSON, prompt text, seeds, input URLs, prompt IDs where correlation is sensitive, output URLs, filenames when sensitive, provider payloads, and provider error bodies.
- Verification output should use endpoint class, operation names, prompt ID hashes, workflow fixture IDs, status transitions, artifact counts, URL host classes, HTTP status, error classes, cleanup state, and skip reasons.

**Common remediation**:

- If `health` reports `unconfigured`, call configure first; unauthenticated mode is valid for default local ComfyUI.
- If `health` reports `degraded`, complete handshake before invoking operations.
- If base URL validation fails, use `http://localhost:8188`, a loopback test origin, or a non-loopback host listed in `allowed_hosts` with the needed private/tailnet flags.
- If `tailnet_only` rejects the endpoint, use a `.ts.net` host or Tailscale IP and do not use loopback.
- If submit validation fails, pass workflow JSON as an object under `workflow` or `prompt` and keep it under `16 MiB`.
- If status or result remains incomplete, check whether ComfyUI history retention contains the prompt ID.
- If wait times out, check status separately or explicitly invoke `comfyui.workflow.cancel`; timeout does not interrupt the remote workflow.
- If output URL logging is needed, log host class and hashes rather than full `/view` URLs.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-comfyui-e2e cargo check -p fcp-comfyui --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-comfyui-e2e cargo test -p fcp-comfyui --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-comfyui-e2e cargo clippy -p fcp-comfyui --all-targets --no-deps -- -D warnings`
