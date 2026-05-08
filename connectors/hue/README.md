# Philips Hue Connector V1 Contract

> **Status**: local bridge CLIP v2 slice documented with capability-token enforcement and local-network boundary
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://developers.meethue.com/
> **Getting-started upstream**: https://developers.meethue.com/develop/get-started-2/

## Purpose

This document fixes the operator-facing contract for `fcp.hue`. The connector exposes a local Philips Hue bridge control slice: bridge health, light inventory, scene inventory, light on/off and brightness changes, and scene recall through CLIP v2-style bridge endpoints.

The connector is intentionally a local bridge adapter. It is not a Hue cloud client, Hue account/OAuth client, bridge discovery tool, app-key provisioning flow, Hue Entertainment UDP client, eventstream subscriber, automation/rules manager, sensor manager, or multi-bridge orchestration layer.

## Current Runtime Snapshot

The current crate exposes these operations:

- `hue.health`
- `hue.list_lights`
- `hue.list_scenes`
- `hue.set_light_state`
- `hue.recall_scene`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-hue`.
- Runtime and manifest connector ID are `fcp.hue`.
- Configuration requires `bridge_url` and `app_key`.
- `request_timeout_ms` defaults to `10000` and must be greater than zero.
- `allow_insecure_ssl` defaults to `false`; when true, reqwest accepts invalid bridge certificates.
- Production bridge URLs must use HTTPS.
- Plain HTTP is accepted only for localhost or loopback test endpoints.
- Bridge URLs are normalized by trimming whitespace and trailing slashes.
- `app_key` is sent as the `hue-application-key` header.
- Client debug output redacts the app key.
- `self_check()` performs a live bridge probe against `/clip/v2/resource/bridge`.
- `health()` is local readiness state and does not prove bridge reachability.
- Runtime computes `manifest_hash` from `manifest.toml`.
- Runtime `invoke` verifies a bound capability token before provider dispatch.
- Runtime `simulate` uses the same capability verifier and reports missing capabilities when appropriate.
- Subscriptions and event streaming are not supported.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- The manifest operation keys are unprefixed suffixes such as `health`; runtime operation IDs are fully qualified IDs such as `hue.health`.
- The manifest defers exact bridge host constraints to runtime configuration because the bridge is local-network selected.
- The manifest requires `network.outbound`, while many newer connector contracts use `network.egress`; this README documents the current manifest as-is.
- `health()` can be ready after configuration even if the bridge is unreachable; `self_check()` is the reachability probe.
- The connector accepts `allow_insecure_ssl` for local bridge certificate handling; operators should keep that explicit in evidence.
- There is no tracked connector verification shell script yet.

A follow-up parity bead should add a tracked verification bundle, decide whether host constraints should be materialized after configuration, and decide whether discovery/app-key provisioning belongs in this crate or a separate setup surface.

## First-Slice Scope

The current Hue README slice documents the existing runtime surface:

- local bridge URL and app-key configuration
- HTTPS production policy and loopback HTTP test allowance
- bridge health probe, light listing, scene listing, light state update, and scene recall
- bound capability-token enforcement for read and write operations
- doctor, health, self-check, introspect, simulate, shutdown, and loopback tests
- drift around manifest operation suffixes, local host constraints, and missing scripted verification

## Auth And Scope Boundary

- Authentication mechanism: Hue bridge application key in the `hue-application-key` header.
- Runtime does not implement link-button pairing, app-key creation, Hue cloud OAuth, remote bridge access, account management, or token refresh.
- Home zone: `z:owner`.
- Allowed source zones: `z:owner`, `z:private`, `z:home`, and `z:infra`.
- Allowed target zones: `z:owner`, `z:home`, and `z:infra`.
- Tailscale tag hint: `tag:fcp-home`.
- Capability families:
  - `hue.read` gates health, light inventory, and scene inventory.
  - `hue.write` gates light-state changes and scene recall.
- Forbidden capabilities: `system.exec`, `system.privileged`, and `network.listen`.
- Hue bridge IPs/hostnames, app keys, light IDs, scene IDs, room names, bridge metadata, schedules inferred from lights, and provider error bodies are sensitive home-environment data. Redact them before sharing evidence.

## Network And Runtime Invariants

- Production bridge access is expected to use HTTPS to the configured local bridge host.
- Loopback tests may use HTTP on `localhost`, `127.0.0.1`, or IPv6 loopback.
- Runtime endpoint shapes:
  - `GET /clip/v2/resource/bridge`
  - `GET /clip/v2/resource/light`
  - `GET /clip/v2/resource/scene`
  - `PUT /clip/v2/resource/light/{light_id}`
  - `PUT /clip/v2/resource/scene/{scene_id}`
- `hue.set_light_state` sends `{"on":{"on":...}}` and optional `{"dimming":{"brightness":...}}`.
- `hue.recall_scene` sends `{"recall":{"action":"active"}}`.
- `light_id` and `scene_id` must be non-blank before dispatch.
- Runtime strips path separators and URL metacharacters from light and scene path segments before constructing URLs.
- Brightness must be finite and between `0` and `100`.
- Provider non-success responses are truncated at 500 bytes before error mapping.
- HTTP timeouts map to `UpstreamTimeout`; 429 maps to FCP rate limiting; 5xx and transport failures are retryable where classified.
- Sandbox profile is `strict`, with `64 MB` memory, `25%` CPU, `30000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `hue.read` | Bridge health, light inventory, and scene inventory. |
| `hue.write` | Light on/off and brightness changes plus scene recall. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `hue.health` | local readiness plus bridge URL metadata | `hue.read` | `Safe` | `Low` | `Strict` | None. |
| `hue.list_lights` | `GET /clip/v2/resource/light` | `hue.read` | `Safe` | `Low` | `Strict` | None. |
| `hue.list_scenes` | `GET /clip/v2/resource/scene` | `hue.read` | `Safe` | `Low` | `Strict` | None. |
| `hue.set_light_state` | `PUT /clip/v2/resource/light/{light_id}` | `hue.write` | `Risky` | `Medium` | `BestEffort` | `light_id`, `on`; optional `brightness`. |
| `hue.recall_scene` | `PUT /clip/v2/resource/scene/{scene_id}` | `hue.write` | `Risky` | `Medium` | `BestEffort` | `scene_id`. |

## Explicit Non-Goals

The current implementation does not include:

- bridge discovery by mDNS, broker discovery, DHCP/router lookup, or Hue app integration
- link-button pairing or app-key creation
- Hue cloud OAuth, remote API access, multi-home account support, or cloud sync
- Hue Entertainment API, eventstream subscriptions, streaming events, replay buffers, or acknowledgements
- grouped-light operations, room/zone operations, sensors, buttons, motion areas, schedules, rules, automations, resource creation/deletion, firmware management, or bridge migration
- persistent bridge inventory, credential storage, or local artifact capture

These are excluded on purpose:

- Light and scene writes have visible physical side effects in a home environment.
- Bridge app keys are local credentials and should stay in operator-controlled configuration.
- HTTP bridge access is deprecated for production use upstream and is kept here only for loopback tests.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configured state, bridge URL, app-key presence, request timeout, transport mode, `allow_insecure_ssl`, and manifest hash
- live bridge health details from `/clip/v2/resource/bridge` through `self_check()`
- operation catalog, schemas, capabilities, risk levels, safety tiers, idempotency classes, and hints
- non-streaming event capabilities
- bound capability-token acceptance and denial in both `invoke` and `simulate`
- specific degraded state when the connector is not configured

The deterministic integration evidence is anchored on loopback tests covering:

- rejection of non-loopback HTTP bridge URLs
- local health metadata and app-key state
- bridge self-check metadata
- out-of-range brightness rejection before outbound dispatch
- scene recall endpoint and payload
- invoke health metadata
- client header behavior, path-segment sanitization, app-key debug redaction, and error mapping

## Source Notes

- `connectors/hue/src/types.rs` defines configuration validation and operation input validation.
- `connectors/hue/src/client.rs` defines CLIP v2 request construction, app-key headers, path sanitization, response decoding, and debug redaction.
- `connectors/hue/src/connector.rs` defines lifecycle handlers, capability-token enforcement, operation metadata, diagnostics, simulate behavior, and non-streaming posture.
- `connectors/hue/src/error.rs` defines provider/FCP error mapping and retry classification.
- `connectors/hue/manifest.toml` defines the operation catalog, capability families, zone policy, sandbox boundary, and local-network notes.
- `connectors/hue/tests/integration.rs` covers loopback bridge behavior and capability-token paths.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/hue/README.md
ubs connectors/hue/README.md
LC_ALL=C rg -n '[^ -~]' connectors/hue/README.md
rg -n '\bmaster\b' connectors/hue/README.md
```

For source or behavior changes, use an `rch`-offloaded connector proof lane:

```bash
fwc manifest fix connectors/hue/manifest.toml --check --json
rch exec -- cargo fmt --manifest-path connectors/hue/Cargo.toml --check
rch exec -- cargo check -p fcp-hue --all-targets
rch exec -- cargo test -p fcp-hue --test integration -- --nocapture
rch exec -- cargo test -p fcp-hue -- --nocapture
rch exec -- cargo clippy -p fcp-hue --all-targets -- -D warnings
```

There is no tracked `scripts/e2e/hue_connector_verification.sh` in this checkout. Add one before claiming a full scripted closeout bundle.

## Operator Guidance

Prerequisites:

- Know the target Hue bridge URL.
- Create or provide a Hue app key out-of-band.
- Use HTTPS for production bridge access.
- Use loopback HTTP only for deterministic tests.

Dedicated environment:

- Prefer a loopback mock bridge or a disposable/test room before sending write operations. Do not recall scenes or change brightness in occupied spaces unless visible side effects are acceptable.

Redaction rules:

- Redact app keys, bridge URLs, bridge IPs, light IDs, scene IDs, room names, bridge metadata, raw provider responses, request logs, and local network topology before sharing evidence.

Common remediation:

- If `health` reports `degraded`, configure the connector with `bridge_url` and `app_key`.
- If `self_check` fails, verify the bridge is reachable from the host and that the app key is valid.
- If configuration rejects `bridge_url`, use HTTPS for non-loopback bridge hosts.
- If local HTTPS fails due to bridge certificates, explicitly set `allow_insecure_ssl` only for the trusted local bridge environment.
- If `set_light_state` rejects brightness, use a finite number between `0` and `100`.
- If `simulate` reports missing capabilities, request `hue.read` or `hue.write` according to the operation.

Rerun commands:

- `git diff --check -- connectors/hue/README.md`
- `ubs connectors/hue/README.md`
- `rch exec -- cargo test -p fcp-hue --test integration -- --nocapture`
