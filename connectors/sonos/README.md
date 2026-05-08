# Sonos Connector V1 Contract

> **Status**: local device SOAP slice documented with capability-token enforcement and cloud-Control-API boundary
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Sonos Control API upstream**: https://docs.sonos.com/docs/control
> **Sonos SOAP upstream**: https://docs.sonos.com/docs/soap-requests-and-responses
> **UPnP AVTransport upstream**: https://upnp.org/specs/av/UPnP-av-AVTransport-v1-Service.pdf
> **UPnP RenderingControl upstream**: https://upnp.org/specs/av/UPnP-av-RenderingControl-v2-Service.pdf

## Purpose

This document fixes the operator-facing contract for `fcp.sonos`. The connector exposes a local Sonos speaker/device SOAP slice: device health, transport status, play, pause, next, previous, and absolute volume control through local device endpoints.

The connector is intentionally a local device adapter. It is not the modern Sonos cloud Control API, OAuth flow, account client, household/group/player discovery client, music service integration, queue editor, event subscriber, or SMAPI service provider.

## Current Runtime Snapshot

The current crate exposes these operations:

- `sonos.health`
- `sonos.get_status`
- `sonos.play`
- `sonos.pause`
- `sonos.next`
- `sonos.previous`
- `sonos.set_volume`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-sonos`.
- Runtime and manifest connector ID are `fcp.sonos`.
- Configuration requires `device_url`.
- `request_timeout_ms` defaults to `10000` and must be greater than zero.
- `allow_insecure_ssl` defaults to `false`; when true, reqwest accepts invalid device certificates.
- `device_url` may use HTTP or HTTPS.
- Embedded username/password credentials in `device_url` are rejected.
- Device URLs are normalized by trimming whitespace and trailing slashes.
- `self_check()` performs a live probe against `/xml/device_description.xml`.
- `health()` is local readiness state and does not prove the speaker is reachable.
- Runtime computes `manifest_hash` from `manifest.toml`.
- Runtime `invoke` verifies a bound capability token before provider dispatch.
- Runtime `simulate` uses the same capability verifier and reports missing capabilities when appropriate.
- Runtime `set_volume` accepts an absolute integer volume from `0` to `100`; relative volume changes are not implemented.
- Subscriptions and event streaming are not supported.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- The manifest operation keys are unprefixed suffixes such as `play`; runtime operation IDs are fully qualified IDs such as `sonos.play`.
- The manifest defers exact device host constraints to runtime configuration because the speaker is local-network selected.
- The manifest requires `network.outbound`, while many newer connector contracts use `network.egress`; this README documents the current manifest as-is.
- Runtime uses direct local device SOAP/UPnP-style paths, not the official Sonos cloud Control API path shape.
- `health()` can be ready after configuration even if the device is unreachable; `self_check()` is the reachability probe.
- There is no tracked connector verification shell script yet.

A follow-up parity bead should add a tracked verification bundle, decide whether a separate cloud Control API connector is needed, and decide whether discovery/group topology belongs in this crate or a separate setup surface.

## First-Slice Scope

The current Sonos README slice documents the existing runtime surface:

- local device URL configuration and validation
- device-description health probe
- AVTransport SOAP controls for status, play, pause, next, and previous
- RenderingControl SOAP volume read/write behavior
- bound capability-token enforcement for read and write operations
- doctor, health, self-check, introspect, simulate, shutdown, and loopback tests
- drift around local host constraints, cloud API non-coverage, and missing scripted verification

## Auth And Scope Boundary

- Authentication mechanism: none implemented for the local device SOAP surface.
- Runtime does not implement Sonos OAuth, cloud bearer tokens, account linking, household discovery, group discovery, player discovery, SMAPI auth headers, music-service credentials, or connector-local credential storage.
- Home zone: `z:owner`.
- Allowed source zones: `z:owner`, `z:private`, `z:home`, and `z:infra`.
- Allowed target zones: `z:owner`, `z:home`, and `z:infra`.
- Tailscale tag hint: `tag:fcp-home`.
- Capability families:
  - `sonos.read` gates health and status reads.
  - `sonos.write` gates playback and volume controls.
- Forbidden capabilities: `system.exec`, `system.privileged`, and `network.listen`.
- Device URLs, speaker hostnames/IPs, friendly names, model names, transport state, queue state inferred from transport controls, volume levels, and upstream error bodies are sensitive home-environment data. Redact them before sharing evidence.

## Network And Runtime Invariants

- Runtime target is the configured local Sonos device URL.
- Runtime endpoint shapes:
  - `GET /xml/device_description.xml`
  - `POST /MediaRenderer/AVTransport/Control`
  - `POST /MediaRenderer/RenderingControl/Control`
- AVTransport service URN: `urn:schemas-upnp-org:service:AVTransport:1`.
- RenderingControl service URN: `urn:schemas-upnp-org:service:RenderingControl:1`.
- SOAP requests use `CONTENT-TYPE: text/xml; charset="utf-8"` and `SOAPACTION` headers.
- `sonos.get_status` calls `GetTransportInfo` and `GetVolume`.
- `sonos.play` calls `Play` with speed `1`.
- `sonos.pause` calls `Pause`.
- `sonos.next` calls `Next`.
- `sonos.previous` calls `Previous`.
- `sonos.set_volume` calls `SetVolume` with channel `Master`.
- Volume must be an integer from `0` to `100` and is rejected before outbound SOAP otherwise.
- Upstream error bodies containing credential markers are redacted; other upstream error bodies are truncated at 512 characters.
- HTTP timeouts map to `UpstreamTimeout`; 408/429/5xx-style API errors are retryable where classified.
- Sandbox profile is `strict`, with `64 MB` memory, `25%` CPU, `30000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `sonos.read` | Device health and transport/volume status. |
| `sonos.write` | Playback controls and absolute volume changes. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `sonos.health` | local readiness plus device URL metadata | `sonos.read` | `Safe` | `Low` | `Strict` | None. |
| `sonos.get_status` | SOAP `GetTransportInfo` plus `GetVolume` | `sonos.read` | `Safe` | `Low` | `Strict` | None. |
| `sonos.play` | SOAP `Play` | `sonos.write` | `Risky` | `Medium` | `BestEffort` | None. |
| `sonos.pause` | SOAP `Pause` | `sonos.write` | `Risky` | `Medium` | `BestEffort` | None. |
| `sonos.next` | SOAP `Next` | `sonos.write` | `Risky` | `Medium` | `BestEffort` | None. |
| `sonos.previous` | SOAP `Previous` | `sonos.write` | `Risky` | `Medium` | `BestEffort` | None. |
| `sonos.set_volume` | SOAP `SetVolume` | `sonos.write` | `Risky` | `Medium` | `BestEffort` | `volume` integer, `0` through `100`. |

## Explicit Non-Goals

The current implementation does not include:

- Sonos cloud Control API, OAuth authorization, bearer-token handling, households, groups, players, sessions, cloud JSON command paths, or cloud events
- SSDP/mDNS discovery, topology discovery, group coordinator selection, or room selection
- queue browsing/editing, source selection, favorite selection, playlist management, line-in controls, mute, group volume, relative volume, seek, shuffle/repeat, or play-mode controls
- SMAPI service-provider implementation, music-service account authentication, metadata browsing, or media URI serving
- event subscriptions, webhook delivery, replay buffers, acknowledgements, or durable state
- persistent storage of speaker inventory, room mappings, transport state, or credentials

These are excluded on purpose:

- Playback and volume controls create audible side effects in a shared physical environment.
- Modern Sonos cloud controls require a different account/OAuth/household/group model than this local SOAP adapter.
- Local device URLs are operator-selected and should not be discovered or broadened implicitly.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configured state, device URL, request timeout, manifest hash, and local readiness
- live device metadata from `/xml/device_description.xml` through `self_check()`
- operation catalog, schemas, capabilities, risk levels, safety tiers, idempotency classes, examples, and Sonos-specific hints
- non-streaming event capabilities
- bound capability-token acceptance and denial in both `invoke` and `simulate`
- specific degraded state when the connector is not configured

The deterministic integration evidence is anchored on loopback tests covering:

- device-description self-check metadata
- `GetTransportInfo` and `GetVolume` parsing
- play, pause, next, previous, and set-volume SOAP action headers and payloads
- 401 upstream error redaction
- malformed XML/null status behavior
- out-of-range volume rejection before outbound dispatch
- timeout/cancel error mapping
- manifest operation coverage, AI hint redaction, embedded credential rejection, debug redaction, and non-streaming event caps

## Source Notes

- `connectors/sonos/src/types.rs` defines configuration validation and device URL normalization.
- `connectors/sonos/src/client.rs` defines local SOAP request construction, device-description probing, AVTransport and RenderingControl actions, XML tag extraction, volume bounds, and upstream error redaction.
- `connectors/sonos/src/connector.rs` defines lifecycle handlers, capability-token enforcement, operation metadata, diagnostics, simulate behavior, and non-streaming posture.
- `connectors/sonos/src/error.rs` defines provider/FCP error mapping and retry classification.
- `connectors/sonos/manifest.toml` defines the operation catalog, capability families, zone policy, sandbox boundary, and local-network notes.
- `connectors/sonos/tests/integration.rs` covers loopback SOAP behavior, lifecycle behavior, capability-token behavior, and redaction posture.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/sonos/README.md
ubs connectors/sonos/README.md
LC_ALL=C rg -n '[^ -~]' connectors/sonos/README.md
rg -n '\bmaster\b' connectors/sonos/README.md
```

For source or behavior changes, use an `rch`-offloaded connector proof lane:

```bash
fwc manifest fix connectors/sonos/manifest.toml --check --json
rch exec -- cargo fmt --manifest-path connectors/sonos/Cargo.toml --check
rch exec -- cargo check -p fcp-sonos --all-targets
rch exec -- cargo test -p fcp-sonos --test integration -- --nocapture
rch exec -- cargo test -p fcp-sonos -- --nocapture
rch exec -- cargo clippy -p fcp-sonos --all-targets -- -D warnings
```

There is no tracked `scripts/e2e/sonos_connector_verification.sh` in this checkout. Add one before claiming a full scripted closeout bundle.

## Operator Guidance

Prerequisites:

- Know the target Sonos device URL.
- Confirm the target speaker/room before write operations.
- Use the loopback fixture for proof when a live speaker is not available.

Dedicated environment:

- Prefer a loopback mock device or an isolated speaker before sending playback or volume operations. Do not run write operations in shared spaces unless audible side effects are acceptable.

Redaction rules:

- Redact device URLs, speaker hostnames/IPs, friendly names, model names, room names, transport state that reveals listening behavior, upstream error bodies, request logs, and local network topology before sharing evidence.

Common remediation:

- If `health` reports `degraded`, configure the connector with `device_url`.
- If `self_check` fails, verify that `/xml/device_description.xml` is reachable from the host.
- If configuration rejects `device_url`, use HTTP or HTTPS without embedded credentials.
- If `set_volume` rejects input, provide an absolute integer between `0` and `100`.
- If play/pause/next/previous fails, verify that the configured device supports the requested AVTransport action for the current source/queue.
- If `simulate` reports missing capabilities, request `sonos.read` or `sonos.write` according to the operation.

Rerun commands:

- `git diff --check -- connectors/sonos/README.md`
- `ubs connectors/sonos/README.md`
- `rch exec -- cargo test -p fcp-sonos --test integration -- --nocapture`
