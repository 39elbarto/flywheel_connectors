# Tlon Connector V3 Contract

> **Status**: planned-only runtime contract documented; live invoke unsupported
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Tlon developer upstream**: https://dev.tlon.io/
> **Urbit upstream**: https://urbit.org/

## Purpose

This document fixes the operator-facing contract for `fcp.tlon`. The current crate declares an incubating Tlon and Urbit messaging surface for direct-message send, channel send, and target resolution, but it does not implement live provider calls yet.

The connector is intentionally planned-only in this checkout. It is not a working Tlon client, Urbit ship client, `%landscape` client, channel reader, invite manager, app installer, fake-ship launcher, durable event bridge, or credentialed network integration.

## Current Runtime Snapshot

The current crate exposes these planned runtime operation IDs:

- `tlon.dm.send`
- `tlon.channel.send`
- `tlon.target.resolve`

Important runtime truths the contract preserves:

- Runtime connector ID is `fcp.tlon`.
- Runtime connector version is `0.1.0`.
- The binary speaks a simple line-delimited JSON-RPC loop over stdin/stdout.
- Supported JSON-RPC methods are `configure`, `handshake`, `health`, `doctor`, `self_check`, `introspect`, `invoke`, `simulate`, and `shutdown`.
- `configure` currently ignores all parameters and only marks the connector configured.
- `handshake` requires prior configuration and returns `surface_status = "incubating"`.
- `handshake` returns no granted capabilities and reports `planned_capabilities = ["tlon.dm", "tlon.channel"]`.
- `health` reports `unconfigured` before configure and `degraded` after configure because live requests are unsupported.
- `doctor` always reports the invoke surface as not implemented.
- `self_check` reports `degraded` before configuration, `degraded` before handshake, and `unsupported` after handshake.
- `introspect` advertises three planned operations with `implemented = false`.
- `invoke` rejects every operation. Known planned operations return an invalid-request error explaining that live invoke support is not implemented.
- `simulate` always returns `allowed = false` and `simulate_capability = "unsupported"`.
- `shutdown` clears configured and handshaken state.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest describes authenticated DM and channel send flows, but runtime live invoke support is absent.
- Manifest required capabilities include `tlon.dm` and `tlon.channel`, while runtime handshake returns no active capabilities and lists them only as planned.
- Manifest state migration hint mentions SSRF-safe base URL validation, but runtime `configure` ignores `base_url`, `auth_ref`, and every other parameter.
- Manifest required network capabilities include DNS, egress, and TLS SNI, but runtime never opens provider sockets.
- Manifest operation schemas are strict and provider-shaped, but runtime invoke does not validate operation inputs because it refuses execution before provider work.
- Runtime `tlon.target.resolve` uses `tlon.channel` as its advertised capability.
- The `TlonError` provider error mapping exists, but the current planned-only invoke path does not use it for live HTTP calls.
- There is no dedicated tracked verification shell script for this connector.

A follow-up implementation bead should introduce real configuration parsing, explicit base URL and private-network policy, credential handling, provider client code, bound capability-token verification, approval posture for sends, live target resolution, and no-mock provider evidence before this connector is described as implemented.

## First-Slice Scope

The current Tlon README slice documents the existing planned-only surface:

- line-delimited JSON-RPC lifecycle
- configured and handshaken state transitions
- planned DM send, channel send, and target resolve metadata
- explicit unsupported invoke and simulation behavior
- redacted JSONL evidence tests for skipped planned operations
- malformed JSON, missing operation, unknown operation, pre-configure denial, and shutdown handling

## Auth And Scope Boundary

- Authentication mechanism: none active in runtime.
- Planned authentication mechanism: credentialed Tlon or Urbit ship access, not implemented.
- Home zone: `z:community`.
- Allowed source zones: `z:owner`, `z:work`, and `z:community`.
- Allowed target zone: `z:community`.
- Manifest capability surface:
  - `tlon.dm` for `tlon.dm.send`.
  - `tlon.channel` for `tlon.channel.send` and `tlon.target.resolve`.
- Runtime capability surface:
  - no active granted capabilities.
  - all capabilities are advertised only as planned.
- The current connector does not persist ship URLs, auth references, login codes, target ships, channel identifiers, message bodies, provider payloads, or provider errors.
- Tlon ship names, channel paths, group/channel membership, login codes, and message bodies can reveal private community context. Treat any future live request and response data as community-zone or work-zone data according to the configured target.

## Network And Runtime Invariants

- Runtime provider network behavior: none.
- Manifest expected provider posture: outbound DNS, egress, and TLS SNI.
- Manifest sandbox profile is `strict`, with `96 MB` memory, `25%` CPU, `60_000 ms` wall-clock timeout, no exec, and no ptrace.
- The current binary does not open inbound sockets.
- The current binary does not open outbound provider sockets.
- The current binary reads newline-delimited JSON from stdin and writes newline-delimited JSON responses to stdout.
- Invalid JSON produces a JSON-RPC error with code `FCP-1001`.
- Unknown methods produce an invalid-request response.

## Capability Families

| Capability | Runtime status | Purpose |
|-----------|----------------|---------|
| `tlon.dm` | planned | Send a direct message to a target Urbit ship. |
| `tlon.channel` | planned | Send to or resolve a Tlon channel target. |

## Operation Inventory

| Operation | Runtime status | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `tlon.dm.send` | planned, not implemented | `tlon.dm` | `Safe` | `Medium` | `BestEffort` | Would send a direct message to a ship. |
| `tlon.channel.send` | planned, not implemented | `tlon.channel` | `Safe` | `Medium` | `BestEffort` | Would send a message into a Tlon or Urbit channel. |
| `tlon.target.resolve` | planned, not implemented | `tlon.channel` | `Safe` | `Low` | `Strict` | Would normalize or validate a DM or channel target before sending. |

## Explicit Non-Goals

The current implementation does not include:

- Tlon account login, Urbit ship login, login-code refresh, cookie/session management, or credential vaulting
- provider HTTP client code, channel send, DM send, channel lookup, target resolution, invite acceptance, or message reads
- fake-ship creation, Urbit runtime launch, app install, desk management, or `%landscape` automation
- webhook, websocket, SSE, polling, replay, or durable event delivery
- attachment upload, rich-text conversion, thread reply handling, channel discovery, allowlist management, or approval flows
- live no-mock integration evidence against a real Tlon or Urbit ship

These are excluded on purpose in the current slice:

- The source is a scaffold that keeps planned metadata visible while refusing live execution.
- Real Tlon or Urbit sends need explicit credential, target, and network policy before any provider socket opens.
- Message bodies and channel paths are sensitive and must not appear in skipped fixture evidence.

## Readiness And Verification Surface

`handle_configure()`, `handle_handshake()`, `handle_health()`, `handle_doctor()`, `handle_self_check()`, `handle_introspect()`, `handle_invoke()`, `handle_simulate()`, and `handle_shutdown()` are part of the public closeout contract. They surface:

- configured and handshaken state
- incubating planned-only posture
- planned capabilities and planned operation metadata
- strict manifest/runtime schema parity for the three planned operations
- explicit unsupported invoke behavior for known planned operations
- explicit denial behavior for simulation
- redacted skipped-operation proof records
- JSON-RPC handling for invalid JSON, lifecycle requests, and shutdown

The deterministic integration evidence is anchored on connector-local tests covering:

- unconfigured, configured, handshaken, and shutdown lifecycle states
- degraded and unsupported readiness reports
- manifest/runtime operation count and schema parity
- strict input and output schemas for planned operations
- planned operation invoke refusal
- simulation denial for planned and unknown operations
- missing operation, unknown operation, and pre-configure denial
- redacted JSONL evidence that hashes ship and channel fixtures instead of leaking raw values
- JSON-RPC process behavior for invalid JSON, configure, handshake, and shutdown

## Source Notes

- `connectors/tlon/src/connector.rs` defines planned operation metadata, lifecycle handlers, readiness, unsupported invoke, simulation denial, and shutdown.
- `connectors/tlon/src/main.rs` defines the line-delimited JSON-RPC process loop.
- `connectors/tlon/src/error.rs` defines future provider error classes and FCP error conversion.
- `connectors/tlon/manifest.toml` defines the planned operation catalog, strict schemas, capability declarations, sandbox boundary, and zone policy.
- `connectors/tlon/tests/integration.rs` covers planned-only lifecycle, skipped invoke evidence, denial paths, and JSON-RPC process behavior.
- `connectors/tlon/tests/conformance_contract.rs` covers manifest/runtime operation parity and schema strictness.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/tlon_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local planned-only tests plus direct `rch` proof commands after the active connector source edits settle.

The verification surface captures:

- planned operation inventory and metadata
- manifest/runtime schema parity
- planned-only lifecycle and readiness behavior
- unsupported invoke and simulation-denial behavior
- redacted skipped-operation evidence
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Do not configure this connector for live Tlon or Urbit traffic yet; runtime live provider support is absent.
- Use the planned-only tests to keep the scaffold honest.
- Treat any future live implementation as a separate credentialed provider-client bead.

**Dedicated environment**:

- Future live validation should use a dedicated test ship, test channels, and non-sensitive message bodies.
- Future local-ship testing should clearly distinguish fake ships from live-network ships.
- Future network policy should make any localhost, LAN, or private-network allowance explicit.

**Redaction rules**:

- Redact ship names when tenant-revealing, channel paths, login codes, auth references, cookies, message bodies, endpoint URLs, provider error bodies, and filesystem paths from live evidence.
- Verification output should use operation IDs, fixture IDs, hashes, lifecycle phase, status/error classes, and cleanup result instead of raw Tlon or Urbit content.

**Common remediation**:

- If `health` reports `unconfigured`, call `configure` first.
- If `self_check` reports `not_handshaken`, call `handshake` after `configure`.
- If `self_check` reports `invoke_surface_unimplemented`, this is expected in the current checkout.
- If `invoke` returns "planned but not implemented", do not retry with live credentials; the runtime intentionally refuses provider calls.
- If `simulate` returns unsupported, treat that as the current contract rather than a transient provider failure.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-tlon-readme cargo check -p fcp-tlon --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-tlon-readme cargo test -p fcp-tlon --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-tlon-readme cargo clippy -p fcp-tlon --all-targets --no-deps -- -D warnings`
- `ubs connectors/tlon/README.md`
