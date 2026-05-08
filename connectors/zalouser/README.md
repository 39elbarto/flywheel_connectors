# Zalo User Connector V1 Contract

> **Status**: quarantined planned-only helper contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: none wired; this crate intentionally ships no personal-account runtime
> **Developer portal context**: https://developers.zalo.me/

## Purpose

This document fixes the operator-facing contract for `fcp.zalouser`. The current crate is a quarantined, planned-only contract for future Zalo personal-account automation. It declares one high-risk helper operation but does not implement live invoke support, does not spawn a helper process, and does not bundle or emulate an upstream personal-account runtime.

This connector is intentionally a denial surface. It exists to make future personal-account automation explicit, auditable, and disabled until a separate proof lane defines the helper policy, security boundary, approval model, and provider-risk posture.

## Current Runtime Snapshot

The current crate exposes this planned operation:

- `zalouser.helper.exec`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-zalouser`.
- Runtime and manifest connector ID are `fcp.zalouser`.
- Manifest status is `quarantined`.
- Manifest archetype is `operational`.
- `handle_configure()` accepts an empty object and only marks the connector configured.
- `handle_handshake()` requires prior configuration and returns no live capabilities.
- `handle_handshake()` advertises `planned_capabilities = ["zalouser.helper"]`.
- `execution_enabled` is always `false`.
- `live_requests_supported` is always `false`.
- `health()` reports `unconfigured` before configure and `degraded` after configure.
- `doctor()` reports disabled invoke surface and disabled helper execution.
- `self_check()` returns `unsupported` with reason `invoke_surface_unimplemented` after configure and handshake.
- `introspect()` marks `zalouser.helper.exec` as `implemented = false`.
- `handle_invoke()` rejects the planned helper operation and unknown operations.
- `handle_simulate()` always returns `allowed = false`.
- `handle_shutdown()` clears configured and handshaken state.

## First-Slice Scope

The current Zalo User README slice documents the existing quarantined surface:

- planned helper-operation declaration
- disabled runtime execution
- owner-zone-only manifest posture
- no network, no listener, no exec, and no helper-process policy
- denial behavior for health, doctor, self-check, introspect, invoke, simulate, and stdio e2e
- explicit separation from the experimental `fcp.zalo` Bot API connector

## Auth And Scope Boundary

- Authentication mechanism: none implemented.
- Runtime does not implement Zalo personal login, QR login, password login, OTP handling, cookie/session storage, Zalo Web protocol automation, app/desktop automation, OAuth, Bot API tokens, or Official Account auth.
- Home zone: `z:owner`.
- Allowed source zones: `z:owner`.
- Allowed target zone: `z:owner`.
- Optional capability: `zalouser.helper`.
- Optional network capabilities are declared for future design space, but the only operation constrains egress to `none.invalid` and port `0`.
- Forbidden capabilities: `network.listen` and `system.exec`.
- The manifest declares a high-risk, risky, policy-approved helper operation, but the runtime refuses all execution.
- Personal Zalo account identifiers, phone numbers, cookies, login factors, contact lists, chat messages, media, device fingerprints, session files, and helper-process logs would be sensitive if this connector ever becomes live. None are handled by this slice.

## Network And Runtime Invariants

- No production API host is used by this runtime.
- No request-response provider client is implemented.
- No helper process is spawned.
- No connector-owned listener is opened.
- `zalouser.helper.exec` network constraints intentionally allow only `host_allow = ["none.invalid"]` and `port_allow = [0]`.
- Operation network constraints deny localhost, private ranges, tailnet ranges, and IP literals.
- Operation network constraints use `dns_max_ips = 0`, `max_redirects = 0`, `connect_timeout_ms = 1000`, and `total_timeout_ms = 15000`.
- Manifest sandbox profile is `strict`, with `96 MB` memory, `25%` CPU, `60000 ms` wall-clock timeout, no exec, and no ptrace.
- The crate's stdio e2e test asserts that no child helper process is created during the planned-only denial path.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `zalouser.helper` | Planned future helper-process execution capability. It is declared but disabled in this slice. |
| `network.egress` | Declared as optional future design space; no live egress is used. |
| `network.dns` | Declared as optional future design space; operation-level constraints set `dns_max_ips = 0`. |
| `network.tls.sni` | Declared as optional future design space; no live TLS/SNI request is made. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Runtime behavior |
|-----------|----------------|------------|------------|-----------|-------------|------------------|
| `zalouser.helper.exec` | none; planned helper process only | `zalouser.helper` | `risky` | `high` | `none` | Always rejected with planned-but-not-implemented / unsupported denial. |

## Explicit Non-Goals

The current implementation does not include:

- live personal-account automation
- Zalo Web reverse engineering
- QR login, password login, OTP handling, cookie/session persistence, contact scraping, message scraping, or media scraping
- helper-process launch, shell execution, desktop automation, mobile app automation, or browser automation
- Zalo Official Account / Bot API support; use `fcp.zalo` for the experimental bot surface
- network egress, webhook ingress, polling, streaming, replay buffers, or durable storage
- account-risk mitigation, ban-risk modeling, provider-policy bypass, or approval workflows beyond the manifest declaration

These are excluded on purpose:

- Personal-account automation is high risk and can expose private account data.
- The crate forbids `system.exec`; a future helper process would require an explicit security design instead of an implicit runtime escape.
- Planned-only denial is safer than shipping partial unofficial automation.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configured and handshaken state
- `execution_enabled = false`
- `live_requests_supported = false`
- planned capability declaration
- disabled helper execution reason `helper_exec_disabled`
- unsupported invoke reason `invoke_surface_unimplemented`
- operation metadata for the planned helper operation
- empty event and resource surfaces

The deterministic evidence is anchored on crate-local and stdio tests covering:

- manifest interface hash validation
- planned helper operation network constraints
- degraded readiness before and after handshake
- unsupported self-check after handshake
- introspection with `implemented = false`
- direct invoke denial for the planned helper operation
- simulate denial for the planned helper operation and unknown operations
- binary stdio lifecycle denying helper execution without creating a child process

## Source Notes

- `connectors/zalouser/src/connector.rs` defines the planned-only lifecycle, disabled operation metadata, invoke denial, simulate denial, and unit tests.
- `connectors/zalouser/src/main.rs` wires the binary/stdio surface to the connector handlers.
- `connectors/zalouser/manifest.toml` defines the quarantined status, owner-zone policy, sandbox boundary, optional capabilities, and disabled helper-operation network constraints.
- `connectors/zalouser/tests/stdio_e2e.rs` covers the binary stdio denial contract and child-process absence evidence.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/zalouser/README.md
ubs connectors/zalouser/README.md
LC_ALL=C rg -n '[^ -~]' connectors/zalouser/README.md
rg -n '\bmaster\b' connectors/zalouser/README.md
```

For source or behavior changes, use an `rch`-offloaded connector proof lane:

```bash
fwc manifest fix connectors/zalouser/manifest.toml --check --json
rch exec -- cargo fmt --manifest-path connectors/zalouser/Cargo.toml --check
rch exec -- cargo check -p fcp-zalouser --all-targets
rch exec -- cargo test -p fcp-zalouser binary_stdio_planned_only_denies_helper_without_child_process -- --nocapture
rch exec -- cargo test -p fcp-zalouser -- --nocapture
rch exec -- cargo clippy -p fcp-zalouser --all-targets -- -D warnings
```

There is no tracked `scripts/e2e/zalouser_connector_verification.sh` in this checkout. Add one before claiming a full scripted closeout bundle.

## Operator Guidance

Prerequisites:

- None for the current denial-only surface.
- Do not supply personal-account credentials to this connector; the runtime has nowhere safe or useful to put them.

Dedicated environment:

- Use the stdio e2e test for proof. There is no live provider environment for this slice.

Redaction rules:

- Do not collect personal Zalo credentials, cookies, QR login tokens, phone numbers, contact lists, chat messages, media, device identifiers, browser profiles, or helper logs for this connector. If future proof work introduces any of those fields, redact them before sharing artifacts.

Common remediation:

- If `health` reports `unconfigured`, call `configure`; this only moves the connector to a degraded planned-only state.
- If `self_check` reports `not_handshaken`, call handshake.
- If `self_check` reports `invoke_surface_unimplemented`, the connector is behaving as designed.
- If `invoke` rejects `zalouser.helper.exec`, the connector is behaving as designed.
- If an operator needs Zalo Bot API behavior, use `fcp.zalo` instead.
- If an operator needs personal-account automation, file a new design bead before changing this crate.

Rerun commands:

- `git diff --check -- connectors/zalouser/README.md`
- `ubs connectors/zalouser/README.md`
- `rch exec -- cargo test -p fcp-zalouser binary_stdio_planned_only_denies_helper_without_child_process -- --nocapture`
