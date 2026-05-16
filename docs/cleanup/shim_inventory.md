# FCP3 Compatibility Shim Inventory

> Bead: `flywheel_connectors-angoc.3.1`
> Generated: 2026-05-12

This inventory reconciles the Phase I.1 bridge-plan guess against the current
checkout. The guessed `fcp_core::compat::policy` and
`fcp_core::compat::evidence` modules do not exist, and there are no workspace
callers to migrate for those paths.

The active compatibility shim in `docs/FCP3_Transition_Scorecard.md` is not an
`fcp_core::compat` module. It is the `ConnectorErrorMapping` helper in
`crates/fcp-sdk/src/migration.rs`. `ConnectorRuntime` has graduated to the
first-class `crates/fcp-sdk/src/runtime.rs` SDK surface.

<!-- compat-shim-inventory-summary: suspected_core_compat_modules=0 suspected_core_compat_callers=0 scorecard_active_shims=1 -->

## Suspected Core Compat Paths

| Shim guess | Module exists | Caller count | Status | Notes |
|------------|---------------|--------------|--------|-------|
| `fcp_core::compat::policy` | no | 0 | absent | No `compat` module is declared under `crates/fcp-core/src/`; no Rust caller uses this path. |
| `fcp_core::compat::evidence` | no | 0 | absent | No `compat` module is declared under `crates/fcp-core/src/`; no Rust caller uses this path. |

<!-- compat-shim-row: id=FCP-CORE-COMPAT-POLICY path=fcp_core::compat::policy module_exists=false caller_count=0 status=absent -->
<!-- compat-shim-row: id=FCP-CORE-COMPAT-EVIDENCE path=fcp_core::compat::evidence module_exists=false caller_count=0 status=absent -->

## Active Scorecard Shims

| Shim | Location | Status | Boundary |
|------|----------|--------|----------|
| `ConnectorRuntime` | `crates/fcp-sdk/src/runtime.rs` | migrated | First-class SDK lifecycle helper for request/background contexts and shutdown. |
| `ConnectorErrorMapping` | `crates/fcp-sdk/src/migration.rs` | active | Shared connector error-to-`FcpError` mapping contract. |

<!-- scorecard-shim-row: id=FCP-SDK-CONNECTOR-RUNTIME symbol=ConnectorRuntime location=crates/fcp-sdk/src/runtime.rs status=migrated -->
<!-- scorecard-shim-row: id=FCP-SDK-CONNECTOR-ERROR-MAPPING symbol=ConnectorErrorMapping location=crates/fcp-sdk/src/migration.rs status=active -->

## Verification Commands

Commands run from the workspace root:

```bash
sg run -l Rust -p 'fcp_core::compat::policy::$$$ITEM' crates connectors tests
sg run -l Rust -p 'fcp_core::compat::evidence::$$$ITEM' crates connectors tests
rg -n '^(pub mod|mod) compat\b|fcp_core::compat::(policy|evidence)|compat::(policy|evidence)' crates/fcp-core/src crates connectors tests
rg -n '#\[deprecated' crates/fcp-core/src
```

The two `sg` caller queries and the targeted `rg` compat query returned no
matches. The deprecated-attribute query found only capability-token deprecation
markers in `crates/fcp-core/src/capability.rs`; those are unrelated to the
Phase I.1 `policy`/`evidence` shim guess.

The bridge-plan pattern
`ast-grep run -l Rust -p '#[deprecated($$$)] $$$ITEM' crates/fcp-core/src/`
does not parse as a valid single Rust pattern in `ast-grep 0.40.5`, so the
inventory uses the targeted caller queries above plus the raw
`#[deprecated]` scan for the current checkout.
