# FCP3 Compatibility Shim Inventory

> Bead: `flywheel_connectors-angoc.3.1`
> Generated: 2026-05-12

This inventory reconciles the Phase I.1 bridge-plan guess against the current
checkout. The guessed `fcp_core::compat::policy` and
`fcp_core::compat::evidence` modules do not exist, and there are no workspace
callers to migrate for those paths.

The compatibility shims in `docs/FCP3_Transition_Scorecard.md` are not
`fcp_core::compat` modules. `ConnectorRuntime` has graduated to the first-class
`crates/fcp-sdk/src/runtime.rs` SDK surface. `ConnectorErrorMapping` has
graduated to the first-class `crates/fcp-sdk/src/error_mapping.rs` SDK surface,
and the legacy `fcp_sdk::migration` trait re-export has been removed after
call sites migrated to `fcp_sdk::ConnectorErrorMapping`.

<!-- compat-shim-inventory-summary: suspected_core_compat_modules=0 suspected_core_compat_callers=0 scorecard_active_shims=0 scorecard_migrating_shims=0 -->

<!-- Ratchet baseline consumed by crates/fcp-conformance/tests/compat_caller_count_decreasing.rs.
     The forbidden `fcp_core::compat::{policy,evidence}` paths have zero workspace callers
     (see the Suspected Core Compat Paths table above), so the ceiling is pinned at 0:
     any newly introduced caller fails the ratchet. -->
forbidden_compat_caller_baseline: 0

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
| `ConnectorErrorMapping` | `crates/fcp-sdk/src/error_mapping.rs` | migrated | First-class SDK error-to-`FcpError` mapping contract; no `fcp_sdk::migration` trait re-export remains. |

<!-- scorecard-shim-row: id=FCP-SDK-CONNECTOR-RUNTIME symbol=ConnectorRuntime location=crates/fcp-sdk/src/runtime.rs status=migrated -->
<!-- scorecard-shim-row: id=FCP-SDK-CONNECTOR-ERROR-MAPPING symbol=ConnectorErrorMapping location=crates/fcp-sdk/src/error_mapping.rs status=migrated legacy_reexport=removed -->

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
