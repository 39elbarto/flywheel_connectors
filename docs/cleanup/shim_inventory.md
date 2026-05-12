# FCP3 Compat Shim Inventory

Bead: `flywheel_connectors-angoc.3.1`

This inventory covers the planned cleanup for legacy
`fcp_core::compat::policy` and `fcp_core::compat::evidence` re-export shims.

forbidden_compat_caller_baseline: 0

## Commands

The bridge-plan command recorded in the bead was tried first:

```bash
ast-grep run -l Rust -p '#[deprecated($$$)] $$$ITEM' crates/fcp-core/src/
```

With the installed `ast-grep`, that pattern is not valid Rust syntax because it
contains multiple top-level AST nodes. The inventory therefore used narrower
valid queries plus a plain text cross-check:

```bash
ast-grep run -l Rust -p 'pub mod compat { $$$BODY }' crates/fcp-core/src/
ast-grep run -l Rust -p 'mod compat { $$$BODY }' crates/fcp-core/src/
ast-grep run -l Rust -p 'fcp_core::compat::policy::$$$ITEM' .
ast-grep run -l Rust -p 'fcp_core::compat::evidence::$$$ITEM' .
rg -n '\b(pub\s+)?mod\s+compat\b|fcp_core::compat::(policy|evidence)|compat::(policy|evidence)' crates docs --glob '*.rs' --glob '*.md'
rg -n '#\[deprecated' crates/fcp-core/src
```

## Results

No `pub mod compat` or private `mod compat` module exists under
`crates/fcp-core/src`.

No Rust caller imports or paths exist for:

- `fcp_core::compat::policy`
- `fcp_core::compat::evidence`
- `compat::policy`
- `compat::evidence`

The only text matches for those planned paths are in
`docs/reality/2026-05-12-reality-check-bridge-plan.md`, where the cleanup plan
was proposed.

The deprecated items currently present in `crates/fcp-core/src` are:

- `crates/fcp-core/src/capability.rs:1046`:
  `CryptographicallyVerified`
- `crates/fcp-core/src/capability.rs:1168`: `VerifiedToken`
- `crates/fcp-core/src/capability.rs:1980`: `CapabilityVerifier::verify`

Those are typestate compatibility markers and a deprecated verifier method, not
`fcp_core::compat::policy` or `fcp_core::compat::evidence` shim modules.

## Migration Decision

There are zero workspace callers to migrate for the two planned compat shim
paths. New code should import policy-owned semantics from `fcp_policy` and
evidence-owned semantics from `fcp_evidence`; the current owner crates still
re-export many definitions from `fcp_core` while the FCP3 carve-out continues.

The companion conformance test
`crates/fcp-conformance/tests/compat_caller_count_decreasing.rs` pins the zero
caller baseline so new Rust code cannot reintroduce those forbidden paths.
