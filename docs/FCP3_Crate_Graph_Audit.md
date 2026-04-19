# FCP3 Crate-Graph and Import-Surface Audit

> **Bead**: `flywheel_connectors-0aczd.3` -- [FCP3/P7.4]
> **Author**: SunnyMoose, 2026-04-19
> **Purpose**: Concrete audit artifact proving the current state of `fcp-core`
> retirement, import-surface migration, and ownership boundary enforcement.

---

## 1. Current Dependency Structure

### Reverse Dependency Counts

| Crate | Direct Reverse Deps | Role |
|-------|-------------------|------|
| **fcp-core** | **175** | Legacy barrel (all consumers import it) |
| **fcp-kernel** | **4** | Execution lifecycle owner (fcp-sdk, fcp-host, fwc, fcp-e2e) |
| **fcp-policy** | **2** | Zone/capability owner (fwc, fcp-e2e) |
| **fcp-evidence** | **2** | Audit/revocation owner (fcp-host, fcp-e2e) |

### Re-Export Chain Direction

**Current state**: Owners re-export FROM fcp-core (backwards from the intended direction).

```
fcp-core (physical definition site — ~80K lines, 30+ modules)
    ^
    |  pub use fcp_core::{...}
    |
fcp-kernel / fcp-policy / fcp-evidence (re-export facades)
```

**Intended future state**: fcp-core re-exports from owners, then shrinks to
shared primitives.

```
fcp-kernel / fcp-policy / fcp-evidence (own type definitions)
    ^
    |  pub use fcp_kernel::{...}  (legacy compat)
    |
fcp-core (thin barrel or retired)
```

---

## 2. Consumer Migration Status

### Crates Using Owner Imports (migrated)

| Consumer | fcp-kernel | fcp-policy | fcp-evidence |
|----------|-----------|-----------|-------------|
| fcp-sdk | yes | -- | -- |
| fcp-host | yes | -- | yes |
| fwc | yes | yes | -- |
| fcp-e2e | yes (dev) | yes (dev) | yes (dev) |

### Crates Using Only fcp-core (not yet migrated)

All 155+ connectors and 17 infrastructure crates still import fcp-core
directly without importing an owner crate. This is the "junk drawer" pattern
that 0aczd tracks.

**Infrastructure crates still on fcp-core only**:
fcp-bootstrap, fcp-conformance, fcp-graphql, fcp-manifest, fcp-mesh,
fcp-oauth, fcp-protocol, fcp-raptorq, fcp-ratelimit, fcp-registry,
fcp-sandbox, fcp-store, fcp-streaming, fcp-tailscale, fcp-telemetry,
fcp-testkit, fcp-webhook

---

## 3. Ownership Surface Proof

### Module-to-Owner Assignment (from `fcp-core/src/lib.rs`)

| Category | Modules | Owner Crate | Re-exported? |
|----------|---------|-------------|-------------|
| Shared primitive | error, tool_schema, util | fcp-core (permanent) | N/A |
| Execution lifecycle | connector, connector_artifacts, connector_descriptors, connector_state, crdt, credential, event, health, lease, lifecycle, operation, protocol, provisioning, quorum, ratelimit, release, secret | fcp-kernel | Yes (all types re-exported) |
| Zone/capability/trust | capability, enforcement, enrollment, pcs, policy, posture, provenance, zone_keys | fcp-policy | Yes (all types re-exported) |
| Audit/revocation/objects | audit, checkpoint, object, revocation, supply_chain | fcp-evidence | Yes (all types re-exported) |

### Dead Code

| File | Size | Status |
|------|------|--------|
| `crates/fcp-core/src/telemetry.rs` | 46KB | Not declared as module in `lib.rs` -- dead code |

### Test Coverage

| Owner Crate | Tests | Coverage |
|-------------|-------|----------|
| fcp-kernel | 32 | Invocation, lifecycle, health, descriptors, lease, checkpoint, computation migration, budget, supply chain, rate limit, quorum, shutdown, idempotency, subscription, provisioning, credential, secret, release, artifacts |
| fcp-policy | 11 | Zone, capability, identity, provenance, approval, risk, zone keys, enforcement, posture, enrollment, PCS |
| fcp-evidence | 7 | Audit, revocation, idempotency, checkpoint, supply chain verification, object |

**Total**: 50 tests proving owner crate re-exports compile and are semantically correct.

---

## 4. What Changed in This Phase (0aczd.1 through 0aczd.3)

| Step | Bead | Deliverable |
|------|------|------------|
| Inventory | 0aczd.1 | `docs/FCP3_Semantic_Ownership_Inventory.md` -- every module classified |
| Re-export expansion | 0aczd.2 | 12 blur modules added to owner crates with 18 new tests |
| This audit | 0aczd.3 | This document -- crate-graph audit, import-surface proof, migration roadmap |

### What Moved

Prior to 0aczd.2, the following modules had NO re-export from any owner crate:
- enforcement, posture, enrollment, pcs (now re-exported by fcp-policy)
- object (now re-exported by fcp-evidence)
- connector_artifacts, release, credential, secret (now re-exported by fcp-kernel)

After 0aczd.2, **every non-primitive module** in fcp-core has a declared
semantic owner AND a re-export from that owner crate.

### What Did Not Move

The physical type definitions still live in fcp-core. This is migration debt,
not ownership blur -- the ownership is declared (in `lib.rs` annotations), the
re-exports exist (in owner crates), and the tests pass (50 tests).

---

## 5. Remaining Migration Blockers

| Blocker | Impact | Required Work |
|---------|--------|---------------|
| Physical type definitions still in fcp-core | 175 crates import fcp-core directly | Move definitions to owner crates, invert re-export chain |
| 155+ connectors use `fcp_core::*` | Every connector imports from the barrel | Switch to `fcp_kernel::*` (connectors need FcpConnector, OperationInfo, etc.) |
| 17 infrastructure crates on fcp-core only | No semantic owner in Cargo.toml | Add owner crate deps, change import paths |
| telemetry.rs dead code | 46KB unused file | Delete or wire into a module |
| fcp-core carries ~20 external deps | Moving types requires moving deps | deps follow the types |

---

## 6. Rerun Commands

```bash
# Verify owner crate tests pass
CARGO_TARGET_DIR=/tmp/fcp-audit cargo +nightly test -p fcp-kernel -p fcp-policy -p fcp-evidence --lib
# Expected: 50 tests ok

# Count reverse deps on fcp-core
CARGO_TARGET_DIR=/tmp/fcp-audit cargo +nightly tree -p fcp-core --depth 1 --edges reverse 2>&1 | wc -l
# Expected: ~180 lines (175 deps + headers)

# Verify ownership annotations in lib.rs
grep -c "Assigned to" crates/fcp-core/src/lib.rs
# Expected: 3 (kernel, policy, evidence)

# Verify all blur modules have re-exports
for owner in fcp-kernel fcp-policy fcp-evidence; do
  echo "=== $owner ===" && grep -c 'pub use fcp_core' crates/$owner/src/lib.rs
done
# Expected: fcp-kernel ~22, fcp-policy ~12, fcp-evidence ~6
```

---

## 7. Proof Artifacts Referenced

- `docs/FCP3_Semantic_Ownership_Inventory.md` (0aczd.1)
- `crates/fcp-core/src/lib.rs` ownership annotations (0aczd.2, commit `1273d5fc`)
- `crates/fcp-kernel/src/lib.rs` re-exports + 32 tests (0aczd.2)
- `crates/fcp-policy/src/lib.rs` re-exports + 11 tests (0aczd.2)
- `crates/fcp-evidence/src/lib.rs` re-exports + 7 tests (0aczd.2)
- This document (0aczd.3)

---

*This document is the crate-graph and import-surface audit for the
`flywheel_connectors-0aczd` epic. It proves that ownership boundaries are
declared, re-exports exist, and tests verify the semantics. The physical
type relocation and consumer migration are documented as remaining blockers
for future phases.*
