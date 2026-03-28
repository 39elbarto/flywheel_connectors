# FCP3 Transition Guardrails

> **Bead**: `flywheel_connectors-hattj` — [FCP3/P1.3]
> **Author**: WhiteCompass (SunnyMoose session, 2026-03-27)
> **Input**: [FCP3_Canonical_Owner_Map.md](FCP3_Canonical_Owner_Map.md) (P1.2)
> **Purpose**: Anti-regression rules for the FCP3 transition period. Review criteria for rejecting architectural backslide.

---

## Guardrail Principles

During the FCP3 transition, all code changes must be evaluated against these guardrails. Reviewers MUST reject PRs that violate these rules unless accompanied by an explicit exemption approved by the project owner.

---

## G1. No New Broad Semantic Buckets

**Rule**: Do not add new types, traits, or modules to fcp-core that span multiple semantic domains.

**Examples of violations**:
- Adding a `ConnectorContext` struct that contains health, policy, and lifecycle state
- Creating a `PlatformState` that merges execution and evidence
- Adding `fn process(request: Value) -> Value` catch-all handlers

**Why**: Broad buckets are how leakage starts. Each new type must have a single domain owner per the canonical owner map.

**Review check**: Does the new type belong to exactly one of {execution, policy, evidence, durability, placement, operator}?

---

## G2. No New Host-Only Truth for Platform Facts

**Rule**: If a fact is needed by SDKs, agents, or mesh peers, it MUST be defined in fcp-core, not fcp-host.

**Examples of violations**:
- Defining a new `HostDecisionKind` enum in fcp-host that agents need to interpret
- Adding `fcp-host::ConcurrencyMode` that connectors must understand
- Creating health status types in fcp-host that SDKs need to implement

**Why**: Host-only truth creates hidden contracts. Consumers of fcp-host types can't replicate behavior without importing the host crate.

**Review check**: Would an SDK or mesh peer need this type? If yes, it belongs in fcp-core.

---

## G3. No New fwc Reach-Through to Low-Level Meaning

**Rule**: fwc must not directly import or manipulate fcp-core types that represent policy decisions, cryptographic operations, or enforcement logic.

**Allowed fwc imports from fcp-core**:
- Presentation types (OperationInfo, ConnectorId, HealthSnapshot)
- Error types (FcpError)
- ID types (OperationId, ZoneId, SessionId)

**Prohibited fwc imports**:
- PolicyEngine, PolicyDecision, PolicyBundle
- Ed25519 signing/verification (fcp-crypto)
- EnforcementCheck, EnforcementPipeline
- CapabilityVerifier (verification is host-side)

**Why**: The CLI must go through fcp-host RPC for policy and enforcement, not bypass it.

**Review check**: Is fwc calling `fcp-crypto` or constructing `PolicyBundle` directly? If yes, it needs an fcp-host RPC endpoint instead.

---

## G4. No New Compatibility-First APIs

**Rule**: New APIs must target the FCP3 architecture, not the FCP2 compatibility layer.

**Examples of violations**:
- Adding new methods to `fcp-sdk::migration::ConnectorErrorMapping`
- Extending the v2 handshake format instead of implementing v3
- Adding new v2-style dispatch arms in connector `main.rs`

**Why**: Compatibility APIs are scheduled for deletion. Extending them increases migration debt.

**Review check**: Is this API using types from `fcp_sdk::migration`? If yes, consider the v3 native path instead.

---

## G5. No New Runtime Compatibility Debt

**Rule**: Do not add shims, adapters, or translation layers between old and new APIs unless they are tracked as explicit migration items with deletion dates.

**If a shim is unavoidable**:
1. Tag it with `// COMPAT-SHIM: delete after <bead-id>`
2. Create a bead to track its removal
3. The shim must not become the primary path

**Review check**: Does this change add a translation between old and new types? Is there a bead to remove it?

---

## G6. No New Direct Semantic Edges Between Non-Adjacent Crates

**Rule**: Type dependencies must follow the layered architecture:

```
connectors → fcp-sdk → fcp-core
                fwc → fcp-host → fcp-core
                      fcp-mesh → fcp-protocol → fcp-core
                     fcp-store → fcp-core
```

**Prohibited edges**:
- connectors importing fcp-host types
- fwc importing fcp-mesh or fcp-store types
- fcp-mesh importing fcp-host types
- fcp-sdk importing fcp-host types

**Review check**: Does the Cargo.toml add a dependency that crosses layers?

---

## G7. Owner Map Enforcement

**Rule**: Any new public type must be assigned an owner per the [canonical owner map](FCP3_Canonical_Owner_Map.md). If the owner crate doesn't exist yet, the type goes in fcp-core with a `// PENDING-CARVE: target crate = <name>` annotation.

**Review check**: Is the new type in the correct owner crate? If not, is there a `PENDING-CARVE` annotation?

---

## G8. Forbidden Overlap Enforcement

**Rule**: The 7 forbidden overlaps from the owner map (F1-F7) must not be extended. Specifically:

| ID | Overlap | Rule |
|----|---------|------|
| F1 | Health aggregation | No new health types in fcp-host; use fcp-core model |
| F2 | Rollout decisions | No new rollout types in fcp-host; pending move to fcp-core |
| F3 | Enforcement ordering | No new enforcement checks without updating fcp-core ordering |
| F4 | Progress/cancellation | No new progress or cancel types in fcp-host |
| F5 | Readiness duplication | No new readiness types in fwc; extend fcp-core |
| F6 | CLI policy manipulation | No direct crypto or policy in fwc |
| F7 | Credential store | No new credential logic without fcp-core trait |

---

## Review Checklist

For every PR during the FCP3 transition:

- [ ] **G1**: No broad semantic bucket added
- [ ] **G2**: No host-only truth for platform facts
- [ ] **G3**: No fwc reach-through to low-level meaning
- [ ] **G4**: No compatibility-first API extension
- [ ] **G5**: No untracked compatibility shim
- [ ] **G6**: No cross-layer crate dependency
- [ ] **G7**: New types assigned to correct owner
- [ ] **G8**: No forbidden overlap extended

---

*These guardrails are active during the entire FCP3 migration. They may be relaxed only by the project owner after the target architecture is fully realized.*
