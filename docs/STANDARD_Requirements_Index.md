# FCP2 Requirements Index: Spec-to-Implementation Matrix (V2-only)

> **Status**: NORMATIVE
> **Version**: 1.0.0
> **Last Updated**: January 2026
> **Bead Reference**: `flywheel_connectors-1n78.1`

---

## Purpose

This document is the **single source of truth** mapping from:
- `FCP_Specification_V2.md`
- `README.md`
- `docs/fcp_model_connectors_rust.md`

...to the **owning Beads** (implementation + tests).

**Goal**: Engineers should be able to implement FCP2 by following the Beads graph **without rereading the spec/docs**.

---

## How to Use This Document

- Treat each entry as a **mechanical checklist** item.
- When you discover a missing requirement, update this matrix first, then:
  - Create the missing owning bead(s), OR
  - Expand the owning bead's scope/acceptance criteria/tests.

---

## Conformance Profiles (Spec §25)

| Profile | Description | Target |
|---------|-------------|--------|
| **MVP** | Must ship first | Reference implementation default |
| **Full** | Post-MVP hardening | Enabled by explicit configuration/policy |

This matrix labels items as **MVP** or **Full**. Many are shared.

---

## V2-Only Clarifications (Spec §26)

- FCP2 makes **no backwards-compat guarantees** with FCP1.
- No hybrid translator layer.
- Clean cutover only.

---

## Pricing / Cost Tracking Clarification

- Connectors MUST emit **usage metrics**.
- We do **not** embed hard-coded pricing tables in connectors (pricing changes frequently).
- If cost estimates are supported, they are explicit and policy/ops-owned (e.g., `CostEstimate`).

---

# A) Spec Coverage Matrix — `FCP_Specification_V2.md`

Below, each chapter lists:
- **Owners**: Implementation beads responsible for building it.
- **Primary Tests/Conformance**: Golden vectors, fuzz, interop, E2E, compliance runner.
- **Notes / Key Requirements**: The "sharp edges" we must not forget.

---

## Conformance Language

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.21` |
| **Tests** | `flywheel_connectors-1n78.21.1` (CDDL + golden vectors) |
| **Notes** | RFC2119 language interpretation. Anything labeled NORMATIVE is part of the interop/security contract. |

---

## §1: Introduction (informative)

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.1` (this matrix) |
| **Tests** | n/a |
| **Notes** | Establishes that FCP is object-native, mesh-authenticated, explicit authority. |

---

## §2: Foundational Axioms

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.3` (canonical serialization), `flywheel_connectors-1n78.4` (IDs + headers), `flywheel_connectors-1n78.11` (audit/checkpoints) |
| **Tests** | `flywheel_connectors-1n78.21.1` (golden vectors + CDDL) |
| **Notes** | Persisted/audited/mirrored things must be representable as canonical mesh objects. Mesh is authenticated; authority is explicit and provable. |

---

## §3: Foundational Primitives

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.4` (ObjectId/EpochId/ZoneId/Schemas/ObjectHeader), `flywheel_connectors-1n78.3` (canonical CBOR + schema hash), `flywheel_connectors-1n78.5` (crypto primitives) |
| **Tests** | `flywheel_connectors-1n78.21.1` (golden vectors + CDDL), `flywheel_connectors-1n78.21.2` (fuzz: parsers/decoders/verifiers) |
| **Notes** | Canonical identifier formats; reject non-canonical forms (no silent normalization). ObjectHeader rules + retention semantics and root pointers. HPKE sealed box shape requirements (used by zone crypto). ZoneCheckpoint is the "root pointer" (GC/security). |

---

## §4: Symbol Layer

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.12` (FCPS framing + SymbolEnvelope AEAD), `flywheel_connectors-1n78.24` (session auth, key schedule, anti-replay), `flywheel_connectors-1n78.14` (RaptorQ + chunking), `flywheel_connectors-1n78.17.2` (multipath + transport priority) |
| **Tests** | `flywheel_connectors-1n78.21.1` (golden vectors), `flywheel_connectors-1n78.21.2` (fuzz), `flywheel_connectors-1n78.21.3` (interop) |
| **Notes** | Session MACs required for throughput; Poly1305 key reuse rules. MTU safety and explicit frame size limits. Multipath delivery must respect ZoneTransportPolicy. |

---

## §5: Zone Architecture

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.26` (ZoneDefinition/ZonePolicy/roles/resource objects/reason codes), `flywheel_connectors-1n78.16` (Zone ↔ Tailscale tag mapping, port gating), `flywheel_connectors-1n78.6` (zone crypto key distribution), `flywheel_connectors-6o25.5` (optional MLS/TreeKEM PCS zones) |
| **Tests** | `flywheel_connectors-1n78.26.1` (policy decision vectors) |
| **Notes** | Zone hierarchy + mapping to Tailscale ACL tags. ZoneDefinitionObject + ZonePolicyObject must be enforceable and auditable. |

---

## §6: Provenance and Taint Tracking

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.8` (provenance model, taint propagation, elevation protocol), `flywheel_connectors-1n78.11` (DecisionReceipt evidence + explainability) |
| **Tests** | `flywheel_connectors-1n78.36.4` (E2E taint/approval flow) |
| **Notes** | Taint propagation is mechanical. Elevation/declassification requires ApprovalTokens and receipts. |

---

## §7: Capability System

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.7` (CapabilityObject + COSE_Sign1 tokens), `flywheel_connectors-1n78.18` (egress proxy + NetworkConstraints enforcement), `flywheel_connectors-kt9r` (credential injection model + zeroize discipline), `flywheel_connectors-1n78.26` (roles/bundles, placement policy) |
| **Tests** | `flywheel_connectors-1n78.21.5` (mechanical compliance runner), `flywheel_connectors-1n78.21.3` (interop tokens/handshake) |
| **Notes** | Capability IDs MUST NOT encode hostnames/ports; use `network_constraints`. Risky/Dangerous requires holder binding proof where applicable. Egress proxy credential injection is normative for strict/moderate. |

---

## §8: Mesh Architecture

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.17` (mesh node baseline), `flywheel_connectors-1n78.17.3` (admission control + anti-amplification + quarantine enforcement), `flywheel_connectors-1n78.17.5` (gossip baseline), `flywheel_connectors-1n78.25` (trust/quorum/degraded mode semantics) |
| **Tests** | `flywheel_connectors-1n78.21.4` (system E2E harness) |
| **Notes** | Admission control is mandatory; symbol request bounding is the big DoS surface. Distributed state must be convergent; quarantine prevents storage poisoning. |

---

## §9: Wire Protocol

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.12` (FCPS), `flywheel_connectors-1n78.13` (FCPC), `flywheel_connectors-1n78.24` (sessions), `flywheel_connectors-1n78.17.4` (SymbolRequest bounding + targeted repair plumbing) |
| **Tests** | `flywheel_connectors-1n78.21.1` (golden vectors), `flywheel_connectors-1n78.21.2` (fuzz), `flywheel_connectors-1n78.21.3` (interop) |
| **Notes** | SymbolRequest bounding and anti-amplification rules are NORMATIVE. Control-plane object model is canonical; retention classes are enforced. SimulateRequest/Response + CostEstimate are NORMATIVE control-plane objects. |

---

## §10: Connector Model

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.20` (SDK: standard method surface, typed schemas), `flywheel_connectors-1n78.33` (connector state: persisted, snapshot, singleton-writer leases), `flywheel_connectors-1n78.34` (leases), `flywheel_connectors-1n78.31` (provisioning automation patterns) |
| **Tests** | `flywheel_connectors-1n78.21.5` (mechanical compliance runner), `flywheel_connectors-h32` (connector test standards) |
| **Notes** | Connectors implement standard methods. Stateful connectors externalize canonical state to mesh. |

---

## §11: Connector Manifest

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.19` (manifest TOML + embedding + validation), `flywheel_connectors-1n78.18` (sandbox profiles + egress enforcement), `flywheel_connectors-1n78.27` (supply chain verification, mirroring) |
| **Tests** | `flywheel_connectors-1n78.21.5` (static + dynamic checks) |
| **Notes** | Manifests extractable without execution (`--manifest`). Sandbox profiles + network guard are enforceable. |

---

## §12: Automation Recipes

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.31` (recipe model + provisioning interface) |
| **Tests** | Connector-specific provisioning test beads (per connector epic) |
| **Notes** | Minimize human prompts; automate OAuth/webhook setup. |

---

## §13: Registry and Supply Chain

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.27` (verify/install/mirror), `flywheel_connectors-1n78.27.2` (optional transparency/TUF/sigstore), `flywheel_connectors-1n78.9` (revocation of binaries) |
| **Tests** | `flywheel_connectors-1n78.27.1` (registry verification + mirroring tests) |
| **Notes** | Registries are sources, not dependencies. Binaries are content-addressed and can be symbol-distributed. |

---

## §14: Lifecycle Management

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-y1q8` (connector activate/update/rollback + crash-loop detection), `flywheel_connectors-1n78.9` (revocation objects/heads/freshness), `flywheel_connectors-7isb` (checkpoint/frontier advancement protocol), `flywheel_connectors-1n78.27` (supply chain + install/mirror + update/rollback artifacts) |
| **Tests** | `flywheel_connectors-dlfp` (lifecycle activation/update/rollback tests), `flywheel_connectors-1n78.36.3` (revocation E2E) |
| **Notes** | Activation MUST fail closed unless verification + policy ceilings + sandbox creation succeed. Revocations enforced before use; freshness policy is mechanical. Fork detection halts advancement unless explicit degraded mode. |

---

## §15: Device-Aware Execution

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.34` (leases), `flywheel_connectors-wwq8` (DeviceProfile schema + fitness), `flywheel_connectors-1n78.17.6` (execution planner) |
| **Tests** | `flywheel_connectors-1n78.34.1` (lease semantics tests), `flywheel_connectors-u4ej` (DeviceProfile unit tests) |
| **Notes** | Leases are fenced locks; quorum rules are explicit. Planner decisions are explainable and deterministic. |

---

## §16: Computation Migration (Full Profile)

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-6o25.4` (migration protocol) |
| **Tests** | `flywheel_connectors-fbql` (migration tests) |
| **Notes** | Checkpoint objects + lease handoff before resume. Fail closed under partition to prevent double execution. |

---

## §17: Security Model

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.18` (sandbox/egress), `flywheel_connectors-1n78.25` (trust/quorum/degraded mode), `flywheel_connectors-1n78.27` (supply chain), `flywheel_connectors-6o25.*` (full-profile hardening) |
| **Tests** | `flywheel_connectors-1n78.21.2` (fuzz/adversarial) |
| **Notes** | Defense-in-depth; threshold secrets; source diversity. |

---

## §18: Trust Model and Byzantine Assumptions

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.25` (n/f assumptions, quorum rules, degraded mode semantics) |
| **Tests** | `flywheel_connectors-1n78.25.*` (tests as defined under that bead) |
| **Notes** | Explicit degraded mode; fail-closed semantics for high-safety tiers. |

---

## §19: Tailscale Integration

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.16` (tailscale client + tag mapping), `flywheel_connectors-1n78.32` (device enrollment/removal), `flywheel_connectors-1n78.17.2` (DERP/Funnel policy controls) |
| **Tests** | `flywheel_connectors-wyz0` (tailscale integration unit tests) |
| **Notes** | Enrollment/removal is normative; removal triggers revocations. |

---

## §20: RaptorQ Deep Integration

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.37` (epoch event buffer + binary distribution), `flywheel_connectors-1n78.14` (RaptorQ primitives), `flywheel_connectors-1n78.15` (stores/repair/quarantine), `flywheel_connectors-1n78.27` (binary verification + mirroring) |
| **Tests** | `flywheel_connectors-1n78.37.1` (epoch/binary distribution tests), `flywheel_connectors-1n78.36.6` (E2E epoch replay + mesh-only install) |
| **Notes** | Epoch finalization must be deterministic and bounded. Binary bytes are untrusted until verified; quarantine-by-default. |

---

## §21: Offline Access

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-31c7` (offline capability + predictive pre-staging), `flywheel_connectors-1n78.15` (background repair + coverage evaluation) |
| **Tests** | `flywheel_connectors-f3xi` (offline capability unit tests), `flywheel_connectors-1n78.36.5` (E2E offline/repair) |
| **Notes** | Coverage is measurable; repair is periodic and bounded. |

---

## §22: Agent Integration

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.30` (introspection + MCP descriptors) |
| **Tests** | `flywheel_connectors-1n78.36.*` (E2E scripts validate explainability) |
| **Notes** | Agents can query schemas/ops/caps; MCP integration is first-class. |

---

## §23: Observability and Audit

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.28` (structured logs + metrics), `flywheel_connectors-1n78.11` (audit chain + DecisionReceipt), `flywheel_connectors-1n78.35` (testing/logging requirements) |
| **Tests** | `flywheel_connectors-1n78.36.*` (E2E requires structured logs) |
| **Notes** | Structured logs MUST include trace/correlation. Audit chain advancement requires quorum unless degraded. |

---

## §24: Error Taxonomy

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.29` (FCP-XXXX ranges, retry semantics, AI recovery hints) |
| **Tests** | All E2E harness scripts (error codes must be stable) |
| **Notes** | Retryable semantics are explicit; recovery hints are safe (no secret leakage). |

---

## §25: Implementation Phases

| Aspect | Details |
|--------|---------|
| **Owners** | MVP: `flywheel_connectors-1n78` + children, Full: `flywheel_connectors-6o25` + children |
| **Tests** | `flywheel_connectors-1n78.21` (suite distinguishes MVP vs Full) |
| **Notes** | Profiles are conformance targets; tests should be profile-aware. |

---

## §27: Conformance Requirements

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.21.1` (CDDL + golden vectors), `flywheel_connectors-1n78.21.2` (fuzz), `flywheel_connectors-1n78.21.3` (interop), `flywheel_connectors-1n78.21.4` (system E2E harness), `flywheel_connectors-1n78.21.5` (mechanical connector compliance) |
| **Tests** | Same as owners |
| **Notes** | MUST ship CDDL for normative CBOR objects. MUST include fuzz targets for parse/verify hot surfaces. |

---

## Appendices (A–G)

| Appendix | Owner Bead | Notes |
|----------|------------|-------|
| A: FZPF v0.1 JSON Schema | `flywheel_connectors-1n78.21.6` | |
| B: RaptorQ configuration + chunking | `flywheel_connectors-1n78.14` | |
| C: Reference connector patterns | `flywheel_connectors-lszk.5` | |
| D: SDK crates list | `flywheel_connectors-1n78.2`, `flywheel_connectors-1n78.20` | Informational |
| E: Conformance checklist | `flywheel_connectors-1n78.21`, `flywheel_connectors-1n78.21.5`, `flywheel_connectors-h32` | |
| F: Golden decision vectors | `flywheel_connectors-1n78.26.1`, `flywheel_connectors-1n78.21.1` | |
| G: Transport priority | `flywheel_connectors-1n78.17.2` | |

---

# B) README Coverage Matrix — `README.md`

The README is an overview; **when it conflicts with `FCP_Specification_V2.md`, implement the Spec**.

---

## TL;DR / Vision / Three Axioms

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78` (MVP epic), `flywheel_connectors-1n78.1` (this matrix) |
| **Tests** | `flywheel_connectors-1n78.21.*` (golden + fuzz + interop + system E2E) |
| **Notes** | Axioms are enforced via canonical objects + symbol distribution + explicit authority chains (not by convention). |

---

## Security Invariants

| Invariant | Owner Beads |
|-----------|-------------|
| Single-zone binding | `flywheel_connectors-1n78.20`, `flywheel_connectors-1n78.33`, `flywheel_connectors-1n78.26` |
| Default deny | `flywheel_connectors-1n78.7`, `flywheel_connectors-1n78.26`, `flywheel_connectors-1n78.21.5` |
| No cross-connector calling | `flywheel_connectors-oip0` (host/gateway orchestrator) |
| Threshold owner key (recommended) | `flywheel_connectors-6o25.6` (Full profile) |
| Threshold secrets (Full) | `flywheel_connectors-6o25.1` |
| Revocation enforcement | `flywheel_connectors-1n78.9` |
| Audit + receipts | `flywheel_connectors-1n78.10`, `flywheel_connectors-1n78.11` |

**Tests**: `flywheel_connectors-1n78.36.*` (vertical slice E2E), `flywheel_connectors-1n78.21.4` (system E2E harness)

**Notes**: These are mechanical invariants; every denial must be explainable with reason codes + evidence.

---

## Zone Architecture / Provenance and Taint

| Aspect | Owner Beads |
|--------|-------------|
| Zones + policy | `flywheel_connectors-1n78.26` |
| Zone crypto + key distribution | `flywheel_connectors-1n78.6` |
| Approval + taint | `flywheel_connectors-1n78.8` |
| Tailscale tag mapping | `flywheel_connectors-1n78.16` |

**Tests**: `flywheel_connectors-1n78.26.1` (policy decision vectors), `flywheel_connectors-1n78.36.4` (taint/approval E2E)

---

## Symbol Layer / FCPS / FCPC / Session Authentication

| Aspect | Owner Beads |
|--------|-------------|
| FCPS | `flywheel_connectors-1n78.12` |
| FCPC | `flywheel_connectors-1n78.13` |
| Sessions | `flywheel_connectors-1n78.24` |
| RaptorQ + chunking | `flywheel_connectors-1n78.14` |

**Tests**: `flywheel_connectors-1n78.21.1` (golden), `flywheel_connectors-1n78.21.2` (fuzz), `flywheel_connectors-1n78.21.3` (interop)

---

## Mesh Architecture / Enrollment

| Aspect | Owner Beads |
|--------|-------------|
| MeshNode + routing/gossip/admission | `flywheel_connectors-1n78.17` |
| Enrollment + key lifecycle | `flywheel_connectors-1n78.32` |
| Trust/quorum model | `flywheel_connectors-1n78.25` |

**Tests**: `flywheel_connectors-1n78.17.1` (mesh integration), `flywheel_connectors-1n78.21.4` (system E2E harness)

---

## Connector Binary Structure / Sandbox / Connector State

| Aspect | Owner Beads |
|--------|-------------|
| Manifest + embedding | `flywheel_connectors-1n78.19` |
| Sandbox + egress proxy | `flywheel_connectors-1n78.18` |
| SDK standard method surface | `flywheel_connectors-1n78.20` |
| Connector state + leases | `flywheel_connectors-1n78.33`, `flywheel_connectors-1n78.34` |

**Tests**: `flywheel_connectors-1n78.18.1` (sandbox allow/deny), `flywheel_connectors-1n78.21.5` (mechanical connector compliance)

---

## Security Model (Threat Model / Receipts / Revocation / Audit)

| Aspect | Owner Beads |
|--------|-------------|
| Threat model + risk surfaces | `flywheel_connectors-1n78.25`, `flywheel_connectors-1n78.17.3` |
| Threshold secrets (Full) | `flywheel_connectors-6o25.1` |
| Operation receipts | `flywheel_connectors-1n78.10` |
| Audit + explainability | `flywheel_connectors-1n78.11` |
| Revocation | `flywheel_connectors-1n78.9` |

**Tests**:
- `flywheel_connectors-q10z` (trust/quorum unit tests)
- `flywheel_connectors-36x3` (revocation unit/adversarial tests)
- `flywheel_connectors-57x7` (exactly-once semantics receipt tests)
- `flywheel_connectors-un5y` (audit chain unit tests)
- `flywheel_connectors-1n78.36.3` (revocation E2E)

---

## Connectors (Tiering + Portfolio)

| Aspect | Owner Beads |
|--------|-------------|
| Portfolio strategy + prioritization | `flywheel_connectors-epqh` |
| Connector library epic | `flywheel_connectors-lszk` |
| Registry (distribution/verification) | `flywheel_connectors-1n78.27` |

**Tests**: `flywheel_connectors-1n78.27.1` (registry tests), `flywheel_connectors-h32` (connector testing standard), `flywheel_connectors-e3i9` (connector E2E framework), `flywheel_connectors-1n78.21.5` (mechanical compliance runner)

**Notes**: Tiering is roadmap guidance; every connector must meet the same mechanical FCP2 compliance requirements. No connector ships with embedded pricing tables; emit usage metrics + optional explicit `CostEstimate` only.

---

## Performance Targets

| Aspect | Owner Beads |
|--------|-------------|
| Benchmarks + budgets | `flywheel_connectors-1n78.23` |

**Tests**: `flywheel_connectors-1n78.23.*` (bench artifacts)

**Budgets include**: cold start, memory idle, request overhead, binary size.

---

## Creating a New Connector

| Aspect | Owner Beads |
|--------|-------------|
| `fcp new` scaffold + compliance precheck | `flywheel_connectors-iqrb.7` |
| Connector planning template | `flywheel_connectors-lszk.5` |
| Connector compliance checklist | `flywheel_connectors-dz01` |
| Connector testing standard | `flywheel_connectors-h32` |
| Mechanical compliance runner | `flywheel_connectors-1n78.21.5` |
| Manifest requirements | `flywheel_connectors-1n78.19` |
| SDK surface | `flywheel_connectors-1n78.20` |

**Notes**: New connectors must be reviewable for compliance mechanically (static+dynamic) without manual "trust me" steps. Prefer `fcp new` to enforce safe defaults.

---

# C) Connector Reference Doc Coverage — `docs/fcp_model_connectors_rust.md`

This doc is the connector-facing "how to implement correctly in Rust" view.

---

| Section | Owner Beads |
|---------|-------------|
| §1: Scope and Alignment | `flywheel_connectors-1n78.1`, `flywheel_connectors-lszk.5` |
| §2: Connector Model and Lifecycle | `flywheel_connectors-1n78.20`, `flywheel_connectors-1n78.33`, `flywheel_connectors-1n78.34` |
| §3: Control-Plane Protocol (FCP2-SYM) | `flywheel_connectors-1n78.12`, `flywheel_connectors-1n78.13`, `flywheel_connectors-1n78.24` |
| §4: Canonical Types and Serialization | `flywheel_connectors-1n78.3`, `flywheel_connectors-1n78.4`, `flywheel_connectors-1n78.6` |
| §5: Zones, Approval Tokens, Provenance, and Taint | `flywheel_connectors-1n78.26`, `flywheel_connectors-1n78.8` |
| §6: Capability System | `flywheel_connectors-1n78.7`, `flywheel_connectors-1n78.18` |
| §7: Invoke, Receipts, and Event Envelopes | `flywheel_connectors-1n78.10`, `flywheel_connectors-1n78.20` |
| §8: Streaming, Replay, and Acks | `flywheel_connectors-1n78.20.1`, `flywheel_connectors-1n78.33` |
| §9: Error Taxonomy | `flywheel_connectors-1n78.29` |
| §10: Agent Integration | `flywheel_connectors-1n78.30` |
| §11: Connector Manifest and Embedding | `flywheel_connectors-1n78.19` |
| §12: Sandbox Profiles and Enforcement | `flywheel_connectors-1n78.18` |
| §13: Automation Recipes and Provisioning | `flywheel_connectors-1n78.31` |
| §14: Registry and Supply Chain | `flywheel_connectors-1n78.27` |
| §15: Lifecycle Management and Revocation | `flywheel_connectors-1n78.9` |
| §16: Device-Aware Execution and Leases | `flywheel_connectors-1n78.34`, `flywheel_connectors-wwq8` |
| §17: Observability and Audit | `flywheel_connectors-1n78.28`, `flywheel_connectors-1n78.11` |
| §18: Connector Archetypes (V2) and Patterns | `flywheel_connectors-lszk.5`, `flywheel_connectors-1n78.20` |
| §19: Rust Connector Skeleton (SDK-aligned) | `flywheel_connectors-1n78.2`, `flywheel_connectors-1n78.20`, `flywheel_connectors-lszk.5` |
| §20: Conformance Checklist (Connector) | `flywheel_connectors-h32`, `flywheel_connectors-1n78.21.5`, `flywheel_connectors-lszk.5` |

---

## Quick Reference: Key Owner Beads by Category

### Core Infrastructure
| Category | Primary Beads |
|----------|---------------|
| Workspace/CI | `flywheel_connectors-1n78.2` |
| Canonical Serialization | `flywheel_connectors-1n78.3` |
| IDs/Headers | `flywheel_connectors-1n78.4` |
| Crypto Primitives | `flywheel_connectors-1n78.5` |

### Security & Policy
| Category | Primary Beads |
|----------|---------------|
| Zones/Policy | `flywheel_connectors-1n78.26` |
| Capabilities | `flywheel_connectors-1n78.7` |
| Taint/Approval | `flywheel_connectors-1n78.8` |
| Revocation | `flywheel_connectors-1n78.9` |
| Sandbox/Egress | `flywheel_connectors-1n78.18` |

### Protocols
| Category | Primary Beads |
|----------|---------------|
| FCPS | `flywheel_connectors-1n78.12` |
| FCPC | `flywheel_connectors-1n78.13` |
| Sessions | `flywheel_connectors-1n78.24` |
| RaptorQ | `flywheel_connectors-1n78.14` |

### Connector SDK
| Category | Primary Beads |
|----------|---------------|
| SDK Methods | `flywheel_connectors-1n78.20` |
| Manifest | `flywheel_connectors-1n78.19` |
| State Model | `flywheel_connectors-1n78.33` |
| Leases | `flywheel_connectors-1n78.34` |

### Conformance & Testing
| Category | Primary Beads |
|----------|---------------|
| Golden Vectors | `flywheel_connectors-1n78.21.1` |
| Fuzz Testing | `flywheel_connectors-1n78.21.2` |
| Interop | `flywheel_connectors-1n78.21.3` |
| System E2E | `flywheel_connectors-1n78.21.4` |
| Connector Compliance | `flywheel_connectors-1n78.21.5` |
| Connector Testing Standard | `flywheel_connectors-h32` |

---

## Acceptance Criteria

This standard is satisfied when:

- [ ] All spec sections map to owning beads
- [ ] All README sections map to owning beads
- [ ] All connector doc sections map to owning beads
- [ ] Engineers can implement FCP2 by following beads without rereading docs
- [ ] Missing requirements are discovered and tracked via bead updates

---

## References

- FCP_Specification_V2.md (canonical spec)
- README.md (overview)
- docs/fcp_model_connectors_rust.md (connector implementation guide)
- STANDARD_Connector_Compliance.md (compliance checklist)
- STANDARD_Connector_Testing.md (connector testing requirements)
- STANDARD_Testing_Logging.md (testing requirements)
