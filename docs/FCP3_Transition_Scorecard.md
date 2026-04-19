# FCP3 Transition Scorecard

> **Bead**: `flywheel_connectors-mm3q4` — [FCP3/P1.5]
> **Author**: WhiteCompass (SunnyMoose session, 2026-03-27)
> **Last reconciled**: SunnyMoose, 2026-04-07 (pl7pj.3)
> **Purpose**: Living scorecard tracking legacy buckets, shims, mesh-first cutover holdouts, and migration status.

---

## Scorecard Summary

| Category | Total Items | Migrated | Pending | Blocked |
|----------|------------|----------|---------|---------|
| Legacy broad buckets | 3 | 3 | 0 | 0 |
| Compatibility shims | 2 | 0 | 2 | 0 |
| Mesh-first cutover holdouts | 8 | 5 | 3 | 0 |
| Forbidden overlap debt | 7 | 4 | 3 | 0 |
| Type MOVE candidates | 9 | 6 | 3 | 0 |

**Overall Progress**: 18 / 29 items migrated (62%)

---

## 1. Legacy Broad Buckets (to be carved)

| Bucket | Current Location | Target | Status | Tracking Bead |
|--------|-----------------|--------|--------|--------------|
| Execution types in fcp-core | fcp-core/src/protocol.rs, connector.rs | fcp-kernel | MIGRATED (fcp-kernel/src/execution_control.rs, 21KB) | whkbp (CLOSED) |
| Policy types in fcp-core | fcp-core/src/policy.rs, capability.rs | fcp-policy | MIGRATED (fcp-policy/src/lib.rs, 6.1KB) | q1d0x (CLOSED) |
| Evidence types in fcp-core | fcp-core/src/audit.rs, health.rs, checkpoint.rs | fcp-evidence | MIGRATED (fcp-evidence/src/lib.rs, 4.4KB) | 2m2hl (CLOSED) |

---

## 2. Compatibility Shims

| Shim | Location | Purpose | Delete After | Status |
|------|----------|---------|-------------|--------|
| ConnectorErrorMapping | fcp-sdk/src/migration.rs | V2->V3 error mapping bridge | P4 convergence | ACTIVE (all 150 connectors use it) |
| ConnectorRuntime | fcp-sdk/src/migration.rs | V2->V3 runtime bridge | P4 convergence | ACTIVE (all 150 connectors use it) |

---

## 3. Mesh-First Cutover Holdouts

The teaching-surface rewrite bead `flywheel_connectors-z1nkz.1` is already
closed. The rows below are not onboarding prose that still tells contributors
to build host-first systems; they are runtime and ownership seams that still
block the final mesh-first cutover.

| Holdout | Current Owner | Target Owner | Impact | Status |
|---------|--------------|-------------|--------|--------|
| Enforcement pipeline ordering | fcp-host (enforcement.rs) | fcp-core (canonical order) | SDKs can't replicate enforcement | PENDING |
| Health aggregation model | fcp-host (health.rs) | fcp-core (HealthAggregation) | SDKs can't aggregate health | PENDING |
| Rollout decision logic | fcp-host (rollout.rs) | fcp-kernel (RolloutDecision) | Non-host platforms can't evaluate rollouts | MIGRATED (fcp-kernel/src/execution_control.rs) |
| Progress emission | fcp-host (progress.rs) | fcp-kernel (ProgressUpdate) | Agents can't consume progress generically | MIGRATED (fcp-kernel/src/execution_control.rs) |
| Cancellation semantics | fcp-host (cancellation.rs) | fcp-kernel (CancelReason) | SDKs can't implement cancel | MIGRATED (fcp-kernel/src/execution_control.rs) |
| Readiness model | fwc (readiness.rs) | fcp-core (ReadinessContract) | Multiple CLIs can't share readiness | MIGRATED (fwc/src/truth.rs KnowledgeState) |
| Policy manipulation | fwc (policy_cmd.rs) | fcp-host RPC | CLI bypasses host for policy | MIGRATED (fwc routes through --host) |
| Credential storage | fwc (credential_store.rs) | fcp-core (CredentialStore trait) | No standard credential interface | PENDING |

---

## 4. Forbidden Overlap Debt (from P1.2)

| ID | Overlap | Owner Map Resolution | Status |
|----|---------|---------------------|--------|
| F1 | Health aggregation (fcp-core vs fcp-host) | fcp-core owns aggregation model | PENDING |
| F2 | Rollout decisions (fcp-core vs fcp-host) | Move to fcp-kernel | RESOLVED (RolloutDecision in fcp-kernel) |
| F3 | Enforcement ordering (fcp-host only) | Declare in fcp-core | PENDING |
| F4 | Progress/cancellation (fcp-host only) | Move to fcp-kernel | RESOLVED (CancelReason, ProgressUpdate in fcp-kernel) |
| F5 | Readiness duplication (fcp-core vs fwc) | fwc truth.rs owns contract | RESOLVED (KnowledgeState taxonomy) |
| F6 | CLI policy manipulation (fwc direct crypto) | Route through fcp-host RPC | RESOLVED (fwc uses --host for policy) |
| F7 | Credential store (fwc only) | Define trait in fcp-core | PENDING |

---

## 5. Type MOVE Candidates

| Type | From | To | Phase | Status |
|------|------|----|-------|--------|
| CancelReason | fcp-host::cancellation | fcp-kernel | P2.1 | MIGRATED |
| CleanupBehavior | fcp-host::cancellation | fcp-kernel | P2.1 | MIGRATED |
| ProgressUpdate | fcp-host::progress | fcp-kernel | P2.1 | MIGRATED |
| RolloutDecision | fcp-host::rollout | fcp-kernel | P2.1 | MIGRATED |
| RolloutEvidence | fcp-host::rollout | fcp-kernel | P2.1 | MIGRATED |
| RolloutObservation | fcp-host::rollout | fcp-kernel | P2.1 | MIGRATED |
| EnforcementCheckOrder | (new) | fcp-core | P2.1 | PENDING |
| ReadinessContract | (new) | fcp-core | P2.2 | PENDING (fwc truth.rs has KnowledgeState taxonomy) |
| CredentialStore trait | (new) | fcp-core | P2.3 | PENDING |

---

## Deletion-Wave Status

This table is the quick audit entrypoint for the `flywheel_connectors-z1nkz`
family. It tells reviewers which deletion wave already has preservation
artifacts and which wave still depends on open cutover work.

| Wave | Status | Primary artifacts | Notes |
|------|--------|-------------------|-------|
| `flywheel_connectors-z1nkz.1` teaching rewrite | CLOSED | README framing, `docs/OPERATIONAL_MODEL_VERSIONS.md`, `docs/FWC_Host_First_Truthfulness_Playbook.md`, `crates/fwc/docs/truthfulness-model.md` | Surviving docs now teach host-backed operation as a transitional boundary, not the end-state architecture |
| `flywheel_connectors-z1nkz.2` runtime/control-plane deletion | IN PROGRESS | `docs/FCP3_Retirement_Kill_List.md`, scoreboard row-state updates, replacement-proof citations in those rows | Runtime seam deletion is still active, so the parent phase cannot close yet |
| `flywheel_connectors-z1nkz.3` workflow-preservation index | OPEN | `docs/FCP3_Acceptance_Contracts.md`, `docs/FCP3_Pre_Cutover_Baseline.md`, this scorecard | Preservation anchors now exist, but the final indexed review bundle still depends on `.2` landing |

---

## Proof Artifacts

Key evidence backing this scorecard:
- **Crate carving**: fcp-kernel (38KB), fcp-policy (6.1KB), fcp-evidence (4.4KB) all exist with tests
- **Type MOVEs**: `CancelReason`, `CleanupBehavior`, `ProgressUpdate`, `RolloutDecision`, `RolloutEvidence`, `RolloutObservation` all in `fcp-kernel/src/execution_control.rs`
- **E2E proof**: 423bu.3 epic (10 children CLOSED) - full invoke flow proven
- **Live verification**: kzabz epic (5 children CLOSED) - 7 connectors verified
- **Performance**: tr2xx epic (6 children CLOSED) - benchmarks + CI gate
- **Gossip upgrade**: br21t epic (6 children CLOSED) - XOR filter + IBLT production
- **Teaching-surface rewrite**: `flywheel_connectors-z1nkz.1` (CLOSED, 2026-04-11) - surviving docs now frame host-first as a transitional boundary rather than the long-term architecture
- **Runtime scaffolding deletion**: `flywheel_connectors-z1nkz.2` (2026-04-19) - deleted deprecated `ChaCha20Nonce::generate()`, migrated raw `asupersync::signal` in fcp-host to `fcp_async_core::signal`, cleaned raw `asupersync::` test imports in fcp-graphql, updated kill list scoreboard from `owner-bead-closed` to `deleted`/`quarantine-blessed` reflecting actual code state
- **Bead graph**: 68 open beads remaining (from 2200+), 24 actionable

---

## Update Protocol

This scorecard should be updated:
- After each crate carving (P2.x) -- mark items as MIGRATED
- After each compatibility shim removal -- mark as DELETED
- After each mesh-first cutover holdout migration -- mark as MIGRATED
- After each forbidden overlap resolution -- mark as RESOLVED

**Format**: `| item | ... | MIGRATED (2026-XX-XX, commit abc123) |`

---

*This is a living document. Keep it current as the FCP3 migration progresses.*
