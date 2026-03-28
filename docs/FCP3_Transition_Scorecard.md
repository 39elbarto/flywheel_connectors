# FCP3 Transition Scorecard

> **Bead**: `flywheel_connectors-mm3q4` — [FCP3/P1.5]
> **Author**: WhiteCompass (SunnyMoose session, 2026-03-27)
> **Purpose**: Living scorecard tracking legacy buckets, shims, host-first teaching, and migration status.

---

## Scorecard Summary

| Category | Total Items | Migrated | Pending | Blocked |
|----------|------------|----------|---------|---------|
| Legacy broad buckets | 3 | 0 | 3 | 0 |
| Compatibility shims | 2 | 0 | 2 | 0 |
| Host-first teaching | 8 | 0 | 8 | 0 |
| Forbidden overlap debt | 7 | 0 | 7 | 0 |
| Type MOVE candidates | 9 | 0 | 9 | 0 |

**Overall Progress**: 0 / 29 items migrated (0%)

---

## 1. Legacy Broad Buckets (to be carved)

| Bucket | Current Location | Target | Status | Tracking Bead |
|--------|-----------------|--------|--------|--------------|
| Execution types in fcp-core | fcp-core/src/protocol.rs, connector.rs | fcp-kernel | PENDING | P2.1 (whkbp) |
| Policy types in fcp-core | fcp-core/src/policy.rs, capability.rs | fcp-policy | PENDING | P2.2 (q1d0x) |
| Evidence types in fcp-core | fcp-core/src/audit.rs, health.rs, checkpoint.rs | fcp-evidence | PENDING | P2.3 (2m2hl) |

---

## 2. Compatibility Shims

| Shim | Location | Purpose | Delete After | Status |
|------|----------|---------|-------------|--------|
| ConnectorErrorMapping | fcp-sdk/src/migration.rs | V2→V3 error mapping bridge | P4 convergence | ACTIVE |
| ConnectorRuntime | fcp-sdk/src/migration.rs | V2→V3 runtime bridge | P4 convergence | ACTIVE |

---

## 3. Host-First Teaching (to become mesh-native)

| Teaching | Current Owner | Target Owner | Impact | Status |
|----------|--------------|-------------|--------|--------|
| Enforcement pipeline ordering | fcp-host (enforcement.rs) | fcp-core (canonical order) | SDKs can't replicate enforcement | PENDING |
| Health aggregation model | fcp-host (health.rs) | fcp-core (HealthAggregation) | SDKs can't aggregate health | PENDING |
| Rollout decision logic | fcp-host (rollout.rs) | fcp-core (RolloutDecision) | Non-host platforms can't evaluate rollouts | PENDING |
| Progress emission | fcp-host (progress.rs) | fcp-core (ProgressUpdate) | Agents can't consume progress generically | PENDING |
| Cancellation semantics | fcp-host (cancellation.rs) | fcp-core (CancelReason) | SDKs can't implement cancel | PENDING |
| Readiness model | fwc (readiness.rs) | fcp-core (ReadinessContract) | Multiple CLIs can't share readiness | PENDING |
| Policy manipulation | fwc (policy_cmd.rs) | fcp-host RPC | CLI bypasses host for policy | PENDING |
| Credential storage | fwc (credential_store.rs) | fcp-core (CredentialStore trait) | No standard credential interface | PENDING |

---

## 4. Forbidden Overlap Debt (from P1.2)

| ID | Overlap | Owner Map Resolution | Status |
|----|---------|---------------------|--------|
| F1 | Health aggregation (fcp-core vs fcp-host) | fcp-core owns aggregation model | PENDING |
| F2 | Rollout decisions (fcp-core vs fcp-host) | Move to fcp-core | PENDING |
| F3 | Enforcement ordering (fcp-host only) | Declare in fcp-core | PENDING |
| F4 | Progress/cancellation (fcp-host only) | Move to fcp-core | PENDING |
| F5 | Readiness duplication (fcp-core vs fwc) | fcp-core owns contract | PENDING |
| F6 | CLI policy manipulation (fwc direct crypto) | Route through fcp-host RPC | PENDING |
| F7 | Credential store (fwc only) | Define trait in fcp-core | PENDING |

---

## 5. Type MOVE Candidates

| Type | From | To | Phase | Status |
|------|------|----|-------|--------|
| CancelReason | fcp-host::cancellation | fcp-core | P2.1 | PENDING |
| CleanupBehavior | fcp-host::cancellation | fcp-core | P2.1 | PENDING |
| ProgressUpdate | fcp-host::progress | fcp-core | P2.1 | PENDING |
| RolloutDecision | fcp-host::rollout | fcp-core | P2.1 | PENDING |
| RolloutEvidence | fcp-host::rollout | fcp-core | P2.1 | PENDING |
| RolloutObservation | fcp-host::rollout | fcp-core | P2.1 | PENDING |
| EnforcementCheckOrder | (new) | fcp-core | P2.1 | PENDING |
| ReadinessContract | (new) | fcp-core | P2.2 | PENDING |
| CredentialStore trait | (new) | fcp-core | P2.3 | PENDING |

---

## Update Protocol

This scorecard should be updated:
- After each crate carving (P2.x) — mark items as MIGRATED
- After each compatibility shim removal — mark as DELETED
- After each host-first teaching migration — mark as MIGRATED
- After each forbidden overlap resolution — mark as RESOLVED

**Format**: `| item | ... | MIGRATED (2026-XX-XX, commit abc123) |`

---

*This is a living document. Keep it current as the FCP3 migration progresses.*
