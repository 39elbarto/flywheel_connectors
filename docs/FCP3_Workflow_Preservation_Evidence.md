# FCP3 Workflow-Preservation Evidence Index

> **Bead**: `flywheel_connectors-z1nkz.3` -- [FCP3/P7.2]
> **Author**: SunnyMoose, 2026-04-19
> **Purpose**: Indexed review bundle for every deletion wave under the
> `flywheel_connectors-z1nkz` family. Enables future reviewers to audit what
> was deleted, what replaced it, and what evidence proves the user-visible and
> operator-visible workflows survived -- without reconstructing history by hand.

---

## How to Use This Document

1. Find the deletion wave you want to audit.
2. Read the "Before" and "After" columns to understand what changed.
3. Follow the artifact pointers to verify the evidence.
4. Run the rerun commands to confirm the replacement path still works.

If any row lacks an artifact pointer or rerun command, the deletion proof is
incomplete and the row should not be treated as cleared.

---

## Deletion Wave 1: Host-First Teaching Surface Rewrite

**Bead**: `flywheel_connectors-z1nkz.1` (CLOSED 2026-04-11)
**Commit**: `cfd9c0f5`
**Agent**: SunnyMoose

### What Was Changed

Five operator-facing teaching surfaces were rewritten to stop normalizing
host-first as the permanent architecture and to elevate mesh-backed as the
converging steady-state target.

| File | Before | After |
|------|--------|-------|
| `README.md` | Taught host-first as the dominant operational mental model | Frames host-backed as a transitional provisioning boundary; adds truth hierarchy (mesh-backed > host-backed > node-local > offline) |
| `docs/OPERATIONAL_MODEL_VERSIONS.md` | V2 (MeshNative) described as "NOT YET OPERATIONAL" | V1 marked "transitional", V2 marked "converging"; post-cutover column added to deployment topology |
| `docs/FWC_Host_First_Truthfulness_Playbook.md` | Framed host-first as the default operating mode for all operators | Frames host-backed as real but transitional; cutover gates linked to scorecard |
| `crates/fwc/docs/truthfulness-model.md` | No truth hierarchy; host-first presented as the only resolved state | Truth hierarchy added with explicit confidence levels per `KnowledgeState` |
| `crates/fwc/src/main.rs` (quickstart tip) | Showed host-only framing | Updated to show truth hierarchy instead of host-only framing |

### Preserved Workflow

The operator-visible workflow is **truthful operational guidance**. Operators
can still:
- Discover what mode they are running in (host-backed vs mesh-backed)
- Understand the confidence level of any truth resolution
- Follow a clear upgrade path from host-backed to mesh-backed

The rewrite did NOT:
- Remove any operational command or capability
- Change the behavior of any fwc command
- Remove the ability to run in host-backed mode

### Rerun Commands

```bash
# Verify truth hierarchy is documented
grep -c "mesh-backed.*host-backed.*node-local.*offline" README.md
# Expected: >= 1

# Verify V1/V2 framing in operational model doc
grep -c "transitional" docs/OPERATIONAL_MODEL_VERSIONS.md
# Expected: >= 1

# Verify KnowledgeState taxonomy still works
cargo +nightly test -p fwc -- truth 2>&1 | tail -5
# Expected: test result: ok
```

### Evidence Artifacts

- Commit diff: `git show cfd9c0f5`
- Bead: `br show z1nkz.1`
- Baseline comparison: `docs/FCP3_Pre_Cutover_Baseline.md` (scenarios T1-T5)

---

## Deletion Wave 2: Runtime and Control-Plane Scaffold Deletion

**Bead**: `flywheel_connectors-z1nkz.2` (CLOSED 2026-04-19)
**Commits**: `fa2c573f` (enforcement/health/credential), `7bb4bb80` (deprecated nonce + async imports), `075eab2b` (scoreboard state), `366c753a` (truth doc cutover refs)
**Agent**: SunnyMoose

### What Was Deleted

| Item | Location | Reason Safe | Replacement |
|------|----------|-------------|-------------|
| `ChaCha20Nonce::generate()` | `fcp-crypto/src/aead.rs` | Zero callers; all code uses `XChaCha20Nonce::generate()` (192-bit nonce, safe for random generation) | `XChaCha20Nonce::generate()` -- already in use across all consumers |
| Raw `asupersync::signal::ctrl_c()` | `fcp-host/src/bin/fcp-host.rs` | Direct dependency on internal async runtime; should go through abstraction layer | `fcp_async_core::signal::ctrl_c()` -- same semantics, canonical import path |
| Raw `asupersync::{Cx, io::*}` imports | `fcp-graphql/tests/client.rs` | Direct dependency on internal async runtime in test code | `fcp_async_core::{Cx, io::*}` -- same types, canonical re-exports |

### What Was Added (Replacement Proof)

| Item | Location | Purpose |
|------|----------|---------|
| `EnforcementCheckOrder` | `fcp-core/src/lib.rs` | Canonical 11-stage enforcement pipeline registration (scorecard holdout resolved) |
| `AggregateHealthState` + 20 tests | `fcp-core/src/health.rs` | Health aggregation model now in fcp-core (scorecard holdout resolved) |
| `CredentialBackend` trait + 8 tests | `fcp-core/src/credential.rs` | Standard credential interface in fcp-core (scorecard holdout resolved) |

### Scoreboard State Updates

The kill list (`docs/FCP3_Retirement_Kill_List.md`) scoreboard was updated from
`owner-bead-closed` to reflect actual code state:

| Row | Old State | New State | Evidence |
|-----|-----------|-----------|----------|
| serve_mcp.rs tokio import | owner-bead-closed | `deleted` | Import removed in prior work |
| Hand-rolled error handling | owner-bead-closed | `deleted` | ConnectorErrorMapping adopted across all 150 connectors |
| Tokio compat handle | owner-bead-closed | `quarantine-blessed` | Required by reqwest/wiremock until those are replaced |
| TokioContextFuture | owner-bead-closed | `quarantine-blessed` | Required by axum test infrastructure |
| asupersync-tokio-compat in fcp-host | owner-bead-closed | `deleted` | fcp-host fully uses native hyper_bridge |
| Workspace tokio dep | owner-bead-closed | `quarantine-blessed` | Used by fcp-registry-server (axum) and test infra |
| Raw asupersync imports | owner-bead-closed | `mostly-deleted` | Only test-server types remain (ServerWebSocket, WebSocketAcceptor) |
| ConnectorRuntime adoption | owner-bead-closed | `deleted` | All connectors use it |

### Preserved Workflow

The operator-visible workflow is **the ability to audit what was deleted, why it
was safe, and what replaced it**. Specifically:

- **Cryptographic operations**: `XChaCha20Nonce::generate()` continues to work
  identically. No operator or connector code was affected.
- **Signal handling**: `ctrl_c()` in the fcp-host binary works identically
  through the `fcp_async_core` abstraction.
- **GraphQL test infrastructure**: Tests run identically; only import paths
  changed.
- **Enforcement, health, credentials**: New fcp-core types provide the same
  semantics that were previously scattered or missing.

### Rerun Commands

```bash
# Verify deprecated nonce is gone
cargo +nightly test -p fcp-crypto -- chacha20 2>&1 | tail -5
# Expected: test result: ok (XChaCha20 tests pass, no ChaCha20Nonce tests)

# Verify fcp-host signal handling compiles
cargo +nightly check -p fcp-host --all-targets 2>&1 | tail -3
# Expected: Finished

# Verify fcp-graphql tests compile
cargo +nightly check -p fcp-graphql --all-targets 2>&1 | tail -3
# Expected: Finished

# Verify enforcement module exists
grep -c "EnforcementCheckOrder" crates/fcp-core/src/lib.rs
# Expected: >= 1

# Verify health aggregation tests
cargo +nightly test -p fcp-core -- health 2>&1 | tail -5
# Expected: test result: ok

# Verify credential backend tests
cargo +nightly test -p fcp-core -- credential 2>&1 | tail -5
# Expected: test result: ok
```

### Evidence Artifacts

- Commit diffs: `git show fa2c573f`, `git show 7bb4bb80`
- Bead: `br show z1nkz.2`
- Kill list: `docs/FCP3_Retirement_Kill_List.md` (scoreboard table)
- Scorecard: `docs/FCP3_Transition_Scorecard.md` (deletion-wave status table)
- Baseline comparison: `docs/FCP3_Pre_Cutover_Baseline.md` (Known Transition Seams)

---

## Cross-Wave Evidence Summary

### Artifact Dependency Graph

```
docs/FCP3_Pre_Cutover_Baseline.md (frozen 2026-04-07)
  ├── defines canonical scenarios (D1-D4, L1-L3, I1-I4, T1-T5, S1-S4)
  ├── defines known transition seams
  └── defines deletion-wave preservation anchors
        ├── z1nkz.1 anchor → README, OPERATIONAL_MODEL_VERSIONS, playbooks
        ├── z1nkz.2 anchor → kill list, scorecard
        └── z1nkz.3 anchor → THIS DOCUMENT

docs/FCP3_Acceptance_Contracts.md
  ├── defines Phase 7 acceptance criteria
  ├── defines Workflow-Preservation Matrix (3 rows, all filled)
  └── defines failure diagnosis rules

docs/FCP3_Retirement_Kill_List.md
  ├── per-seam classification (DELETE/QUARANTINE/REPLACE)
  ├── scoreboard with actual code state
  └── z1nkz preservation artifact index (section)

docs/FCP3_Transition_Scorecard.md
  ├── deletion-wave status table (z1nkz.1, .2, .3)
  ├── proof artifacts list
  └── migration progress (18/29 items)

THIS DOCUMENT (docs/FCP3_Workflow_Preservation_Evidence.md)
  ├── per-wave before/after tables
  ├── per-wave rerun commands
  └── per-wave artifact pointers
```

### Completeness Check

| Wave | Before/After table | Rerun commands | Artifact pointers | Verdict |
|------|-------------------|----------------|-------------------|---------|
| z1nkz.1 teaching rewrite | Yes (5 files) | Yes (3 commands) | Yes (commit, bead, baseline) | COMPLETE |
| z1nkz.2 runtime deletion | Yes (3 deleted, 3 added, 8 scoreboard) | Yes (6 commands) | Yes (commits, bead, kill list, scorecard, baseline) | COMPLETE |
| z1nkz.3 preservation index | N/A (this document IS the artifact) | N/A | Self-referential | COMPLETE |

---

## Failure Diagnosis

- **If a rerun command fails**: the replacement path has regressed. Check the
  commit history for the affected file since the deletion wave landed.
- **If a scoreboard row says "deleted" but code still exists**: run
  `grep -r "<pattern>" crates/` to check. The scoreboard may be stale.
- **If this document references a bead that is re-opened**: the deletion wave
  was reverted and the evidence is no longer valid. Re-verify before citing.
- **If teaching docs regress to normalizing host-first**: re-read the z1nkz.1
  commit diff and compare against the current state of the five teaching
  surfaces.

---

*This document is the z1nkz.3 deliverable. It should not be modified after the
parent bead `flywheel_connectors-z1nkz` closes, except to correct factual
errors discovered during the final proof-bundle assembly (8bqme).*
