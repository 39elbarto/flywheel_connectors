# FCP3 Final Proof Manifest

> **Bead**: `flywheel_connectors-8bqme.3` -- [FCP3/P7.3]
> **Author**: SunnyMoose, 2026-04-19
> **Purpose**: canonical index for final cutover review. Every required artifact,
> rerun command, and blocking prerequisite is enumerated here so the review is
> mechanical rather than reconstructive.

---

## How to Use This Document

1. Walk the **Proof Sections** table to confirm each evidence area is covered.
2. For each section, follow the link to the section index document.
3. Use the **Consolidated Rerun Commands** to spot-check the current tree.
4. Check the **Tooling Prerequisites** before running anything remotely.
5. Walk the **Artifact Manifest** to confirm every referenced file exists.
6. Consult `docs/FCP3_Final_Closure_Checklist.md` for the gate-by-gate status.

---

## Proof Sections

| Section | Reviewer question | Section index | Source beads |
|---------|-------------------|---------------|--------------|
| Semantic and conformance | Are ownership, protocol conformance, and deletion preservation backed by executable proof? | `docs/FCP3_Semantic_Conformance_Proof_Index.md` | 8bqme.1, 0aczd.3, z1nkz.3 |
| Operational | Can the platform be deployed, diagnosed, and operated honestly after cutover? | `docs/FCP3_Operational_Proof_Index.md` | 8bqme.2, o8umn.3, pl7pj.2, pl7pj.3 |
| Performance and resource budget | Do cutover-critical flows still meet README targets with reproducible evidence? | `docs/FCP3_Benchmark_Comparison.md` | ukr33.2, ukr33.1, 34q27.3 |
| Deletion-wave preservation | Did phase-7 deletion preserve semantics and workflows? | `docs/FCP3_Workflow_Preservation_Evidence.md` | z1nkz.3, z1nkz |
| Placeholder closure | Are audited production placeholders genuinely resolved? | `flywheel_connectors-24llg.1.3` bead comments | 24llg.1.3 |
| Quarantine scoreboard | Do transition seams carry explicit state and proof obligations? | `docs/FCP3_Retirement_Kill_List.md`, `docs/FCP3_Transition_Scorecard.md` | etp8q.3, mm3q4 |
| Final closure checklist | Are all review gates satisfied? | `docs/FCP3_Final_Closure_Checklist.md` | 84phy.1 |

---

## Tooling Prerequisites

These must be satisfied before remote rerun commands will succeed.

| Prerequisite | Required state | Verification | Bead |
|--------------|---------------|--------------|------|
| rch version | >= 1.0.17 (retrieval-side `.rchignore` filtering) | `rch --version` | r4x01 |
| asupersync compile | Clean workspace check passes remotely | `rch exec -- cargo check --workspace` | mmvqb |
| `.rchignore` | 16 patterns covering `.beads/recovery_*` paths | `wc -l .rchignore` (expect 16) | r4x01 |
| Rust toolchain | Nightly, as pinned by `rust-toolchain.toml` | `rustup show active-toolchain` | -- |
| `CARGO_TARGET_DIR` | Set to isolated path to avoid lock contention | `echo $CARGO_TARGET_DIR` | -- |

---

## Consolidated Rerun Commands

### Environment setup

```bash
export CARGO_TARGET_DIR=/tmp/fcp-proof-rerun
```

### Semantic and conformance

```bash
# Owner crate re-export tests (50 tests)
rch exec -- cargo test -p fcp-kernel -p fcp-policy -p fcp-evidence --lib

# Protocol conformance vectors
rch exec -- cargo test -p fcp-conformance

# End-to-end compliance scenarios
rch exec -- cargo test -p fcp-e2e

# Ownership annotations in fcp-core
rg -c "Assigned to" crates/fcp-core/src/lib.rs
# Expected: 3 (kernel, policy, evidence)

# Crate-graph reverse deps
cargo +nightly tree -p fcp-core --depth 1 --edges reverse 2>&1 | wc -l
# Expected: ~180 lines
```

### Operational

```bash
# CLI acceptance (57 tests across 2 files)
rch exec -- cargo test -p fwc --test cual_integration
rch exec -- cargo test -p fwc --test cual_fixtures

# Host-backed integration
rch exec -- cargo test -p fcp-host --test host_connector_integration

# Replay bundle contract
rch exec -- cargo test -p fwc test_observability::full_workflow_replay_round_trip -- --exact --nocapture

# Deployment/runbook surface verification
rg -n "Production Mesh Deployment Runbook|Current Honest Topology" README.md
rg -n "Production Deployment Runbook|Bring-up verification loop" docs/FWC_Host_First_Truthfulness_Playbook.md
```

### Performance and resource budget

```bash
# Unified cutover harness (6 criterion groups)
rch exec -- cargo bench -p fcp-conformance --bench cutover_harness -- --output-format bencher

# Crypto benchmarks
rch exec -- cargo bench -p fcp-crypto --bench crypto_benchmarks

# Symbol reconstruction
rch exec -- cargo test -p fcp-raptorq

# Review thresholds: PASS if criterion delta <= +20% p50 / +50% p99
```

### Deletion-wave preservation

```bash
# Bead status verification
br show flywheel_connectors-z1nkz
br show flywheel_connectors-z1nkz.3

# Scorecard and preservation index
rg -n "Deletion-Wave Status|workflow-preservation" docs/FCP3_Transition_Scorecard.md docs/FCP3_Workflow_Preservation_Evidence.md

# Kill list seam state
rg -n "deleted|quarantine-blessed|mostly-deleted" docs/FCP3_Retirement_Kill_List.md
```

### Workspace-wide smoke check

```bash
# Full workspace build
rch exec -- cargo check --workspace --all-targets

# Full workspace clippy
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
```

---

## Artifact Manifest

Every document referenced by the proof sections, with its source bead and role.

### Primary proof documents

| Artifact | Path | Bead | Role |
|----------|------|------|------|
| **This manifest** | `docs/FCP3_Final_Proof_Manifest.md` | 8bqme.3 | Canonical review entry point |
| Semantic/conformance index | `docs/FCP3_Semantic_Conformance_Proof_Index.md` | 8bqme.1 | Ownership, protocol, preservation proof |
| Operational proof index | `docs/FCP3_Operational_Proof_Index.md` | 8bqme.2 | Deployment, operator journeys, replay bundles |
| Benchmark comparison | `docs/FCP3_Benchmark_Comparison.md` | ukr33.2 | Before/after performance proof with thresholds |
| Final closure checklist | `docs/FCP3_Final_Closure_Checklist.md` | 84phy.1 | Gate-by-gate review status |

### Supporting evidence documents

| Artifact | Path | Bead | Role |
|----------|------|------|------|
| Canonical owner map | `docs/FCP3_Canonical_Owner_Map.md` | q6huk | Semantic domain ownership declarations |
| Semantic ownership inventory | `docs/FCP3_Semantic_Ownership_Inventory.md` | 0aczd.1 | Module-level ownership classification |
| Crate-graph audit | `docs/FCP3_Crate_Graph_Audit.md` | 0aczd.3 | Import-surface and reverse-dep proof |
| Workflow preservation evidence | `docs/FCP3_Workflow_Preservation_Evidence.md` | z1nkz.3 | Per-wave before/after tables |
| Pre-cutover baseline | `docs/FCP3_Pre_Cutover_Baseline.md` | 34q27.1 | Frozen canonical scenarios |
| Retirement kill list | `docs/FCP3_Retirement_Kill_List.md` | 9syku.3.3 | Seam-by-seam deletion/quarantine state |
| Transition scorecard | `docs/FCP3_Transition_Scorecard.md` | mm3q4 | Migration progress tracking |
| Transition guardrails | `docs/FCP3_Transition_Guardrails.md` | hattj | Anti-regression rules |
| Acceptance contracts | `docs/FCP3_Acceptance_Contracts.md` | xn3h3 | Per-phase proof obligations |
| Operational model versions | `docs/OPERATIONAL_MODEL_VERSIONS.md` | -- | V1/V2 operating model definitions |
| Truthfulness playbook | `docs/FWC_Host_First_Truthfulness_Playbook.md` | 1g7z0.29.8 | Operator truth contracts and deployment |
| Consumer rewiring guide | `docs/FCP3_Consumer_Rewiring_Guide.md` | d8jbq | Import migration instructions |

### Code-level proof surfaces

| Surface | Path | Test count | Role |
|---------|------|------------|------|
| Owner crate re-exports | `crates/fcp-kernel/src/lib.rs` | 32 | Execution lifecycle ownership proof |
| Owner crate re-exports | `crates/fcp-policy/src/lib.rs` | 11 | Zone/capability/trust ownership proof |
| Owner crate re-exports | `crates/fcp-evidence/src/lib.rs` | 7 | Audit/revocation/object ownership proof |
| Conformance vectors | `crates/fcp-conformance/src/vectors/*.rs` | 15 modules | Protocol golden vectors |
| Conformance tests | `crates/fcp-conformance/tests/*.rs` | ~1075 | Protocol and integration conformance |
| CLI acceptance | `crates/fwc/tests/cual_integration.rs` | 48 | Operator truth classification |
| CLI fixtures | `crates/fwc/tests/cual_fixtures.rs` | 9 | Fixture catalog validation |
| Cutover harness | `crates/fcp-conformance/benches/cutover_harness.rs` | 6 groups | Criterion benchmark harness |
| Crypto benchmarks | `crates/fcp-crypto/benches/crypto_benchmarks.rs` | -- | Ed25519, HPKE, AEAD benchmarks |
| Test observability | `crates/fwc/src/test_observability.rs` | -- | Replay bundle contract enforcement |
| Ownership annotations | `crates/fcp-core/src/lib.rs` | -- | Module-to-owner classification |

---

## Bead Dependency Chain

All blocking beads for this manifest are closed.

| Bead | Title | Status | Closed |
|------|-------|--------|--------|
| mmvqb | asupersync compile break | CLOSED | 2026-04-19 |
| r4x01 | rch artifact retrieval overflow | CLOSED | 2026-04-19 |
| ukr33.2 | Before/after benchmark comparison | CLOSED | 2026-04-19 |
| 8bqme.1 | Semantic/conformance evidence index | CLOSED | 2026-04-19 |
| 8bqme.2 | Operational evidence index | CLOSED | 2026-04-19 |

### Upstream closed dependencies (transitive)

| Bead | Title | Closed |
|------|-------|--------|
| 0aczd | Retire fcp-core as semantic junk drawer | 2026-04-19 |
| 0aczd.1 | fcp-core semantic ownership inventory | 2026-04-19 |
| 0aczd.2 | Blur module re-exports to owner crates | 2026-04-19 |
| 0aczd.3 | Crate-graph and import-surface audit | 2026-04-19 |
| z1nkz | Delete obsolete teaching paths and scaffolding | 2026-04-19 |
| z1nkz.1 | Teaching surface rewrite | 2026-04-10 |
| z1nkz.2 | Runtime scaffolding deletion | 2026-04-19 |
| z1nkz.3 | Workflow-preservation evidence | 2026-04-19 |
| ukr33 | Performance and resource-budget proof | 2026-04-19 |
| ukr33.1 | Repeatable benchmark harness | 2026-04-11 |
| 34q27 | Pre-cutover benchmark baseline | 2026-04-07 |
| o8umn.3 | Operator journey snapshot/transcript proof | 2026-04-06 |
| pl7pj.2 | Production deployment guide | 2026-04-06 |
| pl7pj.3 | Scorecard reconciliation | 2026-04-07 |
| 24llg.1.3 | Placeholder closure audit | 2026-04-19 |
| etp8q.3 | Quarantine scoreboard | -- |

---

## Environment Capture Requirements

When rerunning proof commands for final review, record:

- git revision under test (`git rev-parse HEAD`)
- `CARGO_TARGET_DIR` used
- exact `rch exec` command issued
- worker selected (from rch output) or `local` if rch fell back
- whether the result is a direct measurement, criterion delta, or bounded estimate
- date of rerun

---

## Review Verdict Protocol

For each proof section:

- **PASS**: all rerun commands succeed, all referenced artifacts exist, evidence
  matches the claim in the section index
- **REVIEW**: evidence exists but has a noted gap, intentional regression, or
  method change that requires human judgment
- **FAIL**: referenced artifact is missing, rerun command fails on current tree,
  or evidence contradicts the section claim

The final cutover decision should require PASS on all 7 proof sections listed
in the Proof Sections table above.

---

## Current Status

As of 2026-04-19, this manifest is complete. All blocking beads are closed. All
section indexes are published. The next consumer is `flywheel_connectors-84phy.1`
(final closure checklist), which should walk this manifest to issue the
go-or-no-go record.

*This document is the canonical entry point for FCP3 cutover review. It
replaces the need to reconstruct the proof story from scattered beads, docs,
and test files.*
