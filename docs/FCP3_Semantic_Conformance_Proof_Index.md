# FCP3 Semantic and Conformance Proof Index

> **Bead**: `flywheel_connectors-8bqme.1` -- [FCP3/P7.3]
> **Author**: MagentaOtter, 2026-04-19
> **Purpose**: give final review one indexed semantic/conformance section
> instead of forcing reviewers to reconstruct ownership, protocol proof, and
> deletion evidence from scattered docs and tests.

---

## Reviewer Question

Can a reviewer verify, from one surface, that:

- semantic ownership is explicit rather than smeared across `fcp-core`
- protocol and behavior conformance still have executable proof anchors
- deletion work preserved the semantics it claimed to preserve
- the current tree has a mechanically reviewable path from docs to rerunable
  verification surfaces

## Proof Table

| Proof area | Reviewer question | Primary surfaces | Bead / proof anchors | Rerun anchors |
|------------|-------------------|------------------|----------------------|---------------|
| Canonical semantic ownership map | Is there a declared owner for each major semantic domain? | `docs/FCP3_Canonical_Owner_Map.md`; `docs/FCP3_Semantic_Ownership_Inventory.md`; `docs/FCP3_Transition_Guardrails.md` | `flywheel_connectors-0aczd`; `flywheel_connectors-0aczd.1`; `flywheel_connectors-0aczd.2` | `rg -n "semantic owner crates|forbidden overlaps|canonical owner map" docs/FCP3_Canonical_Owner_Map.md docs/FCP3_Semantic_Ownership_Inventory.md docs/FCP3_Transition_Guardrails.md README.md` |
| Post-retirement crate graph and import surface | Is `fcp-core` retirement backed by an explicit crate-graph/import audit instead of hand-waving? | `docs/FCP3_Crate_Graph_Audit.md`; `crates/fcp-core/src/lib.rs`; `crates/fcp-kernel/src/lib.rs`; `crates/fcp-evidence/src/lib.rs` | `flywheel_connectors-0aczd.3` | `br show flywheel_connectors-0aczd.3`; `rg -n "175 reverse deps|re-exported by owner crates|semantic owner crates" docs/FCP3_Crate_Graph_Audit.md crates/fcp-core/src/lib.rs README.md` |
| Protocol conformance harnesses | Does the repo still have concrete conformance tooling and vector-backed surfaces? | `README.md`; `docs/STANDARD_Requirements_Index.md`; `docs/testing/core_platform_evidence_index.md`; `crates/fcp-conformance/tests/` | `flywheel_connectors-1n78.21.*` ownership in the requirements index; `flywheel_connectors-8bqme.1` | `rch exec -- cargo test -p fcp-conformance`; `rch exec -- cargo test -p fcp-e2e`; `rg -n "golden vectors|interop|conformance" README.md docs/STANDARD_Requirements_Index.md docs/testing/core_platform_evidence_index.md` |
| CLI/operator semantic truth contracts | Are the user-visible semantics documented and backed by replayable evidence? | `README.md`; `crates/fwc/src/readiness.rs`; `crates/fwc/tests/cual_integration.rs`; `crates/fwc/src/test_observability.rs` | `flywheel_connectors-o8umn.3`; `flywheel_connectors-24llg.*` placeholder-closure proof | `rch exec -- cargo test -p fwc --test cual_integration`; `rch exec -- cargo test -p fwc test_observability::full_workflow_replay_round_trip -- --exact --nocapture`; `rg -n "CommandAvailability|trace.jsonl|summary.json|environment.json|replay.sh" README.md crates/fwc/src/readiness.rs crates/fwc/src/test_observability.rs` |
| Deletion-wave semantic preservation | Did phase-7 deletion preserve semantics and workflows instead of deleting proof surfaces? | `docs/FCP3_Workflow_Preservation_Evidence.md`; `docs/FCP3_Pre_Cutover_Baseline.md`; `docs/FCP3_Transition_Scorecard.md` | `flywheel_connectors-z1nkz.3`; `flywheel_connectors-z1nkz` | `br show flywheel_connectors-z1nkz.3`; `rg -n "Deletion-Wave Status|before/after|workflow-preservation" docs/FCP3_Workflow_Preservation_Evidence.md docs/FCP3_Pre_Cutover_Baseline.md docs/FCP3_Transition_Scorecard.md` |
| Closure wiring for this section | Is this semantic/conformance section wired into the final closure review rather than orphaned? | `docs/FCP3_Final_Closure_Checklist.md`; `docs/FCP3_Benchmark_Comparison.md`; `docs/FCP3_Operational_Proof_Index.md` | `flywheel_connectors-84phy.1`; `flywheel_connectors-8bqme.3` | `rg -n "Semantic and conformance evidence bundle indexed|Final proof manifest published" docs/FCP3_Final_Closure_Checklist.md` |

## Section Notes

### 1. Ownership is explicit, even where migration residue remains

The repo already distinguishes:

- execution semantics (`fcp-kernel`)
- policy and trust semantics (`fcp-policy`)
- evidence and receipt semantics (`fcp-evidence`)
- transitional residue and shared vocabulary (`fcp-core`)

The important closure-grade claim is not that all physical type definitions have
already moved. It is that the repository now has an explicit owner map, an
ownership inventory, and a crate-graph/import audit that make the remaining
transitional residue visible and reviewable.

### 2. Conformance remains executable

The semantic story is not doc-only. The repo still points to:

- `crates/fcp-conformance/tests/` for golden-vector and interop-style coverage
- `crates/fcp-e2e/tests/` for end-to-end compliance scenarios
- `docs/STANDARD_Requirements_Index.md` for the mapping between normative areas
  and their owning verification beads

This is the conformance spine that the final proof manifest should cite.

### 3. Deletion proof is part of semantic proof

The semantic/conformance section would be incomplete if the phase-7 deletion
track removed the teaching or workflow surfaces needed to explain current
behavior. `docs/FCP3_Workflow_Preservation_Evidence.md` and
`docs/FCP3_Pre_Cutover_Baseline.md` are therefore semantic-proof inputs, not
just historical notes.

### 4. The remaining manifest step is aggregation, not discovery

After `0aczd.3`, `z1nkz.3`, `8bqme.2`, and `ukr33.2`, the remaining work for the
final proof bundle is to aggregate these section indexes into one manifest. The
semantic/conformance inputs themselves are now indexable and reviewer-facing.

## Fast Review Commands

```bash
br show flywheel_connectors-0aczd.3
br show flywheel_connectors-z1nkz.3
rg -n "semantic owner crates|Emerging owner crates|Transitional semantic bucket" README.md crates/fcp-core/src/lib.rs docs/FCP3_Crate_Graph_Audit.md
rg -n "golden vectors|interop|conformance" README.md docs/STANDARD_Requirements_Index.md docs/testing/core_platform_evidence_index.md
```

Cargo-backed spot checks:

```bash
export CARGO_TARGET_DIR=/tmp/fcp-mg-cod3
rch exec -- cargo test -p fcp-conformance
rch exec -- cargo test -p fcp-e2e
rch exec -- cargo test -p fwc --test cual_integration
```

## Current Verdict

The semantic and conformance section is now assembled in one reviewer-facing
index. The final proof manifest still needs to cite it, but reviewers no longer
need to infer the semantic/conformance story by hopping between the owner map,
crate audit, conformance harnesses, and deletion-wave proof without a guide.
