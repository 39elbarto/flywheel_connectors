# FCP3 Operational Proof Index

This document is the reviewer-facing operational proof section for
`flywheel_connectors-8bqme.2`.

It answers one question directly:

> Can the post-cutover platform be deployed, diagnosed, and operated honestly
> without reconstructing the proof story from scattered docs, beads, and test
> files?

Use this index with:

- `README.md` for the top-level deployment/runbook surface
- `docs/FWC_Host_First_Truthfulness_Playbook.md` for operator truth contracts,
  replay bundles, and deployment/failover interpretation
- `docs/FCP3_Workflow_Preservation_Evidence.md` for deletion-wave workflow proof
- `docs/FCP3_Final_Closure_Checklist.md` for closure-gate status

## Review Protocol

For each section below:

1. Read the human-facing runbook or proof surface.
2. Follow the cited bead and test anchor to confirm the surface is backed by
   executable evidence rather than prose alone.
3. Use the rerun commands to spot-check the contract on the current tree.

The goal is not to prove a fully autonomous active/active mesh today. The goal
is to prove that the repository teaches and verifies the current operating model
truthfully.

## Operational Proof Table

| Proof area | Reviewer question | Primary surfaces | Bead / proof anchors | Rerun anchors |
|------------|-------------------|------------------|----------------------|---------------|
| Deployment topology and runbook | Does the repo teach the current deployment shape honestly, including its limits? | `README.md` production runbook section; `docs/FWC_Host_First_Truthfulness_Playbook.md` deployment runbook | `flywheel_connectors-pl7pj.2`; `flywheel_connectors-pl7pj.3`; `docs/FCP3_Acceptance_Contracts.md` phase-5/phase-6 obligations | `rg -n "Production Mesh Deployment Runbook|Current Honest Topology|Minimum Bring-Up|Rollout And Rollback Loop" README.md`; `rg -n "Production Deployment Runbook|Bring-up verification loop|Failover assumptions" docs/FWC_Host_First_Truthfulness_Playbook.md` |
| Evidence-backed operator journeys | Are healthy, denied, degraded, and drill-down operator flows backed by replayable artifacts? | `docs/FWC_Host_First_Truthfulness_Playbook.md` verification/artifact sections | `flywheel_connectors-o8umn.3`; `crates/fwc/tests/cual_integration.rs`; `crates/fcp-host/tests/host_connector_integration.rs` | `rch exec -- cargo test -p fwc --test cual_integration`; `rch exec -- cargo test -p fcp-host --test host_connector_integration`; `rch exec -- cargo test -p fcp-e2e` |
| Truthful replay bundle contract | When an operator flow fails, does the repo define a deterministic bundle-reading and replay order? | `README.md` debugging loop section; `docs/FWC_Host_First_Truthfulness_Playbook.md` artifact bundle contract | `flywheel_connectors-o8umn.3`; `crates/fwc/src/test_observability.rs`; `crates/fwc/docs/truthfulness-model.md` | `rg -n "summary.json|trace.jsonl|environment.json|replay.sh" README.md docs/FWC_Host_First_Truthfulness_Playbook.md`; `rch exec -- cargo test -p fwc test_observability::full_workflow_replay_round_trip -- --exact --nocapture` |
| Workflow-preservation after deletion | Did phase-7 deletion preserve user-visible and operator-visible workflows instead of just deleting code? | `docs/FCP3_Workflow_Preservation_Evidence.md`; `docs/FCP3_Pre_Cutover_Baseline.md`; `docs/FCP3_Transition_Scorecard.md` | `flywheel_connectors-z1nkz`; `flywheel_connectors-z1nkz.3` | `br show flywheel_connectors-z1nkz`; `br show flywheel_connectors-z1nkz.3`; `rg -n "workflow-preservation index|Deletion-Wave Status" docs/FCP3_Transition_Scorecard.md docs/FCP3_Workflow_Preservation_Evidence.md` |
| Closure readiness of the operational section | Is the operational proof section wired into the closure gate instead of living as an orphan doc? | `docs/FCP3_Final_Closure_Checklist.md` | `flywheel_connectors-84phy.1`; `flywheel_connectors-8bqme.2` | `rg -n "Operational evidence bundle indexed|Operational/deployment/workflow-preservation section still open" docs/FCP3_Final_Closure_Checklist.md` |

## Section Notes

### 1. Deployment topology and runbook

The current truthful operating model is:

- single active `fcp-host`
- staged standby peer
- mesh/object peers that can elevate truth from host-backed to mesh-backed
- no claim of automatic active/active failover yet

That claim is backed by the runbook text in `README.md` and
`docs/FWC_Host_First_Truthfulness_Playbook.md`, plus the phase-5/phase-6 proof
anchors they cite.

### 2. Evidence-backed operator journeys

The operator proof is not just a doc claim. The repo already points reviewers at
the executable proof surfaces that freeze:

- host-backed truth classes
- degraded and refusal outputs
- rollout/rollback/config mutation flows
- replayable evidence-backed diagnostics

The key acceptance anchor here is `flywheel_connectors-o8umn.3`, which closed
with snapshot/transcript proof for healthy, denied, degraded, and drill-down
journeys.

### 3. Truthful replay bundle contract

The bundle-reading order is part of the proof contract:

1. `summary.json`
2. `trace.jsonl`
3. `environment.json`
4. `replay.sh`

If those surfaces disagree, the operational evidence is incomplete. The docs
already teach that order explicitly, and the `fwc` observability tests provide
the executable backstop.

### 4. Workflow preservation after deletion

The operational story would be incomplete if phase-7 cleanup had removed the
operator workflows it was supposed to preserve. The deletion-wave index in
`docs/FCP3_Workflow_Preservation_Evidence.md` is therefore part of the
operational proof section, not a separate concern.

Reviewers should confirm that:

- teaching surfaces were rewritten truthfully
- runtime/control-plane seams were deleted with replacement proof
- one review index now replaces scattered history reconstruction

### 5. Closure wiring

This operational index exists so the final proof manifest and closure review can
cite one document for the operator/deployment/workflow-preservation slice.

Until the final proof manifest is published, this document is the canonical
operational proof aggregation surface.

## Fast Review Commands

```bash
br show flywheel_connectors-pl7pj.2
br show flywheel_connectors-pl7pj.3
br show flywheel_connectors-o8umn.3
br show flywheel_connectors-z1nkz.3
rg -n "Production Mesh Deployment Runbook|Proof Anchors|Rollout And Rollback Loop" README.md
rg -n "Production Deployment Runbook|Proof anchors|Bring-up verification loop|Artifact bundles and replay" docs/FWC_Host_First_Truthfulness_Playbook.md
rg -n "Operational evidence bundle indexed|Operational/deployment/workflow-preservation section still open" docs/FCP3_Final_Closure_Checklist.md
```

For cargo-backed spot checks, keep the remote-compilation path explicit:

```bash
export CARGO_TARGET_DIR=/tmp/fcp-mg-cod5
rch exec -- cargo test -p fwc --test cual_integration
rch exec -- cargo test -p fcp-host --test host_connector_integration
rch exec -- cargo test -p fcp-e2e
```

## Current Verdict

The repository now has the ingredients for a coherent operational proof section:

- truthful deployment/runbook docs
- evidence-backed operator-journey proof
- deterministic replay-bundle guidance
- indexed deletion-wave workflow-preservation evidence

What remains outside this document is the final proof manifest that will cite
this operational section alongside the semantic/conformance and performance
sections.
