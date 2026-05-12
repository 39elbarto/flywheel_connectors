# Agent Readiness Handoff

`fwc agent-readiness` turns the startup readiness report into a handoff bundle
that another agent or an operator can inspect before work starts.

The bundle is redaction-safe and non-destructive. It contains:

- `report.json`: the full `fcp.agent-readiness-report.v1` record.
- `events.jsonl`: one replayable JSONL line for the report summary and each probe.
- `handoff.json`: the compact session handoff with git remote truth, blockers,
  allowed actions, refused actions, and artifact filenames.
- `handoff.md`: the same high-signal summary for a Beads comment or handoff note.

## Start A Session From A Report

1. Generate or receive a readiness bundle:

   ```bash
   fwc agent-readiness fixture \
     --agent GreenLake \
     --scenario agent-mail-unavailable \
     --owned-path-glob 'crates/fcp-evidence/**' \
     --out-dir /tmp/fwc-readiness-greenlake
   ```

2. Read `handoff.md` first. It shows the selected operating mode, remote `main`
   and mirror revisions, active blocker Beads, and exact allowed next actions.

3. If `coordinate` is refused, skip Agent Mail and leave Beads comments for the
   audit trail. Do not repair or restart Agent Mail from this command path.

4. If `cargo_proof` is allowed, run proof through `rch` with an isolated
   `CARGO_TARGET_DIR`. Local Cargo output is not proof for this repository.

5. Before trusting a transferred bundle, replay it:

   ```bash
   fwc agent-readiness replay \
     --report /tmp/fwc-readiness-greenlake/report.json \
     --jsonl /tmp/fwc-readiness-greenlake/events.jsonl
   ```

Replay validates that `events.jsonl` is exactly derivable from `report.json`.
If the replay fails, do not claim, edit, prove, or push from that bundle.

## Approval Gates

The handoff bundle has three action lists:

- `exact_allowed_next_actions`: steps the agent may take from the current
  readiness state.
- `refused_next_actions`: steps the agent must not take until the blocker
  clears.
- `operator_approval_gates`: steps that require explicit user approval even if
  they look like obvious remediation.

Safe actions without extra approval are read-only inspection, replaying the
bundle, `br show`, robot-mode `bv`, `git status`, `git diff`,
`git ls-remote`, `df`, and allowed `rch exec` proof with an isolated target
directory.

These actions are approval-gated and must not be executed by readiness handling:

- Agent Mail repair, reconstruct, restart, stop, or process killing.
- Disk cleanup that deletes files, prunes artifacts, empties caches, or removes
  build output to recover space.
- Any file or folder deletion.
- Worker-fleet repair, restart, or reconfiguration for `rch`.
- Destructive Git cleanup, reset, checkout-overwrite, or clean commands.
- Treating local Cargo output or transfer logs as proof when `rch` proof is
  required.

`flywheel_connectors-d5yeb` is the Agent Mail readiness blocker. If the report
shows an Agent Mail database error, mailbox lock, or unavailable registration,
retry once after a short delay, then proceed without Agent Mail. Do not run
`am doctor repair`, `am doctor reconstruct`, `am service restart`, or any
process-kill workaround, even if a health check suggests it.

`flywheel_connectors-rfbrc` is the rch/disk proof blocker. If the report shows
no healthy `rch` workers, a blocked `rch` status probe, or disk pressure, do not
clean disk, delete artifacts, repair workers, or use local Cargo as proof. Stop
at the refused `cargo_proof` and `push` actions and hand the blocker to the
operator with the report digest and active blocker bead.

## Dry-Run Script

Use the e2e script for a deterministic no-network rehearsal:

```bash
FWC_BIN=/path/to/fwc bash scripts/e2e/agent_readiness_handoff_dry_run.sh \
  --run-id agent-readiness-demo \
  --out-root /tmp/fwc-readiness-demo
```

The script creates the output directory if needed and writes new artifacts, but
it does not delete or clean anything. Pick a fresh `--out-root` when re-running.
