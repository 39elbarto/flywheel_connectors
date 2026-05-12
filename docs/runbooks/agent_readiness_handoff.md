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

## Dry-Run Script

Use the e2e script for a deterministic no-network rehearsal:

```bash
FWC_BIN=/path/to/fwc bash scripts/e2e/agent_readiness_handoff_dry_run.sh \
  --run-id agent-readiness-demo \
  --out-root /tmp/fwc-readiness-demo
```

The script creates the output directory if needed and writes new artifacts, but
it does not delete or clean anything. Pick a fresh `--out-root` when re-running.
