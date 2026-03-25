# TODO True Interactive E2E Mac Execution

Bead: `flywheel_connectors-o8kjw`
Owner: `VioletSummit`
Goal: execute the first real host-backed `fwc -> fcp-host -> connector subprocesses` verification wave on this Mac and preserve evidence.

## Coordination And Tracking

- [x] Create and claim a dedicated Bead for this work.
- [x] Reserve `.beads/issues.jsonl`.
- [x] Reserve the plan and TODO files.
- [x] Reserve the evidence artifact tree.
- [ ] Notify the other active agents about the claimed verification surface.
- [ ] Record any Agent Mail contact-handshake failure so the coordination gap is explicit.
- [ ] Keep polling inbox for ack-required or urgent messages during execution.

## Build Strategy

- [x] Re-check the `rch` constraints for this run.
- [x] Confirm the key build constraint: remote worker artifacts are for worker OS, while the live host and connectors must run on this Mac.
- [ ] Run `rch` verification builds/checks for the exact crates needed in Wave 0 and Wave 1.
- [ ] Produce runnable local macOS binaries for `fwc`, `fcp-host`, `fcp-apple-notes`, and `fcp-apple-reminders`.
- [ ] Record the exact commands used for both remote verification and local runnable builds.
- [ ] Record any divergence between the remote-verification path and local-runnable path.

## Artifact Layout

- [ ] Create `artifacts/true-e2e/<date>/wave0/`.
- [ ] Create `artifacts/true-e2e/<date>/apple-notes/create-read-verify/`.
- [ ] Create `artifacts/true-e2e/<date>/apple-reminders/create-complete-verify/`.
- [ ] Create helper files for `command.txt`, `fwc-output.json`, `host.log`, `verify.json`, `screenshot.png`, and `cleanup.txt`.

## Wave 0: Live Operator Surface Sanity

- [ ] Build or verify fresh `fwc`.
- [ ] Build or verify fresh `fcp-host`.
- [ ] Build or verify fresh Apple connector binaries needed for host inventory.
- [ ] Locate the exact local binary paths to use in the host inventory file.
- [ ] Write a minimal `connectors.json` inventory with Apple Notes and Apple Reminders.
- [ ] Choose a localhost bind address for the host.
- [ ] Start `fcp-host` locally with the minimal inventory.
- [ ] Confirm the host process is actually listening.
- [ ] Capture host startup logs to the Wave 0 artifact directory.
- [ ] Run a live `fwc` discovery command against the host.
- [ ] Run a live `fwc show` or equivalent connector detail command against the host.
- [ ] Run a live `fwc ops` or equivalent operation discovery command against the host.
- [ ] Run a live `fwc status` or equivalent health/introspection command against the host.
- [ ] Record all Wave 0 command outputs.
- [ ] Decide whether the repo-built `fwc` looks trustworthy enough for Wave 1.

## Wave 1A: Apple Notes True E2E

- [ ] Confirm the connector starts and responds to a health-like operation.
- [ ] Choose a timestamped sentinel title/body for the test note.
- [ ] Decide whether to target a dedicated Notes folder or the default folder.
- [ ] Execute the note creation through the live host-backed path.
- [ ] Capture the raw `fwc` JSON result for note creation.
- [ ] Execute a note read-back through the connector path.
- [ ] Execute a note search through the connector path using the sentinel.
- [ ] Run an out-of-band AppleScript read-back for the created note.
- [ ] Open Notes.app if needed for visual verification.
- [ ] Capture a screenshot showing the created note in the UI.
- [ ] Record any macOS Automation or Screen Recording prompt encountered.
- [ ] Decide whether to clean up the note or intentionally leave it as residue.
- [ ] Write `verify.json` with the connector result plus out-of-band confirmation.
- [ ] Write `cleanup.txt` with the final residue decision.

## Wave 1B: Apple Reminders True E2E

- [ ] Confirm the connector starts and responds to a health-like operation.
- [ ] Choose a timestamped sentinel reminder title.
- [ ] Decide whether to use an existing list or create/use a dedicated test list.
- [ ] Execute reminder creation through the live host-backed path.
- [ ] Capture the raw `fwc` JSON result for reminder creation.
- [ ] Execute a list/read-back through the connector path using the sentinel.
- [ ] Execute reminder completion through the connector path.
- [ ] Run an out-of-band AppleScript read-back confirming creation and completion.
- [ ] Open Reminders.app if needed for visual verification.
- [ ] Capture a screenshot showing the reminder state in the UI.
- [ ] Record any macOS Automation or Screen Recording prompt encountered.
- [ ] Decide whether to keep the completed reminder, move it, or otherwise clean up.
- [ ] Write `verify.json` with the connector result plus out-of-band confirmation.
- [ ] Write `cleanup.txt` with the final residue decision.

## Reliability Checks

- [ ] Confirm the host remained up through both Apple scenarios.
- [ ] Confirm the host log does not show silent connector crashes or respawn loops.
- [ ] Confirm the evidence bundle is complete and readable.
- [ ] Confirm no accidental destructive cleanup happened.

## Follow-On Cloud Targets

- [ ] Record the recommended next cloud target order after Apple.
- [ ] Record the exact user-provided prerequisites needed for GitHub.
- [ ] Record the exact user-provided prerequisites needed for Telegram.
- [ ] Record the exact user-provided prerequisites needed for Slack.
- [ ] Record the exact user-provided prerequisites needed for Gmail and Google Calendar.
- [ ] Record why the browser connector remains out of first-wave scope.

## Closeout

- [ ] Update the Bead with notes on what actually worked.
- [ ] Sync Beads state to JSONL.
- [ ] Release file reservations when the run is complete.
- [ ] Summarize completed work, residual blockers, and the next concrete action.
