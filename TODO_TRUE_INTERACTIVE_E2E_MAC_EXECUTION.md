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
- [x] Record any Agent Mail contact-handshake failure so the coordination gap is explicit.
- [x] Keep polling inbox for ack-required or urgent messages during execution.

Current coordination state:
Attempted direct contact / intro for `PeachPond`, `GentleOak`, and `FrostyBridge`, but outbound messaging was blocked by required contact approval and every follow-up `macro_contact_handshake(... auto_accept=true ...)` attempt failed with a transient Agent Mail database error. Inbox polls for `VioletSummit` remained empty through the Apple execution wave.

## Build Strategy

- [x] Re-check the `rch` constraints for this run.
- [x] Confirm the key build constraint: remote worker artifacts are for worker OS, while the live host and connectors must run on this Mac.
- [x] Run `rch` verification builds/checks for the exact crates needed in Wave 0 and Wave 1.
- [x] Produce runnable local macOS binaries for `fwc`, `fcp-host`, `fcp-apple-notes`, and `fcp-apple-reminders`.
- [x] Record the exact commands used for both remote verification and local runnable builds.
- [x] Record any divergence between the remote-verification path and local-runnable path.

Recorded build-path facts:
Remote verification command:
`rch exec -- cargo check -p fwc --bin fwc -p fcp-host --bin fcp-host -p fcp-apple-notes --bin fcp-apple-notes -p fcp-apple-reminders --bin fcp-apple-reminders`
Remote result:
failed on worker `vmi1227854` because `libdbus-sys` could not find `dbus-1.pc`; this is an `rch` worker environment gap for the Linux-side verification path.
Local runnable build command:
`CARGO_TARGET_DIR=/tmp/flywheel_connectors-mac-e2e-target cargo build -p fwc --bin fwc -p fcp-host --bin fcp-host -p fcp-apple-notes --bin fcp-apple-notes -p fcp-apple-reminders --bin fcp-apple-reminders`
Divergence:
the remote path is useful for compile verification only, while the live E2E execution path must use locally built macOS binaries.

## Artifact Layout

- [x] Create `artifacts/true-e2e/<date>/wave0/`.
- [x] Create `artifacts/true-e2e/<date>/apple-notes/create-read-verify/`.
- [x] Create `artifacts/true-e2e/<date>/apple-reminders/create-complete-verify/`.
- [x] Create helper files for `command.txt`, `fwc-output.json`, `host.log`, `verify.json`, `screenshot.png`, and `cleanup.txt`.

## Wave 0: Live Operator Surface Sanity

- [x] Build or verify fresh `fwc`.
- [x] Build or verify fresh `fcp-host`.
- [x] Build or verify fresh Apple connector binaries needed for host inventory.
- [x] Locate the exact local binary paths to use in the host inventory file.
- [x] Write a minimal `connectors.json` inventory with Apple Notes and Apple Reminders.
- [x] Choose a localhost bind address for the host.
- [x] Start `fcp-host` locally with the minimal inventory.
- [x] Confirm the host process is actually listening.
- [x] Capture host startup logs to the Wave 0 artifact directory.
- [x] Run a live `fwc` discovery command against the host.
- [x] Run a live `fwc show` or equivalent connector detail command against the host.
- [x] Run a live `fwc ops` or equivalent operation discovery command against the host.
- [x] Run a live `fwc status` or equivalent health/introspection command against the host.
- [x] Record all Wave 0 command outputs.
- [x] Decide whether the repo-built `fwc` looks trustworthy enough for Wave 1.

Wave 0 artifact facts:
Live host bind:
`http://127.0.0.1:8787`
Live inventory file:
`artifacts/true-e2e/2026-03-25/wave0/connectors.json`
Runnable binaries:
`/tmp/flywheel_connectors-mac-e2e-target/debug/fwc`
`/tmp/flywheel_connectors-mac-e2e-target/debug/fcp-host`
`/tmp/flywheel_connectors-mac-e2e-target/debug/fcp-apple-notes`
`/tmp/flywheel_connectors-mac-e2e-target/debug/fcp-apple-reminders`
Wave 0 outputs captured:
`fwc-list.json`, `fwc-show-apple-notes.json`, `fwc-ops-apple-notes.json`, `fwc-status-apple-notes.json`, `fwc-show-apple-reminders.json`, `rch-check.log`, `local-build.log`, `host.log`
Operator-surface caveat:
`fwc doctor --all --host ...` was not the correct invocation shape and returned a CLI validation error; this is a command-shape/operator-ergonomics issue, not a host failure.

## Wave 1A: Apple Notes True E2E

- [x] Confirm the connector starts and responds to a health-like operation.
- [x] Choose a timestamped sentinel title/body for the test note.
- [x] Decide whether to target a dedicated Notes folder or the default folder.
- [x] Execute the note creation through the live host-backed path.
- [x] Capture the raw `fwc` JSON result for note creation.
- [x] Execute a note read-back through the connector path.
- [x] Execute a note search through the connector path using the sentinel.
- [x] Run an out-of-band AppleScript read-back for the created note.
- [x] Open Notes.app if needed for visual verification.
- [x] Capture a screenshot showing the created note in the UI.
- [x] Record any macOS Automation or Screen Recording prompt encountered.
- [x] Decide whether to clean up the note or intentionally leave it as residue.
- [x] Write `verify.json` with the connector result plus out-of-band confirmation.
- [x] Write `cleanup.txt` with the final residue decision.

Apple Notes live verdict:
`create_note`, `search_notes`, and `get_note` all worked through the patched live `fwc -> fcp-host -> fcp-apple-notes` path. Direct AppleScript read-back matched the connector-returned note id, title, folder, and sentinel-bearing body. A Notes screenshot was captured, but the created note was not cleanly legible in the visible pane, so the strongest proof artifact is the AppleScript cross-check plus the connector JSON outputs.

## Wave 1B: Apple Reminders True E2E

- [x] Confirm the connector starts and responds to a health-like operation.
- [x] Choose a timestamped sentinel reminder title.
- [x] Decide whether to use an existing list or create/use a dedicated test list.
- [x] Execute reminder creation through the live host-backed path.
- [x] Capture the raw `fwc` JSON result for reminder creation.
- [x] Execute a list/read-back through the connector path using the sentinel.
- [x] Execute reminder completion through the connector path.
- [x] Run an out-of-band AppleScript read-back confirming creation and completion.
- [x] Open Reminders.app if needed for visual verification.
- [x] Capture a screenshot showing the reminder state in the UI.
- [x] Record any macOS Automation or Screen Recording prompt encountered.
- [x] Decide whether to keep the completed reminder, move it, or otherwise clean up.
- [x] Write `verify.json` with the connector result plus out-of-band confirmation.
- [x] Write `cleanup.txt` with the final residue decision.

Apple Reminders live verdict:
The connector can create and complete a reminder on the default-list path, and direct AppleScript verification confirmed the reminder id, title, list, and completed=true state. Two real live bugs surfaced:
`list_lists` returned a list name that `create_reminder` could not round-trip back into the same connector, and `list_reminders` failed to surface the reminder that was just created and then completed by id.

## Reliability Checks

- [x] Confirm the host remained up through both Apple scenarios.
- [x] Confirm the host log does not show silent connector crashes or respawn loops.
- [x] Confirm the evidence bundle is complete and readable.
- [x] Confirm no accidental destructive cleanup happened.

## Follow-On Cloud Targets

- [x] Record the recommended next cloud target order after Apple.
- [x] Record the exact user-provided prerequisites needed for GitHub.
- [x] Record the exact user-provided prerequisites needed for Telegram.
- [x] Record the exact user-provided prerequisites needed for Slack.
- [x] Record the exact user-provided prerequisites needed for Gmail and Google Calendar.
- [x] Record why the browser connector remains out of first-wave scope.

Recorded follow-on order and prerequisites:
Recommended next cloud target order:
GitHub -> Telegram -> Slack -> Gmail/Google Calendar
GitHub prerequisites:
PAT with repo scope and a scratch repository where test issues/PR comments can be created safely.
Telegram prerequisites:
bot token plus a safe target chat/channel where test messages can be sent and observed.
Slack prerequisites:
workspace access plus the needed bot/app tokens and a safe test channel.
Gmail / Google Calendar prerequisites:
Google account consent, OAuth client details or whatever auth path the connector currently expects, and permission to create visible residue in mail/calendar data.
Browser first-wave exclusion:
the browser connector does not map cleanly to a simple local Chrome-only verification path and expects a higher-level browser control plane, so it is not the best immediate live target on this Mac.

## Closeout

- [x] Update the Bead with notes on what actually worked.
- [x] Sync Beads state to JSONL.
- [x] Release file reservations when the run is complete.
- [x] Summarize completed work, residual blockers, and the next concrete action.

## Execution Log

- `2026-03-25T18:42` Claimed Bead `flywheel_connectors-o8kjw`, reserved tracking/evidence surfaces, and created this TODO artifact.
- `2026-03-25T18:45` Re-confirmed that heavy Cargo verification should go through `rch`, but live macOS execution still requires local Darwin binaries.
- `2026-03-25T18:47` Attempted contact / intro to active agents; blocked by contact approval. Subsequent handshake attempts failed with transient Agent Mail database errors.
- `2026-03-25T18:50` Created the live artifact tree under `artifacts/true-e2e/2026-03-25/`.
- `2026-03-25T18:55` Ran the exact `rch` verification command for the live-path crates; remote check failed because the worker lacked `dbus-1.pc`.
- `2026-03-25T18:59` Built fresh local macOS binaries into `/tmp/flywheel_connectors-mac-e2e-target/` after isolating the target dir to avoid shared cargo lock contention.
- `2026-03-25T19:02` Generated a real Ed25519 capability keypair plus signed capability tokens for Apple Notes and Apple Reminders under `artifacts/true-e2e/2026-03-25/wave0/tokens/`.
- `2026-03-25T19:05` Started a live local `fcp-host` bound to `127.0.0.1:8787` using the token public key file and the two-connector inventory.
- `2026-03-25T19:06` Verified host health and captured live `fwc` discovery/introspection outputs against the running host.
- `2026-03-25T19:08` Re-polled Agent Mail; inbox still empty.
- `2026-03-25T19:10` Found a real host bug during the first live invoke: subprocess connectors were configured but never handshaken, so host-backed invoke failed with `Connector not handshaken`.
- `2026-03-25T19:12` Patched `fcp-host` to perform automatic subprocess handshake before `invoke`/`simulate`, and added a focused host test plus fixture support to catch this regression.
- `2026-03-25T19:23` Verified the host patch with `CARGO_TARGET_DIR=/tmp/fcp-host-handshake-target rch exec -- cargo test -p fcp-host subprocess_connector_invoke_performs_handshake_automatically -- --nocapture`. `rch` attempted remote offload, but dependency preflight `RCH-E326` forced local fallback.
- `2026-03-25T19:24` Rebuilt the runnable local `fcp-host` binary, restarted the live host, and confirmed Notes health on the patched host.
- `2026-03-25T19:25` Completed Apple Notes live create/search/get plus direct AppleScript read-back. Wrote `verify.json`, `cleanup.txt`, and a screenshot artifact.
- `2026-03-25T19:27` Completed Apple Reminders live create/complete on the default-list path plus direct AppleScript read-back, and captured the connector bugs around list-name round-tripping and missing created reminders in `list_reminders`.
- `2026-03-25T19:28` Captured a Reminders screenshot artifact, but a system prompt interfered with obtaining a clean UI-focused proof image.
- `2026-03-25T19:31` Filed follow-up bug `flywheel_connectors-i05fu` for the Apple Reminders live failures, commented the completed verification bead, closed `flywheel_connectors-o8kjw`, and released the Agent Mail reservations.
