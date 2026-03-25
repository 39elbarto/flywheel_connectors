# Plan For True Interactive End-To-End Verified Tests On Mac

## Goal

Move from "the repo has a huge test suite" to "we have personally exercised real connectors and the real `fwc -> fcp-host -> connector subprocess` path on this Mac, with evidence."

This plan is about truthful, closed-loop verification:

1. Run the real CLI and real host.
2. Talk to the real connector binary.
3. Cause a real side effect or read real external state.
4. Verify that side effect from outside the connector.
5. Capture evidence.

## Current Truths

### The implemented operator path is real

The repo's current real path is:

`fwc -> fcp-host HTTP admin/runtime API -> connector subprocesses`

That is the path we should verify first, not ad hoc connector-only unit harnesses.

### We must use fresh workspace binaries, not the already-installed `fwc`

The currently installed `fwc` on this Mac is `0.1.0`, and its offline catalog already looks stale/inconsistent:

- it does not surface the repo's Apple Notes / Apple Reminders connectors
- `fwc show github --offline --json` reports partial/inconsistent metadata
- `fwc config schema ...` appears inconsistent in this installed build

So the first rule of real E2E work is:

- use freshly built `fwc`
- use freshly built `fcp-host`
- use freshly built connector binaries from this workspace

All builds must be offloaded through `rch`.

### The best Mac-local true E2E targets are Apple Notes and Apple Reminders

These are strong first targets because they are local, GUI-backed, and do not need cloud auth.

They are not mocks:

- `fcp-apple-notes` uses `/usr/bin/osascript`
- `fcp-apple-reminders` uses `/usr/bin/osascript`

That means we can verify them both through:

- connector responses
- AppleScript reads
- actual Notes / Reminders UI screenshots on the Mac

### The browser connector is not a first-wave target

`fcp-browser` is not "just point at local Chrome DevTools."

Its client expects a higher-level HTTP browser control plane with endpoints like:

- `/json/version`
- `/navigate`
- `/screenshot`
- `/extract_text`

So unless we already have a compatible local bridge or we build one, this is not the fastest true-E2E win.

### The host registration path is concrete

`fcp-host` can be started with either:

- `FCP_HOST_CONNECTORS`
- `FCP_HOST_CONNECTORS_FILE`

The managed connector inventory shape is straightforward:

- `id`
- `binary`
- optional `name`
- optional `description`
- optional `args`
- optional `env`
- optional `config`
- optional `categories`
- optional `version`

That gives us a clean way to run a small live connector inventory on localhost.

## Definition Of Done For A "True E2E Verified" Scenario

A scenario only counts if it includes all of the following:

1. Fresh repo-built `fwc`, `fcp-host`, and connector binaries.
2. Live host-backed execution, not offline artifact inspection.
3. A real external or local-system effect.
4. Out-of-band verification outside the connector itself.
5. Evidence saved to disk.
6. Cleanup or explicit residue acceptance.

## Evidence Bundle Per Scenario

For each scenario, capture:

1. The exact command(s) run.
2. `fwc` JSON output.
3. Relevant `fcp-host` logs.
4. A side-channel verification artifact.
5. A screenshot when a GUI is involved.
6. Cleanup confirmation.

Suggested artifact layout:

```text
artifacts/true-e2e/<date>/<connector>/<scenario>/
  command.txt
  fwc-output.json
  host.log
  verify.json
  screenshot.png
  cleanup.txt
```

## Priority Order

## Wave 0: Operator-Surface Sanity

Purpose:

- prove the latest repo-built `fwc` and `fcp-host` are the binaries we should trust
- verify basic CLI and host truthfulness before spending time on service auth

What to test:

1. Fresh-build `fwc` and confirm offline catalog consistency.
2. Fresh-build `fcp-host`.
3. Start `fcp-host` with a tiny connector inventory file.
4. Confirm `fwc list`, `fwc show`, `fwc ops`, `fwc status`, and `fwc doctor` against the live host.

Pass criteria:

- live host inventory matches what we registered
- connector discovery is truthful
- no placeholder or fabricated runtime state

## Wave 1: Best Mac-Local True E2E Targets

### 1. Apple Notes

Why first:

- real local app
- no cloud account needed
- true read and write loop is available
- easy screenshot verification

Scenarios:

1. `health`
2. `list_notes`
3. `search_notes`
4. `create_note`
5. `get_note` for the note just created

Out-of-band verification:

- AppleScript read-back
- open Notes.app and capture screenshot of the created note

Extra macOS requirements:

- Automation permission for Notes
- likely Screen Recording permission if we capture screenshots through automation

### 2. Apple Reminders

Why second:

- same local-only advantage
- equally good GUI verification path
- reversible enough if we use a dedicated test list

Scenarios:

1. `health`
2. `list_lists`
3. `create_reminder`
4. `list_reminders`
5. `complete_reminder`

Out-of-band verification:

- AppleScript read-back
- open Reminders.app and capture screenshot

Extra macOS requirements:

- Automation permission for Reminders

## Wave 2: Lowest-Friction Real Cloud/API Targets

### 3. GitHub

Why high value:

- clean PAT-based setup
- obvious reversible read/write scenarios
- strong operator value for `fwc`

Scenarios:

1. `get_repo` or equivalent read-only sanity check
2. issue list/search
3. create issue in a scratch repo
4. optional comment / close / reopen cycle

Out-of-band verification:

- GitHub web UI screenshot
- optional `gh issue view` read-back

What we need:

- a PAT with appropriate repo scopes
- a dedicated scratch repo

### 4. Telegram

Why high value:

- you already know this family is promising
- bot-token auth is relatively simple
- clear read/write verification in a real chat

Scenarios:

1. doctor/self-check
2. send message to a dedicated chat
3. optional file/media flow

Out-of-band verification:

- Telegram desktop app or phone screenshot

What we need:

- bot token
- dedicated test chat or channel

### 5. Slack

Why good:

- bot token flow is straightforward
- visible UI verification
- streaming exists, but write-first verification is enough for first pass

Scenarios:

1. doctor/self-check
2. list channels
3. post message to dedicated test channel
4. optional edit or reaction flow

Out-of-band verification:

- Slack desktop app screenshot

What we need:

- bot token
- optional app token if we want Socket Mode
- dedicated test workspace/channel

### 6. Notion

Why good:

- token-based auth
- obvious read/write workflow
- visible browser/app verification

Scenarios:

1. search or get page
2. create page in a scratch workspace area
3. append or update content

Out-of-band verification:

- Notion app or browser screenshot

What we need:

- integration token
- a scratch page or database shared with that integration

## Wave 3: Real But Heavier Auth/Provisioning

### 7. Gmail

Why heavier:

- auth is real but more operationally annoying
- write operations are risky

Good first scope:

- read-only first
- send only after read-only path is solid

Scenarios:

1. doctor/self-check
2. list labels
3. list/search messages
4. get one specific message
5. optional send-to-self test in a dedicated mailbox

Out-of-band verification:

- Gmail web UI screenshot

What we need:

- access token, refresh-token flow, or a Google OAuth client flow we control
- ideally a dedicated test Google account

### 8. Google Calendar

Good first scope:

- list calendars
- list events on a scratch calendar
- create a reversible test event

Out-of-band verification:

- Calendar web UI screenshot

What we need:

- same Google auth setup as Gmail
- a dedicated scratch calendar

### 9. Spotify

Why not first:

- OAuth is heavier
- playback verification gets messy

Good first scope:

- read-only search and metadata
- maybe library reads

Later scope:

- playback only if we have a dedicated device and are comfortable with side effects

Out-of-band verification:

- Spotify desktop app or web screenshot

What we need:

- Spotify dev app / OAuth credentials or a direct token path
- optional Premium + active device for playback scenarios

### 10. Discord

Why later than Slack/Telegram:

- bot token is manageable, but gateway/event setup is more stateful
- connector explicitly carries gateway resume-state and lease behavior

Good first scope:

- REST-only read/write checks first
- streaming later

Out-of-band verification:

- Discord app screenshot

What we need:

- bot token
- dedicated test server/channel

## Wave 4: Environment-Specific Targets

### 11. Home Assistant

This is excellent if you have a real local instance.

Good first scope:

- read-only entity state
- one reversible service call on a harmless entity

Out-of-band verification:

- Home Assistant web UI screenshot
- physical or dashboard-visible state change

What we need:

- base URL
- long-lived access token
- a safe test entity

## Not First-Wave

### Browser Connector

Do not treat this as first-wave unless we first solve the control-plane dependency.

To test it for real, we need one of:

1. an existing compatible local browser control-plane service
2. a small adapter that exposes the expected `/navigate` style API
3. a deliberate choice to make "build the browser control plane" its own project

This is still worth doing, but it is not the fastest way to get true E2E confidence in the FCP stack.

## Closed-Loop Verification On macOS

For GUI-backed validation, the loop should be:

1. use `fwc` against live `fcp-host`
2. cause the side effect
3. query the app or service through a second channel
4. capture a screenshot
5. optionally run a tiny AppleScript or UI assertion

For Apple Notes / Apple Reminders specifically:

- create a dedicated test folder/list
- use timestamped sentinel names
- verify via AppleScript query
- verify visually via screenshot
- clean up or mark completed

For cloud apps:

- verify through the provider UI when practical
- prefer dedicated scratch repos/workspaces/channels/calendars/pages

## Fresh-Build Commands We Should Use

All via `rch`:

```bash
rch exec -- cargo build -p fwc --bin fwc
rch exec -- cargo build -p fcp-host --bin fcp-host
rch exec -- cargo build -p fcp-apple-notes --bin fcp-apple-notes
rch exec -- cargo build -p fcp-apple-reminders --bin fcp-apple-reminders
rch exec -- cargo build -p fcp-github --bin fcp-github
rch exec -- cargo build -p fcp-telegram --bin fcp-telegram
rch exec -- cargo build -p fcp-slack --bin fcp-slack
rch exec -- cargo build -p fcp-notion --bin fcp-notion
rch exec -- cargo build -p fcp-gmail --bin fcp-gmail
rch exec -- cargo build -p fcp-google-calendar --bin fcp-google-calendar
```

## Minimal Host Inventory For Wave 1

Example `connectors.json`:

```json
[
  {
    "id": "fcp.apple-notes",
    "binary": "/ABS/PATH/TO/target/debug/fcp-apple-notes",
    "name": "Apple Notes",
    "config": {
      "osascript_path": "/usr/bin/osascript"
    }
  },
  {
    "id": "fcp.apple-reminders",
    "binary": "/ABS/PATH/TO/target/debug/fcp-apple-reminders",
    "name": "Apple Reminders",
    "config": {
      "osascript_path": "/usr/bin/osascript"
    }
  }
]
```

Start host:

```bash
FCP_HOST_BIND=127.0.0.1:8787 \
FCP_HOST_CONNECTORS_FILE=/ABS/PATH/TO/connectors.json \
target/debug/fcp-host
```

## Recommended Immediate Sequence

If we want the fastest path to real confidence, do this:

1. Build fresh `fwc` and `fcp-host` through `rch`.
2. Build fresh Apple Notes and Apple Reminders connectors.
3. Run Wave 0 CLI/host sanity checks.
4. Run Apple Notes true E2E.
5. Run Apple Reminders true E2E.
6. Move to GitHub.
7. Then choose one messaging connector: Telegram first, Slack second, Discord later.

## What I Need From You

To start the first serious wave, I need:

1. Permission to use fresh repo-built binaries instead of the installed `fwc`.
2. Confirmation that we should start with Apple Notes + Apple Reminders first.
3. Willingness to grant macOS Automation permissions when Notes/Reminders prompt.
4. Willingness to grant Screen Recording if we capture UI evidence.
5. A decision on the first cloud target after Apple.

Best recommendation:

1. Apple Notes
2. Apple Reminders
3. GitHub
4. Telegram

## What I Would Do Next

If you say go, I would do this next:

1. Build fresh `fwc`, `fcp-host`, `fcp-apple-notes`, and `fcp-apple-reminders` through `rch`.
2. Create a tiny live `connectors.json`.
3. Start `fcp-host` locally.
4. Run a real Apple Notes create-and-verify scenario.
5. Run a real Apple Reminders create-and-complete scenario.
6. Save evidence artifacts for both.
