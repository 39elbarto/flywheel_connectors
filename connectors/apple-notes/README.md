# Apple Notes Connector V3 Contract

> **Status**: runtime contract documented; manifest/introspection/platform drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Apple scripting upstream**: https://developer.apple.com/documentation/foundation/scripting-support
> **Apple scripting terminology upstream**: https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/AboutScriptingTerminology.html
> **Apple Notes folders upstream**: https://support.apple.com/guide/notes/about-accounts-and-folders-notc3b2d538b/mac

## Purpose

This document fixes the operator-facing contract for `fcp.apple-notes`. The connector exposes the Apple Notes surface currently implemented in this crate: local connector health, note-summary listing, substring search, note retrieval, and note creation through a bounded `/usr/bin/osascript` bridge to the macOS Notes app.

The connector is intentionally a bounded macOS-local bridge. It is not a Notes sync engine, iCloud API client, Notes database reader, media or attachment exporter, folder manager, note editor, note deleter, tag or Smart Folder client, sharing/collaboration manager, streaming event source, or cross-device note replication layer.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `apple_notes.health`
- `apple_notes.list_notes`
- `apple_notes.search_notes`
- `apple_notes.get_note`
- `apple_notes.create_note`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-apple-notes`.
- Manifest ID is `fcp.apple-notes`.
- `BaseConnector` runtime ID is `fcp.apple-notes`.
- Manifest version is `0.1.0`.
- Manifest format is `native`.
- Manifest schema version is `2.1`.
- Configuration accepts:
  - `default_folder`
  - `osascript_path`
  - `subprocess_timeout_secs`
- `osascript_path` defaults to `/usr/bin/osascript`.
- Configuration rejects empty, whitespace-bearing, relative, command-carrier, or non-canonical `osascript_path` values. Production clients only run `/usr/bin/osascript`.
- `subprocess_timeout_secs` defaults to 30 and must be greater than zero.
- `default_folder` is optional and applies when list/create inputs omit `folder`.
- There is no provider token, OAuth flow, credential ID, or network auth material.
- Runtime access to Notes data is mediated by macOS, the Notes app scripting dictionary, and the user's local Automation permission grant.
- `configure()` validates config, builds the process client, sets configured, clears handshaken state, and clears the verifier.
- `handshake()` parses a full `HandshakeRequest`, honors `requested_instance_id`, installs a `CapabilityVerifier`, hashes the checked-in manifest, and reports non-streaming event caps.
- `handshake()` grants only requested capabilities matching `apple_notes.read` or `apple_notes.write`.
- `health()` reports local configured state, platform, manifest hash, and uptime. It does not touch Notes.app.
- `doctor()` reports platform support and configured state. It does not touch Notes.app.
- `self_check()` reports degraded when not configured, failed on non-macOS platforms, and otherwise returns ok with an Automation permission hint. It does not touch Notes.app.
- Runtime `invoke()` uses the FCP `InvokeRequest` shape: `operation`, `input`, and `capability_token`.
- Runtime `invoke()` requires configured and handshaken base state and verifies a bound capability token for the operation capability.
- Runtime capability verification currently passes an empty resource URI list for all Apple Notes operations.
- Runtime `simulate()` validates known operation, configured state, handshake state, and bound capability token. It does not validate full input schema, macOS platform availability, Notes.app availability, or Automation permission.
- Runtime `shutdown()` clears config, client, verifier, configured state, and handshaken state.
- Runtime `subscribe()` and `unsubscribe()` are unsupported.

## Runtime API Adapter

The runtime uses these local AppleScript request shapes:

| Operation | Capability | Required input | Runtime behavior |
|-----------|------------|----------------|------------------|
| `apple_notes.health` | `apple_notes.read` | none | Return local status, platform, and manifest hash without launching Notes.app. |
| `apple_notes.list_notes` | `apple_notes.read` | none | Run a static script that iterates Notes accounts, folders, and notes; optional `folder` scopes by display folder name. |
| `apple_notes.search_notes` | `apple_notes.read` | `query` | Run a static script that checks whether note title or body contains the query substring. |
| `apple_notes.get_note` | `apple_notes.read` | `note_id` | Run a static script that finds a note by stable Notes identifier and returns id, title, folder, and body. |
| `apple_notes.create_note` | `apple_notes.write` | `title`, `body` | Run a static script that creates a note in the requested folder, configured default folder, or first folder of the first account. |

Process and parsing behavior:

- The connector launches `/usr/bin/osascript` directly, never through a shell wrapper.
- User-controlled values are passed as argv, not interpolated into the AppleScript source.
- Child stdin is closed.
- Child stdout and stderr are drained concurrently with a 1 MiB cap per stream.
- The child is polled every 50 ms until it exits or `subprocess_timeout_secs` expires.
- On timeout, the child is killed and the connector returns an internal FCP error.
- Non-zero `osascript` exit status becomes an internal FCP error carrying bounded stderr text.
- `search_notes` rejects an empty or whitespace-only query before subprocess launch.
- `get_note` rejects an empty or whitespace-only `note_id` before subprocess launch.
- `create_note` rejects an empty or whitespace-only `title` before subprocess launch.
- `create_note` does not reject an empty body.
- Note summary output is parsed from tab-separated lines into `{ "notes": [...] }`.
- Note body output is parsed from four newline-separated fields using a split that preserves the remaining body text.
- The connector does not escape tabs in note IDs, titles, or folder names.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- The manifest forbids `system.exec`, but the sandbox uses `deny_exec = false` because this connector has a narrow `/usr/bin/osascript` subprocess carveout.
- The connector is a native Rust binary, but the provider interaction is implemented through static AppleScript executed by `osascript`.
- Runtime has no network capability and intentionally does not call iCloud or any Apple web service.
- Runtime `health()` can report ready on non-macOS after configuration because platform failure is checked by `doctor()`, `self_check()`, and actual client operations.
- `self_check()` does not verify that Notes.app can be automated; it only returns the Automation permission hint on macOS.
- `simulate()` does not validate required input fields, blank string constraints, platform support, app availability, or Automation permission.
- Runtime capability verification does not bind folders, note IDs, note titles, or account names as resource URIs.
- The manifest and introspection expose only a note creation write. There is no edit, move, delete, tag, lock/unlock, attachment, folder creation, or sharing operation.
- The Notes body returned by AppleScript can include Notes app formatting artifacts or HTML-like content depending on the app's scripting behavior.
- Folder selection is by display folder name only. Duplicate folder names across accounts are not disambiguated.
- The connector lists folders inside every account, but it does not expose account selection.
- `InvokeRequest.deadline_ms` is not used to shorten the `osascript` timeout.
- No dedicated tracked verification shell script exists for this connector.

A follow-up parity bead should decide whether to expose account-aware folder targeting, add resource URI binding for notes/folders, make simulation validate input and platform state, surface Automation permission failure more explicitly, consider a safe note-update path if needed, and reconcile the manifest's `system.exec` prohibition with the intentional bounded `osascript` carveout in a machine-checkable way.

## First-Slice Scope

The current Apple Notes README slice documents the existing runtime surface:

- macOS-local `osascript` configuration and canonical binary enforcement
- Note listing, search, get, and create operations
- Local health, doctor, self-check, introspection, simulate, invoke, subscribe, unsubscribe, and shutdown behavior
- Capability-token verification and current empty resource-URI binding
- Static-script and argv behavior for user values
- Bounded subprocess timeout, kill, stdout/stderr cap, and process-error behavior
- Runtime/manifest/platform drift around the subprocess carveout, Automation permission, account/folder ambiguity, simulation, deadlines, and unsupported Notes features
- Existing test orientation through manifest/introspection contract checks, capability denial tests, streaming-denial tests, bounded subprocess tests, argv-shape tests, non-macOS skip behavior, and explicit operator-gated live fixture skips

## Auth And Zone Boundary

- Authentication mechanism: macOS user session and local Notes.app Automation permission.
- Home zone: `z:owner`.
- Allowed source zones: `z:owner` and `z:private`.
- Allowed target zones: `z:owner` and `z:private`.
- Forbidden zones: `z:public`, `z:community`, and `z:work`.
- Runtime capability families:
  - `apple_notes.read`
  - `apple_notes.write`
- Manifest required capabilities are `apple_notes.read` and `apple_notes.write`.
- Manifest forbids `network.listen`, `network.outbound`, `system.exec`, and `system.privileged`, with the current bounded `osascript` carveout represented by `deny_exec = false`.
- The connector does not intentionally persist Notes contents, note IDs, folder names, account names, subprocess output, request counters, or error counters outside process memory.
- Apple Notes payloads can contain private user notes, note HTML/body content, folder names, account-derived organization, and iCloud-synced content visible in the local Notes app. Treat live input and output as owner/private-zone sensitive unless the host supplies a stricter zone policy.

## Explicit Non-Goals

- No iCloud API client.
- No direct Notes database access.
- No media or attachment export.
- No note edit, move, delete, pin, lock, unlock, tag, or share operation.
- No folder or account management.
- No account-scoped folder selection.
- No Smart Folder or tag search.
- No streaming note-change events.
- No durable local note cache.
- No cross-zone note publication.

## Verification

README-only changes do not require Cargo or `rch` verification. Before committing this file, run:

```bash
git diff --check -- connectors/apple-notes/README.md
LC_ALL=C rg -n '[^ -~]' connectors/apple-notes/README.md
rg -n '\bmaster\b' connectors/apple-notes/README.md
ubs connectors/apple-notes/README.md
```

For code changes in this connector, use the workspace-required proof lane from the root `AGENTS.md`:

```bash
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
rch exec -- cargo fmt --check
```
