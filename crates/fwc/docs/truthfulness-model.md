# FWC Truthful Runtime Model

This is the runtime truth contract for `fwc`, not a recommendation to keep the
current host-backed provisioning boundary as the permanent center of the
architecture. Use it to distinguish what is authoritative today from what is
still transitional on the path to mesh-backed steady state.

## Overview

Every `fwc` command output carries an **availability envelope** that tells the consumer exactly where the data came from and whether it can be trusted for live operations. The truth hierarchy ranks sources by confidence:

- **`mesh-backed`** — data backed by distributed mesh state (gossip, placement, multi-node consensus); highest confidence. This is the target steady-state default; currently requires mesh peers with placement evidence.
- **`host-backed`** — data fetched from a running `fcp-host` instance; authoritative for node-local state. This is the current transitional default.
- **`node-local`** — data from the local node without host or mesh backing; intermediate confidence.
- **`offline-artifact`** — data derived from workspace manifests and local files; useful for planning but not authoritative.

The two fundamental modes remain:

- **`live-runtime`** — data from a live truth source (mesh-backed or host-backed); authoritative for current state.
- **`offline-artifact`** — data derived from workspace manifests and local files; useful for planning but not authoritative.

The core invariant: **fwc never fabricates live-runtime data from offline artifacts**, and never silently falls back from one mode to the other.

## The No-Fakes Contract

1. **No silent fallback.** If a command needs a host and none is available, fwc returns a clear error with `next_actions` suggesting `--host <endpoint>` or `--offline`. It never quietly substitutes workspace manifests for live data.

2. **No placeholder authority.** Test tokens, stub certificates, or demo credentials never appear in live CLI paths. Auth failures produce explicit error envelopes with `recoverable: true` and guidance to provide real capability tokens.

3. **No guessed capability bits.** Fields like `supports_simulate`, `health`, and `state` are reported exactly as the host or manifest declares them. If the value is unknown, the output says `"unknown"` or `null` — never a fabricated default.

4. **No misleading live-vs-offline markers.** Every JSON payload includes an `availability` object:
   ```json
   {
     "availability": "live-runtime" | "offline-artifact" | "denied" | ...,
     "command": "list",
     "authoritative": true | false,
     "explanation": "...",
     "recoverable": true | false,
     "next_actions": ["..."]
   }
   ```

## Availability States

| State | Tag | Authoritative | Meaning |
|-------|-----|---------------|---------|
| Live Runtime | `live-runtime` | Yes | Data from a live truth source: mesh-backed (highest confidence) or host-backed (transitional default) |
| Offline Artifact | `offline-artifact` | No | Data from workspace manifests/local files |
| Unsupported | `unsupported` | No | The connector/surface does not implement this |
| Planned | `planned` | No | Feature exists as contract preview only |
| Unavailable | `unavailable` | No | Surface should exist but is temporarily unreachable |
| Denied | `denied` | No | Blocked by policy, auth, or zone restrictions |
| Unknown | `unknown` | No | Cannot determine state (first query pending, mixed signals) |

## Command Classification

Every command is classified by its **truth source** (`catalog.rs::COMMAND_CLASSIFICATIONS`):

- **LiveHost** — authoritative only when backed by a live host (e.g., `invoke`, `simulate`, `list --host`)
- **OfflineArtifact** — works entirely from local artifacts (e.g., `guide`, `task`, `session`)
- **Hybrid** — operates in both modes with explicitly different behavior (e.g., `list`, `show`, `schema`, `ops`)
- **Passthrough** — delegates to a separate subsystem with its own truth model

Hybrid commands require either `--host <endpoint>` or `--offline`. Without either flag, they return a `missing-host` error with recovery guidance.

## Workflow Truth

The intent compiler (`intent.rs`) attaches a `workflow_truth` object to every compiled plan:

```json
{
  "availability": "live-runtime",
  "source_of_truth": "local-intent-compiler",
  "authoritative": false,
  "recoverable": false,
  "exit_code_hint": 0,
  "explanation": "The compiled workflow includes primitives that default to live host truth."
}
```

Key semantics:
- `source_of_truth` is always `"local-intent-compiler"` for plans — the compiler is honest that it is planning, not executing.
- `authoritative` is `false` for plans (the plan hasn't been executed yet).
- `availability` reflects the aggregate of all compiled steps: if any step requires a live host, the workflow truth says `live-runtime`.

## Metadata Provenance

The `MetadataProvenance` enum (`readiness.rs`) tracks where each metadata value originated:

- `declared-by-connector` — from the connector's own manifest
- `observed-by-host` — observed/computed by the host at runtime
- `measured-at-runtime` — measured during actual execution
- `inferred-from-policy` — inferred from policy/zone/config
- `unattributed` — origin not tracked (legacy path)

Only `observed-by-host`, `measured-at-runtime`, and mesh-backed observations are considered authoritative for live operations. When mesh-backed evidence is available, it supersedes host-only observations in the truth hierarchy.

## Operator Playbook

### Successful Invoke

```
fwc --json --host http://host:8787 invoke github issues.create \
  --input '{"owner":"octocat","repo":"hello","title":"New issue"}' \
  --capability-token <token>
```

Expected output contains:
- `"status": "ok"` with `"availability": {"availability": "live-runtime", "authoritative": true}`
- History entry with `"status": "success"`, connector_id, operation_id, timestamp

### Denied Invoke (Preflight Rejection)

Same command, but preflight returns denied:
- `"status": "denied"`, `"phase": "preflight"`, exit code != 0
- `"error": {"type": "policy-denied"}` with reason
- `"next_actions"` array with remediation suggestions (check status, try simulate, review policy)
- History entry records `"status": "denied"` with error_code

### Missing Auth Token

Invoke without `--capability-token`:
- `"status": "error"`, `"error": {"type": "missing-capability-token", "recoverable": true}`
- CLI exits before contacting the host
- `"next_actions"` suggests providing `--capability-token` or `--capability-token-file`

### Conflicting Flags

`fwc --host <url> list --offline`:
- `"status": "error"`, `"error": {"type": "ambiguous-catalog-source"}`
- Clear message: "cannot combine live host mode with --offline"

### Offline Discovery

```
fwc --json list --offline
fwc --json search "github issue" --offline
fwc --json schema github issues.create --offline
```

All produce `"availability": "offline-artifact"`, `"authoritative": false`.
None contain `"host-admin-api"` or `"live-runtime"` anywhere in the payload.

## Agent Playbook

### Planning a Workflow

```
fwc --json plan "create a GitHub issue titled 'Bug report'"
```

Response structure:
- `plan["workflow"]["workflow_truth"]` — truthfulness contract for the compiled plan
- `plan["availability"]` — top-level availability (always `offline-artifact` for plans)
- `plan["workflow"]["steps"]` — ordered `fwc` primitives to execute
- `plan["workflow"]["suggested_command_lines"]` — copy-pasteable commands

The agent should check `workflow_truth.availability`:
- `live-runtime` → plan requires a host to execute
- `offline-artifact` → plan can execute locally
- `unknown` → plan has ambiguous steps, needs clarification

### Export Tools for MCP

```
fwc --json export-tools --host http://host:8787 --format mcp
fwc --json export-tools --offline --format mcp
```

Live export: `"source": "host-admin-api"`, `"availability": "live-runtime"`
Offline export: `"source": "workspace-manifests"`, `"availability": "offline-artifact"`

The tool inventory in live export reflects what the host currently serves. The offline export uses workspace manifests which may be stale.

## Evidence and Transcript Model

### History Entries

Every invoke/simulate call is recorded in the local history store with:
- `connector_id` — exact connector identifier
- `operation_id` — exact operation name
- `status` — `success`, `denied`, `error`, `simulated`, `timeout`, `rate_limited`
- `timestamp` — ISO 8601 when the operation was recorded
- `agent_session` — session ID if running under `fwc session`

Query with: `fwc --json history [--connector X] [--status Y]`

### Transcript Types (catalog.rs)

- `TranscriptEntry` — single event with phase, mode, source, authoritative flag
- `ReplayArtifact` — ordered entries for one scenario, with fixture hash and source flags
- `EvidenceBundleMetadata` — summary: command count, live count, offline count, redaction safety

### Evidence Assertions

Verification tests use these transcript types to prove:
- Live evidence and offline evidence are never mixed in a single authoritative claim
- Replay artifacts are deterministic when they use only offline sources
- Evidence bundles correctly count live vs offline entries

## Verification Surface Map

| Layer | Location | What It Tests |
|-------|----------|---------------|
| Unit tests | `crates/fwc/src/*.rs` | Individual truth contracts, enum semantics, provenance |
| Invariant tests | `crates/fwc/src/intent.rs`, `workflow.rs` | Compiler honesty, step availability aggregation |
| Integration tests | `crates/fwc/tests/cual_integration.rs` | Mock-host E2E flows, availability boundary enforcement |
| Golden vectors | `crates/fwc/src/main.rs` (bottom) | Exit code contracts, command routing, offline mode |

### Key Integration Tests (cual_integration.rs)

**Truth Matrix (bead 29.8.1):**
- `truth_matrix_live_vs_offline_availability_boundary` — live vs offline markers
- `truth_matrix_auth_enforcement_denies_without_capability_token` — early auth denial
- `truth_matrix_simulate_support_honestly_reported` — supports_simulate propagation
- `truth_matrix_metadata_honesty_unknown_stays_unknown` — no fabricated metadata
- `truth_matrix_export_tools_reflects_inventory_provenance` — source provenance
- `truth_matrix_receipt_evidence_in_history` — history receipt completeness

**E2E Scenarios (bead 29.8.2):**
- `e2e_authenticated_invoke_lifecycle_with_evidence_trail` — full lifecycle
- `e2e_denied_invoke_with_recovery_evidence_and_history` — denial + retry + dual history
- `e2e_offline_workflow_never_leaks_live_markers` — isolation regression gate
- `e2e_live_export_reflects_host_inventory_not_stale_manifests` — inventory truth
- `regression_gate_conflicting_offline_and_host_flags_rejected` — flag conflict
- `regression_gate_missing_host_for_live_commands_not_fabricated` — no fabrication
- `regression_gate_plan_commands_include_workflow_truth` — plan truthfulness

## Migration from Ambiguous Semantics

### Before (ambiguous)
- Commands silently used offline data when host was unavailable
- `supports_simulate` defaulted to `true` if not explicitly set
- History entries lacked provenance markers
- No `availability` envelope in JSON output

### After (explicit)
- Every command explicitly declares its data source in `availability`
- Missing host produces an error with `next_actions`, not silent degradation
- `supports_simulate` is exactly what the host/manifest declares
- History entries always include connector_id, operation_id, status, timestamp
- Conflicting `--offline` + `--host` is a hard error

### How to Run Verification

```bash
# All fwc tests (unit + fixture + integration)
cargo test -p fwc

# Integration tests only
cargo test -p fwc --test cual_integration

# Specific regression gates
cargo test -p fwc --test cual_integration -- regression_gate_

# E2E scenarios
cargo test -p fwc --test cual_integration -- e2e_

# Truth matrix tests
cargo test -p fwc --test cual_integration -- truth_matrix_
```

All cargo commands should be run via `rch exec -- ...` for build offloading.
