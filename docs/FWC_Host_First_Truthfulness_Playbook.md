# FWC Truthfulness Playbook

> Status: active operator/agent guide for the `fwc` truth contract (transitional V1 provisioning boundary, converging toward mesh-native V2 steady state)
> Truth hierarchy: **mesh-backed > host-backed > node-local > offline**
> Operational model: **V1 (Host-First, transitional)** — see [OPERATIONAL_MODEL_VERSIONS.md](OPERATIONAL_MODEL_VERSIONS.md) for version definitions and cutover gates
> Primary beads: `flywheel_connectors-1g7z0.29.8`, `flywheel_connectors-1g7z0.29.8.3`
> Implementation anchors: `crates/fwc/src/catalog.rs`, `crates/fwc/src/readiness.rs`, `crates/fwc/src/truth.rs`, `crates/fwc/src/main.rs`, `crates/fwc/tests/cual_integration.rs`, `crates/fwc/src/test_observability.rs`, `docs/testing/e2e_log_schema.md`, `docs/testing/coverage-inventory.md`
>
> This playbook is a truth-contract and cutover-audit reference. It documents
> the still-real host-backed boundary honestly, but it is not the preferred
> long-term architecture to teach new contributors as the end state.

## Purpose

This playbook explains how `fwc` behaves under the current truthfulness model. The host-first provisioning boundary is transitional; the mesh-native truth resolver (`crates/fwc/src/truth.rs`) already supports mesh-backed, host-backed, node-local, and offline resolution strategies. As the cutover completes, mesh-backed answers will become the default highest-confidence source.

The short version:

- live runtime truth comes from the highest-confidence available source: mesh-backed (preferred) or host-backed (current transitional default)
- offline artifact work must be explicit
- the no-fakes invariant is mandatory: placeholder runtime data, guessed capability bits, and hidden file-edit side channels are bugs
- unknown, unsupported, denied, planned, and unavailable states must stay distinct
- tests and transcripts must make truth failures obvious without re-deriving the original planning thread

## The Implemented Truth Boundary

The canonical command classification lives in `crates/fwc/src/catalog.rs`.

| Source class | Meaning | Example posture |
|---|---|---|
| `LiveHost` | Authoritative only when backed by a live truth source (host-backed today, mesh-backed when cutover completes) | `invoke`, `simulate`, lifecycle/config/admin verbs |
| `OfflineArtifact` | Purely local artifact or history workflow | `guide`, `task`, `plan`, `history` |
| `Hybrid` | Live by default, but explicit offline artifact mode is allowed | `list`, `search`, `show`, `ops`, `schema`, `examples`, `suggest`, `template`, `validate`, `export-tools` |
| `Passthrough` | Delegates to another subsystem with its own truth model | trace/audit style subsystems where the boundary is separate |

The resolved runtime mode is also centralized in `crates/fwc/src/catalog.rs`.

| Runtime mode | Meaning | Authority |
|---|---|---|
| `live` | Live host was resolved and reached | authoritative |
| `explicit-offline` | User explicitly requested artifact mode, or the command is inherently local | not authoritative for live runtime |
| `degraded-offline` | Command prefers live truth but is allowed to continue with offline warnings | not authoritative |
| `refused` | Command requires live host truth and no honest live path exists | no execution |

The contract is strict: dispatch resolves mode once, before doing work, and no handler is allowed to silently switch from live runtime to offline artifacts mid-flight.

## The No-Fakes Invariant

The truthfulness contract is not just about better labels. It is a ban on fake runtime confidence.

`fwc` must never:

- present manifest or cache data as though it came from the running host
- advertise connector dry-run semantics when only host preflight exists
- replace `planned`, `unsupported`, `unavailable`, `denied`, or `unknown` with a generic success-looking payload
- mutate runtime state through local file edits and then report the result as if the host accepted it

If a surface cannot produce honest live-runtime truth, it must do one of four things:

1. return a real `live-runtime` result from the host
2. require explicit `--offline` and label the result `offline-artifact`
3. degrade with a visible warning only when the command contract explicitly allows it
4. refuse the operation instead of fabricating success

## Availability Vocabulary

User-facing envelopes should use the `CommandAvailability` vocabulary from `crates/fwc/src/readiness.rs`.

| Availability | Meaning | Recoverable |
|---|---|---|
| `live-runtime` | Result came from a live host/mesh path | no |
| `offline-artifact` | Result came from manifests, local catalog, static contracts, or other offline data | no |
| `unsupported` | The host or connector definitively does not implement the surface | no |
| `planned` | Contract preview exists, but the runtime path is not implemented | no |
| `unavailable` | Host or endpoint should exist but is temporarily unreachable | yes |
| `denied` | Policy, approval, auth, or zone rules blocked the operation | yes |
| `unknown` | The system cannot truthfully classify current availability yet | yes |

Two invariants matter more than any specific wording:

1. Only `live-runtime` is authoritative.
2. Offline success must never pretend to be live success.

## Discovery and Catalog Provenance

Discovery-family commands are expected to emit explicit provenance describing where the data came from.

The current discovery provenance contract in `crates/fwc/src/catalog.rs` distinguishes:

- `live-host-inventory`
- `live-host-introspection`
- `workspace-manifest`
- `local-catalog-cache`
- `static-schema`

Anything in the first two buckets is authoritative. Everything else is an offline or static view and must carry a freshness caveat.

## Outcome And Remediation Matrix

These states are not interchangeable. Operators and agents should read them as different classes of truth.

| State | What it means | How to react |
|---|---|---|
| `live-runtime` | The host answered and the payload is authoritative | Continue with current runtime assumptions |
| `offline-artifact` | The payload is useful, but it came from manifests, cache, or static schema | Treat it as preparation data and re-run against `--host` before assuming live truth |
| `denied` | The runtime path was real, but policy/auth/approval/zone rules blocked it | Inspect policy, zone, approvals, or `fwc auth status` |
| `unsupported` | The connector or host definitively does not implement the surface | Stop retrying the same shape and inspect supported operations or upgrade paths |
| `planned` | The command currently exposes a contract preview only | Do not automate against it as though it were live |
| `unavailable` | The live surface should exist, but the host or endpoint is unreachable | Restore reachability or intentionally switch to `--offline` |
| `unknown` | The system cannot truthfully classify the runtime state yet | Query a specific host, inspect provenance, or run `fwc doctor` |

### Example: Live Runtime Success

```bash
fwc --host http://127.0.0.1:8765 show github
```

What to look for:

- resolved mode is live, not offline
- availability is `live-runtime`
- provenance is host-backed (`live-host-introspection` or `live-host-inventory`)

### Example: Explicit Offline Preparation

```bash
fwc show github --offline
```

What to look for:

- resolved mode is `explicit-offline`
- availability is `offline-artifact`
- provenance is `workspace-manifest`, `local-catalog-cache`, or `static-schema`
- manifest lifecycle metadata may still appear on the connector record, but live runtime state must remain `unknown`
- output carries a caveat that it may not match the running system

### Example: Denial Is A Real Runtime Answer

When a preflight or invoke path returns `denied`, that is not a transport failure and not a reason to fall back to manifest-backed output.

What to look for:

- availability is `denied`
- the payload or error explains whether policy, approval, auth, or zone rules blocked the request
- `next_actions` point to auth, policy, zone, or approval remediation

### Example: Planned Or Unsupported

`planned` means "contract preview only." `unsupported` means "definitively not implemented here." Both are non-authoritative and non-recoverable in the short term, but they mean different things operationally:

- `planned`: wait for the bead to land; do not treat the preview as a live feature
- `unsupported`: inspect `fwc ops <connector>` or upgrade/change connector strategy

### Example: Unavailable Or Unknown

These are the two recoverable "not ready to trust this answer yet" states:

- `unavailable`: the live path exists but is down or unreachable
- `unknown`: the system lacks enough trustworthy signal to classify the state

The fix is to restore reachability, target a specific host, or intentionally switch to `--offline` with eyes open. The fix is not to silently re-label offline data as runtime truth.

## Operator Playbooks

### 1. When you need live runtime truth

Use a real host endpoint or active host context. If the command is classified as live-host or hybrid-with-live-default, lack of host truth should fail clearly rather than quietly consulting manifests.

Good examples:

```bash
fwc --host http://127.0.0.1:8765 list
fwc --host http://127.0.0.1:8765 show github
fwc --host http://127.0.0.1:8765 export-tools --format mcp github
```

Expected outcome:

- source/provenance says host-backed
- availability is `live-runtime`
- the caller can tell this is current running-system truth

### 2. When you intentionally want offline artifact work

Say so explicitly with `--offline` for hybrid commands.

Good examples:

```bash
fwc list --offline
fwc search "github issue" --offline
fwc schema github issues.create --offline
fwc validate github issues.create --offline --input-file payload.json
```

Expected outcome:

- source/provenance points at manifests, local catalog, or static schema
- availability is `offline-artifact`
- output includes the caveat that offline data may not reflect the running system

### 3. When a command is denied

Treat `denied` as a real runtime answer, not as a vague failure.

Operator next steps should usually be:

- inspect auth state with `fwc auth status`
- inspect policy/zone constraints
- obtain approvals or use the correct zone/context

### 4. When a command is unavailable or unknown

Do not patch around these states by fabricating answers.

- `unavailable` means a real surface exists but the live path is currently unreachable
- `unknown` means the system cannot honestly classify the current state yet

The correct remediation is to restore host reachability, run diagnostics, or intentionally switch to `--offline`. It is not acceptable to silently return manifest-backed runtime-looking output.

### 5. When dealing with simulate versus preflight

The simulate contract is intentionally narrower than a generic “preview.”

- real dry-run and host preflight are different things
- connectors that only support preflight must not be advertised as full simulators
- result payloads must say whether the system performed connector simulation or only host-side validation/policy/budget checks

The enforcement types live in `crates/fwc/src/catalog.rs`:

- `SimulateCapability`
- `SimulateResult`
- `DiscoveryDataSource`

## Production Deployment Runbook

This section is the operator-facing deployment guide for the current
transitional platform shape. The host-first provisioning boundary is how
systems come online today; the mesh-native infrastructure (gossip, IBLT,
LiveTruthResolver, KnowledgeState taxonomy) is built and tested but not yet
the production default. This guide teaches honest operation during the
transition.

### Proof anchors

Use these artifacts together when you need to justify a deployment claim:

| Evidence surface | Why it matters |
|---|---|
| `docs/FCP3_Acceptance_Contracts.md` | Names the phase-5 mesh and phase-6 CLI truth proof obligations |
| `docs/testing/core_platform_evidence_index.md` | Lists the rerun commands for the platform crates behind the operator story |
| `crates/fwc/tests/cual_integration.rs` | Freezes operator-truth fixture classes, including `mesh_backed`, `node_local`, `offline`, and `degraded` |
| `crates/fcp-host/tests/host_connector_integration.rs` | Covers rollout, rollback, config mutation, and host-backed lifecycle/admin flows |

If the guide below and those proof surfaces diverge, trust the proof surfaces
and update the guide.

### Current honest topology

Treat production today as a **single-active-host, warm-standby mesh** — this is the transitional provisioning boundary while mesh-native failover and state convergence complete cutover gating.

| Role | Must exist | Current truthful responsibility | Post-cutover role |
|---|---|---|---|
| Active host node | Yes | Runs `fcp-host`, supervises connectors, owns the authoritative live admin state | Becomes one mesh peer among equals |
| Standby host-capable peer | Strongly recommended | Holds the same binaries, manifests, and deployment artifacts so promotion is deliberate and fast | Automatic failover via mesh placement |
| Mesh/object peers | Yes for mesh-backed claims | Supply placement/durability context that can elevate a live answer from host-backed to mesh-backed | Primary truth source (highest confidence) |

Current transitional assumptions (will be superseded by mesh cutover):

- all live operator mutations still flow through the active `fcp-host`
- `FCP_HOST_CONNECTORS_FILE` is the live connector inventory mutation surface
- `FCP_HOST_LIFECYCLE_STATE_FILE` is the local admin-state snapshot that must
  move with the promoted host
- connector admin/lifecycle state is still node-local; the mesh infrastructure
  for automatic state convergence is built (`fcp-mesh` gossip, IBLT) but not
  yet the production default

### Provisioning sequence

1. Build release binaries with remote compilation.
   ```bash
   rch exec -- cargo build -p fcp-host -p fwc --release
   ```
2. Stage the same connector binaries and manifests on the active node and at
   least one standby peer.
3. Provision explicit host-state paths on the active node.
   ```bash
   export FCP_HOST_BIND=0.0.0.0:8787
   export FCP_HOST_CONNECTORS_FILE=/srv/fcp/connectors.json
   export FCP_HOST_LIFECYCLE_STATE_FILE=/srv/fcp/lifecycle-state.json
   ./target/release/fcp-host
   ```
4. Keep the connector inventory file and lifecycle state file under your normal
   deployment backup/replication discipline. They are the current operator truth
   surfaces for live inventory and lifecycle history.

### Secret and config flow

Configuration changes should always preserve a replayable rollback path.

1. Export the live baseline before changing anything.
   ```bash
   fwc config export github --host http://127.0.0.1:8787 --file baseline.json
   ```
2. Validate the current live snapshot.
   ```bash
   fwc config doctor github --host http://127.0.0.1:8787
   ```
3. Import the candidate config document.
   ```bash
   fwc config import github --host http://127.0.0.1:8787 --file candidate.json
   ```
4. Re-run `fwc config doctor`.

Important limitation:

- if `fwc config export` reports a sanitized non-replayable snapshot, the
  exported file is inspection evidence only, not a rollback artifact
- when that happens, either move secrets into credential references or prepare
  a complete replacement config document explicitly before you mutate live state

### Bring-up verification loop

Run this minimum command set after provisioning and after every promotion:

```bash
fwc --host http://127.0.0.1:8787 list
fwc --host http://127.0.0.1:8787 mesh explain-availability github
fwc --host http://127.0.0.1:8787 status github
fwc --host http://127.0.0.1:8787 doctor --zone z:work --all
fwc config doctor github --host http://127.0.0.1:8787
```

How to interpret the answers:

- `list`, `status`, `doctor`, `config doctor`, and rollout/config mutation
  answers are authoritative only when they come from the live host
- `mesh explain-availability` is the surface that can legitimately upgrade the
  story from merely host-backed/node-local truth to mesh-backed truth
- if the best honest answer is still `node_local`, `host_backed`, `degraded`,
  or `offline`, do not describe the deployment as fully mesh-backed yet

### Rollout and rollback sequence

Use rollout commands as the live operator mutation path:

```bash
fwc rollout set github --canary 10 --host http://127.0.0.1:8787
fwc rollout status github --host http://127.0.0.1:8787
fwc status github --host http://127.0.0.1:8787
fwc doctor --zone z:work --all --host http://127.0.0.1:8787
fwc rollout rollback github --to 1.2.2 --host http://127.0.0.1:8787
```

Read the truth contract literally:

- `rollout set` proves that the active node accepted the canary mutation
- `rollout status` proves the current node-local rollout state snapshot
- `rollout rollback` proves that the rollback mutation happened on the active node
- none of those answers by themselves prove later runtime stabilization

The stabilization check is always the same follow-up loop:

1. `fwc rollout status ...`
2. `fwc status ...`
3. `fwc doctor --zone ... --all ...`
4. `fwc mesh explain-availability ...`

### Failover and promotion assumptions

The current failover story is **supervised promotion** — the transitional
boundary while automatic mesh-native failover completes cutover gating. The
mesh infrastructure for automatic placement and state convergence is built
(`fcp-mesh` gossip, `ObjectPlacementPolicy`, `RepairController`) but not yet
the production default.

Use this checklist for the current transitional path:

1. Confirm the current active host is degraded or unavailable via `status`,
   `doctor`, and `mesh explain-availability`.
2. Promote the staged standby peer with the same connector binaries, manifests,
   connector inventory file, and lifecycle state snapshot.
3. Re-run the bring-up verification loop against the promoted host.
4. Only after the promoted host returns truthful live answers should you route
   normal operator traffic to it.

The following capabilities are built and tested but require cutover gate
completion before production use (see `docs/FCP3_Transition_Scorecard.md`):

- automatic lease handoff between nodes (mesh placement)
- automatic multi-node connector-state convergence (gossip sync)
- active/active host mutation safety (distributed consensus)
- post-promotion equivalence without re-running the verification loop

### Evidence and diagnosis bundle

When a deployment check or promotion drill fails, use the replayable evidence
contract rather than ad hoc shell guessing.

Start with the same bundle order described elsewhere in this playbook:

1. `summary.json`
2. `trace.jsonl`
3. `environment.json`
4. `replay.sh`

Then re-run the platform proof surfaces that back this runbook:

```bash
rch exec -- cargo test -p fwc --test cual_integration
rch exec -- cargo test -p fcp-host --test host_connector_integration
rch exec -- cargo test -p fcp-e2e
```

Those commands do not prove a specific deployment is healthy, but they are the
fastest way to separate a local deployment/configuration problem from a broken
platform contract.

## Migration Checklist

Use this checklist whenever you move an older or ambiguous `fwc` surface into the host-first truthful model.

1. Decide whether the command is `live_host`, `offline_artifact`, `hybrid`, or `passthrough` in `crates/fwc/src/catalog.rs`.
2. Resolve runtime mode before doing any real work. Do not let handlers invent fallback behavior ad hoc.
3. Make offline behavior explicit with `--offline` and non-authoritative provenance markers.
4. Remove guessed capability bits, placeholder hashes, demo bundles, and local-file mutation shortcuts from the canonical runtime path.
5. Emit `CommandAvailability` and provenance information so callers can tell live truth from local preparation data.
6. Add or update tests proving the live path, refusal/degradation path, and explicit offline path.
7. Extend the docs and playbooks so operators know how to read the resulting evidence without reopening the planning thread.

## Agent Playbooks

### Adding or changing a command

When you add a new `fwc` command or modify an existing one:

1. Update the command classification matrix in `crates/fwc/src/catalog.rs`.
2. Resolve runtime mode before performing work.
3. Use explicit availability/provenance envelopes instead of inferred success.
4. Add or update tests showing the live path, the explicit offline path if supported, and the refusal path when live truth is required but absent.

### Migrating a formerly ambiguous surface

The migration rule is not “make it work somehow.” The migration rule is:

- live runtime behavior becomes host-authoritative
- offline behavior becomes explicit and visibly non-authoritative
- fake defaults, guessed capability bits, and silent fallbacks are removed rather than hidden

### Reviewing a change for truthfulness regressions

Reject the change if it does any of the following:

- silently falls back from live runtime to manifests or local cache
- replaces `unknown` with a plausible-looking default
- labels preflight-only behavior as simulate or dry-run
- treats offline success as authoritative runtime state
- swallows provenance/source details that tell the caller where the answer came from

## Verification Surfaces

This bead is the documentation layer of a wider evidence stack. The sibling beads provide more of the executable proof surface:

| Bead | Evidence role |
|---|---|
| `flywheel_connectors-1g7z0.29.8.1` | Host-backed integration matrix for live/offline/auth/simulate/MCP boundaries |
| `flywheel_connectors-1g7z0.29.8.2` | End-to-end regression scenarios for the no-fakes invariants |
| `flywheel_connectors-1g7z0.29.8.5` | Transcript scripts, detailed logging, replay bundle contract |
| `flywheel_connectors-1g7z0.29.8.3` | Operator/agent guide for interpreting the evidence correctly |

### Frozen Operator Contract Matrix

The canonical fixture set for stable operator-truth answers now lives in `crates/fwc/testdata/operator_truth/fixture_matrix.json`.

It freezes six representative answer classes spanning the five required operator-truth modes, so downstream CLI work can depend on one shared acceptance matrix without re-reading implementation details:

- `offline`: manifest-backed `show --offline` answers
- `node_local`: host-admin `status <connector> --host ...` answers
- `mesh_backed`: live `mesh explain-availability` answers with placement-backed readiness
- `degraded`: live `health <connector> --host ...` answers where degradation is explicit
- `fallback_derived`: the degraded post-mutation install case, where host mutation succeeded but post-install truth is still degraded
- `refusal`: truthful preflight denial for live `invoke` when policy rejects execution before the connector runs

Each matrix row also freezes the minimum replay contract for later proof-bundle work:

- the acceptance-bundle routing (`bundle_layer` + `bundle_suite`)
- the representative rerun command
- the required artifact bundle members
- the required structured log fields

`crates/fwc/tests/cual_integration.rs` executes the representative flows against the fixture matrix, so changes to operator-facing truth fields or evidence requirements must update both the implementation and the frozen contract fixture set.

### Fast semantic checks

The main local truthfulness semantics already live in:

- `crates/fwc/src/catalog.rs`
- `crates/fwc/src/readiness.rs`
- `crates/fwc/src/main.rs`

Relevant tests already exercise offline/live boundaries and artifact labeling in:

- `crates/fwc/tests/cual_integration.rs`
- `crates/fwc/src/main.rs` unit-style command tests

Read these first when a behavior looks suspicious:

- `catalog.rs` tells you which source-of-truth contract the command is supposed to obey
- `readiness.rs` tells you how the result should be labeled, whether it is authoritative, and what remediation should be suggested
- `main.rs` tests show the actual envelope, refusal, and labeling semantics the CLI emits today

### Artifact bundles and replay

`crates/fwc/src/test_observability.rs` defines the artifact-bundle substrate used for redaction-safe evidence and replay.

Expected bundle files include:

- `trace.jsonl`
- `summary.json`
- `environment.json`
- `replay.sh`

The same module also defines:

- structured scenario IDs as `{layer}:{suite}:{case}`
- redaction rules for sensitive fields and token-like prefixes
- per-entry truthfulness evidence (`command_mode`, provenance markers, phase markers, host request/response ids, receipt ids, reconnect/cancellation markers)
- replay instructions derived from the captured environment and command line, including `rch exec -- ...` for cargo-backed replay

How to read the bundle:

- `trace.jsonl`: the step-by-step timeline and correlation trail, plus per-step truthfulness evidence about mode, provenance, and phase
- `summary.json`: the machine-readable verdict, aggregate log summary, and the deduplicated truthfulness markers observed during the run
- `environment.json`: the execution context needed to decide whether a mismatch is environmental or semantic, including whether replay is expected to stay offloaded through `rch`
- `replay.sh`: the deterministic rerun entrypoint; cargo-backed verification steps should preserve `rch exec -- ...`, and if the script cannot reproduce the scenario, the evidence is incomplete

### Fastest path from a failed run to a reproducible case

Use the bundle in this order when a `fwc` scenario or host-backed workflow fails:

1. Start with `summary.json`.
   This is the fastest way to answer whether the result was `live-runtime`, `offline-artifact`, `planned`, `denied`, or `unknown`, and which `host_request_id`, `host_response_id`, or `receipt_id` you can join on next.
   ```bash
   jq '.truthfulness' artifacts/e2e/workflow/replayable_failure/summary.json
   ```
2. Move to `trace.jsonl`.
   Use it to see the actual phase sequence, provenance markers, reconnect/cancellation markers, and the exact step where the story diverged.
   ```bash
   jq -c '.' artifacts/e2e/workflow/replayable_failure/trace.jsonl
   ```
3. Check `environment.json`.
   This tells you whether the mismatch is semantic or environmental by showing the captured working directory, git SHA, runner prefix, redacted env vars, and replay notes.
   ```bash
   jq '.' artifacts/e2e/workflow/replayable_failure/environment.json
   ```
4. Only then run `replay.sh`.
   A valid replay script should preserve the original rerun envelope, including `rch exec -- ...` for cargo-backed steps.
   ```bash
   bash artifacts/e2e/workflow/replayable_failure/replay.sh
   ```

If `replay.sh` cannot reproduce the failure and `environment.json` does not explain the drift, the evidence bundle is incomplete and the bug is in the observability contract before it is in the connector flow.

### Common failure map

Use these shortcuts instead of guessing:

- Template expansion failed or a macro-style render looks unsafe:
  inspect `summary.json` and `trace.jsonl` first, then compare schema and rendered output directly.
  ```bash
  fwc schema github issues.create --json
  fwc template github issues.create --offline --json
  fwc show github --template '{{json connector}}'
  ```
- Context, preset, bookmark, or pinned-profile activation drift:
  the current tree does not yet expose a dedicated preset/bookmark activation CLI, so debug the persisted target selection surfaces directly through context, session, history, and connector config.
  ```bash
  fwc context current --json
  fwc session list --status paused --json
  fwc session show --json
  fwc history --limit 10 --json
  fwc config get github --json
  fwc config doctor github --json
  ```
- Stale resume path or interrupted workflow recovery:
  treat resume as persisted-state inspection, not as conversational memory.
  ```bash
  fwc session list --status paused --json
  fwc session show --json
  fwc session resume <SESSION_ID> --json
  ```
- Replay diverges from the original failure:
  compare `environment.json` with the current checkout and rerun envelope before widening the investigation.
  ```bash
  jq '.' artifacts/e2e/workflow/replayable_failure/environment.json
  bash artifacts/e2e/workflow/replayable_failure/replay.sh
  ```
- Cargo-backed contract or artifact regressions:
  keep the replay and verification path offloaded through `rch`.
  ```bash
  rch exec -- cargo test -p fwc test_observability::full_workflow_replay_round_trip -- --exact --nocapture
  rch exec -- cargo test -p fwc confusion_workflow -- --nocapture
  ```

### Structured E2E logs

`docs/testing/e2e_log_schema.md` defines the shared JSONL schema for E2E/conformance/script runs.

Use it when you need:

- stable machine-parseable logs
- correlation IDs
- replayable scenario artifacts
- predictable CI failure evidence

For a wider map of which surfaces are already covered versus still missing, use `docs/testing/coverage-inventory.md`.

## Verification Commands

All CPU-heavy Cargo verification for this branch should be offloaded through `rch`.

Use:

```bash
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
rch exec -- cargo test -p fwc
rch exec -- cargo test --workspace
rch exec -- cargo fmt --check
```

If you add scripted transcript or scenario runners, the replay instructions and playbooks should preserve the `rch exec -- ...` prefix for any cargo-backed step.

## Migration Guidance

When closing truthfulness beads, the repository should be able to answer these questions directly from code, tests, and docs:

1. Is this result live runtime truth or explicit offline artifact work?
2. If it is offline, where did it come from and how stale could it be?
3. If the action did not run, was it denied, unavailable, unsupported, planned, or unknown?
4. If a regression occurs, where is the transcript or replay artifact that proves it?

If those answers are not mechanically visible, the surface is not finished yet.
