# FWC Host-First Truthfulness Playbook

> Status: active operator/agent guide for the `fwc` truthfulness migration  
> Primary beads: `flywheel_connectors-1g7z0.29.8`, `flywheel_connectors-1g7z0.29.8.3`  
> Implementation anchors: `crates/fwc/src/catalog.rs`, `crates/fwc/src/readiness.rs`, `crates/fwc/tests/cual_integration.rs`, `crates/fwc/src/test_observability.rs`, `docs/testing/e2e_log_schema.md`

## Purpose

This playbook explains how `fwc` is supposed to behave now that the CLI is moving to a host-first truthful model.

The short version:

- live runtime truth must come from a reachable `fcp-host`
- offline artifact work must be explicit
- unknown, unsupported, denied, planned, and unavailable states must stay distinct
- tests and transcripts must make truth failures obvious without re-deriving the original planning thread

## The Implemented Truth Boundary

The canonical command classification lives in `crates/fwc/src/catalog.rs`.

| Source class | Meaning | Example posture |
|---|---|---|
| `LiveHost` | Authoritative only when backed by a live host | `invoke`, `simulate`, lifecycle/config/admin verbs |
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

### Fast semantic checks

The main local truthfulness semantics already live in:

- `crates/fwc/src/catalog.rs`
- `crates/fwc/src/readiness.rs`
- `crates/fwc/src/main.rs`

Relevant tests already exercise offline/live boundaries and artifact labeling in:

- `crates/fwc/tests/cual_integration.rs`
- `crates/fwc/src/main.rs` unit-style command tests

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
- replay instructions derived from the captured environment and command line

### Structured E2E logs

`docs/testing/e2e_log_schema.md` defines the shared JSONL schema for E2E/conformance/script runs.

Use it when you need:

- stable machine-parseable logs
- correlation IDs
- replayable scenario artifacts
- predictable CI failure evidence

## Verification Commands

All CPU-heavy Cargo verification for this branch should be offloaded through `rch`.

Use:

```bash
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
rch exec -- cargo test -p fwc
rch exec -- cargo test --workspace
cargo fmt --check
```

If you add scripted transcript or scenario runners, the replay instructions and playbooks should preserve the `rch exec -- ...` prefix for any cargo-backed step.

## Migration Guidance

When closing truthfulness beads, the repository should be able to answer these questions directly from code, tests, and docs:

1. Is this result live runtime truth or explicit offline artifact work?
2. If it is offline, where did it come from and how stale could it be?
3. If the action did not run, was it denied, unavailable, unsupported, planned, or unknown?
4. If a regression occurs, where is the transcript or replay artifact that proves it?

If those answers are not mechanically visible, the surface is not finished yet.
