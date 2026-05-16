# Multi-Node Failover Runbook

> Bead: `flywheel_connectors-hr0rr.2.4`

Use this runbook when validating the deterministic A.4 three-node failover
proof, reading replay artifacts from a failing run, or extending the proof from
the local control-plane harness to host-backed mesh peers.

## Proof Command

The focused CI lane is intentionally narrow and avoids the connector feature
fan-out:

```bash
rch exec -- env TMPDIR=/Volumes/trj-data/tmp \
  CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR=/Volumes/trj-data/tmp/fcp-hr0rr-a4-local-mesh-target \
  cargo test -j 1 -p fcp-e2e --no-default-features --test multi_node_failover -- --nocapture
```

For the reusable testkit harness compile/lint proof:

```bash
rch exec -- env TMPDIR=/Volumes/trj-data/tmp \
  CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR=/Volumes/trj-data/tmp/fcp-hr0rr-a4-local-mesh-target \
  cargo clippy -j 1 -p fcp-testkit --lib --no-deps -- -D warnings
```

For the current host-backed handoff seam:

```bash
rch exec -- env TMPDIR=/Volumes/trj-data/tmp \
  CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR=/Volumes/trj-data/tmp/fcp-hr0rr-a4-host-replay-target \
  cargo test -j 1 -p fcp-host --test lease_handoff_e2e \
    leader_departure_flushes_state_reselects_holder_and_fences_stale_writes -- --nocapture
```

## Current Proof Surface

`fcp_testkit::local_mesh::LocalMeshHarness` is a deterministic in-process
control-plane harness. It builds three real `MeshNode` values with in-memory
object/symbol stores, deterministic node signing keys, the mesh HRW
lease-holder selector, signed `OperationReceipt` records, and redaction-safe
replay bundles. It does not start real `fcp-host` processes, use a real
Tailscale network, or prove cross-machine production failover yet.

Treat this as the CI-runnable substrate for A.4, not as final mesh-native
graduation evidence.

The E2E test runs 100 seeds across these `LocalChaosMode` values:

| Mode | What it proves |
| --- | --- |
| `network_partition_then_heal` | The isolated holder loses write authority and the majority elects one replacement holder. |
| `kill_leader_mid_write` | A reissued in-flight write is idempotent after holder replacement. |
| `kill_follower_mid_read` | Follower loss and recovery do not change the active holder's exactly-once receipts. |

`crates/fcp-host/tests/lease_handoff_e2e.rs` is the current host-backed seam.
It launches real `fcp-host` binaries for a three-node HRW singleton-writer
handoff, proves the departing holder flushes canonical state before yielding,
proves the replacement holder fences stale writes, and records a redacted
`host_failover_replay.jsonl` timeline in the test tempdir.

## Evidence Expectations

Each run produces an in-memory `LocalReplayBundle` with:

- `manifest` with scenario ID, seed, chaos mode, node count, and result.
- `events` with hashed node IDs, role transitions, and handoff targets.
- `node_snapshots` for all three nodes.
- `node_timelines` with per-node snapshots at t0, chaos, heal, and end.
- `hashes` for final state, receipt state, and transition state.

The test asserts that repeating the same seed and chaos mode yields the same
final state hash when the 0..99 seed matrix is traversed forward and in
reverse, that idempotent retry paths leave exactly one receipt with zero
duplicate receipts, that the manifest result is `pass`, and that the JSONL event
stream does not contain raw node IDs.

## Replay Bundle Layout

`LocalReplayBundle::write_to_dir` runs the shared
`redacted_replay_bundle` scan before writing and then emits this layout:

```text
<replay-root>/
  manifest.json
  events.jsonl
  hashes.json
  per_node_snapshots/
    node_<index>_<node_hash_prefix>/
      state_at_t0.cbor
      state_at_chaos.cbor
      state_at_heal.cbor
      state_at_end.cbor
```

`manifest.json` records `schema_version`, `scenario_id`, `seed_index`,
`chaos_mode`, `node_count`, and `result`.

`events.jsonl` is the chronological role-transition stream. Each line contains
`node_id_hash`, `prior_role`, `new_role`, `lease_handoff_target_hash`,
`transition_duration_ms`, and logical time. Raw node IDs are intentionally not
written.

`hashes.json` contains:

- `final_state_hash`
- `expected_hash_for_seed`
- `per_node_state_hashes` with one `{node_id_hash, state_hash}` record per
  final node snapshot
- `receipt_hash`
- `transition_hash`

Each snapshot file is canonical CBOR for `fcp.testkit:LocalNodeSnapshot@1.0.0`
using the `fcp-cbor` schema-hash-prefixed serializer.

## Host Handoff Replay

`lease_handoff_e2e.rs` writes:

```text
<host-test-tempdir>/
  host_failover_replay.jsonl
```

Each line has `schema_version`, `phase`, optional `local_node_hash`, and a
phase-specific payload. The current phases are:

- `initial_candidate_set`
- `initial_holder_admitted`
- `departing_holder_flushed_before_yield`
- `replacement_holder_admitted`
- `stale_write_fenced_after_handoff`
- `canonical_state_exposed_after_handoff`

This replay is intentionally smaller than the local `LocalReplayBundle`
because it records observable HTTP/binary-test evidence rather than in-memory
per-node snapshots. It is useful when the host handoff test fails after a
departure, replacement election, stale write, or state-explain regression.

The writer renders and redaction-checks the JSONL before creating the artifact
directory. Raw `node-a`/`node-b`/`node-c` labels and obvious credential-like
strings fail the preflight instead of leaving a partial replay on disk.

## Reading A Failure

1. Extract the failing `seed_index` and `chaos_mode` from the test failure or
   `scenario_id`.
2. Inspect `events.jsonl` first. The last transition before divergence usually
   shows whether the failure came from partition handling, leader handoff, or
   recovery.
3. Compare `state_at_t0.cbor`, `state_at_chaos.cbor`, `state_at_heal.cbor`,
   and `state_at_end.cbor` for the same node directory. Decode them with
   `CanonicalSerializer::deserialize::<LocalNodeSnapshot>` and the
   `fcp.testkit:LocalNodeSnapshot@1.0.0` schema.
4. Compare `hashes.json` against a rerun with the same seed and mode.
   `expected_hash_for_seed` must match `final_state_hash`, and the
   `per_node_state_hashes` array identifies which final node snapshot diverged
   first when the whole-state hash changes.
5. For host-backed handoff failures, inspect `host_failover_replay.jsonl`.
   The first missing phase identifies whether the break happened before holder
   admission, during flush-before-yield, during replacement admission, while
   fencing stale writes, or while exposing canonical state after handoff.

## Common Failures

| Symptom | Likely cause | Next step |
|---------|--------------|-----------|
| `final_state_hash` differs between two runs. | A decision path used process order, wall-clock time, or non-seeded randomness. | Search the failing mode for non-`ChaCha20Rng` decisions and add the value to `events.jsonl`. |
| Forward and reverse seed matrices differ. | A scenario leaked state across iterations or consumed non-local scheduler/process state. | Re-run the failing seed/mode pair alone and compare its replay bundle against the matrix run. |
| `receipt_count` is greater than one. | Idempotency key handling allowed a retry to create a second receipt. | Inspect `events.jsonl` around the handoff and confirm only the current holder called `execute_once`. |
| `duplicate_receipt_count` is non-zero. | The same idempotency key was inserted under multiple receipt records. | Compare `receipt_hash` across reruns and inspect holder promotion order. |
| Redaction assertion fails. | A replay field contains raw node IDs or credential-like text. | Store hashed identifiers with `_hash` suffixes and keep credentials out of replay payloads. |
| Snapshot CBOR fails to deserialize. | The snapshot schema changed without updating the replay writer or test. | Update the schema version and keep old fixture decoding explicit if old artifacts must remain readable. |
| Raw `mesh-harness-node-` appears in an artifact. | Redaction regressed. | Hash the identifier before adding it to manifests, events, or snapshots. |
| `host_failover_replay.jsonl` refuses to write. | Host replay preflight found raw node labels or credential-like strings. | Replace raw host labels with `hash_node_label` and keep credential material out of replay payloads. |
| Test compiles connector dependencies. | The command missed `--no-default-features`. | Re-run the focused E2E command above. |

## Redaction Contract

Replay bundles may contain public hashes, role names, durations, logical time,
and deterministic scenario IDs. They must not contain:

- raw node names
- private signing keys
- bearer tokens
- cookies
- connector credentials

Fields that identify a node or handoff target use a `_hash` suffix. Keep that
convention for future host-backed replay artifacts so operators can compare
timelines without leaking deployment identifiers.

## Graduation Path

This harness is the reusable deterministic substrate for the full A.4 proof.
The full closeout should add a host-backed variant that exercises real
`fcp-host` and `fcp-mesh` state transfer while preserving the same seed matrix,
chaos modes, replay-bundle shape, and redaction checks.
