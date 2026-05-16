# Multi-Node Failover Runbook

> Bead: `flywheel_connectors-hr0rr.2.4`

Use this runbook when validating the deterministic A.4 three-node failover
proof or when extending the proof from the local control-plane harness to
host-backed mesh peers.

## Proof Command

The focused CI lane is intentionally narrow and avoids the connector feature
fan-out:

```bash
TMPDIR=/Volumes/trj-data/tmp \
CARGO_INCREMENTAL=0 \
CARGO_TARGET_DIR=/Volumes/trj-data/tmp/fcp-hr0rr-a4-local-mesh-target \
  rch exec -- cargo test -j 1 -p fcp-e2e --no-default-features --test multi_node_failover -- --nocapture
```

For the reusable testkit harness compile/lint proof:

```bash
TMPDIR=/Volumes/trj-data/tmp \
CARGO_INCREMENTAL=0 \
CARGO_TARGET_DIR=/Volumes/trj-data/tmp/fcp-hr0rr-a4-local-mesh-target \
  rch exec -- cargo clippy -j 1 -p fcp-testkit --lib --no-deps -- -D warnings
```

## Current Proof Surface

`fcp_testkit::local_mesh::LocalMeshHarness` is a deterministic in-process
control-plane harness. It builds three real `MeshNode` values with in-memory
object/symbol stores, uses the mesh HRW lease-holder selector, signs
`OperationReceipt` records, and emits redaction-safe replay bundles. It does
not start real `fcp-host` processes yet.

The E2E test runs 100 seeds across these `LocalChaosMode` values:

| Mode | What it proves |
| --- | --- |
| `network_partition_then_heal` | The isolated holder loses write authority and the majority elects one replacement holder. |
| `kill_leader_mid_write` | A reissued in-flight write is idempotent after holder replacement. |
| `kill_follower_mid_read` | Follower loss and recovery do not change the active holder's exactly-once receipts. |

## Evidence Expectations

Each run produces an in-memory `LocalReplayBundle` with:

- `manifest` with scenario ID, seed, chaos mode, node count, and result.
- `events` with hashed node IDs, role transitions, and handoff targets.
- `node_snapshots` for all three nodes.
- `hashes` for final state, receipt state, and transition state.

The test asserts that repeating the same seed and chaos mode yields the same
final state hash, that idempotent retry paths leave exactly one receipt with
zero duplicate receipts, that the manifest result is `pass`, and that the JSONL
event stream does not contain raw node IDs.

## Common Failures

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Nondeterministic final hash. | A new field was added without stable ordering or seeded input. | Use `BTreeMap`/`BTreeSet` or include explicit seeded ordering in the harness. |
| Duplicate receipt count is non-zero. | A failover path bypassed the idempotency key map. | Route retry writes through `apply_operation` and keep the operation index stable across retry. |
| Redaction assertion fails. | A replay field contains raw node IDs or credential-like text. | Store hashed identifiers with `_hash` suffixes and keep credentials out of replay payloads. |
| Test compiles connector dependencies. | The command missed `--no-default-features`. | Re-run the focused E2E command above. |

## Graduation Path

This harness is the reusable deterministic substrate for the full A.4 proof.
The full closeout should add a host-backed variant that exercises real
`fcp-host` and `fcp-mesh` state transfer while preserving the same seed matrix,
chaos modes, replay-bundle shape, and redaction checks.
