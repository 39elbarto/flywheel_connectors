# Chaos Campaign Runbook

Bead: `flywheel_connectors-angoc.12.3` (Phase R.3) — the operator-facing
runbook for the 7-day continuous-chaos campaign that exercises the
network, disk, process, and transport-class fault scenarios against
the staging cluster.

## Scope

A chaos campaign is a long-running, probabilistic, automated process
that injects faults into a live system on a defined schedule. The
campaign covered by this runbook combines:

- **Network-class scenarios** (filed in `angoc.12.2`): partition
  bisecting / asymmetric / DERP-only / full, packet drop 1/10/50%,
  packet reorder, packet duplication, latency spike 100×, bandwidth
  throttle.
- **Disk-class scenarios** (`angoc.12.3`): disk-full mid-write,
  filesystem quota exhaustion, audit-write atomicity.
- **Process-class scenarios** (`angoc.12.3`): OOM kill of `fcp-host`
  during a multi-step operation, cgroup memory pressure.
- **Transport-class scenarios** (`angoc.12.3`): TCP RST mid-
  handshake, TCP RST during in-flight RPC.

Each scenario is invoked with declared blast radius and a rollback
plan; the orchestrator records start/end timestamps + the operator-
visible recovery latency.

## Pre-conditions

Before starting a campaign:

1. The staging cluster must be in a clean state. Run
   `fwc doctor --json` against every host and confirm all probes are
   `healthy`.
2. `FCP_ENV=staging` MUST be set in the orchestrator environment. The
   orchestrator refuses to start without it; this is the production-
   safety gate.
3. The current main branch must compile and the `cargo test` suite
   must be green. A red baseline means a chaos failure cannot be
   attributed to chaos vs. pre-existing breakage.
4. The on-call operator must be available for the full duration (or
   have explicit handoff arranged).
5. A clean `/tmp/fcp-chaos-kill-switch` path must NOT exist (the
   orchestrator polls this every 5 seconds; existence triggers abort
   within 30 seconds).

## Running the campaign

The canonical 7-day campaign invocation:

```bash
FCP_ENV=staging \
  bash scripts/chaos/staging_7day_campaign.sh \
    --campaign-id 2026-Q2-staging-001 \
    --duration-secs 604800
```

Optional flags:

- `--scenario-dir <path>` — defaults to `scenarios/` in the repo root.
- `--kill-switch <path>` — defaults to `/tmp/fcp-chaos-kill-switch`.
- `--dry-run` — enumerate the campaign plan without injecting faults.
  Useful for the conformance test that asserts the kill-switch fires
  within 30 seconds.

Artifacts land under `chaos-results/<campaign-id>/`:

- `events.jsonl` — structured event stream (one JSON object per line).
- (Future) per-scenario detail under `scenarios/<scenario_name>/`.

## Event-stream schema

Every line in `events.jsonl` carries `{ts, campaign_id, phase, ...}`:

| Phase | Extra fields |
|---|---|
| `start` | `scenario_count`, `duration_secs`, `dry_run` |
| `scenario_pick` | `iteration`, `scenario` |
| `scenario_dry_run` | `iteration`, `scenario` |
| `scenario_end` | `iteration`, `scenario`, `outcome`, `duration_secs` |
| `kill_switch_triggered` | `iterations`, `abort_within_secs` |
| `kill_switch_abort_complete` | `iterations` |
| `deadline_reached` | `iterations` |
| `summary` | `iterations`, `events_file` |

## SLO budget

The campaign succeeds if the staging cluster maintains:

- **Operation-failure-rate** ≤ 1.0% over the 7-day window (failures
  caused by chaos-injected faults that do NOT recover within their
  declared blast-radius window).
- **Recovery-latency p99** ≤ 30 seconds for every scenario class.
- **Zero data corruption** — `fcp audit chain verify` MUST return
  green at the end of the campaign.
- **Zero kill-switch override** — if the kill-switch is needed
  outside the planned smoke test, the campaign is a FAILURE regardless
  of other metrics.

## Kill-switch procedure

If the campaign begins damaging staging beyond the declared blast
radius:

1. `touch /tmp/fcp-chaos-kill-switch`
2. The orchestrator detects the file within 5 seconds (its poll
   interval) and emits `kill_switch_triggered`.
3. In-flight scenarios get up to 30 seconds to wind down cleanly.
4. The orchestrator emits `kill_switch_abort_complete` and exits 0.
5. Operator examines `events.jsonl` to identify the offending scenario.
6. File a P1 bead under `angoc.12` with the scenario name + recovery-
   latency-p99 from the abort.

If `kill_switch_abort_complete` does NOT fire within 60 seconds of
creating the file, the chaos orchestrator itself is wedged. In that
case:

1. `pkill -SIGTERM -f staging_7day_campaign.sh`
2. File a P0 bead — the abort mechanism is the load-bearing safety
   primitive for the entire campaign.

## Failure-injection self-test

Before the real 7-day campaign, run the kill-switch self-test:

```bash
FCP_ENV=staging \
  bash scripts/chaos/staging_7day_campaign.sh \
    --campaign-id selftest \
    --duration-secs 120 \
    --dry-run &
CAMPAIGN_PID=$!
sleep 10
touch /tmp/fcp-chaos-kill-switch
# Expected: campaign exits with `kill_switch_abort_complete` event
# within 30 seconds of the touch.
wait $CAMPAIGN_PID
grep -q '"kill_switch_abort_complete"' chaos-results/selftest/events.jsonl
```

The conformance test `chaos_disk_oom_tcp_e2e.rs::test_kill_switch_aborts_within_30s` automates this check.

## Post-campaign

After `deadline_reached` or `kill_switch_abort_complete`:

1. Archive `chaos-results/<campaign-id>/` to long-term storage.
2. Run `fwc audit chain verify --since <campaign-start-ts>` and pin
   the green result.
3. Compute per-scenario p50/p95/p99 recovery latency from the
   `scenario_end` events and update
   `docs/operator/chaos_campaign_<campaign-id>_results.md`.
4. Update the SLO-budget rolling table at
   `docs/operator/chaos_slo_history.md` (one row per campaign).

## Cross-references

- `crates/fcp-chaos/src/lib.rs` — chaos scenario harness (refuses
  production environment, enforces blast radius, records rollback).
- `crates/fcp-chaos/src/scenarios/net.rs` — network-class scenarios
  (`angoc.12.2`).
- `scenarios/*.toml` — declarative scenario definitions consumed by
  the orchestrator.
- `scripts/chaos/staging_7day_campaign.sh` — campaign orchestrator.
- `crates/fcp-conformance/tests/chaos_disk_oom_tcp_e2e.rs` —
  conformance test (Rust scenarios + kill-switch self-test).
  Currently a deferred follow-up under `angoc.12.3.1`; see the bead
  for the Rust scenario authoring plan.

## Deferred Rust scenarios (`angoc.12.3.1`)

The three disk/process/transport scenarios (`scenarios/disk_full.rs`,
`scenarios/oom_kill.rs`, `scenarios/tcp_rst.rs`) introduced by
`angoc.12.3` are filed as a deferred follow-up bead because they
require deeper integration with the `fcp-host` write path, the
audit-chain WAL replay, and the mesh transport's PeerSuspect state
machine — wiring that is currently active on the PQ-hardening track
and would conflict with concurrent changes. The orchestrator + this
runbook are valuable independent of those scenarios.
