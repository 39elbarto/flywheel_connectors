# Chaos GameDay Runbook

> Bead: `flywheel_connectors-angoc.12.2`

Use this runbook for staging-only network chaos drills driven by `fcp-chaos`.
The harness is blocked in production by construction; if an operator sees a
chaos command targeting production, stop the drill and fix the deployment mode
before running anything.

## Network Scenario Contract

Every network scenario lives in `scenarios/net/*.toml` and declares:

- `blast_radius`: maximum synthetic peer or path units affected.
- `recovery_objective_secs`: maximum allowed recovery window.
- `rollback_steps`: restore actions that are executed on completion and abort.

The unit-test dry run does not mutate packet filters, routes, or live network
state. It traces the planned `iptables` or `tc` action class and proves the
same rollback accounting path used by the generic injector.

| Scenario | Fault | Rollback expectation | Recovery objective |
|----------|-------|----------------------|--------------------|
| `net_partition_bisecting` | Split a synthetic mesh into two reachable halves. | Restore partitioned links, then wait for gossip convergence. | 60s |
| `net_partition_asymmetric` | Drop one-way peer paths while preserving reverse traffic. | Restore asymmetric links, then wait for convergence. | 60s |
| `net_partition_derp_only` | Block direct paths while preserving relay fallback. | Restore direct paths, then verify direct path preference returns. | 90s |
| `net_partition_full` | Drop all peer links in the synthetic mesh. | Restore all peer links, then wait for convergence. | 120s |
| `packet_drop_1pct` | Apply light packet loss. | Clear `tc netem`, then verify packet loss normalizes. | 30s |
| `packet_drop_10pct` | Apply moderate packet loss. | Clear `tc netem`, then verify packet loss normalizes. | 45s |
| `packet_drop_50pct` | Apply severe packet loss. | Clear `tc netem`, then verify packet loss normalizes. | 90s |
| `packet_reorder` | Reorder packets in the synthetic mesh. | Clear `tc netem`, then verify ordering normalizes. | 45s |
| `packet_duplication` | Duplicate packets in the synthetic mesh. | Clear `tc netem`, then verify duplication normalizes. | 45s |
| `latency_spike_100x` | Raise RTT by 100x. | Clear `tc netem`, then verify RTT returns below 2x baseline. | 90s |
| `bandwidth_throttle_1mbps` | Throttle the synthetic mesh to 1Mbps. | Clear `tc tbf`, then verify minimum bandwidth returns. | 90s |

## GameDay Procedure

1. Confirm the target is staging:

   ```bash
   FCP_DEPLOY_MODE=staging cargo test -p fcp-chaos net_scenarios_smoke -- --nocapture
   ```

2. Pick one scenario from `scenarios/net/` and record the bead id, scenario
   file, declared blast radius, recovery objective, and operator on call.
3. Run the dry-run path first and confirm it emits the expected
   `fcp.chaos.net.<scenario>` span name, scenario start/end records, and rollback
   step names.
4. Only after the dry run is clean, enable the staging injector backend that owns
   packet mutation for the target environment.
5. During the drill, watch for:

   - `fcp.chaos.net.<scenario>` span completion.
   - `fcp.chaos.scenario` outcome and recovery fields.
   - `BlastRadiusExceeded` errors.
   - missing rollback-step completion.

6. If the blast radius is exceeded, abort the scenario and apply the declared
   rollback steps. Do not widen the radius mid-run.

## Rollback

Rollback is additive restoration, not cleanup by deletion.

For partition scenarios:

1. Restore the affected peer-link rules.
2. Verify direct and relay paths match pre-drill reachability.
3. Wait for gossip convergence within the declared recovery objective.

For packet-loss, reorder, duplication, latency, and bandwidth scenarios:

1. Clear the `tc netem` or `tc tbf` rule used by the injector.
2. Verify counters return below the scenario threshold.
3. Preserve the dry-run and live-run logs as incident evidence.

Do not remove scenario files, Beads records, or staging artifacts during
rollback.

## Verification

Use these focused checks after modifying network chaos scenarios:

```bash
rustfmt --edition 2024 --check crates/fcp-chaos/src/lib.rs crates/fcp-chaos/src/scenarios/mod.rs crates/fcp-chaos/src/scenarios/net.rs crates/fcp-chaos/tests/net_scenarios_smoke.rs crates/fcp-chaos/tests/net_partition_recovery_sla.rs
git diff --check -- crates/fcp-chaos scenarios docs/ops/chaos_gameday_runbook.md
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-angoc-12-2-chaos-target CARGO_BUILD_JOBS=2 cargo test -p fcp-chaos --test net_scenarios_smoke -- --nocapture
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-angoc-12-2-chaos-target CARGO_BUILD_JOBS=2 cargo test -p fcp-chaos --test net_partition_recovery_sla -- --nocapture
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-angoc-12-2-chaos-target CARGO_BUILD_JOBS=2 cargo clippy -p fcp-chaos --all-targets --no-deps -- -D warnings
```

## Redaction

Network chaos logs must not contain packet payloads, connector secrets, user
content, bearer tokens, or provider response bodies. Scenario names, synthetic
peer ids, packet counters, timings, outcome enums, and rollback step names are
safe to log.
