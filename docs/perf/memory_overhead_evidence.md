# Host-Backed Memory Overhead SLO Evidence

Date: 2026-05-02

Bead: `flywheel_connectors-b5tat`

README SLO row: `Memory overhead | < 10MB per connector | Sandbox limits`

## Harness

The proof uses `crates/fcp-host/benches/memory_overhead.rs`.

The harness starts an empty `fcp-host`, measures its resident set size, then
starts `fcp-host` with three activated `fcp-test-connector` children and
measures the full host-plus-child process tree. The SLO value is:

```text
(RSS(host + connector children) - RSS(empty host)) / connector_count
```

This run uses the checked gate in the harness: `within_target` must be true and
`per_connector_bytes` must be less than or equal to `10 * 1024 * 1024`, or the
bench process exits non-zero.

## Command

The normal `rch exec` wrapper selected `vmi1152480` but failed before Cargo ran
with `timeout: failed to execute process: No such file or directory`. The same
synced worker was used directly over SSH:

```bash
ssh ubuntu@109.205.181.92 'bash -lc "cd /data/projects/flywheel_connectors && export CARGO_TARGET_DIR=/tmp/fcp-b5tat-target TMPDIR=/tmp && cargo bench -p fcp-host --bench memory_overhead"'
```

## Transcript

```text
Finished `bench` profile [optimized] target(s) in 9m 23s
Running benches/memory_overhead.rs (/tmp/fcp-b5tat-target/release/deps/memory_overhead-407f84eb09bee410)
{"activated_tree_rss_bytes":17797120,"benchmark":"host_backed_memory_overhead","connector_count":3,"empty_host_rss_bytes":9027584,"overhead_bytes":8769536,"per_connector_bytes":2923178,"per_connector_mib":2.787759780883789,"samples":5,"slo_status":"PASS","target_per_connector_bytes":10485760,"target_per_connector_mib":10.0,"within_target":true}
```

## Verdict

PASS. The measured host-backed memory overhead was `2,923,178` bytes, or
`2.79 MiB`, per connector. The README SLO budget is `10 MiB` per connector.
