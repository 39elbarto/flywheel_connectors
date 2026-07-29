# PQ Signing Overhead Evidence

Bead: `flywheel_connectors-angoc.8.2`

This document pins the `pq_signing` StatPack schema and the conformance gate
for the hybrid verifier budget. The gate accepts live artifacts from
`artifacts/perf/pq_signing/<machine-class>-<date>-<sha>.json` when present. The
committed JSON blocks below include live evidence when available; remaining
fixture snapshots are placeholders for machine classes that do not yet have a
live artifact.

Budget: hybrid verify p99 <= 2.0 ms for `csd`, `contabo`, and `laptop`.

Live evidence status:

| Machine class | Status | Evidence |
| --- | --- | --- |
| `contabo` | live, 2026-05-13 UTC | `artifacts/perf/pq_signing/contabo-20260513-43e976408-dirty.json`: p99 0.15964849000000003 ms, p99 CI upper 0.16053179000000004 ms, verdict `pass` |
| `csd` | fixture fallback only | Live machine-class artifact still required before closing `flywheel_connectors-angoc.8.3`. |
| `laptop` | fixture fallback only | Live machine-class artifact still required before closing `flywheel_connectors-angoc.8.3`. |

Reproduction command:

```bash
env -u CARGO_TARGET_DIR RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=2400 \
  rch exec -- env CARGO_INCREMENTAL=0 \
  cargo bench -j 1 -p fcp-crypto --bench hybrid_verify -- \
    --samples 10000 \
    --machine-class <machine-class> \
    --git-sha "$(git rev-parse --short HEAD)" \
    --statpack-out "artifacts/perf/pq_signing/<machine-class>-$(date -u +%Y%m%d)-$(git rev-parse --short HEAD).json"
```

Expected live artifact shape:

```json
{
  "schema": "fcp.pq-signing-overhead.v1",
  "machine_class": "csd",
  "artifact_path": "artifacts/perf/pq_signing/csd-20260512-486ae48.json",
  "git_sha": "486ae48",
  "sample_count": 10000,
  "verify_hybrid": {
    "p50": 0.71,
    "p99": 1.42,
    "p999": 1.61,
    "mean": 0.76,
    "std": 0.09,
    "welch_t": 2.41,
    "bootstrap_ci": [0.758, 0.762],
    "tail_amp": 0.267
  },
  "baseline_classical_verify": {
    "p50": 0.19,
    "p99": 0.41,
    "p999": 0.46,
    "mean": 0.2,
    "std": 0.03,
    "welch_t": 0.0,
    "bootstrap_ci": [0.199, 0.201],
    "tail_amp": 0.227
  },
  "welch_p": 0.018,
  "bootstrap_p99_ci_ms": [1.39, 1.46],
  "verdict": "pass"
}
```

<!-- statpack:csd -->

```json
{
  "schema": "fcp.pq-signing-overhead.v1",
  "machine_class": "csd",
  "artifact_path": "artifacts/perf/pq_signing/csd-latest.json",
  "git_sha": "fixture",
  "sample_count": 10000,
  "verify_hybrid": {
    "p50": 0.71,
    "p99": 1.42,
    "p999": 1.61,
    "mean": 0.76,
    "std": 0.09,
    "welch_t": 2.41,
    "bootstrap_ci": [0.758, 0.762],
    "tail_amp": 0.267
  },
  "baseline_classical_verify": {
    "p50": 0.19,
    "p99": 0.41,
    "p999": 0.46,
    "mean": 0.2,
    "std": 0.03,
    "welch_t": 0.0,
    "bootstrap_ci": [0.199, 0.201],
    "tail_amp": 0.227
  },
  "welch_p": 0.018,
  "bootstrap_p99_ci_ms": [1.39, 1.46],
  "verdict": "pass"
}
```

<!-- statpack:contabo -->

```json
{
  "schema": "fcp.pq-signing-overhead.v1",
  "machine_class": "contabo",
  "artifact_path": "artifacts/perf/pq_signing/contabo-20260513-43e976408-dirty.json",
  "git_sha": "43e976408+dirty",
  "sample_count": 10000,
  "verify_hybrid": {
    "p50": 0.141456,
    "p99": 0.15964849000000003,
    "p999": 0.20859571800000096,
    "mean": 0.1423169263000004,
    "std": 0.008829877593358801,
    "welch_t": 614.2872778827799,
    "bootstrap_ci": [0.1421528581000002, 0.14249313070000028],
    "tail_amp": 2.69051834026023
  },
  "baseline_classical_verify": {
    "p50": 0.049243,
    "p99": 0.0625532,
    "p999": 0.10774091200000017,
    "mean": 0.049506741200000134,
    "std": 0.012259810138892314,
    "welch_t": 0.0,
    "bootstrap_ci": [0.049280431700000085, 0.049738125099999954],
    "tail_amp": 3.3949686706435793
  },
  "welch_p": 0.0,
  "bootstrap_p99_ci_ms": [0.15888839999999999, 0.16053179000000004],
  "verdict": "pass"
}
```

<!-- statpack:laptop -->

```json
{
  "schema": "fcp.pq-signing-overhead.v1",
  "machine_class": "laptop",
  "artifact_path": "artifacts/perf/pq_signing/laptop-latest.json",
  "git_sha": "fixture",
  "sample_count": 10000,
  "verify_hybrid": {
    "p50": 0.91,
    "p99": 1.83,
    "p999": 1.97,
    "mean": 0.96,
    "std": 0.12,
    "welch_t": 2.86,
    "bootstrap_ci": [0.956, 0.964],
    "tail_amp": 0.152
  },
  "baseline_classical_verify": {
    "p50": 0.27,
    "p99": 0.54,
    "p999": 0.6,
    "mean": 0.28,
    "std": 0.04,
    "welch_t": 0.0,
    "bootstrap_ci": [0.278, 0.282],
    "tail_amp": 0.222
  },
  "welch_p": 0.009,
  "bootstrap_p99_ci_ms": [1.78, 1.89],
  "verdict": "pass"
}
```

Closeout note: before treating this as production evidence, replace each
remaining fixture block with live StatPack artifacts from the named machine
class and keep the same redaction posture: aggregate numeric fields only, no raw
samples, no hostnames, and no user paths.
