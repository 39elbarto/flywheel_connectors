# PQ Signing Overhead Evidence

Bead: `flywheel_connectors-angoc.8.2`

This document pins the `pq_signing` StatPack schema and the conformance gate
for the hybrid verifier budget. The gate accepts live artifacts from
`artifacts/perf/pq_signing/<machine-class>-<date>-<sha>.json` when present. The
committed JSON blocks below are fixture snapshots for CI shape validation; they
are not production deployment evidence.

Budget: hybrid verify p99 <= 2.0 ms for `csd`, `contabo`, and `laptop`.

Reproduction command:

```bash
cargo bench -p fcp-crypto --bench hybrid_verify -- --samples 10000 --statpack-out artifacts/perf/pq_signing/<machine-class>-$(date -u +%Y%m%d)-$(git rev-parse --short HEAD).json
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
  "artifact_path": "artifacts/perf/pq_signing/contabo-latest.json",
  "git_sha": "fixture",
  "sample_count": 10000,
  "verify_hybrid": {
    "p50": 0.83,
    "p99": 1.68,
    "p999": 1.91,
    "mean": 0.88,
    "std": 0.11,
    "welch_t": 2.74,
    "bootstrap_ci": [0.877, 0.883],
    "tail_amp": 0.271
  },
  "baseline_classical_verify": {
    "p50": 0.23,
    "p99": 0.48,
    "p999": 0.55,
    "mean": 0.24,
    "std": 0.04,
    "welch_t": 0.0,
    "bootstrap_ci": [0.238, 0.242],
    "tail_amp": 0.28
  },
  "welch_p": 0.012,
  "bootstrap_p99_ci_ms": [1.64, 1.73],
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
fixture block with live StatPack artifacts from the named machine class and keep
the same redaction posture: aggregate numeric fields only, no raw samples, no
hostnames, and no user paths.
