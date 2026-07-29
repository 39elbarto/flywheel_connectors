#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FCP_REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
export FCP_REPO_ROOT

python3 - "$@" <<'PY'
import argparse
import datetime as dt
import json
import math
import os
import pathlib
import statistics
import sys
from typing import Any


WELCH_P_ALARM = 0.001


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail when a performance artifact regresses against its recent baseline."
    )
    parser.add_argument("--artifacts-dir", required=True)
    parser.add_argument("--target-bench", required=True)
    parser.add_argument("--target-p99", type=float)
    parser.add_argument("--targets-file")
    parser.add_argument("--tolerance-pct", type=float)
    parser.add_argument("--history-dir")
    parser.add_argument("--force-baseline-resnap", action="store_true")
    parser.add_argument("--audit-path")
    return parser.parse_args()


def repo_root() -> pathlib.Path:
    return pathlib.Path(os.environ.get("FCP_REPO_ROOT", "."))


def resolve_path(path_text: str | None, default: pathlib.Path) -> pathlib.Path:
    if path_text is None:
        return default
    path = pathlib.Path(path_text)
    return path if path.is_absolute() else repo_root() / path


def load_targets(path: pathlib.Path, bench: str) -> tuple[float | None, float | None]:
    if not path.exists():
        return None, None

    try:
        import tomllib  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        return parse_simple_targets(path, bench)

    with path.open("rb") as handle:
        data = tomllib.load(handle)
    section = data.get(bench, {})
    target = section.get("target_p99_ms")
    tolerance = section.get("tolerance_pct")
    return as_float(target), as_float(tolerance)


def parse_simple_targets(path: pathlib.Path, bench: str) -> tuple[float | None, float | None]:
    current = None
    target = None
    tolerance = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            continue
        if current != bench or "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if key == "target_p99_ms":
            target = as_float(value.strip('"'))
        elif key == "tolerance_pct":
            tolerance = as_float(value.strip('"'))
    return target, tolerance


def as_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def load_records(root: pathlib.Path, bench: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.suffix not in {".json", ".jsonl"} or not path.is_file():
            continue
        records.extend(load_records_from_path(path, bench))
    return records


def load_records_from_path(path: pathlib.Path, bench: str) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    values: list[Any] = []
    if path.suffix == ".jsonl":
        for line in text.splitlines():
            if line.strip():
                values.append(json.loads(line))
    else:
        values.append(json.loads(text))

    records = []
    for value in values:
        if not isinstance(value, dict):
            continue
        if not matches_bench(value, path, bench):
            continue
        p99 = extract_number(
            value,
            [
                ("statpack", "p99_ms"),
                ("statpack", "p99"),
                ("summary", "p99_ms"),
                ("benchmarks", bench, "p99_ms"),
                ("p99_ms",),
                ("p99",),
            ],
        )
        if p99 is None:
            continue
        records.append(
            {
                "path": str(path),
                "p99_ms": p99,
                "samples_ms": extract_samples(value),
                "welch_p": extract_number(value, [("welch_p",), ("statpack", "welch_p")]),
            }
        )
    return records


def matches_bench(value: dict[str, Any], path: pathlib.Path, bench: str) -> bool:
    for key in ("bench", "benchmark", "name"):
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate == bench:
            return True
    return bench in path.name or bench in str(path.parent)


def extract_number(value: dict[str, Any], paths: list[tuple[str, ...]]) -> float | None:
    for path in paths:
        current: Any = value
        for key in path:
            if not isinstance(current, dict) or key not in current:
                current = None
                break
            current = current[key]
        number = as_float(current)
        if number is not None:
            return number
    return None


def extract_samples(value: dict[str, Any]) -> list[float]:
    for key in ("samples_ms", "raw_samples_ms", "samples"):
        samples = value.get(key)
        if isinstance(samples, list):
            parsed = [as_float(sample) for sample in samples]
            return [sample for sample in parsed if sample is not None]
    return []


def welch_p_value(baseline: list[float], current: list[float]) -> float | None:
    if len(baseline) < 2 or len(current) < 2:
        return None
    baseline_mean = statistics.fmean(baseline)
    current_mean = statistics.fmean(current)
    baseline_var = statistics.variance(baseline)
    current_var = statistics.variance(current)
    standard_error = math.sqrt((baseline_var / len(baseline)) + (current_var / len(current)))
    if standard_error <= 1.0e-12:
        return None
    t_value = abs(current_mean - baseline_mean) / standard_error
    return math.erfc(t_value / math.sqrt(2.0))


def write_resnap_audit(path: pathlib.Path, bench: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "event": "perf.baseline_resnap",
        "bench": bench,
        "operator_fingerprint": "env:FCP_PERF_GATE_ALLOW_BASELINE_RESNAP",
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True))
        handle.write("\n")


def write_history_line(history_dir: pathlib.Path, log: dict[str, Any]) -> None:
    history_dir.mkdir(parents=True, exist_ok=True)
    path = history_dir / f"{log['bench']}_history.md"
    timestamp = dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")
    fields = [
        f"bench={log['bench']}",
        f"verdict={log['verdict']}",
        f"baseline_p99={log.get('baseline_p99')}",
        f"run_p99={log.get('run_p99')}",
        f"delta_pct={log.get('delta_pct')}",
        f"welch_p={log.get('welch_p')}",
        f"artifact={log.get('artifact')}",
    ]
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"- {timestamp} " + " ".join(fields) + "\n")


def main() -> int:
    args = parse_args()
    artifact_root = pathlib.Path(args.artifacts_dir)
    targets_file = resolve_path(args.targets_file, repo_root() / "docs/perf/perf-targets.toml")
    history_dir = resolve_path(args.history_dir, repo_root() / "docs/perf")
    target_from_file, tolerance_from_file = load_targets(targets_file, args.target_bench)
    target_p99 = args.target_p99 if args.target_p99 is not None else target_from_file
    tolerance_pct = args.tolerance_pct if args.tolerance_pct is not None else tolerance_from_file
    if tolerance_pct is None:
        tolerance_pct = 10.0

    records = load_records(artifact_root, args.target_bench)
    if len(records) < 2:
        write_history_line(
            history_dir,
            {
                "level": "ERROR",
                "span": "fcp.bench.regression_gate",
                "bench": args.target_bench,
                "verdict": "insufficient_history",
                "baseline_p99": None,
                "run_p99": None,
                "delta_pct": None,
                "welch_p": None,
                "artifact": str(artifact_root),
            },
        )
        print(
            f"perf_gate_error=insufficient_history regressed_bench={args.target_bench} "
            f"records={len(records)}",
            file=sys.stderr,
        )
        return 2

    current = records[-1]
    baseline = records[-8:-1] if len(records) >= 8 else records[:-1]
    baseline_p99 = statistics.median([record["p99_ms"] for record in baseline])
    run_p99 = current["p99_ms"]
    delta_pct = ((run_p99 - baseline_p99) / baseline_p99) * 100.0 if baseline_p99 else math.inf
    baseline_samples = [sample for record in baseline for sample in record["samples_ms"]]
    computed_welch = welch_p_value(baseline_samples, current["samples_ms"])
    welch_p = current["welch_p"] if current["welch_p"] is not None else computed_welch

    delta_failed = delta_pct > tolerance_pct
    target_failed = target_p99 is not None and run_p99 > target_p99 * (1.0 + tolerance_pct / 100.0)
    welch_failed = welch_p is not None and welch_p < WELCH_P_ALARM

    verdict = "fail" if delta_failed or target_failed or welch_failed else "pass"
    log = {
        "level": "INFO",
        "span": "fcp.bench.regression_gate",
        "bench": args.target_bench,
        "verdict": verdict,
        "baseline_p99": round(baseline_p99, 6),
        "run_p99": round(run_p99, 6),
        "delta_pct": round(delta_pct, 6),
        "welch_p": None if welch_p is None else round(welch_p, 12),
        "target_p99": target_p99,
        "tolerance_pct": tolerance_pct,
        "artifact": current["path"],
    }

    if args.force_baseline_resnap:
        if os.environ.get("FCP_PERF_GATE_ALLOW_BASELINE_RESNAP") != "1":
            print("perf_gate_error=baseline_resnap_requires_operator_env", file=sys.stderr)
            return 2
        if args.audit_path:
            write_resnap_audit(resolve_path(args.audit_path, repo_root() / args.audit_path), args.target_bench)
        log["verdict"] = "baseline_resnap"
        write_history_line(history_dir, log)
        print(json.dumps(log, sort_keys=True))
        return 0

    write_history_line(history_dir, log)
    stream = sys.stderr if verdict == "fail" else sys.stdout
    print(json.dumps(log, sort_keys=True), file=stream)
    if verdict == "fail":
        print(
            f"regressed_bench={args.target_bench} delta_pct={delta_pct:.1f} "
            f"welch_p={welch_p if welch_p is not None else 'na'}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
