#!/usr/bin/env bash
# scripts/perf/collect_runtime_targets.sh — Phase B.4
# (flywheel_connectors-angoc.1.4).
#
# Orchestrates the seven non-memory runtime perf-target benchmarks and
# writes per-(machine_class, target) JSONL evidence files consumed by
# scripts/ci/perf_regression_gate.sh.
#
# Usage:
#   collect_runtime_targets.sh --machine-class <class> [--target <target>]
#
#   --machine-class : one of {laptop_m2, server_x86, ci_runner}.
#                     Required. Matches the docs/perf/perf-targets.toml
#                     machine-class column.
#   --target        : optional. One of the 7 target names below. If
#                     omitted, all 7 targets run sequentially.
#
# The script is idempotent: each invocation appends a new JSONL line per
# target (tagged with timestamp + commit_sha) to
# perf-results/runtime_targets/<machine_class>/<target>.jsonl. Old lines
# are preserved for longitudinal trend analysis. The gate consumes only
# the latest row per (machine_class, target) pair.

set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${REPO_ROOT}/perf-results/runtime_targets}"

TARGETS=(
    cold_start_ms
    local_invoke_us
    lan_invoke_us
    derp_invoke_ms
    symbol_reconciliation_us
    secret_reconciliation_ms
    cpu_overhead_pct
)

MACHINE_CLASS=""
SELECTED_TARGET=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --machine-class)
            MACHINE_CLASS="$2"
            shift 2
            ;;
        --target)
            SELECTED_TARGET="$2"
            shift 2
            ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "collect_runtime_targets: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

if [[ -z "${MACHINE_CLASS}" ]]; then
    echo "collect_runtime_targets: --machine-class required" >&2
    exit 2
fi

case "${MACHINE_CLASS}" in
    laptop_m2|server_x86|ci_runner) ;;
    *)
        echo "collect_runtime_targets: invalid --machine-class '${MACHINE_CLASS}' (expected: laptop_m2 | server_x86 | ci_runner)" >&2
        exit 2
        ;;
esac

if [[ -n "${SELECTED_TARGET}" ]]; then
    if ! printf '%s\n' "${TARGETS[@]}" | grep -qx "${SELECTED_TARGET}"; then
        echo "collect_runtime_targets: invalid --target '${SELECTED_TARGET}' (expected: ${TARGETS[*]})" >&2
        exit 2
    fi
    TARGETS=("${SELECTED_TARGET}")
fi

OUTPUT_DIR="${ARTIFACT_DIR}/${MACHINE_CLASS}"
mkdir -p "${OUTPUT_DIR}"

GIT_SHA="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# Map target -> bench invocation. Each invocation must print one StatPack-
# format JSONL line to stdout. The orchestrator captures that single line
# and appends it to the per-target file with the standard schema fields.
target_bench_command() {
    case "$1" in
        cold_start_ms)
            echo "cargo bench -p fcp-host --bench cold_start -- --statpack-json"
            ;;
        local_invoke_us)
            echo "cargo bench -p fcp-host --bench local_invoke -- --statpack-json"
            ;;
        lan_invoke_us)
            echo "cargo bench -p fcp-mesh --bench mesh_dispatch_lan -- --statpack-json"
            ;;
        derp_invoke_ms)
            echo "cargo bench -p fcp-mesh --bench mesh_dispatch_derp -- --statpack-json"
            ;;
        symbol_reconciliation_us)
            echo "cargo bench -p fcp-raptorq --bench symbol_reconciliation -- --statpack-json"
            ;;
        secret_reconciliation_ms)
            echo "cargo bench -p fcp-bootstrap --bench frost_recon -- --statpack-json"
            ;;
        cpu_overhead_pct)
            echo "cargo bench -p fcp-host --bench cpu_overhead -- --statpack-json --duration-secs 60"
            ;;
    esac
}

collect_one() {
    local target="$1"
    local out_file="${OUTPUT_DIR}/${target}.jsonl"
    local cmd
    cmd="$(target_bench_command "${target}")"

    echo "{\"ts\":\"${TIMESTAMP}\",\"target\":\"${target}\",\"phase\":\"start\",\"machine_class\":\"${MACHINE_CLASS}\",\"cmd\":\"${cmd}\"}" >&2

    # Run the bench under the workspace's rch wrapper so heavy compilation
    # offloads to remote workers when available. Bench output goes to a
    # tempfile, then the orchestrator extracts the StatPack JSON line.
    local tempfile
    tempfile="$(mktemp -t fcp-perf-XXXX.json)"
    if (cd "${REPO_ROOT}" && eval "${cmd}") > "${tempfile}" 2>&1; then
        # Find the last line that parses as JSON with a numeric p99 field.
        local statpack_line
        statpack_line="$(grep -E '"p99":' "${tempfile}" | tail -n 1 || true)"
        if [[ -z "${statpack_line}" ]]; then
            echo "{\"ts\":\"${TIMESTAMP}\",\"target\":\"${target}\",\"phase\":\"end\",\"machine_class\":\"${MACHINE_CLASS}\",\"verdict\":\"no_statpack_in_output\"}" >&2
            rm -f "${tempfile}"
            return 1
        fi
        # Augment the bench-emitted StatPack line with schema + machine_class
        # + commit_sha + timestamp. The bench is responsible for the
        # numeric fields (p50/p95/p99/samples); the orchestrator adds the
        # provenance fields.
        local augmented
        augmented="$(printf '%s' "${statpack_line}" \
            | sed "s|^{|{\"schema\":\"fcp.runtime-target.v1\",\"target\":\"${target}\",\"machine_class\":\"${MACHINE_CLASS}\",\"commit_sha\":\"${GIT_SHA}\",\"timestamp\":\"${TIMESTAMP}\",|")"
        echo "${augmented}" >> "${out_file}"
        echo "{\"ts\":\"${TIMESTAMP}\",\"target\":\"${target}\",\"phase\":\"end\",\"machine_class\":\"${MACHINE_CLASS}\",\"verdict\":\"appended\",\"out_file\":\"${out_file}\"}" >&2
        rm -f "${tempfile}"
        return 0
    else
        echo "{\"ts\":\"${TIMESTAMP}\",\"target\":\"${target}\",\"phase\":\"end\",\"machine_class\":\"${MACHINE_CLASS}\",\"verdict\":\"bench_failed\",\"log_tail\":\"$(tail -n 3 "${tempfile}" | tr '\n' ' ' | tr -d '"')\"}" >&2
        rm -f "${tempfile}"
        return 1
    fi
}

OVERALL_RC=0
for target in "${TARGETS[@]}"; do
    if ! collect_one "${target}"; then
        OVERALL_RC=1
    fi
done

echo "{\"ts\":\"${TIMESTAMP}\",\"phase\":\"summary\",\"machine_class\":\"${MACHINE_CLASS}\",\"targets_attempted\":${#TARGETS[@]},\"verdict\":$( [[ ${OVERALL_RC} -eq 0 ]] && echo '"all_pass"' || echo '"partial"' )}" >&2

exit "${OVERALL_RC}"
