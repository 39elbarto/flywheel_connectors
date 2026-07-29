#!/usr/bin/env bash
# scripts/perf/run_coz_pilot.sh
# flywheel_connectors-angoc.1.5 (Phase B.5)
#
# Orchestrates a Coz (https://github.com/plasma-umass/coz) causal-
# profiling pilot on the three hot paths identified by the May 2026
# swarm flamegraphs:
#
#   1. Connector activate     (fcp-host)
#   2. JSON-RPC dispatch      (fcp-host)
#   3. RaptorQ encode         (fcp-mesh)
#
# Coz is a causal profiler — it runs the program under a sampled
# "virtual speedup" of selected code lines and reports the resulting
# end-to-end speedup. Unlike sampling profilers (which tell you
# where time is spent), Coz tells you which speedups WOULD MATTER.
# This is the "speedup oracle" referenced in the bridge plan's
# Phase B accretion list.
#
# Output: perf-results/coz/{activate,dispatch,raptorq_encode}.profile
# in Coz's native binary format. The companion findings doc at
# docs/perf/causal_profiling_pilot.md is hand-curated from the
# profile.viewer output once the runs complete.
#
# Usage:
#   run_coz_pilot.sh [--path <activate|dispatch|raptorq_encode>]
#                    [--samples <N>] [--duration-secs <N>]
#
# Environment:
#   COZ           : path to `coz` binary. Defaults to `coz` on PATH.
#                   Set explicitly when coz is installed at e.g.
#                   /usr/local/bin/coz.
#   CARGO         : path to `cargo`. Defaults to `cargo` on PATH.
#
# Platform note: Coz currently supports Linux x86_64 + AArch64
# only. On macOS (the developer hosts), the script emits a
# "COZ_UNSUPPORTED_PLATFORM" diagnostic and exits 2 without
# attempting a run. The pilot is therefore CI-runner-driven.

set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${REPO_ROOT}/perf-results/coz}"
COZ_BIN="${COZ:-coz}"
CARGO_BIN="${CARGO:-cargo}"
SAMPLES="${SAMPLES:-1000}"
DURATION_SECS="${DURATION_SECS:-120}"

SELECTED_PATH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --path) SELECTED_PATH="$2"; shift 2 ;;
        --samples) SAMPLES="$2"; shift 2 ;;
        --duration-secs) DURATION_SECS="$2"; shift 2 ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "run_coz_pilot: unknown arg: $1" >&2
            exit 2
            ;;
    esac
done

ALL_PATHS=(activate dispatch raptorq_encode)

if [[ -n "${SELECTED_PATH}" ]]; then
    if ! printf '%s\n' "${ALL_PATHS[@]}" | grep -qx "${SELECTED_PATH}"; then
        echo "run_coz_pilot: invalid --path '${SELECTED_PATH}' (expected: ${ALL_PATHS[*]})" >&2
        exit 2
    fi
    PATHS=("${SELECTED_PATH}")
else
    PATHS=("${ALL_PATHS[@]}")
fi

# Platform gate.
uname_s="$(uname -s)"
if [[ "${uname_s}" != "Linux" ]]; then
    echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"hot_path\":\"-\",\"phase\":\"platform_unsupported\",\"diagnostic\":\"COZ_UNSUPPORTED_PLATFORM\",\"uname\":\"${uname_s}\",\"note\":\"Coz requires Linux x86_64 or AArch64; macOS/Windows hosts cannot run this pilot. Run on a Linux CI runner instead.\"}" >&2
    exit 2
fi

# Coz availability gate.
if ! command -v "${COZ_BIN}" > /dev/null 2>&1; then
    echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"hot_path\":\"-\",\"phase\":\"coz_unavailable\",\"diagnostic\":\"COZ_NOT_FOUND\",\"coz_bin\":\"${COZ_BIN}\",\"note\":\"install via 'cargo install coz' or apt 'coz-profiler'\"}" >&2
    exit 2
fi

mkdir -p "${ARTIFACT_DIR}"

# Map hot-path -> bench / binary invocation. Each invocation runs the
# target program under Coz with progress points already inserted by
# the bench's #[coz::scope_progress] macros (a build-time feature).
hotpath_bench() {
    case "$1" in
        activate)
            echo "${CARGO_BIN} bench -p fcp-host --bench cold_start --features coz-profile -- --duration-secs ${DURATION_SECS}"
            ;;
        dispatch)
            echo "${CARGO_BIN} bench -p fcp-host --bench local_invoke --features coz-profile -- --duration-secs ${DURATION_SECS}"
            ;;
        raptorq_encode)
            echo "${CARGO_BIN} bench -p fcp-mesh --bench raptorq_encode --features coz-profile -- --duration-secs ${DURATION_SECS}"
            ;;
    esac
}

run_one() {
    local hot_path="$1"
    local profile_file="${ARTIFACT_DIR}/${hot_path}.profile"
    local cmd
    cmd="$(hotpath_bench "${hot_path}")"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    echo "{\"ts\":\"${ts}\",\"hot_path\":\"${hot_path}\",\"phase\":\"start\",\"cmd\":\"${cmd}\",\"profile_file\":\"${profile_file}\",\"samples\":${SAMPLES}}" >&2

    # Run the bench under Coz. Coz wraps the command and writes its
    # progress-based profile to <profile_file>.
    if (cd "${REPO_ROOT}" && "${COZ_BIN}" run --output "${profile_file}" --- $(eval echo "${cmd}")) > /dev/null 2>&1; then
        echo "{\"ts\":\"${ts}\",\"hot_path\":\"${hot_path}\",\"phase\":\"end\",\"verdict\":\"profile_written\",\"profile_file\":\"${profile_file}\"}" >&2
        return 0
    else
        echo "{\"ts\":\"${ts}\",\"hot_path\":\"${hot_path}\",\"phase\":\"end\",\"verdict\":\"profile_failed\"}" >&2
        return 1
    fi
}

OVERALL_RC=0
for hot_path in "${PATHS[@]}"; do
    if ! run_one "${hot_path}"; then
        OVERALL_RC=1
    fi
done

echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"phase\":\"summary\",\"hot_paths_run\":${#PATHS[@]},\"verdict\":$( [[ ${OVERALL_RC} -eq 0 ]] && echo '"all_pass"' || echo '"partial"' )}" >&2

exit "${OVERALL_RC}"
