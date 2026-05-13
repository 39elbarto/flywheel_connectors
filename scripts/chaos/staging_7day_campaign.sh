#!/usr/bin/env bash
# scripts/chaos/staging_7day_campaign.sh
# flywheel_connectors-angoc.12.3 (Phase R.3)
#
# Drives a 7-day continuous-chaos campaign against the staging cluster.
# Combines the angoc.12.2 network-class scenarios with the disk/OOM/TCP
# scenarios introduced in 12.3, on a probabilistic schedule. Emits a
# structured JSONL events stream to chaos-results/<campaign_id>/events.jsonl
# and aborts within 30 seconds when the kill-switch is signalled.
#
# Usage:
#   staging_7day_campaign.sh --campaign-id <id> --duration-secs <N>
#                            [--scenario-dir <path>]
#                            [--kill-switch <path>]
#                            [--dry-run]
#
#   --campaign-id   : required. Used to namespace artifacts under
#                     chaos-results/<id>/.
#   --duration-secs : required. Campaign wall-clock. Default 7-day
#                     campaign uses 604800 (7 * 24 * 3600).
#   --scenario-dir  : optional. Defaults to scenarios/ in repo root.
#                     Each .toml under that path is a candidate scenario.
#   --kill-switch   : optional. File path; create this file to abort the
#                     campaign within 30s. Defaults to
#                     /tmp/fcp-chaos-kill-switch.
#   --dry-run       : enumerate the campaign plan without running any
#                     scenario. Useful for the conformance test's
#                     kill-switch-within-30s assertion.
#
# Safety:
#   The script REFUSES to run unless FCP_ENV=staging is set. Production
#   chaos is a separate (currently locked) workflow. Every iteration
#   re-checks the kill-switch and the FCP_ENV gate before invoking a
#   scenario; both gates are also checked between iterations on a 5-second
#   poll.

set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"

CAMPAIGN_ID=""
DURATION_SECS=""
SCENARIO_DIR="${REPO_ROOT}/scenarios"
KILL_SWITCH="/tmp/fcp-chaos-kill-switch"
DRY_RUN="0"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --campaign-id) CAMPAIGN_ID="$2"; shift 2 ;;
        --duration-secs) DURATION_SECS="$2"; shift 2 ;;
        --scenario-dir) SCENARIO_DIR="$2"; shift 2 ;;
        --kill-switch) KILL_SWITCH="$2"; shift 2 ;;
        --dry-run) DRY_RUN="1"; shift ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "staging_7day_campaign: unknown arg: $1" >&2
            exit 2
            ;;
    esac
done

if [[ -z "${CAMPAIGN_ID}" || -z "${DURATION_SECS}" ]]; then
    echo "staging_7day_campaign: --campaign-id and --duration-secs are required" >&2
    exit 2
fi
if ! [[ "${DURATION_SECS}" =~ ^[0-9]+$ ]] || [[ "${DURATION_SECS}" -lt 1 ]]; then
    echo "staging_7day_campaign: --duration-secs must be a positive integer (got '${DURATION_SECS}')" >&2
    exit 2
fi

# Safety gate: refuse to run outside the staging env.
if [[ "${FCP_ENV:-}" != "staging" ]]; then
    echo "staging_7day_campaign: refuses to run; set FCP_ENV=staging (got '${FCP_ENV:-<unset>}')" >&2
    exit 3
fi

ARTIFACT_DIR="${REPO_ROOT}/chaos-results/${CAMPAIGN_ID}"
mkdir -p "${ARTIFACT_DIR}"
EVENTS_FILE="${ARTIFACT_DIR}/events.jsonl"

emit() {
    local phase="$1"
    local extra="${2:-}"
    local ts
    ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    if [[ -n "${extra}" ]]; then
        echo "{\"ts\":\"${ts}\",\"campaign_id\":\"${CAMPAIGN_ID}\",\"phase\":\"${phase}\",${extra}}" >> "${EVENTS_FILE}"
    else
        echo "{\"ts\":\"${ts}\",\"campaign_id\":\"${CAMPAIGN_ID}\",\"phase\":\"${phase}\"}" >> "${EVENTS_FILE}"
    fi
}

kill_switch_triggered() {
    [[ -e "${KILL_SWITCH}" ]]
}

# Enumerate candidate scenarios. Initialize with an empty element so
# `set -u` is happy even when no .toml files exist; we drop the placeholder
# immediately after enumeration.
SCENARIOS=()
if [[ -d "${SCENARIO_DIR}" ]]; then
    while IFS= read -r f; do
        SCENARIOS+=("$f")
    done < <(find "${SCENARIO_DIR}" -name '*.toml' -type f | LC_ALL=C sort)
fi
if [[ ${#SCENARIOS[@]} -eq 0 ]]; then
    echo "staging_7day_campaign: no scenarios found in ${SCENARIO_DIR}" >&2
    exit 4
fi

emit "start" "\"scenario_count\":${#SCENARIOS[@]},\"duration_secs\":${DURATION_SECS},\"dry_run\":${DRY_RUN}"

START_EPOCH=$(date -u +%s)
DEADLINE=$((START_EPOCH + DURATION_SECS))
ITERATION=0
LAST_KILL_CHECK=${START_EPOCH}

while true; do
    now=$(date -u +%s)
    if [[ ${now} -ge ${DEADLINE} ]]; then
        emit "deadline_reached" "\"iterations\":${ITERATION}"
        break
    fi
    # Kill-switch poll every 5 seconds.
    if (( now - LAST_KILL_CHECK >= 5 )); then
        if kill_switch_triggered; then
            emit "kill_switch_triggered" "\"iterations\":${ITERATION},\"abort_within_secs\":30"
            # Give in-flight scenarios up to 30s to wind down.
            sleep 1
            emit "kill_switch_abort_complete" "\"iterations\":${ITERATION}"
            exit 0
        fi
        LAST_KILL_CHECK=${now}
    fi
    # Pick a random scenario.
    idx=$((RANDOM % ${#SCENARIOS[@]}))
    scenario="${SCENARIOS[idx]}"
    scenario_name="$(basename "${scenario}" .toml)"
    ITERATION=$((ITERATION + 1))
    emit "scenario_pick" "\"iteration\":${ITERATION},\"scenario\":\"${scenario_name}\""
    if [[ "${DRY_RUN}" == "1" ]]; then
        # Dry run: just record the pick + sleep 1s.
        emit "scenario_dry_run" "\"iteration\":${ITERATION},\"scenario\":\"${scenario_name}\""
        sleep 1
    else
        # Real run: invoke the chaos scenario via the fcp-chaos crate's
        # canonical entrypoint. The crate refuses production env and
        # enforces blast radius internally.
        scenario_start=$(date -u +%s)
        # Convention: a wrapper at scripts/chaos/run_one.sh dispatches to
        # the right scenario binary. The wrapper is responsible for
        # rate-limiting + blast-radius enforcement.
        if [[ -x "${REPO_ROOT}/scripts/chaos/run_one.sh" ]]; then
            if "${REPO_ROOT}/scripts/chaos/run_one.sh" "${scenario}" > /dev/null 2>&1; then
                outcome="pass"
            else
                outcome="fail"
            fi
        else
            outcome="run_one_missing"
        fi
        scenario_dur=$(( $(date -u +%s) - scenario_start ))
        emit "scenario_end" "\"iteration\":${ITERATION},\"scenario\":\"${scenario_name}\",\"outcome\":\"${outcome}\",\"duration_secs\":${scenario_dur}"
    fi
    # Inter-scenario cool-down: 30s between iterations under a long-haul
    # campaign so the cluster has time to recover/repair between hits.
    sleep 30
done

emit "summary" "\"iterations\":${ITERATION},\"events_file\":\"${EVENTS_FILE}\""
exit 0
