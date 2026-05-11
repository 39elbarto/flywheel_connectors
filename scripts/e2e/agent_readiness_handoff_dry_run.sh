#!/usr/bin/env bash
# =============================================================================
# agent_readiness_handoff_dry_run.sh - Agent readiness handoff dry-run
# =============================================================================
# Bead:   flywheel_connectors-y2mlu.4
# Schema: fcp.agent-readiness-handoff-dry-run.v1
#
# Exercises the offline `fwc agent-readiness` handoff path without touching
# shared services, deleting files, or cleaning prior artifacts.
#
# Usage:
#   FWC_BIN=/path/to/fwc bash scripts/e2e/agent_readiness_handoff_dry_run.sh [options]
#
# Options:
#   --run-id <id>           Stable run identifier
#   --out-root <path>       Artifact output directory
#   --agent <name>          Agent name recorded in the fixture
#   --scenario <scenario>   Fixture scenario
#   --owned-path-glob <g>   Owned path glob to record
#   -h, --help              Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCHEMA="fcp.agent-readiness-handoff-dry-run.v1"

RUN_ID="agent-readiness-dry-run"
OUT_ROOT="${TMPDIR:-/tmp}/fcp-agent-readiness-handoff-${RUN_ID}"
AGENT="${AGENT_NAME:-GreenLake}"
SCENARIO="agent-mail-unavailable"
OWNED_PATH_GLOB="crates/fcp-evidence/**"
OBSERVED_AT_UNIX_MS="1893456000000"
FWC_BIN="${FWC_BIN:-fwc}"

usage() {
  cat <<'EOF'
Usage: FWC_BIN=/path/to/fwc scripts/e2e/agent_readiness_handoff_dry_run.sh [options]

Options:
  --run-id <id>           Stable run identifier
  --out-root <path>       Artifact output directory
  --agent <name>          Agent name recorded in the fixture
  --scenario <scenario>   Fixture scenario
  --owned-path-glob <g>   Owned path glob to record
  -h, --help              Show this help
EOF
}

fail() {
  printf 'agent readiness handoff dry-run failed: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "missing required command: $1"
  fi
}

require_fwc() {
  if [[ "${FWC_BIN}" == */* ]]; then
    [[ -x "${FWC_BIN}" ]] || fail "FWC_BIN is not executable: ${FWC_BIN}"
  else
    command -v "${FWC_BIN}" >/dev/null 2>&1 || fail "FWC_BIN not found on PATH: ${FWC_BIN}"
  fi
}

refuse_existing() {
  local path="$1"
  [[ ! -e "${path}" ]] || fail "refusing to overwrite existing artifact: ${path}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    --out-root)
      OUT_ROOT="$2"
      shift 2
      ;;
    --agent)
      AGENT="$2"
      shift 2
      ;;
    --scenario)
      SCENARIO="$2"
      shift 2
      ;;
    --owned-path-glob)
      OWNED_PATH_GLOB="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

require_cmd jq
require_fwc

mkdir -p "${OUT_ROOT}"

CLI_OUTPUT="${OUT_ROOT}/cli-output.json"
REPLAY_OUTPUT="${OUT_ROOT}/replay-output.json"
DRY_RUN_REPORT="${OUT_ROOT}/dry-run-report.json"

for artifact in \
  "${CLI_OUTPUT}" \
  "${REPLAY_OUTPUT}" \
  "${DRY_RUN_REPORT}" \
  "${OUT_ROOT}/report.json" \
  "${OUT_ROOT}/events.jsonl" \
  "${OUT_ROOT}/handoff.json" \
  "${OUT_ROOT}/handoff.md"; do
  refuse_existing "${artifact}"
done

"${FWC_BIN}" --format json agent-readiness fixture \
  --scenario "${SCENARIO}" \
  --run-id "${RUN_ID}" \
  --agent "${AGENT}" \
  --observed-at-unix-ms "${OBSERVED_AT_UNIX_MS}" \
  --owned-path-glob "${OWNED_PATH_GLOB}" \
  --out-dir "${OUT_ROOT}" > "${CLI_OUTPUT}"

jq -e \
  --arg schema "fcp.agent-readiness-handoff.v1" \
  --arg run_id "${RUN_ID}" \
  '
    .status == "ok"
    and .handoff.schema == $schema
    and .handoff.run_id == $run_id
    and (.handoff.exact_allowed_next_actions | type == "array" and length > 0)
    and (.handoff.git_truth.remote_main_sha | type == "string")
    and (.handoff.active_blocker_beads | type == "array")
  ' "${CLI_OUTPUT}" >/dev/null

"${FWC_BIN}" --format json agent-readiness replay \
  --report "${OUT_ROOT}/report.json" \
  --jsonl "${OUT_ROOT}/events.jsonl" > "${REPLAY_OUTPUT}"

jq -e '
  .status == "ok"
  and .jsonl_replay.status == "ok"
  and (.jsonl_replay.event_count | type == "number" and . > 0)
' "${REPLAY_OUTPUT}" >/dev/null

jq -n \
  --arg schema "${SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg out_root "${OUT_ROOT}" \
  --arg cli_output "${CLI_OUTPUT}" \
  --arg replay_output "${REPLAY_OUTPUT}" \
  --arg report "${OUT_ROOT}/report.json" \
  --arg events "${OUT_ROOT}/events.jsonl" \
  --arg handoff "${OUT_ROOT}/handoff.json" \
  '{
    schema: $schema,
    run_id: $run_id,
    status: "ok",
    out_root: $out_root,
    artifacts: {
      cli_output: $cli_output,
      replay_output: $replay_output,
      report_json: $report,
      events_jsonl: $events,
      handoff_json: $handoff
    }
  }' > "${DRY_RUN_REPORT}"

printf 'agent readiness handoff dry-run ok: %s\n' "${DRY_RUN_REPORT}"
