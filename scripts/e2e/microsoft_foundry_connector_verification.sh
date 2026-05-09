#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_PATH="scripts/e2e/microsoft_foundry_connector_verification.sh"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/microsoft-foundry/${RUN_ID}}"
LOG_JSONL="${LOG_JSONL:-${OUT_ROOT}/microsoft_foundry_connector_e2e.jsonl}"
COMMAND_LINE="${COMMAND_LINE:-bash ${SCRIPT_PATH}}"

mkdir -p "${OUT_ROOT}/logs"
: >"${LOG_JSONL}"

export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-microsoft-foundry-e2e-target}"
export MICROSOFT_FOUNDRY_CONNECTOR_E2E_JSONL="${LOG_JSONL}"
export MICROSOFT_FOUNDRY_E2E_COMMAND_LINE="${COMMAND_LINE}"
MICROSOFT_FOUNDRY_E2E_GIT_REVISION="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
export MICROSOFT_FOUNDRY_E2E_GIT_REVISION

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for ${SCRIPT_PATH}" >&2
  exit 2
fi

emit_json() {
  jq -cn \
    --arg record_type "$1" \
    --arg command_line "${COMMAND_LINE}" \
    --arg git_revision "${MICROSOFT_FOUNDRY_E2E_GIT_REVISION}" \
    --arg scenario "$2" \
    --arg outcome "$3" \
    --arg details "$4" \
    '{
      record_type: $record_type,
      command_line: $command_line,
      git_revision: $git_revision,
      scenario: $scenario,
      outcome: $outcome,
      details: ($details | fromjson)
    }' >>"${LOG_JSONL}"
}

run_test() {
  local test_name="$1"
  local raw_log="${OUT_ROOT}/logs/${test_name}.cargo-test.log"
  echo "[microsoft-foundry-e2e] cargo test -p fcp-microsoft-foundry --test integration ${test_name}"
  if (
    cd "${REPO_ROOT}"
    cargo test -p fcp-microsoft-foundry --test integration "${test_name}" -- --nocapture
  ) >"${raw_log}" 2>&1; then
    emit_json \
      "microsoft_foundry_connector_e2e_test" \
      "${test_name}" \
      "passed" \
      "$(jq -cn --arg raw_log "${raw_log}" '{raw_log: $raw_log}')"
  else
    emit_json \
      "microsoft_foundry_connector_e2e_test" \
      "${test_name}" \
      "failed" \
      "$(jq -cn --arg raw_log "${raw_log}" '{raw_log: $raw_log}')"
    echo "Microsoft Foundry e2e cargo test failed; see ${raw_log}" >&2
    exit 1
  fi
}

validate_log() {
  local required_ops=(
    "microsoft_foundry.responses.create"
    "microsoft_foundry.responses.cancel"
    "microsoft_foundry.responses.input_items.list"
    "microsoft_foundry.chat.completions"
    "microsoft_foundry.chat.completions_stream"
    "microsoft_foundry.embeddings.create"
    "microsoft_foundry.deployments.list"
  )

  for operation in "${required_ops[@]}"; do
    local count
    count="$(jq -r --arg operation "${operation}" '
      select(.record_type == "microsoft_foundry_connector_e2e" and .operation == $operation and .fixture_or_live_mode == "fixture")
      | .operation
    ' "${LOG_JSONL}" | wc -l | tr -d ' ')"
    if [[ "${count}" -lt 1 ]]; then
      echo "missing Microsoft Foundry fixture JSONL record for ${operation}" >&2
      exit 1
    fi
  done

  if grep -qE 'foundry-test-key|entra-test-token|private prompt|Summarize privately|acct\.openai\.azure\.com|acct\.services\.ai\.azure\.com' "${LOG_JSONL}"; then
    echo "Microsoft Foundry e2e JSONL leaked a test secret, prompt, or raw resource hostname" >&2
    exit 1
  fi

  local live_count
  live_count="$(jq -r '
    select(.record_type == "microsoft_foundry_connector_e2e" and .fixture_or_live_mode == "live")
    | .outcome
  ' "${LOG_JSONL}" | wc -l | tr -d ' ')"
  if [[ "${live_count}" -lt 1 ]]; then
    echo "missing live smoke pass/skip record" >&2
    exit 1
  fi
}

emit_json "microsoft_foundry_connector_e2e_start" "start" "running" "$(jq -cn --arg out_root "${OUT_ROOT}" '{out_root: $out_root}')"
run_test "microsoft_foundry_connector_wiremock_e2e"
run_test "microsoft_foundry_live_smoke_e2e"
validate_log
emit_json "microsoft_foundry_connector_e2e_complete" "complete" "passed" "$(jq -cn --arg log_jsonl "${LOG_JSONL}" '{log_jsonl: $log_jsonl}')"

echo "MICROSOFT_FOUNDRY_CONNECTOR_E2E_JSONL=${LOG_JSONL}"
