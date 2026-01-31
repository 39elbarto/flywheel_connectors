#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_offline_repair_flow"
SEED="0xDEADBEEF"
ZONE="${ZONE:-z:work}"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
OBJECT_FILE="${OUT_DIR}/large_object.cbor"
OBJECT_ID=""
STEP_CONTEXT="null"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

now_ms() {
  local now
  now=$(date +%s%3N 2>/dev/null || true)
  if [[ -z "${now}" || "${now}" == *N ]]; then
    now="$(date +%s)000"
  fi
  printf '%s' "${now}"
}

hash256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256
    return 0
  fi
  echo "Missing required command: sha256sum/shasum/openssl" >&2
  exit 1
}

correlation_id_for_step() {
  local step_number="$1"
  local hex
  hex=$(printf '%s-%s-%s' "${SCRIPT_NAME}" "${SEED}" "${step_number}" | hash256 | awk '{print $1}')
  printf '%s-%s-%s-%s-%s' \
    "${hex:0:8}" "${hex:8:4}" "${hex:12:4}" "${hex:16:4}" "${hex:20:12}"
}

extract_object_id() {
  local file="$1"
  local object_id=""
  object_id=$(jq -r '.object_id // empty' "${file}" 2>/dev/null || true)
  printf '%s' "${object_id}"
}

object_context_json() {
  local coverage_bps="$1"
  local repair_in_progress="$2"
  local object_field="null"

  if [[ -z "${coverage_bps}" ]]; then
    coverage_bps="0"
  fi

  if [[ -n "${OBJECT_ID}" ]]; then
    object_field=$(printf '"%s"' "${OBJECT_ID}")
  fi

  printf '{"object_id":%s,"coverage_bps":%s,"repair_in_progress":%s}' \
    "${object_field}" "${coverage_bps}" "${repair_in_progress}"
}

log_step() {
  local step="$1"
  local step_number="$2"
  local result="$3"
  local duration_ms="$4"
  local artifacts_json="$5"
  local timestamp
  local correlation_id

  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  correlation_id="$(correlation_id_for_step "${step_number}")"

  mkdir -p "$(dirname "${LOG_JSONL}")"
  printf '{"timestamp":"%s","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s,"context":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${step}" "${step_number}" "${correlation_id}" "${duration_ms}" "${result}" "${artifacts_json}" "${STEP_CONTEXT}" >> "${LOG_JSONL}"
}

run_step() {
  local step="$1"
  local step_number="$2"
  local artifacts_json="$3"
  shift 3

  local start_ms end_ms duration_ms rc
  STEP_CONTEXT="null"
  start_ms="$(now_ms)"
  set +e
  "$@"
  rc=$?
  set -e
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  if [[ ${rc} -eq 0 ]]; then
    log_step "${step}" "${step_number}" "pass" "${duration_ms}" "${artifacts_json}"
  else
    log_step "${step}" "${step_number}" "fail" "${duration_ms}" "${artifacts_json}"
    exit ${rc}
  fi
}

step_init() {
  fcp-harness init --nodes=3 --deterministic --seed "${SEED}"
  fcp-harness health --expect=healthy
}

step_create_object() {
  mkdir -p "${OUT_DIR}"
  fcp-harness create-object \
    --content-size=1048576 \
    --zone "${ZONE}" \
    --placement distributed \
    --output "${OBJECT_FILE}"
  OBJECT_ID="$(extract_object_id "${OBJECT_FILE}")"
  STEP_CONTEXT="$(object_context_json 10000 false)"
}

step_initial_coverage() {
  fcp repair status --zone "${ZONE}" --json > "${OUT_DIR}/repair_status_initial.json"
  local coverage_bps
  coverage_bps=$(jq -r '.coverage.coverage_bps' "${OUT_DIR}/repair_status_initial.json")
  STEP_CONTEXT="$(object_context_json "${coverage_bps}" false)"
  jq -e '.coverage.coverage_bps >= 10000' "${OUT_DIR}/repair_status_initial.json" >/dev/null
}

step_node_down() {
  fcp-harness node-down --node node-2
}

step_coverage_degraded() {
  fcp repair status --zone "${ZONE}" --json > "${OUT_DIR}/repair_status_degraded.json"
  local coverage_bps
  coverage_bps=$(jq -r '.coverage.coverage_bps' "${OUT_DIR}/repair_status_degraded.json")
  STEP_CONTEXT="$(object_context_json "${coverage_bps}" true)"
  jq -e '.coverage.coverage_bps < 10000' "${OUT_DIR}/repair_status_degraded.json" >/dev/null
}

step_read_object() {
  fcp-harness read-object \
    --object "${OBJECT_FILE}" \
    --expect-success
}

step_monitor_repair() {
  : > "${OUT_DIR}/repair_progress.jsonl"
  for _ in 1 2 3 4 5; do
    sleep 2
    fcp repair status --zone "${ZONE}" --json >> "${OUT_DIR}/repair_progress.jsonl"
  done
  jq -s 'map(.coverage.coverage_bps) | (length > 1) and (last > first)' \
    "${OUT_DIR}/repair_progress.jsonl" >/dev/null
  local latest
  latest=$(jq -s 'map(.coverage.coverage_bps) | last' "${OUT_DIR}/repair_progress.jsonl")
  STEP_CONTEXT="$(object_context_json "${latest}" true)"
}

step_node_up() {
  fcp-harness node-up --node node-2
}

step_wait_convergence() {
  fcp-harness wait-convergence --timeout 10s
}

step_coverage_restored() {
  fcp repair status --zone "${ZONE}" --json > "${OUT_DIR}/repair_status_restored.json"
  local coverage_bps
  coverage_bps=$(jq -r '.coverage.coverage_bps' "${OUT_DIR}/repair_status_restored.json")
  STEP_CONTEXT="$(object_context_json "${coverage_bps}" false)"
  jq -e '.coverage.coverage_bps >= 10000' "${OUT_DIR}/repair_status_restored.json" >/dev/null
}

step_audit_verify() {
  fcp audit tail \
    --zone "${ZONE}" \
    --filter=type=RepairAction \
    --limit=10 \
    --json > "${OUT_DIR}/repair_audit.jsonl"
  jq -e 'select(.coverage_before < .coverage_after)' "${OUT_DIR}/repair_audit.jsonl" >/dev/null
}

step_teardown() {
  fcp-harness teardown
}

require_cmd fcp-harness
require_cmd fcp
require_cmd fcp-e2e
require_cmd jq

mkdir -p "${OUT_DIR}"

run_step "init" 1 "[]" step_init
run_step "create_object" 2 "[\"${OBJECT_FILE}\"]" step_create_object
run_step "initial_coverage" 3 "[\"${OUT_DIR}/repair_status_initial.json\"]" step_initial_coverage
run_step "node_down" 4 "[]" step_node_down
run_step "coverage_degraded" 5 "[\"${OUT_DIR}/repair_status_degraded.json\"]" step_coverage_degraded
run_step "read_object" 6 "[]" step_read_object
run_step "monitor_repair" 7 "[\"${OUT_DIR}/repair_progress.jsonl\"]" step_monitor_repair
run_step "node_up" 8 "[]" step_node_up
run_step "wait_convergence" 9 "[]" step_wait_convergence
run_step "coverage_restored" 10 "[\"${OUT_DIR}/repair_status_restored.json\"]" step_coverage_restored
run_step "audit_verify" 11 "[\"${OUT_DIR}/repair_audit.jsonl\"]" step_audit_verify
run_step "teardown" 12 "[]" step_teardown

fcp-e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
