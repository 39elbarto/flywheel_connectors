#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_diversity_single_source"
SEED="0xDEADBEEF"
ZONE="${ZONE:-z:work}"
CONNECTOR="${CONNECTOR:-fcp.test-echo}"
MIN_SOURCE_DIVERSITY="${MIN_SOURCE_DIVERSITY:-2}"
SYMBOL_COUNT="${SYMBOL_COUNT:-4}"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"

EXPECTED_FAILURE=""
ACTUAL_FAILURE=""

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

json_or_null() {
  local value="$1"
  if [[ -z "${value}" ]]; then
    printf 'null'
  else
    printf '"%s"' "${value}"
  fi
}

details_json() {
  if [[ -z "${EXPECTED_FAILURE}" && -z "${ACTUAL_FAILURE}" ]]; then
    printf 'null'
    return 0
  fi
  printf '{"expected_failure":%s,"actual_failure":%s}' \
    "$(json_or_null "${EXPECTED_FAILURE}")" \
    "$(json_or_null "${ACTUAL_FAILURE}")"
}

log_step() {
  local step="$1"
  local step_number="$2"
  local result="$3"
  local duration_ms="$4"
  local artifacts_json="$5"
  local timestamp
  local correlation_id
  local details

  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  correlation_id="$(correlation_id_for_step "${step_number}")"
  details="$(details_json)"

  mkdir -p "$(dirname "${LOG_JSONL}")"
  printf '{"timestamp":"%s","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s,"details":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${step}" "${step_number}" "${correlation_id}" "${duration_ms}" "${result}" "${artifacts_json}" "${details}" >> "${LOG_JSONL}"
}

run_step() {
  local step="$1"
  local step_number="$2"
  local artifacts_json="$3"
  local expected_failure="$4"
  shift 4

  local start_ms end_ms duration_ms rc
  EXPECTED_FAILURE="${expected_failure}"
  ACTUAL_FAILURE=""

  start_ms="$(now_ms)"
  set +e
  "$@"
  rc=$?
  set -e
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  if [[ ${rc} -eq 0 ]]; then
    if [[ -n "${EXPECTED_FAILURE}" ]]; then
      ACTUAL_FAILURE="${EXPECTED_FAILURE}"
    fi
    log_step "${step}" "${step_number}" "pass" "${duration_ms}" "${artifacts_json}"
  else
    ACTUAL_FAILURE="exit_code_${rc}"
    log_step "${step}" "${step_number}" "fail" "${duration_ms}" "${artifacts_json}"
    exit ${rc}
  fi
}

step_init() {
  fcp-harness init --nodes=3 --deterministic --seed "${SEED}"
}

step_install() {
  fcp install "${CONNECTOR}" --zone "${ZONE}"
}

step_create_object() {
  mkdir -p "${OUT_DIR}"
  printf '{"min_nodes":1,"max_node_fraction_bps":10000,"target_coverage_bps":10000,"min_source_diversity":%s}\n' \
    "${MIN_SOURCE_DIVERSITY}" > "${OUT_DIR}/placement.json"

  fcp-harness create-object \
    --content='{"message":"diversity single-source test"}' \
    --placement-file "${OUT_DIR}/placement.json" \
    --output "${OUT_DIR}/object.cbor"
}

step_seed_single_source() {
  fcp-harness seed-symbols \
    --object "${OUT_DIR}/object.cbor" \
    --node "node-0" \
    --symbols "${SYMBOL_COUNT}" \
    --output "${OUT_DIR}/seed_report.json"
}

step_reconstruct_denied() {
  fcp-harness reconstruct \
    --object "${OUT_DIR}/object.cbor" \
    --expect-failure=FCP-4001 \
    --output "${OUT_DIR}/reconstruct_denial.cbor"
}

step_repair_plan() {
  fcp-harness repair-plan \
    --object "${OUT_DIR}/object.cbor" \
    --output "${OUT_DIR}/repair_plan.json"
  jq -e '.diversity_deficit >= 1' "${OUT_DIR}/repair_plan.json" >/dev/null
}

require_cmd fcp-harness
require_cmd fcp
require_cmd fcp-e2e
require_cmd jq

mkdir -p "${OUT_DIR}"

run_step "init" 1 "[]" "" step_init
run_step "install_connector" 2 "[]" "" step_install
run_step "create_object" 3 "[\"${OUT_DIR}/object.cbor\",\"${OUT_DIR}/placement.json\"]" "" step_create_object
run_step "seed_single_source" 4 "[\"${OUT_DIR}/seed_report.json\"]" "" step_seed_single_source
run_step "reconstruct_denied" 5 "[\"${OUT_DIR}/reconstruct_denial.cbor\"]" "FCP-4001" step_reconstruct_denied
run_step "repair_plan" 6 "[\"${OUT_DIR}/repair_plan.json\"]" "" step_repair_plan

fcp-e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
