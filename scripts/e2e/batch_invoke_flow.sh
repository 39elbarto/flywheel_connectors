#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_batch_invoke_flow"
SEED="0xDEADBEEF"
ZONE="z:work"
CONNECTOR="fcp.test-echo"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"

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
  printf '{"timestamp":"%s","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${step}" "${step_number}" "${correlation_id}" "${duration_ms}" "${result}" "${artifacts_json}" >> "${LOG_JSONL}"
}

run_step() {
  local step="$1"
  local step_number="$2"
  local artifacts_json="$3"
  shift 3

  local start_ms end_ms duration_ms rc
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

step_install() {
  fcp install "${CONNECTOR}" --zone "${ZONE}"
}

step_verify_install() {
  fcp verify "${CONNECTOR}" --expect=valid
}

step_create_token() {
  fcp-harness create-token \
    --connector="${CONNECTOR}" \
    --operations=echo \
    --zone="${ZONE}" \
    --ttl=3600 \
    --output="${OUT_DIR}/token.cbor"
}

step_prepare_batch() {
  cat <<'JSON' > "${OUT_DIR}/batch.json"
[
  {"operation":"echo","args":{"message":"batch-1"}},
  {"operation":"echo","args":{"message":"batch-2"}},
  {"operation":"echo","args":{"message":"batch-3"}}
]
JSON
}

step_batch_invoke() {
  fcp-harness batch-invoke \
    --connector="${CONNECTOR}" \
    --batch="${OUT_DIR}/batch.json" \
    --token="${OUT_DIR}/token.cbor" \
    --output="${OUT_DIR}/batch_receipts.json"
}

step_verify_batch() {
  jq -e 'length == 3' "${OUT_DIR}/batch_receipts.json" >/dev/null
  jq -e 'all(.[]; (.error // null) == null)' "${OUT_DIR}/batch_receipts.json" >/dev/null
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
run_step "install_connector" 2 "[]" step_install
run_step "verify_install" 3 "[]" step_verify_install
run_step "create_token" 4 "[\"${OUT_DIR}/token.cbor\"]" step_create_token
run_step "prepare_batch" 5 "[\"${OUT_DIR}/batch.json\"]" step_prepare_batch
run_step "batch_invoke" 6 "[\"${OUT_DIR}/batch_receipts.json\"]" step_batch_invoke
run_step "verify_batch" 7 "[]" step_verify_batch
run_step "teardown" 8 "[]" step_teardown

fcp-e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
