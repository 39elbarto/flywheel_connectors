#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_epoch_replay_mirror_install"
SEED="0xDEADBEEF"
ZONE="${ZONE:-z:project:e2e}"
CONNECTOR="${CONNECTOR:-fcp.test-echo}"
REGISTRY_URL="${REGISTRY_URL:-mock://registry}"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
EPOCH_COUNT="${EPOCH_COUNT:-5}"
OFFLINE_EPOCHS="${OFFLINE_EPOCHS:-3}"
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

epoch_context_json() {
  local epoch="$1"
  local gap_detected="$2"
  local replayed="$3"
  printf '{"epoch":%s,"gap_detected":%s,"replayed":%s}' \
    "${epoch}" "${gap_detected}" "${replayed}"
}

mirror_context_json() {
  local install_source="$1"
  local verified="$2"
  printf '{"install_source":"%s","verified":%s}' \
    "${install_source}" "${verified}"
}

step_init() {
  fcp-harness init --nodes=3 --deterministic --seed "${SEED}"
  fcp-harness health --expect=healthy
}

step_policy_zone() {
  fcp-harness create-zone \
    --zone "${ZONE}" \
    --policy "default-deny+verify"
}

step_epoch_stream() {
  fcp-harness epoch-produce \
    --zone "${ZONE}" \
    --epochs "${EPOCH_COUNT}" \
    --output "${OUT_DIR}/epoch_produce.json"
  STEP_CONTEXT="$(epoch_context_json "${EPOCH_COUNT}" false false)"
}

step_node_offline() {
  fcp-harness node-down --node node-1
}

step_epoch_advance() {
  fcp-harness epoch-produce \
    --zone "${ZONE}" \
    --epochs "${OFFLINE_EPOCHS}" \
    --output "${OUT_DIR}/epoch_gap.json"
  STEP_CONTEXT="$(epoch_context_json "${OFFLINE_EPOCHS}" false false)"
}

step_node_online() {
  fcp-harness node-up --node node-1
}

step_replay_gap() {
  fcp-harness epoch-replay \
    --zone "${ZONE}" \
    --node node-1 \
    --output "${OUT_DIR}/epoch_replay.json"
  STEP_CONTEXT="$(epoch_context_json "${OFFLINE_EPOCHS}" true true)"
}

step_verify_frontier() {
  fcp-harness epoch-frontier \
    --zone "${ZONE}" \
    --node node-1 \
    --output "${OUT_DIR}/epoch_frontier.json"
  jq -e '.gap_detected == true' "${OUT_DIR}/epoch_frontier.json" >/dev/null
  jq -e '.replayed == true' "${OUT_DIR}/epoch_frontier.json" >/dev/null
}

step_install_from_registry() {
  fcp install "${CONNECTOR}" --zone "${ZONE}" --registry "${REGISTRY_URL}" --json \
    > "${OUT_DIR}/install_node_a.json"
  STEP_CONTEXT="$(mirror_context_json "registry" true)"
}

step_verify_mirror() {
  fcp-harness mirror-status \
    --zone "${ZONE}" \
    --connector "${CONNECTOR}" \
    --output "${OUT_DIR}/mirror_status.json"
  jq -e '.mirrored == true' "${OUT_DIR}/mirror_status.json" >/dev/null
}

step_install_from_mesh() {
  fcp install "${CONNECTOR}" --zone "${ZONE}" --mirror-only --json \
    > "${OUT_DIR}/install_node_c.json"
  STEP_CONTEXT="$(mirror_context_json "mesh" true)"
}

step_verify_install() {
  jq -e '.verification.status == "verified"' "${OUT_DIR}/install_node_c.json" >/dev/null
  jq -e '.binary_hash | length > 0' "${OUT_DIR}/install_node_c.json" >/dev/null
}

step_audit_verify() {
  fcp audit tail --zone "${ZONE}" --filter=type=Install --limit=10 --json \
    > "${OUT_DIR}/install_audit.jsonl"
  jq -e 'select(.connector_id == "'"${CONNECTOR}"'")' "${OUT_DIR}/install_audit.jsonl" >/dev/null
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
run_step "policy_zone" 2 "[]" step_policy_zone
run_step "epoch_stream" 3 "[\"${OUT_DIR}/epoch_produce.json\"]" step_epoch_stream
run_step "node_offline" 4 "[]" step_node_offline
run_step "epoch_advance" 5 "[\"${OUT_DIR}/epoch_gap.json\"]" step_epoch_advance
run_step "node_online" 6 "[]" step_node_online
run_step "replay_gap" 7 "[\"${OUT_DIR}/epoch_replay.json\"]" step_replay_gap
run_step "verify_frontier" 8 "[\"${OUT_DIR}/epoch_frontier.json\"]" step_verify_frontier
run_step "install_from_registry" 9 "[\"${OUT_DIR}/install_node_a.json\"]" step_install_from_registry
run_step "verify_mirror" 10 "[\"${OUT_DIR}/mirror_status.json\"]" step_verify_mirror
run_step "install_from_mesh" 11 "[\"${OUT_DIR}/install_node_c.json\"]" step_install_from_mesh
run_step "verify_install" 12 "[]" step_verify_install
run_step "audit_verify" 13 "[\"${OUT_DIR}/install_audit.jsonl\"]" step_audit_verify
run_step "teardown" 14 "[]" step_teardown

fcp-e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
