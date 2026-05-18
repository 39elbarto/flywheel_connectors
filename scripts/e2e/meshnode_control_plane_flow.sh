#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_meshnode_control_plane"
SEED="0xC0NTR0L"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
CARGO_LOG="${CARGO_LOG:-${OUT_DIR}/meshnode_control_plane_cargo.log}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
MESHNODE_TARGET_DIR="${MESHNODE_TARGET_DIR:-/tmp/fcp-meshnode-control-plane}"
export RCH_FORCE_REMOTE=1

EXPECTED_FAILURE=""
ACTUAL_FAILURE=""
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
  printf '{"timestamp":"%s","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s,"context":%s,"details":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${step}" "${step_number}" "${correlation_id}" "${duration_ms}" "${result}" "${artifacts_json}" "${STEP_CONTEXT}" "${details}" >> "${LOG_JSONL}"
}

run_step() {
  local step="$1"
  local step_number="$2"
  local artifacts_json="$3"
  local expected_failure="$4"
  local context_json="$5"
  shift 5

  local start_ms end_ms duration_ms rc
  EXPECTED_FAILURE="${expected_failure}"
  ACTUAL_FAILURE=""
  STEP_CONTEXT="${context_json}"

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

run_cargo() {
  "${RCH_BIN}" exec -- env CARGO_TARGET_DIR="${MESHNODE_TARGET_DIR}" cargo "$@"
}

rch_remote_summary_present() {
  local execution_log="$1"

  if [[ "${RCH_REQUIRE_REMOTE}" != "1" ]]; then
    return 0
  fi

  if grep -Eq '^\[RCH\].*(local|refusing local fallback|no admissible workers)' "${execution_log}"; then
    echo "Missing accepted remote rch summary in ${execution_log}" >&2
    echo "rch remote proof is required; refusing local fallback" >&2
    return 2
  fi

  grep -Eq '^\[RCH\].*(remote|worker|executor|accepted|completed)' "${execution_log}" && return 0

  echo "Missing accepted remote rch summary in ${execution_log}" >&2
  echo "rch remote proof is required; refusing local fallback" >&2
  return 2
}

step_prepare() {
  mkdir -p "${OUT_DIR}"
}

step_run_meshnode_tests() {
  local remote_error=""

  if ! run_cargo test -p fcp-mesh --test mesh_integration meshnode_ -- --nocapture \
    --skip meshnode_symbol_ \
    --skip meshnode_decode_status_stops_transfer > "${CARGO_LOG}" 2>&1; then
    tail -40 "${CARGO_LOG}" >&2 || true
    return 1
  fi

  if remote_error="$(rch_remote_summary_present "${CARGO_LOG}" 2>&1)"; then
    return 0
  fi

  printf '%s\n' "${remote_error}" >> "${CARGO_LOG}"
  printf '%s\n' "${remote_error}" >&2
  return 1
}

require_cmd "${RCH_BIN}"

run_step "prepare_output" 1 "{}" "" "{}" step_prepare
run_step \
  "run_meshnode_control_plane_tests" \
  2 \
  '{"crate":"fcp-mesh","target":"mesh_integration","filter":"meshnode_ (skipping symbol_ + decode_status)","log":"meshnode_control_plane_cargo.log"}' \
  "" \
  '{"category":"meshnode","purpose":"control_plane_multi_node"}' \
  step_run_meshnode_tests
