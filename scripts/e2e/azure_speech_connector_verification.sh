#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_PATH="scripts/e2e/azure_speech_connector_verification.sh"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/azure-speech/${RUN_ID}}"
LOG_JSONL="${LOG_JSONL:-${OUT_ROOT}/azure_speech_connector_e2e.jsonl}"
RAW_LOG="${OUT_ROOT}/logs/azure_speech_loopback_e2e.log"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
REMOTE_TARGET_BASE="/tmp/rch-fcp-azure-speech-${RUN_ID}"
TARGET_DIR="${AZURE_SPEECH_CARGO_TARGET_DIR:-${REMOTE_TARGET_BASE}-target}"
COMMAND_LINE="${COMMAND_LINE:-bash ${SCRIPT_PATH}}"
export RCH_FORCE_REMOTE=1

mkdir -p "${OUT_ROOT}/logs"
: >"${LOG_JSONL}"

GIT_REVISION="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for ${SCRIPT_PATH}" >&2
  exit 2
fi

write_summary() {
  local result="$1"
  local status="$2"
  local note="$3"

  jq -n \
    --arg run_id "${RUN_ID}" \
    --arg connector_id "fcp.azure-speech" \
    --arg git_revision "${GIT_REVISION}" \
    --arg result "${result}" \
    --arg status "${status}" \
    --arg note "${note}" \
    --arg log_jsonl "${LOG_JSONL}" \
    --arg raw_log "${RAW_LOG}" \
    --arg target_dir "${TARGET_DIR}" \
    --arg toolchain "${REPO_TOOLCHAIN}" \
    '{
      run_id: $run_id,
      connector_id: $connector_id,
      git_revision: $git_revision,
      result: $result,
      status: $status,
      note: $note,
      log_jsonl: $log_jsonl,
      raw_log: $raw_log,
      target_dir: $target_dir,
      toolchain: $toolchain
    }' >"${OUT_ROOT}/summary.json"
}

log_has_infra_blocker() {
  local log_path="$1"
  local line
  while IFS= read -r line; do
    case "${line}" in
      *"RCH-E"*|*"remote required; refusing local fallback"*|*"rch command did not produce remote proof"*|*"No space left on device"*|*"connection reset by peer"*|*"Backend unavailable"*|*"unable to update registry"*|*"spurious network error"*|*"failed to get successful HTTP response"*|*"timeout: failed to execute process"*|*"missing worker system package"*)
        return 0
        ;;
    esac
  done <"${log_path}"
  return 1
}

classify_failure() {
  local log_path="$1"
  if [[ ! -f "${log_path}" ]]; then
    echo "infra_blocked"
  elif log_has_infra_blocker "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

rch_remote_summary_present() {
  local log_path="$1"
  local line
  while IFS= read -r line; do
    if [[ "${line}" == *"[RCH] remote"* ]]; then
      return 0
    fi
  done <"${log_path}"
  return 1
}

echo "[azure-speech-e2e] cargo test -p fcp-azure-speech --test loopback azure_speech_loopback_e2e_jsonl_matrix"
if ! (
  cd "${REPO_ROOT}"
  env RCH_VISIBILITY=verbose rch exec -- env \
    "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
    "CARGO_TARGET_DIR=${TARGET_DIR}" \
    "AZURE_SPEECH_E2E_COMMAND_LINE=${COMMAND_LINE}" \
    "AZURE_SPEECH_E2E_GIT_REVISION=${GIT_REVISION}" \
    cargo test -p fcp-azure-speech --test loopback azure_speech_loopback_e2e_jsonl_matrix -- --nocapture
) >"${RAW_LOG}" 2>&1
then
  status="$(classify_failure "${RAW_LOG}")"
  write_summary "${status}" "${status}" "Azure Speech loopback matrix command failed; inspect raw_log"
  exit "$([[ "${status}" == "infra_blocked" ]] && echo 2 || echo 1)"
fi

if ! rch_remote_summary_present "${RAW_LOG}"; then
  echo "Azure Speech e2e rch command did not produce remote proof; see ${RAW_LOG}" >&2
  printf '%s\n' "rch command did not produce remote proof" >>"${RAW_LOG}"
  write_summary "infra_blocked" "infra_blocked" "rch command did not produce remote proof"
  exit 2
fi

grep -a '^AZURE_SPEECH_E2E_JSONL ' "${RAW_LOG}" \
  | sed 's/^AZURE_SPEECH_E2E_JSONL //' >"${LOG_JSONL}"

if [[ ! -s "${LOG_JSONL}" ]]; then
  echo "Azure Speech e2e emitted no JSONL records; see ${RAW_LOG}" >&2
  exit 1
fi

required_scenarios=(
  voices_list
  tts_synthesize
  stt_fast_transcribe
  batch_submit
  batch_get
  batch_files
  custom_project_create
  custom_project_list
  custom_project_get
  custom_project_delete
  custom_dataset_create
  custom_dataset_get
  custom_dataset_delete
  custom_model_create
  custom_model_get
  custom_model_delete
  custom_endpoint_create
  custom_endpoint_get
  custom_endpoint_delete
  managed_identity_host_token_handoff
  connector_local_imds_policy_skip
  imds_token_success_skip
  imds_expired_refresh_skip
  imds_missing_permission_skip
  imds_tenant_resource_mismatch_skip
  imds_timeout_skip
  imds_provider_auth_failure_skip
  rate_limit_retry
  provider_error_401
  provider_timeout
  malformed_input
  unsupported_format
  oversized_audio
  capability_zone_denial
  capability_instance_denial
  harness_cancellation
  streaming_blocker
  shutdown_cleanup
  optional_live_smoke
)

for scenario in "${required_scenarios[@]}"; do
  count="$(jq -r --arg scenario "${scenario}" '
    select(.record_type == "azure_speech_connector_e2e" and .scenario == $scenario) | .scenario
  ' "${LOG_JSONL}" | wc -l | tr -d ' ')"
  if [[ "${count}" -lt 1 ]]; then
    echo "missing Azure Speech e2e JSONL scenario ${scenario}" >&2
    exit 1
  fi
done

jq -e '
  select(.record_type == "azure_speech_connector_e2e")
  | [
      .command_line,
      .git_revision,
      .connector_id,
      .operation_id,
      .capability,
      .zone,
      .instance_id,
      .fixture_or_live_mode,
      .region_class,
      .endpoint_class,
      .auth_mode,
      .token_source_class,
      .api_version,
      .resource_id_hash,
      .model_id_hash,
      .project_id_hash,
      .voice_id,
      .language_id,
      .model_id,
      .content_type,
      .input_audio_byte_count,
      .output_audio_byte_count,
      .transcript_length,
      .stream_chunk_count,
      .http_status,
      .retry_backoff_decision,
      .fcp_error_mapping,
      .latency_ms,
      .result,
      .audit_receipt_id,
      .cleanup_result,
      .skip_reason
    ]
  | all(. != null)
' "${LOG_JSONL}" >/dev/null

if grep -aE 'loopback-secret|aad-secret|Bearer|/subscriptions/|11111111-2222-3333-4444-555555555555|project-loopback-123|dataset-loopback-123|model-loopback-123|endpoint-loopback-123|sig=SECRET|Weather|hello|nightly support calls|should-not-leak|transcript text|raw-audio' "${LOG_JSONL}" >/dev/null; then
  echo "Azure Speech e2e JSONL leaked a forbidden secret, transcript, provider URL, or content fragment" >&2
  exit 1
fi

live_count="$(jq -r '
  select(.record_type == "azure_speech_connector_e2e" and .fixture_or_live_mode == "live")
  | .result
' "${LOG_JSONL}" | wc -l | tr -d ' ')"
if [[ "${live_count}" -lt 1 ]]; then
  echo "missing Azure Speech optional live pass/skip JSONL record" >&2
  exit 1
fi

write_summary "passed" "ok" "Azure Speech loopback matrix emitted complete redaction-safe JSONL evidence"

{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -euo pipefail'
  printf '%s\n' ''
  printf '%s\n' "RUN_ID=\"\${RUN_ID:-\$(date -u +%Y%m%dT%H%M%SZ)}\""
  printf '%s\n' "REPO_TOOLCHAIN=\"\${REPO_TOOLCHAIN:-${REPO_TOOLCHAIN}}\""
  printf '%s\n' "AZURE_SPEECH_CARGO_TARGET_DIR=\"\${AZURE_SPEECH_CARGO_TARGET_DIR:-/tmp/rch-fcp-azure-speech-\${RUN_ID}-target}\""
  printf '%s\n' 'export RCH_FORCE_REMOTE=1'
  printf '%s\n' "OUT_ROOT=\"\${OUT_ROOT:-/tmp/fcp-azure-speech-e2e-replay}\" scripts/e2e/azure_speech_connector_verification.sh"
} >"${OUT_ROOT}/replay.sh"
chmod +x "${OUT_ROOT}/replay.sh"

echo "AZURE_SPEECH_E2E_JSONL=${LOG_JSONL}"
echo "Azure Speech verification artifacts written to ${OUT_ROOT}"
