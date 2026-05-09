#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_PATH="scripts/e2e/azure_speech_connector_verification.sh"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/azure-speech/${RUN_ID}}"
LOG_JSONL="${LOG_JSONL:-${OUT_ROOT}/azure_speech_connector_e2e.jsonl}"
RAW_LOG="${OUT_ROOT}/logs/azure_speech_loopback_e2e.log"
TARGET_DIR="${AZURE_SPEECH_CARGO_TARGET_DIR:-/tmp/fcp-azure-speech-e2e-target}"
COMMAND_LINE="${COMMAND_LINE:-bash ${SCRIPT_PATH}}"

mkdir -p "${OUT_ROOT}/logs"
: >"${LOG_JSONL}"

GIT_REVISION="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for ${SCRIPT_PATH}" >&2
  exit 2
fi

echo "[azure-speech-e2e] cargo test -p fcp-azure-speech --test loopback azure_speech_loopback_e2e_jsonl_matrix"
(
  cd "${REPO_ROOT}"
  rch exec -- env \
    "CARGO_TARGET_DIR=${TARGET_DIR}" \
    "AZURE_SPEECH_E2E_COMMAND_LINE=${COMMAND_LINE}" \
    "AZURE_SPEECH_E2E_GIT_REVISION=${GIT_REVISION}" \
    cargo test -p fcp-azure-speech --test loopback azure_speech_loopback_e2e_jsonl_matrix -- --nocapture
) >"${RAW_LOG}" 2>&1

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

if grep -aE 'loopback-secret|aad-secret|Bearer|/subscriptions/|sig=SECRET|Weather|hello|nightly support calls|should-not-leak|transcript text|raw-audio' "${LOG_JSONL}" >/dev/null; then
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

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector_id": "fcp.azure-speech",
  "git_revision": "${GIT_REVISION}",
  "result": "passed",
  "log_jsonl": "${LOG_JSONL}",
  "raw_log": "${RAW_LOG}",
  "target_dir": "${TARGET_DIR}"
}
EOF

cat >"${OUT_ROOT}/replay.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
AZURE_SPEECH_CARGO_TARGET_DIR="${AZURE_SPEECH_CARGO_TARGET_DIR:-/tmp/fcp-azure-speech-e2e-target}"
OUT_ROOT="${OUT_ROOT:-/tmp/fcp-azure-speech-e2e-replay}" scripts/e2e/azure_speech_connector_verification.sh
EOF
chmod +x "${OUT_ROOT}/replay.sh"

echo "AZURE_SPEECH_E2E_JSONL=${LOG_JSONL}"
echo "Azure Speech verification artifacts written to ${OUT_ROOT}"
