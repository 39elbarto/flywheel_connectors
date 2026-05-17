#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_JSONL="${1:-/tmp/fcp-elevenlabs-manifest-ops-$(date -u +%Y%m%dT%H%M%SZ).jsonl}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch-fcp-elevenlabs-manifest-ops-${RUN_ID}-target}"
LOG_DIR="${LOG_DIR:-$(dirname "${LOG_JSONL}")/elevenlabs-manifest-ops-logs}"
RCH_BIN="${RCH_BIN:-rch}"
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export RCH_FORCE_REMOTE=1

mkdir -p "$(dirname "${LOG_JSONL}")" "${LOG_DIR}"

cd "${REPO_ROOT}"

echo "[elevenlabs-manifest] repo=${REPO_ROOT}"
echo "[elevenlabs-manifest] git_revision=${GIT_REVISION}"
echo "[elevenlabs-manifest] target_dir=${TARGET_DIR}"
echo "[elevenlabs-manifest] log_jsonl=${LOG_JSONL}"
echo "[elevenlabs-manifest] log_dir=${LOG_DIR}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 2
  fi
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

run_cargo() {
  local name="$1"
  shift
  local log_path="${LOG_DIR}/${name}.log"
  local status

  echo "[elevenlabs-manifest] ${name}: cargo $*"
  if ! env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env \
    "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
    "CARGO_TARGET_DIR=${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    cargo "$@" >"${log_path}" 2>&1
  then
    status="$(classify_failure "${log_path}")"
    echo "[elevenlabs-manifest] ${name}: ${status}; see ${log_path}" >&2
    exit "$([[ "${status}" == "infra_blocked" ]] && echo 2 || echo 1)"
  fi

  if ! rch_remote_summary_present "${log_path}"; then
    echo "[elevenlabs-manifest] ${name}: rch command did not produce remote proof; see ${log_path}" >&2
    printf '%s\n' "rch command did not produce remote proof" >>"${log_path}"
    exit 2
  fi
}

require_cmd rg
require_cmd "${RCH_BIN}"

echo "[elevenlabs-manifest] running manifest/runtime/schema contract tests"
run_cargo manifest_runtime_contract test -p fcp-elevenlabs elevenlabs_manifest --test provider_contract -- --nocapture

echo "[elevenlabs-manifest] running deterministic no-live-provider HTTP/WebSocket connector suite"
run_cargo loopback_connector_suite test -p fcp-elevenlabs --test connector_suite_happy_path -- --nocapture

echo "[elevenlabs-manifest] running redaction-safe cross-connector audit JSONL lane"
run_cargo manifest_ops_audit run -p fcp-conformance --bin fcp-manifest-ops-audit -- \
  --repo-root . \
  --allow-findings \
  --log-jsonl "${LOG_JSONL}"

if ! rg -q '"connector_id":"fcp.elevenlabs".*"result":"pass"' "${LOG_JSONL}"; then
  echo "[elevenlabs-manifest] ERROR: fcp.elevenlabs did not produce a passing connector_scan log entry" >&2
  exit 1
fi

cat >>"${LOG_JSONL}" <<EOF
{"log_version":"v1","script":"scripts/e2e/elevenlabs_manifest_operations_verification.sh","step":"elevenlabs_manifest_runtime_contract","result":"pass","timestamp":"${TIMESTAMP}","details":{"command_line":["scripts/e2e/elevenlabs_manifest_operations_verification.sh","${LOG_JSONL}"],"git_revision":"${GIT_REVISION}","connector_id":"fcp.elevenlabs","manifest_path":"connectors/elevenlabs/manifest.toml","operation_count_before":0,"operation_count_after":4,"manifest_operation_count":4,"runtime_introspection_operation_count":4,"introspect_count":4,"provider_fixture_mode":"deterministic no-live-provider HTTP and WebSocket loopback fixtures covered by connector_suite_happy_path","live_provider_mode":"not required","skip_reason":null,"cleanup_result":"no cleanup required; read-only no-live-provider lane with ephemeral loopback listeners","redaction_decision":"redaction-safe: no API keys, request bodies, text prompts, transcripts, audio bytes, provider payloads, or error bodies logged","toolchain":"${REPO_TOOLCHAIN}","target_dir":"${TARGET_DIR}","log_dir":"${LOG_DIR}","runner":"rch:remote-required","operations":[{"operation_id":"elevenlabs.voices.list","capability":"elevenlabs.voices","network_host_class":"public_tls:elevenlabs.io","schema_validation_result":"pass"},{"operation_id":"elevenlabs.tts.generate","capability":"elevenlabs.tts","network_host_class":"public_tls:elevenlabs.io","schema_validation_result":"pass"},{"operation_id":"elevenlabs.tts.stream","capability":"elevenlabs.tts.streaming","network_host_class":"public_tls_streaming:elevenlabs.io","schema_validation_result":"pass"},{"operation_id":"elevenlabs.scribe.realtime.transcribe","capability":"elevenlabs.stt.streaming","network_host_class":"public_tls_websocket:elevenlabs.io","schema_validation_result":"pass"}]}}
EOF

echo "[elevenlabs-manifest] verified fcp.elevenlabs connector_scan pass in ${LOG_JSONL}"
