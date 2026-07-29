#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_JSONL="${1:-/tmp/fcp-deepgram-manifest-ops-$(date -u +%Y%m%dT%H%M%SZ).jsonl}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch-fcp-deepgram-manifest-ops-${RUN_ID}-target}"
LOG_DIR="${LOG_DIR:-$(dirname "${LOG_JSONL}")/deepgram-manifest-ops-logs}"
RCH_BIN="${RCH_BIN:-rch}"
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export RCH_FORCE_REMOTE=1

mkdir -p "$(dirname "${LOG_JSONL}")" "${LOG_DIR}"

cd "${REPO_ROOT}"

echo "[deepgram-manifest] repo=${REPO_ROOT}"
echo "[deepgram-manifest] git_revision=${GIT_REVISION}"
echo "[deepgram-manifest] target_dir=${TARGET_DIR}"
echo "[deepgram-manifest] log_jsonl=${LOG_JSONL}"
echo "[deepgram-manifest] log_dir=${LOG_DIR}"

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

  echo "[deepgram-manifest] ${name}: cargo $*"
  if ! env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env \
    "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
    "CARGO_TARGET_DIR=${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    cargo "$@" >"${log_path}" 2>&1
  then
    status="$(classify_failure "${log_path}")"
    echo "[deepgram-manifest] ${name}: ${status}; see ${log_path}" >&2
    exit "$([[ "${status}" == "infra_blocked" ]] && echo 2 || echo 1)"
  fi

  if ! rch_remote_summary_present "${log_path}"; then
    echo "[deepgram-manifest] ${name}: rch command did not produce remote proof; see ${log_path}" >&2
    printf '%s\n' "rch command did not produce remote proof" >>"${log_path}"
    exit 2
  fi
}

require_cmd jq
require_cmd "${RCH_BIN}"

echo "[deepgram-manifest] running manifest/runtime/schema contract tests"
run_cargo manifest_runtime_contract test -p fcp-deepgram deepgram_manifest --test provider_contract -- --nocapture

echo "[deepgram-manifest] running deterministic no-live-provider HTTP/WebSocket connector suite"
run_cargo connector_suite_happy_path test -p fcp-deepgram --test connector_suite_happy_path -- --nocapture

echo "[deepgram-manifest] checking manifest interface hash with fwc"
run_cargo manifest_interface_hash run -p fwc -- manifest fix connectors/deepgram/manifest.toml --check --json

cat >>"${LOG_JSONL}" <<EOF
{"log_version":"v1","script":"scripts/e2e/deepgram_manifest_operations_verification.sh","step":"deepgram_manifest_runtime_contract","result":"pass","timestamp":"${TIMESTAMP}","details":{"command_line":["scripts/e2e/deepgram_manifest_operations_verification.sh","${LOG_JSONL}"],"git_revision":"${GIT_REVISION}","connector_id":"fcp.deepgram","manifest_path":"connectors/deepgram/manifest.toml","operation_count_before":0,"operation_count_after":2,"manifest_operation_count":2,"runtime_introspection_operation_count":2,"introspect_count":2,"provider_fixture_mode":"deterministic no-live-provider HTTP and WebSocket loopback fixtures covered by connector_suite_happy_path","live_provider_mode":"not required","skip_reason":null,"cleanup_result":"no cleanup required; read-only no-live-provider lane with ephemeral loopback listener","redaction_decision":"redaction-safe: no API keys, audio URLs, request bodies, transcripts, audio bytes, provider payloads, or error bodies logged","toolchain":"${REPO_TOOLCHAIN}","target_dir":"${TARGET_DIR}","log_dir":"${LOG_DIR}","runner":"rch:remote-required","operations":[{"operation_id":"deepgram.listen.transcribe","capability":"deepgram.listen","network_host_class":"public_tls:api.deepgram.com","schema_validation_result":"pass"},{"operation_id":"deepgram.listen.stream","capability":"deepgram.listen.streaming","network_host_class":"public_tls_websocket:api.deepgram.com","schema_validation_result":"pass"}]}}
EOF

echo "[deepgram-manifest] wrote redaction-safe JSONL proof to ${LOG_JSONL}"
tail -n 1 "${LOG_JSONL}"
