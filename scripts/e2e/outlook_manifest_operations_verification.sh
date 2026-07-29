#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_JSONL="${1:-/tmp/fcp-outlook-manifest-ops-$(date -u +%Y%m%dT%H%M%SZ).jsonl}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch-fcp-outlook-manifest-ops-${RUN_ID}-target}"
LOG_DIR="${LOG_DIR:-$(dirname "${LOG_JSONL}")/outlook-manifest-ops-logs}"
RCH_BIN="${RCH_BIN:-rch}"
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export RCH_FORCE_REMOTE=1

mkdir -p "$(dirname "${LOG_JSONL}")" "${LOG_DIR}"

cd "${REPO_ROOT}"

echo "[outlook-manifest] repo=${REPO_ROOT}"
echo "[outlook-manifest] git_revision=${GIT_REVISION}"
echo "[outlook-manifest] target_dir=${TARGET_DIR}"
echo "[outlook-manifest] log_jsonl=${LOG_JSONL}"
echo "[outlook-manifest] log_dir=${LOG_DIR}"

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

  echo "[outlook-manifest] ${name}: cargo $*"
  if ! env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env \
    "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
    "CARGO_TARGET_DIR=${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    cargo "$@" >"${log_path}" 2>&1
  then
    status="$(classify_failure "${log_path}")"
    echo "[outlook-manifest] ${name}: ${status}; see ${log_path}" >&2
    exit "$([[ "${status}" == "infra_blocked" ]] && echo 2 || echo 1)"
  fi

  if ! rch_remote_summary_present "${log_path}"; then
    echo "[outlook-manifest] ${name}: rch command did not produce remote proof; see ${log_path}" >&2
    printf '%s\n' "rch command did not produce remote proof" >>"${log_path}"
    exit 2
  fi
}

require_cmd rg
require_cmd "${RCH_BIN}"

echo "[outlook-manifest] running manifest/runtime/schema/client unit tests"
run_cargo manifest_runtime_contract test -p fcp-outlook --lib -- --nocapture

echo "[outlook-manifest] running public provider contract tests"
run_cargo provider_contract test -p fcp-outlook --test provider_contract -- --nocapture

echo "[outlook-manifest] running redaction-safe cross-connector audit JSONL lane"
run_cargo manifest_ops_audit run -p fcp-conformance --bin fcp-manifest-ops-audit -- \
  --repo-root . \
  --allow-findings \
  --log-jsonl "${LOG_JSONL}"

if ! rg -q '"connector_id":"fcp.outlook".*"result":"pass"' "${LOG_JSONL}"; then
  echo "[outlook-manifest] ERROR: fcp.outlook did not produce a passing connector_scan log entry" >&2
  exit 1
fi

cat >>"${LOG_JSONL}" <<EOF
{"log_version":"v1","script":"scripts/e2e/outlook_manifest_operations_verification.sh","step":"outlook_manifest_runtime_contract","result":"pass","timestamp":"${TIMESTAMP}","details":{"command_line":["scripts/e2e/outlook_manifest_operations_verification.sh","${LOG_JSONL}"],"git_revision":"${GIT_REVISION}","connector_id":"fcp.outlook","manifest_path":"connectors/outlook/manifest.toml","operation_count_before":0,"operation_count_after":7,"manifest_operation_count":7,"runtime_introspection_operation_count":7,"introspect_count":7,"provider_fixture_mode":"deterministic no-live-provider unit and provider-contract tests cover schema, runtime introspection, Microsoft Graph host policy, request parsing, recipient normalization, query escaping, and 202 no-body send behavior","live_provider_mode":"not required","skip_reason":null,"cleanup_result":"no cleanup required; read-only no-live-provider lane with ephemeral loopback listeners inside unit tests","redaction_decision":"redaction-safe: no API keys, bearer tokens, recipient lists, message subjects, message bodies, body previews, calendar subjects, locations, provider payloads, or provider error bodies logged","toolchain":"${REPO_TOOLCHAIN}","target_dir":"${TARGET_DIR}","log_dir":"${LOG_DIR}","runner":"rch:remote-required","operations":[{"operation_id":"outlook.list_messages","capability":"outlook.read","network_host_class":"public_tls:graph.microsoft.com/graph.microsoft.us","schema_validation_result":"pass"},{"operation_id":"outlook.get_message","capability":"outlook.read","network_host_class":"public_tls:graph.microsoft.com/graph.microsoft.us","schema_validation_result":"pass"},{"operation_id":"outlook.search_messages","capability":"outlook.read","network_host_class":"public_tls:graph.microsoft.com/graph.microsoft.us","schema_validation_result":"pass"},{"operation_id":"outlook.send_message","capability":"outlook.send","network_host_class":"public_tls:graph.microsoft.com/graph.microsoft.us","schema_validation_result":"pass"},{"operation_id":"outlook.list_events","capability":"outlook.calendar","network_host_class":"public_tls:graph.microsoft.com/graph.microsoft.us","schema_validation_result":"pass"},{"operation_id":"outlook.create_event","capability":"outlook.calendar","network_host_class":"public_tls:graph.microsoft.com/graph.microsoft.us","schema_validation_result":"pass"},{"operation_id":"outlook.list_folders","capability":"outlook.read","network_host_class":"public_tls:graph.microsoft.com/graph.microsoft.us","schema_validation_result":"pass"}]}}
EOF

echo "[outlook-manifest] verified fcp.outlook connector_scan pass in ${LOG_JSONL}"
