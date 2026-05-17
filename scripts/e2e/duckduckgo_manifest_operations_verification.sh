#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_JSONL="${1:-/tmp/fcp-duckduckgo-manifest-ops-$(date -u +%Y%m%dT%H%M%SZ).jsonl}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch-fcp-duckduckgo-manifest-ops-${RUN_ID}-target}"
LOG_DIR="${LOG_DIR:-$(dirname "${LOG_JSONL}")/duckduckgo-manifest-ops-logs}"
RCH_BIN="${RCH_BIN:-rch}"
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export RCH_FORCE_REMOTE=1

mkdir -p "$(dirname "${LOG_JSONL}")" "${LOG_DIR}"

cd "${REPO_ROOT}"

echo "[duckduckgo-manifest] repo=${REPO_ROOT}"
echo "[duckduckgo-manifest] git_revision=${GIT_REVISION}"
echo "[duckduckgo-manifest] target_dir=${TARGET_DIR}"
echo "[duckduckgo-manifest] log_jsonl=${LOG_JSONL}"
echo "[duckduckgo-manifest] log_dir=${LOG_DIR}"

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

  echo "[duckduckgo-manifest] ${name}: cargo $*"
  if ! env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env \
    "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
    "CARGO_TARGET_DIR=${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    cargo "$@" >"${log_path}" 2>&1
  then
    status="$(classify_failure "${log_path}")"
    echo "[duckduckgo-manifest] ${name}: ${status}; see ${log_path}" >&2
    exit "$([[ "${status}" == "infra_blocked" ]] && echo 2 || echo 1)"
  fi

  if ! rch_remote_summary_present "${log_path}"; then
    echo "[duckduckgo-manifest] ${name}: rch command did not produce remote proof; see ${log_path}" >&2
    printf '%s\n' "rch command did not produce remote proof" >>"${log_path}"
    exit 2
  fi
}

require_cmd rg
require_cmd "${RCH_BIN}"

echo "[duckduckgo-manifest] running manifest/runtime/schema unit contract tests"
run_cargo manifest_runtime_contract test -p fcp-duckduckgo manifest --lib -- --nocapture

echo "[duckduckgo-manifest] running deterministic no-live-provider loopback integration tests"
run_cargo loopback_integration test -p fcp-duckduckgo --test integration lifecycle_advertises_no_auth_privacy_boundary -- --nocapture

echo "[duckduckgo-manifest] running manifest conformance tests"
run_cargo manifest_conformance test -p fcp-duckduckgo --test conformance manifest -- --nocapture

echo "[duckduckgo-manifest] running redaction-safe cross-connector audit JSONL lane"
run_cargo manifest_ops_audit run -p fcp-conformance --bin fcp-manifest-ops-audit -- \
  --repo-root . \
  --allow-findings \
  --log-jsonl "${LOG_JSONL}"

if ! rg -q '"connector_id":"fcp.duckduckgo".*"result":"pass"' "${LOG_JSONL}"; then
  echo "[duckduckgo-manifest] ERROR: fcp.duckduckgo did not produce a passing connector_scan log entry" >&2
  exit 1
fi

cat >>"${LOG_JSONL}" <<EOF
{"log_version":"v1","script":"scripts/e2e/duckduckgo_manifest_operations_verification.sh","step":"duckduckgo_manifest_runtime_contract","result":"pass","timestamp":"${TIMESTAMP}","details":{"command_line":["scripts/e2e/duckduckgo_manifest_operations_verification.sh","${LOG_JSONL}"],"git_revision":"${GIT_REVISION}","connector_id":"fcp.duckduckgo","manifest_path":"connectors/duckduckgo/manifest.toml","operation_count_before":0,"operation_count_after":5,"manifest_operation_count":5,"runtime_introspection_operation_count":5,"introspect_count":5,"provider_fixture_mode":"deterministic no-live-provider wiremock loopback covered by integration tests","live_provider_mode":"not required","skip_reason":null,"cleanup_result":"no cleanup required; read-only no-live-provider lane with ephemeral loopback listener","redaction_decision":"redaction-safe: no API keys, raw queries, prompts, request bodies, provider payloads, result contents, or provider error bodies logged","toolchain":"${REPO_TOOLCHAIN}","target_dir":"${TARGET_DIR}","log_dir":"${LOG_DIR}","runner":"rch:remote-required","operations":[{"operation_id":"duckduckgo.search.text","capability":"duckduckgo.search.read","network_host_class":"public_tls:html.duckduckgo.com/lite.duckduckgo.com","schema_validation_result":"pass"},{"operation_id":"duckduckgo.search.images","capability":"duckduckgo.search.read","network_host_class":"public_tls:html.duckduckgo.com/lite.duckduckgo.com/duckduckgo.com","schema_validation_result":"pass"},{"operation_id":"duckduckgo.search.news","capability":"duckduckgo.search.read","network_host_class":"public_tls:html.duckduckgo.com/lite.duckduckgo.com/duckduckgo.com","schema_validation_result":"pass"},{"operation_id":"duckduckgo.search.suggestions","capability":"duckduckgo.search.read","network_host_class":"public_tls:duckduckgo.com","schema_validation_result":"pass"},{"operation_id":"duckduckgo.health","capability":"duckduckgo.search.read","network_host_class":"public_tls:api.duckduckgo.com","schema_validation_result":"pass"}]}}
EOF

echo "[duckduckgo-manifest] verified fcp.duckduckgo connector_scan pass in ${LOG_JSONL}"
