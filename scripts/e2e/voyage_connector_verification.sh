#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_PATH="scripts/e2e/voyage_connector_verification.sh"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/voyage/${RUN_ID}}"
INTEGRATION_JSONL="${INTEGRATION_JSONL:-${OUT_ROOT}/evidence/voyage_integration.jsonl}"
LOCAL_NON_MOCK_JSONL="${LOCAL_NON_MOCK_JSONL:-${OUT_ROOT}/evidence/local_non_mock.jsonl}"
COMMAND_LINE="${COMMAND_LINE:-bash ${SCRIPT_PATH}}"
RCH_BIN="${RCH_BIN:-rch}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
TARGET_PREFIX="${CARGO_TARGET_PREFIX:-/tmp/fcp-voyage-${RUN_ID}}"
BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"
: >"${INTEGRATION_JSONL}"

OVERALL_STATUS="ok"
EXIT_CODE=0

manifest_status="pending"
cargo_check_status="pending"
format_check_status="pending"
conformance_status="pending"
integration_status="pending"
integration_jsonl_status="pending"
local_non_mock_status="pending"
local_non_mock_jsonl_status="pending"
clippy_status="pending"

VOYAGE_E2E_GIT_REVISION="$(git -c "safe.directory=${REPO_ROOT}" -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

promote_overall_status() {
  local next_status="$1"
  case "${next_status}" in
    failed)
      OVERALL_STATUS="failed"
      EXIT_CODE=1
      ;;
    infra_blocked)
      if [[ "${OVERALL_STATUS}" == "ok" ]]; then
        OVERALL_STATUS="infra_blocked"
        EXIT_CODE=2
      fi
      ;;
  esac
}

classify_failure() {
  local log_path="$1"

  if [[ ! -f "${log_path}" ]]; then
    echo "infra_blocked"
    return
  fi

  if grep -Eq 'timeout: failed to execute process|RCH-E|remote required; refusing local fallback|missing worker|No space left on device|dbus-1\.pc|connection reset by peer|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response|all workers failed preflight' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

observed_runner() {
  local log_path="$1"

  if [[ ! -f "${log_path}" ]]; then
    echo "unknown"
  elif grep -Fq "[RCH] remote" "${log_path}"; then
    echo "rch_remote"
  elif grep -Fq "[RCH] local" "${log_path}"; then
    echo "rch_local_fallback"
  else
    echo "rch_unclassified"
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local rc

  echo "[voyage-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
  rc="$?"
  return "${rc}"
}

run_step() {
  local name="$1"
  shift

  if run_logged "${name}" "$@"; then
    echo "passed"
  else
    local status
    status="$(classify_failure "${OUT_ROOT}/logs/${name}.log")"
    promote_overall_status "${status}"
    echo "${status}"
  fi
}

run_rch_step() {
  local name="$1"
  local target_suffix="$2"
  shift 2
  run_step "${name}" env RCH_VISIBILITY=verbose TMPDIR="${TMPDIR:-/tmp}" "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" CARGO_TARGET_DIR="${TARGET_PREFIX}-${target_suffix}" "$@"
}

emit_integration_json() {
  jq -cn \
    --arg record_type "$1" \
    --arg command_line "${COMMAND_LINE}" \
    --arg git_revision "${VOYAGE_E2E_GIT_REVISION}" \
    --arg scenario "$2" \
    --arg outcome "$3" \
    --arg details "$4" \
    '{
      record_type: $record_type,
      command_line: $command_line,
      git_revision: $git_revision,
      scenario: $scenario,
      outcome: $outcome,
      details: ($details | fromjson)
    }' >>"${INTEGRATION_JSONL}"
}

require_cmd jq
require_cmd "${RCH_BIN}"

emit_integration_json "voyage_connector_e2e_start" "start" "running" "$(jq -cn --arg out_root "${OUT_ROOT}" '{out_root: $out_root}')"

manifest_status="$(run_rch_step manifest_check fwc cargo run -q -p fwc -- manifest fix connectors/voyage/manifest.toml --check --json)"
cargo_check_status="$(run_rch_step cargo_check check cargo check -p fcp-voyage --all-targets)"
format_check_status="$(run_rch_step format_check fmt cargo fmt -p fcp-voyage -- --check)"
conformance_status="$(run_rch_step conformance conformance cargo test -p fcp-voyage --test conformance -- --nocapture)"
integration_status="$(run_rch_step integration integration cargo test -p fcp-voyage --test integration -- --nocapture)"
if [[ "${integration_status}" == "passed" ]]; then
  emit_integration_json "voyage_connector_integration" "crate_integration" "passed" "$(jq -cn '{fixture_mode: "wiremock", coverage: ["auth", "base_url_policy", "embeddings", "multimodal_embeddings", "rerank", "rate_limit", "catalog", "health", "lifecycle"]}')"
  integration_jsonl_status="passed"
else
  emit_integration_json "voyage_connector_integration" "crate_integration" "${integration_status}" "$(jq -cn --arg log "${OUT_ROOT}/logs/integration.log" '{fixture_mode: "wiremock", log: $log}')"
  integration_jsonl_status="${integration_status}"
fi

local_non_mock_status="$(run_rch_step local_non_mock local-non-mock cargo test -p fcp-voyage --test local_non_mock -- --nocapture)"
if grep -a '"suite_class":"local_non_mock"' "${OUT_ROOT}/logs/local_non_mock.log" >"${LOCAL_NON_MOCK_JSONL}"; then
  if jq -s -e '
    length >= 3
    and all(.[]; .connector == "voyage")
    and all(.[]; .package == "fcp-voyage")
    and all(.[]; .suite_class == "local_non_mock")
    and all(.[]; .acceptance_suite_class == "local_non_mock")
    and all(.[]; .bead_id == "flywheel_connectors-4kw5f.12")
    and all(.[]; .fixture_mode == "loopback_http")
    and all(.[]; .provider_class == "local_sufficient")
    and all(.[]; .result == "passed")
    and all(.[] | select(.auth_gate? != null); .auth_gate.mode == "bearer_api_key")
    and all(.[] | select(.auth_gate? != null); .auth_gate.credentials_used == true)
    and all(.[] | select(.auth_gate? != null); .auth_gate.secret_material_logged == false)
    and any(.[]; .case == "embeddings" and .request_response_boundary.method == "POST" and .request_response_boundary.path == "/v1/embeddings" and .request_response_boundary.input_count == 1 and .request_response_boundary.raw_input_logged == false)
    and any(.[]; .case == "rerank" and .request_response_boundary.method == "POST" and .request_response_boundary.path == "/v1/rerank" and .request_response_boundary.document_count == 2 and .request_response_boundary.raw_query_logged == false and .request_response_boundary.raw_documents_logged == false)
    and any(.[]; .case == "wrong_capability_no_egress" and .request_response_boundary.method == "none" and .request_response_boundary.egress_observed == false)
  ' "${LOCAL_NON_MOCK_JSONL}" >/dev/null; then
    local_non_mock_jsonl_status="passed"
  else
    local_non_mock_jsonl_status="failed"
    if [[ "${local_non_mock_status}" == "passed" ]]; then
      promote_overall_status failed
    fi
  fi
else
  local_non_mock_jsonl_status="${local_non_mock_status}"
  cat >"${LOCAL_NON_MOCK_JSONL}" <<EOF
{"event":"voyage_local_non_mock_missing_jsonl","status":"${local_non_mock_jsonl_status}","reason":"local_non_mock test emitted no extractable local_non_mock JSONL records","git_revision":"${VOYAGE_E2E_GIT_REVISION}","fixture_mode":"loopback_http","log":"${OUT_ROOT}/logs/local_non_mock.log"}
EOF
  if [[ "${local_non_mock_status}" == "passed" ]]; then
    local_non_mock_jsonl_status="failed"
    promote_overall_status failed
  fi
fi

if grep -qE 'local_voyage_api_key|local acceptance document|local query|first document|second document|should never reach loopback|127\.0\.0\.1:[0-9]+' "${LOCAL_NON_MOCK_JSONL}" "${INTEGRATION_JSONL}"; then
  local_non_mock_jsonl_status="failed"
  integration_jsonl_status="failed"
  promote_overall_status failed
fi

clippy_status="$(run_rch_step clippy clippy cargo clippy -p fcp-voyage --all-targets -- -D warnings)"
emit_integration_json "voyage_connector_e2e_complete" "complete" "${OVERALL_STATUS}" "$(jq -cn --arg integration_jsonl "${INTEGRATION_JSONL}" --arg local_non_mock_jsonl "${LOCAL_NON_MOCK_JSONL}" '{integration_jsonl: $integration_jsonl, local_non_mock_jsonl: $local_non_mock_jsonl}')"

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-voyage",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "${SCRIPT_PATH}",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${VOYAGE_E2E_GIT_REVISION}",
  "target_prefix": "${TARGET_PREFIX}",
  "build_jobs": "${BUILD_JOBS}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "runner": "rch",
  "fixture_mode": "wiremock_and_loopback_http",
  "redaction": "no Voyage API key, loopback endpoint, input text, query text, candidate documents, image URLs, embedding vectors, rerank scores, or provider response body is emitted in extracted evidence"
}
EOF

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-voyage",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "runner": "rch",
  "observed_runners": {
    "manifest_check": "$(observed_runner "${OUT_ROOT}/logs/manifest_check.log")",
    "cargo_check": "$(observed_runner "${OUT_ROOT}/logs/cargo_check.log")",
    "format_check": "$(observed_runner "${OUT_ROOT}/logs/format_check.log")",
    "conformance": "$(observed_runner "${OUT_ROOT}/logs/conformance.log")",
    "integration": "$(observed_runner "${OUT_ROOT}/logs/integration.log")",
    "local_non_mock": "$(observed_runner "${OUT_ROOT}/logs/local_non_mock.log")",
    "clippy": "$(observed_runner "${OUT_ROOT}/logs/clippy.log")"
  },
  "steps": {
    "manifest_check": "${manifest_status}",
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "conformance": "${conformance_status}",
    "integration": "${integration_status}",
    "integration_jsonl": "${integration_jsonl_status}",
    "local_non_mock": "${local_non_mock_status}",
    "local_non_mock_jsonl": "${local_non_mock_jsonl_status}",
    "clippy": "${clippy_status}"
  },
  "artifacts": {
    "integration_jsonl": "${INTEGRATION_JSONL}",
    "local_non_mock_jsonl": "${LOCAL_NON_MOCK_JSONL}",
    "environment": "${OUT_ROOT}/environment.json"
  },
  "redaction_checks": {
    "integration_jsonl": "${integration_jsonl_status}",
    "local_non_mock_jsonl": "${local_non_mock_jsonl_status}"
  }
}
EOF

jq -c '.steps' "${OUT_ROOT}/summary.json"
echo "VOYAGE_CONNECTOR_INTEGRATION_JSONL=${INTEGRATION_JSONL}"
echo "VOYAGE_LOCAL_NON_MOCK_JSONL=${LOCAL_NON_MOCK_JSONL}"
exit "${EXIT_CODE}"
