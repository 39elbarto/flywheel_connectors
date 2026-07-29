#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_PATH="scripts/e2e/ollama_connector_verification.sh"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/ollama/${RUN_ID}}"
LOOPBACK_JSONL="${LOOPBACK_JSONL:-${OUT_ROOT}/evidence/loopback_fixtures.jsonl}"
LOCAL_SMOKE_JSONL="${LOCAL_SMOKE_JSONL:-${OUT_ROOT}/evidence/local_smoke.jsonl}"
LOCAL_NON_MOCK_JSONL="${LOCAL_NON_MOCK_JSONL:-${OUT_ROOT}/evidence/local_non_mock.jsonl}"
RCH_BIN="${RCH_BIN:-rch}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
TARGET_PREFIX="${CARGO_TARGET_PREFIX:-/tmp/fcp-ollama-${RUN_ID}}"
BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0

manifest_status="pending"
cargo_check_status="pending"
format_check_status="pending"
conformance_status="pending"
loopback_status="pending"
loopback_jsonl_status="pending"
local_status="pending"
local_jsonl_status="pending"
local_non_mock_status="pending"
local_non_mock_jsonl_status="pending"
clippy_status="pending"

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

  if grep -Eq '^error:|error\[[E0-9]+\]|could not compile' "${log_path}"; then
    echo "failed"
  elif grep -Eq 'timeout: failed to execute process|RCH-E|remote required; refusing local fallback|missing worker|No space left on device|dbus-1\.pc|connection reset by peer|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response|all workers failed preflight' "${log_path}"; then
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

  echo "[ollama-verification] ${name}: $*" >&2
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
  run_step "${name}" env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" CARGO_TARGET_DIR="${TARGET_PREFIX}-${target_suffix}" "$@"
}

require_cmd jq
require_cmd "${RCH_BIN}"

git_revision="$(git -c "safe.directory=${REPO_ROOT}" -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"

manifest_status="$(run_rch_step manifest_check fwc cargo run -q -p fwc -- manifest fix connectors/ollama/manifest.toml --check --json)"
cargo_check_status="$(run_rch_step cargo_check check cargo check -p fcp-ollama --all-targets)"
format_check_status="$(run_rch_step format_check fmt cargo fmt -p fcp-ollama -- --check)"
conformance_status="$(run_rch_step conformance conformance cargo test -p fcp-ollama --test conformance -- --nocapture)"
loopback_status="$(run_rch_step loopback_jsonl loopback env OLLAMA_E2E_GIT_REVISION="${git_revision}" cargo test -p fcp-ollama --test integration ollama_loopback_e2e_jsonl_matrix -- --nocapture)"
local_status="$(run_rch_step local_jsonl local-smoke env OLLAMA_E2E_GIT_REVISION="${git_revision}" cargo test -p fcp-ollama --test integration ollama_local_smoke_or_structured_skip_jsonl -- --nocapture)"

if grep -a '^OLLAMA_E2E_JSONL ' "${OUT_ROOT}/logs/loopback_jsonl.log" | sed 's/^OLLAMA_E2E_JSONL //' >"${LOOPBACK_JSONL}"; then
  if jq -s -e '
    length >= 6
    and all(.[]; .event == "ollama_fixture_operation")
    and all(.[]; .fixture_mode == "wiremock")
    and all(.[]; .status == "passed")
    and any(.[]; .operation == "chat" and .http_status == 200)
    and any(.[]; .operation == "stream" and .stream_chunk_count >= 1)
    and any(.[]; .operation == "embeddings" and .embedding_dimensions == 4)
    and any(.[]; .operation == "models.list" and .model_count >= 1)
    and any(.[]; .operation == "cancellation")
    and any(.[]; .operation == "cleanup" and .cleanup_result == "shutdown")
  ' "${LOOPBACK_JSONL}" >/dev/null; then
    loopback_jsonl_status="passed"
  else
    loopback_jsonl_status="failed"
    if [[ "${loopback_status}" == "passed" ]]; then
      promote_overall_status failed
    fi
  fi
else
  loopback_jsonl_status="${loopback_status}"
  printf '{"event":"ollama_fixture_missing_jsonl","status":"%s","git_revision":"%s"}\n' "${loopback_jsonl_status}" "${git_revision}" >"${LOOPBACK_JSONL}"
  if [[ "${loopback_status}" == "passed" ]]; then
    loopback_jsonl_status="failed"
    promote_overall_status failed
  fi
fi

if grep -a '^OLLAMA_E2E_JSONL ' "${OUT_ROOT}/logs/local_jsonl.log" | sed 's/^OLLAMA_E2E_JSONL //' >"${LOCAL_SMOKE_JSONL}"; then
  if jq -s -e '
    length >= 1
    and all(.[]; .event == "ollama_fixture_operation")
    and all(.[]; .fixture_mode == "local")
    and all(.[]; (.status == "passed" or .status == "skipped"))
    and any(.[]; (.operation == "local_smoke" or .operation == "local_models.list"))
  ' "${LOCAL_SMOKE_JSONL}" >/dev/null; then
    local_jsonl_status="passed"
  else
    local_jsonl_status="failed"
    if [[ "${local_status}" == "passed" ]]; then
      promote_overall_status failed
    fi
  fi
else
  local_jsonl_status="${local_status}"
  printf '{"event":"ollama_local_missing_jsonl","status":"%s","git_revision":"%s"}\n' "${local_jsonl_status}" "${git_revision}" >"${LOCAL_SMOKE_JSONL}"
  if [[ "${local_status}" == "passed" ]]; then
    local_jsonl_status="failed"
    promote_overall_status failed
  fi
fi

local_non_mock_status="$(run_rch_step local_non_mock local-non-mock cargo test -p fcp-ollama --test local_non_mock -- --nocapture)"
if grep -a '"suite_class":"local_non_mock"' "${OUT_ROOT}/logs/local_non_mock.log" >"${LOCAL_NON_MOCK_JSONL}"; then
  if jq -s -e '
    length >= 4
    and all(.[]; .connector == "ollama")
    and all(.[]; .package == "fcp-ollama")
    and all(.[]; .suite_class == "local_non_mock")
    and all(.[]; .acceptance_suite_class == "local_non_mock")
    and all(.[]; .bead_id == "flywheel_connectors-222k2")
    and all(.[]; .fixture_mode == "raw_tcp_loopback_http")
    and all(.[]; .provider_class == "local_sufficient")
    and all(.[]; .details.result == "passed")
    and any(.[]; .case == "chat_embeddings_models_health" and .details.request_response_boundary.chat_completions.path == "/v1/chat/completions" and .details.request_response_boundary.embeddings.path == "/v1/embeddings" and .details.request_response_boundary.models_list.path == "/v1/models")
    and any(.[]; .case == "streaming_chat_sse" and .details.request_response_boundary.chat_completions_stream.transport == "sse")
    and any(.[]; .case == "authentication_error_mapping" and .details.error_mapping.fcp_error == "Unauthorized" and .details.error_mapping.secret_material_logged == false)
    and any(.[]; .case == "wrong_capability_no_egress" and .details.egress_gate.wrong_capability_rejected_before_http == true and .details.egress_gate.requests_sent == 0)
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
  printf '{"event":"ollama_local_non_mock_missing_jsonl","status":"%s","git_revision":"%s","log":"%s"}\n' "${local_non_mock_jsonl_status}" "${git_revision}" "${OUT_ROOT}/logs/local_non_mock.log" >"${LOCAL_NON_MOCK_JSONL}"
  if [[ "${local_non_mock_status}" == "passed" ]]; then
    local_non_mock_jsonl_status="failed"
    promote_overall_status failed
  fi
fi

if grep -R -E 'private jsonl prompt|private jsonl stream prompt|private jsonl embedding input|private loopback prompt|private streaming prompt|private auth prompt|ollama-local-non-mock-secret|Bearer ollama|ollama-proxy-key|bad Bearer|should-not-leak|must not reach loopback|http://localhost:11434/v1|127\.0\.0\.1:[0-9]+' "${OUT_ROOT}/evidence" >/dev/null 2>&1; then
  promote_overall_status failed
  echo "[ollama-verification] redaction check failed" >&2
fi

clippy_status="$(run_rch_step clippy clippy cargo clippy -p fcp-ollama --all-targets -- -D warnings)"

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-ollama",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "${SCRIPT_PATH}",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_prefix": "${TARGET_PREFIX}",
  "build_jobs": "${BUILD_JOBS}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "runner": "rch",
  "fixture_mode": "wiremock_and_raw_tcp_loopback_http",
  "local_mode": "OLLAMA_E2E_BASE_URL/OLLAMA_E2E_MODEL gated with structured skip",
  "redaction": "no bearer token, API key, prompt text, completion text, embedding input, embedding vector, loopback endpoint, or full base URL is emitted; JSONL carries base_url_class, model hashes, byte counts, status, retry decision, cleanup result, and skip reason"
}
EOF

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-ollama",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "runner": "rch",
  "observed_runners": {
    "manifest_check": "$(observed_runner "${OUT_ROOT}/logs/manifest_check.log")",
    "cargo_check": "$(observed_runner "${OUT_ROOT}/logs/cargo_check.log")",
    "format_check": "$(observed_runner "${OUT_ROOT}/logs/format_check.log")",
    "conformance": "$(observed_runner "${OUT_ROOT}/logs/conformance.log")",
    "loopback_jsonl": "$(observed_runner "${OUT_ROOT}/logs/loopback_jsonl.log")",
    "local_jsonl": "$(observed_runner "${OUT_ROOT}/logs/local_jsonl.log")",
    "local_non_mock": "$(observed_runner "${OUT_ROOT}/logs/local_non_mock.log")",
    "clippy": "$(observed_runner "${OUT_ROOT}/logs/clippy.log")"
  },
  "steps": {
    "manifest_check": "${manifest_status}",
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "conformance": "${conformance_status}",
    "loopback_jsonl": "${loopback_status}",
    "loopback_jsonl_validation": "${loopback_jsonl_status}",
    "local_jsonl": "${local_status}",
    "local_jsonl_validation": "${local_jsonl_status}",
    "local_non_mock": "${local_non_mock_status}",
    "local_non_mock_jsonl": "${local_non_mock_jsonl_status}",
    "clippy": "${clippy_status}"
  },
  "artifacts": {
    "loopback_jsonl": "${LOOPBACK_JSONL}",
    "local_jsonl": "${LOCAL_SMOKE_JSONL}",
    "local_non_mock_jsonl": "${LOCAL_NON_MOCK_JSONL}",
    "environment": "${OUT_ROOT}/environment.json"
  },
  "redaction_checks": {
    "evidence_dir": "${OVERALL_STATUS}"
  }
}
EOF

jq -c '.steps' "${OUT_ROOT}/summary.json"
echo "OLLAMA_LOOPBACK_JSONL=${LOOPBACK_JSONL}"
echo "OLLAMA_LOCAL_SMOKE_JSONL=${LOCAL_SMOKE_JSONL}"
echo "OLLAMA_LOCAL_NON_MOCK_JSONL=${LOCAL_NON_MOCK_JSONL}"
exit "${EXIT_CODE}"
