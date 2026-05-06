#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-/tmp/fcp-ollama-e2e/${RUN_ID}}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-ollama-e2e-target}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0

promote_status() {
  local status="$1"
  case "${status}" in
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
  if grep -Eq 'No space left on device|timeout: failed to execute process|RCH-E|connection reset by peer' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"

  echo "[ollama-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
}

run_step() {
  local name="$1"
  shift
  if run_logged "${name}" "$@"; then
    echo "passed"
  else
    local status
    status="$(classify_failure "${OUT_ROOT}/logs/${name}.log")"
    promote_status "${status}"
    echo "${status}"
  fi
}

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

cargo_check_status="$(run_step cargo_check env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo check -p fcp-ollama --all-targets)"
format_check_status="$(run_step format_check env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo fmt --package fcp-ollama --check)"
clippy_status="$(run_step clippy env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo clippy -p fcp-ollama --all-targets -- -D warnings)"
loopback_status="$(run_step loopback_jsonl env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 OLLAMA_E2E_GIT_REVISION="${git_revision}" cargo test -p fcp-ollama --test integration ollama_loopback_e2e_jsonl_matrix -- --nocapture)"
local_status="$(run_step local_jsonl env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 OLLAMA_E2E_GIT_REVISION="${git_revision}" cargo test -p fcp-ollama --test integration ollama_local_smoke_or_structured_skip_jsonl -- --nocapture)"

if grep -a '^OLLAMA_E2E_JSONL ' "${OUT_ROOT}/logs/loopback_jsonl.log" \
  | sed 's/^OLLAMA_E2E_JSONL //' >"${OUT_ROOT}/evidence/loopback_fixtures.jsonl"; then
  if [[ ! -s "${OUT_ROOT}/evidence/loopback_fixtures.jsonl" ]]; then
    promote_status failed
    printf '{"event":"ollama_fixture_missing_jsonl","status":"failed","git_revision":"%s"}\n' "${git_revision}" >"${OUT_ROOT}/evidence/loopback_fixtures.jsonl"
  fi
fi

if grep -a '^OLLAMA_E2E_JSONL ' "${OUT_ROOT}/logs/local_jsonl.log" \
  | sed 's/^OLLAMA_E2E_JSONL //' >"${OUT_ROOT}/evidence/local_smoke.jsonl"; then
  if [[ ! -s "${OUT_ROOT}/evidence/local_smoke.jsonl" ]]; then
    promote_status failed
    printf '{"event":"ollama_local_missing_jsonl","status":"failed","git_revision":"%s"}\n' "${git_revision}" >"${OUT_ROOT}/evidence/local_smoke.jsonl"
  fi
fi

if grep -R -E 'private jsonl prompt|private jsonl stream prompt|private jsonl embedding input|Bearer ollama|ollama-proxy-key|http://localhost:11434/v1' "${OUT_ROOT}/evidence" >/dev/null 2>&1; then
  OVERALL_STATUS="failed"
  EXIT_CODE=1
  echo "[ollama-verification] redaction check failed" >&2
fi

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-ollama",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/ollama_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_dir": "${TARGET_DIR}",
  "fixture_mode": "wiremock",
  "local_mode": "OLLAMA_E2E_BASE_URL/OLLAMA_E2E_MODEL gated with structured skip",
  "redaction": "no bearer token, prompt text, completion text, embedding input, embedding vector, or full base URL is emitted; JSONL carries base_url_class, model hashes, byte counts, status, retry decision, cleanup result, and skip reason"
}
EOF

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-ollama",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "steps": {
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "clippy": "${clippy_status}",
    "loopback_jsonl": "${loopback_status}",
    "local_jsonl": "${local_status}"
  },
  "artifacts": {
    "loopback_jsonl": "${OUT_ROOT}/evidence/loopback_fixtures.jsonl",
    "local_jsonl": "${OUT_ROOT}/evidence/local_smoke.jsonl",
    "environment": "${OUT_ROOT}/environment.json"
  }
}
EOF

echo "Ollama verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
