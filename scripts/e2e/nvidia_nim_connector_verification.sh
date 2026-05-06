#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-/tmp/fcp-nvidia-nim-e2e/${RUN_ID}}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-nvidia-nim-e2e-target}"

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

  echo "[nvidia-nim-verification] ${name}: $*" >&2
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

cargo_check_status="$(run_step cargo_check env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo check -p fcp-nvidia-nim --all-targets)"
format_check_status="$(run_step format_check env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo fmt --package fcp-nvidia-nim --check)"
clippy_status="$(run_step clippy env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo clippy -p fcp-nvidia-nim --all-targets -- -D warnings)"
unit_tests_status="$(run_step unit_tests env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo test -p fcp-nvidia-nim --lib -- --nocapture)"
integration_tests_status="$(run_step integration_tests env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo test -p fcp-nvidia-nim --test integration -- --nocapture)"
loopback_status="$(run_step loopback_jsonl env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 NVIDIA_NIM_E2E_GIT_REVISION="${git_revision}" cargo test -p fcp-nvidia-nim --test integration nvidia_nim_loopback_e2e_jsonl_matrix -- --nocapture)"
hosted_status="$(run_step hosted_jsonl env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 NVIDIA_NIM_E2E_GIT_REVISION="${git_revision}" cargo test -p fcp-nvidia-nim --test integration nvidia_nim_hosted_smoke_or_structured_skip_jsonl -- --nocapture)"

if grep -a '^NVIDIA_NIM_E2E_JSONL ' "${OUT_ROOT}/logs/loopback_jsonl.log" \
  | sed 's/^NVIDIA_NIM_E2E_JSONL //' >"${OUT_ROOT}/evidence/loopback_fixtures.jsonl"; then
  if [[ ! -s "${OUT_ROOT}/evidence/loopback_fixtures.jsonl" ]]; then
    promote_status failed
    printf '{"event":"nvidia_nim_fixture_missing_jsonl","status":"failed","git_revision":"%s"}\n' "${git_revision}" >"${OUT_ROOT}/evidence/loopback_fixtures.jsonl"
  fi
fi

if grep -a '^NVIDIA_NIM_E2E_JSONL ' "${OUT_ROOT}/logs/hosted_jsonl.log" \
  | sed 's/^NVIDIA_NIM_E2E_JSONL //' >"${OUT_ROOT}/evidence/hosted_smoke.jsonl"; then
  if [[ ! -s "${OUT_ROOT}/evidence/hosted_smoke.jsonl" ]]; then
    promote_status failed
    printf '{"event":"nvidia_nim_hosted_missing_jsonl","status":"failed","git_revision":"%s"}\n' "${git_revision}" >"${OUT_ROOT}/evidence/hosted_smoke.jsonl"
  fi
fi

if grep -R -E 'private jsonl prompt|private jsonl stream prompt|private jsonl embedding input|private jsonl rerank query|private jsonl rerank passage|Bearer nim|nim-key|NVIDIA_API_KEY|integrate.api.nvidia.com/v1|ai.api.nvidia.com/v1' "${OUT_ROOT}/evidence" >/dev/null 2>&1; then
  OVERALL_STATUS="failed"
  EXIT_CODE=1
  echo "[nvidia-nim-verification] redaction check failed" >&2
fi

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-nvidia-nim",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/nvidia_nim_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_dir": "${TARGET_DIR}",
  "fixture_mode": "wiremock",
  "hosted_mode": "NVIDIA_API_KEY gated with structured skip",
  "redaction": "no bearer token, prompt text, completion text, embedding input, embedding vector, rerank query, rerank passage, or full hosted/self-hosted URL is emitted; JSONL carries deployment mode, endpoint class, model hashes, byte counts, ranking counts, status, retry decision, cleanup result, and skip reason"
}
EOF

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-nvidia-nim",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "steps": {
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "clippy": "${clippy_status}",
    "unit_tests": "${unit_tests_status}",
    "integration_tests": "${integration_tests_status}",
    "loopback_jsonl": "${loopback_status}",
    "hosted_jsonl": "${hosted_status}"
  },
  "artifacts": {
    "loopback_jsonl": "${OUT_ROOT}/evidence/loopback_fixtures.jsonl",
    "hosted_jsonl": "${OUT_ROOT}/evidence/hosted_smoke.jsonl",
    "environment": "${OUT_ROOT}/environment.json"
  }
}
EOF

echo "NVIDIA NIM verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
