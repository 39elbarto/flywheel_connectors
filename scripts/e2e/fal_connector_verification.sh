#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/fal/${RUN_ID}}"
TARGET_DIR="${FCP_FAL_TARGET_DIR:-/tmp/fcp-fal-e2e}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
REMOTE_RUNNER="rch:remote-required"
export RCH_FORCE_REMOTE=1

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0

manifest_status="pending"
cargo_check_status="pending"
format_check_status="pending"
unit_test_status="pending"
jsonl_status="pending"
fixture_jsonl_status="pending"
clippy_status="pending"
manifest_check_runner=""

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
  if grep -Eq 'timeout: failed to execute process|RCH-E|remote required; refusing local fallback|rch command did not produce remote proof|\[RCH\] local|missing worker|No space left on device|dbus-1\.pc' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"

  echo "[fal-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
}

require_rch_remote_proof() {
  local name="$1"
  local log_path="$2"

  if grep -Fq "[RCH] remote" "${log_path}"; then
    return 0
  fi

  echo "[fal-verification] ${name}: rch command did not produce remote proof" >&2
  echo "rch command did not produce remote proof" >>"${log_path}"
  return 1
}

run_step() {
  local name="$1"
  shift
  if run_logged "${name}" "$@"; then
    if require_rch_remote_proof "${name}" "${OUT_ROOT}/logs/${name}.log"; then
      echo "passed"
    else
      promote_overall_status infra_blocked
      echo "infra_blocked"
    fi
  else
    local status
    status="$(classify_failure "${OUT_ROOT}/logs/${name}.log")"
    promote_overall_status "${status}"
    echo "${status}"
  fi
}

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

manifest_check_runner="${REMOTE_RUNNER}:cargo-run"
if run_logged \
  manifest_check \
  env RCH_VISIBILITY=verbose rch exec -- env \
    "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    cargo run -q -p fwc -- manifest fix connectors/fal/manifest.toml --check --json
then
  if require_rch_remote_proof manifest_check "${OUT_ROOT}/logs/manifest_check.log"; then
    manifest_status="passed"
  else
    manifest_status="infra_blocked"
  fi
  cp "${OUT_ROOT}/logs/manifest_check.log" "${OUT_ROOT}/evidence/manifest_check.json"
else
  manifest_status="$(classify_failure "${OUT_ROOT}/logs/manifest_check.log")"
  cat >"${OUT_ROOT}/evidence/manifest_check.json" <<EOF
{"status":"${manifest_status}","log":"${OUT_ROOT}/logs/manifest_check.log"}
EOF
fi
promote_overall_status "${manifest_status}"

cargo_check_status="$(run_step cargo_check env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo check -p fcp-fal --all-targets)"
format_check_status="$(run_step format_check env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo fmt --package fcp-fal --check)"
unit_test_status="$(run_step unit_tests env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-fal --all-targets -- --nocapture)"
jsonl_status="$(run_step queue_jsonl env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" FAL_E2E_GIT_REVISION="${git_revision}" cargo test -p fcp-fal --test e2e_jsonl fal_wiremock_and_live_skip_jsonl_matrix -- --nocapture)"
clippy_status="$(run_step clippy env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo clippy -p fcp-fal --all-targets --no-deps -- -D warnings)"

if grep -a '^FAL_E2E_JSONL ' "${OUT_ROOT}/logs/queue_jsonl.log" \
  | sed 's/^FAL_E2E_JSONL //' >"${OUT_ROOT}/evidence/queue_fixtures.jsonl"
then
  if [[ -s "${OUT_ROOT}/evidence/queue_fixtures.jsonl" ]]; then
    fixture_jsonl_status="passed"
  else
    fixture_jsonl_status="failed"
    cat >"${OUT_ROOT}/evidence/queue_fixtures.jsonl" <<EOF
{"event":"fal_fixture_missing_jsonl","status":"failed","reason":"queue test emitted no FAL_E2E_JSONL records","git_revision":"${git_revision}","mode":"wiremock","log":"${OUT_ROOT}/logs/queue_jsonl.log"}
EOF
    if [[ "${jsonl_status}" == "passed" ]]; then
      promote_overall_status failed
    fi
  fi
else
  fixture_jsonl_status="${jsonl_status}"
  cat >"${OUT_ROOT}/evidence/queue_fixtures.jsonl" <<EOF
{"event":"fal_fixture_missing_jsonl","status":"${fixture_jsonl_status}","reason":"queue test did not produce extractable FAL_E2E_JSONL records","git_revision":"${git_revision}","mode":"wiremock","log":"${OUT_ROOT}/logs/queue_jsonl.log"}
EOF
  if [[ "${jsonl_status}" == "passed" ]]; then
    fixture_jsonl_status="failed"
    promote_overall_status failed
  fi
fi

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-fal",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/fal_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_dir": "${TARGET_DIR}",
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "manifest_check_runner": "${manifest_check_runner}",
  "fixture_mode": "wiremock",
  "live_mode": "structured_skip_unless_run_manually_with_FAL_KEY",
  "redaction": "no Fal API key, prompt text, raw params, request URLs, or signed output URLs are emitted; logs carry route, request-id hash, URL host hash, content type, counts, status, and error class"
}
EOF

cat >"${OUT_ROOT}/replay.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="\${FCP_FAL_TARGET_DIR:-${TARGET_DIR}}"
REPO_TOOLCHAIN="\${REPO_TOOLCHAIN:-${REPO_TOOLCHAIN}}"
export RCH_FORCE_REMOTE=1
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo run -q -p fwc -- manifest fix connectors/fal/manifest.toml --check --json
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo check -p fcp-fal --all-targets
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo fmt --package fcp-fal --check
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-fal --all-targets -- --nocapture
git_revision="\$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" FAL_E2E_GIT_REVISION="\${git_revision}" cargo test -p fcp-fal --test e2e_jsonl fal_wiremock_and_live_skip_jsonl_matrix -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo clippy -p fcp-fal --all-targets --no-deps -- -D warnings
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-fal",
  "overall_status": "${OVERALL_STATUS}",
  "runner": "${REMOTE_RUNNER}",
  "artifacts_root": "${OUT_ROOT}",
  "steps": {
    "manifest_check": "${manifest_status}",
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "unit_tests": "${unit_test_status}",
    "queue_jsonl": "${jsonl_status}",
    "fixture_jsonl": "${fixture_jsonl_status}",
    "clippy": "${clippy_status}"
  },
  "artifacts": {
    "manifest_check": "${OUT_ROOT}/evidence/manifest_check.json",
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "unit_test_log": "${OUT_ROOT}/logs/unit_tests.log",
    "queue_jsonl_log": "${OUT_ROOT}/logs/queue_jsonl.log",
    "queue_jsonl": "${OUT_ROOT}/evidence/queue_fixtures.jsonl",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "Fal verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
