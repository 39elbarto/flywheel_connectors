#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/email_generic_connector/${RUN_ID}}"
TARGET_DIR="${EMAIL_GENERIC_CARGO_TARGET_DIR:-/tmp/fcp-email-generic-e2e-target}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0
LAST_STEP_STATUS="not_run"

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
  if [[ ! -f "${log_path}" ]]; then
    echo "infra_blocked"
    return
  fi
  if grep -Eq 'No space left on device|RCH-E|remote required; refusing local fallback|no workers passed health thresholds|no worker assigned|connection reset by peer|missing worker system package|failed to execute process|failed to get successful HTTP response from `https://index\.crates\.io/|unable to update registry `crates-io`|spurious network error' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"

  echo "[email-generic-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
}

run_step() {
  local name="$1"
  shift
  if run_logged "${name}" "$@"; then
    LAST_STEP_STATUS="passed"
  else
    local status
    status="$(classify_failure "${OUT_ROOT}/logs/${name}.log")"
    promote_status "${status}"
    LAST_STEP_STATUS="${status}"
  fi
}

run_rch_cargo_step() {
  local name="$1"
  shift
  run_step "${name}" env \
    RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}" \
    RCH_BUILD_SLOTS="${RCH_BUILD_SLOTS:-2}" \
    RCH_TEST_SLOTS="${RCH_TEST_SLOTS:-2}" \
    RCH_CHECK_SLOTS="${RCH_CHECK_SLOTS:-1}" \
    rch exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    "$@"
  if [[ "${LAST_STEP_STATUS}" == "passed" ]] && grep -Eq 'exec called with non-compilation command|\[RCH\] local' "${OUT_ROOT}/logs/${name}.log"; then
    promote_status infra_blocked
    LAST_STEP_STATUS="infra_blocked"
  fi
}

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
fixture_jsonl="${OUT_ROOT}/evidence/integration_fixture.jsonl"
fixture_stdout_jsonl="${OUT_ROOT}/evidence/integration_fixture_stdout.jsonl"
rch_check_json="${OUT_ROOT}/logs/rch_check.json"
rch_diagnose_fmt_json="${OUT_ROOT}/logs/rch_diagnose_format_check.json"
rch_diagnose_integration_json="${OUT_ROOT}/logs/rch_diagnose_integration_fixture.json"
rch_diagnose_clippy_json="${OUT_ROOT}/logs/rch_diagnose_clippy.json"

(
  cd "${REPO_ROOT}" || exit
  rch check --json >"${rch_check_json}"
) 2>"${OUT_ROOT}/logs/rch_check.stderr" || true
(
  cd "${REPO_ROOT}" || exit
  rch diagnose --json -- cargo fmt --manifest-path connectors/email-generic/Cargo.toml --check >"${rch_diagnose_fmt_json}"
) 2>"${OUT_ROOT}/logs/rch_diagnose_format_check.stderr" || true
(
  cd "${REPO_ROOT}" || exit
  rch diagnose --json -- cargo test -p fcp-email-generic --test integration -- --nocapture >"${rch_diagnose_integration_json}"
) 2>"${OUT_ROOT}/logs/rch_diagnose_integration_fixture.stderr" || true
(
  cd "${REPO_ROOT}" || exit
  rch diagnose --json -- cargo clippy -p fcp-email-generic --all-targets -- -D warnings >"${rch_diagnose_clippy_json}"
) 2>"${OUT_ROOT}/logs/rch_diagnose_clippy.stderr" || true

run_rch_cargo_step format_check cargo fmt --manifest-path connectors/email-generic/Cargo.toml --check
format_check_status="${LAST_STEP_STATUS}"

run_rch_cargo_step integration_fixture \
  EMAIL_GENERIC_FIXTURE_JSONL=1 \
  EMAIL_GENERIC_FIXTURE_JSONL_ARTIFACT="${fixture_jsonl}" \
  cargo test -p fcp-email-generic --test integration -- --nocapture
integration_fixture_status="${LAST_STEP_STATUS}"

grep -a '^EMAIL_GENERIC_FIXTURE_JSONL ' "${OUT_ROOT}/logs/integration_fixture.log" \
  | sed 's/^EMAIL_GENERIC_FIXTURE_JSONL //' >"${fixture_stdout_jsonl}" || true
if [[ -s "${fixture_stdout_jsonl}" ]]; then
  cp "${fixture_stdout_jsonl}" "${fixture_jsonl}"
else
  if [[ "${integration_fixture_status}" == "infra_blocked" ]]; then
    result="skip"
    reason="rch infrastructure blocked integration fixture before JSONL emission"
  else
    result="fail"
    reason="integration fixture did not emit EMAIL_GENERIC_FIXTURE_JSONL records"
    promote_status failed
  fi
  printf '{"log_version":"v1","connector_id":"fcp.email-generic","event":"email_generic_fixture_jsonl_missing","result":"%s","git_revision":"%s","artifact_path":"%s","skip_reason":"%s"}\n' "${result}" "${git_revision}" "${fixture_jsonl}" "${reason}" >"${fixture_jsonl}"
fi

run_rch_cargo_step local_non_mock \
  cargo test -p fcp-email-generic --test local_non_mock -- --nocapture
local_non_mock_status="${LAST_STEP_STATUS}"

run_rch_cargo_step conformance_contract \
  cargo test -p fcp-email-generic --test conformance_contract -- --nocapture
conformance_contract_status="${LAST_STEP_STATUS}"

run_rch_cargo_step clippy \
  cargo clippy -p fcp-email-generic --all-targets -- -D warnings
clippy_status="${LAST_STEP_STATUS}"

run_step diff_check git diff --check -- \
  connectors/email-generic/tests/integration.rs \
  connectors/email-generic/tests/conformance_contract.rs \
  connectors/email-generic/README.md \
  connectors/email-generic/manifest.toml \
  scripts/e2e/email_generic_connector_verification.sh
diff_check_status="${LAST_STEP_STATUS}"

if grep -R -E 'secret|user@example\.com|human@example\.com|outsider@example\.net|noreply@example\.com|Deploy ready|outside sender|robot notice|cGxhbg==|plan\.pdf|Green' "${OUT_ROOT}/evidence" >/dev/null 2>&1; then
  OVERALL_STATUS="failed"
  EXIT_CODE=1
  echo "[email-generic-verification] redaction check failed" >&2
fi

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-email-generic",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/email_generic_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_dir": "${TARGET_DIR}",
  "fixture_mode": "no-live-credential raw TCP IMAP/SMTP loopback through connector-local tests",
  "redaction": "evidence carries hashes, enum decisions, byte counts, lifecycle phases, retry decisions, error mappings, artifact paths, cleanup result, and skip reason; raw senders, subjects, message bodies, attachment bytes, credentials, and provider payloads are forbidden"
}
EOF

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-email-generic",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "steps": {
    "format_check": "${format_check_status}",
    "integration_fixture": "${integration_fixture_status}",
    "local_non_mock": "${local_non_mock_status}",
    "conformance_contract": "${conformance_contract_status}",
    "clippy": "${clippy_status}",
    "diff_check": "${diff_check_status}"
  },
  "artifacts": {
    "integration_fixture_jsonl": "${fixture_jsonl}",
    "integration_fixture_stdout_jsonl": "${fixture_stdout_jsonl}",
    "environment": "${OUT_ROOT}/environment.json",
    "rch_check": "${rch_check_json}",
    "rch_diagnose_format_check": "${rch_diagnose_fmt_json}",
    "rch_diagnose_integration_fixture": "${rch_diagnose_integration_json}",
    "rch_diagnose_clippy": "${rch_diagnose_clippy_json}"
  }
}
EOF

echo "Email generic verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
