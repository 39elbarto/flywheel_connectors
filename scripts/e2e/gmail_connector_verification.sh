#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-/tmp/fcp-gmail-e2e/${RUN_ID}}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-gmail-e2e-target}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
REMOTE_RUNNER="rch:remote-required"
export RCH_FORCE_REMOTE=1

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
  # shellcheck disable=SC2016
  if grep -Eq 'No space left on device|timeout: failed to execute process|RCH-E|no admissible workers|remote required; refusing local fallback|rch command did not produce remote proof|\[RCH\] local|no worker assigned|connection reset by peer|missing worker system package|failed to execute process|failed to get successful HTTP response from `https://index\.crates\.io/|Backend unavailable|unable to update registry `crates-io`|spurious network error' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"

  echo "[gmail-verification] ${name}: $*" >&2
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

run_absence_scan() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"

  echo "[gmail-verification] ${name}: $*" >&2
  if (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1; then
    promote_status failed
    LAST_STEP_STATUS="failed"
  else
    LAST_STEP_STATUS="passed"
  fi
}

rch_remote_summary_present() {
  local log_path="$1"
  grep -Fq "[RCH] remote" "${log_path}"
}

run_rch_cargo_step() {
  local name="$1"
  shift
  run_step "${name}" env \
    RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}" \
    RCH_FORCE_REMOTE=1 \
    RCH_VISIBILITY=verbose \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    "$@"
  if [[ "${LAST_STEP_STATUS}" == "passed" ]]; then
    if ! rch_remote_summary_present "${OUT_ROOT}/logs/${name}.log"; then
      echo "[gmail-verification] ${name}: rch command did not produce remote proof" >&2
      echo "rch command did not produce remote proof" >>"${OUT_ROOT}/logs/${name}.log"
      promote_status infra_blocked
      LAST_STEP_STATUS="infra_blocked"
    fi
  fi
}

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

run_step graduation_gauntlet scripts/graduation/run_gauntlet.sh connectors/gmail
graduation_gauntlet_status="${LAST_STEP_STATUS}"
run_rch_cargo_step format_check cargo fmt -p fcp-gmail -- --check
format_check_status="${LAST_STEP_STATUS}"
run_rch_cargo_step local_non_mock_acceptance \
  cargo test -p fcp-gmail --test local_non_mock -- --nocapture
local_non_mock_status="${LAST_STEP_STATUS}"
run_rch_cargo_step conformance_contract \
  cargo test -p fcp-gmail --test conformance_contract -- --nocapture
conformance_contract_status="${LAST_STEP_STATUS}"
run_rch_cargo_step clippy \
  cargo clippy -p fcp-gmail --test local_non_mock --test conformance_contract --no-deps -- -D warnings
clippy_status="${LAST_STEP_STATUS}"
run_step diff_check git diff --check -- connectors/gmail/Cargo.toml connectors/gmail/manifest.toml connectors/gmail/src/connector.rs connectors/gmail/tests/local_non_mock.rs connectors/gmail/README.md scripts/e2e/gmail_connector_verification.sh
diff_check_status="${LAST_STEP_STATUS}"
run_absence_scan readme_legacy_branch_word_scan rg -n '\bmaster\b' connectors/gmail/README.md
readme_legacy_branch_word_scan_status="${LAST_STEP_STATUS}"
run_absence_scan redaction_scan rg -n 'ya29\.|refresh_token|client_secret|Authorization: Bearer|loopback@example\.invalid|Local acceptance snippet|msg-local-acceptance|thread-local-acceptance' "${OUT_ROOT}/logs"
redaction_scan_status="${LAST_STEP_STATUS}"

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-gmail",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/gmail_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_dir": "${TARGET_DIR}",
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "fixture_mode": "no-live-credential Gmail REST loopback",
  "redaction": "no access token, refresh token, credential secret, email address, message id, thread id, subject, snippet, body text, or provider payload is emitted; evidence carries operation IDs, path classes, counts, and outcome enums"
}
EOF

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-gmail",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "steps": {
    "graduation_gauntlet": "${graduation_gauntlet_status}",
    "format_check": "${format_check_status}",
    "local_non_mock_acceptance": "${local_non_mock_status}",
    "conformance_contract": "${conformance_contract_status}",
    "clippy": "${clippy_status}",
    "diff_check": "${diff_check_status}",
    "readme_legacy_branch_word_scan": "${readme_legacy_branch_word_scan_status}",
    "redaction_scan": "${redaction_scan_status}"
  },
  "artifacts": {
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh",
    "logs": "${OUT_ROOT}/logs"
  }
}
EOF

cat >"${OUT_ROOT}/replay.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

export RCH_FORCE_REMOTE=1
REPO_TOOLCHAIN="\${REPO_TOOLCHAIN:-${REPO_TOOLCHAIN}}"
TARGET_DIR="\${CARGO_TARGET_DIR:-${TARGET_DIR}}"

cd "${REPO_ROOT}"
scripts/graduation/run_gauntlet.sh connectors/gmail
env RCH_REQUIRE_REMOTE="\${RCH_REQUIRE_REMOTE:-1}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo fmt -p fcp-gmail -- --check
env RCH_REQUIRE_REMOTE="\${RCH_REQUIRE_REMOTE:-1}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo test -p fcp-gmail --test local_non_mock -- --nocapture
env RCH_REQUIRE_REMOTE="\${RCH_REQUIRE_REMOTE:-1}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo test -p fcp-gmail --test conformance_contract -- --nocapture
env RCH_REQUIRE_REMOTE="\${RCH_REQUIRE_REMOTE:-1}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo clippy -p fcp-gmail --test local_non_mock --test conformance_contract --no-deps -- -D warnings
git diff --check -- connectors/gmail/Cargo.toml connectors/gmail/manifest.toml connectors/gmail/src/connector.rs connectors/gmail/tests/local_non_mock.rs connectors/gmail/README.md scripts/e2e/gmail_connector_verification.sh
! rg -n '\\bmaster\\b' connectors/gmail/README.md
! rg -n 'ya29\\.|refresh_token|client_secret|Authorization: Bearer|loopback@example\\.invalid|Local acceptance snippet|msg-local-acceptance|thread-local-acceptance' "${OUT_ROOT}/logs"
EOF
chmod +x "${OUT_ROOT}/replay.sh"

echo "Gmail verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
