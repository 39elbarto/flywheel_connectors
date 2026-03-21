#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/microsoft365_connector/${RUN_ID}}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0

manifest_status="pending"
manifest_note=""
cargo_check_status="pending"
format_check_status="pending"
delegated_path_status="pending"
credential_injection_status="pending"
self_check_status="pending"
mail_evidence_status="pending"
calendar_evidence_status="pending"
integration_suite_status="pending"
clippy_status="pending"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"

  echo "[microsoft365-verification] ${name}: $*"
  (
    cd "${REPO_ROOT}"
    "$@"
  ) >"${log_path}" 2>&1
}

run_capture_stdout() {
  local name="$1"
  local stdout_path="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"

  echo "[microsoft365-verification] ${name}: $*"
  (
    cd "${REPO_ROOT}"
    "$@"
  ) >"${stdout_path}" 2>"${log_path}"
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

classify_manifest_failure() {
  local log_path="$1"
  if grep -Eq 'missing worker system package dbus-1\.pc|The system library `dbus-1` required|pkg-config --libs --cflags dbus-1' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

require_cmd rch

if run_capture_stdout \
  manifest_check \
  "${OUT_ROOT}/evidence/manifest_check.json" \
  rch exec -- cargo run -q -p fwc -- manifest fix connectors/microsoft365/manifest.toml --check --json
then
  manifest_status="passed"
else
  manifest_status="$(classify_manifest_failure "${OUT_ROOT}/logs/manifest_check.log")"
  if [[ "${manifest_status}" == "infra_blocked" ]]; then
    manifest_note="rch worker image missing dbus-1.pc while building fwc for manifest validation"
  else
    manifest_note="manifest validation command failed; inspect logs/manifest_check.log"
  fi
  cat > "${OUT_ROOT}/evidence/manifest_check.json" <<EOF
{
  "status": "${manifest_status}",
  "note": "${manifest_note}",
  "log": "${OUT_ROOT}/logs/manifest_check.log"
}
EOF
  promote_overall_status "${manifest_status}"
fi

if run_logged \
  cargo_check \
  rch exec -- cargo check -p fcp-microsoft365 --all-targets
then
  cargo_check_status="passed"
else
  cargo_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  format_check \
  rch exec -- cargo fmt -p fcp-microsoft365 -- --check
then
  format_check_status="passed"
else
  format_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  delegated_me_path_evidence \
  rch exec -- cargo test -p fcp-microsoft365 test_list_messages_explicit_user_keeps_users_prefix -- --nocapture
then
  delegated_path_status="passed"
else
  delegated_path_status="failed"
  promote_overall_status failed
fi

if run_logged \
  credential_injection_evidence \
  rch exec -- cargo test -p fcp-microsoft365 configure_credential_id_mode -- --nocapture
then
  credential_injection_status="passed"
else
  credential_injection_status="failed"
  promote_overall_status failed
fi

if run_logged \
  self_check_reason_evidence \
  rch exec -- cargo test -p fcp-microsoft365 test_self_check_classifies_invalid_token -- --nocapture
then
  self_check_status="passed"
else
  self_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  mail_evidence \
  rch exec -- cargo test -p fcp-microsoft365 --test integration mail_list_messages_happy_path -- --nocapture
then
  mail_evidence_status="passed"
else
  mail_evidence_status="failed"
  promote_overall_status failed
fi

if run_logged \
  calendar_evidence \
  rch exec -- cargo test -p fcp-microsoft365 --test integration calendar_list_events_happy_path -- --nocapture
then
  calendar_evidence_status="passed"
else
  calendar_evidence_status="failed"
  promote_overall_status failed
fi

if run_logged \
  integration_suite \
  rch exec -- cargo test -p fcp-microsoft365 --test integration -- --nocapture
then
  integration_suite_status="passed"
else
  integration_suite_status="failed"
  promote_overall_status failed
fi

if run_logged \
  clippy \
  rch exec -- cargo clippy -p fcp-microsoft365 --all-targets -- -D warnings
then
  clippy_status="passed"
else
  clippy_status="failed"
  promote_overall_status failed
fi

cat > "${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-microsoft365",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "steps": {
    "manifest_check": {
      "status": "${manifest_status}",
      "note": "${manifest_note}"
    },
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "delegated_me_path_evidence": "${delegated_path_status}",
    "credential_injection_evidence": "${credential_injection_status}",
    "self_check_reason_evidence": "${self_check_status}",
    "mail_evidence": "${mail_evidence_status}",
    "calendar_evidence": "${calendar_evidence_status}",
    "integration_suite": "${integration_suite_status}",
    "clippy": "${clippy_status}"
  },
  "artifacts": {
    "manifest_check": "${OUT_ROOT}/evidence/manifest_check.json",
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "delegated_me_path_evidence_log": "${OUT_ROOT}/logs/delegated_me_path_evidence.log",
    "credential_injection_evidence_log": "${OUT_ROOT}/logs/credential_injection_evidence.log",
    "self_check_reason_evidence_log": "${OUT_ROOT}/logs/self_check_reason_evidence.log",
    "mail_evidence_log": "${OUT_ROOT}/logs/mail_evidence.log",
    "calendar_evidence_log": "${OUT_ROOT}/logs/calendar_evidence.log",
    "integration_suite_log": "${OUT_ROOT}/logs/integration_suite.log",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log"
  }
}
EOF

echo "Microsoft 365 verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
