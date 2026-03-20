#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/cloudflare_connector/${RUN_ID}}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0

manifest_status="pending"
manifest_note=""
cargo_check_status="pending"
format_check_status="pending"
doctor_self_check_status="pending"
risky_mutation_status="pending"
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

  echo "[cloudflare-verification] ${name}: $*"
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

  echo "[cloudflare-verification] ${name}: $*"
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
  rch exec -- cargo run -q -p fwc -- manifest fix connectors/cloudflare/manifest.toml --check --json
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
  rch exec -- cargo check -p fcp-cloudflare
then
  cargo_check_status="passed"
else
  cargo_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  format_check \
  rch exec -- cargo fmt --check -p fcp-cloudflare
then
  format_check_status="passed"
else
  format_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  doctor_self_check_evidence \
  rch exec -- cargo test -p fcp-cloudflare --test integration self_check_ready_with_active_token_and_evidence -- --nocapture
then
  doctor_self_check_status="passed"
else
  doctor_self_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  risky_mutation_evidence \
  rch exec -- cargo test -p fcp-cloudflare --test integration invoke_risky_dns_delete_preserves_artifact_evidence -- --nocapture
then
  risky_mutation_status="passed"
else
  risky_mutation_status="failed"
  promote_overall_status failed
fi

if run_logged \
  integration_suite \
  rch exec -- cargo test -p fcp-cloudflare --test integration -- --nocapture
then
  integration_suite_status="passed"
else
  integration_suite_status="failed"
  promote_overall_status failed
fi

if run_logged \
  clippy \
  rch exec -- cargo clippy -p fcp-cloudflare --all-targets -- -D warnings
then
  clippy_status="passed"
else
  clippy_status="failed"
  promote_overall_status failed
fi

cat > "${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-cloudflare",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "steps": {
    "manifest_check": {
      "status": "${manifest_status}",
      "note": "${manifest_note}"
    },
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "doctor_self_check_evidence": "${doctor_self_check_status}",
    "risky_mutation_evidence": "${risky_mutation_status}",
    "integration_suite": "${integration_suite_status}",
    "clippy": "${clippy_status}"
  },
  "artifacts": {
    "manifest_check": "${OUT_ROOT}/evidence/manifest_check.json",
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "doctor_self_check_evidence_log": "${OUT_ROOT}/logs/doctor_self_check_evidence.log",
    "risky_mutation_evidence_log": "${OUT_ROOT}/logs/risky_mutation_evidence.log",
    "integration_suite_log": "${OUT_ROOT}/logs/integration_suite.log",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log"
  }
}
EOF

echo "Cloudflare verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
