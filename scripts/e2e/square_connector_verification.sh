#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/square_connector/${RUN_ID}}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0

manifest_status="pending"
manifest_note=""
fmt_check_status="pending"
cargo_check_status="pending"
health_guidance_status="pending"
doctor_guidance_status="pending"
self_check_status="pending"
retryable_self_check_status="pending"
payments_pagination_status="pending"
catalog_filter_status="pending"
payment_create_status="pending"
compliance_status="pending"
integration_suite_status="pending"
crate_suite_status="pending"
clippy_status="pending"
manifest_check_runner=""
manifest_stdout_path="${OUT_ROOT}/evidence/manifest_check.command.json"

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

  echo "[square-verification] ${name}: $*"
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

  echo "[square-verification] ${name}: $*"
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

FWC_MANIFEST_BIN="${FWC_MANIFEST_BIN:-fwc}"
manifest_check_cmd=()
if command -v "${FWC_MANIFEST_BIN}" >/dev/null 2>&1; then
  manifest_check_runner="local:${FWC_MANIFEST_BIN}"
  manifest_check_cmd=(
    "${FWC_MANIFEST_BIN}"
    manifest
    fix
    connectors/square/manifest.toml
    --check
    --json
  )
else
  manifest_check_runner="rch:cargo-run"
  manifest_check_cmd=(
    rch
    exec
    --
    cargo
    run
    -q
    -p
    fwc
    --
    manifest
    fix
    connectors/square/manifest.toml
    --check
    --json
  )
fi

if run_capture_stdout \
  manifest_check \
  "${manifest_stdout_path}" \
  "${manifest_check_cmd[@]}"
then
  manifest_status="passed"
  cp "${manifest_stdout_path}" "${OUT_ROOT}/evidence/manifest_check.json"
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
  "command_output": "${manifest_stdout_path}",
  "log": "${OUT_ROOT}/logs/manifest_check.log"
}
EOF
  promote_overall_status "${manifest_status}"
fi

if run_logged \
  format_check \
  rch exec -- cargo fmt --manifest-path connectors/square/Cargo.toml --check
then
  fmt_check_status="passed"
else
  fmt_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  cargo_check \
  rch exec -- cargo check -p fcp-square --all-targets
then
  cargo_check_status="passed"
else
  cargo_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  health_guidance_evidence \
  rch exec -- cargo test -p fcp-square --test integration health_unconfigured_includes_guidance -- --nocapture
then
  health_guidance_status="passed"
else
  health_guidance_status="failed"
  promote_overall_status failed
fi

if run_logged \
  doctor_guidance_evidence \
  rch exec -- cargo test -p fcp-square --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture
then
  doctor_guidance_status="passed"
else
  doctor_guidance_status="failed"
  promote_overall_status failed
fi

if run_logged \
  self_check_evidence \
  rch exec -- cargo test -p fcp-square --test integration self_check_ready_with_mock_square_api_and_evidence -- --nocapture
then
  self_check_status="passed"
else
  self_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  retryable_self_check_evidence \
  rch exec -- cargo test -p fcp-square --test integration self_check_retryable_square_failure_reports_degraded -- --nocapture
then
  retryable_self_check_status="passed"
else
  retryable_self_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  payments_pagination_evidence \
  rch exec -- cargo test -p fcp-square --test integration invoke_payments_list_preserves_pagination_evidence -- --nocapture
then
  payments_pagination_status="passed"
else
  payments_pagination_status="failed"
  promote_overall_status failed
fi

if run_logged \
  catalog_filter_evidence \
  rch exec -- cargo test -p fcp-square --test integration invoke_catalog_list_preserves_filter_evidence -- --nocapture
then
  catalog_filter_status="passed"
else
  catalog_filter_status="failed"
  promote_overall_status failed
fi

if run_logged \
  payment_create_evidence \
  rch exec -- cargo test -p fcp-square --test integration invoke_payment_create_preserves_mutation_evidence -- --nocapture
then
  payment_create_status="passed"
else
  payment_create_status="failed"
  promote_overall_status failed
fi

if run_logged \
  compliance_evidence \
  rch exec -- cargo test -p fcp-square --test integration introspection_emits_v3_compliance_evidence -- --nocapture
then
  compliance_status="passed"
else
  compliance_status="failed"
  promote_overall_status failed
fi

if run_logged \
  integration_suite \
  rch exec -- cargo test -p fcp-square --test integration -- --nocapture
then
  integration_suite_status="passed"
else
  integration_suite_status="failed"
  promote_overall_status failed
fi

if run_logged \
  crate_suite \
  rch exec -- cargo test -p fcp-square -- --nocapture
then
  crate_suite_status="passed"
else
  crate_suite_status="failed"
  promote_overall_status failed
fi

if run_logged \
  clippy \
  rch exec -- cargo clippy -p fcp-square --all-targets -- -D warnings
then
  clippy_status="passed"
else
  clippy_status="failed"
  promote_overall_status failed
fi

cat > "${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-square",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/square_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "manifest_check_runner": "${manifest_check_runner}",
  "scope_note": "first slice covers merchant-scoped payments, refunds, orders, catalog reads, customer reads, locations, and readiness evidence"
}
EOF

cat > "${OUT_ROOT}/replay.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

FWC_MANIFEST_BIN="${FWC_MANIFEST_BIN:-fwc}"
if command -v "${FWC_MANIFEST_BIN}" >/dev/null 2>&1; then
  "${FWC_MANIFEST_BIN}" manifest fix connectors/square/manifest.toml --check --json
else
  rch exec -- cargo run -q -p fwc -- manifest fix connectors/square/manifest.toml --check --json
fi
rch exec -- cargo fmt --manifest-path connectors/square/Cargo.toml --check
rch exec -- cargo check -p fcp-square --all-targets
rch exec -- cargo test -p fcp-square --test integration health_unconfigured_includes_guidance -- --nocapture
rch exec -- cargo test -p fcp-square --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture
rch exec -- cargo test -p fcp-square --test integration self_check_ready_with_mock_square_api_and_evidence -- --nocapture
rch exec -- cargo test -p fcp-square --test integration self_check_retryable_square_failure_reports_degraded -- --nocapture
rch exec -- cargo test -p fcp-square --test integration invoke_payments_list_preserves_pagination_evidence -- --nocapture
rch exec -- cargo test -p fcp-square --test integration invoke_catalog_list_preserves_filter_evidence -- --nocapture
rch exec -- cargo test -p fcp-square --test integration invoke_payment_create_preserves_mutation_evidence -- --nocapture
rch exec -- cargo test -p fcp-square --test integration introspection_emits_v3_compliance_evidence -- --nocapture
rch exec -- cargo test -p fcp-square --test integration -- --nocapture
rch exec -- cargo test -p fcp-square -- --nocapture
rch exec -- cargo clippy -p fcp-square --all-targets -- -D warnings
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat > "${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-square",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "steps": {
    "manifest_check": {
      "status": "${manifest_status}",
      "note": "${manifest_note}"
    },
    "format_check": "${fmt_check_status}",
    "cargo_check": "${cargo_check_status}",
    "health_guidance_evidence": "${health_guidance_status}",
    "doctor_guidance_evidence": "${doctor_guidance_status}",
    "self_check_evidence": "${self_check_status}",
    "retryable_self_check_evidence": "${retryable_self_check_status}",
    "payments_pagination_evidence": "${payments_pagination_status}",
    "catalog_filter_evidence": "${catalog_filter_status}",
    "payment_create_evidence": "${payment_create_status}",
    "compliance_evidence": "${compliance_status}",
    "integration_suite": "${integration_suite_status}",
    "crate_suite": "${crate_suite_status}",
    "clippy": "${clippy_status}"
  },
  "artifacts": {
    "manifest_check": "${OUT_ROOT}/evidence/manifest_check.json",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "health_guidance_evidence_log": "${OUT_ROOT}/logs/health_guidance_evidence.log",
    "doctor_guidance_evidence_log": "${OUT_ROOT}/logs/doctor_guidance_evidence.log",
    "self_check_evidence_log": "${OUT_ROOT}/logs/self_check_evidence.log",
    "retryable_self_check_evidence_log": "${OUT_ROOT}/logs/retryable_self_check_evidence.log",
    "payments_pagination_evidence_log": "${OUT_ROOT}/logs/payments_pagination_evidence.log",
    "catalog_filter_evidence_log": "${OUT_ROOT}/logs/catalog_filter_evidence.log",
    "payment_create_evidence_log": "${OUT_ROOT}/logs/payment_create_evidence.log",
    "compliance_evidence_log": "${OUT_ROOT}/logs/compliance_evidence.log",
    "integration_suite_log": "${OUT_ROOT}/logs/integration_suite.log",
    "crate_suite_log": "${OUT_ROOT}/logs/crate_suite.log",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "Square verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
