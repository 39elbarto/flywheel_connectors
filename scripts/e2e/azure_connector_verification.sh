#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/azure_connector/${RUN_ID}}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0

manifest_status="pending"
manifest_note=""
cargo_check_status="pending"
format_check_status="pending"
health_guidance_status="pending"
doctor_guidance_status="pending"
doctor_self_check_status="pending"
retryable_self_check_status="pending"
blob_put_status="pending"
keyvault_set_secret_status="pending"
compliance_status="pending"
integration_suite_status="pending"
clippy_status="pending"
manifest_check_runner=""

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

  echo "[azure-verification] ${name}: $*"
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

  echo "[azure-verification] ${name}: $*"
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
    connectors/azure/manifest.toml
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
    connectors/azure/manifest.toml
    --check
    --json
  )
fi

if run_capture_stdout \
  manifest_check \
  "${OUT_ROOT}/evidence/manifest_check.json" \
  "${manifest_check_cmd[@]}"
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
  rch exec -- cargo check -p fcp-azure --all-targets
then
  cargo_check_status="passed"
else
  cargo_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  format_check \
  rch exec -- cargo fmt -p fcp-azure -- --check
then
  format_check_status="passed"
else
  format_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  health_guidance_evidence \
  rch exec -- cargo test -p fcp-azure --test integration lifecycle_health_unconfigured_includes_guidance -- --nocapture
then
  health_guidance_status="passed"
else
  health_guidance_status="failed"
  promote_overall_status failed
fi

if run_logged \
  doctor_guidance_evidence \
  rch exec -- cargo test -p fcp-azure --test integration doctor_unconfigured_reports_remediation -- --nocapture
then
  doctor_guidance_status="passed"
else
  doctor_guidance_status="failed"
  promote_overall_status failed
fi

if run_logged \
  doctor_self_check_evidence \
  rch exec -- cargo test -p fcp-azure --test integration self_check_ready_with_local_management_override_and_evidence -- --nocapture
then
  doctor_self_check_status="passed"
else
  doctor_self_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  retryable_self_check_evidence \
  rch exec -- cargo test -p fcp-azure --test integration self_check_retryable_management_failure_reports_degraded -- --nocapture
then
  retryable_self_check_status="passed"
else
  retryable_self_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  blob_put_evidence \
  rch exec -- cargo test -p fcp-azure --test integration invoke_blob_put_preserves_artifact_evidence -- --nocapture
then
  blob_put_status="passed"
else
  blob_put_status="failed"
  promote_overall_status failed
fi

if run_logged \
  keyvault_set_secret_evidence \
  rch exec -- cargo test -p fcp-azure --test integration invoke_keyvault_set_secret_preserves_artifact_evidence -- --nocapture
then
  keyvault_set_secret_status="passed"
else
  keyvault_set_secret_status="failed"
  promote_overall_status failed
fi

if run_logged \
  compliance_evidence \
  rch exec -- cargo test -p fcp-azure --test integration introspection_emits_v3_compliance_evidence -- --nocapture
then
  compliance_status="passed"
else
  compliance_status="failed"
  promote_overall_status failed
fi

if run_logged \
  integration_suite \
  rch exec -- cargo test -p fcp-azure --test integration -- --nocapture
then
  integration_suite_status="passed"
else
  integration_suite_status="failed"
  promote_overall_status failed
fi

if run_logged \
  clippy \
  rch exec -- cargo clippy -p fcp-azure --all-targets -- -D warnings
then
  clippy_status="passed"
else
  clippy_status="failed"
  promote_overall_status failed
fi

cat > "${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-azure",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/azure_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "manifest_check_runner": "${manifest_check_runner}"
}
EOF

cat > "${OUT_ROOT}/replay.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

FWC_MANIFEST_BIN="${FWC_MANIFEST_BIN:-fwc}"
if command -v "${FWC_MANIFEST_BIN}" >/dev/null 2>&1; then
  "${FWC_MANIFEST_BIN}" manifest fix connectors/azure/manifest.toml --check --json
else
  rch exec -- cargo run -q -p fwc -- manifest fix connectors/azure/manifest.toml --check --json
fi
rch exec -- cargo check -p fcp-azure --all-targets
rch exec -- cargo fmt -p fcp-azure -- --check
rch exec -- cargo test -p fcp-azure --test integration lifecycle_health_unconfigured_includes_guidance -- --nocapture
rch exec -- cargo test -p fcp-azure --test integration doctor_unconfigured_reports_remediation -- --nocapture
rch exec -- cargo test -p fcp-azure --test integration self_check_ready_with_local_management_override_and_evidence -- --nocapture
rch exec -- cargo test -p fcp-azure --test integration self_check_retryable_management_failure_reports_degraded -- --nocapture
rch exec -- cargo test -p fcp-azure --test integration invoke_blob_put_preserves_artifact_evidence -- --nocapture
rch exec -- cargo test -p fcp-azure --test integration invoke_keyvault_set_secret_preserves_artifact_evidence -- --nocapture
rch exec -- cargo test -p fcp-azure --test integration introspection_emits_v3_compliance_evidence -- --nocapture
rch exec -- cargo test -p fcp-azure --test integration -- --nocapture
rch exec -- cargo clippy -p fcp-azure --all-targets -- -D warnings
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat > "${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-azure",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "steps": {
    "manifest_check": {
      "status": "${manifest_status}",
      "note": "${manifest_note}"
    },
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "health_guidance_evidence": "${health_guidance_status}",
    "doctor_guidance_evidence": "${doctor_guidance_status}",
    "doctor_self_check_evidence": "${doctor_self_check_status}",
    "retryable_self_check_evidence": "${retryable_self_check_status}",
    "blob_put_evidence": "${blob_put_status}",
    "keyvault_set_secret_evidence": "${keyvault_set_secret_status}",
    "compliance_evidence": "${compliance_status}",
    "integration_suite": "${integration_suite_status}",
    "clippy": "${clippy_status}"
  },
  "artifacts": {
    "manifest_check": "${OUT_ROOT}/evidence/manifest_check.json",
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "health_guidance_evidence_log": "${OUT_ROOT}/logs/health_guidance_evidence.log",
    "doctor_guidance_evidence_log": "${OUT_ROOT}/logs/doctor_guidance_evidence.log",
    "doctor_self_check_evidence_log": "${OUT_ROOT}/logs/doctor_self_check_evidence.log",
    "retryable_self_check_evidence_log": "${OUT_ROOT}/logs/retryable_self_check_evidence.log",
    "blob_put_evidence_log": "${OUT_ROOT}/logs/blob_put_evidence.log",
    "keyvault_set_secret_evidence_log": "${OUT_ROOT}/logs/keyvault_set_secret_evidence.log",
    "compliance_evidence_log": "${OUT_ROOT}/logs/compliance_evidence.log",
    "integration_suite_log": "${OUT_ROOT}/logs/integration_suite.log",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "Azure verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
