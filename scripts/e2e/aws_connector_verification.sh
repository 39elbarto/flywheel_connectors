#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/aws_connector/${RUN_ID}}"

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
sts_identity_status="pending"
lambda_list_status="pending"
ec2_terminate_status="pending"
risky_mutation_status="pending"
compliance_status="pending"
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

  echo "[aws-verification] ${name}: $*"
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

  echo "[aws-verification] ${name}: $*"
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
  rch exec -- cargo run -q -p fwc -- manifest fix connectors/aws/manifest.toml --check --json
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
  rch exec -- cargo check -p fcp-aws --all-targets
then
  cargo_check_status="passed"
else
  cargo_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  format_check \
  rch exec -- cargo fmt -p fcp-aws -- --check
then
  format_check_status="passed"
else
  format_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  health_guidance_evidence \
  rch exec -- cargo test -p fcp-aws --test integration lifecycle_health_unconfigured_includes_guidance -- --nocapture
then
  health_guidance_status="passed"
else
  health_guidance_status="failed"
  promote_overall_status failed
fi

if run_logged \
  doctor_guidance_evidence \
  rch exec -- cargo test -p fcp-aws --test integration doctor_unconfigured_reports_remediation -- --nocapture
then
  doctor_guidance_status="passed"
else
  doctor_guidance_status="failed"
  promote_overall_status failed
fi

if run_logged \
  doctor_self_check_evidence \
  rch exec -- cargo test -p fcp-aws --test integration self_check_ready_with_custom_sts_override_and_evidence -- --nocapture
then
  doctor_self_check_status="passed"
else
  doctor_self_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  retryable_self_check_evidence \
  rch exec -- cargo test -p fcp-aws --test integration self_check_retryable_sts_failure_reports_degraded -- --nocapture
then
  retryable_self_check_status="passed"
else
  retryable_self_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  sts_identity_evidence \
  rch exec -- cargo test -p fcp-aws --test integration invoke_sts_identity_preserves_artifact_evidence -- --nocapture
then
  sts_identity_status="passed"
else
  sts_identity_status="failed"
  promote_overall_status failed
fi

if run_logged \
  lambda_list_evidence \
  rch exec -- cargo test -p fcp-aws --test integration invoke_lambda_list_functions_preserves_artifact_evidence -- --nocapture
then
  lambda_list_status="passed"
else
  lambda_list_status="failed"
  promote_overall_status failed
fi

if run_logged \
  ec2_terminate_evidence \
  rch exec -- cargo test -p fcp-aws --test integration invoke_ec2_terminate_preserves_state_transition_evidence -- --nocapture
then
  ec2_terminate_status="passed"
else
  ec2_terminate_status="failed"
  promote_overall_status failed
fi

if run_logged \
  risky_mutation_evidence \
  rch exec -- cargo test -p fcp-aws --test integration invoke_dangerous_s3_delete_preserves_artifact_evidence -- --nocapture
then
  risky_mutation_status="passed"
else
  risky_mutation_status="failed"
  promote_overall_status failed
fi

if run_logged \
  compliance_evidence \
  rch exec -- cargo test -p fcp-aws --test integration introspection_emits_v3_compliance_evidence -- --nocapture
then
  compliance_status="passed"
else
  compliance_status="failed"
  promote_overall_status failed
fi

if run_logged \
  integration_suite \
  rch exec -- cargo test -p fcp-aws --test integration -- --nocapture
then
  integration_suite_status="passed"
else
  integration_suite_status="failed"
  promote_overall_status failed
fi

if run_logged \
  clippy \
  rch exec -- cargo clippy -p fcp-aws --all-targets -- -D warnings
then
  clippy_status="passed"
else
  clippy_status="failed"
  promote_overall_status failed
fi

cat > "${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-aws",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/aws_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}"
}
EOF

cat > "${OUT_ROOT}/replay.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

rch exec -- cargo run -q -p fwc -- manifest fix connectors/aws/manifest.toml --check --json
rch exec -- cargo check -p fcp-aws --all-targets
rch exec -- cargo fmt -p fcp-aws -- --check
rch exec -- cargo test -p fcp-aws --test integration lifecycle_health_unconfigured_includes_guidance -- --nocapture
rch exec -- cargo test -p fcp-aws --test integration doctor_unconfigured_reports_remediation -- --nocapture
rch exec -- cargo test -p fcp-aws --test integration self_check_ready_with_custom_sts_override_and_evidence -- --nocapture
rch exec -- cargo test -p fcp-aws --test integration self_check_retryable_sts_failure_reports_degraded -- --nocapture
rch exec -- cargo test -p fcp-aws --test integration invoke_sts_identity_preserves_artifact_evidence -- --nocapture
rch exec -- cargo test -p fcp-aws --test integration invoke_lambda_list_functions_preserves_artifact_evidence -- --nocapture
rch exec -- cargo test -p fcp-aws --test integration invoke_ec2_terminate_preserves_state_transition_evidence -- --nocapture
rch exec -- cargo test -p fcp-aws --test integration invoke_dangerous_s3_delete_preserves_artifact_evidence -- --nocapture
rch exec -- cargo test -p fcp-aws --test integration introspection_emits_v3_compliance_evidence -- --nocapture
rch exec -- cargo test -p fcp-aws --test integration -- --nocapture
rch exec -- cargo clippy -p fcp-aws --all-targets -- -D warnings
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat > "${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-aws",
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
    "sts_identity_evidence": "${sts_identity_status}",
    "lambda_list_evidence": "${lambda_list_status}",
    "ec2_terminate_evidence": "${ec2_terminate_status}",
    "risky_mutation_evidence": "${risky_mutation_status}",
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
    "sts_identity_evidence_log": "${OUT_ROOT}/logs/sts_identity_evidence.log",
    "lambda_list_evidence_log": "${OUT_ROOT}/logs/lambda_list_evidence.log",
    "ec2_terminate_evidence_log": "${OUT_ROOT}/logs/ec2_terminate_evidence.log",
    "risky_mutation_evidence_log": "${OUT_ROOT}/logs/risky_mutation_evidence.log",
    "compliance_evidence_log": "${OUT_ROOT}/logs/compliance_evidence.log",
    "integration_suite_log": "${OUT_ROOT}/logs/integration_suite.log",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "AWS verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
