#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/cross_cloud_auth_regression/${RUN_ID}}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0

shared_sigv4_unit_status="pending"
gcp_jwt_unit_status="pending"
aws_bundle_status="pending"
s3_presign_unit_status="pending"
s3_presign_integration_status="pending"
s3_presign_credential_ref_status="pending"
s3_e2e_status="pending"
gcp_bundle_status="pending"

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

  echo "[cross-cloud-auth] ${name}: $*"
  (
    cd "${REPO_ROOT}"
    "$@"
  ) >"${log_path}" 2>&1
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

classify_log_failure() {
  local log_path="$1"
  if grep -Eq 'missing worker system package dbus-1\.pc|The system library `dbus-1` required|pkg-config --libs --cflags dbus-1' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

run_step() {
  local status_var="$1"
  local name="$2"
  shift 2

  if run_logged "${name}" "$@"; then
    printf -v "${status_var}" '%s' "passed"
  else
    local next_status
    next_status="$(classify_log_failure "${OUT_ROOT}/logs/${name}.log")"
    printf -v "${status_var}" '%s' "${next_status}"
    promote_overall_status "${next_status}"
  fi
}

require_cmd rch

run_step \
  shared_sigv4_unit_status \
  shared_sigv4_unit_suite \
  rch exec -- cargo test -p fcp-sdk sigv4:: --lib -- --nocapture

run_step \
  gcp_jwt_unit_status \
  gcp_jwt_unit_suite \
  rch exec -- cargo test -p fcp-gcp build_jwt_ --lib -- --nocapture

run_step \
  aws_bundle_status \
  aws_bundle \
  env RUN_ID="${RUN_ID}" OUT_ROOT="${OUT_ROOT}/aws_connector" bash scripts/e2e/aws_connector_verification.sh

run_step \
  s3_presign_unit_status \
  s3_presign_unit_suite \
  rch exec -- cargo test -p fcp-s3 presigned_url --lib -- --nocapture

run_step \
  s3_presign_integration_status \
  s3_presign_integration_suite \
  rch exec -- cargo test -p fcp-s3 --test integration invoke_generate_presigned_url_through_connector -- --nocapture

run_step \
  s3_presign_credential_ref_status \
  s3_presign_credential_ref_suite \
  rch exec -- cargo test -p fcp-s3 --test integration invoke_generate_presigned_url_with_credential_id_returns_unsigned_url -- --nocapture

run_step \
  s3_e2e_status \
  s3_e2e_suite \
  rch exec -- cargo test -p fcp-e2e --features s3 --test s3_compliance_e2e -- --nocapture

run_step \
  gcp_bundle_status \
  gcp_bundle \
  env RUN_ID="${RUN_ID}" OUT_ROOT="${OUT_ROOT}/gcp_connector" bash scripts/e2e/gcp_connector_verification.sh

cat > "${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "suite": "cross_cloud_auth_regression",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/cross_cloud_auth_regression.sh",
  "artifact_root": "${OUT_ROOT}"
}
EOF

cat > "${OUT_ROOT}/replay.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-artifacts/e2e/cross_cloud_auth_regression/${RUN_ID}}"

rch exec -- cargo test -p fcp-sdk sigv4:: --lib -- --nocapture
rch exec -- cargo test -p fcp-gcp build_jwt_ --lib -- --nocapture
env RUN_ID="${RUN_ID}" OUT_ROOT="${OUT_ROOT}/aws_connector" bash scripts/e2e/aws_connector_verification.sh
rch exec -- cargo test -p fcp-s3 presigned_url --lib -- --nocapture
rch exec -- cargo test -p fcp-s3 --test integration invoke_generate_presigned_url_through_connector -- --nocapture
rch exec -- cargo test -p fcp-s3 --test integration invoke_generate_presigned_url_with_credential_id_returns_unsigned_url -- --nocapture
rch exec -- cargo test -p fcp-e2e --features s3 --test s3_compliance_e2e -- --nocapture
env RUN_ID="${RUN_ID}" OUT_ROOT="${OUT_ROOT}/gcp_connector" bash scripts/e2e/gcp_connector_verification.sh
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat > "${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "suite": "cross_cloud_auth_regression",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "steps": {
    "shared_sigv4_unit_suite": "${shared_sigv4_unit_status}",
    "gcp_jwt_unit_suite": "${gcp_jwt_unit_status}",
    "aws_bundle": "${aws_bundle_status}",
    "s3_presign_unit_suite": "${s3_presign_unit_status}",
    "s3_presign_integration_suite": "${s3_presign_integration_status}",
    "s3_presign_credential_ref_suite": "${s3_presign_credential_ref_status}",
    "s3_e2e_suite": "${s3_e2e_status}",
    "gcp_bundle": "${gcp_bundle_status}"
  },
  "artifacts": {
    "shared_sigv4_unit_suite_log": "${OUT_ROOT}/logs/shared_sigv4_unit_suite.log",
    "gcp_jwt_unit_suite_log": "${OUT_ROOT}/logs/gcp_jwt_unit_suite.log",
    "aws_bundle_log": "${OUT_ROOT}/logs/aws_bundle.log",
    "aws_bundle_summary": "${OUT_ROOT}/aws_connector/summary.json",
    "s3_presign_unit_suite_log": "${OUT_ROOT}/logs/s3_presign_unit_suite.log",
    "s3_presign_integration_suite_log": "${OUT_ROOT}/logs/s3_presign_integration_suite.log",
    "s3_presign_credential_ref_suite_log": "${OUT_ROOT}/logs/s3_presign_credential_ref_suite.log",
    "s3_e2e_suite_log": "${OUT_ROOT}/logs/s3_e2e_suite.log",
    "gcp_bundle_log": "${OUT_ROOT}/logs/gcp_bundle.log",
    "gcp_bundle_summary": "${OUT_ROOT}/gcp_connector/summary.json",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "Cross-cloud auth regression artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
