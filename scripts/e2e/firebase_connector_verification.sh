#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/firebase_connector/${RUN_ID}}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

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

  echo "[firebase-verification] ${name}: $*"
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

  echo "[firebase-verification] ${name}: $*"
  (
    cd "${REPO_ROOT}"
    "$@"
  ) >"${stdout_path}" 2>"${log_path}"
}

require_cmd fwc
require_cmd rch

run_capture_stdout \
  manifest_check \
  "${OUT_ROOT}/evidence/manifest_check.json" \
  fwc manifest fix connectors/firebase/manifest.toml --check --json

run_logged \
  cargo_check \
  rch exec -- cargo check -p fcp-firebase --all-targets

run_logged \
  format_check \
  rch exec -- cargo fmt -p fcp-firebase -- --check

run_logged \
  doctor_evidence \
  rch exec -- cargo test -p fcp-firebase --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture

run_logged \
  self_check_secretless_evidence \
  rch exec -- cargo test -p fcp-firebase --test integration self_check_secretless_requires_injection_and_evidence -- --nocapture

run_logged \
  compliance_evidence \
  rch exec -- cargo test -p fcp-firebase --test integration introspection_emits_operation_compliance_evidence -- --nocapture

run_logged \
  integration_suite \
  rch exec -- cargo test -p fcp-firebase --test integration -- --nocapture

run_logged \
  clippy \
  rch exec -- cargo clippy -p fcp-firebase --all-targets -- -D warnings

cat > "${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-firebase",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/firebase_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}"
}
EOF

cat > "${OUT_ROOT}/replay.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

fwc manifest fix connectors/firebase/manifest.toml --check --json
rch exec -- cargo check -p fcp-firebase --all-targets
rch exec -- cargo fmt -p fcp-firebase -- --check
rch exec -- cargo test -p fcp-firebase --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture
rch exec -- cargo test -p fcp-firebase --test integration self_check_secretless_requires_injection_and_evidence -- --nocapture
rch exec -- cargo test -p fcp-firebase --test integration introspection_emits_operation_compliance_evidence -- --nocapture
rch exec -- cargo test -p fcp-firebase --test integration -- --nocapture
rch exec -- cargo clippy -p fcp-firebase --all-targets -- -D warnings
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat > "${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-firebase",
  "artifacts_root": "${OUT_ROOT}",
  "artifacts": {
    "manifest_check": "${OUT_ROOT}/evidence/manifest_check.json",
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "doctor_evidence_log": "${OUT_ROOT}/logs/doctor_evidence.log",
    "self_check_secretless_evidence_log": "${OUT_ROOT}/logs/self_check_secretless_evidence.log",
    "compliance_evidence_log": "${OUT_ROOT}/logs/compliance_evidence.log",
    "integration_suite_log": "${OUT_ROOT}/logs/integration_suite.log",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "Firebase verification artifacts written to ${OUT_ROOT}"
