#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/supabase_connector/${RUN_ID}}"

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

  echo "[supabase-verification] ${name}: $*"
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

  echo "[supabase-verification] ${name}: $*"
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
  fwc manifest fix connectors/supabase/manifest.toml --check --json

run_logged \
  cargo_check \
  rch exec -- cargo check -p fcp-supabase --all-targets

run_logged \
  format_check \
  rch exec -- cargo fmt -p fcp-supabase -- --check

run_logged \
  doctor_self_check_evidence \
  rch exec -- cargo test -p fcp-supabase --test integration self_check_ready_with_secret_key_and_evidence -- --nocapture

run_logged \
  risky_mutation_evidence \
  rch exec -- cargo test -p fcp-supabase --test integration storage_delete_preserves_artifact_evidence -- --nocapture

run_logged \
  conformance_evidence \
  rch exec -- cargo test -p fcp-supabase --test integration introspection_emits_v3_compliance_evidence -- --nocapture

run_logged \
  integration_suite \
  rch exec -- cargo test -p fcp-supabase --test integration -- --nocapture

run_logged \
  clippy \
  rch exec -- cargo clippy -p fcp-supabase --all-targets -- -D warnings

cat > "${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-supabase",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/supabase_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}"
}
EOF

cat > "${OUT_ROOT}/replay.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

fwc manifest fix connectors/supabase/manifest.toml --check --json
rch exec -- cargo check -p fcp-supabase --all-targets
rch exec -- cargo fmt -p fcp-supabase -- --check
rch exec -- cargo test -p fcp-supabase --test integration self_check_ready_with_secret_key_and_evidence -- --nocapture
rch exec -- cargo test -p fcp-supabase --test integration storage_delete_preserves_artifact_evidence -- --nocapture
rch exec -- cargo test -p fcp-supabase --test integration introspection_emits_v3_compliance_evidence -- --nocapture
rch exec -- cargo test -p fcp-supabase --test integration -- --nocapture
rch exec -- cargo clippy -p fcp-supabase --all-targets -- -D warnings
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat > "${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-supabase",
  "artifacts_root": "${OUT_ROOT}",
  "artifacts": {
    "manifest_check": "${OUT_ROOT}/evidence/manifest_check.json",
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "doctor_self_check_evidence_log": "${OUT_ROOT}/logs/doctor_self_check_evidence.log",
    "risky_mutation_evidence_log": "${OUT_ROOT}/logs/risky_mutation_evidence.log",
    "conformance_evidence_log": "${OUT_ROOT}/logs/conformance_evidence.log",
    "integration_suite_log": "${OUT_ROOT}/logs/integration_suite.log",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "Supabase verification artifacts written to ${OUT_ROOT}"
