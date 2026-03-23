#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/amplitude_connector/${RUN_ID}}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0

manifest_status="pending"
manifest_note=""
cargo_check_status="pending"
format_check_status="pending"
health_guidance_status="pending"
doctor_guidance_status="pending"
self_check_status="pending"
retryable_self_check_status="pending"
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

  echo "[amplitude-verification] ${name}: $*"
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

  echo "[amplitude-verification] ${name}: $*"
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

manifest_check_runner="rch:cargo-run"
manifest_check_cmd=(
  rch
  exec
  --
  env
  "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}"
  cargo
  run
  -q
  -p
  fwc
  --
  manifest
  fix
  connectors/amplitude/manifest.toml
  --check
  --json
)

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
  cargo_check \
  rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo check -p fcp-amplitude --all-targets
then
  cargo_check_status="passed"
else
  cargo_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  format_check \
  rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo fmt --manifest-path connectors/amplitude/Cargo.toml --check
then
  format_check_status="passed"
else
  format_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  health_guidance_evidence \
  rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-amplitude --test integration health_unconfigured_includes_guidance -- --nocapture
then
  health_guidance_status="passed"
else
  health_guidance_status="failed"
  promote_overall_status failed
fi

if run_logged \
  doctor_guidance_evidence \
  rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-amplitude --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture
then
  doctor_guidance_status="passed"
else
  doctor_guidance_status="failed"
  promote_overall_status failed
fi

if run_logged \
  self_check_evidence \
  rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-amplitude --test integration self_check_ready_with_mock_amplitude_api_and_evidence -- --nocapture
then
  self_check_status="passed"
else
  self_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  retryable_self_check_evidence \
  rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-amplitude --test integration self_check_retryable_amplitude_failure_reports_degraded -- --nocapture
then
  retryable_self_check_status="passed"
else
  retryable_self_check_status="failed"
  promote_overall_status failed
fi

if run_logged \
  compliance_evidence \
  rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-amplitude --test integration introspection_emits_v3_compliance_evidence -- --nocapture
then
  compliance_status="passed"
else
  compliance_status="failed"
  promote_overall_status failed
fi

if run_logged \
  integration_suite \
  rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-amplitude --test integration -- --nocapture
then
  integration_suite_status="passed"
else
  integration_suite_status="failed"
  promote_overall_status failed
fi

if run_logged \
  crate_suite \
  rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-amplitude -- --nocapture
then
  crate_suite_status="passed"
else
  crate_suite_status="failed"
  promote_overall_status failed
fi

if run_logged \
  clippy \
  rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo clippy -p fcp-amplitude --all-targets -- -D warnings
then
  clippy_status="passed"
else
  clippy_status="failed"
  promote_overall_status failed
fi

cat > "${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-amplitude",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/amplitude_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "manifest_check_runner": "${manifest_check_runner}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "scope_note": "read-only Amplitude retrofit: chart query, cohort listing, event export, and readiness evidence"
}
EOF

cat > "${OUT_ROOT}/replay.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo run -q -p fwc -- manifest fix connectors/amplitude/manifest.toml --check --json
rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo fmt --manifest-path connectors/amplitude/Cargo.toml --check
rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo check -p fcp-amplitude --all-targets
rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-amplitude --test integration health_unconfigured_includes_guidance -- --nocapture
rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-amplitude --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture
rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-amplitude --test integration self_check_ready_with_mock_amplitude_api_and_evidence -- --nocapture
rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-amplitude --test integration self_check_retryable_amplitude_failure_reports_degraded -- --nocapture
rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-amplitude --test integration introspection_emits_v3_compliance_evidence -- --nocapture
rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-amplitude --test integration -- --nocapture
rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-amplitude -- --nocapture
rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo clippy -p fcp-amplitude --all-targets -- -D warnings
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat > "${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-amplitude",
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
    "self_check_evidence": "${self_check_status}",
    "retryable_self_check_evidence": "${retryable_self_check_status}",
    "compliance_evidence": "${compliance_status}",
    "integration_suite": "${integration_suite_status}",
    "crate_suite": "${crate_suite_status}",
    "clippy": "${clippy_status}"
  },
  "artifacts": {
    "manifest_check": "${OUT_ROOT}/evidence/manifest_check.json",
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "health_guidance_evidence_log": "${OUT_ROOT}/logs/health_guidance_evidence.log",
    "doctor_guidance_evidence_log": "${OUT_ROOT}/logs/doctor_guidance_evidence.log",
    "self_check_evidence_log": "${OUT_ROOT}/logs/self_check_evidence.log",
    "retryable_self_check_evidence_log": "${OUT_ROOT}/logs/retryable_self_check_evidence.log",
    "compliance_evidence_log": "${OUT_ROOT}/logs/compliance_evidence.log",
    "integration_suite_log": "${OUT_ROOT}/logs/integration_suite.log",
    "crate_suite_log": "${OUT_ROOT}/logs/crate_suite.log",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "Amplitude verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
