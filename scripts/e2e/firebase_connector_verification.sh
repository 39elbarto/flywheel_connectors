#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/firebase_connector/${RUN_ID}}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
REMOTE_RUNNER="rch:remote-required"
export RCH_FORCE_REMOTE=1

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
risky_mutation_status="pending"
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
  local rc

  echo "[firebase-verification] ${name}: $*"
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
  rc="$?"
  if [[ "${rc}" -eq 0 ]] && ! require_rch_remote_proof "${name}" "${log_path}"; then
    return 1
  fi
  return "${rc}"
}

run_capture_stdout() {
  local name="$1"
  local stdout_path="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local rc

  echo "[firebase-verification] ${name}: $*"
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${stdout_path}" 2>"${log_path}"
  rc="$?"
  if [[ "${rc}" -eq 0 ]] && ! require_rch_remote_proof "${name}" "${log_path}"; then
    return 1
  fi
  return "${rc}"
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
  # shellcheck disable=SC2016
  if grep -Eq 'RCH-E|remote required; refusing local fallback|rch command did not produce remote proof|\[RCH\] local|missing worker system package dbus-1\.pc|The system library `dbus-1` required|pkg-config --libs --cflags dbus-1' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

classify_step_failure() {
  local log_path="$1"
  if grep -Eq 'RCH-E|remote required; refusing local fallback|rch command did not produce remote proof|\[RCH\] local|No space left on device|connection reset by peer|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response|missing worker system package|timeout: failed to execute process' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

require_rch_remote_proof() {
  local name="$1"
  local log_path="$2"

  if grep -Fq "[RCH] remote" "${log_path}"; then
    return 0
  fi

  echo "[firebase-verification] ${name}: rch command did not produce remote proof" >&2
  echo "rch command did not produce remote proof" >>"${log_path}"
  return 1
}

require_cmd rch

manifest_check_runner="${REMOTE_RUNNER}:cargo-run"
manifest_check_cmd=(
  env
  RCH_VISIBILITY=verbose
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
  connectors/firebase/manifest.toml
  --check
  --json
)

if run_capture_stdout \
  manifest_check \
  "${OUT_ROOT}/evidence/manifest_check.json" \
  "${manifest_check_cmd[@]}"
then
  manifest_status="passed"
else
  manifest_status="$(classify_manifest_failure "${OUT_ROOT}/logs/manifest_check.log")"
  if [[ "${manifest_status}" == "infra_blocked" ]]; then
    if grep -Fq "rch command did not produce remote proof" "${OUT_ROOT}/logs/manifest_check.log"; then
      manifest_note="rch command did not produce remote proof for manifest validation"
    else
      manifest_note="infrastructure blocked manifest validation; inspect logs/manifest_check.log"
    fi
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
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo check -p fcp-firebase --all-targets
then
  cargo_check_status="passed"
else
  cargo_check_status="$(classify_step_failure "${OUT_ROOT}/logs/cargo_check.log")"
  promote_overall_status "${cargo_check_status}"
fi

if run_logged \
  format_check \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo fmt -p fcp-firebase -- --check
then
  format_check_status="passed"
else
  format_check_status="$(classify_step_failure "${OUT_ROOT}/logs/format_check.log")"
  promote_overall_status "${format_check_status}"
fi

if run_logged \
  health_guidance_evidence \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-firebase --test integration health_unconfigured_includes_guidance -- --nocapture
then
  health_guidance_status="passed"
else
  health_guidance_status="$(classify_step_failure "${OUT_ROOT}/logs/health_guidance_evidence.log")"
  promote_overall_status "${health_guidance_status}"
fi

if run_logged \
  doctor_guidance_evidence \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-firebase --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture
then
  doctor_guidance_status="passed"
else
  doctor_guidance_status="$(classify_step_failure "${OUT_ROOT}/logs/doctor_guidance_evidence.log")"
  promote_overall_status "${doctor_guidance_status}"
fi

if run_logged \
  doctor_self_check_evidence \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-firebase --test integration self_check_ready_with_access_token_and_evidence -- --nocapture
then
  doctor_self_check_status="passed"
else
  doctor_self_check_status="$(classify_step_failure "${OUT_ROOT}/logs/doctor_self_check_evidence.log")"
  promote_overall_status "${doctor_self_check_status}"
fi

if run_logged \
  retryable_self_check_evidence \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-firebase --test integration self_check_retryable_firestore_api_failure_reports_degraded -- --nocapture
then
  retryable_self_check_status="passed"
else
  retryable_self_check_status="$(classify_step_failure "${OUT_ROOT}/logs/retryable_self_check_evidence.log")"
  promote_overall_status "${retryable_self_check_status}"
fi

if run_logged \
  risky_mutation_evidence \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-firebase --test integration invoke_rtdb_set_preserves_artifact_evidence -- --nocapture
then
  risky_mutation_status="passed"
else
  risky_mutation_status="$(classify_step_failure "${OUT_ROOT}/logs/risky_mutation_evidence.log")"
  promote_overall_status "${risky_mutation_status}"
fi

if run_logged \
  compliance_evidence \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-firebase --test integration introspection_emits_v3_compliance_evidence -- --nocapture
then
  compliance_status="passed"
else
  compliance_status="$(classify_step_failure "${OUT_ROOT}/logs/compliance_evidence.log")"
  promote_overall_status "${compliance_status}"
fi

if run_logged \
  integration_suite \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-firebase --test integration -- --nocapture
then
  integration_suite_status="passed"
else
  integration_suite_status="$(classify_step_failure "${OUT_ROOT}/logs/integration_suite.log")"
  promote_overall_status "${integration_suite_status}"
fi

if run_logged \
  clippy \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo clippy -p fcp-firebase --all-targets -- -D warnings
then
  clippy_status="passed"
else
  clippy_status="$(classify_step_failure "${OUT_ROOT}/logs/clippy.log")"
  promote_overall_status "${clippy_status}"
fi

cat > "${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-firebase",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/firebase_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "manifest_check_runner": "${manifest_check_runner}"
}
EOF

cat > "${OUT_ROOT}/replay.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

REPO_TOOLCHAIN="\${REPO_TOOLCHAIN:-${REPO_TOOLCHAIN}}"
export RCH_FORCE_REMOTE=1
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" cargo run -q -p fwc -- manifest fix connectors/firebase/manifest.toml --check --json
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" cargo check -p fcp-firebase --all-targets
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" cargo fmt -p fcp-firebase -- --check
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" cargo test -p fcp-firebase --test integration health_unconfigured_includes_guidance -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" cargo test -p fcp-firebase --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" cargo test -p fcp-firebase --test integration self_check_ready_with_access_token_and_evidence -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" cargo test -p fcp-firebase --test integration self_check_retryable_firestore_api_failure_reports_degraded -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" cargo test -p fcp-firebase --test integration invoke_rtdb_set_preserves_artifact_evidence -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" cargo test -p fcp-firebase --test integration introspection_emits_v3_compliance_evidence -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" cargo test -p fcp-firebase --test integration -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" cargo clippy -p fcp-firebase --all-targets -- -D warnings
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat > "${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-firebase",
  "overall_status": "${OVERALL_STATUS}",
  "runner": "${REMOTE_RUNNER}",
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
    "risky_mutation_evidence_log": "${OUT_ROOT}/logs/risky_mutation_evidence.log",
    "compliance_evidence_log": "${OUT_ROOT}/logs/compliance_evidence.log",
    "integration_suite_log": "${OUT_ROOT}/logs/integration_suite.log",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "Firebase verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
