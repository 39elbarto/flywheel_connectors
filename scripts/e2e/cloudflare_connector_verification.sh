#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/cloudflare_connector/${RUN_ID}}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"

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
  local previous_pwd
  local rc

  echo "[cloudflare-verification] ${name}: $*"
  previous_pwd="$(pwd)"
  cd "${REPO_ROOT}" || return
  "$@" >"${log_path}" 2>&1
  rc="$?"
  cd "${previous_pwd}" || return
  if [[ "${rc}" -eq 0 ]] && ! require_rch_remote_proof "${name}" "${log_path}" "$@"; then
    return 1
  fi
  return "${rc}"
}

run_capture_stdout() {
  local name="$1"
  local stdout_path="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local previous_pwd
  local rc

  echo "[cloudflare-verification] ${name}: $*"
  previous_pwd="$(pwd)"
  cd "${REPO_ROOT}" || return
  "$@" >"${stdout_path}" 2>"${log_path}"
  rc="$?"
  cd "${previous_pwd}" || return
  if [[ "${rc}" -eq 0 ]] && ! require_rch_remote_proof "${name}" "${log_path}" "$@"; then
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

log_has_remote_proof_failure() {
  local log_path="$1"
  local line
  while IFS= read -r line; do
    if [[ "${line}" == *"rch command did not produce remote proof"* ]]; then
      return 0
    fi
  done < "${log_path}"
  return 1
}

log_has_dbus_blocker() {
  local log_path="$1"
  local line
  while IFS= read -r line; do
    case "${line}" in
      *"missing worker system package dbus-1.pc"*|*"The system library \`dbus-1\` required"*|*"pkg-config --libs --cflags dbus-1"*)
        return 0
        ;;
    esac
  done < "${log_path}"
  return 1
}

log_has_infra_blocker() {
  local log_path="$1"
  local line
  while IFS= read -r line; do
    case "${line}" in
      *"RCH-E"*|*"remote required; refusing local fallback"*|*"rch command did not produce remote proof"*|*"No space left on device"*|*"connection reset by peer"*|*"Backend unavailable"*|*"unable to update registry"*|*"spurious network error"*|*"failed to get successful HTTP response"*|*"missing worker system package"*|*"timeout: failed to execute process"*)
        return 0
        ;;
    esac
  done < "${log_path}"
  return 1
}

classify_manifest_failure() {
  local log_path="$1"
  if [[ ! -f "${log_path}" ]]; then
    echo "infra_blocked"
    return
  fi

  if log_has_infra_blocker "${log_path}" || log_has_dbus_blocker "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

classify_step_failure() {
  local log_path="$1"
  if [[ ! -f "${log_path}" ]]; then
    echo "infra_blocked"
    return
  fi

  if log_has_infra_blocker "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

command_uses_rch_exec() {
  local previous=""
  for arg in "$@"; do
    if [[ "${previous}" == "rch" && "${arg}" == "exec" ]]; then
      return 0
    fi
    previous="${arg}"
  done
  return 1
}

rch_remote_summary_present() {
  local log_path="$1"
  local line
  while IFS= read -r line; do
    if [[ "${line}" == *"[RCH] remote"* ]]; then
      return 0
    fi
  done < "${log_path}"
  return 1
}

require_rch_remote_proof() {
  local name="$1"
  local log_path="$2"
  shift 2

  if command_uses_rch_exec "$@" && ! rch_remote_summary_present "${log_path}"; then
    echo "[cloudflare-verification] ${name}: rch command did not produce remote proof" >&2
    echo "rch command did not produce remote proof" >>"${log_path}"
    return 1
  fi
}

require_cmd jq
require_cmd rch

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
  connectors/cloudflare/manifest.toml
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
    if log_has_remote_proof_failure "${OUT_ROOT}/logs/manifest_check.log"; then
      manifest_note="rch command did not produce remote proof for fallback manifest validation"
    elif log_has_dbus_blocker "${OUT_ROOT}/logs/manifest_check.log"; then
      manifest_note="rch worker image missing dbus-1.pc while building fwc for manifest validation"
    else
      manifest_note="infrastructure blocked manifest validation; inspect logs/manifest_check.log"
    fi
  else
    manifest_note="manifest validation command failed; inspect logs/manifest_check.log"
  fi
  jq -n \
    --arg status "${manifest_status}" \
    --arg note "${manifest_note}" \
    --arg command_output "${manifest_stdout_path}" \
    --arg log "${OUT_ROOT}/logs/manifest_check.log" \
    '{status:$status,note:$note,command_output:$command_output,log:$log}' \
    > "${OUT_ROOT}/evidence/manifest_check.json"
  promote_overall_status "${manifest_status}"
fi

if run_logged \
  cargo_check \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo check -p fcp-cloudflare
then
  cargo_check_status="passed"
else
  cargo_check_status="$(classify_step_failure "${OUT_ROOT}/logs/cargo_check.log")"
  promote_overall_status "${cargo_check_status}"
fi

if run_logged \
  format_check \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo fmt --check -p fcp-cloudflare
then
  format_check_status="passed"
else
  format_check_status="$(classify_step_failure "${OUT_ROOT}/logs/format_check.log")"
  promote_overall_status "${format_check_status}"
fi

if run_logged \
  doctor_self_check_evidence \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-cloudflare --test integration self_check_ready_with_active_token_and_evidence -- --nocapture
then
  doctor_self_check_status="passed"
else
  doctor_self_check_status="$(classify_step_failure "${OUT_ROOT}/logs/doctor_self_check_evidence.log")"
  promote_overall_status "${doctor_self_check_status}"
fi

if run_logged \
  risky_mutation_evidence \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-cloudflare --test integration invoke_risky_dns_delete_preserves_artifact_evidence -- --nocapture
then
  risky_mutation_status="passed"
else
  risky_mutation_status="$(classify_step_failure "${OUT_ROOT}/logs/risky_mutation_evidence.log")"
  promote_overall_status "${risky_mutation_status}"
fi

if run_logged \
  integration_suite \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo test -p fcp-cloudflare --test integration -- --nocapture
then
  integration_suite_status="passed"
else
  integration_suite_status="$(classify_step_failure "${OUT_ROOT}/logs/integration_suite.log")"
  promote_overall_status "${integration_suite_status}"
fi

if run_logged \
  clippy \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo clippy -p fcp-cloudflare --all-targets -- -D warnings
then
  clippy_status="passed"
else
  clippy_status="$(classify_step_failure "${OUT_ROOT}/logs/clippy.log")"
  promote_overall_status "${clippy_status}"
fi

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg connector "fcp-cloudflare" \
  --arg repo_root "${REPO_ROOT}" \
  --arg verification_script "scripts/e2e/cloudflare_connector_verification.sh" \
  --arg artifact_root "${OUT_ROOT}" \
  --arg toolchain "${REPO_TOOLCHAIN}" \
  '{
    run_id: $run_id,
    connector: $connector,
    repo_root: $repo_root,
    verification_script: $verification_script,
    artifact_root: $artifact_root,
    toolchain: $toolchain
  }' > "${OUT_ROOT}/environment.json"

{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -euo pipefail'
  printf '%s\n' ''
  printf '%s\n' "REPO_TOOLCHAIN=\"\${REPO_TOOLCHAIN:-${REPO_TOOLCHAIN}}\""
  printf '%s\n' "env RCH_VISIBILITY=verbose rch exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" cargo run -q -p fwc -- manifest fix connectors/cloudflare/manifest.toml --check --json"
  printf '%s\n' "env RCH_VISIBILITY=verbose rch exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" cargo check -p fcp-cloudflare"
  printf '%s\n' "env RCH_VISIBILITY=verbose rch exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" cargo fmt --check -p fcp-cloudflare"
  printf '%s\n' "env RCH_VISIBILITY=verbose rch exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" cargo test -p fcp-cloudflare --test integration self_check_ready_with_active_token_and_evidence -- --nocapture"
  printf '%s\n' "env RCH_VISIBILITY=verbose rch exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" cargo test -p fcp-cloudflare --test integration invoke_risky_dns_delete_preserves_artifact_evidence -- --nocapture"
  printf '%s\n' "env RCH_VISIBILITY=verbose rch exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" cargo test -p fcp-cloudflare --test integration -- --nocapture"
  printf '%s\n' "env RCH_VISIBILITY=verbose rch exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" cargo clippy -p fcp-cloudflare --all-targets -- -D warnings"
} > "${OUT_ROOT}/replay.sh"
chmod +x "${OUT_ROOT}/replay.sh"

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg connector "fcp-cloudflare" \
  --arg overall_status "${OVERALL_STATUS}" \
  --arg artifacts_root "${OUT_ROOT}" \
  --arg manifest_status "${manifest_status}" \
  --arg manifest_note "${manifest_note}" \
  --arg cargo_check "${cargo_check_status}" \
  --arg format_check "${format_check_status}" \
  --arg doctor_self_check_evidence "${doctor_self_check_status}" \
  --arg risky_mutation_evidence "${risky_mutation_status}" \
  --arg integration_suite "${integration_suite_status}" \
  --arg clippy "${clippy_status}" \
  --arg manifest_check "${OUT_ROOT}/evidence/manifest_check.json" \
  --arg cargo_check_log "${OUT_ROOT}/logs/cargo_check.log" \
  --arg format_check_log "${OUT_ROOT}/logs/format_check.log" \
  --arg doctor_self_check_evidence_log "${OUT_ROOT}/logs/doctor_self_check_evidence.log" \
  --arg risky_mutation_evidence_log "${OUT_ROOT}/logs/risky_mutation_evidence.log" \
  --arg integration_suite_log "${OUT_ROOT}/logs/integration_suite.log" \
  --arg clippy_log "${OUT_ROOT}/logs/clippy.log" \
  --arg environment "${OUT_ROOT}/environment.json" \
  --arg replay "${OUT_ROOT}/replay.sh" \
  '{
    run_id: $run_id,
    connector: $connector,
    overall_status: $overall_status,
    artifacts_root: $artifacts_root,
    steps: {
      manifest_check: {
        status: $manifest_status,
        note: $manifest_note
      },
      cargo_check: $cargo_check,
      format_check: $format_check,
      doctor_self_check_evidence: $doctor_self_check_evidence,
      risky_mutation_evidence: $risky_mutation_evidence,
      integration_suite: $integration_suite,
      clippy: $clippy
    },
    artifacts: {
      manifest_check: $manifest_check,
      cargo_check_log: $cargo_check_log,
      format_check_log: $format_check_log,
      doctor_self_check_evidence_log: $doctor_self_check_evidence_log,
      risky_mutation_evidence_log: $risky_mutation_evidence_log,
      integration_suite_log: $integration_suite_log,
      clippy_log: $clippy_log,
      environment: $environment,
      replay: $replay
    }
  }' > "${OUT_ROOT}/summary.json"

echo "Cloudflare verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
