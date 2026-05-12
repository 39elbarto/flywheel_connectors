#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="invoke_audit_storm_verification"
RUN_ID="${RUN_ID:-invoke-audit-storm-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-}"
TARGET_DIR="${TARGET_DIR:-/tmp/fcp-invoke-audit-storm-e2e}"
USE_RCH="${USE_RCH:-1}"
DRY_RUN=0

for arg in "$@"; do
  case "${arg}" in
    --dry-run)
      DRY_RUN=1
      ;;
    --run-id=*)
      RUN_ID="${arg#--run-id=}"
      ;;
    --out-root=*)
      OUT_ROOT="${arg#--out-root=}"
      ;;
    --use-rch=*)
      USE_RCH="${arg#--use-rch=}"
      ;;
    *)
      echo "unknown argument: ${arg}" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="./out/${SCRIPT_NAME}/${RUN_ID}"
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

STEPS_JSONL="${OUT_ROOT}/steps.jsonl"
TEST_LOG="${OUT_ROOT}/invoke_audit_storm_test.log"
EVIDENCE_JSONL="${OUT_ROOT}/invoke_audit_storm_evidence.jsonl"
SUMMARY_JSON="${OUT_ROOT}/summary.json"
JSONL_PREFIX="INVOKE_AUDIT_STORM_JSONL"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 127
  fi
}

now_ms() {
  local now
  now="$(date +%s%3N 2>/dev/null || true)"
  if [[ -z "${now}" || "${now}" == *N ]]; then
    now="$(date +%s)000"
  fi
  printf '%s' "${now}"
}

log_step() {
  local step="$1"
  local step_number="$2"
  local result="$3"
  local duration_ms="$4"
  local details_json="$5"
  local artifacts_json="$6"
  local timestamp
  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  mkdir -p "${OUT_ROOT}"
  printf '{"timestamp":"%s","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s-%s","duration_ms":%s,"result":"%s","artifacts":%s,"details":%s,"run_id":"%s"}\n' \
    "${timestamp}" \
    "${SCRIPT_NAME}" \
    "${step}" \
    "${step_number}" \
    "${RUN_ID}" \
    "${step_number}" \
    "${duration_ms}" \
    "${result}" \
    "${artifacts_json}" \
    "${details_json}" \
    "${RUN_ID}" >>"${STEPS_JSONL}"
}

run_logged_step() {
  local step="$1"
  local step_number="$2"
  local artifacts_json="$3"
  shift 3

  local start_ms end_ms duration_ms rc details_json
  start_ms="$(now_ms)"
  set +e
  "$@"
  rc=$?
  set -e
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  if [[ ${rc} -eq 0 ]]; then
    details_json='{"exit_code":0}'
    log_step "${step}" "${step_number}" "pass" "${duration_ms}" "${details_json}" "${artifacts_json}"
  else
    details_json="$(jq -cn --arg exit_code "${rc}" '{exit_code: ($exit_code | tonumber)}')"
    log_step "${step}" "${step_number}" "fail" "${duration_ms}" "${details_json}" "${artifacts_json}"
    return "${rc}"
  fi
}

run_storm_test() {
  local git_revision test_command
  git_revision="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"
  if [[ "${git_revision}" != "unknown" ]]; then
    if ! git diff --quiet --ignore-submodules -- \
      || ! git diff --cached --quiet --ignore-submodules -- \
      || [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
      git_revision="${git_revision}-dirty"
    fi
  fi
  test_command="cargo test -p fcp-host --test invoke_audit_storm_e2e same_zone_audit_storm_e2e_jsonl_covers_c128_and_c512 -- --nocapture"

  if [[ ${DRY_RUN} -eq 1 ]]; then
    {
      echo "dry-run: would execute ${test_command}"
      echo "dry-run: USE_RCH=${USE_RCH} TARGET_DIR=${TARGET_DIR}"
    } >"${TEST_LOG}"
    return 0
  fi

  if [[ "${USE_RCH}" == "1" ]]; then
    require_cmd rch
    rch exec -- env \
      CARGO_TARGET_DIR="${TARGET_DIR}" \
      CARGO_INCREMENTAL=0 \
      FCP_GIT_REVISION="${git_revision}" \
      FCP_TEST_COMMAND_LINE="${test_command}" \
      FCP_INVOKE_AUDIT_STORM_RAW_SAMPLES=1 \
      cargo test -p fcp-host --test invoke_audit_storm_e2e \
        same_zone_audit_storm_e2e_jsonl_covers_c128_and_c512 -- --nocapture \
      >"${TEST_LOG}" 2>&1
  else
    env \
      CARGO_TARGET_DIR="${TARGET_DIR}" \
      CARGO_INCREMENTAL=0 \
      FCP_GIT_REVISION="${git_revision}" \
      FCP_TEST_COMMAND_LINE="${test_command}" \
      FCP_INVOKE_AUDIT_STORM_RAW_SAMPLES=1 \
      cargo test -p fcp-host --test invoke_audit_storm_e2e \
        same_zone_audit_storm_e2e_jsonl_covers_c128_and_c512 -- --nocapture \
      >"${TEST_LOG}" 2>&1
  fi
}

extract_and_validate_evidence() {
  if [[ ${DRY_RUN} -eq 1 ]]; then
    printf '%s\n' \
      '{"event":"invoke_audit_same_zone_storm","scenario_id":"dry_run","skip_reason":"dry-run"}' \
      >"${EVIDENCE_JSONL}"
    return 0
  fi

  if ! grep -a "^${JSONL_PREFIX} " "${TEST_LOG}" \
    | sed "s/^${JSONL_PREFIX} //" >"${EVIDENCE_JSONL}"; then
    echo "failed to extract ${JSONL_PREFIX} records from ${TEST_LOG}" >&2
    return 1
  fi
  if [[ ! -s "${EVIDENCE_JSONL}" ]]; then
    echo "no invoke-audit storm evidence records found in ${TEST_LOG}" >&2
    return 1
  fi
  jq -e . "${EVIDENCE_JSONL}" >/dev/null
  jq -s -e '
    length == 2
      and ([.[].scenario_id] | sort == ["same_zone_c128", "same_zone_c512"])
      and all(.[]; .event == "invoke_audit_same_zone_storm")
      and all(.[]; .metrics.entries == .topology.total_appends)
      and all(.[]; .metrics.committed_entries == .topology.total_appends)
      and all(.[]; .metrics.contention_exhaustions == 0)
      and all(.[]; .isomorphism.audit_verify_chain_clean == true)
      and all(.[]; .worker_identity != "unknown")
      and all(.[]; (.raw_samples_nanos | length) == .topology.total_appends)
      and ((map(select(.scenario_id == "same_zone_c512"))[0].metrics.stale_head_retries
        + map(select(.scenario_id == "same_zone_c512"))[0].metrics.serialized_fallbacks) > 0)
  ' "${EVIDENCE_JSONL}" >/dev/null
}

write_summary() {
  jq -s \
    --arg script "${SCRIPT_NAME}" \
    --arg run_id "${RUN_ID}" \
    --arg evidence_jsonl "${EVIDENCE_JSONL}" \
    --arg steps_jsonl "${STEPS_JSONL}" \
    --arg test_log "${TEST_LOG}" \
    '{
      script: $script,
      run_id: $run_id,
      status: "pass",
      generated_at: (now | todate),
      evidence_jsonl: $evidence_jsonl,
      steps_jsonl: $steps_jsonl,
      test_log: $test_log,
      scenario_ids: [.[].scenario_id],
      total_appends: ([.[].topology.total_appends] | add),
      contention_exhaustions: ([.[].metrics.contention_exhaustions] | add),
      stale_head_retries: ([.[].metrics.stale_head_retries] | add),
      serialized_fallbacks: ([.[].metrics.serialized_fallbacks] | add),
      worker_identities: ([.[].worker_identity] | unique),
      redaction_decision: "script extracts only structured invoke-audit storm evidence; records exclude payloads, prompts, credentials, and PII"
    }' "${EVIDENCE_JSONL}" >"${SUMMARY_JSON}"
}

require_cmd jq
mkdir -p "${OUT_ROOT}"
: >"${STEPS_JSONL}"

run_logged_step \
  "run_storm_test" \
  1 \
  "$(jq -cn --arg log "${TEST_LOG}" '{test_log: $log}')" \
  run_storm_test

run_logged_step \
  "extract_and_validate_evidence" \
  2 \
  "$(jq -cn --arg evidence "${EVIDENCE_JSONL}" '{evidence_jsonl: $evidence}')" \
  extract_and_validate_evidence

run_logged_step \
  "write_summary" \
  3 \
  "$(jq -cn --arg summary "${SUMMARY_JSON}" '{summary_json: $summary}')" \
  write_summary

echo "${SCRIPT_NAME} complete. Summary: ${SUMMARY_JSON}"
