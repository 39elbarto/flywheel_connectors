#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="runtime_network_policy_verification"
RUN_ID="${RUN_ID:-runtime-network-policy-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT_ENV="${OUT_ROOT:-}"
OUT_ROOT=""
TARGET_DIR="${TARGET_DIR:-/tmp/fcp-runtime-network-policy-e2e}"
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
  if [[ -n "${OUT_ROOT_ENV}" ]]; then
    OUT_ROOT="${OUT_ROOT_ENV}"
  else
    OUT_ROOT="./out/${SCRIPT_NAME}/${RUN_ID}"
  fi
fi

STEPS_JSONL="${OUT_ROOT}/steps.jsonl"
HOST_TEST_LOG="${OUT_ROOT}/runtime_network_policy_test.log"
SDK_TEST_LOG="${OUT_ROOT}/sdk_host_egress_proxy_test.log"
SANDBOX_TEST_LOG="${OUT_ROOT}/os_sandbox_network_policy_test.log"
EVIDENCE_JSONL="${OUT_ROOT}/runtime_network_policy_decisions.jsonl"
SUMMARY_JSON="${OUT_ROOT}/summary.json"

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

run_policy_test() {
  if [[ ${DRY_RUN} -eq 1 ]]; then
    {
      echo "dry-run: would execute fcp-host runtime network policy e2e JSONL matrices"
      echo "dry-run: USE_RCH=${USE_RCH} TARGET_DIR=${TARGET_DIR}"
    } >"${HOST_TEST_LOG}"
    return 0
  fi

  if [[ "${USE_RCH}" == "1" ]]; then
    require_cmd rch
    rch exec -- env \
      CARGO_TARGET_DIR="${TARGET_DIR}" \
      CARGO_INCREMENTAL=0 \
      cargo test -p fcp-host e2e_jsonl_matrix -- --nocapture \
      >"${HOST_TEST_LOG}" 2>&1
  else
    env \
      CARGO_TARGET_DIR="${TARGET_DIR}" \
      CARGO_INCREMENTAL=0 \
      cargo test -p fcp-host e2e_jsonl_matrix -- --nocapture \
      >"${HOST_TEST_LOG}" 2>&1
  fi
}

run_sdk_proxy_test() {
  if [[ ${DRY_RUN} -eq 1 ]]; then
    {
      echo "dry-run: would execute fcp-sdk host-egress proxy routing e2e JSONL matrices"
      echo "dry-run: USE_RCH=${USE_RCH} TARGET_DIR=${TARGET_DIR}"
    } >"${SDK_TEST_LOG}"
    return 0
  fi

  if [[ "${USE_RCH}" == "1" ]]; then
    require_cmd rch
    rch exec -- env \
      CARGO_TARGET_DIR="${TARGET_DIR}" \
      CARGO_INCREMENTAL=0 \
      cargo test -p fcp-sdk --features connector-http host_egress_proxy -- --nocapture \
      >"${SDK_TEST_LOG}" 2>&1
  else
    env \
      CARGO_TARGET_DIR="${TARGET_DIR}" \
      CARGO_INCREMENTAL=0 \
      cargo test -p fcp-sdk --features connector-http host_egress_proxy -- --nocapture \
      >"${SDK_TEST_LOG}" 2>&1
  fi
}

run_os_sandbox_test() {
  if [[ ${DRY_RUN} -eq 1 ]]; then
    {
      echo "dry-run: would execute fcp-sandbox focused runtime network policy tests"
      echo "dry-run: USE_RCH=${USE_RCH} TARGET_DIR=${TARGET_DIR}"
    } >"${SANDBOX_TEST_LOG}"
    return 0
  fi

  if [[ "${USE_RCH}" == "1" ]]; then
    require_cmd rch
    rch exec -- env \
      CARGO_TARGET_DIR="${TARGET_DIR}" \
      CARGO_INCREMENTAL=0 \
      cargo test -p fcp-sandbox --test no_mock_integration wasi_runtime_network_policy_controls_preview2_socket_hostcalls -- --nocapture \
      >"${SANDBOX_TEST_LOG}" 2>&1
  else
    env \
      CARGO_TARGET_DIR="${TARGET_DIR}" \
      CARGO_INCREMENTAL=0 \
      cargo test -p fcp-sandbox --test no_mock_integration wasi_runtime_network_policy_controls_preview2_socket_hostcalls -- --nocapture \
      >"${SANDBOX_TEST_LOG}" 2>&1
  fi
}

extract_evidence() {
  if [[ ${DRY_RUN} -eq 1 ]]; then
    printf '{"timestamp":"%s","test_name":"runtime_network_policy_e2e_jsonl_matrix","module":"fcp-host","phase":"dry_run","correlation_id":"%s-dry-run","result":"pass","duration_ms":0,"assertions":{"passed":1,"failed":0},"scenario_id":"runtime_network_policy.dry_run","details":{"status":"planned"}}\n' \
      "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
      "${RUN_ID}" >"${EVIDENCE_JSONL}"
    return 0
  fi

  : >"${EVIDENCE_JSONL}"
  for log in "${HOST_TEST_LOG}" "${SDK_TEST_LOG}" "${SANDBOX_TEST_LOG}"; do
    grep -a '^RUNTIME_NETWORK_POLICY_E2E_JSONL ' "${log}" \
      | sed 's/^RUNTIME_NETWORK_POLICY_E2E_JSONL //' >>"${EVIDENCE_JSONL}" || true
  done
  [[ -s "${EVIDENCE_JSONL}" ]]
}

validate_jsonl() {
  local file="$1"
  jq -e -R 'fromjson | type == "object"' "${file}" >/dev/null
}

validate_required_scenarios() {
  if [[ ${DRY_RUN} -eq 1 ]]; then
    return 0
  fi

  local required
  required='[
    "runtime_network_policy.managed_missing_per_op",
    "runtime_network_policy.manifest_missing_per_op",
    "runtime_network_policy.host_allow_fallback_denied",
    "runtime_network_policy.wildcard_host_allow_denied",
    "runtime_network_policy.missing_port_allow_denied",
    "runtime_network_policy.missing_require_sni_denied",
    "runtime_network_policy.missing_deny_private_ranges_denied",
    "runtime_network_policy.unsupported_placeholder_denied",
    "runtime_network_policy.matrix_placeholder_success",
    "runtime_network_policy.local_lan_exception_success",
    "runtime_network_policy.two_op_a_allows_a",
    "runtime_network_policy.two_op_a_denies_b",
    "runtime_network_policy.two_op_b_allows_b",
    "runtime_network_policy.two_op_b_denies_a",
    "runtime_network_policy.redaction_scan",
    "host_egress_proxy_spki_verification.https_spki_allowed",
    "host_egress_proxy_spki_verification.https_spki_denied",
    "host_egress_proxy_spki_verification.tcp_tls_spki_allowed",
    "host_egress_proxy_spki_verification.tcp_tls_spki_denied",
    "host_egress_proxy_tls_transport.https_extra_ca_success",
    "host_egress_proxy_tls_transport.tcp_tls_extra_ca_success",
    "host_egress_proxy_transport.redirect_denied",
    "host_egress_proxy_transport.response_size_denied",
    "host_egress_proxy_transport.sni_denied",
    "sdk_https_proxy_routing",
    "sdk_tls_tcp_proxy_routing",
    "sdk_denied_structured_error",
    "sdk_redaction_scan",
    "os_sandbox_direct_socket_denied",
    "os_sandbox_proxy_allowed",
    "os_sandbox_proxy_policy_denied",
    "os_sandbox_redaction_scan"
  ]'
  jq -s -e --argjson required "${required}" '
    ([.[].scenario_id] | unique) as $seen
    | ($required - $seen) as $missing
    | if ($missing | length) == 0
      then true
      else error("missing required runtime-network scenarios: " + ($missing | join(", ")))
      end
  ' "${EVIDENCE_JSONL}" >/dev/null
}

write_summary() {
  local evidence_count
  evidence_count="$(wc -l <"${EVIDENCE_JSONL}" | tr -d ' ')"
  jq -n \
    --arg script "${SCRIPT_NAME}" \
    --arg run_id "${RUN_ID}" \
    --arg host_test_log "${HOST_TEST_LOG}" \
    --arg sdk_test_log "${SDK_TEST_LOG}" \
    --arg sandbox_test_log "${SANDBOX_TEST_LOG}" \
    --arg evidence_jsonl "${EVIDENCE_JSONL}" \
    --arg steps_jsonl "${STEPS_JSONL}" \
    --arg evidence_count "${evidence_count}" \
    --slurpfile steps "${STEPS_JSONL}" \
    '{
      script: $script,
      run_id: $run_id,
      status: "pass",
      generated_at: (now | todateiso8601),
      beads: [
        "flywheel_connectors-hx0gw",
        "flywheel_connectors-b0qqv",
        "flywheel_connectors-c5bmr",
        "flywheel_connectors-4kw5f.9.6.1",
        "flywheel_connectors-4kw5f.9.6",
        "flywheel_connectors-2zfc5",
        "flywheel_connectors-p3pd4",
        "flywheel_connectors-d9us6"
      ],
      required_2zfc5_scenarios: [
        "runtime_network_policy.managed_missing_per_op",
        "runtime_network_policy.manifest_missing_per_op",
        "runtime_network_policy.host_allow_fallback_denied",
        "runtime_network_policy.wildcard_host_allow_denied",
        "runtime_network_policy.missing_port_allow_denied",
        "runtime_network_policy.missing_require_sni_denied",
        "runtime_network_policy.missing_deny_private_ranges_denied",
        "runtime_network_policy.unsupported_placeholder_denied",
        "runtime_network_policy.matrix_placeholder_success",
        "runtime_network_policy.local_lan_exception_success",
        "runtime_network_policy.two_op_a_allows_a",
        "runtime_network_policy.two_op_a_denies_b",
        "runtime_network_policy.two_op_b_allows_b",
        "runtime_network_policy.two_op_b_denies_a",
        "runtime_network_policy.redaction_scan"
      ],
      required_c5bmr_scenarios: [
        "https_spki_allowed",
        "https_spki_denied",
        "tcp_tls_spki_allowed",
        "tcp_tls_spki_denied"
      ],
      required_4kw5f_9_6_1_scenarios: [
        "host_egress_proxy_tls_transport.https_extra_ca_success",
        "host_egress_proxy_tls_transport.tcp_tls_extra_ca_success",
        "host_egress_proxy_transport.redirect_denied",
        "host_egress_proxy_transport.response_size_denied",
        "host_egress_proxy_transport.sni_denied"
      ],
      required_b0qqv_scenarios: [
        "sdk_https_proxy_routing",
        "sdk_tls_tcp_proxy_routing",
        "sdk_denied_structured_error",
        "sdk_redaction_scan"
      ],
      required_hx0gw_scenarios: [
        "os_sandbox_direct_socket_denied",
        "os_sandbox_proxy_allowed",
        "os_sandbox_proxy_policy_denied",
        "os_sandbox_redaction_scan"
      ],
      evidence_count: ($evidence_count | tonumber),
      evidence_result_counts: (
        [inputs] as $records
        | {
            pass: ($records | map(select(.result == "pass")) | length),
            skip: ($records | map(select(.result == "skip")) | length),
            fail: ($records | map(select(.result == "fail")) | length)
          }
      ),
      step_result_counts: (
        {
          pass: (($steps | map(select(.result == "pass")) | length) + 1),
          skip: ($steps | map(select(.result == "skip")) | length),
          fail: ($steps | map(select(.result == "fail")) | length)
        }
      ),
      artifacts: {
        host_test_log: $host_test_log,
        sdk_test_log: $sdk_test_log,
        sandbox_test_log: $sandbox_test_log,
        evidence_jsonl: $evidence_jsonl,
        steps_jsonl: $steps_jsonl
      },
      rerun: ("USE_RCH=1 scripts/e2e/runtime_network_policy_verification.sh --run-id=" + $run_id)
    }' "${EVIDENCE_JSONL}" >"${SUMMARY_JSON}"
}

require_cmd cargo
require_cmd jq
mkdir -p "${OUT_ROOT}"
: >"${STEPS_JSONL}"

run_logged_step "runtime_network_policy_test" 1 "[\"${HOST_TEST_LOG}\"]" run_policy_test
run_logged_step "sdk_host_egress_proxy_test" 2 "[\"${SDK_TEST_LOG}\"]" run_sdk_proxy_test
run_logged_step "os_sandbox_network_policy_test" 3 "[\"${SANDBOX_TEST_LOG}\"]" run_os_sandbox_test
run_logged_step "extract_decision_jsonl" 4 "[\"${EVIDENCE_JSONL}\"]" extract_evidence
run_logged_step "validate_decision_jsonl" 5 "[\"${EVIDENCE_JSONL}\"]" validate_jsonl "${EVIDENCE_JSONL}"
run_logged_step "validate_required_scenarios" 6 "[\"${EVIDENCE_JSONL}\"]" validate_required_scenarios
run_logged_step "validate_steps_jsonl" 7 "[\"${STEPS_JSONL}\"]" validate_jsonl "${STEPS_JSONL}"
run_logged_step "write_summary" 8 "[\"${SUMMARY_JSON}\"]" write_summary

echo "${SCRIPT_NAME} complete"
echo "  steps: ${STEPS_JSONL}"
echo "  decisions: ${EVIDENCE_JSONL}"
echo "  summary: ${SUMMARY_JSON}"
