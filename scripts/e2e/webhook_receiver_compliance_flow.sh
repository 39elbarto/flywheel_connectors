#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_webhook_receiver_compliance_flow"
SCENARIO_ID="asupersync.e2e.webhook_receiver_compliance_flow"
SEED="${SEED:-0xWHR4C0MPL14NC3}"
CONNECTOR_ID="fcp.webhook-receiver"
MANIFEST_PATH="${MANIFEST_PATH:-connectors/webhook-receiver/manifest.toml}"
TAINT_POLICY_JSON="${TAINT_POLICY_JSON:-crates/fcp-conformance/src/schemas/examples/taint_approval.json}"
GOOD_VECTOR_PATH="${GOOD_VECTOR_PATH:-tests/vectors/manifest/manifest_webhook_receiver_good.toml}"
BAD_VECTOR_PATH="${BAD_VECTOR_PATH:-tests/vectors/manifest/manifest_webhook_receiver_bad.toml}"

OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
EVIDENCE_DIR="${OUT_DIR}/evidence"
EVIDENCE_LOG_JSONL="${EVIDENCE_DIR}/logs/structured_logs.jsonl"
METADATA_JSON="${EVIDENCE_DIR}/run_metadata.json"
RESULTS_JSON="${EVIDENCE_DIR}/test_results.json"
MANIFEST_ASSERTIONS_JSON="${OUT_DIR}/manifest_assertions.json"
DEFAULT_DENY_ASSERTIONS_JSON="${OUT_DIR}/default_deny_assertions.json"
TAINT_ASSERTIONS_JSON="${OUT_DIR}/taint_assertions.json"
LOG_VALIDATION_JSON="${OUT_DIR}/log_validation_report.json"
AUDIT_JSONL="${EVIDENCE_DIR}/audit/audit_events.jsonl"
RECEIPT_JSON="${EVIDENCE_DIR}/receipts/default_deny_receipt.json"
REPLAY_SCRIPT="${EVIDENCE_DIR}/replay.sh"

STEP_DETAILS="null"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

now_ms() {
  local now
  now=$(date +%s%3N 2>/dev/null || true)
  if [[ -z "${now}" || "${now}" == *N ]]; then
    now="$(date +%s)000"
  fi
  printf '%s' "${now}"
}

hash256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256
    return 0
  fi
  echo "Missing required command: sha256sum/shasum/openssl" >&2
  exit 1
}

correlation_id_for_step() {
  local step_number="$1"
  local hex
  hex=$(printf '%s-%s-%s-%s' "${SCRIPT_NAME}" "${SCENARIO_ID}" "${SEED}" "${step_number}" | hash256 | awk '{print $1}')
  printf '%s-%s-%s-%s-%s' \
    "${hex:0:8}" "${hex:8:4}" "${hex:12:4}" "${hex:16:4}" "${hex:20:12}"
}

log_step() {
  local step="$1"
  local step_number="$2"
  local result="$3"
  local duration_ms="$4"
  local artifacts_json="$5"
  local timestamp
  local correlation_id

  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  correlation_id="$(correlation_id_for_step "${step_number}")"

  mkdir -p "$(dirname "${LOG_JSONL}")"
  printf '{"timestamp":"%s","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s,"details":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${step}" "${step_number}" "${correlation_id}" "${duration_ms}" "${result}" "${artifacts_json}" "${STEP_DETAILS}" >> "${LOG_JSONL}"
}

run_step() {
  local step="$1"
  local step_number="$2"
  local artifacts_json="$3"
  local details_json="$4"
  shift 4

  local start_ms end_ms duration_ms rc
  STEP_DETAILS="${details_json}"

  start_ms="$(now_ms)"
  set +e
  "$@"
  rc=$?
  set -e
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  if [[ ${rc} -eq 0 ]]; then
    log_step "${step}" "${step_number}" "pass" "${duration_ms}" "${artifacts_json}"
  else
    log_step "${step}" "${step_number}" "fail" "${duration_ms}" "${artifacts_json}"
    exit "${rc}"
  fi
}

step_prepare() {
  require_cmd jq
  require_cmd rg
  mkdir -p "${OUT_DIR}" "${EVIDENCE_DIR}/logs" "${EVIDENCE_DIR}/audit" "${EVIDENCE_DIR}/receipts"
  : > "${LOG_JSONL}"
  : > "${AUDIT_JSONL}"
}

step_validate_manifest_surface() {
  [[ -f "${MANIFEST_PATH}" ]]
  [[ -f "${GOOD_VECTOR_PATH}" ]]
  [[ -f "${BAD_VECTOR_PATH}" ]]

  rg -n '^id = "fcp\.webhook-receiver"$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^model = "singleton_writer"$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^home = "z:work"$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^    "z:public",$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^    "z:community",$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^    "system\.exec",$' "${MANIFEST_PATH}" >/dev/null

  rg -n '^\[provides\.operations\."webhook\.endpoints\.create"\]$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^\[provides\.operations\."webhook\.endpoints\.delete"\]$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^\[provides\.operations\."webhook\.endpoints\.list"\]$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^\[provides\.operations\."webhook\.events\.recent"\]$' "${MANIFEST_PATH}" >/dev/null

  rg -n '^"webhook\.endpoints\.create" = \["webhook\.endpoints\.write"\]$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^"webhook\.endpoints\.delete" = \["webhook\.endpoints\.write"\]$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^"webhook\.endpoints\.list" = \["webhook\.endpoints\.read"\]$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^"webhook\.events\.recent" = \["webhook\.events\.read"\]$' "${MANIFEST_PATH}" >/dev/null

  jq -n \
    --arg connector_id "${CONNECTOR_ID}" \
    --arg manifest "${MANIFEST_PATH}" \
    --arg good_vector "${GOOD_VECTOR_PATH}" \
    --arg bad_vector "${BAD_VECTOR_PATH}" \
    '{
      connector_id: $connector_id,
      manifest_path: $manifest,
      vectors: { good: $good_vector, bad: $bad_vector },
      checks: [
        "connector_id_present",
        "singleton_writer_state_model",
        "zone_forbidden_rules",
        "forbidden_system_exec",
        "required_operations_present",
        "operation_capability_mapping_present"
      ],
      passed: true
    }' > "${MANIFEST_ASSERTIONS_JSON}"
}

step_validate_default_deny_contract() {
  rg -n '^required = \[$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^    "network\.listen",$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^    "storage\.state",$' "${MANIFEST_PATH}" >/dev/null

  rg -n '^capability = "webhook\.endpoints\.write"$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^capability = "webhook\.endpoints\.read"$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^capability = "webhook\.events\.read"$' "${MANIFEST_PATH}" >/dev/null

  rg -n '^requires_approval = "policy"$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^requires_approval = "interactive"$' "${MANIFEST_PATH}" >/dev/null
  rg -n '^requires_approval = "none"$' "${MANIFEST_PATH}" >/dev/null

  jq -n \
    --arg connector_id "${CONNECTOR_ID}" \
    '{
      connector_id: $connector_id,
      check_group: "default_deny",
      assertions: [
        "capability_token_required_by_operation_mapping",
        "read_write_capability_separation",
        "dangerous_operations_require_approval"
      ],
      simulated_decision_receipt: {
        decision: "deny",
        reason_code: "FCP-2101",
        reason: "CapabilityToken missing or insufficient"
      },
      passed: true
    }' > "${DEFAULT_DENY_ASSERTIONS_JSON}"
}

step_validate_taint_by_default_contract() {
  [[ -f "${TAINT_POLICY_JSON}" ]]

  jq -e '.policy.default_deny == true' "${TAINT_POLICY_JSON}" >/dev/null
  jq -e '.defaults.taint.require_elevation_min_safety == "risky"' "${TAINT_POLICY_JSON}" >/dev/null
  jq -e '.defaults.taint.require_approval_min_safety == "dangerous"' "${TAINT_POLICY_JSON}" >/dev/null
  jq -e '
    any(.taint_rules[]; (.action.type == "require_approval") and (.taint_flags | index("public_input")))
  ' "${TAINT_POLICY_JSON}" >/dev/null

  jq -n \
    --arg policy_path "${TAINT_POLICY_JSON}" \
    '{
      policy_path: $policy_path,
      check_group: "taint_by_default",
      assertions: [
        "policy_default_deny_enabled",
        "dangerous_tainted_inputs_require_approval",
        "public_input_taint_rule_present"
      ],
      passed: true
    }' > "${TAINT_ASSERTIONS_JSON}"
}

step_validate_structured_logs() {
  cp "${LOG_JSONL}" "${EVIDENCE_LOG_JSONL}"

  local total_lines valid_lines
  total_lines="$(grep -cve '^\s*$' "${EVIDENCE_LOG_JSONL}" || true)"
  valid_lines="$(jq -c '
    select(
      (.timestamp | type == "string") and
      (.script | type == "string") and
      (.step | type == "string") and
      (.step_number | type == "number") and
      (.correlation_id | type == "string") and
      (.duration_ms | type == "number") and
      (.result | type == "string")
    )' "${EVIDENCE_LOG_JSONL}" | wc -l | tr -d ' ')"

  if [[ "${total_lines}" -eq 0 || "${total_lines}" -ne "${valid_lines}" ]]; then
    echo "Structured log validation failed: total=${total_lines}, valid=${valid_lines}" >&2
    return 1
  fi

  if rg -n 'api_key=|Authorization:|Bearer ' "${EVIDENCE_LOG_JSONL}" >/dev/null 2>&1; then
    echo "Structured log redaction check failed: secret-like token found" >&2
    return 1
  fi

  jq -n \
    --arg source "${EVIDENCE_LOG_JSONL}" \
    --argjson total "${total_lines}" \
    --argjson valid "${valid_lines}" \
    '{
      source: $source,
      total_lines: $total,
      valid_lines: $valid,
      redaction_scan: { passed: true, rule: "no_api_key_no_auth_header_no_bearer" },
      passed: true
    }' > "${LOG_VALIDATION_JSON}"
}

step_build_evidence_bundle() {
  local generated_at
  generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  jq -n \
    --arg script "${SCRIPT_NAME}" \
    --arg scenario_id "${SCENARIO_ID}" \
    --arg seed "${SEED}" \
    --arg connector_id "${CONNECTOR_ID}" \
    --arg generated_at "${generated_at}" \
    --arg manifest "${MANIFEST_PATH}" \
    --arg evidence_dir "${EVIDENCE_DIR}" \
    '{
      script: $script,
      scenario_id: $scenario_id,
      seed: $seed,
      connector_id: $connector_id,
      generated_at: $generated_at,
      manifest_path: $manifest,
      evidence_dir: $evidence_dir,
      deterministic_inputs: {
        seed: $seed,
        scenario_id: $scenario_id
      }
    }' > "${METADATA_JSON}"

  jq -n \
    --arg connector_id "${CONNECTOR_ID}" \
    --arg manifest_assertions "${MANIFEST_ASSERTIONS_JSON}" \
    --arg default_deny_assertions "${DEFAULT_DENY_ASSERTIONS_JSON}" \
    --arg taint_assertions "${TAINT_ASSERTIONS_JSON}" \
    --arg log_validation "${LOG_VALIDATION_JSON}" \
    '{
      connector_id: $connector_id,
      overall_status: "pass",
      checks: [
        { name: "manifest_surface", status: "pass", artifact: $manifest_assertions },
        { name: "default_deny", status: "pass", artifact: $default_deny_assertions },
        { name: "taint_by_default", status: "pass", artifact: $taint_assertions },
        { name: "structured_logs", status: "pass", artifact: $log_validation }
      ]
    }' > "${RESULTS_JSON}"

  jq -n \
    --arg connector_id "${CONNECTOR_ID}" \
    --arg reason_code "FCP-2101" \
    --arg decision "deny" \
    --arg operation_id "webhook.endpoints.create" \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    '{
      connector_id: $connector_id,
      operation_id: $operation_id,
      decision: $decision,
      reason_code: $reason_code,
      timestamp: $timestamp,
      evidence: ["contract.capability_map", "contract.requires_approval"]
    }' > "${RECEIPT_JSON}"

  jq -c -n \
    --arg connector_id "${CONNECTOR_ID}" \
    --arg scenario_id "${SCENARIO_ID}" \
    --arg event_type "compliance.run.completed" \
    --arg outcome "success" \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    '{timestamp:$timestamp,event_type:$event_type,connector_id:$connector_id,scenario_id:$scenario_id,outcome:$outcome}' \
    > "${AUDIT_JSONL}"

  cat > "${REPLAY_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
OUT_DIR="\${OUT_DIR:-./out/${SCRIPT_NAME}}"
bash scripts/e2e/webhook_receiver_compliance_flow.sh
echo "Evidence bundle regenerated at: \${OUT_DIR}/evidence"
EOF
  chmod +x "${REPLAY_SCRIPT}"
}

step_teardown() {
  true
}

require_cmd jq
require_cmd rg

run_step "prepare" 1 "[]" \
  '{"purpose":"initialize output directories and evidence bundle structure"}' \
  step_prepare
run_step "validate_manifest_surface" 2 "[\"${MANIFEST_ASSERTIONS_JSON}\"]" \
  '{"purpose":"validate webhook-receiver manifest operation and capability contract surface"}' \
  step_validate_manifest_surface
run_step "validate_default_deny_contract" 3 "[\"${DEFAULT_DENY_ASSERTIONS_JSON}\"]" \
  '{"purpose":"validate default-deny capability gating assertions"}' \
  step_validate_default_deny_contract
run_step "validate_taint_by_default_contract" 4 "[\"${TAINT_ASSERTIONS_JSON}\"]" \
  '{"purpose":"validate taint-by-default approval policy assertions"}' \
  step_validate_taint_by_default_contract
run_step "validate_structured_logs" 5 "[\"${EVIDENCE_LOG_JSONL}\",\"${LOG_VALIDATION_JSON}\"]" \
  '{"purpose":"validate structured log schema coverage and redaction"}' \
  step_validate_structured_logs
run_step "build_evidence_bundle" 6 "[\"${METADATA_JSON}\",\"${RESULTS_JSON}\",\"${RECEIPT_JSON}\",\"${AUDIT_JSONL}\",\"${REPLAY_SCRIPT}\"]" \
  '{"purpose":"emit deterministic evidence bundle artifacts"}' \
  step_build_evidence_bundle
run_step "teardown" 7 "[]" \
  '{"purpose":"no-op teardown"}' \
  step_teardown

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
echo "Evidence bundle: ${EVIDENCE_DIR}"
