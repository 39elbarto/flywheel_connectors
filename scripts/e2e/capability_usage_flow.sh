#!/usr/bin/env bash
set -euo pipefail

# E2E: Capability Usage -> Suggestion Flow
# Validates that fcp capabilities report/suggest/export work end-to-end.
# Bead: flywheel_connectors-3qss

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_NAME="capability_usage_flow"
SEED="0xCAFEBABE"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
TARGET_DIR="${CAP_USAGE_TARGET_DIR:-/tmp/fcp-cap-usage-flow}"

REPORT_JSON="${OUT_DIR}/report.json"
SUGGEST_JSON="${OUT_DIR}/suggest.json"
EXPORT_JSON="${OUT_DIR}/export.json"
VERIFICATION_SUMMARY="${OUT_DIR}/capability_usage_contract_summary.json"

STEP_CONTEXT="null"
STEP_MODULE="unknown"
STEP_TEST="unknown"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

run_cargo() {
  if command -v rch >/dev/null 2>&1; then
    rch exec -- cargo "$@"
    return $?
  fi
  cargo "$@"
}

run_fcp() {
  if command -v fcp >/dev/null 2>&1; then
    fcp "$@"
    return $?
  fi
  run_cargo run --target-dir "${TARGET_DIR}" -q -p fcp-cli --bin fcp -- "$@"
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
  hex=$(printf '%s-%s-%s' "${SCRIPT_NAME}" "${SEED}" "${step_number}" | hash256 | awk '{print $1}')
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
  local details

  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  correlation_id="$(correlation_id_for_step "${step_number}")"
  details="$(jq -cn \
    --arg module "${STEP_MODULE}" \
    --arg test_name "${STEP_TEST}" \
    --arg seed "${SEED}" \
    --argjson extra "${STEP_CONTEXT:-null}" \
    '($extra | if type == "object" then . else {} end) + {
      module: $module,
      test_name: $test_name,
      seed: $seed
    }')"

  mkdir -p "$(dirname "${LOG_JSONL}")"
  printf '{"timestamp":"%s","log_version":"v2","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s,"details":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${step}" "${step_number}" "${correlation_id}" \
    "${duration_ms}" "${result}" "${artifacts_json}" "${details}" >> "${LOG_JSONL}"
}

run_step() {
  local step="$1"
  local step_number="$2"
  local artifacts_json="$3"
  shift 3

  local start_ms end_ms duration_ms rc
  STEP_CONTEXT="null"
  STEP_MODULE="unknown"
  STEP_TEST="unknown"
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
    exit ${rc}
  fi
}

# ---------------------------------------------------------------------------
# Step 1: Run unit tests for capabilities module
# ---------------------------------------------------------------------------
step_run_capabilities_unit_tests() {
  STEP_MODULE="fcp-cli::capabilities"
  STEP_TEST="capabilities_unit_tests"
  local log_path="${OUT_DIR}/capabilities_unit_tests.log"
  mkdir -p "$(dirname "${log_path}")"
  (
    cd "${REPO_ROOT}"
    run_cargo test --target-dir "${TARGET_DIR}" -p fcp-cli -- capabilities --nocapture
  ) > "${log_path}" 2>&1
  local test_count
  test_count=$(grep -c '^test capabilities::' "${log_path}" || echo "0")
  STEP_CONTEXT="$(jq -cn --argjson tc "${test_count}" '{test_count: $tc}')"
}

# ---------------------------------------------------------------------------
# Step 2: Generate capabilities report (JSON)
# ---------------------------------------------------------------------------
step_generate_report_json() {
  STEP_MODULE="fcp-cli::capabilities::report"
  STEP_TEST="report_json_output"
  mkdir -p "${OUT_DIR}"
  run_fcp capabilities report --json > "${REPORT_JSON}"
  # Validate the report has expected structure
  jq -e '.schema_version' "${REPORT_JSON}" > /dev/null
  jq -e '.zones | length > 0' "${REPORT_JSON}" > /dev/null
  jq -e '.totals.total > 0' "${REPORT_JSON}" > /dev/null
  local zone_count total_events unused_count
  zone_count=$(jq '.zones | length' "${REPORT_JSON}")
  total_events=$(jq '.totals.total' "${REPORT_JSON}")
  unused_count=$(jq '[.zones[].capabilities[] | select(.total == 0)] | length' "${REPORT_JSON}")
  STEP_CONTEXT="$(jq -cn --argjson zc "${zone_count}" --argjson te "${total_events}" --argjson uc "${unused_count}" \
    '{zone_count: $zc, total_events: $te, unused_count: $uc}')"
}

# ---------------------------------------------------------------------------
# Step 3: Generate suggestions (JSON)
# ---------------------------------------------------------------------------
step_generate_suggest_json() {
  STEP_MODULE="fcp-cli::capabilities::suggest"
  STEP_TEST="suggest_json_output"
  run_fcp capabilities suggest --json > "${SUGGEST_JSON}"
  # Validate suggestions structure
  jq -e '.schema_version' "${SUGGEST_JSON}" > /dev/null
  jq -e '.summary' "${SUGGEST_JSON}" > /dev/null
  local remove_count review_count keep_count
  remove_count=$(jq '.summary.remove_count' "${SUGGEST_JSON}")
  review_count=$(jq '.summary.review_count' "${SUGGEST_JSON}")
  keep_count=$(jq '.summary.keep_count' "${SUGGEST_JSON}")
  # At least some suggestions should exist
  local total_suggestions=$((remove_count + review_count + keep_count))
  [[ ${total_suggestions} -gt 0 ]]
  STEP_CONTEXT="$(jq -cn --argjson rc "${remove_count}" --argjson rv "${review_count}" --argjson kc "${keep_count}" \
    '{remove_count: $rc, review_count: $rv, keep_count: $kc}')"
}

# ---------------------------------------------------------------------------
# Step 4: Verify unused capabilities flagged for removal
# ---------------------------------------------------------------------------
step_verify_unused_flagged() {
  STEP_MODULE="fcp-cli::capabilities::suggest"
  STEP_TEST="unused_flagged_for_removal"
  # Report should show unused capabilities (0 total usage)
  local unused_count
  unused_count=$(jq '[.zones[].capabilities[] | select(.total == 0)] | length' "${REPORT_JSON}")
  # Suggest should recommend removing at least some
  local remove_count
  remove_count=$(jq '.summary.remove_count' "${SUGGEST_JSON}")
  # If there are unused caps, suggestions should recommend removal
  if [[ ${unused_count} -gt 0 ]]; then
    [[ ${remove_count} -gt 0 ]]
  fi
  STEP_CONTEXT="$(jq -cn --argjson uc "${unused_count}" --argjson rc "${remove_count}" \
    '{unused_in_report: $uc, flagged_for_removal: $rc}')"
}

# ---------------------------------------------------------------------------
# Step 5: Export raw aggregates
# ---------------------------------------------------------------------------
step_export_raw_aggregates() {
  STEP_MODULE="fcp-cli::capabilities::export"
  STEP_TEST="export_json_output"
  run_fcp capabilities export > "${EXPORT_JSON}"
  # Validate export has entries
  jq -e '.schema_version' "${EXPORT_JSON}" > /dev/null
  jq -e '.aggregates | length > 0' "${EXPORT_JSON}" > /dev/null
  local aggregate_count
  aggregate_count=$(jq '.aggregates | length' "${EXPORT_JSON}")
  STEP_CONTEXT="$(jq -cn --argjson ac "${aggregate_count}" '{aggregate_count: $ac}')"
}

# ---------------------------------------------------------------------------
# Step 6: Verify zone-filtered suggest
# ---------------------------------------------------------------------------
step_verify_zone_filter() {
  STEP_MODULE="fcp-cli::capabilities::suggest"
  STEP_TEST="zone_filter_narrows_results"
  local filtered_json="${OUT_DIR}/suggest_filtered.json"
  run_fcp capabilities suggest --json --zone "z:work" > "${filtered_json}"
  local filtered_total unfiltered_total
  filtered_total=$(jq '[.recommendations[]] | length' "${filtered_json}")
  unfiltered_total=$(jq '[.recommendations[]] | length' "${SUGGEST_JSON}")
  # Filtered should be <= unfiltered
  [[ ${filtered_total} -le ${unfiltered_total} ]]
  STEP_CONTEXT="$(jq -cn --argjson ft "${filtered_total}" --argjson ut "${unfiltered_total}" \
    '{filtered_count: $ft, unfiltered_count: $ut}')"
}

# ---------------------------------------------------------------------------
# Step 7: Verify suggestion determinism
# ---------------------------------------------------------------------------
step_verify_determinism() {
  STEP_MODULE="fcp-cli::capabilities::suggest"
  STEP_TEST="suggestions_deterministic"
  local run2_json="${OUT_DIR}/suggest_run2.json"
  run_fcp capabilities suggest --json > "${run2_json}"
  # Recommendations should be identical
  local diff_count
  diff_count=$(diff <(jq -S '.recommendations' "${SUGGEST_JSON}") <(jq -S '.recommendations' "${run2_json}") | wc -l || true)
  [[ ${diff_count} -eq 0 ]]
  STEP_CONTEXT='{"deterministic": true}'
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
generate_summary() {
  local total_steps="$1"
  local pass_count fail_count
  pass_count=$(grep -c '"result":"pass"' "${LOG_JSONL}" || echo "0")
  fail_count=$(grep -c '"result":"fail"' "${LOG_JSONL}" || echo "0")
  jq -cn \
    --arg script "${SCRIPT_NAME}" \
    --arg seed "${SEED}" \
    --argjson total "${total_steps}" \
    --argjson pass "${pass_count}" \
    --argjson fail "${fail_count}" \
    '{
      script: $script,
      seed: $seed,
      total_steps: $total,
      passed: $pass,
      failed: $fail,
      result: (if $fail == 0 then "PASS" else "FAIL" end)
    }' > "${VERIFICATION_SUMMARY}"
  cat "${VERIFICATION_SUMMARY}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  require_cmd jq
  require_cmd cargo

  rm -rf "${OUT_DIR}"
  mkdir -p "${OUT_DIR}"

  echo "=== Capability Usage -> Suggestion Flow ==="
  echo "  Seed:    ${SEED}"
  echo "  Output:  ${OUT_DIR}"
  echo ""

  run_step "unit_tests"            1 '{}' step_run_capabilities_unit_tests
  echo "[1/7] Unit tests: PASS"

  run_step "generate_report"       2 '{}' step_generate_report_json
  echo "[2/7] Report generation: PASS"

  run_step "generate_suggestions"  3 '{}' step_generate_suggest_json
  echo "[3/7] Suggestion generation: PASS"

  run_step "verify_unused_flagged" 4 '{}' step_verify_unused_flagged
  echo "[4/7] Unused caps flagged: PASS"

  run_step "export_aggregates"     5 '{}' step_export_raw_aggregates
  echo "[5/7] Export aggregates: PASS"

  run_step "zone_filter"           6 '{}' step_verify_zone_filter
  echo "[6/7] Zone filter: PASS"

  run_step "determinism"           7 '{}' step_verify_determinism
  echo "[7/7] Determinism: PASS"

  echo ""
  generate_summary 7
}

main "$@"
