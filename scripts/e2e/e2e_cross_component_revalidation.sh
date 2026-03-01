#!/usr/bin/env bash
# =============================================================================
# e2e_cross_component_revalidation.sh — Cross-Component E2E Revalidation Pack
# =============================================================================
# Bead:     235t.27.2 (ASUPERSYNC-VALIDATION Cross-Component E2E Revalidation)
# Schema:   asupersync-cross-component-revalidation/v1
#
# Validates end-to-end data paths spanning multiple crates/connectors to prove
# the async migration preserved cross-boundary behavioral contracts.
#
# Data Paths:
#   1. Host → SDK → Connector lifecycle (discovery, introspection, rate limits)
#   2. Error taxonomy chain (AsyncError → FcpError → Wire → Retryability)
#   3. Store → RaptorQ → Repair convergence (encode, distribute, repair, decode)
#   4. Mesh → Store → Protocol (routing, admission, symbol transfer, decode)
#   5. Conformance → Harness → Integration (distributed scenarios, partition)
#   6. Connector integration (all 6 connectors: lifecycle, error mapping, auth)
#   7. User-journey E2E flows (request-response, polling, webhook delivery)
#   8. Failure-recovery stress (timeout storms, cursor gaps, retry cascades)
#
# Usage:
#   bash scripts/e2e/e2e_cross_component_revalidation.sh [options]
#
# Options:
#   --run-id <id>           Stable run identifier (default: UTC timestamp)
#   --out-root <path>       Artifact root directory
#   --dry-run               Emit plan without executing tests
#   --only-paths <csv>      Filter paths (host_sdk,error_chain,store_raptorq,
#                           mesh_store,conformance,connectors,user_journeys,
#                           failure_recovery)
#   --ci                    CI mode (strict: warnings → errors)
#   -h, --help              Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GATE_SCHEMA="asupersync-cross-component-revalidation/v1"
FORENSICS_SCHEMA="asupersync-forensics/v1"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT=""
DRY_RUN=false
CI_MODE="${CI:-false}"
ONLY_PATHS=""

declare -i PATH_PASS=0
declare -i PATH_FAIL=0
declare -i PATH_SKIP=0
declare -i PATH_WARN=0
declare -a DRIFT_RECORDS=()
declare -a REGRESSION_SUMMARIES=()

usage() {
  cat <<'EOF'
Usage: scripts/e2e/e2e_cross_component_revalidation.sh [options]

Cross-Component E2E Revalidation Pack (Script-Driven)

Validates end-to-end data paths spanning multiple crates/connectors after
async runtime migration. Emits forensics/v1 evidence bundles with
actionable diagnostics and deterministic replay.

Options:
  --run-id <id>           Stable run identifier (default: UTC timestamp)
  --out-root <path>       Artifact root (default: artifacts/asupersync/cross-component/<run-id>)
  --dry-run               Emit plan without executing tests
  --only-paths <csv>      Filter: host_sdk,error_chain,store_raptorq,mesh_store,
                          conformance,connectors,user_journeys,failure_recovery
  --ci                    CI mode (warnings promoted to errors)
  -h, --help              Show this help
EOF
}

# ── Utility ─────────────────────────────────────────────────────────────────

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: Missing required command: $1" >&2
    exit 1
  fi
}

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

now_ms() {
  local now
  now=$(date +%s%3N 2>/dev/null || true)
  if [[ -z "${now}" || "${now}" == *N ]]; then
    now="$(date +%s)000"
  fi
  printf '%s' "${now}"
}

log_step() {
  printf '[%s] [CROSS-COMPONENT/%s] %s\n' "$(now_iso)" "$1" "$2"
}

record_step() {
  local scenario_id="$1"
  local operation="$2"
  local outcome="$3"
  local elapsed_ms="$4"
  local contract_id="${5:-n/a}"
  local connector="${6:-n/a}"
  local reason="${7:-}"
  local log_path="${8:-}"

  jq -c -n \
    --arg schema_version "${FORENSICS_SCHEMA}" \
    --arg run_id "${RUN_ID}" \
    --arg scenario_id "${scenario_id}" \
    --arg trace_id "${RUN_ID}-${scenario_id}" \
    --arg correlation_id "${RUN_ID}" \
    --arg connector "${connector}" \
    --arg zone "n/a" \
    --arg operation "${operation}" \
    --argjson attempt 1 \
    --argjson timeout_budget_ms 600000 \
    --arg outcome "${outcome}" \
    --argjson elapsed_ms "${elapsed_ms}" \
    --arg contract_id "${contract_id}" \
    --arg reason "${reason}" \
    --arg log_path "${log_path}" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      scenario_id: $scenario_id,
      trace_id: $trace_id,
      correlation_id: $correlation_id,
      connector: $connector,
      zone: $zone,
      operation: $operation,
      attempt: $attempt,
      timeout_budget_ms: $timeout_budget_ms,
      cancellation_reason: null,
      queue_depth: null,
      decode_budget: null,
      outcome: $outcome,
      elapsed_ms: $elapsed_ms,
      contract_id: (if ($contract_id | length) > 0 then $contract_id else null end),
      reason: (if ($reason | length) > 0 then $reason else null end),
      log_path: (if ($log_path | length) > 0 then $log_path else null end)
    }' >> "${STEPS_FILE}"
}

add_drift() {
  local path_name="$1"
  local test_name="$2"
  local classification="$3"
  local contract_id="$4"
  local reason="$5"
  local rerun_cmd="$6"
  local d
  d="$(jq -c -n \
    --arg path "${path_name}" \
    --arg test_name "${test_name}" \
    --arg classification "${classification}" \
    --arg contract_id "${contract_id}" \
    --arg reason "${reason}" \
    --arg rerun_command "${rerun_cmd}" \
    --arg run_id "${RUN_ID}" \
    '{
      path: $path,
      test_name: $test_name,
      classification: $classification,
      contract_id: $contract_id,
      reason: $reason,
      rerun_command: $rerun_command,
      run_id: $run_id
    }')"
  DRIFT_RECORDS+=("${d}")
}

add_regression() {
  local path_name="$1"
  local test_name="$2"
  local contract_id="$3"
  local reason="$4"
  local rerun_cmd="$5"
  local r
  r="$(jq -c -n \
    --arg path "${path_name}" \
    --arg test_name "${test_name}" \
    --arg contract_id "${contract_id}" \
    --arg reason "${reason}" \
    --arg rerun_command "${rerun_cmd}" \
    '{
      path: $path,
      test_name: $test_name,
      contract_id: $contract_id,
      reason: $reason,
      rerun_command: $rerun_command
    }')"
  REGRESSION_SUMMARIES+=("${r}")
}

should_run_path() {
  local path_name="$1"
  if [[ -z "${ONLY_PATHS}" ]]; then
    return 0
  fi
  echo ",${ONLY_PATHS}," | grep -q ",${path_name}," && return 0
  return 1
}

# Run a cargo test with forensics tracking and drift classification
run_cross_test() {
  local label="$1"
  local package="$2"
  local test_filter="$3"
  local contract_id="$4"
  local path_name="$5"
  local connector="${6:-n/a}"
  local log_file="${OUT_ROOT}/logs/${label}.log"
  local scenario_id="cross_component.${label}"

  mkdir -p "${OUT_ROOT}/logs"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_step "${label}" "[dry-run] cargo test -p ${package} ${test_filter}"
    echo "[dry-run] cargo test -p ${package} ${test_filter}" > "${log_file}"
    record_step "${scenario_id}" "cargo_test" "planned" 0 "${contract_id}" "${connector}" "dry_run" "${log_file}"
    PATH_SKIP=$((PATH_SKIP + 1))
    return 0
  fi

  local start end elapsed status
  start=$(now_ms)
  if command -v rch >/dev/null 2>&1; then
    if rch exec -- cargo test -p "${package}" ${test_filter} -- --nocapture > "${log_file}" 2>&1; then
      status="pass"
    else
      status="fail"
    fi
  else
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-cross-component}" \
      cargo test -p "${package}" ${test_filter} -- --nocapture > "${log_file}" 2>&1 && status="pass" || status="fail"
  fi
  end=$(now_ms)
  elapsed=$((end - start))

  if [[ "${status}" == "pass" ]]; then
    PATH_PASS=$((PATH_PASS + 1))
    log_step "${label}" "PASS (${elapsed}ms)"
    record_step "${scenario_id}" "cargo_test" "pass" "${elapsed}" "${contract_id}" "${connector}" "" "${log_file}"
  else
    PATH_FAIL=$((PATH_FAIL + 1))
    local reason
    reason="$(tail -5 "${log_file}" | head -3 | tr '\n' ' ' | head -c 200)"
    log_step "${label}" "FAIL (${elapsed}ms): ${reason}"
    record_step "${scenario_id}" "cargo_test" "fail" "${elapsed}" "${contract_id}" "${connector}" "${reason}" "${log_file}"
    add_drift "${path_name}" "${test_filter}" "regression" "${contract_id}" "${reason}" \
      "cargo test -p ${package} ${test_filter} -- --nocapture"
    add_regression "${path_name}" "${label}" "${contract_id}" "${reason}" \
      "cargo test -p ${package} ${test_filter} -- --nocapture"
  fi
}

# Run an E2E script with forensics tracking
run_e2e_script() {
  local label="$1"
  local script_path="$2"
  local contract_id="$3"
  local path_name="$4"
  local log_file="${OUT_ROOT}/logs/${label}.log"
  local scenario_id="cross_component.${label}"

  mkdir -p "${OUT_ROOT}/logs"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_step "${label}" "[dry-run] bash ${script_path}"
    echo "[dry-run] bash ${script_path}" > "${log_file}"
    record_step "${scenario_id}" "e2e_script" "planned" 0 "${contract_id}" "n/a" "dry_run" "${log_file}"
    PATH_SKIP=$((PATH_SKIP + 1))
    return 0
  fi

  local start end elapsed status
  start=$(now_ms)
  if bash -lc "set -euo pipefail; cd \"${REPO_ROOT}\"; bash \"${script_path}\"" > "${log_file}" 2>&1; then
    status="pass"
  else
    status="fail"
  fi
  end=$(now_ms)
  elapsed=$((end - start))

  if [[ "${status}" == "pass" ]]; then
    PATH_PASS=$((PATH_PASS + 1))
    log_step "${label}" "PASS (${elapsed}ms)"
    record_step "${scenario_id}" "e2e_script" "pass" "${elapsed}" "${contract_id}" "n/a" "" "${log_file}"
  else
    PATH_FAIL=$((PATH_FAIL + 1))
    local reason
    reason="$(tail -5 "${log_file}" | head -3 | tr '\n' ' ' | head -c 200)"
    log_step "${label}" "FAIL (${elapsed}ms): ${reason}"
    record_step "${scenario_id}" "e2e_script" "fail" "${elapsed}" "${contract_id}" "n/a" "${reason}" "${log_file}"
    add_drift "${path_name}" "$(basename "${script_path}")" "regression" "${contract_id}" "${reason}" \
      "bash ${script_path}"
    add_regression "${path_name}" "${label}" "${contract_id}" "${reason}" \
      "bash ${script_path}"
  fi
}

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)          RUN_ID="$2"; shift 2;;
    --out-root)        OUT_ROOT="$2"; shift 2;;
    --dry-run)         DRY_RUN=true; shift;;
    --only-paths)      ONLY_PATHS="$2"; shift 2;;
    --ci)              CI_MODE=true; shift;;
    -h|--help)         usage; exit 0;;
    *)                 echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

# ── Pre-flight ──────────────────────────────────────────────────────────────
require_cmd jq
require_cmd cargo

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/cross-component/${RUN_ID}"
fi
mkdir -p "${OUT_ROOT}/logs"

STEPS_FILE="${OUT_ROOT}/steps.jsonl"
SUMMARY_FILE="${OUT_ROOT}/summary.json"
DRIFT_FILE="${OUT_ROOT}/drift_classification.json"
REGRESSION_FILE="${OUT_ROOT}/regression_index.json"
REPLAY_FILE="${OUT_ROOT}/replay.sh"
PATH_COVERAGE_FILE="${OUT_ROOT}/path_coverage.json"

: > "${STEPS_FILE}"

log_step "INIT" "Cross-Component E2E Revalidation v1 — run_id=${RUN_ID}"
log_step "INIT" "Output: ${OUT_ROOT}"
echo ""

# =============================================================================
# Path 1: Host → SDK → Connector Lifecycle
# =============================================================================
# Validates: connector discovery, subprocess spawning, introspection,
#            rate-limit enforcement modes (hard/soft/advisory)
# Crates: fcp-host → fcp-sdk → connector registry
# =============================================================================
if should_run_path "host_sdk"; then
  log_step "HOST_SDK" "Path 1: Host → SDK → Connector lifecycle integration"

  # Host discovery with subprocess connectors (full lifecycle)
  run_cross_test "host_sdk_discovery" "fcp-host" \
    "--test host_connector_integration" \
    "contract.host_connector_lifecycle" \
    "host_sdk" "fcp.test-echo"

  # Agent integration (host → agent lifecycle)
  run_cross_test "host_sdk_agent" "fcp-host" \
    "--test agent_integration" \
    "contract.host_agent_lifecycle" \
    "host_sdk" "fcp.test-echo"

  # Rate limit enforcement (host → registry → rate limit policies)
  run_cross_test "host_sdk_rate_limits" "fcp-host" \
    "--test rate_limit_integration" \
    "contract.rate_limit_enforcement" \
    "host_sdk" "fcp.test-echo"

  # SDK retry integration (RetryLoop + backoff policy)
  run_cross_test "host_sdk_retry" "fcp-sdk" \
    "--test retry_integration" \
    "contract.retry_loop_execute" \
    "host_sdk"
else
  log_step "HOST_SDK" "Skipped (--only-paths filter)"
fi

# =============================================================================
# Path 2: Error Taxonomy Chain
# =============================================================================
# Validates: AsyncError → ConnectorError → FcpError → Wire serialization,
#            HTTP status classification, retryability contracts
# Crates: fcp-async-core → fcp-sdk → fcp-core
# =============================================================================
if should_run_path "error_chain"; then
  log_step "ERROR_CHAIN" "Path 2: Error taxonomy chain (AsyncError → FcpError → Wire)"

  # Full error contract test suite (46 tests spanning async → wire)
  run_cross_test "error_chain_contracts" "fcp-sdk" \
    "--test error_contract_tests" \
    "contract.error_taxonomy_chain" \
    "error_chain"

  # SDK migration module (connector error mapping)
  run_cross_test "error_chain_migration" "fcp-sdk" \
    "--lib migration::" \
    "contract.connector_error_mapping" \
    "error_chain"

  # Core error serialization (FcpError → JSON/CBOR roundtrip)
  run_cross_test "error_chain_core_serde" "fcp-core" \
    "--lib error::" \
    "contract.error_serialization" \
    "error_chain"
else
  log_step "ERROR_CHAIN" "Skipped (--only-paths filter)"
fi

# =============================================================================
# Path 3: Store → RaptorQ → Repair Convergence
# =============================================================================
# Validates: encode → store → reconstruct roundtrip, partial loss → repair,
#            multi-node symbol distribution, adversarial robustness
# Crates: fcp-store → fcp-raptorq → repair controller
# =============================================================================
if should_run_path "store_raptorq"; then
  log_step "STORE_RAPTORQ" "Path 3: Store → RaptorQ → Repair convergence"

  # Full store-repair integration suite
  run_cross_test "store_raptorq_roundtrip" "fcp-store" \
    "--test store_repair_integration encode_store_reconstruct" \
    "contract.encode_decode_roundtrip" \
    "store_raptorq"

  # Partial loss → repair convergence
  run_cross_test "store_raptorq_repair" "fcp-store" \
    "--test store_repair_integration partial_loss" \
    "contract.repair_convergence" \
    "store_raptorq"

  # Multi-node symbol distribution
  run_cross_test "store_raptorq_multinode" "fcp-store" \
    "--test store_repair_integration multi_node" \
    "contract.multinode_distribution" \
    "store_raptorq"

  # Adversarial symbol injection robustness
  run_cross_test "store_raptorq_adversarial" "fcp-store" \
    "--test store_repair_integration adversarial" \
    "contract.adversarial_symbol_robustness" \
    "store_raptorq"

  # OTI fidelity
  run_cross_test "store_raptorq_oti" "fcp-store" \
    "--test store_repair_integration oti_fidelity" \
    "contract.oti_fidelity" \
    "store_raptorq"
else
  log_step "STORE_RAPTORQ" "Skipped (--only-paths filter)"
fi

# =============================================================================
# Path 4: Mesh → Store → Protocol
# =============================================================================
# Validates: mesh routing, admission control, symbol transfer, decode status,
#            session auth gating, delivery guarantees
# Crates: fcp-mesh → fcp-store → fcp-protocol
# =============================================================================
if should_run_path "mesh_store"; then
  log_step "MESH_STORE" "Path 4: Mesh → Store → Protocol orchestration"

  # Symbol request handling (mesh → store symbol routing)
  run_cross_test "mesh_store_symbol_request" "fcp-mesh" \
    "--test mesh_integration meshnode_symbol_request" \
    "contract.mesh_symbol_routing" \
    "mesh_store"

  # Decode status feedback (mesh → store → decode completion)
  run_cross_test "mesh_store_decode_status" "fcp-mesh" \
    "--test mesh_integration meshnode_decode_status" \
    "contract.mesh_decode_feedback" \
    "mesh_store"

  # Multi-node symbol transfer (cross-node coordination)
  run_cross_test "mesh_store_multinode" "fcp-mesh" \
    "--test mesh_integration meshnode_multi_node" \
    "contract.mesh_multinode_transfer" \
    "mesh_store"

  # Admission control (byte budget enforcement via mesh)
  run_cross_test "mesh_store_admission" "fcp-mesh" \
    "--test mesh_integration admission" \
    "contract.mesh_admission_control" \
    "mesh_store"

  # Session auth gating (auth → session lifecycle)
  run_cross_test "mesh_store_auth" "fcp-mesh" \
    "--test mesh_integration session_auth" \
    "contract.mesh_session_auth" \
    "mesh_store"

  # Delivery guarantees (at-least-once, ordering)
  run_cross_test "mesh_store_delivery" "fcp-mesh" \
    "--test mesh_integration delivery" \
    "contract.mesh_delivery_guarantees" \
    "mesh_store"
else
  log_step "MESH_STORE" "Skipped (--only-paths filter)"
fi

# =============================================================================
# Path 5: Conformance → Harness → Integration Scenarios
# =============================================================================
# Validates: distributed scenario correctness (partition, split-brain,
#            crash recovery, quorum loss, key rotation)
# Crates: fcp-conformance → harness → simulated network
# =============================================================================
if should_run_path "conformance"; then
  log_step "CONFORMANCE" "Path 5: Conformance → Harness → Integration scenarios"

  # Full integration scenario suite (14 cluster scenarios)
  run_cross_test "conformance_integration" "fcp-conformance" \
    "--test integration_scenarios" \
    "contract.conformance_integration_scenarios" \
    "conformance"

  # Harness infrastructure (MockClock, SimulatedNetwork, TestHarness)
  run_cross_test "conformance_harness" "fcp-conformance" \
    "--lib harness::" \
    "contract.test_harness_infrastructure" \
    "conformance"

  # Compliance module (static + dynamic connector contracts)
  run_cross_test "conformance_compliance" "fcp-conformance" \
    "--lib compliance::" \
    "contract.compliance_static_dynamic" \
    "conformance"
else
  log_step "CONFORMANCE" "Skipped (--only-paths filter)"
fi

# =============================================================================
# Path 6: Connector Integration (All 6 Connectors)
# =============================================================================
# Validates: lifecycle, error mapping, auth credential handling, API
#            interaction patterns across all production connectors
# Crates: connector-{anthropic,openai,discord,telegram,twitter,vectordb}
# =============================================================================
if should_run_path "connectors"; then
  log_step "CONNECTORS" "Path 6: All-connector integration (lifecycle + error mapping)"

  # Anthropic connector (lifecycle + API + error mapping)
  run_cross_test "connector_anthropic" "connector-anthropic" \
    "--all-targets" \
    "contract.connector_anthropic_lifecycle" \
    "connectors" "connector-anthropic"

  # OpenAI connector (lifecycle + streaming + pricing + error mapping)
  run_cross_test "connector_openai" "connector-openai" \
    "--all-targets" \
    "contract.connector_openai_lifecycle" \
    "connectors" "connector-openai"

  # Discord connector (lifecycle + gateway + events + validation)
  run_cross_test "connector_discord" "connector-discord" \
    "--all-targets" \
    "contract.connector_discord_lifecycle" \
    "connectors" "connector-discord"

  # Telegram connector (polling + events + validation + cursor tracking)
  run_cross_test "connector_telegram" "connector-telegram" \
    "--all-targets" \
    "contract.connector_telegram_lifecycle" \
    "connectors" "connector-telegram"

  # Twitter connector (API + streaming + OAuth + error mapping)
  run_cross_test "connector_twitter" "connector-twitter" \
    "--all-targets" \
    "contract.connector_twitter_lifecycle" \
    "connectors" "connector-twitter"

  # VectorDB connector (multi-provider + config + health checks)
  run_cross_test "connector_vectordb" "connector-vectordb" \
    "--all-targets" \
    "contract.connector_vectordb_lifecycle" \
    "connectors" "connector-vectordb"
else
  log_step "CONNECTORS" "Skipped (--only-paths filter)"
fi

# =============================================================================
# Path 7: User-Journey E2E Flows
# =============================================================================
# Validates: complete user-visible flows (request-response, polling, webhook)
# Scripts: request_response_user_flow.sh, polling_user_flow.sh,
#          webhook_delivery_flow.sh
# =============================================================================
if should_run_path "user_journeys"; then
  log_step "USER_JOURNEYS" "Path 7: User-journey E2E flows"

  if [[ -x "${SCRIPT_DIR}/request_response_user_flow.sh" ]]; then
    run_e2e_script "user_journey_request_response" \
      "scripts/e2e/request_response_user_flow.sh" \
      "contract.user_journey_request_response" \
      "user_journeys"
  else
    log_step "USER_JOURNEYS" "WARN: request_response_user_flow.sh not found or not executable"
    PATH_WARN=$((PATH_WARN + 1))
  fi

  if [[ -x "${SCRIPT_DIR}/polling_user_flow.sh" ]]; then
    run_e2e_script "user_journey_polling" \
      "scripts/e2e/polling_user_flow.sh" \
      "contract.user_journey_polling" \
      "user_journeys"
  else
    log_step "USER_JOURNEYS" "WARN: polling_user_flow.sh not found or not executable"
    PATH_WARN=$((PATH_WARN + 1))
  fi

  if [[ -x "${SCRIPT_DIR}/webhook_delivery_flow.sh" ]]; then
    run_e2e_script "user_journey_webhook" \
      "scripts/e2e/webhook_delivery_flow.sh" \
      "contract.user_journey_webhook" \
      "user_journeys"
  else
    log_step "USER_JOURNEYS" "WARN: webhook_delivery_flow.sh not found or not executable"
    PATH_WARN=$((PATH_WARN + 1))
  fi
else
  log_step "USER_JOURNEYS" "Skipped (--only-paths filter)"
fi

# =============================================================================
# Path 8: Failure-Recovery Stress Variants
# =============================================================================
# Validates: retry/cancellation/timeout/reconnect semantics under stress
# Scripts: polling_timeout_backoff_storm.sh, polling_cursor_gap_recovery.sh,
#          webhook_retry_storm.sh, request_timeout_chain.sh,
#          streaming_reconnect_storm.sh, bidirectional_cancel_chain.sh
# =============================================================================
if should_run_path "failure_recovery"; then
  log_step "FAILURE_RECOVERY" "Path 8: Failure-recovery stress variants"

  STRESS_SCRIPTS=(
    "polling_timeout_backoff_storm.sh:contract.timeout_backoff_storm:Polling timeout + bounded backoff"
    "polling_cursor_gap_recovery.sh:contract.cursor_gap_data_loss:Cursor gap detection + fill"
    "webhook_retry_storm.sh:contract.retry_storm_idempotency:Webhook retry + idempotency"
    "request_timeout_chain.sh:contract.timeout_chain_cascade:Concurrent timeout cascade"
    "streaming_reconnect_storm.sh:contract.reconnect_storm_unbounded:Reconnect storm bounded recovery"
    "bidirectional_cancel_chain.sh:contract.cancel_cascade_resource_leak:Cancel cascade + clean shutdown"
  )

  for entry in "${STRESS_SCRIPTS[@]}"; do
    IFS=':' read -r script_name contract_id description <<< "${entry}"
    label="failure_recovery_$(echo "${script_name}" | sed 's/\.sh$//')"

    if [[ -x "${SCRIPT_DIR}/${script_name}" ]]; then
      log_step "FAILURE_RECOVERY" "${description}"
      run_e2e_script "${label}" \
        "scripts/e2e/${script_name}" \
        "${contract_id}" \
        "failure_recovery"
    else
      log_step "FAILURE_RECOVERY" "WARN: ${script_name} not found or not executable"
      PATH_WARN=$((PATH_WARN + 1))
    fi
  done
else
  log_step "FAILURE_RECOVERY" "Skipped (--only-paths filter)"
fi

# =============================================================================
# Generate Path Coverage Report
# =============================================================================
log_step "COVERAGE" "Generating cross-component path coverage report"

jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    paths: [
      {
        id: "host_sdk",
        name: "Host → SDK → Connector Lifecycle",
        components: ["fcp-host", "fcp-sdk", "connector-registry"],
        contracts: ["contract.host_connector_lifecycle", "contract.host_agent_lifecycle", "contract.rate_limit_enforcement", "contract.retry_loop_execute"],
        test_count: 4,
        archetypes: ["request_response"],
        failure_classes: ["baseline_happy_path", "rate_limit_exhaustion"],
        user_impact: ["availability", "correctness"]
      },
      {
        id: "error_chain",
        name: "Error Taxonomy Chain (AsyncError → Wire)",
        components: ["fcp-async-core", "fcp-sdk", "fcp-core"],
        contracts: ["contract.error_taxonomy_chain", "contract.connector_error_mapping", "contract.error_serialization"],
        test_count: 3,
        archetypes: ["request_response"],
        failure_classes: ["error_classification", "retryability_contract"],
        user_impact: ["correctness", "availability"]
      },
      {
        id: "store_raptorq",
        name: "Store → RaptorQ → Repair Convergence",
        components: ["fcp-store", "fcp-raptorq", "repair-controller"],
        contracts: ["contract.encode_decode_roundtrip", "contract.repair_convergence", "contract.multinode_distribution", "contract.adversarial_symbol_robustness", "contract.oti_fidelity"],
        test_count: 5,
        archetypes: ["queue_pubsub"],
        failure_classes: ["symbol_repair_failure", "degraded_availability"],
        user_impact: ["availability", "correctness"]
      },
      {
        id: "mesh_store",
        name: "Mesh → Store → Protocol Orchestration",
        components: ["fcp-mesh", "fcp-store", "fcp-protocol"],
        contracts: ["contract.mesh_symbol_routing", "contract.mesh_decode_feedback", "contract.mesh_multinode_transfer", "contract.mesh_admission_control", "contract.mesh_session_auth", "contract.mesh_delivery_guarantees"],
        test_count: 6,
        archetypes: ["queue_pubsub"],
        failure_classes: ["mesh_integration_regression", "admission_budget_exhaustion", "distributed_lease_contention"],
        user_impact: ["availability", "security", "correctness"]
      },
      {
        id: "conformance",
        name: "Conformance → Harness → Integration",
        components: ["fcp-conformance", "harness", "simulated-network"],
        contracts: ["contract.conformance_integration_scenarios", "contract.test_harness_infrastructure", "contract.compliance_static_dynamic"],
        test_count: 3,
        archetypes: ["queue_pubsub"],
        failure_classes: ["conformance_regression"],
        user_impact: ["correctness"]
      },
      {
        id: "connectors",
        name: "All-Connector Integration",
        components: ["connector-anthropic", "connector-openai", "connector-discord", "connector-telegram", "connector-twitter", "connector-vectordb"],
        contracts: ["contract.connector_anthropic_lifecycle", "contract.connector_openai_lifecycle", "contract.connector_discord_lifecycle", "contract.connector_telegram_lifecycle", "contract.connector_twitter_lifecycle", "contract.connector_vectordb_lifecycle"],
        test_count: 6,
        archetypes: ["request_response", "polling", "streaming", "webhook"],
        failure_classes: ["connector_lifecycle_regression", "error_mapping_drift"],
        user_impact: ["availability", "correctness"]
      },
      {
        id: "user_journeys",
        name: "User-Journey E2E Flows",
        components: ["e2e-scripts"],
        contracts: ["contract.user_journey_request_response", "contract.user_journey_polling", "contract.user_journey_webhook"],
        test_count: 3,
        archetypes: ["request_response", "polling", "webhook"],
        failure_classes: ["user_journey_regression"],
        user_impact: ["availability", "correctness", "security"]
      },
      {
        id: "failure_recovery",
        name: "Failure-Recovery Stress Variants",
        components: ["e2e-scripts"],
        contracts: ["contract.timeout_backoff_storm", "contract.cursor_gap_data_loss", "contract.retry_storm_idempotency", "contract.timeout_chain_cascade", "contract.reconnect_storm_unbounded", "contract.cancel_cascade_resource_leak"],
        test_count: 6,
        archetypes: ["polling", "webhook", "request_response", "streaming", "bidirectional"],
        failure_classes: ["timeout_backoff_storm", "cursor_gap_data_loss", "retry_storm_idempotency", "timeout_chain_cascade", "reconnect_storm_unbounded", "cancel_cascade_resource_leak"],
        user_impact: ["availability", "correctness"]
      }
    ]
  }' > "${PATH_COVERAGE_FILE}"

# =============================================================================
# Generate Drift Classification
# =============================================================================
log_step "DRIFT" "Generating drift classification report"

TOTAL_TESTS=$((PATH_PASS + PATH_FAIL + PATH_SKIP))
DRIFT_COUNT=${#DRIFT_RECORDS[@]}
REGRESSION_COUNT=${#REGRESSION_SUMMARIES[@]}

DRIFT_JSON='[]'
if (( DRIFT_COUNT > 0 )); then
  DRIFT_JSON="$(printf '%s\n' "${DRIFT_RECORDS[@]}" | jq -s 'sort_by(.path, .test_name)')"
fi

REGRESSION_JSON='[]'
if (( REGRESSION_COUNT > 0 )); then
  REGRESSION_JSON="$(printf '%s\n' "${REGRESSION_SUMMARIES[@]}" | jq -s 'sort_by(.path, .test_name)')"
fi

jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --argjson total_tests "${TOTAL_TESTS}" \
  --argjson pass "${PATH_PASS}" \
  --argjson fail "${PATH_FAIL}" \
  --argjson skip "${PATH_SKIP}" \
  --argjson warn "${PATH_WARN}" \
  --argjson drift_count "${DRIFT_COUNT}" \
  --argjson regression_count "${REGRESSION_COUNT}" \
  --argjson drift_records "${DRIFT_JSON}" \
  --argjson regressions "${REGRESSION_JSON}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    summary: {
      total_tests: $total_tests,
      pass: $pass,
      fail: $fail,
      skip: $skip,
      warn: $warn,
      drift_count: $drift_count,
      regression_count: $regression_count
    },
    classification_legend: {
      "regression": "Unexpected cross-component behavioral change requiring investigation",
      "expected_drift": "Known drift from async migration — approved via contract review",
      "approved_variance": "Intentional behavior change documented in migration plan"
    },
    drift_records: $drift_records,
    regressions: $regressions
  }' > "${DRIFT_FILE}"

# =============================================================================
# Generate Regression Index (actionable diagnostics)
# =============================================================================
if (( REGRESSION_COUNT > 0 )); then
  jq -n \
    --arg run_id "${RUN_ID}" \
    --arg generated_at "$(now_iso)" \
    --argjson count "${REGRESSION_COUNT}" \
    --argjson regressions "${REGRESSION_JSON}" \
    '{
      run_id: $run_id,
      generated_at: $generated_at,
      regression_count: $count,
      regressions: $regressions,
      remediation: "Each regression entry includes a rerun_command for targeted investigation. Run with --only-paths to isolate specific data paths."
    }' > "${REGRESSION_FILE}"
fi

# =============================================================================
# Generate Summary
# =============================================================================
log_step "SUMMARY" "Generating cross-component revalidation summary"

OVERALL_STATUS="pass"
if (( PATH_FAIL > 0 )); then
  OVERALL_STATUS="fail"
elif (( PATH_WARN > 0 )); then
  if [[ "${CI_MODE}" == "true" ]]; then
    OVERALL_STATUS="fail"
  else
    OVERALL_STATUS="warn"
  fi
fi

jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --arg overall_status "${OVERALL_STATUS}" \
  --argjson ci_mode "${CI_MODE}" \
  --argjson dry_run "${DRY_RUN}" \
  --argjson total "${TOTAL_TESTS}" \
  --argjson pass "${PATH_PASS}" \
  --argjson fail "${PATH_FAIL}" \
  --argjson skip "${PATH_SKIP}" \
  --argjson warn "${PATH_WARN}" \
  --argjson drift_count "${DRIFT_COUNT}" \
  --argjson regression_count "${REGRESSION_COUNT}" \
  --arg only_paths "${ONLY_PATHS}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    overall_status: $overall_status,
    ci_mode: $ci_mode,
    dry_run: $dry_run,
    data_paths: {
      total_tests: $total,
      pass: $pass,
      fail: $fail,
      skip: $skip,
      warn: $warn
    },
    drift: {
      drift_count: $drift_count,
      regression_count: $regression_count
    },
    filters: {
      only_paths: (if ($only_paths | length) > 0 then $only_paths else null end)
    },
    artifacts: {
      summary: "summary.json",
      steps: "steps.jsonl",
      drift_classification: "drift_classification.json",
      regression_index: "regression_index.json",
      path_coverage: "path_coverage.json",
      replay: "replay.sh",
      logs: "logs/"
    },
    triage_guide: {
      "regression": "Check drift_classification.json for contract IDs. Each entry has rerun_command for targeted debugging.",
      "warn": "Warnings indicate missing E2E scripts. These are expected pre-migration artifacts.",
      "path_isolation": "Use --only-paths <path_id> to rerun specific data paths in isolation."
    }
  }' > "${SUMMARY_FILE}"

# =============================================================================
# Generate Replay Script
# =============================================================================
cat > "${REPLAY_FILE}" <<REPLAY_EOF
#!/usr/bin/env bash
# Replay: Cross-Component E2E Revalidation ${RUN_ID}
# Generated: $(now_iso)
set -euo pipefail

echo "=== Replaying Cross-Component Revalidation: ${RUN_ID} ==="

bash scripts/e2e/e2e_cross_component_revalidation.sh \\
  --run-id "${RUN_ID}" \\
  --out-root "${OUT_ROOT}"$(
  [[ -n "${ONLY_PATHS}" ]] && printf ' \\\n  --only-paths "%s"' "${ONLY_PATHS}"
  [[ "${CI_MODE}" == "true" ]] && printf ' \\\n  --ci'
  )
REPLAY_EOF
chmod +x "${REPLAY_FILE}"

# =============================================================================
# Generate Rerun-Failed Script
# =============================================================================
if (( REGRESSION_COUNT > 0 )); then
  RERUN_FILE="${OUT_ROOT}/rerun_failed.sh"
  {
    echo "#!/usr/bin/env bash"
    echo "# Rerun failed cross-component tests: ${RUN_ID}"
    echo "# Generated: $(now_iso)"
    echo "set -euo pipefail"
    echo ""
    echo "echo '=== Rerunning ${REGRESSION_COUNT} failed tests ==='"
    echo ""
    for r in "${REGRESSION_SUMMARIES[@]}"; do
      rerun_cmd="$(echo "${r}" | jq -r '.rerun_command')"
      test_name="$(echo "${r}" | jq -r '.test_name')"
      echo "echo '--- ${test_name} ---'"
      echo "${rerun_cmd} || echo 'STILL FAILING: ${test_name}'"
      echo ""
    done
  } > "${RERUN_FILE}"
  chmod +x "${RERUN_FILE}"
fi

# =============================================================================
# Summary Output
# =============================================================================
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  CROSS-COMPONENT E2E REVALIDATION — ${RUN_ID}"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "  Overall Status:       ${OVERALL_STATUS}"
echo "  CI Mode:              ${CI_MODE}"
echo "  Dry Run:              ${DRY_RUN}"
echo ""
echo "  Data Path Tests:      ${TOTAL_TESTS} total"
echo "    Pass:               ${PATH_PASS}"
echo "    Fail:               ${PATH_FAIL}"
echo "    Skip:               ${PATH_SKIP}"
echo "    Warn:               ${PATH_WARN}"
echo ""
echo "  Drift Records:        ${DRIFT_COUNT}"
echo "  Regressions:          ${REGRESSION_COUNT}"
if [[ -n "${ONLY_PATHS}" ]]; then
  echo "  Filter:               ${ONLY_PATHS}"
fi
echo ""
echo "  Data Paths Validated:"
echo "    1. host_sdk          — Host → SDK → Connector lifecycle"
echo "    2. error_chain       — Error taxonomy (AsyncError → Wire)"
echo "    3. store_raptorq     — Store → RaptorQ → Repair convergence"
echo "    4. mesh_store        — Mesh → Store → Protocol orchestration"
echo "    5. conformance       — Conformance → Harness → Integration"
echo "    6. connectors        — All 6 connectors (lifecycle + error)"
echo "    7. user_journeys     — User-journey E2E flows"
echo "    8. failure_recovery  — Failure-recovery stress variants"
echo ""
echo "  Artifacts:            ${OUT_ROOT}/"
echo "    summary.json              — revalidation summary"
echo "    steps.jsonl               — per-test forensic steps"
echo "    drift_classification.json — drift + regression records"
echo "    regression_index.json     — actionable failure diagnostics"
echo "    path_coverage.json        — data path coverage map"
echo "    replay.sh                 — deterministic replay"
echo "    logs/                     — per-test execution logs"
echo ""
echo "════════════════════════════════════════════════════════════════════"

if (( REGRESSION_COUNT > 0 )); then
  echo ""
  echo "  Regressions requiring investigation:"
  for r in "${REGRESSION_SUMMARIES[@]}"; do
    path_name="$(echo "${r}" | jq -r '.path')"
    test_name="$(echo "${r}" | jq -r '.test_name')"
    contract_id="$(echo "${r}" | jq -r '.contract_id')"
    reason="$(echo "${r}" | jq -r '.reason[:120]')"
    echo "  - [${path_name}] ${test_name} (${contract_id}): ${reason}"
  done
  echo ""
  echo "  Rerun: bash ${OUT_ROOT}/rerun_failed.sh"
  echo ""
fi

if [[ "${OVERALL_STATUS}" == "fail" ]]; then
  exit 1
fi
