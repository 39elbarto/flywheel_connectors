#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_raptorq_multinode_repair_convergence"
SEED="0xME5HREP"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
STEP_CONTEXT="null"

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

run_fcp_e2e() {
  if command -v fcp-e2e >/dev/null 2>&1; then
    fcp-e2e "$@"
    return $?
  fi
  run_cargo run -q -p fcp-e2e --bin fcp-e2e -- "$@"
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
  details="null"
  if [[ -n "${STEP_CONTEXT}" && "${STEP_CONTEXT}" != "null" && "${STEP_CONTEXT}" != "{}" ]]; then
    details="${STEP_CONTEXT}"
  fi

  mkdir -p "$(dirname "${LOG_JSONL}")"
  printf '{"timestamp":"%s","log_version":"v2","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s,"details":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${step}" "${step_number}" "${correlation_id}" "${duration_ms}" "${result}" "${artifacts_json}" "${details}" >> "${LOG_JSONL}"
}

run_step() {
  local step="$1"
  local step_number="$2"
  local artifacts_json="$3"
  shift 3

  local start_ms end_ms duration_ms rc
  STEP_CONTEXT="null"
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

capture_json_metrics() {
  local source_log="$1"
  local metrics_jsonl="$2"
  grep -E '^\{.*\}$' "${source_log}" > "${metrics_jsonl}" || true
  if [[ ! -s "${metrics_jsonl}" ]]; then
    echo "No JSON metrics emitted by command output: ${source_log}" >&2
    exit 1
  fi
}

metric_for_test() {
  local metrics_jsonl="$1"
  local test_name="$2"
  local jq_expr="$3"
  jq -r --arg test_name "${test_name}" "select(.test_name == \$test_name) | ${jq_expr}" "${metrics_jsonl}" | head -n1
}

step_prepare_output() {
  mkdir -p "${OUT_DIR}"
  : > "${LOG_JSONL}"
}

# Step 2: Validate multi-node symbol distribution meets placement policy
step_multinode_symbol_distribution() {
  local execution_log="${OUT_DIR}/multinode_distribution.execution.log"
  local metrics_jsonl="${OUT_DIR}/multinode_distribution.metrics.jsonl"
  local distinct_nodes max_node_fraction_bps

  run_cargo test -p fcp-store --test store_repair_integration multi_node_symbol_distribution -- --nocapture > "${execution_log}" 2>&1
  capture_json_metrics "${execution_log}" "${metrics_jsonl}"

  distinct_nodes="$(metric_for_test "${metrics_jsonl}" "multi_node_symbol_distribution" '.details.distinct_nodes // empty')"
  max_node_fraction_bps="$(metric_for_test "${metrics_jsonl}" "multi_node_symbol_distribution" '.details.max_node_fraction_bps // empty')"

  [[ -n "${distinct_nodes}" && -n "${max_node_fraction_bps}" ]] || {
    echo "Missing distribution metrics in ${metrics_jsonl}" >&2
    exit 1
  }
  (( distinct_nodes >= 3 )) || {
    echo "Expected >= 3 distinct nodes, got ${distinct_nodes}" >&2
    exit 1
  }
  (( max_node_fraction_bps <= 5000 )) || {
    echo "Expected max node fraction <= 5000 bps, got ${max_node_fraction_bps}" >&2
    exit 1
  }

  STEP_CONTEXT="$(printf '{"category":"multinode_distribution","distinct_nodes":%s,"max_node_fraction_bps":%s}' \
    "${distinct_nodes}" "${max_node_fraction_bps}")"
}

# Step 3: Mesh-level multi-node symbol transfer coordination
step_mesh_multinode_transfer() {
  local execution_log="${OUT_DIR}/mesh_multinode_transfer.execution.log"

  run_cargo test -p fcp-mesh --test mesh_integration meshnode_multi_node_symbol_transfer -- --nocapture > "${execution_log}" 2>&1
  grep -q "meshnode_multi_node_symbol_transfer ... ok" "${execution_log}" || {
    echo "Multi-node symbol transfer did not pass in ${execution_log}" >&2
    exit 1
  }

  STEP_CONTEXT='{"category":"mesh_multinode_transfer","outcome":"multi_peer_symbol_coordination_validated"}'
}

# Step 4: Mesh-level multi-node control plane roundtrip
step_mesh_multinode_control_plane() {
  local execution_log="${OUT_DIR}/mesh_multinode_control_plane.execution.log"

  run_cargo test -p fcp-mesh --test mesh_integration meshnode_multi_node_control_plane_roundtrip -- --nocapture > "${execution_log}" 2>&1
  grep -q "meshnode_multi_node_control_plane_roundtrip ... ok" "${execution_log}" || {
    echo "Multi-node control plane roundtrip did not pass in ${execution_log}" >&2
    exit 1
  }

  STEP_CONTEXT='{"category":"mesh_multinode_control_plane","outcome":"multi_peer_control_plane_validated"}'
}

# Step 5: Repair controller drives convergence under degraded coverage
step_repair_controller_convergence() {
  local execution_log="${OUT_DIR}/repair_controller.execution.log"
  local metrics_jsonl="${OUT_DIR}/repair_controller.metrics.jsonl"
  local coverage_bps repairs_succeeded symbols_added

  run_cargo test -p fcp-store --test store_repair_integration repair_controller_drives_convergence -- --nocapture > "${execution_log}" 2>&1
  capture_json_metrics "${execution_log}" "${metrics_jsonl}"

  coverage_bps="$(metric_for_test "${metrics_jsonl}" "repair_controller_drives_convergence" '.coverage_bps // empty')"
  repairs_succeeded="$(metric_for_test "${metrics_jsonl}" "repair_controller_drives_convergence" '.details.repairs_succeeded // 0')"
  symbols_added="$(metric_for_test "${metrics_jsonl}" "repair_controller_drives_convergence" '.details.symbols_added // 0')"

  [[ -n "${coverage_bps}" ]] || {
    echo "Missing convergence metrics in ${metrics_jsonl}" >&2
    exit 1
  }
  (( coverage_bps >= 10000 )) || {
    echo "Expected restored coverage >= 10000bps, got ${coverage_bps}" >&2
    exit 1
  }

  STEP_CONTEXT="$(printf '{"category":"repair_convergence","coverage_restored_bps":%s,"repairs_succeeded":%s,"symbols_added":%s}' \
    "${coverage_bps}" "${repairs_succeeded}" "${symbols_added}")"
}

# Step 6: Object and symbol stores maintain coherence across operations
step_store_coherence() {
  local execution_log="${OUT_DIR}/store_coherence.execution.log"

  run_cargo test -p fcp-store --test store_repair_integration object_and_symbol_stores_coherent -- --nocapture > "${execution_log}" 2>&1
  grep -q "object_and_symbol_stores_coherent ... ok" "${execution_log}" || {
    echo "Store coherence test did not pass in ${execution_log}" >&2
    exit 1
  }

  STEP_CONTEXT='{"category":"store_coherence","outcome":"object_symbol_stores_coherent"}'
}

# Step 7: Gossip integration with routing for repair discovery
step_gossip_routing_integration() {
  local execution_log="${OUT_DIR}/gossip_routing.execution.log"

  run_cargo test -p fcp-mesh --test mesh_integration test_gossip_routing_integration -- --nocapture > "${execution_log}" 2>&1
  grep -q "test_gossip_routing_integration ... ok" "${execution_log}" || {
    echo "Gossip routing integration did not pass in ${execution_log}" >&2
    exit 1
  }

  STEP_CONTEXT='{"category":"gossip_routing","outcome":"gossip_repair_discovery_validated"}'
}

require_cmd cargo
require_cmd jq

mkdir -p "${OUT_DIR}"

run_step "prepare_output" 1 "[]" step_prepare_output
run_step \
  "multinode_symbol_distribution" \
  2 \
  "[\"${OUT_DIR}/multinode_distribution.execution.log\",\"${OUT_DIR}/multinode_distribution.metrics.jsonl\"]" \
  step_multinode_symbol_distribution
run_step \
  "mesh_multinode_transfer" \
  3 \
  "[\"${OUT_DIR}/mesh_multinode_transfer.execution.log\"]" \
  step_mesh_multinode_transfer
run_step \
  "mesh_multinode_control_plane" \
  4 \
  "[\"${OUT_DIR}/mesh_multinode_control_plane.execution.log\"]" \
  step_mesh_multinode_control_plane
run_step \
  "repair_controller_convergence" \
  5 \
  "[\"${OUT_DIR}/repair_controller.execution.log\",\"${OUT_DIR}/repair_controller.metrics.jsonl\"]" \
  step_repair_controller_convergence
run_step \
  "store_coherence" \
  6 \
  "[\"${OUT_DIR}/store_coherence.execution.log\"]" \
  step_store_coherence
run_step \
  "gossip_routing_integration" \
  7 \
  "[\"${OUT_DIR}/gossip_routing.execution.log\"]" \
  step_gossip_routing_integration

run_fcp_e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
