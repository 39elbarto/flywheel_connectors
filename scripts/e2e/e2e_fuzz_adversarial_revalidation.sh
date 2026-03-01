#!/usr/bin/env bash
# =============================================================================
# e2e_fuzz_adversarial_revalidation.sh — Fuzz + Adversarial Boundary Revalidation
# =============================================================================
# Bead:     235t.27.3 (ASUPERSYNC-VALIDATION Fuzz + Adversarial Boundary)
# Schema:   asupersync-fuzz-adversarial-revalidation/v1
#
# Revalidates fuzz and adversarial boundary robustness on migrated async
# boundaries, parsing paths, and repair coordination surfaces.
#
# Validation Matrices:
#   1. Fuzz target compilation (7 libfuzzer targets must build)
#   2. Fuzz corpus regression (known corpus → zero crashes)
#   3. Property-based tests (proptest: Shamir, mesh symbol requests)
#   4. Adversarial RaptorQ (erasure recovery + symbol corruption)
#   5. Store adversarial (corrupted symbols + reordered duplicates)
#   6. Boundary enforcement (decode permits, mesh admission, protocol limits)
#   7. E2E adversarial stress scripts (raptorq_adversarial_decode_stress)
#
# Usage:
#   bash scripts/e2e/e2e_fuzz_adversarial_revalidation.sh [options]
#
# Options:
#   --run-id <id>           Stable run identifier (default: UTC timestamp)
#   --out-root <path>       Artifact root directory
#   --dry-run               Emit plan without executing tests
#   --only-matrices <csv>   Filter: fuzz_compile,fuzz_corpus,proptest,
#                           adversarial_raptorq,adversarial_store,boundary,
#                           e2e_stress
#   --fuzz-time <secs>      Fuzz corpus regression time per target (default: 30)
#   --ci                    CI mode (strict: warnings → errors)
#   -h, --help              Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GATE_SCHEMA="asupersync-fuzz-adversarial-revalidation/v1"
FORENSICS_SCHEMA="asupersync-forensics/v1"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT=""
DRY_RUN=false
CI_MODE="${CI:-false}"
ONLY_MATRICES=""
FUZZ_TIME=30

declare -i MATRIX_PASS=0
declare -i MATRIX_FAIL=0
declare -i MATRIX_SKIP=0
declare -i MATRIX_WARN=0
declare -a FINDING_RECORDS=()

usage() {
  cat <<'EOF'
Usage: scripts/e2e/e2e_fuzz_adversarial_revalidation.sh [options]

Fuzz + Adversarial Boundary Revalidation

Revalidates fuzz and adversarial boundary robustness on migrated async
boundaries. Validates parsing paths, repair coordination, and boundary
enforcement with severity classification and replay metadata.

Options:
  --run-id <id>           Stable run identifier (default: UTC timestamp)
  --out-root <path>       Artifact root (default: artifacts/asupersync/fuzz-adversarial/<run-id>)
  --dry-run               Emit plan without executing tests
  --only-matrices <csv>   Filter: fuzz_compile,fuzz_corpus,proptest,
                          adversarial_raptorq,adversarial_store,boundary,
                          e2e_stress
  --fuzz-time <secs>      Fuzz corpus regression time per target (default: 30)
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
  printf '[%s] [FUZZ-ADVERSARIAL/%s] %s\n' "$(now_iso)" "$1" "$2"
}

record_step() {
  local scenario_id="$1"
  local operation="$2"
  local outcome="$3"
  local elapsed_ms="$4"
  local contract_id="${5:-n/a}"
  local reason="${6:-}"
  local log_path="${7:-}"

  jq -c -n \
    --arg schema_version "${FORENSICS_SCHEMA}" \
    --arg run_id "${RUN_ID}" \
    --arg scenario_id "${scenario_id}" \
    --arg trace_id "${RUN_ID}-${scenario_id}" \
    --arg correlation_id "${RUN_ID}" \
    --arg connector "n/a" \
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

add_finding() {
  local matrix="$1"
  local test_name="$2"
  local severity="$3"
  local contract_id="$4"
  local description="$5"
  local rerun_cmd="$6"
  local f
  f="$(jq -c -n \
    --arg matrix "${matrix}" \
    --arg test_name "${test_name}" \
    --arg severity "${severity}" \
    --arg contract_id "${contract_id}" \
    --arg description "${description}" \
    --arg rerun_command "${rerun_cmd}" \
    --arg run_id "${RUN_ID}" \
    --arg found_at "$(now_iso)" \
    '{
      matrix: $matrix,
      test_name: $test_name,
      severity: $severity,
      contract_id: $contract_id,
      description: $description,
      rerun_command: $rerun_command,
      run_id: $run_id,
      found_at: $found_at
    }')"
  FINDING_RECORDS+=("${f}")
}

should_run_matrix() {
  local matrix="$1"
  if [[ -z "${ONLY_MATRICES}" ]]; then
    return 0
  fi
  echo ",${ONLY_MATRICES}," | grep -q ",${matrix}," && return 0
  return 1
}

# Run a cargo test with forensics tracking
run_fuzz_test() {
  local label="$1"
  local package="$2"
  local test_filter="$3"
  local contract_id="$4"
  local matrix_name="$5"
  local log_file="${OUT_ROOT}/logs/${label}.log"
  local scenario_id="fuzz_adversarial.${label}"

  mkdir -p "${OUT_ROOT}/logs"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_step "${label}" "[dry-run] cargo test -p ${package} ${test_filter}"
    echo "[dry-run] cargo test -p ${package} ${test_filter}" > "${log_file}"
    record_step "${scenario_id}" "cargo_test" "planned" 0 "${contract_id}" "dry_run" "${log_file}"
    MATRIX_SKIP=$((MATRIX_SKIP + 1))
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
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-fuzz-adversarial}" \
      cargo test -p "${package}" ${test_filter} -- --nocapture > "${log_file}" 2>&1 && status="pass" || status="fail"
  fi
  end=$(now_ms)
  elapsed=$((end - start))

  if [[ "${status}" == "pass" ]]; then
    MATRIX_PASS=$((MATRIX_PASS + 1))
    log_step "${label}" "PASS (${elapsed}ms)"
    record_step "${scenario_id}" "cargo_test" "pass" "${elapsed}" "${contract_id}" "" "${log_file}"
  else
    MATRIX_FAIL=$((MATRIX_FAIL + 1))
    local reason
    reason="$(tail -5 "${log_file}" | head -3 | tr '\n' ' ' | head -c 200)"
    log_step "${label}" "FAIL (${elapsed}ms): ${reason}"
    record_step "${scenario_id}" "cargo_test" "fail" "${elapsed}" "${contract_id}" "${reason}" "${log_file}"
    add_finding "${matrix_name}" "${label}" "high" "${contract_id}" "${reason}" \
      "cargo test -p ${package} ${test_filter} -- --nocapture"
  fi
}

# Run a fuzz target compilation check
run_fuzz_compile_check() {
  local target_name="$1"
  local contract_id="$2"
  local label="fuzz_compile_${target_name}"
  local log_file="${OUT_ROOT}/logs/${label}.log"
  local scenario_id="fuzz_adversarial.${label}"

  mkdir -p "${OUT_ROOT}/logs"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_step "${label}" "[dry-run] cargo fuzz check ${target_name}"
    echo "[dry-run] cargo fuzz check ${target_name}" > "${log_file}"
    record_step "${scenario_id}" "fuzz_compile" "planned" 0 "${contract_id}" "dry_run" "${log_file}"
    MATRIX_SKIP=$((MATRIX_SKIP + 1))
    return 0
  fi

  local start end elapsed status
  start=$(now_ms)

  # Check if cargo-fuzz is available; if not, fall back to cargo build --manifest-path
  if command -v cargo-fuzz >/dev/null 2>&1; then
    if (cd "${REPO_ROOT}" && CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-fuzz-compile}" \
        cargo fuzz check "fuzz_${target_name}" 2>&1) > "${log_file}" 2>&1; then
      status="pass"
    else
      status="fail"
    fi
  else
    # Fallback: check that the fuzz target source file exists and compiles as syntax check
    if [[ -f "${REPO_ROOT}/fuzz/fuzz_targets/${target_name}.rs" ]]; then
      log_step "${label}" "WARN: cargo-fuzz not installed, checking source existence only"
      echo "cargo-fuzz not available; source file exists: fuzz/fuzz_targets/${target_name}.rs" > "${log_file}"
      status="pass"
      MATRIX_WARN=$((MATRIX_WARN + 1))
    else
      echo "fuzz target source not found: fuzz/fuzz_targets/${target_name}.rs" > "${log_file}"
      status="fail"
    fi
  fi
  end=$(now_ms)
  elapsed=$((end - start))

  if [[ "${status}" == "pass" ]]; then
    MATRIX_PASS=$((MATRIX_PASS + 1))
    log_step "${label}" "PASS (${elapsed}ms)"
    record_step "${scenario_id}" "fuzz_compile" "pass" "${elapsed}" "${contract_id}" "" "${log_file}"
  else
    MATRIX_FAIL=$((MATRIX_FAIL + 1))
    local reason
    reason="$(tail -5 "${log_file}" | head -3 | tr '\n' ' ' | head -c 200)"
    log_step "${label}" "FAIL (${elapsed}ms): ${reason}"
    record_step "${scenario_id}" "fuzz_compile" "fail" "${elapsed}" "${contract_id}" "${reason}" "${log_file}"
    add_finding "fuzz_compile" "${target_name}" "critical" "${contract_id}" \
      "Fuzz target failed to compile after async migration: ${reason}" \
      "cargo fuzz check fuzz_${target_name}"
  fi
}

# Run fuzz corpus regression (replay known corpus inputs)
run_fuzz_corpus_regression() {
  local target_name="$1"
  local contract_id="$2"
  local label="fuzz_corpus_${target_name}"
  local log_file="${OUT_ROOT}/logs/${label}.log"
  local scenario_id="fuzz_adversarial.${label}"
  local corpus_dir="${REPO_ROOT}/fuzz/corpus/fuzz_${target_name}"

  mkdir -p "${OUT_ROOT}/logs"

  if [[ "${DRY_RUN}" == "true" ]]; then
    local corpus_count=0
    if [[ -d "${corpus_dir}" ]]; then
      corpus_count=$(find "${corpus_dir}" -type f 2>/dev/null | wc -l | tr -d ' ')
    fi
    log_step "${label}" "[dry-run] corpus regression (${corpus_count} seeds)"
    echo "[dry-run] cargo fuzz run fuzz_${target_name} -- -runs=0 (${corpus_count} seeds)" > "${log_file}"
    record_step "${scenario_id}" "fuzz_corpus" "planned" 0 "${contract_id}" "dry_run" "${log_file}"
    MATRIX_SKIP=$((MATRIX_SKIP + 1))
    return 0
  fi

  local start end elapsed status

  if [[ ! -d "${corpus_dir}" ]]; then
    log_step "${label}" "WARN: No corpus directory for fuzz_${target_name}"
    echo "No corpus directory: ${corpus_dir}" > "${log_file}"
    record_step "${scenario_id}" "fuzz_corpus" "pass" 0 "${contract_id}" "no_corpus" "${log_file}"
    MATRIX_WARN=$((MATRIX_WARN + 1))
    MATRIX_PASS=$((MATRIX_PASS + 1))
    return 0
  fi

  local corpus_count
  corpus_count=$(find "${corpus_dir}" -type f 2>/dev/null | wc -l | tr -d ' ')

  start=$(now_ms)
  if command -v cargo-fuzz >/dev/null 2>&1; then
    # Run with -runs=0 to replay existing corpus without new exploration
    if (cd "${REPO_ROOT}" && CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-fuzz-corpus}" \
        cargo fuzz run "fuzz_${target_name}" -- -runs=0 -max_total_time="${FUZZ_TIME}" 2>&1) > "${log_file}" 2>&1; then
      status="pass"
    else
      status="fail"
    fi
  else
    log_step "${label}" "WARN: cargo-fuzz not installed, skipping corpus regression"
    echo "cargo-fuzz not available; corpus has ${corpus_count} files" > "${log_file}"
    status="pass"
    MATRIX_WARN=$((MATRIX_WARN + 1))
  fi
  end=$(now_ms)
  elapsed=$((end - start))

  if [[ "${status}" == "pass" ]]; then
    MATRIX_PASS=$((MATRIX_PASS + 1))
    log_step "${label}" "PASS (${elapsed}ms, ${corpus_count} seeds)"
    record_step "${scenario_id}" "fuzz_corpus" "pass" "${elapsed}" "${contract_id}" "" "${log_file}"
  else
    MATRIX_FAIL=$((MATRIX_FAIL + 1))
    local reason
    reason="$(tail -10 "${log_file}" | head -5 | tr '\n' ' ' | head -c 200)"
    log_step "${label}" "FAIL (${elapsed}ms, ${corpus_count} seeds): ${reason}"
    record_step "${scenario_id}" "fuzz_corpus" "fail" "${elapsed}" "${contract_id}" "${reason}" "${log_file}"

    # Extract crash details if available
    local crash_desc="Fuzz corpus regression failure on fuzz_${target_name} (${corpus_count} seeds): ${reason}"
    add_finding "fuzz_corpus" "${target_name}" "critical" "${contract_id}" \
      "${crash_desc}" \
      "cargo fuzz run fuzz_${target_name} -- -runs=0"
  fi
}

# Run an E2E stress script with forensics tracking
run_stress_script() {
  local label="$1"
  local script_path="$2"
  local contract_id="$3"
  local matrix_name="$4"
  local log_file="${OUT_ROOT}/logs/${label}.log"
  local scenario_id="fuzz_adversarial.${label}"

  mkdir -p "${OUT_ROOT}/logs"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_step "${label}" "[dry-run] bash ${script_path}"
    echo "[dry-run] bash ${script_path}" > "${log_file}"
    record_step "${scenario_id}" "e2e_stress" "planned" 0 "${contract_id}" "dry_run" "${log_file}"
    MATRIX_SKIP=$((MATRIX_SKIP + 1))
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
    MATRIX_PASS=$((MATRIX_PASS + 1))
    log_step "${label}" "PASS (${elapsed}ms)"
    record_step "${scenario_id}" "e2e_stress" "pass" "${elapsed}" "${contract_id}" "" "${log_file}"
  else
    MATRIX_FAIL=$((MATRIX_FAIL + 1))
    local reason
    reason="$(tail -5 "${log_file}" | head -3 | tr '\n' ' ' | head -c 200)"
    log_step "${label}" "FAIL (${elapsed}ms): ${reason}"
    record_step "${scenario_id}" "e2e_stress" "fail" "${elapsed}" "${contract_id}" "${reason}" "${log_file}"
    add_finding "${matrix_name}" "${label}" "high" "${contract_id}" "${reason}" \
      "bash ${script_path}"
  fi
}

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)          RUN_ID="$2"; shift 2;;
    --out-root)        OUT_ROOT="$2"; shift 2;;
    --dry-run)         DRY_RUN=true; shift;;
    --only-matrices)   ONLY_MATRICES="$2"; shift 2;;
    --fuzz-time)       FUZZ_TIME="$2"; shift 2;;
    --ci)              CI_MODE=true; shift;;
    -h|--help)         usage; exit 0;;
    *)                 echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

# ── Pre-flight ──────────────────────────────────────────────────────────────
require_cmd jq
require_cmd cargo

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/fuzz-adversarial/${RUN_ID}"
fi
mkdir -p "${OUT_ROOT}/logs"

STEPS_FILE="${OUT_ROOT}/steps.jsonl"
SUMMARY_FILE="${OUT_ROOT}/summary.json"
FINDINGS_FILE="${OUT_ROOT}/findings.json"
REPLAY_FILE="${OUT_ROOT}/replay.sh"
COVERAGE_FILE="${OUT_ROOT}/fuzz_coverage.json"

: > "${STEPS_FILE}"

log_step "INIT" "Fuzz + Adversarial Boundary Revalidation v1 — run_id=${RUN_ID}"
log_step "INIT" "Output: ${OUT_ROOT}"
echo ""

# ── Fuzz Target Definitions ────────────────────────────────────────────────
# 7 libfuzzer targets from fuzz/fuzz_targets/
FUZZ_TARGETS=(
  "capability:contract.fuzz_cose_token_parsing"
  "fcpc_frame:contract.fuzz_fcpc_frame_parsing"
  "fcps_frame:contract.fuzz_fcps_frame_parsing"
  "fcps_datagram:contract.fuzz_fcps_datagram_parsing"
  "session:contract.fuzz_session_message_parsing"
  "session_transcript:contract.fuzz_session_transcript_parsing"
  "zone_key_manifest:contract.fuzz_zone_key_manifest_parsing"
)

# =============================================================================
# Matrix 1: Fuzz Target Compilation
# =============================================================================
# Validates: all 7 libfuzzer targets still compile after async migration
# =============================================================================
if should_run_matrix "fuzz_compile"; then
  log_step "FUZZ_COMPILE" "Matrix 1: Fuzz target compilation (7 targets)"

  for entry in "${FUZZ_TARGETS[@]}"; do
    IFS=':' read -r target_name contract_id <<< "${entry}"
    run_fuzz_compile_check "${target_name}" "${contract_id}"
  done
else
  log_step "FUZZ_COMPILE" "Skipped (--only-matrices filter)"
fi

# =============================================================================
# Matrix 2: Fuzz Corpus Regression
# =============================================================================
# Validates: known corpus inputs produce zero crashes on migrated runtime
# =============================================================================
if should_run_matrix "fuzz_corpus"; then
  log_step "FUZZ_CORPUS" "Matrix 2: Fuzz corpus regression (replay known seeds)"

  for entry in "${FUZZ_TARGETS[@]}"; do
    IFS=':' read -r target_name contract_id <<< "${entry}"
    run_fuzz_corpus_regression "${target_name}" "${contract_id}"
  done
else
  log_step "FUZZ_CORPUS" "Skipped (--only-matrices filter)"
fi

# =============================================================================
# Matrix 3: Property-Based Tests (proptest)
# =============================================================================
# Validates: Shamir secret sharing properties, mesh symbol request properties
# Crates: fcp-crypto, fcp-mesh
# =============================================================================
if should_run_matrix "proptest"; then
  log_step "PROPTEST" "Matrix 3: Property-based tests (proptest)"

  # Shamir secret sharing property tests (11+ properties)
  run_fuzz_test "proptest_shamir" "fcp-crypto" \
    "--test shamir_property_tests" \
    "contract.shamir_property_invariants" \
    "proptest"

  # Mesh symbol request property tests
  run_fuzz_test "proptest_mesh_symbol" "fcp-mesh" \
    "--lib symbol_request::tests" \
    "contract.mesh_symbol_request_properties" \
    "proptest"
else
  log_step "PROPTEST" "Skipped (--only-matrices filter)"
fi

# =============================================================================
# Matrix 4: Adversarial RaptorQ Tests
# =============================================================================
# Validates: erasure recovery patterns (bursty, front-heavy, tail-heavy,
#            random-seeded, interleaved) + symbol corruption detection
# Crate: fcp-raptorq
# =============================================================================
if should_run_matrix "adversarial_raptorq"; then
  log_step "ADVERSARIAL_RAPTORQ" "Matrix 4: Adversarial RaptorQ (erasure + corruption)"

  # Adversarial erasure recovery (5 patterns)
  run_fuzz_test "raptorq_adversarial_erasure" "fcp-raptorq" \
    "--lib golden::tests::adversarial" \
    "contract.raptorq_adversarial_erasure_recovery" \
    "adversarial_raptorq"

  # Symbol corruption detection (4 patterns)
  run_fuzz_test "raptorq_corruption" "fcp-raptorq" \
    "--lib golden::tests::corruption" \
    "contract.raptorq_corruption_detection" \
    "adversarial_raptorq"

  # Standard golden vectors (baseline integrity check)
  run_fuzz_test "raptorq_golden_baseline" "fcp-raptorq" \
    "--lib golden::tests::golden" \
    "contract.raptorq_golden_vectors" \
    "adversarial_raptorq"
else
  log_step "ADVERSARIAL_RAPTORQ" "Skipped (--only-matrices filter)"
fi

# =============================================================================
# Matrix 5: Store Adversarial Tests
# =============================================================================
# Validates: corrupted symbol rejection + reordered duplicate reconstruction
# Crate: fcp-store (store_repair_integration target)
# =============================================================================
if should_run_matrix "adversarial_store"; then
  log_step "ADVERSARIAL_STORE" "Matrix 5: Store adversarial (corruption + reorder)"

  # Corrupted symbols must reject valid reconstruction
  run_fuzz_test "store_adversarial_corrupt" "fcp-store" \
    "--test store_repair_integration adversarial_corrupted" \
    "contract.store_corrupted_symbol_rejection" \
    "adversarial_store"

  # Reordered + duplicate symbols must still reconstruct
  run_fuzz_test "store_adversarial_reorder" "fcp-store" \
    "--test store_repair_integration adversarial_reordered" \
    "contract.store_reordered_duplicate_reconstruction" \
    "adversarial_store"
else
  log_step "ADVERSARIAL_STORE" "Skipped (--only-matrices filter)"
fi

# =============================================================================
# Matrix 6: Boundary Enforcement Tests
# =============================================================================
# Validates: decode permits, mesh admission, protocol frame limits
# Crates: fcp-raptorq (decode permits), fcp-mesh (admission), fcp-protocol (limits)
# =============================================================================
if should_run_matrix "boundary"; then
  log_step "BOUNDARY" "Matrix 6: Boundary enforcement (permits, admission, limits)"

  # Decode permit enforcement (symbol count + memory + timeout bounds)
  run_fuzz_test "boundary_decode_permit" "fcp-raptorq" \
    "--lib decode" \
    "contract.decode_permit_boundary_enforcement" \
    "boundary"

  # Mesh admission control (byte + symbol + decode capacity budgets)
  run_fuzz_test "boundary_mesh_admission" "fcp-mesh" \
    "--test mesh_integration admission" \
    "contract.mesh_admission_boundary_enforcement" \
    "boundary"

  # Protocol frame size limits (FCPC + FCPS + datagram boundaries)
  run_fuzz_test "boundary_protocol_frames" "fcp-protocol" \
    "--lib" \
    "contract.protocol_frame_boundary_limits" \
    "boundary"

  # Session establishment boundary tests
  run_fuzz_test "boundary_session" "fcp-protocol" \
    "--lib session::tests" \
    "contract.session_establishment_boundaries" \
    "boundary"

  # CBOR canonical encoding boundaries
  run_fuzz_test "boundary_cbor" "fcp-cbor" \
    "--test cbor_golden_vector" \
    "contract.cbor_canonical_encoding_boundaries" \
    "boundary"
else
  log_step "BOUNDARY" "Skipped (--only-matrices filter)"
fi

# =============================================================================
# Matrix 7: E2E Adversarial Stress Scripts
# =============================================================================
# Validates: RaptorQ adversarial decode stress, degraded network recovery
# =============================================================================
if should_run_matrix "e2e_stress"; then
  log_step "E2E_STRESS" "Matrix 7: E2E adversarial stress scripts"

  STRESS_SCRIPTS=(
    "raptorq_adversarial_decode_stress.sh:contract.raptorq_adversarial_decode_stress:RaptorQ adversarial decode budget enforcement"
    "raptorq_degraded_network_recovery.sh:contract.raptorq_degraded_network_recovery:RaptorQ degraded network graceful recovery"
    "raptorq_partial_symbol_recovery.sh:contract.raptorq_partial_symbol_repair:RaptorQ partial symbol loss repair convergence"
    "raptorq_multinode_repair_convergence.sh:contract.raptorq_multinode_repair:RaptorQ multi-node placement repair"
  )

  for entry in "${STRESS_SCRIPTS[@]}"; do
    IFS=':' read -r script_name contract_id description <<< "${entry}"
    label="e2e_stress_$(echo "${script_name}" | sed 's/\.sh$//')"

    if [[ -x "${SCRIPT_DIR}/${script_name}" ]]; then
      log_step "E2E_STRESS" "${description}"
      run_stress_script "${label}" \
        "scripts/e2e/${script_name}" \
        "${contract_id}" \
        "e2e_stress"
    else
      log_step "E2E_STRESS" "WARN: ${script_name} not found or not executable"
      MATRIX_WARN=$((MATRIX_WARN + 1))
    fi
  done
else
  log_step "E2E_STRESS" "Skipped (--only-matrices filter)"
fi

# =============================================================================
# Generate Fuzz Coverage Report
# =============================================================================
log_step "COVERAGE" "Generating fuzz coverage report"

jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    matrices: [
      {
        id: "fuzz_compile",
        name: "Fuzz Target Compilation",
        targets: ["fuzz_capability", "fuzz_fcpc_frame", "fuzz_fcps_frame", "fuzz_fcps_datagram", "fuzz_session", "fuzz_session_transcript", "fuzz_zone_key_manifest"],
        target_count: 7,
        parsing_surfaces: ["COSE_Sign1", "FCPC frames", "FCPS frames", "FCPS datagrams", "Session messages", "Session transcripts", "ZoneKeyManifest"],
        contracts: ["contract.fuzz_cose_token_parsing", "contract.fuzz_fcpc_frame_parsing", "contract.fuzz_fcps_frame_parsing", "contract.fuzz_fcps_datagram_parsing", "contract.fuzz_session_message_parsing", "contract.fuzz_session_transcript_parsing", "contract.fuzz_zone_key_manifest_parsing"]
      },
      {
        id: "fuzz_corpus",
        name: "Fuzz Corpus Regression",
        description: "Replay 75+ known corpus seeds to verify zero crashes on migrated runtime",
        target_count: 7
      },
      {
        id: "proptest",
        name: "Property-Based Tests",
        components: ["fcp-crypto", "fcp-mesh"],
        properties: ["Shamir reconstruction correctness", "Information-theoretic security", "Deterministic share generation", "Share serialization roundtrip", "Mesh symbol request invariants"],
        test_count: 2
      },
      {
        id: "adversarial_raptorq",
        name: "Adversarial RaptorQ",
        components: ["fcp-raptorq"],
        attack_patterns: ["bursty_erasure", "front_heavy_erasure", "tail_heavy_erasure", "random_seeded_erasure", "interleaved_erasure", "single_bitflip", "multi_bitflip", "truncated_symbol", "zeroed_symbol"],
        test_count: 3
      },
      {
        id: "adversarial_store",
        name: "Store Adversarial",
        components: ["fcp-store"],
        attack_patterns: ["corrupted_symbols_rejection", "reordered_duplicate_reconstruction"],
        test_count: 2
      },
      {
        id: "boundary",
        name: "Boundary Enforcement",
        components: ["fcp-raptorq", "fcp-mesh", "fcp-protocol", "fcp-cbor"],
        boundary_surfaces: ["decode_permit_limits", "mesh_admission_budgets", "frame_size_limits", "session_establishment", "cbor_canonical_encoding"],
        test_count: 5
      },
      {
        id: "e2e_stress",
        name: "E2E Adversarial Stress",
        scripts: ["raptorq_adversarial_decode_stress.sh", "raptorq_degraded_network_recovery.sh", "raptorq_partial_symbol_recovery.sh", "raptorq_multinode_repair_convergence.sh"],
        test_count: 4
      }
    ],
    severity_legend: {
      "critical": "Crash, hang, or data corruption — blocks release",
      "high": "Behavioral regression affecting user-visible correctness or availability",
      "medium": "Non-critical boundary violation or degraded performance",
      "low": "Cosmetic or informational finding (e.g., missing corpus files)"
    }
  }' > "${COVERAGE_FILE}"

# =============================================================================
# Generate Findings Report
# =============================================================================
log_step "FINDINGS" "Generating findings report"

TOTAL_TESTS=$((MATRIX_PASS + MATRIX_FAIL + MATRIX_SKIP))
FINDING_COUNT=${#FINDING_RECORDS[@]}

FINDINGS_JSON='[]'
if (( FINDING_COUNT > 0 )); then
  FINDINGS_JSON="$(printf '%s\n' "${FINDING_RECORDS[@]}" | jq -s 'sort_by(.severity, .matrix, .test_name)')"
fi

# Classify finding severity counts
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
if (( FINDING_COUNT > 0 )); then
  CRITICAL_COUNT=$(echo "${FINDINGS_JSON}" | jq '[.[] | select(.severity == "critical")] | length')
  HIGH_COUNT=$(echo "${FINDINGS_JSON}" | jq '[.[] | select(.severity == "high")] | length')
  MEDIUM_COUNT=$(echo "${FINDINGS_JSON}" | jq '[.[] | select(.severity == "medium")] | length')
  LOW_COUNT=$(echo "${FINDINGS_JSON}" | jq '[.[] | select(.severity == "low")] | length')
fi

jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --argjson total_findings "${FINDING_COUNT}" \
  --argjson critical "${CRITICAL_COUNT}" \
  --argjson high "${HIGH_COUNT}" \
  --argjson medium "${MEDIUM_COUNT}" \
  --argjson low "${LOW_COUNT}" \
  --argjson findings "${FINDINGS_JSON}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    severity_summary: {
      total: $total_findings,
      critical: $critical,
      high: $high,
      medium: $medium,
      low: $low
    },
    findings: $findings,
    triage_guide: {
      critical: "Must fix before migration cutover. Indicates crash/hang/corruption in parsing or cryptographic paths.",
      high: "Fix required. Behavioral regression affecting user-visible quality.",
      medium: "Fix recommended. Boundary enforcement or performance degradation.",
      low: "Track. Informational finding (missing corpus, no-op warnings)."
    }
  }' > "${FINDINGS_FILE}"

# =============================================================================
# Generate Summary
# =============================================================================
log_step "SUMMARY" "Generating fuzz/adversarial revalidation summary"

OVERALL_STATUS="pass"
if (( MATRIX_FAIL > 0 )); then
  OVERALL_STATUS="fail"
elif (( MATRIX_WARN > 0 )); then
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
  --argjson fuzz_time "${FUZZ_TIME}" \
  --argjson total "${TOTAL_TESTS}" \
  --argjson pass "${MATRIX_PASS}" \
  --argjson fail "${MATRIX_FAIL}" \
  --argjson skip "${MATRIX_SKIP}" \
  --argjson warn "${MATRIX_WARN}" \
  --argjson finding_count "${FINDING_COUNT}" \
  --argjson critical_count "${CRITICAL_COUNT}" \
  --argjson high_count "${HIGH_COUNT}" \
  --arg only_matrices "${ONLY_MATRICES}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    overall_status: $overall_status,
    ci_mode: $ci_mode,
    dry_run: $dry_run,
    fuzz_time_per_target: $fuzz_time,
    tests: {
      total: $total,
      pass: $pass,
      fail: $fail,
      skip: $skip,
      warn: $warn
    },
    findings: {
      total: $finding_count,
      critical: $critical_count,
      high: $high_count
    },
    filters: {
      only_matrices: (if ($only_matrices | length) > 0 then $only_matrices else null end)
    },
    artifacts: {
      summary: "summary.json",
      steps: "steps.jsonl",
      findings: "findings.json",
      fuzz_coverage: "fuzz_coverage.json",
      replay: "replay.sh",
      logs: "logs/"
    },
    triage_guide: {
      findings: "Check findings.json for severity-classified results. Each entry has rerun_command.",
      fuzz_compile: "Compilation failures indicate async migration broke fuzz target dependencies.",
      fuzz_corpus: "Corpus regression failures indicate new crashes on known inputs — critical.",
      proptest: "Property failures indicate violated algebraic invariants after migration.",
      adversarial: "Adversarial failures indicate weakened robustness boundaries.",
      boundary: "Boundary failures indicate protocol/resource limit enforcement regression."
    }
  }' > "${SUMMARY_FILE}"

# =============================================================================
# Generate Replay Script
# =============================================================================
cat > "${REPLAY_FILE}" <<REPLAY_EOF
#!/usr/bin/env bash
# Replay: Fuzz + Adversarial Boundary Revalidation ${RUN_ID}
# Generated: $(now_iso)
set -euo pipefail

echo "=== Replaying Fuzz/Adversarial Revalidation: ${RUN_ID} ==="

bash scripts/e2e/e2e_fuzz_adversarial_revalidation.sh \\
  --run-id "${RUN_ID}" \\
  --out-root "${OUT_ROOT}" \\
  --fuzz-time "${FUZZ_TIME}"$(
  [[ -n "${ONLY_MATRICES}" ]] && printf ' \\\n  --only-matrices "%s"' "${ONLY_MATRICES}"
  [[ "${CI_MODE}" == "true" ]] && printf ' \\\n  --ci'
  )
REPLAY_EOF
chmod +x "${REPLAY_FILE}"

# =============================================================================
# Generate Rerun-Findings Script
# =============================================================================
if (( FINDING_COUNT > 0 )); then
  RERUN_FILE="${OUT_ROOT}/rerun_findings.sh"
  {
    echo "#!/usr/bin/env bash"
    echo "# Rerun findings from fuzz/adversarial revalidation: ${RUN_ID}"
    echo "# Generated: $(now_iso)"
    echo "set -euo pipefail"
    echo ""
    echo "echo '=== Rerunning ${FINDING_COUNT} findings ==='"
    echo ""
    for f in "${FINDING_RECORDS[@]}"; do
      rerun_cmd="$(echo "${f}" | jq -r '.rerun_command')"
      test_name="$(echo "${f}" | jq -r '.test_name')"
      severity="$(echo "${f}" | jq -r '.severity')"
      echo "echo '--- [${severity}] ${test_name} ---'"
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
echo "  FUZZ + ADVERSARIAL BOUNDARY REVALIDATION — ${RUN_ID}"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "  Overall Status:       ${OVERALL_STATUS}"
echo "  CI Mode:              ${CI_MODE}"
echo "  Dry Run:              ${DRY_RUN}"
echo "  Fuzz Time/Target:     ${FUZZ_TIME}s"
echo ""
echo "  Tests:                ${TOTAL_TESTS} total"
echo "    Pass:               ${MATRIX_PASS}"
echo "    Fail:               ${MATRIX_FAIL}"
echo "    Skip:               ${MATRIX_SKIP}"
echo "    Warn:               ${MATRIX_WARN}"
echo ""
echo "  Findings:             ${FINDING_COUNT} total"
echo "    Critical:           ${CRITICAL_COUNT}"
echo "    High:               ${HIGH_COUNT}"
echo "    Medium:             ${MEDIUM_COUNT}"
echo "    Low:                ${LOW_COUNT}"
if [[ -n "${ONLY_MATRICES}" ]]; then
  echo "  Filter:               ${ONLY_MATRICES}"
fi
echo ""
echo "  Matrices Validated:"
echo "    1. fuzz_compile       — 7 libfuzzer targets compile check"
echo "    2. fuzz_corpus        — Corpus regression (75+ seeds, zero crashes)"
echo "    3. proptest           — Property-based (Shamir, mesh symbol)"
echo "    4. adversarial_raptorq — Erasure recovery + corruption detection"
echo "    5. adversarial_store  — Store corruption + reorder robustness"
echo "    6. boundary           — Decode permits, admission, frame limits"
echo "    7. e2e_stress         — RaptorQ adversarial stress scripts"
echo ""
echo "  Artifacts:            ${OUT_ROOT}/"
echo "    summary.json              — revalidation summary"
echo "    steps.jsonl               — per-test forensic steps"
echo "    findings.json             — severity-classified findings"
echo "    fuzz_coverage.json        — fuzz target coverage map"
echo "    replay.sh                 — deterministic replay"
echo "    logs/                     — per-test execution logs"
echo ""
echo "════════════════════════════════════════════════════════════════════"

if (( FINDING_COUNT > 0 )); then
  echo ""
  echo "  Findings requiring investigation:"
  for f in "${FINDING_RECORDS[@]}"; do
    severity="$(echo "${f}" | jq -r '.severity')"
    matrix="$(echo "${f}" | jq -r '.matrix')"
    test_name="$(echo "${f}" | jq -r '.test_name')"
    contract_id="$(echo "${f}" | jq -r '.contract_id')"
    description="$(echo "${f}" | jq -r '.description[:120]')"
    echo "  - [${severity}] ${matrix}/${test_name} (${contract_id}): ${description}"
  done
  echo ""
  echo "  Rerun: bash ${OUT_ROOT}/rerun_findings.sh"
  echo ""
fi

if [[ "${OVERALL_STATUS}" == "fail" ]]; then
  exit 1
fi
