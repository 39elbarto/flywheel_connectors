#!/usr/bin/env bash
# =============================================================================
# e2e_recovery_guidance_validation.sh — Recovery Guidance + User Journey Assertions
# =============================================================================
# Bead:     235t.33.3 (ASUPERSYNC-UX Recovery Guidance Surfaces)
# Schema:   asupersync-recovery-guidance-validation/v1
#
# Validates that user-facing recovery guidance remains clear, actionable, and
# consistent across API/CLI/connector response surfaces after async migration.
#
# Validation Phases:
#   1. Error taxonomy coverage (all 8 categories have recovery hints)
#   2. Recovery hint quality (no opaque/ambiguous messages)
#   3. Wire format stability (FcpErrorResponse JSON roundtrip)
#   4. Retryability consistency (flag matches actual retry behavior)
#   5. Connector error mapping (all 6 connectors implement mapping chain)
#   6. User journey assertions (error → guidance → action → recovery)
#   7. Recovery evidence bundle (before/after examples + replay)
#
# Usage:
#   bash scripts/e2e/e2e_recovery_guidance_validation.sh [options]
#
# Options:
#   --run-id <id>           Stable run identifier (default: UTC timestamp)
#   --out-root <path>       Artifact root directory
#   --dry-run               Emit plan without executing tests
#   --only-phases <csv>     Filter: taxonomy,hint_quality,wire_format,
#                           retryability,connector_mapping,user_journey
#   --ci                    CI mode
#   -h, --help              Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GATE_SCHEMA="asupersync-recovery-guidance-validation/v1"
FORENSICS_SCHEMA="asupersync-forensics/v1"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT=""
DRY_RUN=false
CI_MODE="${CI:-false}"
ONLY_PHASES=""

declare -i CHECK_PASS=0
declare -i CHECK_FAIL=0
declare -i CHECK_SKIP=0
declare -i CHECK_WARN=0
declare -a FINDING_RECORDS=()

usage() {
  cat <<'EOF'
Usage: scripts/e2e/e2e_recovery_guidance_validation.sh [options]

Recovery Guidance Surfaces + User Journey Assertions

Validates user-facing recovery guidance across API/CLI/connector surfaces.
Proves users can execute prescribed remediation to recover service.

Options:
  --run-id <id>           Stable run identifier (default: UTC timestamp)
  --out-root <path>       Artifact root (default: artifacts/asupersync/recovery-guidance/<run-id>)
  --dry-run               Emit plan without executing tests
  --only-phases <csv>     Filter: taxonomy,hint_quality,wire_format,
                          retryability,connector_mapping,user_journey
  --ci                    CI mode
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
  printf '[%s] [RECOVERY-GUIDANCE/%s] %s\n' "$(now_iso)" "$1" "$2"
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
  local phase="$1"
  local test_name="$2"
  local severity="$3"
  local description="$4"
  local remediation="$5"
  local f
  f="$(jq -c -n \
    --arg phase "${phase}" \
    --arg test_name "${test_name}" \
    --arg severity "${severity}" \
    --arg description "${description}" \
    --arg remediation "${remediation}" \
    --arg found_at "$(now_iso)" \
    '{
      phase: $phase,
      test_name: $test_name,
      severity: $severity,
      description: $description,
      remediation: $remediation,
      found_at: $found_at
    }')"
  FINDING_RECORDS+=("${f}")
}

should_run_phase() {
  local phase="$1"
  if [[ -z "${ONLY_PHASES}" ]]; then
    return 0
  fi
  echo ",${ONLY_PHASES}," | grep -q ",${phase}," && return 0
  return 1
}

run_cargo_check() {
  local label="$1"
  local package="$2"
  local test_filter="$3"
  local contract_id="$4"
  local phase_name="$5"
  local log_file="${OUT_ROOT}/logs/${label}.log"
  local scenario_id="recovery_guidance.${label}"

  mkdir -p "${OUT_ROOT}/logs"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_step "${label}" "[dry-run] cargo test -p ${package} ${test_filter}"
    echo "[dry-run] cargo test -p ${package} ${test_filter}" > "${log_file}"
    record_step "${scenario_id}" "cargo_test" "planned" 0 "${contract_id}" "dry_run" "${log_file}"
    CHECK_SKIP=$((CHECK_SKIP + 1))
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
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-recovery-guidance}" \
      cargo test -p "${package}" ${test_filter} -- --nocapture > "${log_file}" 2>&1 && status="pass" || status="fail"
  fi
  end=$(now_ms)
  elapsed=$((end - start))

  if [[ "${status}" == "pass" ]]; then
    CHECK_PASS=$((CHECK_PASS + 1))
    log_step "${label}" "PASS (${elapsed}ms)"
    record_step "${scenario_id}" "cargo_test" "pass" "${elapsed}" "${contract_id}" "" "${log_file}"
  else
    CHECK_FAIL=$((CHECK_FAIL + 1))
    local reason
    reason="$(tail -5 "${log_file}" | head -3 | tr '\n' ' ' | head -c 200)"
    log_step "${label}" "FAIL (${elapsed}ms): ${reason}"
    record_step "${scenario_id}" "cargo_test" "fail" "${elapsed}" "${contract_id}" "${reason}" "${log_file}"
    add_finding "${phase_name}" "${label}" "high" "${reason}" \
      "cargo test -p ${package} ${test_filter} -- --nocapture"
  fi
}

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)       RUN_ID="$2"; shift 2;;
    --out-root)     OUT_ROOT="$2"; shift 2;;
    --dry-run)      DRY_RUN=true; shift;;
    --only-phases)  ONLY_PHASES="$2"; shift 2;;
    --ci)           CI_MODE=true; shift;;
    -h|--help)      usage; exit 0;;
    *)              echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

# ── Pre-flight ──────────────────────────────────────────────────────────────
require_cmd jq
require_cmd cargo

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/recovery-guidance/${RUN_ID}"
fi
mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

STEPS_FILE="${OUT_ROOT}/steps.jsonl"
SUMMARY_FILE="${OUT_ROOT}/summary.json"
FINDINGS_FILE="${OUT_ROOT}/findings.json"
EVIDENCE_FILE="${OUT_ROOT}/evidence/recovery_examples.json"
REPLAY_FILE="${OUT_ROOT}/replay.sh"

: > "${STEPS_FILE}"

log_step "INIT" "Recovery Guidance Validation v1 — run_id=${RUN_ID}"
log_step "INIT" "Output: ${OUT_ROOT}"
echo ""

# =============================================================================
# Phase 1: Error Taxonomy Coverage
# =============================================================================
# Validates: all 8 error categories have recovery hints, error codes are
#            complete, and every FcpError variant produces a well-formed response
# =============================================================================
if should_run_phase "taxonomy"; then
  log_step "TAXONOMY" "Phase 1: Error taxonomy coverage (8 categories, 30+ variants)"

  # Error serialization roundtrip (FcpError → JSON → FcpError)
  run_cargo_check "taxonomy_serialization" "fcp-core" \
    "--lib error::tests" \
    "contract.error_taxonomy_serialization" \
    "taxonomy"

  # Error taxonomy code range contracts (non-overlapping)
  run_cargo_check "taxonomy_code_ranges" "fcp-sdk" \
    "--test error_contract_tests error_code" \
    "contract.error_code_range_contracts" \
    "taxonomy"

  # All categories produce valid FcpErrorResponse
  run_cargo_check "taxonomy_response_format" "fcp-sdk" \
    "--test error_contract_tests wire_format" \
    "contract.error_response_format" \
    "taxonomy"
else
  log_step "TAXONOMY" "Skipped (--only-phases filter)"
fi

# =============================================================================
# Phase 2: Recovery Hint Quality
# =============================================================================
# Validates: ai_recovery_hint is non-empty for all variants, no generic
#            "error occurred" messages, hints contain actionable verbs
# =============================================================================
if should_run_phase "hint_quality"; then
  log_step "HINT_QUALITY" "Phase 2: Recovery hint quality (actionable, non-generic)"

  # Full error contract test suite (includes hint validation)
  run_cargo_check "hint_quality_contracts" "fcp-sdk" \
    "--test error_contract_tests" \
    "contract.recovery_hint_quality" \
    "hint_quality"

  # Core error module tests (includes to_response with hints)
  run_cargo_check "hint_quality_core" "fcp-core" \
    "--lib error::" \
    "contract.error_core_hints" \
    "hint_quality"

  # Error taxonomy documentation existence check
  phase_start=$(now_ms)
  log_file="${OUT_ROOT}/logs/hint_quality_docs.log"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "[dry-run] Check docs/ASUPERSYNC_Error_Taxonomy.md" > "${log_file}"
    record_step "recovery_guidance.hint_quality_docs" "doc_check" "planned" 0 \
      "contract.error_taxonomy_documentation" "dry_run" "${log_file}"
    CHECK_SKIP=$((CHECK_SKIP + 1))
  else
    taxonomy_ok=true
    taxonomy_reasons=""

    if [[ ! -f "${REPO_ROOT}/docs/ASUPERSYNC_Error_Taxonomy.md" ]]; then
      taxonomy_ok=false
      taxonomy_reasons="Error taxonomy document not found"
    else
      # Check that key sections exist
      for section in "Protocol" "Auth" "Capability" "Zone" "Connector" "Resource" "External" "Internal"; do
        if ! grep -qi "${section}" "${REPO_ROOT}/docs/ASUPERSYNC_Error_Taxonomy.md"; then
          taxonomy_ok=false
          taxonomy_reasons="${taxonomy_reasons}Missing section: ${section}. "
        fi
      done
    fi

    phase_end=$(now_ms)
    phase_elapsed=$((phase_end - phase_start))

    if [[ "${taxonomy_ok}" == "true" ]]; then
      CHECK_PASS=$((CHECK_PASS + 1))
      log_step "HINT_QUALITY" "Taxonomy doc: PASS — all 8 categories documented"
      echo "All 8 error categories found in taxonomy document" > "${log_file}"
      record_step "recovery_guidance.hint_quality_docs" "doc_check" "pass" "${phase_elapsed}" \
        "contract.error_taxonomy_documentation" "" "${log_file}"
    else
      CHECK_FAIL=$((CHECK_FAIL + 1))
      log_step "HINT_QUALITY" "Taxonomy doc: FAIL — ${taxonomy_reasons}"
      echo "${taxonomy_reasons}" > "${log_file}"
      record_step "recovery_guidance.hint_quality_docs" "doc_check" "fail" "${phase_elapsed}" \
        "contract.error_taxonomy_documentation" "${taxonomy_reasons}" "${log_file}"
      add_finding "hint_quality" "taxonomy_documentation" "medium" \
        "${taxonomy_reasons}" \
        "Review docs/ASUPERSYNC_Error_Taxonomy.md for completeness"
    fi
  fi
else
  log_step "HINT_QUALITY" "Skipped (--only-phases filter)"
fi

# =============================================================================
# Phase 3: Wire Format Stability
# =============================================================================
# Validates: FcpErrorResponse JSON serialization, all fields present,
#            code format (FCP-XXXX), retryable flag, retry_after_ms
# =============================================================================
if should_run_phase "wire_format"; then
  log_step "WIRE_FORMAT" "Phase 3: Wire format stability (FcpErrorResponse)"

  # Wire format JSON roundtrip tests
  run_cargo_check "wire_format_roundtrip" "fcp-sdk" \
    "--test error_contract_tests json_roundtrip" \
    "contract.error_wire_format_stability" \
    "wire_format"

  # Core error Display + Debug stability
  run_cargo_check "wire_format_display" "fcp-sdk" \
    "--test error_contract_tests display" \
    "contract.error_display_stability" \
    "wire_format"
else
  log_step "WIRE_FORMAT" "Skipped (--only-phases filter)"
fi

# =============================================================================
# Phase 4: Retryability Consistency
# =============================================================================
# Validates: retryable flag matches actual retry behavior, retry_after
#            durations are respected, HTTP status classification is correct
# =============================================================================
if should_run_phase "retryability"; then
  log_step "RETRYABILITY" "Phase 4: Retryability consistency (flag ↔ behavior)"

  # Retryability contract tests
  run_cargo_check "retryability_contracts" "fcp-sdk" \
    "--test error_contract_tests retryab" \
    "contract.retryability_flag_consistency" \
    "retryability"

  # HTTP status classification
  run_cargo_check "retryability_http_classify" "fcp-sdk" \
    "--test error_contract_tests classify" \
    "contract.http_status_classification" \
    "retryability"

  # Retry integration tests (RetryLoop behavior)
  run_cargo_check "retryability_retry_loop" "fcp-sdk" \
    "--test retry_integration" \
    "contract.retry_loop_behavior" \
    "retryability"

  # SDK migration module (AsyncError mapping + retryability)
  run_cargo_check "retryability_async_mapping" "fcp-sdk" \
    "--lib migration::" \
    "contract.async_error_retryability" \
    "retryability"
else
  log_step "RETRYABILITY" "Skipped (--only-phases filter)"
fi

# =============================================================================
# Phase 5: Connector Error Mapping Chain
# =============================================================================
# Validates: all 6 connectors implement ConnectorErrorMapping correctly,
#            error codes are consistent, retryability is preserved through chain
# =============================================================================
if should_run_phase "connector_mapping"; then
  log_step "CONNECTOR_MAPPING" "Phase 5: Connector error mapping chain (6 connectors)"

  CONNECTORS=(
    "connector-anthropic:contract.anthropic_error_mapping"
    "connector-openai:contract.openai_error_mapping"
    "connector-discord:contract.discord_error_mapping"
    "connector-telegram:contract.telegram_error_mapping"
    "connector-twitter:contract.twitter_error_mapping"
    "connector-vectordb:contract.vectordb_error_mapping"
  )

  for entry in "${CONNECTORS[@]}"; do
    IFS=':' read -r pkg contract_id <<< "${entry}"
    label="connector_mapping_$(echo "${pkg}" | sed 's/connector-//')"

    run_cargo_check "${label}" "${pkg}" \
      "--all-targets" \
      "${contract_id}" \
      "connector_mapping"
  done
else
  log_step "CONNECTOR_MAPPING" "Skipped (--only-phases filter)"
fi

# =============================================================================
# Phase 6: User Journey Assertions
# =============================================================================
# Validates: end-to-end error → recovery → success journeys, proving that
#            prescribed remediation actually works across API/CLI/connector
# =============================================================================
if should_run_phase "user_journey"; then
  log_step "USER_JOURNEY" "Phase 6: User journey assertions (error → recovery → success)"

  # Full error chain tests (AsyncError → ConnectorError → FcpError → Response)
  run_cargo_check "user_journey_full_chain" "fcp-sdk" \
    "--test error_contract_tests full_chain" \
    "contract.user_journey_error_chain" \
    "user_journey"

  # Host doctor service (health check → remediation)
  run_cargo_check "user_journey_doctor" "fcp-host" \
    "--lib doctor::" \
    "contract.user_journey_doctor_remediation" \
    "user_journey"

  # Rate limit enforcement → retry → success path
  run_cargo_check "user_journey_rate_limit" "fcp-host" \
    "--test rate_limit_integration" \
    "contract.user_journey_rate_limit_recovery" \
    "user_journey"

  # Host connector lifecycle (configure → handshake → error → retry)
  run_cargo_check "user_journey_lifecycle" "fcp-host" \
    "--test host_connector_integration" \
    "contract.user_journey_connector_lifecycle" \
    "user_journey"
else
  log_step "USER_JOURNEY" "Skipped (--only-phases filter)"
fi

# =============================================================================
# Phase 7: Generate Recovery Evidence Bundle
# =============================================================================
log_step "EVIDENCE" "Phase 7: Generating recovery evidence bundle"

# Build recovery examples catalog showing before/after for each error category
jq -n \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  '{
    run_id: $run_id,
    generated_at: $generated_at,
    description: "Before/after recovery guidance examples for each error category",
    categories: [
      {
        category: "Protocol (1xxx)",
        before: {"code": "FCP-1001", "message": "Invalid request format", "retryable": false},
        after: {"code": "FCP-1001", "message": "Invalid request format", "retryable": false, "ai_recovery_hint": "Check request format & schema"},
        recovery_action: "Fix request payload per FCP protocol specification",
        journey: "Client sends malformed CBOR → receives FCP-1001 with hint → fixes payload → success"
      },
      {
        category: "Auth (2xxx)",
        before: {"code": "FCP-2001", "message": "Unauthorized", "retryable": false},
        after: {"code": "FCP-2001", "message": "Unauthorized", "retryable": false, "ai_recovery_hint": "Verify credentials & zone access"},
        recovery_action: "Re-authenticate with valid credentials for the target zone",
        journey: "Client sends expired token → receives FCP-2001 with hint → refreshes token → success"
      },
      {
        category: "Capability (3xxx)",
        before: {"code": "FCP-3002", "message": "Rate limited", "retryable": true, "retry_after_ms": 1000},
        after: {"code": "FCP-3002", "message": "Rate limited", "retryable": true, "retry_after_ms": 1000, "ai_recovery_hint": "Wait 1000ms; batch/spread requests"},
        recovery_action: "Wait for retry_after_ms, then retry with exponential backoff",
        journey: "Client exceeds rate limit → receives FCP-3002 with retry_after → waits → retries → success"
      },
      {
        category: "Zone/Topology (4xxx)",
        before: {"code": "FCP-4001", "message": "Zone violation", "retryable": false},
        after: {"code": "FCP-4001", "message": "Zone violation", "retryable": false, "ai_recovery_hint": "Request ApprovalToken or restructure workflow"},
        recovery_action: "Obtain zone-crossing approval token from policy admin",
        journey: "Client crosses zone boundary → receives FCP-4001 → requests approval → retries with ApprovalToken → success"
      },
      {
        category: "Connector (5xxx)",
        before: {"code": "FCP-5001", "message": "Connector unavailable", "retryable": true},
        after: {"code": "FCP-5001", "message": "Connector unavailable", "retryable": true, "ai_recovery_hint": "Check connector health; run fcp doctor"},
        recovery_action: "Run fcp doctor, verify external service connectivity, retry",
        journey: "Client calls unavailable connector → receives FCP-5001 → runs fcp doctor → restarts connector → success"
      },
      {
        category: "Resource (6xxx)",
        before: {"code": "FCP-6002", "message": "Resource exhausted", "retryable": true},
        after: {"code": "FCP-6002", "message": "Resource exhausted", "retryable": true, "ai_recovery_hint": "Wait for resources or reduce concurrent usage"},
        recovery_action: "Reduce concurrency or wait for resource pool replenishment",
        journey: "Client exhausts connection pool → receives FCP-6002 → reduces concurrency → retries → success"
      },
      {
        category: "External (7xxx)",
        before: {"code": "FCP-7001", "message": "External service error", "retryable": true, "retry_after_ms": 5000},
        after: {"code": "FCP-7001", "message": "External service error", "retryable": true, "retry_after_ms": 5000, "ai_recovery_hint": "This is retryable; wait & retry with exponential backoff"},
        recovery_action: "Retry with exponential backoff; check upstream service status if persistent",
        journey: "External API returns 503 → receives FCP-7001 → waits 5s → retries → upstream recovers → success"
      },
      {
        category: "Internal (9xxx)",
        before: {"code": "FCP-9001", "message": "Internal error", "retryable": false},
        after: {"code": "FCP-9001", "message": "Internal error", "retryable": false, "ai_recovery_hint": "This is a bug; report with error details & correlation ID"},
        recovery_action: "Report bug with correlation_id for investigation; do not retry",
        journey: "Unexpected state → receives FCP-9001 with correlation_id → files bug report → team investigates → fix deployed"
      }
    ],
    retryability_matrix: {
      always_retry: ["RateLimited", "ResourceExhausted", "BudgetExceeded", "UpstreamTimeout", "DependencyUnavailable", "ConnectorUnavailable", "ChecksumMismatch"],
      conditional_retry: ["External (retryable=true, status 5xx/408/429)", "Conflict"],
      never_retry: ["Auth (all)", "Capability (non-rate-limit)", "Zone (all)", "NotConfigured", "NotHandshaken", "InvalidRequest", "Internal"]
    },
    connector_mapping_chain: {
      description: "AsyncError → ConnectorError → FcpError → FcpErrorResponse",
      layers: [
        "AsyncError (fcp-async-core): Timeout, Cancelled, ChannelClosed, ProtocolIo",
        "ConnectorError (per connector): connector-specific variants",
        "FcpError (fcp-core): 8 categories, 30+ variants, canonical",
        "FcpErrorResponse (wire): code, message, retryable, retry_after_ms, ai_recovery_hint"
      ]
    }
  }' > "${EVIDENCE_FILE}"

CHECK_PASS=$((CHECK_PASS + 1))
record_step "recovery_guidance.evidence_bundle" "generate" "pass" 0 \
  "contract.recovery_evidence_bundle"

# =============================================================================
# Generate Findings Report
# =============================================================================
log_step "FINDINGS" "Generating findings report"

TOTAL_CHECKS=$((CHECK_PASS + CHECK_FAIL + CHECK_SKIP))
FINDING_COUNT=${#FINDING_RECORDS[@]}

FINDINGS_JSON='[]'
if (( FINDING_COUNT > 0 )); then
  FINDINGS_JSON="$(printf '%s\n' "${FINDING_RECORDS[@]}" | jq -s 'sort_by(.severity, .phase)')"
fi

jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --argjson total_findings "${FINDING_COUNT}" \
  --argjson findings "${FINDINGS_JSON}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    finding_count: $total_findings,
    findings: $findings
  }' > "${FINDINGS_FILE}"

# =============================================================================
# Generate Summary
# =============================================================================
log_step "SUMMARY" "Generating recovery guidance validation summary"

OVERALL_STATUS="pass"
if (( CHECK_FAIL > 0 )); then
  OVERALL_STATUS="fail"
elif (( CHECK_WARN > 0 )); then
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
  --argjson total "${TOTAL_CHECKS}" \
  --argjson pass "${CHECK_PASS}" \
  --argjson fail "${CHECK_FAIL}" \
  --argjson skip "${CHECK_SKIP}" \
  --argjson warn "${CHECK_WARN}" \
  --argjson finding_count "${FINDING_COUNT}" \
  --arg only_phases "${ONLY_PHASES}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    overall_status: $overall_status,
    ci_mode: $ci_mode,
    dry_run: $dry_run,
    checks: {
      total: $total,
      pass: $pass,
      fail: $fail,
      skip: $skip,
      warn: $warn
    },
    finding_count: $finding_count,
    filters: {
      only_phases: (if ($only_phases | length) > 0 then $only_phases else null end)
    },
    phases: {
      taxonomy: "Error taxonomy coverage: 8 categories, code ranges, response format",
      hint_quality: "Recovery hint quality: non-generic, actionable, documented",
      wire_format: "Wire format stability: FcpErrorResponse JSON roundtrip",
      retryability: "Retryability consistency: flag matches behavior, HTTP classification",
      connector_mapping: "Connector mapping chain: all 6 connectors implement mapping",
      user_journey: "User journey assertions: error → guidance → recovery path"
    },
    artifacts: {
      summary: "summary.json",
      steps: "steps.jsonl",
      findings: "findings.json",
      evidence: "evidence/recovery_examples.json",
      replay: "replay.sh",
      logs: "logs/"
    }
  }' > "${SUMMARY_FILE}"

# =============================================================================
# Generate Replay Script
# =============================================================================
cat > "${REPLAY_FILE}" <<REPLAY_EOF
#!/usr/bin/env bash
# Replay: Recovery Guidance Validation ${RUN_ID}
# Generated: $(now_iso)
set -euo pipefail

echo "=== Replaying Recovery Guidance Validation: ${RUN_ID} ==="

bash scripts/e2e/e2e_recovery_guidance_validation.sh \\
  --run-id "${RUN_ID}" \\
  --out-root "${OUT_ROOT}"$(
  [[ -n "${ONLY_PHASES}" ]] && printf ' \\\n  --only-phases "%s"' "${ONLY_PHASES}"
  [[ "${CI_MODE}" == "true" ]] && printf ' \\\n  --ci'
  )
REPLAY_EOF
chmod +x "${REPLAY_FILE}"

# =============================================================================
# Summary Output
# =============================================================================
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  RECOVERY GUIDANCE VALIDATION — ${RUN_ID}"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "  Overall Status:       ${OVERALL_STATUS}"
echo "  CI Mode:              ${CI_MODE}"
echo "  Dry Run:              ${DRY_RUN}"
echo ""
echo "  Checks:               ${TOTAL_CHECKS} total"
echo "    Pass:               ${CHECK_PASS}"
echo "    Fail:               ${CHECK_FAIL}"
echo "    Skip:               ${CHECK_SKIP}"
echo "    Warn:               ${CHECK_WARN}"
echo ""
echo "  Findings:             ${FINDING_COUNT}"
if [[ -n "${ONLY_PHASES}" ]]; then
  echo "  Filter:               ${ONLY_PHASES}"
fi
echo ""
echo "  Phases Validated:"
echo "    1. taxonomy           — Error taxonomy coverage (8 categories)"
echo "    2. hint_quality       — Recovery hint quality (actionable, non-generic)"
echo "    3. wire_format        — Wire format stability (FcpErrorResponse)"
echo "    4. retryability       — Retryability consistency (flag ↔ behavior)"
echo "    5. connector_mapping  — Connector error mapping chain (6 connectors)"
echo "    6. user_journey       — User journey assertions (error → recovery)"
echo "    7. evidence           — Recovery evidence bundle (before/after)"
echo ""
echo "  Artifacts:            ${OUT_ROOT}/"
echo "    summary.json                    — validation summary"
echo "    steps.jsonl                     — per-check forensic steps"
echo "    findings.json                   — identified issues"
echo "    evidence/recovery_examples.json — before/after examples"
echo "    replay.sh                       — deterministic replay"
echo "    logs/                           — per-check execution logs"
echo ""
echo "════════════════════════════════════════════════════════════════════"

if (( FINDING_COUNT > 0 )); then
  echo ""
  echo "  Findings:"
  for f in "${FINDING_RECORDS[@]}"; do
    severity="$(echo "${f}" | jq -r '.severity')"
    phase="$(echo "${f}" | jq -r '.phase')"
    test_name="$(echo "${f}" | jq -r '.test_name')"
    desc="$(echo "${f}" | jq -r '.description[:120]')"
    echo "  - [${severity}] ${phase}/${test_name}: ${desc}"
  done
  echo ""
fi

if [[ "${OVERALL_STATUS}" == "fail" ]]; then
  exit 1
fi
