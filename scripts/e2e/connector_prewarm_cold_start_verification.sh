#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-}"
REQUIRE_PRODUCTION_SOAK="${REQUIRE_PRODUCTION_SOAK:-0}"
EVIDENCE_JSONL_IN="${EVIDENCE_JSONL_IN:-}"

usage() {
  cat <<'EOF'
Usage: scripts/e2e/connector_prewarm_cold_start_verification.sh [options]

Options:
  --run-id <id>      Run identifier for artifact paths
  --out-root <path>  Artifact root (default: artifacts/e2e/connector-prewarm-cold-start/<run-id>)
  --require-production-soak
                     Fail unless evidence is host-backed/live soak evidence
  --evidence-jsonl <path>
                     Validate an existing production/smoke evidence JSONL file
                     instead of running the embedded rch Cargo lane
  -h, --help         Show this help

Runs the connector cold-start prewarm evidence lane through rch, extracts
redaction-safe JSONL emitted by the fcp-e2e swarm gauntlet test, validates the
required scenario coverage, and writes an operator replay bundle.

By default this validates the deterministic smoke lane. Set
REQUIRE_PRODUCTION_SOAK=1 or pass --require-production-soak for final
acceptance gating; offline policy evidence must not satisfy that mode.
Remote prerequisite skips are non-fatal for deterministic smoke evidence but
fail closed when production-soak evidence is required.
Use --evidence-jsonl to validate externally collected production-soak records
through the same fail-closed schema, boundary, scenario, and redaction checks.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    --out-root)
      OUT_ROOT="$2"
      shift 2
      ;;
    --require-production-soak)
      REQUIRE_PRODUCTION_SOAK=1
      shift
      ;;
    --evidence-jsonl)
      EVIDENCE_JSONL_IN="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/e2e/connector-prewarm-cold-start/${RUN_ID}"
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 2
  fi
}

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

mark_validation_redaction_failed() {
  local reason="$1"
  if [[ -s "${VALIDATION_JSON}" ]]; then
    local validation_redaction_tmp="${VALIDATION_JSON}.redaction"
    if jq --arg reason "${reason}" \
      '.redaction_scan_ok = false | .redaction_scan_reason = $reason | .status = "failed"' \
      "${VALIDATION_JSON}" > "${validation_redaction_tmp}"; then
      mv "${validation_redaction_tmp}" "${VALIDATION_JSON}"
    fi
  fi
}

require_cmd jq
if [[ -z "${EVIDENCE_JSONL_IN}" ]]; then
  require_cmd rch
fi

case "${REQUIRE_PRODUCTION_SOAK}" in
  1|true|TRUE|yes|YES)
    require_production_soak_json=true
    ;;
  0|false|FALSE|no|NO)
    require_production_soak_json=false
    ;;
  *)
    echo "REQUIRE_PRODUCTION_SOAK must be 0/1/true/false/yes/no" >&2
    exit 2
    ;;
esac

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

TEST_LOG="${OUT_ROOT}/logs/prewarm-cold-start-test.log"
EVIDENCE_JSONL="${OUT_ROOT}/evidence/prewarm-cold-start.jsonl"
VALIDATION_JSON="${OUT_ROOT}/evidence/validation.json"
SKIP_JSONL="${OUT_ROOT}/evidence/prewarm-cold-start-skip.jsonl"
SUMMARY_JSON="${OUT_ROOT}/summary.json"
ENVIRONMENT_JSON="${OUT_ROOT}/environment.json"
REPLAY_SH="${OUT_ROOT}/replay.sh"

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
target_dir="${PREWARM_CARGO_TARGET_DIR:-/tmp/fcp-prewarm-cold-start-${RUN_ID}}"
test_status="passed"
evidence_status="passed"
validation_status="passed"
redaction_status="passed"
overall_status="passed"
skip_reason=""
exit_code=0

if [[ -n "${EVIDENCE_JSONL_IN}" ]]; then
  if [[ ! -s "${EVIDENCE_JSONL_IN}" ]]; then
    echo "Evidence JSONL input does not exist or is empty: ${EVIDENCE_JSONL_IN}" >&2
    exit 2
  fi
  echo "[connector-prewarm-cold-start] validating provided evidence JSONL ${EVIDENCE_JSONL_IN}"
  test_status="provided"
  cp "${EVIDENCE_JSONL_IN}" "${EVIDENCE_JSONL}"
  printf 'validated provided evidence JSONL: %s\n' "${EVIDENCE_JSONL_IN}" >"${TEST_LOG}"
else
  echo "[connector-prewarm-cold-start] running fcp-e2e prewarm evidence lane"
  if ! (
    cd "${REPO_ROOT}"
    env RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}" rch exec -- env \
      RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}" \
      CARGO_TARGET_DIR="${target_dir}" \
      PREWARM_EVIDENCE_CARGO_TARGET_DIR="${target_dir}" \
      CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" \
      CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}" \
      CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}" \
      CARGO_PROFILE_TEST_DEBUG="${CARGO_PROFILE_TEST_DEBUG:-0}" \
      RUSTFLAGS="${RUSTFLAGS:--Cdebuginfo=0}" \
      cargo test -p fcp-e2e --no-default-features --test swarm_gauntlet_e2e prewarm_cold_start -- --nocapture
  ) >"${TEST_LOG}" 2>&1; then
    test_status="failed"
  fi
fi

if [[ "${test_status}" == "failed" ]]; then
  if grep -aE '(no workers passed|all workers failed preflight|failed to execute process|topology preflight|Permission denied|No such file or directory|refus(ed|ing) local fallback)' "${TEST_LOG}" >/dev/null; then
    skip_reason="rch_remote_prerequisite_unavailable"
    test_status="skipped"
    evidence_status="skipped"
    if [[ "${require_production_soak_json}" == "true" ]]; then
      overall_status="failed"
      validation_status="failed"
      exit_code=1
    else
      overall_status="skipped"
      validation_status="skipped"
    fi
    jq -c -n \
      --arg record_type "swarm_prewarm_cold_start_skip" \
      --arg schema_version "swarm-prewarm-cold-start/v2" \
      --arg run_id "${RUN_ID}" \
      --arg git_revision "${git_revision}" \
      --arg worker_id "rch-unavailable" \
      --arg target_dir "${target_dir}" \
      --arg skip_reason "${skip_reason}" \
      --arg log_path "${TEST_LOG}" \
      '{
        record_type: $record_type,
        schema_version: $schema_version,
        run_id: $run_id,
        git_revision: $git_revision,
        worker_id: $worker_id,
        cargo_target_dir: $target_dir,
        skip_reason: $skip_reason,
        log_path: $log_path
      }' > "${SKIP_JSONL}"
  else
    overall_status="failed"
    exit_code=1
  fi
fi

if [[ "${overall_status}" == "passed" ]]; then
  if [[ -z "${EVIDENCE_JSONL_IN}" ]]; then
    if ! grep -a '^FCP_PREWARM_COLD_START_JSONL ' "${TEST_LOG}" \
      | sed 's/^FCP_PREWARM_COLD_START_JSONL //' > "${EVIDENCE_JSONL}"
    then
      evidence_status="failed"
    fi
  fi

  if [[ ! -s "${EVIDENCE_JSONL}" ]] || ! jq -c . "${EVIDENCE_JSONL}" >/dev/null; then
    evidence_status="failed"
  fi

  if [[ "${evidence_status}" == "passed" ]]; then
    if ! jq -s --argjson require_production_soak "${require_production_soak_json}" '
      def nonempty_string($key):
        (.[$key] | type) == "string" and (.[$key] | length) > 0;
      def positive_number($key):
        (.[$key] | type) == "number" and .[$key] > 0;
      def blake3_hash:
        type == "string" and test("^blake3:[0-9a-f]{64}$");
      def same($key):
        .[$key] == .evidence[$key];
      def same_optional($key):
        .[$key] == (.evidence[$key] // null);
      def production_host_boundary_ok:
        (.host_boundary | type) == "string"
        and (.host_boundary | startswith("fcp-host::"))
        and ((.host_boundary | gsub("^\\s+|\\s+$"; "")) != "fcp-host::supervisor::ConnectorPrewarmConfig::decide_checkout")
        and ((.host_boundary | contains("ConnectorPrewarmConfig::decide_checkout")) | not);
      def nested_evidence_matches:
        (.evidence | type) == "object"
        and same("schema_version")
        and same("execution_mode")
        and same("source_kind")
        and same("scenario_id")
        and same("connector_id")
        and same("command_line")
        and same("git_revision")
        and same("worker_id")
        and same("cargo_target_dir")
        and same("cargo_target_dir_class")
        and same("cargo_target_dir_hash")
        and same("connector_fixture_id")
        and same("host_boundary")
        and same("manifest_hash")
        and same("zone")
        and same("strategy")
        and same("pool_state")
        and same("admission_decision")
        and same("warm_checkout")
        and same("activation_latency_ms")
        and same("baseline_on_demand_latency_ms")
        and (.p50_activation_latency_ms == .evidence.latency.p50_ms)
        and (.p95_activation_latency_ms == .evidence.latency.p95_ms)
        and (.p99_activation_latency_ms == .evidence.latency.p99_ms)
        and (.baseline_p50_activation_latency_ms == .evidence.baseline_latency.p50_ms)
        and (.baseline_p95_activation_latency_ms == .evidence.baseline_latency.p95_ms)
        and (.baseline_p99_activation_latency_ms == .evidence.baseline_latency.p99_ms)
        and same("sandbox_layer")
        and same("sandbox_profile")
        and same("sandbox_boundary")
        and same("credential_mode")
        and same("rss_bytes")
        and same("process_count")
        and same("concurrent_startups")
        and same("error_mapping")
        and same("cleanup_result")
        and same_optional("restart_reason")
        and same_optional("fallback_reason")
        and same_optional("unsafe_rejection_reason")
        and same_optional("skip_reason")
        and same("shutdown_cleanup_verified");
      def required:
        [
          "prewarm_empty_pool",
          "prewarm_warm_hit",
          "prewarm_stale_entry",
          "prewarm_crash_before_checkout",
          "prewarm_shutdown_cleanup",
          "prewarm_concurrent_swarm_startup",
          "prewarm_exhausted_under_burst",
          "prewarm_sandbox_limits_unavailable",
          "prewarm_checkout_cancelled_before_admit",
          "prewarm_zygote_rejected_without_security_proof"
        ];
      def promotion_improvement_scenarios:
        [
          "prewarm_warm_hit",
          "prewarm_shutdown_cleanup",
          "prewarm_concurrent_swarm_startup"
        ];
      def has_positive_improvement($records; $scenario):
        any($records[];
          .scenario_id == $scenario
          and (.p50_activation_latency_improvement_ms | type) == "number"
          and .p50_activation_latency_improvement_ms > 0
          and (.p95_activation_latency_improvement_ms | type) == "number"
          and .p95_activation_latency_improvement_ms > 0
          and (.p99_activation_latency_improvement_ms | type) == "number"
          and .p99_activation_latency_improvement_ms > 0
        );
      def promotion_improvement_failures($records):
        promotion_improvement_scenarios
        | map(select(has_positive_improvement($records; .) | not));
      def latency_order_ok:
        (.p50_activation_latency_ms | type) == "number"
        and (.p95_activation_latency_ms | type) == "number"
        and (.p99_activation_latency_ms | type) == "number"
        and (.baseline_p50_activation_latency_ms | type) == "number"
        and (.baseline_p95_activation_latency_ms | type) == "number"
        and (.baseline_p99_activation_latency_ms | type) == "number"
        and .p50_activation_latency_ms > 0
        and .p50_activation_latency_ms <= .p95_activation_latency_ms
        and .p95_activation_latency_ms <= .p99_activation_latency_ms
        and .baseline_p50_activation_latency_ms > 0
        and .baseline_p50_activation_latency_ms <= .baseline_p95_activation_latency_ms
        and .baseline_p95_activation_latency_ms <= .baseline_p99_activation_latency_ms;
      def latency_regression_ok:
        (.activation_latency_ms | type) == "number"
        and (.baseline_on_demand_latency_ms | type) == "number"
        and .activation_latency_ms <= .baseline_on_demand_latency_ms
        and .p50_activation_latency_ms <= .baseline_p50_activation_latency_ms
        and .p95_activation_latency_ms <= .baseline_p95_activation_latency_ms
        and .p99_activation_latency_ms <= .baseline_p99_activation_latency_ms;
      def latency_improvement_consistency_ok:
        (.p50_activation_latency_improvement_ms | type) == "number"
        and (.p95_activation_latency_improvement_ms | type) == "number"
        and (.p99_activation_latency_improvement_ms | type) == "number"
        and .p50_activation_latency_improvement_ms == (.baseline_p50_activation_latency_ms - .p50_activation_latency_ms)
        and .p95_activation_latency_improvement_ms == (.baseline_p95_activation_latency_ms - .p95_activation_latency_ms)
        and .p99_activation_latency_improvement_ms == (.baseline_p99_activation_latency_ms - .p99_activation_latency_ms);
      def rch_command_line_ok:
        (.command_line | type) == "array"
        and (.command_line | length) >= 4
        and .command_line[0] == "rch"
        and .command_line[1] == "exec"
        and ((.command_line | index("--")) as $separator
          | ($separator != null)
            and ((.command_line | index("cargo")) as $cargo | ($cargo != null and $cargo > $separator)));
      def target_dir_provenance_ok:
        . as $record
        | ("CARGO_TARGET_DIR=" + $record.cargo_target_dir) as $target_dir_arg
        | ($record.cargo_target_dir | type) == "string"
          and ($record.command_line | type) == "array"
          and (($record.command_line | index("--")) as $separator
            | ($record.command_line | index("cargo")) as $cargo
            | ($record.command_line | index($target_dir_arg)) as $target_dir
            | $separator != null
              and $cargo != null
              and $target_dir != null
              and $target_dir > $separator
              and $target_dir < $cargo);
      def ids: map(.scenario_id);
      def missing: required - (ids);
      def duplicate_scenarios:
        group_by(.scenario_id)
        | map(select(length > 1) | .[0].scenario_id);
      {
        record_count: length,
        require_production_soak: $require_production_soak,
        missing_scenarios: missing,
        duplicate_scenarios: duplicate_scenarios,
        scenario_set_exact: ((ids | sort) == (required | sort)),
        schema_ok: all(.[]; .schema_version == "swarm-prewarm-cold-start/v2"),
        record_type_ok: all(.[]; .record_type == "swarm_prewarm_cold_start_evidence"),
        execution_mode_shape_ok: all(.[];
          (.execution_mode | type) == "string"
          and (.source_kind | type) == "string"
        ),
        command_provenance_ok: all(.[];
          rch_command_line_ok
        ),
        target_dir_provenance_ok: all(.[];
          target_dir_provenance_ok
        ),
        required_fields_ok: all(.[];
          (.command_line | type) == "array"
          and (.command_line | length) > 0
          and all(.command_line[]; type == "string" and length > 0)
          and nonempty_string("git_revision")
          and nonempty_string("worker_id")
          and nonempty_string("cargo_target_dir")
          and nonempty_string("cargo_target_dir_class")
          and (.cargo_target_dir_hash | blake3_hash)
          and nonempty_string("connector_fixture_id")
          and nonempty_string("host_boundary")
          and nonempty_string("manifest_hash")
          and nonempty_string("zone")
          and nonempty_string("strategy")
          and nonempty_string("pool_state")
          and nonempty_string("admission_decision")
          and nonempty_string("sandbox_layer")
          and nonempty_string("sandbox_profile")
          and nonempty_string("sandbox_boundary")
          and nonempty_string("credential_mode")
          and nonempty_string("error_mapping")
          and nonempty_string("cleanup_result")
        ),
        resource_fields_ok: all(.[];
          positive_number("pool_size")
          and positive_number("activation_latency_ms")
          and positive_number("baseline_on_demand_latency_ms")
          and positive_number("rss_bytes")
          and positive_number("process_count")
          and positive_number("concurrent_startups")
          and (.warm_checkout | type) == "boolean"
        ),
        decision_shape_ok: all(.[];
          if .admission_decision == "admit_warm" then
            .warm_checkout == true
            and (.fallback_reason == null)
            and (.unsafe_rejection_reason == null)
          elif .admission_decision == "fallback_on_demand" then
            .warm_checkout == false
            and nonempty_string("fallback_reason")
            and (.unsafe_rejection_reason == null)
          elif .admission_decision == "reject_unsafe" then
            .warm_checkout == false
            and (.fallback_reason == null)
            and nonempty_string("unsafe_rejection_reason")
          else
            false
          end
        ),
        cleanup_shape_ok: all(.[];
          .shutdown_cleanup_verified == true
          and .cleanup_result == "verified"
        ),
        boundary_shape_ok: all(.[];
          (.host_boundary | type) == "string"
          and (.host_boundary | startswith("fcp-host::"))
          and (.sandbox_boundary | type) == "string"
          and (.sandbox_boundary | startswith("fcp-sandbox::"))
        ),
        nested_evidence_ok: all(.[];
          nested_evidence_matches
        ),
        manifest_hash_shape_ok: all(.[];
          (.manifest_hash | blake3_hash)
          and (.evidence.manifest_hash | blake3_hash)
        ),
        production_soak_ok: (
          if $require_production_soak then
            all(.[];
              .execution_mode == "soak"
              and (.source_kind == "host_backed" or .source_kind == "live")
              and production_host_boundary_ok
              and (.sandbox_boundary | type) == "string"
              and (.sandbox_boundary | startswith("fcp-sandbox::"))
            )
          else true end
        ),
        production_improvement_summary: {
          required_positive_improvement_scenarios: promotion_improvement_scenarios,
          missing_or_nonpositive: promotion_improvement_failures(.)
        },
        production_improvement_ok: (
          if $require_production_soak then
            (promotion_improvement_failures(.) | length) == 0
          else true end
        ),
        percentile_fields_ok: all(.[];
          (.p50_activation_latency_ms | type) == "number"
          and (.p95_activation_latency_ms | type) == "number"
          and (.p99_activation_latency_ms | type) == "number"
          and (.baseline_p50_activation_latency_ms | type) == "number"
          and (.baseline_p95_activation_latency_ms | type) == "number"
          and (.baseline_p99_activation_latency_ms | type) == "number"
        ),
        latency_order_ok: all(.[];
          latency_order_ok
        ),
        latency_regression_ok: all(.[];
          latency_regression_ok
        ),
        latency_improvement_consistency_ok: all(.[];
          latency_improvement_consistency_ok
        ),
        redaction_shape_ok: all(.[];
          (.connector_id | type) == "string"
          and (.worker_id | type) == "string"
          and (.credential_mode | type) == "string"
          and (.cleanup_result | type) == "string"
          and (.cargo_target_dir_class | type) == "string"
          and (.cargo_target_dir_hash | type) == "string"
        ),
        latency_summary: {
          p50: {
            current_max_ms: (map(.p50_activation_latency_ms) | max),
            baseline_max_ms: (map(.baseline_p50_activation_latency_ms) | max),
            improvement_min_ms: (map(.p50_activation_latency_improvement_ms) | min)
          },
          p95: {
            current_max_ms: (map(.p95_activation_latency_ms) | max),
            baseline_max_ms: (map(.baseline_p95_activation_latency_ms) | max),
            improvement_min_ms: (map(.p95_activation_latency_improvement_ms) | min)
          },
          p99: {
            current_max_ms: (map(.p99_activation_latency_ms) | max),
            baseline_max_ms: (map(.baseline_p99_activation_latency_ms) | max),
            improvement_min_ms: (map(.p99_activation_latency_improvement_ms) | min)
          },
          scenarios_without_p99_improvement: (
            map(select(.p99_activation_latency_improvement_ms == 0) | .scenario_id) | sort
          )
        },
        production_boundary_summary: {
          execution_modes: (map(.execution_mode) | unique | sort),
          source_kinds: (map(.source_kind) | unique | sort),
          host_boundaries: (map(.host_boundary) | unique | sort),
          sandbox_boundaries: (map(.sandbox_boundary) | unique | sort)
        }
      } as $v
      | $v
      | .status = (
          if (
            ($v.missing_scenarios | length) == 0
            and ($v.duplicate_scenarios | length) == 0
            and $v.scenario_set_exact
            and $v.schema_ok
            and $v.record_type_ok
            and $v.execution_mode_shape_ok
            and $v.command_provenance_ok
            and $v.target_dir_provenance_ok
            and $v.required_fields_ok
            and $v.resource_fields_ok
            and $v.decision_shape_ok
            and $v.cleanup_shape_ok
            and $v.boundary_shape_ok
            and $v.nested_evidence_ok
            and $v.manifest_hash_shape_ok
            and $v.production_soak_ok
            and $v.production_improvement_ok
            and $v.percentile_fields_ok
            and $v.latency_order_ok
            and $v.latency_regression_ok
            and $v.latency_improvement_consistency_ok
            and $v.redaction_shape_ok
          )
          then "passed"
          else "failed"
          end
        )
    ' "${EVIDENCE_JSONL}" > "${VALIDATION_JSON}"; then
      validation_status="failed"
    elif [[ "$(jq -r '.status // "failed"' "${VALIDATION_JSON}")" != "passed" ]]; then
      validation_status="failed"
    fi
  fi

  if [[ "${evidence_status}" == "failed" || "${validation_status}" == "failed" ]]; then
    overall_status="failed"
    exit_code=1
  fi
fi

if [[ -s "${EVIDENCE_JSONL}" ]]; then
  if grep -aE '(sk-live-|Bearer[[:space:]]+|super-secret-value|secret_seed|private_key|/Users/|/private/var/)' "${EVIDENCE_JSONL}" >/dev/null; then
    redaction_status="failed"
    overall_status="failed"
    validation_status="failed"
    mark_validation_redaction_failed "secret_or_private_path_marker"
    exit_code=1
  elif jq -s -e 'any(.[]; .cargo_target_dir_class == "private_absolute")' "${EVIDENCE_JSONL}" >/dev/null; then
    redaction_status="failed"
    overall_status="failed"
    validation_status="failed"
    mark_validation_redaction_failed "private_absolute_target_dir"
    exit_code=1
  fi
fi

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg script "scripts/e2e/connector_prewarm_cold_start_verification.sh" \
  --arg repo_root "${REPO_ROOT}" \
  --arg artifact_root "${OUT_ROOT}" \
  --arg git_revision "${git_revision}" \
  --arg target_dir "${target_dir}" \
  --arg rch_require_remote "${RCH_REQUIRE_REMOTE:-1}" \
  --arg evidence_jsonl_in "${EVIDENCE_JSONL_IN}" \
  --argjson require_production_soak "${require_production_soak_json}" \
  --arg generated_at "$(now_iso)" \
  '{
    run_id: $run_id,
    script: $script,
    repo_root: $repo_root,
    artifact_root: $artifact_root,
    git_revision: $git_revision,
    cargo_target_dir: $target_dir,
    rch_require_remote: $rch_require_remote,
    evidence_jsonl_in: (if ($evidence_jsonl_in | length) > 0 then $evidence_jsonl_in else null end),
    require_production_soak: $require_production_soak,
    generated_at: $generated_at
  }' > "${ENVIRONMENT_JSON}"

evidence_count="0"
if [[ -s "${EVIDENCE_JSONL}" ]]; then
  evidence_count="$(wc -l < "${EVIDENCE_JSONL}" | tr -d ' ')"
fi

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg status "${overall_status}" \
  --arg test_status "${test_status}" \
  --arg evidence_status "${evidence_status}" \
  --arg validation_status "${validation_status}" \
  --arg redaction_status "${redaction_status}" \
  --arg skip_reason "${skip_reason}" \
  --argjson evidence_count "${evidence_count}" \
  --arg test_log "${TEST_LOG}" \
  --arg evidence_jsonl "${EVIDENCE_JSONL}" \
  --arg validation_json "${VALIDATION_JSON}" \
  --arg skip_jsonl "${SKIP_JSONL}" \
  --arg environment_json "${ENVIRONMENT_JSON}" \
  --argjson require_production_soak "${require_production_soak_json}" \
  '{
    run_id: $run_id,
    status: $status,
    test_status: $test_status,
    evidence_status: $evidence_status,
    validation_status: $validation_status,
    redaction_status: $redaction_status,
    require_production_soak: $require_production_soak,
    skip_reason: (if ($skip_reason | length) > 0 then $skip_reason else null end),
    evidence_count: $evidence_count,
    artifacts: {
      test_log: $test_log,
      evidence_jsonl: $evidence_jsonl,
      validation_json: $validation_json,
      skip_jsonl: $skip_jsonl,
      environment_json: $environment_json
    }
  }' > "${SUMMARY_JSON}"

cat > "${REPLAY_SH}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "${REPO_ROOT}"
RUN_ID="${RUN_ID}" OUT_ROOT="${OUT_ROOT}" RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}" REQUIRE_PRODUCTION_SOAK="${REQUIRE_PRODUCTION_SOAK}" EVIDENCE_JSONL_IN="${EVIDENCE_JSONL_IN}" \\
  bash scripts/e2e/connector_prewarm_cold_start_verification.sh \\
  --run-id "${RUN_ID}" \\
  --out-root "${OUT_ROOT}"
EOF
chmod +x "${REPLAY_SH}"

echo "Connector prewarm cold-start artifacts written to ${OUT_ROOT}"
exit "${exit_code}"
