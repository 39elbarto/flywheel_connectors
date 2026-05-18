#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-}"
REQUIRE_PRODUCTION_SOAK="${REQUIRE_PRODUCTION_SOAK:-0}"
EVIDENCE_JSONL_IN="${EVIDENCE_JSONL_IN:-}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
export RCH_FORCE_REMOTE=1

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
Set RCH_BIN=/path/to/rch to validate a patched rch binary; the emitted evidence
still must prove the replay command uses the canonical `rch exec --` shape.
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

validate_run_id() {
  if [[ ! "${RUN_ID}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "RUN_ID must use only A-Z, a-z, 0-9, '.', '_', and '-': ${RUN_ID}" >&2
    exit 2
  fi
}

hash_text_sha256() {
  printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
}

display_rch_bin() {
  basename "${RCH_BIN}"
}

rch_bin_path_redacted() {
  case "${RCH_BIN}" in
    */*) printf 'true' ;;
    *) printf 'false' ;;
  esac
}

evidence_jsonl_in_path_redacted() {
  if [[ -n "${EVIDENCE_JSONL_IN}" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

json_null_or_sha256() {
  local value="$1"
  if [[ -n "${value}" ]]; then
    jq -n --arg hash "sha256:$(hash_text_sha256 "${value}")" '$hash'
  else
    printf 'null'
  fi
}

json_bool_nonempty() {
  local value="$1"
  if [[ -n "${value}" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

cargo_target_dir_class() {
  local path="$1"
  case "${path}" in
    /tmp|/tmp/*|/private/tmp|/private/tmp/*)
      printf 'tmp'
      ;;
    /*)
      printf 'absolute'
      ;;
    *)
      printf 'relative'
      ;;
  esac
}

redaction_pattern() {
  printf '%s' '(sk-live-|bearer[[:space:]]+|authorization:|token=|access_token|refresh_token|id_token|client_secret|api_key|super-secret-value|secret_seed|private_key|secret_key|password|cookie|credential=|credential:|/users/|/home/|/data/projects/|/private/var/|/var/folders/|/volumes/|c:\\\\users\\\\|operation:|principal:|zone:|z:|provider_body|provider_response_body|provider_payload_body|reviewer_email|reviewer_phone)'
}

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

mark_validation_redaction_passed() {
  if [[ -s "${VALIDATION_JSON}" ]]; then
    local validation_redaction_tmp="${VALIDATION_JSON}.redaction"
    if jq '.redaction_scan_ok = true | .redaction_scan_reason = null' \
      "${VALIDATION_JSON}" > "${validation_redaction_tmp}"; then
      mv "${validation_redaction_tmp}" "${VALIDATION_JSON}"
    fi
  fi
}

require_cmd jq
require_cmd shasum
if [[ -z "${EVIDENCE_JSONL_IN}" ]]; then
  require_cmd "${RCH_BIN}"
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

validate_run_id

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
remote_proof_status="not_applicable"
remote_proof_reason=""
remote_proof_summary=""
overall_status="passed"
skip_reason=""
exit_code=0

rch_summary_line() {
  grep -aE '\[RCH\][[:space:]]+(remote|local|failed)' "${TEST_LOG}" | tail -n 1 || true
}

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
    env RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose \
      "${RCH_BIN}" exec -- env \
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
      --arg cargo_target_dir_class "$(cargo_target_dir_class "${target_dir}")" \
      --arg cargo_target_dir_hash "sha256:$(hash_text_sha256 "${target_dir}")" \
      --arg skip_reason "${skip_reason}" \
      --arg log_artifact "logs/prewarm-cold-start-test.log" \
      '{
        record_type: $record_type,
        schema_version: $schema_version,
        run_id: $run_id,
        git_revision: $git_revision,
        worker_id: $worker_id,
        cargo_target_dir_class: $cargo_target_dir_class,
        cargo_target_dir_hash: $cargo_target_dir_hash,
        skip_reason: $skip_reason,
        log_artifact: $log_artifact
      }' > "${SKIP_JSONL}"
  else
    overall_status="failed"
    exit_code=1
  fi
fi

if [[ -z "${EVIDENCE_JSONL_IN}" && "${test_status}" == "passed" ]]; then
  remote_proof_summary="$(rch_summary_line)"
  if [[ "${remote_proof_summary}" =~ \[RCH\][[:space:]]+remote ]]; then
    remote_proof_status="passed"
  elif [[ "${remote_proof_summary}" =~ \[RCH\][[:space:]]+local ]]; then
    remote_proof_status="failed"
    remote_proof_reason="rch_local_fallback_observed"
    validation_status="failed"
    overall_status="failed"
    exit_code=1
  else
    remote_proof_status="failed"
    remote_proof_reason="rch_remote_summary_missing"
    validation_status="failed"
    overall_status="failed"
    exit_code=1
  fi
elif [[ -n "${EVIDENCE_JSONL_IN}" ]]; then
  remote_proof_status="provided_evidence_not_reexecuted"
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
      def positive_integer_value:
        type == "number" and . == floor and . > 0;
      def nonnegative_integer_value:
        type == "number" and . == floor and . >= 0;
      def positive_integer($key):
        (.[$key] | positive_integer_value);
      def blake3_hash:
        type == "string" and test("^blake3:[0-9a-f]{64}$");
      def git_object_id:
        type == "string" and test("^[0-9a-f]{7,40}$");
      def worker_id_label:
        type == "string" and test("^[A-Za-z0-9._-]{1,128}$");
      def execution_mode_label:
        type == "string" and (. == "smoke" or . == "soak");
      def source_kind_label:
        type == "string" and (. == "offline" or . == "host_backed" or . == "live");
      def canonical_boundary_label:
        type == "string" and test("^[-A-Za-z0-9_.:]+$");
      def latency_percentile_object_ok:
        type == "object"
        and (.p50_ms | positive_integer_value)
        and (.p95_ms | positive_integer_value)
        and (.p99_ms | positive_integer_value)
        and (.p999_ms | positive_integer_value)
        and (.max_ms | positive_integer_value)
        and (.mean_ms | positive_integer_value)
        and .p50_ms <= .p95_ms
        and .p95_ms <= .p99_ms
        and .p99_ms <= .p999_ms
        and .p999_ms <= .max_ms;
      def same($key):
        .[$key] == .evidence[$key];
      def same_optional($key):
        .[$key] == (.evidence[$key] // null);
      def production_host_boundary_ok:
        (.host_boundary | type) == "string"
        and (.host_boundary | canonical_boundary_label)
        and (.host_boundary | startswith("fcp-host::"))
        and ((.host_boundary | gsub("^\\s+|\\s+$"; "")) != "fcp-host::supervisor::ConnectorPrewarmConfig::decide_checkout")
        and ((.host_boundary | contains("ConnectorPrewarmConfig::decide_checkout")) | not);
      def nested_latency_shape_ok:
        (.evidence | type) == "object"
        and (.evidence.latency | latency_percentile_object_ok)
        and (.evidence.baseline_latency | latency_percentile_object_ok);
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
        and same("pool_size")
        and same("admission_decision")
        and same("warm_checkout")
        and same("activation_latency_ms")
        and same("baseline_on_demand_latency_ms")
        and nested_latency_shape_ok
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
        (.p50_activation_latency_ms | positive_integer_value)
        and (.p95_activation_latency_ms | positive_integer_value)
        and (.p99_activation_latency_ms | positive_integer_value)
        and (.baseline_p50_activation_latency_ms | positive_integer_value)
        and (.baseline_p95_activation_latency_ms | positive_integer_value)
        and (.baseline_p99_activation_latency_ms | positive_integer_value)
        and .p50_activation_latency_ms <= .p95_activation_latency_ms
        and .p95_activation_latency_ms <= .p99_activation_latency_ms
        and .baseline_p50_activation_latency_ms <= .baseline_p95_activation_latency_ms
        and .baseline_p95_activation_latency_ms <= .baseline_p99_activation_latency_ms;
      def latency_regression_ok:
        (.activation_latency_ms | positive_integer_value)
        and (.baseline_on_demand_latency_ms | positive_integer_value)
        and .activation_latency_ms <= .baseline_on_demand_latency_ms
        and .p50_activation_latency_ms <= .baseline_p50_activation_latency_ms
        and .p95_activation_latency_ms <= .baseline_p95_activation_latency_ms
        and .p99_activation_latency_ms <= .baseline_p99_activation_latency_ms;
      def latency_improvement_consistency_ok:
        (.p50_activation_latency_improvement_ms | nonnegative_integer_value)
        and (.p95_activation_latency_improvement_ms | nonnegative_integer_value)
        and (.p99_activation_latency_improvement_ms | nonnegative_integer_value)
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
          (.execution_mode | execution_mode_label)
          and (.source_kind | source_kind_label)
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
          and (.worker_id | worker_id_label)
          and nonempty_string("cargo_target_dir")
          and nonempty_string("cargo_target_dir_class")
          and (.cargo_target_dir_hash | blake3_hash)
          and nonempty_string("connector_fixture_id")
          and nonempty_string("host_boundary")
          and nonempty_string("manifest_hash")
          and (.zone | blake3_hash)
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
        git_revision_provenance_ok: all(.[];
          (.git_revision | git_object_id)
        ),
        worker_id_shape_ok: all(.[];
          (.worker_id | worker_id_label)
        ),
        target_dir_class_ok: all(.[];
          .cargo_target_dir_class == "tmp"
          or .cargo_target_dir_class == "absolute"
          or .cargo_target_dir_class == "relative"
        ),
        resource_fields_ok: all(.[];
          positive_integer("pool_size")
          and positive_integer("activation_latency_ms")
          and positive_integer("baseline_on_demand_latency_ms")
          and positive_integer("rss_bytes")
          and positive_integer("process_count")
          and positive_integer("concurrent_startups")
          and (.warm_checkout | type) == "boolean"
        ),
        decision_shape_ok: all(.[];
          if .admission_decision == "admit_warm" then
            .warm_checkout == true
            and (.fallback_reason == null)
            and (.unsafe_rejection_reason == null)
            and .error_mapping == "ok"
          elif .admission_decision == "fallback_on_demand" then
            .warm_checkout == false
            and nonempty_string("fallback_reason")
            and (.unsafe_rejection_reason == null)
            and .error_mapping == ("fallback_on_demand:" + .fallback_reason)
          elif .admission_decision == "reject_unsafe" then
            .warm_checkout == false
            and (.fallback_reason == null)
            and nonempty_string("unsafe_rejection_reason")
            and .error_mapping == ("reject_unsafe:" + .unsafe_rejection_reason)
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
          and (.host_boundary | canonical_boundary_label)
          and (.host_boundary | startswith("fcp-host::"))
          and (.sandbox_boundary | type) == "string"
          and (.sandbox_boundary | canonical_boundary_label)
          and (.sandbox_boundary | startswith("fcp-sandbox::"))
        ),
        nested_evidence_ok: all(.[];
          nested_evidence_matches
        ),
        nested_latency_shape_ok: all(.[];
          nested_latency_shape_ok
        ),
        manifest_hash_shape_ok: all(.[];
          (.manifest_hash | blake3_hash)
          and (.evidence.manifest_hash | blake3_hash)
        ),
        zone_hash_shape_ok: all(.[];
          (.zone | blake3_hash)
          and (.evidence.zone | blake3_hash)
        ),
        production_soak_ok: (
          if $require_production_soak then
            all(.[];
              .execution_mode == "soak"
              and (.source_kind == "host_backed" or .source_kind == "live")
              and production_host_boundary_ok
              and (.sandbox_boundary | type) == "string"
              and (.sandbox_boundary | canonical_boundary_label)
              and (.sandbox_boundary | startswith("fcp-sandbox::"))
            )
          else true end
        ),
        production_skip_reason_ok: (
          if $require_production_soak then
            all(.[];
              ((.skip_reason // "") == "")
              and ((.evidence.skip_reason // "") == "")
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
          (.p50_activation_latency_ms | positive_integer_value)
          and (.p95_activation_latency_ms | positive_integer_value)
          and (.p99_activation_latency_ms | positive_integer_value)
          and (.baseline_p50_activation_latency_ms | positive_integer_value)
          and (.baseline_p95_activation_latency_ms | positive_integer_value)
          and (.baseline_p99_activation_latency_ms | positive_integer_value)
          and (.p50_activation_latency_improvement_ms | nonnegative_integer_value)
          and (.p95_activation_latency_improvement_ms | nonnegative_integer_value)
          and (.p99_activation_latency_improvement_ms | nonnegative_integer_value)
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
          and (.worker_id | worker_id_label)
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
            and $v.git_revision_provenance_ok
            and $v.worker_id_shape_ok
            and $v.target_dir_class_ok
            and $v.resource_fields_ok
            and $v.decision_shape_ok
            and $v.cleanup_shape_ok
            and $v.boundary_shape_ok
            and $v.nested_evidence_ok
            and $v.nested_latency_shape_ok
            and $v.manifest_hash_shape_ok
            and $v.zone_hash_shape_ok
            and $v.production_soak_ok
            and $v.production_skip_reason_ok
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
  if grep -aEi "$(redaction_pattern)" "${EVIDENCE_JSONL}" >/dev/null; then
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
  elif jq -s -e 'any(.[]; .cargo_target_dir == "/tmp" or .cargo_target_dir == "/private/tmp" or .cargo_target_dir == "target" or .cargo_target_dir == "./target")' "${EVIDENCE_JSONL}" >/dev/null; then
    redaction_status="failed"
    overall_status="failed"
    validation_status="failed"
    mark_validation_redaction_failed "shared_target_dir_root"
    exit_code=1
  else
    mark_validation_redaction_passed
  fi
fi

if [[ -s "${SKIP_JSONL}" ]]; then
  if grep -aEi "$(redaction_pattern)" "${SKIP_JSONL}" >/dev/null; then
    redaction_status="failed"
    overall_status="failed"
    validation_status="failed"
    mark_validation_redaction_failed "skip_artifact_secret_or_private_path_marker"
    exit_code=1
  elif ! jq -s -e '
    all(.[]; .record_type == "swarm_prewarm_cold_start_skip"
      and .schema_version == "swarm-prewarm-cold-start/v2"
      and (.git_revision | test("^[0-9a-f]{7,40}$"))
      and (.cargo_target_dir_class == "tmp" or .cargo_target_dir_class == "absolute" or .cargo_target_dir_class == "relative")
      and (.cargo_target_dir_hash | test("^sha256:[0-9a-f]{64}$"))
      and .log_artifact == "logs/prewarm-cold-start-test.log"
      and (.skip_reason | type == "string" and length > 0)
      and (has("cargo_target_dir") | not)
      and (has("log_path") | not))
  ' "${SKIP_JSONL}" >/dev/null; then
    redaction_status="failed"
    overall_status="failed"
    validation_status="failed"
    mark_validation_redaction_failed "skip_artifact_contract_failed"
    exit_code=1
  fi
fi

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg script "scripts/e2e/connector_prewarm_cold_start_verification.sh" \
  --arg repo_root_hash "sha256:$(hash_text_sha256 "${REPO_ROOT}")" \
  --arg artifact_root_class "$(cargo_target_dir_class "${OUT_ROOT}")" \
  --arg artifact_root_hash "sha256:$(hash_text_sha256 "${OUT_ROOT}")" \
  --arg git_revision "${git_revision}" \
  --arg cargo_target_dir_class "$(cargo_target_dir_class "${target_dir}")" \
  --arg cargo_target_dir_hash "sha256:$(hash_text_sha256 "${target_dir}")" \
  --arg rch_bin "$(display_rch_bin)" \
  --arg rch_bin_hash "sha256:$(hash_text_sha256 "${RCH_BIN}")" \
  --argjson rch_bin_path_redacted "$(rch_bin_path_redacted)" \
  --arg rch_require_remote "${RCH_REQUIRE_REMOTE}" \
  --arg rch_force_remote "${RCH_FORCE_REMOTE:-1}" \
  --arg remote_proof_status "${remote_proof_status}" \
  --arg remote_proof_reason "${remote_proof_reason}" \
  --argjson remote_proof_summary_present "$(json_bool_nonempty "${remote_proof_summary}")" \
  --argjson remote_proof_summary_hash "$(json_null_or_sha256 "${remote_proof_summary}")" \
  --argjson evidence_jsonl_in_hash "$(json_null_or_sha256 "${EVIDENCE_JSONL_IN}")" \
  --argjson evidence_jsonl_in_path_redacted "$(evidence_jsonl_in_path_redacted)" \
  --argjson require_production_soak "${require_production_soak_json}" \
  --arg generated_at "$(now_iso)" \
  '{
    run_id: $run_id,
    script: $script,
    repo_root_redacted: true,
    repo_root_hash: $repo_root_hash,
    artifact_root_class: $artifact_root_class,
    artifact_root_hash: $artifact_root_hash,
    git_revision: $git_revision,
    cargo_target_dir_class: $cargo_target_dir_class,
    cargo_target_dir_hash: $cargo_target_dir_hash,
    rch_bin: $rch_bin,
    rch_bin_hash: $rch_bin_hash,
    rch_bin_path_redacted: $rch_bin_path_redacted,
    rch_require_remote: $rch_require_remote,
    rch_force_remote: $rch_force_remote,
    remote_proof: {
      status: $remote_proof_status,
      reason: (if ($remote_proof_reason | length) > 0 then $remote_proof_reason else null end),
      rch_summary_present: $remote_proof_summary_present,
      rch_summary_hash: $remote_proof_summary_hash
    },
    evidence_jsonl_in_path_redacted: $evidence_jsonl_in_path_redacted,
    evidence_jsonl_in_hash: $evidence_jsonl_in_hash,
    require_production_soak: $require_production_soak,
    generated_at: $generated_at
  }' > "${ENVIRONMENT_JSON}"

if grep -aEi "$(redaction_pattern)" "${ENVIRONMENT_JSON}" >/dev/null; then
  redaction_status="failed"
  overall_status="failed"
  validation_status="failed"
  mark_validation_redaction_failed "metadata_secret_or_private_path_marker"
  exit_code=1
fi

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
  --arg remote_proof_status "${remote_proof_status}" \
  --arg remote_proof_reason "${remote_proof_reason}" \
  --argjson remote_proof_summary_present "$(json_bool_nonempty "${remote_proof_summary}")" \
  --argjson remote_proof_summary_hash "$(json_null_or_sha256 "${remote_proof_summary}")" \
  --arg skip_reason "${skip_reason}" \
  --argjson evidence_count "${evidence_count}" \
  --argjson require_production_soak "${require_production_soak_json}" \
  '{
    run_id: $run_id,
    status: $status,
    test_status: $test_status,
    evidence_status: $evidence_status,
    validation_status: $validation_status,
    redaction_status: $redaction_status,
    remote_proof_status: $remote_proof_status,
    remote_proof_reason: (if ($remote_proof_reason | length) > 0 then $remote_proof_reason else null end),
    remote_proof_summary_present: $remote_proof_summary_present,
    remote_proof_summary_hash: $remote_proof_summary_hash,
    require_production_soak: $require_production_soak,
    skip_reason: (if ($skip_reason | length) > 0 then $skip_reason else null end),
    evidence_count: $evidence_count,
    artifacts: {
      test_log: "logs/prewarm-cold-start-test.log",
      evidence_jsonl: "evidence/prewarm-cold-start.jsonl",
      validation_json: "evidence/validation.json",
      skip_jsonl: "evidence/prewarm-cold-start-skip.jsonl",
      environment_json: "environment.json"
    }
  }' > "${SUMMARY_JSON}"

if grep -aEi "$(redaction_pattern)" "${SUMMARY_JSON}" >/dev/null; then
  redaction_status="failed"
  overall_status="failed"
  validation_status="failed"
  mark_validation_redaction_failed "metadata_secret_or_private_path_marker"
  exit_code=1
fi

{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -euo pipefail'
  printf 'cd %q\n' "${REPO_ROOT}"
  printf 'RUN_ID=%q OUT_ROOT=%q RCH_BIN=%q RCH_REQUIRE_REMOTE=%q RCH_FORCE_REMOTE=%q REQUIRE_PRODUCTION_SOAK=%q EVIDENCE_JSONL_IN=%q \\\n' \
    "${RUN_ID}" "${OUT_ROOT}" "${RCH_BIN}" "${RCH_REQUIRE_REMOTE}" "${RCH_FORCE_REMOTE:-1}" "${REQUIRE_PRODUCTION_SOAK}" "${EVIDENCE_JSONL_IN}"
  printf '  bash scripts/e2e/connector_prewarm_cold_start_verification.sh \\\n'
  printf '  --run-id %q \\\n' "${RUN_ID}"
  printf '  --out-root %q\n' "${OUT_ROOT}"
} > "${REPLAY_SH}"
chmod +x "${REPLAY_SH}"

echo "Connector prewarm cold-start artifacts written to ${OUT_ROOT}"
exit "${exit_code}"
