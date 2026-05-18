#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="scripts/e2e/lattice_delegation_assurance_gauntlet.sh"
RUN_ID="${RUN_ID:-lattice-assurance-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="${OUT_DIR:-target/fcp-crypto-pq}"
ARTIFACT="${ARTIFACT:-${OUT_DIR}/lattice-delegation-assurance-gauntlet.${RUN_ID}.jsonl}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-lattice-assurance-${RUN_ID}}"
ARTIFACT_STAGE_ROOT="${ARTIFACT_STAGE_ROOT:-${OUT_DIR}/rch-lattice-evidence/${RUN_ID}}"
LOG_PREFIX="${OUT_DIR}/${RUN_ID}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"

validate_run_id() {
  case "${RUN_ID}" in
    ""|*/*|*\\*|*..*|*[!A-Za-z0-9._-]*)
      printf 'invalid RUN_ID: use only ASCII letters, digits, dot, underscore, or hyphen; path separators and .. are forbidden\n' >&2
      exit 64
      ;;
  esac
}

validate_artifact_path() {
  case "${ARTIFACT}" in
    target/fcp-crypto-pq/*/*.jsonl)
      printf 'invalid ARTIFACT: reusable evidence path must be a single JSONL file directly under target/fcp-crypto-pq\n' >&2
      exit 64
      ;;
    target/fcp-crypto-pq/*.jsonl) ;;
    *)
      printf 'invalid ARTIFACT: reusable evidence path must be a relative target/fcp-crypto-pq/*.jsonl path\n' >&2
      exit 64
      ;;
  esac

  case "${ARTIFACT}" in
    ""|/*|*\\*|*..*|*//*|*[!A-Za-z0-9._/-]*)
      printf 'invalid ARTIFACT: reusable evidence path must be relative, redaction-safe, and free of traversal\n' >&2
      exit 64
      ;;
  esac
}

validate_out_dir() {
  if [ "${OUT_DIR}" != "target/fcp-crypto-pq" ]; then
    printf 'invalid OUT_DIR: assurance gauntlet evidence logs must use target/fcp-crypto-pq\n' >&2
    exit 64
  fi
}

validate_artifact_stage_root() {
  local expected_stage_root="${OUT_DIR}/rch-lattice-evidence/${RUN_ID}"
  if [ "${ARTIFACT_STAGE_ROOT}" != "${expected_stage_root}" ]; then
    printf 'invalid ARTIFACT_STAGE_ROOT: assurance gauntlet staged evidence must use %s\n' "${expected_stage_root}" >&2
    exit 64
  fi
}

validate_run_id
validate_artifact_path
validate_out_dir
validate_artifact_stage_root
mkdir -p "${OUT_DIR}" "${ARTIFACT_STAGE_ROOT}"
: > "${ARTIFACT}"

repo_root() {
  pwd -P 2>/dev/null || pwd
}

git_safe() {
  local root
  root="$(repo_root)"
  git -c "safe.directory=${root}" -C "${root}" "$@"
}

raw_git_revision() {
  git_safe rev-parse HEAD 2>/dev/null || printf 'unknown'
}

GAUNTLET_GIT_REVISION="${FCP_LATTICE_GIT_REVISION:-$(raw_git_revision)}"

git_revision() {
  printf '%s' "${GAUNTLET_GIT_REVISION}"
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

hash_text() {
  printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
}

json_string_or_null() {
  local value="$1"
  if [ -n "${value}" ]; then
    jq -Rn --arg value "${value}" '$value'
  else
    printf 'null'
  fi
}

target_dir_class() {
  case "${TARGET_DIR}" in
    /tmp|/tmp/*|/private/tmp|/private/tmp/*)
      printf 'ephemeral_tmp'
      ;;
    target|target/*)
      printf 'repo_relative_target'
      ;;
    *)
      printf 'custom_hashed'
      ;;
  esac
}

host_class() {
  printf '%s-%s' "$(uname -s 2>/dev/null || printf unknown)" "$(uname -m 2>/dev/null || printf unknown)"
}

tool_version() {
  local tool="$1"
  shift
  if command -v "${tool}" >/dev/null 2>&1; then
    "$tool" "$@" 2>/dev/null | head -n 1
  else
    printf 'unavailable'
  fi
}

append_json() {
  local step="$1"
  local result="$2"
  local details="$3"
  jq -cn \
    --arg schema "fcp.lattice_delegation.assurance_gauntlet.v1" \
    --arg script "${SCRIPT_NAME}" \
    --arg run_id "${RUN_ID}" \
    --arg step "${step}" \
    --arg result "${result}" \
    --arg git_revision "$(git_revision)" \
    --arg cargo_target_dir_class "$(target_dir_class)" \
    --arg cargo_target_dir_hash "sha256:$(hash_text "${TARGET_DIR}")" \
    --arg build_profile "dev-test-bench" \
    --arg worker_host_class "$(host_class)" \
    --argjson details "${details}" \
    '{schema:$schema,script:$script,run_id:$run_id,step:$step,result:$result,git_revision:$git_revision,cargo_target_dir_class:$cargo_target_dir_class,cargo_target_dir_hash:$cargo_target_dir_hash,build_profile:$build_profile,worker_host_class:$worker_host_class,details:$details}' \
    >> "${ARTIFACT}"
}

fail_step() {
  append_json "$1" "fail" "$2"
  printf 'lattice assurance gauntlet step failed: %s\n' "$1" >&2
  exit 1
}

assert_stable_revision() {
  local step="$1"
  local current_revision
  current_revision="$(raw_git_revision)"
  if [ "${GAUNTLET_GIT_REVISION}" != "unknown" ] &&
    [ "${current_revision}" != "unknown" ] &&
    [ "${current_revision}" != "${GAUNTLET_GIT_REVISION}" ]; then
    case "${current_revision}" in
      "${GAUNTLET_GIT_REVISION}"*) return 0 ;;
    esac
    case "${GAUNTLET_GIT_REVISION}" in
      "${current_revision}"*) return 0 ;;
    esac
    fail_step "${step}" "$(jq -cn \
      --arg expected "${GAUNTLET_GIT_REVISION}" \
      --arg actual "${current_revision}" \
      '{expected_git_revision:$expected,actual_git_revision:$actual,cleanup_result:"not_applicable"}')"
  fi
}

require_command() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    fail_step "prerequisite_${tool}" "$(jq -cn --arg missing "${tool}" \
      '{missing:$missing,cleanup_result:"not_applicable"}')"
  fi
}

require_text() {
  local needle="$1"
  local path="$2"
  local step="$3"
  if ! grep -Fq "${needle}" "${path}"; then
    fail_step "${step}" "$(jq -cn --arg path "${path}" --arg missing "${needle}" \
      '{path:$path,missing:$missing,cleanup_result:"not_applicable"}')"
  fi
}

require_known_git_revision() {
  local revision
  revision="$(git_revision)"
  if ! printf '%s' "${revision}" | grep -Eq '^[0-9a-f]{7,40}$'; then
    fail_step "preflight_git_revision" "$(jq -cn --arg git_revision "${revision}" \
      '{git_revision:$git_revision,required_shape:"hex_commit_id_7_to_40_chars",cleanup_result:"not_applicable"}')"
  fi
}

assert_clean_tree() {
  local step="$1"
  local status
  git_safe update-index -q --refresh 2>/dev/null || true
  status="$(git_safe status --porcelain --untracked-files=normal)"
  if [ -n "${status}" ]; then
    fail_step "${step}" "$(jq -cn --arg status "${status}" \
      '{dirty_tree_entries:($status | split("\n") | map(select(length > 0))),cleanup_result:"not_applicable"}')"
  fi
}

append_tool_versions() {
  append_json "tool_versions" "pass" "$(jq -cn \
    --arg cargo "$(tool_version cargo -V)" \
    --arg rustc "$(tool_version rustc -V)" \
    --arg rustfmt "$(tool_version rustfmt -V)" \
    --arg clippy "$(tool_version clippy-driver -V)" \
    --arg rch "$(tool_version "${RCH_BIN}" --version)" \
    --arg lake "$(tool_version lake --version)" \
    --arg jq "$(tool_version jq --version)" \
    --arg git "$(tool_version git --version)" \
    --arg ubs "$(tool_version ubs --version)" \
    '{cargo:$cargo,rustc:$rustc,rustfmt:$rustfmt,clippy:$clippy,rch:$rch,lake:$lake,jq:$jq,git:$git,ubs:$ubs,cleanup_result:"not_applicable"}')"
}

extract_passed_tests() {
  local log="$1"
  sed -n 's/.*test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' "${log}" | tail -n 1
}

benchmark_groups_observed_for_log() {
  local log="$1"
  local -a groups=()
  if grep -Fq "lattice_trapdoor_master_setup" "${log}"; then
    groups+=("trap_gen")
  fi
  if grep -Fq "lattice_delegate_one_hop" "${log}"; then
    groups+=("delegate")
  fi
  if grep -Fq "lattice_sample_pre_real_route" "${log}"; then
    groups+=("sample_pre")
  fi
  if grep -Fq "lattice_verify_real_route" "${log}"; then
    groups+=("verify")
  fi
  if grep -Fq "lattice_full_crypto_route" "${log}"; then
    groups+=("full_crypto_route")
  fi
  printf '%s\n' "${groups[@]}" | sort -u | jq -R -s 'split("\n") | map(select(length > 0))'
}

benchmark_group_details_for_step() {
  local step="$1"
  local log="$2"
  case "${step}" in
    "criterion_lattice_crypto_bench")
      jq -cn \
        --argjson groups "$(benchmark_groups_observed_for_log "${log}")" \
        '{benchmark_group_source:"criterion_log",benchmark_groups_observed:$groups}'
      ;;
    "host_lattice_dispatcher_e2e")
      jq -cn \
        '{benchmark_group_source:"host_dispatcher_e2e",benchmark_groups_observed:["host_dispatcher_pipeline"]}'
      ;;
    *)
      printf '{}'
      ;;
  esac
}

rch_summary_line() {
  local log="$1"
  grep -E '\[RCH\] (remote|local|failed)' "${log}" | tail -n 1 || true
}

fallback_decision_for_log() {
  local display_command="$1"
  local log="$2"
  local summary
  summary="$(rch_summary_line "${log}")"
  if [ -z "${summary}" ]; then
    case "${display_command}" in
      *"rch exec"*) printf 'rch_summary_unobserved' ;;
      *) printf 'not_needed' ;;
    esac
  elif printf '%s' "${summary}" | grep -Eq 'remote required; refusing local fallback|refus(ed|ing) local fallback'; then
    printf 'rch_local_fallback_refused'
  elif printf '%s' "${summary}" | grep -Fq 'failed'; then
    printf 'rch_remote_failed'
  elif printf '%s' "${summary}" | grep -Fq '[RCH] local'; then
    printf 'rch_local_fallback'
  elif printf '%s' "${summary}" | grep -Fq '[RCH] remote'; then
    printf 'not_needed'
  else
    printf 'rch_summary_unclassified'
  fi
}

worker_execution_class_for_log() {
  local display_command="$1"
  local log="$2"
  local summary
  summary="$(rch_summary_line "${log}")"
  if [ -z "${summary}" ]; then
    case "${display_command}" in
      *"rch exec"*) printf 'unknown' ;;
      *) printf 'not_applicable' ;;
    esac
  elif printf '%s' "${summary}" | grep -Eq 'remote required; refusing local fallback|refus(ed|ing) local fallback'; then
    printf 'local_fallback_refused'
  elif printf '%s' "${summary}" | grep -Fq 'failed'; then
    printf 'remote_failed'
  elif printf '%s' "${summary}" | grep -Fq '[RCH] local'; then
    printf 'local'
  elif printf '%s' "${summary}" | grep -Fq '[RCH] remote'; then
    printf 'remote'
  else
    printf 'unknown'
  fi
}

is_rch_exec_command() {
  local display_command="$1"
  case "${display_command}" in
    *"rch exec"*) return 0 ;;
    *) return 1 ;;
  esac
}

require_remote_rch_success() {
  local step="$1"
  local display_command="$2"
  local log_artifact="$3"
  local log_hash="$4"
  local duration_seconds="$5"
  local fallback_decision="$6"
  local worker_execution_class="$7"
  local rch_summary_json="$8"
  if is_rch_exec_command "${display_command}" &&
    [ "${worker_execution_class}" != "remote" ]; then
    fail_step "remote_rch_required_${step}" "$(jq -cn \
      --arg command_line "${display_command}" \
      --arg log_artifact "${log_artifact}" \
      --arg log_hash "sha256:${log_hash}" \
      --arg fallback_decision "${fallback_decision}" \
      --arg worker_execution_class "${worker_execution_class}" \
      --argjson duration_seconds "${duration_seconds}" \
      --argjson rch_summary "${rch_summary_json}" \
      '{command_line:$command_line,log_artifact:$log_artifact,log_hash:$log_hash,duration_seconds:$duration_seconds,fallback_decision:$fallback_decision,worker_execution_class:$worker_execution_class,rch_summary:$rch_summary,required_worker_execution_class:"remote",cleanup_result:"not_applicable"}')"
  fi
}

run_and_capture() {
  local step="$1"
  local display_command="$2"
  shift 2
  local log="${LOG_PREFIX}.${step}.log"
  local started
  local fallback_decision worker_execution_class rch_summary rch_summary_json
  assert_stable_revision "stable_revision_before_${step}"
  started="$(date -u +%s)"
  if "$@" >"${log}" 2>&1; then
    local ended duration hash passed_tests passed_tests_json benchmark_group_details
    ended="$(date -u +%s)"
    duration=$((ended - started))
    hash="$(sha256_file "${log}")"
    passed_tests="$(extract_passed_tests "${log}")"
    passed_tests_json="$(json_string_or_null "${passed_tests}")"
    fallback_decision="$(fallback_decision_for_log "${display_command}" "${log}")"
    worker_execution_class="$(worker_execution_class_for_log "${display_command}" "${log}")"
    rch_summary="$(rch_summary_line "${log}")"
    rch_summary_json="$(json_string_or_null "${rch_summary}")"
    benchmark_group_details="$(benchmark_group_details_for_step "${step}" "${log}")"
    require_remote_rch_success \
      "${step}" \
      "${display_command}" \
      "target/fcp-crypto-pq/${RUN_ID}.${step}.log" \
      "${hash}" \
      "${duration}" \
      "${fallback_decision}" \
      "${worker_execution_class}" \
      "${rch_summary_json}"
    assert_stable_revision "stable_revision_after_${step}"
    assert_clean_tree "clean_tree_after_${step}"
    append_json "${step}" "pass" "$(jq -cn \
      --arg command_line "${display_command}" \
      --arg log_artifact "target/fcp-crypto-pq/${RUN_ID}.${step}.log" \
      --arg log_hash "sha256:${hash}" \
      --arg fallback_decision "${fallback_decision}" \
      --arg worker_execution_class "${worker_execution_class}" \
      --argjson duration_seconds "${duration}" \
      --argjson passed_tests "${passed_tests_json}" \
      --argjson rch_summary "${rch_summary_json}" \
      --argjson benchmark_group_details "${benchmark_group_details}" \
      '{command_line:$command_line,log_artifact:$log_artifact,log_hash:$log_hash,duration_seconds:$duration_seconds,passed_tests:$passed_tests,retry_count:0,fallback_decision:$fallback_decision,worker_execution_class:$worker_execution_class,rch_summary:$rch_summary,cache_decision:"cargo_target_dir_hashed",cleanup_result:"not_applicable"} + $benchmark_group_details')"
  else
    local ended duration hash
    ended="$(date -u +%s)"
    duration=$((ended - started))
    hash="$(sha256_file "${log}")"
    fallback_decision="$(fallback_decision_for_log "${display_command}" "${log}")"
    worker_execution_class="$(worker_execution_class_for_log "${display_command}" "${log}")"
    rch_summary="$(rch_summary_line "${log}")"
    rch_summary_json="$(json_string_or_null "${rch_summary}")"
    fail_step "${step}" "$(jq -cn \
      --arg command_line "${display_command}" \
      --arg log_artifact "target/fcp-crypto-pq/${RUN_ID}.${step}.log" \
      --arg log_hash "sha256:${hash}" \
      --arg fallback_decision "${fallback_decision}" \
      --arg worker_execution_class "${worker_execution_class}" \
      --argjson duration_seconds "${duration}" \
      --argjson rch_summary "${rch_summary_json}" \
      '{command_line:$command_line,log_artifact:$log_artifact,log_hash:$log_hash,duration_seconds:$duration_seconds,retry_count:0,fallback_decision:$fallback_decision,worker_execution_class:$worker_execution_class,rch_summary:$rch_summary,cache_decision:"cargo_target_dir_hashed",cleanup_result:"not_applicable"}')"
  fi
}

run_rch_cargo() {
  local step="$1"
  local display_command="$2"
  shift 2
  run_and_capture "${step}" "${display_command}" \
    env RCH_VISIBILITY=verbose RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE}" RCH_FORCE_REMOTE=1 \
    "${RCH_BIN}" exec -- env \
      CARGO_TARGET_DIR="${TARGET_DIR}" \
      CARGO_PROFILE_DEV_DEBUG=0 \
      CARGO_PROFILE_TEST_DEBUG=0 \
      CARGO_INCREMENTAL=0 \
      FCP_LATTICE_GIT_REVISION="$(git_revision)" \
      FCP_LATTICE_EVIDENCE_ROOT="${ARTIFACT_STAGE_ROOT}" \
      RUSTFLAGS=-Cdebuginfo=0 \
      "$@"
}

require_artifact() {
  local step="$1"
  local path="$2"
  if [ ! -s "${path}" ]; then
    fail_step "${step}" "$(jq -cn --arg artifact "${path}" \
      '{artifact_path:$artifact,missing_or_empty:true,cleanup_result:"not_applicable"}')"
  fi
}

append_artifact_hash() {
  local step="$1"
  local path="$2"
  require_artifact "${step}" "${path}"
  append_json "${step}" "pass" "$(jq -cn \
    --arg artifact "${path}" \
    --arg artifact_hash "sha256:$(sha256_file "${path}")" \
    '{artifact_path:$artifact,artifact_hash:$artifact_hash,cleanup_result:"not_applicable_generated_artifact"}')"
}

artifact_stage_path() {
  local path="$1"
  case "${path}" in
    target/*)
      printf '%s/%s' "${ARTIFACT_STAGE_ROOT}" "${path#target/}"
      ;;
    *)
      printf '%s/%s' "${ARTIFACT_STAGE_ROOT}" "${path}"
      ;;
  esac
}

artifact_log_path() {
  local path="$1"
  case "${path}" in
    target/fcp-crypto-pq/*)
      printf '%s.crypto_representation_profile_tests.log' "${LOG_PREFIX}"
      ;;
    target/fcp-policy/*)
      printf '%s.policy_lattice_delegation_tests.log' "${LOG_PREFIX}"
      ;;
    target/fcp-host/*)
      printf '%s.host_lattice_dispatcher_e2e.log' "${LOG_PREFIX}"
      ;;
    *)
      return 1
      ;;
  esac
}

materialize_logged_artifact() {
  local path="$1"
  local log materialized
  log="$(artifact_log_path "${path}")" || return 0
  if [ ! -s "${path}" ] && [ -s "${log}" ]; then
    mkdir -p "$(dirname "${path}")"
    materialized="$(jq -R -c --arg artifact "${path}" \
      'fromjson? | select(.artifact_path == $artifact)' \
      "${log}")"
    if [ -n "${materialized}" ]; then
      printf '%s\n' "${materialized}" > "${path}"
    fi
  fi
}

materialize_staged_artifact() {
  local path="$1"
  local staged
  staged="$(artifact_stage_path "${path}")"
  if [ -s "${staged}" ] && [ "${staged}" != "${path}" ]; then
    mkdir -p "$(dirname "${path}")"
    cp "${staged}" "${path}"
  fi
  materialize_logged_artifact "${path}"
}

append_materialized_artifact_hash() {
  local step="$1"
  local path="$2"
  materialize_staged_artifact "${path}"
  append_artifact_hash "${step}" "${path}"
}

scan_jsonl_artifact() {
  local path="$1"
  local forbidden
  for forbidden in \
    "/home/" \
    "/data/projects/" \
    "/Users/" \
    "/Volumes/" \
    "/private/var/" \
    "/var/folders/" \
    "/tmp" \
    "/private/tmp" \
    "C:\\\\Users\\\\" \
    "trapdoor_material" \
    "trapdoor_coefficients" \
    "secret_seed" \
    "expanded_secret_matrix" \
    "preimage_coefficients" \
    "preimage_bytes" \
    "raw_operation" \
    "raw_principal" \
    "raw_zone" \
    "send_message" \
    "agent-alpha" \
    "agent-beta" \
    "provider_body" \
    "reviewer_contact"; do
    if grep -Fq "${forbidden}" "${path}"; then
      fail_step "redaction_scan" "$(jq -cn --arg artifact "${path}" --arg forbidden "${forbidden}" \
        '{artifact_path:$artifact,forbidden:$forbidden,cleanup_result:"not_applicable"}')"
    fi
  done
  for forbidden in \
    "authorization:" \
    "bearer" \
    "agent:" \
    "op:" \
    "operation:" \
    "principal:" \
    "zone:" \
    "token=" \
    "z:" \
    "access_token" \
    "refresh_token" \
    "id_token" \
    "client_secret" \
    "api_key" \
    "private_key" \
    "secret_key" \
    "password" \
    "cookie" \
    "credential=" \
    "credential:" \
    "provider_response_body" \
    "provider_payload_body" \
    "reviewer_email" \
    "reviewer_phone"; do
    if grep -Fqi "${forbidden}" "${path}"; then
      fail_step "redaction_scan" "$(jq -cn --arg artifact "${path}" --arg forbidden "${forbidden}" \
        '{artifact_path:$artifact,forbidden_case_insensitive:$forbidden,cleanup_result:"not_applicable"}')"
    fi
  done
}

append_redaction_scan() {
  local scanned=0
  local scanned_paths_json='[]'
  for artifact in "$@"; do
    require_artifact "redaction_scan_prerequisite" "${artifact}"
    scan_jsonl_artifact "${artifact}"
    scanned_paths_json="$(jq -cn --argjson paths "${scanned_paths_json}" --arg artifact "${artifact}" \
      '$paths + [$artifact]')"
    scanned=$((scanned + 1))
  done
  append_json "redaction_scan" "pass" "$(jq -cn --argjson scanned "${scanned}" --argjson scanned_paths "${scanned_paths_json}" \
    '{scanned_jsonl_artifacts:$scanned,scanned_artifact_paths:$scanned_paths,trapdoor_payload:"absent",preimage_payload:"absent",rng_seed_payload:"absent",operation_plaintext:"absent",principal_plaintext:"absent",zone_label_plaintext:"absent",auth_header_values:"absent",credential_markers:"absent",local_private_paths:"absent",provider_payloads:"absent",reviewer_private_data:"absent",cleanup_result:"not_applicable"}')"
}

validate_jsonl_contract() {
  local step="$1"
  local path="$2"
  local filter="$3"
  local diagnostic
  require_artifact "${step}" "${path}"
  if ! diagnostic="$(jq -e -s "${filter}" "${path}" 2>&1 >/dev/null)"; then
    if [ -z "${diagnostic}" ]; then
      diagnostic="contract_filter_returned_false"
    fi
    fail_step "${step}" "$(jq -cn \
      --arg artifact "${path}" \
      --arg validation_error "${diagnostic}" \
      '{artifact_path:$artifact,validation_error:$validation_error,cleanup_result:"not_applicable"}')"
  fi
}

validate_artifact_contracts() {
  validate_jsonl_contract "validate_crypto_representation_contract" \
    "target/fcp-crypto-pq/representation-profile-evidence.jsonl" '
      def required_representation_profiles:
        [
          "SMALL_TEST",
          "V4_REFERENCE"
        ];
      def representation_profile_ids:
        map(.profile);
      def nonnegative_integer:
        type == "number" and . == floor and . >= 0;
      def positive_integer:
        nonnegative_integer and . > 0;
      def matrix_dimensions_shape:
        type == "object" and
        (.n | positive_integer) and
        (.m | positive_integer) and
        (.q | positive_integer) and
        (.coefficient_bytes | positive_integer);
      def encoded_public_lengths_shape:
        type == "object" and
        (.master_public_seed_bytes | positive_integer) and
        (.zone_period_public_seed_bytes | positive_integer) and
        (.operation_hash_bytes | positive_integer);
      def encoded_lengths_shape:
        type == "object" and
        (.public_matrix_seed_bytes | positive_integer) and
        (.public_matrix_expanded_bytes | positive_integer) and
        (.trapdoor_storage_bytes | positive_integer) and
        (.preimage_encoded_bytes | positive_integer);
      def allocation_estimate_shape:
        type == "object" and
        (.public_matrix_expanded_bytes | positive_integer) and
        (.max_public_matrix_expanded_bytes | positive_integer) and
        (.preimage_encoded_bytes | positive_integer) and
        (.max_preimage_encoded_bytes | positive_integer);
      length > 0 and
      ((representation_profile_ids | sort) == (required_representation_profiles | sort)) and
      all(.[]; type == "object" and
        (.command_line | type == "string") and
        (.git_revision | (type == "string" and test("^[0-9a-f]{7,40}$"))) and
        .artifact_path == "target/fcp-crypto-pq/representation-profile-evidence.jsonl" and
        (.fixture_id | type == "string") and
        (.profile | type == "string") and
        (.representation_version | positive_integer) and
        (.params | type == "object") and
        (.matrix_dimensions | matrix_dimensions_shape) and
        (.encoded_public_lengths | encoded_public_lengths_shape) and
        (.encoded_lengths | encoded_lengths_shape) and
        (.allocation_estimate | allocation_estimate_shape) and
        (.relation_check_result | type == "object") and
        (.trapdoor_norm_quality_bucket | type == "object") and
        (.secret_storage_len_bucket | type == "object") and
        (.redaction | type == "object") and
        (.timing_ms | nonnegative_integer) and
        (.result | type == "string") and
        has("skip_reason"))
    '

  validate_jsonl_contract "validate_crypto_route_contract" \
    "target/fcp-crypto-pq/trapgen-delegate-route-evidence.jsonl" '
      def hex_hash:
        type == "string" and test("^[0-9a-f]{64}$");
      def nonnegative_integer:
        type == "number" and . == floor and . >= 0;
      def positive_integer:
        nonnegative_integer and . > 0;
      def matrix_dimensions_shape:
        type == "object" and
        (.n | positive_integer) and
        (.m | positive_integer) and
        (.q | positive_integer) and
        (.coefficient_bytes | positive_integer);
      def allocation_estimate_shape:
        type == "object" and
        (.public_matrix_expanded_bytes | positive_integer) and
        (.max_public_matrix_expanded_bytes | positive_integer) and
        (.preimage_encoded_bytes | positive_integer) and
        (.max_preimage_encoded_bytes | positive_integer);
      def route_timings_shape:
        type == "object" and
        (.trap_gen | nonnegative_integer) and
        (.delegate | nonnegative_integer) and
        (.relation_checks | nonnegative_integer);
      def required_route_scenarios:
        [
          "passed:SMALL_TEST",
          "passed:V4_REFERENCE",
          "denied:malformed root basis",
          "denied:malformed child basis",
          "denied:wrong parent",
          "denied:wrong zone",
          "denied:wrong period",
          "denied:wrong parameter profile",
          "denied:unsupported custom profile",
          "denied:fixture-only trapdoor used on production route"
        ];
      def route_scenario_ids:
        map(
          if .result == "passed" and .skip_reason == null then
            "passed:" + .parameter_profile
          elif .result == "denied" and (.skip_reason | type == "string") then
            "denied:" + .skip_reason
          else
            "invalid_route_scenario"
          end
        );
      length > 0 and
      ((route_scenario_ids | sort) == (required_route_scenarios | sort)) and
      all(.[]; type == "object" and
        (.command_line | type == "string") and
        (.git_revision | (type == "string" and test("^[0-9a-f]{7,40}$"))) and
        (.primitive_route_id | type == "string") and
        (.primitive_route_revision | positive_integer) and
        (.representation_version | positive_integer) and
        (.parameter_profile | type == "string") and
        (.fixture_id | type == "string") and
        (.zone_id_hash | hex_hash) and
        (.period_id_hash | hex_hash) and
        (.matrix_dimensions | matrix_dimensions_shape) and
        (.allocation_summary | allocation_estimate_shape) and
        (.primitive_timings_ms | route_timings_shape) and
        (.timing_ms | nonnegative_integer) and
        (.cleanup | type == "string") and
        (.result | type == "string") and
        has("skip_reason") and
        (.skip_reason == null or (.skip_reason | type == "string")))
    '

  validate_jsonl_contract "validate_crypto_public_matrix_contract" \
    "target/fcp-crypto-pq/public-matrix-reconstruction-evidence.jsonl" '
      def hex_hash:
        type == "string" and test("^[0-9a-f]{64}$");
      def nonnegative_integer:
        type == "number" and . == floor and . >= 0;
      def positive_integer:
        nonnegative_integer and . > 0;
      def optional_hex_hash:
        . == null or hex_hash;
      def matrix_dimensions_shape:
        type == "object" and
        (.n | positive_integer) and
        (.m | positive_integer) and
        (.q | positive_integer) and
        (.coefficient_bytes | positive_integer);
      def public_material_summary_shape:
        type == "object" and
        (.kind | type == "string") and
        (.public_seed_bytes | positive_integer) and
        (.tail_coefficients_bytes | nonnegative_integer) and
        (.binding_hash_hex | hex_hash) and
        (.material_digest_hex | optional_hex_hash);
      def allocation_estimate_shape:
        type == "object" and
        (.public_matrix_expanded_bytes | positive_integer) and
        (.max_public_matrix_expanded_bytes | positive_integer) and
        (.preimage_encoded_bytes | positive_integer) and
        (.max_preimage_encoded_bytes | positive_integer);
      def required_public_matrix_scenarios:
        [
          "passed:SMALL_TEST",
          "passed:V4_REFERENCE",
          "denied:malformed public tail",
          "denied:wrong public binding hash",
          "denied:wrong public seed",
          "denied:wrong route revision",
          "denied:V4 malformed public tail",
          "denied:V4 wrong public binding hash",
          "denied:V4 wrong public seed",
          "denied:V4 wrong route revision",
          "denied:unsupported custom profile"
        ];
      def public_matrix_scenario_ids:
        map(
          if .result == "passed" and .skip_reason == null then
            "passed:" + .parameter_profile
          elif .result == "denied" and (.skip_reason | type == "string") then
            "denied:" + .skip_reason
          else
            "invalid_public_matrix_scenario"
          end
        );
      length > 0 and
      ((public_matrix_scenario_ids | sort) == (required_public_matrix_scenarios | sort)) and
      all(.[]; type == "object" and
        (.command_line | type == "string") and
        (.git_revision | (type == "string" and test("^[0-9a-f]{7,40}$"))) and
        (.primitive_route_id | type == "string") and
        (.primitive_route_revision | positive_integer) and
        (.representation_version | positive_integer) and
        (.public_matrix_material_version | positive_integer) and
        (.parameter_profile | type == "string") and
        (.fixture_id | type == "string") and
        (.zone_id_hash | hex_hash) and
        (.period_id_hash | hex_hash) and
        (.public_material_summary | public_material_summary_shape) and
        (.matrix_dimensions | matrix_dimensions_shape) and
        (.reconstruction_result | type == "string") and
        (.allocation_summary | allocation_estimate_shape) and
        (.timing_ms | nonnegative_integer) and
        (.result | type == "string") and
        has("skip_reason") and
        (.skip_reason == null or (.skip_reason | type == "string")))
    '

  # shellcheck disable=SC2016 # jq variables/functions are intentionally single-quoted.
  validate_jsonl_contract "validate_crypto_sample_pre_contract" \
    "target/fcp-crypto-pq/sample-pre-verify-evidence.jsonl" '
      def hex_hash:
        type == "string" and test("^[0-9a-f]{64}$");
      def tagged_hash:
        type == "string" and test("^hash:[0-9a-f]{64}$");
      def nonnegative_integer:
        type == "number" and . == floor and . >= 0;
      def positive_integer:
        nonnegative_integer and . > 0;
      def matrix_dimensions_shape:
        type == "object" and
        (.n | positive_integer) and
        (.m | positive_integer) and
        (.q | positive_integer) and
        (.coefficient_bytes | positive_integer);
      def primitive_timings_shape:
        type == "object" and
        (.trap_gen | nonnegative_integer) and
        (.delegate | nonnegative_integer) and
        (.sample_pre | nonnegative_integer) and
        (.verify | nonnegative_integer);
      def sample_pre_scenarios($profile):
        [
          "passed:" + $profile + ":success",
          "denied:" + $profile + ":forged equation",
          "denied:" + $profile + ":wrong norm",
          "denied:" + $profile + ":wrong zone",
          "denied:" + $profile + ":wrong period",
          "denied:" + $profile + ":malformed preimage",
          "denied:" + $profile + ":outside period"
        ];
      def required_sample_pre_scenarios:
        sample_pre_scenarios("SMALL_TEST") + sample_pre_scenarios("V4_REFERENCE");
      def sample_pre_scenario_ids:
        map(
          if .result == "passed" and .skip_reason == null then
            "passed:" + .parameter_profile + ":success"
          elif .result == "denied" and (.skip_reason | type == "string") then
            "denied:" + .parameter_profile + ":" + .skip_reason
          else
            "invalid_sample_pre_scenario"
          end
        );
      length > 0 and
      ((sample_pre_scenario_ids | sort) == (required_sample_pre_scenarios | sort)) and
      all(.[]; type == "object" and
        (.command_line | type == "string") and
        (.git_revision | (type == "string" and test("^[0-9a-f]{7,40}$"))) and
        (.primitive_route_id | type == "string") and
        (.primitive_route_revision | positive_integer) and
        (.representation_version | positive_integer) and
        (.parameter_profile | type == "string") and
        (.fixture_id | type == "string") and
        (.zone_id_hash | hex_hash) and
        (.period_id_hash | hex_hash) and
        (.h_fixture_id | tagged_hash) and
        (.matrix_dimensions | matrix_dimensions_shape) and
        (.norm_bound_squared | nonnegative_integer) and
        (.observed_norm_squared | nonnegative_integer) and
        (.observed_norm_bucket | type == "string") and
        (.primitive_timings_ms | primitive_timings_shape) and
        (.verify_outcome | type == "string") and
        has("error_mapping") and
        (.timeout_cancel_result | type == "string") and
        (.cleanup | type == "string") and
        (.result | type == "string") and
        has("skip_reason") and
        (.skip_reason == null or (.skip_reason | type == "string")))
    '

  validate_jsonl_contract "validate_crypto_formal_contract" \
    "target/fcp-crypto-pq/lattice-delegation-formal-correspondence-evidence.jsonl" '
      def hex_hash:
        type == "string" and test("^[0-9a-f]{64}$");
      def tagged_hash:
        type == "string" and test("^hash:[0-9a-f]{64}$");
      def optional_hex_hash:
        . == null or hex_hash;
      def nonnegative_integer:
        type == "number" and . == floor and . >= 0;
      def positive_integer:
        nonnegative_integer and . > 0;
      def matrix_dimensions_shape:
        type == "object" and
        (.n | positive_integer) and
        (.m | positive_integer) and
        (.q | positive_integer) and
        (.coefficient_bytes | positive_integer);
      def public_material_summary_shape:
        type == "object" and
        (.kind | type == "string") and
        (.public_seed_bytes | positive_integer) and
        (.tail_coefficients_bytes | nonnegative_integer) and
        (.binding_hash_hex | hex_hash) and
        (.material_digest_hex | optional_hex_hash);
      def required_formal_profiles:
        [
          "SMALL_TEST",
          "V4_REFERENCE"
        ];
      def required_formal_theorem_names:
        [
          "Fcp.Invariants.LatticeDelegation.lattice_delegation_chain_corruption_rejected",
          "Fcp.Invariants.LatticeDelegation.lattice_delegation_sis_assumption_boundary_complete",
          "Fcp.Invariants.LatticeDelegation.lattice_trapdoor_capability_unforgeability_reduces_to_sis_assumptions"
        ];
      def required_formal_assumption_ids:
        [
          "FCP-PQ-SIS-HARDNESS-V1",
          "FCP-PQ-RANDOM-ORACLE-DOMAIN-SEPARATION-V1",
          "FCP-PQ-MP12-CHKP-GPV-ROUTE-CORRESPONDENCE-V1",
          "FCP-PQ-IMPLEMENTATION-ENCODING-CORRESPONDENCE-V1",
          "FCP-POLICY-DISPATCHER-BINDING-CORRESPONDENCE-V1",
          "FCP-POLICY-REPLAY-DENIAL-CORRESPONDENCE-V1"
        ];
      def formal_profile_ids:
        map(.parameter_profile);
      length > 0 and
      ((formal_profile_ids | sort) == (required_formal_profiles | sort)) and
      all(.[]; type == "object" and
        .schema == "fcp.crypto_pq.lattice_formal_correspondence.v1" and
        (.command_line | type == "string") and
        (.git_revision | (type == "string" and test("^[0-9a-f]{7,40}$"))) and
        (.theorem_names |
          if type == "array" then
            (sort == (required_formal_theorem_names | sort))
          else false end) and
        (.assumption_ids |
          if type == "array" then
            (sort == (required_formal_assumption_ids | sort))
          else false end) and
        (.fixture_id_hash | tagged_hash) and
        .fixture_category == "deterministic-public-correspondence" and
        (.parameter_profile | type == "string") and
        (.primitive_route_id | type == "string") and
        (.primitive_route_revision | positive_integer) and
        (.representation_version | positive_integer) and
        (.public_matrix_material_version | positive_integer) and
        (.zone_id_hash | hex_hash) and
        (.period_id_hash | hex_hash) and
        (.public_material_summary | public_material_summary_shape) and
        (.matrix_dimensions | matrix_dimensions_shape) and
        (.checks | type == "object") and
        .checks.public_material_reconstruction == true and
        .checks.route_profile_domain_separation == true and
        .checks.operation_principal_domain_separation == true and
        .checks.malformed_public_header_rejected == true and
        .checks.malformed_tail_coefficients_rejected == true and
        .checks.stale_route_revision_rejected == true and
        .checks.unsupported_profile_rejected == true and
        (.artifact_hashes | type == "object") and
        (.artifact_hashes.public_seed_hash_hex | hex_hash) and
        (.artifact_hashes.public_material_digest_hex | optional_hex_hash) and
        (.duration_ms | nonnegative_integer) and
        .result == "passed" and
        has("skip_reason") and
        .skip_reason == null)
    '

  validate_jsonl_contract "validate_policy_formal_contract" \
    "target/fcp-policy/lattice-delegation-policy-correspondence-evidence.jsonl" '
      def hex_hash:
        type == "string" and test("^[0-9a-f]{64}$");
      def nonnegative_integer:
        type == "number" and . == floor and . >= 0;
      def positive_integer:
        nonnegative_integer and . > 0;
      def required_formal_profiles:
        [
          "SMALL_TEST",
          "V4_REFERENCE"
        ];
      def required_formal_theorem_names:
        [
          "Fcp.Invariants.LatticeDelegation.lattice_delegation_chain_corruption_rejected",
          "Fcp.Invariants.LatticeDelegation.lattice_delegation_sis_assumption_boundary_complete",
          "Fcp.Invariants.LatticeDelegation.lattice_trapdoor_capability_unforgeability_reduces_to_sis_assumptions"
        ];
      def required_formal_assumption_ids:
        [
          "FCP-PQ-SIS-HARDNESS-V1",
          "FCP-PQ-RANDOM-ORACLE-DOMAIN-SEPARATION-V1",
          "FCP-PQ-MP12-CHKP-GPV-ROUTE-CORRESPONDENCE-V1",
          "FCP-PQ-IMPLEMENTATION-ENCODING-CORRESPONDENCE-V1",
          "FCP-POLICY-DISPATCHER-BINDING-CORRESPONDENCE-V1",
          "FCP-POLICY-REPLAY-DENIAL-CORRESPONDENCE-V1"
        ];
      def formal_profile_ids:
        map(.parameter_profile);
      length > 0 and
      ((formal_profile_ids | sort) == (required_formal_profiles | sort)) and
      all(.[]; type == "object" and
        .schema == "fcp.policy.lattice_formal_correspondence.v1" and
        (.command_line | type == "string") and
        (.git_revision | (type == "string" and test("^[0-9a-f]{7,40}$"))) and
        (.theorem_names |
          if type == "array" then
            (sort == (required_formal_theorem_names | sort))
          else false end) and
        (.assumption_ids |
          if type == "array" then
            (sort == (required_formal_assumption_ids | sort))
          else false end) and
        (.fixture_id_hash | hex_hash) and
        (.parameter_profile | type == "string") and
        (.route_revision | positive_integer) and
        (.representation_version | positive_integer) and
        (.public_matrix_material_version | positive_integer) and
        (.zone_id_hash | hex_hash) and
        (.period_id_hash | hex_hash) and
        (.certificate_id_hash | hex_hash) and
        (.trust_set_id_hash | hex_hash) and
        (.request_descriptor_hash | hex_hash) and
        (.checks | type == "object") and
        .checks.zone_period_public_key_shape == true and
        .checks.delegation_certificate_claims == true and
        .checks.operation_binding_rejected == true and
        .checks.principal_binding_rejected == true and
        .checks.request_binding_rejected == true and
        .checks.dispatcher_enforcement_checks == true and
        .checks.trust_set_replay_denied == true and
        .checks.stale_route_revision_rejected == true and
        .checks.certificate_envelope_rejected == true and
        (.duration_ms | nonnegative_integer) and
        .result == "passed" and
        has("skip_reason") and
        .skip_reason == null)
    '

  validate_jsonl_contract "validate_host_dispatcher_contract" \
    "target/fcp-host/lattice-policy-dispatcher-evidence.jsonl" '
      def hex_hash:
        type == "string" and test("^[0-9a-f]{64}$");
      def nonnegative_integer:
        type == "number" and . == floor and . >= 0;
      def positive_integer:
        nonnegative_integer and . > 0;
      def host_matrix_dimensions_shape:
        type == "object" and
        (.n | positive_integer) and
        (.m | positive_integer) and
        (.q_bits | positive_integer) and
        (.depth | positive_integer);
      def host_target_dir_class:
        type == "string" and (
          . == "tmp_absolute" or
          . == "absolute" or
          . == "relative" or
          . == "unset"
        );
      def stable_lattice_error_mapping:
        type == "string" and test("^LATTICE_[A-Z0-9_]+$");
      def required_scenarios:
        [
          "allow_small_test",
          "allow_v4_reference",
          "deny_forged_preimage",
          "deny_forged_v4_reference",
          "deny_mismatched_zone",
          "deny_mismatched_period",
          "deny_mismatched_operation",
          "deny_mismatched_principal",
          "deny_malformed_preimage",
          "deny_missing_certificate",
          "deny_incomplete_delegation_chain",
          "deny_chain_too_deep",
          "deny_trust_set_replay",
          "deny_trust_set_replay_v4_reference"
        ];
      def scenario_ids:
        map(.scenario);
      length > 0 and
      ((scenario_ids | sort) == (required_scenarios | sort)) and
      all(.[]; type == "object" and
        (.command_line | type == "string") and
        (.git_revision | (type == "string" and test("^[0-9a-f]{7,40}$"))) and
        (.build_profile | type == "string") and
        (.cargo_target_dir_hash | hex_hash) and
        (.cargo_target_dir_class | host_target_dir_class) and
        (.worker_host_class | type == "string") and
        (.timing_sample_count | positive_integer) and
        .artifact_path == "target/fcp-host/lattice-policy-dispatcher-evidence.jsonl" and
        (.parameter_profile | type == "string") and
        (.fixture_id_hash | hex_hash) and
        (.scenario | type == "string") and
        (.zone_id_hash | hex_hash) and
        (.period_id_hash | hex_hash) and
        (.cert_id_hash | hex_hash) and
        (.trust_set_id_hash | hex_hash) and
        (.trust_set_source_hash | hex_hash) and
        (.operation_id_hash | hex_hash) and
        (.principal_id_hash | hex_hash) and
        (.request_binding_result | type == "string") and
        (.matrix_dimensions | host_matrix_dimensions_shape) and
        (.primitive_timings | type == "object") and
        (.pipeline_checks | type == "array") and
        (.norm_bound_bucket | type == "string") and
        (.verifier_result | type == "string") and
        has("receipt_id_hash") and
        (.receipt_id_hash == null or (.receipt_id_hash | hex_hash)) and
        (.dispatcher_decision | type == "string") and
        (if .dispatcher_decision == "allow" then
          .verifier_result == "ok"
          and .error_mapping == null
          and (.receipt_id_hash | hex_hash)
        elif .dispatcher_decision == "deny" then
          (.verifier_result | stable_lattice_error_mapping)
          and .error_mapping == .verifier_result
          and .receipt_id_hash == null
        else
          false
        end) and
        (.benchmark_summary | type == "string") and
        (.cleanup_result | type == "string") and
        has("skip_reason")) and
      any(.[]; .scenario == "allow_v4_reference" and .dispatcher_decision == "allow" and .verifier_result == "ok") and
      any(.[]; .scenario == "deny_forged_v4_reference" and .dispatcher_decision == "deny" and .error_mapping == "LATTICE_VERIFICATION_EQUATION_FAILED") and
      any(.[]; .scenario == "deny_trust_set_replay_v4_reference" and .dispatcher_decision == "deny" and .error_mapping == "LATTICE_REQUEST_BINDING_MISMATCH") and
      any(.[]; .scenario == "deny_mismatched_operation" and .dispatcher_decision == "deny" and .error_mapping == "LATTICE_OPERATION_MISMATCH") and
      any(.[]; .scenario == "deny_mismatched_principal" and .dispatcher_decision == "deny" and .error_mapping == "LATTICE_PRINCIPAL_MISMATCH")
    '

  append_json "jsonl_contract_validation" "pass" "$(jq -cn \
    '{validated_artifacts:["target/fcp-crypto-pq/representation-profile-evidence.jsonl","target/fcp-crypto-pq/trapgen-delegate-route-evidence.jsonl","target/fcp-crypto-pq/public-matrix-reconstruction-evidence.jsonl","target/fcp-crypto-pq/sample-pre-verify-evidence.jsonl","target/fcp-crypto-pq/lattice-delegation-formal-correspondence-evidence.jsonl","target/fcp-policy/lattice-delegation-policy-correspondence-evidence.jsonl","target/fcp-host/lattice-policy-dispatcher-evidence.jsonl"],required_representation_profiles:["SMALL_TEST","V4_REFERENCE"],representation_profile_cardinality:"exactly_once",required_route_scenarios:["passed:SMALL_TEST","passed:V4_REFERENCE","denied:malformed root basis","denied:malformed child basis","denied:wrong parent","denied:wrong zone","denied:wrong period","denied:wrong parameter profile","denied:unsupported custom profile","denied:fixture-only trapdoor used on production route"],route_scenario_cardinality:"exactly_once",required_public_matrix_scenarios:["passed:SMALL_TEST","passed:V4_REFERENCE","denied:malformed public tail","denied:wrong public binding hash","denied:wrong public seed","denied:wrong route revision","denied:V4 malformed public tail","denied:V4 wrong public binding hash","denied:V4 wrong public seed","denied:V4 wrong route revision","denied:unsupported custom profile"],public_matrix_scenario_cardinality:"exactly_once",sample_pre_scenario_cardinality:"exactly_once_per_profile",required_formal_profiles:["SMALL_TEST","V4_REFERENCE"],formal_profile_cardinality:"exactly_once_per_formal_artifact",required_formal_theorem_names:["Fcp.Invariants.LatticeDelegation.lattice_delegation_chain_corruption_rejected","Fcp.Invariants.LatticeDelegation.lattice_delegation_sis_assumption_boundary_complete","Fcp.Invariants.LatticeDelegation.lattice_trapdoor_capability_unforgeability_reduces_to_sis_assumptions"],required_formal_assumption_ids:["FCP-PQ-SIS-HARDNESS-V1","FCP-PQ-RANDOM-ORACLE-DOMAIN-SEPARATION-V1","FCP-PQ-MP12-CHKP-GPV-ROUTE-CORRESPONDENCE-V1","FCP-PQ-IMPLEMENTATION-ENCODING-CORRESPONDENCE-V1","FCP-POLICY-DISPATCHER-BINDING-CORRESPONDENCE-V1","FCP-POLICY-REPLAY-DENIAL-CORRESPONDENCE-V1"],crypto_formal_check_cardinality:"all_true_per_profile",policy_formal_check_cardinality:"all_true_per_profile",required_host_scenarios:["allow_small_test","allow_v4_reference","deny_forged_preimage","deny_forged_v4_reference","deny_mismatched_zone","deny_mismatched_period","deny_mismatched_operation","deny_mismatched_principal","deny_malformed_preimage","deny_missing_certificate","deny_incomplete_delegation_chain","deny_chain_too_deep","deny_trust_set_replay","deny_trust_set_replay_v4_reference"],host_scenario_cardinality:"exactly_once",cleanup_result:"not_applicable"}')"
}

validate_gauntlet_contract() {
  # shellcheck disable=SC2016 # jq variables/functions are intentionally single-quoted.
  validate_jsonl_contract "validate_gauntlet_contract" "${ARTIFACT}" '
    def sha256_hash:
      type == "string" and test("^sha256:[0-9a-f]{64}$");
    def git_revision_hash:
      type == "string" and test("^[0-9a-f]{7,40}$");
    def safe_label:
      type == "string" and test("^[A-Za-z0-9._-]+$") and (contains("..") | not);
    def gauntlet_build_profile:
      . == "dev-test-bench";
    def gauntlet_target_dir_class:
      type == "string" and (
        . == "ephemeral_tmp" or
        . == "repo_relative_target" or
        . == "custom_hashed"
      );
    def required_host_scenarios:
      [
        "allow_small_test",
        "allow_v4_reference",
        "deny_forged_preimage",
        "deny_forged_v4_reference",
        "deny_mismatched_zone",
        "deny_mismatched_period",
        "deny_mismatched_operation",
        "deny_mismatched_principal",
        "deny_malformed_preimage",
        "deny_missing_certificate",
        "deny_incomplete_delegation_chain",
        "deny_chain_too_deep",
        "deny_trust_set_replay",
        "deny_trust_set_replay_v4_reference"
      ];
    def required_profile_ids:
      [
        "SMALL_TEST",
        "V4_REFERENCE"
      ];
    def required_theorem_names:
      [
        "lattice_delegation_chain_corruption_rejected",
        "lattice_delegation_sis_assumption_boundary_complete",
        "lattice_trapdoor_capability_unforgeability_reduces_to_sis_assumptions"
      ];
    def required_assumption_ids:
      [
        "FCP-PQ-SIS-HARDNESS-V1",
        "FCP-PQ-RANDOM-ORACLE-DOMAIN-SEPARATION-V1",
        "FCP-PQ-MP12-CHKP-GPV-ROUTE-CORRESPONDENCE-V1",
        "FCP-PQ-IMPLEMENTATION-ENCODING-CORRESPONDENCE-V1",
        "FCP-POLICY-DISPATCHER-BINDING-CORRESPONDENCE-V1",
        "FCP-POLICY-REPLAY-DENIAL-CORRESPONDENCE-V1"
      ];
    def required_benchmark_groups:
      [
        "trap_gen",
        "delegate",
        "sample_pre",
        "verify",
        "full_crypto_route",
        "host_dispatcher_pipeline"
      ];
    def required_criterion_benchmark_groups:
      [
        "trap_gen",
        "delegate",
        "sample_pre",
        "verify",
        "full_crypto_route"
      ];
    def required_command_steps:
      [
        "lean_lake_workspace_probe",
        "lean_lake_build",
        "crypto_representation_profile_tests",
        "crypto_v4_unit_tests",
        "policy_lattice_delegation_tests",
        "host_lattice_dispatcher_e2e",
        "criterion_lattice_crypto_bench",
        "rustfmt_lattice_surfaces",
        "cargo_check_lattice_surfaces",
        "cargo_clippy_crypto_representation",
        "cargo_clippy_policy_lattice",
        "cargo_clippy_host_dispatcher",
        "bash_syntax",
        "git_diff_check",
        "ubs_lattice_surfaces"
      ];
    def required_test_command_steps:
      [
        "crypto_representation_profile_tests",
        "crypto_v4_unit_tests",
        "policy_lattice_delegation_tests",
        "host_lattice_dispatcher_e2e"
      ];
    def required_artifact_hash_steps:
      [
        "crypto_representation_artifact",
        "crypto_route_artifact",
        "crypto_public_matrix_artifact",
        "crypto_sample_pre_artifact",
        "crypto_formal_artifact",
        "policy_formal_artifact",
        "host_dispatcher_artifact"
      ];
    def required_singleton_steps:
      [
        "tool_versions",
        "validate_lean_ids"
      ] +
      required_command_steps +
      required_artifact_hash_steps +
      [
        "jsonl_contract_validation",
        "redaction_scan",
        "summary",
        "final_redaction_scan"
      ];
    def critical_steps_singleton:
      . as $records |
      all(required_singleton_steps[]; . as $step |
        ([ $records[] | select(.step == $step) ] | length) == 1);
    def allowed_steps_only:
      . as $records |
      all($records[]; .step as $step |
        (required_singleton_steps | index($step)) != null);
    def populated_tool_version:
      type == "string" and length > 0 and . != "unavailable";
    def positive_test_count:
      type == "string" and test("^[1-9][0-9]*$");
    def nonnegative_integer:
      type == "number" and . == floor and . >= 0;
    def nonempty_string:
      type == "string" and length > 0;
    def safe_relative_jsonl_artifact_path:
      type == "string" and
      test("^[A-Za-z0-9._/-]+[.]jsonl$") and
      startswith("target/fcp-crypto-pq/") and
      ((sub("^target/fcp-crypto-pq/"; "") | contains("/")) | not) and
      (startswith("/") | not) and
      (contains("..") | not) and
      (contains("//") | not);
    def required_tool_versions:
      any(.[]; .step == "tool_versions" and .result == "pass" and
        (.details.cargo | populated_tool_version) and
        (.details.rustc | populated_tool_version) and
        (.details.rustfmt | populated_tool_version) and
        (.details.clippy | populated_tool_version) and
        (.details.rch | populated_tool_version) and
        (.details.lake | populated_tool_version) and
        (.details.jq | populated_tool_version) and
        (.details.git | populated_tool_version) and
        (.details.ubs | populated_tool_version) and
        (.details.cleanup_result | type == "string"));
    def required_artifact_hash($step; $path):
      any(.[]; .step == $step and .result == "pass" and
        .details.artifact_path == $path and
        (.details.artifact_hash | sha256_hash) and
        (.details.cleanup_result | type == "string"));
    def non_rch_command_proof:
      (.details.command_line | contains("rch exec") | not) and
      .details.fallback_decision == "not_needed" and
      .details.worker_execution_class == "not_applicable" and
      .details.rch_summary == null;
    def rch_remote_proof:
      .details.fallback_decision == "not_needed" and
      .details.worker_execution_class == "remote" and
      (.details.rch_summary | type == "string" and contains("[RCH] remote") and (contains("remote required") | not) and (contains("refusing local fallback") | not));
    def rch_command_proof:
      (.details.command_line | contains("rch exec")) and
      rch_remote_proof;
    def expected_command_log_artifact:
      "target/fcp-crypto-pq/" + .run_id + "." + .step + ".log";
    def command_record_contract:
      if (.details | has("command_line")) then
        (.details.command_line | nonempty_string) and
        .details.log_artifact == expected_command_log_artifact and
        (.details.log_hash | sha256_hash) and
        (.details.duration_seconds | nonnegative_integer) and
        (.details.retry_count | nonnegative_integer) and
        (non_rch_command_proof or rch_command_proof) and
        .details.cache_decision == "cargo_target_dir_hashed" and
        (.details.cleanup_result | type == "string")
      else true end;
    def required_command_steps_present:
      . as $records |
      all(required_command_steps[]; . as $step |
        any($records[]; .step == $step and .result == "pass" and
          (.details | has("command_line")) and
          command_record_contract));
    def required_test_counts_present:
      . as $records |
      all(required_test_command_steps[]; . as $step |
        any($records[]; .step == $step and .result == "pass" and
          (.details | has("command_line")) and
          (.details.passed_tests | positive_test_count)));
    def benchmark_group_coverage_present:
      . as $records |
      any($records[]; .step == "criterion_lattice_crypto_bench" and .result == "pass" and
        .details.benchmark_group_source == "criterion_log" and
        (.details.benchmark_groups_observed | type == "array") and
        ((.details.benchmark_groups_observed | sort) == (required_criterion_benchmark_groups | sort))) and
      any($records[]; .step == "host_lattice_dispatcher_e2e" and .result == "pass" and
        .details.benchmark_group_source == "host_dispatcher_e2e" and
        (.details.benchmark_groups_observed | type == "array") and
        (.details.benchmark_groups_observed | index("host_dispatcher_pipeline") != null));
    def final_redaction_scan_covers_summary_artifact:
      . as $records |
      ([range(0; length) as $i |
        select($records[$i].step == "summary" and $records[$i].result == "pass") |
        {index:$i, artifact_path:$records[$i].details.artifact_path}][-1]) as $summary |
      ([range(0; length) as $i |
        select($records[$i].step == "final_redaction_scan" and $records[$i].result == "pass") |
        {index:$i, record:$records[$i]}][-1]) as $final_scan |
      ($summary != null) and
      ($final_scan != null) and
      ($summary.artifact_path | safe_relative_jsonl_artifact_path) and
      ($final_scan.index > $summary.index) and
      ($final_scan.index == ($summary.index + 1)) and
      ($final_scan.index == (length - 1)) and
      ($final_scan.record.details.scanned_jsonl_artifacts == 1) and
      ($final_scan.record.details.summary_record == "covered") and
      ($final_scan.record.details.scanned_artifact_path == $summary.artifact_path) and
      ($final_scan.record.details.post_summary_artifact_hash | sha256_hash) and
      ($final_scan.record.details.cleanup_result | type == "string");
    def redaction_scan_covers_expected_artifacts:
      . as $records |
      ([ $records[] | select(.step == "summary" and .result == "pass") | .details.artifact_path ][0] // null) as $summary_artifact |
      ($summary_artifact | safe_relative_jsonl_artifact_path) and
      any($records[]; .step == "redaction_scan" and .result == "pass" and
        .details.scanned_jsonl_artifacts == 8 and
        (.details.scanned_artifact_paths | type == "array") and
        ((.details.scanned_artifact_paths | sort) == ([
          $summary_artifact,
          "target/fcp-crypto-pq/representation-profile-evidence.jsonl",
          "target/fcp-crypto-pq/trapgen-delegate-route-evidence.jsonl",
          "target/fcp-crypto-pq/public-matrix-reconstruction-evidence.jsonl",
          "target/fcp-crypto-pq/sample-pre-verify-evidence.jsonl",
          "target/fcp-crypto-pq/lattice-delegation-formal-correspondence-evidence.jsonl",
          "target/fcp-policy/lattice-delegation-policy-correspondence-evidence.jsonl",
          "target/fcp-host/lattice-policy-dispatcher-evidence.jsonl"
        ] | sort)) and
        .details.trapdoor_payload == "absent" and
        .details.preimage_payload == "absent" and
        .details.rng_seed_payload == "absent" and
        .details.operation_plaintext == "absent" and
        .details.principal_plaintext == "absent" and
        .details.zone_label_plaintext == "absent" and
        .details.auth_header_values == "absent" and
        .details.credential_markers == "absent" and
        .details.local_private_paths == "absent" and
        .details.provider_payloads == "absent" and
        .details.reviewer_private_data == "absent" and
        (.details.cleanup_result | type == "string"));
    def top_level_provenance_consistent:
      ([.[] | .run_id] | unique | length == 1) and
      ([.[] | .git_revision] | unique | length == 1) and
      ([.[] | .cargo_target_dir_class] | unique | length == 1) and
      ([.[] | .cargo_target_dir_hash] | unique | length == 1) and
      ([.[] | .build_profile] | unique | length == 1) and
      ([.[] | .worker_host_class] | unique | length == 1);
    length > 0 and
    top_level_provenance_consistent and
    allowed_steps_only and
    critical_steps_singleton and
    all(.[]; type == "object" and
      .schema == "fcp.lattice_delegation.assurance_gauntlet.v1" and
      .script == "scripts/e2e/lattice_delegation_assurance_gauntlet.sh" and
      (.run_id | safe_label) and
      (.step | type == "string") and
      .result == "pass" and
      (.git_revision | git_revision_hash) and
      (.cargo_target_dir_class | gauntlet_target_dir_class) and
      (.cargo_target_dir_hash | sha256_hash) and
      (.build_profile | gauntlet_build_profile) and
      (.worker_host_class | safe_label) and
      (.details | type == "object") and
      command_record_contract) and
    required_tool_versions and
    required_command_steps_present and
    required_test_counts_present and
    benchmark_group_coverage_present and
    any(.[]; .step == "validate_lean_ids" and .result == "pass") and
    any(.[]; .step == "jsonl_contract_validation" and .result == "pass") and
    required_artifact_hash("crypto_representation_artifact"; "target/fcp-crypto-pq/representation-profile-evidence.jsonl") and
    required_artifact_hash("crypto_route_artifact"; "target/fcp-crypto-pq/trapgen-delegate-route-evidence.jsonl") and
    required_artifact_hash("crypto_public_matrix_artifact"; "target/fcp-crypto-pq/public-matrix-reconstruction-evidence.jsonl") and
    required_artifact_hash("crypto_sample_pre_artifact"; "target/fcp-crypto-pq/sample-pre-verify-evidence.jsonl") and
    required_artifact_hash("crypto_formal_artifact"; "target/fcp-crypto-pq/lattice-delegation-formal-correspondence-evidence.jsonl") and
    required_artifact_hash("policy_formal_artifact"; "target/fcp-policy/lattice-delegation-policy-correspondence-evidence.jsonl") and
    required_artifact_hash("host_dispatcher_artifact"; "target/fcp-host/lattice-policy-dispatcher-evidence.jsonl") and
    redaction_scan_covers_expected_artifacts and
    final_redaction_scan_covers_summary_artifact and
    any(.[]; .step == "summary" and .result == "pass" and
      (.details.artifact_path | safe_relative_jsonl_artifact_path) and
      (.details.pre_summary_artifact_hash | sha256_hash) and
      .details.final_artifact_hash_output == "stdout:LATTICE_ASSURANCE_GAUNTLET_SHA256" and
      (.details.profile_ids | type == "array" and
        ((. | sort) == (required_profile_ids | sort))) and
      (.details.scenario_ids | type == "array" and
        ((. | sort) == (required_host_scenarios | sort))) and
      (.details.theorem_names | type == "array" and
        ((. | sort) == (required_theorem_names | sort))) and
      (.details.assumption_ids | type == "array" and
        ((. | sort) == (required_assumption_ids | sort))) and
      (.details.benchmark_groups | type == "array" and
        ((. | sort) == (required_benchmark_groups | sort))) and
      .details.stable_lattice_error_mapping == "covered_by_host_dispatcher_e2e" and
      (.details.cleanup_result | type == "string"))
  '
}

require_command jq
require_command git
require_command "${RCH_BIN}"
require_command ubs
require_command shasum
require_command cargo
require_command rustc
require_command rustfmt
require_command clippy-driver
require_command lake

append_tool_versions
require_known_git_revision
assert_stable_revision "preflight_stable_revision"
assert_clean_tree "preflight_clean_tree"

LEAN_FILE="lean/Fcp/Invariants/LatticeDelegation.lean"
for theorem in \
  "lattice_delegation_chain_corruption_rejected" \
  "lattice_delegation_sis_assumption_boundary_complete" \
  "lattice_trapdoor_capability_unforgeability_reduces_to_sis_assumptions"; do
  require_text "${theorem}" "${LEAN_FILE}" "validate_lean_theorem_ids"
done

for assumption_id in \
  "FCP-PQ-SIS-HARDNESS-V1" \
  "FCP-PQ-RANDOM-ORACLE-DOMAIN-SEPARATION-V1" \
  "FCP-PQ-MP12-CHKP-GPV-ROUTE-CORRESPONDENCE-V1" \
  "FCP-PQ-IMPLEMENTATION-ENCODING-CORRESPONDENCE-V1" \
  "FCP-POLICY-DISPATCHER-BINDING-CORRESPONDENCE-V1" \
  "FCP-POLICY-REPLAY-DENIAL-CORRESPONDENCE-V1"; do
  require_text "${assumption_id}" "${LEAN_FILE}" "validate_lean_assumption_ids"
done

append_json "validate_lean_ids" "pass" "$(jq -cn \
  '{theorem_names:["lattice_delegation_chain_corruption_rejected","lattice_delegation_sis_assumption_boundary_complete","lattice_trapdoor_capability_unforgeability_reduces_to_sis_assumptions"],assumption_ids:["FCP-PQ-SIS-HARDNESS-V1","FCP-PQ-RANDOM-ORACLE-DOMAIN-SEPARATION-V1","FCP-PQ-MP12-CHKP-GPV-ROUTE-CORRESPONDENCE-V1","FCP-PQ-IMPLEMENTATION-ENCODING-CORRESPONDENCE-V1","FCP-POLICY-DISPATCHER-BINDING-CORRESPONDENCE-V1","FCP-POLICY-REPLAY-DENIAL-CORRESPONDENCE-V1"],cleanup_result:"not_applicable"}')"

run_and_capture "lean_lake_workspace_probe" "lake env lean --version" lake env lean --version
run_and_capture "lean_lake_build" "lake build" lake build

run_rch_cargo "crypto_representation_profile_tests" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo test --locked -p fcp-crypto-pq --test representation_profile -- --nocapture" \
  cargo test --locked -p fcp-crypto-pq --test representation_profile -- --nocapture

run_rch_cargo "crypto_v4_unit_tests" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo test --locked -p fcp-crypto-pq --lib v4_ -- --nocapture" \
  cargo test --locked -p fcp-crypto-pq --lib v4_ -- --nocapture

run_rch_cargo "policy_lattice_delegation_tests" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo test --locked -p fcp-policy --test lattice_delegation_proptest -- --nocapture" \
  cargo test --locked -p fcp-policy --test lattice_delegation_proptest -- --nocapture

run_rch_cargo "host_lattice_dispatcher_e2e" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo test --locked -p fcp-host --test lattice_policy_dispatcher_e2e -- --nocapture" \
  cargo test --locked -p fcp-host --test lattice_policy_dispatcher_e2e -- --nocapture

run_rch_cargo "criterion_lattice_crypto_bench" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo bench --locked -p fcp-crypto-pq --bench lattice_vs_ed25519_vs_mldsa -- --sample-size 10 --measurement-time 1 --warm-up-time 1" \
  cargo bench --locked -p fcp-crypto-pq --bench lattice_vs_ed25519_vs_mldsa -- --sample-size 10 --measurement-time 1 --warm-up-time 1

run_rch_cargo "rustfmt_lattice_surfaces" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> rustfmt --edition 2024 --check lattice proof Rust surfaces" \
  rustfmt --edition 2024 --check \
    crates/fcp-crypto-pq/tests/representation_profile.rs \
    crates/fcp-policy/tests/lattice_delegation_proptest.rs \
    crates/fcp-host/tests/lattice_policy_dispatcher_e2e.rs \
    crates/fcp-crypto-pq/benches/lattice_vs_ed25519_vs_mldsa.rs

run_rch_cargo "cargo_check_lattice_surfaces" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo check --locked -p fcp-crypto-pq -p fcp-policy -p fcp-host --all-targets" \
  cargo check --locked -p fcp-crypto-pq -p fcp-policy -p fcp-host --all-targets

run_rch_cargo "cargo_clippy_crypto_representation" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo clippy --locked -p fcp-crypto-pq --test representation_profile --no-deps -- -D warnings" \
  cargo clippy --locked -p fcp-crypto-pq --test representation_profile --no-deps -- -D warnings

run_rch_cargo "cargo_clippy_policy_lattice" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo clippy --locked -p fcp-policy --test lattice_delegation_proptest --no-deps -- -D warnings" \
  cargo clippy --locked -p fcp-policy --test lattice_delegation_proptest --no-deps -- -D warnings

run_rch_cargo "cargo_clippy_host_dispatcher" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo clippy --locked -p fcp-host --test lattice_policy_dispatcher_e2e --no-deps -- -D warnings" \
  cargo clippy --locked -p fcp-host --test lattice_policy_dispatcher_e2e --no-deps -- -D warnings

run_and_capture "bash_syntax" \
  "bash -n scripts/e2e/lattice_delegation_formal_correspondence.sh scripts/e2e/lattice_delegation_assurance_gauntlet.sh" \
  bash -n scripts/e2e/lattice_delegation_formal_correspondence.sh scripts/e2e/lattice_delegation_assurance_gauntlet.sh

run_and_capture "git_diff_check" \
  "git diff --check -- lattice proof surfaces" \
  git_safe diff --check -- \
    scripts/e2e/lattice_delegation_formal_correspondence.sh \
    scripts/e2e/lattice_delegation_assurance_gauntlet.sh \
    crates/fcp-crypto-pq/tests/representation_profile.rs \
    crates/fcp-policy/tests/lattice_delegation_proptest.rs \
    crates/fcp-host/tests/lattice_policy_dispatcher_e2e.rs \
    crates/fcp-crypto-pq/benches/lattice_vs_ed25519_vs_mldsa.rs

run_and_capture "ubs_lattice_surfaces" \
  "ubs lattice proof surfaces" \
  ubs \
    scripts/e2e/lattice_delegation_formal_correspondence.sh \
    scripts/e2e/lattice_delegation_assurance_gauntlet.sh \
    crates/fcp-crypto-pq/tests/representation_profile.rs \
    crates/fcp-policy/tests/lattice_delegation_proptest.rs \
    crates/fcp-host/tests/lattice_policy_dispatcher_e2e.rs \
    crates/fcp-crypto-pq/benches/lattice_vs_ed25519_vs_mldsa.rs

append_materialized_artifact_hash "crypto_representation_artifact" "target/fcp-crypto-pq/representation-profile-evidence.jsonl"
append_materialized_artifact_hash "crypto_route_artifact" "target/fcp-crypto-pq/trapgen-delegate-route-evidence.jsonl"
append_materialized_artifact_hash "crypto_public_matrix_artifact" "target/fcp-crypto-pq/public-matrix-reconstruction-evidence.jsonl"
append_materialized_artifact_hash "crypto_sample_pre_artifact" "target/fcp-crypto-pq/sample-pre-verify-evidence.jsonl"
append_materialized_artifact_hash "crypto_formal_artifact" "target/fcp-crypto-pq/lattice-delegation-formal-correspondence-evidence.jsonl"
append_materialized_artifact_hash "policy_formal_artifact" "target/fcp-policy/lattice-delegation-policy-correspondence-evidence.jsonl"
append_materialized_artifact_hash "host_dispatcher_artifact" "target/fcp-host/lattice-policy-dispatcher-evidence.jsonl"

validate_artifact_contracts

append_redaction_scan \
  "${ARTIFACT}" \
  "target/fcp-crypto-pq/representation-profile-evidence.jsonl" \
  "target/fcp-crypto-pq/trapgen-delegate-route-evidence.jsonl" \
  "target/fcp-crypto-pq/public-matrix-reconstruction-evidence.jsonl" \
  "target/fcp-crypto-pq/sample-pre-verify-evidence.jsonl" \
  "target/fcp-crypto-pq/lattice-delegation-formal-correspondence-evidence.jsonl" \
  "target/fcp-policy/lattice-delegation-policy-correspondence-evidence.jsonl" \
  "target/fcp-host/lattice-policy-dispatcher-evidence.jsonl"

pre_summary_artifact_hash="$(sha256_file "${ARTIFACT}")"
append_json "summary" "pass" "$(jq -cn \
  --arg artifact "${ARTIFACT}" \
  --arg pre_summary_artifact_hash "sha256:${pre_summary_artifact_hash}" \
  '{artifact_path:$artifact,pre_summary_artifact_hash:$pre_summary_artifact_hash,final_artifact_hash_output:"stdout:LATTICE_ASSURANCE_GAUNTLET_SHA256",profile_ids:["SMALL_TEST","V4_REFERENCE"],scenario_ids:["allow_small_test","allow_v4_reference","deny_forged_preimage","deny_forged_v4_reference","deny_mismatched_zone","deny_mismatched_period","deny_mismatched_operation","deny_mismatched_principal","deny_malformed_preimage","deny_missing_certificate","deny_incomplete_delegation_chain","deny_chain_too_deep","deny_trust_set_replay","deny_trust_set_replay_v4_reference"],theorem_names:["lattice_delegation_chain_corruption_rejected","lattice_delegation_sis_assumption_boundary_complete","lattice_trapdoor_capability_unforgeability_reduces_to_sis_assumptions"],assumption_ids:["FCP-PQ-SIS-HARDNESS-V1","FCP-PQ-RANDOM-ORACLE-DOMAIN-SEPARATION-V1","FCP-PQ-MP12-CHKP-GPV-ROUTE-CORRESPONDENCE-V1","FCP-PQ-IMPLEMENTATION-ENCODING-CORRESPONDENCE-V1","FCP-POLICY-DISPATCHER-BINDING-CORRESPONDENCE-V1","FCP-POLICY-REPLAY-DENIAL-CORRESPONDENCE-V1"],benchmark_groups:["trap_gen","delegate","sample_pre","verify","full_crypto_route","host_dispatcher_pipeline"],stable_lattice_error_mapping:"covered_by_host_dispatcher_e2e",cleanup_result:"not_applicable_generated_artifact"}')"

# The summary is appended after the normal redaction_scan record, so scan the
# finished artifact before success output can name it as reusable evidence.
scan_jsonl_artifact "${ARTIFACT}"
post_summary_artifact_hash="$(sha256_file "${ARTIFACT}")"
append_json "final_redaction_scan" "pass" "$(jq -cn \
  --arg artifact "${ARTIFACT}" \
  --arg post_summary_artifact_hash "sha256:${post_summary_artifact_hash}" \
  '{scanned_jsonl_artifacts:1,summary_record:"covered",scanned_artifact_path:$artifact,post_summary_artifact_hash:$post_summary_artifact_hash,cleanup_result:"not_applicable"}')"
scan_jsonl_artifact "${ARTIFACT}"

validate_gauntlet_contract

final_artifact_hash="$(sha256_file "${ARTIFACT}")"
printf 'LATTICE_ASSURANCE_GAUNTLET_JSONL %s\n' "${ARTIFACT}"
printf 'LATTICE_ASSURANCE_GAUNTLET_SHA256 sha256:%s\n' "${final_artifact_hash}"
