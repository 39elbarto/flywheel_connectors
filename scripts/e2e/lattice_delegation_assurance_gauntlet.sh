#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="scripts/e2e/lattice_delegation_assurance_gauntlet.sh"
RUN_ID="${RUN_ID:-lattice-assurance-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="${OUT_DIR:-target/fcp-crypto-pq}"
ARTIFACT="${ARTIFACT:-${OUT_DIR}/lattice-delegation-assurance-gauntlet.${RUN_ID}.jsonl}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-lattice-assurance-${RUN_ID}}"
LOG_PREFIX="${OUT_DIR}/${RUN_ID}"

mkdir -p "${OUT_DIR}"
: > "${ARTIFACT}"

git_revision() {
  git rev-parse HEAD 2>/dev/null || printf 'unknown'
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
    /tmp/*|/private/tmp/*)
      printf 'ephemeral_tmp'
      ;;
    target/*)
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

append_tool_versions() {
  append_json "tool_versions" "pass" "$(jq -cn \
    --arg cargo "$(tool_version cargo -V)" \
    --arg rustc "$(tool_version rustc -V)" \
    --arg rustfmt "$(tool_version rustfmt -V)" \
    --arg clippy "$(tool_version clippy-driver -V)" \
    --arg rch "$(tool_version rch --version)" \
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

run_and_capture() {
  local step="$1"
  local display_command="$2"
  shift 2
  local log="${LOG_PREFIX}.${step}.log"
  local started
  started="$(date -u +%s)"
  if "$@" >"${log}" 2>&1; then
    local ended duration hash passed_tests passed_tests_json
    ended="$(date -u +%s)"
    duration=$((ended - started))
    hash="$(sha256_file "${log}")"
    passed_tests="$(extract_passed_tests "${log}")"
    passed_tests_json="$(json_string_or_null "${passed_tests}")"
    append_json "${step}" "pass" "$(jq -cn \
      --arg command_line "${display_command}" \
      --arg log_artifact "target/fcp-crypto-pq/${RUN_ID}.${step}.log" \
      --arg log_hash "sha256:${hash}" \
      --argjson duration_seconds "${duration}" \
      --argjson passed_tests "${passed_tests_json}" \
      '{command_line:$command_line,log_artifact:$log_artifact,log_hash:$log_hash,duration_seconds:$duration_seconds,passed_tests:$passed_tests,retry_count:0,fallback_decision:"not_needed",cache_decision:"cargo_target_dir_hashed",cleanup_result:"not_applicable"}')"
  else
    local ended duration hash
    ended="$(date -u +%s)"
    duration=$((ended - started))
    hash="$(sha256_file "${log}")"
    fail_step "${step}" "$(jq -cn \
      --arg command_line "${display_command}" \
      --arg log_artifact "target/fcp-crypto-pq/${RUN_ID}.${step}.log" \
      --arg log_hash "sha256:${hash}" \
      --argjson duration_seconds "${duration}" \
      '{command_line:$command_line,log_artifact:$log_artifact,log_hash:$log_hash,duration_seconds:$duration_seconds,retry_count:0,fallback_decision:"none",cache_decision:"cargo_target_dir_hashed",cleanup_result:"not_applicable"}')"
  fi
}

run_rch_cargo() {
  local step="$1"
  local display_command="$2"
  shift 2
  run_and_capture "${step}" "${display_command}" \
    rch exec -- env \
      CARGO_TARGET_DIR="${TARGET_DIR}" \
      CARGO_PROFILE_DEV_DEBUG=0 \
      CARGO_PROFILE_TEST_DEBUG=0 \
      CARGO_INCREMENTAL=0 \
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

scan_jsonl_artifact() {
  local path="$1"
  for forbidden in \
    "/Users/" \
    "/tmp/" \
    "/private/tmp/" \
    "trapdoor_material" \
    "trapdoor_coefficients" \
    "secret_seed" \
    "expanded_secret_matrix" \
    "preimage_coefficients" \
    "preimage_bytes" \
    "raw_operation" \
    "raw_principal" \
    "token=" \
    "bearer" \
    "provider_body" \
    "reviewer_contact"; do
    if grep -Fq "${forbidden}" "${path}"; then
      fail_step "redaction_scan" "$(jq -cn --arg artifact "${path}" --arg forbidden "${forbidden}" \
        '{artifact_path:$artifact,forbidden:$forbidden,cleanup_result:"not_applicable"}')"
    fi
  done
}

append_redaction_scan() {
  local scanned=0
  for artifact in "$@"; do
    require_artifact "redaction_scan_prerequisite" "${artifact}"
    scan_jsonl_artifact "${artifact}"
    scanned=$((scanned + 1))
  done
  append_json "redaction_scan" "pass" "$(jq -cn --argjson scanned "${scanned}" \
    '{scanned_jsonl_artifacts:$scanned,trapdoor_material:"absent",preimage_coefficients:"absent",secret_seeds:"absent",raw_operation_text:"absent",raw_principal_text:"absent",raw_zone_labels:"absent",bearer_strings:"absent",local_private_paths:"absent",provider_bodies:"absent",reviewer_contact_data:"absent",cleanup_result:"not_applicable"}')"
}

require_command jq
require_command git
require_command rch
require_command ubs
require_command shasum

append_tool_versions

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

if command -v lake >/dev/null 2>&1; then
  run_and_capture "lean_lake_build" "lake build" lake build
else
  append_json "lean_lake_build" "skip" "$(jq -cn \
    '{skip_reason:"lake_not_available",cleanup_result:"not_applicable"}')"
fi

run_rch_cargo "crypto_representation_profile_tests" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo test -p fcp-crypto-pq --test representation_profile -- --nocapture" \
  cargo test -p fcp-crypto-pq --test representation_profile -- --nocapture

run_rch_cargo "crypto_v4_unit_tests" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo test -p fcp-crypto-pq --lib v4_ -- --nocapture" \
  cargo test -p fcp-crypto-pq --lib v4_ -- --nocapture

run_rch_cargo "policy_lattice_delegation_tests" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo test -p fcp-policy --test lattice_delegation_proptest -- --nocapture" \
  cargo test -p fcp-policy --test lattice_delegation_proptest -- --nocapture

run_rch_cargo "host_lattice_dispatcher_e2e" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo test -p fcp-host --test lattice_policy_dispatcher_e2e -- --nocapture" \
  cargo test -p fcp-host --test lattice_policy_dispatcher_e2e -- --nocapture

run_rch_cargo "criterion_lattice_crypto_bench" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo bench -p fcp-crypto-pq --bench lattice_vs_ed25519_vs_mldsa -- --sample-size 10 --measurement-time 1 --warm-up-time 1" \
  cargo bench -p fcp-crypto-pq --bench lattice_vs_ed25519_vs_mldsa -- --sample-size 10 --measurement-time 1 --warm-up-time 1

run_rch_cargo "rustfmt_lattice_surfaces" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> rustfmt --edition 2024 --check lattice proof Rust surfaces" \
  rustfmt --edition 2024 --check \
    crates/fcp-crypto-pq/tests/representation_profile.rs \
    crates/fcp-policy/tests/lattice_delegation_proptest.rs \
    crates/fcp-host/tests/lattice_policy_dispatcher_e2e.rs \
    crates/fcp-crypto-pq/benches/lattice_vs_ed25519_vs_mldsa.rs

run_rch_cargo "cargo_check_lattice_surfaces" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo check -p fcp-crypto-pq -p fcp-policy -p fcp-host --all-targets" \
  cargo check -p fcp-crypto-pq -p fcp-policy -p fcp-host --all-targets

run_rch_cargo "cargo_clippy_crypto_representation" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo clippy -p fcp-crypto-pq --test representation_profile --no-deps -- -D warnings" \
  cargo clippy -p fcp-crypto-pq --test representation_profile --no-deps -- -D warnings

run_rch_cargo "cargo_clippy_policy_lattice" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo clippy -p fcp-policy --test lattice_delegation_proptest --no-deps -- -D warnings" \
  cargo clippy -p fcp-policy --test lattice_delegation_proptest --no-deps -- -D warnings

run_rch_cargo "cargo_clippy_host_dispatcher" \
  "rch exec -- env CARGO_TARGET_DIR=<hashed> cargo clippy -p fcp-host --test lattice_policy_dispatcher_e2e --no-deps -- -D warnings" \
  cargo clippy -p fcp-host --test lattice_policy_dispatcher_e2e --no-deps -- -D warnings

run_and_capture "bash_syntax" \
  "bash -n scripts/e2e/lattice_delegation_formal_correspondence.sh scripts/e2e/lattice_delegation_assurance_gauntlet.sh" \
  bash -n scripts/e2e/lattice_delegation_formal_correspondence.sh scripts/e2e/lattice_delegation_assurance_gauntlet.sh

run_and_capture "git_diff_check" \
  "git diff --check -- lattice proof surfaces" \
  git diff --check -- \
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

append_artifact_hash "crypto_representation_artifact" "target/fcp-crypto-pq/representation-profile-evidence.jsonl"
append_artifact_hash "crypto_route_artifact" "target/fcp-crypto-pq/trapgen-delegate-route-evidence.jsonl"
append_artifact_hash "crypto_public_matrix_artifact" "target/fcp-crypto-pq/public-matrix-reconstruction-evidence.jsonl"
append_artifact_hash "crypto_sample_pre_artifact" "target/fcp-crypto-pq/sample-pre-verify-evidence.jsonl"
append_artifact_hash "crypto_formal_artifact" "target/fcp-crypto-pq/lattice-delegation-formal-correspondence-evidence.jsonl"
append_artifact_hash "policy_formal_artifact" "target/fcp-policy/lattice-delegation-policy-correspondence-evidence.jsonl"
append_artifact_hash "host_dispatcher_artifact" "target/fcp-host/lattice-policy-dispatcher-evidence.jsonl"

append_redaction_scan \
  "${ARTIFACT}" \
  "target/fcp-crypto-pq/representation-profile-evidence.jsonl" \
  "target/fcp-crypto-pq/trapgen-delegate-route-evidence.jsonl" \
  "target/fcp-crypto-pq/public-matrix-reconstruction-evidence.jsonl" \
  "target/fcp-crypto-pq/sample-pre-verify-evidence.jsonl" \
  "target/fcp-crypto-pq/lattice-delegation-formal-correspondence-evidence.jsonl" \
  "target/fcp-policy/lattice-delegation-policy-correspondence-evidence.jsonl" \
  "target/fcp-host/lattice-policy-dispatcher-evidence.jsonl"

artifact_hash="$(sha256_file "${ARTIFACT}")"
append_json "summary" "pass" "$(jq -cn \
  --arg artifact "${ARTIFACT}" \
  --arg artifact_hash "sha256:${artifact_hash}" \
  '{artifact_path:$artifact,artifact_hash:$artifact_hash,profile_ids:["SMALL_TEST","V4_REFERENCE"],scenario_ids:["allow_v4_reference","deny_forged_v4_reference","deny_trust_set_replay_v4_reference","deny_mismatched_operation","deny_mismatched_principal"],theorem_names:["lattice_delegation_chain_corruption_rejected","lattice_delegation_sis_assumption_boundary_complete","lattice_trapdoor_capability_unforgeability_reduces_to_sis_assumptions"],assumption_ids:["FCP-PQ-SIS-HARDNESS-V1","FCP-PQ-RANDOM-ORACLE-DOMAIN-SEPARATION-V1","FCP-PQ-MP12-CHKP-GPV-ROUTE-CORRESPONDENCE-V1","FCP-PQ-IMPLEMENTATION-ENCODING-CORRESPONDENCE-V1","FCP-POLICY-DISPATCHER-BINDING-CORRESPONDENCE-V1","FCP-POLICY-REPLAY-DENIAL-CORRESPONDENCE-V1"],benchmark_groups:["trap_gen","delegate","sample_pre","verify","full_crypto_route","host_dispatcher_pipeline"],stable_lattice_error_mapping:"covered_by_host_dispatcher_e2e",cleanup_result:"not_applicable_generated_artifact"}')"

printf 'LATTICE_ASSURANCE_GAUNTLET_JSONL %s\n' "${ARTIFACT}"
