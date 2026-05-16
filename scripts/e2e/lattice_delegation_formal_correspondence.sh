#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="scripts/e2e/lattice_delegation_formal_correspondence.sh"
RUN_ID="${RUN_ID:-lattice-delegation-formal-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="${OUT_DIR:-target/fcp-crypto-pq}"
ARTIFACT="${ARTIFACT:-${OUT_DIR}/lattice-delegation-formal-correspondence-proof.${RUN_ID}.jsonl}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-lattice-formal-${RUN_ID}}"

mkdir -p "${OUT_DIR}"
: > "${ARTIFACT}"

raw_git_revision() {
  git rev-parse HEAD 2>/dev/null || printf 'unknown'
}

FORMAL_GIT_REVISION="${FCP_LATTICE_GIT_REVISION:-$(raw_git_revision)}"

git_revision() {
  printf '%s' "${FORMAL_GIT_REVISION}"
}

append_json() {
  local step="$1"
  local result="$2"
  local details="$3"
  jq -cn \
    --arg schema "fcp.lattice_delegation.formal_correspondence.v1" \
    --arg script "${SCRIPT_NAME}" \
    --arg run_id "${RUN_ID}" \
    --arg step "${step}" \
    --arg result "${result}" \
    --arg git_revision "$(git_revision)" \
    --argjson details "${details}" \
    '{schema:$schema,script:$script,run_id:$run_id,step:$step,result:$result,git_revision:$git_revision,details:$details}' \
    >> "${ARTIFACT}"
}

fail_step() {
  append_json "$1" "fail" "$2"
  printf 'lattice formal correspondence step failed: %s\n' "$1" >&2
  exit 1
}

assert_stable_revision() {
  local step="$1"
  local current_revision
  current_revision="$(raw_git_revision)"
  if [ "${FORMAL_GIT_REVISION}" != "unknown" ] &&
    [ "${current_revision}" != "unknown" ] &&
    [ "${current_revision}" != "${FORMAL_GIT_REVISION}" ]; then
    case "${current_revision}" in
      "${FORMAL_GIT_REVISION}"*) return 0 ;;
    esac
    case "${FORMAL_GIT_REVISION}" in
      "${current_revision}"*) return 0 ;;
    esac
    fail_step "${step}" "$(jq -cn \
      --arg expected "${FORMAL_GIT_REVISION}" \
      --arg actual "${current_revision}" \
      '{expected_git_revision:$expected,actual_git_revision:$actual,cleanup_result:"not_applicable"}')"
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

run_and_capture() {
  local step="$1"
  shift
  local log="${OUT_DIR}/${RUN_ID}.${step}.log"
  assert_stable_revision "stable_revision_before_${step}"
  if "$@" >"${log}" 2>&1; then
    local hash
    hash="$(shasum -a 256 "${log}" | awk '{print $1}')"
    assert_stable_revision "stable_revision_after_${step}"
    append_json "${step}" "pass" "$(jq -cn \
      --arg log_hash "sha256:${hash}" \
      --arg log_artifact_class "relative-target-log" \
      --arg cleanup_result "not_applicable" \
      '{log_hash:$log_hash,log_artifact_class:$log_artifact_class,cleanup_result:$cleanup_result}')"
  else
    local hash
    hash="$(shasum -a 256 "${log}" | awk '{print $1}')"
    fail_step "${step}" "$(jq -cn \
      --arg log_hash "sha256:${hash}" \
      --arg log_artifact_class "relative-target-log" \
      --arg cleanup_result "not_applicable" \
      '{log_hash:$log_hash,log_artifact_class:$log_artifact_class,cleanup_result:$cleanup_result}')"
  fi
}

assert_stable_revision "preflight_stable_revision"

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
  run_and_capture "lean_lake_build" lake build
else
  append_json "lean_lake_build" "skip" "$(jq -cn \
    '{skip_reason:"lake_not_available",cleanup_result:"not_applicable"}')"
fi

if ! command -v rch >/dev/null 2>&1; then
  fail_step "prerequisite_rch" "$(jq -cn '{missing:"rch",cleanup_result:"not_applicable"}')"
fi

run_and_capture "rust_crypto_correspondence" \
  rch exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_PROFILE_DEV_DEBUG=0 \
    CARGO_PROFILE_TEST_DEBUG=0 \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS=-Cdebuginfo=0 \
    FCP_LATTICE_GIT_REVISION="$(git_revision)" \
    FCP_CRYPTO_PQ_FORMAL_CORRESPONDENCE_COMMAND_LINE="cargo test -p fcp-crypto-pq --test representation_profile lean_sis_assumption_boundary_correspondence_fixture_jsonl_is_secret_free -- --nocapture" \
    cargo test -p fcp-crypto-pq --test representation_profile \
      lean_sis_assumption_boundary_correspondence_fixture_jsonl_is_secret_free -- --nocapture

run_and_capture "rust_policy_correspondence" \
  rch exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_PROFILE_DEV_DEBUG=0 \
    CARGO_PROFILE_TEST_DEBUG=0 \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS=-Cdebuginfo=0 \
    FCP_LATTICE_GIT_REVISION="$(git_revision)" \
    FCP_POLICY_LATTICE_FORMAL_CORRESPONDENCE_COMMAND_LINE="cargo test -p fcp-policy --test lattice_delegation_proptest lattice_delegation_formal_correspondence_fixture_jsonl_is_secret_free -- --nocapture" \
    cargo test -p fcp-policy --test lattice_delegation_proptest \
      lattice_delegation_formal_correspondence_fixture_jsonl_is_secret_free -- --nocapture

run_and_capture "rust_crypto_existing_v4" \
  rch exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_PROFILE_DEV_DEBUG=0 \
    CARGO_PROFILE_TEST_DEBUG=0 \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS=-Cdebuginfo=0 \
    FCP_LATTICE_GIT_REVISION="$(git_revision)" \
    cargo test -p fcp-crypto-pq --lib v4_ -- --nocapture

run_and_capture "ubs_touched_files" \
  ubs \
    lean/Fcp/Invariants/LatticeDelegation.lean \
    lean/witnesses/formal_invariants.v1.json \
    crates/fcp-crypto-pq/tests/representation_profile.rs \
    crates/fcp-policy/tests/lattice_delegation_proptest.rs \
    scripts/e2e/lattice_delegation_formal_correspondence.sh

for forbidden in "/Users/" "/tmp/" "trapdoor_coefficients" "secret_seed" "expanded_secret_matrix" \
  "preimage_coefficients" "preimage_bytes" "bearer" "token=" "op:" "principal:" "z:"; do
  if grep -Fq "${forbidden}" "${ARTIFACT}"; then
    fail_step "redaction_scan" "$(jq -cn --arg forbidden "${forbidden}" \
      '{forbidden:$forbidden,cleanup_result:"not_applicable"}')"
  fi
done

artifact_hash="$(shasum -a 256 "${ARTIFACT}" | awk '{print $1}')"
append_json "summary" "pass" "$(jq -cn \
  --arg artifact "target/fcp-crypto-pq/lattice-delegation-formal-correspondence-proof.jsonl" \
  --arg artifact_hash "sha256:${artifact_hash}" \
  '{artifact_path:$artifact,artifact_hash:$artifact_hash,profile_ids:["SMALL_TEST","V4_REFERENCE"],route_revision:1,cleanup_result:"not_applicable_generated_artifact"}')"

printf 'LATTICE_FORMAL_CORRESPONDENCE_JSONL %s\n' "${ARTIFACT}"
