#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-/tmp/fcp-github-e2e/${RUN_ID}}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-github-e2e-target}"
STATUS_JSONL="${OUT_ROOT}/evidence/verification_steps.jsonl"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
GITHUB_RUN_LIVE_TESTS="${GITHUB_RUN_LIVE_TESTS:-0}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
REMOTE_RUNNER="rch:remote-required"
export RCH_FORCE_REMOTE=1

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="passed"
EXIT_CODE=0

promote_status() {
  local status="$1"
  case "${status}" in
    failed)
      OVERALL_STATUS="failed"
      EXIT_CODE=1
      ;;
    infra_blocked)
      if [[ "${OVERALL_STATUS}" == "passed" ]]; then
        OVERALL_STATUS="infra_blocked"
        EXIT_CODE=2
      fi
      ;;
  esac
}

classify_failure() {
  local log_path="$1"

  if [[ ! -f "${log_path}" ]]; then
    echo "infra_blocked"
    return
  fi

  if grep -Eqi 'RCH-E|remote required; refusing local fallback|rch command did not produce remote proof|\[RCH\] local|No space left on device|connection reset by peer|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response|missing worker system package|timeout: failed to execute process' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

json_array_from_args() {
  if [[ $# -eq 0 ]]; then
    printf '[]'
    return
  fi
  printf '%s\n' "$@" | jq -R . | jq -s .
}

record_step() {
  local name="$1"
  local status="$2"
  local duration_ms="$3"
  local log_path="$4"
  shift 4
  local argv_json
  argv_json="$(json_array_from_args "$@")"

  jq -cn \
    --arg schema_version "fcp-github-verification/v1" \
    --arg run_id "${RUN_ID}" \
    --arg connector "fcp-github" \
    --arg fixture_id "github-loopback-local-acceptance" \
    --arg step "${name}" \
    --arg status "${status}" \
    --arg git_revision "${git_revision}" \
    --arg target_dir "${TARGET_DIR}" \
    --arg log_path "${log_path}" \
    --argjson duration_ms "${duration_ms}" \
    --argjson argv "${argv_json}" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      connector: $connector,
      fixture_id: $fixture_id,
      step: $step,
      status: $status,
      duration_ms: $duration_ms,
      git_revision: $git_revision,
      target_dir: $target_dir,
      log_path: $log_path,
      argv: $argv
    }' >>"${STATUS_JSONL}"
}

command_uses_rch_exec() {
  local previous=""
  for arg in "$@"; do
    if [[ "${previous}" == "rch" && "${arg}" == "exec" ]]; then
      return 0
    fi
    previous="${arg}"
  done
  return 1
}

require_rch_remote_proof() {
  local name="$1"
  local log_path="$2"
  shift 2

  if ! command_uses_rch_exec "$@"; then
    return 0
  fi

  if grep -Fq "[RCH] remote" "${log_path}"; then
    return 0
  fi

  echo "[github-verification] ${name}: rch command did not produce remote proof" >&2
  echo "rch command did not produce remote proof" >>"${log_path}"
  return 1
}

run_logged_with_remote_policy() {
  local require_remote_proof="$1"
  shift
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local start_seconds end_seconds duration_ms rc status

  echo "[github-verification] ${name}: $*" >&2
  start_seconds="$(date -u +%s)"
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
  rc="$?"
  status="passed"
  if [[ "${rc}" -eq 0 && "${require_remote_proof}" == "1" ]] && ! require_rch_remote_proof "${name}" "${log_path}" "$@"; then
    rc=1
  fi
  if [[ "${rc}" -ne 0 ]]; then
    status="$(classify_failure "${log_path}")"
    promote_status "${status}"
  fi
  end_seconds="$(date -u +%s)"
  duration_ms="$(((end_seconds - start_seconds) * 1000))"
  record_step "${name}" "${status}" "${duration_ms}" "${log_path}" "$@"
}

run_logged() {
  run_logged_with_remote_policy 1 "$@"
}

graduation_gauntlet_pre_promotion_pending() {
  local jsonl_path="$1"

  if [[ ! -f "${jsonl_path}" ]]; then
    return 1
  fi

  jq -s -e '
    [.[] | select(.verdict == "fail")] as $failures
    | ($failures | length) == 1
      and $failures[0].check == "readme_status_match"
  ' "${jsonl_path}" >/dev/null
}

run_graduation_gauntlet_step() {
  local jsonl_path="${OUT_ROOT}/evidence/graduation_gauntlet.jsonl"
  local log_path="${OUT_ROOT}/logs/graduation_gauntlet.log"
  local start_seconds end_seconds duration_ms rc status

  echo "[github-verification] graduation_gauntlet: scripts/graduation/run_gauntlet.sh --jsonl ${jsonl_path} connectors/github" >&2
  start_seconds="$(date -u +%s)"
  (
    cd "${REPO_ROOT}" || exit
    scripts/graduation/run_gauntlet.sh --jsonl "${jsonl_path}" connectors/github
  ) >"${log_path}" 2>&1
  rc="$?"

  if [[ "${rc}" -eq 0 ]]; then
    status="passed"
  elif graduation_gauntlet_pre_promotion_pending "${jsonl_path}"; then
    status="pre_promotion_pending"
    echo "pre-promotion gauntlet reached only readme_status_match; PROVEN status has not been claimed yet" >>"${log_path}"
  else
    status="$(classify_failure "${log_path}")"
    promote_status "${status}"
  fi

  end_seconds="$(date -u +%s)"
  duration_ms="$(((end_seconds - start_seconds) * 1000))"
  record_step \
    graduation_gauntlet \
    "${status}" \
    "${duration_ms}" \
    "${log_path}" \
    scripts/graduation/run_gauntlet.sh --jsonl "${jsonl_path}" connectors/github
}

run_no_match() {
  local name="$1"
  local pattern="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local start_seconds end_seconds duration_ms rc status

  echo "[github-verification] ${name}: rg ${pattern} $*" >&2
  start_seconds="$(date -u +%s)"
  (
    cd "${REPO_ROOT}" || exit
    rg -n "${pattern}" "$@"
  ) >"${log_path}" 2>&1
  rc="$?"
  status="passed"
  case "${rc}" in
    0)
      status="failed"
      promote_status failed
      ;;
    1)
      status="passed"
      ;;
    *)
      status="$(classify_failure "${log_path}")"
      promote_status "${status}"
      ;;
  esac
  end_seconds="$(date -u +%s)"
  duration_ms="$(((end_seconds - start_seconds) * 1000))"
  record_step "${name}" "${status}" "${duration_ms}" "${log_path}" rg -n "${pattern}" "$@"
}

run_rch_cargo_step() {
  local name="$1"
  shift

  run_logged "${name}" env \
    RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE}" \
    RCH_FORCE_REMOTE=1 \
    RCH_VISIBILITY=verbose \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    "$@"
}

run_rch_format_step() {
  local name="$1"
  shift

  # `cargo fmt --check` validates source state; it is not accepted remote Cargo proof.
  run_logged_with_remote_policy 0 "${name}" env \
    RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE}" \
    RCH_FORCE_REMOTE=1 \
    RCH_VISIBILITY=verbose \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    "$@"
}

record_skipped() {
  local name="$1"
  local reason="$2"
  local log_path="${OUT_ROOT}/logs/${name}.log"
  shift 2

  printf '%s\n' "${reason}" >"${log_path}"
  record_step "${name}" skipped 0 "${log_path}" "$@"
}

for required in jq git rg rch; do
  if ! command -v "${required}" >/dev/null 2>&1; then
    echo "Missing required command: ${required}" >&2
    exit 2
  fi
done

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

run_graduation_gauntlet_step

run_logged \
  diff_check \
  git diff --check -- \
    connectors/github/README.md \
    connectors/github/manifest.toml \
    connectors/github/src/client.rs \
    connectors/github/src/connector.rs \
    connectors/github/src/error.rs \
    connectors/github/src/main.rs \
    connectors/github/src/types.rs \
    connectors/github/tests/conformance_contract.rs \
    connectors/github/tests/integration.rs \
    connectors/github/tests/local_non_mock.rs \
    scripts/e2e/github_connector_verification.sh

legacy_branch_word="$(printf 'mast%ser' '')"
run_no_match \
  readme_legacy_branch_word_scan \
  "\\b${legacy_branch_word}\\b" \
  connectors/github/README.md \
  scripts/e2e/github_connector_verification.sh

run_rch_cargo_step \
  cargo_check \
  cargo check -p fcp-github --all-targets

run_rch_cargo_step \
  unit_suite \
  cargo test -p fcp-github -- --nocapture

run_rch_cargo_step \
  integration_suite \
  cargo test -p fcp-github --test integration -- --nocapture

run_rch_cargo_step \
  local_non_mock_acceptance \
  cargo test -p fcp-github --test local_non_mock -- --nocapture

run_rch_cargo_step \
  conformance_contract \
  cargo test -p fcp-github --test conformance_contract -- --nocapture

if [[ "${GITHUB_RUN_LIVE_TESTS}" == "1" && -f "${REPO_ROOT}/connectors/github/tests/live_verification.rs" ]]; then
  run_rch_cargo_step \
    live_verification \
    env FCP_LIVE_SANDBOX=1 cargo test -p fcp-github --test live_verification -- --nocapture
elif [[ "${GITHUB_RUN_LIVE_TESTS}" == "1" ]]; then
  record_skipped \
    live_verification \
    "No tracked connectors/github/tests/live_verification.rs exists in this checkout; add it before enabling opt-in live GitHub sandbox tests." \
    cargo test -p fcp-github --test live_verification -- --nocapture
else
  record_skipped \
    live_verification \
    "No tracked GitHub live-verification test exists in this checkout; the default acceptance lane is the loopback local_non_mock suite." \
    cargo test -p fcp-github --test live_verification -- --nocapture
fi

run_rch_format_step \
  format_check \
  cargo fmt -p fcp-github -- --check

run_rch_cargo_step \
  clippy \
  cargo clippy -p fcp-github --all-targets -- -D warnings

if grep -R -E 'gh[pousr]_[[:alnum:]_]+|github_pat_[[:alnum:]_]+|Authorization: Bearer|X-FCP-Credential-ID|client_secret|webhook_secret|GITHUB_TOKEN' "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence" >/dev/null 2>&1; then
  echo "[github-verification] redaction scan failed" >&2
  promote_status failed
  record_step redaction_scan failed 0 "${OUT_ROOT}/logs/redaction_scan.log" grep -R -E redaction-patterns "${OUT_ROOT}"
else
  record_step redaction_scan passed 0 "${OUT_ROOT}/logs/redaction_scan.log" grep -R -E redaction-patterns "${OUT_ROOT}"
fi

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-github",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/github_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_dir": "${TARGET_DIR}",
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "rch_require_remote": "${RCH_REQUIRE_REMOTE}",
  "github_run_live_tests": "${GITHUB_RUN_LIVE_TESTS}",
  "fixture_mode": "deterministic connector fixtures by default; live GitHub sandbox tests are opt-in",
  "redaction": "logs and JSONL must not contain GitHub tokens, bearer authorization headers, credential IDs, OAuth client secrets, webhook secrets, or provider payload bodies"
}
EOF

cat >"${OUT_ROOT}/replay.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

RUN_ID="${RUN_ID}" \\
OUT_ROOT="${OUT_ROOT}" \\
CARGO_TARGET_DIR="${TARGET_DIR}" \\
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE}" \\
RCH_FORCE_REMOTE=1 \\
REPO_TOOLCHAIN="${REPO_TOOLCHAIN}" \\
GITHUB_RUN_LIVE_TESTS="${GITHUB_RUN_LIVE_TESTS}" \\
scripts/e2e/github_connector_verification.sh
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-github",
  "status": "${OVERALL_STATUS}",
  "exit_code": ${EXIT_CODE},
  "runner": "${REMOTE_RUNNER}",
  "artifacts_root": "${OUT_ROOT}",
  "artifacts": {
    "status_jsonl": "${STATUS_JSONL}",
    "graduation_gauntlet": "${OUT_ROOT}/evidence/graduation_gauntlet.jsonl",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh",
    "logs": "${OUT_ROOT}/logs"
  }
}
EOF

echo "GitHub verification artifacts written to ${OUT_ROOT} (status=${OVERALL_STATUS})" >&2
exit "${EXIT_CODE}"
