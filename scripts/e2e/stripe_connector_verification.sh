#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-/tmp/fcp-stripe-e2e/${RUN_ID}}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-stripe-e2e-target}"
STATUS_JSONL="${OUT_ROOT}/evidence/verification_steps.jsonl"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
STRIPE_RUN_LIVE_TESTS="${STRIPE_RUN_LIVE_TESTS:-0}"

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

  if grep -Eqi 'RCH-E|remote required; refusing local fallback|No space left on device|connection reset by peer|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response|missing worker system package|timeout: failed to execute process' "${log_path}"; then
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
    --arg schema_version "fcp-stripe-verification/v1" \
    --arg run_id "${RUN_ID}" \
    --arg connector "fcp-stripe" \
    --arg fixture_id "stripe-deterministic-fixture-suite" \
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

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local start_seconds end_seconds duration_ms rc status

  echo "[stripe-verification] ${name}: $*" >&2
  start_seconds="$(date -u +%s)"
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
  rc="$?"
  status="passed"
  if [[ "${rc}" -ne 0 ]]; then
    status="$(classify_failure "${log_path}")"
    promote_status "${status}"
  fi
  end_seconds="$(date -u +%s)"
  duration_ms="$(((end_seconds - start_seconds) * 1000))"
  record_step "${name}" "${status}" "${duration_ms}" "${log_path}" "$@"
}

run_no_match() {
  local name="$1"
  local pattern="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local start_seconds end_seconds duration_ms rc status

  echo "[stripe-verification] ${name}: rg ${pattern} $*" >&2
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

  run_logged "${name}" env RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE}" rch exec -- env \
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

run_logged \
  graduation_gauntlet \
  scripts/graduation/run_gauntlet.sh \
    --jsonl "${OUT_ROOT}/evidence/graduation_gauntlet.jsonl" \
    connectors/stripe

run_logged \
  diff_check \
  git diff --check -- \
    connectors/stripe/README.md \
    connectors/stripe/manifest.toml \
    connectors/stripe/src/client.rs \
    connectors/stripe/src/connector.rs \
    connectors/stripe/src/error.rs \
    connectors/stripe/src/limits.rs \
    connectors/stripe/src/main.rs \
    connectors/stripe/src/types.rs \
    connectors/stripe/tests/conformance_contract.rs \
    connectors/stripe/tests/integration.rs \
    connectors/stripe/tests/live_verification.rs \
    connectors/stripe/tests/mutation.rs \
    scripts/e2e/stripe_connector_verification.sh

run_no_match \
  readme_master_word_scan \
  '\bmaster\b' \
  connectors/stripe/README.md \
  scripts/e2e/stripe_connector_verification.sh

run_rch_cargo_step \
  cargo_check \
  cargo check -p fcp-stripe --all-targets

run_rch_cargo_step \
  unit_suite \
  cargo test -p fcp-stripe -- --nocapture

run_rch_cargo_step \
  integration_suite \
  cargo test -p fcp-stripe --test integration -- --nocapture

run_rch_cargo_step \
  conformance_contract \
  cargo test -p fcp-stripe --test conformance_contract -- --nocapture

run_rch_cargo_step \
  mutation_suite \
  cargo test -p fcp-stripe --test mutation -- --nocapture

if [[ "${STRIPE_RUN_LIVE_TESTS}" == "1" ]]; then
  run_rch_cargo_step \
    live_verification \
    env FCP_LIVE_SANDBOX=1 cargo test -p fcp-stripe --test live_verification -- --nocapture
else
  record_skipped \
    live_verification \
    "Set STRIPE_RUN_LIVE_TESTS=1 and provision STRIPE_SECRET_KEY in the worker environment to run opt-in live Stripe sandbox tests." \
    cargo test -p fcp-stripe --test live_verification -- --nocapture
fi

run_rch_cargo_step \
  format_check \
  cargo fmt -p fcp-stripe -- --check

run_rch_cargo_step \
  clippy \
  cargo clippy -p fcp-stripe --all-targets -- -D warnings

if grep -R -E 'sk_(live|test)_[[:alnum:]_]+|rk_(live|test)_[[:alnum:]_]+|whsec_[[:alnum:]_]+|Authorization: Bearer|Stripe-Signature|X-FCP-Credential-Id|"client_secret"|card\[number\]|card_number' "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence" >/dev/null 2>&1; then
  echo "[stripe-verification] redaction scan failed" >&2
  promote_status failed
  record_step redaction_scan failed 0 "${OUT_ROOT}/logs/redaction_scan.log" grep -R -E redaction-patterns "${OUT_ROOT}"
else
  record_step redaction_scan passed 0 "${OUT_ROOT}/logs/redaction_scan.log" grep -R -E redaction-patterns "${OUT_ROOT}"
fi

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-stripe",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/stripe_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_dir": "${TARGET_DIR}",
  "rch_require_remote": "${RCH_REQUIRE_REMOTE}",
  "stripe_run_live_tests": "${STRIPE_RUN_LIVE_TESTS}",
  "fixture_mode": "deterministic connector fixtures by default; live Stripe sandbox tests are opt-in",
  "redaction": "logs and JSONL must not contain Stripe secret keys, restricted keys, webhook secrets, bearer authorization headers, signature headers, credential IDs, client secrets, or raw card numbers"
}
EOF

cat >"${OUT_ROOT}/replay.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

RUN_ID="${RUN_ID}" \\
OUT_ROOT="${OUT_ROOT}" \\
CARGO_TARGET_DIR="${TARGET_DIR}" \\
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE}" \\
STRIPE_RUN_LIVE_TESTS="${STRIPE_RUN_LIVE_TESTS}" \\
scripts/e2e/stripe_connector_verification.sh
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-stripe",
  "status": "${OVERALL_STATUS}",
  "exit_code": ${EXIT_CODE},
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

echo "Stripe verification artifacts written to ${OUT_ROOT} (status=${OVERALL_STATUS})" >&2
exit "${EXIT_CODE}"
