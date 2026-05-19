#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-/tmp/fcp-telegram-e2e/${RUN_ID}}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-telegram-e2e-target}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0
LAST_STEP_STATUS="not_run"

promote_status() {
  local status="$1"
  case "${status}" in
    failed)
      OVERALL_STATUS="failed"
      EXIT_CODE=1
      ;;
    infra_blocked)
      if [[ "${OVERALL_STATUS}" == "ok" ]]; then
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
  # shellcheck disable=SC2016
  if grep -Eq 'No space left on device|timeout: failed to execute process|RCH-E|remote required; refusing local fallback|no admissible workers|no worker assigned|connection reset by peer|missing worker system package|failed to execute process|failed to get successful HTTP response from `https://index\.crates\.io/|Backend unavailable|unable to update registry `crates-io`|spurious network error' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"

  echo "[telegram-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
}

run_step() {
  local name="$1"
  shift
  if run_logged "${name}" "$@"; then
    LAST_STEP_STATUS="passed"
  else
    local status
    status="$(classify_failure "${OUT_ROOT}/logs/${name}.log")"
    promote_status "${status}"
    LAST_STEP_STATUS="${status}"
  fi
}

rch_remote_summary_present() {
  local log_path="$1"
  grep -E '^\[RCH\][[:space:]]+remote[[:space:]]+' "${log_path}" \
    | grep -Ev '^\[RCH\][[:space:]]+remote[[:space:]]+required([;[:space:]]|$)' >/dev/null
}

run_rch_cargo_step_with_remote_policy() {
  local require_remote_proof="$1"
  shift
  local name="$1"
  shift
  run_step "${name}" env RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}" rch exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    "$@"
  if [[ "${LAST_STEP_STATUS}" == "passed" && "${require_remote_proof}" == "1" ]]; then
    if ! rch_remote_summary_present "${OUT_ROOT}/logs/${name}.log"; then
      echo "[telegram-verification] ${name}: rch command did not produce remote proof" >&2
      echo "rch command did not produce remote proof" >>"${OUT_ROOT}/logs/${name}.log"
      promote_status infra_blocked
      LAST_STEP_STATUS="infra_blocked"
    fi
  fi
}

run_rch_cargo_step() {
  run_rch_cargo_step_with_remote_policy 1 "$@"
}

run_rch_format_step() {
  # `cargo fmt --check` validates source state; it is not accepted remote Cargo proof.
  run_rch_cargo_step_with_remote_policy 0 "$@"
}

json_bool_for_env() {
  local name="$1"
  if [[ -n "${!name:-}" ]]; then
    echo "true"
  else
    echo "false"
  fi
}

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
token_present="$(json_bool_for_env TELEGRAM_BOT_TOKEN)"
secret_present="$(json_bool_for_env TELEGRAM_WEBHOOK_SECRET_TOKEN)"
approval_present="$(json_bool_for_env TELEGRAM_LIVE_WRITE_APPROVAL)"

run_rch_format_step format_check cargo fmt -p fcp-telegram -- --check
format_check_status="${LAST_STEP_STATUS}"

run_rch_cargo_step loopback_jsonl \
  FCP_TELEGRAM_E2E_GIT_REVISION="${git_revision}" \
  TELEGRAM_LOOPBACK_E2E_ARTIFACT="${OUT_ROOT}/evidence/loopback_matrix.jsonl" \
  cargo test -p fcp-telegram --features test-support --test integration telegram_loopback_e2e_jsonl_matrix -- --nocapture
loopback_jsonl_status="${LAST_STEP_STATUS}"

run_rch_cargo_step local_non_mock_acceptance \
  cargo test -p fcp-telegram --test local_non_mock -- --nocapture
local_non_mock_status="${LAST_STEP_STATUS}"

run_rch_cargo_step conformance_contract \
  cargo test -p fcp-telegram --test conformance_contract -- --nocapture
conformance_contract_status="${LAST_STEP_STATUS}"

live_skip_jsonl_path="${OUT_ROOT}/evidence/live_optional_skip.jsonl"
if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && "${TELEGRAM_LIVE_WRITE_APPROVAL:-}" == "yes" ]]; then
  run_rch_cargo_step live_optional \
    FCP_TELEGRAM_E2E_GIT_REVISION="${git_revision}" \
    cargo test -p fcp-telegram --test live_verification -- --nocapture
  live_optional_status="${LAST_STEP_STATUS}"
  cat >"${live_skip_jsonl_path}" <<EOF
{"log_version":"v1","connector_id":"fcp.telegram","event":"telegram_live_optional","scenario":"live_optional_executed","result":"pass","provider_mode":"live_telegram_bot_api","command_line":"cargo test -p fcp-telegram --test live_verification -- --nocapture","git_revision":"${git_revision}","artifact_paths":["${live_skip_jsonl_path}"],"env_presence":{"TELEGRAM_BOT_TOKEN":${token_present},"TELEGRAM_WEBHOOK_SECRET_TOKEN":${secret_present},"TELEGRAM_LIVE_WRITE_APPROVAL":${approval_present}},"fixture_id":"telegram-live-operator-approved","operation":"telegram.live_verification","update_id_hash":null,"chat_id_hash":null,"user_id_hash":null,"sender_policy_decision":"operator_approved_live_read_only","capability_decision":"live_test_capability_tokens","retry_backoff":"live_provider_default","http_status":null,"fcp_error_mapping":"none","event_topic":null,"payload_byte_count":null,"cleanup":"connector_shutdown_by_test","skip_reason":null,"redaction_decision":"redaction-safe: no bot token or provider payload is emitted in JSONL evidence"}
EOF
else
  live_optional_status="structured_skip"
  cat >"${live_skip_jsonl_path}" <<EOF
{"log_version":"v1","connector_id":"fcp.telegram","event":"telegram_live_optional","scenario":"live_optional_prerequisites","result":"skip","provider_mode":"live_telegram_bot_api","command_line":"cargo test -p fcp-telegram --test live_verification -- --nocapture","git_revision":"${git_revision}","artifact_paths":["${live_skip_jsonl_path}"],"env_presence":{"TELEGRAM_BOT_TOKEN":${token_present},"TELEGRAM_WEBHOOK_SECRET_TOKEN":${secret_present},"TELEGRAM_LIVE_WRITE_APPROVAL":${approval_present}},"fixture_id":"telegram-live-operator-approved","operation":"telegram.live_verification","update_id_hash":null,"chat_id_hash":null,"user_id_hash":null,"sender_policy_decision":"not_exercised","capability_decision":"not_exercised","retry_backoff":"not_exercised","http_status":null,"fcp_error_mapping":"not_exercised","event_topic":null,"payload_byte_count":null,"cleanup":"no_live_resources_allocated","skip_reason":"requires TELEGRAM_BOT_TOKEN and TELEGRAM_LIVE_WRITE_APPROVAL=yes","redaction_decision":"redaction-safe: only prerequisite presence booleans are emitted"}
EOF
fi

run_rch_cargo_step clippy \
  cargo clippy -p fcp-telegram --features test-support --all-targets -- -D warnings
clippy_status="${LAST_STEP_STATUS}"

run_step diff_check git diff --check -- connectors/telegram/tests/integration.rs connectors/telegram/tests/local_non_mock.rs connectors/telegram/README.md scripts/e2e/telegram_connector_verification.sh
diff_check_status="${LAST_STEP_STATUS}"

loopback_jsonl_path="${OUT_ROOT}/evidence/loopback_matrix.jsonl"
loopback_stdout_jsonl_path="${OUT_ROOT}/evidence/loopback_stdout.jsonl"
if grep -a '^TELEGRAM_LOOPBACK_E2E_JSONL ' "${OUT_ROOT}/logs/loopback_jsonl.log" \
  | sed 's/^TELEGRAM_LOOPBACK_E2E_JSONL //' >"${loopback_stdout_jsonl_path}"; then
  if [[ ! -s "${loopback_stdout_jsonl_path}" ]]; then
    promote_status failed
    printf '{"event":"telegram_loopback_missing_jsonl","status":"failed","git_revision":"%s"}\n' "${git_revision}" >"${loopback_stdout_jsonl_path}"
  fi
  cp "${loopback_stdout_jsonl_path}" "${loopback_jsonl_path}"
fi

if grep -R -E '[0-9]{6,}:[A-Za-z0-9_-]{20,}|telegram-loopback-secret|208214988|999999999|authorized webhook|denied webhook|retry transient|rate limit fixture|telegram-loopback-photo|telegram-loopback-file' "${OUT_ROOT}/evidence" >/dev/null 2>&1; then
  OVERALL_STATUS="failed"
  EXIT_CODE=1
  echo "[telegram-verification] redaction check failed" >&2
fi

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-telegram",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/telegram_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_dir": "${TARGET_DIR}",
  "fixture_mode": "no-live-credential Telegram Bot API loopback plus host-forwarded webhook ingest through the connector boundary",
  "live_mode": "side-effect-gated live Telegram smoke emits structured skips unless operator credentials and explicit approval are provided",
  "redaction": "no Telegram bot token, webhook secret, raw user id, raw chat id, update id, message text, media id, file id, or provider payload is emitted; evidence carries hashes, route classes, outcome enums, status codes, byte counts, and skip reasons"
}
EOF

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-telegram",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "steps": {
    "format_check": "${format_check_status}",
    "loopback_jsonl": "${loopback_jsonl_status}",
    "local_non_mock_acceptance": "${local_non_mock_status}",
    "conformance_contract": "${conformance_contract_status}",
    "live_optional": "${live_optional_status}",
    "clippy": "${clippy_status}",
    "diff_check": "${diff_check_status}"
  },
  "artifacts": {
    "loopback_jsonl": "${OUT_ROOT}/evidence/loopback_matrix.jsonl",
    "loopback_stdout_jsonl": "${OUT_ROOT}/evidence/loopback_stdout.jsonl",
    "live_optional_jsonl": "${live_skip_jsonl_path}",
    "environment": "${OUT_ROOT}/environment.json"
  }
}
EOF

echo "Telegram verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
