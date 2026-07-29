#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-/tmp/fcp-telegram-e2e/${RUN_ID}}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-telegram-e2e-target}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
REMOTE_RUNNER="rch:remote-required"
PROOF_GOVERNOR="${PROOF_GOVERNOR:-1}"
if [[ -z "${FWC_BIN:-}" ]]; then
  if [[ -x "${REPO_ROOT}/target/debug/fwc" ]]; then
    FWC_BIN="${REPO_ROOT}/target/debug/fwc"
  else
    FWC_BIN="fwc"
  fi
fi
export RCH_FORCE_REMOTE=1

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence" "${OUT_ROOT}/proof"

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
  if grep -Eq 'No space left on device|timeout: failed to execute process|RCH-E|remote required; refusing local fallback|rch command did not produce remote proof|\[RCH\] local|no admissible workers|no worker assigned|connection reset by peer|missing worker system package|failed to execute process|failed to get successful HTTP response from `https://index\.crates\.io/|Backend unavailable|unable to update registry `crates-io`|spurious network error|not a valid fwc command|local_fallback_refused' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    return 1
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

json_array_from_args() {
  if [[ $# -eq 0 ]]; then
    printf '[]'
    return
  fi
  printf '%s\n' "$@" | jq -R . | jq -s .
}

write_proof_corpus() {
  local name="$1"
  local corpus_path="$2"
  shift 2
  local claim_key="telegram-connector-verifier-${name}"
  local argv_json
  argv_json="$(json_array_from_args "$@")"
  jq -n \
    --arg claim_key "${claim_key}" \
    --arg purpose "Run Telegram connector verifier step ${name} through the fail-closed rch proof governor." \
    --argjson rerun_argv "${argv_json}" \
    '{
      schema: "fcp.proof-graph-indexer-corpus.v1",
      verification_scripts: [
        {
          claim_key: $claim_key,
          script_path: "scripts/e2e/telegram_connector_verification.sh",
          purpose: $purpose,
          rerun_argv: $rerun_argv,
          required_env_keys: [],
          source: {
            source_id: "telegram.connector.verifier",
            path: "scripts/e2e/telegram_connector_verification.sh",
            line: 1
          }
        }
      ]
    }' >"${corpus_path}"
}

governor_step_status() {
  local classification="$1"
  case "${classification}" in
    accepted_remote_proof)
      echo "passed"
      ;;
    infra_blocked|refused_local_fallback)
      echo "infra_blocked"
      ;;
    remote_command_failed|not_proof|failed_closed|missing)
      echo "failed"
      ;;
    *)
      echo "failed"
      ;;
  esac
}

run_governed_rch_cargo_step() {
  local name="$1"
  shift
  local corpus_path="${OUT_ROOT}/proof/${name}.corpus.json"
  local proof_json="${OUT_ROOT}/proof/${name}.proof.json"
  local proof_jsonl="${OUT_ROOT}/proof/${name}.rch_remote_proof.jsonl"
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local claim_key="telegram-connector-verifier-${name}"
  local classification status rch_summary_line

  echo "[telegram-verification] ${name}: fwc proof run ${claim_key} --execute" >&2
  if ! require_cmd jq >"${log_path}" 2>&1; then
    LAST_STEP_STATUS="infra_blocked"
    promote_status infra_blocked
    return
  fi
  if ! require_cmd "${FWC_BIN}" >>"${log_path}" 2>&1; then
    LAST_STEP_STATUS="infra_blocked"
    promote_status infra_blocked
    return
  fi

  # shellcheck disable=SC2129
  write_proof_corpus "${name}" "${corpus_path}" "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" "$@" >>"${log_path}" 2>&1
  (
    cd "${REPO_ROOT}" || exit
    "${FWC_BIN}" --json proof run "${claim_key}" --corpus "${corpus_path}" --execute
  ) >"${proof_json}" 2>>"${log_path}"

  cat "${proof_json}" >>"${log_path}"
  classification="$(jq -r '
    if .status == "error"
      and (
        .error.type == "unknown-command"
        or ((.error.message // "") | test("not a valid fwc command"))
      )
    then
      "infra_blocked"
    else
      .execution.rch_remote_proof.classification_label // "missing"
    end
  ' "${proof_json}" 2>>"${log_path}" || echo missing)"
  rch_summary_line="$(jq -r '.execution.rch_remote_proof.evidence.rch_summary_line // ""' "${proof_json}" 2>>"${log_path}" || true)"
  if [[ "${rch_summary_line}" == *"remote required; refusing local fallback"* ]]; then
    classification="refused_local_fallback"
    jq -c '
      (.execution.rch_remote_proof.jsonl_record // empty) as $record
      | if $record == "" then
          empty
        else
          ($record | fromjson)
          | .worker_id = null
          | .selector_reason = "local_fallback_refused"
          | .blocker_reason = "local_fallback_refused"
          | .exit_kind = {state: "blocked"}
        end
    ' "${proof_json}" >"${proof_jsonl}" 2>>"${log_path}" || true
  else
    jq -r '.execution.rch_remote_proof.jsonl_record // empty' "${proof_json}" >"${proof_jsonl}" 2>>"${log_path}" || true
  fi
  status="$(governor_step_status "${classification}")"
  if [[ "${status}" != "passed" ]]; then
    promote_status "${status}"
  fi
  LAST_STEP_STATUS="${status}"
}

run_legacy_rch_cargo_step_with_remote_policy() {
  local require_remote_proof="$1"
  shift
  local name="$1"
  shift
  run_step "${name}" env \
    RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}" \
    RCH_FORCE_REMOTE=1 \
    RCH_VISIBILITY=verbose \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
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

run_rch_cargo_step_with_remote_policy() {
  local require_remote_proof="$1"
  shift
  local name="$1"
  shift

  if [[ "${require_remote_proof}" == "1" && "${PROOF_GOVERNOR}" == "1" ]]; then
    run_governed_rch_cargo_step "${name}" "$@"
    return
  fi

  run_legacy_rch_cargo_step_with_remote_policy "${require_remote_proof}" "${name}" "$@"
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
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "proof_governor_enabled": "${PROOF_GOVERNOR}",
  "proof_governor": "Cargo-backed verifier steps run through fwc proof run; accepted_remote_proof is the only passing rch proof classification. refused_local_fallback and infra_blocked keep the verifier non-green. format_check is a source-state check, not accepted remote Cargo proof.",
  "proof_artifacts": "${OUT_ROOT}/proof",
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
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
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
    "proof_governor_json": "${OUT_ROOT}/proof/*.proof.json",
    "proof_governor_jsonl": "${OUT_ROOT}/proof/*.rch_remote_proof.jsonl",
    "environment": "${OUT_ROOT}/environment.json"
  }
}
EOF

echo "Telegram verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
