#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-/tmp/fcp-slack-e2e/${RUN_ID}}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-slack-e2e-target}"
PROOF_GOVERNOR="${PROOF_GOVERNOR:-1}"
FWC_BIN="${FWC_BIN:-fwc}"

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
  if grep -Eq 'No space left on device|timeout: failed to execute process|RCH-E|no admissible workers|remote required; refusing local fallback|no worker assigned|connection reset by peer|missing worker system package|failed to execute process|failed to get successful HTTP response from `https://index\.crates\.io/|Backend unavailable|unable to update registry `crates-io`|spurious network error' "${log_path}"; then
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

  echo "[slack-verification] ${name}: $*" >&2
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

run_rch_cargo_step() {
  local name="$1"
  shift
  if [[ "${PROOF_GOVERNOR}" == "1" ]]; then
    run_governed_rch_cargo_step "${name}" "$@"
    return
  fi
  run_legacy_rch_cargo_step "${name}" "$@"
}

run_rch_format_step() {
  local name="$1"
  shift
  # `cargo fmt --check` validates source state; it is not accepted remote Cargo proof.
  run_step "${name}" env RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}" rch exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    "$@"
}

run_legacy_rch_cargo_step() {
  local name="$1"
  shift
  run_step "${name}" env RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}" rch exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    "$@"
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
  local claim_key="slack-connector-verifier-${name}"
  local argv_json
  argv_json="$(json_array_from_args "$@")"
  jq -n \
    --arg claim_key "${claim_key}" \
    --arg purpose "Run Slack connector verifier step ${name} through the fail-closed rch proof governor." \
    --argjson rerun_argv "${argv_json}" \
    '{
      schema: "fcp.proof-graph-indexer-corpus.v1",
      verification_scripts: [
        {
          claim_key: $claim_key,
          script_path: "scripts/e2e/slack_connector_verification.sh",
          purpose: $purpose,
          rerun_argv: $rerun_argv,
          required_env_keys: [],
          source: {
            source_id: "slack.connector.verifier",
            path: "scripts/e2e/slack_connector_verification.sh",
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
  local claim_key="slack-connector-verifier-${name}"
  local classification status

  echo "[slack-verification] ${name}: fwc proof run ${claim_key} --execute" >&2
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
  write_proof_corpus "${name}" "${corpus_path}" "$@" >>"${log_path}" 2>&1
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
  jq -r '.execution.rch_remote_proof.jsonl_record // empty' "${proof_json}" >"${proof_jsonl}" 2>>"${log_path}" || true
  status="$(governor_step_status "${classification}")"
  if [[ "${status}" != "passed" ]]; then
    promote_status "${status}"
  fi
  LAST_STEP_STATUS="${status}"
}

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

run_rch_format_step format_check cargo fmt -p fcp-slack -- --check
format_check_status="${LAST_STEP_STATUS}"
run_rch_cargo_step loopback_jsonl \
  FCP_SLACK_E2E_GIT_REVISION="${git_revision}" \
  SLACK_LOOPBACK_E2E_ARTIFACT="${OUT_ROOT}/evidence/loopback_policy_matrix.jsonl" \
  cargo test -p fcp-slack --test integration slack_loopback_e2e_jsonl_matrix -- --nocapture
loopback_jsonl_status="${LAST_STEP_STATUS}"
run_rch_cargo_step local_non_mock_acceptance \
  cargo test -p fcp-slack --test local_non_mock -- --nocapture
local_non_mock_status="${LAST_STEP_STATUS}"
run_rch_cargo_step socket_policy \
  cargo test -p fcp-slack --test integration socket_mode_ -- --nocapture
socket_policy_status="${LAST_STEP_STATUS}"
run_rch_cargo_step live_smoke_skip_jsonl \
  FCP_SLACK_E2E_GIT_REVISION="${git_revision}" \
  SLACK_LIVE_E2E_ARTIFACT="${OUT_ROOT}/evidence/live_smoke_skip.jsonl" \
  cargo test -p fcp-slack --test live_verification slack_live_smoke_structured_skip_jsonl -- --nocapture
live_skip_status="${LAST_STEP_STATUS}"
run_rch_cargo_step clippy \
  cargo clippy -p fcp-slack --test integration --test live_verification --test local_non_mock --no-deps -- -D warnings
clippy_status="${LAST_STEP_STATUS}"
run_step diff_check git diff --check -- connectors/slack/Cargo.toml connectors/slack/manifest.toml connectors/slack/src/connector.rs connectors/slack/tests/integration.rs connectors/slack/tests/live_verification.rs connectors/slack/tests/local_non_mock.rs connectors/slack/README.md scripts/e2e/slack_connector_verification.sh
diff_check_status="${LAST_STEP_STATUS}"

loopback_jsonl_path="${OUT_ROOT}/evidence/loopback_policy_matrix.jsonl"
loopback_stdout_jsonl_path="${OUT_ROOT}/evidence/loopback_stdout.jsonl"
if grep -a "^${SLACK_LOOPBACK_E2E_JSONL_PREFIX:-SLACK_LOOPBACK_E2E_JSONL} " "${OUT_ROOT}/logs/loopback_jsonl.log" \
  | sed "s/^${SLACK_LOOPBACK_E2E_JSONL_PREFIX:-SLACK_LOOPBACK_E2E_JSONL} //" >"${loopback_stdout_jsonl_path}"; then
  if [[ ! -s "${loopback_stdout_jsonl_path}" ]]; then
    promote_status failed
    printf '{"event":"slack_loopback_missing_jsonl","status":"failed","git_revision":"%s"}\n' "${git_revision}" >"${loopback_stdout_jsonl_path}"
  fi
  cp "${loopback_stdout_jsonl_path}" "${loopback_jsonl_path}"
fi

live_skip_jsonl_path="${OUT_ROOT}/evidence/live_smoke_skip.jsonl"
live_skip_stdout_jsonl_path="${OUT_ROOT}/evidence/live_smoke_skip_stdout.jsonl"
if grep -a '^SLACK_LIVE_E2E_JSONL ' "${OUT_ROOT}/logs/live_smoke_skip_jsonl.log" \
  | sed 's/^SLACK_LIVE_E2E_JSONL //' >"${live_skip_stdout_jsonl_path}"; then
  if [[ ! -s "${live_skip_stdout_jsonl_path}" ]]; then
    promote_status failed
    printf '{"event":"slack_live_smoke_missing_jsonl","status":"failed","git_revision":"%s"}\n' "${git_revision}" >"${live_skip_stdout_jsonl_path}"
  fi
  cp "${live_skip_stdout_jsonl_path}" "${live_skip_jsonl_path}"
fi

if grep -R -E 'xoxb-|xapp-|private slack message|TSECRET|CSECRET|USECRET|1700000000\.000001' "${OUT_ROOT}/evidence" >/dev/null 2>&1; then
  OVERALL_STATUS="failed"
  EXIT_CODE=1
  echo "[slack-verification] redaction check failed" >&2
fi

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-slack",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/slack_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_dir": "${TARGET_DIR}",
  "proof_governor_enabled": "${PROOF_GOVERNOR}",
  "proof_governor": "Cargo-backed verifier steps run through fwc proof run; accepted_remote_proof is the only passing rch proof classification. refused_local_fallback and infra_blocked keep the verifier non-green. format_check is a source-state check, not accepted remote Cargo proof.",
  "proof_artifacts": "${OUT_ROOT}/proof",
  "fixture_mode": "no-live-credential Slack Socket Mode/Web API loopback",
  "live_mode": "side-effect-gated live Slack smoke emits structured skips unless operator credentials and explicit write approval are provided",
  "redaction": "no Slack bearer token, app token, channel id, user id, team id, event id, thread timestamp, message text, or provider payload is emitted; evidence carries hashes, route classes, outcome enums, and skip reasons"
}
EOF

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-slack",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "steps": {
    "format_check": "${format_check_status}",
    "loopback_jsonl": "${loopback_jsonl_status}",
    "local_non_mock_acceptance": "${local_non_mock_status}",
    "socket_policy": "${socket_policy_status}",
    "live_smoke_skip_jsonl": "${live_skip_status}",
    "clippy": "${clippy_status}",
    "diff_check": "${diff_check_status}"
  },
  "artifacts": {
    "loopback_jsonl": "${OUT_ROOT}/evidence/loopback_policy_matrix.jsonl",
    "loopback_stdout_jsonl": "${OUT_ROOT}/evidence/loopback_stdout.jsonl",
    "live_smoke_skip_jsonl": "${OUT_ROOT}/evidence/live_smoke_skip.jsonl",
    "live_smoke_skip_stdout_jsonl": "${OUT_ROOT}/evidence/live_smoke_skip_stdout.jsonl",
    "proof_governor_json": "${OUT_ROOT}/proof/*.proof.json",
    "proof_governor_jsonl": "${OUT_ROOT}/proof/*.rch_remote_proof.jsonl",
    "environment": "${OUT_ROOT}/environment.json"
  }
}
EOF

echo "Slack verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
