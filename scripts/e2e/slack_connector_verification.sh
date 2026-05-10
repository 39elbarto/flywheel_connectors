#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-/tmp/fcp-slack-e2e/${RUN_ID}}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-slack-e2e-target}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0

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
  if grep -Eq 'No space left on device|timeout: failed to execute process|RCH-E|connection reset by peer|missing worker system package|failed to execute process' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
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
    echo "passed"
  else
    local status
    status="$(classify_failure "${OUT_ROOT}/logs/${name}.log")"
    promote_status "${status}"
    echo "${status}"
  fi
}

run_rch_cargo_step() {
  local name="$1"
  shift
  run_step "${name}" env RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}" rch exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    "$@"
}

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

format_check_status="$(run_rch_cargo_step format_check cargo fmt -p fcp-slack -- --check)"
loopback_jsonl_status="$(run_rch_cargo_step loopback_jsonl \
  FCP_SLACK_E2E_GIT_REVISION="${git_revision}" \
  SLACK_LOOPBACK_E2E_ARTIFACT="${OUT_ROOT}/evidence/loopback_policy_matrix.jsonl" \
  cargo test -p fcp-slack --test integration slack_loopback_e2e_jsonl_matrix -- --nocapture)"
socket_policy_status="$(run_rch_cargo_step socket_policy \
  cargo test -p fcp-slack --test integration socket_mode_ -- --nocapture)"
live_skip_status="$(run_rch_cargo_step live_smoke_skip_jsonl \
  FCP_SLACK_E2E_GIT_REVISION="${git_revision}" \
  SLACK_LIVE_E2E_ARTIFACT="${OUT_ROOT}/evidence/live_smoke_skip.jsonl" \
  cargo test -p fcp-slack --test live_verification slack_live_smoke_structured_skip_jsonl -- --nocapture)"
clippy_status="$(run_rch_cargo_step clippy \
  cargo clippy -p fcp-slack --test integration --test live_verification -- -D warnings)"
diff_check_status="$(run_step diff_check git diff --check -- connectors/slack/tests/integration.rs connectors/slack/tests/live_verification.rs connectors/slack/README.md scripts/e2e/slack_connector_verification.sh)"

if grep -a "^${SLACK_LOOPBACK_E2E_JSONL_PREFIX:-SLACK_LOOPBACK_E2E_JSONL} " "${OUT_ROOT}/logs/loopback_jsonl.log" \
  | sed "s/^${SLACK_LOOPBACK_E2E_JSONL_PREFIX:-SLACK_LOOPBACK_E2E_JSONL} //" >"${OUT_ROOT}/evidence/loopback_stdout.jsonl"; then
  if [[ ! -s "${OUT_ROOT}/evidence/loopback_stdout.jsonl" ]]; then
    promote_status failed
    printf '{"event":"slack_loopback_missing_jsonl","status":"failed","git_revision":"%s"}\n' "${git_revision}" >"${OUT_ROOT}/evidence/loopback_stdout.jsonl"
  fi
fi

if grep -a '^SLACK_LIVE_E2E_JSONL ' "${OUT_ROOT}/logs/live_smoke_skip_jsonl.log" \
  | sed 's/^SLACK_LIVE_E2E_JSONL //' >"${OUT_ROOT}/evidence/live_smoke_skip_stdout.jsonl"; then
  if [[ ! -s "${OUT_ROOT}/evidence/live_smoke_skip_stdout.jsonl" ]]; then
    promote_status failed
    printf '{"event":"slack_live_smoke_missing_jsonl","status":"failed","git_revision":"%s"}\n' "${git_revision}" >"${OUT_ROOT}/evidence/live_smoke_skip_stdout.jsonl"
  fi
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
    "environment": "${OUT_ROOT}/environment.json"
  }
}
EOF

echo "Slack verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
