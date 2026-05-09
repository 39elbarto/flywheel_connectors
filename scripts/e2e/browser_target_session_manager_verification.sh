#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-}"

usage() {
  cat <<'EOF'
Usage: scripts/e2e/browser_target_session_manager_verification.sh [options]

Options:
  --run-id <id>      Run identifier for artifact paths
  --out-root <path>  Artifact root (default: artifacts/e2e/browser_target_session_manager/<run-id>)
  -h, --help         Show this help

Runs the deterministic Browser direct-CDP target/session manager proof test
through rch, extracts redaction-safe JSONL events from test stdout, and writes
an operator replay bundle.
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
  OUT_ROOT="${REPO_ROOT}/artifacts/e2e/browser_target_session_manager/${RUN_ID}"
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 2
  fi
}

require_cmd jq
require_cmd rch

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

TEST_LOG="${OUT_ROOT}/logs/target_session_manager_test.log"
EVENTS_JSONL="${OUT_ROOT}/evidence/manager-events.jsonl"
SUMMARY_JSON="${OUT_ROOT}/evidence/manager-summary.json"
ENVIRONMENT_JSON="${OUT_ROOT}/environment.json"
REPLAY_SH="${OUT_ROOT}/replay.sh"
RUN_SUMMARY_JSON="${OUT_ROOT}/summary.json"

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
test_status="passed"
events_status="passed"
summary_status="passed"

echo "[browser-target-session-manager] running deterministic manager proof"
if ! (
  cd "${REPO_ROOT}"
  env RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}" rch exec -- env \
    RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}" \
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-browser-target-session-manager}" \
    CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" \
    cargo test -p fcp-browser test_direct_cdp_manager_artifact_contains_closeout_evidence --lib -- --nocapture
) >"${TEST_LOG}" 2>&1; then
  test_status="failed"
fi

if ! grep -a '^BROWSER_TARGET_SESSION_MANAGER_JSONL ' "${TEST_LOG}" \
  | sed 's/^BROWSER_TARGET_SESSION_MANAGER_JSONL //' >"${EVENTS_JSONL}"
then
  events_status="failed"
fi

if [[ ! -s "${EVENTS_JSONL}" ]] || ! jq -c . "${EVENTS_JSONL}" >/dev/null; then
  events_status="failed"
fi

if ! grep -a '^BROWSER_TARGET_SESSION_MANAGER_SUMMARY ' "${TEST_LOG}" \
  | sed 's/^BROWSER_TARGET_SESSION_MANAGER_SUMMARY //' \
  | tail -n 1 >"${SUMMARY_JSON}"
then
  summary_status="failed"
fi

if [[ ! -s "${SUMMARY_JSON}" ]] || ! jq -e '.schema_version == "fcp-browser-target-session-manager-evidence.v1"' "${SUMMARY_JSON}" >/dev/null; then
  summary_status="failed"
fi

event_count="$(wc -l <"${EVENTS_JSONL}" | tr -d ' ')"
overall_status="passed"
exit_code=0
if [[ "${test_status}" != "passed" || "${events_status}" != "passed" || "${summary_status}" != "passed" ]]; then
  overall_status="failed"
  exit_code=1
fi

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg script "scripts/e2e/browser_target_session_manager_verification.sh" \
  --arg repo_root "${REPO_ROOT}" \
  --arg artifact_root "${OUT_ROOT}" \
  --arg git_revision "${git_revision}" \
  --arg target_dir "${CARGO_TARGET_DIR:-/tmp/fcp-browser-target-session-manager}" \
  --arg rch_require_remote "${RCH_REQUIRE_REMOTE:-1}" \
  '{
    run_id: $run_id,
    script: $script,
    repo_root: $repo_root,
    artifact_root: $artifact_root,
    git_revision: $git_revision,
    cargo_target_dir: $target_dir,
    rch_require_remote: $rch_require_remote,
    redaction: "manager events include hashes and omit raw target ids, cookie scopes, URLs, credentials, and local paths"
  }' >"${ENVIRONMENT_JSON}"

cat >"${REPLAY_SH}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

env RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}" rch exec -- env \
  RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}" \
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-browser-target-session-manager}" \
  CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" \
  cargo test -p fcp-browser test_direct_cdp_manager_artifact_contains_closeout_evidence --lib -- --nocapture
EOF
chmod +x "${REPLAY_SH}"

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg overall_status "${overall_status}" \
  --arg test_status "${test_status}" \
  --arg events_status "${events_status}" \
  --arg summary_status "${summary_status}" \
  --arg event_count "${event_count}" \
  --arg events_jsonl "${EVENTS_JSONL}" \
  --arg manager_summary "${SUMMARY_JSON}" \
  --arg test_log "${TEST_LOG}" \
  --arg environment "${ENVIRONMENT_JSON}" \
  --arg replay "${REPLAY_SH}" \
  '{
    run_id: $run_id,
    connector: "fcp-browser",
    scenario: "browser_target_session_manager",
    overall_status: $overall_status,
    steps: {
      cargo_test: $test_status,
      manager_events_jsonl: $events_status,
      manager_summary: $summary_status
    },
    manager_event_count: ($event_count | tonumber),
    artifacts: {
      manager_events_jsonl: $events_jsonl,
      manager_summary: $manager_summary,
      test_log: $test_log,
      environment: $environment,
      replay: $replay
    }
  }' >"${RUN_SUMMARY_JSON}"

echo "[browser-target-session-manager] ${overall_status}: ${RUN_SUMMARY_JSON}"
exit "${exit_code}"
