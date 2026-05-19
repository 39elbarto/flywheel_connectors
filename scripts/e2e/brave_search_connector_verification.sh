#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/brave_search_connector/${RUN_ID}}"
TARGET_DIR="${FCP_BRAVE_SEARCH_TARGET_DIR:-/tmp/fcp-brave-search-e2e-${RUN_ID}}"
RCH_BIN="${RCH_BIN:-rch}"
DEFAULT_FWC_BIN="${REPO_ROOT}/target/debug/fwc"
if [[ -x "${DEFAULT_FWC_BIN}" ]]; then
  FWC_BIN="${FWC_BIN:-${DEFAULT_FWC_BIN}}"
else
  FWC_BIN="${FWC_BIN:-fwc}"
fi
PROOF_GOVERNOR="${PROOF_GOVERNOR:-1}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
REMOTE_RUNNER="rch:remote-required"
export RCH_FORCE_REMOTE=1
export RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence" "${OUT_ROOT}/proof"

OVERALL_STATUS="ok"
EXIT_CODE=0
LAST_STEP_STATUS="not_run"

manifest_status="pending"
cargo_check_status="pending"
format_check_status="pending"
integration_status="pending"
local_non_mock_status="pending"
local_non_mock_jsonl_status="pending"
live_status="pending"
live_jsonl_status="pending"
manifest_ops_status="pending"
manifest_ops_jsonl_status="pending"
crate_suite_status="pending"
clippy_status="pending"

promote_overall_status() {
  local next_status="$1"
  case "${next_status}" in
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
  elif grep -Eq 'timeout: failed to execute process|RCH-E|remote required; refusing local fallback|rch command did not produce remote proof|\[RCH\] local|no admissible workers|missing worker|No space left on device|dbus-1\.pc|connection reset by peer|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

has_rch_remote_worker_proof() {
  local log_path="$1"

  if grep -E '^\[RCH\] remote [^[:space:];]+' "${log_path}" \
    | grep -Ev '^\[RCH\] remote required([;[:space:]]|$)' >/dev/null
  then
    return 0
  fi

  return 1
}

require_rch_remote_proof() {
  local name="$1"
  local log_path="$2"

  if has_rch_remote_worker_proof "${log_path}"; then
    return 0
  fi

  echo "[brave-search-verification] ${name}: rch command did not produce remote proof" >&2
  echo "rch command did not produce remote proof" >>"${log_path}"
  return 1
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local rc

  echo "[brave-search-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
  rc="$?"
  if [[ "${rc}" -eq 0 ]] && ! require_rch_remote_proof "${name}" "${log_path}"; then
    return 1
  fi
  return "${rc}"
}

run_step() {
  local name="$1"
  shift
  if run_logged "${name}" "$@"; then
    echo "passed"
  else
    local status
    status="$(classify_failure "${OUT_ROOT}/logs/${name}.log")"
    promote_overall_status "${status}"
    echo "${status}"
  fi
}

run_logged_without_remote_proof() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"

  echo "[brave-search-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
}

run_step_without_remote_proof() {
  local name="$1"
  shift
  if run_logged_without_remote_proof "${name}" "$@"; then
    echo "passed"
  else
    local status
    status="$(classify_failure "${OUT_ROOT}/logs/${name}.log")"
    promote_overall_status "${status}"
    echo "${status}"
  fi
}

capture_step_without_remote_proof() {
  local output_var="$1"
  shift
  local status
  status="$(run_step_without_remote_proof "$@")"
  printf -v "${output_var}" '%s' "${status}"
  promote_overall_status "${status}"
}

capture_rch_cargo_step() {
  local output_var="$1"
  shift
  local name="$1"
  shift

  run_rch_cargo_step "${name}" "$@"
  printf -v "${output_var}" '%s' "${LAST_STEP_STATUS}"
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

run_legacy_rch_cargo_step() {
  local name="$1"
  shift
  local status

  status="$(run_step "${name}" env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "$@")"
  promote_overall_status "${status}"
  LAST_STEP_STATUS="${status}"
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
  local claim_key="brave-search-connector-verifier-${name}"
  local argv_json
  argv_json="$(json_array_from_args "$@")"
  jq -n \
    --arg claim_key "${claim_key}" \
    --arg purpose "Run Brave Search connector verifier step ${name} through the fail-closed rch proof governor." \
    --argjson rerun_argv "${argv_json}" \
    '{
      schema: "fcp.proof-graph-indexer-corpus.v1",
      verification_scripts: [
        {
          claim_key: $claim_key,
          script_path: "scripts/e2e/brave_search_connector_verification.sh",
          purpose: $purpose,
          rerun_argv: $rerun_argv,
          required_env_keys: [],
          source: {
            source_id: "brave-search.connector.verifier",
            path: "scripts/e2e/brave_search_connector_verification.sh",
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

governor_classification_from_proof() {
  local proof_json="$1"
  local log_path="$2"
  jq -r '
    def proof_text:
      [
        .execution.stdout_preview // "",
        .execution.stderr_preview // "",
        .execution.rch_remote_proof.evidence.rch_summary_line // ""
      ] | join("\n") | ascii_downcase;
    if .status == "error"
      and (
        .error.type == "unknown-command"
        or ((.error.message // "") | test("not a valid fwc command"))
      )
    then
      "infra_blocked"
    elif (proof_text | contains("refusing local fallback"))
    then
      "refused_local_fallback"
    else
      .execution.rch_remote_proof.classification_label // "missing"
    end
  ' "${proof_json}" 2>>"${log_path}" || echo missing
}

write_normalized_proof_jsonl() {
  local proof_json="$1"
  local proof_jsonl="$2"
  local log_path="$3"
  jq -r '
    def proof_text:
      [
        .execution.stdout_preview // "",
        .execution.stderr_preview // "",
        .execution.rch_remote_proof.evidence.rch_summary_line // ""
      ] | join("\n") | ascii_downcase;
    . as $proof
    | if (.execution.rch_remote_proof.jsonl_record // "") == "" then
      empty
    else
      .execution.rch_remote_proof.jsonl_record
      | fromjson
      | if ($proof | proof_text | contains("refusing local fallback")) then
          .worker_id = null
          | .selector_reason = "local_fallback_refused"
          | .blocker_reason = "local_fallback_refused"
          | .exit_kind = {"state": "blocked"}
        else
          .
        end
      | @json
    end
  ' "${proof_json}" >"${proof_jsonl}" 2>>"${log_path}" || true
}

run_self_test() {
  require_cmd grep
  require_cmd jq

  local self_test_root="${OUT_ROOT}/self-test"
  local positive_log="${self_test_root}/remote-worker.log"
  local refused_log="${self_test_root}/remote-required-refused.log"
  local proof_json="${self_test_root}/stale-fwc-refusal.proof.json"
  local proof_log="${self_test_root}/stale-fwc-refusal.log"
  local proof_jsonl="${self_test_root}/stale-fwc-refusal.rch_remote_proof.jsonl"
  local summary_json="${self_test_root}/summary.json"
  local raw_record classification

  mkdir -p "${self_test_root}"

  printf '%s\n' '[RCH] remote vmi123 (1.2s)' >"${positive_log}"
  if ! has_rch_remote_worker_proof "${positive_log}"; then
    echo "self-test failed: remote worker proof line was rejected" >&2
    return 1
  fi

  printf '%s\n' '[RCH] remote required; refusing local fallback (no worker assigned)' >"${refused_log}"
  if has_rch_remote_worker_proof "${refused_log}"; then
    echo "self-test failed: remote-required refusal was accepted as worker proof" >&2
    return 1
  fi

  raw_record="$(jq -nc '{
    schema: "fcp.rch-remote-proof-evidence.v1",
    command: ["rch", "exec", "--", "cargo", "check"],
    cwd: ".",
    git_revision: "self-test",
    worker_id: "required;",
    rch_summary_line: "[RCH] remote required; refusing local fallback (no worker assigned)",
    target_dir: "/tmp/fcp-brave-search-self-test",
    started_at_unix_ms: 1,
    finished_at_unix_ms: 2,
    exit_kind: {"state": "remote_failed", "exit_code": 1},
    blocker_reason: null,
    redaction: {"flags": ["command_checked"]}
  }')"

  jq -n \
    --arg jsonl_record "${raw_record}" \
    '{
      status: "error",
      execution: {
        stdout_preview: "",
        stderr_preview: "[RCH] local (no admissible workers: critical_pressure=5)\n[RCH] remote required; refusing local fallback (no worker assigned)\n",
        rch_remote_proof: {
          classification_label: "remote_command_failed",
          evidence: {
            rch_summary_line: "[RCH] remote required; refusing local fallback (no worker assigned)"
          },
          jsonl_record: $jsonl_record
        }
      }
    }' >"${proof_json}"

  classification="$(governor_classification_from_proof "${proof_json}" "${proof_log}")"
  if [[ "${classification}" != "refused_local_fallback" ]]; then
    echo "self-test failed: expected refused_local_fallback, got ${classification}" >&2
    return 1
  fi

  write_normalized_proof_jsonl "${proof_json}" "${proof_jsonl}" "${proof_log}"
  if ! jq -e '
    .worker_id == null
    and .selector_reason == "local_fallback_refused"
    and .blocker_reason == "local_fallback_refused"
    and .exit_kind == {"state": "blocked"}
  ' "${proof_jsonl}" >/dev/null
  then
    echo "self-test failed: normalized JSONL did not preserve fail-closed refusal fields" >&2
    return 1
  fi

  cat >"${summary_json}" <<EOF
{
  "status": "passed",
  "checks": {
    "remote_worker_line_accepted": "passed",
    "remote_required_refusal_rejected_as_worker": "passed",
    "stale_fwc_refusal_classification": "${classification}",
    "normalized_jsonl": "passed"
  },
  "artifacts": {
    "remote_worker_log": "${positive_log}",
    "remote_required_refusal_log": "${refused_log}",
    "stale_fwc_proof_json": "${proof_json}",
    "stale_fwc_normalized_jsonl": "${proof_jsonl}"
  }
}
EOF

  echo "Brave Search verifier self-test passed; artifacts written to ${self_test_root}"
}

if [[ "${BRAVE_SEARCH_VERIFIER_SELF_TEST:-0}" == "1" ]]; then
  run_self_test
  exit "$?"
fi

run_governed_rch_cargo_step() {
  local name="$1"
  shift
  local corpus_path="${OUT_ROOT}/proof/${name}.corpus.json"
  local proof_json="${OUT_ROOT}/proof/${name}.proof.json"
  local proof_jsonl="${OUT_ROOT}/proof/${name}.rch_remote_proof.jsonl"
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local claim_key="brave-search-connector-verifier-${name}"
  local classification status

  echo "[brave-search-verification] ${name}: fwc proof run ${claim_key} --execute" >&2
  if ! require_cmd jq >"${log_path}" 2>&1; then
    LAST_STEP_STATUS="infra_blocked"
    promote_overall_status infra_blocked
    return
  fi
  if ! require_cmd "${FWC_BIN}" >>"${log_path}" 2>&1; then
    LAST_STEP_STATUS="infra_blocked"
    promote_overall_status infra_blocked
    return
  fi

  # shellcheck disable=SC2129
  write_proof_corpus "${name}" "${corpus_path}" "$@" >>"${log_path}" 2>&1
  (
    cd "${REPO_ROOT}" || exit
    "${FWC_BIN}" --json proof run "${claim_key}" --corpus "${corpus_path}" --execute
  ) >"${proof_json}" 2>>"${log_path}"

  cat "${proof_json}" >>"${log_path}"
  classification="$(governor_classification_from_proof "${proof_json}" "${log_path}")"
  if [[ "${classification}" == "refused_local_fallback" ]] && ! jq -e \
    '.execution.rch_remote_proof.classification_label == "refused_local_fallback"' \
    "${proof_json}" >/dev/null 2>>"${log_path}"
  then
    echo "[brave-search-verification] ${name}: normalized stale fwc local-fallback refusal classification" >>"${log_path}"
  fi
  write_normalized_proof_jsonl "${proof_json}" "${proof_jsonl}" "${log_path}"
  status="$(governor_step_status "${classification}")"
  if [[ "${status}" != "passed" ]]; then
    promote_overall_status "${status}"
  fi
  LAST_STEP_STATUS="${status}"
}

require_cmd grep
require_cmd jq
require_cmd sed
require_cmd "${RCH_BIN}"

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
manifest_ops_jsonl="${OUT_ROOT}/evidence/manifest_ops_audit.jsonl"

capture_rch_cargo_step manifest_status manifest_check \
  "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
  "CARGO_TARGET_DIR=${TARGET_DIR}" \
  cargo run -q -p fwc -- manifest fix connectors/brave-search/manifest.toml --check --json

if [[ "${manifest_status}" == "passed" ]]; then
  cp "${OUT_ROOT}/logs/manifest_check.log" "${OUT_ROOT}/evidence/manifest_check.json"
else
  cat >"${OUT_ROOT}/evidence/manifest_check.json" <<EOF
{"status":"${manifest_status}","log":"${OUT_ROOT}/logs/manifest_check.log"}
EOF
fi

capture_rch_cargo_step cargo_check_status cargo_check \
  "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
  "CARGO_TARGET_DIR=${TARGET_DIR}" \
  CARGO_INCREMENTAL=0 \
  cargo check -p fcp-brave-search --all-targets

capture_step_without_remote_proof format_check_status format_check env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env \
  "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
  "CARGO_TARGET_DIR=${TARGET_DIR}" \
  cargo fmt --manifest-path connectors/brave-search/Cargo.toml --check

capture_rch_cargo_step integration_status integration_suite \
  "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
  "CARGO_TARGET_DIR=${TARGET_DIR}" \
  CARGO_INCREMENTAL=0 \
  cargo test -p fcp-brave-search --test integration -- --nocapture

capture_rch_cargo_step local_non_mock_status local_non_mock_jsonl \
  "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
  "CARGO_TARGET_DIR=${TARGET_DIR}" \
  CARGO_INCREMENTAL=0 \
  "BRAVE_SEARCH_E2E_GIT_REVISION=${git_revision}" \
  cargo test -p fcp-brave-search --test local_non_mock -- --nocapture

if grep -a '"connector":"brave-search".*"suite_class":"local_non_mock"' "${OUT_ROOT}/logs/local_non_mock_jsonl.log" >"${OUT_ROOT}/evidence/local_non_mock.jsonl"; then
  local_non_mock_jsonl_status="passed"
else
  local_non_mock_jsonl_status="${local_non_mock_status}"
  if [[ "${local_non_mock_status}" == "passed" ]]; then
    local_non_mock_jsonl_status="failed"
    cat >"${OUT_ROOT}/evidence/local_non_mock.jsonl" <<EOF
{"event":"brave_search_local_non_mock_missing_jsonl","status":"failed","reason":"local_non_mock test emitted no structured Brave Search artifact","git_revision":"${git_revision}","fixture_mode":"loopback_http","log":"${OUT_ROOT}/logs/local_non_mock_jsonl.log"}
EOF
    promote_overall_status failed
  fi
fi

capture_rch_cargo_step live_status live_jsonl \
  "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
  "CARGO_TARGET_DIR=${TARGET_DIR}" \
  CARGO_INCREMENTAL=0 \
  cargo test -p fcp-brave-search --test live_verification brave_search_live_read_self_check_or_structured_skip_jsonl -- --nocapture

if grep -a '^BRAVE_SEARCH_LIVE_JSONL ' "${OUT_ROOT}/logs/live_jsonl.log" \
  | sed 's/^BRAVE_SEARCH_LIVE_JSONL //' >"${OUT_ROOT}/evidence/live_smoke.jsonl"
then
  if [[ -s "${OUT_ROOT}/evidence/live_smoke.jsonl" ]]; then
    live_jsonl_status="passed"
  else
    live_jsonl_status="failed"
  fi
else
  live_jsonl_status="${live_status}"
fi

if [[ "${live_status}" == "passed" && "${live_jsonl_status}" == "failed" ]]; then
  cat >"${OUT_ROOT}/evidence/live_smoke.jsonl" <<EOF
{"event":"brave_search_live_missing_jsonl","status":"failed","reason":"live_verification test emitted no BRAVE_SEARCH_LIVE_JSONL records","git_revision":"${git_revision}","fixture_mode":"live_or_structured_skip","log":"${OUT_ROOT}/logs/live_jsonl.log"}
EOF
  promote_overall_status failed
fi

capture_rch_cargo_step manifest_ops_status manifest_ops_audit \
  "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
  "CARGO_TARGET_DIR=${TARGET_DIR}" \
  CARGO_INCREMENTAL=0 \
  cargo run -p fcp-conformance --bin fcp-manifest-ops-audit -- \
  --repo-root . \
  --allow-findings \
  --log-jsonl "${manifest_ops_jsonl}"

if [[ -f "${manifest_ops_jsonl}" ]] && grep -a '"connector_id":"fcp.brave-search".*"result":"pass"' "${manifest_ops_jsonl}" >"${OUT_ROOT}/evidence/manifest_ops_brave_search.jsonl"; then
  manifest_ops_jsonl_status="passed"
else
  manifest_ops_jsonl_status="${manifest_ops_status}"
  if [[ "${manifest_ops_status}" == "passed" ]]; then
    manifest_ops_jsonl_status="failed"
    cat >"${OUT_ROOT}/evidence/manifest_ops_brave_search.jsonl" <<EOF
{"event":"brave_search_manifest_ops_missing_pass","status":"failed","reason":"manifest audit emitted no passing fcp.brave-search connector_scan entry","git_revision":"${git_revision}","log":"${OUT_ROOT}/logs/manifest_ops_audit.log","audit_jsonl":"${manifest_ops_jsonl}"}
EOF
    promote_overall_status failed
  fi
fi

capture_rch_cargo_step crate_suite_status crate_suite \
  "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
  "CARGO_TARGET_DIR=${TARGET_DIR}" \
  CARGO_INCREMENTAL=0 \
  cargo test -p fcp-brave-search -- --nocapture

capture_rch_cargo_step clippy_status clippy \
  "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
  "CARGO_TARGET_DIR=${TARGET_DIR}" \
  CARGO_INCREMENTAL=0 \
  cargo clippy -p fcp-brave-search --all-targets --no-deps -- -D warnings

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-brave-search",
  "connector_id": "fcp.brave-search",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/brave_search_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_dir": "${TARGET_DIR}",
  "runner": "${REMOTE_RUNNER}",
  "rch_require_remote": "${RCH_REQUIRE_REMOTE}",
  "proof_governor": "${PROOF_GOVERNOR}",
  "fwc_bin": "${FWC_BIN}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "fixture_modes": ["wiremock", "loopback_http", "live_read_only_or_structured_skip"],
  "live_mode": "FCP_LIVE_READ and BRAVE_SEARCH_API_KEY gated",
  "redaction": "no API keys, credential IDs, full provider payloads, private query text, provider error bodies, or sensitive result text are emitted; artifacts carry operation names, status, fixture mode, counts, and wrapper evidence"
}
EOF

cat >"${OUT_ROOT}/replay.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_ROOT}"
export RCH_FORCE_REMOTE=1
export RCH_REQUIRE_REMOTE="\${RCH_REQUIRE_REMOTE:-${RCH_REQUIRE_REMOTE}}"
RUN_ID="\${RUN_ID:-${RUN_ID}}" \\
OUT_ROOT="\${OUT_ROOT:-${OUT_ROOT}}" \\
FCP_BRAVE_SEARCH_TARGET_DIR="\${FCP_BRAVE_SEARCH_TARGET_DIR:-${TARGET_DIR}}" \\
RCH_BIN="\${RCH_BIN:-${RCH_BIN}}" \\
FWC_BIN="\${FWC_BIN:-${FWC_BIN}}" \\
PROOF_GOVERNOR="\${PROOF_GOVERNOR:-${PROOF_GOVERNOR}}" \\
REPO_TOOLCHAIN="\${REPO_TOOLCHAIN:-${REPO_TOOLCHAIN}}" \\
scripts/e2e/brave_search_connector_verification.sh
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-brave-search",
  "connector_id": "fcp.brave-search",
  "overall_status": "${OVERALL_STATUS}",
  "runner": "${REMOTE_RUNNER}",
  "proof_governor": "${PROOF_GOVERNOR}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "artifacts_root": "${OUT_ROOT}",
  "steps": {
    "manifest_check": "${manifest_status}",
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "integration_suite": "${integration_status}",
    "local_non_mock_jsonl": "${local_non_mock_status}",
    "local_non_mock_jsonl_extract": "${local_non_mock_jsonl_status}",
    "live_jsonl": "${live_status}",
    "live_jsonl_extract": "${live_jsonl_status}",
    "manifest_ops_audit": "${manifest_ops_status}",
    "manifest_ops_jsonl_extract": "${manifest_ops_jsonl_status}",
    "crate_suite": "${crate_suite_status}",
    "clippy": "${clippy_status}"
  },
  "artifacts": {
    "manifest_check": "${OUT_ROOT}/evidence/manifest_check.json",
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "integration_suite_log": "${OUT_ROOT}/logs/integration_suite.log",
    "local_non_mock_log": "${OUT_ROOT}/logs/local_non_mock_jsonl.log",
    "local_non_mock_jsonl": "${OUT_ROOT}/evidence/local_non_mock.jsonl",
    "live_log": "${OUT_ROOT}/logs/live_jsonl.log",
    "live_jsonl": "${OUT_ROOT}/evidence/live_smoke.jsonl",
    "manifest_ops_log": "${OUT_ROOT}/logs/manifest_ops_audit.log",
    "manifest_ops_jsonl": "${manifest_ops_jsonl}",
    "manifest_ops_brave_search_jsonl": "${OUT_ROOT}/evidence/manifest_ops_brave_search.jsonl",
    "proof_dir": "${OUT_ROOT}/proof",
    "crate_suite_log": "${OUT_ROOT}/logs/crate_suite.log",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "Brave Search verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
