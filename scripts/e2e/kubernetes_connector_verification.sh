#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-/tmp/fcp-kubernetes-e2e/${RUN_ID}}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-kubernetes-e2e-target}"
STATUS_JSONL="${OUT_ROOT}/evidence/verification_steps.jsonl"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
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

  if grep -Eqi 'RCH-E|remote required; refusing local fallback|rch command did not produce remote proof|\[RCH\] local|No space left on device|connection reset by peer|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response|missing worker system package|timeout: failed to execute process|not a valid fwc command|local_fallback_refused' "${log_path}"; then
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
    --arg schema_version "fcp-kubernetes-verification/v1" \
    --arg run_id "${RUN_ID}" \
    --arg connector "fcp-kubernetes" \
    --arg fixture_id "kubernetes-loopback-local-acceptance" \
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

  if grep -E '^\[RCH\][[:space:]]+remote[[:space:]]+' "${log_path}" \
    | grep -Ev '^\[RCH\][[:space:]]+remote[[:space:]]+required([;[:space:]]|$)' >/dev/null; then
    return 0
  fi

  echo "[kubernetes-verification] ${name}: rch command did not produce remote proof" >&2
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

  echo "[kubernetes-verification] ${name}: $*" >&2
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

  echo "[kubernetes-verification] graduation_gauntlet: scripts/graduation/run_gauntlet.sh --jsonl ${jsonl_path} connectors/kubernetes" >&2
  start_seconds="$(date -u +%s)"
  (
    cd "${REPO_ROOT}" || exit
    scripts/graduation/run_gauntlet.sh --jsonl "${jsonl_path}" connectors/kubernetes
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
    scripts/graduation/run_gauntlet.sh --jsonl "${jsonl_path}" connectors/kubernetes
}

run_no_match() {
  local name="$1"
  local pattern="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local start_seconds end_seconds duration_ms rc status

  echo "[kubernetes-verification] ${name}: rg ${pattern} $*" >&2
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

write_proof_corpus() {
  local name="$1"
  local corpus_path="$2"
  shift 2
  local claim_key="kubernetes-connector-verifier-${name}"
  local argv_json
  argv_json="$(json_array_from_args "$@")"
  jq -n \
    --arg claim_key "${claim_key}" \
    --arg purpose "Run Kubernetes connector verifier step ${name} through the fail-closed rch proof governor." \
    --argjson rerun_argv "${argv_json}" \
    '{
      schema: "fcp.proof-graph-indexer-corpus.v1",
      verification_scripts: [
        {
          claim_key: $claim_key,
          script_path: "scripts/e2e/kubernetes_connector_verification.sh",
          purpose: $purpose,
          rerun_argv: $rerun_argv,
          required_env_keys: [],
          source: {
            source_id: "kubernetes.connector.verifier",
            path: "scripts/e2e/kubernetes_connector_verification.sh",
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
  local claim_key="kubernetes-connector-verifier-${name}"
  local classification status rch_summary_line
  local start_seconds end_seconds duration_ms

  echo "[kubernetes-verification] ${name}: fwc proof run ${claim_key} --execute" >&2
  start_seconds="$(date -u +%s)"
  if ! require_cmd jq >"${log_path}" 2>&1; then
    end_seconds="$(date -u +%s)"
    duration_ms="$(((end_seconds - start_seconds) * 1000))"
    promote_status infra_blocked
    record_step "${name}" infra_blocked "${duration_ms}" "${log_path}" require_cmd jq
    return
  fi
  if ! require_cmd "${FWC_BIN}" >>"${log_path}" 2>&1; then
    end_seconds="$(date -u +%s)"
    duration_ms="$(((end_seconds - start_seconds) * 1000))"
    promote_status infra_blocked
    record_step "${name}" infra_blocked "${duration_ms}" "${log_path}" require_cmd "${FWC_BIN}"
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
  end_seconds="$(date -u +%s)"
  duration_ms="$(((end_seconds - start_seconds) * 1000))"
  record_step "${name}" "${status}" "${duration_ms}" "${log_path}" \
    "${FWC_BIN}" --json proof run "${claim_key}" --corpus "${corpus_path}" --execute
}

run_legacy_rch_cargo_step_with_remote_policy() {
  local require_remote_proof="$1"
  shift
  local name="$1"
  shift
  local rch_require_remote="${RCH_REQUIRE_REMOTE:-1}"

  if [[ "${require_remote_proof}" == "0" ]]; then
    rch_require_remote=0
  fi

  run_logged_with_remote_policy "${require_remote_proof}" "${name}" env \
    RCH_REQUIRE_REMOTE="${rch_require_remote}" \
    RCH_FORCE_REMOTE=1 \
    RCH_VISIBILITY=verbose \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    "$@"
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
  local name="$1"
  shift

  # `cargo fmt --check` validates source state; it is not accepted remote Cargo proof.
  run_rch_cargo_step_with_remote_policy 0 "${name}" "$@"
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
    connectors/kubernetes/README.md \
    connectors/kubernetes/manifest.toml \
    connectors/kubernetes/src/client.rs \
    connectors/kubernetes/src/connector.rs \
    connectors/kubernetes/src/types.rs \
    connectors/kubernetes/tests/integration.rs \
    connectors/kubernetes/tests/local_non_mock.rs \
    scripts/e2e/kubernetes_connector_verification.sh

run_no_match \
  readme_master_word_scan \
  '\bmaster\b' \
  connectors/kubernetes/README.md \
  scripts/e2e/kubernetes_connector_verification.sh

run_rch_cargo_step \
  cargo_check \
  cargo check -p fcp-kubernetes --all-targets

run_rch_cargo_step \
  unit_suite \
  cargo test -p fcp-kubernetes -- --nocapture

run_rch_cargo_step \
  integration_suite \
  cargo test -p fcp-kubernetes --test integration -- --nocapture

run_rch_cargo_step \
  local_non_mock_acceptance \
  cargo test -p fcp-kubernetes --test local_non_mock -- --nocapture

run_rch_format_step \
  format_check \
  cargo fmt -p fcp-kubernetes -- --check

run_rch_cargo_step \
  clippy \
  cargo clippy -p fcp-kubernetes --all-targets -- -D warnings

if grep -R -E 'test-k8s-token|Authorization: Bearer|X-FCP-Credential-Id|secret-value|password=' "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence" >/dev/null 2>&1; then
  echo "[kubernetes-verification] redaction scan failed" >&2
  promote_status failed
  record_step redaction_scan failed 0 "${OUT_ROOT}/logs/redaction_scan.log" grep -R -E redaction-patterns "${OUT_ROOT}"
else
  record_step redaction_scan passed 0 "${OUT_ROOT}/logs/redaction_scan.log" grep -R -E redaction-patterns "${OUT_ROOT}"
fi

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-kubernetes",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/kubernetes_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_dir": "${TARGET_DIR}",
  "rch_require_remote": "${RCH_REQUIRE_REMOTE}",
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "proof_governor_enabled": "${PROOF_GOVERNOR}",
  "proof_governor": "Cargo-backed verifier steps run through fwc proof run; accepted_remote_proof is the only passing rch proof classification. refused_local_fallback and infra_blocked keep the verifier non-green. format_check is a source-state check, not accepted remote Cargo proof.",
  "proof_artifacts": "${OUT_ROOT}/proof",
  "fixture_mode": "local loopback HTTP Kubernetes API fixture plus connector integration fixtures",
  "redaction": "logs and JSONL must not contain bearer tokens, credential IDs, raw Authorization headers, secret values, provider payload bodies, or private cluster material"
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
PROOF_GOVERNOR="${PROOF_GOVERNOR}" \\
FWC_BIN="${FWC_BIN}" \\
scripts/e2e/kubernetes_connector_verification.sh
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-kubernetes",
  "status": "${OVERALL_STATUS}",
  "exit_code": ${EXIT_CODE},
  "artifacts_root": "${OUT_ROOT}",
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "artifacts": {
    "status_jsonl": "${STATUS_JSONL}",
    "graduation_gauntlet": "${OUT_ROOT}/evidence/graduation_gauntlet.jsonl",
    "proof_governor_json": "${OUT_ROOT}/proof/*.proof.json",
    "proof_governor_jsonl": "${OUT_ROOT}/proof/*.rch_remote_proof.jsonl",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh",
    "logs": "${OUT_ROOT}/logs"
  }
}
EOF

echo "Kubernetes verification artifacts written to ${OUT_ROOT} (status=${OVERALL_STATUS})" >&2
exit "${EXIT_CODE}"
