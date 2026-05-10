#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/aws_bedrock/${RUN_ID}}"
RUN_MODE="${AWS_BEDROCK_VERIFY_MODE:-}"

usage() {
  cat <<'EOF'
Usage: scripts/e2e/aws_bedrock_connector_verification.sh [--mode replay|live]

Modes:
  replay  Run deterministic WireMock-backed evidence only. This is the default.
  live    Also run the gated live AWS Bedrock smoke test. Requires AWS_BEDROCK_* vars.

Legacy compatibility:
  AWS_BEDROCK_E2E=1 without --mode still selects live mode.
EOF
}

while (($#)); do
  case "$1" in
    --mode)
      if [[ $# -lt 2 ]]; then
        echo "--mode requires replay or live" >&2
        exit 64
      fi
      RUN_MODE="$2"
      shift 2
      ;;
    --mode=*)
      RUN_MODE="${1#--mode=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "${RUN_MODE}" ]]; then
  if [[ "${AWS_BEDROCK_E2E:-}" == "1" ]]; then
    RUN_MODE="live"
  else
    RUN_MODE="replay"
  fi
fi

case "${RUN_MODE}" in
  replay)
    unset AWS_BEDROCK_E2E
    ;;
  live)
    export AWS_BEDROCK_E2E=1
    ;;
  *)
    echo "invalid --mode: ${RUN_MODE}; expected replay or live" >&2
    exit 64
    ;;
esac

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0

manifest_status="pending"
cargo_check_status="pending"
format_check_status="pending"
integration_status="pending"
clippy_status="pending"
live_smoke_status="pending"
fixture_boundary_status="pending"
manifest_check_runner=""

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
  if grep -Eq 'timeout: failed to execute process|No such file or directory|RCH-E|missing worker|dbus-1\.pc|No space left on device' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"

  echo "[aws-bedrock-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}"
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
    promote_overall_status "${status}"
    echo "${status}"
  fi
}

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

FWC_MANIFEST_BIN="${FWC_MANIFEST_BIN:-fwc}"
if command -v "${FWC_MANIFEST_BIN}" >/dev/null 2>&1; then
  manifest_check_runner="local:${FWC_MANIFEST_BIN}"
  if run_logged \
    manifest_check \
    "${FWC_MANIFEST_BIN}" manifest fix connectors/aws-bedrock/manifest.toml --check --json
  then
    manifest_status="passed"
    cp "${OUT_ROOT}/logs/manifest_check.log" "${OUT_ROOT}/evidence/manifest_check.json"
  else
    manifest_status="$(classify_failure "${OUT_ROOT}/logs/manifest_check.log")"
    promote_overall_status "${manifest_status}"
    cat >"${OUT_ROOT}/evidence/manifest_check.json" <<EOF
{"schema_version":"1.0.0","status":"${manifest_status}","redaction_scope":"public","log":"${OUT_ROOT}/logs/manifest_check.log"}
EOF
  fi
else
  manifest_check_runner="rch:cargo-run"
  if run_logged \
    manifest_check \
    rch exec -- cargo run -q -p fwc -- manifest fix connectors/aws-bedrock/manifest.toml --check --json
  then
    manifest_status="passed"
    cp "${OUT_ROOT}/logs/manifest_check.log" "${OUT_ROOT}/evidence/manifest_check.json"
  else
    manifest_status="$(classify_failure "${OUT_ROOT}/logs/manifest_check.log")"
    promote_overall_status "${manifest_status}"
    cat >"${OUT_ROOT}/evidence/manifest_check.json" <<EOF
{"schema_version":"1.0.0","status":"${manifest_status}","redaction_scope":"public","log":"${OUT_ROOT}/logs/manifest_check.log"}
EOF
  fi
fi

cargo_check_status="$(run_step cargo_check rch exec -- cargo check -p fcp-aws-bedrock --all-targets)"
format_check_status="$(run_step format_check rch exec -- cargo fmt -p fcp-aws-bedrock -- --check)"
integration_status="$(run_step integration_suite rch exec -- cargo test -p fcp-aws-bedrock --test integration -- --nocapture)"
clippy_status="$(run_step clippy rch exec -- cargo clippy -p fcp-aws-bedrock --all-targets -- -D warnings)"

if grep -a '^AWS_BEDROCK_FIXTURE_JSONL ' "${OUT_ROOT}/logs/integration_suite.log" \
  | sed 's/^AWS_BEDROCK_FIXTURE_JSONL //' >"${OUT_ROOT}/evidence/fixture_boundary.jsonl"
then
  if [[ -s "${OUT_ROOT}/evidence/fixture_boundary.jsonl" ]]; then
    fixture_boundary_status="passed"
  else
    fixture_boundary_status="failed"
    cat >"${OUT_ROOT}/evidence/fixture_boundary.jsonl" <<EOF
{"schema_version":"1.0.0","event":"bedrock_fixture_missing_jsonl","status":"failed","reason":"integration suite emitted no AWS_BEDROCK_FIXTURE_JSONL records","git_revision":"${git_revision}","fixture_mode":"wiremock","redaction_scope":"public","log":"${OUT_ROOT}/logs/integration_suite.log"}
EOF
    if [[ "${integration_status}" == "passed" ]]; then
      promote_overall_status failed
    fi
  fi
else
  fixture_boundary_status="${integration_status}"
  cat >"${OUT_ROOT}/evidence/fixture_boundary.jsonl" <<EOF
{"schema_version":"1.0.0","event":"bedrock_fixture_missing_jsonl","status":"${fixture_boundary_status}","reason":"integration suite did not produce extractable AWS_BEDROCK_FIXTURE_JSONL records","git_revision":"${git_revision}","fixture_mode":"wiremock","redaction_scope":"public","log":"${OUT_ROOT}/logs/integration_suite.log"}
EOF
  if [[ "${integration_status}" == "passed" ]]; then
    fixture_boundary_status="failed"
    promote_overall_status failed
  fi
fi

if [[ "${RUN_MODE}" == "live" ]]; then
  live_smoke_status="$(run_step live_smoke rch exec -- cargo test -p fcp-aws-bedrock --test live_verification -- --nocapture)"
  if grep -a '^AWS_BEDROCK_E2E_JSONL ' "${OUT_ROOT}/logs/live_smoke.log" \
    | sed 's/^AWS_BEDROCK_E2E_JSONL //' >"${OUT_ROOT}/evidence/live_smoke.jsonl"
  then
    if grep -q '"status":"skipped"' "${OUT_ROOT}/evidence/live_smoke.jsonl"; then
      live_smoke_status="skipped"
    fi
  else
    cat >"${OUT_ROOT}/evidence/live_smoke.jsonl" <<EOF
{"schema_version":"1.0.0","event":"bedrock_live_smoke_missing_jsonl","status":"${live_smoke_status}","reason":"live verification command did not emit AWS_BEDROCK_E2E_JSONL records","git_revision":"${git_revision}","fixture_mode":"live","region":"${AWS_BEDROCK_REGION:-unset}","redaction_scope":"public","log":"${OUT_ROOT}/logs/live_smoke.log"}
EOF
    if [[ "${live_smoke_status}" == "passed" ]]; then
      live_smoke_status="failed"
      promote_overall_status failed
    fi
  fi
else
  live_smoke_status="skipped"
  cat >"${OUT_ROOT}/evidence/live_smoke.jsonl" <<EOF
{"schema_version":"1.0.0","event":"bedrock_live_smoke_skipped","status":"skipped","skip_reason":"verification mode is replay; pass --mode live with AWS_BEDROCK_* variables for real Bedrock proof","git_revision":"${git_revision}","fixture_mode":"wiremock","region":"${AWS_BEDROCK_REGION:-unset}","api_styles":["converse","converse_stream","invoke_model","invoke_model_stream","models.list"],"redaction_scope":"hashed","redaction":"no prompts, completions, AWS keys, session tokens, or full signatures are emitted"}
EOF
fi

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "schema_version": "1.0.0",
  "run_id": "${RUN_ID}",
  "connector": "fcp-aws-bedrock",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/aws_bedrock_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "verification_mode": "${RUN_MODE}",
  "manifest_check_runner": "${manifest_check_runner}",
  "aws_bedrock_e2e_enabled": "$([[ "${RUN_MODE}" == "live" ]] && echo true || echo false)"
}
EOF

cat >"${OUT_ROOT}/replay.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

FWC_MANIFEST_BIN="${FWC_MANIFEST_BIN:-fwc}"
if command -v "${FWC_MANIFEST_BIN}" >/dev/null 2>&1; then
  "${FWC_MANIFEST_BIN}" manifest fix connectors/aws-bedrock/manifest.toml --check --json
else
  rch exec -- cargo run -q -p fwc -- manifest fix connectors/aws-bedrock/manifest.toml --check --json
fi
rch exec -- cargo check -p fcp-aws-bedrock --all-targets
rch exec -- cargo fmt -p fcp-aws-bedrock -- --check
rch exec -- cargo test -p fcp-aws-bedrock --test integration -- --nocapture
rch exec -- cargo clippy -p fcp-aws-bedrock --all-targets -- -D warnings
if [[ "${AWS_BEDROCK_E2E:-}" == "1" ]]; then
  rch exec -- cargo test -p fcp-aws-bedrock --test live_verification -- --nocapture
fi
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "schema_version": "1.0.0",
  "run_id": "${RUN_ID}",
  "connector": "fcp-aws-bedrock",
  "verification_mode": "${RUN_MODE}",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "steps": {
    "manifest_check": "${manifest_status}",
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "integration_suite": "${integration_status}",
    "fixture_boundary": "${fixture_boundary_status}",
    "clippy": "${clippy_status}",
    "live_smoke": "${live_smoke_status}"
  },
  "artifacts": {
    "manifest_check": "${OUT_ROOT}/evidence/manifest_check.json",
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "integration_suite_log": "${OUT_ROOT}/logs/integration_suite.log",
    "fixture_boundary_jsonl": "${OUT_ROOT}/evidence/fixture_boundary.jsonl",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "live_smoke_jsonl": "${OUT_ROOT}/evidence/live_smoke.jsonl",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "AWS Bedrock verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
