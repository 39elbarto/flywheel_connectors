#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/bootstrap_hardware_token/${RUN_ID}}"
MISSING_PROVIDER_PATH="${FCP_BOOTSTRAP_MISSING_PROVIDER_PATH:-/definitely/missing/fcp-bootstrap-provider.so}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0
cargo_check_status="pending"
missing_provider_status="pending"
configured_provider_status="skipped"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"

  echo "[bootstrap-hardware-token] ${name}: $*"
  (
    cd "${REPO_ROOT}"
    "$@"
  ) >"${log_path}" 2>&1
}

run_capture_stdout() {
  local name="$1"
  local stdout_path="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"

  echo "[bootstrap-hardware-token] ${name}: $*"
  (
    cd "${REPO_ROOT}"
    "$@"
  ) >"${stdout_path}" 2>"${log_path}"
}

promote_failure() {
  OVERALL_STATUS="failed"
  EXIT_CODE=1
}

extract_report_json() {
  local stdout_path="$1"
  local json_path="$2"

  if ! grep '^HARDWARE_TOKEN_REPORT_JSON=' "${stdout_path}" | tail -n 1 | sed 's/^HARDWARE_TOKEN_REPORT_JSON=//' >"${json_path}"; then
    echo "{\"status\":\"failed\",\"reason\":\"report marker not found\",\"stdout\":\"${stdout_path}\"}" >"${json_path}"
    return 1
  fi
}

summarize_report() {
  local report_path="$1"
  local summary_path="$2"

  jq '{
    provider_count: (.providers | length),
    providers: (
      .providers
      | map({
          provider,
          token_count: (.tokens | length),
          slots: (.tokens | map(.slot)),
          candidate_labels: (.tokens | map(.label)),
          issues: (.issues | map({stage, slot, message}))
        })
    )
  }' "${report_path}" >"${summary_path}"
}

require_cmd rch
require_cmd jq

if run_logged \
  cargo_check \
  rch exec -- cargo check -p fcp-bootstrap --all-targets
then
  cargo_check_status="passed"
else
  cargo_check_status="failed"
  promote_failure
fi

missing_stdout="${OUT_ROOT}/evidence/missing_provider_report.stdout"
missing_json="${OUT_ROOT}/evidence/missing_provider_report.json"
missing_summary="${OUT_ROOT}/evidence/missing_provider_summary.json"

if run_capture_stdout \
  missing_provider_report \
  "${missing_stdout}" \
  env FCP_BOOTSTRAP_PKCS11_PROVIDER="${MISSING_PROVIDER_PATH}" \
  rch exec -- cargo test -p fcp-bootstrap --test no_mock_integration token_detector_env_report_emits_json -- --nocapture
then
  extract_report_json "${missing_stdout}" "${missing_json}"
  summarize_report "${missing_json}" "${missing_summary}"
  missing_provider_status="passed"
else
  missing_provider_status="failed"
  echo "{\"status\":\"failed\",\"reason\":\"missing-provider discovery command failed\",\"log\":\"${OUT_ROOT}/logs/missing_provider_report.log\"}" >"${missing_json}"
  promote_failure
fi

configured_stdout="${OUT_ROOT}/evidence/configured_provider_report.stdout"
configured_json="${OUT_ROOT}/evidence/configured_provider_report.json"
configured_summary="${OUT_ROOT}/evidence/configured_provider_summary.json"

if [[ -n "${FCP_BOOTSTRAP_PKCS11_PROVIDER:-}" ]]; then
  if run_capture_stdout \
    configured_provider_report \
    "${configured_stdout}" \
    env FCP_BOOTSTRAP_PKCS11_PROVIDER="${FCP_BOOTSTRAP_PKCS11_PROVIDER}" \
    FCP_BOOTSTRAP_EXPECT_TOKEN="${FCP_BOOTSTRAP_EXPECT_TOKEN:-0}" \
    rch exec -- cargo test -p fcp-bootstrap --test no_mock_integration token_detector_env_report_emits_json -- --nocapture
  then
    extract_report_json "${configured_stdout}" "${configured_json}"
    summarize_report "${configured_json}" "${configured_summary}"
    configured_provider_status="passed"
  else
    configured_provider_status="failed"
    echo "{\"status\":\"failed\",\"reason\":\"configured-provider discovery command failed\",\"log\":\"${OUT_ROOT}/logs/configured_provider_report.log\"}" >"${configured_json}"
    promote_failure
  fi
else
  cat > "${configured_json}" <<EOF
{
  "status": "skipped",
  "reason": "Set FCP_BOOTSTRAP_PKCS11_PROVIDER to capture real provider/slot candidates"
}
EOF
fi

cat > "${OUT_ROOT}/evidence/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "overall_status": "${OVERALL_STATUS}",
  "cargo_check_status": "${cargo_check_status}",
  "missing_provider_status": "${missing_provider_status}",
  "configured_provider_status": "${configured_provider_status}",
  "artifacts": {
    "missing_provider_report": "${missing_json}",
    "missing_provider_summary": "${missing_summary}",
    "configured_provider_report": "${configured_json}",
    "configured_provider_summary": "${configured_summary}"
  }
}
EOF

cat > "${OUT_ROOT}/BUNDLE_MANIFEST.json" <<EOF
{
  "schema_version": "asupersync-forensics/v1",
  "run_id": "${RUN_ID}",
  "scenario_id": "asupersync.e2e.bootstrap_hardware_token_discovery",
  "bundle_root": "${OUT_ROOT}",
  "artifacts": [
    {"name": "logs/cargo_check.log", "type": "cargo_check_log", "required": true},
    {"name": "logs/missing_provider_report.log", "type": "command_log", "required": true},
    {"name": "evidence/missing_provider_report.json", "type": "discovery_report", "required": true},
    {"name": "evidence/missing_provider_summary.json", "type": "summary", "required": true},
    {"name": "evidence/configured_provider_report.json", "type": "discovery_report", "required": false},
    {"name": "evidence/configured_provider_summary.json", "type": "summary", "required": false},
    {"name": "evidence/summary.json", "type": "summary", "required": true},
    {"name": "replay.sh", "type": "replay_script", "required": true}
  ]
}
EOF

cat > "${OUT_ROOT}/replay.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "${REPO_ROOT}"
OUT_ROOT="${OUT_ROOT}" RUN_ID="${RUN_ID}" FCP_BOOTSTRAP_MISSING_PROVIDER_PATH="${MISSING_PROVIDER_PATH}" bash scripts/e2e/bootstrap_hardware_token_discovery.sh
EOF
chmod +x "${OUT_ROOT}/replay.sh"

echo "Bootstrap hardware-token discovery evidence bundle: ${OUT_ROOT}"
echo "  cargo_check_status=${cargo_check_status}"
echo "  missing_provider_status=${missing_provider_status}"
echo "  configured_provider_status=${configured_provider_status}"

exit "${EXIT_CODE}"
