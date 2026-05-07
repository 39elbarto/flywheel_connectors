#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/comfyui/${RUN_ID}}"
TARGET_DIR="${FCP_COMFYUI_TARGET_DIR:-/tmp/fcp-comfyui-e2e}"
RCH_BIN="${RCH_BIN:-rch}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0

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
  if grep -Eq 'timeout: failed to execute process|RCH-E|missing worker|No space left on device|dbus-1\.pc|connection reset by peer' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"

  echo "[comfyui-verification] ${name}: $*" >&2
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
manifest_check_runner=""
if command -v "${FWC_MANIFEST_BIN}" >/dev/null 2>&1; then
  manifest_check_runner="local:${FWC_MANIFEST_BIN}"
  if run_logged manifest_check "${FWC_MANIFEST_BIN}" manifest fix connectors/comfyui/manifest.toml --check --json; then
    manifest_status="passed"
    cp "${OUT_ROOT}/logs/manifest_check.log" "${OUT_ROOT}/evidence/manifest_check.json"
  else
    manifest_status="$(classify_failure "${OUT_ROOT}/logs/manifest_check.log")"
    promote_overall_status "${manifest_status}"
    cat >"${OUT_ROOT}/evidence/manifest_check.json" <<EOF
{"status":"${manifest_status}","log":"${OUT_ROOT}/logs/manifest_check.log"}
EOF
  fi
else
  manifest_check_runner="rch:cargo-run"
  if run_logged manifest_check "${RCH_BIN}" exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" cargo run -q -p fwc -- manifest fix connectors/comfyui/manifest.toml --check --json; then
    manifest_status="passed"
    cp "${OUT_ROOT}/logs/manifest_check.log" "${OUT_ROOT}/evidence/manifest_check.json"
  else
    manifest_status="$(classify_failure "${OUT_ROOT}/logs/manifest_check.log")"
    promote_overall_status "${manifest_status}"
    cat >"${OUT_ROOT}/evidence/manifest_check.json" <<EOF
{"status":"${manifest_status}","log":"${OUT_ROOT}/logs/manifest_check.log"}
EOF
  fi
fi

cargo_check_status="$(run_step cargo_check "${RCH_BIN}" exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" cargo check -p fcp-comfyui --all-targets)"
format_check_status="$(run_step format_check "${RCH_BIN}" exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" cargo fmt --package fcp-comfyui --check)"
loopback_status="$(run_step loopback_jsonl "${RCH_BIN}" exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" COMFYUI_E2E_GIT_REVISION="${git_revision}" cargo test -p fcp-comfyui --test integration comfyui_loopback_e2e_jsonl_matrix -- --nocapture)"
live_status="$(run_step live_jsonl "${RCH_BIN}" exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" COMFYUI_E2E_GIT_REVISION="${git_revision}" cargo test -p fcp-comfyui --test live_verification comfyui_live_health_or_structured_skip_jsonl -- --nocapture)"
clippy_status="$(run_step clippy "${RCH_BIN}" exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" cargo clippy -p fcp-comfyui --all-targets --no-deps -- -D warnings)"

fixture_jsonl_status="${loopback_status}"
if grep -a '^COMFYUI_E2E_JSONL ' "${OUT_ROOT}/logs/loopback_jsonl.log" \
  | sed 's/^COMFYUI_E2E_JSONL //' \
  | grep -a '"fixture_mode":"wiremock"' >"${OUT_ROOT}/evidence/loopback_fixtures.jsonl"
then
  if [[ -s "${OUT_ROOT}/evidence/loopback_fixtures.jsonl" ]]; then
    fixture_jsonl_status="passed"
  fi
fi

live_jsonl_status="${live_status}"
if grep -a '^COMFYUI_E2E_JSONL ' "${OUT_ROOT}/logs/live_jsonl.log" \
  | sed 's/^COMFYUI_E2E_JSONL //' \
  | grep -a '"fixture_mode":"live"' >"${OUT_ROOT}/evidence/live_health.jsonl"
then
  if [[ -s "${OUT_ROOT}/evidence/live_health.jsonl" ]]; then
    live_jsonl_status="passed"
  fi
fi

redaction_status="passed"
if grep -E 'comfy-secret|COMFYUI_AUTHORIZATION_HEADER|private prompt|workflow":|output.png' \
  "${OUT_ROOT}/evidence/loopback_fixtures.jsonl" "${OUT_ROOT}/evidence/live_health.jsonl" >/dev/null 2>&1
then
  redaction_status="failed"
  promote_overall_status failed
fi

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-comfyui",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/comfyui_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_dir": "${TARGET_DIR}",
  "manifest_check_runner": "${manifest_check_runner}",
  "rch_bin": "${RCH_BIN}",
  "fixture_mode": "wiremock",
  "live_mode": "COMFYUI_BASE_URL gated",
  "redaction": "JSONL carries base-url class, prompt id hash, workflow fixture id, operation, output count, HTTP status, retry decision, cleanup result, and skip reason; it never emits workflow JSON, prompt text, auth headers, full base URLs, or full artifact URLs"
}
EOF

cat >"${OUT_ROOT}/replay.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="\${FCP_COMFYUI_TARGET_DIR:-${TARGET_DIR}}"
RCH_BIN="\${RCH_BIN:-${RCH_BIN}}"
FWC_MANIFEST_BIN="\${FWC_MANIFEST_BIN:-fwc}"
if command -v "\${FWC_MANIFEST_BIN}" >/dev/null 2>&1; then
  "\${FWC_MANIFEST_BIN}" manifest fix connectors/comfyui/manifest.toml --check --json
else
  "\${RCH_BIN}" exec -- env CARGO_TARGET_DIR="\${TARGET_DIR}" cargo run -q -p fwc -- manifest fix connectors/comfyui/manifest.toml --check --json
fi
"\${RCH_BIN}" exec -- env CARGO_TARGET_DIR="\${TARGET_DIR}" cargo check -p fcp-comfyui --all-targets
"\${RCH_BIN}" exec -- env CARGO_TARGET_DIR="\${TARGET_DIR}" cargo fmt --package fcp-comfyui --check
git_revision="\$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
"\${RCH_BIN}" exec -- env CARGO_TARGET_DIR="\${TARGET_DIR}" COMFYUI_E2E_GIT_REVISION="\${git_revision}" cargo test -p fcp-comfyui --test integration comfyui_loopback_e2e_jsonl_matrix -- --nocapture
"\${RCH_BIN}" exec -- env CARGO_TARGET_DIR="\${TARGET_DIR}" COMFYUI_E2E_GIT_REVISION="\${git_revision}" cargo test -p fcp-comfyui --test live_verification comfyui_live_health_or_structured_skip_jsonl -- --nocapture
"\${RCH_BIN}" exec -- env CARGO_TARGET_DIR="\${TARGET_DIR}" cargo clippy -p fcp-comfyui --all-targets --no-deps -- -D warnings
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-comfyui",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "steps": {
    "manifest_check": "${manifest_status}",
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "loopback_jsonl": "${loopback_status}",
    "fixture_jsonl": "${fixture_jsonl_status}",
    "live_jsonl": "${live_status}",
    "live_jsonl_extract": "${live_jsonl_status}",
    "clippy": "${clippy_status}",
    "redaction": "${redaction_status}"
  },
  "artifacts": {
    "manifest_check": "${OUT_ROOT}/evidence/manifest_check.json",
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "loopback_log": "${OUT_ROOT}/logs/loopback_jsonl.log",
    "loopback_jsonl": "${OUT_ROOT}/evidence/loopback_fixtures.jsonl",
    "live_log": "${OUT_ROOT}/logs/live_jsonl.log",
    "live_jsonl": "${OUT_ROOT}/evidence/live_health.jsonl",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "ComfyUI verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
