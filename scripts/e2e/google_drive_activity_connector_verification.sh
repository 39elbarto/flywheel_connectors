#!/usr/bin/env bash
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-/home/ubuntu/.cache/fcp-google-docs-bd-2oc12}"
OUTPUT_DIR="${1:-/tmp/fcp-google-drive-activity-e2e/latest}"
EVIDENCE_DIR="${OUTPUT_DIR}/evidence"
mkdir -p "${EVIDENCE_DIR}"

declare -a STEP_NAMES=()
declare -a STEP_STATUSES=()

run_step() {
  local name="$1"
  shift
  STEP_NAMES+=("${name}")
  if (cd "${REPO_ROOT}" && "$@") >"${EVIDENCE_DIR}/${name}.log" 2>&1; then
    STEP_STATUSES+=("ok")
    printf 'ok   %s\n' "${name}"
  else
    STEP_STATUSES+=("failed")
    printf 'fail %s (see %s)\n' "${name}" "${EVIDENCE_DIR}/${name}.log" >&2
  fi
}

run_step manifest_check env CARGO_TARGET_DIR="${TARGET_DIR}" cargo run -q --locked -p fwc -- \
  manifest fix connectors/google-drive-activity/manifest.toml --check --json
run_step fmt_check cargo fmt --all -- --check
run_step cargo_check env CARGO_TARGET_DIR="${TARGET_DIR}" cargo check --locked -p fcp-google-drive-activity
run_step cargo_test env CARGO_TARGET_DIR="${TARGET_DIR}" cargo test --locked -p fcp-google-drive-activity
run_step cargo_clippy env CARGO_TARGET_DIR="${TARGET_DIR}" cargo clippy --locked -p fcp-google-drive-activity --all-targets -- -D warnings
run_step read_only_surface bash -c \
  '! rg -n "(delete|update|create|watch|raw_request)" connectors/google-drive-activity/manifest.toml | rg "provides.operations"'

overall="ok"
for status in "${STEP_STATUSES[@]}"; do
  if [[ "${status}" != "ok" ]]; then overall="failed"; fi
done

steps_json='[]'
for index in "${!STEP_NAMES[@]}"; do
  steps_json="$(jq -c \
    --arg name "${STEP_NAMES[$index]}" \
    --arg status "${STEP_STATUSES[$index]}" \
    '. + [{name:$name,status:$status}]' <<<"${steps_json}")"
done
jq -n \
  --arg overall_status "${overall}" \
  --arg connector "google-drive-activity" \
  --arg target_dir "${TARGET_DIR}" \
  --argjson steps "${steps_json}" \
  '{overall_status:$overall_status,connector:$connector,offline_only:true,target_dir:$target_dir,steps:$steps}' \
  >"${OUTPUT_DIR}/summary.json"

printf 'summary: %s\n' "${OUTPUT_DIR}/summary.json"
[[ "${overall}" == "ok" ]]
