#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCHEMA_VERSION="mesh-cutover-gates-3node-harness/v1"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT="${OUT_ROOT:-}"
HOSTS_RAW="${FCP_CUTOVER_GATE_HOSTS:-}"
FWC_CMD="${FWC_CMD:-fwc}"
DRY_RUN=false

usage() {
  cat <<'EOF'
Usage: scripts/e2e/cutover_gates_3node.sh [options]

Runs the mesh-native cutover-gates proof against three real host endpoints.

Options:
  --hosts <h1,h2,h3>     Comma or space separated fcp-host admin endpoints.
                          Defaults to FCP_CUTOVER_GATE_HOSTS.
  --fwc-cmd <command>    fwc command to run. Defaults to FWC_CMD or "fwc".
  --run-id <id>          Stable run identifier. Defaults to UTC timestamp.
  --out-root <path>      Artifact root. Defaults to artifacts/e2e/mesh_cutover_gates_3node/<run-id>.
  --dry-run              Emit a structured skip artifact without probing hosts.
  -h, --help             Show this help.
EOF
}

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

now_ms() {
  local now
  now=$(date +%s%3N 2>/dev/null || true)
  if [[ -z "${now}" || "${now}" == *N ]]; then
    now="$(date +%s)000"
  fi
  printf '%s' "${now}"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

hash256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256
    return 0
  fi
  echo "Missing required command: sha256sum/shasum/openssl" >&2
  exit 1
}

hash_text() {
  printf '%s' "$1" | hash256 | awk '{print $1}'
}

record_step() {
  local step="$1" outcome="$2" reason="$3" elapsed_ms="$4" host_index="$5" host_hash="$6" artifact_path="$7"

  jq -c -n \
    --arg schema_version "${SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg timestamp "$(now_iso)" \
    --arg step "${step}" \
    --arg outcome "${outcome}" \
    --arg reason "${reason}" \
    --arg host_hash "${host_hash}" \
    --arg artifact_path "${artifact_path}" \
    --argjson elapsed_ms "${elapsed_ms}" \
    --argjson host_index "${host_index}" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      timestamp: $timestamp,
      script: "scripts/e2e/cutover_gates_3node.sh",
      step: $step,
      host_index: $host_index,
      host_hash: (if $host_hash == "" then null else $host_hash end),
      outcome: $outcome,
      reason: (if $reason == "" then null else $reason end),
      elapsed_ms: $elapsed_ms,
      artifact_path: (if $artifact_path == "" then null else $artifact_path end),
      redaction_scope: "hashed-host-endpoints"
    }' >> "${STEPS_JSONL}"
}

write_summary() {
  local status="$1" reason="$2"
  shift 2

  local host_files=("$@")
  if [[ ${#host_files[@]} -eq 0 ]]; then
    jq -c -n \
      --arg schema_version "${SCHEMA_VERSION}" \
      --arg run_id "${RUN_ID}" \
      --arg timestamp "$(now_iso)" \
      --arg status "${status}" \
      --arg reason "${reason}" \
      --arg steps_jsonl "${STEPS_JSONL}" \
      '{
        schema_version: $schema_version,
        run_id: $run_id,
        timestamp: $timestamp,
        status: $status,
        reason: (if $reason == "" then null else $reason end),
        required_hosts: 3,
        host_count: 0,
        hosts: [],
        steps_jsonl: $steps_jsonl,
        pass_condition: "exactly three host endpoints and every host reports fwc mesh cutover-gates overall_status=green with all four gates green"
      }' > "${SUMMARY_JSON}"
    return 0
  fi

  jq -s \
    --arg schema_version "${SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg timestamp "$(now_iso)" \
    --arg status "${status}" \
    --arg reason "${reason}" \
    --arg steps_jsonl "${STEPS_JSONL}" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      timestamp: $timestamp,
      status: $status,
      reason: (if $reason == "" then null else $reason end),
      required_hosts: 3,
      host_count: length,
      hosts: .,
      steps_jsonl: $steps_jsonl,
      pass_condition: "exactly three host endpoints and every host reports fwc mesh cutover-gates overall_status=green with all four gates green"
    }' "${host_files[@]}" > "${SUMMARY_JSON}"
}

write_replay() {
  cat > "${REPLAY_SH}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "${REPO_ROOT}"
FCP_CUTOVER_GATE_HOSTS='${HOSTS_RAW}' FWC_CMD='${FWC_CMD}' \\
  bash scripts/e2e/cutover_gates_3node.sh --run-id '${RUN_ID}' --out-root '${OUT_ROOT}'
EOF
  chmod +x "${REPLAY_SH}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hosts)
      HOSTS_RAW="${2:?--hosts requires a value}"
      shift 2
      ;;
    --fwc-cmd)
      FWC_CMD="${2:?--fwc-cmd requires a value}"
      shift 2
      ;;
    --run-id)
      RUN_ID="${2:?--run-id requires a value}"
      shift 2
      ;;
    --out-root)
      OUT_ROOT="${2:?--out-root requires a value}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/e2e/mesh_cutover_gates_3node/${RUN_ID}"
fi

STEPS_JSONL="${OUT_ROOT}/steps.jsonl"
SUMMARY_JSON="${OUT_ROOT}/summary.json"
REPLAY_SH="${OUT_ROOT}/replay.sh"

mkdir -p "${OUT_ROOT}/hosts"
printf '' > "${STEPS_JSONL}"

require_cmd jq
write_replay

if [[ "${DRY_RUN}" == true ]]; then
  record_step "dry_run" "skipped" "dry-run requested; no host endpoints probed" 0 0 "" ""
  write_summary "skipped" "dry-run requested; no host endpoints probed"
  echo "Mesh cutover-gates 3-node harness skipped: dry run. Summary: ${SUMMARY_JSON}"
  exit 0
fi

HOSTS_RAW="${HOSTS_RAW//,/ }"
read -r -a HOSTS <<< "${HOSTS_RAW}"

if [[ ${#HOSTS[@]} -eq 0 ]]; then
  record_step "host_configuration" "skipped" "FCP_CUTOVER_GATE_HOSTS or --hosts is required for live 3-node proof" 0 0 "" ""
  write_summary "skipped" "FCP_CUTOVER_GATE_HOSTS or --hosts is required for live 3-node proof"
  echo "Mesh cutover-gates 3-node harness skipped: no hosts configured. Summary: ${SUMMARY_JSON}"
  exit 0
fi

if [[ ${#HOSTS[@]} -ne 3 ]]; then
  record_step "host_configuration" "failed" "exactly three host endpoints are required" 0 0 "" ""
  write_summary "failed" "exactly three host endpoints are required"
  echo "Expected exactly three host endpoints, got ${#HOSTS[@]}. Summary: ${SUMMARY_JSON}" >&2
  exit 2
fi

read -r -a FWC_CMD_ARR <<< "${FWC_CMD}"
require_cmd "${FWC_CMD_ARR[0]}"

declare -a HOST_VERDICTS=()
overall="passed"
overall_reason=""

for idx in "${!HOSTS[@]}"; do
  host="${HOSTS[$idx]}"
  host_number=$((idx + 1))
  host_hash="$(hash_text "${host}")"
  payload_path="${OUT_ROOT}/hosts/host_${host_number}_payload.json"
  stderr_path="${OUT_ROOT}/hosts/host_${host_number}_stderr.log"
  verdict_path="${OUT_ROOT}/hosts/host_${host_number}_verdict.json"

  start_ms="$(now_ms)"
  set +e
  "${FWC_CMD_ARR[@]}" --json --host "${host}" mesh cutover-gates > "${payload_path}" 2> "${stderr_path}"
  rc=$?
  set -e
  end_ms="$(now_ms)"
  elapsed_ms=$((end_ms - start_ms))

  if [[ ${rc} -ne 0 ]]; then
    record_step "probe_host" "failed" "fwc exited nonzero" "${elapsed_ms}" "${host_number}" "${host_hash}" "${payload_path}"
    jq -c -n \
      --arg host_hash "${host_hash}" \
      --arg payload_path "${payload_path}" \
      --arg stderr_path "${stderr_path}" \
      --arg status "failed" \
      --arg reason "fwc exited nonzero" \
      --argjson host_index "${host_number}" \
      --argjson exit_code "${rc}" \
      '{host_index:$host_index,host_hash:$host_hash,status:$status,reason:$reason,exit_code:$exit_code,payload_path:$payload_path,stderr_path:$stderr_path}' \
      > "${verdict_path}"
    HOST_VERDICTS+=("${verdict_path}")
    overall="failed"
    overall_reason="one or more host probes failed"
    continue
  fi

  if jq -e '
      .schema_version == "1.2.0"
      and .subcommand == "cutover-gates"
      and .overall_status == "green"
      and .gate_count == 4
      and ((.gates // []) | length == 4)
      and ((.gates // []) | all(.status == "green"))
      and (.live_telemetry.reason_code == "direct-cutover-telemetry-available")
    ' "${payload_path}" >/dev/null; then
    record_step "probe_host" "passed" "" "${elapsed_ms}" "${host_number}" "${host_hash}" "${payload_path}"
    jq -c \
      --arg host_hash "${host_hash}" \
      --arg payload_path "${payload_path}" \
      --arg status "passed" \
      --arg reason "" \
      --argjson host_index "${host_number}" \
      '{
        host_index: $host_index,
        host_hash: $host_hash,
        status: $status,
        reason: null,
        payload_path: $payload_path,
        schema_version,
        data_hash,
        overall_status,
        gate_statuses: [.gates[] | {gate_id, status}]
      }' "${payload_path}" > "${verdict_path}"
  else
    record_step "probe_host" "failed" "host cutover-gates payload was not green for all four gates" "${elapsed_ms}" "${host_number}" "${host_hash}" "${payload_path}"
    jq -c \
      --arg host_hash "${host_hash}" \
      --arg payload_path "${payload_path}" \
      --arg status "failed" \
      --arg reason "host cutover-gates payload was not green for all four gates" \
      --argjson host_index "${host_number}" \
      '{
        host_index: $host_index,
        host_hash: $host_hash,
        status: $status,
        reason: $reason,
        payload_path: $payload_path,
        schema_version: (.schema_version // null),
        data_hash: (.data_hash // null),
        overall_status: (.overall_status // null),
        live_telemetry: (.live_telemetry // null),
        gate_statuses: [(.gates // [])[] | {gate_id, status}]
      }' "${payload_path}" > "${verdict_path}"
    overall="failed"
    overall_reason="one or more hosts did not report all four cutover gates green"
  fi

  HOST_VERDICTS+=("${verdict_path}")
done

write_summary "${overall}" "${overall_reason}" "${HOST_VERDICTS[@]}"

if [[ "${overall}" == "passed" ]]; then
  echo "Mesh cutover-gates 3-node harness passed. Summary: ${SUMMARY_JSON}"
  exit 0
fi

echo "Mesh cutover-gates 3-node harness failed. Summary: ${SUMMARY_JSON}" >&2
exit 1
