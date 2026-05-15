#!/usr/bin/env bash
# Validate mesh cutover gates against three live fcp-host endpoints.
#
# This harness is intentionally live-only for green proof: it does not start
# hosts, does not synthesize telemetry, and does not treat missing endpoints as
# success. Use --dry-run to write the planned evidence bundle without probing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_NAME="mesh_cutover_gates_3node"
SCHEMA_VERSION="fcp-mesh-cutover-gates-3node/v1"

RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-}"
HOSTS_CSV="${FCP_CUTOVER_GATE_HOSTS:-}"
DRY_RUN=false

usage() {
  cat <<'EOF'
Usage: scripts/e2e/mesh_cutover_gates_3node.sh [options]

Validates `fwc --host <endpoint> mesh cutover-gates --json` against a
three-node live mesh. The run passes only when each supplied host reports all
four stable cutover gates green and all hosts agree on the same gate data_hash.

Options:
  --hosts <csv>       Comma-separated fcp-host endpoints. Requires at least 3.
                      Env fallback: FCP_CUTOVER_GATE_HOSTS.
  --run-id <id>       Stable run id. Env fallback: RUN_ID.
  --out-root <path>   Evidence root. Env fallback: OUT_ROOT.
  --dry-run           Write a planned bundle without contacting hosts.
  -h, --help          Show this help.
EOF
}

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

now_ms() {
  local now
  now="$(date +%s%3N 2>/dev/null || true)"
  if [[ -z "${now}" || "${now}" == *N ]]; then
    now="$(date +%s)000"
  fi
  printf '%s' "${now}"
}

hash_value() {
  local value="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "${value}" | sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s' "${value}" | shasum -a 256 | awk '{print $1}'
  else
    printf '%s' "${value}" | openssl dgst -sha256 | awk '{print $NF}'
  fi
}

run_fwc() {
  if [[ -n "${FWC_BIN:-}" ]]; then
    "${FWC_BIN}" "$@"
  elif command -v fwc >/dev/null 2>&1; then
    fwc "$@"
  else
    (cd "${REPO_ROOT}" && cargo run -q -p fwc -- "$@")
  fi
}

record_log() {
  local step="$1" result="$2" duration_ms="$3" details_json="$4"
  jq -c -n \
    --arg timestamp "$(now_iso)" \
    --arg script "${SCRIPT_NAME}" \
    --arg step "${step}" \
    --arg correlation_id "${RUN_ID}" \
    --argjson duration_ms "${duration_ms}" \
    --arg result "${result}" \
    --argjson details "${details_json}" \
    '{
      timestamp: $timestamp,
      log_version: "v1",
      script: $script,
      step: $step,
      correlation_id: $correlation_id,
      duration_ms: $duration_ms,
      result: $result,
      details: $details
    }' >> "${LOG_JSONL}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hosts)
      HOSTS_CSV="${2:-}"
      shift 2
      ;;
    --run-id)
      RUN_ID="${2:-}"
      shift 2
      ;;
    --out-root)
      OUT_ROOT="${2:-}"
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
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/mesh-cutover-gates/3node/${RUN_ID}"
fi

mkdir -p "${OUT_ROOT}/hosts"
LOG_JSONL="${LOG_JSONL:-${OUT_ROOT}/mesh_cutover_gates_3node.jsonl}"
SUMMARY_JSON="${OUT_ROOT}/summary.json"
MANIFEST_JSON="${OUT_ROOT}/manifest.json"
REPLAY_SH="${OUT_ROOT}/replay.sh"
: > "${LOG_JSONL}"

if ! command -v jq >/dev/null 2>&1; then
  echo "Missing required command: jq" >&2
  exit 2
fi

IFS=',' read -r -a RAW_HOSTS <<< "${HOSTS_CSV}"
HOSTS=()
for host in "${RAW_HOSTS[@]}"; do
  host="${host#"${host%%[![:space:]]*}"}"
  host="${host%"${host##*[![:space:]]}"}"
  if [[ -n "${host}" ]]; then
    HOSTS+=("${host}")
  fi
done

if [[ "${DRY_RUN}" == "true" ]]; then
  host_count="${#HOSTS[@]}"
  jq -n \
    --arg schema_version "${SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg status "planned" \
    --argjson host_count "${host_count}" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      status: $status,
      host_count: $host_count,
      required_hosts: 3,
      proof_contract: "Run without --dry-run and provide at least three live host endpoints; green proof requires every host to report four green gates and the same data_hash."
    }' > "${SUMMARY_JSON}"
  record_log "plan" "pass" 0 "$(jq -c '.' "${SUMMARY_JSON}")"
  printf 'planned: %s\n' "${SUMMARY_JSON}"
  exit 0
fi

if [[ "${#HOSTS[@]}" -lt 3 ]]; then
  details="$(jq -n \
    --arg reason "missing-hosts" \
    --argjson host_count "${#HOSTS[@]}" \
    '{reason: $reason, host_count: $host_count, required_hosts: 3}')"
  record_log "preflight" "fail" 0 "${details}"
  echo "Expected at least three host endpoints via --hosts or FCP_CUTOVER_GATE_HOSTS." >&2
  exit 2
fi

start_ms="$(now_ms)"
host_summaries=()
expected_data_hash=""
failures=0

for index in "${!HOSTS[@]}"; do
  host="${HOSTS[$index]}"
  ordinal=$((index + 1))
  host_hash="sha256:$(hash_value "${host}")"
  output_path="${OUT_ROOT}/hosts/host_${ordinal}.json"
  host_start_ms="$(now_ms)"

  if ! run_fwc --json --host "${host}" mesh cutover-gates > "${output_path}"; then
    failures=$((failures + 1))
    elapsed=$(( $(now_ms) - host_start_ms ))
    details="$(jq -n \
      --arg host_hash "${host_hash}" \
      --arg output_path "${output_path}" \
      '{host_hash: $host_hash, output_path: $output_path, reason: "fwc-command-failed"}')"
    record_log "probe-host-${ordinal}" "fail" "${elapsed}" "${details}"
    host_summaries+=("${details}")
    continue
  fi

  schema_version="$(jq -r '.schema_version // ""' "${output_path}")"
  overall_status="$(jq -r '.overall_status // ""' "${output_path}")"
  gate_count="$(jq -r '.gate_count // 0' "${output_path}")"
  data_hash="$(jq -r '.data_hash // ""' "${output_path}")"
  green_count="$(jq '[.gates[]? | select(.status == "green")] | length' "${output_path}")"
  direct_available="$(jq -r '.live_telemetry.direct_gate_telemetry_available // false' "${output_path}")"

  host_status="pass"
  reason=""
  if [[ "${schema_version}" != "1.2.0" ]]; then
    host_status="fail"
    reason="unexpected-schema-version"
  elif [[ "${overall_status}" != "green" ]]; then
    host_status="fail"
    reason="overall-not-green"
  elif [[ "${gate_count}" != "4" || "${green_count}" != "4" ]]; then
    host_status="fail"
    reason="not-all-gates-green"
  elif [[ "${direct_available}" != "true" ]]; then
    host_status="fail"
    reason="direct-telemetry-unavailable"
  elif [[ -n "${expected_data_hash}" && "${data_hash}" != "${expected_data_hash}" ]]; then
    host_status="fail"
    reason="data-hash-mismatch"
  fi

  if [[ -z "${expected_data_hash}" ]]; then
    expected_data_hash="${data_hash}"
  fi

  if [[ "${host_status}" != "pass" ]]; then
    failures=$((failures + 1))
  fi

  elapsed=$(( $(now_ms) - host_start_ms ))
  details="$(jq -n \
    --arg host_hash "${host_hash}" \
    --arg output_path "${output_path}" \
    --arg schema_version "${schema_version}" \
    --arg overall_status "${overall_status}" \
    --arg data_hash "${data_hash}" \
    --arg reason "${reason}" \
    --argjson gate_count "${gate_count}" \
    --argjson green_count "${green_count}" \
    --argjson direct_gate_telemetry_available "${direct_available}" \
    '{
      host_hash: $host_hash,
      output_path: $output_path,
      schema_version: $schema_version,
      overall_status: $overall_status,
      gate_count: $gate_count,
      green_count: $green_count,
      direct_gate_telemetry_available: $direct_gate_telemetry_available,
      data_hash: $data_hash,
      reason: (if ($reason | length) > 0 then $reason else null end)
    }')"
  record_log "probe-host-${ordinal}" "${host_status}" "${elapsed}" "${details}"
  host_summaries+=("${details}")
done

total_elapsed_ms=$(( $(now_ms) - start_ms ))
if [[ "${failures}" -eq 0 ]]; then
  status="pass"
else
  status="fail"
fi

printf '%s\n' "${host_summaries[@]}" | jq -s \
  --arg schema_version "${SCHEMA_VERSION}" \
  --arg run_id "${RUN_ID}" \
  --arg status "${status}" \
  --arg data_hash "${expected_data_hash}" \
  --argjson host_count "${#HOSTS[@]}" \
  --argjson failures "${failures}" \
  --argjson duration_ms "${total_elapsed_ms}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    status: $status,
    host_count: $host_count,
    required_hosts: 3,
    failures: $failures,
    duration_ms: $duration_ms,
    agreed_data_hash: $data_hash,
    hosts: .
  }' > "${SUMMARY_JSON}"

jq -n \
  --arg schema_version "${SCHEMA_VERSION}" \
  --arg run_id "${RUN_ID}" \
  --arg summary "${SUMMARY_JSON}" \
  --arg log_jsonl "${LOG_JSONL}" \
  --arg replay "${REPLAY_SH}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    artifacts: {
      summary: $summary,
      log_jsonl: $log_jsonl,
      replay: $replay
    }
  }' > "${MANIFEST_JSON}"

cat > "${REPLAY_SH}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

: "${FCP_CUTOVER_GATE_HOSTS:?set comma-separated live fcp-host endpoints}"
bash scripts/e2e/mesh_cutover_gates_3node.sh \
  --hosts "${FCP_CUTOVER_GATE_HOSTS}" \
  --out-root "${OUT_ROOT:-artifacts/mesh-cutover-gates/3node/replay}"
EOF
chmod +x "${REPLAY_SH}"

if [[ "${status}" != "pass" ]]; then
  echo "mesh cutover gates 3-node proof failed: ${SUMMARY_JSON}" >&2
  exit 1
fi

printf 'pass: %s\n' "${SUMMARY_JSON}"
