#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKS_FILE="${SCRIPT_DIR}/checks/core.sh"

# shellcheck source=checks/core.sh
source "${CHECKS_FILE}"

JSONL_PATH=""
LIST_CHECKS=0
CONNECTOR_ARG=""

usage() {
  cat <<'EOF'
Usage:
  scripts/graduation/run_gauntlet.sh [--jsonl <path>] <connector-path>
  scripts/graduation/run_gauntlet.sh --list-checks
EOF
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/ }"
  value="${value//$'\r'/ }"
  printf '%s' "${value}"
}

emit_jsonl() {
  local connector="$1"
  local check="$2"
  local verdict="$3"
  local duration_ms="$4"
  local stderr_excerpt="$5"
  local line

  line="{\"connector\":\"$(json_escape "${connector}")\",\"check\":\"$(json_escape "${check}")\",\"verdict\":\"$(json_escape "${verdict}")\",\"duration_ms\":${duration_ms},\"stderr_excerpt\":\"$(json_escape "${stderr_excerpt}")\"}"
  printf '%s\n' "${line}"
  if [[ -n "${JSONL_PATH}" ]]; then
    printf '%s\n' "${line}" >>"${JSONL_PATH}"
  fi
}

normalize_path() {
  local path="$1"
  case "${path}" in
    /*)
      printf '%s\n' "${path}"
      ;;
    *)
      printf '%s/%s\n' "$(pwd)" "${path}"
      ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list-checks)
      LIST_CHECKS=1
      shift
      ;;
    --jsonl)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --jsonl" >&2
        exit 1
      fi
      JSONL_PATH="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      if [[ -n "${CONNECTOR_ARG}" ]]; then
        echo "only one connector path may be provided" >&2
        exit 1
      fi
      CONNECTOR_ARG="$1"
      shift
      ;;
  esac
done

if [[ "${LIST_CHECKS}" -eq 1 ]]; then
  graduation_list_checks
  exit 0
fi

if [[ -z "${CONNECTOR_ARG}" ]]; then
  echo "missing connector path" >&2
  usage >&2
  exit 1
fi

CONNECTOR_PATH="$(normalize_path "${CONNECTOR_ARG}")"

for check_record in "${GRADUATION_CHECKS[@]}"; do
  IFS='|' read -r check_id exit_code _description <<<"${check_record}"
  check_fn="graduation_check_${check_id}"
  start_seconds="$(date -u +%s)"

  if output="$("${check_fn}" "${CONNECTOR_PATH}" 2>&1)"; then
    end_seconds="$(date -u +%s)"
    emit_jsonl "${CONNECTOR_ARG}" "${check_id}" "pass" "$(((end_seconds - start_seconds) * 1000))" ""
    continue
  fi

  end_seconds="$(date -u +%s)"
  emit_jsonl "${CONNECTOR_ARG}" "${check_id}" "fail" "$(((end_seconds - start_seconds) * 1000))" "${output}"
  echo "check=${check_id} verdict=fail code=${exit_code} connector=${CONNECTOR_ARG} detail=${output}" >&2
  exit "${exit_code}"
done

exit 0
