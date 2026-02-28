#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REGISTRY_PATH="${1:-${SCRIPT_DIR}/scenario_registry.json}"
SCHEMA_VERSION="asupersync-e2e-scenario-registry/v1"
RUN_MATRIX_PATH="${SCRIPT_DIR}/run_matrix.sh"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

fail() {
  echo "Scenario registry validation failed: $*" >&2
  exit 1
}

check_unique_field() {
  local field="$1"
  local duplicates
  duplicates="$(jq -r ".scenarios[].${field}" "${REGISTRY_PATH}" | sort | uniq -d || true)"
  if [[ -n "${duplicates}" ]]; then
    fail "duplicate ${field} values found: ${duplicates}"
  fi
}

require_cmd jq
require_cmd rg

[[ -f "${REGISTRY_PATH}" ]] || fail "registry file not found: ${REGISTRY_PATH}"
[[ -f "${RUN_MATRIX_PATH}" ]] || fail "run matrix script not found: ${RUN_MATRIX_PATH}"

jq -e . "${REGISTRY_PATH}" >/dev/null

jq -e \
  --arg schema "${SCHEMA_VERSION}" \
  '
    .schema_version == $schema
    and (.registry_version | type == "number")
    and (.governance_rules | type == "object")
    and (.scenarios | type == "array" and length > 0)
  ' "${REGISTRY_PATH}" >/dev/null \
  || fail "registry envelope/schema metadata invalid"

jq -e '
  .scenarios
  | all(
      (.key | type == "string" and test("^[a-z0-9_]+$"))
      and (.scenario_id | type == "string" and test("^asupersync\\.e2e\\.[a-z0-9_]+$"))
      and (.script | type == "string" and test("^scripts/e2e/[a-z0-9_]+\\.sh$"))
      and (.required | type == "boolean")
      and (.contract_id | type == "string" and test("^contract\\.[a-z0-9_]+$"))
      and (.archetype | IN("request_response","streaming","bidirectional","queue_pubsub","polling","webhook","database","file_blob","cli_process","browser"))
      and (.failure_class | type == "string" and length > 0)
      and (.user_impact_category | IN("security","availability","correctness","performance","cost_control"))
    )
' "${REGISTRY_PATH}" >/dev/null \
  || fail "one or more scenario records fail pattern/type validation"

check_unique_field "key"
check_unique_field "scenario_id"
check_unique_field "script"
check_unique_field "contract_id"

while IFS= read -r script_path; do
  [[ -f "${REPO_ROOT}/${script_path}" ]] || fail "script missing: ${script_path}"
done < <(jq -r '.scenarios[].script' "${REGISTRY_PATH}")

mapfile -t registry_keys < <(jq -r '.scenarios[].key' "${REGISTRY_PATH}" | sort -u)
mapfile -t matrix_keys < <(
  rg -o --no-filename '"[a-z0-9_]+\|[^"]+\|[^"]+\|(true|false)"' "${RUN_MATRIX_PATH}" \
    | sed -E 's/^"([a-z0-9_]+)\|.*$/\1/' \
    | sort -u
)

missing_in_registry="$(comm -23 <(printf '%s\n' "${matrix_keys[@]}") <(printf '%s\n' "${registry_keys[@]}") || true)"
extra_in_registry="$(comm -13 <(printf '%s\n' "${matrix_keys[@]}") <(printf '%s\n' "${registry_keys[@]}") || true)"

[[ -z "${missing_in_registry}" ]] || fail "run_matrix scenarios missing from registry: ${missing_in_registry}"
[[ -z "${extra_in_registry}" ]] || fail "registry scenarios not present in run_matrix: ${extra_in_registry}"

echo "Scenario registry valid: ${REGISTRY_PATH}"
echo "Scenarios validated: ${#registry_keys[@]}"
