#!/usr/bin/env bash
# test_coverage_scan.sh — suite-class coverage scanner for connectors and core crates.
#
# Codifies the V3 testing taxonomy from:
#   - docs/V3_Connector_Acceptance_Contract.md
#   - docs/testing/coverage-inventory.md
#   - docs/testing/live-suite-classification.md
#
# Verifies:
#   1. Clean source-adjacent pure-unit floors for connectors and crates
#   2. Deterministic-contract presence
#   3. Acceptance-suite presence (`local_non_mock`, `host_e2e`, or `live`)
#   4. Required live-suite presence for connectors classified above Tier A
#   5. Naming violations such as fake-backed `no_mock_integration.rs`
#
# The scanner emits a stable JSON document for downstream CI/dashboard beads and
# a compact diff-friendly text summary for humans.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

COVERAGE_DOC="${REPO_ROOT}/docs/testing/coverage-inventory.md"
LIVE_DOC="${REPO_ROOT}/docs/testing/live-suite-classification.md"
V3_DOC="${REPO_ROOT}/docs/V3_Connector_Acceptance_Contract.md"
FCP_E2E_TESTS_DIR="${REPO_ROOT}/crates/fcp-e2e/tests"

CHECK_MODE="all"
ONLY_SCOPE="all"
JSON_OUT=""
SUMMARY_OUT=""
CONNECTOR_MINIMUM_TESTS="${CONNECTOR_MINIMUM_TESTS:-${MINIMUM_TESTS:-5}}"
CRATE_MINIMUM_TESTS="${CRATE_MINIMUM_TESTS:-${MINIMUM_TESTS:-5}}"

declare -A CONNECTOR_EXISTS=()
declare -A LIVE_TIER_BY_CONNECTOR=()
declare -A E2E_FILES_BY_CONNECTOR=()
declare -a UNOWNED_FCP_E2E_FILES=()

declare -a CONNECTOR_ROWS=()
declare -a CRATE_ROWS=()

usage() {
  cat <<'EOF'
Usage: scripts/ci/test_coverage_scan.sh [options]

Scans connector/core-crate test surfaces and classifies them into the V3 suite
taxonomy (`pure_unit`, `deterministic_contract`, `local_non_mock`, `host_e2e`,
`live`), while checking the clean source-adjacent pure-unit floor and minimum
acceptance presence.

Options:
  --check <mode>              all | pure-unit-floor | acceptance (default: all)
  --only <scope>              all | connectors | crates (default: all)
  --json-out <path>           Write machine-readable JSON report
  --summary-out <path>        Write human-readable summary
  --connector-minimum-tests N Minimum clean src tests for connectors (default: 5)
  --crate-minimum-tests N     Minimum clean src tests for crates (default: 5)
  -h, --help                  Show this help

Environment:
  MINIMUM_TESTS               Shared default for both connector/crate floors
  CONNECTOR_MINIMUM_TESTS     Override connector floor
  CRATE_MINIMUM_TESTS         Override crate floor
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

json_bool() {
  if [[ "${1}" == "true" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

relative_path() {
  local path="$1"
  printf '%s\n' "${path#${REPO_ROOT}/}"
}

json_string_array() {
  if (($# == 0)); then
    printf '[]'
    return 0
  fi

  printf '%s\n' "$@" | LC_ALL=C sort -u | jq -Rsc 'split("\n") | map(select(length > 0))'
}

json_issue() {
  local code="$1"
  local severity="$2"
  local message="$3"
  local paths_json="$4"

  jq -cn \
    --arg code "${code}" \
    --arg severity "${severity}" \
    --arg message "${message}" \
    --argjson paths "${paths_json}" \
    '{
      code: $code,
      severity: $severity,
      message: $message,
      paths: $paths
    }'
}

count_test_annotations() {
  local file="$1"
  local count

  count="$(
    rg -c \
      -e '#\[test\]' \
      -e '#\[fcp_async_core::test\]' \
      -e '#\[fcp_async_core::runtime::test\]' \
      "${file}" 2>/dev/null | awk -F: '{sum += $NF} END {print sum + 0}'
  )"

  printf '%s' "${count:-0}"
}

file_has_fake_signal() {
  local file="$1"
  rg -n -P \
    '^(?!\s*//).*?\b(?:wiremock|MockServer|MockApiServer|Mock[A-Z][A-Za-z0-9_]*|Fake[A-Z][A-Za-z0-9_]*)\b' \
    "${file}" >/dev/null 2>&1
}

file_has_live_gate_signal() {
  local file="$1"
  rg -n -P \
    '^(?!\s*//).*?\b(?:FCP_LIVE_(?:SANDBOX|READ|WRITE|DEVICE|LOCAL)|LiveGate::(?:sandbox|read_only|write|device|for_tier)|LiveTier::(?:LocalSufficient|SandboxRequired|DeviceRequired|LiveReadOnly|LiveWriteRequired)|EnvironmentManifest::(?:sandbox|local|device|read_only|write(?:_required)?)|LiveEnvironment::from_manifest)\b' \
    "${file}" >/dev/null 2>&1
}

file_has_host_e2e_signal() {
  local file="$1"
  rg -n -P \
    '^(?!\s*//).*?\b(?:host_e2e|subprocess_e2e|fcp_e2e::host_e2e)\b' \
    "${file}" >/dev/null 2>&1
}

append_assoc_line() {
  local map_name="$1"
  local key="$2"
  local value="$3"
  local -n map_ref="${map_name}"

  if [[ -n "${map_ref[${key}]-}" ]]; then
    map_ref["${key}"]+=$'\n'"${value}"
  else
    map_ref["${key}"]="${value}"
  fi
}

extract_e2e_connector_id() {
  local file="$1"
  local id=""

  id="$(
    rg -o -N 'ConnectorId::from_static\("([^"]+)"\)' "${file}" 2>/dev/null \
      | sed -E 's/.*"([^"]+)".*/\1/' | head -n1 || true
  )"

  if [[ -z "${id}" ]]; then
    id="$(
      rg -o -N 'connector_id:\s*"fcp\.([^"]+)"' "${file}" 2>/dev/null \
        | sed -E 's/.*"fcp\.([^"]+)".*/\1/' | head -n1 || true
    )"
  fi

  printf '%s' "${id}"
}

load_connector_inventory() {
  local dir connector_id
  while IFS= read -r dir; do
    connector_id="$(basename "${dir}")"
    CONNECTOR_EXISTS["${connector_id}"]=1
  done < <(find "${REPO_ROOT}/connectors" -mindepth 1 -maxdepth 1 -type d | LC_ALL=C sort)
}

load_live_tiers() {
  local current_tier=""
  local line token

  while IFS= read -r line; do
    case "${line}" in
      "### Tier A"*)
        current_tier="local_sufficient"
        ;;
      "### Tier B"*)
        current_tier="sandbox_required"
        ;;
      "### Tier C"*)
        current_tier="device_required"
        ;;
      "### Tier D"*)
        current_tier="live_read_only"
        ;;
      "### Tier E"*)
        current_tier="live_write_required"
        ;;
      "### "*)
        current_tier=""
        ;;
    esac

    [[ -n "${current_tier}" ]] || continue

    while IFS= read -r token; do
      token="${token#\`}"
      token="${token%\`}"
      if [[ -n "${CONNECTOR_EXISTS[${token}]-}" ]]; then
        LIVE_TIER_BY_CONNECTOR["${token}"]="${current_tier}"
      fi
    done < <(printf '%s\n' "${line}" | rg -o '`[^`]+`' || true)
  done < "${LIVE_DOC}"
}

load_fcp_e2e_inventory() {
  local file connector_id

  [[ -d "${FCP_E2E_TESTS_DIR}" ]] || return 0

  while IFS= read -r file; do
    connector_id="$(extract_e2e_connector_id "${file}")"
    if [[ -n "${connector_id}" ]]; then
      append_assoc_line E2E_FILES_BY_CONNECTOR "${connector_id}" "${file}"
    else
      UNOWNED_FCP_E2E_FILES+=("$(relative_path "${file}")")
    fi
  done < <(find "${FCP_E2E_TESTS_DIR}" -maxdepth 1 -type f -name '*.rs' | LC_ALL=C sort)
}

classify_test_file() {
  local file="$1"
  local source="$2"

  local base
  local fake_signal=false
  local live_gate_signal=false
  local host_marker=false
  local live_named=false
  local host_named=false
  local local_named=false
  local acceptance_named=false
  local class=""
  local misnamed_no_mock=false
  local reserved_acceptance=false
  local live_named_without_gate=false

  base="$(basename "${file}")"
  file_has_fake_signal "${file}" && fake_signal=true
  file_has_live_gate_signal "${file}" && live_gate_signal=true
  file_has_host_e2e_signal "${file}" && host_marker=true

  case "${base}" in
    *live*.rs|*sandbox*.rs|*nightly_live*.rs)
      live_named=true
      ;;
  esac

  case "${base}" in
    *host_e2e*.rs|*subprocess_e2e*.rs)
      host_named=true
      ;;
  esac

  case "${base}" in
    local_non_mock.rs|fixture_acceptance.rs|no_mock_integration.rs)
      local_named=true
      ;;
  esac

  case "${base}" in
    *acceptance*.rs)
      acceptance_named=true
      ;;
  esac

  if [[ "${live_gate_signal}" == "true" || "${live_named}" == "true" ]]; then
    class="live"
  elif [[ "${host_marker}" == "true" || "${host_named}" == "true" ]]; then
    class="host_e2e"
  elif [[ "${local_named}" == "true" && "${fake_signal}" != "true" ]]; then
    class="local_non_mock"
  elif [[ "${source}" == "fcp_e2e" && "${fake_signal}" != "true" ]]; then
    class="host_e2e"
  else
    class="deterministic_contract"
  fi

  if [[ "${base}" == "no_mock_integration.rs" && "${fake_signal}" == "true" ]]; then
    misnamed_no_mock=true
  fi

  if [[ "${acceptance_named}" == "true" && "${class}" != "local_non_mock" && "${class}" != "host_e2e" && "${class}" != "live" ]]; then
    reserved_acceptance=true
  fi

  if [[ "${live_named}" == "true" && "${live_gate_signal}" != "true" ]]; then
    live_named_without_gate=true
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${class}" \
    "${fake_signal}" \
    "${live_gate_signal}" \
    "${host_marker}" \
    "${misnamed_no_mock}" \
    "${reserved_acceptance}" \
    "${live_named_without_gate}"
}

scan_entity() {
  local kind="$1"
  local dir="$2"

  local id path minimum_tests live_tier
  local source_test_total=0
  local clean_pure_unit_tests=0
  local contaminated_src_tests=0
  local source_files_with_tests=0
  local clean_source_files=0
  local contaminated_source_files=0
  local has_clean_pure_unit_signal=false
  local has_deterministic_contract=false
  local has_acceptance_suite=false
  local requires_live_suite=false
  local has_required_live_suite=false
  local status="pass"

  local -a contaminated_src_paths=()
  local -a suite_file_rows=()
  local -a issue_rows=()
  local -a acceptance_classes_present=()
  local -a deterministic_contract_paths=()
  local -a local_non_mock_paths=()
  local -a host_e2e_paths=()
  local -a live_paths=()
  local -a source_files_to_scan=()
  local -a test_files_to_scan=()

  local file count rel suite_source suite_class fake_signal live_gate_signal host_marker
  local misnamed_no_mock reserved_acceptance live_named_without_gate

  id="$(basename "${dir}")"
  path="$(relative_path "${dir}")"

  if [[ "${kind}" == "connector" ]]; then
    minimum_tests="${CONNECTOR_MINIMUM_TESTS}"
    live_tier="${LIVE_TIER_BY_CONNECTOR[${id}]-}"
  else
    minimum_tests="${CRATE_MINIMUM_TESTS}"
    live_tier=""
  fi

  if [[ -d "${dir}/src" ]]; then
    while IFS= read -r file; do
      source_files_to_scan+=("${file}")
    done < <(find "${dir}/src" -type f -name '*.rs' | LC_ALL=C sort)
  fi

  if [[ -d "${dir}/tests" ]]; then
    while IFS= read -r file; do
      test_files_to_scan+=("${file}")
    done < <(find "${dir}/tests" -maxdepth 1 -type f -name '*.rs' | LC_ALL=C sort)
  fi

  for file in "${source_files_to_scan[@]}"; do
    count="$(count_test_annotations "${file}")"
    (( count > 0 )) || continue

    source_test_total=$((source_test_total + count))
    source_files_with_tests=$((source_files_with_tests + 1))
    rel="$(relative_path "${file}")"

    if file_has_fake_signal "${file}"; then
      contaminated_src_tests=$((contaminated_src_tests + count))
      contaminated_source_files=$((contaminated_source_files + 1))
      contaminated_src_paths+=("${rel}")
    else
      clean_pure_unit_tests=$((clean_pure_unit_tests + count))
      clean_source_files=$((clean_source_files + 1))
      has_clean_pure_unit_signal=true
    fi
  done

  for file in "${test_files_to_scan[@]}"; do
    suite_source="crate_tests"
    rel="$(relative_path "${file}")"
    count="$(count_test_annotations "${file}")"
    IFS=$'\t' read -r suite_class fake_signal live_gate_signal host_marker misnamed_no_mock reserved_acceptance live_named_without_gate \
      <<< "$(classify_test_file "${file}" "${suite_source}")"

    case "${suite_class}" in
      deterministic_contract)
        has_deterministic_contract=true
        deterministic_contract_paths+=("${rel}")
        ;;
      local_non_mock)
        has_acceptance_suite=true
        local_non_mock_paths+=("${rel}")
        acceptance_classes_present+=("local_non_mock")
        ;;
      host_e2e)
        has_acceptance_suite=true
        host_e2e_paths+=("${rel}")
        acceptance_classes_present+=("host_e2e")
        ;;
      live)
        has_acceptance_suite=true
        has_required_live_suite=true
        live_paths+=("${rel}")
        acceptance_classes_present+=("live")
        ;;
    esac

    suite_file_rows+=(
      "$(jq -cn \
        --arg path "${rel}" \
        --arg class "${suite_class}" \
        --arg source "${suite_source}" \
        --argjson test_count "${count}" \
        --argjson fake_signal "$(json_bool "${fake_signal}")" \
        --argjson live_gate_signal "$(json_bool "${live_gate_signal}")" \
        --argjson host_marker "$(json_bool "${host_marker}")" \
        '{
          path: $path,
          class: $class,
          source: $source,
          test_count: $test_count,
          fake_signal: $fake_signal,
          live_gate_signal: $live_gate_signal,
          host_marker: $host_marker
        }'
      )"
    )

    if [[ "${misnamed_no_mock}" == "true" ]]; then
      issue_rows+=(
        "$(json_issue \
          "misnamed_no_mock_integration" \
          "error" \
          "${rel} uses fake or mock infrastructure and therefore belongs to deterministic_contract, not local_non_mock." \
          "$(json_string_array "${rel}")"
        )"
      )
    fi

    if [[ "${reserved_acceptance}" == "true" ]]; then
      issue_rows+=(
        "$(json_issue \
          "reserved_acceptance_name_without_acceptance_boundary" \
          "error" \
          "${rel} uses an acceptance-style filename without providing a V3 acceptance boundary." \
          "$(json_string_array "${rel}")"
        )"
      )
    fi

    if [[ "${live_named_without_gate}" == "true" ]]; then
      issue_rows+=(
        "$(json_issue \
          "live_suite_missing_env_gate" \
          "error" \
          "${rel} is named like a live suite but does not reference the shared FCP live gating helpers or env vars." \
          "$(json_string_array "${rel}")"
        )"
      )
    fi
  done

  if [[ "${kind}" == "connector" && -n "${E2E_FILES_BY_CONNECTOR[${id}]-}" ]]; then
    while IFS= read -r file; do
      [[ -n "${file}" ]] || continue
      suite_source="fcp_e2e"
      rel="$(relative_path "${file}")"
      count="$(count_test_annotations "${file}")"
      IFS=$'\t' read -r suite_class fake_signal live_gate_signal host_marker misnamed_no_mock reserved_acceptance live_named_without_gate \
        <<< "$(classify_test_file "${file}" "${suite_source}")"

      case "${suite_class}" in
        deterministic_contract)
          has_deterministic_contract=true
          deterministic_contract_paths+=("${rel}")
          ;;
        host_e2e)
          has_acceptance_suite=true
          host_e2e_paths+=("${rel}")
          acceptance_classes_present+=("host_e2e")
          ;;
        live)
          has_acceptance_suite=true
          has_required_live_suite=true
          live_paths+=("${rel}")
          acceptance_classes_present+=("live")
          ;;
      esac

      suite_file_rows+=(
        "$(jq -cn \
          --arg path "${rel}" \
          --arg class "${suite_class}" \
          --arg source "${suite_source}" \
          --argjson test_count "${count}" \
          --argjson fake_signal "$(json_bool "${fake_signal}")" \
          --argjson live_gate_signal "$(json_bool "${live_gate_signal}")" \
          --argjson host_marker "$(json_bool "${host_marker}")" \
          '{
            path: $path,
            class: $class,
            source: $source,
            test_count: $test_count,
            fake_signal: $fake_signal,
            live_gate_signal: $live_gate_signal,
            host_marker: $host_marker
          }'
        )"
      )

      if [[ "${live_named_without_gate}" == "true" ]]; then
        issue_rows+=(
          "$(json_issue \
            "live_suite_missing_env_gate" \
            "error" \
            "${rel} is named like a live suite but does not reference the shared FCP live gating helpers or env vars." \
            "$(json_string_array "${rel}")"
          )"
        )
      fi
    done < <(printf '%s\n' "${E2E_FILES_BY_CONNECTOR[${id}]}")
  fi

  if [[ "${kind}" == "connector" && -n "${live_tier}" && "${live_tier}" != "local_sufficient" ]]; then
    requires_live_suite=true
  fi

  if [[ "${has_clean_pure_unit_signal}" != "true" ]]; then
    issue_rows+=(
      "$(json_issue \
        "missing_pure_unit_signal" \
        "error" \
        "${kind} ${id} has no clean source-adjacent pure_unit signal in src/**/*.rs." \
        "$(json_string_array "${contaminated_src_paths[@]}")"
      )"
    )
  fi

  if (( clean_pure_unit_tests < minimum_tests )); then
    issue_rows+=(
      "$(json_issue \
        "pure_unit_floor_below_minimum" \
        "error" \
        "${kind} ${id} has ${clean_pure_unit_tests} clean source-adjacent tests; minimum is ${minimum_tests}." \
        "$(json_string_array "${contaminated_src_paths[@]}")"
      )"
    )
  fi

  if (( contaminated_source_files > 0 )); then
    issue_rows+=(
      "$(json_issue \
        "src_mock_leakage" \
        "error" \
        "${kind} ${id} has inline mock/fake leakage in src tests; those tests do not count as clean pure_unit coverage." \
        "$(json_string_array "${contaminated_src_paths[@]}")"
      )"
    )
  fi

  if [[ "${has_deterministic_contract}" != "true" ]]; then
    issue_rows+=(
      "$(json_issue \
        "missing_deterministic_contract" \
        "error" \
        "${kind} ${id} has no deterministic_contract suite in tests/ or fcp-e2e coverage." \
        "[]"
      )"
    )
  fi

  if [[ "${has_acceptance_suite}" != "true" ]]; then
    issue_rows+=(
      "$(json_issue \
        "missing_acceptance_suite" \
        "error" \
        "${kind} ${id} has no acceptance suite (local_non_mock, host_e2e, or live)." \
        "[]"
      )"
    )
  fi

  if [[ "${requires_live_suite}" == "true" && "${has_required_live_suite}" != "true" ]]; then
    issue_rows+=(
      "$(json_issue \
        "missing_required_live_suite" \
        "error" \
        "connector ${id} is classified as ${live_tier} and therefore requires an environment-gated live suite." \
        "[]"
      )"
    )
  fi

  if ((${#issue_rows[@]} > 0)); then
    status="fail"
  fi

  if [[ "${kind}" == "connector" ]]; then
    CONNECTOR_ROWS+=(
      "$(jq -cn \
        --arg kind "${kind}" \
        --arg id "${id}" \
        --arg path "${path}" \
        --arg live_tier "${live_tier}" \
        --arg status "${status}" \
        --argjson minimum_pure_unit_tests "${minimum_tests}" \
        --argjson source_test_total "${source_test_total}" \
        --argjson clean_pure_unit_tests "${clean_pure_unit_tests}" \
        --argjson contaminated_src_tests "${contaminated_src_tests}" \
        --argjson source_files_with_tests "${source_files_with_tests}" \
        --argjson clean_source_files "${clean_source_files}" \
        --argjson contaminated_source_files "${contaminated_source_files}" \
        --argjson has_clean_pure_unit_signal "$(json_bool "${has_clean_pure_unit_signal}")" \
        --argjson has_deterministic_contract "$(json_bool "${has_deterministic_contract}")" \
        --argjson has_acceptance_suite "$(json_bool "${has_acceptance_suite}")" \
        --argjson requires_live_suite "$(json_bool "${requires_live_suite}")" \
        --argjson has_required_live_suite "$(json_bool "${has_required_live_suite}")" \
        --argjson contaminated_src_paths "$(json_string_array "${contaminated_src_paths[@]}")" \
        --argjson acceptance_classes_present "$(json_string_array "${acceptance_classes_present[@]}")" \
        --argjson deterministic_contract_paths "$(json_string_array "${deterministic_contract_paths[@]}")" \
        --argjson local_non_mock_paths "$(json_string_array "${local_non_mock_paths[@]}")" \
        --argjson host_e2e_paths "$(json_string_array "${host_e2e_paths[@]}")" \
        --argjson live_paths "$(json_string_array "${live_paths[@]}")" \
        --argjson suite_files "$(printf '%s\n' "${suite_file_rows[@]}" | jq -s 'sort_by(.path, .source)')" \
        --argjson issues "$(printf '%s\n' "${issue_rows[@]}" | jq -s 'sort_by(.code, .message)')" \
        '{
          kind: $kind,
          id: $id,
          path: $path,
          live_tier: (if ($live_tier | length) > 0 then $live_tier else null end),
          minimum_pure_unit_tests: $minimum_pure_unit_tests,
          source_adjacent: {
            total_tests: $source_test_total,
            clean_pure_unit_tests: $clean_pure_unit_tests,
            contaminated_tests: $contaminated_src_tests,
            files_with_tests: $source_files_with_tests,
            clean_files: $clean_source_files,
            contaminated_files: $contaminated_source_files,
            contaminated_paths: $contaminated_src_paths
          },
          suite_counts: {
            deterministic_contract: ($deterministic_contract_paths | length),
            local_non_mock: ($local_non_mock_paths | length),
            host_e2e: ($host_e2e_paths | length),
            live: ($live_paths | length)
          },
          suite_paths: {
            deterministic_contract: $deterministic_contract_paths,
            local_non_mock: $local_non_mock_paths,
            host_e2e: $host_e2e_paths,
            live: $live_paths
          },
          suite_files: $suite_files,
          acceptance_classes_present: $acceptance_classes_present,
          has_clean_pure_unit_signal: $has_clean_pure_unit_signal,
          has_deterministic_contract: $has_deterministic_contract,
          has_acceptance_suite: $has_acceptance_suite,
          requires_live_suite: $requires_live_suite,
          has_required_live_suite: $has_required_live_suite,
          status: $status,
          issues: $issues
        }'
      )"
    )
  else
    CRATE_ROWS+=(
      "$(jq -cn \
        --arg kind "${kind}" \
        --arg id "${id}" \
        --arg path "${path}" \
        --arg status "${status}" \
        --argjson minimum_pure_unit_tests "${minimum_tests}" \
        --argjson source_test_total "${source_test_total}" \
        --argjson clean_pure_unit_tests "${clean_pure_unit_tests}" \
        --argjson contaminated_src_tests "${contaminated_src_tests}" \
        --argjson source_files_with_tests "${source_files_with_tests}" \
        --argjson clean_source_files "${clean_source_files}" \
        --argjson contaminated_source_files "${contaminated_source_files}" \
        --argjson has_clean_pure_unit_signal "$(json_bool "${has_clean_pure_unit_signal}")" \
        --argjson has_deterministic_contract "$(json_bool "${has_deterministic_contract}")" \
        --argjson has_acceptance_suite "$(json_bool "${has_acceptance_suite}")" \
        --argjson contaminated_src_paths "$(json_string_array "${contaminated_src_paths[@]}")" \
        --argjson acceptance_classes_present "$(json_string_array "${acceptance_classes_present[@]}")" \
        --argjson deterministic_contract_paths "$(json_string_array "${deterministic_contract_paths[@]}")" \
        --argjson local_non_mock_paths "$(json_string_array "${local_non_mock_paths[@]}")" \
        --argjson host_e2e_paths "$(json_string_array "${host_e2e_paths[@]}")" \
        --argjson live_paths "$(json_string_array "${live_paths[@]}")" \
        --argjson suite_files "$(printf '%s\n' "${suite_file_rows[@]}" | jq -s 'sort_by(.path, .source)')" \
        --argjson issues "$(printf '%s\n' "${issue_rows[@]}" | jq -s 'sort_by(.code, .message)')" \
        '{
          kind: $kind,
          id: $id,
          path: $path,
          minimum_pure_unit_tests: $minimum_pure_unit_tests,
          source_adjacent: {
            total_tests: $source_test_total,
            clean_pure_unit_tests: $clean_pure_unit_tests,
            contaminated_tests: $contaminated_src_tests,
            files_with_tests: $source_files_with_tests,
            clean_files: $clean_source_files,
            contaminated_files: $contaminated_source_files,
            contaminated_paths: $contaminated_src_paths
          },
          suite_counts: {
            deterministic_contract: ($deterministic_contract_paths | length),
            local_non_mock: ($local_non_mock_paths | length),
            host_e2e: ($host_e2e_paths | length),
            live: ($live_paths | length)
          },
          suite_paths: {
            deterministic_contract: $deterministic_contract_paths,
            local_non_mock: $local_non_mock_paths,
            host_e2e: $host_e2e_paths,
            live: $live_paths
          },
          suite_files: $suite_files,
          acceptance_classes_present: $acceptance_classes_present,
          has_clean_pure_unit_signal: $has_clean_pure_unit_signal,
          has_deterministic_contract: $has_deterministic_contract,
          has_acceptance_suite: $has_acceptance_suite,
          status: $status,
          issues: $issues
        }'
      )"
    )
  fi
}

issue_codes_for_check() {
  case "${CHECK_MODE}" in
    pure-unit-floor)
      printf '%s\n' \
        "missing_pure_unit_signal" \
        "pure_unit_floor_below_minimum" \
        "src_mock_leakage"
      ;;
    acceptance)
      printf '%s\n' \
        "missing_deterministic_contract" \
        "missing_acceptance_suite" \
        "missing_required_live_suite" \
        "misnamed_no_mock_integration" \
        "reserved_acceptance_name_without_acceptance_boundary" \
        "live_suite_missing_env_gate"
      ;;
    all)
      printf '%s\n' \
        "missing_pure_unit_signal" \
        "pure_unit_floor_below_minimum" \
        "src_mock_leakage" \
        "missing_deterministic_contract" \
        "missing_acceptance_suite" \
        "missing_required_live_suite" \
        "misnamed_no_mock_integration" \
        "reserved_acceptance_name_without_acceptance_boundary" \
        "live_suite_missing_env_gate"
      ;;
    *)
      echo "Unsupported check mode: ${CHECK_MODE}" >&2
      exit 1
      ;;
  esac
}

scan_scope() {
  local dir

  if [[ "${ONLY_SCOPE}" == "all" || "${ONLY_SCOPE}" == "connectors" ]]; then
    while IFS= read -r dir; do
      scan_entity "connector" "${dir}"
    done < <(find "${REPO_ROOT}/connectors" -mindepth 1 -maxdepth 1 -type d | LC_ALL=C sort)
  fi

  if [[ "${ONLY_SCOPE}" == "all" || "${ONLY_SCOPE}" == "crates" ]]; then
    while IFS= read -r dir; do
      [[ -f "${dir}/Cargo.toml" ]] || continue
      scan_entity "crate" "${dir}"
    done < <(find "${REPO_ROOT}/crates" -mindepth 1 -maxdepth 1 -type d | LC_ALL=C sort)
  fi
}

while (($# > 0)); do
  case "$1" in
    --check)
      CHECK_MODE="${2:-}"
      shift 2
      ;;
    --only)
      ONLY_SCOPE="${2:-}"
      shift 2
      ;;
    --json-out)
      JSON_OUT="${2:-}"
      shift 2
      ;;
    --summary-out)
      SUMMARY_OUT="${2:-}"
      shift 2
      ;;
    --connector-minimum-tests)
      CONNECTOR_MINIMUM_TESTS="${2:-}"
      shift 2
      ;;
    --crate-minimum-tests)
      CRATE_MINIMUM_TESTS="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

case "${CHECK_MODE}" in
  all|pure-unit-floor|acceptance)
    ;;
  *)
    echo "Unsupported --check mode: ${CHECK_MODE}" >&2
    exit 1
    ;;
esac

case "${ONLY_SCOPE}" in
  all|connectors|crates)
    ;;
  *)
    echo "Unsupported --only scope: ${ONLY_SCOPE}" >&2
    exit 1
    ;;
esac

require_cmd rg
require_cmd jq
require_cmd find
require_cmd sed
require_cmd awk

load_connector_inventory
load_live_tiers
load_fcp_e2e_inventory
scan_scope

CONNECTORS_JSON='[]'
CRATES_JSON='[]'

if ((${#CONNECTOR_ROWS[@]} > 0)); then
  CONNECTORS_JSON="$(printf '%s\n' "${CONNECTOR_ROWS[@]}" | jq -s 'sort_by(.id)')"
fi

if ((${#CRATE_ROWS[@]} > 0)); then
  CRATES_JSON="$(printf '%s\n' "${CRATE_ROWS[@]}" | jq -s 'sort_by(.id)')"
fi

FINAL_JSON="$(
  jq -n \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg check_mode "${CHECK_MODE}" \
    --arg only_scope "${ONLY_SCOPE}" \
    --arg coverage_doc "$(relative_path "${COVERAGE_DOC}")" \
    --arg live_doc "$(relative_path "${LIVE_DOC}")" \
    --arg v3_doc "$(relative_path "${V3_DOC}")" \
    --argjson connector_minimum_tests "${CONNECTOR_MINIMUM_TESTS}" \
    --argjson crate_minimum_tests "${CRATE_MINIMUM_TESTS}" \
    --argjson connectors "${CONNECTORS_JSON}" \
    --argjson crates "${CRATES_JSON}" \
    --argjson unowned_fcp_e2e_files "$(json_string_array "${UNOWNED_FCP_E2E_FILES[@]}")" \
    '{
      "$schema": "fcp-test-coverage-scan-v1",
      generated_at: $generated_at,
      config: {
        check_mode: $check_mode,
        only_scope: $only_scope,
        connector_minimum_tests: $connector_minimum_tests,
        crate_minimum_tests: $crate_minimum_tests
      },
      sources: {
        coverage_inventory: $coverage_doc,
        live_suite_classification: $live_doc,
        v3_acceptance_contract: $v3_doc
      },
      connectors: $connectors,
      crates: $crates,
      unowned_fcp_e2e_files: $unowned_fcp_e2e_files,
      summary: {
        connectors: {
          total: ($connectors | length),
          with_clean_pure_unit_signal: ([$connectors[] | select(.has_clean_pure_unit_signal)] | length),
          meeting_pure_unit_floor: ([$connectors[] | select(.source_adjacent.clean_pure_unit_tests >= .minimum_pure_unit_tests)] | length),
          with_src_mock_leakage: ([$connectors[] | select(.source_adjacent.contaminated_files > 0)] | length),
          with_deterministic_contract: ([$connectors[] | select(.has_deterministic_contract)] | length),
          with_acceptance_suite: ([$connectors[] | select(.has_acceptance_suite)] | length),
          requiring_live_suite: ([$connectors[] | select(.requires_live_suite)] | length),
          with_required_live_suite: ([$connectors[] | select(.requires_live_suite and .has_required_live_suite)] | length),
          failing_entities: ([$connectors[] | select(.status == "fail")] | length),
          issue_counts: (
            [$connectors[].issues[]?.code] | group_by(.) | map({code: .[0], count: length})
          )
        },
        crates: {
          total: ($crates | length),
          with_clean_pure_unit_signal: ([$crates[] | select(.has_clean_pure_unit_signal)] | length),
          meeting_pure_unit_floor: ([$crates[] | select(.source_adjacent.clean_pure_unit_tests >= .minimum_pure_unit_tests)] | length),
          with_src_mock_leakage: ([$crates[] | select(.source_adjacent.contaminated_files > 0)] | length),
          with_deterministic_contract: ([$crates[] | select(.has_deterministic_contract)] | length),
          with_acceptance_suite: ([$crates[] | select(.has_acceptance_suite)] | length),
          failing_entities: ([$crates[] | select(.status == "fail")] | length),
          issue_counts: (
            [$crates[].issues[]?.code] | group_by(.) | map({code: .[0], count: length})
          )
        }
      }
    }'
)"

FILTERED_ISSUE_CODES_JSON="$(issue_codes_for_check | jq -Rsc 'split("\n") | map(select(length > 0))')"

SUMMARY_TEXT="$(
  jq -r \
    --arg check_mode "${CHECK_MODE}" \
    --arg only_scope "${ONLY_SCOPE}" \
    --argjson filtered_codes "${FILTERED_ISSUE_CODES_JSON}" \
    '
    def relevant_issues: [.issues[] | . as $issue | select($filtered_codes | index($issue.code))];
    def entity_lines:
      (.connectors + .crates)
      | map(select((relevant_issues | length) > 0))
      | sort_by(.kind, .id)
      | map(
          "  FAIL "
          + .kind + ":" + .id
          + " pure=" + (.source_adjacent.clean_pure_unit_tests|tostring) + "/" + (.minimum_pure_unit_tests|tostring)
          + " det=" + (.suite_counts.deterministic_contract|tostring)
          + " acc=" + ((.suite_counts.local_non_mock + .suite_counts.host_e2e + .suite_counts.live)|tostring)
          + (if .kind == "connector" and .live_tier != null then " tier=" + .live_tier else "" end)
          + " issues=" + ((relevant_issues | map(.code) | unique | sort | join(",")))
        );
    [
      "Test Coverage Scan",
      "==================",
      "Check: " + $check_mode,
      "Scope: " + $only_scope,
      "",
      "Summary:",
      "  Connectors: "
        + (.summary.connectors.total|tostring)
        + " total, "
        + (.summary.connectors.meeting_pure_unit_floor|tostring)
        + " meet pure-unit floor, "
        + (.summary.connectors.with_deterministic_contract|tostring)
        + " have deterministic_contract, "
        + (.summary.connectors.with_acceptance_suite|tostring)
        + " have acceptance suites, "
        + (.summary.connectors.requiring_live_suite|tostring)
        + " require live suites",
      "  Crates:     "
        + (.summary.crates.total|tostring)
        + " total, "
        + (.summary.crates.meeting_pure_unit_floor|tostring)
        + " meet pure-unit floor, "
        + (.summary.crates.with_deterministic_contract|tostring)
        + " have deterministic_contract, "
        + (.summary.crates.with_acceptance_suite|tostring)
        + " have acceptance suites",
      "",
      (if (entity_lines | length) > 0 then "Relevant Failures:" else "Relevant Failures: none" end)
    ] + entity_lines
    | join("\n")
    ' <<< "${FINAL_JSON}"
)"

if [[ -n "${JSON_OUT}" ]]; then
  printf '%s\n' "${FINAL_JSON}" > "${JSON_OUT}"
fi

if [[ -n "${SUMMARY_OUT}" ]]; then
  printf '%s\n' "${SUMMARY_TEXT}" > "${SUMMARY_OUT}"
fi

printf '%s\n' "${SUMMARY_TEXT}"

FAIL_COUNT="$(
  jq -r \
    --argjson filtered_codes "${FILTERED_ISSUE_CODES_JSON}" \
    '
      (.connectors + .crates)
      | map([.issues[] | . as $issue | select($filtered_codes | index($issue.code))] | length)
      | add // 0
    ' <<< "${FINAL_JSON}"
)"

if [[ "${FAIL_COUNT}" -gt 0 ]]; then
  exit 1
fi

exit 0
