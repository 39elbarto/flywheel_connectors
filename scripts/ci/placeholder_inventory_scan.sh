#!/usr/bin/env bash
# placeholder_inventory_scan.sh — enforce the committed production-placeholder
# inventory against runtime surfaces and repo-wide placeholder spread.
#
# Scans runtime roots (`connectors`, `crates`) for:
#   1. audited anchors that are still present
#   2. inventory drift when anchors move or disappear
#   3. unexpected placeholder spread outside anchored paths
#   4. approved-exception matches that stay inside narrow allowlist globs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="${DEFAULT_REPO_ROOT}"
INVENTORY_PATH=""

JSON_OUT=""
LOG_OUT=""

usage() {
  cat <<'EOF'
Usage: scripts/ci/placeholder_inventory_scan.sh [options]

Scans the committed placeholder inventory against runtime roots and fails on
inventory drift, known production gaps, or placeholder spread outside approved
exception paths.

Options:
  --repo-root <path>  Override repository root (default: current repo)
  --json-out <path>  Write JSON artifact to path
  --log-out <path>   Write human summary log to path
  -h, --help         Show this help

Examples:
  bash scripts/ci/placeholder_inventory_scan.sh
  bash scripts/ci/placeholder_inventory_scan.sh --json-out docs/testing/placeholder-scan.json --log-out docs/testing/placeholder-scan.log
  bash scripts/ci/placeholder_inventory_scan.sh --repo-root /tmp/placeholder-fixture
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

while (($# > 0)); do
  case "$1" in
    --repo-root)
      REPO_ROOT="$2"
      shift 2
      ;;
    --json-out)
      JSON_OUT="$2"
      shift 2
      ;;
    --log-out)
      LOG_OUT="$2"
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

require_cmd jq
require_cmd rg

if [[ ! -d "${REPO_ROOT}" ]]; then
  echo "Repository root does not exist: ${REPO_ROOT}" >&2
  exit 1
fi

REPO_ROOT="$(cd "${REPO_ROOT}" && pwd)"
INVENTORY_PATH="${REPO_ROOT}/docs/testing/placeholder-inventory.json"

if [[ ! -f "${INVENTORY_PATH}" ]]; then
  echo "Missing inventory: ${INVENTORY_PATH}" >&2
  exit 1
fi

readonly DEFAULT_SCAN_ROOTS=(connectors crates)
ACTIVE_SCAN_ROOTS=()
for scan_root in "${DEFAULT_SCAN_ROOTS[@]}"; do
  if [[ -d "${REPO_ROOT}/${scan_root}" ]]; then
    ACTIVE_SCAN_ROOTS+=("${scan_root}")
  fi
done
if [[ "${#ACTIVE_SCAN_ROOTS[@]}" -eq 0 ]]; then
  echo "No scan roots found under ${REPO_ROOT}; expected at least one of: ${DEFAULT_SCAN_ROOTS[*]}" >&2
  exit 1
fi
ALL_INVENTORY_ANCHORS_JSON="$(jq -c '[.findings[] | .anchors[] | {path, needle}]' "${INVENTORY_PATH}")"

path_matches_any_glob() {
  local path="$1"
  shift || true
  local pattern
  for pattern in "$@"; do
    [[ -z "${pattern}" ]] && continue
    case "${path}" in
      ${pattern}) return 0 ;;
    esac
  done
  return 1
}

needle_uses_repo_wide_scan() {
  local needle_lc
  needle_lc="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "${needle_lc}" in
    *placeholder*|*planned_only*|*stub*|*todo*|*not\ implemented*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

finding_results_json=""
finding_sep=""

while IFS= read -r finding; do
  id="$(jq -r '.id' <<<"${finding}")"
  title="$(jq -r '.title' <<<"${finding}")"
  classification="$(jq -r '.classification' <<<"${finding}")"
  owner_bead="$(jq -r '.owner_bead' <<<"${finding}")"
  allowed_scaffold_candidate="$(jq -r '.allowed_scaffold_candidate' <<<"${finding}")"
  approved_exception_class="$(jq -r '.approved_exception_class // empty' <<<"${finding}")"

  disposition="runtime_blocker"
  if [[ -n "${approved_exception_class}" ]]; then
    disposition="approved_exception"
  elif [[ "${allowed_scaffold_candidate}" == "true" ]]; then
    disposition="allowed_scaffold_candidate"
  fi

  allowed_globs=()
  if [[ -n "${approved_exception_class}" ]]; then
    mapfile -t allowed_globs < <(
      jq -r \
        --arg class_id "${approved_exception_class}" \
        '.approved_exception_classes[]
         | select(.id == $class_id)
         | .allowed_path_globs[]?' \
        "${INVENTORY_PATH}"
    )
  fi

  anchor_results_json=""
  anchor_sep=""
  finding_matches_json=""
  finding_match_sep=""

  while IFS= read -r anchor; do
    path="$(jq -r '.path' <<<"${anchor}")"
    needle="$(jq -r '.needle' <<<"${anchor}")"
    abs_path="${REPO_ROOT}/${path}"

    if needle_uses_repo_wide_scan "${needle}"; then
      scan_lines="$(
        (
          cd "${REPO_ROOT}"
          rg -n -F --with-filename --no-heading -- "${needle}" "${ACTIVE_SCAN_ROOTS[@]}" || true
        )
      )"
    else
      scan_lines="$(
        (
          cd "${REPO_ROOT}"
          rg -n -F --with-filename --no-heading -- "${needle}" "${path}" || true
        )
      )"
    fi

    anchor_matches_json=""
    anchor_match_sep=""
    anchor_found=false

    while IFS= read -r match; do
      [[ -z "${match}" ]] && continue
      match_path="${match%%:*}"
      match_rest="${match#*:}"
      match_line="${match_rest%%:*}"
      match_text="${match_rest#*:}"

      anchored=false
      if [[ "${match_path}" == "${path}" ]]; then
        anchored=true
        anchor_found=true
      fi

      inventory_anchored=false
      if jq -e \
        --arg path "${match_path}" \
        --arg needle "${needle}" \
        'any(.[]; .path == $path and .needle == $needle)' \
        <<<"${ALL_INVENTORY_ANCHORS_JSON}" >/dev/null; then
        inventory_anchored=true
      fi

      allowlisted=false
      if [[ -n "${approved_exception_class}" ]] && path_matches_any_glob "${match_path}" "${allowed_globs[@]}"; then
        allowlisted=true
      fi

      match_json="$(
        jq -cn \
          --arg path "${match_path}" \
          --arg needle "${needle}" \
          --argjson line "${match_line}" \
          --arg text "${match_text}" \
          --argjson anchored "${anchored}" \
          --argjson inventory_anchored "${inventory_anchored}" \
          --argjson allowlisted "${allowlisted}" \
          '{
            path: $path,
            needle: $needle,
            line: $line,
            text: $text,
            anchored: $anchored,
            inventory_anchored: $inventory_anchored,
            allowlisted: $allowlisted
          }'
      )"

      finding_matches_json+="${finding_match_sep}${match_json}"
      finding_match_sep=","
      if [[ "${anchored}" == "true" ]]; then
        anchor_matches_json+="${anchor_match_sep}${match_json}"
        anchor_match_sep=","
      fi
    done <<< "${scan_lines}"

    if [[ "${anchor_found}" == "true" ]]; then
      status="present"
    else
      status="missing"
    fi

    anchor_result_json="$(
      jq -cn \
        --arg path "${path}" \
        --arg needle "${needle}" \
        --arg status "${status}" \
        --argjson matches "[${anchor_matches_json}]" \
        '{
          path: $path,
          needle: $needle,
          status: $status,
          matches: $matches
        }'
    )"

    anchor_results_json+="${anchor_sep}${anchor_result_json}"
    anchor_sep=","
  done < <(jq -c '.anchors[]' <<<"${finding}")

  anchor_results_json="[${anchor_results_json}]"
  finding_matches_json="$(
    jq -c 'sort_by(.path, .line, .needle) | unique_by([.path, .line, .needle])' \
      <<<"[${finding_matches_json}]"
  )"
  finding_status="present"
  if ! jq -e 'all(.[]; .status == "present")' <<<"${anchor_results_json}" >/dev/null; then
    finding_status="drifted"
  fi

  unexpected_matches_json="$(
    jq -c '[.[] | select(.inventory_anchored == false and .allowlisted == false)]' \
      <<<"${finding_matches_json}"
  )"
  allowlisted_matches_json="$(
    jq -c '[.[] | select(.anchored == false and .allowlisted == true)]' \
      <<<"${finding_matches_json}"
  )"
  anchored_matches_json="$(
    jq -c '[.[] | select(.anchored == true)]' <<<"${finding_matches_json}"
  )"

  gate_status="cleared"
  gate_reason="No active placeholder matches remain."
  enforced_failure=false

  if [[ "${finding_status}" != "present" ]]; then
    gate_status="inventory_drift"
    gate_reason="Committed inventory anchors no longer match the workspace."
    enforced_failure=true
  elif jq -e 'length > 0' <<<"${unexpected_matches_json}" >/dev/null; then
    gate_status="unexpected_match"
    gate_reason="Placeholder marker appears outside the anchored path or approved exception globs."
    enforced_failure=true
  elif [[ -n "${approved_exception_class}" ]]; then
    gate_status="approved_exception"
    gate_reason="Finding is quarantined behind an approved exception class."
  elif jq -e 'length > 0' <<<"${anchored_matches_json}" >/dev/null; then
    gate_status="known_gap_blocking"
    gate_reason="Known production/runtime placeholder gap is still present."
    enforced_failure=true
  fi

  finding_result_json="$(
    jq -cn \
      --arg id "${id}" \
      --arg title "${title}" \
      --arg classification "${classification}" \
      --arg owner_bead "${owner_bead}" \
      --arg disposition "${disposition}" \
      --arg status "${finding_status}" \
      --arg gate_status "${gate_status}" \
      --arg gate_reason "${gate_reason}" \
      --arg approved_exception_class "${approved_exception_class}" \
      --argjson allowed_scaffold_candidate "${allowed_scaffold_candidate}" \
      --argjson enforced_failure "${enforced_failure}" \
      --argjson anchors "${anchor_results_json}" \
      --argjson matches "${finding_matches_json}" \
      --argjson anchored_matches "${anchored_matches_json}" \
      --argjson allowlisted_matches "${allowlisted_matches_json}" \
      --argjson unexpected_matches "${unexpected_matches_json}" \
      '{
        id: $id,
        title: $title,
        classification: $classification,
        owner_bead: $owner_bead,
        disposition: $disposition,
        status: $status,
        gate_status: $gate_status,
        gate_reason: $gate_reason,
        enforced_failure: $enforced_failure,
        allowed_scaffold_candidate: $allowed_scaffold_candidate,
        approved_exception_class: (if $approved_exception_class == "" then null else $approved_exception_class end),
        anchors: $anchors,
        matches: $matches,
        anchored_matches: $anchored_matches,
        allowlisted_matches: $allowlisted_matches,
        unexpected_matches: $unexpected_matches
      }'
  )"

  finding_results_json+="${finding_sep}${finding_result_json}"
  finding_sep=","
done < <(jq -c '.findings[]' "${INVENTORY_PATH}")

finding_results_json="[${finding_results_json}]"
approved_exception_classes_json="$(jq '.approved_exception_classes' "${INVENTORY_PATH}")"
generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

report_json="$(
  jq -cn \
    --arg generated_at "${generated_at}" \
    --arg inventory_path "docs/testing/placeholder-inventory.json" \
    --argjson approved_exception_classes "${approved_exception_classes_json}" \
    --argjson findings "${finding_results_json}" \
    '{
      generated_at: $generated_at,
      inventory_path: $inventory_path,
      approved_exception_classes: $approved_exception_classes,
      summary: {
        total_findings: ($findings | length),
        present: ($findings | map(select(.status == "present")) | length),
        drifted: ($findings | map(select(.status != "present")) | length),
        runtime_blockers: ($findings | map(select(.classification == "runtime_blocker")) | length),
        status_drifts: ($findings | map(select(.classification == "status_drift")) | length),
        operator_gaps: ($findings | map(select(.classification == "operator_gap")) | length),
        scaffold_gaps: ($findings | map(select(.classification == "scaffold_gap")) | length),
        allowed_scaffold_candidates: ($findings | map(select(.allowed_scaffold_candidate == true)) | length),
        failing_findings: ($findings | map(select(.enforced_failure == true)) | length),
        known_gap_blocking: ($findings | map(select(.gate_status == "known_gap_blocking")) | length),
        unexpected_match_findings: ($findings | map(select(.gate_status == "unexpected_match")) | length),
        approved_exception_findings: ($findings | map(select(.gate_status == "approved_exception")) | length),
        cleared_findings: ($findings | map(select(.gate_status == "cleared")) | length)
      },
      findings: $findings
    }'
)"

log_text="Production Placeholder Scan
Generated: ${generated_at}
Inventory: docs/testing/placeholder-inventory.json
Repository root: ${REPO_ROOT}
Scan roots: ${ACTIVE_SCAN_ROOTS[*]}

Summary:
- findings: $(jq -r '.summary.total_findings' <<<"${report_json}")
- present: $(jq -r '.summary.present' <<<"${report_json}")
- drifted: $(jq -r '.summary.drifted' <<<"${report_json}")
- runtime blockers: $(jq -r '.summary.runtime_blockers' <<<"${report_json}")
- status drifts: $(jq -r '.summary.status_drifts' <<<"${report_json}")
- operator gaps: $(jq -r '.summary.operator_gaps' <<<"${report_json}")
- scaffold gaps: $(jq -r '.summary.scaffold_gaps' <<<"${report_json}")
- allowed scaffold candidates: $(jq -r '.summary.allowed_scaffold_candidates' <<<"${report_json}")
- failing findings: $(jq -r '.summary.failing_findings' <<<"${report_json}")
- known gap blocking: $(jq -r '.summary.known_gap_blocking' <<<"${report_json}")
- unexpected match findings: $(jq -r '.summary.unexpected_match_findings' <<<"${report_json}")
- approved exception findings: $(jq -r '.summary.approved_exception_findings' <<<"${report_json}")
- cleared findings: $(jq -r '.summary.cleared_findings' <<<"${report_json}")

Recipes:
- local/ci: bash scripts/ci/placeholder_inventory_scan.sh --json-out docs/testing/placeholder-scan.json --log-out docs/testing/placeholder-scan.log
- seeded fixture: bash scripts/e2e/placeholder_inventory_scan_fixture.sh

Approved exception classes:"

while IFS= read -r line; do
  log_text+=$'
'"${line}"
done < <(
  jq -r '.approved_exception_classes[] | "- \(.id): \(.allowed_path_globs | join(", "))"' \
    <<<"${report_json}"
)

log_text+=$'

Findings:'

while IFS= read -r block; do
  log_text+=$'
'"${block}"
done < <(
  jq -r '
    .findings[]
    | "[" + .gate_status + "] "
      + .id + " (" + .classification + ", " + .disposition + ", owner " + .owner_bead + ")"
      + "\n  " + .title
      + "\n  reason: " + .gate_reason
      + "\n  anchors:"
      + (
          .anchors
          | map("\n    - [" + .status + "] " + .path + " :: " + .needle)
          | join("")
        )
      + (
          if (.unexpected_matches | length) == 0 then
            "\n  unexpected matches: none"
          else
            "\n  unexpected matches:"
            + (
                .unexpected_matches
                | map("\n    - " + .path + ":" + (.line | tostring) + " :: " + .needle)
                | join("")
              )
          end
        )
      + (
          if (.allowlisted_matches | length) == 0 then
            "\n  allowlisted matches: none"
          else
            "\n  allowlisted matches:"
            + (
                .allowlisted_matches
                | map("\n    - " + .path + ":" + (.line | tostring) + " :: " + .needle)
                | join("")
              )
          end
        )
  ' <<<"${report_json}"
)

log_text+=$'
'

if [[ -n "${JSON_OUT}" ]]; then
  mkdir -p "$(dirname "${JSON_OUT}")"
  printf '%s\n' "${report_json}" > "${JSON_OUT}"
fi

if [[ -n "${LOG_OUT}" ]]; then
  mkdir -p "$(dirname "${LOG_OUT}")"
  printf '%s' "${log_text}" > "${LOG_OUT}"
fi

if [[ -z "${JSON_OUT}" && -z "${LOG_OUT}" ]]; then
  printf '%s' "${log_text}"
fi

if jq -e '.summary.failing_findings == 0 and .summary.drifted == 0' <<<"${report_json}" >/dev/null; then
  exit 0
fi

exit 1
