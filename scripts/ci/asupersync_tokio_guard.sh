#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LEDGER_PATH="${REPO_ROOT}/.config/asupersync/tokio_exception_ledger.json"
REPORT_PATH="${REPO_ROOT}/artifacts/asupersync/guardrails/tokio_guard_report.json"

CI_MODE=false

usage() {
  cat <<'EOF'
Usage: scripts/ci/asupersync_tokio_guard.sh [options]

Validates ASUPERSYNC Tokio-prohibition guardrails for flywheel_connectors-1ud0u.

Options:
  --ledger <path>   Guardrail policy JSON path
  --report <path>   Output report JSON path
  --ci              CI mode: non-zero exit on any failure, machine-readable output
  -h, --help        Show this help
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ledger)
      LEDGER_PATH="$2"
      shift 2
      ;;
    --report)
      REPORT_PATH="$2"
      shift 2
      ;;
    --ci)
      CI_MODE=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

require_cmd jq
require_cmd rg
require_cmd cargo

if [[ ! -f "${LEDGER_PATH}" ]]; then
  echo "Ledger file not found: ${LEDGER_PATH}" >&2
  exit 1
fi

if ! jq -e '.schema_version == 1' "${LEDGER_PATH}" >/dev/null; then
  echo "Ledger schema_version must be 1: ${LEDGER_PATH}" >&2
  exit 1
fi

REPORT_DIR="$(dirname "${REPORT_PATH}")"
mkdir -p "${REPORT_DIR}"

NOW_EPOCH="$(date -u +%s)"
GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

DEP_SCAN_JSON="$(mktemp)"
ACTIVE_DEP_EXCEPTIONS_JSON="$(mktemp)"
EXPIRED_DEP_EXCEPTIONS_JSON="$(mktemp)"
MISSING_DEP_EXCEPTIONS_JSON="$(mktemp)"
INVARIANT_RESULTS_JSONL="$(mktemp)"
INVARIANT_RESULTS_JSON="$(mktemp)"
trap 'rm -f "${DEP_SCAN_JSON}" "${ACTIVE_DEP_EXCEPTIONS_JSON}" "${EXPIRED_DEP_EXCEPTIONS_JSON}" "${MISSING_DEP_EXCEPTIONS_JSON}" "${INVARIANT_RESULTS_JSONL}" "${INVARIANT_RESULTS_JSON}"' EXIT

FORBIDDEN_JSON="$(jq '.forbidden_direct_dependencies' "${LEDGER_PATH}")"

cargo metadata --format-version 1 --no-deps \
  | jq --argjson forbidden "${FORBIDDEN_JSON}" '
      [
        .packages[]
        | select(.manifest_path | test("/(crates|connectors)/"))
        | . as $pkg
        | .dependencies[] as $dep
        | select($forbidden | index($dep.name))
        | {
            crate: $pkg.name,
            dependency: $dep.name,
            kind: ($dep.kind // "normal"),
            manifest_path: $pkg.manifest_path
          }
      ]
    ' > "${DEP_SCAN_JSON}"

jq --argjson now "${NOW_EPOCH}" '
    [
      .dependency_exceptions[]
      | . + {expires_epoch: (.expires_on | fromdateiso8601)}
      | select(.expires_epoch >= $now)
    ]
  ' "${LEDGER_PATH}" > "${ACTIVE_DEP_EXCEPTIONS_JSON}"

jq --argjson now "${NOW_EPOCH}" '
    [
      .dependency_exceptions[]
      | . + {expires_epoch: (.expires_on | fromdateiso8601)}
      | select(.expires_epoch < $now)
    ]
  ' "${LEDGER_PATH}" > "${EXPIRED_DEP_EXCEPTIONS_JSON}"

jq --slurpfile exceptions "${ACTIVE_DEP_EXCEPTIONS_JSON}" '
    [
      .[] as $dep
      | $dep
      | select(
          (
            [
              $exceptions[0][]
              | select(
                  .crate == $dep.crate
                  and .dependency == $dep.dependency
                  and (
                    (.kind // "any") == "any"
                    or (.kind // "any") == $dep.kind
                  )
                )
            ]
            | length
          ) == 0
        )
    ]
  ' "${DEP_SCAN_JSON}" > "${MISSING_DEP_EXCEPTIONS_JSON}"

while IFS= read -r invariant; do
  id="$(jq -r '.id' <<< "${invariant}")"
  pattern="$(jq -r '.pattern' <<< "${invariant}")"
  max_count="$(jq -r '.max_count' <<< "${invariant}")"
  owner_bead="$(jq -r '.owner_bead' <<< "${invariant}")"
  expires_on="$(jq -r '.expires_on' <<< "${invariant}")"

  mapfile -t scope_paths < <(jq -r '.scope[]' <<< "${invariant}")
  scan_paths=()
  for rel_path in "${scope_paths[@]}"; do
    target="${REPO_ROOT}/${rel_path}"
    if [[ -e "${target}" ]]; then
      scan_paths+=("${target}")
    fi
  done

  if [[ ${#scan_paths[@]} -eq 0 ]]; then
    count=0
  else
    count="$( (rg -n --no-heading -e "${pattern}" "${scan_paths[@]}" 2>/dev/null || true) | wc -l | tr -d '[:space:]')"
  fi

  expired="$(jq -r --argjson now "${NOW_EPOCH}" '((.expires_on | fromdateiso8601) < $now)' <<< "${invariant}")"
  over_limit=false
  if (( count > max_count )); then
    over_limit=true
  fi

  status="pass"
  if [[ "${expired}" == "true" || "${over_limit}" == "true" ]]; then
    status="fail"
  fi

  jq -c -n \
    --arg id "${id}" \
    --arg pattern "${pattern}" \
    --arg owner_bead "${owner_bead}" \
    --arg expires_on "${expires_on}" \
    --argjson max_count "${max_count}" \
    --argjson count "${count}" \
    --argjson expired "$([[ "${expired}" == "true" ]] && echo true || echo false)" \
    --argjson over_limit "$([[ "${over_limit}" == "true" ]] && echo true || echo false)" \
    --arg status "${status}" \
    '{
      id: $id,
      pattern: $pattern,
      count: $count,
      max_count: $max_count,
      owner_bead: $owner_bead,
      expires_on: $expires_on,
      expired: $expired,
      over_limit: $over_limit,
      status: $status
    }' >> "${INVARIANT_RESULTS_JSONL}"
done < <(jq -c '.source_invariants[]' "${LEDGER_PATH}")

jq -s '.' "${INVARIANT_RESULTS_JSONL}" > "${INVARIANT_RESULTS_JSON}"

MISSING_DEP_COUNT="$(jq 'length' "${MISSING_DEP_EXCEPTIONS_JSON}")"
EXPIRED_DEP_COUNT="$(jq 'length' "${EXPIRED_DEP_EXCEPTIONS_JSON}")"
FAILED_INVARIANT_COUNT="$(jq '[.[] | select(.status != "pass")] | length' "${INVARIANT_RESULTS_JSON}")"

PASSED=true
if (( MISSING_DEP_COUNT > 0 || EXPIRED_DEP_COUNT > 0 || FAILED_INVARIANT_COUNT > 0 )); then
  PASSED=false
fi

jq -n \
  --arg generated_at "${GENERATED_AT}" \
  --arg ledger_path "${LEDGER_PATH}" \
  --arg report_version "1" \
  --argjson passed "$([[ "${PASSED}" == "true" ]] && echo true || echo false)" \
  --argjson forbidden_direct_dependencies "${FORBIDDEN_JSON}" \
  --slurpfile direct_forbidden_dependencies "${DEP_SCAN_JSON}" \
  --slurpfile missing_dependency_exceptions "${MISSING_DEP_EXCEPTIONS_JSON}" \
  --slurpfile expired_dependency_exceptions "${EXPIRED_DEP_EXCEPTIONS_JSON}" \
  --slurpfile source_invariants "${INVARIANT_RESULTS_JSON}" \
  '{
    report_version: $report_version,
    generated_at: $generated_at,
    ledger_path: $ledger_path,
    passed: $passed,
    forbidden_direct_dependencies: $forbidden_direct_dependencies,
    direct_forbidden_dependencies: $direct_forbidden_dependencies[0],
    missing_dependency_exceptions: $missing_dependency_exceptions[0],
    expired_dependency_exceptions: $expired_dependency_exceptions[0],
    source_invariants: $source_invariants[0],
    summary: {
      missing_dependency_exceptions: ($missing_dependency_exceptions[0] | length),
      expired_dependency_exceptions: ($expired_dependency_exceptions[0] | length),
      failed_source_invariants: ([ $source_invariants[0][] | select(.status != "pass") ] | length)
    }
  }' > "${REPORT_PATH}"

echo "ASUPERSYNC Tokio guardrail report: ${REPORT_PATH}"
jq -r '
  [
    "passed=\(.passed)",
    "missing_dependency_exceptions=\(.summary.missing_dependency_exceptions)",
    "expired_dependency_exceptions=\(.summary.expired_dependency_exceptions)",
    "failed_source_invariants=\(.summary.failed_source_invariants)"
  ] | join(" ")
' "${REPORT_PATH}"

if [[ "${PASSED}" != "true" ]]; then
  echo "" >&2
  echo "====== ASUPERSYNC TOKIO GUARD FAILURE ======" >&2
  echo "" >&2

  if (( MISSING_DEP_COUNT > 0 )); then
    echo "FORBIDDEN DEPENDENCY VIOLATIONS (${MISSING_DEP_COUNT}):" >&2
    echo "  These crates still depend on forbidden Tokio-related crates." >&2
    echo "  Fix: remove the dependency; the guardrail is zero-tolerance." >&2
    jq -r '.[] | "  - \(.crate) depends on \(.dependency) (\(.kind))"' "${MISSING_DEP_EXCEPTIONS_JSON}" >&2
    echo "" >&2
  fi

  if (( EXPIRED_DEP_COUNT > 0 )); then
    echo "STALE LEGACY EXCEPTION ENTRIES (${EXPIRED_DEP_COUNT}):" >&2
    echo "  Legacy exception records remain in the policy file and must be deleted." >&2
    echo "  Fix: remove the stale records or complete the underlying migration immediately." >&2
    jq -r '.[] | "  - \(.crate)/\(.dependency) expired \(.expires_on) (owner: \(.owner_bead))"' "${EXPIRED_DEP_EXCEPTIONS_JSON}" >&2
    echo "" >&2
  fi

  if (( FAILED_INVARIANT_COUNT > 0 )); then
    echo "FAILED SOURCE INVARIANTS (${FAILED_INVARIANT_COUNT}):" >&2
    echo "  These pattern counts exceed the allowed maximum. Tokio usage is still present." >&2
    echo "  Fix: remove the remaining Tokio references; the guardrail is zero-tolerance." >&2
    jq -r '[.source_invariants[] | select(.status != "pass")] | .[] | "  - \(.id): count=\(.count) max=\(.max_count) (over_limit=\(.over_limit), expired=\(.expired))"' "${REPORT_PATH}" >&2
    echo "" >&2
  fi

  echo "Report: ${REPORT_PATH}" >&2
  echo "Ledger: ${LEDGER_PATH}" >&2
  echo "Bead: flywheel_connectors-1ud0u.4" >&2
  echo "" >&2
  echo "============================================" >&2
  exit 1
fi
