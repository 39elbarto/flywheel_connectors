#!/usr/bin/env bash
# coverage_scanner.sh — Phase H.3 (flywheel_connectors-angoc.18.3).
#
# Walks connectors/ and emits a JSONL row per connector indicating whether
# the connector has tests/local_non_mock.rs (loopback acceptance) or
# tests/live_verification.rs (gated live verification). One of the two is
# required for the connector to count as "covered" under the Phase H
# coverage discipline.
#
# Output: one JSON object per line on stdout:
#   {"connector":"<name>","has_local_non_mock":<bool>,"has_live_verification":<bool>,"verdict":"covered"|"gap"}
#
# Exit code:
#   0 — every connector has at least one of the two files
#   1 — at least one connector has neither (gap detected)
#
# Designed for CI gating; the companion conformance test
# crates/fcp-conformance/tests/coverage_scanner_conformance.rs pins a
# baseline of currently-uncovered connectors so this script can run on a
# ratchet model without requiring the whole tree be fixed in one sweep.

set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
CONNECTORS_DIR="${REPO_ROOT}/connectors"

if [[ ! -d "${CONNECTORS_DIR}" ]]; then
    echo "coverage_scanner: connectors/ not found at ${CONNECTORS_DIR}" >&2
    exit 2
fi

gap_count=0
covered_count=0

# Iterate in sorted order for deterministic JSONL output.
while IFS= read -r connector_dir; do
    connector="$(basename "${connector_dir}")"
    has_local="false"
    has_live="false"
    [[ -f "${connector_dir}/tests/local_non_mock.rs" ]] && has_local="true"
    [[ -f "${connector_dir}/tests/live_verification.rs" ]] && has_live="true"

    if [[ "${has_local}" == "true" || "${has_live}" == "true" ]]; then
        verdict="covered"
        covered_count=$((covered_count + 1))
    else
        verdict="gap"
        gap_count=$((gap_count + 1))
    fi

    printf '{"connector":"%s","has_local_non_mock":%s,"has_live_verification":%s,"verdict":"%s"}\n' \
        "${connector}" "${has_local}" "${has_live}" "${verdict}"
done < <(find "${CONNECTORS_DIR}" -maxdepth 1 -mindepth 1 -type d | LC_ALL=C sort)

# Final summary to stderr so stdout stays clean JSONL.
echo "coverage_scanner: covered=${covered_count} gap=${gap_count}" >&2

if [[ "${gap_count}" -gt 0 ]]; then
    exit 1
fi
exit 0
