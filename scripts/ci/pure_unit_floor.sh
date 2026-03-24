#!/usr/bin/env bash
# pure_unit_floor.sh — CI gate for minimum unit-test presence per connector.
#
# Scans every connector crate's src/ directory for #[test] and
# #[fcp_async_core::runtime::test] annotations.  Fails (exit 1) if any
# connector falls below MINIMUM_TESTS.
#
# Usage:
#   scripts/ci/pure_unit_floor.sh            # default minimum = 5
#   MINIMUM_TESTS=10 scripts/ci/pure_unit_floor.sh
#
# Remediation:
#   If a connector is below the floor, add unit tests to its src/ files.
#   Every connector should have at least:
#     - Error type construction + retryability tests
#     - Config deserialization tests
#     - Operation info / metadata tests
#   See connectors/anthropic/src/ for a reference pattern.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONNECTORS_DIR="$REPO_ROOT/connectors"
MINIMUM_TESTS="${MINIMUM_TESTS:-5}"

violations=0
total_connectors=0
total_tests=0

# Collect results for sorted output
declare -a results=()

for connector_dir in "$CONNECTORS_DIR"/*/; do
    [ -d "$connector_dir/src" ] || continue
    name="$(basename "$connector_dir")"
    total_connectors=$((total_connectors + 1))

    count=$(grep -rc '#\[test\]\|#\[fcp_async_core::runtime::test\]' "$connector_dir/src/" 2>/dev/null \
        | awk -F: '{sum+=$2} END {print sum+0}')
    total_tests=$((total_tests + count))

    if [ "$count" -lt "$MINIMUM_TESTS" ]; then
        results+=("FAIL  ${count}  ${name}")
        violations=$((violations + 1))
    else
        results+=("ok    ${count}  ${name}")
    fi
done

# Print sorted (failures first, then by count ascending)
printf "%-6s %4s  %s\n" "STATUS" "TESTS" "CONNECTOR"
printf "%-6s %4s  %s\n" "------" "-----" "---------"
# Failures first
for line in "${results[@]}"; do
    if [[ "$line" == FAIL* ]]; then
        printf "%s\n" "$line"
    fi
done
# Then passes
for line in "${results[@]}"; do
    if [[ "$line" == ok* ]]; then
        printf "%s\n" "$line"
    fi
done

echo ""
echo "Summary: ${total_connectors} connectors, ${total_tests} total tests, ${violations} below floor (minimum=${MINIMUM_TESTS})"

if [ "$violations" -gt 0 ]; then
    echo ""
    echo "FAILED: ${violations} connector(s) below the pure-unit floor of ${MINIMUM_TESTS} tests."
    echo ""
    echo "Remediation:"
    echo "  1. Add unit tests to the failing connector's src/ files."
    echo "  2. At minimum, test: error types, config parsing, operation metadata."
    echo "  3. Re-run: scripts/ci/pure_unit_floor.sh"
    exit 1
fi

echo "PASSED: All connectors meet the pure-unit floor."
exit 0
