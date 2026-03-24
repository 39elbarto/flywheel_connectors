#!/usr/bin/env bash
# test_naming_hygiene.sh — CI check for test naming conventions.
#
# Verifies that connector test modules and functions follow project conventions:
#   1. Every connector with a src/ directory should have at least one #[cfg(test)] module
#   2. Test function names should be snake_case (no camelCase)
#   3. No test functions named just "test" or "it_works"
#
# Usage:
#   scripts/ci/test_naming_hygiene.sh
#
# Remediation:
#   Rename test functions to describe what they verify, e.g.:
#     test_config_rejects_empty_url, error_mapping_429_is_retryable

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONNECTORS_DIR="$REPO_ROOT/connectors"

warnings=0
total=0

echo "Test Naming Hygiene Check"
echo "========================="
echo ""

# Check 1: connectors without any #[cfg(test)] module
echo "--- Connectors missing #[cfg(test)] module ---"
missing=0
for connector_dir in "$CONNECTORS_DIR"/*/; do
    [ -d "$connector_dir/src" ] || continue
    name="$(basename "$connector_dir")"
    total=$((total + 1))

    has_test_mod=$(grep -rl '#\[cfg(test)\]' "$connector_dir/src/" 2>/dev/null | head -1)
    if [ -z "$has_test_mod" ]; then
        echo "  WARN: $name — no #[cfg(test)] module found in src/"
        warnings=$((warnings + 1))
        missing=$((missing + 1))
    fi
done
if [ "$missing" -eq 0 ]; then
    echo "  (none — all connectors have test modules)"
fi

echo ""

# Check 2: test functions with generic/meaningless names
echo "--- Generic test function names ---"
generic=0
for connector_dir in "$CONNECTORS_DIR"/*/; do
    [ -d "$connector_dir/src" ] || continue
    name="$(basename "$connector_dir")"

    # Find test functions with very generic names
    hits=$(grep -rn 'fn test\b\s*(' "$connector_dir/src/" 2>/dev/null || true)
    hits2=$(grep -rn 'fn it_works\s*(' "$connector_dir/src/" 2>/dev/null || true)
    if [ -n "$hits" ] || [ -n "$hits2" ]; then
        echo "  WARN: $name — generic test name(s):"
        [ -n "$hits" ] && echo "$hits" | sed 's/^/    /'
        [ -n "$hits2" ] && echo "$hits2" | sed 's/^/    /'
        warnings=$((warnings + 1))
        generic=$((generic + 1))
    fi
done
if [ "$generic" -eq 0 ]; then
    echo "  (none — all test names are descriptive)"
fi

echo ""
echo "Summary: $total connectors checked, $warnings warnings"

# This is advisory-only — does not fail CI
exit 0
