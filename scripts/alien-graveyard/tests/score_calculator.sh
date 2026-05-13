#!/usr/bin/env bash
# Test harness for scripts/alien-graveyard/score.sh
# (flywheel_connectors-angoc.11.3 / Phase Q.K).

set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../../.." && pwd)}"
SCORE_SH="${REPO_ROOT}/scripts/alien-graveyard/score.sh"

if [[ ! -x "${SCORE_SH}" ]]; then
    echo "FAIL: ${SCORE_SH} not executable" >&2
    exit 2
fi

pass=0
fail=0

assert_equal() {
    local label="$1"
    local expected="$2"
    local actual="$3"
    if [[ "${expected}" == "${actual}" ]]; then
        echo "PASS: ${label}"
        pass=$((pass + 1))
    else
        echo "FAIL: ${label}"
        echo "  expected: ${expected}"
        echo "  actual:   ${actual}"
        fail=$((fail + 1))
    fi
}

# Test 1: invocation exits 0 and emits a ranked table to stdout.
out=$(bash "${SCORE_SH}" 2>/dev/null) && rc=0 || rc=$?
assert_equal "score.sh exit 0" "0" "${rc}"
echo "${out}" | grep -q "^# Alien Graveyard EV — ranked totals" && r1=ok || r1=missing-header
assert_equal "header present" "ok" "${r1}"

# Test 2: Top-1 is the bucket with the highest total. Per the pinned matrix,
# Q.B totals 79 and is the highest.
top1=$(bash "${SCORE_SH}" 2>/dev/null | awk -F'|' '/^\| 1 /{gsub(/ /,"",$3); print $3}')
assert_equal "Top-1 bucket is Q.B" "Q.B" "${top1}"

# Test 3: bottom-1 (rank 10) is Q.D (EV 49).
last=$(bash "${SCORE_SH}" 2>/dev/null | awk -F'|' '/^\| 10 /{gsub(/ /,"",$3); print $3}')
assert_equal "Rank-10 bucket is Q.D" "Q.D" "${last}"

# Test 4: top-5 list on stderr matches the canonical commitment.
err=$(bash "${SCORE_SH}" 2>&1 >/dev/null)
top5_line=$(echo "${err}" | grep "^Top-5:" | sed 's/^Top-5: //')
assert_equal "Top-5 commitment" "Q.B,Q.J,Q.I,Q.H,Q.G" "${top5_line}"

# Test 5: methodology version is exposed in stdout.
m_line=$(bash "${SCORE_SH}" 2>/dev/null | grep "^Methodology:" | sed 's/^Methodology: //')
assert_equal "Methodology version" "2026.Q3.v1" "${m_line}"

echo
echo "Summary: ${pass} passed, ${fail} failed"
[[ "${fail}" -eq 0 ]] || exit 1
exit 0
