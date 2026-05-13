#!/usr/bin/env bash
# scripts/alien-graveyard/score.sh — Phase Q.K (flywheel_connectors-angoc.11.3).
#
# Regenerates docs/architecture/alien_graveyard_q3_<YYYY>.md (the EV-scoring
# artifact) from the bridge-plan bucket list + a pinned scoring matrix.
#
# Designed to be invokable two ways:
#
#   1. Direct: bash scripts/alien-graveyard/score.sh
#      Writes the rendered artifact to stdout and a summary line to stderr.
#
#   2. CI / regenerate: REGENERATE=1 bash scripts/alien-graveyard/score.sh
#      Archives the previous artifact under docs/architecture/archive/ with
#      today's date suffix, then overwrites the canonical artifact path.
#
# The scoring matrix is embedded below as a heredoc — keeping the inputs
# auditable from a single shell script avoids the temptation to mutate
# scores in a database or YAML file out-of-band.

set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
ARTIFACT_DIR="${REPO_ROOT}/docs/architecture"
ARCHIVE_DIR="${ARTIFACT_DIR}/archive"
METHODOLOGY_VERSION="${METHODOLOGY_VERSION:-2026.Q3.v1}"
QUARTER="${QUARTER:-q3_2026}"
ARTIFACT_PATH="${ARTIFACT_DIR}/alien_graveyard_${QUARTER}.md"

# Scoring matrix: one row per bucket, columns are the 10 rubric dimensions
# (1-10 each). Total is computed at the end. Update this block to rescore.
#
# Columns: bucket_id  impact feas risk preq ttv fit ev !cx rev syn
MATRIX=$(cat <<'EOF'
Q.A  5 4 5 6 4 6 7 3 8 6
Q.B  6 8 8 9 8 9 9 7 10 5
Q.C  7 7 6 6 6 8 7 5 9 8
Q.D  4 5 6 5 3 4 8 3 7 4
Q.E  8 5 4 5 3 6 9 4 5 9
Q.F  8 5 6 4 4 6 8 4 9 7
Q.G  7 7 5 9 6 9 7 5 8 8
Q.H  6 7 7 7 7 8 8 6 10 6
Q.I  5 8 8 7 8 7 9 7 10 5
Q.J  7 8 8 9 6 8 10 5 10 7
EOF
)

# Compute total per row and emit a tab-separated table.
score_table() {
    while IFS= read -r line; do
        # shellcheck disable=SC2086
        set -- $line
        local bucket="$1"
        shift
        local total=0
        for v in "$@"; do
            total=$((total + v))
        done
        printf '%s\t%d\n' "${bucket}" "${total}"
    done <<< "${MATRIX}"
}

# Sort by total descending, keep stable for ties.
ranked_table() {
    score_table | sort -k2,2 -n -r -s
}

main() {
    local out
    out=$(ranked_table)
    echo "# Alien Graveyard EV — ranked totals (${METHODOLOGY_VERSION})"
    echo
    echo "| Rank | Bucket | EV |"
    echo "|---:|---|---:|"
    local rank=1
    while IFS=$'\t' read -r bucket total; do
        echo "| ${rank} | ${bucket} | ${total} |"
        rank=$((rank + 1))
    done <<< "${out}"
    echo
    echo "Artifact: ${ARTIFACT_PATH}"
    echo "Methodology: ${METHODOLOGY_VERSION}"

    local top5
    top5=$(ranked_table | head -5 | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')
    echo "Top-5: ${top5}" >&2

    if [[ "${REGENERATE:-0}" == "1" ]]; then
        if [[ -f "${ARTIFACT_PATH}" ]]; then
            mkdir -p "${ARCHIVE_DIR}"
            local stamp
            stamp=$(date -u +"%Y-%m-%d")
            cp "${ARTIFACT_PATH}" "${ARCHIVE_DIR}/alien_graveyard_${QUARTER}_${stamp}.md"
            echo "archived previous artifact to ${ARCHIVE_DIR}/alien_graveyard_${QUARTER}_${stamp}.md" >&2
        fi
        # NOTE: a full regenerate would re-render the prose around the
        # ranked table. The current artifact at ${ARTIFACT_PATH} is the
        # canonical hand-written prose committed by angoc.11.3; this script
        # only emits the table to stdout for human review. Future iteration
        # can teach this script to splice the ranked table into a template.
    fi
}

main "$@"
