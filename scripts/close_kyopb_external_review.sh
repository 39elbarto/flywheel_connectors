#!/usr/bin/env bash
set -euo pipefail

BEAD_ID="flywheel_connectors-kyopb.1.3.1.1.6.3"
REPO=""
REQUIRE_REVIEW_MARKER="1"

usage() {
  cat <<'EOF'
Usage: scripts/close_kyopb_external_review.sh [options]

Options:
  --bead <id>                 External review bead to validate
  --repo <owner/repo>          GitHub repository for contributor lookup
  --allow-markerless-comment   Only require a non-contributor comment author
  -h, --help                  Show this help

Validates the mechanical no-self-review gate for the KYOPB external lattice
crypto review bead. The gate passes only when the target Beads thread contains
at least one comment whose author is not present in the GitHub contributor list.
By default, that comment must also contain the marker
`external_review_attestation: complete` so local agent comments do not satisfy
the gate accidentally.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bead)
      BEAD_ID="$2"
      shift 2
      ;;
    --repo)
      REPO="$2"
      shift 2
      ;;
    --allow-markerless-comment)
      REQUIRE_REVIEW_MARKER="0"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 2
  fi
}

require_cmd br
require_cmd gh
require_cmd git
require_cmd jq

if [[ -z "${REPO}" ]]; then
  REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
fi

contributors_json="$(
  gh api --paginate "repos/${REPO}/contributors" --jq '.[].login' |
    jq -Rsc 'split("\n") | map(select(length > 0) | ascii_downcase)'
)"
comments_json="$(br comments list "${BEAD_ID}" --json)"

external_comments_json="$(
  jq -c \
    --argjson contributors "${contributors_json}" \
    --arg require_marker "${REQUIRE_REVIEW_MARKER}" '
      [
        .[]
        | . as $comment
        | (($comment.author // "") | ascii_downcase) as $author
        | (($comment.text // "") | ascii_downcase) as $text
        | select($author != "")
        | select(($contributors | index($author)) | not)
        | select(
            $require_marker == "0"
            or ($text | contains("external_review_attestation: complete"))
          )
        | {
            id: $comment.id,
            author: $comment.author,
            created_at: $comment.created_at
          }
      ]
    ' <<<"${comments_json}"
)"

external_count="$(jq 'length' <<<"${external_comments_json}")"

if [[ "${external_count}" -eq 0 ]]; then
  cat >&2 <<EOF
KYOPB external review closure gate failed.

Bead: ${BEAD_ID}
Repo: ${REPO}
Reason: no qualifying non-contributor review comment found.

Expected:
- A Beads comment on ${BEAD_ID} authored by the external reviewer identity.
- The author must not appear in gh api repos/${REPO}/contributors.
- Unless --allow-markerless-comment is passed, the comment text must include:
  external_review_attestation: complete

This script only enforces the mechanical contributor-list gate. The operator
must still verify the full reviewer identity policy in the runbook.
EOF
  exit 1
fi

jq -cn \
  --arg bead_id "${BEAD_ID}" \
  --arg repo "${REPO}" \
  --argjson external_comments "${external_comments_json}" \
  '{
    result: "pass",
    bead_id: $bead_id,
    repo: $repo,
    qualifying_external_review_comments: $external_comments
  }'
