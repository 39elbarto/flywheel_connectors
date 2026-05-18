#!/usr/bin/env bash
# workspace_source_hygiene.sh - fail on editor/patch backup artifacts in source roots.
#
# This is intentionally non-destructive: it only reports files that should not
# live under code, docs, workflow, or test roots. Operators must remove local
# ignored artifacts manually after explicit approval.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

usage() {
  cat <<'EOF'
Usage: scripts/ci/workspace_source_hygiene.sh [--repo-root <path>]

Fails when source/workflow roots contain editor, merge, or patch backup files
such as *.orig, *.rej, *.bak, *.tmp, *.swp, or *~.
EOF
}

while (($# > 0)); do
  case "$1" in
    --repo-root)
      REPO_ROOT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "${REPO_ROOT}" ]]; then
  echo "Repository root does not exist: ${REPO_ROOT}" >&2
  exit 2
fi

REPO_ROOT="$(cd "${REPO_ROOT}" && pwd)"
cd "${REPO_ROOT}"

scan_roots=()
for root in connectors crates scripts .github docs fuzz; do
  if [[ -d "${root}" ]]; then
    scan_roots+=("${root}")
  fi
done

if [[ "${#scan_roots[@]}" -eq 0 ]]; then
  echo "No source roots found under ${REPO_ROOT}" >&2
  exit 2
fi

findings="$(
  find "${scan_roots[@]}" \
    \( \
      -path '*/target/*' -o \
      -path '*/.git/*' -o \
      -path '*/.beads/*' -o \
      -path '*/artifacts/*' -o \
      -path '*/coverage/*' \
    \) -prune -o \
    -type f \
    \( \
      -name '*.orig' -o \
      -name '*.rej' -o \
      -name '*.bak' -o \
      -name '*.bk' -o \
      -name '*.tmp' -o \
      -name '*.temp' -o \
      -name '*.swp' -o \
      -name '*.swo' -o \
      -name '*~' \
    \) -print \
    | LC_ALL=C sort
)"

if [[ -n "${findings}" ]]; then
  cat >&2 <<'EOF'
Workspace source hygiene check failed.

The following ignored/editor/patch backup artifacts are under source roots.
Do not delete them from an agent session without explicit operator approval.
EOF
  printf '%s\n' "${findings}" >&2
  exit 1
fi

echo "Workspace source hygiene check passed for: ${scan_roots[*]}"
