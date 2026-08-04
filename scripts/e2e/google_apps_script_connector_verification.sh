#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-/home/ubuntu/.cache/fcp-google-apps-script-verification}"
BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

cd "${REPO_ROOT}"

cargo fmt --all -- --check
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" \
  cargo check -p fcp-google-apps-script --all-targets
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" \
  cargo test -p fcp-google-apps-script --tests
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" \
  cargo clippy -p fcp-google-apps-script --all-targets --no-deps -- -D warnings
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" \
  cargo run -q -p fwc -- manifest fix connectors/google-apps-script/manifest.toml --check --json

echo "google-apps-script connector verification passed"
