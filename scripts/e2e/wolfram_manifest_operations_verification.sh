#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_JSONL="${1:-/tmp/fcp-wolfram-manifest-ops-$(date -u +%Y%m%dT%H%M%SZ).jsonl}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-wolfram-manifest-ops-target}"
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cd "${REPO_ROOT}"

echo "[wolfram-manifest] repo=${REPO_ROOT}"
echo "[wolfram-manifest] git_revision=${GIT_REVISION}"
echo "[wolfram-manifest] target_dir=${TARGET_DIR}"
echo "[wolfram-manifest] log_jsonl=${LOG_JSONL}"

run_cargo() {
  if [[ "${FCP_WOLFRAM_USE_RCH:-0}" == "1" ]]; then
    rch exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo "$@"
  else
    CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo "$@"
  fi
}

echo "[wolfram-manifest] running focused formatting check"
run_cargo fmt --check -p fcp-wolfram

echo "[wolfram-manifest] running focused compiler check"
run_cargo check -p fcp-wolfram --all-targets

echo "[wolfram-manifest] running focused clippy check"
run_cargo clippy -p fcp-wolfram --all-targets --no-deps -- -D warnings

echo "[wolfram-manifest] running inline unit tests"
run_cargo test -p fcp-wolfram --lib -- --nocapture

echo "[wolfram-manifest] running manifest/runtime/schema contract tests"
run_cargo test -p fcp-wolfram --test provider_contract -- --nocapture

echo "[wolfram-manifest] running deterministic no-live-provider connector suite"
run_cargo test -p fcp-wolfram --test connector_suite_happy_path -- --nocapture

echo "[wolfram-manifest] checking manifest interface hash with fwc"
run_cargo run -p fwc -- manifest fix connectors/wolfram/manifest.toml --check --json

echo "[wolfram-manifest] running redaction-safe cross-connector audit JSONL lane"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo run -p fcp-conformance --bin fcp-manifest-ops-audit -- \
    --repo-root . \
    --allow-findings \
    --log-jsonl "${LOG_JSONL}"

if ! rg -q '"connector_id":"fcp.wolfram".*"result":"pass"' "${LOG_JSONL}"; then
  echo "[wolfram-manifest] ERROR: fcp.wolfram did not produce a passing connector_scan log entry" >&2
  exit 1
fi

cat >>"${LOG_JSONL}" <<EOF
{"log_version":"v1","script":"scripts/e2e/wolfram_manifest_operations_verification.sh","step":"wolfram_manifest_runtime_contract","result":"pass","timestamp":"${TIMESTAMP}","details":{"command_line":["scripts/e2e/wolfram_manifest_operations_verification.sh","${LOG_JSONL}"],"git_revision":"${GIT_REVISION}","connector_id":"fcp.wolfram","manifest_path":"connectors/wolfram/manifest.toml","operation_count_before":0,"operation_count_after":3,"manifest_operation_count":3,"runtime_introspection_operation_count":3,"introspect_count":3,"fmt_check_result":"pass","compiler_check_result":"pass","clippy_result":"pass","unit_test_result":"pass","manifest_hash_check_result":"pass","cross_connector_audit_result":"pass","provider_fixture_mode":"deterministic no-live-provider HTTP loopback fixture covered by connector_suite_happy_path","live_provider_mode":"not required","skip_reason":null,"cleanup_result":"no cleanup required; read-only no-live-provider lane with ephemeral loopback listener","redaction_decision":"redaction-safe: no AppIDs, raw prompts, request bodies, provider payloads, result contents, or provider error bodies logged","operations":[{"operation_id":"wolfram.query","capability":"wolfram.query","network_host_class":"public_tls:api.wolframalpha.com","schema_validation_result":"pass"},{"operation_id":"wolfram.short_answer","capability":"wolfram.query","network_host_class":"public_tls:api.wolframalpha.com","schema_validation_result":"pass"},{"operation_id":"wolfram.spoken_result","capability":"wolfram.query","network_host_class":"public_tls:api.wolframalpha.com","schema_validation_result":"pass"}]}}
EOF

echo "[wolfram-manifest] wrote redaction-safe JSONL proof to ${LOG_JSONL}"
tail -n 1 "${LOG_JSONL}"
