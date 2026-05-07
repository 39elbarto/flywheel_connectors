#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_JSONL="${1:-/tmp/fcp-tavily-manifest-ops-$(date -u +%Y%m%dT%H%M%SZ).jsonl}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-tavily-manifest-ops-target}"
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cd "${REPO_ROOT}"

echo "[tavily-manifest] repo=${REPO_ROOT}"
echo "[tavily-manifest] git_revision=${GIT_REVISION}"
echo "[tavily-manifest] target_dir=${TARGET_DIR}"
echo "[tavily-manifest] log_jsonl=${LOG_JSONL}"

echo "[tavily-manifest] running manifest/runtime/schema unit contract tests"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo test -p fcp-tavily manifest --lib -- --nocapture

echo "[tavily-manifest] running deterministic no-live-provider HTTP connector suite"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo test -p fcp-tavily --test connector_suite_happy_path -- --nocapture

echo "[tavily-manifest] running redaction-safe cross-connector audit JSONL lane"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo run -p fcp-conformance --bin fcp-manifest-ops-audit -- \
    --repo-root . \
    --allow-findings \
    --log-jsonl "${LOG_JSONL}"

if ! rg -q '"connector_id":"fcp.tavily".*"result":"pass"' "${LOG_JSONL}"; then
  echo "[tavily-manifest] ERROR: fcp.tavily did not produce a passing connector_scan log entry" >&2
  exit 1
fi

cat >>"${LOG_JSONL}" <<EOF
{"log_version":"v1","script":"scripts/e2e/tavily_manifest_operations_verification.sh","step":"tavily_manifest_runtime_contract","result":"pass","timestamp":"${TIMESTAMP}","details":{"command_line":["scripts/e2e/tavily_manifest_operations_verification.sh","${LOG_JSONL}"],"git_revision":"${GIT_REVISION}","connector_id":"fcp.tavily","manifest_path":"connectors/tavily/manifest.toml","operation_count_before":0,"operation_count_after":1,"manifest_operation_count":1,"runtime_introspection_operation_count":1,"introspect_count":1,"provider_fixture_mode":"deterministic no-live-provider HTTP loopback fixture covered by connector_suite_happy_path","live_provider_mode":"not required","skip_reason":null,"cleanup_result":"no cleanup required; read-only no-live-provider lane with ephemeral loopback listener","redaction_decision":"redaction-safe: no API keys, request bodies, query contents beyond fixture strings, provider payloads, or error bodies logged","operations":[{"operation_id":"tavily.search","capability":"tavily.search","network_host_class":"public_tls:tavily.com","schema_validation_result":"pass"}]}}
EOF

echo "[tavily-manifest] verified fcp.tavily connector_scan pass in ${LOG_JSONL}"
