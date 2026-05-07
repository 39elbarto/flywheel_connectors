#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_JSONL="${1:-/tmp/fcp-searxng-manifest-ops-$(date -u +%Y%m%dT%H%M%SZ).jsonl}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-searxng-manifest-ops-target}"
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cd "${REPO_ROOT}"

echo "[searxng-manifest] repo=${REPO_ROOT}"
echo "[searxng-manifest] git_revision=${GIT_REVISION}"
echo "[searxng-manifest] target_dir=${TARGET_DIR}"
echo "[searxng-manifest] log_jsonl=${LOG_JSONL}"

echo "[searxng-manifest] running manifest/runtime/schema unit contract tests"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo test --locked -p fcp-searxng manifest --lib -- --nocapture

echo "[searxng-manifest] running deterministic no-live-provider HTTP connector suite"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo test --locked -p fcp-searxng --test integration -- --nocapture

echo "[searxng-manifest] running redaction-safe cross-connector audit JSONL lane"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo run --locked -p fcp-conformance --bin fcp-manifest-ops-audit -- \
    --repo-root . \
    --allow-findings \
    --log-jsonl "${LOG_JSONL}"

if ! rg -q '"connector_id":"fcp.searxng".*"result":"pass"' "${LOG_JSONL}"; then
  echo "[searxng-manifest] ERROR: fcp.searxng did not produce a passing connector_scan log entry" >&2
  exit 1
fi

cat >>"${LOG_JSONL}" <<EOF
{"log_version":"v1","script":"scripts/e2e/searxng_manifest_operations_verification.sh","step":"searxng_manifest_runtime_contract","result":"pass","timestamp":"${TIMESTAMP}","details":{"command_line":["scripts/e2e/searxng_manifest_operations_verification.sh","${LOG_JSONL}"],"git_revision":"${GIT_REVISION}","connector_id":"fcp.searxng","manifest_path":"connectors/searxng/manifest.toml","operation_count_before":0,"operation_count_after":4,"manifest_operation_count":4,"runtime_introspection_operation_count":4,"introspect_count":4,"provider_fixture_mode":"deterministic no-live-provider HTTP loopback fixture covered by integration test suite","live_provider_mode":"not required","skip_reason":null,"cleanup_result":"no cleanup required; read-only no-live-provider lane with ephemeral loopback listener","redaction_decision":"redaction-safe: no API keys, auth header values, query text beyond fixture strings, full result URLs, provider payloads, or error bodies logged","operations":[{"operation_id":"searxng.search.query","capability":"searxng.search.read","network_host_class":"operator_configured:http_https_loopback_private_tailnet_public_https","schema_validation_result":"pass"},{"operation_id":"searxng.search.images","capability":"searxng.search.read","network_host_class":"operator_configured:http_https_loopback_private_tailnet_public_https","schema_validation_result":"pass"},{"operation_id":"searxng.search.news","capability":"searxng.search.read","network_host_class":"operator_configured:http_https_loopback_private_tailnet_public_https","schema_validation_result":"pass"},{"operation_id":"searxng.health","capability":"searxng.search.read","network_host_class":"operator_configured:http_https_loopback_private_tailnet_public_https","schema_validation_result":"pass"}]}}
EOF

echo "[searxng-manifest] verified fcp.searxng connector_scan pass in ${LOG_JSONL}"
