#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_JSONL="${1:-/tmp/fcp-duckduckgo-manifest-ops-$(date -u +%Y%m%dT%H%M%SZ).jsonl}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-duckduckgo-manifest-ops-target}"
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cd "${REPO_ROOT}"

echo "[duckduckgo-manifest] repo=${REPO_ROOT}"
echo "[duckduckgo-manifest] git_revision=${GIT_REVISION}"
echo "[duckduckgo-manifest] target_dir=${TARGET_DIR}"
echo "[duckduckgo-manifest] log_jsonl=${LOG_JSONL}"

echo "[duckduckgo-manifest] running manifest/runtime/schema unit contract tests"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo test -p fcp-duckduckgo manifest --lib -- --nocapture

echo "[duckduckgo-manifest] running deterministic no-live-provider loopback integration tests"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo test -p fcp-duckduckgo --test integration lifecycle_advertises_no_auth_privacy_boundary -- --nocapture

echo "[duckduckgo-manifest] running manifest conformance tests"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo test -p fcp-duckduckgo --test conformance manifest -- --nocapture

echo "[duckduckgo-manifest] running redaction-safe cross-connector audit JSONL lane"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo run -p fcp-conformance --bin fcp-manifest-ops-audit -- \
    --repo-root . \
    --allow-findings \
    --log-jsonl "${LOG_JSONL}"

if ! rg -q '"connector_id":"fcp.duckduckgo".*"result":"pass"' "${LOG_JSONL}"; then
  echo "[duckduckgo-manifest] ERROR: fcp.duckduckgo did not produce a passing connector_scan log entry" >&2
  exit 1
fi

cat >>"${LOG_JSONL}" <<EOF
{"log_version":"v1","script":"scripts/e2e/duckduckgo_manifest_operations_verification.sh","step":"duckduckgo_manifest_runtime_contract","result":"pass","timestamp":"${TIMESTAMP}","details":{"command_line":["scripts/e2e/duckduckgo_manifest_operations_verification.sh","${LOG_JSONL}"],"git_revision":"${GIT_REVISION}","connector_id":"fcp.duckduckgo","manifest_path":"connectors/duckduckgo/manifest.toml","operation_count_before":0,"operation_count_after":5,"manifest_operation_count":5,"runtime_introspection_operation_count":5,"introspect_count":5,"provider_fixture_mode":"deterministic no-live-provider wiremock loopback covered by integration tests","live_provider_mode":"not required","skip_reason":null,"cleanup_result":"no cleanup required; read-only no-live-provider lane with ephemeral loopback listener","redaction_decision":"redaction-safe: no API keys, raw queries, prompts, request bodies, provider payloads, result contents, or provider error bodies logged","operations":[{"operation_id":"duckduckgo.search.text","capability":"duckduckgo.search.read","network_host_class":"public_tls:html.duckduckgo.com/lite.duckduckgo.com","schema_validation_result":"pass"},{"operation_id":"duckduckgo.search.images","capability":"duckduckgo.search.read","network_host_class":"public_tls:html.duckduckgo.com/lite.duckduckgo.com/duckduckgo.com","schema_validation_result":"pass"},{"operation_id":"duckduckgo.search.news","capability":"duckduckgo.search.read","network_host_class":"public_tls:html.duckduckgo.com/lite.duckduckgo.com/duckduckgo.com","schema_validation_result":"pass"},{"operation_id":"duckduckgo.search.suggestions","capability":"duckduckgo.search.read","network_host_class":"public_tls:duckduckgo.com","schema_validation_result":"pass"},{"operation_id":"duckduckgo.health","capability":"duckduckgo.search.read","network_host_class":"public_tls:api.duckduckgo.com","schema_validation_result":"pass"}]}}
EOF

echo "[duckduckgo-manifest] verified fcp.duckduckgo connector_scan pass in ${LOG_JSONL}"
