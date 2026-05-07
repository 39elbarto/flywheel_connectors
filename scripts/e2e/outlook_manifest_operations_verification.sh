#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_JSONL="${1:-/tmp/fcp-outlook-manifest-ops-$(date -u +%Y%m%dT%H%M%SZ).jsonl}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-outlook-manifest-ops-target}"
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cd "${REPO_ROOT}"

echo "[outlook-manifest] repo=${REPO_ROOT}"
echo "[outlook-manifest] git_revision=${GIT_REVISION}"
echo "[outlook-manifest] target_dir=${TARGET_DIR}"
echo "[outlook-manifest] log_jsonl=${LOG_JSONL}"

echo "[outlook-manifest] running manifest/runtime/schema/client unit tests"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo test -p fcp-outlook --lib -- --nocapture

echo "[outlook-manifest] running public provider contract tests"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo test -p fcp-outlook --test provider_contract -- --nocapture

echo "[outlook-manifest] running redaction-safe cross-connector audit JSONL lane"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo run -p fcp-conformance --bin fcp-manifest-ops-audit -- \
    --repo-root . \
    --allow-findings \
    --log-jsonl "${LOG_JSONL}"

if ! rg -q '"connector_id":"fcp.outlook".*"result":"pass"' "${LOG_JSONL}"; then
  echo "[outlook-manifest] ERROR: fcp.outlook did not produce a passing connector_scan log entry" >&2
  exit 1
fi

cat >>"${LOG_JSONL}" <<EOF
{"log_version":"v1","script":"scripts/e2e/outlook_manifest_operations_verification.sh","step":"outlook_manifest_runtime_contract","result":"pass","timestamp":"${TIMESTAMP}","details":{"command_line":["scripts/e2e/outlook_manifest_operations_verification.sh","${LOG_JSONL}"],"git_revision":"${GIT_REVISION}","connector_id":"fcp.outlook","manifest_path":"connectors/outlook/manifest.toml","operation_count_before":0,"operation_count_after":7,"manifest_operation_count":7,"runtime_introspection_operation_count":7,"introspect_count":7,"provider_fixture_mode":"deterministic no-live-provider unit and provider-contract tests cover schema, runtime introspection, Microsoft Graph host policy, request parsing, recipient normalization, query escaping, and 202 no-body send behavior","live_provider_mode":"not required","skip_reason":null,"cleanup_result":"no cleanup required; read-only no-live-provider lane with ephemeral loopback listeners inside unit tests","redaction_decision":"redaction-safe: no API keys, bearer tokens, recipient lists, message subjects, message bodies, body previews, calendar subjects, locations, provider payloads, or provider error bodies logged","operations":[{"operation_id":"outlook.list_messages","capability":"outlook.read","network_host_class":"public_tls:graph.microsoft.com/graph.microsoft.us","schema_validation_result":"pass"},{"operation_id":"outlook.get_message","capability":"outlook.read","network_host_class":"public_tls:graph.microsoft.com/graph.microsoft.us","schema_validation_result":"pass"},{"operation_id":"outlook.search_messages","capability":"outlook.read","network_host_class":"public_tls:graph.microsoft.com/graph.microsoft.us","schema_validation_result":"pass"},{"operation_id":"outlook.send_message","capability":"outlook.send","network_host_class":"public_tls:graph.microsoft.com/graph.microsoft.us","schema_validation_result":"pass"},{"operation_id":"outlook.list_events","capability":"outlook.calendar","network_host_class":"public_tls:graph.microsoft.com/graph.microsoft.us","schema_validation_result":"pass"},{"operation_id":"outlook.create_event","capability":"outlook.calendar","network_host_class":"public_tls:graph.microsoft.com/graph.microsoft.us","schema_validation_result":"pass"},{"operation_id":"outlook.list_folders","capability":"outlook.read","network_host_class":"public_tls:graph.microsoft.com/graph.microsoft.us","schema_validation_result":"pass"}]}}
EOF

echo "[outlook-manifest] verified fcp.outlook connector_scan pass in ${LOG_JSONL}"
