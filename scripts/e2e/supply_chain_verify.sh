#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_NAME="supply_chain_verify"
SCHEMA_VERSION="fcp-supply-chain-e2e/v1"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT=""

CONNECTOR_ID="fcp.telegram:base:v1"
ZONE_ID="z:work"
TARGET_DIR="${SUPPLY_CHAIN_VERIFY_TARGET_DIR:-/tmp/fcp-supply-chain-verify}"
HOST_OVERRIDE_TEST="fcp_host_binary_supply_chain_verify_route_honors_dev_override_env"

usage() {
  cat <<'EOF'
Usage: scripts/e2e/supply_chain_verify.sh [options]

Exercises the supply-chain verification flow across:
  - `fcp connector verify`
  - `fcp install --verify-only`
  - `fcp connector report --supply-chain`
  - the live `fcp-host` dev-override verification route test

Options:
  --run-id <id>      Stable run identifier (default: UTC timestamp)
  --out-root <path>  Artifact root (default: artifacts/supply-chain/<run-id>)
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)
      RUN_ID="${2:-}"
      shift 2
      ;;
    --out-root)
      OUT_ROOT="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

now_ms() {
  local now
  now=$(date +%s%3N 2>/dev/null || true)
  if [[ -z "${now}" || "${now}" == *N ]]; then
    now="$(date +%s)000"
  fi
  printf '%s' "${now}"
}

run_cargo() {
  (
    cd "${REPO_ROOT}"
    rch exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" cargo "$@"
  )
}

run_fcp_json() {
  local stdout_path="$1"
  local stderr_path="$2"
  shift 2
  run_cargo run -q -p fcp-cli --bin fcp -- "$@" >"${stdout_path}" 2>"${stderr_path}"
}

run_exact_test() {
  local package="$1"
  local integration_test="$2"
  local test_name="$3"
  local log_path="$4"
  run_cargo test -p "${package}" --test "${integration_test}" "${test_name}" -- --exact --nocapture \
    >"${log_path}" 2>&1
}

record_step() {
  local test_name="$1"
  local stage="$2"
  local bundle_id="$3"
  local result="$4"
  local duration_ms="$5"
  local error_code="${6:-}"
  local evidence_id="${7:-}"
  local decision="${8:-}"
  local reason_code="${9:-}"
  local output_path="${10:-}"

  jq -cn \
    --arg schema_version "${SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg test "${test_name}" \
    --arg stage "${stage}" \
    --arg bundle_id "${bundle_id}" \
    --arg result "${result}" \
    --arg error_code "${error_code}" \
    --arg evidence_id "${evidence_id}" \
    --arg decision "${decision}" \
    --arg reason_code "${reason_code}" \
    --arg output_path "${output_path}" \
    --argjson duration_ms "${duration_ms}" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      test: $test,
      stage: $stage,
      bundle_id: $bundle_id,
      result: $result,
      error_code: (if ($error_code | length) == 0 then null else $error_code end),
      evidence_id: (if ($evidence_id | length) == 0 then null else $evidence_id end),
      decision: (if ($decision | length) == 0 then null else $decision end),
      reason_code: (if ($reason_code | length) == 0 then null else $reason_code end),
      duration_ms: $duration_ms,
      output_path: (if ($output_path | length) == 0 then null else $output_path end)
    }' >> "${LOG_JSONL}"
}

validate_log() {
  local line_no=0
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line_no=$((line_no + 1))
    [[ -z "${line//[[:space:]]/}" ]] && continue
    jq -e '
      (.schema_version | type == "string")
      and (.run_id | type == "string")
      and (.test | type == "string")
      and (.stage | type == "string")
      and (.bundle_id | type == "string")
      and (.result | type == "string")
      and (.duration_ms | type == "number")
    ' <<<"${line}" >/dev/null || {
      echo "Invalid step record at line ${line_no}" >&2
      echo "${line}" >&2
      exit 1
    }
  done < "${LOG_JSONL}"
}

write_attestation() {
  local path="$1"
  local digest="$2"
  local slsa_level="$3"
  jq -n \
    --arg digest "${digest}" \
    --argjson slsa_level "${slsa_level}" \
    '{
      format: "fcp-supply-chain-attestation",
      schema_version: "1.0",
      subject_digest: $digest,
      predicate_type: "https://slsa.dev/provenance/v1",
      builder_id: "builder://github/actions",
      build_type: "https://slsa.dev/container-based-build/v1",
      materials: [
        {
          uri: "git+https://github.com/flywheel/connectors@refs/heads/main",
          digest: "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
      ],
      metadata: {
        build_started_at: "2026-02-01T12:00:00Z",
        build_finished_at: "2026-02-01T12:05:00Z",
        invocation_id: "gha-run-42"
      },
      slsa_level: $slsa_level,
      provenance_hash: "blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      trust_root: {
        root_type: "sigstore",
        root_id: "sigstore-public-good"
      },
      builder_allowlist: ["builder://github/actions"],
      signature: {
        algorithm: "ed25519",
        key_id: "owner-key-1",
        signature: "sig-data",
        signed_fields: [
          "format",
          "schema_version",
          "subject_digest",
          "predicate_type",
          "builder_id",
          "build_type",
          "materials",
          "metadata",
          "slsa_level",
          "provenance_hash",
          "trust_root",
          "builder_allowlist"
        ]
      }
    }' > "${path}"
}

write_sbom() {
  local path="$1"
  local digest="$2"
  jq -n \
    --arg connector_id "${CONNECTOR_ID}" \
    --arg digest "${digest}" \
    '{
      format: "fcp-sbom",
      schema_version: "1.0",
      bom_format: "cyclonedx",
      bom_version: "1",
      tool_chain: ["cargo", "rustc"],
      components: [
        {
          component_id: $connector_id,
          name: $connector_id,
          version: "1.0.0",
          hashes: [$digest],
          licenses: ["Apache-2.0"]
        }
      ],
      dependencies: [],
      trust_root: {
        root_type: "sigstore",
        root_id: "sbom-root"
      },
      signature: {
        algorithm: "ed25519",
        key_id: "owner-key-1",
        signature: "sig-data",
        signed_fields: [
          "format",
          "schema_version",
          "bom_format",
          "bom_version",
          "tool_chain",
          "components",
          "dependencies",
          "trust_root"
        ]
      }
    }' > "${path}"
}

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/supply-chain/${RUN_ID}"
fi

LOG_JSONL="${OUT_ROOT}/steps.jsonl"
SUMMARY_JSON="${OUT_ROOT}/summary.json"
REPLAY_SH="${OUT_ROOT}/replay.sh"
RAW_DIR="${OUT_ROOT}/raw"
FIXTURE_DIR="${OUT_ROOT}/fixtures"

VALID_VERIFY_JSON="${RAW_DIR}/verify_valid.json"
VALID_VERIFY_STDERR="${RAW_DIR}/verify_valid.stderr"
VALID_INSTALL_JSON="${RAW_DIR}/install_valid.json"
VALID_INSTALL_STDERR="${RAW_DIR}/install_valid.stderr"
INVALID_INSTALL_JSON="${RAW_DIR}/install_invalid.json"
INVALID_INSTALL_STDERR="${RAW_DIR}/install_invalid.stderr"
VALID_REPORT_JSON="${RAW_DIR}/report_valid.json"
VALID_REPORT_STDERR="${RAW_DIR}/report_valid.stderr"
PREPARE_INSTALL_JSON="${RAW_DIR}/prepare_install.json"
PREPARE_INSTALL_STDERR="${RAW_DIR}/prepare_install.stderr"
HOST_OVERRIDE_LOG="${RAW_DIR}/host_dev_override.log"

VALID_ATTESTATION="${FIXTURE_DIR}/attestation.valid.json"
INVALID_ATTESTATION="${FIXTURE_DIR}/attestation.invalid.json"
VALID_SBOM="${FIXTURE_DIR}/sbom.valid.json"

require_cmd jq
require_cmd rch
require_cmd bash

mkdir -p "${RAW_DIR}" "${FIXTURE_DIR}"
: > "${LOG_JSONL}"

cat > "${REPLAY_SH}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "${REPO_ROOT}"
bash scripts/e2e/supply_chain_verify.sh --run-id "${RUN_ID}" --out-root "${OUT_ROOT}"
EOF
chmod +x "${REPLAY_SH}"

# Prepare artifact digest from the real install flow before generating fixtures.
run_fcp_json "${PREPARE_INSTALL_JSON}" "${PREPARE_INSTALL_STDERR}" \
  install "${CONNECTOR_ID}" --zone "${ZONE_ID}" --verify-only --json

ARTIFACT_DIGEST="$(jq -r '.verification.supply_chain_artifact_digest' "${PREPARE_INSTALL_JSON}")"
if [[ -z "${ARTIFACT_DIGEST}" || "${ARTIFACT_DIGEST}" == "null" ]]; then
  echo "Failed to derive supply-chain artifact digest" >&2
  exit 1
fi

write_attestation "${VALID_ATTESTATION}" "${ARTIFACT_DIGEST}" 3
write_attestation "${INVALID_ATTESTATION}" "${ARTIFACT_DIGEST}" 1
write_sbom "${VALID_SBOM}" "${ARTIFACT_DIGEST}"

VERIFY_EVIDENCE_ID=""
INSTALL_EVIDENCE_ID=""
REPORT_EVIDENCE_ID=""
INVALID_ERROR_CODE=""

step_verify_valid() {
  local start_ms end_ms duration_ms evidence_id decision reason_code
  start_ms="$(now_ms)"
  run_fcp_json "${VALID_VERIFY_JSON}" "${VALID_VERIFY_STDERR}" \
    connector verify "${CONNECTOR_ID}" \
    --attestation "${VALID_ATTESTATION}" \
    --sbom "${VALID_SBOM}" \
    --digest "${ARTIFACT_DIGEST}" \
    --min-slsa-level 3 \
    --json
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  decision="$(jq -r '.decision' "${VALID_VERIFY_JSON}")"
  reason_code="$(jq -r '.reason_code' "${VALID_VERIFY_JSON}")"
  evidence_id="$(jq -r '.evidence_digest' "${VALID_VERIFY_JSON}")"

  [[ "${decision}" == "allow" ]]
  [[ "${reason_code}" == "verified" ]]
  [[ -n "${evidence_id}" && "${evidence_id}" != "null" ]]

  VERIFY_EVIDENCE_ID="${evidence_id}"
  record_step \
    "fcp connector verify" \
    "verify_valid" \
    "${CONNECTOR_ID}" \
    "pass" \
    "${duration_ms}" \
    "" \
    "${evidence_id}" \
    "${decision}" \
    "${reason_code}" \
    "${VALID_VERIFY_JSON}"
}

step_install_valid() {
  local start_ms end_ms duration_ms evidence_id decision reason_code
  start_ms="$(now_ms)"
  run_fcp_json "${VALID_INSTALL_JSON}" "${VALID_INSTALL_STDERR}" \
    install "${CONNECTOR_ID}" \
    --zone "${ZONE_ID}" \
    --verify-only \
    --attestation "${VALID_ATTESTATION}" \
    --sbom "${VALID_SBOM}" \
    --min-slsa-level 3 \
    --json
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  decision="allow"
  reason_code="$(jq -r '.verification.supply_chain_reason_code' "${VALID_INSTALL_JSON}")"
  evidence_id="$(jq -r '.verification.supply_chain_evidence_digest' "${VALID_INSTALL_JSON}")"

  jq -e '.verification.supply_chain_policy_satisfied == true' "${VALID_INSTALL_JSON}" >/dev/null
  [[ "${reason_code}" == "verified" ]]
  [[ -n "${evidence_id}" && "${evidence_id}" != "null" ]]
  [[ "${evidence_id}" == "${VERIFY_EVIDENCE_ID}" ]]

  INSTALL_EVIDENCE_ID="${evidence_id}"
  record_step \
    "fcp install --verify-only" \
    "install_valid" \
    "${CONNECTOR_ID}" \
    "pass" \
    "${duration_ms}" \
    "" \
    "${evidence_id}" \
    "${decision}" \
    "${reason_code}" \
    "${VALID_INSTALL_JSON}"
}

step_install_invalid() {
  local start_ms end_ms duration_ms rc error_code message
  start_ms="$(now_ms)"
  set +e
  run_fcp_json "${INVALID_INSTALL_JSON}" "${INVALID_INSTALL_STDERR}" \
    install "${CONNECTOR_ID}" \
    --zone "${ZONE_ID}" \
    --verify-only \
    --attestation "${INVALID_ATTESTATION}" \
    --sbom "${VALID_SBOM}" \
    --min-slsa-level 4 \
    --json
  rc=$?
  set -e
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  if [[ ${rc} -eq 0 ]]; then
    echo "Expected invalid install to fail" >&2
    exit 1
  fi

  error_code="$(jq -r '.code' "${INVALID_INSTALL_JSON}")"
  message="$(jq -r '.message' "${INVALID_INSTALL_JSON}")"

  [[ "${error_code}" == "FCP-4015" ]]
  [[ "${message}" == *"slsa_level_insufficient"* ]]

  INVALID_ERROR_CODE="${error_code}"
  record_step \
    "fcp install --verify-only" \
    "install_invalid" \
    "${CONNECTOR_ID}" \
    "pass" \
    "${duration_ms}" \
    "${error_code}" \
    "" \
    "deny" \
    "slsa_level_insufficient" \
    "${INVALID_INSTALL_JSON}"
}

step_host_dev_override() {
  local start_ms end_ms duration_ms
  start_ms="$(now_ms)"
  run_exact_test \
    "fcp-host" \
    "host_connector_integration" \
    "${HOST_OVERRIDE_TEST}" \
    "${HOST_OVERRIDE_LOG}"
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  grep -Eq 'test result: ok\.' "${HOST_OVERRIDE_LOG}"

  record_step \
    "${HOST_OVERRIDE_TEST}" \
    "dev_policy_override" \
    "${CONNECTOR_ID}" \
    "pass" \
    "${duration_ms}" \
    "" \
    "" \
    "allow" \
    "allowed_unsigned" \
    "${HOST_OVERRIDE_LOG}"
}

step_report_valid() {
  local start_ms end_ms duration_ms evidence_id decision reason_code
  start_ms="$(now_ms)"
  run_fcp_json "${VALID_REPORT_JSON}" "${VALID_REPORT_STDERR}" \
    connector report "${CONNECTOR_ID}" \
    --supply-chain \
    --attestation "${VALID_ATTESTATION}" \
    --sbom "${VALID_SBOM}" \
    --digest "${ARTIFACT_DIGEST}" \
    --min-slsa-level 3 \
    --json
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  decision="$(jq -r '.decision' "${VALID_REPORT_JSON}")"
  reason_code="$(jq -r '.reason_code' "${VALID_REPORT_JSON}")"
  evidence_id="$(jq -r '.evidence_digest' "${VALID_REPORT_JSON}")"

  [[ "${decision}" == "allow" ]]
  [[ "${reason_code}" == "verified" ]]
  [[ "${evidence_id}" == "${VERIFY_EVIDENCE_ID}" ]]
  [[ "$(jq -r '.attestation.builder_id' "${VALID_REPORT_JSON}")" == "builder://github/actions" ]]
  [[ "$(jq -r '.attestation.trust_root.root_id' "${VALID_REPORT_JSON}")" == "sigstore-public-good" ]]
  [[ "$(jq -r '.sbom.trust_root.root_id' "${VALID_REPORT_JSON}")" == "sbom-root" ]]
  jq -e '.sbom.component_count == 1' "${VALID_REPORT_JSON}" >/dev/null

  REPORT_EVIDENCE_ID="${evidence_id}"
  record_step \
    "fcp connector report --supply-chain" \
    "report_valid" \
    "${CONNECTOR_ID}" \
    "pass" \
    "${duration_ms}" \
    "" \
    "${evidence_id}" \
    "${decision}" \
    "${reason_code}" \
    "${VALID_REPORT_JSON}"
}

step_verify_valid
step_install_valid
step_install_invalid
step_host_dev_override
step_report_valid

validate_log

jq -n \
  --arg schema_version "${SCHEMA_VERSION}" \
  --arg run_id "${RUN_ID}" \
  --arg connector_id "${CONNECTOR_ID}" \
  --arg artifact_digest "${ARTIFACT_DIGEST}" \
  --arg verify_evidence_id "${VERIFY_EVIDENCE_ID}" \
  --arg install_evidence_id "${INSTALL_EVIDENCE_ID}" \
  --arg report_evidence_id "${REPORT_EVIDENCE_ID}" \
  --arg invalid_error_code "${INVALID_ERROR_CODE}" \
  --arg log_jsonl "${LOG_JSONL}" \
  --arg replay_sh "${REPLAY_SH}" \
  --arg host_override_log "${HOST_OVERRIDE_LOG}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    connector_id: $connector_id,
    artifact_digest: $artifact_digest,
    evidence: {
      verify: $verify_evidence_id,
      install: $install_evidence_id,
      report: $report_evidence_id,
      deterministic_across_verify_install_report: (
        $verify_evidence_id == $install_evidence_id
        and $install_evidence_id == $report_evidence_id
      )
    },
    invalid_rejection: {
      error_code: $invalid_error_code,
      expected_reason_code: "slsa_level_insufficient"
    },
    dev_override: {
      host_test: "fcp_host_binary_supply_chain_verify_route_honors_dev_override_env",
      expected_reason_code: "allowed_unsigned",
      log_path: $host_override_log
    },
    artifacts: {
      steps: $log_jsonl,
      replay: $replay_sh
    }
  }' > "${SUMMARY_JSON}"

echo "${SCRIPT_NAME} complete."
echo "  Steps:   ${LOG_JSONL}"
echo "  Summary: ${SUMMARY_JSON}"
echo "  Replay:  ${REPLAY_SH}"
