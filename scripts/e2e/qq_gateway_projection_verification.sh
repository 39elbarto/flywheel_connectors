#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-}"

usage() {
  cat <<'EOF'
Usage: scripts/e2e/qq_gateway_projection_verification.sh [options]

Options:
  --run-id <id>      Run identifier for artifact paths
  --out-root <path>  Artifact root (default: artifacts/e2e/qq-gateway-projection/<run-id>)
  -h, --help         Show this help

Runs the QQ gateway projection evidence lane through rch, extracts
redaction-safe JSONL emitted by the connector e2e test, validates required
policy/reply/media/replay/shutdown coverage, and writes an operator replay
bundle. A passing run requires an accepted `[RCH] remote` proof summary; local
fallback, local fallback refusal, or a missing RCH summary is non-green.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    --out-root)
      OUT_ROOT="$2"
      shift 2
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

validate_run_id() {
  if [[ ! "${RUN_ID}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "RUN_ID must use only A-Z, a-z, 0-9, '.', '_', and '-': ${RUN_ID}" >&2
    exit 2
  fi
}

validate_run_id

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/e2e/qq-gateway-projection/${RUN_ID}"
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 2
  fi
}

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

json_string_or_null() {
  local value="$1"
  if [[ -n "${value}" ]]; then
    jq -Rn --arg value "${value}" '$value'
  else
    printf 'null'
  fi
}

hash_text_sha256() {
  printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
}

path_class() {
  local path="$1"
  case "${path}" in
    /tmp|/tmp/*|/private/tmp|/private/tmp/*)
      printf 'tmp'
      ;;
    target|target/*|./target|./target/*)
      printf 'relative'
      ;;
    /*)
      printf 'absolute'
      ;;
    *)
      printf 'relative'
      ;;
  esac
}

path_redacted() {
  local path="$1"
  case "${path}" in
    /*) printf 'true' ;;
    *) printf 'false' ;;
  esac
}

display_rch_bin() {
  basename "${RCH_BIN}"
}

rch_bin_path_redacted() {
  case "${RCH_BIN}" in
    */*) printf 'true' ;;
    *) printf 'false' ;;
  esac
}

rch_summary_line() {
  local log_path="$1"
  grep -aE '^\[RCH\] (remote|local|failed)' "${log_path}" | tail -n 1 || true
}

fallback_decision_for_log() {
  local log_path="$1"
  local summary
  summary="$(rch_summary_line "${log_path}")"
  if [[ -z "${summary}" ]]; then
    printf 'rch_summary_unobserved'
  elif printf '%s' "${summary}" | grep -Eq 'remote required; refusing local fallback|refus(ed|ing) local fallback'; then
    printf 'rch_local_fallback_refused'
  elif printf '%s' "${summary}" | grep -Fq '[RCH] local'; then
    if grep -aqE 'remote required; refusing local fallback|refus(ed|ing) local fallback' "${log_path}"; then
      printf 'rch_local_fallback_refused'
    else
      printf 'rch_local_fallback'
    fi
  elif printf '%s' "${summary}" | grep -Fq 'failed'; then
    printf 'rch_remote_failed'
  elif printf '%s' "${summary}" | grep -Eq '^\[RCH\] remote([[:space:]]|$)' &&
    ! printf '%s' "${summary}" | grep -Eq 'remote required; refusing local fallback|refus(ed|ing) local fallback'; then
    printf 'not_needed'
  else
    printf 'rch_summary_unclassified'
  fi
}

worker_execution_class_for_log() {
  local log_path="$1"
  local summary
  summary="$(rch_summary_line "${log_path}")"
  if [[ -z "${summary}" ]]; then
    printf 'unknown'
  elif printf '%s' "${summary}" | grep -Eq 'remote required; refusing local fallback|refus(ed|ing) local fallback'; then
    printf 'local_fallback_refused'
  elif printf '%s' "${summary}" | grep -Fq '[RCH] local'; then
    if grep -aqE 'remote required; refusing local fallback|refus(ed|ing) local fallback' "${log_path}"; then
      printf 'local_fallback_refused'
    else
      printf 'local'
    fi
  elif printf '%s' "${summary}" | grep -Fq 'failed'; then
    printf 'remote_failed'
  elif printf '%s' "${summary}" | grep -Eq '^\[RCH\] remote([[:space:]]|$)' &&
    ! printf '%s' "${summary}" | grep -Eq 'remote required; refusing local fallback|refus(ed|ing) local fallback'; then
    printf 'remote'
  else
    printf 'unknown'
  fi
}

require_cmd jq
RCH_BIN="${RCH_BIN:-rch}"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
RCH_VISIBILITY="${RCH_VISIBILITY:-verbose}"
export RCH_REQUIRE_REMOTE
export RCH_FORCE_REMOTE=1
export RCH_VISIBILITY

require_cmd "${RCH_BIN}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

TEST_LOG_ARTIFACT="logs/qq-gateway-projection-test.log"
EVIDENCE_JSONL_ARTIFACT="evidence/qq-gateway-projection.jsonl"
VALIDATION_JSON_ARTIFACT="evidence/validation.json"
SKIP_JSONL_ARTIFACT="evidence/qq-gateway-projection-skip.jsonl"
RCH_PROOF_JSON_ARTIFACT="evidence/rch-remote-proof.json"
SUMMARY_JSON_ARTIFACT="summary.json"
ENVIRONMENT_JSON_ARTIFACT="environment.json"
REPLAY_SH_ARTIFACT="replay.sh"

TEST_LOG="${OUT_ROOT}/${TEST_LOG_ARTIFACT}"
EVIDENCE_JSONL="${OUT_ROOT}/${EVIDENCE_JSONL_ARTIFACT}"
VALIDATION_JSON="${OUT_ROOT}/${VALIDATION_JSON_ARTIFACT}"
SKIP_JSONL="${OUT_ROOT}/${SKIP_JSONL_ARTIFACT}"
RCH_PROOF_JSON="${OUT_ROOT}/${RCH_PROOF_JSON_ARTIFACT}"
SUMMARY_JSON="${OUT_ROOT}/${SUMMARY_JSON_ARTIFACT}"
ENVIRONMENT_JSON="${OUT_ROOT}/${ENVIRONMENT_JSON_ARTIFACT}"
REPLAY_SH="${OUT_ROOT}/${REPLAY_SH_ARTIFACT}"

git_revision="$(git -c "safe.directory=${REPO_ROOT}" -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
target_dir="${QQ_CARGO_TARGET_DIR:-/tmp/fcp-qq-gateway-projection-${RUN_ID}}"
test_status="passed"
evidence_status="passed"
validation_status="passed"
overall_status="passed"
skip_reason=""
rch_proof_status="pending"
rch_summary=""
fallback_decision="rch_summary_unobserved"
worker_execution_class="unknown"
exit_code=0

echo "[qq-gateway-projection] running fcp-qq gateway projection evidence lane"
if ! (
  cd "${REPO_ROOT}"
  "${RCH_BIN}" exec -- env \
    RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}" \
    CARGO_TARGET_DIR="${target_dir}" \
    CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" \
    CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}" \
    CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}" \
    CARGO_PROFILE_TEST_DEBUG="${CARGO_PROFILE_TEST_DEBUG:-0}" \
    RUSTFLAGS="${RUSTFLAGS:--Cdebuginfo=0}" \
    cargo test -p fcp-qq qq_gateway_projection_logs_policy_replay_and_shutdown --test gateway_projection_e2e -- --nocapture
) >"${TEST_LOG}" 2>&1; then
  test_status="failed"
fi

rch_summary="$(rch_summary_line "${TEST_LOG}")"
fallback_decision="$(fallback_decision_for_log "${TEST_LOG}")"
worker_execution_class="$(worker_execution_class_for_log "${TEST_LOG}")"
if [[ "${test_status}" == "passed" ]]; then
  if [[ "${worker_execution_class}" == "remote" ]]; then
    rch_proof_status="passed"
  else
    rch_proof_status="failed"
    test_status="failed"
    overall_status="failed"
    validation_status="failed"
    exit_code=1
    printf '%s\n' "rch command did not produce accepted remote proof" >>"${TEST_LOG}"
  fi
else
  rch_proof_status="failed"
fi

if [[ "${test_status}" == "failed" ]]; then
  if grep -aE '(no admissible workers|no workers passed|no worker assigned|all workers failed preflight|failed to execute process|topology preflight|Permission denied|No such file or directory|remote required; refusing local fallback|refus(ed|ing) local fallback)' "${TEST_LOG}" >/dev/null; then
    overall_status="skipped"
    skip_reason="rch_remote_prerequisite_unavailable"
    test_status="skipped"
    evidence_status="skipped"
    validation_status="skipped"
    jq -c -n \
      --arg record_type "qq_gateway_projection_skip" \
      --arg schema_version "qq-gateway-projection/v1" \
      --arg run_id "${RUN_ID}" \
      --arg git_revision "${git_revision}" \
      --arg cargo_target_dir_class "$(path_class "${target_dir}")" \
      --arg cargo_target_dir_hash "sha256:$(hash_text_sha256 "${target_dir}")" \
      --arg skip_reason "${skip_reason}" \
      --arg log_artifact "${TEST_LOG_ARTIFACT}" \
      --arg fallback_decision "${fallback_decision}" \
      --arg worker_execution_class "${worker_execution_class}" \
      --argjson rch_summary "$(json_string_or_null "${rch_summary}")" \
      '{
        record_type: $record_type,
        schema_version: $schema_version,
        run_id: $run_id,
        git_revision: $git_revision,
        cargo_target_dir_class: $cargo_target_dir_class,
        cargo_target_dir_hash: $cargo_target_dir_hash,
        skip_reason: $skip_reason,
        log_artifact: $log_artifact,
        fallback_decision: $fallback_decision,
        worker_execution_class: $worker_execution_class,
        rch_summary: $rch_summary
      }' > "${SKIP_JSONL}"
  else
    overall_status="failed"
    exit_code=1
  fi
fi

jq -n \
  --arg status "${rch_proof_status}" \
  --arg fallback_decision "${fallback_decision}" \
  --arg worker_execution_class "${worker_execution_class}" \
  --arg required_worker_execution_class "remote" \
  --argjson rch_summary "$(json_string_or_null "${rch_summary}")" \
  --arg log_artifact "${TEST_LOG_ARTIFACT}" \
  --arg rch_bin "$(display_rch_bin)" \
  --arg rch_bin_hash "sha256:$(hash_text_sha256 "${RCH_BIN}")" \
  --argjson rch_bin_path_redacted "$(rch_bin_path_redacted)" \
  --arg rch_require_remote "${RCH_REQUIRE_REMOTE}" \
  --arg rch_force_remote "${RCH_FORCE_REMOTE}" \
  --arg rch_visibility "${RCH_VISIBILITY}" \
  '{
    status: $status,
    fallback_decision: $fallback_decision,
    worker_execution_class: $worker_execution_class,
    required_worker_execution_class: $required_worker_execution_class,
    rch_summary: $rch_summary,
    log_artifact: $log_artifact,
    rch_bin: $rch_bin,
    rch_bin_hash: $rch_bin_hash,
    rch_bin_path_redacted: $rch_bin_path_redacted,
    rch_require_remote: $rch_require_remote,
    rch_force_remote: $rch_force_remote,
    rch_visibility: $rch_visibility
  }' > "${RCH_PROOF_JSON}"

if [[ "${overall_status}" == "passed" ]]; then
  if ! grep -a '^QQ_GATEWAY_PROJECTION_JSONL ' "${TEST_LOG}" \
    | sed 's/^QQ_GATEWAY_PROJECTION_JSONL //' > "${EVIDENCE_JSONL}"
  then
    evidence_status="failed"
  fi

  if [[ ! -s "${EVIDENCE_JSONL}" ]] || ! jq -c . "${EVIDENCE_JSONL}" >/dev/null; then
    evidence_status="failed"
  fi

  if [[ "${evidence_status}" == "passed" ]]; then
    if ! jq -s -e '
      def required:
        [
          "log_start",
          "gateway_disabled_drop",
          "missing_route_binding_drop",
          "missing_message_identity_drop",
          "missing_reply_target_drop",
          "channel_policy_denied",
          "channel_policy_allowed",
          "c2c_policy_denied",
          "c2c_policy_allowed",
          "queue_full_policy_denied",
          "queue_full_backpressure_drop",
          "hello_session_restore",
          "malformed_control_envelope_denied",
          "malformed_data_id_envelope_denied",
          "allowed_group_mention",
          "missing_group_mention_drop",
          "untyped_message_id_not_mention",
          "structured_group_mention",
          "text_substring_not_mention",
          "explicit_text_group_mention",
          "oversized_media_policy_drop",
          "unknown_media_size_policy_drop",
          "media_content_type_policy_drop",
          "media_content_type_malformed_drop",
          "media_content_type_policy_allowed",
          "reply_media_projection",
          "voice_asr_projection",
          "slash_approval_projection",
          "duplicate_drop",
          "stale_sequence_replay_drop",
          "heartbeat_ack",
          "heartbeat_request",
          "reconnect_requested",
          "invalid_session_resumable",
          "restored_session_reconnect_resume",
          "invalid_session_identify_required",
          "reconnect_backoff_capped",
          "reconnect_attempts_exhausted",
          "hello_after_reconnect_exhaustion",
          "post_hello_reconnect_resume",
          "gateway_drain_first_batch",
          "gateway_drain_final_batch",
          "shutdown_pending_queue_drop",
          "shutdown"
        ];
      def steps: map(.step);
      def missing: required - steps;
      {
        record_count: length,
        missing_steps: missing,
        status_ok: all(.[]; .status == "ok"),
        redaction_shape_ok: all(.[]; (.step | type) == "string" and (.details | type) == "object"),
        log_start_shape_ok: any(.[];
          .step == "log_start"
          and (.details.artifact_path_hash | type) == "string"
          and (.details.artifact_path_hash | test("^sha256:[0-9a-f]{64}$"))
          and .details.artifact_path_class == "temp_jsonl"
          and (.details.command_line_hash | type) == "string"
          and (.details.command_line_hash | test("^sha256:[0-9a-f]{64}$"))
          and (.details.command_arg_count | type) == "number"
          and .details.command_arg_count >= 1
          and (.details.git_revision | type) == "string"
          and ((.details | has("path")) | not)
          and ((.details | has("command_line")) | not)
        ),
        disabled_shape_ok: any(.[]; .step == "gateway_disabled_drop" and .details.accepted == false and .details.reason_code == "gateway_disabled" and .details.normalized == null and .details.policy == null and .details.lifecycle.action == "none"),
        binding_shape_ok: (
          any(.[]; .step == "missing_route_binding_drop" and .details.reason_code == "group_sender_missing" and .details.policy.reason_code == "group_sender_missing")
          and any(.[]; .step == "missing_message_identity_drop" and .details.reason_code == "message_id_missing" and .details.policy.reason_code == "message_id_missing")
          and any(.[]; .step == "missing_reply_target_drop" and .details.reason_code == "reply_target_missing" and .details.policy.reason_code == "reply_target_missing")
        ),
        channel_shape_ok: (
          any(.[]; .step == "channel_policy_denied" and .details.accepted == false and .details.reason_code == "channel_not_allowed")
          and any(.[]; .step == "channel_policy_allowed" and .details.accepted == true and .details.policy.reason_code == "channel_allowed" and .details.policy.mentioned_bot == true)
        ),
        c2c_shape_ok: (
          any(.[]; .step == "c2c_policy_denied" and .details.accepted == false and .details.reason_code == "c2c_sender_not_allowed" and .details.policy.reason_code == "c2c_sender_not_allowed" and .details.normalized.routing == "c2c" and .details.runtime.accepted_events == 0 and .details.runtime.queue_depth == 0)
          and any(.[]; .step == "c2c_policy_allowed" and .details.accepted == true and .details.policy.reason_code == "c2c_allowed" and .details.policy.mentioned_bot == true and .details.normalized.routing == "c2c" and .details.runtime.accepted_events == 1 and .details.runtime.queue_depth == 1)
        ),
        queue_shape_ok: (
          any(.[];
            .step == "queue_full_backpressure_drop"
            and .details.accepted == false
            and .details.reason_code == "queue_full"
            and .details.normalized == null
            and .details.policy == null
            and .details.runtime.queue_depth == 1
            and .details.runtime.max_queue_depth == 1
            and .details.runtime.accepted_events == 1
            and .details.runtime.dropped_events == 2
            and .details.lifecycle.action == "none"
          )
          and any(.[];
            .step == "queue_full_policy_denied"
            and .details.accepted == false
            and .details.reason_code == "group_not_allowed"
            and .details.policy.reason_code == "group_not_allowed"
            and .details.normalized.routing == "group"
            and .details.runtime.queue_depth == 1
            and .details.runtime.max_queue_depth == 1
            and .details.runtime.accepted_events == 1
            and .details.runtime.dropped_events == 1
            and .details.lifecycle.action == "none"
          )
        ),
        group_policy_shape_ok: (
          any(.[]; .step == "allowed_group_mention" and .details.accepted == true and .details.policy.reason_code == "group_allowed")
          and any(.[]; .step == "missing_group_mention_drop" and .details.reason_code == "missing_group_mention")
          and any(.[]; .step == "untyped_message_id_not_mention" and .details.policy.mentioned_bot == false)
          and any(.[]; .step == "structured_group_mention" and .details.accepted == true and .details.policy.mentioned_bot == true)
          and any(.[]; .step == "text_substring_not_mention" and .details.accepted == false and .details.reason_code == "missing_group_mention" and .details.policy.mentioned_bot == false)
          and any(.[]; .step == "explicit_text_group_mention" and .details.accepted == true and .details.policy.reason_code == "group_allowed" and .details.policy.mentioned_bot == true)
        ),
        malformed_control_shape_ok: any(.[];
          .step == "malformed_control_envelope_denied"
          and .details.project_denied == true
          and .details.error_code_present == true
          and .details.error_mentions_bounds == true
          and .details.raw_event_logged == false
        ) and any(.[];
          .step == "malformed_data_id_envelope_denied"
          and .details.project_denied == true
          and .details.error_code_present == true
          and .details.error_mentions_bounds == true
          and .details.raw_event_logged == false
        ),
        reply_shape_ok: any(.[];
          .step == "reply_media_projection"
          and .details.normalized.is_reply == true
          and (.details.normalized.reply_to_hash | type) == "string"
          and (.details.normalized.attachment_filename_hashes | type) == "array"
          and (.details.normalized.attachment_filename_hashes | length) == 1
          and (.details.normalized.attachment_url_hashes | type) == "array"
          and (.details.normalized.attachment_url_hashes | length) == 1
        ),
        media_shape_ok: (
          any(.[]; .step == "oversized_media_policy_drop" and .details.reason_code == "attachment_bytes_exceeded")
          and any(.[]; .step == "unknown_media_size_policy_drop" and .details.reason_code == "attachment_size_unknown")
          and any(.[];
            .step == "media_content_type_policy_drop"
            and .details.accepted == false
            and .details.reason_code == "attachment_content_type_not_allowed"
            and .details.policy.reason_code == "attachment_content_type_not_allowed"
            and .details.normalized.has_attachments == true
            and (.details.normalized.attachment_content_types | type) == "array"
            and (.details.normalized.attachment_content_types | length) == 1
            and .details.runtime.accepted_events == 0
            and .details.runtime.queue_depth == 0
          )
          and any(.[];
            .step == "media_content_type_malformed_drop"
            and .details.accepted == false
            and .details.reason_code == "attachment_content_type_missing"
            and .details.policy.reason_code == "attachment_content_type_missing"
            and .details.normalized.has_attachments == true
            and (.details.normalized.attachment_content_types | type) == "array"
            and (.details.normalized.attachment_content_types | length) == 1
            and .details.runtime.accepted_events == 0
            and .details.runtime.queue_depth == 0
          )
          and any(.[];
            .step == "media_content_type_policy_allowed"
            and .details.accepted == true
            and .details.policy.reason_code == "group_allowed"
            and .details.normalized.has_attachments == true
            and (.details.normalized.attachment_content_types | type) == "array"
            and (.details.normalized.attachment_content_types | length) == 1
            and .details.runtime.accepted_events == 1
            and .details.runtime.queue_depth == 1
          )
        ),
        voice_shape_ok: any(.[];
          .step == "voice_asr_projection"
          and .details.accepted == true
          and .details.normalized.has_attachments == true
          and (.details.normalized.text_len | type) == "number"
          and .details.normalized.text_len > 0
          and (.details.normalized.attachment_filename_hashes | type) == "array"
          and (.details.normalized.attachment_filename_hashes | length) == 1
          and (.details.normalized.attachment_url_hashes | type) == "array"
          and (.details.normalized.attachment_url_hashes | length) == 1
        ),
        slash_shape_ok: any(.[]; .step == "slash_approval_projection" and .details.accepted == true and .details.normalized.interaction_kind == "approval" and (.details.normalized.command_name_hash | type) == "string" and .details.normalized.approval_action == "approve"),
        replay_shape_ok: (
          any(.[]; .step == "duplicate_drop" and .details.reason_code == "duplicate_event")
          and any(.[];
            .step == "stale_sequence_replay_drop"
            and .details.accepted == false
            and .details.reason_code == "stale_sequence"
            and .details.normalized == null
            and .details.policy == null
            and .details.runtime.stale_sequence_events == 1
            and .details.lifecycle.action == "none"
          )
        ),
        heartbeat_shape_ok: (
          any(.[]; .step == "heartbeat_ack" and .details.reason_code == "heartbeat_ack")
          and any(.[]; .step == "heartbeat_request" and .details.reason_code == "heartbeat_request" and .details.lifecycle.action == "send_heartbeat")
        ),
        reconnect_shape_ok: (
          any(.[]; .step == "reconnect_requested" and .details.reason_code == "reconnect_requested" and .details.runtime.reconnect_attempts == 1 and .details.runtime.terminal_reconnect_failures == 0)
          and any(.[]; .step == "invalid_session_resumable" and .details.reason_code == "invalid_session_resumable" and .details.runtime.reconnect_attempts == 2)
          and any(.[];
            .step == "invalid_session_identify_required"
            and .details.reason_code == "invalid_session_identify_required"
            and .details.runtime.reconnect_attempts == 1
            and .details.runtime.terminal_reconnect_failures == 0
            and .details.lifecycle.action == "reconnect_identify"
            and .details.lifecycle.resume_session_id == null
            and .details.lifecycle.resume_sequence == 12
            and .details.lifecycle.reconnect_after_ms == 300
          )
          and any(.[];
            .step == "reconnect_backoff_capped"
            and .details.reason_code == "reconnect_requested"
            and .details.runtime.reconnect_attempts == 2
            and .details.runtime.max_reconnect_attempts == 2
            and .details.runtime.terminal_reconnect_failures == 0
            and .details.runtime.reconnect_backoff_ms == 250
            and .details.runtime.max_reconnect_backoff_ms == 300
            and .details.lifecycle.action == "reconnect_identify"
            and .details.lifecycle.reconnect_after_ms == 300
          )
          and any(.[]; .step == "reconnect_attempts_exhausted" and .details.reason_code == "reconnect_attempts_exhausted" and .details.runtime.reconnect_attempts == 3 and .details.runtime.max_reconnect_attempts == 2 and .details.runtime.terminal_reconnect_failures == 1 and .details.lifecycle.action == "stop_reconnect")
          and any(.[];
            .step == "hello_after_reconnect_exhaustion"
            and .details.reason_code == "hello"
            and .details.runtime.reconnect_attempts == 0
            and .details.runtime.terminal_reconnect_failures == 1
            and (.details.runtime.session_id_hash | type) == "string"
            and (.details.runtime.session_id_hash | test("^[0-9a-f]{24}$"))
            and .details.lifecycle.action == "resume"
            and (.details.lifecycle.resume_session_id_hash | type) == "string"
            and (.details.lifecycle.resume_session_id_hash | test("^[0-9a-f]{24}$"))
            and .details.lifecycle.reconnect_after_ms == null
          )
          and any(.[];
            .step == "post_hello_reconnect_resume"
            and .details.reason_code == "reconnect_requested"
            and .details.runtime.reconnect_attempts == 1
            and .details.runtime.terminal_reconnect_failures == 1
            and .details.lifecycle.action == "reconnect_resume"
            and (.details.lifecycle.resume_session_id_hash | type) == "string"
            and (.details.lifecycle.resume_session_id_hash | test("^[0-9a-f]{24}$"))
            and .details.lifecycle.reconnect_after_ms == 250
          )
        ),
        restore_shape_ok: any(.[];
          .step == "restored_session_reconnect_resume"
          and .details.accepted == false
          and .details.reason_code == "reconnect_requested"
          and .details.normalized == null
          and .details.policy == null
          and .details.lifecycle.action == "reconnect_resume"
          and (.details.lifecycle.resume_session_id_hash | type) == "string"
          and (.details.lifecycle.resume_session_id_hash | test("^[0-9a-f]{24}$"))
          and .details.lifecycle.resume_sequence == 44
          and .details.lifecycle.reconnect_after_ms == 125
          and (.details.runtime.session_id_hash | type) == "string"
          and (.details.runtime.session_id_hash | test("^[0-9a-f]{24}$"))
          and .details.runtime.last_sequence == 44
          and .details.runtime.reconnect_attempts == 1
          and .details.runtime.terminal_reconnect_failures == 0
        ),
        drain_shape_ok: (
          any(.[]; .step == "gateway_drain_first_batch" and .details.drained_count == 2 and .details.remaining_count == 1)
          and any(.[]; .step == "gateway_drain_final_batch" and .details.drained_count == 1 and .details.remaining_count == 0 and .details.runtime.queue_depth == 0)
        ),
        shutdown_shape_ok: any(.[];
          .step == "shutdown"
          and .status == "ok"
          and .details.health_status == "Starting"
          and .details.gateway_runtime_present == false
          and .details.project_after_shutdown_denied == true
          and .details.drain_after_shutdown_denied == true
        ),
        pending_shutdown_shape_ok: any(.[];
          .step == "shutdown_pending_queue_drop"
          and .status == "ok"
          and .details.accepted_before_shutdown == true
          and .details.queued_before_shutdown == 1
          and .details.health_status == "Starting"
          and .details.gateway_runtime_present == false
          and .details.project_after_shutdown_denied == true
          and .details.drain_after_shutdown_denied == true
        )
      } as $v
      | $v
      | .status = (
          if (($v.missing_steps | length) == 0 and $v.status_ok and $v.redaction_shape_ok and $v.log_start_shape_ok and $v.disabled_shape_ok and $v.binding_shape_ok and $v.channel_shape_ok and $v.c2c_shape_ok and $v.queue_shape_ok and $v.group_policy_shape_ok and $v.malformed_control_shape_ok and $v.reply_shape_ok and $v.media_shape_ok and $v.voice_shape_ok and $v.slash_shape_ok and $v.replay_shape_ok and $v.heartbeat_shape_ok and $v.reconnect_shape_ok and $v.restore_shape_ok and $v.drain_shape_ok and $v.shutdown_shape_ok and $v.pending_shutdown_shape_ok)
          then "passed"
          else "failed"
          end
        )
      | select(.status == "passed")
    ' "${EVIDENCE_JSONL}" > "${VALIDATION_JSON}"; then
      validation_status="failed"
    fi
  fi

  if [[ "${evidence_status}" == "failed" || "${validation_status}" == "failed" ]]; then
    overall_status="failed"
    exit_code=1
  fi
fi

if [[ "${overall_status}" == "passed" ]]; then
  for forbidden in \
    "/Users/" \
    "/home/" \
    "/data/projects/" \
    "/private/var/" \
    "/var/folders/" \
    "/Volumes/" \
    "C:\\Users\\" \
    "Bearer" \
    "Authorization" \
    "authorization" \
    "access_token" \
    "refresh_token" \
    "token=" \
    "sk-live-" \
    "AKIA" \
    "-----BEGIN" \
    "principal:" \
    "provider_body" \
    "test-secret" \
    "session-1" \
    "restored-session" \
    "session-should-not-stick" \
    "session-after-exhaustion" \
    "hello-1" \
    "evt-accepted" \
    "evt-untyped-message-id" \
    "evt-structured-mention" \
    "evt-text-substring" \
    "evt-explicit-text-mention" \
    "evt-reply-media" \
    "evt-voice-asr" \
    "evt-slash-approval" \
    "evt-oversized-media" \
    "evt-unknown-size-media" \
    "evt-media-type-denied" \
    "evt-media-type-allowed" \
    "evt-malformed-data-id" \
    "evt-disabled" \
    "evt-missing-binding" \
    "evt-missing-message-id" \
    "evt-missing-reply-target" \
    "evt-channel-denied" \
    "evt-channel-allowed" \
    "evt-c2c-denied" \
    "evt-c2c-allowed" \
    "evt-queue-fill" \
    "evt-queue-full-policy-denied" \
    "evt-queue-full" \
    "evt-stale-sequence" \
    "evt-reconnect-requested" \
    "evt-invalid-session" \
    "evt-restored-reconnect" \
    "evt-reconnect-cap-first" \
    "evt-reconnect-cap-capped" \
    "evt-reconnect-exhausted" \
    "evt-hello-after-exhaustion" \
    "evt-post-hello-reconnect" \
    "evt-after-shutdown" \
    "msg-accepted" \
    "msg-untyped-message-id" \
    "msg-structured-mention" \
    "msg-text-substring" \
    "msg-explicit-text-mention" \
    "msg-reply-media" \
    "msg-voice-asr" \
    "msg-slash-approval" \
    "msg-oversized-media" \
    "msg-unknown-size-media" \
    "msg-media-type-denied" \
    "msg-media-type-allowed" \
    "msg-disabled" \
    "msg-missing-binding" \
    "msg-missing-message-id" \
    "msg-missing-reply-target" \
    "msg-channel-denied" \
    "msg-channel-allowed" \
    "msg-c2c-denied" \
    "msg-c2c-allowed" \
    "msg-queue-fill" \
    "msg-queue-full-policy-denied" \
    "msg-queue-full" \
    "msg-stale-sequence" \
    "msg-after-shutdown" \
    "bot-openid" \
    "group-allowed" \
    "group-slash" \
    "group-disabled" \
    "group-binding" \
    "group-denied" \
    "group-queue" \
    "group-voice" \
    "group-media-type" \
    "group-text" \
    "channel-denied" \
    "channel-allowed" \
    "guild-denied" \
    "sender-denied" \
    "member-1" \
    "member-slash" \
    "member-disabled" \
    "member-queue" \
    "member-voice" \
    "member-media-type" \
    "member-text" \
    "member-c2c-denied" \
    "member-c2c-allowed" \
    "Alice" \
    "gateway disabled should not authorize" \
    "event missing sender binding" \
    "event missing message id" \
    "blank reply target" \
    "c2c allowlist should deny" \
    "c2c allowlist should authorize" \
    "queue fill message" \
    "queue should not hide denied sender policy" \
    "queue backpressure message" \
    "stale sequence should drop" \
    "deploy status" \
    "plain message" \
    "not a mention segment" \
    "prefix not-bot-openid suffix" \
    "please @bot-openid check this" \
    "please inspect this" \
    "see attached trace" \
    "too large" \
    "missing size metadata" \
    "blocked media type" \
    "allowed media type" \
    "after shutdown should deny" \
    "approve deployment from voice" \
    "/approve rollout-42" \
    "rollout-42" \
    "cdn.qq.example" \
    "trace.png" \
    "voice.amr" \
    "oversized.bin" \
    "missing-size.pdf" \
    "disallowed.exe" \
    "allowed.png"
  do
    if grep -aF -- "${forbidden}" "${EVIDENCE_JSONL}" >/dev/null; then
      overall_status="failed"
      validation_status="failed"
      exit_code=1
      break
    fi
  done
fi

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg script "scripts/e2e/qq_gateway_projection_verification.sh" \
  --arg repo_root_hash "sha256:$(hash_text_sha256 "${REPO_ROOT}")" \
  --argjson repo_root_path_redacted "$(path_redacted "${REPO_ROOT}")" \
  --arg artifact_root_class "$(path_class "${OUT_ROOT}")" \
  --arg artifact_root_hash "sha256:$(hash_text_sha256 "${OUT_ROOT}")" \
  --arg git_revision "${git_revision}" \
  --arg cargo_target_dir_class "$(path_class "${target_dir}")" \
  --arg cargo_target_dir_hash "sha256:$(hash_text_sha256 "${target_dir}")" \
  --arg rch_bin "$(display_rch_bin)" \
  --arg rch_bin_hash "sha256:$(hash_text_sha256 "${RCH_BIN}")" \
  --argjson rch_bin_path_redacted "$(rch_bin_path_redacted)" \
  --arg rch_require_remote "${RCH_REQUIRE_REMOTE}" \
  --arg rch_force_remote "${RCH_FORCE_REMOTE}" \
  --arg rch_visibility "${RCH_VISIBILITY}" \
  --arg generated_at "$(now_iso)" \
  '{
    run_id: $run_id,
    script: $script,
    repo_root_hash: $repo_root_hash,
    repo_root_path_redacted: $repo_root_path_redacted,
    artifact_root_class: $artifact_root_class,
    artifact_root_hash: $artifact_root_hash,
    git_revision: $git_revision,
    cargo_target_dir_class: $cargo_target_dir_class,
    cargo_target_dir_hash: $cargo_target_dir_hash,
    rch_bin: $rch_bin,
    rch_bin_hash: $rch_bin_hash,
    rch_bin_path_redacted: $rch_bin_path_redacted,
    rch_require_remote: $rch_require_remote,
    rch_force_remote: $rch_force_remote,
    rch_visibility: $rch_visibility,
    generated_at: $generated_at
  }' > "${ENVIRONMENT_JSON}"

evidence_count="0"
if [[ -s "${EVIDENCE_JSONL}" ]]; then
  evidence_count="$(wc -l < "${EVIDENCE_JSONL}" | tr -d ' ')"
fi

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg status "${overall_status}" \
  --arg test_status "${test_status}" \
  --arg evidence_status "${evidence_status}" \
  --arg validation_status "${validation_status}" \
  --arg rch_proof_status "${rch_proof_status}" \
  --arg skip_reason "${skip_reason}" \
  --argjson evidence_count "${evidence_count}" \
  --arg artifact_root_class "$(path_class "${OUT_ROOT}")" \
  --arg artifact_root_hash "sha256:$(hash_text_sha256 "${OUT_ROOT}")" \
  --arg test_log "${TEST_LOG_ARTIFACT}" \
  --arg evidence_jsonl "${EVIDENCE_JSONL_ARTIFACT}" \
  --arg validation_json "${VALIDATION_JSON_ARTIFACT}" \
  --arg skip_jsonl "${SKIP_JSONL_ARTIFACT}" \
  --arg rch_proof_json "${RCH_PROOF_JSON_ARTIFACT}" \
  --arg environment_json "${ENVIRONMENT_JSON_ARTIFACT}" \
  --arg fallback_decision "${fallback_decision}" \
  --arg worker_execution_class "${worker_execution_class}" \
  --argjson rch_summary "$(json_string_or_null "${rch_summary}")" \
  '{
    run_id: $run_id,
    status: $status,
    test_status: $test_status,
    evidence_status: $evidence_status,
    validation_status: $validation_status,
    rch_proof_status: $rch_proof_status,
    skip_reason: (if ($skip_reason | length) > 0 then $skip_reason else null end),
    evidence_count: $evidence_count,
    artifact_root: {
      class: $artifact_root_class,
      hash: $artifact_root_hash
    },
    rch_remote_proof: {
      fallback_decision: $fallback_decision,
      worker_execution_class: $worker_execution_class,
      required_worker_execution_class: "remote",
      rch_summary: $rch_summary
    },
    artifacts: {
      test_log: $test_log,
      evidence_jsonl: $evidence_jsonl,
      validation_json: $validation_json,
      skip_jsonl: $skip_jsonl,
      rch_proof_json: $rch_proof_json,
      environment_json: $environment_json
    }
  }' > "${SUMMARY_JSON}"

cat > "${REPLAY_SH}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "${REPO_ROOT}"
RUN_ID="${RUN_ID}" OUT_ROOT="${OUT_ROOT}" RCH_BIN="${RCH_BIN}" RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE}" RCH_FORCE_REMOTE="${RCH_FORCE_REMOTE}" RCH_VISIBILITY="${RCH_VISIBILITY}" \\
  bash scripts/e2e/qq_gateway_projection_verification.sh \\
  --run-id "${RUN_ID}" \\
  --out-root "${OUT_ROOT}"
EOF
chmod +x "${REPLAY_SH}"

echo "QQ gateway projection artifacts written to ${OUT_ROOT}"
exit "${exit_code}"
