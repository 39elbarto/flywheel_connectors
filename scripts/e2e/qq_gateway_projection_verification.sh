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
bundle.
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

require_cmd jq
require_cmd rch

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

TEST_LOG="${OUT_ROOT}/logs/qq-gateway-projection-test.log"
EVIDENCE_JSONL="${OUT_ROOT}/evidence/qq-gateway-projection.jsonl"
VALIDATION_JSON="${OUT_ROOT}/evidence/validation.json"
SKIP_JSONL="${OUT_ROOT}/evidence/qq-gateway-projection-skip.jsonl"
SUMMARY_JSON="${OUT_ROOT}/summary.json"
ENVIRONMENT_JSON="${OUT_ROOT}/environment.json"
REPLAY_SH="${OUT_ROOT}/replay.sh"

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
target_dir="${QQ_CARGO_TARGET_DIR:-/tmp/fcp-qq-gateway-projection-${RUN_ID}}"
test_status="passed"
evidence_status="passed"
validation_status="passed"
overall_status="passed"
skip_reason=""
exit_code=0

echo "[qq-gateway-projection] running fcp-qq gateway projection evidence lane"
if ! (
  cd "${REPO_ROOT}"
  env RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}" rch exec -- env \
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

if [[ "${test_status}" == "failed" ]]; then
  if grep -aE '(no workers passed|no worker assigned|all workers failed preflight|failed to execute process|topology preflight|Permission denied|No such file or directory|refus(ed|ing) local fallback)' "${TEST_LOG}" >/dev/null; then
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
      --arg target_dir "${target_dir}" \
      --arg skip_reason "${skip_reason}" \
      --arg log_path "${TEST_LOG}" \
      '{
        record_type: $record_type,
        schema_version: $schema_version,
        run_id: $run_id,
        git_revision: $git_revision,
        cargo_target_dir: $target_dir,
        skip_reason: $skip_reason,
        log_path: $log_path
      }' > "${SKIP_JSONL}"
  else
    overall_status="failed"
    exit_code=1
  fi
fi

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
          "queue_full_policy_denied",
          "queue_full_backpressure_drop",
          "hello_session_restore",
          "allowed_group_mention",
          "missing_group_mention_drop",
          "untyped_message_id_not_mention",
          "structured_group_mention",
          "oversized_media_policy_drop",
          "reply_media_projection",
          "voice_asr_projection",
          "slash_approval_projection",
          "duplicate_drop",
          "stale_sequence_replay_drop",
          "heartbeat_ack",
          "heartbeat_request",
          "reconnect_requested",
          "invalid_session_resumable",
          "reconnect_attempts_exhausted",
          "gateway_drain_first_batch",
          "gateway_drain_final_batch",
          "shutdown"
        ];
      def steps: map(.step);
      def missing: required - steps;
      {
        record_count: length,
        missing_steps: missing,
        status_ok: all(.[]; .status == "ok"),
        redaction_shape_ok: all(.[]; (.step | type) == "string" and (.details | type) == "object"),
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
        ),
        reply_shape_ok: any(.[]; .step == "reply_media_projection" and .details.normalized.is_reply == true and (.details.normalized.reply_to_hash | type) == "string"),
        media_shape_ok: any(.[]; .step == "oversized_media_policy_drop" and .details.reason_code == "attachment_bytes_exceeded"),
        voice_shape_ok: any(.[]; .step == "voice_asr_projection" and .details.accepted == true and .details.normalized.has_attachments == true and (.details.normalized.text_len | type) == "number" and .details.normalized.text_len > 0),
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
        reconnect_shape_ok: (any(.[]; .step == "reconnect_requested" and .details.reason_code == "reconnect_requested" and .details.runtime.reconnect_attempts == 1 and .details.runtime.terminal_reconnect_failures == 0)
          and any(.[]; .step == "invalid_session_resumable" and .details.reason_code == "invalid_session_resumable" and .details.runtime.reconnect_attempts == 2)
          and any(.[]; .step == "reconnect_attempts_exhausted" and .details.reason_code == "reconnect_attempts_exhausted" and .details.runtime.max_reconnect_attempts == 1 and .details.runtime.terminal_reconnect_failures == 1 and .details.lifecycle.action == "stop_reconnect")
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
        )
      } as $v
      | $v
      | .status = (
          if (($v.missing_steps | length) == 0 and $v.status_ok and $v.redaction_shape_ok and $v.disabled_shape_ok and $v.binding_shape_ok and $v.channel_shape_ok and $v.queue_shape_ok and $v.group_policy_shape_ok and $v.reply_shape_ok and $v.media_shape_ok and $v.voice_shape_ok and $v.slash_shape_ok and $v.replay_shape_ok and $v.heartbeat_shape_ok and $v.reconnect_shape_ok and $v.drain_shape_ok and $v.shutdown_shape_ok)
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
    "test-secret" \
    "session-1" \
    "hello-1" \
    "evt-accepted" \
    "evt-untyped-message-id" \
    "evt-structured-mention" \
    "evt-reply-media" \
    "evt-voice-asr" \
    "evt-slash-approval" \
    "evt-oversized-media" \
    "evt-disabled" \
    "evt-missing-binding" \
    "evt-missing-message-id" \
    "evt-missing-reply-target" \
    "evt-queue-fill" \
    "evt-queue-full" \
    "evt-stale-sequence" \
    "evt-reconnect-requested" \
    "evt-invalid-session" \
    "evt-reconnect-cap-first" \
    "evt-reconnect-exhausted" \
    "evt-after-shutdown" \
    "msg-accepted" \
    "msg-untyped-message-id" \
    "msg-structured-mention" \
    "msg-reply-media" \
    "msg-voice-asr" \
    "msg-slash-approval" \
    "msg-oversized-media" \
    "msg-disabled" \
    "msg-missing-binding" \
    "msg-missing-message-id" \
    "msg-missing-reply-target" \
    "msg-queue-fill" \
    "msg-queue-full" \
    "msg-stale-sequence" \
    "msg-after-shutdown" \
    "bot-openid" \
    "group-allowed" \
    "group-slash" \
    "group-disabled" \
    "group-binding" \
    "group-queue" \
    "member-1" \
    "member-slash" \
    "member-disabled" \
    "member-queue" \
    "Alice" \
    "gateway disabled should not authorize" \
    "event missing sender binding" \
    "event missing message id" \
    "blank reply target" \
    "queue fill message" \
    "queue backpressure message" \
    "stale sequence should drop" \
    "deploy status" \
    "plain message" \
    "not a mention segment" \
    "please inspect this" \
    "see attached trace" \
    "too large" \
    "after shutdown should deny" \
    "approve deployment from voice" \
    "/approve rollout-42" \
    "rollout-42" \
    "cdn.qq.example" \
    "trace.png" \
    "voice.amr" \
    "oversized.bin"
  do
    if grep -aF "${forbidden}" "${EVIDENCE_JSONL}" >/dev/null; then
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
  --arg repo_root "${REPO_ROOT}" \
  --arg artifact_root "${OUT_ROOT}" \
  --arg git_revision "${git_revision}" \
  --arg target_dir "${target_dir}" \
  --arg rch_require_remote "${RCH_REQUIRE_REMOTE:-1}" \
  --arg generated_at "$(now_iso)" \
  '{
    run_id: $run_id,
    script: $script,
    repo_root: $repo_root,
    artifact_root: $artifact_root,
    git_revision: $git_revision,
    cargo_target_dir: $target_dir,
    rch_require_remote: $rch_require_remote,
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
  --arg skip_reason "${skip_reason}" \
  --argjson evidence_count "${evidence_count}" \
  --arg test_log "${TEST_LOG}" \
  --arg evidence_jsonl "${EVIDENCE_JSONL}" \
  --arg validation_json "${VALIDATION_JSON}" \
  --arg skip_jsonl "${SKIP_JSONL}" \
  --arg environment_json "${ENVIRONMENT_JSON}" \
  '{
    run_id: $run_id,
    status: $status,
    test_status: $test_status,
    evidence_status: $evidence_status,
    validation_status: $validation_status,
    skip_reason: (if ($skip_reason | length) > 0 then $skip_reason else null end),
    evidence_count: $evidence_count,
    artifacts: {
      test_log: $test_log,
      evidence_jsonl: $evidence_jsonl,
      validation_json: $validation_json,
      skip_jsonl: $skip_jsonl,
      environment_json: $environment_json
    }
  }' > "${SUMMARY_JSON}"

cat > "${REPLAY_SH}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "${REPO_ROOT}"
RUN_ID="${RUN_ID}" OUT_ROOT="${OUT_ROOT}" RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}" \\
  bash scripts/e2e/qq_gateway_projection_verification.sh \\
  --run-id "${RUN_ID}" \\
  --out-root "${OUT_ROOT}"
EOF
chmod +x "${REPLAY_SH}"

echo "QQ gateway projection artifacts written to ${OUT_ROOT}"
exit "${exit_code}"
