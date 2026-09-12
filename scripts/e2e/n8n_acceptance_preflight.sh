#!/usr/bin/env bash
set -euo pipefail

# Redaction-safe, read-only policy gate for the nqm81.10 supervised worker.
#
# This file intentionally contains no provider, issuer, credential, secret, or
# write path.  It validates a closed metadata projection and, when requested,
# only stats the fixed approval-request path.  It never reads request/response
# bodies, creates/removes files, or echoes input values.

readonly SCHEMA="fwc.n8n.acceptance-preflight.v1"
readonly MAX_INPUT_BYTES=262144
readonly APPROVAL_ROOT="/var/lib/fwc-n8n/approval-requests"
readonly WRAPPER="/usr/local/bin/fwc-n8n"
readonly JQ_BIN="/usr/bin/jq"
readonly WC_BIN="/usr/bin/wc"
readonly STAT_BIN="/usr/bin/stat"
readonly EEC_WORKFLOW_ID="oD8zytCtv5PiSYzc"
readonly EEC_VERSION_ID="85f41fbd-96e2-42d0-9022-98592eb35011"
readonly EEC_GRAPH_DIGEST="blake3-256:9a1dcf488e8b929a22a847f38aee6601dbf4000d13325b05236cf8c018be8b3a"
readonly EEC_STATE_DIGEST="blake3-256:1b431688626cba116259425ed22acb74fed2bbe423330a7b7f039b1d2908f91c"
readonly PLAN_DIGEST="blake3-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
readonly PARENT_BINDING="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
readonly ARTIFACT_DIGEST="sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
readonly SELFTEST_REVISION="0123456789abcdef0123456789abcdef01234567"

PLAN=""
SELF_TEST=0
NOW_MS=""

jq() {
  "$JQ_BIN" "$@"
}

wc() {
  "$WC_BIN" "$@"
}

stat() {
  "$STAT_BIN" "$@"
}

require_dependencies() {
  if [[ ! -x "$JQ_BIN" || ! -x "$WC_BIN" || ! -x "$STAT_BIN" ]]; then
    emit_failure "checker_dependency_missing"
    return 1
  fi
}

emit_failure() {
  printf '{"schema":"%s","verdict":"fail","abort_code":"%s"}\n' "$SCHEMA" "$1"
}

emit_success() {
  printf '{"schema":"%s","verdict":"pass","abort_code":null}\n' "$SCHEMA"
}

emit_self_test_success() {
  printf '{"schema":"%s","verdict":"pass","mode":"self-test","acceptance":false,"cases":16}\n' "$SCHEMA"
}

emit_self_test_failure() {
  printf '{"schema":"%s","verdict":"fail","mode":"self-test","abort_code":"self_test_failed"}\n' "$SCHEMA"
}

jq_gate() {
  local code="$1"
  shift
  if jq -e "$@" <<<"$PLAN" >/dev/null 2>&1; then
    return 0
  fi
  emit_failure "$code"
  return 1
}

load_plan() {
  local source="${1:-}"
  local raw=""
  local byte_count=0

  if [[ -n "$source" ]]; then
    if [[ ! -f "$source" || -L "$source" || ! -r "$source" ]]; then
      emit_failure "input_document_invalid"
      return 1
    fi
    if LC_ALL=C IFS= read -r -N "$((MAX_INPUT_BYTES + 1))" raw <"$source"; then
      emit_failure "input_bounds_invalid"
      return 1
    fi
  else
    if LC_ALL=C IFS= read -r -N "$((MAX_INPUT_BYTES + 1))" raw; then
      emit_failure "input_bounds_invalid"
      return 1
    fi
  fi

  byte_count="$(LC_ALL=C printf '%s' "$raw" | wc -c)"
  if ! [[ "$byte_count" =~ ^[0-9]+$ ]] || (( byte_count == 0 || byte_count > MAX_INPUT_BYTES )); then
    emit_failure "input_bounds_invalid"
    return 1
  fi
  if ! PLAN="$(LC_ALL=C printf '%s' "$raw" | jq -c -s 'if length == 1 and (.[0] | type) == "object" then .[0] else error("one object required") end' 2>/dev/null)"; then
    emit_failure "input_document_invalid"
    return 1
  fi
}

gate_schema() {
  jq_gate "schema_invalid" '
    (.schema == "fwc.n8n.acceptance-preflight.v1") and
    ((keys_unsorted | sort) ==
      ["apply_guard", "approval", "approval_file", "command", "correlations",
       "counters", "dry_run", "evidence", "input", "parser", "provenance",
       "schema", "server_order", "target", "uri"])
  '
}

gate_command() {
  jq_gate "literal_run_once_required" '
    def step_ok($index; $phase; $operation; $keys; $types):
      .command.steps[$index] as $s
      | (($s | type) == "object")
        and (($s | keys_unsorted | sort) ==
          ["approval_token_material_present", "argv", "byte_count", "document_count",
           "empty", "operation_keys", "operation_types", "outer_keys", "phase",
           "server", "trailing_bytes", "unknown_keys"])
        and ($s.phase == $phase)
        and ($s.server == "eec")
        and ($s.argv == ["/usr/local/bin/fwc-n8n", "run-once", $operation])
        and (($s.operation_keys | sort) == ($keys | sort))
        and ($s.operation_types == $types)
        and ($s.document_count == 1)
        and (($s.byte_count | type) == "number")
        and (($s.byte_count | floor) == $s.byte_count)
        and ($s.byte_count > 0 and $s.byte_count <= 262144)
        and ($s.trailing_bytes == 0)
        and ($s.empty == false)
        and ($s.unknown_keys == false)
        and ($s.approval_token_material_present == false)
        and (($s.outer_keys | sort) == ["correlation_id", "input", "server_id"]);

    ((.command | type) == "object")
    and ((.command | keys_unsorted | sort) == ["fallbacks", "mode", "steps", "wrapper"])
    and (.command.wrapper == "/usr/local/bin/fwc-n8n")
    and (.command.mode == "run_once")
    and ((.command.fallbacks | type) == "object")
    and ((.command.fallbacks | keys_unsorted | sort) == ["direct_bridge", "direct_host", "route", "shell"])
    and (.command.fallbacks.route == false)
    and (.command.fallbacks.direct_host == false)
    and (.command.fallbacks.direct_bridge == false)
    and (.command.fallbacks.shell == false)
    and ((.command.steps | type) == "array")
    and (.command.steps | length == 4)
    and step_ok(0; "baseline"; "n8n.workflows.get"; ["id"]; {"id":"string"})
    and step_ok(1; "dry_run"; "n8n.mcp_access.reconcile";
      ["desired", "dryRun", "scope", "workflowIds"];
      {"desired":"boolean", "dryRun":"boolean", "scope":"string", "workflowIds":"array"})
    and step_ok(2; "apply"; "n8n.mcp_access.reconcile";
      ["desired", "dryRun", "guard", "scope", "workflowIds"];
      {"desired":"boolean", "dryRun":"boolean", "guard":"object", "scope":"string", "workflowIds":"array"})
    and step_ok(3; "reconciliation"; "n8n.workflows.get"; ["id"]; {"id":"string"})
  '
}

gate_input() {
  jq_gate "input_bounds_invalid" '
    ((.input | type) == "object")
    and ((.input | keys_unsorted | sort) == ["max_bytes", "metadata_only", "trailing_json_rejected"])
    and (.input.max_bytes == 262144)
    and (.input.metadata_only == true)
    and (.input.trailing_json_rejected == true)
  '
}

gate_server_order() {
  jq_gate "server_order_invalid" '
    ((.server_order | type) == "array")
    and (.server_order == ["eec", "hetzner"])
  '
}

gate_parser() {
  jq_gate "direct_result_required" '
    ((.parser | type) == "object")
    and ((.parser | keys_unsorted | sort) ==
      ["concatenated_json", "direct_result", "nested_result", "projection_keys",
       "raw_response_persisted", "raw_stderr_persisted", "raw_stdout_persisted",
       "safe_projection", "status_ok", "top_level_error"])
    and (.parser.direct_result == true)
    and (.parser.status_ok == true)
    and (.parser.top_level_error == "absent_or_null")
    and (.parser.nested_result == false)
    and (.parser.concatenated_json == false)
    and (.parser.safe_projection == true)
    and (.parser.projection_keys | sort ==
      ["active", "activeVersionId", "draft", "id", "isArchived", "published", "stateDigest", "versionId"])
    and (.parser.raw_response_persisted == false)
    and (.parser.raw_stdout_persisted == false)
    and (.parser.raw_stderr_persisted == false)
  '
}

gate_correlations() {
  if ! jq -e '
    (.correlations | type == "object") and
    ((.correlations | keys_unsorted | sort) ==
      ["apply", "approval_ref", "baseline", "dry_run", "idempotency_key", "reconciliation"])
    and ((.correlations | to_entries | map(.value)) as $ids
      | ($ids | all(.[]; (type == "string" and test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")))))
  ' <<<"$PLAN" >/dev/null 2>&1; then
    emit_failure "correlation_missing"
    return 1
  fi
  if ! jq -e '
    (.correlations | to_entries | map(.value)) as $ids
    | (($ids | unique | length) == ($ids | length))
  ' <<<"$PLAN" >/dev/null 2>&1; then
    emit_failure "correlation_reused"
    return 1
  fi
  return 0
}

gate_target() {
  jq_gate "baseline_mismatch" \
    --arg workflow "$EEC_WORKFLOW_ID" \
    --arg version "$EEC_VERSION_ID" \
    --arg graph "$EEC_GRAPH_DIGEST" \
    --arg state "$EEC_STATE_DIGEST" '
      ((.target | type) == "object")
      and ((.target | keys_unsorted | sort) ==
        ["active", "active_version_id", "classification", "graph_digest", "is_archived",
         "published", "state_digest", "version_id", "workflow_id"])
      and (.target.classification == "exact")
      and (.target.workflow_id == $workflow)
      and (.target.version_id == $version)
      and (.target.active == false)
      and (.target.active_version_id == null)
      and (.target.published == null)
      and (.target.is_archived == false)
      and (.target.graph_digest == $graph)
      and (.target.state_digest == $state)
      and (.target.graph_digest | test("^blake3-256:[0-9a-f]{64}$"))
      and (.target.state_digest | test("^blake3-256:[0-9a-f]{64}$"))
    '
}

gate_dry_run() {
  jq_gate "dry_run_invalid" \
    --arg workflow "$EEC_WORKFLOW_ID" '
      def blake3_digest_ok:
        if type != "string" then false
        else (test("^blake3-256:[0-9a-f]{64}$") and ((split(":")[1] | explode | unique | length) > 1))
        end;

      ((.dry_run | type) == "object")
      and ((.dry_run | keys_unsorted | sort) ==
        ["changed", "classification", "desired", "dry_run", "exceptions", "guard_keys",
         "matching_target", "plan_digest", "planned", "readback_digest", "scope",
         "workflow_id", "workflow_ids_count"])
      and (.dry_run.classification == "exact")
      and (.dry_run.scope == "workflow_ids")
      and (.dry_run.desired == true)
      and (.dry_run.dry_run == true)
      and (.dry_run.planned == 1)
      and (.dry_run.changed == 0)
      and (.dry_run.exceptions == 0)
      and (.dry_run.guard_keys == [])
      and (.dry_run.matching_target == true)
      and (.dry_run.workflow_id == $workflow)
      and (.dry_run.workflow_ids_count == 1)
      and (.dry_run.plan_digest == .dry_run.readback_digest)
      and (.dry_run.plan_digest | blake3_digest_ok)
    '
}

gate_apply_guard() {
  jq_gate "dry_run_digest_mismatch" \
    --arg approval_ref "$(jq -er '.correlations.approval_ref' <<<"$PLAN")" \
    --arg idempotency_key "$(jq -er '.correlations.idempotency_key' <<<"$PLAN")" '
      def blake3_digest_ok:
        if type != "string" then false
        else (test("^blake3-256:[0-9a-f]{64}$") and ((split(":")[1] | explode | unique | length) > 1))
        end;

      ((.apply_guard | type) == "object")
      and ((.apply_guard | keys_unsorted | sort) ==
        ["approval_ref", "dry_run", "dry_run_digest", "idempotency_key", "keys",
         "matches_dry_run", "matches_target"])
      and (.apply_guard.dry_run == false)
      and (.apply_guard.keys | sort == ["approvalRef", "dryRunDigest", "idempotencyKey"])
      and (.apply_guard.approval_ref == $approval_ref)
      and (.apply_guard.dry_run_digest == .dry_run.plan_digest)
      and (.apply_guard.dry_run_digest | blake3_digest_ok)
      and (.apply_guard.idempotency_key == $idempotency_key)
      and (.apply_guard.matches_dry_run == true)
      and (.apply_guard.matches_target == true)
    '
}

gate_uri() {
  jq_gate "resource_binding_mismatch" '
    ((.uri | type) == "object")
    and ((.uri | keys_unsorted | sort) ==
      ["direct_resource_uri", "direct_server", "matches_source_encoder", "official_resource_uri",
       "official_tool", "official_uri_encoded"])
    and (.uri.direct_server == "eec")
    and (.uri.direct_resource_uri == "fwc-n8n://eec")
    and (.uri.official_tool | IN("publish_workflow", "unpublish_workflow"))
    and (.uri.official_uri_encoded == true)
    and (.uri.matches_source_encoder == true)
    and (.uri.official_resource_uri ==
      ("fwc-mcp-bridge://eec/tools/" + (.uri.official_tool | gsub("_"; "%5F"))))
  '
}

# The authoritative fcp-host N8nApprovalIssueRequest contract leaves
# workflow_id empty for mcp_access_reconcile; the target is carried by
# input_projection.workflow_ids_match_target and workflow_ids_count below.
gate_approval() {
  if ! jq_gate "approval_envelope_invalid" '
      def sha256_binding_ok:
        if type != "string" then false
        else (test("^[0-9a-f]{64}$") and ((explode | unique | length) > 1))
        end;

      ((.approval | type) == "object")
      and ((.approval | keys_unsorted | sort) ==
        ["expires_at_ms", "input_projection", "official_mcp_payload_digest",
         "official_mcp_resource_uri", "official_mcp_tool", "operation",
         "parent_binding_inputs", "parent_binding_sha256", "parent_binding_verified",
         "raw_request_body_present", "raw_seed_present", "raw_token_present",
         "schema", "server", "workflow_id"])
      and (.approval.schema == "fwc.n8n.owner-approval-request.v1")
      and (.approval.operation == "mcp_access_reconcile")
      and (.approval.server == "eec")
      and (.approval.workflow_id == "")
      and (.approval.official_mcp_tool == "")
      and (.approval.official_mcp_resource_uri == "")
      and (.approval.official_mcp_payload_digest == "")
      and (.approval.parent_binding_sha256 | sha256_binding_ok)
      and (.approval.parent_binding_verified == true)
      and (.approval.parent_binding_inputs == ["server_id", "resource_uri", "operation", "input"])
      and (.approval.raw_token_present == false)
      and (.approval.raw_seed_present == false)
      and (.approval.raw_request_body_present == false)
      and ((.approval.input_projection | type) == "object")
      and ((.approval.input_projection | keys_unsorted | sort) ==
        ["desired", "dry_run", "guard_keys", "scope", "types", "workflow_ids_count",
         "workflow_ids_match_target"])
      and (.approval.input_projection.scope == "workflow_ids")
      and (.approval.input_projection.desired == true)
      and (.approval.input_projection.dry_run == false)
      and (.approval.input_projection.guard_keys | sort == ["approvalRef", "dryRunDigest", "idempotencyKey"])
      and (.approval.input_projection.types ==
        {"approvalRef":"string", "desired":"boolean", "dryRun":"boolean",
         "dryRunDigest":"string", "guard":"object", "idempotencyKey":"string",
         "scope":"string", "workflowIds":"array"})
      and (.approval.input_projection.workflow_ids_count == 1)
      and (.approval.input_projection.workflow_ids_match_target == true)
      and ((.approval.expires_at_ms | type) == "number")
      and ((.approval.expires_at_ms | floor) == .approval.expires_at_ms)
    '; then
    return 1
  fi

  if ! jq -e '(.approval.expires_at_ms | tostring | test("^[0-9]{13}$"))' <<<"$PLAN" >/dev/null 2>&1; then
    emit_failure "expiry_not_13_digits"
    return 1
  fi

  if ! NOW_MS="$(jq -nr 'now * 1000 | floor | tostring' 2>/dev/null)" || ! [[ "$NOW_MS" =~ ^[0-9]{13}$ ]]; then
    emit_failure "expiry_not_13_digits"
    return 1
  fi

  if ! jq -e --argjson now "$NOW_MS" '(.approval.expires_at_ms > $now)' <<<"$PLAN" >/dev/null 2>&1; then
    emit_failure "expiry_stale"
    return 1
  fi
  if ! jq -e --argjson now "$NOW_MS" '(.approval.expires_at_ms <= ($now + 60000))' <<<"$PLAN" >/dev/null 2>&1; then
    emit_failure "expiry_over_60s"
    return 1
  fi
  return 0
}

approval_file_projection_ok() {
  jq -e '
    ((.approval_file | type) == "object")
    and ((.approval_file | keys_unsorted | sort) == ["cleanup", "file_metadata", "path", "root", "root_metadata", "state"])
    and (.approval_file.root == "/var/lib/fwc-n8n/approval-requests")
    and (.approval_file.state | IN("present", "absent"))
    and ((.approval_file.path | type) == "string")
    and ((.approval_file.root_metadata | type) == "object")
    and ((.approval_file.root_metadata | keys_unsorted | sort) == ["directory", "mode", "symlink", "uid"])
    and (.approval_file.root_metadata.directory == true)
    and (.approval_file.root_metadata.symlink == false)
    and (.approval_file.root_metadata.uid == 0)
    and (.approval_file.root_metadata.mode == "0700")
    and ((.approval_file.file_metadata | type) == "object")
    and ((.approval_file.file_metadata | keys_unsorted | sort) == ["hardlinks", "mode", "regular", "size_bytes", "symlink", "uid"])
    and ((.approval_file.file_metadata.hardlinks | type) == "number")
    and ((.approval_file.file_metadata.hardlinks | floor) == .approval_file.file_metadata.hardlinks)
    and ((.approval_file.file_metadata.size_bytes | type) == "number")
    and ((.approval_file.file_metadata.size_bytes | floor) == .approval_file.file_metadata.size_bytes)
    and (.approval_file.file_metadata.uid == 0)
    and (.approval_file.file_metadata.mode == "0600")
    and ((.approval_file.file_metadata.symlink | type) == "boolean")
    and ((.approval_file.file_metadata.regular | type) == "boolean")
    and ((.approval_file.cleanup | type) == "object")
    and ((.approval_file.cleanup | keys_unsorted | sort) == ["file_absent", "state"])
    and (.approval_file.cleanup.state | IN("pending", "verified_absent", "failed"))
    and ((.approval_file.cleanup.file_absent | type) == "boolean")
  ' <<<"$PLAN" >/dev/null 2>&1
}

check_directory_metadata() {
  local directory="$1"
  local expected_root="$2"
  local metadata=""
  local uid=""
  local mode=""
  local kind=""
  local mode_value=0

  if [[ ! -d "$directory" || -L "$directory" ]]; then
    return 1
  fi
  if ! metadata="$(stat -c '%u %a %F' -- "$directory" 2>/dev/null)"; then
    return 1
  fi
  read -r uid mode kind <<<"$metadata"
  if [[ "$kind" != "directory" || "$uid" != "0" ]]; then
    return 1
  fi
  mode_value=$((8#$mode))
  if (( (mode_value & 18) != 0 )); then
    return 1
  fi
  if [[ "$expected_root" == "yes" && "$mode_value" -ne 448 ]]; then
    return 1
  fi
}

gate_approval_file() {
  if ! approval_file_projection_ok; then
    emit_failure "approval_file_metadata_invalid"
    return 1
  fi

  local path=""
  local state=""
  local cleanup_state=""
  local cleanup_absent=""
  local basename=""
  path="$(jq -er '.approval_file.path' <<<"$PLAN" 2>/dev/null)"
  state="$(jq -er '.approval_file.state' <<<"$PLAN" 2>/dev/null)"
  cleanup_state="$(jq -er '.approval_file.cleanup.state' <<<"$PLAN" 2>/dev/null)"
  cleanup_absent="$(jq -er '.approval_file.cleanup.file_absent' <<<"$PLAN" 2>/dev/null)"

  case "$path" in
    "$APPROVAL_ROOT"/*) ;;
    *) emit_failure "approval_file_metadata_invalid"; return 1 ;;
  esac
  if [[ "$path" == "$APPROVAL_ROOT" || "$path" == *"/../"* || "$path" == *"/./"* ]]; then
    emit_failure "approval_file_metadata_invalid"
    return 1
  fi
  local relative="${path#"$APPROVAL_ROOT"/}"
  if [[ "$relative" == */* ]]; then
    emit_failure "approval_file_metadata_invalid"
    return 1
  fi
  basename="${path##*/}"
  if ! [[ "$basename" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
    emit_failure "approval_file_metadata_invalid"
    return 1
  fi

  if [[ "$cleanup_state" == "failed" ]]; then
    emit_failure "approval_cleanup_failed"
    return 1
  fi
  if [[ "$state" == "present" ]]; then
    if [[ "$cleanup_state" != "pending" || "$cleanup_absent" != "false" ]]; then
      emit_failure "approval_cleanup_failed"
      return 1
    fi
    if ! jq -e '
      (.approval_file.file_metadata.regular == true)
      and (.approval_file.file_metadata.symlink == false)
      and (.approval_file.file_metadata.hardlinks == 1)
      and (.approval_file.file_metadata.uid == 0)
      and (.approval_file.file_metadata.mode == "0600")
      and (.approval_file.file_metadata.size_bytes > 0 and .approval_file.file_metadata.size_bytes <= 65536)
    ' <<<"$PLAN" >/dev/null 2>&1; then
      emit_failure "approval_file_metadata_invalid"
      return 1
    fi
  else
    if [[ "$cleanup_state" != "verified_absent" || "$cleanup_absent" != "true" ]]; then
      emit_failure "approval_cleanup_failed"
      return 1
    fi
    if ! jq -e '
      (.approval_file.file_metadata.regular == false)
      and (.approval_file.file_metadata.symlink == false)
      and (.approval_file.file_metadata.hardlinks == 0)
      and (.approval_file.file_metadata.size_bytes == 0)
    ' <<<"$PLAN" >/dev/null 2>&1; then
      emit_failure "approval_file_metadata_invalid"
      return 1
    fi
  fi

  if (( SELF_TEST == 1 )); then
    return 0
  fi

  if ! check_directory_metadata "/var" "no" \
    || ! check_directory_metadata "/var/lib" "no" \
    || ! check_directory_metadata "/var/lib/fwc-n8n" "no" \
    || ! check_directory_metadata "$APPROVAL_ROOT" "yes"; then
    emit_failure "approval_file_metadata_invalid"
    return 1
  fi

  if [[ "$state" == "present" ]]; then
    local metadata=""
    local uid=""
    local mode=""
    local hardlinks=""
    local size_bytes=""
    local kind=""
    if [[ ! -f "$path" || -L "$path" ]]; then
      emit_failure "approval_file_metadata_invalid"
      return 1
    fi
    if ! metadata="$(stat -c '%u %a %h %s %F' -- "$path" 2>/dev/null)"; then
      emit_failure "approval_file_metadata_invalid"
      return 1
    fi
    read -r uid mode hardlinks size_bytes kind <<<"$metadata"
    if [[ "$uid" != "0" || "$kind" != "regular file" || "$hardlinks" != "1" || "$mode" != "600" ]]; then
      emit_failure "approval_file_metadata_invalid"
      return 1
    fi
    if ! [[ "$size_bytes" =~ ^[0-9]+$ ]] || (( size_bytes == 0 || size_bytes > 65536 )); then
      emit_failure "approval_file_metadata_invalid"
      return 1
    fi
    if ! jq -e --argjson size "$size_bytes" '.approval_file.file_metadata.size_bytes == $size' <<<"$PLAN" >/dev/null 2>&1; then
      emit_failure "approval_file_metadata_invalid"
      return 1
    fi
  else
    if [[ -e "$path" || -L "$path" ]]; then
      emit_failure "approval_cleanup_failed"
      return 1
    fi
  fi
}

gate_provenance() {
  if ! jq -e '
    def hex_digest_ok($pattern):
      if type != "string" then false
      else (test($pattern) and ((explode | unique | length) > 1))
      end;
    def prefixed_digest_ok($pattern):
      if type != "string" then false
      else (test($pattern) and ((split(":")[1] | explode | unique | length) > 1))
      end;

    ((.provenance | type) == "object")
    and ((.provenance | keys_unsorted | sort) ==
      ["artifact_digest_installed", "artifact_digest_matches", "artifact_digest_source",
       "artifact_digest_verified", "artifact_mode", "directory_mode", "exact_artifact_count",
       "installed_revision", "installed_revision_matches", "manifest_verified", "pointer_only",
       "pointer_path", "provenance_path", "provenance_path_is_symlink", "receipt_path",
       "receipt_path_is_symlink", "receipt_schema", "receipt_verified", "release_id",
       "source_base", "source_revision", "source_revision_matches"])
    and (.provenance.pointer_path == "/usr/local/lib/fwc-n8n/current")
    and (.provenance.pointer_only == false)
    and (.provenance.provenance_path_is_symlink == false)
    and (.provenance.receipt_path_is_symlink == false)
    and (.provenance.receipt_schema == "fwc.n8n.provision-receipt.v1")
    and (.provenance.source_base == "origin/main")
    and (.provenance.release_id | test("^release-[A-Za-z0-9._-]+$"))
    and (.provenance.provenance_path | test("^/usr/local/lib/fwc-n8n/(current|releases/[A-Za-z0-9._-]+)/provenance\\.json$"))
    and (.provenance.receipt_path | test("^/usr/local/lib/fwc-n8n/(current|releases/[A-Za-z0-9._-]+)/provision-receipt\\.json$"))
    and (.provenance.source_revision | hex_digest_ok("^[0-9a-f]{40}$"))
    and (.provenance.installed_revision | hex_digest_ok("^[0-9a-f]{40}$"))
    and (.provenance.source_revision == .provenance.installed_revision)
    and (.provenance.source_revision_matches == true)
    and (.provenance.installed_revision_matches == true)
    and (.provenance.artifact_digest_source | prefixed_digest_ok("^sha256:[0-9a-f]{64}$"))
    and (.provenance.artifact_digest_installed | prefixed_digest_ok("^sha256:[0-9a-f]{64}$"))
    and (.provenance.artifact_digest_source == .provenance.artifact_digest_installed)
    and (.provenance.artifact_digest_matches == true)
    and (.provenance.artifact_digest_verified == true)
    and (.provenance.receipt_verified == true)
    and (.provenance.manifest_verified == true)
    and ((.provenance.exact_artifact_count | type) == "number")
    and ((.provenance.exact_artifact_count | floor) == .provenance.exact_artifact_count)
    and (.provenance.exact_artifact_count >= 12)
  ' <<<"$PLAN" >/dev/null 2>&1; then
    emit_failure "provenance_mismatch"
    return 1
  fi
  if ! jq -e '
    (.provenance.artifact_mode == "0600")
    and (.provenance.directory_mode == "0700")
  ' <<<"$PLAN" >/dev/null 2>&1; then
    emit_failure "mode_failed"
    return 1
  fi
}

gate_counters() {
  if ! jq -e '
    ((.counters | type) == "object")
    and ((.counters | keys_unsorted | sort) ==
      ["automatic_retry", "eec", "eec_disposition", "hetzner", "hetzner_continued_after_eec_no_go"])
    and (.counters.eec_disposition | IN("ready", "go", "no_go", "unknown"))
    and ((.counters.eec | type) == "object")
    and ((.counters.hetzner | type) == "object")
    and ((.counters.eec | keys_unsorted | sort) == ["apply", "approval", "baseline", "dry_run", "reconciliation"])
    and ((.counters.hetzner | keys_unsorted | sort) == ["apply", "approval", "baseline", "dry_run", "reconciliation"])
    and (all([.counters.eec, .counters.hetzner][]; all(.[]; (type == "number" and floor == . and . >= 0 and . <= 1))))
    and (.counters.eec.baseline == 1)
    and (.counters.eec.dry_run == 1)
    and (.counters.eec.apply <= .counters.eec.approval)
    and (.counters.automatic_retry == false)
    and (.counters.hetzner_continued_after_eec_no_go == false)
  ' <<<"$PLAN" >/dev/null 2>&1; then
    emit_failure "operation_counter_invalid"
    return 1
  fi
  if ! jq -e '
    if (.counters.eec_disposition == "no_go" or .counters.eec_disposition == "unknown")
    then (all(.counters.hetzner[]; . == 0) and (.counters.hetzner_continued_after_eec_no_go == false))
    else true
    end
  ' <<<"$PLAN" >/dev/null 2>&1; then
    emit_failure "eec_not_proven"
    return 1
  fi
}

gate_evidence() {
  if ! jq -e '
    ((.evidence | type) == "object")
    and ((.evidence | keys_unsorted | sort) == ["checksums", "processes", "redaction"])
    and ((.evidence.redaction | type) == "object")
    and ((.evidence.redaction | keys_unsorted | sort) ==
      ["credentials", "raw_provider_bodies", "raw_request_bodies", "raw_stderr",
       "raw_stdout", "seeds", "tokens"])
    and (all(.evidence.redaction[]; type == "boolean"))
  ' <<<"$PLAN" >/dev/null 2>&1; then
    emit_failure "redaction_failed"
    return 1
  fi
  if ! jq -e 'all(.evidence.redaction[]; . == false)' <<<"$PLAN" >/dev/null 2>&1; then
    emit_failure "redaction_failed"
    return 1
  fi
  if ! jq -e '
    ((.evidence.checksums | type) == "object")
    and ((.evidence.checksums | keys_unsorted | sort) ==
      ["after_finalization", "artifact_mode", "directory_mode", "independent_verification", "manifest_name"])
    and (.evidence.checksums.manifest_name == "SHA256SUMS")
    and (.evidence.checksums.independent_verification == true)
    and (.evidence.checksums.after_finalization == true)
  ' <<<"$PLAN" >/dev/null 2>&1; then
    emit_failure "checksum_failed"
    return 1
  fi
  if ! jq -e '
    (.evidence.checksums.artifact_mode == "0600")
    and (.evidence.checksums.directory_mode == "0700")
  ' <<<"$PLAN" >/dev/null 2>&1; then
    emit_failure "mode_failed"
    return 1
  fi
  if ! jq -e '
    ((.evidence.processes | type) == "object")
    and ((.evidence.processes | keys_unsorted | sort) ==
      ["bridge_count", "issuer_count", "launcher_count", "matching_count", "scan_completed"])
    and (.evidence.processes.scan_completed == true)
    and (all([.evidence.processes.matching_count, .evidence.processes.launcher_count,
      .evidence.processes.issuer_count, .evidence.processes.bridge_count][];
      (type == "number" and floor == . and . == 0)))
  ' <<<"$PLAN" >/dev/null 2>&1; then
    emit_failure "process_leak"
    return 1
  fi
}

validate_plan() {
  gate_schema || return 1
  gate_command || return 1
  gate_input || return 1
  gate_server_order || return 1
  gate_parser || return 1
  gate_correlations || return 1
  gate_target || return 1
  gate_dry_run || return 1
  gate_apply_guard || return 1
  gate_uri || return 1
  gate_approval || return 1
  gate_approval_file || return 1
  gate_provenance || return 1
  gate_counters || return 1
  gate_evidence || return 1
}

base_plan() {
  local expiry=""
  expiry="$(jq -nr 'now * 1000 | floor + 55000 | tostring')"
  jq -cn \
    --arg expiry "$expiry" \
    --arg plan "$PLAN_DIGEST" \
    --arg parent "$PARENT_BINDING" \
    --arg artifact "$ARTIFACT_DIGEST" \
    --arg graph "$EEC_GRAPH_DIGEST" \
    --arg state "$EEC_STATE_DIGEST" \
    --arg workflow "$EEC_WORKFLOW_ID" \
    --arg version "$EEC_VERSION_ID" \
    --arg revision "$SELFTEST_REVISION" '
    {
      schema: "fwc.n8n.acceptance-preflight.v1",
      command: {
        wrapper: "/usr/local/bin/fwc-n8n",
        mode: "run_once",
        fallbacks: {route:false, direct_host:false, direct_bridge:false, shell:false},
        steps: [
          {phase:"baseline", server:"eec", argv:["/usr/local/bin/fwc-n8n","run-once","n8n.workflows.get"], document_count:1, byte_count:120, trailing_bytes:0, empty:false, unknown_keys:false, approval_token_material_present:false, outer_keys:["server_id","input","correlation_id"], operation_keys:["id"], operation_types:{id:"string"}},
          {phase:"dry_run", server:"eec", argv:["/usr/local/bin/fwc-n8n","run-once","n8n.mcp_access.reconcile"], document_count:1, byte_count:180, trailing_bytes:0, empty:false, unknown_keys:false, approval_token_material_present:false, outer_keys:["server_id","input","correlation_id"], operation_keys:["scope","desired","dryRun","workflowIds"], operation_types:{scope:"string",desired:"boolean",dryRun:"boolean",workflowIds:"array"}},
          {phase:"apply", server:"eec", argv:["/usr/local/bin/fwc-n8n","run-once","n8n.mcp_access.reconcile"], document_count:1, byte_count:260, trailing_bytes:0, empty:false, unknown_keys:false, approval_token_material_present:false, outer_keys:["server_id","input","correlation_id"], operation_keys:["scope","desired","dryRun","workflowIds","guard"], operation_types:{scope:"string",desired:"boolean",dryRun:"boolean",workflowIds:"array",guard:"object"}},
          {phase:"reconciliation", server:"eec", argv:["/usr/local/bin/fwc-n8n","run-once","n8n.workflows.get"], document_count:1, byte_count:120, trailing_bytes:0, empty:false, unknown_keys:false, approval_token_material_present:false, outer_keys:["server_id","input","correlation_id"], operation_keys:["id"], operation_types:{id:"string"}}
        ]
      },
      input: {max_bytes:262144, metadata_only:true, trailing_json_rejected:true},
      server_order:["eec","hetzner"],
      parser: {
        direct_result:true, status_ok:true, top_level_error:"absent_or_null", nested_result:false,
        concatenated_json:false, safe_projection:true,
        projection_keys:["active","activeVersionId","draft","id","isArchived","published","stateDigest","versionId"],
        raw_response_persisted:false, raw_stdout_persisted:false, raw_stderr_persisted:false
      },
      correlations: {
        baseline:"11111111-1111-4111-8111-111111111111",
        dry_run:"22222222-2222-4222-8222-222222222222",
        apply:"33333333-3333-4333-8333-333333333333",
        reconciliation:"44444444-4444-4444-8444-444444444444",
        idempotency_key:"55555555-5555-4555-8555-555555555555",
        approval_ref:"66666666-6666-4666-8666-666666666666"
      },
      target: {
        classification:"exact", workflow_id:$workflow, version_id:$version, active:false,
        active_version_id:null, published:null, is_archived:false, graph_digest:$graph, state_digest:$state
      },
      dry_run: {
        classification:"exact", scope:"workflow_ids", desired:true, dry_run:true,
        planned:1, changed:0, exceptions:0, guard_keys:[], matching_target:true,
        workflow_id:$workflow, workflow_ids_count:1, plan_digest:$plan, readback_digest:$plan
      },
      apply_guard: {
        dry_run:false, keys:["approvalRef","dryRunDigest","idempotencyKey"],
        approval_ref:"66666666-6666-4666-8666-666666666666", dry_run_digest:$plan,
        idempotency_key:"55555555-5555-4555-8555-555555555555", matches_dry_run:true, matches_target:true
      },
      uri: {
        direct_resource_uri:"fwc-n8n://eec", direct_server:"eec", official_tool:"publish_workflow",
        official_resource_uri:"fwc-mcp-bridge://eec/tools/publish%5Fworkflow",
        official_uri_encoded:true, matches_source_encoder:true
      },
      approval: {
        schema:"fwc.n8n.owner-approval-request.v1", operation:"mcp_access_reconcile", server:"eec", workflow_id:"",
        official_mcp_tool:"", official_mcp_resource_uri:"", official_mcp_payload_digest:"",
        parent_binding_sha256:$parent, parent_binding_verified:true,
        parent_binding_inputs:["server_id","resource_uri","operation","input"],
        expires_at_ms:($expiry|tonumber), raw_token_present:false, raw_seed_present:false, raw_request_body_present:false,
        input_projection: {
          scope:"workflow_ids", desired:true, dry_run:false,
          guard_keys:["approvalRef","dryRunDigest","idempotencyKey"],
          types:{scope:"string",desired:"boolean",dryRun:"boolean",workflowIds:"array",guard:"object",approvalRef:"string",dryRunDigest:"string",idempotencyKey:"string"},
          workflow_ids_count:1, workflow_ids_match_target:true
        }
      },
      approval_file: {
        state:"absent", path:"/var/lib/fwc-n8n/approval-requests/nqm81-selftest.json",
        root:"/var/lib/fwc-n8n/approval-requests",
        root_metadata:{directory:true, symlink:false, uid:0, mode:"0700"},
        file_metadata:{regular:false, symlink:false, hardlinks:0, uid:0, mode:"0600", size_bytes:0},
        cleanup:{state:"verified_absent", file_absent:true}
      },
      provenance: {
        provenance_path:"/usr/local/lib/fwc-n8n/releases/release-selftest/provenance.json",
        receipt_path:"/usr/local/lib/fwc-n8n/releases/release-selftest/provision-receipt.json",
        pointer_path:"/usr/local/lib/fwc-n8n/current", pointer_only:false,
        provenance_path_is_symlink:false, receipt_path_is_symlink:false,
        release_id:"release-selftest", receipt_schema:"fwc.n8n.provision-receipt.v1",
        source_base:"origin/main", source_revision:$revision, installed_revision:$revision,
        source_revision_matches:true, installed_revision_matches:true,
        artifact_digest_source:$artifact, artifact_digest_installed:$artifact,
        artifact_digest_matches:true, artifact_digest_verified:true,
        receipt_verified:true, manifest_verified:true, exact_artifact_count:14,
        artifact_mode:"0600", directory_mode:"0700"
      },
      counters: {
        eec_disposition:"ready",
        eec:{baseline:1, dry_run:1, approval:0, apply:0, reconciliation:0},
        hetzner:{baseline:0, dry_run:0, approval:0, apply:0, reconciliation:0},
        automatic_retry:false, hetzner_continued_after_eec_no_go:false
      },
      evidence: {
        redaction:{raw_provider_bodies:false, raw_request_bodies:false, credentials:false, tokens:false, seeds:false, raw_stdout:false, raw_stderr:false},
        checksums:{manifest_name:"SHA256SUMS", independent_verification:true, after_finalization:true, artifact_mode:"0600", directory_mode:"0700"},
        processes:{scan_completed:true, matching_count:0, launcher_count:0, issuer_count:0, bridge_count:0}
      }
    }'
}

expect_failure() {
  local expected="$1"
  local fixture="$2"
  local output=""
  PLAN="$fixture"
  if output="$(validate_plan)"; then
    return 1
  fi
  [[ "$output" == *"\"abort_code\":\"$expected\""* ]]
}

run_self_test() {
  SELF_TEST=1
  local base=""
  local fixture=""
  base="$(base_plan)"
  PLAN="$base"
  if ! validate_plan >/dev/null; then
    emit_self_test_failure
    return 1
  fi

  fixture="$(jq -c --arg workflow "$EEC_WORKFLOW_ID" '.approval.workflow_id = $workflow' <<<"$base")"
  if ! expect_failure "approval_envelope_invalid" "$fixture"; then emit_self_test_failure; return 1; fi

  fixture="$(jq -c '.command.fallbacks.route = true' <<<"$base")"
  if ! expect_failure "literal_run_once_required" "$fixture"; then emit_self_test_failure; return 1; fi

  fixture="$(jq -c '.dry_run.plan_digest = ("blake3-256:" + ("b" * 64))' <<<"$base")"
  if ! expect_failure "dry_run_invalid" "$fixture"; then emit_self_test_failure; return 1; fi

  fixture="$(jq -c '.apply_guard.dry_run_digest = ("blake3-256:" + ("c" * 64))' <<<"$base")"
  if ! expect_failure "dry_run_digest_mismatch" "$fixture"; then emit_self_test_failure; return 1; fi

  fixture="$(jq -c '.approval.parent_binding_sha256 = ("a" * 64)' <<<"$base")"
  if ! expect_failure "approval_envelope_invalid" "$fixture"; then emit_self_test_failure; return 1; fi

  fixture="$(jq -c '.approval.expires_at_ms = 123456789012' <<<"$base")"
  if ! expect_failure "expiry_not_13_digits" "$fixture"; then emit_self_test_failure; return 1; fi

  fixture="$(jq -c 'now as $n | .approval.expires_at_ms = (($n * 1000) | floor) + 61001' <<<"$base")"
  if ! expect_failure "expiry_over_60s" "$fixture"; then emit_self_test_failure; return 1; fi

  fixture="$(jq -c '.correlations.apply = .correlations.baseline' <<<"$base")"
  if ! expect_failure "correlation_reused" "$fixture"; then emit_self_test_failure; return 1; fi

  fixture="$(jq -c '.uri.official_resource_uri = "fwc-mcp-bridge://eec/tools/publish_workflow"' <<<"$base")"
  if ! expect_failure "resource_binding_mismatch" "$fixture"; then emit_self_test_failure; return 1; fi

  fixture="$(jq -c '.approval_file.state = "present" | .approval_file.cleanup = {state:"pending",file_absent:false} | .approval_file.file_metadata = {regular:true,symlink:false,hardlinks:1,uid:0,mode:"0664",size_bytes:10}' <<<"$base")"
  if ! expect_failure "approval_file_metadata_invalid" "$fixture"; then emit_self_test_failure; return 1; fi

  fixture="$(jq -c '.approval_file.cleanup.state = "failed"' <<<"$base")"
  if ! expect_failure "approval_cleanup_failed" "$fixture"; then emit_self_test_failure; return 1; fi

  fixture="$(jq -c '.provenance.installed_revision = "2222222222222222222222222222222222222222"' <<<"$base")"
  if ! expect_failure "provenance_mismatch" "$fixture"; then emit_self_test_failure; return 1; fi

  fixture="$(jq -c '.evidence.redaction.raw_stdout = true' <<<"$base")"
  if ! expect_failure "redaction_failed" "$fixture"; then emit_self_test_failure; return 1; fi

  fixture="$(jq -c '.evidence.checksums.independent_verification = false' <<<"$base")"
  if ! expect_failure "checksum_failed" "$fixture"; then emit_self_test_failure; return 1; fi

  fixture="$(jq -c '.evidence.processes.issuer_count = 1' <<<"$base")"
  if ! expect_failure "process_leak" "$fixture"; then emit_self_test_failure; return 1; fi

  emit_self_test_success
}

usage() {
  printf '%s\n' "usage: n8n_acceptance_preflight.sh [--self-test] [PLAN.json]"
}

main() {
  require_dependencies || return 1
  if [[ "${1:-}" == "--help" ]]; then
    usage
    emit_failure "input_arguments_invalid"
    return 1
  fi
  if [[ "${1:-}" == "--self-test" ]]; then
    if [[ "$#" -ne 1 ]]; then
      emit_failure "input_arguments_invalid"
      return 1
    fi
    run_self_test
    return $?
  fi
  if [[ "$#" -gt 1 ]]; then
    emit_failure "input_arguments_invalid"
    return 1
  fi
  load_plan "${1:-}" || return 1
  if validate_plan; then
    emit_success
    return 0
  fi
  return 1
}

main "$@"
