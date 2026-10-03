#!/usr/bin/env bash
set -euo pipefail

# Redaction-safe, read-only policy gate for the nqm81.10 supervised worker.
#
# Provider reads require the explicit --read-only-check mode; the default and
# self-tests never contact a provider. There is no issuer, secret or write path.
# The default validates a closed metadata projection and, when requested,
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
  printf '{"schema":"%s","verdict":"pass","mode":"self-test","acceptance":false,"cases":18}\n' "$SCHEMA"
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

expect_success() {
  local fixture="$1"
  PLAN="$fixture"
  validate_plan >/dev/null
}

run_release_metadata_self_test() {
  local assembler="$1" consumer="$2"
  python3 - "$assembler" "$consumer" <<'PY'
import copy
import json
import pathlib
import subprocess
import sys
import uuid
assembler, consumer = sys.argv[1:]
source = pathlib.Path(consumer).read_text()
contract = '#[serde(deny_unknown_fields)]\nstruct Provenance {\n    schema: String,\n    release_id: String,\n    git_revision: String,\n}'
assert contract in source
rid = 'release-20261003-37936e82d-publish-reasons-rc43c'
revision = '37936e82d0d8da485ae4ce505728d8149fcdbae7'
emit = ['bash', assembler, '--emit-release-provenance', rid, revision]
check = ['bash', assembler, '--check-release-metadata', rid, revision]
produced = subprocess.run(emit, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
assert produced.returncode == 0
expected = json.loads(produced.stdout)
assert set(expected) == {'schema', 'release_id', 'git_revision'}
cases = [('exact_native_provenance', produced.stdout, True)]
for label, key, value in (
    ('assembler_field_denied', 'assembler_sha256', 'ab' * 32),
    ('unknown_field_denied', 'unknown', 'HOSTILE_METADATA_CANARY'),
    ('wrong_schema_denied', 'schema', 'HOSTILE_METADATA_CANARY'),
    ('wrong_release_denied', 'release_id', 'HOSTILE_METADATA_CANARY'),
    ('wrong_revision_denied', 'git_revision', 'HOSTILE_METADATA_CANARY'),
):
    altered = copy.deepcopy(expected); altered[key] = value
    cases.append((label, json.dumps(altered).encode(), False))
altered = copy.deepcopy(expected); del altered['git_revision']
cases.extend([('missing_field_denied', json.dumps(altered).encode(), False),
    ('malformed_denied', b'HOSTILE_METADATA_CANARY', False),
    ('oversize_denied', b' ' * 65537, False),
    ('duplicate_field_denied', produced.stdout.rstrip()[:-1] + b',"schema":"fwc.n8n.provenance.v1"}', False)])
for label, raw, allowed in cases:
    result = subprocess.run(check, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    assert (result.returncode == 0) == allowed
    assert b'HOSTILE_METADATA_CANARY' not in result.stdout + result.stderr
# Execute the actual shared producer write branch in a retained SSD fixture.
text = pathlib.Path(assembler).read_text()
start = text.index('release_provenance() {')
body = text[text.index("<<'PY'\n", start) + 7:text.index('\nPY\n}', start)]
fixture = pathlib.Path('/srv/dev-ssd/fcp/nqm81-34') / ('rc43c-metadata-producer-' + str(uuid.uuid4()))
fixture.mkdir(mode=0o700)
written = fixture / 'provenance.json'
write = subprocess.run([sys.executable, '-c', body, 'write', rid, revision, str(written)],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
assert write.returncode == 0 and written.read_bytes() == produced.stdout
checked = subprocess.run(check, input=written.read_bytes(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
assert checked.returncode == 0
again = subprocess.run([sys.executable, '-c', body, 'write', rid, revision, str(written)],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
assert again.returncode != 0 and written.read_bytes() == produced.stdout
assert b'HOSTILE_METADATA_CANARY' not in again.stdout + again.stderr
print(json.dumps({'cases': len(cases), 'metadata_producer_native_contract': True,
    'retained_write_fixture': str(fixture), 'write_and_no_overwrite': True,
    'no_build': True, 'no_seed': True, 'labels': [c[0] for c in cases]}))
PY
}

run_recovery_parser_self_test() {
  local binary="$1"
  [[ -f "$binary" && -x "$binary" ]] || return 1
  python3 - "$binary" <<'PY'
import copy
import json
import os
import subprocess
import sys

assert os.geteuid() != 0, "owner-denial test requires unprivileged execution"
binary = sys.argv[1]
base = {"expected_current_release_id": "synthetic-current", "expected_current_receipt_blake3": "00" * 32,
    "target_release_id": "synthetic-target", "target_receipt_blake3": "00" * 32}
cases = []
for name, field, value, code in [
    ("arbitrary-field", "hostileField", "HOSTILE_RECOVERY_CANARY", "invalid_input"),
    ("runtime-key", "owner_public_key", "HOSTILE_RECOVERY_CANARY", "invalid_input"),
    ("arbitrary-current-path", "expected_current_release_id", "/tmp/HOSTILE_RECOVERY_CANARY", "recovery_denied"),
    ("arbitrary-target-path", "target_release_id", "../HOSTILE_RECOVERY_CANARY", "recovery_denied"),
    ("bad-pin", "target_receipt_blake3", "HOSTILE_RECOVERY_CANARY", "recovery_denied"),
    ("equal-ids", "target_release_id", "synthetic-current", "recovery_denied"),
]:
    value_input = copy.deepcopy(base)
    value_input[field] = value
    cases.append((name, "preflight", value_input, code))
cases.append(("root-apply-denial", "apply", base, "recovery_owner_required"))
cases.append(("missing-field", "preflight", {"target_release_id": "synthetic"}, "invalid_input"))
cases.append(("concatenated-json", "preflight", (json.dumps(base) + " {}").encode(), "invalid_input"))
cases.append(("oversize-input", "preflight", b" " * (262144 + 1), "input_too_large"))
for name, mode, value, code in cases:
    argv = [binary, "recovery", "--mode", mode]
    payload = value if isinstance(value, bytes) else json.dumps(value).encode()
    result = subprocess.run(argv, input=payload, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=10, check=False)
    assert result.returncode == 1 and len(result.stdout) <= 262144 and len(result.stderr) <= 65536
    response = json.loads(result.stdout)
    assert response["schema"] == "fwc.n8n.error.v1" and response["code"] == code
    assert b"HOSTILE_RECOVERY_CANARY" not in result.stdout + result.stderr
    if code == "recovery_denied":
        assert response["diagnostic"] == "invalid_request"
    print(json.dumps({"scenario": name, "argv": argv, "exit": result.returncode, "safe_code": code}))
print(json.dumps({"mode": "recovery-parser-self-test", "cases": 10, "verdict": "pass", "real_apply": False}))
PY
}

run_producer_replay_self_test() {
  local binary="$1" evidence="$2" assembler
  assembler="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/n8n_release_assembler.sh"
  [[ -f "$binary" && -x "$binary" && -d "$evidence" && ! -L "$evidence" ]] || return 1
  [[ "$(readlink -f -- "$evidence")" == /srv/dev-ssd/fcp/nqm81-34/* ]] || return 1
  python3 - "$binary" "$assembler" "$evidence" <<'PY'
import copy
import hashlib
import json
import os
import pathlib
import subprocess
import sys

binary, assembler, evidence = sys.argv[1:]
root = pathlib.Path(evidence)
names = ["tools_documentation", "search_nodes", "get_node", "validate_node", "get_template", "search_templates", "validate_workflow"]
input_schema = {"type": "object", "description": "synthetic reviewed input"}
output_schema = {"type": "object", "description": "synthetic reviewed output"}

def invoke(argv, value):
    result = subprocess.run(argv, input=json.dumps(value).encode(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=20, check=False)
    assert len(result.stdout) <= 262144 and len(result.stderr) <= 65536
    return result

def projection(output):
    result = invoke([binary, "schema-projection"], {"input_schema": input_schema, "output_schema": output})
    assert result.returncode == 0
    return json.loads(result.stdout)

pins = projection(output_schema)
baseline = {"integrity": "blake3", "input_schema": input_schema, "output_schema": output_schema,
    "input_schema_digest": pins["input_schema_digest"], "output_schema_digest": pins["output_schema_digest"]}
request = {"expected_catalog": dict.fromkeys(names, pins["input_schema_digest"]),
    "reviewed_baselines": {name: copy.deepcopy(baseline) for name in names},
    "catalog": {"tools": [{"name": name, "inputSchema": copy.deepcopy(input_schema),
        "outputSchema": copy.deepcopy(output_schema)} for name in names]}}
cases = [("reviewed-input-output-profile-produced", copy.deepcopy(request), 0)]
metadata = copy.deepcopy(request)
for tool in metadata["catalog"]["tools"]:
    tool["inputSchema"]["description"] = "synthetic metadata change"
    tool["outputSchema"]["description"] = "synthetic metadata change"
cases.append(("metadata-input-output-compatible", metadata, 0))
unrelated = copy.deepcopy(metadata)
unrelated["catalog"]["tools"].append({"name": "unreviewed_new_tool", "inputSchema": {"type": "object"}})
cases.append(("unrelated-new-tool-no-authority", unrelated, 0))
incorrect = copy.deepcopy(request)
incorrect["reviewed_baselines"][names[0]]["output_schema_digest"] = "00" * 32
cases.append(("incorrect-output-pin-denied", incorrect, 1))
semantic = copy.deepcopy(request)
semantic["catalog"]["tools"][0]["outputSchema"]["required"] = ["security"]
cases.append(("semantic-output-drift-denied", semantic, 1))
unknown = copy.deepcopy(request)
unknown["catalog"]["tools"][0]["outputSchema"]["unknownSecurityKeyword"] = True
cases.append(("unknown-output-keyword-denied", unknown, 1))
absent = copy.deepcopy(request)
del absent["catalog"]["tools"][0]["outputSchema"]
cases.append(("present-absent-swap-denied", absent, 1))
raw = copy.deepcopy(request)
del raw["reviewed_baselines"]
for tool in raw["catalog"]["tools"]:
    del tool["outputSchema"]
cases.append(("raw-default-absent-output-admitted", raw, 0))
added = copy.deepcopy(raw)
added["catalog"]["tools"][0]["outputSchema"] = copy.deepcopy(output_schema)
cases.append(("raw-default-added-output-denied", added, 1))
for name, value, expected in cases:
    argv = ["bash", assembler, "--offline-catalog-bindings", binary]
    # Exclusive creation retains reproducible synthetic inputs without ever
    # overwriting a prior evidence packet or archived candidate.
    with (root / (name + ".input.json")).open("x") as stream:
        json.dump(value, stream, sort_keys=True)
    result = invoke(argv, value)
    assert result.returncode == expected, name
    if expected == 0:
        policy = json.loads(result.stdout)
        assert policy["callable_tools"] == names
        assert set(policy["expected_output_catalog"]) == set(names)
        assert set(policy["reviewed_schemas"]) == (set(names) if "reviewed_baselines" in value else set())
    receipt = {"scenario": name, "argv": argv, "exit": result.returncode,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(), "synthetic": True}
    with (root / (name + ".receipt.json")).open("x") as stream:
        json.dump(receipt, stream, sort_keys=True)
    print(json.dumps(receipt, sort_keys=True))
# Exercise the same official validation function invoked before normal builds.
official_tools = ("publish_workflow", "unpublish_workflow", "archive_workflow", "execute_workflow")
official_input = {"type": "object"}
official_output = {"type": "object", "properties": {"reason": {"enum": ["blocked", "insufficient_api_key_scope", "insufficient_permissions"]}}}
def native_sha(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
official_baseline = {"integrity": "sha256", "input_schema": official_input,
    "output_schema": official_output, "input_schema_digest": native_sha(official_input),
    "output_schema_digest": native_sha(official_output)}
official = {server: {tool: copy.deepcopy(official_baseline) for tool in official_tools} for server in ("eec", "hetzner")}
official["local"] = {}
effective = {f"FWC_N8N_{server.upper()}_{tool.removesuffix('_workflow').upper()}_{direction.upper()}_SCHEMA_DIGEST":
    baseline[f"{direction}_schema_digest"]
    for server in ("eec", "hetzner") for tool, baseline in official[server].items()
    for direction in ("input", "output")}
official_cases = [("official-new-admitted-output-accepted", copy.deepcopy(official), dict(effective), 0)]
old_pins = dict(effective)
old_pins["FWC_N8N_EEC_PUBLISH_OUTPUT_SCHEMA_DIGEST"] = "sha256:103216d1ba8bb8e017ec6c068c2764c2ef3fd7950f34f413b32204d541ccfe13"
official_cases.append(("official-old-output-refused-before-build", copy.deepcopy(official), old_pins, 1))
for direction in ("input", "output"):
    bad = copy.deepcopy(official)
    bad["eec"]["publish_workflow"][f"{direction}_schema_digest"] = "sha256:" + "0" * 64
    official_cases.append((f"official-wrong-{direction}-pin-denied", bad, dict(effective), 1))
absent = copy.deepcopy(official); absent["eec"]["publish_workflow"]["output_schema"] = None
official_cases.append(("official-output-presence-change-denied", absent, dict(effective), 1))
unknown = copy.deepcopy(official)
unknown["eec"]["publish_workflow"]["output_schema"]["unknownSecurityKeyword"] = True
unknown["eec"]["publish_workflow"]["output_schema_digest"] = native_sha(unknown["eec"]["publish_workflow"]["output_schema"])
unknown_pins = dict(effective); unknown_pins["FWC_N8N_EEC_PUBLISH_OUTPUT_SCHEMA_DIGEST"] = unknown["eec"]["publish_workflow"]["output_schema_digest"]
official_cases.append(("official-unknown-schema-denied", unknown, unknown_pins, 1))
extra = copy.deepcopy(official); extra["eec"]["unreviewed_tool"] = copy.deepcopy(official_baseline)
official_cases.append(("official-extra-tool-denied", extra, dict(effective), 1))
official_cases.append(("official-override-without-admission-denied", None, dict(effective), 1))
official_cases.append(("official-no-admission-current-defaults", None, {}, 0))
local_only_path = pathlib.Path("/srv/dev-ssd/fcp/nqm81-34/schema-export-local-baselines-UNAPPROVED.json")
local_only_raw = local_only_path.read_bytes()
assert hashlib.sha256(local_only_raw).hexdigest() == "0cf5648c1d96c017fa8ada9c4c7f9a5446a301a802eb746ea06d1f98a93d7d54"
local_only = json.loads(local_only_raw)
assert set(local_only) == {"_authority", "local"}
official_cases.append(("official-local-only-admitted-defaults-accepted", local_only, {}, 0))
official_cases.append(("official-local-only-changed-override-denied", local_only,
    {"FWC_N8N_EEC_PUBLISH_OUTPUT_SCHEMA_DIGEST": effective["FWC_N8N_EEC_PUBLISH_OUTPUT_SCHEMA_DIGEST"]}, 1))
for name, value, pins, expected in official_cases:
    input_path = root / (name + ".input.json")
    if name.startswith("official-local-only-"):
        with input_path.open("xb") as stream: stream.write(local_only_raw)
    else:
        with input_path.open("x") as stream: json.dump(value, stream, sort_keys=True)
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "LANG": "C", "LC_ALL": "C", **pins}
    if value is not None: environment["FWC_N8N_REVIEWED_SCHEMA_BASELINES"] = str(input_path)
    argv = ["bash", assembler, "--check-official-baselines", binary]
    result = subprocess.run(argv, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=100)
    assert result.returncode == expected and len(result.stdout) <= 262144 and len(result.stderr) <= 65536, name
    assert b"unknownSecurityKeyword" not in result.stdout + result.stderr
    receipt = {"scenario": name, "argv": argv, "environment": environment, "exit": result.returncode,
        "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "before_build_only": True, "synthetic": True}
    with (root / (name + ".receipt.json")).open("x") as stream: json.dump(receipt, stream, sort_keys=True)
    print(json.dumps(receipt, sort_keys=True))
print(json.dumps({"mode": "producer-replay-self-test", "cases": 9 + len(official_cases), "acceptance": False, "verdict": "pass"}))
PY
}

run_compatibility_self_test() {
  local binary="$1" input output baseline profile metadata changed invalid
  [[ -f "$binary" && -x "$binary" ]] || { emit_self_test_failure; return 1; }
  input='{"description":"reviewed","type":"object"}'
  output='{"description":"reviewed output","type":"object"}'
  baseline="$(jq -nc --argjson input "$input" --argjson output "$output" \
    --arg in_digest "sha256:$(printf '%s' "$input" | /usr/bin/sha256sum | cut -d ' ' -f1)" \
    --arg out_digest "sha256:$(printf '%s' "$output" | /usr/bin/sha256sum | cut -d ' ' -f1)" \
    '{integrity:"sha256",input_schema:$input,output_schema:$output,input_schema_digest:$in_digest,output_schema_digest:$out_digest}')"
  profile="$(printf '%s' "$baseline" | /usr/bin/timeout 10 "$binary" reviewed-schema-profile)" || { emit_self_test_failure; return 1; }
  jq -e '.profile == "mcp-schema-descriptions-v1" and (.input_compatibility_digest|length)==64 and (.output_compatibility_digest|length)==64' <<<"$profile" >/dev/null || return 1
  metadata='{"description":"changed","type":"object"}'
  baseline="$(jq --argjson input "$metadata" \
    --arg digest "sha256:$(printf '%s' "$metadata" | /usr/bin/sha256sum | cut -d ' ' -f1)" \
    '.input_schema=$input | .input_schema_digest=$digest' <<<"$baseline")"
  changed="$(printf '%s' "$baseline" | /usr/bin/timeout 10 "$binary" reviewed-schema-profile)" || return 1
  [[ "$(jq -r '.input_compatibility_digest' <<<"$profile")" == "$(jq -r '.input_compatibility_digest' <<<"$changed")" ]] || return 1
  metadata='{"default":{},"description":"changed","type":"object"}'
  baseline="$(jq --argjson input "$metadata" \
    --arg digest "sha256:$(printf '%s' "$metadata" | /usr/bin/sha256sum | cut -d ' ' -f1)" \
    '.input_schema=$input | .input_schema_digest=$digest' <<<"$baseline")"
  changed="$(printf '%s' "$baseline" | /usr/bin/timeout 10 "$binary" reviewed-schema-profile)" || return 1
  [[ "$(jq -r '.input_compatibility_digest' <<<"$profile")" != "$(jq -r '.input_compatibility_digest' <<<"$changed")" ]] || return 1
  invalid="$(jq '.output_schema_digest="tampered"' <<<"$baseline")"
  if printf '%s' "$invalid" | /usr/bin/timeout 10 "$binary" reviewed-schema-profile >/dev/null 2>&1; then return 1; fi
  invalid="$(jq '.output_schema=null' <<<"$baseline")"
  if printf '%s' "$invalid" | /usr/bin/timeout 10 "$binary" reviewed-schema-profile >/dev/null 2>&1; then return 1; fi
  invalid="$(jq '.output_schema.type="string"' <<<"$baseline")"
  if printf '%s' "$invalid" | /usr/bin/timeout 10 "$binary" reviewed-schema-profile >/dev/null 2>&1; then return 1; fi
  baseline="$(jq '.input_schema_digest="tampered"' <<<"$baseline")"
  if printf '%s' "$baseline" | /usr/bin/timeout 10 "$binary" reviewed-schema-profile >/dev/null 2>&1; then return 1; fi
  printf '{"schema":"%s","verdict":"pass","mode":"compatibility-self-test","acceptance":false,"cases":7}\n' "$SCHEMA"
}

run_self_test() {
  SELF_TEST=1
  local base=""
  local fixture=""
  base="$(base_plan)"
  # fresh_integer_13_digit_unix_millisecond
  if ! expect_success "$base"; then
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

  # reject_19_digit_unix_nanoseconds
  fixture="$(jq -c '.approval.expires_at_ms = 1234567890123456789' <<<"$base")"
  if ! expect_failure "expiry_not_13_digits" "$fixture"; then emit_self_test_failure; return 1; fi

  # reject_10_digit_unix_seconds
  fixture="$(jq -c '.approval.expires_at_ms = 1234567890' <<<"$base")"
  if ! expect_failure "expiry_not_13_digits" "$fixture"; then emit_self_test_failure; return 1; fi

  # reject_expired_13_digit_unix_millisecond
  fixture="$(jq -c 'now as $n | .approval.expires_at_ms = ((($n * 1000) | floor) - 1)' <<<"$base")"
  if ! expect_failure "expiry_stale" "$fixture"; then emit_self_test_failure; return 1; fi

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

read_only_projection() {
  local target="$1" version="${2:-}" execution="${3:-}"
  if [[ "$target" == local ]]; then
    jq -e 'type == "object" and .schema == "fwc.n8n.local-run-once.v1" and
      .provider == "local_mcp" and .response.operation == "knowledge_query" and
      .response.result.status == "Completed" and .response.result.shutdown.reaped == true and
      .response.result.shutdown.group_absent == true and
      .response.result.startup.network_disabled == true and
      (.response.result | has("teardown_error_code")) and
      .response.result.teardown_error_code == null and
      (.response.result.responses | type == "array" and length == 1 and
        (.[0] | type == "object" and
        ((has("isError") | not) or .isError == false) and
        (.content | type == "array" and length > 0 and length <= 64 and
          all(.[]; type == "object" and .type == "text" and
            (.text | type == "string" and length > 0 and length <= 262144 and test("\\S"))))))' >/dev/null 2>&1
  else
    jq -e --arg version "$version" --arg execution "$execution" '
      type == "object" and .status == "ok" and
      .result.id == $execution and .result.workflowVersionId == $version' >/dev/null 2>&1
  fi
}

run_read_only_self_test() {
  local local_ok='{"schema":"fwc.n8n.local-run-once.v1","provider":"local_mcp","response":{"operation":"knowledge_query","result":{"status":"Completed","startup":{"network_disabled":true},"shutdown":{"reaped":true,"group_absent":true},"teardown_error_code":null,"responses":[{"content":[{"type":"text","text":"HOSTILE-CANARY"}]}]}}}'
  read_only_projection local <<<"$local_ok" || return 1
  if read_only_projection local <<<"$(jq '.response.result.shutdown.reaped=false' <<<"$local_ok")"; then return 1; fi
  if read_only_projection local <<<"$(jq '.response.result.status="Failed"' <<<"$local_ok")"; then return 1; fi
  read_only_projection eec version-1 execution-1 <<<'{"status":"ok","result":{"id":"execution-1","workflowVersionId":"version-1","data":"HOSTILE-CANARY"}}' || return 1
  if read_only_projection hetzner version-2 execution-1 <<<'{"status":"ok","result":{"id":"execution-1","workflowVersionId":"version-1"}}'; then return 1; fi
  if read_only_projection eec version-1 execution-1 <<<'{"status":"ok","result":{"id":"execution-1","versionId":"version-1"}}'; then return 1; fi
  if read_only_projection eec version-1 execution-2 <<<'{"status":"ok","result":{"id":"execution-1","workflowVersionId":"version-1"}}'; then return 1; fi
  local catalog='{"status":"ok","result":{"capabilities":{"schema":"fwc.n8n.capabilities.v1","serverId":"eec","tools":[]}}}'
  read_only_catalog_projection eec <<<"$catalog" || return 1
  if read_only_catalog_projection hetzner <<<"$catalog"; then return 1; fi
  if read_only_catalog_projection eec <<<"$(jq '.result.capabilities.tools=[{name:"HOSTILE-CANARY",class:"unknown",status:"unreviewed",inputSchemaDigest:"invalid",outputSchemaDigest:"invalid"}]' <<<"$catalog")"; then return 1; fi
  local projected
  projected="$(safe_read_only_failure local "$PARENT_BINDING" <<<'{"schema":"fwc.n8n.error.v1","status":"error","code":"HOSTILE-CANARY","correlationId":"HOSTILE-CANARY","diagnostic":"HOSTILE-CANARY"}')"
  [[ "$projected" != *HOSTILE-CANARY* ]] || return 1
  if read_only_projection local <<<"$(jq '.provider="HOSTILE-CANARY"' <<<"$local_ok")"; then return 1; fi
  if read_only_projection local <<<"$(jq '.response.operation="validation_run"' <<<"$local_ok")"; then return 1; fi
  projected="$(safe_read_only_failure eec "$PARENT_BINDING" <<<'{"schema":"fwc.n8n.error.v1","status":"error","code":"official_mcp_plan_failed","diagnostic":"external.mcp.discovery_jsonrpc_error","rpcPhase":"discovery","rpcCode":-32602,"correlationId":"12345678-1234-4234-8234-123456789abc"}')"
  jq -e '.code=="official_mcp_plan_failed" and .diagnostic=="external.mcp.discovery_jsonrpc_error" and .rpc_phase=="discovery" and .rpc_code == -32602 and .observed_correlation_id != null' <<<"$projected" >/dev/null || return 1
  projected="$(safe_read_only_failure eec "$PARENT_BINDING" <<<'{"schema":"fwc.n8n.error.v1","status":"error","code":"unknown_outcome","diagnostic":"owned.egress_stage.response_body_read","rpcPhase":"HOSTILE-CANARY","rpcCode":"HOSTILE-CANARY"}')"
  jq -e '.diagnostic=="owned.egress_stage.response_body_read" and .rpc_phase==null and .rpc_code==null' <<<"$projected" >/dev/null || return 1
  projected="$(emit_read_only_failure local "$PARENT_BINDING" HOSTILE-CANARY 124)"
  jq -e '.abort_code=="outer_guard_timeout" and .exit_code==124 and .teardown=="unverified" and .verdict=="fail"' <<<"$projected" >/dev/null || return 1
  [[ "$projected" != *HOSTILE-CANARY* ]] || return 1
  local fixture code
  for code in host_n8n_invoke_failed teardown_failed process_group_present io_worker_failed; do
    fixture="$(jq -nc --arg code "$code" '{schema:"fwc.n8n.error.v1",status:"error",code:$code,diagnostic:"invoke_unknown"}')"
    projected="$(safe_read_only_failure local "$PARENT_BINDING" <<<"$fixture")"
    jq -e --arg code "$code" '.code==$code and .diagnostic=="invoke_unknown"' <<<"$projected" >/dev/null || return 1
  done
  for fixture in \
    '.response.result.responses[0].isError=true' \
    '.response.result.responses=["HOSTILE-CANARY"]' \
    '.response.result.responses[0].isError=null' \
    '.response.result.responses[0].content=[]' \
    '.response.result.responses[0].content[0].text="   "'; do
    if read_only_projection local <<<"$(jq "$fixture" <<<"$local_ok")"; then return 1; fi
  done
  read_only_projection local <<<"$(jq '.response.result.responses[0].isError=false' <<<"$local_ok")" || return 1
  printf '%s\n' '{"schema":"fwc.n8n.compatibility-read.v1","mode":"self-test","verdict":"pass","cases":26,"boundaries":["bridge-code-invoke_unknown-pairs","hostile-denial","meaningful-tool-result"],"acceptance":false}'
}

safe_read_only_failure() {
  # Whitelist actual wrapper error codes; never reflect arbitrary upstream text.
  jq -c --arg target "$1" --arg requested "$2" --argjson exit_code "${3:-1}" '
    . as $r |
    {schema:"fwc.n8n.compatibility-read.v1",mode:"read-only",target:$target,
      verdict:"fail",abort_code:"read_only_probe_failed",provider_attempts:"unknown",exit_code:$exit_code,
      requested_correlation_id:$requested,
      code:(if $r.schema == "fwc.n8n.error.v1" and $r.status == "error" and
        (["bundle_unavailable","local_provider_policy_invalid","local_provider_failed",
          "invalid_input","invalid_operation_input","input_read_timeout",
          "cancelled","credential_broker_unavailable","credential_oversized",
          "credential_backend_failed","credential_invalid","official_mcp_response_invalid",
          "official_mcp_plan_failed","unknown_outcome","host_n8n_invoke_failed",
          "teardown_failed","process_group_present","io_worker_failed",
          "bridge_failed","output_encoding_failed"] | index($r.code)) != null
        then $r.code elif $r.schema == "fwc.n8n.local-run-once.v1" and
          $r.provider == "local_mcp" and $r.response.operation == "knowledge_query" and
          (["unsupported_platform","invalid_policy","invalid_request","process_start",
            "package_identity","process_identity","process_stop","startup_timeout",
            "request_timeout","cancelled","invalid_frame","catalog_mismatch","unknown_tool",
            "too_many_calls","frame_too_large","provider_error"] | index($r.response.result.result_code)) != null
        then $r.response.result.result_code else "unclassified_wrapper_failure" end),
      diagnostic:(if (["provider_unauthorized","provider_forbidden","provider_not_found",
        "provider_conflict","provider_rate_limited","provider_unavailable","validation_failed","invoke_unknown",
        "response_protocol","response_auth","response_rate_limited","response_capability",
        "response_zone","response_connector","response_resource","response_upstream_timeout",
        "response_dependency_unavailable","response_internal",
        "external.mcp.discovery_jsonrpc_error","external.mcp.discovery_tool_result_error",
        "external.mcp.execute_call_jsonrpc_error","external.mcp.execute_call_tool_result_error",
        "owned.egress_stage.host_authorization_binding","owned.egress_stage.credential_lease",
        "owned.egress_stage.policy_preflight","owned.egress_stage.dns_resolution",
        "owned.egress_stage.tls_policy_validation","owned.egress_stage.outbound_transport",
        "owned.egress_stage.response_body_read",
        "response_external_4xx","response_external_5xx","response_external_other",
        "response_external_unknown","child.protocol","child.auth","child.capability",
        "child.zone","child.connector","child.resource","child.external","child.internal",
        "child.unknown"] | index($r.diagnostic)) != null
        then $r.diagnostic else null end),
      rpc_phase:(if (["discovery","execute_call"] | index($r.rpcPhase)) != null then $r.rpcPhase else null end),
      rpc_code:(if ($r.rpcCode|type) == "number" and ($r.rpcCode|floor) == $r.rpcCode and
        $r.rpcCode >= -2147483648 and $r.rpcCode <= 2147483647 then $r.rpcCode else null end),
      teardown:(if $r.schema == "fwc.n8n.local-run-once.v1" then
        {reaped:(if ($r.response.result.shutdown.reaped|type)=="boolean" then $r.response.result.shutdown.reaped else null end),
         group_absent:(if ($r.response.result.shutdown.group_absent|type)=="boolean" then $r.response.result.shutdown.group_absent else null end)} else null end),
      observed_correlation_id:(if ($r.correlationId | type) == "string" and
        ($r.correlationId | test("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"))
        then $r.correlationId elif $r.schema == "fwc.n8n.local-run-once.v1" and
          ($r.response.result.correlation_id|type)=="string" and
          ($r.response.result.correlation_id|test("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"))
        then $r.response.result.correlation_id else null end)}' 2>/dev/null
}

emit_read_only_failure() {
  local target="$1" requested="$2" response="$3" exit_code="${4:-1}" projected=""
  if [[ "$exit_code" == 124 || "$exit_code" == 137 ]]; then
    printf '{"schema":"fwc.n8n.compatibility-read.v1","verdict":"fail","abort_code":"outer_guard_timeout","exit_code":%s,"requested_correlation_id":"%s","teardown":"unverified","provider_attempts":"unknown"}\n' "$exit_code" "$requested"
    return 0
  fi
  projected="$(safe_read_only_failure "$target" "$requested" "$exit_code" <<<"$response")" || {
    emit_failure read_only_probe_failed; return 0;
  }
  [[ -n "$projected" ]] || { emit_failure read_only_probe_failed; return 0; }
  printf '%s\n' "$projected"
}

run_actual_read_only_error_test() {
  local binary="$1" response="" projected="" actual_exit=0 correlation="12345678-1234-4234-8234-123456789abc"
  # A source wrapper outside an installed release fails bundle verification
  # before any provider or credential dispatch. Never accept the installed CLI.
  [[ -x "$binary" && "$(readlink -e "$binary")" == /srv/dev-ssd/fcp/targets/*/debug/fwc-n8n ]] || return 1
  if response="$(jq -nc --arg correlation "$correlation" \
      '{input:{action:{tool_documentation:{topic:null,depth:"essentials"}}},correlation_id:$correlation}' |
      /usr/bin/timeout 10s "$binary" run-once n8n.knowledge.query 2>/dev/null)"; then return 1; else actual_exit="$?"; fi
  [[ "$actual_exit" == 1 ]] || return 1
  projected="$(safe_read_only_failure local "$correlation" "$actual_exit" <<<"$response")" || return 1
  jq -e --arg correlation "$correlation" '.code == "bundle_unavailable" and
      .exit_code == 1 and .observed_correlation_id == $correlation' <<<"$projected" >/dev/null || return 1
  printf '%s\n' "$projected"
  printf '%s\n' '{"schema":"fwc.n8n.compatibility-read.v1","mode":"actual-source-cli-error","verdict":"pass","acceptance":false}'
}

run_read_only_check() {
  local target="${1:-}" workflow="${2:-}" execution="${3:-}" version="${4:-}" response="" operation="" correlation budget guard
  correlation="$(cat /proc/sys/kernel/random/uuid)"
  [[ -x "$WRAPPER" && -x /usr/bin/timeout ]] || { emit_failure checker_dependency_missing; return 1; }
  if [[ "$target" == local && "$#" == 1 ]]; then
    operation=n8n.knowledge.query
    # Read only fixed public policy budgets. Allow startup + one call + both
    # TERM/KILL teardown windows, five-second framing and fifteen-second margin.
    budget="$(jq -er '[.startup_timeout_ms,.request_timeout_ms,.shutdown_timeout_ms] |
      if all(.[]; type=="number" and floor==. and .>0 and .<=600000)
      then .[0]+.[1]+2*.[2] else error("invalid") end' \
      /usr/local/lib/fwc-n8n/current/policy/local-mcp.json 2>/dev/null)" || {
      emit_failure local_budget_invalid; return 1;
    }
    guard="$(( (budget + 999) / 1000 + 20 ))"
    # Fixed credential-free knowledge request, never workflow validation/execution.
    response="$(jq -nc --arg correlation "$correlation" '{input:{action:{tool_documentation:{topic:null,depth:"essentials"}}},correlation_id:$correlation}' |
      /usr/bin/timeout "${guard}s" "$WRAPPER" run-once "$operation" 2>/dev/null)" || {
      emit_read_only_failure "$target" "$correlation" "$response" "$?"; return 1;
    }
    read_only_projection local <<<"$response" || {
      emit_read_only_failure "$target" "$correlation" "$response" 0; return 1;
    }
  elif [[ ( "$target" == eec || "$target" == hetzner ) && "$#" == 4 &&
          "$workflow" =~ ^[A-Za-z0-9_-]{1,128}$ &&
          "$execution" =~ ^[A-Za-z0-9_-]{1,128}$ &&
          "$version" =~ ^[A-Za-z0-9_-]{1,128}$ ]]; then
    operation=n8n.executions.get
    response="$(jq -nc --arg server "$target" --arg workflow "$workflow" --arg id "$execution" --arg correlation "$correlation" \
      '{server_id:$server,input:{workflow_id:$workflow,id:$id},deadline_ms:20000,correlation_id:$correlation}' |
      /usr/bin/timeout 25s "$WRAPPER" run-once "$operation" 2>/dev/null)" || {
      emit_read_only_failure "$target" "$correlation" "$response" "$?"; return 1;
    }
    # Consume the full result in memory but persist no graph, credentials or items.
    read_only_projection "$target" "$version" "$execution" <<<"$response" || {
      emit_failure readback_version_mismatch; return 1;
    }
    jq -e --arg workflow "$workflow" '.result.workflowId == $workflow' <<<"$response" >/dev/null 2>&1 || {
      emit_failure readback_identity_mismatch; return 1;
    }
  else
    emit_failure input_arguments_invalid
    return 1
  fi
  printf '{"schema":"fwc.n8n.compatibility-read.v1","mode":"read-only","target":"%s","operation":"%s","verdict":"pass","wrapper_invocations":1,"requested_correlation_id":"%s","upgrade_acceptance":false}\n' "$target" "$operation" "$correlation"
}

read_only_catalog_projection() {
  # Only the wrapper's compact, unreviewed hash projection may reach evidence.
  jq -e --arg target "$1" '
    .status == "ok" and .result.capabilities.schema == "fwc.n8n.capabilities.v1" and
    .result.capabilities.serverId == $target and
    (.result.capabilities.tools | type == "array" and length <= 256 and
      all(.[]; .class == "unknown" and .status == "unreviewed" and
        (.name | type == "string" and test("^[A-Za-z0-9_.:-]{1,256}$")) and
        (.inputSchemaDigest | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
        (.outputSchemaDigest | type == "string" and test("^sha256:[0-9a-f]{64}$"))))' >/dev/null 2>&1
}

run_read_only_catalog() {
  local target="${1:-}" response="" correlation
  correlation="$(cat /proc/sys/kernel/random/uuid)"
  [[ "$#" == 1 && ( "$target" == eec || "$target" == hetzner ) ]] || {
    emit_failure input_arguments_invalid; return 1;
  }
  [[ -x "$WRAPPER" && -x /usr/bin/timeout ]] || { emit_failure checker_dependency_missing; return 1; }
  response="$(jq -nc --arg server "$target" --arg correlation "$correlation" '{server_id:$server,input:{},deadline_ms:20000,correlation_id:$correlation}' |
    /usr/bin/timeout 25s "$WRAPPER" run-once n8n.capabilities.inspect 2>/dev/null)" || {
    emit_read_only_failure "$target" "$correlation" "$response" "$?"; return 1;
  }
  read_only_catalog_projection "$target" <<<"$response" || {
    emit_failure read_only_projection_invalid; return 1;
  }
  jq -c --arg target "$target" '{schema:"fwc.n8n.compatibility-catalog.v1",target:$target,
    mode:"read-only",reviewed:false,upgrade_acceptance:false,
    tools:[.result.capabilities.tools[] | {name,inputSchemaDigest,outputSchemaDigest}]}' <<<"$response"
}

usage() {
  printf '%s\n' "usage: n8n_acceptance_preflight.sh [--self-test] [PLAN.json] | --compatibility-self-test SOURCE_BINARY"
  printf '%s\n' "explicit future provider reads: --read-only-check local | --read-only-check eec|hetzner WORKFLOW_ID EXECUTION_ID EXPECTED_WORKFLOW_VERSION_ID"
  printf '%s\n' "official catalog only: --read-only-catalog eec|hetzner; offline projections: --read-only-self-test"
  printf '%s\n' "actual offline error emitter: --actual-read-only-error-self-test SOURCE_DEBUG_BINARY"
}

main() {
  require_dependencies || return 1
  if [[ "${1:-}" == "--release-metadata-self-test" && "$#" == 3 ]]; then
    run_release_metadata_self_test "$2" "$3"
    return $?
  fi
  if [[ "${1:-}" == "--actual-read-only-error-self-test" && "$#" == 2 ]]; then
    run_actual_read_only_error_test "$2"
    return $?
  fi
  if [[ "${1:-}" == "--read-only-catalog" ]]; then
    shift
    run_read_only_catalog "$@"
    return $?
  fi
  if [[ "${1:-}" == "--read-only-self-test" && "$#" == 1 ]]; then
    run_read_only_self_test
    return $?
  fi
  if [[ "${1:-}" == "--read-only-check" ]]; then
    shift
    run_read_only_check "$@"
    return $?
  fi
  if [[ "${1:-}" == "--help" ]]; then
    usage
    emit_failure "input_arguments_invalid"
    return 1
  fi
  if [[ "${1:-}" == "--compatibility-self-test" ]]; then
    [[ "$#" == 2 ]] || { emit_failure "input_arguments_invalid"; return 1; }
    run_compatibility_self_test "$2"
    return $?
  fi
  if [[ "${1:-}" == "--producer-replay-self-test" ]]; then
    [[ "$#" == 3 ]] || { emit_failure "input_arguments_invalid"; return 1; }
    run_producer_replay_self_test "$2" "$3"
    return $?
  fi
  if [[ "${1:-}" == "--recovery-parser-self-test" ]]; then
    [[ "$#" == 2 ]] || { emit_failure "input_arguments_invalid"; return 1; }
    run_recovery_parser_self_test "$2"
    return $?
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
