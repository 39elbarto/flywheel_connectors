#!/usr/bin/env bash
# Redaction-safe, read-only harness for the fixed installed fwc-n8n path.
# It prints JSONL metadata only; provider responses are hashed and discarded.
# The measured total is wrapper-invocation wall-clock time, not provider
# latency or live-acceptance evidence.
set -u

SCHEMA=fwc.n8n.routing-benchmark.v3
INSTALL_ROOT=/usr/local/lib/fwc-n8n
CURRENT_ROOT=$INSTALL_ROOT/current
BIN=$CURRENT_ROOT/bin/fwc-n8n
POLICY=$CURRENT_ROOT/policy/local-mcp.json
SAMPLES=${FWC_N8N_SAMPLES:-5}
MAX_ESTIMATE_BYTES=10485760
TOKEN_ESTIMATE_MODE=byte_count_estimate_not_tokenization
NOT_COLLECTED='["startup_latency_ms","provider_latency_ms","provider_vs_total","provider_call_count","peak_rss_kib","peak_pss_kib","peak_private_kib","nested_teardown_state","tokenization","live_acceptance"]'

release_id=
binary_sha256_16=
policy_sha256_16=
operation_route=
operation_class=
host_operation=
input=

usage() {
    printf '%s\n' \
        "usage: $0 [--self-test] <eec|hetzner> <list|capabilities|\"get\" workflow_id>" \
        "       FWC_N8N_SAMPLES=5 $0 eec list"
}

validate_server() {
    case "$1" in
        eec|hetzner) return 0 ;;
        *) return 1 ;;
    esac
}

configure_operation() {
    case "$1" in
        list)
            input='{"limit":1}'
            host_operation='n8n.workflows.list'
            operation_route='typed_rest_fcp'
            operation_class='workflow_list_read'
            ;;
        capabilities)
            input='{}'
            host_operation='n8n.capabilities.inspect'
            operation_route='official_mcp'
            operation_class='capability_discovery'
            ;;
        get)
            if [[ -z "${workflow_id:-}" || ! "$workflow_id" =~ ^[A-Za-z0-9_-]+$ ]]; then
                printf '%s\n' 'get requires an alphanumeric workflow_id (the value is never printed)' >&2
                return 64
            fi
            input=$(printf '{"id":"%s"}' "$workflow_id")
            host_operation='n8n.workflows.get'
            operation_route='typed_rest_fcp'
            operation_class='known_id_read'
            ;;
        *) return 1 ;;
    esac
}

assert_equal() {
    if [[ "$1" != "$2" ]]; then
        printf 'offline self-test failed: expected %s, got %s\n' "$2" "$1" >&2
        return 1
    fi
}

assert_contains() {
    case "$1" in
        *"$2"*) return 0 ;;
        *)
            printf 'offline self-test failed: missing %s\n' "$2" >&2
            return 1
            ;;
    esac
}

estimate_tokens_from_bytes() {
    local bytes=$1

    if [[ ! "$bytes" =~ ^[0-9]+$ ]] || (( bytes > MAX_ESTIMATE_BYTES )); then
        return 1
    fi
    printf '%s\n' "$(( (bytes + 3) / 4 ))"
}

common_json() {
    printf '{"schema":"%s","route":"%s","operation_class":"%s","server":"%s","operation":"%s","release_id":"%s","current_ref":"fixed_current","binary_sha256_16":"%s","policy_sha256_16":"%s"' \
        "$SCHEMA" "$operation_route" "$operation_class" "$server" "$host_operation" "$release_id" "$binary_sha256_16" "$policy_sha256_16"
}

run_self_test() {
    workflow_id=self_test_only

    if ! validate_server eec || ! validate_server hetzner || validate_server other; then
        printf '%s\n' 'offline self-test failed: server allowlist' >&2
        return 1
    fi

    configure_operation list || return 1
    assert_equal "$operation_route" typed_rest_fcp || return 1
    assert_equal "$operation_class" workflow_list_read || return 1

    configure_operation get || return 1
    assert_equal "$operation_route" typed_rest_fcp || return 1
    assert_equal "$operation_class" known_id_read || return 1

    configure_operation capabilities || return 1
    assert_equal "$operation_route" official_mcp || return 1
    assert_equal "$operation_class" capability_discovery || return 1

    if configure_operation unknown; then
        printf '%s\n' 'offline self-test failed: unknown operation was accepted' >&2
        return 1
    fi

    assert_equal "$SCHEMA" fwc.n8n.routing-benchmark.v3 || return 1
    assert_equal "$TOKEN_ESTIMATE_MODE" byte_count_estimate_not_tokenization || return 1
    assert_equal "$(estimate_tokens_from_bytes 0)" 0 || return 1
    assert_equal "$(estimate_tokens_from_bytes 1)" 1 || return 1
    assert_equal "$(estimate_tokens_from_bytes 4)" 1 || return 1
    assert_equal "$(estimate_tokens_from_bytes 5)" 2 || return 1
    if estimate_tokens_from_bytes $((MAX_ESTIMATE_BYTES + 1)) >/dev/null; then
        printf '%s\n' 'offline self-test failed: token estimate bound' >&2
        return 1
    fi

    server=eec
    release_id=self_test_release
    binary_sha256_16=0123456789abcdef
    policy_sha256_16=fedcba9876543210
    configure_operation list || return 1
    fixture=$(printf '%s,"phase":"sample","total_latency_ms":17,"response_bytes":5,"token_estimate":2,"token_estimate_mode":"%s","wrapper_invocation_count":1,"teardown_state":"wrapper_exit_zero","not_collected":%s}' \
        "$(common_json)" "$TOKEN_ESTIMATE_MODE" "$NOT_COLLECTED")
    assert_contains "$fixture" '"schema":"fwc.n8n.routing-benchmark.v3"' || return 1
    assert_contains "$fixture" '"current_ref":"fixed_current"' || return 1
    assert_contains "$fixture" '"binary_sha256_16":"0123456789abcdef"' || return 1
    assert_contains "$fixture" '"policy_sha256_16":"fedcba9876543210"' || return 1
    assert_contains "$fixture" '"total_latency_ms":17' || return 1
    assert_contains "$fixture" '"token_estimate_mode":"byte_count_estimate_not_tokenization"' || return 1
    assert_contains "$fixture" '"provider_latency_ms"' || return 1
    assert_contains "$fixture" '"peak_rss_kib"' || return 1
    assert_contains "$fixture" '"provider_call_count"' || return 1
    assert_contains "$fixture" '"nested_teardown_state"' || return 1

    printf '%s\n' 'offline self-test: PASS (route/class allowlist, bounded byte estimate, release/policy metadata, schema/not_collected consistency)'
}

prepare_release_metadata() {
    local resolved_current resolved_bin resolved_policy

    if [[ ! -L "$CURRENT_ROOT" ]]; then
        printf '%s\n' 'fixed current path is not a symlink' >&2
        return 66
    fi
    resolved_current=$(readlink -f -- "$CURRENT_ROOT") || {
        printf '%s\n' 'fixed current path cannot be resolved' >&2
        return 66
    }
    if [[ "$(dirname "$resolved_current")" != "$INSTALL_ROOT/releases" ]]; then
        printf '%s\n' 'fixed current path is not a direct immutable release child' >&2
        return 66
    fi
    release_id=${resolved_current##*/}
    if [[ -z "$release_id" || ! "$release_id" =~ ^[A-Za-z0-9._-]+$ ]]; then
        printf '%s\n' 'fixed current release id is invalid' >&2
        return 66
    fi

    resolved_bin=$(readlink -f -- "$BIN") || {
        printf '%s\n' 'fixed current binary cannot be resolved' >&2
        return 66
    }
    if [[ "$resolved_bin" != "$resolved_current/bin/fwc-n8n" || ! -x "$resolved_bin" ]]; then
        printf '%s\n' 'fixed current binary is not the immutable release binary' >&2
        return 66
    fi
    binary_sha256_16=$(sha256sum -- "$resolved_bin" | cut -c1-16)
    if [[ ! "$binary_sha256_16" =~ ^[0-9a-f]{16}$ ]]; then
        printf '%s\n' 'fixed current binary digest is invalid' >&2
        return 66
    fi

    resolved_policy=$(readlink -f -- "$POLICY") || {
        printf '%s\n' 'fixed current policy cannot be resolved' >&2
        return 66
    }
    if [[ "$resolved_policy" != "$resolved_current/policy/local-mcp.json" || ! -f "$resolved_policy" ]]; then
        printf '%s\n' 'fixed current policy is not the immutable release policy' >&2
        return 66
    fi
    policy_sha256_16=$(sha256sum -- "$resolved_policy" | cut -c1-16)
    if [[ ! "$policy_sha256_16" =~ ^[0-9a-f]{16}$ ]]; then
        printf '%s\n' 'fixed current policy digest is invalid' >&2
        return 66
    fi
}

emit_preflight() {
    printf '%s,"phase":"preflight","not_collected":%s}\n' "$(common_json)" "$NOT_COLLECTED"
}

if [[ "${1:-}" == '--self-test' ]]; then
    run_self_test
    exit $?
fi

if [[ $# -lt 2 || $# -gt 3 ]]; then
    usage >&2
    exit 64
fi

server=$1
operation=$2
workflow_id=${3:-}

if ! validate_server "$server"; then
    usage >&2
    exit 64
fi
if ! configure_operation "$operation"; then
    usage >&2
    exit 64
fi
if [[ "$operation" != get && $# -ne 2 ]]; then
    usage >&2
    exit 64
fi

if [[ ! "$SAMPLES" =~ ^[1-9][0-9]*$ || "$SAMPLES" -gt 25 ]]; then
    printf '%s\n' 'FWC_N8N_SAMPLES must be an integer from 1 to 25' >&2
    exit 64
fi

if [[ ! -x "$BIN" ]]; then
    printf '%s\n' 'fwc-n8n binary is not executable' >&2
    exit 66
fi

prepare_release_metadata || exit $?
emit_preflight

latencies=()
bytes_total=0
token_estimates_total=0
token_estimates_complete=true
for ((sample = 1; sample <= SAMPLES; sample++)); do
    request=$(printf '{"server_id":"%s","input":%s,"deadline_ms":30000}\n' "$server" "$input")
    request_bytes=$(LC_ALL=C printf '%s' "$request" | wc -c)
    started_ns=$(date +%s%N)
    if output=$(printf '%s' "$request" | \
        "$BIN" run-once "$host_operation" 2>/dev/null); then
        rc=0
    else
        rc=$?
    fi
    finished_ns=$(date +%s%N)
    latency_ms=$(( (finished_ns - started_ns) / 1000000 ))
    response_bytes=$(LC_ALL=C printf '%s' "$output" | wc -c)
    response_digest=$(LC_ALL=C printf '%s' "$output" | sha256sum | cut -c1-16)
    if token_estimate=$(estimate_tokens_from_bytes "$response_bytes"); then
        token_estimates_total=$((token_estimates_total + token_estimate))
    else
        token_estimate=null
        token_estimates_complete=false
    fi
    if (( rc == 0 )); then
        teardown_state=wrapper_exit_zero
    else
        teardown_state=wrapper_exit_nonzero
    fi
    latencies+=("$latency_ms")
    bytes_total=$((bytes_total + response_bytes))
    printf '%s,"phase":"sample","sample":%s,"rc":%s,"request_bytes":%s,"response_bytes":%s,"response_sha256_16":"%s","total_latency_ms":%s,"startup_latency_ms":null,"provider_latency_ms":null,"provider_vs_total":null,"token_estimate":%s,"token_estimate_mode":"%s","peak_rss_kib":null,"peak_pss_kib":null,"peak_private_kib":null,"provider_call_count":null,"wrapper_invocation_count":1,"observed_process":"fwc-n8n","teardown_state":"%s","nested_teardown_state":null,"not_collected":%s}\n' \
        "$(common_json)" "$sample" "$rc" "$request_bytes" "$response_bytes" "$response_digest" "$latency_ms" "$token_estimate" "$TOKEN_ESTIMATE_MODE" "$teardown_state" "$NOT_COLLECTED"
done

sorted=($(printf '%s\n' "${latencies[@]}" | sort -n))
middle=$(( (SAMPLES - 1) / 2 ))
p50=${sorted[$middle]}
p95=${sorted[$((SAMPLES - 1))]}
if [[ "$token_estimates_complete" == true ]]; then
    mean_token_estimate=$((token_estimates_total / SAMPLES))
else
    mean_token_estimate=null
fi
printf '%s,"phase":"summary","samples":%s,"p50_total_latency_ms":%s,"p95_total_latency_ms":%s,"mean_response_bytes":%s,"mean_token_estimate":%s,"token_estimate_mode":"%s","provider_latency_ms":null,"provider_vs_total":null,"provider_call_count":null,"peak_rss_kib":null,"peak_pss_kib":null,"peak_private_kib":null,"not_collected":%s}\n' \
    "$(common_json)" "$SAMPLES" "$p50" "$p95" "$((bytes_total / SAMPLES))" "$mean_token_estimate" "$TOKEN_ESTIMATE_MODE" "$NOT_COLLECTED"
printf '%s,"phase":"teardown","wrapper_invocations":%s,"observed_process":"fwc-n8n","teardown_state":"all_wrappers_exited","provider_call_count":null,"nested_teardown_state":null,"not_collected":%s}\n' \
    "$(common_json)" "$SAMPLES" "$NOT_COLLECTED"
