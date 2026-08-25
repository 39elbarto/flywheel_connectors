#!/usr/bin/env bash
# Redaction-safe, read-only latency harness for the fixed installed fwc-n8n path.
# It prints JSONL metadata only; provider responses are hashed and discarded.
# The measured latency is process-invocation wall-clock time, not provider
# latency or live-acceptance evidence.
set -u

INSTALL_ROOT=/usr/local/lib/fwc-n8n
CURRENT_ROOT=$INSTALL_ROOT/current
BIN=$CURRENT_ROOT/bin/fwc-n8n
SAMPLES=${FWC_N8N_SAMPLES:-5}
NOT_COLLECTED='["provider_latency_ms","startup_latency_ms","shutdown_latency_ms","call_count","token_estimate","peak_rss_kib","peak_pss_kib","peak_private_kib","post_run_process_state","live_acceptance"]'

release_id=
binary_sha256_16=
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

    printf '%s\n' 'offline self-test: PASS (route labels, operation allowlist, unknown-operation rejection)'
}

prepare_release_metadata() {
    local resolved_current resolved_bin

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
}

emit_preflight() {
    printf '{"schema":"fwc.n8n.routing-benchmark.v2","route":"%s","operation_class":"%s","phase":"preflight","server":"%s","operation":"%s","release_id":"%s","release_ref":"fixed_current","binary_sha256_16":"%s","not_collected":%s}\n' \
        "$operation_route" "$operation_class" "$server" "$host_operation" "$release_id" "$binary_sha256_16" "$NOT_COLLECTED"
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

memory_snapshot() {
    local phase=$1
    local count=0 rss=0 pss=0 private=0 cmdline pid

    for cmdline in /proc/[0-9]*/cmdline; do
        [[ -r "$cmdline" ]] || continue
        pid=${cmdline#/proc/}
        pid=${pid%/cmdline}
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
        cmdline=${cmdline% }
        [[ "$cmdline" == 'node /usr/local/bin/n8n-mcp' ]] || continue
        count=$((count + 1))
        if [[ -r "/proc/$pid/smaps_rollup" ]]; then
            read -r one_rss one_pss one_private < <(
                awk '/^Rss:/{r=$2} /^Pss:/{s=$2} /^Private_Clean:/{c=$2} /^Private_Dirty:/{d=$2} END{print r+0, s+0, c+d}' \
                    "/proc/$pid/smaps_rollup"
            )
            rss=$((rss + one_rss))
            pss=$((pss + one_pss))
            private=$((private + one_private))
        fi
    done

    printf '{"schema":"fwc.n8n.routing-benchmark.v2","route":"%s","operation_class":"%s","phase":"%s","server":"%s","operation":"%s","release_id":"%s","release_ref":"fixed_current","binary_sha256_16":"%s","telemetry":"n8n_mcp_memory","processes":%s,"rss_kib":%s,"pss_kib":%s,"private_kib":%s,"not_collected":%s}\n' \
        "$operation_route" "$operation_class" "$phase" "$server" "$host_operation" "$release_id" "$binary_sha256_16" "$count" "$rss" "$pss" "$private" "$NOT_COLLECTED"
}

prepare_release_metadata
emit_preflight
memory_snapshot before

latencies=()
bytes_total=0
for ((sample = 1; sample <= SAMPLES; sample++)); do
    started_ns=$(date +%s%N)
    if output=$(printf '{"server_id":"%s","input":%s,"deadline_ms":30000}\n' "$server" "$input" | \
        "$BIN" run-once "$host_operation" 2>/dev/null); then
        rc=0
    else
        rc=$?
    fi
    finished_ns=$(date +%s%N)
    latency_ms=$(( (finished_ns - started_ns) / 1000000 ))
    response_bytes=$(LC_ALL=C printf '%s' "$output" | wc -c)
    response_digest=$(LC_ALL=C printf '%s' "$output" | sha256sum | cut -c1-16)
    latencies+=("$latency_ms")
    bytes_total=$((bytes_total + response_bytes))
    printf '{"schema":"fwc.n8n.routing-benchmark.v2","route":"%s","operation_class":"%s","phase":"sample","operation":"%s","server":"%s","sample":%s,"release_id":"%s","release_ref":"fixed_current","binary_sha256_16":"%s","rc":%s,"latency_ms":%s,"response_bytes":%s,"response_sha256_16":"%s","not_collected":%s}\n' \
        "$operation_route" "$operation_class" "$host_operation" "$server" "$sample" "$release_id" "$binary_sha256_16" "$rc" "$latency_ms" "$response_bytes" "$response_digest" "$NOT_COLLECTED"
done

sorted=($(printf '%s\n' "${latencies[@]}" | sort -n))
middle=$(( (SAMPLES - 1) / 2 ))
p50=${sorted[$middle]}
p95=${sorted[$((SAMPLES - 1))]}
printf '{"schema":"fwc.n8n.routing-benchmark.v2","route":"%s","operation_class":"%s","phase":"summary","operation":"%s","server":"%s","samples":%s,"release_id":"%s","release_ref":"fixed_current","binary_sha256_16":"%s","p50_ms":%s,"p95_ms":%s,"mean_response_bytes":%s,"not_collected":%s}\n' \
    "$operation_route" "$operation_class" "$host_operation" "$server" "$SAMPLES" "$release_id" "$binary_sha256_16" "$p50" "$p95" "$((bytes_total / SAMPLES))" "$NOT_COLLECTED"

memory_snapshot after
