#!/usr/bin/env bash
# Redaction-safe, read-only latency harness for the installed fwc-n8n path.
# It prints JSONL metadata only; provider responses are hashed and discarded.
set -u

BIN=${FWC_N8N_BIN:-/usr/local/lib/fwc-n8n/current/bin/fwc-n8n}
SAMPLES=${FWC_N8N_SAMPLES:-5}

usage() {
    printf '%s\n' \
        "usage: $0 <eec|hetzner> <list|capabilities|\"get\" workflow_id>" \
        "       FWC_N8N_SAMPLES=5 FWC_N8N_BIN=/path/to/fwc-n8n $0 eec list"
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
    usage >&2
    exit 64
fi

server=$1
operation=$2
workflow_id=${3:-}

case "$server" in
    eec|hetzner) ;;
    *) usage >&2; exit 64 ;;
esac

case "$operation" in
    list)
        input='{"limit":1}'
        host_operation='n8n.workflows.list'
        ;;
    capabilities)
        input='{}'
        host_operation='n8n.capabilities.inspect'
        ;;
    get)
        if [[ -z "$workflow_id" || ! "$workflow_id" =~ ^[A-Za-z0-9_-]+$ ]]; then
            printf '%s\n' 'get requires an alphanumeric workflow_id (the value is never printed)' >&2
            exit 64
        fi
        input=$(printf '{"id":"%s"}' "$workflow_id")
        host_operation='n8n.workflows.get'
        ;;
    *) usage >&2; exit 64 ;;
esac

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

    printf '{"telemetry":"n8n_mcp_memory","phase":"%s","processes":%s,"rss_kib":%s,"pss_kib":%s,"private_kib":%s}\n' \
        "$phase" "$count" "$rss" "$pss" "$private"
}

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
    printf '{"route":"typed_rest_fcp","operation":"%s","server":"%s","sample":%s,"rc":%s,"latency_ms":%s,"response_bytes":%s,"response_sha256_16":"%s"}\n' \
        "$host_operation" "$server" "$sample" "$rc" "$latency_ms" "$response_bytes" "$response_digest"
done

sorted=($(printf '%s\n' "${latencies[@]}" | sort -n))
middle=$(( (SAMPLES - 1) / 2 ))
p50=${sorted[$middle]}
p95=${sorted[$((SAMPLES - 1))]}
printf '{"summary":{"route":"typed_rest_fcp","operation":"%s","server":"%s","samples":%s,"p50_ms":%s,"p95_ms":%s,"mean_response_bytes":%s}}\n' \
    "$host_operation" "$server" "$SAMPLES" "$p50" "$p95" "$((bytes_total / SAMPLES))"

memory_snapshot after
