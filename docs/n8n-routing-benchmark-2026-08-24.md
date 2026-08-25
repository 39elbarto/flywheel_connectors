# n8n routing benchmark — preliminary evidence

Date: 2026-08-24

This is a bounded, read-only measurement packet for
`flywheel_connectors-nqm81.14`. It is preliminary evidence, not final
acceptance: each latency class has five samples, tokenization was not run, and
official MCP was measured only through capability discovery (`tools/list`), not
through a side-effecting `tools/call`.

## Offline harness contract

`scripts/n8n_routing_benchmark.sh` emits redaction-safe JSONL metadata bound to
the fixed `/usr/local/lib/fwc-n8n/current` symlink. A normal run records the
immutable release ID and a truncated SHA-256 reference for the fixed
`fwc-n8n` binary; it does not accept a caller-selected binary path or print
catalogs, provider payloads, credentials, or workflow IDs. The `--self-test`
mode exercises only the local operation and server allowlists and does not
read the runtime or invoke a provider.

Every preflight, memory, sample, and summary record has `route`,
`operation_class`, `phase`, and `not_collected`. `capabilities.inspect` is
classified as `official_mcp`; workflow list/get remain `typed_rest_fcp`.
`latency_ms` is process-invocation wall-clock metadata. The harness does not
collect provider-vs-total latency, token estimates, per-request peak memory,
or provider live-acceptance evidence; those fields remain explicitly listed
in `not_collected`. Persistent MCP observations are a warm baseline and do not
prove zero-idle memory.

## Scope and redaction

- EEC and Hetzner were measured separately; no server was inferred from a
  workflow name.
- The known-ID read used one existing workflow ID per server. IDs, names,
  graphs, executions, credentials, and provider bodies were not written to the
  report.
- The FCP harness records only latency, return code, response byte count, and a
  short response digest. It discards the response body.
- No workflow write, activation, execution, deletion, credential operation, or
  automatic retry was performed.

Reproduction for the typed FCP route:

```bash
FWC_N8N_SAMPLES=5 scripts/n8n_routing_benchmark.sh eec list
FWC_N8N_SAMPLES=5 scripts/n8n_routing_benchmark.sh hetzner list
FWC_N8N_SAMPLES=5 scripts/n8n_routing_benchmark.sh eec get <known-workflow-id>
FWC_N8N_SAMPLES=5 scripts/n8n_routing_benchmark.sh hetzner get <known-workflow-id>
FWC_N8N_SAMPLES=1 scripts/n8n_routing_benchmark.sh eec capabilities
FWC_N8N_SAMPLES=1 scripts/n8n_routing_benchmark.sh hetzner capabilities
```

The `get` ID is validated but never printed. The script also emits before/after
counts and RSS/PSS/private totals for existing local `n8n-mcp` processes.

## Measured latency

Values are p50/p95 in milliseconds; `response bytes` is the mean compact
response size observed by the caller.

| Operation and route | EEC | Hetzner |
| --- | ---: | ---: |
| `workflows.list`, typed FCP run-once | 669 / 742; 482 B | 1132 / 1166; 510 B |
| `workflows.get`, typed FCP run-once | 683 / 825; 611 B | 1080 / 1234; 757 B |
| `workflows.list`, current MCP profile | 248 / 254; 635 B | 684 / 741; 606 B |
| `workflows.get`, current MCP profile | 239 / 281; 351 B | 707 / 761; 323 B |
| local node search (`webhook`, core) | 15 / 55; 1776 B | 14 / 48; 1776 B |
| local template pattern search | 8 / 11; 125 B | 8 / 9; 125 B |
| official MCP capability discovery, one sample | 1730; 9067 B | 1286; 9071 B |

The current MCP-profile measurements used the already connected server-scoped
read-only tools. They are a warm persistent-profile baseline, not an
on-demand process measurement. The local node/template calls are knowledge
operations and do not prove provider-server access.

## Memory and teardown evidence

At the first process snapshot there were 22 existing
`node /usr/local/bin/n8n-mcp` processes: about 1,419,280 KiB RSS, 1,271,364
KiB PSS, and 1,228,816 KiB private memory. At the final snapshot there were
still 22: about 1,486,660 KiB RSS, 1,293,482 KiB PSS, and 1,248,488 KiB
private. The change is an observed interval difference, not an attribution to
one operation. No residual FCP bundle, bridge, or host process was found after
the run-once samples.

Therefore:

- the current persistent MCP profile does not meet the zero-idle-process
  objective;
- the typed FCP path left no provider process behind in this measurement;
- the final host snapshot had about 9 GiB available RAM, swap almost full, and
  116 GiB free on the HDD, so further cold Cargo or high-concurrency
  benchmarking is deferred.

## Preliminary routing conclusion

- Known-ID workflow reads favor typed REST semantics for isolation and
  redaction, but the current warm profile was faster because it avoids
  per-invocation startup. The cost of that speed is persistent process memory.
- Node and template knowledge clearly belongs to the local knowledge route;
  its latency is orders of magnitude lower than a provider read.
- Official MCP is currently evidenced only for discovery. Its tool-call path
  remains owner-policy/provisioning/live-acceptance gated and must not be
  treated as a measured write-capable route.
- The final routing choice must also include token counts. This packet records
  byte sizes only; it intentionally does not claim token savings.

Remaining `.14` work is to add a controlled tokenizer/token-estimation step,
repeat the measurements under a documented resource envelope, and decide
whether the current-profile baseline can be retired after the on-demand path
passes its owner/live acceptance. This report does not close the bead.

## Live read-only verification — 2026-08-25

An owner-approved, sequential read-only run covered EEC and Hetzner with three
samples per operation. It used the fixed current release
`release-20260824-90819213-static` and binary reference
`ab9cfea00bc29dbb`; only redacted JSONL metadata was retained. Known workflow
IDs were resolved in shell variables and are not present in this document.

| Operation class | EEC p50/p95 | Hetzner p50/p95 | Mean response bytes | Result |
| --- | ---: | ---: | ---: | --- |
| `workflows.list` / `typed_rest_fcp` | 655 / 658 ms | 830 / 1084 ms | 482 / 510 | 3/3 each |
| known-ID `workflows.get` / `typed_rest_fcp` | 651 / 698 ms | 853 / 1198 ms | 611 / 757 | 3/3 each |
| `capabilities.inspect` / `official_mcp` (`tools/list`) | 1334 / 1346 ms | 1233 / 1439 ms | 9067 / 9071 | 3/3 each |

The benchmark measured invocation wall-clock time, not provider latency. The
official-MCP row proves only the fixed capability-discovery path; it does not
authorize or measure generic `tools/call` or workflow side effects.

During the run, the existing persistent MCP baseline remained at 18
`node /usr/local/bin/n8n-mcp` processes. Across the recorded before/after
snapshots, RSS was approximately 1,049,000–1,132,000 KiB, PSS
925,000–1,008,000 KiB, and private memory 882,000–965,000 KiB. After the
benchmark, no `fwc-n8n`, `fcp-n8n`, `fcp-mcp-bridge`, or `fcp-host` process
remained. This supports request teardown for the FWC path but does not prove
zero idle memory for the persistent MCP baseline.

The live packet remains incomplete for final `.14` acceptance: token estimates,
provider-vs-total latency, per-invocation peak memory, current-profile parity
for every operation class, and a routing-policy change were not performed.
