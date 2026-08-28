# n8n routing benchmark — bounded harness contract

Date: 2026-08-24

This is a bounded, read-only harness-contract packet for
`flywheel_connectors-nqm81.14`. It defines what the offline harness can prove;
it is not live n8n/API acceptance. Official MCP remains limited to capability
discovery (`tools/list`), not a side-effecting `tools/call`.

## Offline harness contract

`scripts/n8n_routing_benchmark.sh` emits schema
`fwc.n8n.routing-benchmark.v3` JSONL metadata bound to the fixed
`/usr/local/lib/fwc-n8n/current` symlink. A normal run records the immutable
release ID, the fixed-current reference, and truncated SHA-256 references for
the fixed `fwc-n8n` binary and `policy/local-mcp.json`. It does not accept a
caller-selected binary/path or print catalogs, provider payloads, credentials,
or workflow IDs. `--self-test` is fully offline: it exercises only the
allowlists, schema fixture, bounded byte estimate, and redaction-safe metadata
shape; it does not read the runtime or invoke a provider.

Every preflight, sample, summary, and teardown record has `route`,
`operation_class`, `phase`, and `not_collected`. `capabilities.inspect` is
classified as `official_mcp`; workflow list/get remain `typed_rest_fcp`.
`total_latency_ms` is measured from wrapper invocation through wrapper exit.
`startup_latency_ms`, `provider_latency_ms`, and `provider_vs_total` remain
explicitly `null` and listed in `not_collected`: this host `run-once` stdout
does not expose internal phase telemetry, and the harness does not change
runtime instrumentation.

`token_estimate` is a bounded estimate only: `ceil(response_bytes / 4)` with a
10 MiB response-byte bound, labelled
`byte_count_estimate_not_tokenization`. No tokenizer runs and no claim of real
token count is made. The wrapper's own exit is observed as
`wrapper_exit_zero`/`wrapper_exit_nonzero`; `wrapper_invocation_count` is
therefore factual. Provider call count, nested-child teardown, and peak
RSS/PSS/private memory are `null`/`not_collected` because the request-scoped
child is not safely sampled by this shell-only contract. The old global scan of
persistent `n8n-mcp` processes is intentionally not part of this schema.

## Scope and redaction

- EEC and Hetzner were measured separately; no server was inferred from a
  workflow name.
- The known-ID read used one existing workflow ID per server. IDs, names,
  graphs, executions, credentials, and provider bodies were not written to the
  report.
- The harness records only bounded request/response byte counts, total wrapper
  time, return code, a short response digest, the byte-count estimate, and the
  observed wrapper exit state. It discards the response body.
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

The `get` ID is validated but never printed. A normal run emits `preflight`, one
`sample` per invocation, `summary`, and `teardown` phases. It emits no global
process baseline and does not claim that wrapper exit proves nested child
absence.

## Measured latency

The existing rows below are historical redacted observations. Values are p50/p95
in milliseconds; `response bytes` is the mean compact response size observed by
the caller. They predate schema v3 and do not retroactively prove the fields
listed above.

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
- The final routing choice must also include token counts. This packet now
  records only a clearly labelled byte-count estimate; it intentionally does
  not claim tokenization or token savings.

The offline harness-contract slice is complete. Live provider-vs-total timing,
true tokenization, request-scoped child peak memory, provider call count, and
nested teardown proof remain `not_collected` and require runtime/provider
instrumentation or an owner-approved live measurement packet. This document
does not claim those results or close any routing-policy decision.

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

The live packet remains incomplete for final `.14` acceptance: provider-vs-total
latency, true tokenization, per-invocation peak memory, provider call count,
nested teardown proof, current-profile parity for every operation class, and a
routing-policy change were not performed. The harness contract records these
gaps honestly instead of inferring them from persistent-process snapshots.

## Owner-approved live read-only benchmark — 2026-08-27

An owner-approved, sequential read-only run covered EEC and Hetzner using the
immutable current release `release-20260827-b43afd0ce-static`. The benchmark
metadata was bound to the fixed current reference with
`binary_sha256_16=b8a923f7bda30ef3` and
`policy_sha256_16=7fe825fcda28a330`. Three samples were collected for each
operation. Every sample had `rc=0`, `writes=0`, and `retries=0`; workflow IDs
and response bodies were discarded.

The reported latency is total FWC wrapper-invocation wall-clock time, not
provider latency:

| Server | Operation / route | p50/p95 total ms | Mean response bytes | Byte estimate | Samples | rc / writes / retries |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| EEC | `workflows.list` / `typed_rest_fcp` | 697 / 784 | 482 | 121 | 3 | 0 / 0 / 0 |
| EEC | `workflows.get` / `typed_rest_fcp` | 821 / 917 | 611 | 153 | 3 | 0 / 0 / 0 |
| EEC | `capabilities.inspect` / `official_mcp` | 1849 / 2504 | 9067 | 2267 | 3 | 0 / 0 / 0 |
| Hetzner | `workflows.list` / `typed_rest_fcp` | 1116 / 1163 | 510 | 128 | 3 | 0 / 0 / 0 |
| Hetzner | `workflows.get` / `typed_rest_fcp` | 1174 / 1244 | 757 | 190 | 3 | 0 / 0 / 0 |
| Hetzner | `capabilities.inspect` / `official_mcp` | 1222 / 1280 | 9071 | 2268 | 3 | 0 / 0 / 0 |

The following remain explicitly `not_collected`: provider latency, provider
call count, per-invocation peak RSS/PSS/private memory, real tokenization, and
nested teardown state. The FWC wrappers completed for these samples. That
completion is not proof of zero-idle memory or process state for a persistent
MCP profile.

## Current-release live capability verification — 2026-08-28

An owner-approved, sequential read-only `capabilities.inspect` run used the
installed immutable current release `release-20260828-d88e9d018-static`.
The fixed-current metadata was recorded as
`binary_sha256_16=5003243a224998f5f` and
`policy_sha256_16=7fe825fcda28a330`. Both server calls returned `rc=0`,
`status=ok`, `provider=official_mcp`, and `toolCount=34`; no workflow write,
`tools/call`, retry, credential value, workflow ID, or response body was
retained.

The live response marked every tool `class=unknown` and
`status=unreviewed`. The four release-bound tools needed by the current
lifecycle/execute contract nevertheless returned the following exact schema
digests:

| Server | Tool | Input schema digest | Output schema digest |
| --- | --- | --- | --- |
| EEC | `publish_workflow` | `sha256:b5fd649c299287d5bbf4091589d2e0c2cf54d3d8a87e5b4e97f5022d0bd74fcf` | `sha256:ec97a0fe010542c1aa3fcf484cc4531f27dfb72ce6d4a161d7dcd31d7f0b8ddf` |
| EEC | `unpublish_workflow` | `sha256:4d365469269cb9f2e3d2629cd2d86bdb23b1687cbff015895b59c78228d96115` | `sha256:31e476b490845afb45d0354ecdfb3fe26015d14d3967747119c5eecef0d2d00c` |
| EEC | `archive_workflow` | `sha256:e4d70f8c252f37f524219cb7f49d356823f3aa90db65a83a4e05f6fae0b89aac` | `sha256:ace6f4d62ecae252208fc3f17ef34d73f1cbb8044d42cb87add79146a56b4472` |
| EEC | `execute_workflow` | `sha256:73dc25c767561b5a2ad876e0d20bd7de221f2c644728de04365c346b2d1a3ef7` | `sha256:85d462b2dc634ca404ad6f43fa1bc773126b8695911c285d1cd3a4ae73eacb3f` |
| Hetzner | `publish_workflow` | `sha256:0df0eb8d4d0c0940bde97d3e2e3af5f9a184ed492dd98a23581bc72c8a17dba4` | `sha256:ff5dd02b739450a5567394322bf7b0c97ff303f91d6980ed480608f41ecbcdd0` |
| Hetzner | `unpublish_workflow` | `sha256:cc4142a9a5e7c283600ea6f34b6da198d618a2e05de7173f013986ad895a8a1a` | `sha256:2ef9307e809a33df73e644c134abad7756d76e5dc7db5484f1786b87bea04957` |
| Hetzner | `archive_workflow` | `sha256:9f4b360851418b0d0f3d71208a2465cd36c801cc3d452311c14d238720d0cdcf` | `sha256:83ca4eed4b170a03ef636348e35e28c0fcf5f217a176208fe8893f10ab4476b0` |
| Hetzner | `execute_workflow` | `sha256:89642ea4227211fc6a6b6d9f49f546019ac077f6021c7661baa59c2a58d864bd` | `sha256:951004b01987be0ee79562c09439b21d6cc66599c8a37a1bcb9350929105537b` |

This is current-release capability evidence, not lifecycle acceptance. The
unreviewed server classification remains a deliberate gate: publish,
unpublish, archive, execute, and generic MCP calls still require their
separate owner-approved disposable acceptance and independent readback.

## Offline verification performed

Only the following checks are in scope for this packet:

```bash
bash -n scripts/n8n_routing_benchmark.sh
scripts/n8n_routing_benchmark.sh --self-test
git diff --check
```

No live n8n/API call, Cargo command, Beads write, workflow write, lifecycle
action, credential read, or commit/push is part of this verification.
