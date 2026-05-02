# Profiling Gamma Sweep - 2026-05-02

Agent: TealOtter
Scope: `fcp-store`, `fcp-raptorq`, `fcp-tailscale`, `fcp-bootstrap`
Mode: `/profiling-software-performance`

## Summary

This sweep looked for hot paths used by mesh sync, repair, and bootstrap:

- RaptorQ encode/decode and lossy repair-tail reconstruction.
- Store repair queue maintenance, durable WAL/checkpoint, and cursor walks.
- Tailscale status/peer/tag conversion in mesh handshake discovery.
- Bootstrap hardware-token detection, session selection, and certificate/key selection.

No quick-win code patch was applied. The concrete issues found are benchmark
coverage gaps and algorithm/data-structure risks that should be benchmarked
before changing behavior.

## Existing Bench Coverage

| Crate | Criterion coverage found | Gap |
| --- | --- | --- |
| `fcp-store` | `benches/symbol_store.rs`, `benches/repair_controller.rs` | Durable WAL/checkpoint/replay and queue-churn isolation missing |
| `fcp-raptorq` | none | Encode/decode hot paths unmeasured |
| `fcp-tailscale` | none | Status parse, peer conversion, tag filtering unmeasured |
| `fcp-bootstrap` | none | Hardware-token detection, session selection, cert/key selection unmeasured |

## Bench Evidence Captured

Command:

```bash
TMPDIR=/Volumes/USB_NVME CARGO_TARGET_DIR=/Volumes/USB_NVME/fcp-tealotter-prof cargo bench -p fcp-store --bench repair_controller -- --warm-up-time 0.1 --measurement-time 0.4 --sample-size 10
```

Result: passed. Short-run Criterion estimates:

- `repair_controller_plan_zone/1000`: 264.45 us to 271.81 us
- `repair_controller_plan_zone/10000`: 4.7361 ms to 4.8725 ms
- `repair_controller_plan_zone/100000`: 67.885 ms to 70.175 ms

Command:

```bash
TMPDIR=/Volumes/USB_NVME CARGO_TARGET_DIR=/Volumes/USB_NVME/fcp-tealotter-prof cargo bench -p fcp-store --bench symbol_store -- --warm-up-time 0.1 --measurement-time 0.4 --sample-size 10
```

Result: passed. Representative short-run Criterion estimates:

- `put_symbol/64`: 12.595 us to 13.060 us
- `put_symbol/4096`: 26.176 us to 26.572 us
- `get_symbol/single_lookup`: 113.58 ns to 113.98 ns
- `get_all_symbols/1000`: 27.613 us to 28.614 us
- `get_distribution/500`: 6.7574 us to 6.9247 us
- `list_zone/500`: 4.5654 us to 6.8372 us

No `[profiling][regression]` bead was filed because these benches do not carry
a pinned baseline or threshold comparator. The run only proves current bench
targets build and produce measurements under the isolated target dir.

## Findings Filed

| Bead | Class | Crate | Finding |
| --- | --- | --- | --- |
| `flywheel_connectors-ztdcm` | `[profiling][benches-missing]` | `fcp-store` | Durable WAL/checkpoint/replay and durable cursor walks lack Criterion coverage |
| `flywheel_connectors-u97n8` | `[profiling][algorithm]` | `fcp-store` | Repair queue is a sorted `Vec` under write lock with linear scan, full sort, `remove(0)`, and repeated `retain` |
| `flywheel_connectors-0orhf` | `[profiling][benches-missing]` | `fcp-raptorq` | Encode/decode paths lack Criterion coverage |
| `flywheel_connectors-qmepq` | `[profiling][algorithm]` | `fcp-raptorq` | Decode rebuilds full state on repair-symbol retries |
| `flywheel_connectors-g2dfl` | `[profiling][benches-missing]` | `fcp-tailscale` | LocalAPI status parse, peer conversion, and tag filtering lack Criterion coverage |
| `flywheel_connectors-qfsse` | `[profiling][algorithm]` | `fcp-tailscale` | Peer/tag helpers allocate and clone on handshake scans |
| `flywheel_connectors-ome5t` | `[profiling][benches-missing]` | `fcp-bootstrap` | Hardware-token bootstrap detection/session/cert selection lacks Criterion coverage |
| `flywheel_connectors-vkq68` | `[profiling][algorithm]` | `fcp-bootstrap` | Certificate selection is quadratic over cert/key matching and issuer-chain scans |

`br sync --flush-only` was run after each bead create.

## Hot Path Notes

### `fcp-store`

`RepairController` stores queued repairs as `RwLock<Vec<QueuedRepair>>`.
`upsert_repair` scans for an existing object, mutates or pushes, then sorts the
whole queue on every queue/refresh. `next_repair` dequeues with `remove(0)`,
which shifts the whole vector under the write lock. During zone evaluation,
missing-policy and missing-distribution branches call `remove_queued_repair`;
that function runs `retain` over the whole queue under the same lock.

The proposed direction in `flywheel_connectors-u97n8` is an indexed priority
queue: `BinaryHeap` plus `HashMap<ObjectId, generation/request>`, or `BTreeSet`
plus map, with lazy stale-generation popping.

Durable store paths are also unbenchmarked: checkpoint snapshot rewrite,
WAL append/checkpoint trigger, `get_all_symbols`, `get_distribution`,
`list_zone`, and WAL replay/read scanning.

### `fcp-raptorq`

`RaptorQEncoder::new` chunks payloads into `Vec<Vec<u8>>`; `encode_all` clones
source symbols and generates all repairs. `RaptorQDecoder::add_symbol` is the
ingest hot path. At decode time, `try_reconstruct` rebuilds decoder state,
clones buffered source/repair payloads, and allocates virtual zero-padding
rows. Dense fallback repartitions received symbols, allocates a full constraint
matrix and RHS vectors, then verifies constraints with nested loops.

The code already backs off source-symbol retries, but still attempts a full
decode immediately on every repair-symbol arrival. That is correctness-friendly
but potentially expensive in lossy repair tails.

### `fcp-tailscale`

`TailscaleClient::online_peers` consumes the status peer map and filters online
peers. `TailscaleStatus::peers` validates IDs but constructs a fresh
`HashMap<NodeId, PeerInfo>` and clones each peer. `PeerInfo::tailscale_tags`
and `fcp_tags` allocate vectors on each call. These helpers are convenient, but
large-tailnet handshake scans need iterator or caller-buffer variants.

### `fcp-bootstrap`

Hardware-token discovery and provisioning have several unmeasured hot paths.
`TokenDetectionReport::all_tokens`, `fcp_compatible_tokens`, and `issues`
allocate cloned vectors. `select_and_authenticate` clones the candidate list,
calls `issues().len()`, ranks/selects, authenticates, and clones the full report
into the outcome. `select_certificate_for_provisioning` enumerates certs and
keys, matches pairs with nested loops, parses X.509 repeatedly while scanning
issuer chains, sorts compatible candidates, and clones selected material.

The proposed direction in `flywheel_connectors-vkq68` is to index keys by
`CKA_ID`, parse certificate DER once into cached metadata, index issuer
candidates, and choose the deterministic best candidate with a single pass
instead of sorting the full compatible vector.

## Known Non-Scope Issue

The existing `fcp-conformance` `enforcement_check_order_conformance.rs` E0277
build issue was left untouched as requested.
