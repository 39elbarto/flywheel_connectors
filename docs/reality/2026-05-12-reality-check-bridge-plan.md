# 2026-05-12 Reality Check & Bridge Plan

Author: SunnyMoose (Claude Opus 4.7, /reality-check-for-project full run; revised in-place 2026-05-12 with three ambition rounds — R1 R2 R3 — and `/alien-graveyard` accretion)
Date: 2026-05-12
Vision baseline: README.md + docs/quarterly/2026-Q2-claims-vs-reality.md
Code baseline: HEAD = 1c1a2070a (main)

## Executive Summary

The project is in remarkable shape against its own vision. Of 32 Vision-Checklist items extracted from README, **22 are WORKING with substantive code + tests that have real assertions**, **8 are UNPROVEN** (code exists, no stored evidence), **2 are PARTIAL** (the README explicitly acknowledges this), and **0 are STUB / NO_BEAD**. The single load-bearing gap is the **Mesh-Native cutover (V2)** — explicitly flagged in the README as `STEADY-STATE TARGET (NOT YET OPERATIONAL)`. Every other gap is a refinement: performance evidence longitudinality, Zone Isolation graduation from LIMITED to PROVEN, tooling friction (agent-mail/disk-pressure), Windows sandbox parity, AWS Bedrock parity, 49 incubating connectors needing scope graduation, and uneven live-coverage discipline.

This is the bridge plan to close every conceivable gap. The plan now has **21 phases** (A–U), with Phase Q rewritten in R3 as the 10-bucket alien-graveyard accretion ledger and Phase U added as the capstone Brilliance-Integration synthesis. Phase order is: the original 13 phases (A–M), four ambition-round R1 phases — **N (Post-Quantum hardening cutover)**, **O (Formal verification gate via Lean)**, **P (Adversarial coverage)**, and **Q (Alien-graveyard accretion)** — plus three ambition-round R2 phases — **R (Chaos Engineering)**, **S (Formal Modeling in TLA+/CSP)**, and **T (Hardware Acceleration / SIMD / NEON / AES-NI / AVX-512)**. The R2 pass also threads ~25 specific mathematical/algorithmic accretions across the existing phases — polynomial vector commitments (KZG/IPA), Mitzenmacher-Pagh masked IBLTs, HyperLogLog/LogLog-Beta cardinality estimators, δ-state CRDTs with HVV revocation vectors, Hybrid Logical Clocks, ZK-SNARK predicate constraints (PLONK/HALO2), Reed-Solomon / Chiesa systematic codes, adaptive Bloom filters, CHERI-analogous capabilities, Wesolowski VDFs for owner key rate-limiting, BLS threshold aggregate signatures for quorum, coreset benchmark sampling, smoothed-analysis regret bounds, ε-δ differential privacy noise on telemetry, Reed-Muller binary attestation, anonymous credentials (Camenisch-Lysyanskaya / BBS+) for cross-zone delegation, Snowflake / Avalanche metastability consensus, Narwhal/Bullshark DAG-mempool for the audit chain, Coz causal profiling, eBPF audit-absence detection, the WASI Preview 3 / Component Model migration, and Hermit deterministic runtime for benches+fuzz. Every phase includes concrete file paths, statistical methodology where applicable, fault models, acceptance criteria, and the test/bench/conformance harness names that close it out.

### Ambition-round invariants applied to every phase

1. **No phase ships without OTLP spans** that carry `peer`, `lease_id`, `freshness_ms`, `truth_source`, and `decision_trace[]`. Telemetry is part of the deliverable, not an afterthought.
2. **Every claim must have a Lean proof obligation OR an explicit "no formal model" note** in `docs/formal/coverage-matrix.md` so the auditable surface is complete.
3. **Every test that touches the wire must have a proptest fuzzer companion** that injects malformed/oversized/time-skewed/mid-stream-disconnect inputs.
4. **Every cutover phase has a shadow-mode period** where the old and new paths both answer and an operator-side differ-diff watches for divergence.
5. **Every performance number includes Welch's t-test + bootstrap 95% CI** against a stored prior baseline; single-run "result" is not a result.

---

## Phase A — Mesh-Native Cutover (V2): the single load-bearing gap

**Target**: flip the `Mesh-Native Architecture` row from `STEADY-STATE TARGET (NOT YET OPERATIONAL)` to `PROVEN`, with mesh-backed invoke as the highest-confidence default and a fwc-visible truth label on every command output.

### A.0 Operational scaffolding (cutover precondition gates)

- **A.0.1** `fwc mesh explain-availability --json` must expose `has_mesh_replica`, `replica_count`, `quorum_summary`, `placement_policy_age`, `hrw_lease_holder`, `hrw_lease_quorum_height` so the `mesh-inventory-placement` gate predicate can evaluate (currently SKIP). Implementation surface: `crates/fwc/src/commands/mesh.rs::explain_availability`, fed by `fcp_mesh::placement::PlacementInventoryView`. Acceptance: `crates/fwc/tests/mesh_explain_availability_schema.rs` golden vector pinning the JSON shape; conformance test `crates/fcp-conformance/tests/mesh_explain_availability_field_coverage.rs` failing CI if any field is dropped.
- **A.0.2** `fwc audit chain status --json` must expose `quorum_signers`, `last_quorum_height`, `quorum_freshness_secs`, `quorum_rotation_epoch`, and `next_rotation_eta_secs` so the `mesh-audit-chain-quorum` gate can evaluate. Surface: `crates/fwc/src/commands/audit.rs::chain_status`, fed by `fcp_audit::quorum::QuorumHeadView`. Test: `crates/fwc/tests/audit_chain_status_shape.rs`.
- **A.0.3** `fwc policy distribution --json` must expose `peer_count`, `owner_signature_freshness`, `propagation_lag_p50/p99/p999`, `byzantine_evicted_peers[]` for the `mesh-policy-object-distribution` gate. Test: `crates/fwc/tests/policy_distribution_shape.rs`.
- **A.0.4** `fwc connector state status --json` must expose `canonical_status`, `replica_count`, `schema_version`, `root_object_id`, `crdt_merge_lattice_height`, `pending_writes_in_flight` (partially done via `host_connector_state_explain_payload_with_canonical_status` — verify exposure all the way to the CLI). Test: `crates/fwc/tests/connector_state_status_shape.rs`.
- **A.0.5** Every command in A.0.1–A.0.4 emits a structured OTLP span via `fcp_telemetry::span!` with attributes `peer.tailscale_node_id`, `lease.id`, `freshness.ms`, `decision_trace[]`. Conformance: `crates/fcp-telemetry/tests/otlp_span_field_coverage.rs`.

### A.1 ConnectorStateRoot externalization (hr0rr.2.2 — already in_progress)

- ConnectorStateRoot becomes a content-addressed mesh object (not a local file); local file flips to CACHE classification.
- **δ-state CRDT formulation (Almeida, Shoker, Baquero 2018, "Delta state replicated data types", JPDC 2018)**: ConnectorStateRoot is a δ-state CRDT rather than a state-based CRDT. Only deltas gossip; full state is fetched on demand via vector-commitment opening (A.1.bis below). Replay size is bounded by Almeida et al.'s theorem: a peer that has consumed deltas `{δ_1, ..., δ_k}` needs only `O(k)` bytes to catch up, **not** `O(|state|)`. Implementation: `crates/fcp-store/src/connector_state/delta_crdt.rs::DeltaStateRoot` with a `delta_buffer: VecDeque<Delta>` ring buffer and a compaction threshold = 1024 entries.
- **CRDT JOIN-semilattice formalism**: `ConnectorStateRoot` is a `LwwLatticeRoot` parameterized by `(node_id, hybrid_logical_clock, monotonic_seq)`. The carrier is a join-semilattice `(S, ⊔)` where `⊔` is idempotent, commutative, associative. Concurrent writes from two leaseholders during a partition heal via `merge(a, b) = a ⊔ b` satisfying `merge(a,b) ⊒ a ∧ merge(a,b) ⊒ b`. The merge function is encoded in `crates/fcp-store/src/connector_state/crdt.rs::ConnectorStateMerge`. **Acceptance**: property test `crates/fcp-store/tests/connector_state_merge_properties.rs` verifies idempotence (`a ⊔ a = a`), commutativity (`a ⊔ b = b ⊔ a`), and associativity (`(a ⊔ b) ⊔ c = a ⊔ (b ⊔ c)`) via proptest with 10,000 iterations + shrinking. Cross-references Phase O Lean proof `lean/FCP/Mesh/CrdtMerge.lean`.
- **Single-writer fallback**: when `singleton_writer = true` in manifest, CRDT merge is rejected at write time; conflict reports a `WriterFencingViolation` audit event with both fencing tokens. Connectors that opt into multi-writer CRDT explicitly declare `state_strategy = "lww_lattice"` or `"or_set"` in `manifest.toml`.
- Eviction policy: LRU + replica-count threshold; cache invalidation on mesh root rotation via subscription to `RootRotationGossip`.
- Tests: `crates/fcp-e2e/tests/fcp_store_connector_state_externalization_e2e.rs`, snapshot golden vector `tests/snapshots/connector_state_root_v1.cbor.bin`, latency matrix `docs/perf/connector_state_externalization_evidence.md` (target p99 < 5ms for cached read, < 50ms for mesh fetch on LAN).

### A.1.bis Vector commitments (KZG / IPA) for ConnectorStateRoot openings

- **Why**: today every mesh peer that wants to verify a subset of ConnectorStateRoot must fetch and re-hash the entire root — `O(n)` bytes and `O(n)` BLAKE3 work. A polynomial commitment lets us open **any subset** with a small `O(1)` (KZG) or `O(log n)` (IPA / Bulletproofs-Halo2) proof.
- **Scheme selection**: hybrid — **KZG10** (Kate-Zaverucha-Goldberg 2010, "Constant-size commitments to polynomials and their applications", AsiaCrypt 2010) for the steady-state pairing-friendly path with **BDFG batched openings** (Boneh-Drake-Fisch-Gabizon 2020, "Efficient polynomial commitment schemes for multiple points and polynomials", ePrint 2020/081) so a peer can open `k` positions with a single proof. Fallback path uses **Bulletproofs-style Inner Product Arguments (IPA)** (Bowe-Grigg-Hopwood 2019, "Recursive Proof Composition without a Trusted Setup", ePrint 2019/1021 — Halo) when a trusted setup is unacceptable for a zone.
- **Binding to Pedersen vector commitments**: the polynomial commitment is constructed over a Pedersen vector commitment of the leaves (one G1 element per leaf), embedded in `crates/fcp-crypto-pq/src/vector_commit/{kzg.rs, ipa.rs}`. The trusted setup (for KZG) is the zone-owner-signed "powers of tau" file at `zones/<zone>/kzg-srs.bin` with a public ceremony transcript. KZG ceremony participants documented in `docs/security/kzg_ceremony_<zone>.md`.
- **Verification cost**: `O(log n)` (IPA) or `O(1)` pairing check (KZG) instead of `O(n)` for state-subset openings. Mesh-reconciliation bandwidth drops by `n / log n`.
- **Acceptance**: `crates/fcp-crypto-pq/tests/kzg_open_batch_proptest.rs` proves opening soundness; `crates/fcp-e2e/tests/mesh_state_subset_opening_e2e.rs` runs a 100-peer mesh reconciliation and shows total bytes-on-wire dropped ≥ 50× vs. the BLAKE3-only baseline.
- **Fallback**: if KZG setup fails or the IPA prover is unavailable, fall back to full-root BLAKE3 hash + transmit (current behavior).

### A.2 Mesh-backed invoke path (the headline cutover, hr0rr.2.3)

- Add `MeshInvokeTransport` adjacent to `HostInvokeTransport` in `fcp-host` and `fwc`.

- **HRW (Highest Random Weight / rendezvous hashing) lease coordination** via `fcp-mesh::planner::HrwLeaseElector`:
  - Weight function: `w(peer, key) = blake3(peer.node_id || key || epoch).leading_u64()`
  - Concrete tie-breaking rules in priority order: (1) higher weight wins; (2) on weight tie, lexicographic `peer.node_id` wins; (3) on node_id tie (impossible but defensive), `peer.enrollment_seq` wins; (4) on all ties, abort with `LeaseElectionTie` and require operator intervention.
  - Per-key lease TTL = 5s with proactive renewal at 3s; expired lease triggers re-election within one gossip round (target p99 < 200ms LAN).
  - **Fencing token**: every lease carries `fencing_token = (epoch, seq)`; writes with stale fencing tokens are rejected by `fcp-store::write_with_fencing`.
  - Spec doc: `docs/architecture/adr/A2-hrw-lease-coordination.md`. Tests: `crates/fcp-mesh/tests/hrw_lease_election_properties.rs` (proptest: ∀ peer set, ∀ key, election is deterministic and uniform within 2% of ideal load distribution), `crates/fcp-mesh/tests/hrw_lease_failover_e2e.rs` (kill leaseholder, assert new holder elected within 1 gossip round and old fencing tokens are rejected).

- **Anti-entropy via Masked IBLT + adaptive Bloom + XOR filter reconciliation**:
  - **Probe layer — adaptive Bloom filter (Larisch, Choffnes, Levin, Maggs, Mislove, Wilson 2017 "CRLite" + Bender et al. 2018 "Bloom filters, adaptivity, and the dictionary problem", FOCS 2018)**: per-peer `AdaptiveBloomFilter` that online-tunes its false-positive rate based on observed reconciliation success — starts at fpr = 2^-12 and ratchets down to 2^-20 if a session sees > 16 false positives. Surface: `crates/fcp-mesh/src/anti_entropy/adaptive_bloom.rs::AdaptiveBloom`.
  - **XOR filter (Graf-Lemire 2020, "Xor filters: faster and smaller than Bloom and cuckoo filters", JEA 2020)** for fast set-difference probe (false-positive rate < 2^-32, lookup O(1)) — used after the adaptive Bloom for high-precision pre-IBLT probing.
  - **Masked IBLT (Mitzenmacher-Pagh 2018, "Simple multi-party set reconciliation", DCC 2018, "Masked IBLT" variant with biased hashing)**: standard IBLT requires `capacity = O(d)` where `d` is the set-difference size and degrades catastrophically when `d` is mis-estimated. Masked IBLT uses biased hashing on a "mask" derived from `blake3(epoch || peer_pair)` so anti-entropy is **O(min(d, n))** regardless of `d/n` ratio, and the decoder gracefully falls back to chunked exchange when over-budget. Cell size = (key_hash, value_hash, count, mask_idx). Implementation: `crates/fcp-mesh/src/anti_entropy/masked_iblt.rs::MaskedIblt`.
  - **False-positive surface budget**: total FPR across the layered probe (adaptive Bloom × XOR × Masked IBLT) is bounded at `2^-50` per reconciliation round; quantified in `docs/architecture/adr/A2-anti-entropy-reconciliation.md` with derivation. Conformance: `crates/fcp-conformance/tests/anti_entropy_fpr_budget.rs` empirically measures FPR over 10^6 random reconciliation rounds and asserts ≤ 2^-45 (5-bit safety margin).
  - **Latency budgets**: adaptive-Bloom probe < 5ms LAN p99; XOR filter exchange < 50ms LAN p99, < 500ms DERP p99; Masked IBLT decode < 100ms for diffs up to 1024 entries, < 500ms for diffs up to 16k entries; full reconciliation round budget = 1s LAN, 5s DERP.
  - Mesh-wide convergence SLO: post-write, all peers reflect the new state within `convergence_secs = 2 × p99(filter_exchange) + p99(iblt_decode)` (target < 1s LAN).
  - Spec doc: `docs/architecture/adr/A2-anti-entropy-reconciliation.md`. Tests: `crates/fcp-mesh/tests/anti_entropy_convergence_5_node_e2e.rs` writes 1000 objects, drops 10% of gossip packets, asserts convergence within budget; `crates/fcp-conformance/tests/iblt_decode_latency_budget.rs`; `crates/fcp-mesh/tests/masked_iblt_adversarial_diff_size.rs` (proves convergence when actual `d` is 10× the predicted value).

- **HyperLogLog + LogLog-Beta for mesh telemetry cardinality**:
  - **Why**: when fwc/operator queries probe mesh state, peer-count, replica-count-per-object, and dirty-set size are cardinality estimates with provable error bounds. Exact counters cost `O(n)` storage and bandwidth; HLL gives `O(log log n)` with bounded error.
  - **Scheme**: HyperLogLog (Flajolet-Fusy-Gandouet-Meunier 2007 "HyperLogLog: the analysis of a near-optimal cardinality estimation algorithm", AofA 2007) with the **LogLog-Beta correction (Qin et al. 2016 "LogLog-Beta and More: A New Algorithm for Cardinality Estimation Based on LogLog Counting", arXiv 1612.02284)** for low-cardinality bias correction. Standard error = 1.04/√m, with m = 16384 registers giving ~0.8% error.
  - **Surface**: `crates/fcp-mesh/src/telemetry/hll.rs::HllEstimator`. Used by `fwc mesh explain-availability --json` for `replica_count` (point estimate + 95% CI), `peer_count`, `dirty_set_size`.
  - **Acceptance**: `crates/fcp-mesh/tests/hll_estimator_error_bounds.rs` proptest over 1M random multisets, asserts measured error ≤ 1.5× theoretical bound.

- **Mesh-membership churn handling**:
  - **New peer joins mid-invoke**: in-flight invokes hold their elected leaseholder until completion; new peer is folded into HRW only for subsequent operations. Hold time bounded by `invoke_max_duration_secs = 60`.
  - **Peer fails mid-invoke**: detection via missed gossip heartbeat (3 × heartbeat_interval = 1.5s); leaseholder re-elected; if failed peer was the leaseholder, the in-flight invoke is restarted from the most recent `OperationIntent` checkpoint (idempotent semantics preserved by `OperationReceipt`).
  - **Slow-loris peer detection**: any peer whose gossip RTT exceeds `2 × p99_rtt_rolling_5min` for 3 consecutive intervals is flagged; flagged peers are excluded from leaseholder election (but still receive replicas). Surface: `fcp_mesh::peer::SloLorisGuard`.
  - **Byzantine peer eviction**: peers that emit conflicting fencing tokens, signatures that fail verification, or revocation-stale data exceeding 2 × SLA are quarantined; eviction requires owner-signed `PeerEvictionEvidence` object; eviction is replayed via `RevocationPushMessage` priority gossip.
  - Tests: `crates/fcp-e2e/tests/mesh_churn_chaos.rs` (chaos harness: random kill, partition, slow-loris, byzantine peer; asserts convergence and no double-execution); `crates/fcp-mesh/tests/byzantine_eviction_e2e.rs`.

- **Quorum signatures on the audit chain with rotation (BLS threshold aggregate)**:
  - Quorum = n-f, where n = enrolled-node count, f = floor((n-1)/3) for Byzantine-tolerant, or floor(n/2) for crash-tolerant (per-zone policy in `ZoneQuorumPolicy`).
  - **Threshold BLS aggregate signatures (Boneh-Lynn-Shacham 2001 "Short signatures from the Weil pairing", AsiaCrypt 2001, with the Boneh-Drijvers-Neven 2018 "Compact multi-signatures for smaller blockchains", AsiaCrypt 2018 BLS-PoP scheme)**: instead of `n` separate Ed25519 signatures (linear-size quorum proof), produce a single aggregated BLS signature of `t`-of-`n` signers via Lagrange-interpolation over BLS12-381 G1. Constant-size quorum signature regardless of `n`.
  - **Rogue-key attack defense**: every signer at enrollment publishes a **proof-of-possession** (BLS-PoP) signing the verifying key itself; aggregators verify each PoP before accepting a public key into the aggregate. Surface: `crates/fcp-crypto-pq/src/bls/threshold.rs::BlsThresholdSigner` + `crates/fcp-crypto-pq/src/bls/pop.rs::ProofOfPossession`.
  - **Hybrid path**: aggregate BLS is co-emitted with the Ed25519 + ML-DSA hybrid from Phase N for crypto-agility — a verifier accepts the audit-chain entry if **any** of the three signatures verifies and the chain ordering is consistent.
  - Signers rotate every `quorum_epoch_secs = 86400` (24h); rotation is driven by `QuorumRotationEvent` with overlap window of 1h where both old and new signers are accepted. Threshold rotation uses **Pedersen VSS** for verifiable key resharing without dealer dependence.
  - Tests: `crates/fcp-audit/tests/quorum_rotation_e2e.rs`, `crates/fcp-audit/tests/bls_threshold_aggregate_round_trip.rs`, `crates/fcp-conformance/tests/audit_chain_quorum_signature_coverage.rs`, `crates/fcp-crypto-pq/tests/bls_rogue_key_resistance.rs`.

- **Snowflake / Avalanche consensus for fast probabilistic finality (mesh decisions other than audit)**:
  - **Why**: not every mesh decision needs full BFT; for low-stakes decisions (placement hints, peer-eviction recommendations, gossip rate-shaping) we want sub-second finality with probabilistic safety.
  - **Scheme**: Snowflake / Snowball / Avalanche family (Rocket-Yin-Sekniqi-van Renesse-Sirer 2019 "Scalable and Probabilistic Leaderless BFT Consensus through Metastability", arXiv 1906.08936) — repeated sampling of `k` peers with `α`-supermajority and `β` consecutive successes; metastability resistance comes from the gradient of conflicting preferences self-amplifying.
  - **Parameters** (tens of peers): `k=20, α=0.8·k=16, β=8`; expected rounds to finality ≈ 10; per-round latency ≈ 30ms LAN → finality < 500ms.
  - **Surface**: `crates/fcp-mesh/src/consensus/avalanche.rs::AvalancheVoter`. Cross-references HRW lease coordination (used for low-stakes placement hints, NOT for invoke-critical leases).
  - **Acceptance**: `crates/fcp-mesh/tests/avalanche_metastability_property.rs` proptest with 30 peers, 50% adversarial preference flipping; safety (no conflicting decisions accepted) and liveness (decision within 50 rounds) hold with overwhelming probability.

- **DAG-based mempool (Narwhal / Bullshark) for audit-chain write path**:
  - **Why**: when the audit chain becomes write-throughput-bound (1000+ events/s sustained, as observed under heavy swarm sessions per memory 2026-05-02), serializing every write through quorum signing is the bottleneck. A DAG-mempool architecture (Danezis-Kokoris-Kogias-Sonnino-Spiegelman 2022 "Narwhal and Tusk: A DAG-based Mempool and Efficient BFT Consensus", EuroSys 2022; Spiegelman et al. 2022 "Bullshark: DAG BFT Protocols Made Practical", CCS 2022) makes writes `O(1)` and shifts ordering to an asynchronous post-commit pass.
  - **Plan**: introduce `crates/fcp-audit/src/dag_mempool.rs` with Narwhal-style block-and-reference DAG; Bullshark provides the asynchronous total-ordering finalizer. Each "block" carries a batch of audit events + references to ≥ `n-f` previous blocks; ordering rule = DFS over the DAG using round-robin anchor selection.
  - **Acceptance**: `crates/fcp-e2e/tests/narwhal_audit_throughput_e2e.rs` demonstrates 10× write-throughput improvement vs. the sequential chain on a 5-node cluster, while preserving total-order consistency.
  - **Fallback**: keep the linear hash-chain implementation for zones with `audit_chain_topology = "linear"` in zone policy.

- **eBPF audit-chain absence detector**:
  - **Why**: the existing audit chain proves "every recorded event happened"; an eBPF-hooked syscall watcher proves the **converse** — "every cross-zone I/O syscall has a matching audit entry". Catches absence-of-audit, not just presence.
  - **Plan**: `crates/fcp-audit-ebpf/` ships an Aya-based eBPF program that attaches to `LSM file_open`, `socket_connect`, `socket_sendmsg` hooks; emits a kernel ringbuf event per intercepted call; userspace reconciles against the audit chain within a 5s window. Missing matches surface as `AuditAbsenceAlert`.
  - **Platform**: Linux 5.10+ (LSM BPF). On macOS/Windows, a fall-back DTrace / ETW probe with the same semantics.
  - **Acceptance**: `crates/fcp-audit-ebpf/tests/syscall_audit_completeness.rs` runs a workload that emits 10k cross-zone I/O ops; asserts ≥ 99.99% audit matches within the 5s window and zero false absence alerts under benign load.

- **Fault model & partition tolerance**:
  - CAP positioning: AP (availability + partition-tolerance) for read paths; CP (consistency + partition-tolerance) for `singleton_writer` operations. Operator-visible label in `fwc connector state status` reports the CAP class.
  - **Partition test matrix**: bisecting partition, asymmetric partition (A→B works but B→A drops), DERP-only partition, full-network partition. Each case in `crates/fcp-e2e/tests/partition_matrix_e2e.rs`.
  - **No-double-execution invariant**: under any partition + heal sequence, `OperationIntent` + `OperationReceipt` ensure each idempotency-key is executed at most once. Property test `crates/fcp-conformance/tests/no_double_execution_under_partition_property.rs` runs 10,000 random partition sequences.

- Transparent fallback: if mesh peer unreachable, fall back to host-backed without changing the operator-visible answer shape (only the truth label changes from `mesh-backed` → `host-backed`).

- Tests:
  - `crates/fcp-e2e/tests/mesh_invoke_3_node_e2e.rs` — deterministic 3-node harness, mesh peer answers, no host involvement.
  - `crates/fcp-e2e/tests/mesh_invoke_5_node_chaos.rs` — 5-node with random failures.
  - `crates/fcp-e2e/tests/mesh_invoke_failover_e2e.rs` — peer goes down, transparent host downgrade with truth-label change.
  - `crates/fcp-conformance/tests/mesh_invoke_truth_label_conformance.rs` — every mesh-backed reply carries `truth_source: "mesh-backed"` exactly when the gate is green.

### A.3 LiveTruthResolver wired into fwc surface (hr0rr.2.5)

- `fwc list`, `fwc status`, `fwc doctor`, `fwc connector state status`, `fwc audit chain status` all consult LiveTruthResolver.
- Truth label injected into every CommandEnvelope via a new `TruthClassifiedEnvelope` wrapper.
- Mesh-backed default with transparent host-backed downgrade visible in `decision_trace`.
- **Connector-id → mesh-peer routing via adaptive Bloom**: replace the existing `HashMap<ConnectorId, PeerId>` routing index with an **adaptive Bloom filter family** (per Larisch et al. + Bender et al. 2018) sharded by zone. Each routing query: (a) Bloom probe `O(1)`; (b) on positive, IPA-opened vector commitment proves the binding; (c) on negative, definitively skip the peer. The adaptive component tunes FPR online to balance bandwidth-savings vs. retry-on-FP. Surface: `crates/fcp-mesh/src/routing/adaptive_bloom_route.rs::AdaptiveRouteIndex`.
- Tests:
  - `crates/fwc/tests/truth_label_surface_test.rs` — every command output JSON has `truth.source` and `truth.freshness`.
  - `crates/fwc/tests/readme_status_pinning.rs` — update the V2 cutover assertion to expect mesh-backed wiring (this test currently gates AGAINST the cutover — flipping it is the cutover signal).
  - `crates/fcp-mesh/tests/adaptive_route_index_bandwidth.rs` — asserts bandwidth-per-route < 16 bytes amortized at FPR ≤ 2^-16 over a 10k-connector mesh.

### A.4 Cutover gate evaluation flip (hr0rr.2.1)

- All four cutover gates in `docs/FCP3_Transition_Scorecard.md` flip from SKIP to PASS.
- Add a CI job `scripts/ci/cutover_gate_regression.sh` that fails the README quarterly debiasing if any gate regresses to SKIP.

### A.4.bis Hybrid Logical Clocks (HLC) for audit-chain global ordering

- **Why**: audit events span zones; per-zone monotonic `seq` cannot establish causal happens-before across zone boundaries; pure NTP wall-clock cannot establish causality at all and is exposed to skew/leap-seconds.
- **Scheme**: Hybrid Logical Clocks (Kulkarni-Demirbas-Madappa-Avva-Leone 2014 "Logical Physical Clocks", OPODIS 2014). Every event gets a 96-bit timestamp `HLC = (physical_ms: u64, logical_counter: u32)`. On event creation: `physical_ms = max(local_now_ms, last_seen_hlc.physical_ms)`; if `physical_ms == last.physical_ms` then `logical_counter = last.logical_counter + 1` else `logical_counter = 0`. On event receipt: `physical_ms = max(local_now_ms, local_hlc.physical_ms, incoming_hlc.physical_ms) + 1ms`; bounded by NTP skew + ε where ε = 100ms by default.
- **Encoding**: CBOR map `{0: physical_ms (uint), 1: logical_counter (uint)}` with deterministic key order; canonical bytes per fcp-cbor canonicalize spec. Surface: `crates/fcp-audit/src/hlc.rs::HybridLogicalClock`.
- **Acceptance**: `crates/fcp-audit/tests/hlc_causal_consistency_property.rs` proptest: for any partial-order of events across zones with bounded NTP skew, the HLC ordering is a total order that respects happens-before.
- **Bound**: max divergence between HLC and wall-clock = `(max(NTP_skew_ms) + ε)`; alerts surface in `fwc audit chain status --json` as `hlc_physical_drift_ms`.

### A.4.tris Hierarchical Version Vectors (HVV) for capability revocation freshness

- **Why**: per-peer-pair version vectors blow up `O(n²)` for revocation across n peers in a hierarchical zone topology; HVV gives near-constant overhead per zone hierarchy level.
- **Scheme**: Hierarchical Version Vectors (Almeida 2022 "Hierarchical Version Vectors", arXiv 2202.12366) — version vectors are organized by zone hierarchy `z:public ⊑ z:work ⊑ z:project:* ⊑ z:private ⊑ z:owner`; each level carries a single vector entry rather than per-peer.
- **Plan**: replace `RevocationRegistry`'s per-peer freshness map with `HierarchicalVersionVector` indexed by zone-tree node. Revocation freshness check is `O(depth)` instead of `O(peers)`.
- **Surface**: `crates/fcp-core/src/revocation/hvv.rs::HierarchicalVersionVector`. Integrates with `RevocationSlaChecker` (existing) and `RevocationPushMessage` priority gossip.
- **Acceptance**: `crates/fcp-conformance/tests/hvv_revocation_freshness_property.rs` proptest over 1000 random zone-hierarchy revocation sequences; assert freshness-check correctness and `O(depth)` cost.

### A.5 Pre-cutover shadow-mode (N-day differ-diff)

- **Shadow harness**: `crates/fcp-e2e/src/shadow.rs::ShadowInvokeHarness` runs every operator-invoked operation through **both** the host-backed transport and the mesh-backed transport, captures both answers, and emits a `ShadowDiff` event to OTLP + structured JSONL at `artifacts/shadow/<date>-<sha>/shadow_diff.jsonl`.
- **Differ rules**: byte-equivalent up to known-mutable fields (timestamps with `tolerance = 50ms`, request_ids, signatures); any other divergence is an operator-actionable alert via `fwc doctor`.
- **Duration**: minimum 14 days continuous shadow mode in production-like environment with > 100k operations, zero unexplained divergences, before flipping the default to mesh-backed.
- **Acceptance**: `docs/reality/2026-05-XX-mesh-shadow-evidence.md` records 14-day window, divergence histogram (target: 0 unexplained, 100% mutable-field divergences), and operator sign-off.

### A.6 Telemetry: per-interaction OTLP spans

- Every mesh interaction (lease election, gossip round, IBLT exchange, anti-entropy reconciliation, invoke dispatch, fallback decision) emits an OTLP span with attributes: `peer.tailscale_node_id`, `peer.region`, `lease.id`, `lease.fencing_token`, `freshness.ms`, `decision_trace[]`, `outcome.code`, `transport.priority` (1/2/3/4 per README), `quorum.height`, `crdt.merge_height`, `hlc.physical_ms`, `hlc.logical_counter` (per A.4.bis).
- Conformance: `crates/fcp-telemetry/tests/mesh_otlp_span_field_coverage.rs` enforces that every code path that touches mesh transport opens a span with the full attribute set; missing attributes fail CI.
- Sinks: local OTLP collector + (optional) remote via `OTEL_EXPORTER_OTLP_ENDPOINT`. Default sample rate = 1.0 during shadow mode, 0.1 thereafter.

### A.6.bis CHERI-analogous in-process capability tagging (forward-looking)

- **Why**: today's FCP capability typestate (Phase C.4 `ApprovalToken<Pending|Approved>`) gives **compile-time** capability discipline within a single process; under co-tenant execution (multiple connectors sharing an `fcp-host` process, the eventual fast-path), we want **hardware-backed bit-tight tag invariants** so that a memory-safety bug in one connector cannot forge another connector's capability.
- **Scheme**: CHERI (Watson, Woodruff, Neumann et al. 2015 "CHERI: A Hybrid Capability-System Architecture for Scalable Software Compartmentalization", IEEE S&P 2015; Morello/CHERIoT for embedded). Each in-process capability is a 128-bit hardware-tagged pointer; the tag bit is cleared by any non-capability arithmetic so forgery is impossible without explicit `CSetBounds`/`CSeal` operations.
- **Plan**: target CHERIoT-RTOS / Arm Morello as a tier-2 platform; provide a software-emulated `TaggedCapability<T>` shim on tier-1 (x86_64/aarch64) for analogous discipline at the type level. Surface: `crates/fcp-cap-cheri/src/tagged.rs::TaggedCapability` with `#[cfg(target_arch = "morello")]` selecting the hardware backend.
- **Analogy to FCP typestate**: the CHERI `CSeal` / `CUnseal` pair maps directly to the `ApprovalToken<Approved>::consume()` typestate transition; both prevent capability-arithmetic forgery, just at different layers.
- **Acceptance (tier-2)**: `crates/fcp-cap-cheri/tests/cheri_capability_forgery_resistance.rs` (gated `#[cfg(target_arch = "morello")]`) runs a fuzz harness that attempts every arithmetic on a sealed capability; assert all attempts clear the tag bit and any subsequent dereference traps.
- **Spec doc**: `docs/security/cheri_analogy.md` documents the mapping and the long-term roadmap (no hard cutover required).

### A.6.tris Differential-privacy noise on cross-peer telemetry

- **Why**: when `fwc doctor` and `fwc mesh explain-availability` report usage metrics (request counts, error rates, latency histograms) to peers or to a shared OTLP collector, a single connector's behavior could leak via fine-grained counters.
- **Scheme**: `(ε, δ)`-differential privacy via the **Laplace mechanism** (Dwork-McSherry-Nissim-Smith 2006 "Calibrating noise to sensitivity in private data analysis", TCC 2006) on every aggregate counter exported. ε = 1.0, δ = 10^-6 per epoch (24h), budget-tracked per zone via a moments-accountant.
- **Surface**: `crates/fcp-telemetry/src/dp.rs::LaplaceMechanism` + `DpBudget` accountant. Counters export `value_noised = value + Lap(sensitivity/ε)`; sensitivity is bounded per-metric by the connector's `manifest.toml::telemetry_sensitivity` declaration.
- **Acceptance**: `crates/fcp-telemetry/tests/dp_budget_accounting.rs` proptest verifies budget accumulation across compositions; `crates/fcp-telemetry/tests/dp_membership_inference_resistance.rs` runs a membership-inference adversary against the noised counters and asserts adversary advantage ≤ ε-bound.

### A.7 Production evidence artifact (the final cutover beat)

- `docs/perf/mesh_invoke_production_evidence.md`: 3-node deterministic E2E run, 1000-invoke matrix, per-truth-source latency distribution (p50/p99/p999), gate-by-gate green output.
- `docs/reality/2026-05-XX-mesh-native-graduation.md`: prose narrative + evidence pointers + signed quarterly debiasing entry.

---

## Phase B — Performance Evidence Longitudinality

**Target**: every README performance target has a written evidence doc in `docs/perf/` plus a CI regression gate with rigorous statistical methodology.

### B.1 Establish `docs/perf/` evidence convention

- One doc per target with: target threshold, harness invocation, measured p50/p99/p999, machine class, date, git SHA, **Welch's t-test result vs. prior baseline, bootstrap 95% CI for p99**, noise floor, and reproduction command.
- Already present: `docs/perf/memory_overhead_evidence.md`.
- New: `cold_start_evidence.md`, `local_invoke_evidence.md`, `lan_invoke_evidence.md`, `derp_invoke_evidence.md`, `symbol_reconstruction_evidence.md`, `secret_reconstruction_evidence.md`, `cpu_overhead_evidence.md`, `pq_signing_overhead_evidence.md` (see Phase N).

### B.2 Statistical methodology (binding)

- **Sample size**: minimum 1000 measurements per data point; if std/mean ratio > 0.10, increase to 10,000 before reporting.
- **Welch's t-test**: report `t-statistic`, `df`, `p-value` for null hypothesis "no regression vs. prior baseline". `p < 0.001` blocks a green CI; `p < 0.05` warns.
- **Bootstrap CI for p99**: 10,000-resample percentile bootstrap, report `[p99_lower, p99_upper]` 95% CI. The upper bound is what gates CI.
- **Tail-amplification ratio**: report `p999 / p50` as a single tail-shape metric; ratio > 100× triggers an investigation issue.
- **Histograms**: every doc embeds a full HDR histogram (linked artifact, 5 decimal places, range 1µs–60s), not just summary points. Format: HdrHistogram v1.2 binary + ASCII gnuplot.
- Helper: `crates/fcp-bench/src/stats.rs::StatPack` produces `{p50, p99, p999, mean, std, welch_t, bootstrap_ci, tail_amp}` from a sample vector.

### B.3 Noise modeling per machine class

- Machine classes:
  - **csd** (local M-class Mac, low concurrency): noise floor ~50µs.
  - **Contabo VPS workers** (8 rch workers, high concurrency): noise floor ~200µs, scheduling jitter ~500µs.
  - **local laptop** (developer workstation, variable load): noise floor ~100µs, jitter up to 5ms.
- Each evidence doc reports the class + noise floor + jitter bound. Targets are deemed "met" only if the measured p99 ≤ target − 2 × noise floor (i.e. 2-σ headroom).
- Calibration harness: `scripts/perf/calibrate_noise.sh` runs a no-op tight loop for 60s on the target machine and stores `artifacts/perf/calibration/<host>.json`.

### B.4 Memory: RSS + USS + PSS

- RSS alone is misleading for shared-pages cases (multiple connectors sharing libc + tokio runtime).
- Measure all three: **RSS** (resident set size), **USS** (unique set size — pages not shared), **PSS** (proportional set size — shared pages divided across sharers).
- Helper: `crates/fcp-bench/src/memory.rs::MemorySnapshot` reads `/proc/<pid>/smaps` on Linux, `task_info` on macOS, `GetProcessMemoryInfo` on Windows.
- Target reframe: README's `< 10MB per connector` is interpreted as USS (the only "honest" per-connector cost) and asserted in `docs/perf/memory_overhead_evidence.md` as such.

### B.5 Latency histograms (p999 + tail-amp)

- Add `p999` and `tail_amplification_ratio` to every latency target's evidence doc.
- Target tail-amplification ratio: `p999 / p50 ≤ 50×` for all latency targets except DERP path (where 100× is acceptable due to relay scheduling).

### B.6 Symbol reconstruction: K-sweep + erasure patterns + code-family selection

- Vary K ∈ {40, 100, 1000, 10000}, erasure pattern ∈ {head, tail, random, adversarial}.
- **Adversarial pattern**: chooses the erasures that maximize decode CPU per RaptorQ's known weak symbol distributions (see `crates/fcp-raptorq/src/adversarial.rs::worst_case_erasure`).
- Measure **decode CPU per symbol** (cycles/symbol) using `rdtsc` on x86 or `pmccntr_el0` on aarch64, plus wall-clock.
- Evidence: `docs/perf/symbol_reconstruction_evidence.md` with one table per (K, pattern) cell.
- Acceptance: even under adversarial pattern, K=1000 decode ≤ 250ms p99 (relaxed from 50ms target for K=1000 adversarial — target was for "1MB object", which is typically K≈40).

### B.6.bis Code-family selection: Reed-Solomon over primitive extensions + Chiesa systematic codes for small messages

- **Why**: RaptorQ has known inefficiencies for small messages: O(K²) decode cost dominates O(K log K) encoding setup; for `K < 100` (payloads < ~1MB) we can do much better.
- **Schemes**:
  - **Reed-Solomon over primitive field extensions**: RS(255, 223) over GF(2^8) with the **Berlekamp-Massey decoder** is `O(K²)` but the constants are tiny (~1 cycle/byte/symbol with AVX2 GF-multiplication tables). For `K ≤ 32` this beats RaptorQ in wall-clock.
  - **Chiesa systematic codes (Chiesa-Yu 2014 "Quasi-Optimal Codes for Reliable Multicast", FOCS 2014, and follow-up Ben-Sasson-Carmon-Chiesa-Riabzev 2020 "Fast Reed-Solomon Interactive Oracle Proofs of Proximity")**: `O(K log K)` encode + decode with constants competitive with RaptorQ; particularly attractive when the decoder needs to be batched across many symbols (mesh anti-entropy case).
  - **Runtime selection**: based on `K` and target decode-budget. Decision boundary derived from a per-machine-class cost curve.
- **Surface**: `crates/fcp-raptorq/src/code_family.rs::ErasureCode` trait with implementations `RaptorQ`, `ReedSolomonGf256`, `ChiesaSystematic`; the dispatch layer picks the right code at runtime via `select_code(K, target_decode_us, machine_class)`.
- **Evidence**: `docs/perf/erasure_code_selection_curve.md` — decode-cost-per-symbol curve for each code over K ∈ {8, 16, 32, 64, 128, 256, 512, 1024, 4096}, with the runtime selection boundary marked.
- **Acceptance**: `crates/fcp-raptorq/tests/code_family_dispatch_correctness.rs` proves every code decodes correctly under the agreed K-sweep + erasure-pattern matrix; `crates/fcp-raptorq/benches/code_family_decode_per_symbol.rs` exports the selection curve.

### B.7 Secret reconstruction: k/n + group + share-size sweep

- Vary `k/n ∈ {2/3, 3/5, 3/7, 5/9}`, group ∈ {Ristretto, P-256}, share size ∈ {32B, 256B, 4KB}.
- Evidence: `docs/perf/secret_reconstruction_evidence.md` table per cell.
- Acceptance: k=3/n=5 Ristretto 32B share reconstruction p99 ≤ 750ms (README target); k=5/n=9 P-256 4KB share ≤ 3s (relaxed target documented).

### B.8 CPU overhead: idle / light / heavy load

- Three regimes:
  - **Idle** (1 req in last 60s): target < 1% steady-state CPU per README.
  - **Light load** (10 req/s sustained): target < 3% per connector.
  - **Heavy load** (1000 req/s sustained): target < 15% per connector for request-response archetype; streaming archetype budgets defined per connector in `manifest.toml::performance_budget`.
- Measurement: `/proc/<pid>/stat` deltas over 60s windows; reported as both `user_cpu_pct` and `kernel_cpu_pct`.
- Evidence: `docs/perf/cpu_overhead_evidence.md` with the three regimes per representative connector (github, stripe, telegram, gmail, postgresql).

### B.9 Bench harness CI gate

- New: `scripts/ci/perf_regression_gate.sh`.
- Reads `docs/perf/perf-targets.toml` (canonical thresholds from README).
- Runs each `bench_cmd` benchmark, parses the StatPack, compares to threshold AND to rolling 7-day median to absorb noise.
- Fails CI on regression (>10% over p99 target, or p < 0.001 Welch's t vs. baseline).

### B.10 Longitudinal store

- `artifacts/perf/<bench>/<date>-<sha>.json` — one StatPack per CI run.
- `docs/perf/<bench>_history.md` — auto-generated trend doc with last 30 runs + sparkline ASCII chart.

### B.11 Connector-level performance budget

- Each connector gets a `manifest.toml` `[performance_budget]` block: `cold_start_max_ms`, `local_invoke_max_ms`, `memory_uss_max_mb`, `idle_cpu_max_pct`.
- Conformance test `crates/fcp-conformance/tests/per_connector_budget_assertion.rs` asserts budget ≤ workspace target and that the connector actually meets it under light load.

### B.12 Coreset-based benchmark sampling

- **Why**: running all 200+ benchmarks every CI is wasteful when the bench-to-bench correlation is high; we want a small subset that bounds the worst-case approximation error vs. the full benchmark suite mean.
- **Scheme**: weighted coresets (Bachem-Lucic-Krause 2018 "Scalable k-means Clustering via Lightweight Coresets", KDD 2018; Feldman-Schmidt-Sohler 2020 "Turning Big Data Into Tiny Data: Constant-Size Coresets for k-Means", JACM 2020). Pick a `ε`-coreset of size `O(k log k / ε²)` where `k` is the number of benchmark "clusters" (we cluster by `{archetype, latency_band, memory_band}`); the weighted coreset preserves the suite mean within multiplicative `(1±ε)` error.
- **Plan**: nightly CI runs the full suite; per-PR CI runs only the coreset (`scripts/ci/perf_coreset_gate.sh`). Coreset recomputation weekly via `scripts/perf/recompute_coreset.sh`.
- **Surface**: `crates/fcp-bench/src/coreset.rs::CoresetSelector` produces the weighted sample; `docs/perf/coreset_evidence.md` records the coreset selection + worst-case approximation error vs. full-suite results.
- **Acceptance**: coreset of size 25 (vs. full suite of ~200) preserves p99 latency estimate of every individual benchmark within `ε ≤ 5%` with probability ≥ 0.99, validated over 30 days of CI data.

### B.13 Coz causal profiling for speedup-oracle bench targeting

- **Why**: traditional CPU sampling tells us where time is spent; **Coz** (Curtsinger-Berger 2015 "Coz: finding code that counts with causal profiling", SOSP 2015 — Best Paper) tells us where **speedups would actually move end-to-end latency**. Critical for prioritizing optimization work that converts to operator-visible wins.
- **Plan**: integrate `coz` (Rust bindings via `coz-rs` crate) into the bench harness with progress points at every wire-format encode/decode and every mesh round trip. Run weekly Coz sweeps; output is a "speedup oracle" table ranking call-sites by predicted end-to-end latency improvement per 1% local speedup.
- **Surface**: `crates/fcp-bench/src/coz_harness.rs` + `docs/perf/coz_speedup_oracle.md` (auto-generated weekly).
- **Acceptance**: at least 3 optimizations per quarter are selected from Coz top-10 ranking and shipped with measured wall-clock improvement vs. the Coz prediction (cross-validate predicted vs. actual within ±30%).

### B.14 Hermit (deterministic runtime) for reproducible benchmarks + fuzzing

- **Why**: bench results are noisy due to scheduling, ASLR, hyperthreading, and time-of-day; fuzz crash reproduction is fragile for the same reasons. Meta's **Hermit** (Detlefs-Knies-Vahldiek-Oberwagner et al. 2022 "Hermit: Low-Latency, High-Throughput, and Transparent Remote Memory via Feedback-Directed Asynchrony", OSDI 2022 — distinct from the Hermit deterministic-execution runtime; reference both: Bergan et al. 2010 "CoreDet" and Meta's open-sourced Hermit at github.com/facebookexperimental/hermit for the deterministic-execution use) provides fully-deterministic process execution by intercepting time, randomness, and scheduling.
- **Plan**: run all benchmark suites and all fuzz harnesses under Hermit for **bit-exact reproducibility**. Failing fuzz inputs become byte-exact reproducers; bench measurements lose their scheduling noise (jitter floor drops from ~500µs to ~10µs).
- **Surface**: `scripts/perf/hermit_bench.sh`, `scripts/fuzz/hermit_fuzz.sh`. Linux-only initially; Mac fallback uses the Rust `std::time::Instant` mock + `rand_chacha` seeded RNGs.
- **Acceptance**: under Hermit, every bench in the coreset (B.12) produces byte-identical timing histograms across 10 runs on the same machine; every fuzz crash reproduces deterministically from the saved seed + input.

### Sub-bead inventory (round 2)

- `flywheel_connectors-angoc.1.1` [B.2] StatPack helper crate with proptest property tests
- `flywheel_connectors-angoc.1.2` [B.9] perf_regression_gate.sh CI gate with synthetic baseline test
- `flywheel_connectors-angoc.1.3` [B.11] per-connector `[performance_budget]` manifest field + conformance

---

## Phase C — Zone Isolation Graduation (LIMITED → PROVEN)

### C.1 Force `allowed_zones` non-empty

- Remove the empty-set permissive backcompat branch in `crates/fcp-host/src/bin/fcp-host.rs` `allowed_zones()` and `verify_live_request()`.
- Replace with explicit refusal: `HostError::ZoneEnvelopeRequired` if `allowed_zones` not configured.
- Migration: add a one-time bootstrap flow that writes the default zone set if missing (gated on confirmation).

### C.2 Information Flow Control (IFC) formalism

- Adopt a Denning-style label lattice with elements drawn from `ZoneId` ordered by `z:public ⊑ z:community ⊑ z:work ⊑ z:project:* ⊑ z:private ⊑ z:owner`.
- Each runtime value carries a `Label` = (confidentiality, integrity); operations are typed by `flows_to(l1, l2) ⟹ l1 ⊑ l2`.
- **Declassification rules**: only through an explicit `ApprovalToken` typestate; the declassification produces a `DeclassificationEvent` audit entry with the approver's signature and the source/target labels.
- **Taint tracking**: every `Provenance` instance carries `Taint = HashSet<ZoneId>` of zones that contributed data; taint joins on combination. Read at egress: a value can only leave to zone `z` if `taint ⊑ z` per the lattice.
- Spec: `docs/security/ifc-formalism.md` with the full lattice definition, typing rules, and soundness statement.
- Tests:
  - `crates/fcp-core/tests/ifc_lattice_properties.rs` — proptest verifies lattice laws (reflexivity, antisymmetry, transitivity, JOIN/MEET correctness) over 100,000 random label pairs.
  - `crates/fcp-core/tests/declassification_requires_approval.rs` — every code path that declassifies must consume an `ApprovalToken<DeclassificationApproved>` typestate.

### C.3 Connect to Lean formal proofs

- The `lean/` corpus contains an in-flight proof of zone-flow soundness under `kyopb.1.3.1.1.6.2.1`. Land the proof: `lean/FCP/Zone/Lattice.lean` proves `theorem zone_flow_soundness : ∀ (op : Operation), zone_check(op) = Pass → ¬ ∃ (leak : Leak), reachable(op, leak)`.
- Gate the README "Zone Isolation PROVEN" status flip on `make lean-verify` succeeding (cross-references Phase O).

### C.4 Cross-zone capability delegation with ApprovalToken typestate

- `ApprovalToken<Pending>` → `ApprovalToken<Approved>` → consumed at delegation site.
- Compile-fail trybuild test: `crates/fcp-core/tests/approval_token_typestate_compile_fail.rs` ensures `Pending` cannot be passed to a delegation API requiring `Approved`.

### C.4.bis ZK-SNARK predicate constraints on capabilities (PLONK / HALO2)

- **Why**: today, capability constraints like "can this token spend ≤ X in zone Y" or "is this user in the org admin set" are evaluated at use-time with the inputs in plaintext. For privacy-preserving capabilities (e.g., a Stripe connector token whose spending limit shouldn't leak the org's revenue), we want the predicate to verify without revealing the inputs.
- **Schemes**:
  - **PLONK** (Gabizon-Williamson-Ciobotaru 2019 "PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge", ePrint 2019/953) for universal-setup SNARKs with constant proof size and `O(n log n)` proving.
  - **Halo2** (Bowe-Grigg-Hopwood 2019, "Recursive Proof Composition without a Trusted Setup", ePrint 2019/1021) for setup-free recursion when a zone forbids trusted setups.
- **Plan**: capability predicates compile to arithmetic circuits via `crates/fcp-cap-zk/src/circuit/`; the prover generates a SNARK proof at delegation time; the verifier checks the proof at invocation time without seeing the witness. The capability token carries `predicate_proof: PlonkProof` alongside the existing `predicate_program`.
- **Concrete use cases**:
  - Stripe connector: "can spend ≤ $X in zone z:billing" → prove range `0 ≤ amount ≤ X` without revealing `amount`.
  - Slack connector: "is the requesting user in admins" → prove set membership in `admins[]` without revealing the user ID.
  - GitHub connector: "this repo is private and the requestor has push access" → prove conjunction without revealing repo name.
- **Surface**: `crates/fcp-cap-zk/src/{circuit.rs, prover.rs, verifier.rs}`. Predicate compiler in `crates/fcp-cap-zk/src/compile.rs` lifts a subset of the existing predicate DSL to Halo2 circuit gates.
- **Acceptance**: `crates/fcp-cap-zk/tests/predicate_zk_soundness_property.rs` (soundness: no false proof passes), `crates/fcp-cap-zk/tests/predicate_zk_zero_knowledge_property.rs` (zk: simulator-indistinguishability), `crates/fcp-e2e/tests/cap_zk_stripe_spending_limit_e2e.rs` (end-to-end Stripe spending-limit case).
- **Performance**: verifier cost target ≤ 5ms p99 (constant time for PLONK); prover cost target ≤ 500ms at delegation time (acceptable since delegation is rare).
- **Fallback**: if the circuit compile fails or proof generation times out, fall back to plaintext predicate evaluation with the existing typestate.

### C.4.tris Anonymous credentials (Camenisch-Lysyanskaya / BBS+) for cross-zone delegation

- **Why**: when an agent in `z:work` delegates a capability to `z:project:alpha`, the receiving zone today learns the identity of the delegating agent. For unlinkability across zones (and to prevent cross-zone traffic-analysis), the receiving zone should learn only "some authorized agent delegated this", not which one.
- **Schemes**: Camenisch-Lysyanskaya signatures (Camenisch-Lysyanskaya 2002 "A Signature Scheme with Efficient Protocols", SCN 2002) and **BBS+ blind signatures** (Au-Susilo-Mu 2006 "Constant-Size Dynamic k-TAA", SCN 2006; BBS+ standardized in IETF draft-irtf-cfrg-bbs-signatures). BBS+ supports selective disclosure of attributes + unlinkable show.
- **Plan**: introduce `crates/fcp-cap-anon/src/bbs.rs::BbsCredential` parallel to the existing `CapabilityToken`. At delegation time, the delegator obtains a BBS+ credential signed by the zone authority; at use time, the agent presents a **proof of possession** with selective disclosure (e.g., "I have a credential with `role = admin` and `zone = z:work`") that cannot be linked across shows.
- **Surface**: integrates with `RevocationRegistry` via **dynamic accumulators** (Camenisch-Kohlweiss-Soriente 2008) so credentials can be revoked without breaking unlinkability.
- **Acceptance**: `crates/fcp-cap-anon/tests/bbs_unlinkability_property.rs` proptest: two shows of the same credential are computationally indistinguishable from two shows of different credentials with the same disclosed attributes. `crates/fcp-cap-anon/tests/bbs_revocation_round_trip.rs` exercises revocation.
- **Fallback**: zones with `delegation_privacy = "off"` use the existing identified-delegator path.

### C.5 Zone-binding fuzzer with proptest shrinking

- `crates/fcp-conformance/tests/zone_binding_mutation_fuzz.rs`: proptest with `proptest::strategy::Strategy::prop_map` to randomly mutate the `Zone` field of an in-flight `InvokeRequest` between zone-check and dispatch; assert every mutation is rejected with a structured error and an audit event is emitted.
- Shrinking ensures the smallest reproducer is logged on failure.

### C.6 Property-based test: ∀ request, ∀ mutation, ∃ proof

- `crates/fcp-conformance/tests/zone_mutation_preservation_or_rejection_property.rs`: for any request `r` and any mutation `m`, the runtime must either (a) preserve the request semantics with an unchanged effective zone, or (b) reject the request with `ZoneError::MutationDetected`. Never silently accept a mutated zone.
- The proof artifact emitted by the proptest is a `ZoneMutationPropertyProof` JSON blob stored under `artifacts/proofs/zone_mutation/<date>-<sha>.json`.

### C.7 Cross-zone leak E2E

- `crates/fcp-e2e/tests/zone_isolation_full_e2e.rs` — drive 5-zone workload, assert no `z:public → z:private` capability invocation succeeds, no `z:work → z:owner` data flow without `ApprovalToken`.

### C.8 README status update

- Move Zone Isolation row from LIMITED to PROVEN with `crates/fcp-e2e/tests/zone_isolation_full_e2e.rs` + `lean/FCP/Zone/Lattice.lean` as evidence pointers.

### Sub-bead inventory (round 2)

- `flywheel_connectors-angoc.2.1` [C.1] Remove permissive empty-allowed_zones branch in fcp-host
- `flywheel_connectors-angoc.2.2` [C.7] 5-zone cross-zone leak E2E test
- `flywheel_connectors-angoc.2.3` [C.4] ApprovalToken<Pending|Approved> typestate + trybuild compile-fail tests

---

## Phase D — Tooling Friction (multi-agent coordination)

### D.1 Agent-mail SQLite corruption (`flywheel_connectors-d5yeb`)

- **Root-cause analysis**: identify whether corruption is WAL-related, concurrent-writer, or schema-migration; record root-cause class in `docs/ops/agent-mail-corruption-rca.md`.
- **Per-page checksum verification**: before opening, the new `am doctor verify --read-only` reads every SQLite page header, verifies the per-page checksum (PRAGMA `cell_size_check = ON` + `integrity_check`), and reports the first corrupted page if any. **No writes are issued** (AGENTS.md `am service` protection).
- **Transparent fallback**: if SQLite corrupt, agents proceed without agent-mail and emit a one-line warning (do NOT auto-repair).
- Tests: `crates/agent-mail-tools/tests/sqlite_corruption_chaos.rs` corrupts a page mid-session; agents must still close their beads.

### D.2 Local disk pressure (`flywheel_connectors-rfbrc`)

- Pre-write space check via **`statvfs` (POSIX)** / `GetDiskFreeSpaceExW` (Windows) for an **atomic snapshot** of free space + inode count. `df` is not used because it can race with cleanup processes and returns stale data.
- Helper: `crates/fcp-host/src/disk_pressure.rs::DiskPressureGuard::check_atomic(min_bytes, min_inodes)`.
- Pre-write space check on `br sync --flush-only`: if free space < 1GB or free inodes < 10,000, fail loudly with a remediation message including the `CARGO_TARGET_DIR=/Volumes/USB_NVME/...` quarantine pattern.
- Pre-write space check on git pack writes via a pre-commit hook (`.git/hooks/pre-commit` augmented to call `fwc doctor disk`).

### D.3 rch worker drift daemon

- Existing AGENTS.md documents three rch failure classes; surface them in `rch doctor` as named failure codes (RCH-E326, RCH-WORKER-DRIFT, RCH-RETRIEVAL-FAIL).
- **New daemon** `rch worker-capability-prober` runs every 5 minutes:
  - Probes each worker via `cargo +nightly check --lib --manifest-path .rch/probes/fcp-core/Cargo.toml`
  - Records expected outputs hash + nightly version + git HEAD into `~/.rch/worker_capabilities/<worker_id>.json`
  - On drift (hash mismatch, version mismatch, HEAD divergence), **auto-evicts** the worker from the pool and emits an OTLP alert
- Operator surface: `rch workers status --json` shows last probe time + drift status per worker.

### D.4 Mazurkiewicz-trace coordination for agent claims

- When two agents both claim the same bead concurrently, the current beads workflow silently accepts the later writer. Replace this with a **Mazurkiewicz-trace** model: independent claim operations on disjoint beads commute and are accepted; conflicting claims on the same bead require a deterministic tiebreaker.
- Tiebreaker: lowest `agent_name` lex order wins the claim; the loser sees an explicit `ClaimContested(other_agent)` error and is invited to pick a different bead.
- Implementation: `crates/br-tools/src/claim_trace.rs::MazurkiewiczClaimResolver`; integrated into `br update <id> --status=in_progress` via an advisory check before the JSONL flush.
- Tests: `crates/br-tools/tests/concurrent_claim_resolution.rs` simulates 10 agents claiming the same bead; assert exactly one wins, all others get `ClaimContested`.

---

## Phase E — Windows Sandbox Parity (`flywheel_connectors-r4qcg.*`)

### E.1 AppContainer + Job Object + LowBox token + Integrity Level composition (r4qcg.1)

- Use **all four mechanisms in concert**:
  - **Job Objects** to enforce memory/CPU/wall-clock budgets and limit child-process creation.
  - **LowBox token** (via `NtCreateLowBoxToken`) to apply the AppContainer SID and capability set at process creation.
  - **AppContainer profile** for filesystem and capability isolation (auto-namespaced %LOCALAPPDATA% + capability-gated APIs).
  - **Integrity Level** = `SECURITY_MANDATORY_LOW_RID` for all connector processes; system-integrity processes cannot be opened/written by Low-integrity processes.
- Spec: `docs/security/windows_sandbox_composition.md`.
- Tests: `crates/fcp-sandbox/tests/windows_sandbox_lifecycle.rs` (gated `#[cfg(windows)]`) creates the four layers, runs a connector that attempts to escape (e.g. open a System32 file, spawn a process, raise integrity), and asserts all escape attempts fail.

### E.2 Machine-checked capability mapping table (r4qcg.2)

- Document the FCP-cap → Windows-cap mapping in `docs/security/windows_sandbox_capabilities.md` as a TOML table consumed by the conformance test.
- **Conformance test** `crates/fcp-conformance/tests/windows_capability_mapping_exhaustive.rs`: every FCP capability must have **exactly one** entry of:
  - `WIN_CAP_ALLOWED("internetClient")` (or other named Win capability)
  - `WIN_CAP_DENIED` (capability cannot exist under AppContainer)
  - `WIN_CAP_UNSUPPORTED` (Windows port doesn't expose this capability yet)
- Missing or duplicate entries fail CI. There is **no default fall-through**.

### E.3 Windows roadmap closeout (r4qcg.3)

- Status update in README from "Windows sandbox roadmap-only" to "Windows sandbox PROVEN" with E2E evidence pointer `docs/perf/windows_sandbox_evidence.md` (Windows CI runner output).

### E.4 WebAssembly Component Model + WASI Preview 3 migration

- **Why**: the current WASI sandbox is on Preview 1/2 (snapshot-1 / snapshot-2) which exchanges opaque byte buffers across the wasm boundary. The **Component Model** + WASI Preview 3 give us **strong types at the boundary** (resources, records, variants, lists with element types), so cross-connector composition is type-checked at link time rather than runtime-marshalled.
- **Plan**: define every connector ABI as a WIT (Wasm Interface Type) world; connectors compile to `*.component.wasm` artifacts; the host links components via `wasmtime::component::Linker`. Preview 3 adds async I/O at the component layer so streaming connectors don't need ad-hoc `Stream<Item = Bytes>` adapters.
- **Surface**: `crates/fcp-sandbox-wasm/src/component_linker.rs::ComponentLinker`; `wit/` directory with one `*.wit` per connector archetype (`request-response.wit`, `streaming.wit`, `webhook.wit`, `pubsub.wit`).
- **Migration order**: smallest connectors first (echo, time, ping) to debug the toolchain; then incubating connectors (Phase G) graduate **directly to components**; then re-port the high-impact connectors (github, stripe, gmail) last.
- **Acceptance**: `crates/fcp-conformance/tests/wasm_component_link_compatibility.rs` proves every shipped `*.component.wasm` links against every other component without runtime type errors; `crates/fcp-e2e/tests/component_streaming_pipe_e2e.rs` exercises a streaming connector through Preview 3 async APIs.
- **Fallback**: legacy Preview 1 connectors remain runnable via a `LegacyP1Adapter` so this is non-breaking.

---

## Phase F — AWS Bedrock Parity (`flywheel_connectors-4kw5f.2.9.2.13.*`)

### F.1 SigV4 implementation with derivation cache + clock-skew tolerance

- Implement SigV4 signer in `connectors/aws-bedrock/src/sigv4.rs`.
- **Signing key derivation cache**: SigV4 derives a `signing_key` per `(secret, date, region, service)`; cache these keys for 24h (the AWS-recommended max) keyed by `blake3(secret || date || region || service)` so successive requests within the same date avoid four rounds of HMAC. Cache eviction: LRU 1024 entries.
- **Per-region clock skew tolerance**: AWS allows ±15min skew on `X-Amz-Date`. Track per-region observed skew via a rolling EWMA from `Date` response headers; if observed skew exceeds 5min, log a warning and resync via NTP if available. Connector continues to function as long as skew < 15min.
- Tests: `connectors/aws-bedrock/tests/sigv4_canonical_vectors.rs` round-trips against the AWS canonical SigV4 test vectors (15 vectors from AWS docs).

### F.2 Provider-router shim reusing OAI-compat normalization layer

- Anthropic/Claude on Bedrock has a different request/response shape than direct Anthropic API; OpenAI-compat normalization layer in `crates/fcp-llm-shim/src/oai_compat.rs` already handles a similar problem for multiple LLM providers.
- Add `BedrockShim` in `connectors/aws-bedrock/src/router.rs` that delegates to `OaiCompat::normalize` for the body shape and adds Bedrock-specific authentication + model-arn translation.
- Conformance test against a stored Bedrock response fixture: `connectors/aws-bedrock/tests/bedrock_provider_router_conformance.rs`.

### F.3 Stream parsing: event-stream + OAI-compat SSE

- Bedrock's native streaming format is **AWS Event-Stream binary** (a length-prefixed binary protocol). The OAI-compat layer expects **SSE** (`text/event-stream`).
- The shim implements both: `EventStreamParser` in `connectors/aws-bedrock/src/event_stream.rs` (binary, length-prefixed, CRC32-checksum-validated) and a translator to OAI-compat SSE so downstream consumers see a uniform stream.
- Tests: `connectors/aws-bedrock/tests/event_stream_round_trip.rs` (binary parse), `connectors/aws-bedrock/tests/streaming_oai_compat_translation.rs`.

### F.4 Live E2E with operator gating

- `connectors/aws-bedrock/tests/live_verification.rs` gated by `FCP_LIVE_SERVICE=1` + `AWS_PROFILE`.
- UBS triage clean on the connector.

### F.5 Reed-Muller binary attestation (defense in depth on top of TUF/sigstore)

- **Why**: the current connector-binary supply chain relies on signatures (sigstore/cosign + TUF). If a signing key is compromised, an adversary can mint a valid-looking malicious binary. Adding a **code-theoretic** binding makes distribution require solving a hard code-decoding problem in addition to the signature.
- **Scheme**: Reed-Muller codes RM(r, m) (Reed 1954; Muller 1954) — bind the SHA-512 of each binary to a RM(2, 11) codeword over GF(2) of length 2048; publish the codeword + signed-position-set; verifier reconstructs the binary hash from the codeword positions and compares.
- **Defense argument**: an attacker with the signing key still has to construct a malicious binary whose hash decodes to the same RM codeword positions; the minimum-distance bound of RM(2, 11) is `d = 2^{m-r} = 512` bit flips, making collision search infeasible without breaking SHA-512 too.
- **Surface**: `crates/fcp-supply-chain/src/reed_muller.rs::ReedMullerAttest`; integrates into the existing `sigstore_envelope` builder so every release ships `(signature, rm_codeword)`.
- **Acceptance**: `crates/fcp-supply-chain/tests/reed_muller_collision_resistance.rs` empirical proof that random binary hashes do not collide on the RM codeword positions across 10^9 trials; `crates/fcp-conformance/tests/binary_attest_dual_layer.rs` proves every released artifact has both signature and RM codeword and both verify.
- **Fallback**: signature-only verification path remains supported; RM layer is **defense in depth**, not a replacement.

---

## Phase G — 49 Incubating Connectors: Graduation

### G.1 Scope inventory

- For each of the 49 connectors flagged `incubating/quarantined/placeholder/stub` in its README:
  - Document the current scope limit (read-only? partial webhooks? no streaming?).
  - Define the graduation criteria.
  - File one bead per connector under a new epic `flywheel_connectors-incubation-graduation`.

### G.2 Prioritized graduation batches

- **Batch 1 (high-impact)**: postgresql, stripe, github, gmail, telegram, slack, kubernetes.
- **Batch 2 (Google family)**: google-calendar, google-drive, google-docs, google-sheets, google-people, google-chat, google-meet, google-admin-reports, google-workspace-events.
- **Batch 3 (AI/ML)**: huggingface, deepseek, llm-router, google-ai.
- **Batch 4 (everything else)**: aws, azure, browser, cron, docusign, figma, firebase, linear, make, mastodon, mattermost, metabase, mongodb, mysql, netlify, nextcloud-talk, pandadoc, plaid, redis, s3, snowflake, sonos, sqlite, supabase, terraform, tlon, vectordb, youtube, zalo, zalouser, zapier, zendesk.

### G.3 Graduation gauntlet (12-point checklist, all must be green)

Each connector graduates only after meeting **every** point:

1. `operations_info()` returns typed `OperationInfo` for every operation (not a placeholder).
2. `network_constraints` declared in `manifest.toml` for every operation that touches the network (deny localhost, deny private CIDR, max_redirects, bounded timeout).
3. `ai_hints` populated with realistic examples and safety notes.
4. `idempotency_class` declared per operation (`Pure`, `Idempotent`, `AtMostOnce`, `Risky`, `Dangerous`).
5. `safety_tier` declared per operation (`Safe`, `Warn`, `RequiresApproval`).
6. `integration.rs` present and passing (mocked external service).
7. `local_non_mock.rs` OR `live_verification.rs` present and passing.
8. README status is not "placeholder" / "TBD" / "stub".
9. Secretless via `SecretFetchHook` — no plain-text credentials in test fixtures.
10. `crates/fcp-conformance/tests/manifest_operation_field_coverage_conformance.rs` passes for this connector.
11. `operations_info()` output matches `manifest.toml` declared operations exactly (no drift).
12. **Latency budget asserted**: connector-level performance budget enforced by `crates/fcp-conformance/tests/per_connector_budget_assertion.rs` (Phase B.11).

### G.4 Three-pass review for each graduation

Every graduation goes through:

- **`/security-audit beta`** (CrimsonWolf-style reviewer pass): looks for unbounded allocations, TOCTOU, signature/auth bypasses, secret-leak paths, panic on attacker-controlled input.
- **`/profiling-software-performance`**: identifies p99 hot paths and asserts they meet the connector budget.
- **`/testing-fuzzing`**: emits proptest harness for the operation surface + adversarial connector response fuzzer (see Phase P).

### G.5 Per-graduated-connector evidence

- Each graduated connector ships `local_non_mock.rs` (deterministic loopback) AND `live_verification.rs` (gated by env).
- Each manifest gets explicit `network_constraints` for all webhook/callback operations.
- A graduation memo `docs/connectors/graduations/<connector>-graduation-2026-XX.md` records the audit/profiling/fuzzing pass outputs and the 12-point checklist green.

---

## Phase H — Coverage Discipline (Unify Live/Loopback Test Patterns)

### H.1 Coverage scanner baseline

- Run `scripts/ci/test_coverage_scan.sh` to produce a baseline coverage matrix.
- For each connector, expected: `integration.rs` + (`local_non_mock.rs` OR `live_verification.rs`) — pick the right pattern per archetype (request-response → loopback; streaming → live).

### H.2 Drive 100% loopback or live coverage

- 153 connectors have `integration.rs` (87%); fill the remaining 13%.
- 40 have `live_verification.rs` (23%); raise to 100% of connectors that touch an external provider.
- 7 have `local_non_mock.rs` (4%); raise to 100% of infrastructure-style connectors.

### H.3 Differential testing: loopback vs live byte-equivalence

- For every connector that has both `local_non_mock.rs` and `live_verification.rs`, add a differential harness `connectors/<name>/tests/diff_loopback_vs_live.rs` that runs the same operation against both and asserts byte-equivalence **modulo known-mutable fields** (timestamps with tolerance, server-assigned IDs, signatures).
- Field-mutability registry: `crates/fcp-testkit/src/diff_registry.rs::MutableFields` declares per-operation the fields that can vary between runs; everything else must match byte-for-byte.
- Failures emit a structured `DifferentialDiff` artifact with full field-by-field comparison.

### H.4 Mutation testing on connector responses

- For every connector, add `connectors/<name>/tests/response_mutation_robustness.rs`: introduces single-byte mutations in the wire response (HTTP body, header, JSON field) and asserts the connector either rejects with structured `ConnectorError::ResponseMutated` or **surfaces a structured error**. **Silent acceptance is a bug.**
- Mutation strategy: byte-flip every position once (linear), plus 1000 random multi-byte mutations (random).
- Reuse: `crates/fcp-testkit/src/mutation.rs::ResponseMutator::flip_each_byte / random_multi`.

### H.5 Conformance gate

- Conformance test `crates/fcp-conformance/tests/coverage_discipline_gate.rs` fails if a connector lacks both `local_non_mock.rs` and `live_verification.rs`, or if the differential test (H.3) or mutation test (H.4) is missing.

---

## Phase I — Compatibility Shim Removal (FCP3 Scorecard pending items)

### I.1 Identify the 2 unmigrated compatibility shims

- From `docs/FCP3_Transition_Scorecard.md`: 0/2 compatibility shims migrated.
- **Concrete identification protocol**: run `ast-grep run -l Rust -p '#[deprecated($$$)] $$$ITEM'` across `crates/fcp-core/src/` to enumerate every shim; cross-reference with `docs/FCP3_Crate_Graph_Audit.md`. The 2 likely candidates are the legacy `fcp_core::compat::policy` and `fcp_core::compat::evidence` re-export modules (verify by running the ast-grep query and pinning the exact paths in the bead body).
- For each shim:
  - Find all callers via `ast-grep run -l Rust -p 'fcp_core::compat::$MOD::$$$ITEM'`.
  - Migrate each caller to the canonical path in `fcp-kernel` / `fcp-policy` / `fcp-evidence`.
  - Delete the shim.
  - Run full `cargo check --workspace --all-targets` via `rch exec`.
- Each shim becomes a bead with deletion plan + tests that prove no caller depends on the old path.

### I.2 Forbidden-overlap holdouts (3 pending)

- Scorecard shows 4/7 resolved; identify the 3 pending by running `cargo metadata --format-version 1 | jq` to compute the forbidden-overlap crate-pair set and diffing against `docs/FCP3_Crate_Graph_Audit.md`.
- Likely candidates (verify with the metadata diff): `fcp-host` ↔ `fcp-mesh` (some types still live in host that should live in mesh); `fcp-store` ↔ `fcp-raptorq` (symbol-store types overlap); `fcp-protocol` ↔ `fcp-crypto` (envelope types).
- One bead per holdout with a **precise ownership boundary**: "Type X moves to crate Y; crate Z imports it via the canonical re-export path A::B::X". The boundary statement is the bead acceptance criterion.

### I.3 Tests

- `crates/fcp-core/tests/compat_shim_absence.rs` — ast-grep-driven test fails if `fcp_core::compat::policy` or `fcp_core::compat::evidence` symbols exist post-removal.
- Per-shim `trybuild` compile-fail test under `crates/fcp-core/tests/compat_compile_fail/` proving the old import path no longer compiles.
- `crates/fcp-conformance/tests/forbidden_overlap_resolution.rs` parses `cargo metadata`, computes the forbidden-overlap pair set, asserts 0 pending pairs against `docs/FCP3_Crate_Graph_Audit.md`.
- `crates/fcp-conformance/tests/fcp3_scorecard_completeness.rs` every Scorecard row is `DONE` or has an explicit operator-facing remediation pointer.
- `crates/fcp-conformance/tests/crate_graph_no_forbidden_overlap.rs` cargo-metadata-driven; fails CI if any forbidden-overlap pair is re-introduced.
- `crates/fcp-e2e/tests/fcp3_cleanup_workspace_health_e2e.rs` after removals: `cargo check` + `cargo clippy -D warnings` + `cargo test --workspace --no-run` on a clean checkout; zero warnings.

### I.4 Logging contract

- INFO: per-shim removal completion `{shim_path, callers_migrated_count, sha}`; per-overlap resolution `{type_name, from_crate, to_crate, canonical_path}`.
- DEBUG: ast-grep query patterns + match counts per caller-migration pass.
- TRACE: per-call-site rewrite `{file, line, before_path, after_path}`.

### I.5 Rollback / fallback

- Shim removal breaks an external/test caller → single revert commit; shim reinstated with a deadline label + tracking bead.
- Forbidden-overlap migration introduces a cycle (`cargo metadata` detection blocks): rollback restores prior crate ownership; alternate canonical path renegotiated in a follow-up PR.
- Type move breaks serde compatibility (CBOR/JSON wire format): conformance + golden-vector tests catch; migration paused, deserialize compat shim added with an explicit deadline label.

### I.6 Operator-visible doctor checks

- `fwc doctor fcp3-scorecard` reads `docs/FCP3_Transition_Scorecard.md`, asserts every row is PASS not SKIP; reports pending rows.
- `fwc doctor crate-graph` cargo-metadata-driven detection of forbidden-overlap pairs; reports each pair with its canonical-ownership remediation step.

### I.7 Observability hooks

- Build-time only — no runtime spans (this is a compile-time + crate-graph cleanup).
- `cargo check` emits zero deprecated-import warnings post-cleanup; CI gate enforces this.

### Sub-bead inventory (round 2)

- `flywheel_connectors-angoc.3.1` [I.1] Enumerate + migrate callers of fcp_core::compat::policy + compat::evidence shims
- `flywheel_connectors-angoc.3.2` [I.2] Compute forbidden-overlap holdouts + file one bead per holdout

---

## Phase J — Computation Migration Hardening

### J.1 Automatic optimal-device execution: cost model + Thompson sampling

- README acknowledges "automatic optimal-device execution is still hardening".
- **Cost model**: `device_cost(d, op) = α · load(d) + β · cost_weight(d) · (1 - load(d)) + γ · latency_weight(d) · (1 - load(d)) + δ · (1 - stability_score(d))` where:
  - `load(d) ∈ [0, 1]` is the device's normalized utilization
  - `cost_weight(d)` is the configured $/CPU-hour (or battery cost for mobile)
  - `latency_weight(d)` is the expected RTT to the originator
  - `stability_score(d)` is the EWMA of recent successful completions / total dispatches
  - `α, β, γ, δ` are tunable per-zone; defaults `(0.4, 0.2, 0.3, 0.1)`.
- **Multi-armed bandit (Thompson sampling)**: in addition to the cost model, maintain per-(device, operation_class) Beta(α, β) reward distributions. On each dispatch, sample from the posterior and pick the device with the highest sample. Update α (success) / β (failure) on completion. This learns device preferences over time and gracefully adapts to drift (e.g. a device gets slower after a kernel update).
- Implementation: `crates/fcp-mesh/src/planner/bandit.rs::ThompsonScheduler`.
- Tests: 5-device cluster, 1000-task workload, assert near-optimal device selection ≥ 95% of the time vs. an oracle that knows true costs (`crates/fcp-e2e/tests/thompson_scheduler_e2e.rs`). Comparison metric: regret = oracle_total_cost − scheduler_total_cost; target regret < 5% of oracle.

- **Smoothed-analysis regret bound for adversarial inputs**:
  - **Why**: Thompson sampling has `O(√(KT log T))` worst-case regret only in the standard stochastic setting. In adversarial-but-bounded-noise settings (which is what we actually have — operators occasionally trigger weird load patterns), we want **smoothed analysis** (Spielman-Teng 2004 "Smoothed Analysis of Algorithms: Why the Simplex Algorithm Usually Takes Polynomial Time", JACM 2004) regret bounds.
  - **Plan**: model the cost-model formula as a smoothed input (true cost + zero-mean Gaussian noise with variance σ²); apply Beggs-style smoothed regret analysis to derive a regret bound `R(T) ≤ c · √(KT log T) · poly(1/σ)` that holds with high probability under any input + bounded noise.
  - **Acceptance**: `crates/fcp-mesh/tests/smoothed_regret_bound_property.rs` proves empirically that scheduler regret stays under the smoothed bound across 10^4 random workloads + adversarial-but-bounded perturbations.
  - **Documentation**: full regret-bound derivation in `docs/architecture/adr/J1-thompson-smoothed-regret.md` with citation to Spielman-Teng 2004 and Bubeck-Cesa-Bianchi 2012 "Regret Analysis of Stochastic and Nonstochastic Multi-Armed Bandit Problems".

### J.2 CRIU pre-copy + post-copy + dirty-page tracking

- Reference proof uses planned handoff; add tests for unplanned (failure-driven) handoff.
- **Pre-copy with dirty-page tracking**:
  - Iteration `i` transfers all pages modified since iteration `i-1`; budget = `2 × bandwidth_estimate_bytes_per_round`.
  - **Dirty-rate threshold**: if dirty-rate exceeds 80% of bandwidth (i.e. the working set is being rewritten faster than we can transfer), fall back to **stop-and-checkpoint** mode (freeze, snapshot, transfer).
  - Maximum 5 pre-copy rounds before forced stop-and-checkpoint.
- **Post-copy**: on resume, fault-in pages on demand via RDMA-like page-fault forwarding; bound by 100ms page-fault timeout before terminating the resumed process.
- Tests:
  - Planned handoff: `crates/fcp-e2e/tests/criu_planned_handoff.rs`.
  - Unplanned (kill-9 the source mid-execution): `crates/fcp-e2e/tests/criu_unplanned_handoff.rs`; assert another device picks up via the last `OperationIntent` checkpoint.
  - Dirty-page chaos: `crates/fcp-e2e/tests/criu_dirty_page_pressure.rs` simulates a 1GB working set with 100MB/s dirty rate, asserts the scheduler correctly falls back to checkpoint after 5 rounds.

### Sub-bead inventory (round 2)

- `flywheel_connectors-angoc.4.1` [J.2] Unplanned-handoff E2E (kill -9 source mid-execution, 3 checkpoint windows)
- `flywheel_connectors-angoc.4.2` [J.1.bis] Thompson sampling scheduler + cost-model monotonicity proptest

---

## Phase K — Documentation & Quarterly Discipline

### K.1 Next quarterly debiasing (2026-Q3)

- Run the full README claims-vs-reality reconciliation on the first business day of 2026-Q3 (target: 2026-07-01).
- Publish to `docs/quarterly/2026-Q3-claims-vs-reality.md`.
- Update README audit status note.
- **File paths to verify**: every status-table row in README.md must be re-checked against the evidence pointer files listed in this bridge plan (B, C, E, F, J, N, O).

### K.2 Reality-check cadence

- Run `/reality-check-for-project` monthly, not quarterly.
- Persist the output to `docs/reality/<date>-reality-check.md`.
- **Acceptance**: at month boundary, if no `<YYYY-MM>-reality-check.md` exists, CI emits a warning and an actionable bead is filed automatically (via `crates/br-tools/src/scheduled_reality_check.rs`).

### K.3 README freshness

- README is 136KB / 2000+ lines; some sections (e.g. Architecture deep-dive) may have drifted.
- Audit: read each numbered section, verify code reality, mark stale sections for revision.
- **Drift detector**: `scripts/ci/readme_drift_check.sh` ast-greps every `crates/.../*.rs` file referenced in the README, fails CI if the path no longer exists or the symbol it references is gone.

### K.4 Tests

- `crates/br-tools/tests/scheduled_reality_check_filing.rs` — simulate month boundary with missing `docs/reality/<month>-*.md`; assert exactly one bead filed with title `[reality-check] <YYYY-MM> reality-check pass overdue` at P2.
- `crates/br-tools/tests/scheduled_reality_check_idempotency.rs` — bead is not refiled while still open.
- `crates/fcp-conformance/tests/readme_drift_check_correctness.rs` — synthetic README with valid + invalid paths; drift script exits non-zero only on the invalid case.
- `crates/fcp-conformance/tests/readme_freshness_audit.rs` — every numbered README section has a recent reality-check pointer OR an explicit owner annotation.
- `crates/fcp-conformance/tests/quarterly_artifact_completeness.rs` — most recent `docs/quarterly/<YYYY>-Q<n>-claims-vs-reality.md` exists, parseable, covers every README status-table row.
- `crates/fcp-e2e/tests/reality_check_cadence_e2e.rs` — simulate 6 months of CI; assert one reality-check artifact per month + a quarterly artifact at Q boundary.

### K.5 Logging contract

- INFO: per-month reality-check completion `{date, sections_reviewed, drift_count}`; quarterly artifact publication `{quarter, rows_reconciled}`.
- DEBUG: per-section freshness verdict (FRESH / STALE_SECTION / BROKEN_REFERENCE) with rationale; ast-grep query results.
- TRACE: per-symbol drift check `{file, line, symbol_name, exists_at_head}`.

### K.6 Rollback / fallback

- Monthly reality-check missed: `scheduled_reality_check` files a bead automatically. If more than one month is missed, escalates priority and notifies the maintainer via agent-mail (degrades gracefully if unavailable).
- Drift detector false-positive on intentional narrative reference: maintainer adds the path to `docs/.readme-drift-ignore` allowlist with a justification; CI honors the allowlist and emits a one-line warning to keep it visible.
- Quarterly artifact missing at boundary: CI gate goes red; emergency manual debiasing pass authorized by maintainer with an audit-chain entry recording the override.

### K.7 Operator-visible doctor check

- `fwc doctor reality-cadence` verifies (a) `docs/reality/<YYYY-MM>-reality-check.md` exists for current month, (b) `docs/quarterly/<YYYY-Q?>-claims-vs-reality.md` exists for current quarter, (c) `scripts/ci/readme_drift_check.sh` exits 0 against HEAD, (d) `docs/.readme-drift-ignore` entries carry justifications. Output: `{healthy, missing_artifacts:[...], drift_count}`.

### K.8 Observability hooks

- Metric `fcp_reality_check_freshness_days` (age of latest `docs/reality/<month>-reality-check.md`).
- Metric `fcp_readme_drift_count` (number of dead README references).
- OTLP spans during cadence job runs (`fcp.cadence.monthly`, `fcp.cadence.quarterly`).

### Sub-bead inventory (round 2)

- `flywheel_connectors-angoc.5.1` [K.2] Monthly scheduled_reality_check bead auto-filer
- `flywheel_connectors-angoc.5.2` [K.3] README drift detector script + conformance test

---

## Phase L — Cross-cutting: Reduce Operator/Agent Friction

### L.1 fwc doctor everything

- `fwc doctor` checks: agent-mail health, disk pressure (statvfs), rch worker reachability + capability drift, beads DB integrity, recent commit signing, AGENT_NAME prefix, OTLP collector reachability, Lean toolchain (for Phase O), PQ key material presence (Phase N).
- Output is structured JSON with `commands` array of remediation actions (per `world-class-doctor-mode-for-cli-tools` skill: 24-axiom kernel, single `mutate()` chokepoint, capabilities reflection, robot-docs, fixtures, per-run scoring artifact).
- Acceptance criterion: `fwc doctor --json` returns `{"healthy": true, "score": ≥ 800}` (out of 1000) on the reference operator environment.

### L.2 Standard agent onboarding macro

- `fwc agent-bootstrap --name <Name>` runs the full agent-readiness handoff dry-run + registers identity + reserves a default file scope + lists ready beads + prints the AGENT_NAME-prefixed commit template + verifies OTLP + Lean + PQ + rch.
- Test: `crates/fwc/tests/agent_bootstrap_e2e.rs`.

### L.3 Cross-agent session search

- `cass` already exists; ensure it has fresh indexes of the recent swarm sessions documented in memory (2026-05-02, 2026-04-19, 2026-03-15 etc.).
- Add `cass autoindex --since 7d` invoked daily by a cron defined in `.github/workflows/cass-autoindex.yml`.

### Sub-bead inventory (round 2)

- `flywheel_connectors-angoc.6.1` [L.1] fwc doctor self-test against fixture environment
- `flywheel_connectors-angoc.6.2` [L.2] fwc agent-bootstrap idempotent onboarding command

---

## Phase M — Audit Surface Expansion

### M.1 Cross-zone audit explorer

- Add `fwc audit explain --zone z:work --since 24h` so operators can see audit chain entries scoped to a zone, including quorum height and signers.
- Add `fwc audit chain status --json` (already in A.0.2) with quorum freshness.
- Acceptance: `crates/fwc/tests/audit_explain_zone_scope.rs` golden vector.

### M.2 Capability replay

- `fwc capability replay <token>` reconstructs the full predicate evaluation trace from the audit chain.
- Useful for forensics + agent debugging.
- File path: `crates/fwc/src/commands/capability.rs::replay`. Test: `crates/fwc/tests/capability_replay_round_trip.rs`.

### M.3 Audit chain export to OTLP

- Every audit chain append emits a parallel OTLP span with the same fields, so an external observability stack can ingest the audit chain without parsing FCP-specific formats.
- Conformance: `crates/fcp-audit/tests/audit_otlp_parity.rs`.

### Sub-bead inventory (round 2)

- `flywheel_connectors-angoc.7.1` [M.1] fwc audit explain command with golden-vector E2E
- `flywheel_connectors-angoc.7.2` [M.5] Audit-chain OTLP parity export + e2e collector test

---

## Phase N — Post-Quantum Hardening Cutover (NEW)

**Target**: ML-DSA + X-Wing already shipped per session memory (commits 1zlht, kfr9j cleanup). Make hybrid PQ-signing the default for every signed object during a transitional period, measure the performance impact, and provide an explicit cutover path.

### N.1 Hybrid signing default

- Every signed object (capability token, audit event, manifest, gossip frame, revocation, operation receipt, zone checkpoint) gets a **dual signature**: classical (Ed25519) + PQ (ML-DSA-65).
- Wire format: `SignedEnvelope { payload, sig_classical: Ed25519Signature, sig_pq: MlDsa65Signature }` in `crates/fcp-crypto/src/hybrid.rs`.
- Verification policy:
  - **Transitional (current)**: at least one signature must verify; both is preferred. Failure of one signature emits a `PqSignatureMismatch` warning audit event.
  - **Steady state (after N-day soak)**: both signatures must verify; either failure rejects the envelope.
- The transitional vs. steady-state switch is gated by a zone-level `PqSigningPolicy` setting.

### N.2 Performance impact measurement

- ML-DSA-65 sign: ~0.5ms; verify: ~0.2ms (per published benchmarks).
- Hybrid impact on capability token verification (already < 1ms target): expect ~2× slowdown.
- Measure on csd + Contabo + laptop (Phase B.3 classes).
- Evidence: `docs/perf/pq_signing_overhead_evidence.md` with the full StatPack (B.2) for `verify_classical`, `verify_pq`, `verify_hybrid`, and the ratio.
- Acceptance: hybrid verify p99 ≤ 2ms (relaxed from 1ms classical-only target; documented in README).

### N.3 Key rotation policy

- ML-DSA keys rotate on the same epoch boundary as Ed25519 (per `KeyRotationSchedule`).
- Owner has both an Ed25519 root + an ML-DSA root, both attested in the bootstrap; loss of either is treated as full owner compromise.
- Tests: `crates/fcp-crypto/tests/hybrid_key_rotation_e2e.rs`.

### N.3.bis Verifiable Delay Functions (VDF) for rate-limited owner-key operations

- **Why**: even with the owner key material in possession (rare), an adversary could burst-mint a large set of capability tokens, exhausting downstream rate-limits and amplifying blast radius before revocation can propagate. We want owner-key operations to be **asymmetrically slow to mint, fast to verify**.
- **Scheme**: Wesolowski VDF (Wesolowski 2019 "Efficient Verifiable Delay Functions", EUROCRYPT 2019) over the RSA group with `T = 2^30` squarings (≈ 60s on commodity hardware). Verifier checks via a single Fiat-Shamir-derived proof in ~1ms.
- **Plan**: every owner-key signing operation prepends a VDF evaluation; the resulting `(vdf_proof, signature)` envelope is verified by every relying party. Adversary with the key material is bounded to ~1 owner-action per minute even on optimized hardware (no known parallelism advantage on Wesolowski's sequential squaring).
- **Surface**: `crates/fcp-crypto-pq/src/vdf/wesolowski.rs::WesolowskiVdf`; integrates with `OwnerKeySigner::sign_with_rate_limit`.
- **Acceptance**: `crates/fcp-crypto-pq/tests/vdf_asymmetric_cost.rs` measures eval cost ≥ 30s on the reference machine class (csd), verify cost ≤ 5ms; `crates/fcp-conformance/tests/owner_burst_attack_resistance.rs` simulates an attacker with stolen owner key + 1000-core compute, demonstrates the attacker is bounded to ≤ 100 owner-actions per hour.
- **Fallback**: zones with `owner_vdf_required = false` (e.g., low-stakes test zones) skip the VDF.

### N.4 Migration plan

- Phase N.4.a (week 0–2): roll out hybrid signing in shadow mode; old verifier accepts classical-only, new verifier accepts both.
- Phase N.4.b (week 2–6): require PQ signature on new objects; old objects still verified classical-only.
- Phase N.4.c (week 6+): both signatures required; classical-only objects rejected.
- Cutover gate doc: `docs/security/pq_cutover_plan.md`.

### N.5 Conformance

- `crates/fcp-conformance/tests/hybrid_signing_coverage.rs`: every signed-object type in the codebase has a hybrid-signing round-trip test.
- `crates/fcp-conformance/tests/pq_downgrade_attack_rejection.rs`: an attacker that strips the PQ signature must be rejected once steady state is reached.

### Sub-bead inventory (round 2)

- `flywheel_connectors-angoc.8.1` [N.1] SignedEnvelope hybrid signing default + 7-type roundtrip suite
- `flywheel_connectors-angoc.8.2` [N.1.bis+N.2] Downgrade-attack rejection + hybrid verify perf evidence

---

## Phase O — Formal Verification Gate via Lean (NEW)

**Target**: the `lean/` corpus has zone-flow lattice proofs in flight under `kyopb.1.3.1.1.6.2.1`. Make the README "Zone Isolation PROVEN" claim **mechanically contingent** on Lean proof compilation. Wire the proof corpus into CI.

### O.1 Lean toolchain pin

- Pin Lean version in `lean-toolchain` file at repo root.
- `lake-manifest.json` pins mathlib version.
- `make lean-verify` invokes `lake build` and reports per-file proof success/failure.

### O.2 Proof corpus expansion

Existing in-flight proofs to land:

- `lean/FCP/Zone/Lattice.lean` — zone-flow soundness (Phase C.3 dependency).
- `lean/FCP/Capability/Typestate.lean` — capability typestate soundness (Unverified → UnboundVerified → BoundVerified → ConstraintsEnforced cannot be skipped).
- `lean/FCP/Audit/HashChain.lean` — hash-chain tamper-evidence (∀ tampering m, verify_chain(m(chain)) = Err).
- `lean/FCP/Crypto/HybridSignature.lean` — hybrid signature soundness (∀ adversary A with classical OR PQ break, A cannot forge a hybrid signature).
- `lean/FCP/Mesh/CrdtMerge.lean` — ConnectorStateRoot CRDT merge satisfies lattice laws (Phase A.1).

### O.3 CI gate

- `.github/workflows/lean-verify.yml`: runs `make lean-verify` on every PR.
- Regression: if any proof file goes from `verified` to `failing`, CI blocks the merge.
- Coverage matrix: `docs/formal/coverage-matrix.md` lists every README claim and either the Lean theorem that proves it or an explicit "no formal model" note.

### O.4 Acceptance

- README's "Zone Isolation PROVEN" row is **only** allowed to be `PROVEN` if `lean/FCP/Zone/Lattice.lean` compiles green in the most recent CI run. Enforced by `crates/fcp-conformance/tests/readme_lean_proven_gate.rs` which reads the latest CI artifact and asserts the proof's compile-status.

### O.5 Tests

- The five Lean proofs in O.2 ARE the verification — `lake build` is the test runner.
- `crates/fcp-conformance/tests/lean_ci_artifact_freshness.rs` — latest CI artifact is <24h old and reports 5/5 proofs green.
- `crates/fcp-conformance/tests/lean_coverage_matrix_completeness.rs` — every protocol-level claim in README has a Lean OR TLA+ (Phase S) obligation OR an explicit "no formal model" note with justification.
- `crates/fcp-conformance/tests/lean_toolchain_pin_match.rs` — `lean-toolchain` + `lake-manifest.json` mathlib version match `docs/formal/toolchain_pin.md` exactly.
- `scripts/ci/lean_regression_test.sh` — deliberately introduce a malformed proof; CI workflow must fail the PR with a structured error pointing to the failing theorem.

### O.6 Logging contract

- INFO: per `make lean-verify` run `{total_proofs, green, red, duration_seconds}`.
- DEBUG: per-proof compile output `{proof_file, success, lake_output_lines}`.
- TRACE: mathlib version + Lean compiler version + cache hit/miss per proof.
- CI step emits a structured GitHub Actions summary with per-proof status; counterexample artifact attached on failure.

### O.7 Rollback / fallback

- Proof regression on a PR: CI blocks merge with the failing proof file + line. Revert is single-PR scope.
- Mathlib version drift: `lean_toolchain_pin_match` conformance fails; remediation = update the pin in lockstep with the proof corpus (manual review required).
- Toolchain unavailable in CI runner: workflow fails fast with "Lean toolchain missing"; `fwc doctor lean` catches early; emergency-skip path requires operator-recorded justification in the commit body.
- README PROVEN row out of sync with Lean: `readme_lean_proven_gate` fails CI; remediation = revert the README claim to LIMITED until proof restored.

### O.8 Operator-visible doctor check

- `fwc doctor lean` verifies (a) `lean-toolchain` present, (b) `elan` + `lake` binaries reachable, (c) latest CI `lean-verify` artifact green, (d) `docs/formal/coverage-matrix.md` exists + lists all 5 proofs, (e) all 5 proof files exist + compile locally.

### O.9 Observability hooks

- Metric `fcp_lean_proofs_green` (gauge, 0–5).
- CI annotation per proof on PR view.
- README badge auto-updated by `.github/workflows/lean-verify.yml` reflecting current state.

### Sub-bead inventory (round 2)

- `flywheel_connectors-angoc.9.1` [O.1+O.2 skeleton] Lean toolchain pin + 5 proof-corpus skeleton files + CI
- `flywheel_connectors-angoc.9.2` [O.4] Formal coverage matrix + completeness conformance

---

## Phase P — Adversarial Coverage (NEW)

**Target**: every protocol parser, every connector response handler, every audit-chain entry handler is fuzzed against a structured-input fuzzer. The runtime must never panic, never leak secrets, never silently accept malformed input.

### P.1 Protocol-parser fuzz targets

Add fuzz targets (libfuzzer + `cargo fuzz`) for every wire-format parser:

- `fuzz/fuzz_targets/fcpc_frame_parser.rs` — control-plane framing.
- `fuzz/fuzz_targets/fcps_frame_parser.rs` — data-plane symbol frames.
- `fuzz/fuzz_targets/cose_envelope_parser.rs` — COSE/CWT capability tokens.
- `fuzz/fuzz_targets/capability_claim_parser.rs` — `AuthClaims` decoding.
- `fuzz/fuzz_targets/manifest_toml_parser.rs` — `manifest.toml` ingestion.
- `fuzz/fuzz_targets/audit_chain_entry_parser.rs` — audit-chain entry decoding.
- `fuzz/fuzz_targets/cbor_canonical_decoder.rs` — already partially exists (memory: 2026-05-02 swarm).
- `fuzz/fuzz_targets/raptorq_symbol_decoder.rs` — symbol reconstruction inputs.
- `fuzz/fuzz_targets/iblt_decoder.rs` — IBLT delta decoding (Phase A.2).
- `fuzz/fuzz_targets/event_stream_parser.rs` — AWS Event-Stream (Phase F.3).
- `fuzz/fuzz_targets/sigv4_canonical_request.rs` — SigV4 input canonicalization.

Each target seeded with a corpus from `crates/fcp-testkit/corpus/<format>/`.

### P.2 Adversarial connector

- `connectors/_adversarial/` — a fake connector that returns malformed responses, oversized payloads (> 1GB), mid-stream disconnect, time-skewed timestamps (±1 year), invalid UTF-8 in headers, deeply-nested JSON (> 1000 levels), oversized JSON keys (> 1MB), null-byte injection, header smuggling, CRLF injection.
- Used by `crates/fcp-host/tests/host_robustness_against_adversarial_connector.rs` to ensure the host never panics, never leaks secrets in logs, never propagates malformed data to operators.

### P.3 Property test: ∀ adversarial input, ∀ FCP layer, runtime either rejects or continues safely

- `crates/fcp-conformance/tests/adversarial_input_property.rs`:
  - For every FCP wire-layer entry point (frame parser, envelope decoder, manifest loader, capability verifier), proptest generates adversarial inputs and asserts:
    - **No panic** (catch_unwind wraps every call).
    - **No secret leak** (after the call, audit each emitted log line and OTLP span for any byte sequence in the secret material; assert no match).
    - **Structured error or success** — every return is either `Ok(_)` (semantically valid) or `Err(StructuredError)` (one of the documented error variants), never `Err(Box<dyn Any>)` or panic.

### P.4 Secret-leak detector

- `crates/fcp-testkit/src/secret_taint.rs::SecretTaintTracker`: a runtime guard that registers known-secret byte sequences and scans every log line, span attribute, and outbound wire frame for matches. Any match emits a `SecretLeakAlert` audit event with the call site.
- Used in P.3 to make secret-leak assertions concrete.

### P.5 Crash artifact retention

- Every fuzz target retains crash inputs under `artifacts/fuzz/<target>/<sha>/crashes/`.
- Crash triage workflow: `scripts/fuzz/triage.sh` runs each crash against the latest HEAD, classifies as `FIXED`, `STILL_CRASHES`, or `NEW_VARIANT`, and files a bead for STILL_CRASHES and NEW_VARIANT.

### Sub-bead inventory (round 2)

- `flywheel_connectors-angoc.10.1` [P.1a] First 4 protocol-parser fuzz targets + adversarial input property
- `flywheel_connectors-angoc.10.2` [P.2+P.4] Adversarial connector + SecretTaintTracker runtime guard

---

## Phase Q — Alien-Graveyard Accretion (R3 REWRITTEN: 10-bucket ledger)

**Target**: apply the `/alien-graveyard` skill to mine the corpus for project-specific dark-arts wins. Earlier rounds (R1, R2) folded ~25 mathematical primitives directly into Phases A/B/C/F/N/T (HLC, HVV, KZG, Masked IBLT, BLS threshold, Avalanche, Narwhal, etc.). Round 3 adds the remaining 10 buckets — each pinned to a concrete FCP data structure, a test that proves it works, and a fallback if the technique doesn't pan out. The R1 sketches (old Q.1–Q.5) have been promoted to integrated phases (HLC → A.4.bis, witness-quorum lease → folded into A.2 Avalanche, CRDT JOIN → A.1) and are removed here to eliminate redundancy. A summary of where the R1 alien-graveyard ideas actually landed is in U.1 below.

### Q.A — Verifiable computation for capability tokens: STARK aggregation over `CapabilityInvocationBatch`

- **Bucket**: A (Verifiable computation that maps to FCP capability tokens).
- **Pick**: **STARK aggregation** (Ben-Sasson-Bentov-Horesh-Riabzev 2018 "Scalable, transparent, and post-quantum secure computational integrity", ePrint 2018/046) over `Fiat-Shamir Bulletproofs` or `Plonkish arithmetization`. Rationale: FCP already has Halo2/PLONK ZK for predicate constraints (C.4.bis); a separate STARK aggregator covers the **batch invocation** case which PLONK does poorly. STARKs are also PQ-secure, aligning with Phase N.
- **Where it goes**: Phase C, new sub-section **C.4.quater** (after C.4.tris BBS+ anonymous credentials), wired upstream of Phase M.2 capability replay.
- **FCP data structure touched**: `CapabilityInvocationBatch` (new type in `crates/fcp-audit/src/invocation_batch.rs`) — a Merkle-Damgård-chained batch of `(CapabilityToken, AuthClaims, OperationReceipt)` triples emitted by a single peer over a 5-minute window. The peer ships **one STARK proof** that says "I validated all 10000 invocations correctly per the capability typestate state machine" instead of 10000 individual signatures. The batch root commits via the existing audit-chain HLC ordering (A.4.bis) so the STARK proof sits **inside** an audit-chain entry, not parallel to it.
- **Acceptance**: `crates/fcp-cap-zk/tests/stark_invocation_batch_aggregate.rs` proves a 10k-invocation batch verifies in ≤ 50ms p99 (vs. 10k × 0.2ms = 2s for individual ML-DSA verifies — 40× win); `crates/fcp-conformance/tests/audit_chain_stark_batch_coverage.rs` proves every batched audit entry carries a verifiable proof.
- **Fallback**: if the STARK prover blows the prover-time budget (target ≤ 5s per batch on csd class), fall back to **chunked verification** (1000-invocation batches, BLS aggregate signature per chunk per A.2). The audit-chain entry format includes a `proof_kind` enum so verifiers transparently handle both.

### Q.B — Probabilistic data structures for mesh state: Quotient filter for the revocation-aware capability cache

- **Bucket**: B (Probabilistic data structures matched to mesh state).
- **Pick**: **Quotient filter** (Bender-Farach-Colton-Goswami-Johnson-McCauley-Singh 2012 "Don't Thrash: How to Cache Your Hash on Flash", VLDB 2012) over Cuckoo and learned index. Rationale: the revocation-aware capability cache needs **deletes** (when a capability is revoked we want it gone from the positive cache); Bloom can't delete, Cuckoo's stash adds worst-case unpredictability, learned indices retrain too slowly when the revocation set churns. Quotient filters support deletes natively, cache-line aligned, and compose with the HVV revocation freshness check (A.4.tris).
- **Where it goes**: Phase A, **A.3 LiveTruthResolver** sub-section — replaces the proposed adaptive-Bloom routing index with a **layered Quotient + adaptive-Bloom** structure (adaptive Bloom for negative-cache fast probe, Quotient filter for positive-cache with delete-on-revoke).
- **FCP data structure touched**: `RevocationRegistry` (existing) gains a `quotient_cache: QuotientFilter<ObjectId>` field; `RevocationPushMessage` (existing, priority gossip) drives `quotient_cache.remove(object_id)` on every revocation event. Cross-references the HVV hierarchy (A.4.tris) so cache-eviction propagates `O(depth)` not `O(peers)`.
- **Acceptance**: `crates/fcp-core/tests/quotient_revocation_cache_property.rs` proptest over 10^6 random insert/lookup/delete sequences asserts: (1) no false negatives after delete; (2) FPR ≤ 2^-16; (3) memory ≤ 10 bytes per entry. `crates/fcp-e2e/tests/revocation_quotient_cache_freshness_e2e.rs` proves cache-eviction latency ≤ 100ms p99 from revocation issuance to all-peer eviction.
- **Fallback**: HashMap-backed exact cache (current behavior) with periodic full rebuild on revocation. Slower but correct.

### Q.C — Coordination-avoidance: I-CONFLUENCE analysis for host→mesh migration operations

- **Bucket**: C (Coordination-avoidance techniques).
- **Pick**: **I-CONFLUENCE** (Bailis-Fekete-Franklin-Ghodsi-Hellerstein-Stoica 2014 "Coordination Avoidance in Database Systems", VLDB 2014). Rationale: Phase A's host→mesh cutover is precisely the regime where I-CONFLUENCE answers the operationally-critical question: "which operations need quorum coordination, and which are coordination-free?" Bloom analysis (Boom et al. 2011) labels operations monotonic; I-CONFLUENCE goes further by labeling operations safe-under-merge given a specific invariant.
- **Where it goes**: Phase A, new sub-section **A.2.quater** (between A.2 mesh-backed invoke and A.3 LiveTruthResolver). Drives the per-operation `coordination_class` annotation on `OperationInfo`.
- **FCP data structure touched**: `OperationInfo` (existing, in every connector) gains a new field `coordination_class: CoordinationClass` ∈ `{IConfluent, RequiresQuorum, RequiresFencing}`. The mesh dispatch layer (`MeshInvokeTransport`, A.2) consults this field: `IConfluent` ops skip HRW lease entirely and replicate eventually; `RequiresQuorum` ops drive Avalanche consensus (A.2); `RequiresFencing` ops drive HRW lease + fencing token. Yields **measurable throughput gains** for the 60%+ of read-mostly operations in the connector corpus.
- **Acceptance**: `crates/fcp-conformance/tests/i_confluence_operation_classification.rs` reads every connector's `manifest.toml` + `operations_info()` output, asserts every operation has a `coordination_class` annotation and that the annotation is consistent with the operation's `idempotency_class` (Pure → IConfluent allowed, Dangerous → RequiresQuorum required). `crates/fcp-e2e/tests/i_confluent_dispatch_throughput_e2e.rs` shows ≥ 3× throughput improvement on IConfluent read workloads vs. always-quorum dispatch.
- **Fallback**: classify every operation `RequiresQuorum` (current behavior — safe but slow).

### Q.D — Stream-processing audit-chain anomaly detection: Flink-CEP-style complex event patterns

- **Bucket**: D (Stream processing for the audit chain).
- **Pick**: **Calcite/Flink-CEP-style complex event patterns** (Akidau et al. 2015 "The Dataflow Model", VLDB 2015 — windowing primitives; Cugola-Margara 2012 "Processing Flows of Information", ACM CS 2012 — CEP fundamentals) over reservoir sampling. Rationale: reservoir sampling preserves audit-chain history under compaction but doesn't surface anomalies; CEP turns the audit chain into an actionable signal stream. Reservoir sampling is folded into Phase A's audit-chain compaction path as a sub-bullet, not its own bucket pick.
- **Where it goes**: Phase M (Audit Surface Expansion), new sub-section **M.4** after M.3 audit-OTLP export.
- **FCP data structure touched**: new `crates/fcp-audit-cep/src/pattern.rs::EventPattern` DSL compiles to a `NFA<AuditEvent>`; the NFA runs over the live audit-chain stream (with HLC-respecting ordering from A.4.bis). Patterns like `Capability(c).use().followedBy(60s, Capability(c).use_from_other_zone())` surface as `AnomalyAlert` audit-chain events (back-feeds into the chain itself, providing a tamper-evident anomaly record). Reuses the BLS quorum signers (A.2) so an alert is itself a quorum-signed audit entry.
- **Acceptance**: `crates/fcp-audit-cep/tests/cep_pattern_correctness_property.rs` proves every documented pattern's NFA matches the spec on a synthetic event stream. `crates/fcp-e2e/tests/cep_cross_zone_anomaly_detection_e2e.rs` injects a "capability X used from z:work then z:public within 60s" sequence, asserts an `AnomalyAlert` surfaces within 1s and quorum-signs correctly. **Reservoir sampling sub-deliverable**: `crates/fcp-audit/src/compaction/reservoir.rs::ReservoirCompactor` keeps an unbiased sample of size `k = 10000` across audit-chain compaction; property test `reservoir_unbiased_property.rs`.
- **Fallback**: operator-driven SQL queries over the audit chain via `fwc audit explain` (existing) — strictly less responsive but no NFA runtime needed.

### Q.E — Formal methods that pay rent: Datalog policy engine via Soufflé

- **Bucket**: E (Formal methods that pay rent).
- **Pick**: **Datalog / Soufflé** (Scholz-Jordan-Subotic-Westmann 2016 "On Fast Large-Scale Program Analysis in Datalog", CC 2016) over refinement-types and Z3. Rationale: refinement types are already approximated by the capability typestate (C.4); Z3 is great for one-shot policy satisfiability but not for the **continuous evaluation** of policy across every operation; Datalog gives free incremental evaluation, fixpoint guarantees, and **provenance tracking** which is exactly what audit-chain forensics needs.
- **Where it goes**: Phase C, new sub-section **C.9** (after C.8 README status update). Datalog also feeds Phase M.2 capability replay with provenance traces.
- **FCP data structure touched**: existing `crates/fcp-policy/src/engine.rs::PolicyEngine` gets a Datalog backend `crates/fcp-policy-datalog/src/souffle_backend.rs::DatalogBackend`. Rules live in `policies/*.dl`; `ZoneId`, `ObjectId`, `CapabilityToken` are Datalog relations; policy decisions like `permits(token, op, zone)` become Datalog queries. Every `permits` derivation carries a **provenance witness** (the proof tree) that the audit-chain entry records — making `fwc capability replay` (M.2) automatic. Cross-references the IFC label lattice in C.2 — Soufflé natively handles lattice JOIN/MEET as Datalog operators.
- **Acceptance**: `crates/fcp-policy-datalog/tests/datalog_policy_equivalence.rs` proves the Datalog backend agrees with the procedural backend on 10^5 random policy/operation pairs (differential test); `crates/fcp-policy-datalog/tests/provenance_witness_completeness.rs` proves every derivation carries a complete proof tree. **Soufflé incremental eval target**: incremental-update latency ≤ 1ms p99 for adding/removing a single fact in a 10k-fact knowledge base.
- **Fallback**: existing procedural `PolicyEngine` remains the production path; Datalog backend is opt-in per zone via `zone_policy.toml::engine = "datalog"`. Zone owners who don't want the Soufflé dependency keep the procedural engine.

### Q.F — Performance dark-arts: io_uring for the fcp-host JSON-RPC dispatch loop

- **Bucket**: F (Performance dark-arts).
- **Pick**: **io_uring** (Axboe 2019 "io_uring: A New Asynchronous I/O Interface for Linux"; kernel 5.1+) over buddy allocator, eBPF XDP, DPDK, NUMA placement. Rationale: profiling under heavy swarm sessions (memory: 2026-05-02) shows the fcp-host JSON-RPC dispatch loop is **syscall-bound** (read+write+epoll for every connector invoke = 4-6 syscalls per RPC); io_uring collapses this to a single batched submission. DPDK/AF_XDP are huge wins for bulk symbol flow (Phase A.2 RaptorQ shipping) — these are tracked as **separate sub-deliverables** but the bucket's primary pick is io_uring because it touches every connector invoke, not just symbol-heavy ones. NUMA placement is a follow-on after io_uring lands.
- **Where it goes**: Phase T (Hardware Acceleration), new sub-section **T.8** (after T.7 acceptance). Phase B's evidence convention (B.2 StatPack) measures the win.
- **FCP data structure touched**: existing `crates/fcp-host/src/dispatch.rs::JsonRpcDispatcher` gains an `IoUringDispatcher` alternate impl behind `#[cfg(target_os = "linux")]`. The `OperationIntent` → `OperationReceipt` lifecycle is unchanged on the wire; only the host's I/O loop changes. Cross-references the deterministic Hermit runtime (B.14): io_uring's submission queue is part of Hermit's interception set for bench reproducibility. Sub-deliverable **DPDK/AF_XDP** for `RaptorQSymbolShipper` (Phase A.2) — when shipping > 1000 symbols/s a peer can opt into kernel-bypass via `manifest.toml::transport_class = "afxdp"`.
- **Acceptance**: `crates/fcp-host/benches/iouring_dispatch_throughput.rs` reports throughput (RPCs/s) for the io_uring path vs. the epoll path on csd, Contabo, and Linux laptop; target ≥ 2× throughput at p99 latency parity. `crates/fcp-host/tests/iouring_dispatch_correctness.rs` proves byte-equivalence with the epoll path on the full operator-visible surface. **DPDK sub-acceptance**: `crates/fcp-raptorq/benches/afxdp_symbol_ship_throughput.rs` reports ≥ 4× throughput vs. UDP socket path at 1000-symbol/s sustained.
- **Fallback**: epoll-based dispatcher (current behavior) is the cross-platform path and remains the default on macOS, Windows, and Linux < 5.10.

### Q.G — Cryptographic accretion: Threshold KEM (HPKE) for cross-mesh sealed-object encapsulation

- **Bucket**: G (Cryptographic accretion).
- **Pick**: **Threshold HPKE / Threshold KEM** (Boneh-Gentry-Lynn-Shacham 2003 "Aggregate and Verifiably Encrypted Signatures from Bilinear Maps", EUROCRYPT 2003; HPKE RFC 9180 + Krawczyk threshold-KEM extensions) over PCD aggregate signatures and lattice VRFs. Rationale: PCD (Bitansky-Chiesa 2011) overlaps significantly with the STARK aggregation already in Q.A; lattice VRFs are scheduled for the Phase N PQ track but don't yet have a productive FCP-side consumer; threshold KEM has an **immediate use case** in the cross-mesh sealed-object case where a mesh peer wants to share a ciphertext that decrypts only if `t`-of-`n` recipient zones cooperate.
- **Where it goes**: Phase N (Post-Quantum Hardening Cutover), new sub-section **N.6** (after N.5 conformance). Composes with the existing X-Wing HPKE work.
- **FCP data structure touched**: existing `crates/fcp-hpke/src/sealed_object.rs::SealedObject` gains a `ThresholdSealed` variant: ciphertext is encapsulated under a threshold-KEM public key whose secret is `t`-of-`n` shared across recipient zones via the existing FROST DKG ceremony (already used for BLS signing in A.2). Decap requires `t` decryption shares; partial decryption shares are combined via Lagrange interpolation. Reuses the Pedersen VSS infrastructure from A.2 (BLS threshold rotation) — a single VSS deployment now serves both signing and KEM.
- **Acceptance**: `crates/fcp-hpke/tests/threshold_kem_round_trip.rs` proves `t`-of-`n` decap correctness; `crates/fcp-hpke/tests/threshold_kem_safety_below_t.rs` proves the ciphertext is computationally hiding when fewer than `t` shares are combined; `crates/fcp-e2e/tests/cross_mesh_sealed_object_e2e.rs` exercises a 5-zone deployment where a sealed object decrypts only after 3 zones cooperate.
- **Fallback**: standard (non-threshold) HPKE encapsulation to a single recipient zone (current behavior) — multi-zone sealed objects fall back to per-zone re-encryption.

### Q.H — Adaptive control for operator surface: Bayesian optimization for RaptorQ `K`-tuning

- **Bucket**: H (Adaptive control for the operator surface).
- **Pick**: **Bayesian optimization with Gaussian-process surrogate** (Snoek-Larochelle-Adams 2012 "Practical Bayesian Optimization of Machine Learning Algorithms", NeurIPS 2012; Frazier 2018 "A Tutorial on Bayesian Optimization") over the multi-armed-bandit option, because Thompson sampling for connector failover is **already in J.1** and the new contribution should target a different surface. RaptorQ's `K` (source-symbol count) trades decode latency against decode probability; today it's a static manifest constant; BayesOpt learns the right K per workload + per machine class.
- **Where it goes**: Phase J (Computation Migration Hardening), new sub-section **J.3** (after J.2 CRIU).
- **FCP data structure touched**: existing `crates/fcp-raptorq/src/encoder.rs::RaptorQEncoder` gains a `KSelector` strategy; `BayesOptKSelector` maintains a per-(connector, machine_class) GP posterior over `K`; on each encode it samples K via expected improvement; observed decode latency + decode success feed back into the posterior. Reuses the Phase B StatPack infrastructure for measurement. Cross-references the code-family dispatch (B.6.bis): BayesOpt picks both the code family (RS / RaptorQ / Chiesa) and K jointly.
- **Acceptance**: `crates/fcp-raptorq/tests/bayes_opt_k_convergence_property.rs` proves the BayesOpt regret bound holds empirically (regret ≤ `O(√T log T)` over 10^4 random workloads). `crates/fcp-e2e/tests/bayes_opt_k_throughput_e2e.rs` proves ≥ 20% throughput improvement vs. static K on a 5-machine-class workload.
- **Fallback**: static `K = manifest.toml::raptorq_k` (current behavior) — used when the GP posterior has < 100 observations or when the operator pins K explicitly.

### Q.I — Domain-specific AI-agent accretion: Conformal prediction for connector reliability

- **Bucket**: I (Domain-specific accretion for AI agent ops).
- **Pick**: **Conformal prediction** (Vovk-Gammerman-Shafer 2005 "Algorithmic Learning in a Random World"; Angelopoulos-Bates 2021 "A Gentle Introduction to Conformal Prediction and Distribution-Free Uncertainty Quantification") over Mixture-of-Experts (MoE) routing and differential privacy. Rationale: MoE LLM-router is already partially addressed by Q.H bandit framework; DP is in A.6.tris; conformal prediction is the **unique-to-this-project** add — when a connector says `success: true`, an AI agent consuming the response needs a **calibrated p-value** that the answer is correct, not just a boolean. Conformal prediction gives distribution-free guarantees.
- **Where it goes**: Phase L (Cross-cutting: Reduce Operator/Agent Friction), new sub-section **L.4** (after L.3 cross-agent session search).
- **FCP data structure touched**: existing `OperationReceipt` (the audit-chain entry confirming an invocation) gains a `confidence: ConformalScore` field. `ConformalCalibrator` (new, in `crates/fcp-conformal/src/calibrator.rs`) consumes the past audit-chain entries (HLC-ordered, A.4.bis) for each `(connector, operation)` pair, fits a non-conformity score, and emits a calibrated p-value for new invocations. Reuses Phase M.2 capability replay for ground-truth labels (operator-observed corrections). The `confidence` field is consumed by downstream AI agents via `fwc invoke --include-confidence`.
- **Acceptance**: `crates/fcp-conformal/tests/conformal_coverage_property.rs` proves the marginal-coverage guarantee: for any α ∈ (0,1), the empirical fraction of incorrect-but-claimed-correct invocations is bounded by α + `O(1/√n)`. `crates/fcp-e2e/tests/conformal_agent_decision_quality_e2e.rs` shows an AI agent using the confidence score makes ≥ 15% fewer incorrect downstream decisions vs. the boolean-only baseline.
- **Fallback**: boolean `success: bool` only (current behavior) — AI agents that don't understand the conformal field ignore it.

### Q.J — End-to-end TLA+ model expansion: capability lifecycle + FROST DKG + agent-mail ordering

- **Bucket**: J (End-to-end TLA+ model).
- **Pick**: Expand Phase S's TLA+ corpus to cover three more state machines that were previously implicit: (1) capability lifecycle (mint → use → revoke → expire); (2) FROST DKG ceremony state machine; (3) agent-mail message ordering.
- **Where it goes**: Phase S (Formal Modeling in TLA+/CSP), new sub-sections **S.6, S.7, S.8** (after S.5 acceptance).
- **FCP data structures touched**:
  - **S.6 Capability lifecycle**: `specs/tla/capability_lifecycle.tla` models `CapabilityToken<Pending|Approved|Used|Revoked|Expired>` typestate + the revocation push interaction (A.4.tris HVV) + the audit-chain `OperationReceipt` emission. Invariants: `RevokeBeforeUse` (∀ token, if revoke happens before use, use is rejected); `NoDoubleSpend` (∀ token, ∀ trace, token is consumed at most `max_uses` times); `RevocationPropagationSLO` (∀ revoke, all peers reflect within `revocation_freshness_sla_secs` from A.4.tris HVV).
  - **S.7 FROST DKG state machine**: `specs/tla/frost_dkg.tla` models the FROST ceremony rounds (Komlo-Goldberg 2020 "FROST: Flexible Round-Optimized Schnorr Threshold Signatures") + Pedersen VSS resharing. Invariants: `KeyAgreement` (all honest participants derive the same group public key); `SecretConfidentiality` (no `t-1` collusion learns the secret); `RotationLiveness` (∀ rotation, ceremony completes within bounded rounds).
  - **S.8 Agent-mail message ordering**: `specs/tla/agent_mail_ordering.tla` models the SQLite-backed agent-mail message queue (Phase D.1) + the Mazurkiewicz-trace concurrent-claim resolver (D.4). Invariants: `CausalDeliveryOrdering` (∀ message, recipients see it after sender's prior messages); `NoLostMessage` (modulo storage corruption — paired with the corruption-fallback rule from D.1); `ClaimUniqueness` (∀ bead, ∀ trace, exactly one agent's claim is accepted).
- **Acceptance**: `make tla-check` (Phase S.1) extends to all three models; CI gate fails merge if any invariant is violated. `docs/formal/coverage-matrix.md` (Phase O) adds rows for capability lifecycle, FROST DKG, agent-mail ordering with the TLA+ spec path as the proof obligation.
- **Fallback**: prose-only specification (current state) — formal model is opt-in for high-stakes design changes; the coverage-matrix row marks it `prose-only` rather than `formal-checked`.

### Q.K — EV scoring + selection

- Each of Q.A–Q.J is scored per the `alien-graveyard` 10-dim rubric (correctness uplift, latency impact, complexity cost, fallback safety, fits-with-spec, proof-friendliness, operator-visible, post-quantum readiness, performance evidence cost, breaking-change risk).
- Top-5 by EV are scheduled for landing in 2026-Q3; remainder filed as research beads in 2026-Q4.
- Scoring artifact: `docs/architecture/alien_graveyard_q3_2026.md` — generated by `scripts/alien-graveyard/score.sh` from this section's `Bucket → Pick → FCP structure → Test → Fallback` table.

### Sub-bead inventory (round 2)

- `flywheel_connectors-angoc.11.1` [Q.C] I-CONFLUENCE coordination_class on every operation + mesh dispatch routing
- `flywheel_connectors-angoc.11.2` [Q.B] QuotientFilter revocation cache on RevocationRegistry
- `flywheel_connectors-angoc.11.3` [Q.K] EV scoring of 10 alien-graveyard buckets + Top-5 commitment artifact

---

## Phase R — Chaos Engineering (NEW)

**Target**: production-grade resilience requires **continuous chaos injection**, not just CI-time fault tests. Phase R adds a dedicated chaos harness, a catalogue of blast-radius-bounded scenarios, and a runbook for every failure class.

### R.1 Chaos harness architecture

- **Surface**: `crates/fcp-chaos/` — Rust harness with declarative scenario DSL (`scenarios/*.toml`); runs in `staging` continuously, **never** in `production` (enforced by a hard-coded `assert!(env != Production)` at chaos-injector init).
- **Scenarios** (each scenario declares `blast_radius`, `recovery_objective_secs`, `rollback_steps`):
  - **Network**: net-partition (bisecting, asymmetric, DERP-only, full), packet-drop (1%, 10%, 50%), packet-reorder, packet-duplication, latency-spike (RTT × 100), bandwidth-throttle (1Mbps).
  - **Clock**: NTP skew injection (±30s, ±5min, ±1h), leap-second simulation, clock-step-back (the worst).
  - **Peer**: random kill `kill -9`, slow-loris (CPU starvation), byzantine peer (lies about IBLT digest, forges fencing tokens), graceful leave, ungraceful leave (TCP RST).
  - **Disk**: disk-full mid-write, EIO injection on every Nth fsync, slow-disk (1MB/s sustained), btrfs/ext4 metadata corruption (controlled fault-injection layer).
  - **Memory**: OOM-kill `fcp-host` mid-invoke, malloc-fail-randomly (every Nth allocation), memory-pressure (background process eats 90% RAM).
  - **TCP**: every TCP RST scenario (mid-handshake, mid-stream, after FIN), half-open connections (peer dies without RST), TIME_WAIT exhaustion.
  - **Lease theft**: a chaos peer aggressively re-elects HRW leases without proper coordination; assert fencing tokens correctly reject stale-writer effects.
- **Surface for each**: `crates/fcp-chaos/src/scenarios/{net.rs, clock.rs, peer.rs, disk.rs, memory.rs, tcp.rs, lease.rs}`.

### R.2 Continuous chaos in staging

- A dedicated staging cluster runs `fcp-chaos run --scenario-set continuous --duration infinity --severity escalating`; the harness picks scenarios at random with escalating severity, asserts SLOs hold within the configured recovery objective, and emits OTLP `ChaosScenario` + `ChaosOutcome` spans.
- **Blast radius bounds**: every scenario declares a max impact (number of peers affected, bytes corrupted, seconds of downtime); the harness aborts if any scenario exceeds its declared bound.
- **Rollback procedure**: every scenario has a paired teardown step (`scenarios/<name>.toml::rollback_steps`); on scenario failure or harness abort, rollback is applied automatically.

### R.3 GameDay runbook + monthly exercise

- `docs/ops/chaos_gameday_runbook.md` — operator-facing runbook with one section per scenario class, the SLOs that should hold, the alerting signatures, and the manual-intervention escape hatch.
- Monthly GameDay: a live drill where operators react to a randomly-chosen chaos scenario; outcomes filed to `docs/ops/gameday/<date>-<scenario>.md`.

### R.4 Acceptance

- 30 consecutive days of continuous chaos in staging without unexplained SLO breach (`crates/fcp-chaos/tests/staging_30day_stability.rs` is a meta-test that reads the staging artifacts).
- One GameDay per month for 3 consecutive months with no operator surprises (no scenario causes a runbook-divergent operator action).

### Sub-bead inventory (round 2)

- `flywheel_connectors-angoc.12.1` [R.1] fcp-chaos crate skeleton + DSL parser + production-env + blast-radius guards
- `flywheel_connectors-angoc.12.2` [R.1 net] 11 network chaos scenarios + recovery SLA test + runbook section

---

## Phase S — Formal Modeling in TLA+ / CSP (NEW)

**Target**: model-check the cutover state machines and the mesh-consensus invariants in **TLA+** (Lamport's specification language with TLC model checker) and the message-passing protocols in **CSP** (Hoare's Communicating Sequential Processes via the FDR refinement checker). Catches deadlocks, livelocks, and unreachable rollback states **before** code is written.

### S.1 Cutover state-machine TLA+ specification

- **Why**: the operator-driven mesh cutover (Phase A) is a state machine: `V1Only → V2Shadow → V2Default → V1Fallback (rollback) → V2Permanent`. We need to prove no operator action sequence leaves the system in an unrecoverable state, and that every transition has a well-defined rollback.
- **Plan**: `specs/tla/cutover.tla` models the cutover state machine + operator action set; `specs/tla/cutover.cfg` declares the invariants:
  - `Safety`: no state has both `V1Only` and `V2Default` simultaneously.
  - `Liveness`: from `V2Shadow`, every operator action sequence eventually reaches `V2Default` OR `V1Fallback`.
  - `Recoverability`: every reachable state has a path back to `V1Only` via some operator action sequence.
- **TLC model check**: configure with bounded operator-action sequences (depth ≤ 20); TLC enumerates the full state space and proves all invariants hold.
- **Surface**: `specs/tla/`, `Makefile` target `make tla-check`; CI workflow `.github/workflows/tla-check.yml`.

### S.2 Mesh consensus invariant model

- **Why**: HRW lease coordination (A.2) + Avalanche consensus (A.2 below) + quorum signatures must compose without deadlock or fairness violation.
- **Plan**: `specs/tla/mesh_consensus.tla` models the lease + consensus + quorum interaction; invariants:
  - `SafetyOfFencing`: no two writers ever commit with the same fencing token.
  - `LivenessUnderPartition`: from any partition-heal, leases are eventually re-elected within `2 × p99(gossip_round)`.
  - `QuorumDurability`: a quorum-signed audit entry, once committed, is reachable from every future quorum's view.
- **Surface**: `specs/tla/mesh_consensus.tla`, `specs/tla/mesh_consensus.cfg`.

### S.3 Capability typestate CSP model

- **Why**: the `ApprovalToken<Pending|Approved>` typestate + revocation interaction is a concurrent message-passing system; CSP refinement checking via FDR catches livelocks (e.g., a revocation message racing with a delegation message both stuck waiting for the other).
- **Plan**: `specs/csp/capability_typestate.csp` models the typestate + revocation; FDR refinement check:
  - `CapabilitySpec ⊑_FD CapabilityImpl` (failures-divergences refinement).
  - No divergent traces (no unbounded internal action).
- **Surface**: `specs/csp/`, `make csp-check` (requires FDR4 toolchain).

### S.4 Continuous TLA+ / CSP in CI

- `.github/workflows/formal-models.yml` runs `make tla-check` + `make csp-check` on every PR that touches `crates/fcp-mesh/`, `crates/fcp-host/`, `crates/fcp-core/`. Failures block merge.
- Cross-references Phase O (Lean): TLA+ catches state-machine bugs; Lean proves type-level + crypto soundness; together they cover both protocol-level and code-level correctness.

### S.5 Acceptance

- `make tla-check && make csp-check` is green at HEAD.
- `docs/formal/coverage-matrix.md` (Phase O) lists every protocol claim with either a Lean proof OR a TLA+ model OR an explicit "no formal model" note.
- Every cutover step in `docs/security/pq_cutover_plan.md` (N.4) is mirrored by a TLA+ state in `specs/tla/cutover.tla`.

### Sub-bead inventory (round 2)

- `flywheel_connectors-angoc.13.1` [S.1] cutover.tla TLA+ spec + TLC CI gate + alignment e2e
- `flywheel_connectors-angoc.13.2` [S.6] capability_lifecycle.tla + alignment e2e (Q.J graft)

---

## Phase T — Hardware Acceleration (NEW)

**Target**: every cryptographic operation has a hardware-accelerated fast path with **runtime feature detection** and a portable software fallback. AES-NI / VAES, AVX-512 for BLAKE3 + ML-DSA polynomial arithmetic, Apple CryptoKit for HPKE, NEON for ARM, AVX2 for x86_64 fallback.

### T.1 Feature-detection dispatch layer

- **Plan**: `crates/fcp-crypto-hw/src/cpuid.rs::HwFeatureSet` runtime-detects available ISA extensions once at startup; every crypto primitive carries a function-pointer table (`fn_table.{aes_encrypt, sha512_compress, mldsa_ntt, ...}`) populated based on detection.
- **Detection sources**:
  - x86_64: `cpuid` leaves 1, 7, 7.1 for SSE/AES-NI/AVX2/AVX-512F/VAES/AVX-512VL/GFNI/VPCLMULQDQ.
  - aarch64: `HWCAP_AES`, `HWCAP_SHA2`, `HWCAP_SVE` via `getauxval` (Linux) or `sysctl` (macOS, `hw.optional.arm.FEAT_AES`).
  - Apple Silicon: `sysctlbyname` queries for AMX, Apple-specific cryptographic primitives.
- **Surface**: `crates/fcp-crypto-hw/src/dispatch.rs::FnTable` per-primitive.

### T.2 BLAKE3: AVX-512 / VAES / NEON

- BLAKE3 already SIMD-aware via the upstream crate, but ensure the AVX-512 path is selected on capable hardware (the upstream default is AVX2-conservative). Surface: `crates/fcp-crypto-hw/src/blake3.rs::Blake3Hasher` with explicit feature selection.
- **Acceptance**: `crates/fcp-crypto-hw/benches/blake3_throughput.rs` reports throughput per ISA tier; AVX-512 path target ≥ 8 GB/s on capable hosts.

### T.3 AES / GCM: AES-NI + VAES + CLMUL

- All HPKE-AES-GCM operations dispatch to the AES-NI path on x86_64, VAES (vector AES) for AVX-512 hosts (4-block parallel encryption), ARMv8 AES crypto extensions on aarch64.
- Apple Silicon: integrate with `CryptoKit` via `crypto-kit-sys` for hardware-accelerated AES-GCM that uses the Secure Enclave when keys are origined there.
- **Surface**: `crates/fcp-crypto-hw/src/aes_gcm.rs::AesGcmDispatch`.
- **Acceptance**: `crates/fcp-crypto-hw/benches/aes_gcm_throughput.rs` reports throughput per tier; AES-NI target ≥ 4 GB/s; VAES target ≥ 12 GB/s on AVX-512 hosts.

### T.4 ML-DSA / X-Wing polynomial arithmetic: AVX-512 + NEON

- ML-DSA's hot path is NTT (Number Theoretic Transform) over a Kyber-style modulus. AVX-512F gives 8-wide 64-bit lanes; NEON gives 4-wide 32-bit lanes.
- Vectorized NTT in `crates/fcp-crypto-pq/src/ntt_avx512.rs` (gated `#[cfg(target_feature = "avx512f")]`) and `crates/fcp-crypto-pq/src/ntt_neon.rs` (aarch64).
- **Acceptance**: ML-DSA-65 sign p99 drops from ~0.5ms (portable) to ≤ 0.15ms (AVX-512) or ≤ 0.25ms (NEON). Hybrid verify p99 drops from ~2ms target (N.2) to ≤ 0.8ms.

### T.5 Apple CryptoKit integration for HPKE on Apple Silicon

- **Why**: Apple Silicon's Secure Enclave can hold HPKE recipient private keys with hardware-backed isolation; Rust → Swift bridging via `crypto-kit-sys` exposes the `kSecAttrTokenIDSecureEnclave` path.
- **Plan**: when `cfg(target_os = "macos") && hw_feature_set.has_secure_enclave()`, route HPKE decap operations through CryptoKit; key material never leaves the enclave.
- **Surface**: `crates/fcp-crypto-hw/src/apple_se.rs::SecureEnclaveHpke`.
- **Acceptance**: `crates/fcp-crypto-hw/tests/secure_enclave_hpke_e2e.rs` (gated `#[cfg(target_os = "macos")]`) — round-trip HPKE decap via the enclave path; key extraction attempt must fail.

### T.6 Feature-detection robustness

- **Cross-test**: `crates/fcp-crypto-hw/tests/feature_detection_consistency.rs` — every dispatch tier produces byte-identical output on a fixed test-vector set; portable path is the reference.
- **CI matrix**: `.github/workflows/crypto-hw-matrix.yml` runs the test suite on x86_64 (no AVX, AVX2-only, AVX-512), aarch64 (no AES ext, AES ext), macOS Apple Silicon.

### T.7 Acceptance

- Every crypto primitive in `crates/fcp-crypto/`, `crates/fcp-crypto-pq/`, `crates/fcp-hpke/` has a hardware-accelerated fast path + portable fallback.
- `docs/perf/crypto_hw_evidence.md` documents the speedups per ISA tier with StatPack (B.2).
- `fwc doctor` reports the detected feature set and which crypto primitives are running on which dispatch tier.

### Sub-bead inventory (round 2)

- `flywheel_connectors-angoc.14.1` [T.1] fcp-crypto-hw crate skeleton: HwFeatureSet detection + dispatch table
- `flywheel_connectors-angoc.14.2` [T.2] BLAKE3 AVX-512/VAES/NEON dispatch + cross-tier consistency

---

## Phase U — Brilliance Integration (R3 CAPSTONE)

**Target**: stitch the ~35 alien-graveyard additions (R1 + R2 + R3) into a coherent picture. This phase is not a delivery phase — it is the **synthesis** that proves the additions reinforce each other rather than sitting as 35 disconnected dark-arts patches. It also surfaces the design tensions that the integration creates and the explicit reconciliation for each.

### U.1 Where the R1/R2/R3 alien-graveyard ideas actually landed

R1 Phase Q was a sketch of 5 candidate techniques. R2 and R3 promoted them into integrated phases:

| R1 sketch | Landed at | FCP structure |
| --- | --- | --- |
| Q.1 Lamport SBP | A.1 δ-state CRDT + CRDT JOIN semilattice | `ConnectorStateRoot` |
| Q.2 HLC | A.4.bis | `AuditEvent.timestamp` |
| Q.3 CRDT JOIN for policy | A.1 + folded into Q.C I-CONFLUENCE | `OperationInfo.coordination_class` |
| Q.4 Witness-set quorum | folded into A.2 Avalanche + BLS threshold | `ZoneQuorumPolicy` |
| Q.5 Anti-entropy witness-quorum | A.2 Masked IBLT + Avalanche | `MaskedIblt`, `AvalancheVoter` |

R3's Q.A–Q.J adds 10 new buckets; together with R2's ~25 mathematical primitives this is a 35-piece accretion ledger.

### U.2 The coherent-protocol picture

The mesh-state protocol that emerges from the additions is not 35 disconnected primitives — it is a **single layered stack** where each layer's output is the next layer's input:

```
Layer 7 (Operator surface):    fwc + LiveTruthResolver (A.3) + Conformal scores (Q.I)
Layer 6 (Audit/Anomaly):       Audit chain (M) + Narwhal-Bullshark DAG (A.2) + Flink-CEP (Q.D) + eBPF absence (A.2)
Layer 5 (Verifiable computation): STARK batch (Q.A) + ZK-SNARK predicates (C.4.bis) + BBS+ creds (C.4.tris) + Wesolowski VDF (N.3.bis)
Layer 4 (Consensus):           HRW + Fencing (A.2) + BLS Threshold (A.2) + Avalanche (A.2) + FROST DKG (S.7)
Layer 3 (Anti-entropy):        Adaptive Bloom (A.2) + XOR filter (A.2) + Masked IBLT (A.2) + Quotient cache (Q.B)
Layer 2 (State + Commit):      δ-state CRDT (A.1) + KZG/IPA vector commits (A.1.bis) + HLC (A.4.bis) + HVV (A.4.tris)
Layer 1 (Crypto + Hardware):   Hybrid Ed25519 + ML-DSA (N) + Threshold KEM (Q.G) + AES-NI/VAES/NEON (T) + io_uring (Q.F)
```

The **integration glue** (not a separate phase, but the synthesis):
- **HLC (A.4.bis) is the canonical time** consumed by every higher layer: δ-state deltas (A.1), Narwhal DAG anchors (A.2), Flink-CEP windows (Q.D), Conformal calibration history (Q.I), STARK batch boundaries (Q.A). One clock, six consumers.
- **KZG/IPA vector commits (A.1.bis) are the canonical subset-opening primitive** used by: connector-state subset reads (A.1), capability invocation batch openings (Q.A STARK alternates with KZG when batch < 100), adaptive-Bloom route bindings (A.3). One commitment scheme, three consumers.
- **BLS threshold (A.2) + FROST DKG (S.7) + Pedersen VSS (A.2)** form a single key-material substrate consumed by both signing (audit-chain quorum) and encryption (Q.G threshold KEM). One DKG ceremony, two output capabilities.
- **The audit chain (M) is the universal sink**: every layer's "I did the right thing" claim lands as an audit-chain entry — STARK proofs (Q.A), Avalanche decisions (A.2), revocation events (A.4.tris), CEP anomaly alerts (Q.D), Conformal calibration updates (Q.I). The chain is the **observable behavior** of the mesh.
- **Datalog policy engine (Q.E) is the universal allow/deny decider**: every layer's policy question routes to the same Soufflé fact base — IFC label lattice (C.2), capability typestate (C.4), I-CONFLUENCE coordination class (Q.C), Bayesian-tuned K (Q.H). One policy language, four consumers.

### U.3 Design tensions surfaced by the integration (and reconciliations)

Integrating 35 primitives reveals five real tensions that earlier rounds glossed over. Each gets an explicit reconciliation:

- **Tension 1 (consistency)**: δ-state CRDT (A.1) assumes **eventual consistency**, but the audit chain (M) and BLS quorum signatures (A.2) want **linearizability**.
  - **Reconciliation**: the audit chain is **append-only linearizable** within a quorum view, but δ-state CRDT changes are **lifted** into the audit chain as `StateCommitEvent` audit entries via HLC ordering (A.4.bis). The audit chain linearizes the **commit events**, not the CRDT state itself. Property test: `crates/fcp-conformance/tests/state_commit_linearizability_property.rs`.

- **Tension 2 (privacy)**: Differential-privacy noise on telemetry (A.6.tris) **adds noise**, but conformal prediction (Q.I) needs **clean** calibration history for distribution-free guarantees.
  - **Reconciliation**: DP noise applies to **cross-zone exported counters**, not to the local audit chain that feeds the conformal calibrator. Conformal lives **inside the zone** that owns the connector's history; DP applies **at zone egress**. The DP budget accountant (A.6.tris `DpBudget`) and the conformal calibrator (Q.I `ConformalCalibrator`) read from disjoint sub-views of the audit chain. ADR: `docs/architecture/adr/U3-dp-vs-conformal-zone-boundary.md`.

- **Tension 3 (commits)**: KZG vector commits (A.1.bis) require a **trusted setup**, but the zone-trust model (C.2 IFC) forbids trusted setups in zones marked `delegation_privacy = "off"`.
  - **Reconciliation**: zones declare `vector_commit_scheme ∈ {"kzg10", "ipa_halo2"}` in `zone_policy.toml`; the Halo2 IPA path (already in A.1.bis as fallback) is the setup-free alternative. The KZG ceremony transcript (A.1.bis `docs/security/kzg_ceremony_<zone>.md`) is signed by the zone owner so a zone that allows KZG explicitly accepts the trust assumption. Conformance: `crates/fcp-conformance/tests/vector_commit_scheme_policy_match.rs` proves no zone uses KZG without an owner-signed ceremony transcript.

- **Tension 4 (verification cost)**: STARK aggregation (Q.A) gives **O(1) verify** but **O(n log² n) prove** — for some connectors the prover cost may exceed the 5s budget.
  - **Reconciliation**: the audit-chain entry's `proof_kind` enum (Q.A) allows the prover to emit any of `{ml_dsa_per_entry, bls_aggregate, stark_batch}`. The selection is driven by Bayesian optimization (Q.H extended to choose proof kind alongside `K`) — a connector that consistently misses the STARK prover budget gracefully degrades to BLS aggregate (A.2) or per-entry ML-DSA (N). Verifiers handle all three transparently. Test: `crates/fcp-cap-zk/tests/proof_kind_dispatch_correctness.rs`.

- **Tension 5 (coordination class vs. typestate)**: I-CONFLUENCE (Q.C) classifies operations `IConfluent` to skip coordination, but the capability typestate (C.4 `ApprovalToken<Approved>::consume()`) requires a linearizable consume — the typestate is **stricter** than I-CONFLUENCE allows.
  - **Reconciliation**: I-CONFLUENCE applies to the **data plane** (state replication, content addressing), not to the **capability plane** (typestate transitions). Capability consume is always coordination-required via HRW fencing (A.2). The `coordination_class` field on `OperationInfo` is interpreted as "for the operation's **data effects**" — capability-handling code paths are coordination-required regardless. Property test: `crates/fcp-conformance/tests/capability_consume_always_fenced.rs` proves no IConfluent operation can skip the typestate fencing path.

### U.4 Cross-references — every R3 add is reachable from at least one previously-shipped FCP path

Sanity check (validated in the bead-generation gate): for every Q.A–Q.J pick, list (a) the existing FCP file the code lives next to, (b) the existing test it composes with, (c) the existing bead epic it grafts onto. Stored as `docs/architecture/alien_graveyard_reachability_2026-05-12.md` — generated by `scripts/alien-graveyard/reachability.sh` from this phase's tables.

### U.5 Acceptance (Brilliance Integration)

- [ ] The 7-layer stack diagram in U.2 compiles to an actual `crates/fcp-protocol/src/architecture/layers.rs` constant that the linter checks against the crate dependency graph (each layer can only depend on its own and lower).
- [ ] All five tensions in U.3 have a green property test or conformance test demonstrating the reconciliation holds.
- [ ] `docs/architecture/alien_graveyard_reachability_2026-05-12.md` lists all 10 R3 picks with their `(file_neighbor, test_neighbor, epic_graft)` triple.
- [ ] No alien-graveyard add is orphaned: every Q.A–Q.J entry is referenced from at least one acceptance bullet in the master acceptance criteria list at the bottom of this document.

### Sub-bead inventory (round 2)

- `flywheel_connectors-angoc.15.1` [U.1] master_reachability.md ledger + completeness conformance
- `flywheel_connectors-angoc.15.2` [U.2] 7-layer stack LAYERS constant + linter-enforced crate-graph alignment

---


## Cross-cutting Test Obligations

Every phase above must ship:
1. **Unit tests** for new types/functions.
2. **Integration tests** for cross-module behavior.
3. **E2E test** that exercises the operator-visible surface.
4. **Conformance test** if it touches the README status table.
5. **Golden vector** if it touches CBOR/COSE/audit chain serialization.
6. **Bench** if it touches a performance target (with StatPack per B.2).
7. **Doctor check** so operators can self-diagnose.
8. **JSONL evidence artifact** for downstream reality-check passes.
9. **OTLP span coverage** with required attributes (peer, lease, freshness, decision_trace).
10. **Fuzz harness** for every wire-format parser the phase introduces (Phase P).
11. **Lean proof obligation** (or explicit "no formal model" note) per Phase O.

---

## Bead Generation Plan (Phase 3a input)

Convert this bridge plan into beads via the frozen template. Suggested epic structure:

- Epic `flywheel_connectors-mesh-cutover-2026-Q2` (Phase A)
- Epic `flywheel_connectors-perf-evidence-2026-Q2` (Phase B)
- Epic `flywheel_connectors-zone-isolation-graduation` (Phase C)
- Epic `flywheel_connectors-tooling-stability` (Phase D)
- Epic `flywheel_connectors-windows-sandbox` (Phase E) — extends r4qcg
- Epic `flywheel_connectors-aws-bedrock-graduation` (Phase F) — extends 4kw5f.2.9.2.13
- Epic `flywheel_connectors-incubation-graduation` (Phase G)
- Epic `flywheel_connectors-coverage-discipline` (Phase H)
- Epic `flywheel_connectors-fcp3-cleanup` (Phase I)
- Epic `flywheel_connectors-migration-hardening` (Phase J)
- Epic `flywheel_connectors-quarterly-cadence` (Phase K)
- Epic `flywheel_connectors-operator-friction` (Phase L)
- Epic `flywheel_connectors-audit-explorer` (Phase M)
- Epic `flywheel_connectors-pq-cutover` (Phase N)
- Epic `flywheel_connectors-formal-verification-gate` (Phase O)
- Epic `flywheel_connectors-adversarial-coverage` (Phase P)
- Epic `flywheel_connectors-alien-graveyard-2026-Q3` (Phase Q — 10 buckets Q.A–Q.J)
- Epic `flywheel_connectors-chaos-engineering` (Phase R)
- Epic `flywheel_connectors-formal-modeling-tla-csp` (Phase S — extended in Q.J with capability lifecycle, FROST DKG, agent-mail ordering)
- Epic `flywheel_connectors-hardware-acceleration` (Phase T — extended in Q.F with io_uring + DPDK)
- Epic `flywheel_connectors-brilliance-integration` (Phase U — synthesis, layer diagram, tension reconciliations)

Dependency chain:
- Phase A.0 blocks Phase A.1–A.7.
- Phase A blocks Phase C's README status update (Zone Isolation can't go PROVEN before Mesh-Native unless gated separately).
- Phase A.1.bis (KZG/IPA) blocks A.2's reduced-bandwidth subset-opening claim.
- Phase B can run in parallel to A.
- Phase G batches can run in parallel by batch boundary.
- Phase K depends on A finishing for the next quarterly to report the cutover.
- Phase N can run in parallel to A but depends on the StatPack methodology in B.2.
- Phase O blocks the README "Zone Isolation PROVEN" claim flip (cross-references Phase C.3 + C.8).
- Phase P is precondition for any connector graduation in Phase G (the fuzz pass in G.4 depends on P harnesses).
- R3 alien-graveyard dependencies (Phase Q rewritten):
  - Q.A (STARK invocation batch) depends on A.2 BLS quorum (proof_kind dispatch) + C.4.bis Halo2 prover toolchain.
  - Q.B (Quotient cache) depends on A.4.tris HVV revocation hierarchy + existing `RevocationRegistry`.
  - Q.C (I-CONFLUENCE) depends on every connector having typed `OperationInfo` (Phase G.3 criterion 1).
  - Q.D (Flink-CEP audit anomalies) depends on A.4.bis HLC ordering + A.2 BLS quorum (alerts are quorum-signed).
  - Q.E (Datalog policy) composes with C.2 IFC lattice; differential against existing `PolicyEngine`.
  - Q.F (io_uring) is Linux-only; macOS/Windows keep epoll; cross-references B.14 Hermit determinism.
  - Q.G (Threshold KEM) reuses A.2 BLS DKG / Pedersen VSS — no new ceremony required.
  - Q.H (Bayesian K-tuning) depends on B.2 StatPack + B.6.bis code-family dispatch.
  - Q.I (Conformal prediction) depends on Phase M audit-chain explorer for ground-truth labels.
  - Q.J (TLA+ expansion) extends Phase S; depends on S.1 toolchain pin.
- Phase U (Brilliance Integration) depends on **all** of A, C, M, N, S, T plus Q.A–Q.J landing; runs as the final synthesis pass before the 2026-Q3 quarterly debiasing (Phase K.1).
- Phase R depends on Phase A complete (chaos needs the mesh up); blocks Phase K's quarterly graduation claim.
- Phase S can run in parallel to A and informs A's design — TLA+ models should be written **before** the cutover code lands so the model-check catches state-machine bugs early.
- Phase T can run in parallel to N; the AVX-512 / NEON ML-DSA paths in T.4 are needed to meet the relaxed hybrid-verify p99 ≤ 2ms target in N.2 on lower-end hardware.

## Acceptance Criteria

Bridge plan is complete when:
- [ ] Every README status table row is `PROVEN` or explicitly marked with operator-facing remediation status.
- [ ] Every performance target has a written evidence doc plus CI regression gate, including StatPack (B.2), noise-class calibration (B.3), USS/PSS memory (B.4), p999 + tail-amp (B.5), K-sweep symbol recon (B.6), k/n + group + share-size secret recon (B.7), idle/light/heavy CPU (B.8).
- [ ] Every connector ships either `local_non_mock.rs` or `live_verification.rs` (or both), plus differential test (H.3) and mutation test (H.4).
- [ ] Every cutover gate in FCP3_Transition_Scorecard.md is PASS, not SKIP.
- [ ] All 22 currently-open beads either close or have an explicit "intentionally deferred" annotation.
- [ ] `fwc doctor --json` returns `{"healthy": true, "score": ≥ 800}` across reference operator environments.
- [ ] Mesh-Native shadow mode has run ≥ 14 days with zero unexplained divergences (A.5).
- [ ] Every mesh interaction emits a complete OTLP span per A.6 conformance.
- [ ] Hybrid PQ signing is the steady-state default per N.4.c; PQ downgrade-attack rejection conformance is green.
- [ ] `make lean-verify` is green on every PR; `docs/formal/coverage-matrix.md` lists every README claim with its proof obligation or explicit no-model note.
- [ ] Every wire-format parser has a fuzz target (P.1) with corpus and crash-triage workflow.
- [ ] Adversarial connector + property test (P.2, P.3) are green; secret-leak detector (P.4) has zero hits across the full test suite.
- [ ] Alien-graveyard Top-3 (per Q.6 EV scoring) are landed; remainder filed as research beads.
- [ ] Vector commitments (KZG/IPA, A.1.bis) cut mesh state-subset opening bandwidth ≥ 50× vs. BLAKE3 baseline on the 100-peer harness.
- [ ] Masked IBLT (A.2) converges under `d ≥ 10× predicted` without falling out of budget; layered FPR ≤ 2^-45 over 10^6 rounds.
- [ ] HLL (A.2) standard error ≤ 1.5× theoretical bound across 1M proptest sets.
- [ ] HLC (A.4.bis) preserves cross-zone happens-before under bounded NTP skew; physical-drift alert surfaces in `fwc audit chain status`.
- [ ] HVV (A.4.tris) revocation freshness check cost is `O(depth)`, validated by proptest.
- [ ] BLS threshold quorum (A.2) produces constant-size aggregate signatures + rogue-key resistance per BLS-PoP.
- [ ] Avalanche consensus (A.2) hits sub-500ms finality with safety + liveness under 50% adversarial preference flipping.
- [ ] Narwhal/Bullshark audit-chain mempool (A.2) demonstrates ≥ 10× write-throughput vs. linear chain.
- [ ] eBPF audit-absence detector (A.2) catches ≥ 99.99% of cross-zone I/O within 5s window with zero false alerts.
- [ ] ZK-SNARK predicate proofs (C.4.bis) verify ≤ 5ms p99; Stripe spending-limit case green E2E.
- [ ] BBS+ anonymous credentials (C.4.tris) pass unlinkability + revocation property tests.
- [ ] Wesolowski VDF (N.3.bis) bounds owner-key burst to ≤ 100 actions/h even with 1000-core attacker.
- [ ] Reed-Muller binary attestation (F.5) co-released with every signature; collision-resistance empirically validated.
- [ ] WASI Preview 3 / Component Model (E.4) is the default linker path for new connectors; legacy P1 adapter green.
- [ ] Coreset bench sampling (B.12) preserves p99 estimate within ε ≤ 5% over 30 days; coreset size ≤ 25 vs. full suite.
- [ ] Coz speedup-oracle (B.13) drives ≥ 3 shipped optimizations per quarter with predicted vs. actual within ±30%.
- [ ] Hermit deterministic runtime (B.14) produces byte-identical bench histograms across 10 runs; every fuzz crash reproduces from saved seed.
- [ ] Reed-Solomon + Chiesa code-family dispatch (B.6.bis) beats RaptorQ for K ≤ 32 in wall-clock decode.
- [ ] Adaptive Bloom routing (A.3) keeps amortized bytes-per-route ≤ 16 at FPR ≤ 2^-16 over 10k connectors.
- [ ] Smoothed-analysis regret bound (J.1) holds empirically under adversarial-but-bounded noise workloads.
- [ ] Differential-privacy telemetry (A.6.tris) bounds membership-inference adversary advantage to ε-budget.
- [ ] CHERI-analogous `TaggedCapability<T>` (A.6.bis) passes forgery-resistance fuzz on Morello tier-2 CI; tier-1 software analogue green.
- [ ] Phase R: 30 consecutive days of continuous chaos in staging without unexplained SLO breach; monthly GameDay for 3 months with no runbook-divergent operator action.
- [ ] Phase S: `make tla-check && make csp-check` green on every PR touching mesh/host/core; coverage matrix has TLA+/CSP/Lean entry for every protocol claim.
- [ ] Phase T: every crypto primitive has a hardware-accelerated fast path + portable fallback; AVX-512 BLAKE3 ≥ 8 GB/s; ML-DSA-65 sign p99 ≤ 0.15ms on AVX-512 host; Apple SE HPKE round-trip green; cross-tier byte-identical outputs validated by `feature_detection_consistency` test.
- [ ] Phase Q.A (STARK invocation batch): 10k-invocation batch verifies in ≤ 50ms p99; `CapabilityInvocationBatch` audit-chain entries carry verifiable proofs; chunked-BLS fallback transparently dispatched via `proof_kind` enum.
- [ ] Phase Q.B (Quotient cache): revocation cache supports deletes, FPR ≤ 2^-16, memory ≤ 10 B/entry, eviction-to-all-peers ≤ 100ms p99 from revocation issuance.
- [ ] Phase Q.C (I-CONFLUENCE): every connector's `OperationInfo` carries a `coordination_class`; conformance test passes; IConfluent throughput ≥ 3× quorum baseline on read workloads; `capability_consume_always_fenced` property holds.
- [ ] Phase Q.D (Flink-CEP + reservoir sampling): pattern correctness property green; cross-zone anomaly E2E surfaces an `AnomalyAlert` within 1s with valid quorum signature; reservoir compactor preserves unbiased k=10000 sample.
- [ ] Phase Q.E (Datalog policy via Soufflé): backend agrees with procedural engine on 10^5 random pairs; provenance witness completeness proven; incremental-update p99 ≤ 1ms on 10k-fact base.
- [ ] Phase Q.F (io_uring + DPDK/AF_XDP): io_uring dispatch ≥ 2× throughput at p99 parity on Linux; byte-equivalence with epoll path; AF_XDP symbol-ship ≥ 4× throughput sustained at 1000 sym/s.
- [ ] Phase Q.G (Threshold HPKE KEM): t-of-n decap correctness + below-t hiding properties green; 5-zone cross-mesh sealed-object E2E green; ceremony reuses A.2 FROST DKG infrastructure.
- [ ] Phase Q.H (Bayesian K-tuning): GP regret bound holds empirically over 10^4 workloads; ≥ 20% throughput improvement vs. static K on 5-machine-class suite; integrates with code-family dispatch (B.6.bis).
- [ ] Phase Q.I (Conformal prediction): marginal-coverage guarantee within `α + O(1/√n)`; AI-agent decision-quality E2E shows ≥ 15% fewer incorrect downstream decisions vs. boolean-only baseline.
- [ ] Phase Q.J (TLA+ capability lifecycle + FROST DKG + agent-mail): three new specs pass `make tla-check`; coverage-matrix rows added; `RevokeBeforeUse`, `NoDoubleSpend`, `KeyAgreement`, `SecretConfidentiality`, `CausalDeliveryOrdering`, `ClaimUniqueness` invariants all hold.
- [ ] Phase U (Brilliance Integration): 7-layer stack diagram materialized as `crates/fcp-protocol/src/architecture/layers.rs` + linter-enforced dependency boundaries; all 5 R3 tensions (consistency, privacy, commits, verification cost, coordination vs. typestate) have green property/conformance tests; `alien_graveyard_reachability_2026-05-12.md` lists `(file_neighbor, test_neighbor, epic_graft)` for every Q.A–Q.J pick; the `state_commit_linearizability`, `vector_commit_scheme_policy_match`, `proof_kind_dispatch_correctness`, `capability_consume_always_fenced` tests are green; the DP-vs-conformal zone-boundary ADR is published.
- [ ] Next quarterly debiasing (2026-Q3) finds zero new overclaims.
