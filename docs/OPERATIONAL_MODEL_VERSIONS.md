# Operational Model Versions

> This document defines the two operational model versions for FCP, what each
> provides, and which fwc commands require which version. V1 is the current
> transitional provisioning boundary; V2 is the converging steady-state target.
> The truth hierarchy already classifies answers as mesh-backed > host-backed >
> node-local > offline regardless of which version the operator is using.
>
> This is a cutover-audit reference, not the preferred onboarding story. Use it
> to see which operator workflows still depend on the transitional host-backed
> boundary and which ones already have a mesh-backed destination.

## V1: Host-First (Current Provisioning Boundary, Transitional)

V1 is the current provisioning and operational boundary. Operators use V1
semantics today while the mesh-native cutover (V2) converges to steady state.

### What V1 Provides

| Capability | Status | Evidence |
|------------|--------|----------|
| `fwc -> fcp-host -> connector subprocesses` | Proven | CLI integration tests, host admin API, stdio/JSON-RPC supervision |
| Host-backed runtime answers | Proven | `crates/fwc/src/truth.rs` KnowledgeState taxonomy |
| Node-local truth resolution | Proven | `crates/fwc/src/catalog.rs` runtime mode dispatch |
| Offline artifact mode (explicit) | Proven | `--offline` flag, artifact-backed discovery |
| Single-active-host deployment | Proven | One `fcp-host` instance per node |
| Zone isolation (cryptographic) | Proven | Zone encryption keys, Tailscale ACL enforcement |
| Capability tokens (CWT/COSE) | Proven | CBOR-encoded, COSE-signed, revocation-checked |
| Tamper-evident audit chain | Proven | Hash-linked events, monotonic seq, quorum checkpoints |
| Revocation enforcement | Implemented | First-class revocation objects, O(1) freshness checks |
| Egress proxy with CIDR deny | Implemented | Manifest-aware network guardrails |
| Secretless connector flows | Implemented | `credential_id` host-side injection |
| Supply chain attestations | Implemented | Registry attestation schemas, verification policy |

### What V1 Does NOT Provide

- Automatic multi-node placement or failover
- Mesh-backed answers (answers backed by distributed mesh state)
- Cross-device symbol reconstruction
- Automatic computation migration between devices
- Mesh-native gossip-based state sync as the primary truth source

### V1 Operator Contract

Treat this as the minimum honest contract for the boundary that still exists
today, not as the architecture contributors should optimize around long term.

1. Start `fcp-host` on the node where connectors will run.
2. Use `fwc --host http://<host>:<port>` for all live operations.
3. Trust host-backed answers as authoritative for current runtime state.
4. Use `--offline` explicitly when you want artifact-backed data.
5. Do not assume mesh-native features are available.

---

## V2: Mesh-Native (Steady-State Target, Converging)

V2 is the intended steady-state architecture. The mesh infrastructure (gossip,
IBLT, XOR filters, LiveTruthResolver, KnowledgeState taxonomy, symbol-first
object distribution) is built and tested. The remaining work is production
evidence and cutover gating — see `docs/FCP3_Transition_Scorecard.md`.

### What V2 Will Provide (When Operational)

| Capability | Current Status | Notes |
|------------|---------------|-------|
| Mesh-backed answers (highest confidence) | Designed | `LiveTruthResolver` with mesh strategy exists but not production-proven |
| Multi-node device mesh (Tailscale peers) | Designed | MeshNode, gossip, IBLT, XOR filters implemented but not operational default |
| Symbol-first object distribution | Implemented | RaptorQ codec, object-symbol framing, repair machinery in-tree |
| Automatic computation migration | Designed | Migration state machines exist, not operational |
| Cross-device secret reconstruction | Implemented | Shamir sharing + FROST threshold signing exist |
| Mesh-native gossip sync | Implemented | Gossip protocol with consistency checks, not production default |
| Automatic failover / placement | Designed | ObjectPlacementPolicy and RepairController exist |
| Offline resilience via symbol locality | Designed | Probabilistic availability model, not yet E2E proven |

### V2 Cutover Gates

The transition from V1 to V2 requires completing these gates:

1. Production evidence that mesh-backed answers are correct and consistent.
2. Zone-wide TruthPrecedencePolicy enforcement (all operators in a zone see the same answer).
3. Proven multi-node placement and failover for at least one real workload.
4. Mesh-native gossip as the default state sync mechanism (not just available, but default).
5. Operator documentation that teaches V2 as the primary path (this document is part of that rewrite).

The FCP3 Transition Scorecard (`docs/FCP3_Transition_Scorecard.md`) tracks
progress toward these gates. Gate 5 is addressed by the current teaching-surface
rewrite (bead z1nkz.1).

---

## FWC Command Truth-Source Matrix

Every `fwc` command still executes against the current provisioning boundary
today, but the truth hierarchy (mesh-backed > host-backed > node-local >
offline) already classifies answers regardless of version. The table below is a
cutover map: it shows which commands still depend on host-backed execution,
which ones are already honest offline artifact workflows, and where mesh-backed
truth is expected to replace the transitional path.

| Command | V1 (Host-First) | V2 (Mesh-Native) | Notes |
|---------|-----------------|-------------------|-------|
| **Discovery** | | | |
| `list` | Host-backed or offline | Will add mesh-backed source | Hybrid: `--offline` for artifact mode |
| `search` | Host-backed or offline | Will add mesh-backed source | Hybrid |
| `show` | Host-backed or offline | Will add mesh-backed source | Hybrid |
| `ops` | Host-backed or offline | Will add mesh-backed source | Hybrid |
| `schema` | Host-backed or offline | Will add mesh-backed source | Hybrid |
| `examples` | Host-backed or offline | Will add mesh-backed source | Hybrid |
| `zones` | Host-backed | Will show mesh zone topology | V1 shows host-known zones |
| **Lifecycle** | | | |
| `doctor` | Host-backed | Will add mesh health checks | V1 checks host + connector health |
| `status` | Host-backed | Will add mesh placement status | V1 shows host-supervised state |
| `health` | Host-backed | Will aggregate mesh-wide health | V1 shows node-local health |
| `install` | Host-local install | Will add mesh-coordinated install | V1 installs on current host only |
| `update` | Host-local update | Will add mesh-coordinated rollout | |
| `pin` | Host-local pin | Will pin across mesh | |
| `rollout` | Host-local rollout | Will coordinate across nodes | |
| **Execution** | | | |
| `invoke` | Host-backed (requires `--host`) | Mesh-routed execution | V1 requires live host |
| `simulate` | Host-backed (requires `--host`) | Mesh-routed simulation | V1 requires live host |
| `preflight` | Host-backed | Mesh-aware preflight | |
| `cancel` | Host-backed | Mesh-routed cancellation | |
| **Workflow** | | | |
| `task` | Offline artifact | Unchanged | Local intent compilation |
| `plan` | Offline artifact | Unchanged | Local intent compilation |
| `explain` | Offline artifact | Unchanged | Local intent compilation |
| `do` | Host-backed (materializes via host) | Mesh-routed materialization | Safe by default (simulation mode) |
| **Composition** | | | |
| `pipeline` | Host-backed | Mesh-routed pipeline | |
| `recipe` | Host-backed | Mesh-routed recipe | |
| `map` | Host-backed | Mesh-parallel map | |
| `batch-file` | Host-backed | Mesh-parallel batch | |
| **History** | | | |
| `history` | Offline artifact (local audit trail) | Will merge mesh-wide audit | |
| `replay` | Offline artifact | Unchanged | |
| `compare` | Offline artifact | Unchanged | |
| `undo` | Host-backed (reversal via host) | Mesh-routed reversal | |
| `approvals` | Host-backed | Mesh-coordinated approvals | |
| **Auth** | | | |
| `auth` | Host-local credential management | Mesh-distributed credentials | |
| `config` | Host-local configuration | Mesh-synced configuration | |
| **Export** | | | |
| `export-tools` | Offline artifact | Unchanged | |
| `serve-mcp` | Host-backed MCP server | Mesh-backed MCP server | |
| **Evidence** | | | |
| `supply-chain` | Host-local verification | Mesh-wide attestation | |
| `audit` | Host-local audit trail | Mesh-wide audit aggregation | |
| `manifest` | Offline artifact | Unchanged | |
| `net` | Host-backed | Mesh-wide network view | |
| `trace` | Host-backed | Mesh-wide trace correlation | |
| `policy` | Host-backed | Mesh-synced policy | |
| **Truth** | | | |
| `mesh explain-availability` | Shows V1 truth source classification | Will show mesh placement evidence | Already classifies answers by source |

---

## How to Check Your Current Version

```bash
# The answer classification tells you what version you're operating under.
# If you see "host-backed" or "node-local", you are on V1.
# If you see "mesh-backed", the specific answer has V2-level evidence.
fwc --host http://127.0.0.1:8787 mesh explain-availability <connector>
```

---

## References

- [README.md](../README.md) — project overview with truth hierarchy framing
- [FWC_Host_First_Truthfulness_Playbook.md](FWC_Host_First_Truthfulness_Playbook.md) — operator guide (transitional, converging toward mesh-native)
- [FCP3_Transition_Scorecard.md](FCP3_Transition_Scorecard.md) — V2 cutover gate progress
- `crates/fwc/src/truth.rs` — KnowledgeState taxonomy and LiveTruthResolver (mesh-backed resolution)
- `crates/fwc/src/catalog.rs` — command source classification and runtime mode dispatch
