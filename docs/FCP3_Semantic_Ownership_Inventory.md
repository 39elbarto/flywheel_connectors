# FCP3 Semantic Ownership Inventory

> **Bead**: `flywheel_connectors-0aczd.1` — [FCP3/P7.4]
> **Author**: SandyBridge (2026-04-19)
> **Supersedes**: the earlier phase-1 inventory in this file
> **Purpose**: Explicitly inventory the semantic ownership still trapped in `fcp-core`, distinguish acceptable shared residue from ownership blur, and name the intended long-term owner for every remaining meaning.

---

## 1. Current Boundary Snapshot

The repository now has three explicit semantic owner crates:

| Semantic domain | Intended owner crate | Current physical definition reality |
|-----------------|----------------------|-------------------------------------|
| Execution / connector lifecycle | `fcp-kernel` | Mostly still defined in `fcp-core`, then re-exported by `fcp-kernel` |
| Zone / capability / provenance policy | `fcp-policy` | Mostly still defined in `fcp-core`, then re-exported by `fcp-policy` |
| Audit / revocation / checkpoints / supply chain evidence | `fcp-evidence` | Mostly still defined in `fcp-core`, then re-exported by `fcp-evidence` |

That means `fcp-core` is no longer just a shared primitive crate. It is still the physical definition site for most platform semantics, while the split crates act as the semantic facade. This bead inventories what remains there and which residues are acceptable versus still architecturally blurry.

---

## 2. What Counts As Acceptable Residue

Only the following kinds of meaning are acceptable to remain in `fcp-core` after the larger carve-out:

| Residue class | Examples in `fcp-core` | Why acceptable |
|---------------|------------------------|----------------|
| Shared error/result primitives | `error.rs`, `FcpError`, `FcpResult` | Cross-cut every crate; narrow, mechanical, and not domain-owning |
| Mechanical helper surfaces | `tool_schema`, `util` | Support code generation / schema plumbing without owning business semantics |
| External type convenience re-exports | `async_trait`, `DateTime`, `Utc`, `Uuid` | Ergonomic compatibility only; not protocol semantics |

Everything else below should be treated as temporary migration residue, not as a justified permanent home.

---

## 3. Assigned Semantics Still Physically Trapped In `fcp-core`

These domains already have an intended owner crate, but `fcp-core` is still the place where the types actually live.

| `fcp-core` module group | Semantic payload still trapped there | Intended owner | Status |
|-------------------------|--------------------------------------|----------------|--------|
| `connector`, `protocol`, `operation`, `provisioning` | invocation requests/responses, sessions, connector traits, operation metadata, provisioning contracts | `fcp-kernel` | Assigned owner, still physically trapped |
| `event`, `health`, `lifecycle`, `connector_descriptors` | subscription/event contracts, self-check and readiness contracts, lifecycle state machine, descriptor/readiness metadata | `fcp-kernel` | Assigned owner, still physically trapped |
| `capability`, `policy`, `provenance`, `zone_keys`, `posture`, `enrollment` | zone model, capabilities, taint/provenance, zone keys, posture / admission semantics | `fcp-policy` | Assigned owner, still physically trapped |
| `audit`, `checkpoint`, `revocation`, `supply_chain` | audit chain, receipts, checkpoints, revocation, verification evidence | `fcp-evidence` | Assigned owner, still physically trapped |

These are not ownership mysteries anymore. They are migration debt: the owner is known, but the definitions have not yet moved.

---

## 4. Remaining Ownership Blur Inside `fcp-core`

This is the actual phase-7 residue that still makes `fcp-core` a semantic junk drawer. Each row names the still-live meaning, the best current target owner, and whether that target is settled or still provisional.

| `fcp-core` module | Still-live meaning | Intended long-term owner | Why it is still blur |
|-------------------|--------------------|--------------------------|----------------------|
| `connector_state` | connector state roots, snapshots, deltas, resumable state contracts | dedicated durability/state contract, with `fcp-kernel` as temporary facade | state durability is not a shared primitive and not purely execution |
| `crdt` | replicated state merge semantics | dedicated durability/state contract | CRDT semantics are durable data-model ownership, not generic core glue |
| `object` | content-addressed object metadata, retention, placement hooks | dedicated object/durability contract, likely adjacent to `fcp-store` | object semantics are still bundled into the compatibility barrel |
| `lease` | execution / migration lease contracts and transfer semantics | temporary `fcp-kernel`, eventual dedicated placement/execution contract if the split continues | lease semantics straddle execution and placement today |
| `quorum` | node signatures, quorum policy, degraded-mode safety contracts | temporary `fcp-kernel`, eventual trust/placement contract if needed | trust coordination still lives in the generic barrel |
| `credential` | credential references and access semantics | dedicated credential / secret-management contract | credentials are neither operator-only nor shared primitive |
| `secret` | secret material semantics and recovery/share boundaries | bootstrap / secret-management contract | secret handling should not remain an unowned core grab-bag |
| `ratelimit` | rate limit declarations, enforcement modes, throttle signals | split between `fcp-policy` policy semantics and `fcp-kernel` execution reporting, or a future dedicated `fcp-ratelimit` contract | currently mixes governance semantics with execution-facing status types |
| `release` | release / rollout metadata beyond pure execution control | supply-chain / registry-facing contract | release semantics are distinct from the kernel lifecycle core |
| `connector_artifacts` | connector package / artifact metadata | registry / supply-chain contract | artifact identity and packaging are not general core primitives |
| `enforcement` | canonical enforcement result and ordering semantics | `fcp-policy` | implementation lives in `fcp-host`, but canonical ordering/results still need a clean policy-owned surface |
| `pcs` | post-compromise security (TreeKEM-style group ratcheting, epoch state, forward secrecy) | co-owner with `fcp-policy` for zone-level security, or dedicated `fcp-pcs` | `pub mod pcs` (not wildcard re-exported) — accessible as `fcp_core::pcs::*` but not via `use fcp_core::*` |

**Note**: `telemetry.rs` exists as a 46KB source file but is **not declared as a module** in `lib.rs` and is therefore dead code. It should either be deleted or wired in during the 0aczd.2 migration.

None of these rows qualify as acceptable permanent residue. Each still represents either missing crate carving or an unresolved owner boundary.

---

## 5. Residue Classification

This is the final phase-7 classification for `fcp-core`.

### Acceptable Shared Primitive Residue

- `error.rs`
- `tool_schema`
- `util`
- external convenience re-exports (`async_trait`, `DateTime`, `Utc`, `Uuid`)

### Assigned But Still Physically Trapped

- Execution semantics already claimed by `fcp-kernel`
- Policy semantics already claimed by `fcp-policy`
- Evidence semantics already claimed by `fcp-evidence`

### Still Ownership-Blurred And Must Move Or Be Narrowed

- `connector_state`
- `crdt`
- `object`
- `lease`
- `quorum`
- `credential`
- `secret`
- `ratelimit`
- `release`
- `connector_artifacts`
- canonical enforcement-order/result types currently implied by `enforcement`
- `pcs` (post-compromise security, `pub mod` but not wildcard re-exported)
- `telemetry.rs` (dead code: 46KB file not declared as module in `lib.rs`)

---

## 6. Why `fcp-core` Still Functions As A Semantic Junk Drawer

Three active mechanisms keep `fcp-core` in that role:

1. `crates/fcp-core/src/lib.rs` still wildcard re-exports nearly every internal module, so importing `fcp_core::*` continues to expose almost the entire platform semantic surface.
2. The split owner crates (`fcp-kernel`, `fcp-policy`, `fcp-evidence`) currently re-export from `fcp-core`, which means semantic ownership is declared socially but not yet enforced mechanically.
3. Several non-primitive domains do not yet have a crisp owner crate at all (`connector_state`, `object`, `credential`, `secret`, `pcs`, parts of rate limiting / release / leases). Additionally, `telemetry.rs` (46KB) exists as dead code — not wired into `lib.rs`.

Until those three conditions change, `fcp-core` remains more than a primitive substrate.

---

## 7. Concrete Exit Criteria For `fcp-core`

`fcp-core` stops being a semantic junk drawer only when all of the following are true:

- The split owner crates define their own types instead of re-exporting them from `fcp-core`.
- `fcp-core` no longer wildcard re-exports domain modules that belong to `fcp-kernel`, `fcp-policy`, or `fcp-evidence`.
- Every blurred module in Section 4 is either moved to a real owner crate or explicitly reduced to a narrow shared primitive with a documented justification.
- New work follows `docs/FCP3_Transition_Guardrails.md` and does not add fresh semantic surface to `fcp-core` except documented shared primitives.

---

## 8. Recommended Follow-On Work

This inventory implies the next migration slices:

1. Move physically trapped execution/policy/evidence definitions out of `fcp-core` and invert the re-export direction.
2. Create or name the missing long-term homes for state/object/credential/secret/pcs semantics, and either wire in or delete the dead `telemetry.rs` file.
3. Replace `fcp-core` wildcard exports with a deliberately narrow primitive surface.

This document is the phase-7 reference for `flywheel_connectors-0aczd.2`: everything in Section 4 must move, narrow, or be deleted.
