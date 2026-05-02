# V2 Mesh-Native Cutover — Track C Documentation (br-hr0rr)

**Status:** Mechanism wired (2026-05-02). Operational proof pending C.1–C.5.
**Closed beads:** `flywheel_connectors-hr0rr` (parent), `hr0rr.1` [C.6],
`flywheel_connectors-4la3k` [C.7], `flywheel_connectors-nsrx3` [C.8].
**Open follow-ups:** `flywheel_connectors-ksiz8` [C.9] (this document +
mesh-availability proof harness), plus C.1–C.5 not yet broken out as
beads.

## TL;DR

The post-cutover **truth-resolution default** is `V2MeshNative` and
**Risky / Dangerous tier requests are mechanically refused** when the
host classifies itself in `DeploymentMode::Evaluation`. Operators do
not need to opt in; legacy V1 host-first behaviour is still reachable
via `FCP_TRUTH_PRECEDENCE_DEFAULT=v1` for back-compat tests and
operator-mediated rollback during a phased deployment.

The **operational-deployment** posture (multi-node failover, lease
coordination, ConnectorState replication) is **not yet proven** — the
cutover MECHANISM is in place and CI-enforced, but the operational
substrate that makes a mesh-native production deployment trustworthy
end-to-end remains under construction. See the
"What's NOT yet operational" section below.

---

## What changed at the cutover

### 1. `TruthPrecedencePolicy::default()` returns V2 (br-4la3k)

Source: `crates/fwc/src/truth.rs` (`impl Default for TruthPrecedencePolicy`).

| Before                         | After                                                                       |
|--------------------------------|------------------------------------------------------------------------------|
| `Self::v1_default()` always    | `if env requests v1 → v1_default else v2_default`                            |
| Precedence: HostBacked > Mesh… | Precedence: **MeshBacked** > HostBacked > NodeLocal > Offline                |
| `model_version: V1HostFirst`   | `model_version: V2MeshNative`                                                |

A pure-function classifier
`truth_precedence_env_requests_v1(Option<&str>)` (in the same module)
recognizes the documented synonyms — `v1`, `v1-host-first`,
`v1_host_first`, `host-first`, `host_first` (case-insensitive,
whitespace-trimmed). Any other value is **not** treated as a rollback
signal, so a typo cannot accidentally roll back the cutover.

### 2. `EnforcementCheckId::DeploymentTier` wired into the canonical pipeline (br-nsrx3)

Source: `crates/fcp-core/src/enforcement.rs` (canonical order),
`crates/fcp-host/src/enforcement.rs` (host check).

The canonical enforcement-check ordering grew from 12 to **13** entries:

```text
0  CanonicalDecode
1  ZoneMembership
2  CapabilityVerify
3  DeploymentTier         ← NEW (br-nsrx3)
4  HolderProof
5  CheckpointFreshness
6  RevocationFreshness
7  TaintApproval
8  PolicyCeiling
9  CapabilityConstraints
10 ConnectorManifest
11 Budget
12 RateLimit
```

`DeploymentTier` runs **right after** `CapabilityVerify` and **before**
the expensive crypto / freshness / budget checks, so a request that
will be refused on tier grounds short-circuits early.

The host's `DeploymentTierCheck` composes
`fcp_host::deployment_mode::admit_safety_tier(&classification, tier)`
(the predicate hr0rr.1 / CrimsonWolf shipped in commit `26d7919dd` but
left unwired). The per-(mode × tier) admission matrix is:

| Tier      | Evaluation                          | MeshActive               |
|-----------|-------------------------------------|--------------------------|
| Safe      | ALLOW                               | ALLOW                    |
| Risky     | DENY (`TIER_REQUIRES_MESH_ACTIVE`)  | ALLOW                    |
| Dangerous | DENY (`TIER_REQUIRES_MESH_ACTIVE`)  | ALLOW                    |
| Critical  | ALLOW (own elevation gating)        | ALLOW (own elevation)    |
| Forbidden | DENY (`TIER_FORBIDDEN`)             | DENY (`TIER_FORBIDDEN`)  |

`Critical` is intentionally not blocked here because it carries its
own quorum/elevation gating downstream (`ApprovalScope` +
`ApprovalToken`), and that gating already requires mesh participation
by construction.

#### Back-compat: missing fields skip the check

`EnforcementContext` grew two `Option` fields: `safety_tier` and
`deployment_classification`. Pre-nsrx3 callers that don't populate
them get `CheckOutcome::Skip` from `DeploymentTierCheck`. Hosts that
want strict enforcement MUST populate both on every
`EnforcementContextBuilder`. This is deliberately permissive so the
wiring change does not break existing host integrations during the
phased rollout.

### 3. Compile-time enforcement: `ConstraintsEnforced` typestate (m8j0q.A.6)

Source: `crates/fcp-core/src/capability.rs`. Documented in
`docs/architecture/adr/m8j0q-constraint-typestate.md`.

The dispatch boundary requires
`CapabilityToken<ConstraintsEnforced>`. The only path from
`CapabilityToken<BoundVerified>` to `ConstraintsEnforced` is
`promote_with_constraints(...)`, which **consumes self** so the
un-enforced witness cannot be reused. trybuild fixtures in
`crates/fcp-core/tests/ui/` lock this in CI:

- `bound_cannot_reach_constraints_enforced_api.rs` (compile-fail)
- `unbound_cannot_reach_constraints_enforced_api.rs` (compile-fail)
- `constraints_enforced_dispatch_compiles.rs` (must compile)

Together with `DeploymentTier`, this means a request that crosses
into the subprocess sandbox has provably:

1. been verified cryptographically (`BoundVerified`),
2. been evaluated against its capability constraints
   (`ConstraintsEnforced`), AND
3. been admitted under the host's current deployment posture
   (`DeploymentTier` allow).

---

## Operational rollback

Set the environment variable
`FCP_TRUTH_PRECEDENCE_DEFAULT=v1` before launching `fcp-host` or
`fwc` to force `TruthPrecedencePolicy::default()` back to
`v1_default()` (legacy host-first precedence). Use cases:

- Back-compat tests that depend on V1 host-first ordering.
- Operator-mediated downgrade during a phased deployment if a V2
  rollout produces unexpected resolution behaviour.
- Bisecting whether a regression is in V2-default vs. V1.

Recognized synonyms (case-insensitive, whitespace-trimmed):
`v1`, `V1`, `v1-host-first`, `V1-Host-First`, `v1_host_first`,
`V1_HOST_FIRST`, `host-first`, `Host-First`, `host_first`,
`HOST_FIRST`. **Any other value silently leaves the default at V2.**

The rollback is **not** intended for production use; production
should run on the V2 default and treat the env var as a debugging
lever only.

---

## Test coverage landing with the cutover mechanism

| Crate          | Tests added                                                                                          | Source                                          |
|----------------|------------------------------------------------------------------------------------------------------|-------------------------------------------------|
| `fwc`          | 8 new (V2-default + env-rollback matrix across 12 v1 spellings + 8 not-rollback typos + classifier) | `crates/fwc/src/truth.rs::tests`                |
| `fcp-host`     | 11 unit + 2 pipeline-integration (per-(mode × tier) admission matrix + canonical-slot pin)          | `crates/fcp-host/src/enforcement.rs::tests`     |
| `fcp-core`     | 1 new + 2 updated (`canonical_order_has_13_checks`, `…_places_deployment_tier_after_capability_verify`) | `crates/fcp-core/src/enforcement.rs::tests`   |
| `fcp-e2e`      | 1 new mechanism-proof harness (this bead, ksiz8)                                                     | `crates/fcp-e2e/tests/v2_cutover_mechanism_e2e.rs` |

Pre-existing test suites unaffected: `fcp-core` 3993 lib tests,
`fcp-host` 3270 lib tests, `fcp-policy` 47 lib tests all green
post-merge.

---

## What's NOT yet operational

The cutover **mechanism** is wired but the **operational substrate**
that would justify upgrading the quarterly Mesh-Native Architecture
row from `IMPLEMENTED` to `PROVEN` is not yet built. The original
hr0rr epic body listed five children to break out; only C.6
(DeploymentMode classifier API) and C.7/C.8 (this work) have landed.

| Child | Title                                                                                                          | Status                                  |
|-------|----------------------------------------------------------------------------------------------------------------|-----------------------------------------|
| C.1   | Mesh-backed cutover gates in scorecard (predicates from `bv --robot-triage` + `mesh explain-availability`)     | Not tracked. File when prioritized.     |
| C.2   | `ConnectorStateRoot` / `ConnectorStateObject` externalized to fcp-store symbol layer                            | Not tracked. File when prioritized.     |
| C.3   | Single-writer execution leases via HRW (rendezvous-hash) — wire `fcp-mesh/src/planner.rs` into host dispatcher  | Not tracked. File when prioritized.     |
| C.4   | Multi-node failover proof (3-node test harness, seeded partition+heal, `crates/fcp-e2e/tests/multi_node_failover.rs`) | Not tracked. File when prioritized. |
| C.5   | `LiveTruthResolver` wired into `fwc list/status/doctor` by default; downgrade only on mesh unavailability       | Partial. `LiveTruthResolver` exists; the `fwc list/status/doctor` integration is incomplete. |
| C.6   | Deprecate host-first as production mode; refuse Risky/Dangerous outside mesh-active                             | **DONE** (hr0rr.1, commit 26d7919dd).   |
| C.7   | Flip `TruthPrecedencePolicy::default()` to V2MeshNative                                                          | **DONE** (4la3k, commit 96482ca7a).     |
| C.8   | Wire `admit_safety_tier` into the enforcement pipeline                                                           | **DONE** (nsrx3, commit 868b481c8).     |
| C.9   | Documentation + mesh-availability proof acceptance                                                               | **DONE** (this doc, ksiz8).             |

Until C.1–C.5 land, the README §Limitations bullet
**"Production deployment is still single-active-host"** remains
accurate: the cutover mechanism IS wired, but the operational
posture that would justify deleting that bullet (multi-node
failover, lease coordination, mesh-replicated state) is not yet
built. The mechanism enforces the V2 contract; the substrate to
make V2 a true production guarantee is the next milestone family.

---

## Mesh-availability proof harness

A mechanism-proof E2E lives at
`crates/fcp-e2e/tests/v2_cutover_mechanism_e2e.rs`. It exercises the
post-cutover behaviours that ARE testable today against in-process
fixtures (no live mesh required):

1. `TruthPrecedencePolicy::default()` returns `V2MeshNative` —
   regression-locks 4la3k.
2. The canonical enforcement pipeline includes `DeploymentTier` at
   index 3, right after `CapabilityVerify` — regression-locks the
   nsrx3 slot invariant.
3. A `Risky` request in `Evaluation` mode is denied at
   `DeploymentTier` with `TIER_REQUIRES_MESH_ACTIVE` — locks the
   bead's marquee end-to-end behaviour.
4. The same `Risky` request in `MeshActive` mode is admitted —
   pins the not-over-blocked invariant.

Items that require a real multi-node mesh fixture (genuine
`fwc mesh explain-availability` against ≥1 connector with placement
evidence) remain `#[ignore]`d in the harness with explicit messages
pointing to C.1–C.4 as the prerequisites. The team can re-enable
those tests when the mesh-availability surface is operational.

---

## Operator quick reference

### "Is my host running V2 or rolled back to V1?"

```bash
# V2 default (production):
FCP_TRUTH_PRECEDENCE_DEFAULT=  fwc status
# (or just unset the env var)

# V1 rollback (debugging / back-compat tests only):
FCP_TRUTH_PRECEDENCE_DEFAULT=v1 fwc status
```

The host's boot log records the active `DeploymentMode` (Evaluation
vs. MeshActive) and the categorical `DeploymentClassificationReason`.
See `fcp_host::deployment_mode::emit_boot_log`.

### "Why is my Risky operation being refused?"

If `fcp-host` is in `DeploymentMode::Evaluation` (insufficient mesh
quorum / lease coordinator unreachable / stale revocation snapshot),
the `DeploymentTier` enforcement check refuses with reason code
`TIER_REQUIRES_MESH_ACTIVE`. The structured denial explanation
includes the requested tier, the current mode, and the categorical
classification reason — operators can see exactly which signal made
the host non-mesh-active.

To clear the refusal: bring up enough healthy mesh peers
(`MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE`), confirm the lease coordinator
is reachable, and wait for the next health-check cycle.

### "I'm running a single-host evaluation deployment and need a Risky operation through."

The supported path is to run a multi-node deployment. The deliberate
design choice (CrimsonWolf, hr0rr.1) is that production-class Risky
operations require mesh participation; single-host deployments are
explicitly Evaluation-mode and refuse those tiers by construction.

There is no "force allow" override — the env-var rollback only
changes truth precedence, not tier admission. If the host classifies
itself in Evaluation mode, Risky/Dangerous requests refuse regardless
of `FCP_TRUTH_PRECEDENCE_DEFAULT` setting.

---

## Cross-references

- ADR: `docs/architecture/adr/m8j0q-constraint-typestate.md` — typestate ladder for constraint enforcement
- ADR: `docs/architecture/adr/m8j0q-emergency-revocation-protocol.md` — kill-switch / panic-button protocol
- ADR: `docs/architecture/adr/m8j0q-revocation-cascade.md` — issuer-chain revocation walker
- Source: `crates/fwc/src/truth.rs` — `TruthPrecedencePolicy`, V1/V2 defaults, env-var classifier
- Source: `crates/fcp-host/src/deployment_mode.rs` — `DeploymentMode`, `MeshQuorumSignals`, `admit_safety_tier`
- Source: `crates/fcp-host/src/enforcement.rs` — `DeploymentTierCheck` and the integrated `EnforcementPipeline`
- Source: `crates/fcp-core/src/enforcement.rs` — `EnforcementCheckId`, canonical order
- E2E: `crates/fcp-e2e/tests/v2_cutover_mechanism_e2e.rs` — this bead's mechanism-proof harness
- Quarterly: `docs/quarterly/2026-Q2-claims-vs-reality.md` — reconciliation source for status-row deltas
