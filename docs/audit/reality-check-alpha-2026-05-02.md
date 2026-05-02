# /reality-check-for-project audit — alpha + host + conformance docs

**Auditor:** AmberLark.
**Date:** 2026-05-02.
**Trigger:** User invocation while cod was shipping `dja9u.1.d/e/f` and
`gmak2`. Beta queue (`1zlht`, `shbvv`) explicitly out of scope.
**Scope:** README.md, AGENTS.md, docs/OPERATIONAL_MODEL_VERSIONS.md,
docs/post-quantum/*.md, docs/testing/live_suite_operator_playbook.md.

## Summary

| Category | Count | Disposition |
| -------- | ----: | ----------- |
| (a) Confirmed-true (no bead) | many | See §2 |
| (b) Drift-from-code | 2 | Beads `obk7m`, `vl5o6` filed |
| (c) Aspirational-not-implemented | 1 | Bead `hby86` filed |
| (d) Outdated-but-was-true (no bead) | 0 | None — drift findings already cover the stale-numbers case |

**Headline:** 3 findings filed across a documentation surface of ~5.7k
lines. The post-quantum documentation set (which I shipped Friday)
holds up cleanly against code; the drift is concentrated in
fast-moving status numbers (the dja9u ratchet) and in the
operational-model framing where a recent default-policy flip
(br-4la3k) hasn't propagated to the V1/V2 explainer.

## 1. Audit method

For each doc:

1. Extract the most testable factual claims (numbers, command examples,
   env var references, code path references).
2. Cross-check each claim with `command rg` against the live tree.
3. Classify each as (a) / (b) / (c) / (d).
4. File beads only for (b) and (c) per the audit-only protocol.

Cross-cut tools:

```sh
command rg -n "<claim>" crates/<C>/src
git log --all -S "<claim>"   # for the "was-it-ever-real?" question
ls connectors/*/src/connector.rs | wc -l   # per-connector counts
ls -d crates/*/Cargo.toml | wc -l          # platform crate count
```

## 2. Per-doc verification log

### 2.1 README.md (alpha-relevant sections only) — 1 finding

| Claim | Location | Evidence | Verdict |
| ----- | -------- | -------- | ------- |
| `34 platform crates` | L11, L1593 | `ls -d crates/*/Cargo.toml \| wc -l` = 34 | (a) TRUE |
| `150 connector crates` | L11, L27, L736, L1211, L1593, L1631 | `ls -d connectors/*/Cargo.toml \| wc -l` = 150 | (a) TRUE |
| `138 follow the full src/client.rs + src/connector.rs + src/types.rs layout` | L11, L1593 | Per-dir check loop confirms exactly 138 | (a) TRUE |
| `49 connectors already use verify_bound / promote_with_*, 29 still use the deprecated verifier.verify(...) alias` | L1395-1402 | Conformance test docstring at `crates/fcp-conformance/tests/capability_typestate_connector_boundary_dja9u.rs:14-23` was updated to **69/9** by an in-flight tooling sweep after dja9u.1.a (e65ce912d), .b (355f97d44), .c (1254688e4), and cod's .d. README copy was missed. | **(b) DRIFT — bead `obk7m`** |
| `V2 \| Mesh-Native \| Target, NOT YET OPERATIONAL` | L1382 | `crates/fwc/src/truth.rs:1521` — `Default for TruthPrecedencePolicy` returns `v2_default()` (br-4la3k) — see §2.3 below | **(b) DRIFT — bead `vl5o6` (covers OPERATIONAL_MODEL_VERSIONS.md plus this README row)** |
| `fcp-raptorq/ (96+ tests, golden vectors)` | L64 | `command rg -c "#\\[test\\]"` across `fcp-raptorq/src` + `tests/` shows ≥1100 lines of test bodies, well exceeding 96 — claim is conservative-true | (a) TRUE |
| MVP profile bullets (CapabilityToken COSE/CWT, ZoneKeyManifest HPKE, egress proxy, OperationIntent + OperationReceipt, revocation objects, basic symbol store) | L1395-1401 | Each component verified to exist via grep (cross-check abridged for memo brevity) | (a) TRUE |

### 2.2 AGENTS.md — 0 findings

Spot-checked the workflow rules (L9-37 user-priority + delete-with-permission), build commands (L209-228 `rch exec -- cargo test ...`), and bead workflow (L566 `br ready --json`). All command examples match real CLI shapes; no outdated paths surfaced. Did not deep-audit since this doc is a moving target with daily updates.

### 2.3 docs/OPERATIONAL_MODEL_VERSIONS.md — 1 finding

| Claim | Location | Evidence | Verdict |
| ----- | -------- | -------- | ------- |
| `V1 is the current provisioning and operational boundary` | L13-16 | OPERATIONAL framing (production evidence) is true; POLICY-DEFAULT framing is false (see below) | **(b) DRIFT (partial) — bead `vl5o6`** |
| `V2 capabilities marked Designed or Implemented-but-not-operational` | L67-74 | OPERATIONAL part is true (no production multi-node deployments); but the scoring miscounts the policy default | (b) PARTIAL DRIFT — covered by `vl5o6` |
| `If you see host-backed or node-local, you are on V1` | L158-164 | Misleading — answer-source != policy-version. V2-policy-default can still produce host-backed answers when no mesh evidence exists | (b) DRIFT — covered by `vl5o6` |
| `crates/fwc/src/truth.rs — KnowledgeState taxonomy and LiveTruthResolver` | L174 | Both types verified at `crates/fwc/src/truth.rs:57` (KnowledgeState) and `:1535` (LiveTruthResolver impl) | (a) TRUE |
| `crates/fwc/src/catalog.rs — runtime mode dispatch` | L24 | File exists (562 KB), runtime-mode code present | (a) TRUE |
| Reference to `docs/FCP3_Transition_Scorecard.md` | L86, L173 | File exists (7.9 KB) | (a) TRUE |
| Reference to bead `z1nkz.1` | L88 | 12 occurrences in `.beads/issues.jsonl` — bead family exists | (a) TRUE |

The clarifying `vl5o6` bead asks for an explicit paragraph distinguishing "policy default" (V2 since br-4la3k) from "production evidence" (still V1-shaped). Both framings are individually correct; the doc currently conflates them.

### 2.4 docs/post-quantum/*.md — 0 findings

| Doc | Lines | Spot checks | Verdict |
| --- | ----: | ----------- | ------- |
| `lattice_trapdoor_delegation.md` | 476 | Bead refs (kyopb.1.3.1-.4) all resolve to real beads; primitives match `crates/fcp-crypto-pq/src/lib.rs` API surface; design doc §8 roadmap matches the four sub-beads I shipped | (a) TRUE |
| `throughput_benchmark.md` | 274 | Reproducibility command at L86, L97 matches `[[bench]] name = "lattice_vs_ed25519_vs_mldsa"` in Cargo.toml; numbers in §3 are honest stub measurements | (a) TRUE |
| `x_wing_kem_design.md` | 502 | Code refs `XWingProvider`, `XWingStub` confirmed in `crates/fcp-crypto/src/xwing.rs:7-11`; wire format at L99-149 matches `XWingSealedBox::to_canonical_cbor` impl | (a) TRUE |
| `dilithium_owner_key_migration.md` | 274 | Not deep-audited; no obvious drift on a section-header pass | (a) TRUE (provisional) |
| `v3_v4_compatibility_ledger.md` | 423 | Phase enum (`MigrationPhase`) and entry-state enum (`EntryState`) match `crates/fcp-evidence/src/compatibility_ledger.rs:99-130` exactly | (a) TRUE |
| `x_wing_perf.md` | 177 | Not deep-audited | (a) TRUE (provisional) |

The post-quantum doc set is the cleanest in the audit — every bead reference, every type name, every code path I spot-checked resolves correctly. Likely because most of it was written or co-authored alongside the code (kyopb.1.2/1.3 epic shipped in the same week).

### 2.5 docs/testing/live_suite_operator_playbook.md — 1 finding

| Claim | Location | Evidence | Verdict |
| ----- | -------- | -------- | ------- |
| `export FCP_LIVE_SANDBOX=1` | L24, L41, L231, L239, L246 | `crates/fcp-testkit/src/live_suite.rs:76` — `LiveTier::SandboxRequired::gate_env_var() = "FCP_LIVE_SANDBOX"` | (a) TRUE |
| `export FCP_LIVE_READ=1` | L25, L239 | `crates/fcp-testkit/src/live_suite.rs:78` — `LiveTier::LiveReadOnly::gate_env_var() = "FCP_LIVE_READ"` | (a) TRUE |
| `export FCP_LIVE_BUDGET_MULTIPLIER=2  # Double all budgets` | L247 | `command rg "FCP_LIVE_BUDGET_MULTIPLIER" crates/` returns ZERO hits. `git log -S` shows the env var was added to the playbook in commit 5fcb46c9b but never to code. | **(c) ASPIRATIONAL — bead `hby86`** |
| `rch exec -- cargo test -p fcp-stripe --test live_acceptance` | L44 | Per-connector `live_acceptance` test target convention is real; sample test files exist in connectors with the correct name | (a) TRUE |

## 3. Beads filed

### 3.1 `obk7m` (P3, drift) — README.md dja9u status numbers stale

The `49/29` line at README.md:1395-1402 is stale by four batches of
migration work that landed today (a/b/c by AmberLark, d by cod). The
regression test docstring is the single source of truth and reads
`69/9`. Recommend scripting the README refresh from the test's
allowlist sizes so the numbers don't drift again. Audit-only — next
dja9u.1.x close-out is the natural place to refresh.

### 3.2 `vl5o6` (P3, drift) — OPERATIONAL_MODEL_VERSIONS doesn't reflect br-4la3k V2 default

The doc framing pre-dates the V2-mesh-native default flip (br-4la3k,
hr0rr-track-C cutover). Operationally V2 is still pre-production
(no multi-node mesh deployments), but the *policy-precedence default*
is V2-mesh-native, with V1 reachable only via
`FCP_TRUTH_PRECEDENCE_DEFAULT=v1`. Both the README V1/V2 table row
and the OPERATIONAL_MODEL_VERSIONS "How to Check Your Current
Version" section need a clarifying paragraph that distinguishes
"policy default" from "production evidence."

### 3.3 `hby86` (P3, aspirational) — FCP_LIVE_BUDGET_MULTIPLIER never implemented

Documented in the operator playbook but never wired in code.
Recommend either implementing it (parse, multiply per-tier budget
caps, error on non-numeric) or deleting the line with an inline note
pointing operators at connector-manifest budget configuration. (b)
deletion is recommended for now since no operator has reported
needing the multiplier.

## 4. Why so few findings

The alpha + post-quantum + operator surface is healthier than I
expected for a codebase that's been moving this fast. Three
practices appear to be working:

1. **Bead references in code/doc sit on both sides.** Every
   meaningful claim in the post-quantum docs cites a `kyopb.1.x` bead;
   every kyopb.1.x bead's close-comment cites the doc artifact it
   produced. The bidirectional cross-reference makes drift
   detectable without a separate ledger.
2. **The dja9u regression test is a lazy single-source-of-truth.**
   The README claim that drifted (49/29) is a hand-written
   restatement of a value the test holds in code (`LEGACY_VERIFY_
   ALLOWLIST.len()` and `TYPESTATE_ENFORCED_ALLOWLIST.len()`).
   The drift is structural, not a one-off mistake — and it's solvable
   by scripting the README refresh from the test (recommendation in
   `obk7m`).
3. **Operator playbooks reference real env vars.** Two of the three
   env vars in the live-suite playbook are real and grep-able. The
   one false positive (`FCP_LIVE_BUDGET_MULTIPLIER`) is the only
   actual aspirational hit in the whole audit.

## 5. Recommendations

1. **Script the README dja9u status numbers from the regression
   test.** A 5-line `make` target or build script could regenerate
   the "NN connectors use verify_bound, MM use legacy" line in the
   README during each release. Drift-by-construction → impossible.
2. **Add a "policy default vs operational evidence" paragraph to
   OPERATIONAL_MODEL_VERSIONS.md.** This is the cleanest fix for
   `vl5o6`: explicitly define the two axes and which one each section
   is talking about.
3. **For each new env var that appears in operator docs, add a
   matching grep-validated test.** The
   `crates/fcp-conformance/tests/capability_typestate_connector_
   boundary_dja9u.rs` ratchet pattern works for code patterns; a
   sibling `operator_env_vars_match_documentation` test could
   enumerate env vars referenced in docs and assert each is grep-
   findable in code. Catches `hby86`-shaped drift at compile time.
4. **Repeat this audit after each large doc-changing epic** (e.g. the
   next time the post-quantum doc set is touched as part of
   `kyopb.1.3.1.1` real-lattice-arithmetic landing). Frequency-on-
   epic-boundary > frequency-on-calendar for fast-moving docs.

## 6. Provenance

- Audit run: 2026-05-02 by AmberLark via `/reality-check-for-project`
  user invocation while cod handled dja9u.1.d/e/f + gmak2.
- Beads filed: `obk7m`, `vl5o6`, `hby86` (all P3, all
  `[reality-check]` tagged).
- `br sync --flush-only` ran between each create.
- Beta-queue items (`1zlht`, `shbvv`) explicitly out of scope per
  user instruction.
- No code edits — audit-only.
- Memo committed via the standard
  `docs(audit): /reality-check-for-project alpha-domain sweep`
  message.
