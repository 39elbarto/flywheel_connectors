# Claims vs Reality Quarterly Report — Q2 2026

> Period: Q2 2026 (April–June)
> Current auditor: GoldenFinch (Codex)
> Prior baseline: SunnyMoose MOR/C2.4 audit, 2026-04-10
> Current snapshot date: 2026-05-03 (pre-docs commit `7f0bd5e7b`)
> Capability-token follow-up: 2026-05-05 (`flywheel_connectors-01yaq`)
> Quarter note: The date is still Q2, so this report was revised in-place
> rather than split into a Q3 report.

## Summary

GoldenFinch re-ran the README claims-vs-reality pass after the May 2026
security, E2E, conformance, golden-vector, and fuzz waves. Code remains the
ground truth: the README's 16-row feature table was compared against live
source files, crate-local tests, E2E scenarios, conformance harnesses, fuzz
targets, and open security findings.

**Result at 2026-05-03:** one status overclaim, eleven status underclaims,
one connector-inventory underclaim, and one stale evidence path.

- **Overclaim fixed at the 2026-05-03 snapshot:** `Capability Tokens (CWT/COSE)`
  was no longer `PROVEN` because open finding `flywheel_connectors-01yaq` showed
  that `CapabilityToken<BoundVerified>` accepted instance-agnostic tokens.
- **2026-05-05 follow-up:** `flywheel_connectors-01yaq` is repaired in code and
  tests: `BoundVerified` now requires an explicit `INSTANCE_ID` claim, so the
  README Capability Tokens row has been restored to `PROVEN`.
- **Underclaims fixed:** rows with direct E2E/conformance/golden proof moved
  from `IMPLEMENTED` to `PROVEN`.
- **Still intentionally limited:** `Zone Isolation` remains `LIMITED` because
  `allowed_zones` is opt-in in the host-backed path.
- **Still not operational:** `Mesh-Native Architecture` remains
  `STEADY-STATE TARGET (NOT YET OPERATIONAL)` under the br-lvz4t pin.

There is no README status label named "Production"; this report uses the
README's status vocabulary. `PROVEN` means direct proof in this repository, not
live multi-node production deployment.

## Feature Status Delta Table

| Feature | README before 2026-05-03 pass | README after pass | Verdict | Evidence checked | Notes |
|---------|--------------------------------|-------------------|---------|------------------|-------|
| Host-First Control Plane | `IMPLEMENTED` | `PROVEN` | Underclaim fixed | `crates/fcp-conformance/tests/host_invoke_loop_conformance.rs`, `crates/fcp-e2e/tests/capability_enforcement_concurrent_e2e.rs`, `crates/fcp-host/src/{supervisor,enforcement,health}.rs` | Current operator path has direct conformance and concurrent E2E proof. |
| Truthful Runtime Resolution | `IMPLEMENTED` | `PROVEN` | Underclaim fixed | `crates/fwc/src/{truth,catalog}.rs`, `crates/fwc/tests/{cual_integration,readme_status_pinning}.rs` | Truth-source taxonomy and README drift pinning are tested. |
| Zone Isolation | `LIMITED` | `LIMITED` | Accurate | `crates/fcp-core/src/{zone_keys,pcs,policy}.rs`, `crates/fcp-host/src/bin/fcp-host.rs`, host/e2e capability tests | Remains limited because empty `allowed_zones` is still permissive in the host-backed path. |
| Capability Tokens (CWT/COSE) | `PROVEN` | `IMPLEMENTED` | Overclaim fixed at 2026-05-03; restored 2026-05-05 | `crates/fcp-crypto/src/cose.rs`, `crates/fcp-core/src/capability.rs`, `crates/fcp-core/tests/capability_verifier_predicate_matrix.rs`, `crates/fcp-conformance/tests/capability_*.rs`, `crates/fcp-host/tests/capability_token_typestate_runtime.rs` | Historical May 3 result was blocked by open `flywheel_connectors-01yaq`; the follow-up fix now rejects missing `INSTANCE_ID` for `BoundVerified`. |
| Tamper-Evident Audit | `PROVEN` | `PROVEN` | Accurate | `crates/fcp-audit/`, `crates/fcp-core/src/audit.rs`, audit golden/vector tests | Hash-linked chain and checkpoints remain directly proven. |
| Revocation | `IMPLEMENTED` | `PROVEN` | Underclaim fixed | `crates/fcp-e2e/tests/revocation_cascade_e2e.rs`, `crates/fcp-e2e/tests/capability_enforcement_concurrent_e2e.rs`, `crates/fcp-conformance/tests/host_invoke_loop_conformance.rs` | Revocation freshness and rejection are now in E2E/conformance paths. |
| Egress Proxy | `IMPLEMENTED` | `PROVEN` | Underclaim + stale path fixed | `crates/fcp-sandbox/src/egress.rs`, `crates/fcp-e2e/tests/egress_proxy_e2e.rs` | README previously pointed at removed `fcp-host/src/egress.rs`. |
| Secretless Connectors | `IMPLEMENTED` | `IMPLEMENTED` | Accurate | `crates/fcp-sandbox/src/egress.rs`, credential authorization/injection tests | Integrated path exists; broad connector-family proof is still not enough for `PROVEN`. |
| Threshold Owner Key | `IMPLEMENTED` | `PROVEN` | Underclaim fixed | `crates/fcp-bootstrap/src/ceremony.rs`, `crates/fcp-e2e/tests/threshold_owner_key_e2e.rs` | FROST DKG/signing/survivor-quorum E2E exists; universal default remains a separate rollout choice. |
| Threshold Secrets | `IMPLEMENTED` | `PROVEN` | Underclaim fixed | `crates/fcp-core/src/secret.rs`, `crates/fcp-e2e/tests/threshold_secrets_e2e.rs` | Shamir + HPKE sealing + k-of-n reconstruction and fail-closed cases are directly proven. |
| Supply Chain Attestations | `IMPLEMENTED` | `PROVEN` | Underclaim fixed | `crates/fcp-registry/src/lib.rs`, `crates/fcp-e2e/tests/supply_chain_attestation_e2e.rs`, registry tests | Real cosign/TUF E2E and registry hardening exist; external release distribution remains outside repo proof. |
| Offline Access | `IMPLEMENTED` | `PROVEN` | Underclaim fixed | `crates/fcp-e2e/tests/{offline_access,offline_repair}_e2e.rs`, `crates/fcp-store/src/offline.rs` | Both connector-side offline queue/cache and store repair flows have E2E proof. |
| Mesh-Stored Policy Objects | `IMPLEMENTED` | `PROVEN` | Underclaim fixed | `crates/fcp-e2e/tests/mesh_policy_object_e2e.rs`, `crates/fcp-core/src/policy.rs` | Owner-signed bundles, gossip, evaluation, audit denial, and revocation are proven. |
| Symbol-First Protocol | `IMPLEMENTED` | `PROVEN` | Underclaim fixed | `crates/fcp-e2e/tests/symbol_first_protocol_e2e.rs`, `crates/fcp-raptorq/`, golden vectors | Real RaptorQ encode/decode and loss/fungibility scenarios exist. |
| Mesh-Native Architecture | `STEADY-STATE TARGET (NOT YET OPERATIONAL)` | `STEADY-STATE TARGET (NOT YET OPERATIONAL)` | Accurate | `crates/fwc/tests/readme_status_pinning.rs`, `crates/fwc/src/main.rs`, `crates/fwc/src/truth.rs`, `crates/fcp-mesh/src/` | Building blocks are tested; normal operator invoke still routes through host `/rpc/invoke`. |
| Computation Migration | `IMPLEMENTED` | `PROVEN` | Underclaim fixed | `crates/fcp-e2e/tests/computation_migration_reference.rs`, `crates/fcp-kernel/src/computation_migration.rs`, `crates/fcp-store/src/resume_handshake.rs` | Default E2E feature set includes the reference migrate/resume proof. |

## Inventory Claims Checked

| Claim | README before | Live measurement | Verdict | Command shape |
|-------|---------------|------------------|---------|---------------|
| Platform crates under `crates/` | 34 | 34 | Accurate | `rg --files crates \| rg '/Cargo.toml$'` |
| Connector crates under `connectors/` | 150 | 150 | Accurate | `rg --files connectors \| rg '/Cargo.toml$'` |
| Connector manifests | 150 | 150 | Accurate | `rg --files connectors \| rg '/manifest\\.toml$'` |
| Connector tests | 150 | 150 | Accurate | Per-connector scan for `#[cfg(test)]`, `#[test]`, proptest, wiremock, or mock tests |
| `ConnectorErrorMapping` coverage | 150 | 150 | Accurate | `rg -l 'ConnectorErrorMapping' connectors` grouped by connector |
| Full `client.rs`/`connector.rs`/`types.rs` layout | 138 | 138 | Accurate | Per-connector file-existence scan |
| Explicit `OperationInfo` structs | 137 | 147 | Underclaim fixed | `rg -l 'OperationInfo' connectors` grouped by connector |
| Fuzz targets | not summarized in README feature table | 176 | Evidence surfaced | `rg --files fuzz/fuzz_targets` |

## Overclaims Found

1. **Capability Tokens (CWT/COSE): `PROVEN` -> `IMPLEMENTED`**
   - Concrete issue: `flywheel_connectors-01yaq`.
   - Why it matters: the docs and typestate ADRs describe `BoundVerified` as full instance-binding proof, but the 2026-05-03 live code/tests allowed promotion of instance-agnostic tokens.
   - README action: downgraded the row and made the caveat explicit while preserving the COSE/CWT evidence.
   - 2026-05-05 follow-up: repaired. `verify_bound` and
     `promote_with_instance` now require a text `INSTANCE_ID` claim before
     producing `BoundVerified`, and the README row is back to `PROVEN`.

## Underclaims Found

1. **Host-First Control Plane:** direct host invoke conformance and concurrent capability E2E justify `PROVEN`.
2. **Truthful Runtime Resolution:** tested truth-source taxonomy and README drift pinning justify `PROVEN`.
3. **Revocation:** revocation-cascade and concurrent freshness E2E justify `PROVEN`.
4. **Egress Proxy:** real `EgressGuard` E2E denial/audit proof justifies `PROVEN`.
5. **Threshold Owner Key:** FROST owner-key E2E justifies `PROVEN`.
6. **Threshold Secrets:** Shamir/HPKE threshold-secret E2E justifies `PROVEN`.
7. **Supply Chain Attestations:** real cosign/TUF E2E justifies `PROVEN` for repo-local verification.
8. **Offline Access:** offline cache/queue plus store repair E2E justify `PROVEN`.
9. **Mesh-Stored Policy Objects:** mesh policy object E2E justifies `PROVEN`.
10. **Symbol-First Protocol:** RaptorQ symbol E2E/golden proof justifies `PROVEN`.
11. **Computation Migration:** reference connector migrate/resume E2E justifies `PROVEN`.
12. **Connector inventory:** `OperationInfo` coverage is 147 connectors, not 137.

## Still-Honest Limits

- `Zone Isolation` stays `LIMITED`; the host-backed path still has an opt-in
  `allowed_zones` branch.
- `Secretless Connectors` stays `IMPLEMENTED`; credential injection and
  authorization exist, but broad connector-family proof is still incomplete.
- `Mesh-Native Architecture` stays `STEADY-STATE TARGET (NOT YET OPERATIONAL)`;
  mesh components are real, but production operator invoke remains host-first.

## Debiasing Notes

- The May security/evidence wave created more underclaims than overclaims.
  The README lagged behind new E2E/conformance evidence in 11 rows.
- The single overclaim was important: status labels must incorporate known
  open security findings, not just count tests. `flywheel_connectors-01yaq`
  prevented the capability-token row from staying `PROVEN` at the 2026-05-03
  snapshot; the 2026-05-05 follow-up repaired that blocker.
- `PROVEN` should remain an evidence label, not a production-deployment label.
  The Mesh-Native row stays explicitly non-operational even though many mesh
  components are implemented and tested.
- Future quarterly passes should always re-measure connector inventory counts;
  `OperationInfo` coverage moved from 137 to 147 without the README being
  updated.

## Actions Taken

- README feature status labels reconciled to the 2026-05-03 live checkout.
- README audit-status note updated to point at this quarterly report.
- README connector inventory corrected from 137 to 147 `OperationInfo` structs.
- README egress evidence paths corrected from removed `fcp-host/src/egress.rs`
  to `fcp-sandbox/src/egress.rs` plus the E2E scenario.
- README CPU-overhead proof wording updated to name the host-backed benchmark.

## Next Quarter Focus

- Resolved 2026-05-05: `flywheel_connectors-01yaq` repaired instance-binding
  semantics for `BoundVerified`; Capability Tokens were re-evaluated to
  `PROVEN`.
- Decide what proof would let Secretless Connectors graduate from
  `IMPLEMENTED` to `PROVEN`.
- Keep Mesh-Native non-operational wording pinned until ordinary `fwc invoke`
  uses a real mesh-backed path with E2E evidence.
- Re-run connector inventory measurements rather than carrying forward counts.
