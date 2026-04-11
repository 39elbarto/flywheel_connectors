# Claims vs Reality Audit [MOR/C2.4]

> Date: 2026-04-10
> Auditor: SunnyMoose (Claude Opus 4.6)
> Scope: All feature status labels in README.md feature table

## Methodology

Each feature's status label (`PROVEN`, `IMPLEMENTED`, `DESIGNED`, `PLANNED`) was
verified by:

1. Locating the primary source files implementing the feature
2. Counting unit tests and integration/E2E tests
3. Checking for production-grade evidence (E2E test suites, golden vectors, conformance)
4. Comparing the claim against the evidence

Status definitions:
- `PROVEN` = Direct proof exists in the current repo (E2E tests, golden vectors, conformance suites)
- `IMPLEMENTED` = Code and tests exist but wider E2E proof or production hardening is incomplete
- `DESIGNED` = Architectural target or scaffolding exists but operational story is not complete
- `PLANNED` = Intended direction with little or no built surface

## Reconciliation Table

| Feature | Claimed | Evidence Files | Test Count | E2E? | Verdict | Notes |
|---------|---------|----------------|-----------|------|---------|-------|
| Host-First Control Plane | `IMPLEMENTED` | `crates/fcp-host/src/{supervisor,enforcement,health,agent_api}.rs` | 240+ | Yes (enforcement pipeline) | **ACCURATE** | 11-stage enforcement pipeline, MCP 2025 API surface |
| Truthful Runtime Resolution | `IMPLEMENTED` | `crates/fwc/src/{truth,catalog}.rs` | 86+896 | Integration tests | **ACCURATE** | KnowledgeState taxonomy (6 states), LiveTruthResolver, DecisionTrace |
| Zone Isolation | `PROVEN` | `crates/fcp-core/src/{zone_keys,pcs,policy}.rs`, `crates/fcp-host/src/enforcement.rs` | 240+180 | Yes | **ACCURATE** | Full cryptographic enforcement with PCS TreeKEM, zone key rotation |
| Capability Tokens (CWT/COSE) | `PROVEN` | `crates/fcp-crypto/src/cose.rs`, `crates/fcp-core/src/capability.rs` | 218+31 | Yes (conformance) | **ACCURATE** | COSE_Sign1 with deterministic CBOR, CWT claims, phantom types |
| Tamper-Evident Audit | `PROVEN` | `crates/fcp-audit/src/lib.rs`, `crates/fcp-core/src/audit.rs` | 126+347 | Golden vectors | **ACCURATE** | Hash-linked chain, monotonic seq, quorum-signed checkpoints |
| Revocation | `IMPLEMENTED` | `crates/fcp-core/src/revocation.rs` | 104 | Unit tests | **ACCURATE** | RevocationObject, 5 scopes, O(1) freshness; broader E2E still open |
| Egress Proxy | `IMPLEMENTED` | `crates/fcp-host/src/egress.rs`, `crates/fcp-sandbox/` | 270 | Partial | **ACCURATE** | CIDR deny defaults, credential injection; production hardening TBD |
| Secretless Connectors | `IMPLEMENTED` | `crates/fcp-host/src/egress.rs`, `crates/fcp-sdk/` | 270+ | Partial | **ACCURATE** | credential_id flows exist; broader proof work still open per description |
| Threshold Owner Key | `IMPLEMENTED` | `crates/fcp-bootstrap/src/ceremony.rs` | 93 | Unit tests | **ACCURATE** | FROST ceremony/signing; not yet universal default per description |
| Threshold Secrets | `IMPLEMENTED` | `crates/fcp-core/src/secret.rs` | 123 | Golden vectors | **ACCURATE** | Full Shamir GF(2^8) with k-of-n shares, reconstruction, cold recovery |
| Supply Chain Attestations | `IMPLEMENTED` | `crates/fcp-registry/src/lib.rs` | 347 | Unit tests | **ACCURATE** | AttestationType schema, verification policy; release signing incomplete |
| Offline Access | `IMPLEMENTED` | `crates/fcp-store/src/offline.rs`, E2E repair tests | 108+77 | Yes (E2E repair) | **ACCURATE** | ObjectPlacementPolicy, AccessPatternTracker, repair controllers |
| Mesh-Stored Policy Objects | `IMPLEMENTED` | `crates/fcp-core/src/policy.rs` | 128 | Unit tests | **ACCURATE** | Owner-signed policy bundles; wider mesh-backed cutover TBD |
| Symbol-First Protocol | `IMPLEMENTED` | `crates/fcp-raptorq/src/`, `crates/fcp-store/src/symbol_store.rs` | 96+ | Golden vectors | **ACCURATE** | Full encode/decode, chunking, multipath aggregation |
| Mesh-Native Architecture | `DESIGNED` | `crates/fcp-mesh/src/{gossip,iblt,node,planner}.rs` | 259+ | Unit tests | **ACCURATE** | XOR filters, IBLT, gossip implemented; zero production evidence |
| Computation Migration | `DESIGNED` | `crates/fcp-core/src/migration.rs`, `crates/fcp-core/src/computation_migration.rs` | 205 | Unit tests | **ACCURATE** | State machines and framework; not operational |

## Summary

**All 16 feature status labels are accurate.** No overclaims were found.

The README already includes accurate qualifying language for each feature:
- PROVEN features have direct E2E or golden vector evidence
- IMPLEMENTED features explicitly note incomplete E2E proof or production hardening
- DESIGNED features explicitly note they are architectural targets, not operational

### Test Coverage Totals

| Category | Tests |
|----------|-------|
| Core security (zones, capability, audit, revocation) | 1,200+ |
| Host enforcement pipeline | 240+ |
| Egress/sandbox | 270+ |
| Offline/repair (including E2E) | 185+ |
| Mesh gossip/IBLT | 259+ |
| FWC truth/catalog | 982+ |
| Registry/supply chain | 347+ |
| Secret sharing | 123 |
| Conformance/E2E harness | 89 files |

### Recommendations

1. No status label changes needed.
2. Evidence pointers added to README feature table (see commit).
3. Quarterly re-audit recommended (feeds into C2.5 debiasing process).
