# FCP3 Acceptance Contracts and Proof Artifacts

> **Bead**: `flywheel_connectors-xn3h3` — [FCP3/P1.4]
> **Author**: WhiteCompass (SunnyMoose session, 2026-03-27)
> **Input**: [FCP3_Canonical_Owner_Map.md](FCP3_Canonical_Owner_Map.md) (P1.2), [FCP3_Transition_Guardrails.md](FCP3_Transition_Guardrails.md) (P1.3)
> **Purpose**: Concrete proof obligations for each FCP3 phase. What counts as "done" for ownership, protocol, convergence, mesh, CLI, and deletion.

---

## Proof Framework

Each phase produces a **proof bundle** containing:
1. **Unit test matrix**: Named tests that verify the phase's acceptance criteria
2. **E2E script matrix**: Integration scripts that verify cross-crate behavior
3. **Structured logging fields**: Log fields that demonstrate runtime compliance
4. **Artifact bundle**: Documents, configs, or generated files that serve as evidence
5. **Failure diagnosis outputs**: What to check when a proof fails

---

## Phase 1: Semantic Lock (Ownership Proof)

### Acceptance Criteria
- [ ] Every major noun has a single owner (documented in owner map)
- [ ] Forbidden overlaps are listed and enforced
- [ ] Transition guardrails are defined and reviewable

### Unit Test Matrix
| Test | Crate | Purpose |
|------|-------|---------|
| `test_no_fcp_host_types_in_connector_crates` | fcp-e2e | Verify connectors don't import fcp-host |
| `test_no_fcp_crypto_in_fwc` | fcp-e2e | Verify fwc doesn't import crypto directly |
| `test_no_cross_layer_deps` | fcp-e2e | Verify dependency graph follows layered architecture |
| `test_owner_map_coverage` | fcp-e2e | Verify all public types in fcp-core have owner annotations |

### Artifact Bundle
- `docs/FCP3_Semantic_Ownership_Inventory.md` (complete)
- `docs/FCP3_Canonical_Owner_Map.md` (complete)
- `docs/FCP3_Transition_Guardrails.md` (complete)

### Failure Diagnosis
- If `test_no_cross_layer_deps` fails: check `Cargo.toml` for prohibited dependency edges
- If owner map coverage drops: check for new un-annotated public types

---

## Phase 2: Crate Carving (Protocol and Durable Truth Proof)

### Acceptance Criteria
- [ ] fcp-kernel carved from broad execution buckets (P2.1)
- [ ] fcp-policy carved as single owner of zone/capability/provenance (P2.2)
- [ ] fcp-evidence carved as owner of receipts/checkpoints/revocation (P2.3)
- [ ] Consumers rewired to owned kernel/policy/evidence crates (P2.4)

### Unit Test Matrix
| Test | Crate | Purpose |
|------|-------|---------|
| `test_fcp_kernel_owns_invoke_lifecycle` | fcp-kernel | InvokeRequest/Response, SessionId, FcpConnector trait defined here |
| `test_fcp_policy_owns_capability_types` | fcp-policy | CapabilityToken, PolicyEngine, PolicyDecision defined here |
| `test_fcp_evidence_owns_audit_types` | fcp-evidence | AuditEvent, DecisionReceipt, HealthSnapshot defined here |
| `test_no_execution_types_in_fcp_core` | fcp-core | fcp-core no longer defines types moved to kernel/policy/evidence |
| `test_consumers_import_from_new_crates` | fcp-e2e | fcp-host, connectors import from fcp-kernel, not fcp-core |

### E2E Script Matrix
| Script | Purpose |
|--------|---------|
| `e2e/test_invoke_through_kernel.sh` | Full invoke cycle using fcp-kernel types |
| `e2e/test_policy_decision_through_fcp_policy.sh` | Policy evaluation using fcp-policy |
| `e2e/test_audit_trail_through_fcp_evidence.sh` | Audit event creation using fcp-evidence |

### Structured Logging Fields
```json
{
  "phase": "crate_carving",
  "source_crate": "fcp-kernel",
  "type_name": "InvokeRequest",
  "consumer_crate": "fcp-host",
  "import_path": "fcp_kernel::InvokeRequest"
}
```

### Failure Diagnosis
- If `test_no_execution_types_in_fcp_core` fails: a type wasn't moved, check re-exports
- If consumer tests fail: check import paths weren't updated

---

## Phase 3: Durable Object Alignment (Store Convergence Proof)

### Acceptance Criteria
- [ ] FCPS durable object schemas defined canonically (P3.2)
- [ ] Store, manifest, and registry contracts aligned (P3.3)
- [ ] Store handles schema evolution without breaking readers

### Unit Test Matrix
| Test | Crate | Purpose |
|------|-------|---------|
| `test_durable_object_roundtrip` | fcp-store | Every durable object serializes/deserializes correctly |
| `test_schema_evolution_backward_compat` | fcp-store | Old readers handle new schema gracefully |
| `test_manifest_hash_stability` | fcp-manifest | Manifest hash unchanged after refactor |
| `test_registry_uses_canonical_schemas` | fcp-registry | Registry objects use fcp-core schemas, not local types |

### E2E Script Matrix
| Script | Purpose |
|--------|---------|
| `e2e/test_store_migration.sh` | Store migration from v2 to v3 schema |
| `e2e/test_manifest_validation.sh` | Validate all 150 connectors' manifests post-refactor |

---

## Phase 4: Host and SDK Convergence (Runtime Proof)

### Acceptance Criteria
- [ ] First connector family migrated end-to-end (P4.4)
- [ ] SDK and host use the same type paths from carved crates
- [ ] Enforcement pipeline uses platform-canonical check ordering

### Unit Test Matrix
| Test | Crate | Purpose |
|------|-------|---------|
| `test_connector_uses_fcp_kernel_types` | migrated-connector | Connector imports from fcp-kernel |
| `test_host_enforcement_uses_canonical_order` | fcp-host | Enforcement check order matches fcp-core definition |
| `test_sdk_runtime_uses_carved_types` | fcp-sdk | ConnectorRuntime uses fcp-kernel types |

### E2E Script Matrix
| Script | Purpose |
|--------|---------|
| `e2e/test_full_invoke_migrated_connector.sh` | Configure → handshake → invoke → verify through migrated connector |
| `e2e/test_enforcement_pipeline_order.sh` | Verify 11-check enforcement order matches specification |

### Structured Logging Fields
```json
{
  "phase": "convergence",
  "connector_id": "fcp.example",
  "invoke_type_source": "fcp-kernel",
  "enforcement_check_count": 11,
  "enforcement_order_canonical": true
}
```

---

## Phase 5: Mesh Pilot (Placement Proof)

### Acceptance Criteria
- [ ] Mesh placement planner contract implemented (P5.1)
- [ ] Two-node pilot with failure drills and evidence (P5.4)
- [ ] Lease handoff works across nodes

### Unit Test Matrix
| Test | Crate | Purpose |
|------|-------|---------|
| `test_placement_planner_assigns_node` | fcp-mesh | Planner assigns connector to node based on zone/lease |
| `test_lease_handoff_between_nodes` | fcp-mesh | Lease transfers cleanly between nodes |
| `test_failure_detection_and_recovery` | fcp-mesh | Node failure detected, lease reassigned |

### E2E Script Matrix
| Script | Purpose |
|--------|---------|
| `e2e/test_two_node_mesh_pilot.sh` | Two-node cluster with connector placement, failover, and recovery |
| `e2e/test_mesh_gossip_convergence.sh` | Gossip state converges after partition healing |

### Artifact Bundle
- Network partition test results
- Lease transfer timing measurements
- Gossip convergence time measurements

---

## Phase 6: CLI Truthfulness (Operator Proof)

### Acceptance Criteria
- [ ] fwc reports only platform-canonical truth (no host-local lies)
- [ ] All fwc health/status commands use fcp-host RPC, not local state
- [ ] Policy simulation goes through fcp-host, not direct crypto

### Unit Test Matrix
| Test | Crate | Purpose |
|------|-------|---------|
| `test_fwc_health_uses_rpc` | fwc | Health command calls fcp-host RPC, not local aggregation |
| `test_fwc_policy_uses_rpc` | fwc | Policy simulation calls fcp-host RPC, not local crypto |
| `test_fwc_no_direct_crypto_import` | fwc | No fcp-crypto in fwc dependency tree |

---

## Phase 7: Final Deletion (Cleanup Proof)

### Acceptance Criteria
- [ ] All `COMPAT-SHIM` annotations removed
- [ ] All `PENDING-CARVE` annotations resolved
- [ ] fcp-sdk::migration module deleted or deprecated
- [ ] No re-exports of moved types from old locations

### Unit Test Matrix
| Test | Crate | Purpose |
|------|-------|---------|
| `test_no_compat_shim_annotations` | fcp-e2e | Grep for `COMPAT-SHIM` returns zero |
| `test_no_pending_carve_annotations` | fcp-e2e | Grep for `PENDING-CARVE` returns zero |
| `test_no_migration_module_usage` | fcp-e2e | No imports from `fcp_sdk::migration` |

---

## Verification Schedule

| Phase | Proof Type | When |
|-------|-----------|------|
| P1 (Semantic Lock) | Artifact review | Before any crate carving begins |
| P2 (Crate Carving) | Unit + E2E | After each crate is carved |
| P3 (Store Alignment) | Unit + migration | After schema changes |
| P4 (Convergence) | Unit + E2E + logs | After first connector family migrated |
| P5 (Mesh Pilot) | E2E + perf | After two-node deployment |
| P6 (CLI Truth) | Unit + integration | After fwc refactor |
| P7 (Deletion) | Grep + compile | Final phase |

---

*This contract is the single source of truth for what "done" means in each FCP3 phase. Contributors should implement the named tests as they complete each phase.*
