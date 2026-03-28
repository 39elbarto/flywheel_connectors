# FCP3 FCPS Durable Object Schemas

> **Bead**: `flywheel_connectors-gg5sl` — [FCP3/P3.2]
> **Author**: WhiteCompass (SunnyMoose session, 2026-03-28)
> **Purpose**: Canonical durable object schemas for facts that survive process death.

---

## Design Principles

1. **Replay-friendly**: Every durable object has enough context for deterministic replay.
2. **Self-describing**: Each object carries its schema version for migration.
3. **Content-addressed**: Objects are keyed by content hash for deduplication.
4. **Inspection-friendly**: Human-readable JSON representation alongside compact CBOR.

---

## Object Header (Common to All)

```
FcpsDurableObject {
  schema_version: u32,             // Monotonically increasing
  object_type: string,             // "receipt", "checkpoint", "lease", etc.
  object_id: ObjectId,             // Content-addressed hash
  zone: ZoneId,                    // Owning zone
  created_at: DateTime<Utc>,
  created_by: NodeId,
  signature: Option<Signature>,    // Ed25519 over canonical CBOR
}
```

---

## 1. Operation Receipt

Immutable record proving an operation was executed.

```
OperationReceiptObject {
  header: FcpsDurableObject { object_type: "receipt" },

  // Identity
  request_id: RequestId,
  connector_id: ConnectorId,
  operation_id: OperationId,
  session_id: SessionId,

  // Authorization
  capability_id: CapabilityId,
  principal: Principal,
  policy_decision: PolicyDecision,
  decision_receipt: DecisionReceipt?,

  // Execution
  status: InvokeStatus,
  started_at: DateTime<Utc>,
  completed_at: DateTime<Utc>,
  duration_ms: u64,

  // Evidence
  input_hash: [u8; 32],           // BLAKE3 of canonical input
  output_hash: [u8; 32],          // BLAKE3 of canonical output
  usage_metrics: [UsageMetric],
  cost_estimate: CostEstimate?,
  provenance: Provenance?,

  // Idempotency
  idempotency_key: Option<String>,
  idempotency_class: IdempotencyClass,
  intent_id: Option<ObjectId>,    // Links to OperationIntent
}
```

### Fixture: Successful Invoke Receipt
```json
{
  "schema_version": 1,
  "object_type": "receipt",
  "object_id": "obj:blake3:abc123...",
  "zone": "z:work",
  "request_id": "r:abc",
  "connector_id": "fcp.slack",
  "operation_id": "slack.send_message",
  "status": "Ok",
  "duration_ms": 245,
  "input_hash": "deadbeef...",
  "output_hash": "cafebabe...",
  "idempotency_class": "AtMostOnce"
}
```

---

## 2. Checkpoint

Snapshot of connector/computation state at a point in time.

```
CheckpointObject {
  header: FcpsDurableObject { object_type: "checkpoint" },

  // Identity
  connector_id: ConnectorId,
  sequence: u64,                   // Monotonic checkpoint number
  epoch_id: EpochId?,              // PCS epoch if applicable

  // State
  trigger: CheckpointTrigger,      // Manual, TimeElapsed, OperationCount, etc.
  state_root_hash: [u8; 32],      // Merkle root of connector state
  state_model: ConnectorStateModel,
  state_data: Option<Vec<u8>>,    // Compact serialized state (CBOR)

  // Lineage
  parent_checkpoint_id: Option<ObjectId>,
  parent_state_root_hash: Option<[u8; 32]>,
  operations_since_parent: u64,

  // Validation
  fork_detection: ForkDetectionResult,
  verified_by: [NodeId],           // Nodes that verified this checkpoint
}
```

---

## 3. Lease Record

Exclusive ownership claim for a resource or computation.

```
LeaseObject {
  header: FcpsDurableObject { object_type: "lease" },

  // Identity
  lease_id: LeaseId,
  purpose: LeasePurpose,           // OperationExecution, ComputationMigration, etc.
  holder: NodeId,

  // Scope
  connector_id: ConnectorId?,
  zone: ZoneId,

  // Timing
  acquired_at: DateTime<Utc>,
  expires_at: DateTime<Utc>,
  last_renewed_at: DateTime<Utc>,
  renewal_count: u32,

  // Fencing
  fence_token: u64,               // Monotonic fencing token

  // Handoff
  handoff_to: Option<NodeId>,
  handoff_initiated_at: Option<DateTime<Utc>>,
}
```

---

## 4. Revocation Record

Invalidation of a capability, credential, or session.

```
RevocationObject {
  header: FcpsDurableObject { object_type: "revocation" },

  // What was revoked
  scope: RevocationScope,          // Capability, Session, Credential, Zone, Node
  target_id: String,               // The revoked entity's ID

  // Context
  reason: String,
  initiated_by: Principal,

  // Timing
  effective_at: DateTime<Utc>,

  // Evidence
  audit_event_id: ObjectId?,       // Link to audit event
  supersedes: Option<ObjectId>,    // Previous revocation replaced by this one
}
```

---

## 5. Connector Identity Record

Canonical descriptor for a connector's deployment.

```
ConnectorIdentityObject {
  header: FcpsDurableObject { object_type: "connector_identity" },

  // Identity
  connector_id: ConnectorId,
  version: semver::Version,

  // Deployment
  lifecycle_state: LifecycleState,
  deployed_at: DateTime<Utc>,
  deployed_by: NodeId,

  // Trust
  manifest_hash: [u8; 32],
  attestation: Option<SupplyChainAttestation>,
  sbom: Option<SoftwareBillOfMaterials>,

  // Capabilities
  supported_operations: [OperationId],
  supported_capabilities: [CapabilityId],
  safety_tier: SafetyTier,
}
```

---

## 6. Explanation Bundle

Human-readable justification for a platform decision.

```
ExplanationBundle {
  header: FcpsDurableObject { object_type: "explanation" },

  // What is being explained
  subject_type: string,            // "policy_denial", "rollback", "revocation", etc.
  subject_id: ObjectId,            // The object being explained

  // Explanation
  summary: String,                 // One-line human-readable summary
  details: Vec<ExplanationStep>,
  recommendation: Option<String>,  // Suggested operator action

  // Context
  triggered_by: String,            // What event triggered this explanation
  related_objects: [ObjectId],     // Links to related durable objects
}

ExplanationStep {
  order: u32,
  label: String,
  description: String,
  evidence: Option<Value>,         // Structured evidence supporting this step
  passed: bool,
}
```

### Fixture: Policy Denial Explanation
```json
{
  "schema_version": 1,
  "object_type": "explanation",
  "subject_type": "policy_denial",
  "summary": "Operation slack.delete_channel denied: missing required capability 'slack.admin' in zone z:work",
  "details": [
    {"order": 1, "label": "zone_membership", "passed": true, "description": "Principal user:alice is a member of z:work"},
    {"order": 2, "label": "capability_verify", "passed": false, "description": "Token grants [slack.messages] but operation requires [slack.admin]"}
  ],
  "recommendation": "Request capability 'slack.admin' from zone administrator"
}
```

---

## 7. Connector Runtime State

Durable snapshot of connector-managed state.

```
ConnectorStateObject {
  header: FcpsDurableObject { object_type: "connector_state" },

  // Identity
  connector_id: ConnectorId,
  state_model: ConnectorStateModel, // Stateless, KeyValue, Document, CRDT

  // State
  state_root: ConnectorStateRoot,
  delta_since_checkpoint: Option<ConnectorStateDelta>,

  // Cursor
  cursor: Option<CursorState>,     // For incremental sync connectors

  // Conflict Resolution
  fork_detection: StateForkDetectionResult,
  last_merge: Option<DateTime<Utc>>,
}
```

---

## Schema Evolution Rules

1. **Additive only**: New fields are always optional. Old readers ignore unknown fields.
2. **Version bump**: `schema_version` increments on structural changes.
3. **Migration path**: Each version includes a migration function from N-1 to N.
4. **Round-trip**: Objects must round-trip through CBOR encode → decode without loss.
5. **Deterministic encoding**: Canonical CBOR (sorted keys, minimal length) for hash stability.

---

## Inspection & Replay

### Object Inspection
```bash
# Inspect a receipt
fwc store inspect --object-id obj:blake3:abc123...
# Output: human-readable JSON with field descriptions

# List checkpoints for a connector
fwc store list --type checkpoint --connector fcp.slack --since 2h
```

### Replay
```bash
# Replay an operation from a receipt
fwc replay --receipt-id obj:blake3:abc123... --dry-run
# Uses input_hash to verify inputs, re-executes, compares output_hash
```

---

*These schemas define the durable vocabulary for FCP facts. All persistent state must conform to these object types. New durable facts require a new schema in this document.*
