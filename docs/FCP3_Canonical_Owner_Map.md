# FCP3 Canonical Owner Map

> **Bead**: `flywheel_connectors-q6huk` — [FCP3/P1.2]
> **Author**: WhiteCompass (SunnyMoose session, 2026-03-27)
> **Input**: [FCP3_Semantic_Ownership_Inventory.md](FCP3_Semantic_Ownership_Inventory.md) (P1.1)
> **Purpose**: Every major semantic noun has one clear home. Forbidden overlaps are listed so future work knows what not to reintroduce.

---

## Ownership Principles

1. **Single owner**: Each concept has exactly one crate that defines its authoritative types and semantics.
2. **Consumers don't redefine**: A crate may consume types from an owner but must not create parallel definitions.
3. **Host orchestrates, core defines**: fcp-host orchestrates execution using fcp-core semantics, but does not define new platform semantics.
4. **CLI projects, host decides**: fwc projects host decisions to operators but does not make policy decisions locally.
5. **Mesh extends, core contracts**: fcp-mesh extends placement semantics but the placement CONTRACT lives in fcp-core.

---

## 1. Execution Lifecycle

| Noun | Owner | Crate | Consumers |
|------|-------|-------|-----------|
| ConnectorId | fcp-core | capability.rs | all |
| SessionId | fcp-core | protocol.rs | fcp-host, fcp-protocol |
| InstanceId | fcp-core | protocol.rs | fcp-host, fcp-sdk |
| RequestId | fcp-core | protocol.rs | fcp-host, fcp-streaming |
| InvokeRequest | fcp-core | protocol.rs | fcp-host, fcp-streaming, fcp-store |
| InvokeResponse | fcp-core | protocol.rs | fcp-host, fcp-streaming |
| InvokeStatus | fcp-core | protocol.rs | fcp-host, fcp-streaming |
| HandshakeRequest/Response | fcp-core | protocol.rs | fcp-host, fcp-protocol |
| SimulateRequest/Response | fcp-core | protocol.rs | fcp-host |
| FcpConnector trait | fcp-core | connector.rs | fcp-host, connectors |
| BaseConnector | fcp-core | connector.rs | connectors |
| OperationInfo | fcp-core | protocol.rs | fcp-host, fcp-sdk, fwc |
| OperationId | fcp-core | capability.rs | all |
| **ProcessState** | **fcp-host** | supervisor.rs | fcp-host only |
| **RestartPolicy** | **fcp-host** | supervisor.rs | fcp-host only |
| **ShutdownCoordinator** | **fcp-host** | supervisor.rs | fcp-host only |
| **CancelReason** | **fcp-core** (MOVE) | — | fcp-host, fwc, SDKs |
| **CleanupBehavior** | **fcp-core** (MOVE) | — | fcp-host, fwc, SDKs |
| **ProgressUpdate** | **fcp-core** (MOVE) | — | fcp-host, fwc, agents |
| CommandTruthSource | fwc | catalog.rs | fwc only |
| CommandExecutionMode | fwc | catalog.rs | fwc only |

---

## 2. Policy (Zones, Capabilities, Provenance)

| Noun | Owner | Crate | Consumers |
|------|-------|-------|-----------|
| CapabilityId | fcp-core | capability.rs | all |
| CapabilityToken | fcp-core | capability.rs | fcp-host, fcp-protocol, fcp-sdk |
| CapabilityVerifier | fcp-core | capability.rs | fcp-host, fcp-protocol |
| CapabilityGrant | fcp-core | capability.rs | fcp-host |
| PolicyEngine | fcp-core | policy.rs | fcp-host |
| PolicyDecision | fcp-core | policy.rs | fcp-host, fcp-audit |
| PolicyBundle | fcp-core | policy.rs | fcp-host, fcp-store |
| ZoneId | fcp-core | capability.rs | all |
| ZoneTransportPolicy | fcp-core | policy.rs | fcp-host |
| ZonePolicyObject | fcp-core | policy.rs | fcp-store |
| UsageBudgetPolicy | fcp-core | policy.rs | fcp-host, fcp-ratelimit |
| RateLimitEnforcement | fcp-core | ratelimit.rs | fcp-host, fcp-ratelimit |
| RiskLevel | fcp-core | protocol.rs | all |
| SafetyTier | fcp-core | protocol.rs | all |
| TrustLevel | fcp-core | protocol.rs | fcp-audit |
| Provenance | fcp-core | protocol.rs | fcp-store |
| **EnforcementPipeline** | **fcp-host** | enforcement.rs | fcp-host only |
| **Enforcement check ordering** | **fcp-core** (MOVE) | — | fcp-host, SDKs |

---

## 3. Evidence (Audit, Health, Receipts)

| Noun | Owner | Crate | Consumers |
|------|-------|-------|-----------|
| AuditEvent | fcp-core | audit.rs | fcp-host, fcp-store |
| DecisionReceipt | fcp-core | audit.rs | fcp-host, fcp-store |
| HealthSnapshot | fcp-core | health.rs | fcp-host, fcp-protocol |
| SelfCheckReport | fcp-core | health.rs | fcp-host, fcp-protocol |
| HealthState | fcp-core | health.rs | fcp-host |
| EventEnvelope | fcp-core | event.rs | fcp-host, fcp-streaming |
| EventData | fcp-core | event.rs | fcp-host, fcp-streaming |
| ResponseMetadata | fcp-core | protocol.rs | fcp-host |
| **HealthAggregator** | **fcp-host** | health.rs | fcp-host only |
| **ComponentHealth** | **fcp-host** | health.rs | fcp-host only |
| **DoctorReport** | **fcp-host** | doctor.rs | fcp-host only |
| MetadataProvenance | fwc | readiness.rs | fwc only |
| ReadinessLevel | fwc | readiness.rs | fwc only |

---

## 4. Durability (Store, Checkpoints, State)

| Noun | Owner | Crate | Consumers |
|------|-------|-------|-----------|
| OperationIntent | fcp-core | idempotency.rs | fcp-host, fcp-store |
| OperationReceipt | fcp-core | idempotency.rs | fcp-host, fcp-store |
| IdempotencyClass | fcp-core | protocol.rs | fcp-host |
| LifecycleState | fcp-core | lifecycle.rs | fcp-host |
| LifecycleManager | fcp-core | lifecycle.rs | fcp-host |
| CheckpointProposal | fcp-core | checkpoint.rs | fcp-host, fcp-store |
| ComputationCheckpoint | fcp-core | checkpoint.rs | fcp-host, fcp-store |
| Lease | fcp-core | lease.rs | fcp-host, fcp-store |
| LeaseResponse | fcp-core | lease.rs | fcp-host |
| ConnectorStateRoot | fcp-core | state.rs | fcp-store |
| RevocationObject | fcp-core | revocation.rs | fcp-store |
| StoredObject | fcp-core | object.rs | fcp-store |
| **RolloutDecision** | **fcp-core** (MOVE) | — | fcp-host, SDKs |
| **RolloutEvidence** | **fcp-core** (MOVE) | — | fcp-host, SDKs, audit |
| **RolloutObservation** | **fcp-core** (MOVE) | — | fcp-host, SDKs |

---

## 5. Placement (Mesh, Leases, Routing)

| Noun | Owner | Crate | Consumers |
|------|-------|-------|-----------|
| NodeId | fcp-core | quorum.rs | fcp-host, fcp-mesh |
| LeasePurpose | fcp-core | lease.rs | fcp-host |
| ObjectPlacementPolicy | fcp-core | object.rs | fcp-store |
| **Mesh gossip protocol** | **fcp-mesh** | gossip.rs | fcp-host |
| **FCPS framing** | **fcp-protocol** | fcps.rs | fcp-mesh, fcp-store |
| **RaptorQ erasure coding** | **fcp-raptorq** | — | fcp-store |

---

## 6. Operator Truth (CLI, Admin, MCP)

| Noun | Owner | Crate | Consumers |
|------|-------|-------|-----------|
| ManagedConnectorConfig | fcp-host | admin_state.rs | fcp-host, operators |
| DesiredRuntimeState | fcp-host | admin_state.rs | fcp-host |
| DiscoveryEndpoint | fcp-host | discovery.rs | agents, operators |
| ToolDescriptor | fcp-host | discovery.rs | agents |
| McpServerCapabilities | fcp-host | agent_api.rs | agents |
| ConnectorManifest | fcp-manifest | — | fcp-host, fwc |
| Schema tools (McpTool, ClaudeTool) | fcp-core | tool_schema.rs | fcp-sdk |

---

## Forbidden Overlaps

These overlaps MUST NOT be reintroduced by future work:

### F1. Health Aggregation Model
- **Current**: fcp-core defines `HealthSnapshot`/`HealthState`; fcp-host re-defines `ComponentHealth`/`ConnectorHealth`/`MeshHealth`/`HealthAggregator`
- **Rule**: fcp-core owns the aggregation model. fcp-host implements it using fcp-core types.
- **Migration**: Move host health aggregation types to fcp-core as `HealthAggregation` model.

### F2. Rollout Decision Semantics
- **Current**: fcp-core defines `LifecycleState`; fcp-host defines `RolloutDecision`/`RolloutEvidence`/`RolloutObservation`
- **Rule**: The decision enum and evidence schema are platform-canonical (belong in fcp-core). The observation-gathering logic stays in fcp-host.
- **Migration**: Move `RolloutDecision`, `RolloutEvidence`, `RolloutObservation` to fcp-core.

### F3. Enforcement Pipeline Ordering
- **Current**: The 11-check enforcement sequence and short-circuit logic is fcp-host-only knowledge.
- **Rule**: The canonical check ordering must be declared in fcp-core so SDKs and sidecars can replicate it.
- **Migration**: Define `EnforcementCheckOrder` enum in fcp-core. fcp-host implements the pipeline.

### F4. Progress and Cancellation Schemas
- **Current**: `ProgressUpdate`, `CancelReason`, `CleanupBehavior` defined only in fcp-host.
- **Rule**: These are platform-agnostic schemas needed by SDKs and agents.
- **Migration**: Move to fcp-core.

### F5. Readiness Model Duplication
- **Current**: fcp-core defines `ReadinessDescriptor`; fwc defines `ReadinessLevel`/`CommandAvailability`/`MetadataProvenance`
- **Rule**: The readiness CONTRACT belongs in fcp-core. fwc may define CLI-specific presentation types.
- **Migration**: Define `ReadinessContract` in fcp-core that fwc implements.

### F6. Policy Manipulation in CLI
- **Current**: fwc `policy_cmd.rs` directly manipulates `PolicyBundle`, computes hashes, signs with Ed25519.
- **Rule**: Policy manipulation must go through fcp-host RPC. The CLI never touches crypto directly.
- **Migration**: Add policy simulation RPC to fcp-host. fwc calls it via RPC.

### F7. Credential Store Trait
- **Current**: fwc owns credential storage at `~/.fwc/credentials.enc` with no fcp-core abstraction.
- **Rule**: `CredentialStore` trait belongs in fcp-core. fwc implements it with keychain+encrypted-file backend.
- **Migration**: Define `CredentialStore` trait in fcp-core.

---

## Summary: What Goes Where

| Crate | Owns | Does NOT Own |
|-------|------|-------------|
| **fcp-core** | All platform types, decision point enums, trait contracts, policy engine, lifecycle state machine, tool schema | Process management, caching, CLI presentation |
| **fcp-host** | Process supervision, enforcement pipeline implementation, resilience internals (circuit/bulkhead/shedder), health check scheduling, admin state, discovery endpoint, MCP protocol | Decision semantics, type definitions, policy evaluation logic |
| **fwc** | CLI presentation, command classification, metadata provenance, local credential storage, operation history, schema navigation, intent compilation | Policy decisions, enforcement, health aggregation, lifecycle management |
| **fcp-protocol** | FCPS framing, wire format, session negotiation | Semantic meaning of framed content |
| **fcp-mesh** | Gossip protocol, routing tables, peer management | Placement policy (owned by fcp-core) |
| **fcp-store** | Persistence layer, WAL, object storage | Object semantics (owned by fcp-core) |
| **fcp-sdk** | Authoring helpers, ConnectorErrorMapping, ConnectorRuntime | Platform semantics |

---

*This owner map is the authoritative contract for where new code belongs. Cite this document when proposing crate splits, type moves, or new features.*
