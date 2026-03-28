# FCP3 Semantic Ownership Inventory

> **Bead**: `flywheel_connectors-2d0vg` — [FCP3/P1.1]
> **Author**: WhiteCompass (SunnyMoose session, 2026-03-27)
> **Purpose**: Authoritative inventory of semantic ownership across the FCP codebase. Later refactor beads reference this instead of rediscovering leakage from scratch.

---

## 1. Domain Taxonomy

Every major noun is classified into one of six semantic domains:

| Domain | Definition | Primary Owner Today |
|--------|-----------|-------------------|
| **Execution** | Connect, handshake, invoke, cancel, shutdown lifecycle | fcp-core (types), fcp-host (process supervision) |
| **Policy** | Zones, capabilities, provenance, budgets, transport constraints | fcp-core (types + PolicyEngine), fcp-host (enforcement pipeline) |
| **Evidence** | Audit events, decision receipts, health snapshots, provenance records | fcp-core (types), fcp-host (aggregation) |
| **Durability** | Store invariants, FCPS framing, idempotency, checkpoints, leases | fcp-core (types), fcp-store (persistence) |
| **Placement** | Mesh routing, node identity, lease coordination, zone assignment | fcp-core (types), fcp-mesh (gossip + routing) |
| **Operator** | CLI commands, connector inventory, MCP tool export, host admin | fwc (CLI), fcp-host (admin API + discovery) |

---

## 2. fcp-core: The Type Authority (230+ public types)

fcp-core defines the canonical types consumed by every other crate. Key counts by domain:

- **Execution**: 24 major types (ConnectorId, SessionId, InvokeRequest/Response, FcpConnector trait, ...)
- **Policy**: 28 major types (CapabilityToken, PolicyEngine, PolicyDecision, ZoneTransportPolicy, ...)
- **Evidence**: 62 major types (AuditEvent, Provenance, HealthSnapshot, DecisionReceipt, ...)
- **Durability**: 41 major types (OperationIntent/Receipt, Lease, CheckpointProposal, ConnectorStateRoot, ...)
- **Placement**: 9 major types (ZoneId, NodeId, LeasePurpose, ObjectPlacementPolicy, ...)

### Critical Decision Points in fcp-core (28 types that gate behavior)

| Type | Domain | What It Gates |
|------|--------|---------------|
| CapabilityToken | policy | Invoke authorization |
| CapabilityVerifier | policy | Token validity |
| PolicyDecision | policy | Operation permission |
| PolicyEngine | policy | Access evaluation |
| ZoneTransportPolicy | policy | Transport method selection |
| UsageBudgetPolicy | policy | Rate limit enforcement |
| RateLimitEnforcement | policy | Rate-limit action |
| HandshakeRequest/Response | execution | Connector initialization |
| InvokeRequest/Response | execution | Operation initiation/completion |
| InvokeStatus | execution | Result interpretation |
| FcpConnector trait | execution | Connector protocol contract |
| LifecycleState | durability | Operational readiness |
| LifecycleManager trait | durability | State transition enforcement |
| OperationIntent | durability | Pre-commit exactly-once gate |
| OperationReceipt | durability | Terminal operation marker |
| LeaseResponse | placement | Lease ownership change |
| ForkDetectionResult | durability | State divergence detection |
| CheckpointAdvanceState | durability | Checkpoint publication |
| FreshnessResult | durability | Stale revocation handling |
| RetentionClass | durability | Retention policy |
| DeviceEnrollmentApproval | policy | Node admission |
| PrerequisiteStatus | evidence | Prerequisite fulfillment |
| PostureCheckResult | policy | Posture validation |
| ProvisioningStatus | execution | Provisioning progression |
| SecretAccessToken | durability | Secret access |
| DegradedModeState | durability | Fallback behavior |

---

## 3. fcp-host: Process Supervision + Enforcement (150+ types)

fcp-host is the runtime orchestrator. It owns process-level concerns and the enforcement pipeline.

### Host-Owned Domains

| Module | Domain | Owned Concepts |
|--------|--------|---------------|
| supervisor.rs | execution | ProcessState machine (Starting→Running→Stopping→Stopped/Failed), RestartPolicy, ShutdownCoordinator, HealthCheckScheduler, ResourceLimits |
| enforcement.rs | policy | 11-stage enforcement pipeline (CanonicalDecode → ZoneMembership → CapabilityVerify → HolderProof → CheckpointFreshness → RevocationFreshness → TaintApproval → PolicyCeiling → ConnectorManifest → RateLimit → Budget) |
| resilience.rs | execution | CircuitBreaker (Closed→Open→HalfOpen), Bulkhead, LoadShedder (priority-based), HealthRouter |
| health.rs | evidence | HealthAggregator, ComponentHealth, ConnectorHealth, MeshHealth |
| rollout.rs | placement | RolloutController (Scheduled→Hold→Promote→Rollback), RolloutEvidence, crash-loop detection |
| cancellation.rs | execution | CancellationController, CancelReason, CleanupBehavior |
| progress.rs | evidence | ProgressController, ProgressUpdate, PhaseTransition |
| budget.rs | policy | BudgetTracker (per-zone windowed usage), BudgetPolicyEngine |
| discovery.rs | evidence | DiscoveryEndpoint, ToolDescriptor, PreflightRequest/Response, DiscoveryCache |
| admin_state.rs | operator | ManagedConnectorConfig, ConnectorInventoryMutation, DesiredRuntimeState |
| doctor.rs | evidence | DoctorReport, DoctorService, CheckResult |
| supply_chain.rs | policy | SupplyChainGate (wraps fcp-core VerificationPipeline with caching) |
| batch.rs | execution | BatchInvokeRequest, dependency-ordered multi-tool execution |
| agent_api.rs | execution | MCP 2025 protocol surface |

### Host-Local Process State (NOT shared)

These exist only in fcp-host process memory:
- ProcessState, RestartTracker, ExponentialBackoff, ShutdownCoordinator
- CircuitBreaker, Bulkhead, LoadShedder internal state
- DiscoveryCache (LRU), OutputCapture (ring buffer)
- SubprocessRegistry, ConnectorProcessRunner

### Reach-Through Edges (fcp-host → fcp-core)

| fcp-host Module | fcp-core Types Consumed | Decision Impact |
|-----------------|------------------------|-----------------|
| rollout.rs | LifecycleManager, LifecycleState, RolloutPolicy, CanaryPolicy, ConnectorHealth, SelfCheckReport | Controls promotion/rollback |
| enforcement.rs | Zone memberships, capability tokens, checkpoint freshness, revocation, taint approvals, policy ceilings, rate limits, budgets | 11-stage authorization gate |
| budget.rs | UsageBudgetPolicy, UsageBudgetUsage, BudgetEnforcement | Allow/Warn/Deny decisions |
| supply_chain.rs | VerificationPipeline, SupplyChainVerificationPolicy, VerificationDecision | Artifact trust gate |
| discovery.rs | OperationInfo, RateLimit, SafetyTier | Tool catalog construction |
| resilience.rs | ConnectorHealth | Health-based routing |

### Types That Should Move to fcp-core

| Candidate | Current Location | Rationale |
|-----------|-----------------|-----------|
| RolloutObservation | fcp-host::rollout | Observation schema is platform-agnostic; SDKs need it |
| RolloutEvidence | fcp-host::rollout | Audit evidence should be canonical across implementations |
| RolloutDecision | fcp-host::rollout | Decision semantics (Scheduled/Hold/Promote/Rollback) are platform-neutral |
| ProgressUpdate | fcp-host::progress | Progress schema is deployment-agnostic |
| CancelReason | fcp-host::cancellation | Cancellation reason codes are platform-agnostic |
| CleanupBehavior | fcp-host::cancellation | Cleanup modes are platform policy |

---

## 4. fwc: Operator Surface + Metadata Provenance (34k+ lines main.rs)

fwc is the CLI tool. It owns operator-facing concerns and metadata provenance tracking.

### fwc-Owned Domains

| Module | Domain | Owned Concepts |
|--------|--------|---------------|
| catalog.rs | operator | CommandTruthSource (LiveHost/OfflineArtifact/Hybrid/Passthrough), CommandExecutionMode, HostAbsentBehavior |
| readiness.rs | operator | MetadataProvenance (5 origins), MetadataField<T> (Known/Unknown/Unsupported/Unreachable), ReadinessLevel, CommandAvailability |
| search.rs | operator | Cross-connector semantic search with scoring weights, faceted filters |
| schema_nav.rs | operator | JSON Schema walker, scaffold template generation |
| pipe.rs | operator | Two-operation pipe planning, MapRule, MappingSpec |
| intent.rs | operator | Semantic intent compilation, WorkflowTruth, IntentMode |
| workflow.rs | operator | Multi-step approval workflows, ExecutionReceipt, ClarificationPrompt |
| routing.rs | operator | Smart connector auto-routing (health → rate limit → history → safety) |
| zone_scope.rs | policy | Per-zone MCP tool scoping, capability enforcement |
| policy_cmd.rs | policy | Policy simulation, bundle diffing (heavy fcp-core reach-through) |
| credential_store.rs | operator | Keychain-first credential store, AuthMethod detection |
| session.rs | operator | Agent session management (~/.fwc/sessions/) |
| history.rs | evidence | Operation history with audit chain (~/.fwc/history/) |
| replay.rs | operator | Operation replay from history with TTL |
| lifecycle_mutations.rs | execution | Enable/Disable/Start/Stop/Restart state machine |
| prerequisite.rs | evidence | Prerequisite checking, repair, drift detection |
| audit.rs | evidence | Connector metadata gap audit matrix |
| validate.rs | operator | Pre-invoke JSON Schema validation with fix suggestions |
| extract.rs | operator | jq-style field extraction for --extract |
| batch.rs | operator | Map-over-inputs parallel execution |
| reactive_rules.rs | operator | Event-triggered operation execution |
| event_stream.rs | operator | Event streaming with backpressure |
| rate_limit.rs | evidence | Rate limit status (Ok/Warning/Critical thresholds) |
| rate_forecast.rs | operator | Rate limit consumption forecasting |

### fwc Host-Local State

| State | Location | Persistence |
|-------|----------|-------------|
| Credentials | ~/.fwc/credentials.enc | Encrypted file |
| Sessions | ~/.fwc/sessions/*.json | Per-session files |
| Operation locks | ~/.fwc/locks/*.json | Advisory locks with TTL |
| History | ~/.fwc/history/*.json | Operation audit trail |
| Replay inputs | ~/.fwc/replay/*.json | 7-day TTL |
| Connector cache | In-memory | Session-scoped |
| Search index | In-memory | Session-scoped |
| Rate limit cache | Local cache | Refreshed from host |

### fwc Reach-Through Edges

| Module | What It Reaches Into | Concern |
|--------|---------------------|---------|
| readiness.rs | fcp-core ConnectorDescriptor, OperationInfo, ReadinessDescriptor | Metadata import for readiness |
| policy_cmd.rs | fcp-core PolicyBundle, ZonePolicyObject, DecisionReceipt + fcp-crypto Ed25519 | Policy simulation (heavy) |
| new_cmd.rs | fcp-core validate_canonical_id() | Connector ID validation |
| manifest_cmd.rs | fcp-manifest ConnectorManifest | Manifest parsing + hashing |
| supply_chain_cmd.rs | fcp-core VerificationPipeline | Attestation validation |

---

## 5. Semantic Leakage Map

These are the most significant reach-through edges where ownership is blurred:

### Critical Leakage Points

1. **fcp-host rollout.rs ↔ fcp-core LifecycleManager**: Host makes rollout decisions using core lifecycle state. The observation, evidence, and decision types are host-local but should be platform-canonical.

2. **fcp-host enforcement.rs ↔ fcp-core PolicyEngine**: The 11-stage enforcement pipeline lives in fcp-host but evaluates fcp-core policy types. The pipeline ORDER and SHORT-CIRCUIT logic is host-local knowledge that should be platform-owned.

3. **fwc policy_cmd.rs ↔ fcp-core PolicyBundle**: The CLI directly manipulates policy bundles, computes hashes, signs with Ed25519. This should go through fcp-host RPC, not direct crypto access.

4. **fwc readiness.rs ↔ fcp-core introspection types**: The CLI builds its own readiness model by importing fcp-core types. The readiness CONTRACT should be defined in fcp-core, not reimplemented in fwc.

5. **fcp-host health.rs re-defines HealthState**: fcp-core already has HealthState/SelfCheckReport but fcp-host defines its own ComponentHealth/ConnectorHealth/MeshHealth aggregation types. The aggregation model should be platform-canonical.

### Forbidden Overlaps (for P1.2 owner map)

| Concept | Current Owners | Recommended Single Owner |
|---------|---------------|------------------------|
| Health aggregation | fcp-core (HealthSnapshot), fcp-host (HealthAggregator) | fcp-core should own the aggregation model |
| Rollout decision semantics | fcp-core (LifecycleState), fcp-host (RolloutDecision) | fcp-core should own the decision enum |
| Enforcement pipeline order | fcp-host only | Should be declared in fcp-core as canonical check ordering |
| Progress schema | fcp-host only | fcp-core should own ProgressUpdate |
| Cancellation reasons | fcp-host only | fcp-core should own CancelReason |
| Readiness model | fcp-core (ReadinessDescriptor), fwc (ReadinessLevel) | fcp-core should own the full readiness model |
| Credential storage | fwc only | fcp-core should define CredentialStore trait |

---

## 6. State Machines

### Process Lifecycle (fcp-host supervisor.rs)
```
Starting → Running → Stopping → Stopped
                  ↘              ↗
                    → Failed
```

### Circuit Breaker (fcp-host resilience.rs)
```
Closed ──[failure threshold]──→ Open ──[timeout]──→ HalfOpen
  ↑                                                      ↓
  └────────────────[success]───────────────────────────────┘
```

### Connector Lifecycle (fcp-core, evaluated by fcp-host rollout.rs)
```
Pending → Installing → Canary → Production
                         ↓         ↓
                      RolledBack  RolledBack
```

### Cancellation (fcp-host cancellation.rs)
```
Requested → [cleanup] → Completed | PartialSuccess | Failed
```

---

## 7. Summary Statistics

| Crate | Public Types | Decision Points | Reach-Through Edges | Host-Local State Items |
|-------|-------------|-----------------|--------------------|-----------------------|
| fcp-core | 230+ | 28 | 0 (origin) | 0 |
| fcp-host | 150+ | 11 (pipeline) + 8 (other) | 6 major modules | 20+ internal types |
| fwc | N/A (CLI) | 9 command gates | 5 modules | 10 storage locations |

---

*This inventory is the authoritative reference for FCP3 Phase 1. Subsequent beads (P1.2 owner map, P1.3 guardrails, P2.x crate carving) should cite this document rather than re-analyzing the codebase.*
