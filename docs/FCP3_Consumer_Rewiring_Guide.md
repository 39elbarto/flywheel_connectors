# FCP3 Consumer Rewiring Guide

> **Bead**: `flywheel_connectors-d8jbq` — [FCP3/P2.4]
> **Author**: WhiteCompass (SunnyMoose session, 2026-03-28)
> **Purpose**: Step-by-step guide for rewiring consumers from fcp-core broad imports to targeted fcp-kernel/fcp-policy/fcp-evidence imports.

---

## Rewiring Principle

**Before (broad bucket)**:
```rust
use fcp_core::{InvokeRequest, CapabilityToken, AuditEvent};
```

**After (targeted owners)**:
```rust
use fcp_kernel::InvokeRequest;
use fcp_policy::CapabilityToken;
use fcp_evidence::AuditEvent;
```

Both compile identically since the new crates re-export from fcp-core. The difference is semantic: consumers now depend on the correct owner crate.

---

## Consumer Priority Order

| Priority | Consumer | Impact | Execution Types | Policy Types | Evidence Types |
|----------|----------|--------|----------------|-------------|---------------|
| 1 | **fcp-host** | Highest (orchestrator) | Heavy | Heavy | Heavy |
| 2 | **fcp-sdk** | High (connector authors) | Heavy | Light | None |
| 3 | **fwc** | High (CLI) | Medium | Medium | Medium |
| 4 | **fcp-streaming** | Medium | Heavy | Light | Medium |
| 5 | **fcp-store** | Medium | Light | Light | Heavy |
| 6 | **fcp-mesh** | Medium | Medium | Medium | Medium |
| 7 | **connectors** (150+) | Low priority, high volume | Medium | Light | None |

---

## Rewiring Steps Per Consumer

### Step 1: Add Dependencies

In the consumer's `Cargo.toml`:
```toml
[dependencies]
fcp-kernel = { path = "../fcp-kernel" }
fcp-policy = { path = "../fcp-policy" }
fcp-evidence = { path = "../fcp-evidence" }
# Keep fcp-core for types not yet carved
fcp-core = { path = "../fcp-core" }
```

### Step 2: Classify Imports

For each `use fcp_core::{ ... }` statement, classify each type:

| Type | New Home | Import From |
|------|----------|-------------|
| InvokeRequest, InvokeResponse, InvokeStatus | fcp-kernel | `use fcp_kernel::*` |
| FcpConnector, BaseConnector | fcp-kernel | `use fcp_kernel::*` |
| CapabilityToken, PolicyEngine | fcp-policy | `use fcp_policy::*` |
| AuditEvent, DecisionReceipt | fcp-evidence | `use fcp_evidence::*` |
| FcpError, FcpResult | fcp-kernel (re-exports) | `use fcp_kernel::{FcpError, FcpResult}` |

### Step 3: Update Import Paths

Replace `fcp_core::` with the appropriate owner crate:
```rust
// Before
use fcp_core::{InvokeRequest, CapabilityToken, AuditEvent, FcpError};

// After
use fcp_kernel::{InvokeRequest, FcpError};
use fcp_policy::CapabilityToken;
use fcp_evidence::AuditEvent;
```

### Step 4: Remove fcp-core Dependency (Eventually)

Once all types are imported from the new crates, remove `fcp-core` from `Cargo.toml`. This is the final step — don't do this until ALL imports are migrated.

---

## Import Classification Reference

### fcp-kernel (Execution)
```
InvokeRequest, InvokeResponse, InvokeStatus, InvokeContext, InvokeValidationError
HandshakeRequest, HandshakeResponse, SessionId
SimulateRequest, SimulateResponse
FcpConnector, BaseConnector, RequestResponse, Streaming, Bidirectional, Polling, Webhook
ConnectorMetrics, ConnectorId, InstanceId, OperationId, RequestId
OperationInfo, Introspection, AgentHint, ApprovalMode, EventInfo, ResourceTypeInfo
LifecycleState, LifecycleManager, LifecycleTransition, TransitionReason
HealthSnapshot, HealthState, SelfCheckReport, SelfCheckStatus
EventCaps, AuthCaps, TransportCaps, HostInfo, ResponseMetadata
FcpError, FcpResult
IdempotencyClass, OperationIntent, OperationReceipt
Lease, LeaseResponse, LeasePurpose
CheckpointProposal, ComputationCheckpoint
ShutdownRequest, ShutdownAck
```

### fcp-policy (Policy)
```
CapabilityId, CapabilityToken, CapabilityGrant, CapabilityVerifier, CapabilityConstraints
ZoneId, ZoneDefinitionObject, ZonePolicyObject, ZoneTransportPolicy
PolicyEngine, PolicyDecision, PolicyBundle, PolicyBundleSignature
RiskLevel, SafetyTier, TrustLevel
Principal, PrincipalId, RoleObject, RoleAssignment, RoleGraph
Provenance, ProvenanceStep, TaintLevel, IntegrityLevel, ConfidentialityLevel
ApprovalToken, SecretAccessToken
PostureRequirements, PostureCheckResult
UsageBudgetPolicy, RateLimitEnforcement
```

### fcp-evidence (Evidence)
```
AuditEvent, AuditHead
DecisionReceipt, Decision, DecisionReasonCode
TraceContext, CorrelationId
EventEnvelope, EventData, EventAck, EventNack
RevocationObject, RevocationEvent, RevocationRegistry
ZoneCheckpoint
ProvenanceRecord, ProvenanceViolation
ForkEvidence, ForkDetectionResult
```

---

## Verification

After rewiring a consumer, run:
```bash
cargo check -p <consumer> --lib
cargo test -p <consumer> --lib
```

To detect backslides, grep for remaining broad imports:
```bash
grep -r "use fcp_core::" crates/<consumer>/src/ | grep -v "// COMPAT:"
```

---

*This guide should be followed for each consumer in priority order. Mark each consumer as DONE in the transition scorecard when complete.*
