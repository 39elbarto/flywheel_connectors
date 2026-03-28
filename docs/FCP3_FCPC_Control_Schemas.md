# FCP3 FCPC Control, Admin, and Session Schemas

> **Bead**: `flywheel_connectors-vqfld` — [FCP3/P3.1]
> **Author**: WhiteCompass (SunnyMoose session, 2026-03-28)
> **Purpose**: Canonical FCPC wire schemas for live control plane interactions. HTTP admin API becomes an adapter over these.

---

## Design Principles

1. **Wire-first**: Schemas are defined for CBOR transport, with JSON as a derived view.
2. **Envelope pattern**: All messages use `FcpcEnvelope` with correlation, trace, and timing.
3. **Request-response pairs**: Each control operation has typed request and response schemas.
4. **Replay-friendly**: All fields needed for deterministic replay are in the envelope.

---

## 1. Envelope Schema

```
FcpcEnvelope {
  type: string,                    // "invoke_request", "health_response", etc.
  id: RequestId,                   // Unique per-request correlation
  correlation_id: CorrelationId?,  // Links related requests across sessions
  trace_id: string?,               // OpenTelemetry trace context
  timestamp: DateTime<Utc>,        // Wall-clock time of creation
  source: NodeId,                  // Originating node
  target: ConnectorId?,            // Target connector (if applicable)
  zone: ZoneId?,                   // Zone context
  session: SessionId?,             // Session context
  payload: Value,                  // Type-specific payload (see below)
}
```

### Success Response Envelope
```
FcpcSuccessResponse {
  type: "success",
  id: RequestId,
  in_reply_to: RequestId,
  duration_ms: u64,
  payload: Value,
}
```

### Error Response Envelope
```
FcpcErrorResponse {
  type: "error",
  id: RequestId,
  in_reply_to: RequestId,
  error_code: string,              // Machine-readable: "capability_denied", "not_found", etc.
  error_message: string,           // Human-readable description
  retry_after_ms: u64?,            // Hint for retryable errors
  details: Value?,                 // Structured error context
}
```

---

## 2. Session Lifecycle

### session.open
```
SessionOpenRequest {
  zone: ZoneId,
  principal: Principal,
  capabilities_requested: [CapabilityId],
  transport_preferences: TransportCaps?,
  agent_hint: AgentHint?,
}
```
```
SessionOpenResponse {
  session_id: SessionId,
  capabilities_granted: [CapabilityGrant],
  server_capabilities: ServerCapabilities,
  heartbeat_interval_ms: u64,
}
```

### session.close
```
SessionCloseRequest {
  session_id: SessionId,
  reason: string?,
  drain: bool,                     // If true, wait for in-flight to complete
}
```

### session.heartbeat
```
SessionHeartbeat {
  session_id: SessionId,
  sequence: u64,
  metrics: SessionMetrics?,        // Optional live metrics snapshot
}
```

---

## 3. Connector Control

### connector.configure
```
ConfigureRequest {
  connector_id: ConnectorId,
  config: Value,                   // Connector-specific configuration
  credential_id: CredentialId?,    // Reference to stored credential
}
```

### connector.handshake
```
HandshakeRequest {
  // Existing fcp_core::HandshakeRequest fields
  protocol_version: string,
  zone: ZoneId,
  host_public_key: [u8],
  nonce: [u8; 32],
  capabilities_requested: [CapabilityId],
  instance_id: InstanceId?,
  host_info: HostInfo?,
  transport_caps: TransportCaps?,
}
```

### connector.invoke
```
InvokeRequest {
  // Existing fcp_core::InvokeRequest fields
  id: RequestId,
  connector_id: ConnectorId,
  operation_id: OperationId,
  parameters: Value,
  capability_token: CapabilityToken,
  zone: ZoneId,
  context: InvokeContext?,
}
```

### connector.health
```
HealthRequest {
  connector_id: ConnectorId,
}
HealthResponse {
  state: HealthState,
  snapshot: HealthSnapshot,
}
```

### connector.doctor
```
DoctorRequest {
  connector_id: ConnectorId,
}
DoctorResponse {
  status: DoctorStatus,            // Healthy, Degraded, Unhealthy
  checks: [DoctorCheck],
}
```

### connector.self_check
```
SelfCheckRequest {
  connector_id: ConnectorId,
}
SelfCheckResponse: SelfCheckReport
```

### connector.simulate
```
SimulateRequest {
  // Existing fcp_core::SimulateRequest fields
  id: RequestId,
  connector_id: ConnectorId,
  operation: OperationId,
  parameters: Value,
  capability_token: CapabilityToken,
}
SimulateResponse {
  would_succeed: bool,
  risk_summary: string?,
  estimated_cost: CostEstimate?,
}
```

---

## 4. Admin Operations

### admin.discovery
```
DiscoveryRequest {
  filter: DiscoveryFilter?,        // Zone, connector, health filters
  include_tools: bool,
  include_health: bool,
}
DiscoveryResponse {
  connectors: [ConnectorSummary],
  tools: [ToolDescriptor]?,
  host_health: HostHealthResponse?,
}
```

### admin.lifecycle
```
LifecycleActionRequest {
  connector_id: ConnectorId,
  action: LifecycleAction,         // Enable, Disable, Start, Stop, Restart
  reason: string?,
}
LifecycleActionResponse {
  previous_state: LifecycleState,
  new_state: LifecycleState,
  transition: LifecycleTransition,
}
```

### admin.policy_simulate
```
PolicySimulateRequest {
  invoke: InvokeRequest,
  zone_policy: ZonePolicyObject?,  // Optional policy override for simulation
}
PolicySimulateResponse {
  decision: PolicyDecision,
  receipt: DecisionReceipt,
  enforcement_trace: [EnforcementCheckRecord],
}
```

### admin.preflight
```
PreflightRequest {
  connector_id: ConnectorId,
  operation: OperationId,
  zone: ZoneId,
  estimate_cost: bool,
}
PreflightResponse {
  allowed: bool,
  rate_limit_info: PreflightRateLimit?,
  estimated_cost: EstimatedCost?,
  enforcement_decision: PolicyDecision?,
}
```

---

## 5. Evidence Retrieval

### evidence.audit_tail
```
AuditTailRequest {
  zone: ZoneId?,
  connector_id: ConnectorId?,
  since: DateTime<Utc>?,
  limit: u32,
}
AuditTailResponse {
  events: [AuditEvent],
  cursor: string?,                 // Pagination cursor
}
```

### evidence.decision_receipt
```
DecisionReceiptRequest {
  request_id: RequestId,
}
DecisionReceiptResponse {
  receipt: DecisionReceipt?,
  not_found_reason: string?,
}
```

### evidence.health_history
```
HealthHistoryRequest {
  connector_id: ConnectorId,
  window_minutes: u32,
}
HealthHistoryResponse {
  snapshots: [TimestampedHealthSnapshot],
}
```

---

## 6. Example Session Transcript

```json
// 1. Open session
→ {"type":"session.open","id":"r:001","zone":"z:work","principal":{"id":"user:alice"},"capabilities_requested":["slack.messages"]}
← {"type":"success","id":"r:001a","in_reply_to":"r:001","payload":{"session_id":"s:abc","capabilities_granted":[{"capability":"slack.messages","operations":["slack.send_message","slack.list_channels"]}]}}

// 2. Health check
→ {"type":"connector.health","id":"r:002","target":"fcp.slack","session":"s:abc"}
← {"type":"success","id":"r:002a","in_reply_to":"r:002","payload":{"state":"Ready","snapshot":{"uptime_secs":3600}}}

// 3. Invoke
→ {"type":"connector.invoke","id":"r:003","target":"fcp.slack","session":"s:abc","payload":{"operation_id":"slack.send_message","parameters":{"channel":"C123","text":"hello"},"capability_token":"..."}}
← {"type":"success","id":"r:003a","in_reply_to":"r:003","duration_ms":245,"payload":{"status":"Ok","data":{"ts":"1234567890.123456"}}}

// 4. Close session
→ {"type":"session.close","id":"r:004","session":"s:abc","drain":true}
← {"type":"success","id":"r:004a","in_reply_to":"r:004","payload":{"drained_operations":0}}
```

---

*These schemas are the normative contract for FCPC. The HTTP admin API, MCP adapter, and CLI all derive their wire formats from these canonical definitions.*
