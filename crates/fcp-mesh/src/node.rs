//! MeshNode orchestration glue for FCP2.
//!
//! This module ties together admission control, gossip, symbol requests,
//! degraded-mode control-plane transport, and execution planning into a
//! single cohesive node interface.
//!
//! The goal is to provide a safe, explicit surface for MeshNode behavior
//! without embedding transport specifics.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use fcp_core::{
    CapabilityVerifier, FcpError, InvokeRequest, InvokeValidationError, ObjectId, OperationIntent,
    OperationReceipt, RevocationRegistry, TailscaleNodeId, ZoneId, ZoneTransportPolicy,
};
use fcp_crypto::{CwtClaims, Ed25519Signature, Ed25519VerifyingKey};
use fcp_protocol::{DecodeStatus, SymbolAck, SymbolRequest};
use fcp_raptorq::RaptorQConfig;
use fcp_store::{ObjectStore, QuarantineStore, SymbolStore};
use fcp_tailscale::NodeId;
use fcp_telemetry::TraceContext;
use fcp_telemetry::trace_capture::{
    AdmissionOutcome, CapturedTrace, GossipEvent, LeaseEvent, RoutingDecision, SessionEvent,
    TraceCapture, TraceCaptureConfig, TraceEvent, TraceExportFormat,
};
use hex::encode;
use thiserror::Error;
use tracing::debug;

use crate::admission::{
    AdmissionController, AdmissionError, AdmissionPolicy, ObjectAdmissionClass,
};
use crate::degraded::{
    ControlPlaneEnvelope, ControlPlaneHandler, DegradedModeDecoder, DegradedModeEncoder,
    DegradedTransportError, RetentionClass,
};
use crate::device::DeviceProfile;
use crate::gossip::{GossipConfig, MeshGossip};
use crate::planner::{
    CandidateNode, ExecutionPlanner, HeldLease, NodeInfo, PlannerContext, PlannerInput,
};
use crate::session::MeshSession;
use crate::symbol_request::{
    SymbolRequestError, SymbolRequestHandler, SymbolRequestMetrics, SymbolRequestPolicy,
    SymbolResponse, SymbolResponseBuilder, TargetedRepairEngine, ValidatedRequest,
};
use crate::transport::{RankedPath, TransportPath, TransportSelector};

/// MeshNode configuration (builder-style).
#[derive(Debug, Clone)]
pub struct MeshNodeConfig {
    /// Local node ID (Tailscale).
    pub node_id: String,
    /// Admission control policy.
    pub admission_policy: AdmissionPolicy,
    /// Gossip configuration.
    pub gossip_config: GossipConfig,
    /// Symbol request policy.
    pub symbol_request_policy: SymbolRequestPolicy,
    /// RaptorQ configuration for degraded control-plane transport.
    pub raptorq_config: RaptorQConfig,
    /// Sender instance ID for degraded-mode frames (reboot-safety).
    pub sender_instance_id: u64,
    /// Trace capture configuration.
    pub trace_capture: TraceCaptureConfig,
    /// Optional allowlist of zones to capture.
    pub trace_capture_zones: Option<HashSet<ZoneId>>,
}

impl MeshNodeConfig {
    /// Create a new config with defaults and a node ID.
    #[must_use]
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            admission_policy: AdmissionPolicy::default(),
            gossip_config: GossipConfig::default(),
            symbol_request_policy: SymbolRequestPolicy::default(),
            raptorq_config: RaptorQConfig::default(),
            sender_instance_id: rand::random::<u64>(),
            trace_capture: TraceCaptureConfig::default(),
            trace_capture_zones: None,
        }
    }

    /// Override admission policy.
    #[must_use]
    pub fn with_admission_policy(mut self, policy: AdmissionPolicy) -> Self {
        self.admission_policy = policy;
        self
    }

    /// Override gossip configuration.
    #[must_use]
    pub fn with_gossip_config(mut self, config: GossipConfig) -> Self {
        self.gossip_config = config;
        self
    }

    /// Override symbol request policy.
    #[must_use]
    pub fn with_symbol_request_policy(mut self, policy: SymbolRequestPolicy) -> Self {
        self.symbol_request_policy = policy;
        self
    }

    /// Override RaptorQ configuration.
    #[must_use]
    pub fn with_raptorq_config(mut self, config: RaptorQConfig) -> Self {
        self.raptorq_config = config;
        self
    }

    /// Override sender instance ID.
    #[must_use]
    pub const fn with_sender_instance_id(mut self, sender_instance_id: u64) -> Self {
        self.sender_instance_id = sender_instance_id;
        self
    }

    /// Override trace capture configuration.
    #[must_use]
    pub fn with_trace_capture_config(mut self, config: TraceCaptureConfig) -> Self {
        self.trace_capture = config;
        self
    }

    /// Override trace capture zone allowlist.
    #[must_use]
    pub fn with_trace_capture_zones<I>(mut self, zones: I) -> Self
    where
        I: IntoIterator<Item = ZoneId>,
    {
        self.trace_capture_zones = Some(zones.into_iter().collect());
        self
    }
}

/// MeshNode errors for orchestration surfaces.
#[derive(Debug, Error)]
pub enum MeshNodeError {
    /// Admission control rejected a request.
    #[error("admission rejected: {0}")]
    Admission(#[from] AdmissionError),

    /// Symbol request handling error.
    #[error("symbol request error: {0}")]
    SymbolRequest(#[from] SymbolRequestError),

    /// Object store error.
    #[error("object store error: {0}")]
    ObjectStore(#[from] fcp_store::ObjectStoreError),

    /// Symbol store error.
    #[error("symbol store error: {0}")]
    SymbolStore(#[from] fcp_store::SymbolStoreError),

    /// Quarantine error.
    #[error("quarantine error: {0}")]
    Quarantine(#[from] fcp_store::QuarantineError),

    /// Degraded-mode transport error.
    #[error("degraded transport error: {0}")]
    DegradedTransport(#[from] DegradedTransportError),

    /// Enforcement error.
    #[error("enforcement error: {0}")]
    Enforcement(#[from] MeshNodeEnforcementError),

    /// Trace capture not enabled.
    #[error("trace capture not enabled")]
    TraceNotEnabled,

    /// Trace export error.
    #[error("trace export error: {0}")]
    TraceExport(#[from] fcp_telemetry::trace_capture::TraceError),
}

/// Enforcement errors for control-plane requests.
#[derive(Debug, Error)]
pub enum MeshNodeEnforcementError {
    /// Invoke request validation error.
    #[error("invoke validation error: {0}")]
    InvokeValidation(#[from] InvokeValidationError),

    /// Capability token verification failed.
    #[error("capability verification failed: {0}")]
    CapabilityVerification(#[from] FcpError),

    /// Holder proof required for holder-bound token.
    #[error("holder proof required for holder node {holder_node}")]
    HolderProofRequired { holder_node: String },

    /// Holder proof node mismatch.
    #[error("holder proof node mismatch: expected {expected}, got {actual}")]
    HolderProofNodeMismatch { expected: String, actual: String },

    /// Holder proof verification failed.
    #[error("holder proof verification failed")]
    HolderProofInvalid,

    /// Holder proof key missing.
    #[error("holder proof key missing for holder node {holder_node}")]
    HolderKeyMissing { holder_node: String },

    /// Capability token missing JTI claim.
    #[error("capability token missing jti claim")]
    MissingTokenJti,

    /// Capability token revoked.
    #[error("capability token revoked: {token_id}")]
    TokenRevoked { token_id: ObjectId },

    /// Receipt validation error.
    #[error("receipt validation failed: {0}")]
    ReceiptValidation(#[from] fcp_core::OperationValidationError),
}

/// Per-peer state used for planning.
#[derive(Debug, Clone)]
pub struct PeerState {
    /// Device profile.
    pub profile: DeviceProfile,
    /// Symbols present on peer.
    pub local_symbols: HashSet<ObjectId>,
    /// Leases held by peer.
    pub held_leases: Vec<HeldLease>,
    /// Last observed timestamp (ms since epoch).
    pub last_seen_ms: u64,
}

/// MeshNode metrics (coarse-grained).
#[derive(Debug, Default, Clone)]
pub struct MeshNodeMetrics {
    /// Symbol request metrics.
    pub symbol_requests: SymbolRequestMetrics,
    /// Gossip announcements emitted.
    pub gossip_announcements: u64,
    /// Gossip summaries processed.
    pub gossip_updates: u64,
    /// Peer updates applied.
    pub peer_updates: u64,
}

/// MeshNode orchestration entrypoint.
pub struct MeshNode {
    local_node: NodeId,
    local_node_ts: TailscaleNodeId,
    admission: AdmissionController,
    gossip: MeshGossip,
    symbol_requests: SymbolRequestHandler,
    symbol_metrics: SymbolRequestMetrics,
    planner: ExecutionPlanner,
    degraded_encoder: DegradedModeEncoder,
    degraded_decoder: DegradedModeDecoder,
    object_store: Arc<dyn ObjectStore>,
    symbol_store: Arc<dyn SymbolStore>,
    quarantine_store: Arc<QuarantineStore>,
    sessions: HashMap<NodeId, MeshSession>,
    peer_signing_keys: HashMap<NodeId, Ed25519VerifyingKey>,
    peers: HashMap<NodeId, PeerState>,
    local_profile: Option<DeviceProfile>,
    local_symbols: HashSet<ObjectId>,
    local_leases: Vec<HeldLease>,
    sent_symbols: HashMap<ObjectId, (u64, HashSet<u32>)>,
    metrics: MeshNodeMetrics,
    trace_capture: Option<TraceCapture>,
    trace_capture_zones: Option<HashSet<ZoneId>>,
}

impl MeshNode {
    /// Create a new MeshNode with explicit stores.
    #[must_use]
    pub fn new(
        config: MeshNodeConfig,
        object_store: Arc<dyn ObjectStore>,
        symbol_store: Arc<dyn SymbolStore>,
        quarantine_store: Arc<QuarantineStore>,
    ) -> Self {
        let local_node = NodeId::new(config.node_id.clone());
        let local_node_ts = TailscaleNodeId::new(config.node_id.clone());
        let trace_capture = if config.trace_capture.enabled {
            let capture_id = encode(TraceContext::generate().trace_id);
            Some(
                TraceCapture::new(capture_id, config.trace_capture.clone())
                    .with_node(config.node_id.clone()),
            )
        } else {
            None
        };

        Self {
            admission: AdmissionController::new(config.admission_policy),
            gossip: MeshGossip::new(local_node_ts.clone(), config.gossip_config),
            symbol_requests: SymbolRequestHandler::new(config.symbol_request_policy),
            symbol_metrics: SymbolRequestMetrics::default(),
            planner: ExecutionPlanner::new(),
            degraded_encoder: DegradedModeEncoder::new(
                config.raptorq_config.clone(),
                config.sender_instance_id,
            ),
            degraded_decoder: DegradedModeDecoder::new(config.raptorq_config),
            object_store,
            symbol_store,
            quarantine_store,
            sessions: HashMap::new(),
            peer_signing_keys: HashMap::new(),
            local_node,
            local_node_ts,
            peers: HashMap::new(),
            local_profile: None,
            local_symbols: HashSet::new(),
            local_leases: Vec::new(),
            sent_symbols: HashMap::new(),
            metrics: MeshNodeMetrics::default(),
            trace_capture,
            trace_capture_zones: config.trace_capture_zones,
        }
    }

    /// Local node ID (planner/admission).
    #[must_use]
    pub const fn local_node_id(&self) -> &NodeId {
        &self.local_node
    }

    /// Local node ID (gossip/FCPS).
    #[must_use]
    pub const fn local_tailscale_id(&self) -> &TailscaleNodeId {
        &self.local_node_ts
    }

    fn trace_id(&self) -> Option<String> {
        self.trace_capture
            .as_ref()
            .map(|capture| capture.trace_id().to_string())
    }

    fn trace_zone_enabled(&self, zone_id: Option<&ZoneId>) -> bool {
        let Some(zone_id) = zone_id else {
            return true;
        };

        match &self.trace_capture_zones {
            None => true,
            Some(zones) => zones.contains(zone_id),
        }
    }

    fn record_trace_event(&mut self, event: TraceEvent) {
        if let Some(capture) = self.trace_capture.as_mut() {
            if let Err(err) = capture.record(event) {
                debug!(error = %err, "trace capture dropped event");
            }
        }
    }

    fn record_admission_outcome(
        &mut self,
        peer: &NodeId,
        decision: &str,
        reason_code: Option<&str>,
        authenticated: bool,
        zone_id: Option<&ZoneId>,
        now_ms: u64,
    ) {
        if !self.trace_zone_enabled(zone_id) {
            return;
        }

        let Some(trace_id) = self.trace_id() else {
            return;
        };

        self.record_trace_event(TraceEvent::Admission(AdmissionOutcome {
            timestamp: now_ms,
            trace_id,
            peer_node: peer.as_str().to_string(),
            request_type: "symbol_request".to_string(),
            decision: decision.to_string(),
            reason_code: reason_code.map(str::to_string),
            budget_remaining: None,
            authenticated,
        }));
    }

    fn record_lease_deltas(
        &mut self,
        node_id: &NodeId,
        previous: &[HeldLease],
        next: &[HeldLease],
        now_ms: u64,
    ) {
        let Some(trace_id) = self.trace_id() else {
            return;
        };

        let mut previous_map = HashMap::new();
        for lease in previous {
            previous_map.insert((lease.subject_id, lease.purpose), lease.expires_at);
        }

        let mut next_map = HashMap::new();
        for lease in next {
            next_map.insert((lease.subject_id, lease.purpose), lease.expires_at);
        }

        for (key, next_expiry) in next_map {
            let (subject_id, purpose) = key;
            match previous_map.remove(&key) {
                None => {
                    self.record_trace_event(TraceEvent::Lease(LeaseEvent {
                        timestamp: now_ms,
                        trace_id: trace_id.clone(),
                        operation: "acquire".to_string(),
                        subject_id: subject_id.to_string(),
                        purpose: purpose.to_string(),
                        node_id: node_id.as_str().to_string(),
                        success: true,
                        conflict_holder: None,
                    }));
                }
                Some(prev_expiry) if prev_expiry != next_expiry => {
                    self.record_trace_event(TraceEvent::Lease(LeaseEvent {
                        timestamp: now_ms,
                        trace_id: trace_id.clone(),
                        operation: "renew".to_string(),
                        subject_id: subject_id.to_string(),
                        purpose: purpose.to_string(),
                        node_id: node_id.as_str().to_string(),
                        success: true,
                        conflict_holder: None,
                    }));
                }
                _ => {}
            }
        }

        for (key, _) in previous_map {
            let (subject_id, purpose) = key;
            self.record_trace_event(TraceEvent::Lease(LeaseEvent {
                timestamp: now_ms,
                trace_id: trace_id.clone(),
                operation: "release".to_string(),
                subject_id: subject_id.to_string(),
                purpose: purpose.to_string(),
                node_id: node_id.as_str().to_string(),
                success: true,
                conflict_holder: None,
            }));
        }
    }

    fn admission_reason_code(err: &AdmissionError) -> &'static str {
        match err {
            AdmissionError::ByteBudgetExceeded { .. } => "byte_budget_exceeded",
            AdmissionError::SymbolBudgetExceeded { .. } => "symbol_budget_exceeded",
            AdmissionError::AuthFailureBudgetExceeded { .. } => "auth_failure_budget_exceeded",
            AdmissionError::DecodeCapacityExceeded { .. } => "decode_capacity_exceeded",
            AdmissionError::DecodeCpuBudgetExceeded { .. } => "decode_cpu_budget_exceeded",
            AdmissionError::AmplificationViolation { .. } => "amplification_violation",
            AdmissionError::AuthenticationRequired => "authentication_required",
            AdmissionError::ProofOfNeedRequired => "proof_of_need_required",
            AdmissionError::ObjectQuarantined { .. } => "object_quarantined",
            AdmissionError::NotReachable { .. } => "not_reachable",
            AdmissionError::QuarantineQuotaExceeded { .. } => "quarantine_quota_exceeded",
        }
    }

    fn symbol_request_reason_code(err: &SymbolRequestError) -> &'static str {
        match err {
            SymbolRequestError::InvalidRequest { .. } => "invalid_request",
            SymbolRequestError::BoundsExceeded { .. } => "bounds_exceeded",
            SymbolRequestError::HintTooLarge { .. } => "hint_too_large",
            SymbolRequestError::AdmissionRejected(admission) => {
                Self::admission_reason_code(admission)
            }
            SymbolRequestError::ObjectNotFound { .. } => "object_not_found",
            SymbolRequestError::SignatureInvalid => "signature_invalid",
            SymbolRequestError::AlreadyComplete { .. } => "already_complete",
        }
    }

    /// Update local device profile and symbol/lease state.
    pub fn update_local_state(
        &mut self,
        profile: DeviceProfile,
        local_symbols: HashSet<ObjectId>,
        held_leases: Vec<HeldLease>,
    ) {
        let now_ms = current_time_ms();
        let previous_leases = self.local_leases.clone();
        let local_node = self.local_node.clone();
        self.record_lease_deltas(&local_node, &previous_leases, &held_leases, now_ms);
        self.local_profile = Some(profile);
        self.local_symbols = local_symbols;
        self.local_leases = held_leases;
    }

    /// Update or insert peer state.
    pub fn update_peer_state(
        &mut self,
        node_id: NodeId,
        profile: DeviceProfile,
        local_symbols: HashSet<ObjectId>,
        held_leases: Vec<HeldLease>,
        now_ms: u64,
    ) {
        let previous_leases = self
            .peers
            .get(&node_id)
            .map(|state| state.held_leases.clone())
            .unwrap_or_default();
        self.record_lease_deltas(&node_id, &previous_leases, &held_leases, now_ms);
        let state = PeerState {
            profile,
            local_symbols,
            held_leases,
            last_seen_ms: now_ms,
        };
        self.peers.insert(node_id, state);
        self.metrics.peer_updates += 1;
    }

    /// Remove a peer from tracking.
    pub fn remove_peer(&mut self, node_id: &NodeId) {
        self.peers.remove(node_id);
        self.peer_signing_keys.remove(node_id);
    }

    /// Register a peer's signing key for signature verification.
    pub fn register_peer_signing_key(&mut self, peer_id: NodeId, key: Ed25519VerifyingKey) {
        self.peer_signing_keys.insert(peer_id, key);
    }

    /// Remove a peer's signing key.
    pub fn remove_peer_signing_key(&mut self, peer_id: &NodeId) {
        self.peer_signing_keys.remove(peer_id);
    }

    /// Current peer count (excluding local).
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Register an authenticated mesh session for a peer.
    pub fn register_session(&mut self, session: MeshSession, now_ms: u64) {
        self.admission
            .set_authenticated(&session.peer_id, true, now_ms);
        let peer_id = session.peer_id.clone();
        let session_id = encode(session.session_id.as_bytes());
        let suite = session.suite.as_str().to_string();
        self.sessions.insert(peer_id.clone(), session);

        let Some(trace_id) = self.trace_id() else {
            return;
        };
        self.record_trace_event(TraceEvent::Session(SessionEvent {
            timestamp: now_ms,
            trace_id,
            session_id,
            kind: "established".to_string(),
            peer_node: peer_id.as_str().to_string(),
            suite: Some(suite),
            failure_reason: None,
        }));
    }

    /// Remove a mesh session for a peer (marks unauthenticated).
    pub fn remove_session(&mut self, peer_id: &NodeId, now_ms: u64) {
        if let Some(session) = self.sessions.remove(peer_id) {
            if let Some(trace_id) = self.trace_id() {
                self.record_trace_event(TraceEvent::Session(SessionEvent {
                    timestamp: now_ms,
                    trace_id,
                    session_id: encode(session.session_id.as_bytes()),
                    kind: "closed".to_string(),
                    peer_node: peer_id.as_str().to_string(),
                    suite: Some(session.suite.as_str().to_string()),
                    failure_reason: None,
                }));
            }
        }
        self.admission.set_authenticated(peer_id, false, now_ms);
    }

    /// Check whether a peer is authenticated.
    #[must_use]
    pub fn is_peer_authenticated(&self, peer_id: &NodeId) -> bool {
        self.sessions.contains_key(peer_id) || self.admission.is_authenticated(peer_id)
    }

    /// Build a planner input from current local + peer state.
    fn build_planner_input(&self, now_ms: u64) -> PlannerInput {
        let mut nodes = Vec::new();
        let mut singleton_holder: Option<String> = None;
        let now_secs = now_ms / 1000;

        if let Some(profile) = &self.local_profile {
            if singleton_holder.is_none()
                && self.local_leases.iter().any(|lease| {
                    lease.purpose == crate::planner::LeasePurpose::SingletonWriter
                        && lease.expires_at > now_secs
                })
            {
                singleton_holder = Some(profile.node_id.as_str().to_string());
            }

            nodes.push(NodeInfo {
                profile: profile.clone(),
                local_symbols: self.local_symbols.clone(),
                held_leases: self.local_leases.clone(),
            });
        }

        for state in self.peers.values() {
            if singleton_holder.is_none()
                && state.held_leases.iter().any(|lease| {
                    lease.purpose == crate::planner::LeasePurpose::SingletonWriter
                        && lease.expires_at > now_secs
                })
            {
                singleton_holder = Some(state.profile.node_id.as_str().to_string());
            }

            nodes.push(NodeInfo {
                profile: state.profile.clone(),
                local_symbols: state.local_symbols.clone(),
                held_leases: state.held_leases.clone(),
            });
        }

        let mut input = PlannerInput::new(nodes, now_ms);
        if let Some(holder) = singleton_holder {
            input = input.with_singleton_holder(holder);
        }
        input
    }

    /// Plan execution candidates for a connector.
    #[must_use]
    pub fn plan_execution(&self, context: &PlannerContext, now_ms: u64) -> Vec<CandidateNode> {
        let input = self.build_planner_input(now_ms);
        self.planner.plan(&input, context)
    }

    /// Enforce capability, holder proof, and revocation checks for an invoke request.
    ///
    /// Returns the verified capability claims on success.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeEnforcementError` if idempotency validation, capability
    /// verification, holder proof checks, or revocation checks fail.
    pub fn enforce_invoke_request<F>(
        &self,
        request: &InvokeRequest,
        required_capability: &fcp_core::CapabilityId,
        verifier: &CapabilityVerifier,
        revocations: &RevocationRegistry,
        resource_uris: &[String],
        mut holder_key_lookup: F,
    ) -> Result<CwtClaims, MeshNodeEnforcementError>
    where
        F: FnMut(&TailscaleNodeId) -> Option<Ed25519VerifyingKey>,
    {
        request.validate_idempotency_key()?;

        let claims = verifier.verify(
            &request.capability_token,
            required_capability,
            &request.operation,
            resource_uris,
        )?;

        if let Some(holder_node) = claims.get_holder_node() {
            let proof = request.holder_proof.as_ref().ok_or_else(|| {
                MeshNodeEnforcementError::HolderProofRequired {
                    holder_node: holder_node.to_string(),
                }
            })?;

            if proof.holder_node.as_str() != holder_node {
                return Err(MeshNodeEnforcementError::HolderProofNodeMismatch {
                    expected: holder_node.to_string(),
                    actual: proof.holder_node.as_str().to_string(),
                });
            }

            let token_jti = claims
                .get_jti()
                .ok_or(MeshNodeEnforcementError::MissingTokenJti)?;
            let signable =
                fcp_core::HolderProof::signable_bytes(&request.id, &request.operation, token_jti);

            let key = holder_key_lookup(&proof.holder_node).ok_or_else(|| {
                MeshNodeEnforcementError::HolderKeyMissing {
                    holder_node: proof.holder_node.as_str().to_string(),
                }
            })?;

            let signature = Ed25519Signature::from_bytes(&proof.signature);
            if key.verify(&signable, &signature).is_err() {
                return Err(MeshNodeEnforcementError::HolderProofInvalid);
            }
        }

        let token_jti = claims
            .get_jti()
            .ok_or(MeshNodeEnforcementError::MissingTokenJti)?;
        let token_id = ObjectId::from_unscoped_bytes(token_jti);
        if revocations.is_revoked(&token_id) {
            return Err(MeshNodeEnforcementError::TokenRevoked { token_id });
        }

        Ok(claims)
    }

    /// Validate that a receipt correctly references its intent.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeEnforcementError::ReceiptValidation` if binding fails.
    pub fn validate_receipt_binding(
        &self,
        receipt: &OperationReceipt,
        intent: &OperationIntent,
    ) -> Result<(), MeshNodeEnforcementError> {
        fcp_core::validate_receipt_intent_binding(receipt, intent)?;
        Ok(())
    }

    /// Announce an admitted object for gossip.
    pub fn announce_object(
        &mut self,
        zone_id: &ZoneId,
        object_id: &ObjectId,
        mut admission: ObjectAdmissionClass,
        now_ms: u64,
    ) -> bool {
        if self.quarantine_store.contains(object_id) {
            admission = ObjectAdmissionClass::Quarantined;
        }

        let added = self
            .gossip
            .announce_object(zone_id, object_id, admission, now_ms / 1000);
        if added {
            self.metrics.gossip_announcements += 1;
            if self.trace_zone_enabled(Some(zone_id)) {
                if let Some(trace_id) = self.trace_id() {
                    self.record_trace_event(TraceEvent::Gossip(GossipEvent {
                        timestamp: now_ms,
                        trace_id,
                        gossip_type: "announce_object".to_string(),
                        object_count: 1,
                        peer_node: None,
                        success: true,
                    }));
                }
            }
        }
        added
    }

    /// Announce a symbol for gossip (admitted objects only).
    pub fn announce_symbol(
        &mut self,
        zone_id: &ZoneId,
        object_id: &ObjectId,
        esi: u32,
        mut admission: ObjectAdmissionClass,
        now_ms: u64,
    ) -> bool {
        if self.quarantine_store.contains(object_id) {
            admission = ObjectAdmissionClass::Quarantined;
        }

        let added = self
            .gossip
            .announce_symbol(zone_id, object_id, esi, admission, now_ms / 1000);
        if added {
            self.metrics.gossip_announcements += 1;
            if self.trace_zone_enabled(Some(zone_id)) {
                if let Some(trace_id) = self.trace_id() {
                    self.record_trace_event(TraceEvent::Gossip(GossipEvent {
                        timestamp: now_ms,
                        trace_id,
                        gossip_type: "announce_symbol".to_string(),
                        object_count: 1,
                        peer_node: None,
                        success: true,
                    }));
                }
            }
        }
        added
    }

    /// Handle a symbol request using admission control and targeted repair.
    ///
    /// # Errors
    /// Returns `SymbolRequestError` on validation or store failures.
    pub async fn handle_symbol_request(
        &mut self,
        request: SymbolRequest,
        peer: &NodeId,
        is_authenticated: bool,
        now_ms: u64,
    ) -> Result<SymbolResponse, SymbolRequestError> {
        let (validated, meta) = self
            .validate_symbol_request(&request, peer, is_authenticated, now_ms)
            .await?;

        let response = match self
            .build_symbol_response(&request, &validated, &meta, now_ms)
            .await
        {
            Ok(response) => response,
            Err(err) => {
                self.record_admission_outcome(
                    peer,
                    "reject",
                    Some(Self::symbol_request_reason_code(&err)),
                    validated.is_authenticated,
                    Some(&request.zone_id),
                    now_ms,
                );
                return Err(err);
            }
        };

        self.record_admission_outcome(
            peer,
            "admit",
            None,
            validated.is_authenticated,
            Some(&request.zone_id),
            now_ms,
        );
        Ok(response)
    }

    fn check_symbol_request_gate(
        &mut self,
        request: &SymbolRequest,
        peer: &NodeId,
        authenticated: bool,
        now_ms: u64,
    ) -> Result<(), SymbolRequestError> {
        if self.symbol_requests.should_stop(&request.object_id) {
            self.record_admission_outcome(
                peer,
                "reject",
                Some(Self::symbol_request_reason_code(
                    &SymbolRequestError::AlreadyComplete {
                        object_id: request.object_id.to_string(),
                    },
                )),
                authenticated,
                Some(&request.zone_id),
                now_ms,
            );
            return Err(SymbolRequestError::AlreadyComplete {
                object_id: request.object_id.to_string(),
            });
        }

        if self.quarantine_store.contains(&request.object_id) {
            self.record_admission_outcome(
                peer,
                "reject",
                Some(Self::admission_reason_code(
                    &AdmissionError::ObjectQuarantined {
                        object_id: request.object_id.to_string(),
                    },
                )),
                authenticated,
                Some(&request.zone_id),
                now_ms,
            );
            return Err(SymbolRequestError::AdmissionRejected(
                AdmissionError::ObjectQuarantined {
                    object_id: request.object_id.to_string(),
                },
            ));
        }

        Ok(())
    }

    async fn validate_symbol_request(
        &mut self,
        request: &SymbolRequest,
        peer: &NodeId,
        is_authenticated: bool,
        now_ms: u64,
    ) -> Result<(ValidatedRequest, fcp_store::ObjectSymbolMeta), SymbolRequestError> {
        let mut authenticated = is_authenticated || self.is_peer_authenticated(peer);

        self.check_symbol_request_gate(request, peer, authenticated, now_ms)?;

        // Fetch metadata first to get accurate symbol size for admission control
        let meta = match self.load_symbol_meta(request).await {
            Ok(meta) => meta,
            Err(err) => {
                self.record_admission_outcome(
                    peer,
                    "reject",
                    Some(Self::symbol_request_reason_code(&err)),
                    authenticated,
                    Some(&request.zone_id),
                    now_ms,
                );
                return Err(err);
            }
        };

        if !authenticated {
            authenticated = match self.verify_symbol_request_signature(peer, request) {
                Ok(is_authenticated) => is_authenticated,
                Err(err) => {
                    self.record_admission_outcome(
                        peer,
                        "reject",
                        Some(Self::symbol_request_reason_code(&err)),
                        authenticated,
                        Some(&request.zone_id),
                        now_ms,
                    );
                    return Err(err);
                }
            };
        }
        self.admission
            .set_authenticated(peer, authenticated, now_ms);

        let validated = match self.symbol_requests.validate_request(
            request,
            authenticated,
            &mut self.admission,
            peer,
            now_ms,
            meta.oti.symbol_size,
        ) {
            Ok(validated) => {
                self.symbol_metrics.record_validated();
                validated
            }
            Err(SymbolRequestError::BoundsExceeded {
                requested,
                max_allowed,
            }) => {
                self.symbol_metrics.record_bounds_rejection();
                self.record_admission_outcome(
                    peer,
                    "reject",
                    Some(Self::symbol_request_reason_code(
                        &SymbolRequestError::BoundsExceeded {
                            requested,
                            max_allowed,
                        },
                    )),
                    authenticated,
                    Some(&request.zone_id),
                    now_ms,
                );
                return Err(SymbolRequestError::BoundsExceeded {
                    requested,
                    max_allowed,
                });
            }
            Err(SymbolRequestError::AdmissionRejected(err)) => {
                self.symbol_metrics.record_admission_rejection();
                self.record_admission_outcome(
                    peer,
                    "reject",
                    Some(Self::admission_reason_code(&err)),
                    authenticated,
                    Some(&request.zone_id),
                    now_ms,
                );
                return Err(SymbolRequestError::AdmissionRejected(err));
            }
            Err(err) => {
                self.record_admission_outcome(
                    peer,
                    "reject",
                    Some(Self::symbol_request_reason_code(&err)),
                    authenticated,
                    Some(&request.zone_id),
                    now_ms,
                );
                return Err(err);
            }
        };

        Ok((validated, meta))
    }

    async fn build_symbol_response(
        &mut self,
        request: &SymbolRequest,
        validated: &ValidatedRequest,
        meta: &fcp_store::ObjectSymbolMeta,
        now_ms: u64,
    ) -> Result<SymbolResponse, SymbolRequestError> {
        let symbols = self.symbol_store.get_all_symbols(&request.object_id).await;
        let mut available = HashSet::new();
        for symbol in symbols {
            available.insert(symbol.meta.esi);
        }

        if available.is_empty() {
            return Err(SymbolRequestError::ObjectNotFound {
                object_id: request.object_id.to_string(),
            });
        }

        let mut engine = TargetedRepairEngine::new();
        engine.register_available(request.object_id, available.iter().copied());

        let sent_entry = self
            .sent_symbols
            .entry(request.object_id)
            .or_insert_with(|| (now_ms, HashSet::new()));

        sent_entry.0 = now_ms; // Update timestamp
        let already_sent = &mut sent_entry.1;
        let already_sent_count = already_sent.len();

        let builder = SymbolResponseBuilder::new(
            request.object_id,
            meta.zone_id.clone(),
            request.zone_key_id,
            validated.max_response_symbols,
        );

        let response = builder
            .add_from_repair_engine(&engine, validated, already_sent)
            .build(available.len() as u32, already_sent_count);

        debug!(
            object_id = %response.object_id,
            symbols = response.symbol_esis.len(),
            was_bounded = response.was_bounded,
            "symbol request response prepared"
        );

        already_sent.extend(response.symbol_esis.iter().copied());
        self.symbol_requests
            .track_transfer(request, response.symbol_esis.iter().copied(), now_ms);
        self.symbol_metrics
            .record_symbols_sent(response.symbol_count(), request.missing_hint.is_some());

        Ok(response)
    }

    fn verify_symbol_request_signature(
        &self,
        peer: &NodeId,
        request: &SymbolRequest,
    ) -> Result<bool, SymbolRequestError> {
        let Some(key) = self.peer_signing_keys.get(peer) else {
            return Ok(false);
        };

        request
            .verify(key)
            .map(|()| true)
            .map_err(|_| SymbolRequestError::SignatureInvalid)
    }

    async fn load_symbol_meta(
        &self,
        request: &SymbolRequest,
    ) -> Result<fcp_store::ObjectSymbolMeta, SymbolRequestError> {
        let meta = self
            .symbol_store
            .get_object_meta(&request.object_id)
            .await
            .map_err(|err| match err {
                fcp_store::SymbolStoreError::ObjectNotFound(_) => {
                    SymbolRequestError::ObjectNotFound {
                        object_id: request.object_id.to_string(),
                    }
                }
                other => SymbolRequestError::InvalidRequest {
                    reason: format!("symbol store error: {other}"),
                },
            })?;

        if meta.zone_id != request.zone_id {
            return Err(SymbolRequestError::InvalidRequest {
                reason: format!(
                    "request zone_id {} does not match stored object zone_id {}",
                    request.zone_id, meta.zone_id
                ),
            });
        }

        Ok(meta)
    }

    /// Apply a decode status update (targeted repair feedback).
    pub fn handle_decode_status(&mut self, status: &DecodeStatus, now_ms: u64) {
        self.symbol_requests.process_decode_status(status, now_ms);
    }

    /// Apply a SymbolAck and stop further sends.
    pub fn handle_symbol_ack(&mut self, ack: &SymbolAck, now_ms: u64) {
        self.symbol_requests.process_symbol_ack(ack, now_ms);
        self.symbol_metrics.record_ack();
        self.sent_symbols.remove(&ack.object_id);
    }

    /// Prune stale state (transfers, sent_symbols).
    /// Returns total items pruned.
    pub fn prune_stale_state(&mut self, now_ms: u64) -> usize {
        let mut pruned = 0;

        // Prune symbol requests
        pruned += self.symbol_requests.prune_stale_state(now_ms);

        // Prune sent_symbols (using same TTL from policy)
        let ttl = self.symbol_requests.policy().transfer_state_ttl_ms;
        let expired_threshold = now_ms.saturating_sub(ttl);

        let initial_len = self.sent_symbols.len();
        self.sent_symbols
            .retain(|_, (ts, _)| *ts >= expired_threshold);
        pruned += initial_len - self.sent_symbols.len();

        if pruned > 0 {
            debug!(pruned, "pruned stale mesh node state");
        }
        pruned
    }

    /// Encode a control-plane envelope for degraded transport.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError::DegradedTransport` if encoding fails.
    pub fn encode_control_plane(
        &mut self,
        envelope: &ControlPlaneEnvelope,
        epoch_id: u64,
    ) -> Result<Vec<fcp_protocol::FcpsFrame>, MeshNodeError> {
        Ok(self.degraded_encoder.encode(envelope, epoch_id)?)
    }

    /// Decode a control-plane frame in degraded mode.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError::DegradedTransport` if decoding fails.
    pub fn decode_control_plane(
        &mut self,
        frame: &fcp_protocol::FcpsFrame,
        expected_zone_id: &ZoneId,
        retention: RetentionClass,
    ) -> Result<Option<ControlPlaneEnvelope>, MeshNodeError> {
        Ok(self
            .degraded_decoder
            .process_frame(frame, expected_zone_id, retention)?)
    }

    /// Decode a control-plane frame and enforce retention via handler.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError` if decoding fails or the handler rejects the
    /// envelope.
    pub fn process_control_plane_frame(
        &mut self,
        frame: &fcp_protocol::FcpsFrame,
        expected_zone_id: &ZoneId,
        retention: RetentionClass,
        handler: &dyn ControlPlaneHandler,
    ) -> Result<Option<ControlPlaneEnvelope>, MeshNodeError> {
        let envelope = self.decode_control_plane(frame, expected_zone_id, retention)?;
        if let Some(ref env) = envelope {
            handler.handle(env.clone())?;
        }
        Ok(envelope)
    }

    /// Snapshot metrics.
    #[must_use]
    pub fn metrics(&self) -> MeshNodeMetrics {
        let mut metrics = self.metrics.clone();
        metrics.symbol_requests = self.symbol_metrics.clone();
        metrics
    }

    /// Snapshot trace capture (if enabled).
    #[must_use]
    pub fn trace_snapshot(&self) -> Option<CapturedTrace> {
        self.trace_capture.as_ref().map(TraceCapture::snapshot)
    }

    /// Snapshot trace capture with redaction (if enabled).
    #[must_use]
    pub fn trace_redacted_snapshot(&self) -> Option<CapturedTrace> {
        self.trace_capture
            .as_ref()
            .map(TraceCapture::redacted_snapshot)
    }

    /// Export trace capture to a file.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError::TraceNotEnabled` if capture is disabled or
    /// `MeshNodeError::TraceExport` if serialization/IO fails.
    pub fn export_trace_to_path<P: AsRef<Path>>(
        &self,
        path: P,
        redacted: bool,
        format: TraceExportFormat,
    ) -> Result<(), MeshNodeError> {
        let Some(capture) = self.trace_capture.as_ref() else {
            return Err(MeshNodeError::TraceNotEnabled);
        };

        capture.export_to_path(path, redacted, format)?;
        Ok(())
    }

    /// Rank candidate transport paths according to zone policy.
    #[must_use]
    pub fn rank_transport_paths(
        &self,
        policy: &ZoneTransportPolicy,
        paths: &[TransportPath],
    ) -> Vec<RankedPath> {
        TransportSelector::rank_paths(paths, policy)
    }

    /// Select the best eligible transport path according to policy and priority.
    #[must_use]
    pub fn best_transport_path(
        &self,
        policy: &ZoneTransportPolicy,
        paths: &[TransportPath],
    ) -> Option<RankedPath> {
        TransportSelector::best_path(paths, policy)
    }

    /// Select deterministic multipath routes for a symbol.
    #[must_use]
    pub fn select_transport_paths(
        &mut self,
        policy: &ZoneTransportPolicy,
        paths: &[TransportPath],
        object_id: &ObjectId,
        symbol_index: u32,
        fanout: usize,
    ) -> Vec<TransportPath> {
        let selected =
            TransportSelector::select_multipath(paths, policy, object_id, symbol_index, fanout);

        if let Some(trace_id) = self.trace_id() {
            let now_ms = current_time_ms();
            if selected.is_empty() {
                self.record_trace_event(TraceEvent::Routing(RoutingDecision {
                    timestamp: now_ms,
                    trace_id,
                    source_node: self.local_node.as_str().to_string(),
                    target_node: None,
                    object_id: object_id.to_string(),
                    path_type: "none".to_string(),
                    decision: "dropped".to_string(),
                    reason: Some("no_eligible_path".to_string()),
                }));
            } else {
                for path in &selected {
                    self.record_trace_event(TraceEvent::Routing(RoutingDecision {
                        timestamp: now_ms,
                        trace_id: trace_id.clone(),
                        source_node: self.local_node.as_str().to_string(),
                        target_node: Some(path.peer.as_str().to_string()),
                        object_id: object_id.to_string(),
                        path_type: transport_path_kind_label(path.kind).to_string(),
                        decision: "routed".to_string(),
                        reason: None,
                    }));
                }
            }
        }

        selected
    }

    /// Access underlying gossip state (mutable).
    pub fn gossip_mut(&mut self) -> &mut MeshGossip {
        &mut self.gossip
    }

    /// Access admission controller (mutable).
    pub fn admission_mut(&mut self) -> &mut AdmissionController {
        &mut self.admission
    }

    /// Access object store.
    #[must_use]
    pub fn object_store(&self) -> &Arc<dyn ObjectStore> {
        &self.object_store
    }

    /// Access symbol store.
    #[must_use]
    pub fn symbol_store(&self) -> &Arc<dyn SymbolStore> {
        &self.symbol_store
    }

    /// Access quarantine store.
    #[must_use]
    pub fn quarantine_store(&self) -> &Arc<QuarantineStore> {
        &self.quarantine_store
    }
}

fn transport_path_kind_label(kind: crate::transport::TransportPathKind) -> &'static str {
    match kind {
        crate::transport::TransportPathKind::Direct => "direct",
        crate::transport::TransportPathKind::Mesh => "mesh",
        crate::transport::TransportPathKind::Derp => "derp",
        crate::transport::TransportPathKind::Funnel => "funnel",
    }
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransportPathKind;
    use crate::device::DeviceProfileBuilder;
    use crate::planner::{LeasePurpose, PlannerContext};
    use bytes::Bytes;
    use fcp_core::{ObjectId, ZoneId, ZoneKeyId};
    use fcp_crypto::Ed25519SigningKey;
    use fcp_protocol::session::{
        MeshSessionId, SessionCryptoSuite, SessionKeys, SessionReplayPolicy, TransportLimits,
    };
    use fcp_protocol::{
        DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED, DecodeStatus, SymbolAck, SymbolAckReason,
        SymbolRequest,
    };
    use fcp_store::{
        MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
        ObjectAdmissionPolicy, ObjectSymbolMeta, ObjectTransmissionInfo, QuarantineStore,
        QuarantinedObject, StoredSymbol, SymbolMeta,
    };
    use raptorq::ObjectTransmissionInformation;

    fn test_node(name: &str) -> MeshNode {
        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
        MeshNode::new(
            MeshNodeConfig::new(name).with_sender_instance_id(42),
            object_store,
            symbol_store,
            quarantine_store,
        )
    }

    fn test_node_with_trace(name: &str) -> MeshNode {
        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
        let trace_config = TraceCaptureConfig::new().enabled();
        MeshNode::new(
            MeshNodeConfig::new(name)
                .with_sender_instance_id(42)
                .with_trace_capture_config(trace_config),
            object_store,
            symbol_store,
            quarantine_store,
        )
    }

    fn test_device_profile(node_name: &str) -> DeviceProfile {
        DeviceProfileBuilder::new(NodeId::new(node_name)).build()
    }

    fn test_session(peer_name: &str) -> MeshSession {
        MeshSession::new(
            MeshSessionId::new(),
            NodeId::new(peer_name),
            SessionCryptoSuite::Suite1,
            SessionKeys {
                k_mac_i2r: [1u8; 32],
                k_mac_r2i: [2u8; 32],
                k_ctx: [3u8; 32],
            },
            TransportLimits::default(),
            true,
            1000,
            SessionReplayPolicy::default(),
        )
    }

    fn test_object_header() -> fcp_core::ObjectHeader {
        let zone_id = ZoneId::work();
        fcp_core::ObjectHeader {
            schema: fcp_cbor::SchemaId::new("fcp.test", "TestObj", semver::Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: fcp_core::Provenance::new(zone_id),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_object_id(name: &str) -> ObjectId {
        let hash = blake3::hash(name.as_bytes());
        ObjectId::from_bytes(*hash.as_bytes())
    }

    #[test]
    fn meshnode_transport_helpers_respect_policy() {
        let mut node = test_node("node-1");
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        };

        let paths = vec![
            TransportPath::new(
                TransportPathKind::Direct,
                NodeId::new("peer-1"),
                "direct",
                None,
            ),
            TransportPath::new(TransportPathKind::Derp, NodeId::new("peer-2"), "derp", None),
            TransportPath::new(
                TransportPathKind::Funnel,
                NodeId::new("peer-3"),
                "funnel",
                None,
            ),
        ];

        let ranked = node.rank_transport_paths(&policy, &paths);
        assert!(
            ranked
                .iter()
                .any(|entry| entry.path.kind == TransportPathKind::Direct)
        );
        assert!(
            ranked
                .iter()
                .any(|entry| entry.path.kind == TransportPathKind::Derp && !entry.eligible)
        );

        let object_id = test_object_id("meshnode-transport");
        let selection = node.select_transport_paths(&policy, &paths, &object_id, 1, 1);
        assert_eq!(selection.len(), 1);
        assert_eq!(selection[0].kind, TransportPathKind::Direct);
    }

    #[test]
    fn trace_capture_records_session_events() {
        let mut node = test_node_with_trace("node-1");
        let session = test_session("peer-1");
        let peer_id = session.peer_id.clone();

        node.register_session(session, 1000);
        node.remove_session(&peer_id, 2000);

        let snapshot = node.trace_snapshot().expect("trace capture enabled");
        assert_eq!(snapshot.events.len(), 2);
        assert!(matches!(snapshot.events[0], TraceEvent::Session(_)));
        assert!(matches!(snapshot.events[1], TraceEvent::Session(_)));
    }

    #[test]
    fn trace_capture_respects_zone_allowlist() {
        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
        let trace_config = TraceCaptureConfig::new().enabled();
        let mut node = MeshNode::new(
            MeshNodeConfig::new("node-1")
                .with_sender_instance_id(42)
                .with_trace_capture_config(trace_config)
                .with_trace_capture_zones([ZoneId::work()]),
            object_store,
            symbol_store,
            quarantine_store,
        );

        let object_id_work = test_object_id("trace-zone-work");
        let object_id_private = test_object_id("trace-zone-private");
        node.announce_object(
            &ZoneId::work(),
            &object_id_work,
            ObjectAdmissionClass::Admitted,
            10,
        );
        node.announce_object(
            &ZoneId::private(),
            &object_id_private,
            ObjectAdmissionClass::Admitted,
            20,
        );

        let snapshot = node.trace_snapshot().expect("trace capture enabled");
        assert_eq!(snapshot.events.len(), 1);
    }

    #[test]
    fn trace_capture_records_lease_deltas() {
        let mut node = test_node_with_trace("node-1");
        let lease = HeldLease {
            subject_id: test_object_id("lease-1"),
            purpose: LeasePurpose::SingletonWriter,
            expires_at: 100,
        };

        node.update_local_state(test_device_profile("node-1"), HashSet::new(), vec![lease]);

        let snapshot = node.trace_snapshot().expect("trace capture enabled");
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| matches!(event, TraceEvent::Lease(_)))
        );
    }

    #[test]
    fn meshnode_best_transport_path_returns_none_when_forbidden() {
        let node = test_node("node-1");
        let policy = ZoneTransportPolicy {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: false,
        };

        let paths = vec![TransportPath::new(
            TransportPathKind::Direct,
            NodeId::new("peer-1"),
            "direct",
            None,
        )];

        let best = node.best_transport_path(&policy, &paths);
        assert!(best.is_none());
    }

    // ---- Symbol request lifecycle tests ----

    #[test]
    fn prune_stale_state_clears_transfer_tracking() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([9u8; 8]);
        let object_id = test_object_id("meshnode-prune-state");

        let oti = ObjectTransmissionInformation::new(256, 64, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 2,
            first_symbol_at: 0,
        };

        let request = SymbolRequest::new(
            test_object_header(),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            2,
            1,
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        runtime.block_on(async {
            node.symbol_store
                .put_object_meta(meta)
                .await
                .expect("store meta");

            for esi in 0..2u32 {
                let symbol = StoredSymbol {
                    meta: SymbolMeta {
                        object_id,
                        esi,
                        zone_id: zone_id.clone(),
                        source_node: Some(1),
                        stored_at: 0,
                    },
                    data: bytes::Bytes::from(vec![u8::try_from(esi).unwrap_or(0); 64]),
                };
                node.symbol_store
                    .put_symbol(symbol)
                    .await
                    .expect("store symbol");
            }

            let _ = node
                .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
                .await
                .expect("symbol request");
        });

        assert_eq!(node.symbol_requests.active_transfer_count(), 1);
        assert!(node.sent_symbols.contains_key(&object_id));

        let ttl = node.symbol_requests.policy().transfer_state_ttl_ms;
        let pruned = node.prune_stale_state(ttl + 1);

        assert!(pruned > 0);
        assert_eq!(node.symbol_requests.active_transfer_count(), 0);
        assert!(!node.sent_symbols.contains_key(&object_id));
    }

    #[test]
    fn symbol_request_rejects_quarantined_object() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([10u8; 8]);
        let object_id = test_object_id("meshnode-quarantined-request");

        node.quarantine_store()
            .quarantine(QuarantinedObject {
                object_id,
                zone_id: zone_id.clone(),
                data: Bytes::from_static(b"quarantined"),
                source_peer: None,
                received_at: 0,
                peer_reputation: -5,
            })
            .expect("quarantine");

        let request = SymbolRequest::new(
            test_object_header(),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        let err = runtime.block_on(async {
            node.handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
                .await
                .expect_err("quarantined request should fail")
        });

        assert!(matches!(
            err,
            SymbolRequestError::AdmissionRejected(AdmissionError::ObjectQuarantined { .. })
        ));
    }

    #[test]
    fn symbol_request_accepts_signed_unauthenticated_peer() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([11u8; 8]);
        let object_id = test_object_id("meshnode-signed-unauth");
        let peer_id = NodeId::new("peer-1");

        let oti = ObjectTransmissionInformation::new(256, 64, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 2,
            first_symbol_at: 0,
        };

        let mut request = SymbolRequest::new(
            test_object_header(),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED + 5,
            1,
        );

        let signing_key = Ed25519SigningKey::generate();
        request.sign(&signing_key);
        node.register_peer_signing_key(peer_id.clone(), signing_key.verifying_key());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        let result = runtime.block_on(async {
            node.symbol_store
                .put_object_meta(meta)
                .await
                .expect("store meta");

            for esi in 0..2u32 {
                let symbol = StoredSymbol {
                    meta: SymbolMeta {
                        object_id,
                        esi,
                        zone_id: zone_id.clone(),
                        source_node: Some(1),
                        stored_at: 0,
                    },
                    data: bytes::Bytes::from(vec![u8::try_from(esi).unwrap_or(0); 64]),
                };
                node.symbol_store
                    .put_symbol(symbol)
                    .await
                    .expect("store symbol");
            }

            node.handle_symbol_request(request, &peer_id, false, 0)
                .await
        });

        assert!(result.is_ok());
    }

    #[test]
    fn symbol_request_rejects_invalid_signature() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([12u8; 8]);
        let object_id = test_object_id("meshnode-bad-signature");
        let peer_id = NodeId::new("peer-1");

        let oti = ObjectTransmissionInformation::new(256, 64, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 2,
            first_symbol_at: 0,
        };

        let mut request = SymbolRequest::new(
            test_object_header(),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED + 5,
            1,
        );

        let signing_key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();
        request.sign(&wrong_key);
        node.register_peer_signing_key(peer_id.clone(), signing_key.verifying_key());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        let err = runtime
            .block_on(async {
                node.symbol_store
                    .put_object_meta(meta)
                    .await
                    .expect("store meta");

                for esi in 0..2u32 {
                    let symbol = StoredSymbol {
                        meta: SymbolMeta {
                            object_id,
                            esi,
                            zone_id: zone_id.clone(),
                            source_node: Some(1),
                            stored_at: 0,
                        },
                        data: bytes::Bytes::from(vec![u8::try_from(esi).unwrap_or(0); 64]),
                    };
                    node.symbol_store
                        .put_symbol(symbol)
                        .await
                        .expect("store symbol");
                }

                node.handle_symbol_request(request, &peer_id, false, 0)
                    .await
            })
            .expect_err("invalid signature should fail");

        assert!(matches!(err, SymbolRequestError::SignatureInvalid));
    }

    // ---- MeshNodeConfig builder tests ----

    #[test]
    fn config_new_sets_node_id() {
        let config = MeshNodeConfig::new("test-node");
        assert_eq!(config.node_id, "test-node");
    }

    #[test]
    fn config_builder_methods_chain() {
        let policy = AdmissionPolicy::default();
        let gossip_config = GossipConfig::default();
        let sym_policy = SymbolRequestPolicy::default();
        let raptorq_config = RaptorQConfig::default();

        let config = MeshNodeConfig::new("node-1")
            .with_admission_policy(policy)
            .with_gossip_config(gossip_config)
            .with_symbol_request_policy(sym_policy)
            .with_raptorq_config(raptorq_config)
            .with_sender_instance_id(999);

        assert_eq!(config.node_id, "node-1");
        assert_eq!(config.sender_instance_id, 999);
    }

    // ---- Node identity tests ----

    #[test]
    fn local_node_id_matches_config() {
        let node = test_node("my-node");
        assert_eq!(node.local_node_id().as_str(), "my-node");
    }

    #[test]
    fn local_tailscale_id_matches_config() {
        let node = test_node("ts-node");
        assert_eq!(node.local_tailscale_id().as_str(), "ts-node");
    }

    // ---- Peer management tests ----

    #[test]
    fn initial_peer_count_is_zero() {
        let node = test_node("node-1");
        assert_eq!(node.peer_count(), 0);
    }

    #[test]
    fn update_peer_state_increments_count() {
        let mut node = test_node("node-1");
        let profile = test_device_profile("peer-1");

        node.update_peer_state(NodeId::new("peer-1"), profile, HashSet::new(), vec![], 1000);
        assert_eq!(node.peer_count(), 1);
    }

    #[test]
    fn update_same_peer_does_not_duplicate() {
        let mut node = test_node("node-1");
        let profile = test_device_profile("peer-1");

        node.update_peer_state(
            NodeId::new("peer-1"),
            profile.clone(),
            HashSet::new(),
            vec![],
            1000,
        );
        node.update_peer_state(NodeId::new("peer-1"), profile, HashSet::new(), vec![], 2000);
        assert_eq!(node.peer_count(), 1);
    }

    #[test]
    fn multiple_peers_tracked_independently() {
        let mut node = test_node("node-1");

        for i in 0..3 {
            let name = format!("peer-{i}");
            let profile = test_device_profile(&name);
            node.update_peer_state(NodeId::new(&name), profile, HashSet::new(), vec![], 1000);
        }
        assert_eq!(node.peer_count(), 3);
    }

    #[test]
    fn remove_peer_decrements_count() {
        let mut node = test_node("node-1");
        let profile = test_device_profile("peer-1");

        node.update_peer_state(NodeId::new("peer-1"), profile, HashSet::new(), vec![], 1000);
        assert_eq!(node.peer_count(), 1);

        node.remove_peer(&NodeId::new("peer-1"));
        assert_eq!(node.peer_count(), 0);
    }

    #[test]
    fn remove_nonexistent_peer_is_noop() {
        let mut node = test_node("node-1");
        node.remove_peer(&NodeId::new("ghost"));
        assert_eq!(node.peer_count(), 0);
    }

    // ---- Local state tests ----

    #[test]
    fn update_local_state_sets_profile() {
        let mut node = test_node("node-1");
        let profile = test_device_profile("node-1");

        node.update_local_state(profile, HashSet::new(), vec![]);
        assert!(node.local_profile.is_some());
    }

    // ---- Session management tests ----

    #[test]
    fn no_session_means_not_authenticated() {
        let node = test_node("node-1");
        assert!(!node.is_peer_authenticated(&NodeId::new("peer-1")));
    }

    #[test]
    fn register_session_authenticates_peer() {
        let mut node = test_node("node-1");
        let session = test_session("peer-1");

        node.register_session(session, 1000);
        assert!(node.is_peer_authenticated(&NodeId::new("peer-1")));
    }

    #[test]
    fn remove_session_deauthenticates_peer() {
        let mut node = test_node("node-1");
        let session = test_session("peer-1");

        node.register_session(session, 1000);
        assert!(node.is_peer_authenticated(&NodeId::new("peer-1")));

        node.remove_session(&NodeId::new("peer-1"), 2000);
        assert!(!node.is_peer_authenticated(&NodeId::new("peer-1")));
    }

    // ---- Gossip delegation tests ----

    #[test]
    fn announce_object_increments_metric() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        let added =
            node.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, 1000);
        assert!(added);
        assert_eq!(node.metrics().gossip_announcements, 1);
    }

    #[test]
    fn announce_symbol_increments_metric() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let object_id = ObjectId::from_bytes([0x22; 32]);

        let added = node.announce_symbol(
            &zone_id,
            &object_id,
            0,
            ObjectAdmissionClass::Admitted,
            1000,
        );
        assert!(added);
        assert_eq!(node.metrics().gossip_announcements, 1);
    }

    #[test]
    fn quarantined_object_not_announced() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let object_id = ObjectId::from_bytes([0x33; 32]);

        let added = node.announce_object(
            &zone_id,
            &object_id,
            ObjectAdmissionClass::Quarantined,
            1000,
        );
        // Quarantined objects must not be gossiped (NORMATIVE)
        assert!(!added);
        assert_eq!(node.metrics().gossip_announcements, 0);
    }

    #[test]
    fn quarantine_store_overrides_admission() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let object_id = ObjectId::from_bytes([0x34; 32]);

        node.quarantine_store()
            .quarantine(QuarantinedObject {
                object_id,
                zone_id: zone_id.clone(),
                data: Bytes::from_static(b"quarantined"),
                source_peer: None,
                received_at: 0,
                peer_reputation: -10,
            })
            .expect("quarantine");

        let added =
            node.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, 1000);
        assert!(!added);
        assert_eq!(node.metrics().gossip_announcements, 0);
    }

    #[test]
    fn quarantine_store_overrides_symbol_admission() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let object_id = ObjectId::from_bytes([0x35; 32]);

        node.quarantine_store()
            .quarantine(QuarantinedObject {
                object_id,
                zone_id: zone_id.clone(),
                data: Bytes::from_static(b"quarantined"),
                source_peer: None,
                received_at: 0,
                peer_reputation: -10,
            })
            .expect("quarantine");

        let added = node.announce_symbol(
            &zone_id,
            &object_id,
            0,
            ObjectAdmissionClass::Admitted,
            1000,
        );
        assert!(!added);
        assert_eq!(node.metrics().gossip_announcements, 0);
    }

    // ---- Decode status / ack delegation tests ----

    #[test]
    fn handle_decode_status_delegates_to_handler() {
        let mut node = test_node("node-1");
        let object_id = ObjectId::from_bytes([0x44; 32]);

        let status = DecodeStatus {
            header: test_object_header(),
            object_id,
            zone_id: ZoneId::work(),
            zone_key_id: ZoneKeyId::from_bytes([0x55; 8]),
            epoch_id: 1,
            received_unique: 10,
            needed: 0,
            complete: true,
            missing_hint: None,
            signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
        };

        // Should not panic
        node.handle_decode_status(&status, 1000);
    }

    #[test]
    fn handle_symbol_ack_increments_ack_metric() {
        let mut node = test_node("node-1");
        let object_id = ObjectId::from_bytes([0x66; 32]);

        let ack = SymbolAck::new(
            test_object_header(),
            object_id,
            ZoneId::work(),
            ZoneKeyId::from_bytes([0x77; 8]),
            1,
            SymbolAckReason::Complete,
            5,
        );

        node.handle_symbol_ack(&ack, 1000);
        assert_eq!(node.metrics().symbol_requests.acks_received, 1);
    }

    // ---- Metrics tests ----

    #[test]
    fn initial_metrics_are_zero() {
        let node = test_node("node-1");
        let m = node.metrics();
        assert_eq!(m.gossip_announcements, 0);
        assert_eq!(m.gossip_updates, 0);
        assert_eq!(m.peer_updates, 0);
        assert_eq!(m.symbol_requests.acks_received, 0);
    }

    #[test]
    fn peer_update_metric_increments() {
        let mut node = test_node("node-1");
        let profile = test_device_profile("peer-1");

        node.update_peer_state(NodeId::new("peer-1"), profile, HashSet::new(), vec![], 1000);
        assert_eq!(node.metrics().peer_updates, 1);
    }

    // ---- Planner integration tests ----

    #[test]
    fn build_planner_input_without_local_state_is_empty() {
        let node = test_node("node-1");
        let input = node.build_planner_input(1000);
        assert!(input.nodes.is_empty());
    }

    #[test]
    fn build_planner_input_includes_local_and_peers() {
        let mut node = test_node("node-1");
        let local_profile = test_device_profile("node-1");
        let peer_profile = test_device_profile("peer-1");

        node.update_local_state(local_profile, HashSet::new(), vec![]);
        node.update_peer_state(
            NodeId::new("peer-1"),
            peer_profile,
            HashSet::new(),
            vec![],
            1000,
        );

        let input = node.build_planner_input(2000);
        assert_eq!(input.nodes.len(), 2);
    }

    #[test]
    fn build_planner_input_includes_singleton_holder() {
        let mut node = test_node("node-1");
        let local_profile = test_device_profile("node-1");
        let obj_id = ObjectId::from_bytes([0xAA; 32]);

        let lease = HeldLease {
            subject_id: obj_id,
            purpose: LeasePurpose::SingletonWriter,
            expires_at: 999_999, // Far future
        };

        node.update_local_state(local_profile, HashSet::new(), vec![lease]);

        let input = node.build_planner_input(1000);
        assert_eq!(input.nodes.len(), 1);
        assert!(input.singleton_lease_holder.is_some());
    }

    #[test]
    fn plan_execution_returns_candidates() {
        use crate::device::{DeviceProfileBuilder, InstalledConnector};

        let mut node = test_node("node-1");
        let connector_id =
            fcp_core::ConnectorId::new("fcp.test", "test", "v1").expect("valid connector id");
        let installed = InstalledConnector::new(
            connector_id.clone(),
            "1.0.0",
            ObjectId::from_bytes([0xBB; 32]),
        );
        let local_profile = DeviceProfileBuilder::new(NodeId::new("node-1"))
            .add_connector(installed)
            .build();

        node.update_local_state(local_profile, HashSet::new(), vec![]);

        let context = PlannerContext::new(connector_id);
        let candidates = node.plan_execution(&context, 2000);
        // Node has the required connector installed, should be a candidate
        assert!(!candidates.is_empty());
    }

    // ---- Store accessor tests ----

    #[test]
    fn store_accessors_return_valid_refs() {
        let node = test_node("node-1");
        // Just verify the accessors don't panic and return the stores
        let _ = node.object_store();
        let _ = node.symbol_store();
        let _ = node.quarantine_store();
    }

    // ---- Mutable accessor tests ----

    #[test]
    fn gossip_mut_and_admission_mut_accessible() {
        let mut node = test_node("node-1");
        // Should not panic - verifies mutable borrows work
        let _ = node.gossip_mut();
        let _ = node.admission_mut();
    }

    // ---- Error type coverage ----

    #[test]
    fn error_types_display_correctly() {
        let err = MeshNodeEnforcementError::HolderProofRequired {
            holder_node: "node-1".to_string(),
        };
        assert!(err.to_string().contains("holder proof required"));

        let err = MeshNodeEnforcementError::HolderProofNodeMismatch {
            expected: "node-1".to_string(),
            actual: "node-2".to_string(),
        };
        assert!(err.to_string().contains("node mismatch"));

        let err = MeshNodeEnforcementError::HolderProofInvalid;
        assert!(err.to_string().contains("verification failed"));

        let err = MeshNodeEnforcementError::HolderKeyMissing {
            holder_node: "node-1".to_string(),
        };
        assert!(err.to_string().contains("key missing"));

        let err = MeshNodeEnforcementError::MissingTokenJti;
        assert!(err.to_string().contains("missing jti"));

        let err = MeshNodeEnforcementError::TokenRevoked {
            token_id: ObjectId::from_bytes([0x00; 32]),
        };
        assert!(err.to_string().contains("revoked"));
    }

    #[test]
    fn mesh_node_error_variants_display() {
        let admission_err = AdmissionError::ObjectQuarantined {
            object_id: "test".to_string(),
        };
        let err = MeshNodeError::Admission(admission_err);
        assert!(err.to_string().contains("admission rejected"));

        let sym_err = SymbolRequestError::AlreadyComplete {
            object_id: "test".to_string(),
        };
        let err = MeshNodeError::SymbolRequest(sym_err);
        assert!(err.to_string().contains("symbol request error"));
    }
}
