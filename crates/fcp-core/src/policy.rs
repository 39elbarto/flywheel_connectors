//! Policy objects and evaluation helpers for FCP2.
//!
//! This module defines zone policy objects and a minimal evaluation pipeline
//! that produces stable decision reason codes and decision receipts.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use fcp_cbor::SchemaId;
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::{
    ApprovalScope, ApprovalToken, CapabilityGrant, CapabilityId, ConfidentialityLevel, ConnectorId,
    Decision, DecisionReceipt, FlowCheckResult, IntegrityLevel, InvokeRequest, NodeId,
    NodeSignature, ObjectHeader, ObjectId, OperationId, PrincipalId, Provenance, ProvenanceRecord,
    ProvenanceViolation, RoleObject, SafetyTier, SanitizerReceipt, TaintFlag, TaintFlags,
    TaintLevel, ZoneId,
};

// ─────────────────────────────────────────────────────────────────────────────
// Zone Transport Policy
// ─────────────────────────────────────────────────────────────────────────────

/// Transport modes observed by the policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// Direct LAN/peer-to-peer transport.
    Lan,
    /// DERP relay transport.
    Derp,
    /// Funnel ingress transport.
    Funnel,
}

/// Zone transport policy (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTransportPolicy {
    pub allow_lan: bool,
    pub allow_derp: bool,
    pub allow_funnel: bool,
}

impl ZoneTransportPolicy {
    /// Check whether a transport mode is permitted.
    #[must_use]
    pub const fn allows(&self, mode: TransportMode) -> bool {
        match mode {
            TransportMode::Lan => self.allow_lan,
            TransportMode::Derp => self.allow_derp,
            TransportMode::Funnel => self.allow_funnel,
        }
    }
}

impl Default for ZoneTransportPolicy {
    fn default() -> Self {
        Self {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        }
    }
}

/// Decision receipt emission policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionReceiptPolicy {
    pub emit_on_allow: bool,
    pub emit_on_deny: bool,
}

impl Default for DecisionReceiptPolicy {
    fn default() -> Self {
        Self {
            emit_on_allow: false,
            emit_on_deny: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy Objects
// ─────────────────────────────────────────────────────────────────────────────

/// `ZoneDefinitionObject` (owner-signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneDefinitionObject {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub name: String,
    pub integrity_level: IntegrityLevel,
    pub confidentiality_level: ConfidentialityLevel,
    pub symbol_port: u16,
    pub control_port: u16,
    pub transport_policy: ZoneTransportPolicy,
    pub policy_object_id: ObjectId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<ObjectId>,
    pub signature: NodeSignature,
}

/// `ZonePolicyObject` (owner-signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonePolicyObject {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    #[serde(default)]
    pub principal_allow: Vec<PolicyPattern>,
    #[serde(default)]
    pub principal_deny: Vec<PolicyPattern>,
    #[serde(default)]
    pub connector_allow: Vec<PolicyPattern>,
    #[serde(default)]
    pub connector_deny: Vec<PolicyPattern>,
    #[serde(default)]
    pub capability_allow: Vec<PolicyPattern>,
    #[serde(default)]
    pub capability_deny: Vec<PolicyPattern>,
    #[serde(default)]
    pub capability_ceiling: Vec<CapabilityId>,
    #[serde(default)]
    pub transport_policy: ZoneTransportPolicy,
    #[serde(default)]
    pub decision_receipts: DecisionReceiptPolicy,
    /// Device posture requirements for this zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_posture: Option<crate::posture::PostureRequirements>,
}

/// A bounded glob-only policy pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPattern {
    pub pattern: String,
}

impl PolicyPattern {
    #[must_use]
    pub fn matches(&self, value: &str) -> bool {
        pattern_matches(&self.pattern, value)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Resource Objects
// ─────────────────────────────────────────────────────────────────────────────

/// Zone-bound handle to an external resource (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceObject {
    pub header: ObjectHeader,
    pub resource_uri: String,
    pub integrity_label: IntegrityLevel,
    pub confidentiality_label: ConfidentialityLevel,
    #[serde(default)]
    pub taint_flags: TaintFlags,
}

// ─────────────────────────────────────────────────────────────────────────────
// Decision Reason Codes
// ─────────────────────────────────────────────────────────────────────────────

/// Stable policy decision reason codes (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionReasonCode {
    Allow,
    CapabilityInsufficient,
    CheckpointStaleFrontier,
    RevocationStaleFrontier,
    TaintPublicInputDangerous,
    TaintUnverifiedLinkRisky,
    TaintMaliciousInput,
    TaintRiskyRequiresElevation,
    TaintCrossZoneUnapproved,
    IntegrityInsufficient,
    ZonePolicyPrincipalDenied,
    ZonePolicyConnectorDenied,
    ZonePolicyCapabilityDenied,
    ZonePolicyPrincipalNotAllowed,
    ZonePolicyConnectorNotAllowed,
    ZonePolicyCapabilityNotAllowed,
    ApprovalMissingElevation,
    ApprovalMissingDeclassification,
    ApprovalMissingExecution,
    ApprovalExecutionScopeMismatch,
    ApprovalExpired,
    ApprovalZoneMismatch,
    ApprovalTokenInvalid,
    TransportDerpForbidden,
    TransportFunnelForbidden,
    TransportLanForbidden,
    SanitizerReceiptInvalid,
    SanitizerCoverageInsufficient,
    PostureAttestationMissing,
    PostureAttestationExpired,
    PostureAttestationInvalid,
    PostureRequirementNotMet,
    PostureVerifierNotAllowed,
}

impl DecisionReasonCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::CapabilityInsufficient => "capability.insufficient",
            Self::CheckpointStaleFrontier => "checkpoint.stale_frontier",
            Self::RevocationStaleFrontier => "revocation.stale_frontier",
            Self::TaintPublicInputDangerous => "taint.public_input_dangerous",
            Self::TaintUnverifiedLinkRisky => "taint.unverified_link_risky",
            Self::TaintMaliciousInput => "taint.malicious_input",
            Self::TaintRiskyRequiresElevation => "taint.risky_requires_elevation",
            Self::TaintCrossZoneUnapproved => "taint.cross_zone_unapproved",
            Self::IntegrityInsufficient => "integrity.insufficient",
            Self::ZonePolicyPrincipalDenied => "zone_policy.principal_denied",
            Self::ZonePolicyConnectorDenied => "zone_policy.connector_denied",
            Self::ZonePolicyCapabilityDenied => "zone_policy.capability_denied",
            Self::ZonePolicyPrincipalNotAllowed => "zone_policy.principal_not_allowed",
            Self::ZonePolicyConnectorNotAllowed => "zone_policy.connector_not_allowed",
            Self::ZonePolicyCapabilityNotAllowed => "zone_policy.capability_not_allowed",
            Self::ApprovalMissingElevation => "approval.missing_elevation",
            Self::ApprovalMissingDeclassification => "approval.missing_declassification",
            Self::ApprovalMissingExecution => "approval.missing_execution",
            Self::ApprovalExecutionScopeMismatch => "approval.execution_scope_mismatch",
            Self::ApprovalExpired => "approval.expired",
            Self::ApprovalZoneMismatch => "approval.zone_mismatch",
            Self::ApprovalTokenInvalid => "approval.token_invalid",
            Self::TransportDerpForbidden => "transport.derp_forbidden",
            Self::TransportFunnelForbidden => "transport.funnel_forbidden",
            Self::TransportLanForbidden => "transport.lan_forbidden",
            Self::SanitizerReceiptInvalid => "taint.sanitizer_invalid",
            Self::SanitizerCoverageInsufficient => "taint.sanitizer_coverage_insufficient",
            Self::PostureAttestationMissing => "posture.attestation_missing",
            Self::PostureAttestationExpired => "posture.attestation_expired",
            Self::PostureAttestationInvalid => "posture.attestation_invalid",
            Self::PostureRequirementNotMet => "posture.requirement_not_met",
            Self::PostureVerifierNotAllowed => "posture.verifier_not_allowed",
        }
    }

    #[must_use]
    pub const fn from_provenance_violation(error: &ProvenanceViolation) -> Self {
        match error {
            ProvenanceViolation::PublicInputForDangerousOperation => {
                Self::TaintPublicInputDangerous
            }
            ProvenanceViolation::MaliciousInputDetected => Self::TaintMaliciousInput,
            ProvenanceViolation::TaintedInputForRiskyOperation { .. } => {
                Self::TaintRiskyRequiresElevation
            }
            ProvenanceViolation::InsufficientIntegrity { .. } => Self::IntegrityInsufficient,
            ProvenanceViolation::InvalidElevation { .. } => Self::ApprovalMissingElevation,
            ProvenanceViolation::InvalidDeclassification { .. } => {
                Self::ApprovalMissingDeclassification
            }
            ProvenanceViolation::CrossZoneUnapprovedForDangerousOperation => {
                Self::TaintCrossZoneUnapproved
            }
            ProvenanceViolation::SanitizerCoverageInsufficient => {
                Self::SanitizerCoverageInsufficient
            }
            ProvenanceViolation::ApprovalTokenInvalid => Self::ApprovalTokenInvalid,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Decision Models
// ─────────────────────────────────────────────────────────────────────────────

/// Policy decision result.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub reason_code: DecisionReasonCode,
    pub evidence: Vec<ObjectId>,
    pub explanation: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy Simulation (CLI/Test Harness Support)
// ─────────────────────────────────────────────────────────────────────────────

/// Input payload for policy simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySimulationInput {
    /// Zone policy to evaluate (authoritative for simulation).
    pub zone_policy: ZonePolicyObject,
    /// Invoke request under evaluation.
    pub invoke_request: InvokeRequest,
    /// Transport mode to evaluate against.
    #[serde(default = "default_transport_mode")]
    pub transport: TransportMode,
    /// Whether checkpoint freshness is satisfied.
    #[serde(default = "default_true")]
    pub checkpoint_fresh: bool,
    /// Whether revocation freshness is satisfied.
    #[serde(default = "default_true")]
    pub revocation_fresh: bool,
    /// Whether execution approvals are required for this operation.
    #[serde(default)]
    pub execution_approval_required: bool,
    /// Sanitizer receipts to apply (optional).
    #[serde(default)]
    pub sanitizer_receipts: Vec<SanitizerReceipt>,
    /// Related object ids (optional).
    #[serde(default)]
    pub related_object_ids: Vec<ObjectId>,
    /// Explicit request object id override (optional).
    #[serde(default)]
    pub request_object_id: Option<ObjectId>,
    /// Explicit input hash override (optional).
    #[serde(default)]
    pub request_input_hash: Option<[u8; 32]>,
    /// Safety tier for the requested operation.
    #[serde(default = "default_safety_tier")]
    pub safety_tier: SafetyTier,
    /// Optional principal override (otherwise derived from capability token).
    #[serde(default)]
    pub principal: Option<String>,
    /// Optional capability id override (otherwise derived from capability token).
    #[serde(default)]
    pub capability_id: Option<String>,
    /// Optional explicit provenance record (otherwise derived from request/zone).
    #[serde(default)]
    pub provenance_record: Option<ProvenanceRecord>,
    /// Optional override for evaluation time (epoch ms).
    #[serde(default)]
    pub now_ms: Option<u64>,
    /// Optional device posture attestation.
    #[serde(default)]
    pub posture_attestation: Option<crate::posture::PostureAttestation>,
}

/// Errors returned by policy simulation.
#[derive(Debug, thiserror::Error)]
pub enum PolicySimulationError {
    #[error("missing required claim: {claim}")]
    MissingClaim { claim: &'static str },
    #[error("invalid principal id '{value}': {message}")]
    InvalidPrincipal { value: String, message: String },
    #[error("invalid capability id '{value}': {message}")]
    InvalidCapability { value: String, message: String },
    #[error("failed to parse token claims: {message}")]
    TokenClaims { message: String },
    #[error("zone mismatch: request zone '{request_zone}' vs policy zone '{policy_zone}'")]
    ZoneMismatch {
        request_zone: String,
        policy_zone: String,
    },
}

/// Simulate a policy decision for a given invocation.
///
/// This does NOT execute connector logic or write mesh objects.
///
/// # Errors
/// Returns [`PolicySimulationError`] if required inputs are missing or invalid.
pub fn simulate_policy_decision(
    input: &PolicySimulationInput,
) -> Result<DecisionReceipt, PolicySimulationError> {
    let invoke = &input.invoke_request;
    if invoke.zone_id != input.zone_policy.zone_id {
        return Err(PolicySimulationError::ZoneMismatch {
            request_zone: invoke.zone_id.as_str().to_string(),
            policy_zone: input.zone_policy.zone_id.as_str().to_string(),
        });
    }

    let claims = invoke
        .capability_token
        .raw
        .claims_unverified()
        .map_err(|err| PolicySimulationError::TokenClaims {
            message: err.to_string(),
        })?;

    let principal_str = input
        .principal
        .as_deref()
        .or_else(|| claims.get_subject())
        .ok_or(PolicySimulationError::MissingClaim { claim: "sub" })?;
    let principal =
        PrincipalId::new(principal_str).map_err(|err| PolicySimulationError::InvalidPrincipal {
            value: principal_str.to_string(),
            message: err.to_string(),
        })?;

    let capability_str = input
        .capability_id
        .as_deref()
        .or_else(|| claims.get_capability_id())
        .ok_or(PolicySimulationError::MissingClaim {
            claim: "capability_id",
        })?;
    let capability_id = CapabilityId::new(capability_str).map_err(|err| {
        PolicySimulationError::InvalidCapability {
            value: capability_str.to_string(),
            message: err.to_string(),
        }
    })?;

    let request_object_id = input
        .request_object_id
        .unwrap_or_else(|| ObjectId::from_unscoped_bytes(invoke.id.0.as_bytes()));

    let provenance = input
        .provenance_record
        .clone()
        .unwrap_or_else(|| provenance_from_request(invoke));

    let now_ms = input
        .now_ms
        .unwrap_or_else(|| u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0));

    let decision_input = PolicyDecisionInput {
        request_object_id,
        zone_id: invoke.zone_id.clone(),
        principal,
        connector_id: invoke.connector_id.clone(),
        operation_id: invoke.operation.clone(),
        capability_id,
        safety_tier: input.safety_tier,
        provenance,
        approval_tokens: &invoke.approval_tokens,
        sanitizer_receipts: &input.sanitizer_receipts,
        request_input: Some(&invoke.input),
        request_input_hash: input.request_input_hash,
        related_object_ids: &input.related_object_ids,
        transport: input.transport,
        checkpoint_fresh: input.checkpoint_fresh,
        revocation_fresh: input.revocation_fresh,
        execution_approval_required: input.execution_approval_required,
        now_ms,
        posture_attestation: input.posture_attestation.as_ref(),
    };

    let engine = PolicyEngine {
        zone_policy: input.zone_policy.clone(),
    };
    let decision = engine.evaluate_invoke(&decision_input);
    let header = ObjectHeader {
        schema: SchemaId::new("fcp.core", "DecisionReceipt", Version::new(1, 0, 0)),
        zone_id: invoke.zone_id.clone(),
        created_at: now_ms / 1000,
        provenance: Provenance::new(invoke.zone_id.clone()),
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    };
    let signature = NodeSignature::new(NodeId::new("policy-sim"), [0u8; 64], now_ms / 1000);

    Ok(decision.to_receipt(header, request_object_id, signature))
}

const fn default_true() -> bool {
    true
}

const fn default_transport_mode() -> TransportMode {
    TransportMode::Lan
}

const fn default_safety_tier() -> SafetyTier {
    SafetyTier::Safe
}

fn provenance_from_request(req: &InvokeRequest) -> ProvenanceRecord {
    let origin = req
        .provenance
        .as_ref()
        .map_or_else(|| req.zone_id.clone(), |p| p.origin_zone.clone());
    let mut record = ProvenanceRecord::new(origin);

    if let Some(prov) = &req.provenance {
        match prov.taint {
            TaintLevel::Untainted => {}
            TaintLevel::Tainted => {
                record.taint_flags.insert(TaintFlag::PublicInput);
            }
            TaintLevel::HighlyTainted => {
                record.taint_flags.insert(TaintFlag::PublicInput);
                record.taint_flags.insert(TaintFlag::PotentiallyMalicious);
            }
        }
    }

    record
}

impl PolicyDecision {
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub const fn allow(evidence: Vec<ObjectId>) -> Self {
        Self {
            decision: Decision::Allow,
            reason_code: DecisionReasonCode::Allow,
            evidence,
            explanation: None,
        }
    }

    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub const fn deny(reason_code: DecisionReasonCode, evidence: Vec<ObjectId>) -> Self {
        Self {
            decision: Decision::Deny,
            reason_code,
            evidence,
            explanation: None,
        }
    }

    #[must_use]
    pub fn to_receipt(
        &self,
        header: ObjectHeader,
        request_object_id: ObjectId,
        signature: NodeSignature,
    ) -> DecisionReceipt {
        DecisionReceipt {
            header,
            request_object_id,
            decision: self.decision,
            reason_code: self.reason_code.as_str().to_string(),
            evidence: self.evidence.clone(),
            explanation: self.explanation.clone(),
            signature,
        }
    }
}

/// Invocation context for policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecisionInput<'a> {
    pub request_object_id: ObjectId,
    pub zone_id: ZoneId,
    pub principal: PrincipalId,
    pub connector_id: ConnectorId,
    pub operation_id: OperationId,
    pub capability_id: CapabilityId,
    pub safety_tier: SafetyTier,
    pub provenance: ProvenanceRecord,
    pub approval_tokens: &'a [ApprovalToken],
    pub sanitizer_receipts: &'a [SanitizerReceipt],
    pub request_input: Option<&'a serde_json::Value>,
    pub request_input_hash: Option<[u8; 32]>,
    pub related_object_ids: &'a [ObjectId],
    pub transport: TransportMode,
    pub checkpoint_fresh: bool,
    pub revocation_fresh: bool,
    pub execution_approval_required: bool,
    pub now_ms: u64,
    /// Device posture attestation for the requesting node.
    pub posture_attestation: Option<&'a crate::posture::PostureAttestation>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy Engine
// ─────────────────────────────────────────────────────────────────────────────

/// Policy evaluator for `ZonePolicyObject` instances.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    pub zone_policy: ZonePolicyObject,
}

impl PolicyEngine {
    /// Evaluate an invocation request against the zone policy.
    #[must_use]
    pub fn evaluate_invoke(&self, input: &PolicyDecisionInput<'_>) -> PolicyDecision {
        if !input.revocation_fresh {
            return PolicyDecision::deny(DecisionReasonCode::RevocationStaleFrontier, Vec::new());
        }
        if !input.checkpoint_fresh {
            return PolicyDecision::deny(DecisionReasonCode::CheckpointStaleFrontier, Vec::new());
        }

        if let Some(reason) = check_transport(&self.zone_policy.transport_policy, input.transport) {
            return PolicyDecision::deny(reason, Vec::new());
        }

        if let Some(reason) = check_pattern_lists(&self.zone_policy, input) {
            return PolicyDecision::deny(reason, Vec::new());
        }

        // Check posture requirements
        if let Some(ref posture_requirements) = self.zone_policy.requires_posture {
            if !posture_requirements.is_empty() {
                if let Some(reason) = check_posture(posture_requirements, input) {
                    return PolicyDecision::deny(reason, Vec::new());
                }
            }
        }

        if !self.zone_policy.capability_ceiling.is_empty()
            && !self
                .zone_policy
                .capability_ceiling
                .contains(&input.capability_id)
        {
            return PolicyDecision::deny(DecisionReasonCode::CapabilityInsufficient, Vec::new());
        }

        let mut evidence = Vec::new();
        let mut provenance = input.provenance.clone();

        if let Some(reason) = apply_sanitizer_receipts(input, &mut provenance, &mut evidence) {
            return PolicyDecision::deny(reason, evidence);
        }

        if matches!(
            input.safety_tier,
            SafetyTier::Risky
                | SafetyTier::Dangerous
                | SafetyTier::Critical
                | SafetyTier::Forbidden
        ) && provenance.taint_flags.contains(TaintFlag::UnverifiedLink)
        {
            return PolicyDecision::deny(DecisionReasonCode::TaintUnverifiedLinkRisky, evidence);
        }

        if matches!(
            input.safety_tier,
            SafetyTier::Dangerous | SafetyTier::Critical | SafetyTier::Forbidden
        ) && provenance.taint_flags.contains(TaintFlag::PublicInput)
        {
            return PolicyDecision::deny(DecisionReasonCode::TaintPublicInputDangerous, evidence);
        }

        if let Some(reason) = apply_flow_approvals(input, &mut provenance, &mut evidence) {
            return PolicyDecision::deny(reason, evidence);
        }

        if input.execution_approval_required {
            match find_execution_approval(input) {
                Ok(Some(token)) => evidence.push(approval_token_object_id(token)),
                Ok(None) => {
                    return PolicyDecision::deny(
                        DecisionReasonCode::ApprovalMissingExecution,
                        evidence,
                    );
                }
                Err(reason) => return PolicyDecision::deny(reason, evidence),
            }
        }

        if let Err(error) = provenance.can_drive_operation(input.safety_tier) {
            return PolicyDecision::deny(
                DecisionReasonCode::from_provenance_violation(&error),
                evidence,
            );
        }

        PolicyDecision::allow(evidence)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Role Graph (DAG enforcement)
// ─────────────────────────────────────────────────────────────────────────────

/// Role graph validation errors.
#[derive(Debug, thiserror::Error)]
pub enum RoleGraphError {
    #[error("unknown role id: {role_id}")]
    UnknownRole { role_id: ObjectId },

    #[error("role inheritance cycle detected: {cycle:?}")]
    RoleCycle { cycle: Vec<ObjectId> },
}

/// Role graph for resolving role inheritance.
#[derive(Debug, Clone)]
pub struct RoleGraph {
    roles: HashMap<ObjectId, RoleObject>,
}

impl RoleGraph {
    #[must_use]
    pub const fn new(roles: HashMap<ObjectId, RoleObject>) -> Self {
        Self { roles }
    }

    /// Validate that role inheritance is acyclic.
    ///
    /// # Errors
    /// Returns [`RoleGraphError::RoleCycle`] if a cycle is detected or
    /// [`RoleGraphError::UnknownRole`] if a referenced role is missing.
    pub fn validate_acyclic(&self) -> Result<(), RoleGraphError> {
        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();

        for role_id in self.roles.keys() {
            self.visit(role_id, &mut visiting, &mut visited, &mut Vec::new())?;
        }

        Ok(())
    }

    fn visit(
        &self,
        role_id: &ObjectId,
        visiting: &mut HashSet<ObjectId>,
        visited: &mut HashSet<ObjectId>,
        stack: &mut Vec<ObjectId>,
    ) -> Result<(), RoleGraphError> {
        if visited.contains(role_id) {
            return Ok(());
        }
        if visiting.contains(role_id) {
            stack.push(*role_id);
            return Err(RoleGraphError::RoleCycle {
                cycle: stack.clone(),
            });
        }

        let role = self
            .roles
            .get(role_id)
            .ok_or(RoleGraphError::UnknownRole { role_id: *role_id })?;

        visiting.insert(*role_id);
        stack.push(*role_id);

        for included in &role.includes {
            self.visit(included, visiting, visited, stack)?;
        }

        visiting.remove(role_id);
        visited.insert(*role_id);
        stack.pop();
        Ok(())
    }

    /// Resolve effective capability grants for a role set.
    ///
    /// # Errors
    /// Returns [`RoleGraphError::UnknownRole`] if any role id is missing.
    pub fn resolve_caps(
        &self,
        role_ids: &[ObjectId],
    ) -> Result<Vec<CapabilityGrant>, RoleGraphError> {
        let mut resolved = Vec::new();
        let mut seen = HashSet::new();

        for role_id in role_ids {
            self.collect_caps(role_id, &mut seen, &mut resolved)?;
        }

        Ok(resolved)
    }

    fn collect_caps(
        &self,
        role_id: &ObjectId,
        seen: &mut HashSet<ObjectId>,
        out: &mut Vec<CapabilityGrant>,
    ) -> Result<(), RoleGraphError> {
        if seen.contains(role_id) {
            return Ok(());
        }
        let role = self
            .roles
            .get(role_id)
            .ok_or(RoleGraphError::UnknownRole { role_id: *role_id })?;
        seen.insert(*role_id);
        out.extend(role.caps.iter().cloned());
        for included in &role.includes {
            self.collect_caps(included, seen, out)?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal Helpers
// ─────────────────────────────────────────────────────────────────────────────

const fn check_transport(
    policy: &ZoneTransportPolicy,
    mode: TransportMode,
) -> Option<DecisionReasonCode> {
    if policy.allows(mode) {
        None
    } else {
        Some(match mode {
            TransportMode::Lan => DecisionReasonCode::TransportLanForbidden,
            TransportMode::Derp => DecisionReasonCode::TransportDerpForbidden,
            TransportMode::Funnel => DecisionReasonCode::TransportFunnelForbidden,
        })
    }
}

fn check_pattern_lists(
    policy: &ZonePolicyObject,
    input: &PolicyDecisionInput<'_>,
) -> Option<DecisionReasonCode> {
    if matches_any(&policy.principal_deny, input.principal.as_ref()) {
        return Some(DecisionReasonCode::ZonePolicyPrincipalDenied);
    }
    if matches_any(&policy.connector_deny, input.connector_id.as_ref()) {
        return Some(DecisionReasonCode::ZonePolicyConnectorDenied);
    }
    if matches_any(&policy.capability_deny, input.capability_id.as_ref()) {
        return Some(DecisionReasonCode::ZonePolicyCapabilityDenied);
    }

    if !policy.principal_allow.is_empty()
        && !matches_any(&policy.principal_allow, input.principal.as_ref())
    {
        return Some(DecisionReasonCode::ZonePolicyPrincipalNotAllowed);
    }
    if !policy.connector_allow.is_empty()
        && !matches_any(&policy.connector_allow, input.connector_id.as_ref())
    {
        return Some(DecisionReasonCode::ZonePolicyConnectorNotAllowed);
    }
    if !policy.capability_allow.is_empty()
        && !matches_any(&policy.capability_allow, input.capability_id.as_ref())
    {
        return Some(DecisionReasonCode::ZonePolicyCapabilityNotAllowed);
    }

    None
}

fn matches_any(patterns: &[PolicyPattern], value: &str) -> bool {
    patterns.iter().any(|pattern| pattern.matches(value))
}

fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.is_empty() {
        return true;
    }

    let mut index = 0usize;
    for (idx, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if idx == 0 && !pattern.starts_with('*') && !value.starts_with(part) {
            return false;
        }
        if idx == parts.len() - 1 && !pattern.ends_with('*') && !value.ends_with(part) {
            return false;
        }

        match value[index..].find(part) {
            Some(pos) => {
                index += pos + part.len();
            }
            None => return false,
        }
    }

    true
}

fn check_posture(
    requirements: &crate::posture::PostureRequirements,
    input: &PolicyDecisionInput<'_>,
) -> Option<DecisionReasonCode> {
    use crate::posture::{PostureAttestation, PostureCheckResult};

    let Some(attestation) = input.posture_attestation else {
        return Some(DecisionReasonCode::PostureAttestationMissing);
    };

    // Check expiry first (before is_valid which also checks expiry)
    if attestation.is_expired() {
        return Some(DecisionReasonCode::PostureAttestationExpired);
    }

    // Check schema validity
    if attestation.schema != PostureAttestation::SCHEMA {
        return Some(DecisionReasonCode::PostureAttestationInvalid);
    }

    match requirements.is_satisfied_by(attestation) {
        PostureCheckResult::Satisfied => None,
        PostureCheckResult::AttestationExpired | PostureCheckResult::AttestationTooOld => {
            Some(DecisionReasonCode::PostureAttestationExpired)
        }
        PostureCheckResult::VerifierNotAllowed => {
            Some(DecisionReasonCode::PostureVerifierNotAllowed)
        }
        PostureCheckResult::RequirementNotMet { .. } => {
            Some(DecisionReasonCode::PostureRequirementNotMet)
        }
    }
}

fn apply_flow_approvals(
    input: &PolicyDecisionInput<'_>,
    provenance: &mut ProvenanceRecord,
    evidence: &mut Vec<ObjectId>,
) -> Option<DecisionReasonCode> {
    match provenance.can_flow_to(&input.zone_id) {
        FlowCheckResult::Allowed => None,
        FlowCheckResult::RequiresElevation => apply_elevation(input, provenance, evidence).err(),
        FlowCheckResult::RequiresDeclassification => {
            apply_declassification(input, provenance, evidence).err()
        }
        FlowCheckResult::RequiresBoth => {
            if let Err(reason) = apply_elevation(input, provenance, evidence) {
                return Some(reason);
            }
            if let Err(reason) = apply_declassification(input, provenance, evidence) {
                return Some(reason);
            }
            None
        }
    }
}

fn apply_elevation(
    input: &PolicyDecisionInput<'_>,
    provenance: &mut ProvenanceRecord,
    evidence: &mut Vec<ObjectId>,
) -> Result<(), DecisionReasonCode> {
    let required = IntegrityLevel::from_zone(&input.zone_id);

    let token = input
        .approval_tokens
        .iter()
        .find(|token| token.is_valid(input.now_ms) && token.zone_id == input.zone_id)
        .and_then(|token| match &token.scope {
            ApprovalScope::Elevation(scope) => {
                if scope.operation_id == input.operation_id.as_str()
                    && scope.target_integrity >= required
                {
                    Some(token)
                } else {
                    None
                }
            }
            _ => None,
        })
        .ok_or(DecisionReasonCode::ApprovalMissingElevation)?;

    let token_id = approval_token_object_id(token);
    let target = match &token.scope {
        ApprovalScope::Elevation(scope) => scope.target_integrity,
        _ => required,
    };

    provenance
        .apply_elevation(target, token_id, input.now_ms)
        .map_err(|_| DecisionReasonCode::ApprovalMissingElevation)?;

    evidence.push(token_id);
    Ok(())
}

fn apply_declassification(
    input: &PolicyDecisionInput<'_>,
    provenance: &mut ProvenanceRecord,
    evidence: &mut Vec<ObjectId>,
) -> Result<(), DecisionReasonCode> {
    let target = ConfidentialityLevel::from_zone(&input.zone_id);

    let token = input
        .approval_tokens
        .iter()
        .find(|token| token.is_valid(input.now_ms) && token.zone_id == input.zone_id)
        .and_then(|token| match &token.scope {
            ApprovalScope::Declassification(scope) => {
                let objects_match = if input.related_object_ids.is_empty() {
                    scope.object_ids.contains(&input.request_object_id)
                } else {
                    input
                        .related_object_ids
                        .iter()
                        .all(|id| scope.object_ids.contains(id))
                };

                if scope.from_zone == provenance.current_zone
                    && scope.to_zone == input.zone_id
                    && scope.target_confidentiality <= provenance.confidentiality_label
                    && scope.target_confidentiality == target
                    && objects_match
                {
                    Some(token)
                } else {
                    None
                }
            }
            _ => None,
        })
        .ok_or(DecisionReasonCode::ApprovalMissingDeclassification)?;

    let token_id = approval_token_object_id(token);
    let new_level = match &token.scope {
        ApprovalScope::Declassification(scope) => scope.target_confidentiality,
        _ => target,
    };

    provenance
        .apply_declassification(new_level, token_id, input.now_ms)
        .map_err(|_| DecisionReasonCode::ApprovalMissingDeclassification)?;

    evidence.push(token_id);
    Ok(())
}

fn find_execution_approval<'a>(
    input: &PolicyDecisionInput<'a>,
) -> Result<Option<&'a ApprovalToken>, DecisionReasonCode> {
    let mut saw_execution_scope = false;
    let mut had_mismatch = false;

    for token in input.approval_tokens {
        if !token.is_valid(input.now_ms) || token.zone_id != input.zone_id {
            continue;
        }

        let ApprovalScope::Execution(scope) = &token.scope else {
            continue;
        };
        saw_execution_scope = true;

        if scope.connector_id != input.connector_id.as_str() {
            continue;
        }
        if !pattern_matches(&scope.method_pattern, input.operation_id.as_str()) {
            continue;
        }
        if let Some(request_id) = scope.request_object_id {
            if request_id != input.request_object_id {
                had_mismatch = true;
                continue;
            }
        }
        if let Some(expected_hash) = scope.input_hash {
            if input.request_input_hash != Some(expected_hash) {
                had_mismatch = true;
                continue;
            }
        }
        if !scope.input_constraints.is_empty()
            && !input_constraints_match(scope.input_constraints.as_slice(), input.request_input)
        {
            had_mismatch = true;
            continue;
        }

        return Ok(Some(token));
    }

    if saw_execution_scope && had_mismatch {
        Err(DecisionReasonCode::ApprovalExecutionScopeMismatch)
    } else {
        Ok(None)
    }
}

fn input_constraints_match(
    constraints: &[crate::InputConstraint],
    input: Option<&serde_json::Value>,
) -> bool {
    let Some(value) = input else {
        return false;
    };

    constraints
        .iter()
        .all(|constraint| value.pointer(&constraint.pointer) == Some(&constraint.expected))
}

fn apply_sanitizer_receipts(
    input: &PolicyDecisionInput<'_>,
    provenance: &mut ProvenanceRecord,
    evidence: &mut Vec<ObjectId>,
) -> Option<DecisionReasonCode> {
    for receipt in input.sanitizer_receipts {
        if !receipt.is_valid() {
            return Some(DecisionReasonCode::SanitizerReceiptInvalid);
        }

        if !receipt_covers_inputs(receipt, &provenance.input_sources) {
            return Some(DecisionReasonCode::SanitizerCoverageInsufficient);
        }

        let receipt_id = sanitizer_receipt_object_id(receipt);
        provenance.apply_taint_reduction(
            &receipt.cleared_flags,
            receipt_id,
            receipt.covered_inputs.clone(),
            receipt.timestamp_ms,
        );
        evidence.push(receipt_id);
    }

    None
}

fn receipt_covers_inputs(receipt: &SanitizerReceipt, inputs: &[ObjectId]) -> bool {
    if inputs.is_empty() {
        return true;
    }
    inputs.iter().all(|input| receipt.covers_input(input))
}

fn approval_token_object_id(token: &ApprovalToken) -> ObjectId {
    // SECURITY: Use content-addressed ID to prevent malleability.
    // We use the full canonical encoding of the token.
    // Note: We use from_unscoped_bytes here because we don't have the Zone ObjectIdKey available
    // in this context, but this still ensures the ID is bound to the token content.
    let bytes =
        fcp_cbor::to_canonical_cbor(token).unwrap_or_else(|_| token.token_id.as_bytes().to_vec());
    ObjectId::from_unscoped_bytes(&bytes)
}

fn sanitizer_receipt_object_id(receipt: &SanitizerReceipt) -> ObjectId {
    ObjectId::from_unscoped_bytes(receipt.receipt_id.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ApprovalScope, CapabilityGrant, CapabilityId, ConfidentialityLevel, ConnectorId, Decision,
        ElevationScope, IntegrityLevel, NodeId, NodeSignature, ObjectId, OperationId, PrincipalId,
        Provenance, ProvenanceRecord, ProvenanceViolation, SafetyTier, TaintFlag, ZoneId,
    };
    use fcp_cbor::SchemaId;
    use semver::Version;

    // ── helpers ────────────────────────────────────────────────────────────

    fn test_header() -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.core", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_signature() -> NodeSignature {
        NodeSignature::new(NodeId::new("test-node"), [0u8; 64], 1_000)
    }

    fn minimal_zone_policy() -> ZonePolicyObject {
        ZonePolicyObject {
            header: test_header(),
            zone_id: ZoneId::work(),
            principal_allow: Vec::new(),
            principal_deny: Vec::new(),
            connector_allow: Vec::new(),
            connector_deny: Vec::new(),
            capability_allow: Vec::new(),
            capability_deny: Vec::new(),
            capability_ceiling: Vec::new(),
            transport_policy: ZoneTransportPolicy {
                allow_lan: true,
                allow_derp: true,
                allow_funnel: true,
            },
            decision_receipts: DecisionReceiptPolicy::default(),
            requires_posture: None,
        }
    }

    fn minimal_decision_input() -> PolicyDecisionInput<'static> {
        static EMPTY_APPROVALS: &[ApprovalToken] = &[];
        static EMPTY_RECEIPTS: &[SanitizerReceipt] = &[];
        static EMPTY_OBJECTS: &[ObjectId] = &[];

        PolicyDecisionInput {
            request_object_id: ObjectId::from_unscoped_bytes(b"req-1"),
            zone_id: ZoneId::work(),
            principal: PrincipalId::new("user:alice").unwrap(),
            connector_id: ConnectorId::from_static("test:conn:v1"),
            operation_id: OperationId::from_static("op.test"),
            capability_id: CapabilityId::new("cap.test").unwrap(),
            safety_tier: SafetyTier::Safe,
            provenance: ProvenanceRecord::new(ZoneId::work()),
            approval_tokens: EMPTY_APPROVALS,
            sanitizer_receipts: EMPTY_RECEIPTS,
            request_input: None,
            request_input_hash: None,
            related_object_ids: EMPTY_OBJECTS,
            transport: TransportMode::Lan,
            checkpoint_fresh: true,
            revocation_fresh: true,
            execution_approval_required: false,
            now_ms: 1_000,
            posture_attestation: None,
        }
    }

    // ── existing test ──────────────────────────────────────────────────────

    #[test]
    fn test_approval_token_object_id_is_content_addressed() {
        let mut token = ApprovalToken {
            token_id: "test-token-123".to_string(),
            issued_at_ms: 1000,
            expires_at_ms: 2000,
            issuer: "issuer".to_string(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "op".to_string(),
                original_provenance_id: ObjectId::from_unscoped_bytes(b"prov"),
                target_integrity: IntegrityLevel::Owner,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        let id1 = approval_token_object_id(&token);

        if let ApprovalScope::Elevation(ref mut scope) = token.scope {
            scope.target_integrity = IntegrityLevel::Untrusted;
        }
        let id2 = approval_token_object_id(&token);

        assert_ne!(id1, id2);
        assert_ne!(id1, ObjectId::from_unscoped_bytes(b"test-token-123"));
    }

    // ── TransportMode ──────────────────────────────────────────────────────

    #[test]
    fn transport_mode_serde_roundtrip() {
        for mode in [
            TransportMode::Lan,
            TransportMode::Derp,
            TransportMode::Funnel,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: TransportMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    #[test]
    fn transport_mode_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&TransportMode::Lan).unwrap(),
            "\"lan\""
        );
        assert_eq!(
            serde_json::to_string(&TransportMode::Derp).unwrap(),
            "\"derp\""
        );
        assert_eq!(
            serde_json::to_string(&TransportMode::Funnel).unwrap(),
            "\"funnel\""
        );
    }

    // ── ZoneTransportPolicy ────────────────────────────────────────────────

    #[test]
    fn zone_transport_policy_default_allows_only_lan() {
        let policy = ZoneTransportPolicy::default();
        assert!(policy.allow_lan);
        assert!(!policy.allow_derp);
        assert!(!policy.allow_funnel);
    }

    #[test]
    fn zone_transport_policy_allows_checks_each_mode() {
        let policy = ZoneTransportPolicy {
            allow_lan: false,
            allow_derp: true,
            allow_funnel: false,
        };
        assert!(!policy.allows(TransportMode::Lan));
        assert!(policy.allows(TransportMode::Derp));
        assert!(!policy.allows(TransportMode::Funnel));
    }

    #[test]
    fn zone_transport_policy_allows_all_when_all_true() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        assert!(policy.allows(TransportMode::Lan));
        assert!(policy.allows(TransportMode::Derp));
        assert!(policy.allows(TransportMode::Funnel));
    }

    #[test]
    fn zone_transport_policy_serde_roundtrip() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: true,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: ZoneTransportPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.allow_lan, policy.allow_lan);
        assert_eq!(back.allow_derp, policy.allow_derp);
        assert_eq!(back.allow_funnel, policy.allow_funnel);
    }

    // ── DecisionReceiptPolicy ──────────────────────────────────────────────

    #[test]
    fn decision_receipt_policy_default_emits_on_deny_only() {
        let policy = DecisionReceiptPolicy::default();
        assert!(!policy.emit_on_allow);
        assert!(policy.emit_on_deny);
    }

    #[test]
    fn decision_receipt_policy_serde_roundtrip() {
        let policy = DecisionReceiptPolicy {
            emit_on_allow: true,
            emit_on_deny: false,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: DecisionReceiptPolicy = serde_json::from_str(&json).unwrap();
        assert!(back.emit_on_allow);
        assert!(!back.emit_on_deny);
    }

    // ── PolicyPattern ──────────────────────────────────────────────────────

    #[test]
    fn policy_pattern_exact_match() {
        let pat = PolicyPattern {
            pattern: "user:alice".into(),
        };
        assert!(pat.matches("user:alice"));
        assert!(!pat.matches("user:bob"));
    }

    #[test]
    fn policy_pattern_wildcard_star_matches_all() {
        let pat = PolicyPattern {
            pattern: "*".into(),
        };
        assert!(pat.matches("anything"));
        assert!(pat.matches(""));
    }

    #[test]
    fn policy_pattern_prefix_wildcard() {
        let pat = PolicyPattern {
            pattern: "user:*".into(),
        };
        assert!(pat.matches("user:alice"));
        assert!(pat.matches("user:bob"));
        assert!(!pat.matches("service:foo"));
    }

    #[test]
    fn policy_pattern_suffix_wildcard() {
        let pat = PolicyPattern {
            pattern: "*:admin".into(),
        };
        assert!(pat.matches("user:admin"));
        assert!(pat.matches("service:admin"));
        assert!(!pat.matches("user:alice"));
    }

    #[test]
    fn policy_pattern_middle_wildcard() {
        let pat = PolicyPattern {
            pattern: "a*z".into(),
        };
        assert!(pat.matches("az"));
        assert!(pat.matches("abcz"));
        assert!(!pat.matches("bz"));
        assert!(!pat.matches("ay"));
    }

    #[test]
    fn policy_pattern_multi_wildcard() {
        let pat = PolicyPattern {
            pattern: "a*b*c".into(),
        };
        assert!(pat.matches("abc"));
        assert!(pat.matches("aXXbYYc"));
        assert!(!pat.matches("aXXc")); // missing 'b'
    }

    #[test]
    fn policy_pattern_empty_matches_empty() {
        let pat = PolicyPattern { pattern: String::new() };
        assert!(pat.matches(""));
        assert!(!pat.matches("anything"));
    }

    // ── DecisionReasonCode ─────────────────────────────────────────────────

    #[test]
    fn decision_reason_code_as_str_select_variants() {
        assert_eq!(DecisionReasonCode::Allow.as_str(), "allow");
        assert_eq!(
            DecisionReasonCode::CapabilityInsufficient.as_str(),
            "capability.insufficient"
        );
        assert_eq!(
            DecisionReasonCode::TransportDerpForbidden.as_str(),
            "transport.derp_forbidden"
        );
        assert_eq!(
            DecisionReasonCode::ZonePolicyPrincipalDenied.as_str(),
            "zone_policy.principal_denied"
        );
        assert_eq!(
            DecisionReasonCode::PostureAttestationMissing.as_str(),
            "posture.attestation_missing"
        );
        assert_eq!(
            DecisionReasonCode::SanitizerReceiptInvalid.as_str(),
            "taint.sanitizer_invalid"
        );
    }

    #[test]
    fn decision_reason_code_serde_roundtrip() {
        let code = DecisionReasonCode::TaintPublicInputDangerous;
        let json = serde_json::to_string(&code).unwrap();
        let back: DecisionReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, back);
    }

    #[test]
    fn decision_reason_code_from_provenance_violation() {
        assert_eq!(
            DecisionReasonCode::from_provenance_violation(
                &ProvenanceViolation::PublicInputForDangerousOperation
            ),
            DecisionReasonCode::TaintPublicInputDangerous,
        );
        assert_eq!(
            DecisionReasonCode::from_provenance_violation(
                &ProvenanceViolation::MaliciousInputDetected
            ),
            DecisionReasonCode::TaintMaliciousInput,
        );
        assert_eq!(
            DecisionReasonCode::from_provenance_violation(
                &ProvenanceViolation::CrossZoneUnapprovedForDangerousOperation
            ),
            DecisionReasonCode::TaintCrossZoneUnapproved,
        );
        assert_eq!(
            DecisionReasonCode::from_provenance_violation(
                &ProvenanceViolation::SanitizerCoverageInsufficient
            ),
            DecisionReasonCode::SanitizerCoverageInsufficient,
        );
        assert_eq!(
            DecisionReasonCode::from_provenance_violation(
                &ProvenanceViolation::ApprovalTokenInvalid
            ),
            DecisionReasonCode::ApprovalTokenInvalid,
        );
    }

    // ── PolicyDecision ─────────────────────────────────────────────────────

    #[test]
    fn policy_decision_allow_has_allow_fields() {
        let ev = vec![ObjectId::from_unscoped_bytes(b"ev1")];
        let d = PolicyDecision::allow(ev.clone());
        assert_eq!(d.decision, Decision::Allow);
        assert_eq!(d.reason_code, DecisionReasonCode::Allow);
        assert_eq!(d.evidence, ev);
        assert!(d.explanation.is_none());
    }

    #[test]
    fn policy_decision_deny_has_deny_fields() {
        let d = PolicyDecision::deny(DecisionReasonCode::TransportDerpForbidden, Vec::new());
        assert_eq!(d.decision, Decision::Deny);
        assert_eq!(d.reason_code, DecisionReasonCode::TransportDerpForbidden);
    }

    #[test]
    fn policy_decision_to_receipt_preserves_decision() {
        let d = PolicyDecision::deny(
            DecisionReasonCode::CapabilityInsufficient,
            vec![ObjectId::from_unscoped_bytes(b"ev")],
        );
        let receipt = d.to_receipt(
            test_header(),
            ObjectId::from_unscoped_bytes(b"req"),
            test_signature(),
        );
        assert_eq!(receipt.decision, Decision::Deny);
        assert_eq!(receipt.reason_code, "capability.insufficient");
        assert_eq!(receipt.evidence.len(), 1);
        assert_eq!(
            receipt.request_object_id,
            ObjectId::from_unscoped_bytes(b"req")
        );
    }

    // ── ResourceObject ─────────────────────────────────────────────────────

    #[test]
    fn resource_object_serde_roundtrip() {
        let obj = ResourceObject {
            header: test_header(),
            resource_uri: "https://example.com/file.pdf".to_string(),
            integrity_label: IntegrityLevel::Private,
            confidentiality_label: ConfidentialityLevel::Private,
            taint_flags: TaintFlags::default(),
        };
        let json = serde_json::to_string(&obj).unwrap();
        let back: ResourceObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back.resource_uri, "https://example.com/file.pdf");
    }

    // ── RoleGraph ──────────────────────────────────────────────────────────

    #[test]
    fn role_graph_acyclic_single_role() {
        let id_a = ObjectId::from_unscoped_bytes(b"role-a");
        let role_a = RoleObject {
            name: "admin".into(),
            caps: vec![CapabilityGrant {
                capability: CapabilityId::new("cap.read").unwrap(),
                operation: None,
            }],
            includes: Vec::new(),
        };
        let mut roles = HashMap::new();
        roles.insert(id_a, role_a);
        let graph = RoleGraph::new(roles);
        assert!(graph.validate_acyclic().is_ok());
    }

    #[test]
    fn role_graph_acyclic_linear_chain() {
        let id_a = ObjectId::from_unscoped_bytes(b"role-a");
        let id_b = ObjectId::from_unscoped_bytes(b"role-b");
        let role_a = RoleObject {
            name: "base".into(),
            caps: vec![],
            includes: Vec::new(),
        };
        let role_b = RoleObject {
            name: "admin".into(),
            caps: vec![],
            includes: vec![id_a],
        };
        let mut roles = HashMap::new();
        roles.insert(id_a, role_a);
        roles.insert(id_b, role_b);
        let graph = RoleGraph::new(roles);
        assert!(graph.validate_acyclic().is_ok());
    }

    #[test]
    fn role_graph_detects_cycle() {
        let id_a = ObjectId::from_unscoped_bytes(b"role-a");
        let id_b = ObjectId::from_unscoped_bytes(b"role-b");
        let role_a = RoleObject {
            name: "alpha".into(),
            caps: vec![],
            includes: vec![id_b],
        };
        let role_b = RoleObject {
            name: "beta".into(),
            caps: vec![],
            includes: vec![id_a],
        };
        let mut roles = HashMap::new();
        roles.insert(id_a, role_a);
        roles.insert(id_b, role_b);
        let graph = RoleGraph::new(roles);
        let err = graph.validate_acyclic().unwrap_err();
        assert!(matches!(err, RoleGraphError::RoleCycle { .. }));
    }

    #[test]
    fn role_graph_detects_unknown_role() {
        let id_a = ObjectId::from_unscoped_bytes(b"role-a");
        let id_missing = ObjectId::from_unscoped_bytes(b"role-missing");
        let role_a = RoleObject {
            name: "orphan".into(),
            caps: vec![],
            includes: vec![id_missing],
        };
        let mut roles = HashMap::new();
        roles.insert(id_a, role_a);
        let graph = RoleGraph::new(roles);
        let err = graph.validate_acyclic().unwrap_err();
        assert!(matches!(err, RoleGraphError::UnknownRole { .. }));
    }

    #[test]
    fn role_graph_resolve_caps_collects_inherited() {
        let id_a = ObjectId::from_unscoped_bytes(b"role-base");
        let id_b = ObjectId::from_unscoped_bytes(b"role-derived");
        let cap_read = CapabilityGrant {
            capability: CapabilityId::new("cap.read").unwrap(),
            operation: None,
        };
        let cap_write = CapabilityGrant {
            capability: CapabilityId::new("cap.write").unwrap(),
            operation: None,
        };
        let role_a = RoleObject {
            name: "base".into(),
            caps: vec![cap_read.clone()],
            includes: Vec::new(),
        };
        let role_b = RoleObject {
            name: "derived".into(),
            caps: vec![cap_write.clone()],
            includes: vec![id_a],
        };
        let mut roles = HashMap::new();
        roles.insert(id_a, role_a);
        roles.insert(id_b, role_b);
        let graph = RoleGraph::new(roles);
        let caps = graph.resolve_caps(&[id_b]).unwrap();
        assert_eq!(caps.len(), 2);
        assert!(caps.contains(&cap_write));
        assert!(caps.contains(&cap_read));
    }

    #[test]
    fn role_graph_resolve_caps_deduplicates_diamond() {
        let id_a = ObjectId::from_unscoped_bytes(b"role-root");
        let id_b = ObjectId::from_unscoped_bytes(b"role-left");
        let id_c = ObjectId::from_unscoped_bytes(b"role-right");
        let cap_root = CapabilityGrant {
            capability: CapabilityId::new("cap.root").unwrap(),
            operation: None,
        };
        let role_a = RoleObject {
            name: "root".into(),
            caps: vec![cap_root],
            includes: Vec::new(),
        };
        let role_b = RoleObject {
            name: "left".into(),
            caps: vec![],
            includes: vec![id_a],
        };
        let role_c = RoleObject {
            name: "right".into(),
            caps: vec![],
            includes: vec![id_a],
        };
        let mut roles = HashMap::new();
        roles.insert(id_a, role_a);
        roles.insert(id_b, role_b);
        roles.insert(id_c, role_c);
        let graph = RoleGraph::new(roles);
        // Resolve from both branches — root caps should appear once
        let caps = graph.resolve_caps(&[id_b, id_c]).unwrap();
        assert_eq!(caps.len(), 1);
    }

    // ── PolicyEngine ───────────────────────────────────────────────────────

    #[test]
    fn engine_allow_minimal_input() {
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(decision.reason_code, DecisionReasonCode::Allow);
    }

    #[test]
    fn engine_deny_revocation_stale() {
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let mut input = minimal_decision_input();
        input.revocation_fresh = false;
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, DecisionReasonCode::RevocationStaleFrontier);
    }

    #[test]
    fn engine_deny_checkpoint_stale() {
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let mut input = minimal_decision_input();
        input.checkpoint_fresh = false;
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, DecisionReasonCode::CheckpointStaleFrontier);
    }

    #[test]
    fn engine_deny_transport_derp_forbidden() {
        let mut policy = minimal_zone_policy();
        policy.transport_policy.allow_derp = false;
        let engine = PolicyEngine { zone_policy: policy };
        let mut input = minimal_decision_input();
        input.transport = TransportMode::Derp;
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, DecisionReasonCode::TransportDerpForbidden);
    }

    #[test]
    fn engine_deny_transport_funnel_forbidden() {
        let mut policy = minimal_zone_policy();
        policy.transport_policy.allow_funnel = false;
        let engine = PolicyEngine { zone_policy: policy };
        let mut input = minimal_decision_input();
        input.transport = TransportMode::Funnel;
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, DecisionReasonCode::TransportFunnelForbidden);
    }

    #[test]
    fn engine_deny_transport_lan_forbidden() {
        let mut policy = minimal_zone_policy();
        policy.transport_policy.allow_lan = false;
        let engine = PolicyEngine { zone_policy: policy };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, DecisionReasonCode::TransportLanForbidden);
    }

    #[test]
    fn engine_deny_principal_on_deny_list() {
        let mut policy = minimal_zone_policy();
        policy.principal_deny.push(PolicyPattern { pattern: "user:alice".into() });
        let engine = PolicyEngine { zone_policy: policy };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, DecisionReasonCode::ZonePolicyPrincipalDenied);
    }

    #[test]
    fn engine_deny_connector_on_deny_list() {
        let mut policy = minimal_zone_policy();
        policy.connector_deny.push(PolicyPattern { pattern: "test:conn:*".into() });
        let engine = PolicyEngine { zone_policy: policy };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, DecisionReasonCode::ZonePolicyConnectorDenied);
    }

    #[test]
    fn engine_deny_capability_on_deny_list() {
        let mut policy = minimal_zone_policy();
        policy.capability_deny.push(PolicyPattern { pattern: "cap.*".into() });
        let engine = PolicyEngine { zone_policy: policy };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, DecisionReasonCode::ZonePolicyCapabilityDenied);
    }

    #[test]
    fn engine_deny_principal_not_on_allow_list() {
        let mut policy = minimal_zone_policy();
        policy.principal_allow.push(PolicyPattern { pattern: "user:bob".into() });
        let engine = PolicyEngine { zone_policy: policy };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, DecisionReasonCode::ZonePolicyPrincipalNotAllowed);
    }

    #[test]
    fn engine_allow_principal_on_allow_list() {
        let mut policy = minimal_zone_policy();
        policy.principal_allow.push(PolicyPattern { pattern: "user:*".into() });
        let engine = PolicyEngine { zone_policy: policy };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Allow);
    }

    #[test]
    fn engine_deny_connector_not_on_allow_list() {
        let mut policy = minimal_zone_policy();
        policy.connector_allow.push(PolicyPattern { pattern: "other:conn:*".into() });
        let engine = PolicyEngine { zone_policy: policy };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, DecisionReasonCode::ZonePolicyConnectorNotAllowed);
    }

    #[test]
    fn engine_deny_capability_not_on_allow_list() {
        let mut policy = minimal_zone_policy();
        policy.capability_allow.push(PolicyPattern { pattern: "cap.other".into() });
        let engine = PolicyEngine { zone_policy: policy };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, DecisionReasonCode::ZonePolicyCapabilityNotAllowed);
    }

    #[test]
    fn engine_deny_capability_ceiling_blocks() {
        let mut policy = minimal_zone_policy();
        policy.capability_ceiling.push(CapabilityId::new("cap.other").unwrap());
        let engine = PolicyEngine { zone_policy: policy };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, DecisionReasonCode::CapabilityInsufficient);
    }

    #[test]
    fn engine_allow_capability_in_ceiling() {
        let mut policy = minimal_zone_policy();
        policy.capability_ceiling.push(CapabilityId::new("cap.test").unwrap());
        let engine = PolicyEngine { zone_policy: policy };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Allow);
    }

    #[test]
    fn engine_deny_tainted_public_input_dangerous_tier() {
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let mut input = minimal_decision_input();
        input.safety_tier = SafetyTier::Dangerous;
        input.provenance.taint_flags.insert(TaintFlag::PublicInput);
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, DecisionReasonCode::TaintPublicInputDangerous);
    }

    #[test]
    fn engine_deny_unverified_link_risky_tier() {
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let mut input = minimal_decision_input();
        input.safety_tier = SafetyTier::Risky;
        input.provenance.taint_flags.insert(TaintFlag::UnverifiedLink);
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, DecisionReasonCode::TaintUnverifiedLinkRisky);
    }

    #[test]
    fn engine_allow_tainted_safe_tier() {
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let mut input = minimal_decision_input();
        input.safety_tier = SafetyTier::Safe;
        input.provenance.taint_flags.insert(TaintFlag::PublicInput);
        let decision = engine.evaluate_invoke(&input);
        // PublicInput with Safe tier should still be allowed
        assert_eq!(decision.decision, Decision::Allow);
    }

    #[test]
    fn engine_execution_approval_missing_denies() {
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let mut input = minimal_decision_input();
        input.execution_approval_required = true;
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, DecisionReasonCode::ApprovalMissingExecution);
    }

    // ── check_transport (via PolicyEngine) ─────────────────────────────────

    #[test]
    fn check_transport_returns_correct_reason_per_mode() {
        // Deny all transports
        let policy = ZoneTransportPolicy {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: false,
        };
        assert_eq!(check_transport(&policy, TransportMode::Lan), Some(DecisionReasonCode::TransportLanForbidden));
        assert_eq!(check_transport(&policy, TransportMode::Derp), Some(DecisionReasonCode::TransportDerpForbidden));
        assert_eq!(check_transport(&policy, TransportMode::Funnel), Some(DecisionReasonCode::TransportFunnelForbidden));
    }

    #[test]
    fn check_transport_none_when_allowed() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        assert_eq!(check_transport(&policy, TransportMode::Lan), None);
        assert_eq!(check_transport(&policy, TransportMode::Derp), None);
        assert_eq!(check_transport(&policy, TransportMode::Funnel), None);
    }

    // ── input_constraints_match ────────────────────────────────────────────

    #[test]
    fn input_constraints_match_returns_false_when_no_input() {
        let constraints = vec![crate::InputConstraint {
            pointer: "/key".into(),
            expected: serde_json::Value::String("val".into()),
        }];
        assert!(!input_constraints_match(&constraints, None));
    }

    #[test]
    fn input_constraints_match_returns_true_when_matched() {
        let constraints = vec![crate::InputConstraint {
            pointer: "/key".into(),
            expected: serde_json::json!("val"),
        }];
        let input = serde_json::json!({"key": "val"});
        assert!(input_constraints_match(&constraints, Some(&input)));
    }

    #[test]
    fn input_constraints_match_returns_false_on_mismatch() {
        let constraints = vec![crate::InputConstraint {
            pointer: "/key".into(),
            expected: serde_json::json!("val"),
        }];
        let input = serde_json::json!({"key": "wrong"});
        assert!(!input_constraints_match(&constraints, Some(&input)));
    }

    #[test]
    fn input_constraints_match_empty_constraints_always_true() {
        let input = serde_json::json!({"anything": true});
        assert!(input_constraints_match(&[], Some(&input)));
    }

    // ── pattern_matches edge cases ─────────────────────────────────────────

    #[test]
    fn pattern_matches_double_wildcard() {
        // "**" is just two wildcards — matches anything
        let pat = PolicyPattern { pattern: "**".into() };
        assert!(pat.matches("anything"));
        assert!(pat.matches(""));
    }

    #[test]
    fn pattern_matches_no_match_when_prefix_differs() {
        let pat = PolicyPattern { pattern: "abc*".into() };
        assert!(pat.matches("abcdef"));
        assert!(!pat.matches("xabc"));
    }

    #[test]
    fn pattern_matches_no_match_when_suffix_differs() {
        let pat = PolicyPattern { pattern: "*xyz".into() };
        assert!(pat.matches("abcxyz"));
        assert!(!pat.matches("xyzabc"));
    }
}
