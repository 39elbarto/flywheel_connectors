//! FCP3 Semantic Boundary Preservation Tests
//!
//! These tests verify that the FCP3 crate carving boundaries are maintained.
//! They detect regressions where types leak across semantic domain boundaries
//! or consumers bypass the intended owner crate.
//!
//! Bead: flywheel_connectors-qvsq8 [FCP3/P2.5]

// ── fcp-kernel exports execution types ────────────────────────────

#[test]
fn kernel_owns_invoke_lifecycle() {
    // InvokeRequest, InvokeResponse, InvokeStatus must be accessible from fcp-kernel
    let _ = std::any::type_name::<fcp_kernel::InvokeRequest>();
    let _ = std::any::type_name::<fcp_kernel::InvokeResponse>();
    let _: fcp_kernel::InvokeStatus = fcp_kernel::InvokeStatus::Ok;
}

#[test]
fn kernel_owns_connector_traits() {
    // FcpConnector and archetype traits must be accessible from fcp-kernel
    let _ = std::any::type_name::<dyn fcp_kernel::FcpConnector>();
    let _ = std::any::type_name::<dyn fcp_kernel::RequestResponse>();
    let _ = std::any::type_name::<dyn fcp_kernel::Streaming>();
}

#[test]
fn kernel_owns_session_lifecycle() {
    let _ = std::any::type_name::<fcp_kernel::HandshakeRequest>();
    let _ = std::any::type_name::<fcp_kernel::HandshakeResponse>();
    let _ = std::any::type_name::<fcp_kernel::SessionId>();
}

#[test]
fn kernel_owns_lifecycle_state_machine() {
    let _: fcp_kernel::LifecycleState = fcp_kernel::LifecycleState::Pending;
    let _: fcp_kernel::LifecycleState = fcp_kernel::LifecycleState::Canary;
    let _: fcp_kernel::LifecycleState = fcp_kernel::LifecycleState::Production;
    let _: fcp_kernel::LifecycleState = fcp_kernel::LifecycleState::RolledBack;
}

#[test]
fn kernel_owns_operation_metadata() {
    let _ = std::any::type_name::<fcp_kernel::OperationInfo>();
    let _ = std::any::type_name::<fcp_kernel::Introspection>();
    let _ = std::any::type_name::<fcp_kernel::AgentHint>();
    let _: fcp_kernel::ApprovalMode = fcp_kernel::ApprovalMode::Interactive;
}

#[test]
fn kernel_owns_health_types() {
    let _: fcp_kernel::HealthState = fcp_kernel::HealthState::Ready;
    let _: fcp_kernel::SelfCheckStatus = fcp_kernel::SelfCheckStatus::Ok;
}

#[test]
fn kernel_owns_identity_types() {
    let _ = fcp_kernel::ConnectorId::from_static("fcp.test");
    let _ = fcp_kernel::OperationId::from_static("test.op");
}

#[test]
fn kernel_owns_error_types() {
    let _: fcp_kernel::FcpError = fcp_kernel::FcpError::Internal {
        message: "test".into(),
    };
}

// ── fcp-policy exports policy types ───────────────────────────────

#[test]
fn policy_owns_capability_types() {
    let _ = std::any::type_name::<fcp_policy::CapabilityToken>();
    let _ = std::any::type_name::<fcp_policy::CapabilityVerifier>();
    let _ = fcp_policy::CapabilityId::from_static("test.cap");
}

#[test]
fn policy_owns_zone_types() {
    let _ = fcp_policy::ZoneId::from_static("z:test");
    let _ = std::any::type_name::<fcp_policy::ZoneTransportPolicy>();
}

#[test]
fn policy_owns_risk_classification() {
    let _: fcp_policy::RiskLevel = fcp_policy::RiskLevel::Low;
    let _: fcp_policy::SafetyTier = fcp_policy::SafetyTier::Safe;
    let _: fcp_policy::TrustLevel = fcp_policy::TrustLevel::Verified;
}

#[test]
fn policy_owns_decision_types() {
    let _ = std::any::type_name::<fcp_policy::PolicyDecision>();
    let _ = std::any::type_name::<fcp_policy::PolicyEngine>();
}

// ── fcp-evidence exports evidence types ───────────────────────────

#[test]
fn evidence_owns_audit_types() {
    let _ = std::any::type_name::<fcp_evidence::AuditEvent>();
    let _ = std::any::type_name::<fcp_evidence::AuditHead>();
    let _ = std::any::type_name::<fcp_evidence::DecisionReceipt>();
}

#[test]
fn evidence_owns_event_types() {
    let _ = std::any::type_name::<fcp_evidence::EventEnvelope>();
    let _ = std::any::type_name::<fcp_evidence::EventData>();
}

#[test]
fn evidence_owns_revocation_types() {
    let _ = std::any::type_name::<fcp_evidence::RevocationObject>();
    let _ = std::any::type_name::<fcp_evidence::RevocationEvent>();
}

// ── Cross-crate type identity ─────────────────────────────────────

#[test]
fn kernel_and_core_export_same_types() {
    // Verify that fcp_kernel::InvokeRequest IS the same type as fcp_core::InvokeRequest
    assert_eq!(
        std::any::TypeId::of::<fcp_kernel::InvokeRequest>(),
        std::any::TypeId::of::<fcp_core::InvokeRequest>(),
        "fcp_kernel::InvokeRequest must be the same type as fcp_core::InvokeRequest"
    );
    assert_eq!(
        std::any::TypeId::of::<fcp_kernel::FcpError>(),
        std::any::TypeId::of::<fcp_core::FcpError>(),
        "fcp_kernel::FcpError must be the same type as fcp_core::FcpError"
    );
}

#[test]
fn policy_and_core_export_same_types() {
    assert_eq!(
        std::any::TypeId::of::<fcp_policy::CapabilityToken>(),
        std::any::TypeId::of::<fcp_core::CapabilityToken>(),
        "fcp_policy::CapabilityToken must be the same type as fcp_core::CapabilityToken"
    );
}

#[test]
fn evidence_and_core_export_same_types() {
    assert_eq!(
        std::any::TypeId::of::<fcp_evidence::AuditEvent>(),
        std::any::TypeId::of::<fcp_core::AuditEvent>(),
        "fcp_evidence::AuditEvent must be the same type as fcp_core::AuditEvent"
    );
}
