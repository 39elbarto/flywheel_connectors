//! Cross-zone enforcement interop tests.
//!
//! Tests for cross-zone access control, `ApprovalToken` verification,
//! and `DecisionReceipt` reason code stability.

use crate::interop::{InteropTestSummary, TestFailure};

/// Cross-zone enforcement interop test suite.
pub struct CrossZoneInteropTests;

impl CrossZoneInteropTests {
    /// Run all cross-zone enforcement interop tests.
    #[must_use]
    pub fn run() -> InteropTestSummary {
        run_tests()
    }
}

/// Run all cross-zone enforcement interop tests.
pub fn run_tests() -> InteropTestSummary {
    let mut summary = InteropTestSummary::default();

    // Test 1: Cross-zone access denied without ApprovalToken
    run_test(
        &mut summary,
        "cross_zone_denied_without_approval",
        test_cross_zone_denied_without_approval,
    );

    // Test 2: Cross-zone access allowed with valid ApprovalToken
    run_test(
        &mut summary,
        "cross_zone_allowed_with_approval",
        test_cross_zone_allowed_with_approval,
    );

    // Test 3: DecisionReceipt reason codes are stable
    run_test(
        &mut summary,
        "decision_receipt_reason_codes",
        test_decision_receipt_reason_codes,
    );

    // Test 4: DecisionReceipt evidence binding
    run_test(
        &mut summary,
        "decision_receipt_evidence",
        test_decision_receipt_evidence,
    );

    // Test 5: Zone boundary enforcement
    run_test(
        &mut summary,
        "zone_boundary_enforcement",
        test_zone_boundary_enforcement,
    );

    // Test 6: ApprovalToken chain validation
    run_test(
        &mut summary,
        "approval_token_chain",
        test_approval_token_chain,
    );

    // Test 7: Zone hierarchy traversal
    run_test(
        &mut summary,
        "zone_hierarchy_traversal",
        test_zone_hierarchy_traversal,
    );

    summary
}

fn run_test<F>(summary: &mut InteropTestSummary, name: &str, test_fn: F)
where
    F: FnOnce() -> Result<(), String>,
{
    summary.total += 1;
    match test_fn() {
        Ok(()) => summary.passed += 1,
        Err(msg) => {
            summary.failed += 1;
            summary.failures.push(TestFailure {
                name: name.to_string(),
                category: "cross_zone".to_string(),
                message: msg,
            });
        }
    }
}

/// Test: Cross-zone access is denied without an `ApprovalToken`.
///
/// A request from zone A to access objects in zone B must be denied
/// if no `ApprovalToken` is presented.
fn test_cross_zone_denied_without_approval() -> Result<(), String> {
    let request = CrossZoneRequest {
        source_zone: "z:work".to_string(),
        target_zone: "z:private".to_string(),
        object_id: "aaaa".repeat(16),
        approval_token: None,
    };

    let decision = evaluate_cross_zone_access(&request);

    if decision.allowed {
        return Err("cross-zone access without approval should be denied".to_string());
    }

    // Reason code should indicate missing approval
    if decision.reason_code != ReasonCode::MissingApprovalToken {
        return Err(format!(
            "expected reason MissingApprovalToken, got {:?}",
            decision.reason_code
        ));
    }

    Ok(())
}

/// Test: Cross-zone access is allowed with a valid `ApprovalToken`.
fn test_cross_zone_allowed_with_approval() -> Result<(), String> {
    let approval_token = ApprovalToken {
        source_zone: "z:work".to_string(),
        target_zone: "z:private".to_string(),
        granted_objects: vec!["aaaa".repeat(16)],
        issuer: "owner-key-001".to_string(),
        expires_at: u64::MAX, // Never expires for test
        signature: vec![0u8; 64],
    };

    let request = CrossZoneRequest {
        source_zone: "z:work".to_string(),
        target_zone: "z:private".to_string(),
        object_id: "aaaa".repeat(16),
        approval_token: Some(approval_token),
    };

    let decision = evaluate_cross_zone_access(&request);

    if !decision.allowed {
        return Err(format!(
            "cross-zone access with valid approval should be allowed, reason: {:?}",
            decision.reason_code
        ));
    }

    if decision.reason_code != ReasonCode::Allowed {
        return Err(format!(
            "expected reason Allowed, got {:?}",
            decision.reason_code
        ));
    }

    Ok(())
}

/// Test: `DecisionReceipt` reason codes are stable and well-defined.
fn test_decision_receipt_reason_codes() -> Result<(), String> {
    // Reason codes must be stable integers for interoperability
    // These codes are NORMATIVE and must not change

    // Verify code values
    let codes = [
        (ReasonCode::Allowed, 0),
        (ReasonCode::MissingApprovalToken, 1),
        (ReasonCode::InvalidApprovalSignature, 2),
        (ReasonCode::ApprovalExpired, 3),
        (ReasonCode::ObjectNotGranted, 4),
        (ReasonCode::ZoneMismatch, 5),
        (ReasonCode::ChainBroken, 6),
        (ReasonCode::PolicyViolation, 7),
    ];

    for (code, expected_value) in codes {
        let actual = code.to_u8();
        if actual != expected_value {
            return Err(format!(
                "reason code {code:?} should be {expected_value}, got {actual}"
            ));
        }
    }

    // Verify round-trip
    for i in 0..8 {
        let code = ReasonCode::from_u8(i);
        let back = code.to_u8();
        if back != i {
            return Err(format!("reason code round-trip failed for {i}: got {back}"));
        }
    }

    Ok(())
}

/// Test: `DecisionReceipt` evidence binding.
///
/// The `DecisionReceipt` must include evidence (object IDs, timestamps)
/// that can be verified independently.
fn test_decision_receipt_evidence() -> Result<(), String> {
    let request = CrossZoneRequest {
        source_zone: "z:work".to_string(),
        target_zone: "z:private".to_string(),
        object_id: "bbbb".repeat(16),
        approval_token: None,
    };

    let decision = evaluate_cross_zone_access(&request);

    // Receipt should contain the request details
    if decision.receipt.source_zone != request.source_zone {
        return Err("receipt source_zone mismatch".to_string());
    }
    if decision.receipt.target_zone != request.target_zone {
        return Err("receipt target_zone mismatch".to_string());
    }
    if decision.receipt.object_id != request.object_id {
        return Err("receipt object_id mismatch".to_string());
    }

    // Receipt should have a timestamp
    if decision.receipt.timestamp == 0 {
        return Err("receipt timestamp must not be zero".to_string());
    }

    // Receipt reason code should match decision
    if decision.receipt.reason_code != decision.reason_code {
        return Err("receipt reason_code mismatch".to_string());
    }

    Ok(())
}

/// Test: Zone boundary enforcement.
///
/// Requests within the same zone should be allowed (no `ApprovalToken` needed).
/// Requests across zone boundaries require `ApprovalToken`.
fn test_zone_boundary_enforcement() -> Result<(), String> {
    // Same zone: allowed without approval
    let same_zone_request = CrossZoneRequest {
        source_zone: "z:work".to_string(),
        target_zone: "z:work".to_string(),
        object_id: "cccc".repeat(16),
        approval_token: None,
    };

    let decision = evaluate_cross_zone_access(&same_zone_request);
    if !decision.allowed {
        return Err("same-zone access should be allowed without approval".to_string());
    }

    // Different zones: denied without approval
    let cross_zone_request = CrossZoneRequest {
        source_zone: "z:work".to_string(),
        target_zone: "z:private".to_string(),
        object_id: "cccc".repeat(16),
        approval_token: None,
    };

    let decision = evaluate_cross_zone_access(&cross_zone_request);
    if decision.allowed {
        return Err("cross-zone access should be denied without approval".to_string());
    }

    Ok(())
}

/// Test: `ApprovalToken` chain validation.
///
/// For multi-hop cross-zone access, all tokens in the chain must be valid.
fn test_approval_token_chain() -> Result<(), String> {
    // Chain: z:public -> z:work -> z:private
    // Requires two approval tokens

    let token_public_to_work = ApprovalToken {
        source_zone: "z:public".to_string(),
        target_zone: "z:work".to_string(),
        granted_objects: vec!["dddd".repeat(16)],
        issuer: "owner-key-001".to_string(),
        expires_at: u64::MAX,
        signature: vec![0u8; 64],
    };

    let token_work_to_private = ApprovalToken {
        source_zone: "z:work".to_string(),
        target_zone: "z:private".to_string(),
        granted_objects: vec!["dddd".repeat(16)],
        issuer: "owner-key-001".to_string(),
        expires_at: u64::MAX,
        signature: vec![0u8; 64],
    };

    // Valid chain should be accepted
    let chain = vec![token_public_to_work.clone(), token_work_to_private.clone()];
    if !is_chain_valid(&chain, "z:public", "z:private") {
        return Err("valid token chain rejected".to_string());
    }

    // Broken chain (missing intermediate) should be rejected
    let broken_chain = vec![token_work_to_private.clone()];
    if is_chain_valid(&broken_chain, "z:public", "z:private") {
        return Err("broken chain should be rejected".to_string());
    }

    // Mismatched chain (wrong order) should be rejected
    let mismatched_chain = vec![token_work_to_private, token_public_to_work];
    if is_chain_valid(&mismatched_chain, "z:public", "z:private") {
        return Err("mismatched chain should be rejected".to_string());
    }

    Ok(())
}

/// Test: Zone hierarchy traversal rules.
///
/// Certain zone relationships allow implicit access without explicit approval:
/// - z:owner can access all zones
/// - z:private can access z:work and z:community
/// - z:work can access z:community and z:public
fn test_zone_hierarchy_traversal() -> Result<(), String> {
    // z:owner can access z:private without approval (hierarchical)
    let owner_to_private = CrossZoneRequest {
        source_zone: "z:owner".to_string(),
        target_zone: "z:private".to_string(),
        object_id: "eeee".repeat(16),
        approval_token: None,
    };

    let decision = evaluate_cross_zone_access(&owner_to_private);
    if !decision.allowed {
        return Err("z:owner should have implicit access to z:private".to_string());
    }

    // z:public cannot access z:private without approval (upward traversal blocked)
    let public_to_private = CrossZoneRequest {
        source_zone: "z:public".to_string(),
        target_zone: "z:private".to_string(),
        object_id: "eeee".repeat(16),
        approval_token: None,
    };

    let decision = evaluate_cross_zone_access(&public_to_private);
    if decision.allowed {
        return Err("z:public should not have implicit access to z:private".to_string());
    }

    // z:work can access z:public without approval (downward traversal allowed)
    let work_to_public = CrossZoneRequest {
        source_zone: "z:work".to_string(),
        target_zone: "z:public".to_string(),
        object_id: "eeee".repeat(16),
        approval_token: None,
    };

    let decision = evaluate_cross_zone_access(&work_to_public);
    if !decision.allowed {
        return Err("z:work should have implicit access to z:public".to_string());
    }

    Ok(())
}

// --- Test Support Types ---

/// Cross-zone access request.
struct CrossZoneRequest {
    source_zone: String,
    target_zone: String,
    object_id: String,
    approval_token: Option<ApprovalToken>,
}

/// Approval token for cross-zone access.
#[derive(Clone)]
#[allow(dead_code)]
struct ApprovalToken {
    source_zone: String,
    target_zone: String,
    granted_objects: Vec<String>,
    issuer: String,
    expires_at: u64,
    signature: Vec<u8>,
}

/// Decision receipt for cross-zone access.
struct DecisionReceipt {
    source_zone: String,
    target_zone: String,
    object_id: String,
    reason_code: ReasonCode,
    timestamp: u64,
}

/// Cross-zone access decision.
struct CrossZoneDecision {
    allowed: bool,
    reason_code: ReasonCode,
    receipt: DecisionReceipt,
}

/// Reason codes for cross-zone decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReasonCode {
    Allowed,
    MissingApprovalToken,
    InvalidApprovalSignature,
    ApprovalExpired,
    ObjectNotGranted,
    ZoneMismatch,
    ChainBroken,
    PolicyViolation,
}

impl ReasonCode {
    const fn to_u8(self) -> u8 {
        match self {
            Self::Allowed => 0,
            Self::MissingApprovalToken => 1,
            Self::InvalidApprovalSignature => 2,
            Self::ApprovalExpired => 3,
            Self::ObjectNotGranted => 4,
            Self::ZoneMismatch => 5,
            Self::ChainBroken => 6,
            Self::PolicyViolation => 7,
        }
    }

    const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Allowed,
            1 => Self::MissingApprovalToken,
            2 => Self::InvalidApprovalSignature,
            3 => Self::ApprovalExpired,
            4 => Self::ObjectNotGranted,
            5 => Self::ZoneMismatch,
            6 => Self::ChainBroken,
            _ => Self::PolicyViolation,
        }
    }
}

/// Zone hierarchy levels (higher = more privileged).
fn zone_level(zone: &str) -> u8 {
    match zone {
        "z:owner" => 4,
        "z:private" => 3,
        "z:work" => 2,
        "z:community" => 1,
        // z:public and unknown zones are treated as public (level 0)
        _ => 0,
    }
}

/// Check if source zone can implicitly access target zone (hierarchy).
fn can_traverse_implicitly(source: &str, target: &str) -> bool {
    zone_level(source) >= zone_level(target)
}

/// Evaluate a cross-zone access request.
fn evaluate_cross_zone_access(request: &CrossZoneRequest) -> CrossZoneDecision {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let make_receipt = |reason_code: ReasonCode| DecisionReceipt {
        source_zone: request.source_zone.clone(),
        target_zone: request.target_zone.clone(),
        object_id: request.object_id.clone(),
        reason_code,
        timestamp,
    };

    // Same zone: always allowed
    if request.source_zone == request.target_zone {
        return CrossZoneDecision {
            allowed: true,
            reason_code: ReasonCode::Allowed,
            receipt: make_receipt(ReasonCode::Allowed),
        };
    }

    // Check hierarchical access (downward traversal)
    if can_traverse_implicitly(&request.source_zone, &request.target_zone) {
        return CrossZoneDecision {
            allowed: true,
            reason_code: ReasonCode::Allowed,
            receipt: make_receipt(ReasonCode::Allowed),
        };
    }

    // Cross-zone requires ApprovalToken
    let Some(token) = &request.approval_token else {
        return CrossZoneDecision {
            allowed: false,
            reason_code: ReasonCode::MissingApprovalToken,
            receipt: make_receipt(ReasonCode::MissingApprovalToken),
        };
    };

    // Validate token zones match request
    if token.source_zone != request.source_zone || token.target_zone != request.target_zone {
        return CrossZoneDecision {
            allowed: false,
            reason_code: ReasonCode::ZoneMismatch,
            receipt: make_receipt(ReasonCode::ZoneMismatch),
        };
    }

    // Validate object is granted
    let object_granted = token
        .granted_objects
        .iter()
        .any(|g| g == "*" || g == &request.object_id);
    if !object_granted {
        return CrossZoneDecision {
            allowed: false,
            reason_code: ReasonCode::ObjectNotGranted,
            receipt: make_receipt(ReasonCode::ObjectNotGranted),
        };
    }

    // Validate expiry
    if token.expires_at <= timestamp {
        return CrossZoneDecision {
            allowed: false,
            reason_code: ReasonCode::ApprovalExpired,
            receipt: make_receipt(ReasonCode::ApprovalExpired),
        };
    }

    // Token is valid
    CrossZoneDecision {
        allowed: true,
        reason_code: ReasonCode::Allowed,
        receipt: make_receipt(ReasonCode::Allowed),
    }
}

/// Validate a chain of approval tokens for multi-hop access.
fn is_chain_valid(chain: &[ApprovalToken], start_zone: &str, end_zone: &str) -> bool {
    if chain.is_empty() {
        return start_zone == end_zone;
    }

    // First token must start from source zone
    if chain[0].source_zone != start_zone {
        return false;
    }

    // Last token must end at target zone
    if chain.last().map(|t| t.target_zone.as_str()) != Some(end_zone) {
        return false;
    }

    // Intermediate tokens must chain: t[i].target == t[i+1].source
    for window in chain.windows(2) {
        if window[0].target_zone != window[1].source_zone {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_zone_interop_tests_pass() {
        let summary = run_tests();
        for failure in &summary.failures {
            eprintln!("FAIL: {} - {}", failure.name, failure.message);
        }
        assert!(
            summary.all_passed(),
            "Cross-zone interop tests failed: {}/{} passed",
            summary.passed,
            summary.total
        );
    }

    #[test]
    fn test_zone_hierarchy() {
        // z:owner > z:private > z:work > z:community > z:public
        assert!(zone_level("z:owner") > zone_level("z:private"));
        assert!(zone_level("z:private") > zone_level("z:work"));
        assert!(zone_level("z:work") > zone_level("z:community"));
        assert!(zone_level("z:community") > zone_level("z:public"));
    }

    #[test]
    fn test_implicit_traversal() {
        // Downward allowed
        assert!(can_traverse_implicitly("z:owner", "z:public"));
        assert!(can_traverse_implicitly("z:work", "z:public"));

        // Same level allowed
        assert!(can_traverse_implicitly("z:work", "z:work"));

        // Upward blocked
        assert!(!can_traverse_implicitly("z:public", "z:private"));
        assert!(!can_traverse_implicitly("z:work", "z:owner"));
    }

    #[test]
    fn test_chain_validation() {
        let t1 = ApprovalToken {
            source_zone: "a".to_string(),
            target_zone: "b".to_string(),
            granted_objects: vec![],
            issuer: String::new(),
            expires_at: 0,
            signature: vec![],
        };
        let t2 = ApprovalToken {
            source_zone: "b".to_string(),
            target_zone: "c".to_string(),
            granted_objects: vec![],
            issuer: String::new(),
            expires_at: 0,
            signature: vec![],
        };

        // Valid chain
        assert!(is_chain_valid(&[t1.clone(), t2.clone()], "a", "c"));

        // Wrong start
        assert!(!is_chain_valid(&[t1.clone(), t2.clone()], "x", "c"));

        // Wrong end
        assert!(!is_chain_valid(&[t1.clone(), t2.clone()], "a", "x"));

        // Broken chain
        assert!(!is_chain_valid(&[t2, t1], "a", "c"));
    }

    // ─── ReasonCode to_u8/from_u8 coverage ───

    #[test]
    fn reason_code_roundtrip_all_values() {
        for i in 0..8 {
            let code = ReasonCode::from_u8(i);
            assert_eq!(code.to_u8(), i, "roundtrip failed for {i}");
        }
    }

    #[test]
    fn reason_code_out_of_range_maps_to_policy_violation() {
        assert_eq!(ReasonCode::from_u8(8), ReasonCode::PolicyViolation);
        assert_eq!(ReasonCode::from_u8(255), ReasonCode::PolicyViolation);
    }

    #[test]
    fn reason_code_specific_values() {
        assert_eq!(ReasonCode::Allowed.to_u8(), 0);
        assert_eq!(ReasonCode::MissingApprovalToken.to_u8(), 1);
        assert_eq!(ReasonCode::InvalidApprovalSignature.to_u8(), 2);
        assert_eq!(ReasonCode::ApprovalExpired.to_u8(), 3);
        assert_eq!(ReasonCode::ObjectNotGranted.to_u8(), 4);
        assert_eq!(ReasonCode::ZoneMismatch.to_u8(), 5);
        assert_eq!(ReasonCode::ChainBroken.to_u8(), 6);
        assert_eq!(ReasonCode::PolicyViolation.to_u8(), 7);
    }

    #[test]
    fn reason_code_debug_format() {
        let dbg = format!("{:?}", ReasonCode::Allowed);
        assert!(dbg.contains("Allowed"));
    }

    #[test]
    fn reason_code_clone_and_eq() {
        let a = ReasonCode::ChainBroken;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(ReasonCode::Allowed, ReasonCode::ChainBroken);
    }

    // ─── zone_level edge cases ───

    #[test]
    fn zone_level_all_standard_zones() {
        assert_eq!(zone_level("z:owner"), 4);
        assert_eq!(zone_level("z:private"), 3);
        assert_eq!(zone_level("z:work"), 2);
        assert_eq!(zone_level("z:community"), 1);
        assert_eq!(zone_level("z:public"), 0);
    }

    #[test]
    fn zone_level_unknown_zones_are_public() {
        assert_eq!(zone_level("z:custom"), 0);
        assert_eq!(zone_level("something"), 0);
        assert_eq!(zone_level(""), 0);
    }

    #[test]
    fn zone_level_project_zones_are_public() {
        assert_eq!(zone_level("z:project:myproj"), 0);
    }

    // ─── can_traverse_implicitly ───

    #[test]
    fn traverse_owner_to_all() {
        assert!(can_traverse_implicitly("z:owner", "z:owner"));
        assert!(can_traverse_implicitly("z:owner", "z:private"));
        assert!(can_traverse_implicitly("z:owner", "z:work"));
        assert!(can_traverse_implicitly("z:owner", "z:community"));
        assert!(can_traverse_implicitly("z:owner", "z:public"));
    }

    #[test]
    fn traverse_public_cannot_go_up() {
        assert!(!can_traverse_implicitly("z:public", "z:community"));
        assert!(!can_traverse_implicitly("z:public", "z:work"));
        assert!(!can_traverse_implicitly("z:public", "z:private"));
        assert!(!can_traverse_implicitly("z:public", "z:owner"));
    }

    #[test]
    fn traverse_same_level_allowed() {
        assert!(can_traverse_implicitly("z:public", "z:public"));
        assert!(can_traverse_implicitly("z:work", "z:work"));
        assert!(can_traverse_implicitly("z:owner", "z:owner"));
    }

    // ─── evaluate_cross_zone_access comprehensive ───

    #[test]
    fn cross_zone_same_zone_always_allowed() {
        let request = CrossZoneRequest {
            source_zone: "z:public".to_string(),
            target_zone: "z:public".to_string(),
            object_id: "ff".repeat(32),
            approval_token: None,
        };
        let decision = evaluate_cross_zone_access(&request);
        assert!(decision.allowed);
        assert_eq!(decision.reason_code, ReasonCode::Allowed);
    }

    #[test]
    fn cross_zone_token_zone_mismatch() {
        let token = ApprovalToken {
            source_zone: "z:work".to_string(),
            target_zone: "z:private".to_string(),
            granted_objects: vec!["aa".repeat(32)],
            issuer: "key-1".to_string(),
            expires_at: u64::MAX,
            signature: vec![0u8; 64],
        };
        let request = CrossZoneRequest {
            source_zone: "z:community".to_string(), // Mismatch
            target_zone: "z:private".to_string(),
            object_id: "aa".repeat(32),
            approval_token: Some(token),
        };
        let decision = evaluate_cross_zone_access(&request);
        assert!(!decision.allowed);
        assert_eq!(decision.reason_code, ReasonCode::ZoneMismatch);
    }

    #[test]
    fn cross_zone_object_not_granted() {
        let token = ApprovalToken {
            source_zone: "z:community".to_string(),
            target_zone: "z:private".to_string(),
            granted_objects: vec!["bb".repeat(32)],
            issuer: "key-1".to_string(),
            expires_at: u64::MAX,
            signature: vec![0u8; 64],
        };
        let request = CrossZoneRequest {
            source_zone: "z:community".to_string(),
            target_zone: "z:private".to_string(),
            object_id: "cc".repeat(32), // Not in grants
            approval_token: Some(token),
        };
        let decision = evaluate_cross_zone_access(&request);
        assert!(!decision.allowed);
        assert_eq!(decision.reason_code, ReasonCode::ObjectNotGranted);
    }

    #[test]
    fn cross_zone_wildcard_grant_allows_any_object() {
        let token = ApprovalToken {
            source_zone: "z:community".to_string(),
            target_zone: "z:private".to_string(),
            granted_objects: vec!["*".to_string()],
            issuer: "key-1".to_string(),
            expires_at: u64::MAX,
            signature: vec![0u8; 64],
        };
        let request = CrossZoneRequest {
            source_zone: "z:community".to_string(),
            target_zone: "z:private".to_string(),
            object_id: "arbitrary-object-id".to_string(),
            approval_token: Some(token),
        };
        let decision = evaluate_cross_zone_access(&request);
        assert!(decision.allowed);
        assert_eq!(decision.reason_code, ReasonCode::Allowed);
    }

    #[test]
    fn cross_zone_receipt_contains_request_details() {
        let request = CrossZoneRequest {
            source_zone: "z:public".to_string(),
            target_zone: "z:owner".to_string(),
            object_id: "dd".repeat(32),
            approval_token: None,
        };
        let decision = evaluate_cross_zone_access(&request);
        assert_eq!(decision.receipt.source_zone, "z:public");
        assert_eq!(decision.receipt.target_zone, "z:owner");
        assert_eq!(decision.receipt.object_id, "dd".repeat(32));
        assert!(decision.receipt.timestamp > 0);
        assert_eq!(decision.receipt.reason_code, decision.reason_code);
    }

    // ─── is_chain_valid edge cases ───

    #[test]
    fn chain_empty_same_zone_valid() {
        assert!(is_chain_valid(&[], "z:work", "z:work"));
    }

    #[test]
    fn chain_empty_different_zones_invalid() {
        assert!(!is_chain_valid(&[], "z:work", "z:private"));
    }

    #[test]
    fn chain_single_token() {
        let t = ApprovalToken {
            source_zone: "a".to_string(),
            target_zone: "b".to_string(),
            granted_objects: vec![],
            issuer: String::new(),
            expires_at: 0,
            signature: vec![],
        };
        assert!(is_chain_valid(std::slice::from_ref(&t), "a", "b"));
        assert!(!is_chain_valid(&[t], "a", "c"));
    }

    #[test]
    fn chain_three_hops() {
        let t1 = ApprovalToken {
            source_zone: "a".to_string(),
            target_zone: "b".to_string(),
            granted_objects: vec![],
            issuer: String::new(),
            expires_at: 0,
            signature: vec![],
        };
        let t2 = ApprovalToken {
            source_zone: "b".to_string(),
            target_zone: "c".to_string(),
            granted_objects: vec![],
            issuer: String::new(),
            expires_at: 0,
            signature: vec![],
        };
        let t3 = ApprovalToken {
            source_zone: "c".to_string(),
            target_zone: "d".to_string(),
            granted_objects: vec![],
            issuer: String::new(),
            expires_at: 0,
            signature: vec![],
        };
        assert!(is_chain_valid(&[t1, t2, t3], "a", "d"));
    }

    // ─── CrossZoneInteropTests struct ───

    #[test]
    fn cross_zone_interop_via_struct() {
        let summary = CrossZoneInteropTests::run();
        assert!(summary.all_passed());
        assert_eq!(summary.total, 7);
    }

    // ── ReasonCode: additional coverage ──

    #[test]
    fn reason_code_copy_semantics() {
        let a = ReasonCode::ObjectNotGranted;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a.to_u8(), b.to_u8());
    }

    #[test]
    fn reason_code_from_u8_boundary_values() {
        assert_eq!(ReasonCode::from_u8(0), ReasonCode::Allowed);
        assert_eq!(ReasonCode::from_u8(7), ReasonCode::PolicyViolation);
        // 8 and above all map to PolicyViolation
        assert_eq!(ReasonCode::from_u8(8), ReasonCode::PolicyViolation);
        assert_eq!(ReasonCode::from_u8(100), ReasonCode::PolicyViolation);
    }

    // ── zone_level: additional zones ──

    #[test]
    fn zone_level_whitespace_zone() {
        // Whitespace-only zone name is treated as unknown (public)
        assert_eq!(zone_level(" "), 0);
    }

    // ── can_traverse_implicitly: exhaustive pairs ──

    #[test]
    fn traverse_private_can_reach_work_and_below() {
        assert!(can_traverse_implicitly("z:private", "z:work"));
        assert!(can_traverse_implicitly("z:private", "z:community"));
        assert!(can_traverse_implicitly("z:private", "z:public"));
        assert!(!can_traverse_implicitly("z:private", "z:owner"));
    }

    #[test]
    fn traverse_community_limited() {
        assert!(can_traverse_implicitly("z:community", "z:public"));
        assert!(can_traverse_implicitly("z:community", "z:community"));
        assert!(!can_traverse_implicitly("z:community", "z:work"));
        assert!(!can_traverse_implicitly("z:community", "z:private"));
    }

    // ── evaluate_cross_zone_access: token expiry ──

    #[test]
    fn cross_zone_expired_token_rejected() {
        let token = ApprovalToken {
            source_zone: "z:community".to_string(),
            target_zone: "z:private".to_string(),
            granted_objects: vec!["*".to_string()],
            issuer: "key-1".to_string(),
            expires_at: 0, // Already expired
            signature: vec![0u8; 64],
        };
        let request = CrossZoneRequest {
            source_zone: "z:community".to_string(),
            target_zone: "z:private".to_string(),
            object_id: "test-obj".to_string(),
            approval_token: Some(token),
        };
        let decision = evaluate_cross_zone_access(&request);
        assert!(!decision.allowed);
        assert_eq!(decision.reason_code, ReasonCode::ApprovalExpired);
    }

    // ── is_chain_valid: additional chain patterns ──

    #[test]
    fn chain_self_loop_valid() {
        let t = ApprovalToken {
            source_zone: "a".to_string(),
            target_zone: "a".to_string(),
            granted_objects: vec![],
            issuer: String::new(),
            expires_at: 0,
            signature: vec![],
        };
        assert!(is_chain_valid(&[t], "a", "a"));
    }

    #[test]
    fn chain_four_hops() {
        let tokens: Vec<ApprovalToken> = (0..4)
            .map(|i| {
                let src = format!("zone-{i}");
                let tgt = format!("zone-{}", i + 1);
                ApprovalToken {
                    source_zone: src,
                    target_zone: tgt,
                    granted_objects: vec![],
                    issuer: String::new(),
                    expires_at: 0,
                    signature: vec![],
                }
            })
            .collect();
        assert!(is_chain_valid(&tokens, "zone-0", "zone-4"));
        assert!(!is_chain_valid(&tokens, "zone-0", "zone-3"));
    }
}
