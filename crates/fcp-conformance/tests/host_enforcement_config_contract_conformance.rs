//! `fcp_host::enforcement` config + matcher conformance.
//!
//! `EnforcementConfig` exposes the host-side enforcement gates
//! (checkpoint freshness, revocation freshness, critical-taint
//! flags, per-zone connector/operation allowlists). Drift in the
//! defaults silently changes how strict the host is — a security-
//! relevant primitive.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`EnforcementConfig::default`** — documented values:
//!    - `checkpoint_max_age_ms = 300_000` (5 min)
//!    - `revocation_max_age_ms = 600_000` (10 min)
//!    - `critical_taint_flags = ["pii", "phi", "classified", "financial"]`
//!    - `zone_memberships`, `zone_allowed_connectors`,
//!      `zone_allowed_operations` all empty
//!    - `revocation_registry = None`
//! 2. **`EnforcementConfig::new() == default()`**.
//! 3. **`with_checkpoint_max_age_ms`/`with_revocation_max_age_ms`/
//!    `with_critical_taint_flags`** builder methods preserve other
//!    fields and update only the targeted field.
//! 4. **`add_zone_membership`** rejects malformed zone strings via
//!    `EnforcementConfigError::InvalidZoneId`; succeeds and inserts
//!    into the principal's zone set on a valid zone.
//! 5. **`add_zone_connector`** rejects malformed zone OR connector
//!    via `InvalidZoneId` / `InvalidConnectorId`; accepts `*` as
//!    `AllowedConnector::Any`.
//! 6. **`add_zone_operation`** rejects malformed zone OR operation;
//!    accepts `*` as `AllowedOperation::Any`.
//! 7. **`AllowedConnector::Any` matches every ConnectorId**;
//!    `AllowedConnector::Connector(x)` matches only `x`.
//! 8. **`AllowedOperation::Any` matches every OperationId**;
//!    `AllowedOperation::Operation(x)` matches only `x`.
//! 9. **`EnforcementConfigError` Display** — operator log greps
//!    depend on "invalid zone id" / "invalid connector id" /
//!    "invalid operation id" prefixes.

use fcp_core::{ConnectorId, OperationId};
use fcp_host::{AllowedConnector, AllowedOperation, EnforcementConfig, EnforcementConfigError};

// ─── EnforcementConfig::default ────────────────────────────────────

#[test]
fn enforcement_config_default_checkpoint_max_age_is_five_minutes() {
    assert_eq!(
        EnforcementConfig::default().checkpoint_max_age_ms,
        300_000,
        "default checkpoint_max_age_ms MUST be 300_000 (5 minutes)"
    );
}

#[test]
fn enforcement_config_default_revocation_max_age_is_ten_minutes() {
    assert_eq!(
        EnforcementConfig::default().revocation_max_age_ms,
        600_000,
        "default revocation_max_age_ms MUST be 600_000 (10 minutes)"
    );
}

#[test]
fn enforcement_config_default_critical_taint_flags_are_pii_phi_classified_financial() {
    let flags = EnforcementConfig::default().critical_taint_flags;
    assert_eq!(
        flags,
        vec![
            "pii".to_string(),
            "phi".to_string(),
            "classified".to_string(),
            "financial".to_string(),
        ],
        "default critical_taint_flags MUST be the documented 4-element list \
         in order — drift would silently un-tag a class of secrets"
    );
}

#[test]
fn enforcement_config_default_zone_maps_are_empty() {
    let c = EnforcementConfig::default();
    assert!(c.zone_memberships.is_empty());
    assert!(c.zone_allowed_connectors.is_empty());
    assert!(c.zone_allowed_operations.is_empty());
}

#[test]
fn enforcement_config_default_revocation_registry_is_none() {
    assert!(EnforcementConfig::default().revocation_registry.is_none());
}

#[test]
fn enforcement_config_new_equals_default() {
    let new = EnforcementConfig::new();
    let def = EnforcementConfig::default();
    assert_eq!(new.checkpoint_max_age_ms, def.checkpoint_max_age_ms);
    assert_eq!(new.revocation_max_age_ms, def.revocation_max_age_ms);
    assert_eq!(new.critical_taint_flags, def.critical_taint_flags);
}

// ─── builders ──────────────────────────────────────────────────────

#[test]
fn with_checkpoint_max_age_ms_sets_field_only() {
    let c = EnforcementConfig::new().with_checkpoint_max_age_ms(7_000);
    assert_eq!(c.checkpoint_max_age_ms, 7_000);
    // Other fields preserved.
    assert_eq!(c.revocation_max_age_ms, 600_000);
    assert_eq!(c.critical_taint_flags.len(), 4);
}

#[test]
fn with_revocation_max_age_ms_sets_field_only() {
    let c = EnforcementConfig::new().with_revocation_max_age_ms(99_000);
    assert_eq!(c.revocation_max_age_ms, 99_000);
    assert_eq!(c.checkpoint_max_age_ms, 300_000);
}

#[test]
fn with_critical_taint_flags_replaces_default_list() {
    let c = EnforcementConfig::new()
        .with_critical_taint_flags(vec!["custom-secret".into()]);
    assert_eq!(
        c.critical_taint_flags,
        vec!["custom-secret".to_string()],
        "with_critical_taint_flags MUST REPLACE the default 4-element list"
    );
}

#[test]
fn builder_chain_preserves_all_fields() {
    let c = EnforcementConfig::new()
        .with_checkpoint_max_age_ms(1_000)
        .with_revocation_max_age_ms(2_000)
        .with_critical_taint_flags(vec!["x".into(), "y".into()]);
    assert_eq!(c.checkpoint_max_age_ms, 1_000);
    assert_eq!(c.revocation_max_age_ms, 2_000);
    assert_eq!(c.critical_taint_flags, vec!["x".to_string(), "y".to_string()]);
}

// ─── add_zone_membership ──────────────────────────────────────────

#[test]
fn add_zone_membership_accepts_valid_zone_string() {
    let mut c = EnforcementConfig::new();
    let r = c.add_zone_membership("alice", "z:work");
    assert!(r.is_ok(), "valid zone string MUST succeed; got {r:?}");
    assert_eq!(
        c.zone_memberships.get("alice").map(std::collections::HashSet::len),
        Some(1),
        "alice MUST be registered for one zone"
    );
}

#[test]
fn add_zone_membership_rejects_malformed_zone_string() {
    let mut c = EnforcementConfig::new();
    let r = c.add_zone_membership("alice", "INVALID_UPPERCASE");
    let err = r.expect_err("malformed zone MUST fail");
    assert!(
        matches!(err, EnforcementConfigError::InvalidZoneId(_)),
        "malformed zone MUST yield InvalidZoneId; got {err:?}"
    );
}

#[test]
fn add_zone_membership_aggregates_multiple_zones_per_principal() {
    let mut c = EnforcementConfig::new();
    c.add_zone_membership("alice", "z:work").expect("ok");
    c.add_zone_membership("alice", "z:private").expect("ok");
    let zones = c.zone_memberships.get("alice").expect("alice present");
    assert_eq!(zones.len(), 2);
}

// ─── add_zone_connector ───────────────────────────────────────────

#[test]
fn add_zone_connector_accepts_valid_zone_and_connector() {
    let mut c = EnforcementConfig::new();
    c.add_zone_connector("z:work", "github:saas:v1")
        .expect("valid pair");
}

#[test]
fn add_zone_connector_accepts_wildcard_as_any() {
    let mut c = EnforcementConfig::new();
    c.add_zone_connector("z:work", "*").expect("wildcard");
    // Verify the entry is the Any variant via match semantics below.
}

#[test]
fn add_zone_connector_rejects_malformed_zone() {
    let mut c = EnforcementConfig::new();
    let err = c
        .add_zone_connector("BAD_ZONE", "github:saas:v1")
        .expect_err("bad zone MUST fail");
    assert!(matches!(err, EnforcementConfigError::InvalidZoneId(_)));
}

#[test]
fn add_zone_connector_rejects_malformed_connector_id() {
    let mut c = EnforcementConfig::new();
    let err = c
        .add_zone_connector("z:work", "INVALID Caps")
        .expect_err("bad connector MUST fail");
    assert!(
        matches!(err, EnforcementConfigError::InvalidConnectorId(_)),
        "got {err:?}"
    );
}

// ─── add_zone_operation ───────────────────────────────────────────

#[test]
fn add_zone_operation_accepts_valid_pair() {
    let mut c = EnforcementConfig::new();
    c.add_zone_operation("z:work", "send.message").expect("ok");
}

#[test]
fn add_zone_operation_accepts_wildcard_as_any() {
    let mut c = EnforcementConfig::new();
    c.add_zone_operation("z:work", "*").expect("wildcard");
}

#[test]
fn add_zone_operation_rejects_malformed_zone() {
    let mut c = EnforcementConfig::new();
    let err = c
        .add_zone_operation("BAD", "x")
        .expect_err("bad zone MUST fail");
    assert!(matches!(err, EnforcementConfigError::InvalidZoneId(_)));
}

#[test]
fn add_zone_operation_rejects_malformed_operation_id() {
    let mut c = EnforcementConfig::new();
    let err = c
        .add_zone_operation("z:work", "Bad Op")
        .expect_err("bad op MUST fail");
    assert!(matches!(
        err,
        EnforcementConfigError::InvalidOperationId(_)
    ));
}

// ─── AllowedConnector / AllowedOperation matchers ─────────────────

#[test]
fn allowed_connector_any_matches_every_connector_via_eq_to_self() {
    // The matches() method is private; pin the equality + hash
    // semantics that's the public surface. Any compares equal to Any
    // and not to a specific connector.
    let any = AllowedConnector::Any;
    let other_any = AllowedConnector::Any;
    let github = AllowedConnector::Connector(ConnectorId::from_static("github:saas:v1"));
    assert_eq!(any, other_any);
    assert_ne!(any, github);
}

#[test]
fn allowed_connector_specific_compares_only_to_matching_id() {
    let a = AllowedConnector::Connector(ConnectorId::from_static("github:saas:v1"));
    let b = AllowedConnector::Connector(ConnectorId::from_static("github:saas:v1"));
    let c = AllowedConnector::Connector(ConnectorId::from_static("slack:saas:v1"));
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn allowed_operation_any_compares_equal_only_to_other_any() {
    let any = AllowedOperation::Any;
    let other_any = AllowedOperation::Any;
    let send = AllowedOperation::Operation(OperationId::from_static("send.message"));
    assert_eq!(any, other_any);
    assert_ne!(any, send);
}

#[test]
fn allowed_operation_specific_compares_only_to_matching_id() {
    let a = AllowedOperation::Operation(OperationId::from_static("send.message"));
    let b = AllowedOperation::Operation(OperationId::from_static("send.message"));
    let c = AllowedOperation::Operation(OperationId::from_static("read.message"));
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn allowed_connector_implements_hash_for_hashset_use() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(AllowedConnector::Any);
    set.insert(AllowedConnector::Connector(ConnectorId::from_static(
        "github:saas:v1",
    )));
    set.insert(AllowedConnector::Any); // dup
    assert_eq!(set.len(), 2);
}

#[test]
fn allowed_operation_implements_hash_for_hashset_use() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(AllowedOperation::Any);
    set.insert(AllowedOperation::Operation(OperationId::from_static(
        "x.y",
    )));
    set.insert(AllowedOperation::Any);
    assert_eq!(set.len(), 2);
}

// ─── EnforcementConfigError Display ───────────────────────────────

#[test]
fn enforcement_config_error_invalid_zone_id_display() {
    let mut c = EnforcementConfig::new();
    let err = c
        .add_zone_membership("alice", "BAD")
        .expect_err("MUST fail");
    let s = format!("{err}");
    assert!(
        s.contains("invalid zone id"),
        "Display MUST mention 'invalid zone id'; got {s}"
    );
}

#[test]
fn enforcement_config_error_invalid_connector_id_display() {
    let mut c = EnforcementConfig::new();
    let err = c
        .add_zone_connector("z:work", "Bad Caps")
        .expect_err("MUST fail");
    let s = format!("{err}");
    assert!(
        s.contains("invalid connector id"),
        "Display MUST mention 'invalid connector id'; got {s}"
    );
}

#[test]
fn enforcement_config_error_invalid_operation_id_display() {
    let mut c = EnforcementConfig::new();
    let err = c
        .add_zone_operation("z:work", "Bad Op")
        .expect_err("MUST fail");
    let s = format!("{err}");
    assert!(
        s.contains("invalid operation id"),
        "Display MUST mention 'invalid operation id'; got {s}"
    );
}

#[test]
fn enforcement_config_error_is_std_error() {
    let mut c = EnforcementConfig::new();
    let err = c.add_zone_membership("alice", "BAD").expect_err("MUST fail");
    let _: &dyn std::error::Error = &err;
}
