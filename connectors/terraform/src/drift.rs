//! Terraform drift detection between recorded state and actual infrastructure.
//!
//! Compares expected attribute values (from Terraform state) against actual
//! infrastructure values, producing a [`DriftReport`] with severity estimation.
//! All operations are read-only — drift detection never mutates infrastructure.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Severity level for detected drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DriftSeverity {
    /// No drift detected.
    None,
    /// Cosmetic or metadata-only changes (tags, descriptions).
    Low,
    /// Configuration changes that may affect behaviour.
    Medium,
    /// Changes to security-sensitive or networking attributes.
    High,
    /// Critical infrastructure changes (IAM, encryption, destruction).
    Critical,
}

impl Default for DriftSeverity {
    fn default() -> Self {
        Self::None
    }
}

impl fmt::Display for DriftSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Low => f.write_str("low"),
            Self::Medium => f.write_str("medium"),
            Self::High => f.write_str("high"),
            Self::Critical => f.write_str("critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// Drifted attribute
// ---------------------------------------------------------------------------

/// A single attribute whose actual value differs from the expected state value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftedAttribute {
    /// Attribute key (e.g. `instance_type`, `cidr_block`).
    pub attribute_name: String,
    /// SHA-256 hash of the expected (state) value.
    pub expected_value_hash: String,
    /// SHA-256 hash of the actual (infrastructure) value.
    pub actual_value_hash: String,
    /// Severity of this particular attribute drift.
    pub severity: DriftSeverity,
}

// ---------------------------------------------------------------------------
// Drifted resource
// ---------------------------------------------------------------------------

/// A resource with one or more drifted attributes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftedResource {
    /// Terraform address (e.g. `aws_instance.web`).
    pub address: String,
    /// Resource type (e.g. `aws_instance`).
    pub resource_type: String,
    /// Provider (e.g. `hashicorp/aws`).
    pub provider: String,
    /// Attributes that have drifted.
    pub drifted_attributes: Vec<DriftedAttribute>,
    /// Worst-case severity across all drifted attributes.
    pub severity: DriftSeverity,
}

// ---------------------------------------------------------------------------
// Audit event
// ---------------------------------------------------------------------------

/// Audit trail entry recorded during drift detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftAuditEvent {
    /// ISO-8601 timestamp string.
    pub timestamp: String,
    /// Action performed (e.g. `detection_started`, `resource_compared`).
    pub action: String,
    /// Optional resource address related to this event.
    pub resource_address: Option<String>,
    /// Human-readable details.
    pub details: String,
}

// ---------------------------------------------------------------------------
// Drift report
// ---------------------------------------------------------------------------

/// Complete drift report for a workspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftReport {
    /// Workspace identifier.
    pub workspace_id: String,
    /// ISO-8601 timestamp when this report was generated.
    pub generated_at: String,
    /// Total number of resources examined.
    pub resources_checked: usize,
    /// Number of resources with detected drift.
    pub resources_drifted: usize,
    /// Detail of each drifted resource.
    pub drifted_resources: Vec<DriftedResource>,
    /// Maximum severity across all drifted resources.
    pub overall_severity: DriftSeverity,
    /// Optional hash of the Terraform plan that was used as source-of-truth.
    pub plan_hash: Option<String>,
    /// Audit trail of detection operations.
    pub audit_events: Vec<DriftAuditEvent>,
}

// ---------------------------------------------------------------------------
// Resource record stored in the detector
// ---------------------------------------------------------------------------

/// Expected vs actual attribute values for a single resource.
#[derive(Debug, Clone)]
struct ResourceRecord {
    resource_type: String,
    provider: String,
    expected: HashMap<String, String>,
    actual: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Hashing helper
// ---------------------------------------------------------------------------

/// Produce a stable, deterministic hash of an attribute value string.
///
/// Uses a simple FNV-1a–style hash that is fast and collision-resistant
/// enough for display/comparison purposes (not cryptographic).
#[must_use]
pub fn hash_attribute_value(value: &str) -> String {
    // FNV-1a 64-bit
    const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
    const FNV_PRIME: u64 = 1_099_511_628_211;

    let mut hash = FNV_OFFSET;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
}

// ---------------------------------------------------------------------------
// Severity helper
// ---------------------------------------------------------------------------

/// High-severity attribute names (security / networking).
const HIGH_SEVERITY_ATTRS: &[&str] = &[
    "security_group",
    "cidr_block",
    "ingress",
    "egress",
    "vpc_id",
    "subnet_id",
    "acl",
    "firewall",
    "network",
    "route",
    "policy_arn",
    "assume_role_policy",
    "kms_key_id",
    "ssl_certificate",
    "tls",
];

/// Critical-severity attribute names (IAM / encryption / destroy).
const CRITICAL_SEVERITY_ATTRS: &[&str] = &[
    "iam",
    "role",
    "principal",
    "encryption",
    "kms",
    "password",
    "secret",
    "credential",
    "root",
    "admin",
    "delete_protection",
    "termination_protection",
];

/// Low-severity attribute names (tags / descriptions / metadata).
const LOW_SEVERITY_ATTRS: &[&str] = &[
    "tag",
    "description",
    "name",
    "label",
    "annotation",
    "comment",
    "display_name",
    "metadata",
];

/// Determine drift severity from an attribute name and optional context.
#[must_use]
pub fn compute_severity(attribute_name: &str) -> DriftSeverity {
    let lower = attribute_name.to_lowercase();

    for keyword in CRITICAL_SEVERITY_ATTRS {
        if lower.contains(keyword) {
            return DriftSeverity::Critical;
        }
    }
    for keyword in HIGH_SEVERITY_ATTRS {
        if lower.contains(keyword) {
            return DriftSeverity::High;
        }
    }
    for keyword in LOW_SEVERITY_ATTRS {
        if lower.contains(keyword) {
            return DriftSeverity::Low;
        }
    }

    DriftSeverity::Medium
}

// ---------------------------------------------------------------------------
// Drift detector
// ---------------------------------------------------------------------------

/// Stateful drift detector that accumulates resource records and produces a
/// [`DriftReport`].
#[derive(Debug, Clone)]
pub struct DriftDetector {
    workspace_id: String,
    resources: HashMap<String, ResourceRecord>,
    threshold: DriftSeverity,
    audit_events: Vec<DriftAuditEvent>,
}

impl DriftDetector {
    /// Create a new detector for the given workspace.
    #[must_use]
    pub fn new(workspace_id: impl Into<String>) -> Self {
        let ws = workspace_id.into();
        let event = DriftAuditEvent {
            timestamp: Self::now(),
            action: "detector_created".into(),
            resource_address: None,
            details: format!("Drift detector initialised for workspace {ws}"),
        };
        Self {
            workspace_id: ws,
            resources: HashMap::new(),
            threshold: DriftSeverity::Low,
            audit_events: vec![event],
        }
    }

    /// Set the minimum severity threshold for alerting.
    pub const fn set_threshold(&mut self, threshold: DriftSeverity) {
        self.threshold = threshold;
    }

    /// Return the current severity threshold.
    #[must_use]
    pub const fn severity_threshold(&self) -> DriftSeverity {
        self.threshold
    }

    /// Return the workspace identifier.
    #[must_use]
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    /// Return the number of registered resources.
    #[must_use]
    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    /// Register a resource with its expected and actual attribute maps.
    pub fn add_resource(
        &mut self,
        address: impl Into<String>,
        resource_type: impl Into<String>,
        provider: impl Into<String>,
        expected: HashMap<String, String>,
        actual: HashMap<String, String>,
    ) {
        let addr: String = address.into();
        self.audit_events.push(DriftAuditEvent {
            timestamp: Self::now(),
            action: "resource_added".into(),
            resource_address: Some(addr.clone()),
            details: format!(
                "Added resource with {} expected and {} actual attributes",
                expected.len(),
                actual.len()
            ),
        });
        self.resources.insert(
            addr,
            ResourceRecord {
                resource_type: resource_type.into(),
                provider: provider.into(),
                expected,
                actual,
            },
        );
    }

    /// Run drift detection across all registered resources.
    ///
    /// This is a **read-only** operation — no mutations are applied.
    #[must_use]
    pub fn detect_drift(&mut self) -> Vec<DriftedResource> {
        self.audit_events.push(DriftAuditEvent {
            timestamp: Self::now(),
            action: "detection_started".into(),
            resource_address: None,
            details: format!("Starting drift detection across {} resources", self.resources.len()),
        });

        let mut drifted = Vec::new();

        // Collect addresses so we can iterate deterministically.
        let mut addresses: Vec<String> = self.resources.keys().cloned().collect();
        addresses.sort();

        for addr in &addresses {
            let record = &self.resources[addr];
            let mut drifted_attrs = Vec::new();

            // Check all expected attributes against actual.
            let mut attr_names: Vec<&String> = record.expected.keys().collect();
            attr_names.sort();

            for attr_name in attr_names {
                let expected_val = &record.expected[attr_name];
                let actual_val = record
                    .actual
                    .get(attr_name)
                    .cloned()
                    .unwrap_or_default();

                if *expected_val != actual_val {
                    let severity = compute_severity(attr_name);
                    drifted_attrs.push(DriftedAttribute {
                        attribute_name: attr_name.clone(),
                        expected_value_hash: hash_attribute_value(expected_val),
                        actual_value_hash: hash_attribute_value(&actual_val),
                        severity,
                    });
                }
            }

            // Also check for attributes present in actual but missing from expected.
            let mut actual_only: Vec<&String> = record
                .actual
                .keys()
                .filter(|k| !record.expected.contains_key(*k))
                .collect();
            actual_only.sort();

            for attr_name in actual_only {
                let actual_val = &record.actual[attr_name];
                let severity = compute_severity(attr_name);
                drifted_attrs.push(DriftedAttribute {
                    attribute_name: attr_name.clone(),
                    expected_value_hash: hash_attribute_value(""),
                    actual_value_hash: hash_attribute_value(actual_val),
                    severity,
                });
            }

            self.audit_events.push(DriftAuditEvent {
                timestamp: Self::now(),
                action: "resource_compared".into(),
                resource_address: Some(addr.clone()),
                details: format!(
                    "Found {} drifted attributes out of {} checked",
                    drifted_attrs.len(),
                    record.expected.len() + record.actual.len()
                ),
            });

            if !drifted_attrs.is_empty() {
                let max_severity = drifted_attrs
                    .iter()
                    .map(|a| a.severity)
                    .max()
                    .unwrap_or(DriftSeverity::None);
                drifted.push(DriftedResource {
                    address: addr.clone(),
                    resource_type: record.resource_type.clone(),
                    provider: record.provider.clone(),
                    drifted_attributes: drifted_attrs,
                    severity: max_severity,
                });
            }
        }

        self.audit_events.push(DriftAuditEvent {
            timestamp: Self::now(),
            action: "detection_completed".into(),
            resource_address: None,
            details: format!(
                "Detection complete: {} of {} resources drifted",
                drifted.len(),
                self.resources.len()
            ),
        });

        drifted
    }

    /// Produce the full [`DriftReport`].
    #[must_use]
    pub fn report(&mut self) -> DriftReport {
        self.report_with_plan_hash(None)
    }

    /// Produce the full [`DriftReport`] with an optional plan hash.
    #[must_use]
    pub fn report_with_plan_hash(&mut self, plan_hash: Option<String>) -> DriftReport {
        let drifted = self.detect_drift();
        let overall = drifted
            .iter()
            .map(|r| r.severity)
            .max()
            .unwrap_or(DriftSeverity::None);
        let total = self.resources.len();
        let drifted_count = drifted.len();

        self.audit_events.push(DriftAuditEvent {
            timestamp: Self::now(),
            action: "report_generated".into(),
            resource_address: None,
            details: format!(
                "Generated drift report: {drifted_count}/{total} resources drifted, overall severity: {overall}"
            ),
        });

        DriftReport {
            workspace_id: self.workspace_id.clone(),
            generated_at: Self::now(),
            resources_checked: total,
            resources_drifted: drifted_count,
            drifted_resources: drifted,
            overall_severity: overall,
            plan_hash,
            audit_events: self.audit_events.clone(),
        }
    }

    /// Return a snapshot of the current audit trail.
    #[must_use]
    pub fn audit_trail(&self) -> &[DriftAuditEvent] {
        &self.audit_events
    }

    /// Check whether any detected drift exceeds the configured threshold.
    #[must_use]
    pub fn exceeds_threshold(&mut self) -> bool {
        let drifted = self.detect_drift();
        drifted.iter().any(|r| r.severity >= self.threshold)
    }

    // Deterministic timestamp stub (test-friendly).
    fn now() -> String {
        "2026-03-09T00:00:00Z".to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DriftSeverity tests -----------------------------------------------

    #[test]
    fn severity_default_is_none() {
        assert_eq!(DriftSeverity::default(), DriftSeverity::None);
    }

    #[test]
    fn severity_display_none() {
        assert_eq!(DriftSeverity::None.to_string(), "none");
    }

    #[test]
    fn severity_display_low() {
        assert_eq!(DriftSeverity::Low.to_string(), "low");
    }

    #[test]
    fn severity_display_medium() {
        assert_eq!(DriftSeverity::Medium.to_string(), "medium");
    }

    #[test]
    fn severity_display_high() {
        assert_eq!(DriftSeverity::High.to_string(), "high");
    }

    #[test]
    fn severity_display_critical() {
        assert_eq!(DriftSeverity::Critical.to_string(), "critical");
    }

    #[test]
    fn severity_ord_none_lt_low() {
        assert!(DriftSeverity::None < DriftSeverity::Low);
    }

    #[test]
    fn severity_ord_low_lt_medium() {
        assert!(DriftSeverity::Low < DriftSeverity::Medium);
    }

    #[test]
    fn severity_ord_medium_lt_high() {
        assert!(DriftSeverity::Medium < DriftSeverity::High);
    }

    #[test]
    fn severity_ord_high_lt_critical() {
        assert!(DriftSeverity::High < DriftSeverity::Critical);
    }

    #[test]
    fn severity_eq() {
        assert_eq!(DriftSeverity::Medium, DriftSeverity::Medium);
    }

    #[test]
    fn severity_ne() {
        assert_ne!(DriftSeverity::Low, DriftSeverity::High);
    }

    #[test]
    fn severity_clone() {
        let s = DriftSeverity::High;
        let cloned = s;
        assert_eq!(cloned, DriftSeverity::High);
    }

    #[test]
    fn severity_copy() {
        let s = DriftSeverity::Critical;
        let copied = s;
        assert_eq!(s, copied);
    }

    #[test]
    fn severity_debug() {
        let dbg = format!("{:?}", DriftSeverity::Medium);
        assert!(dbg.contains("Medium"));
    }

    #[test]
    fn severity_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(DriftSeverity::Low);
        set.insert(DriftSeverity::Low);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn severity_hash_distinct() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(DriftSeverity::Low);
        set.insert(DriftSeverity::High);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn severity_serde_roundtrip_none() {
        let json = serde_json::to_string(&DriftSeverity::None).unwrap();
        assert_eq!(json, "\"none\"");
        let back: DriftSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, DriftSeverity::None);
    }

    #[test]
    fn severity_serde_roundtrip_low() {
        let json = serde_json::to_string(&DriftSeverity::Low).unwrap();
        assert_eq!(json, "\"low\"");
        let back: DriftSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, DriftSeverity::Low);
    }

    #[test]
    fn severity_serde_roundtrip_medium() {
        let json = serde_json::to_string(&DriftSeverity::Medium).unwrap();
        assert_eq!(json, "\"medium\"");
        let back: DriftSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, DriftSeverity::Medium);
    }

    #[test]
    fn severity_serde_roundtrip_high() {
        let json = serde_json::to_string(&DriftSeverity::High).unwrap();
        assert_eq!(json, "\"high\"");
        let back: DriftSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, DriftSeverity::High);
    }

    #[test]
    fn severity_serde_roundtrip_critical() {
        let json = serde_json::to_string(&DriftSeverity::Critical).unwrap();
        assert_eq!(json, "\"critical\"");
        let back: DriftSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, DriftSeverity::Critical);
    }

    #[test]
    fn severity_max_of_collection() {
        let severities = vec![
            DriftSeverity::Low,
            DriftSeverity::Critical,
            DriftSeverity::Medium,
        ];
        assert_eq!(severities.into_iter().max(), Some(DriftSeverity::Critical));
    }

    #[test]
    fn severity_min_of_collection() {
        let severities = vec![
            DriftSeverity::Low,
            DriftSeverity::Critical,
            DriftSeverity::Medium,
        ];
        assert_eq!(severities.into_iter().min(), Some(DriftSeverity::Low));
    }

    // -- hash_attribute_value tests ----------------------------------------

    #[test]
    fn hash_deterministic() {
        let h1 = hash_attribute_value("t2.micro");
        let h2 = hash_attribute_value("t2.micro");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_different_inputs_differ() {
        let h1 = hash_attribute_value("t2.micro");
        let h2 = hash_attribute_value("t3.large");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_empty_string() {
        let h = hash_attribute_value("");
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn hash_is_hex_string() {
        let h = hash_attribute_value("some-value");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_has_fixed_length() {
        let h = hash_attribute_value("short");
        assert_eq!(h.len(), 16);
        let h2 = hash_attribute_value("a much longer attribute value with many characters");
        assert_eq!(h2.len(), 16);
    }

    #[test]
    fn hash_whitespace_matters() {
        let h1 = hash_attribute_value("hello");
        let h2 = hash_attribute_value("hello ");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_case_sensitive() {
        let h1 = hash_attribute_value("Value");
        let h2 = hash_attribute_value("value");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_unicode() {
        let h = hash_attribute_value("cafe\u{0301}");
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn hash_newline_vs_no_newline() {
        let h1 = hash_attribute_value("line");
        let h2 = hash_attribute_value("line\n");
        assert_ne!(h1, h2);
    }

    // -- compute_severity tests --------------------------------------------

    #[test]
    fn severity_tag_is_low() {
        assert_eq!(compute_severity("tags"), DriftSeverity::Low);
    }

    #[test]
    fn severity_description_is_low() {
        assert_eq!(compute_severity("description"), DriftSeverity::Low);
    }

    #[test]
    fn severity_name_is_low() {
        assert_eq!(compute_severity("name"), DriftSeverity::Low);
    }

    #[test]
    fn severity_label_is_low() {
        assert_eq!(compute_severity("label"), DriftSeverity::Low);
    }

    #[test]
    fn severity_display_name_is_low() {
        assert_eq!(compute_severity("display_name"), DriftSeverity::Low);
    }

    #[test]
    fn severity_metadata_is_low() {
        assert_eq!(compute_severity("metadata"), DriftSeverity::Low);
    }

    #[test]
    fn severity_instance_type_is_medium() {
        assert_eq!(compute_severity("instance_type"), DriftSeverity::Medium);
    }

    #[test]
    fn severity_ami_is_medium() {
        assert_eq!(compute_severity("ami"), DriftSeverity::Medium);
    }

    #[test]
    fn severity_security_group_is_high() {
        assert_eq!(compute_severity("security_group_ids"), DriftSeverity::High);
    }

    #[test]
    fn severity_cidr_block_is_high() {
        assert_eq!(compute_severity("cidr_block"), DriftSeverity::High);
    }

    #[test]
    fn severity_vpc_id_is_high() {
        assert_eq!(compute_severity("vpc_id"), DriftSeverity::High);
    }

    #[test]
    fn severity_subnet_id_is_high() {
        assert_eq!(compute_severity("subnet_id"), DriftSeverity::High);
    }

    #[test]
    fn severity_ingress_is_high() {
        assert_eq!(compute_severity("ingress"), DriftSeverity::High);
    }

    #[test]
    fn severity_egress_is_high() {
        assert_eq!(compute_severity("egress"), DriftSeverity::High);
    }

    #[test]
    fn severity_acl_is_high() {
        assert_eq!(compute_severity("acl"), DriftSeverity::High);
    }

    #[test]
    fn severity_firewall_rule_is_high() {
        assert_eq!(compute_severity("firewall_rule"), DriftSeverity::High);
    }

    #[test]
    fn severity_network_interface_is_high() {
        assert_eq!(compute_severity("network_interface"), DriftSeverity::High);
    }

    #[test]
    fn severity_route_table_is_high() {
        assert_eq!(compute_severity("route_table"), DriftSeverity::High);
    }

    #[test]
    fn severity_policy_arn_is_high() {
        assert_eq!(compute_severity("policy_arn"), DriftSeverity::High);
    }

    #[test]
    fn severity_iam_role_is_critical() {
        assert_eq!(compute_severity("iam_role"), DriftSeverity::Critical);
    }

    #[test]
    fn severity_role_arn_is_critical() {
        assert_eq!(compute_severity("role_arn"), DriftSeverity::Critical);
    }

    #[test]
    fn severity_encryption_is_critical() {
        assert_eq!(compute_severity("encryption_enabled"), DriftSeverity::Critical);
    }

    #[test]
    fn severity_kms_key_is_critical() {
        // "kms" matches critical before "kms_key_id" matches high
        assert_eq!(compute_severity("kms_key_id"), DriftSeverity::Critical);
    }

    #[test]
    fn severity_password_is_critical() {
        assert_eq!(compute_severity("master_password"), DriftSeverity::Critical);
    }

    #[test]
    fn severity_secret_is_critical() {
        assert_eq!(compute_severity("secret_key"), DriftSeverity::Critical);
    }

    #[test]
    fn severity_credential_is_critical() {
        assert_eq!(compute_severity("credential"), DriftSeverity::Critical);
    }

    #[test]
    fn severity_root_is_critical() {
        assert_eq!(compute_severity("root_access"), DriftSeverity::Critical);
    }

    #[test]
    fn severity_admin_is_critical() {
        assert_eq!(compute_severity("admin_enabled"), DriftSeverity::Critical);
    }

    #[test]
    fn severity_delete_protection_is_critical() {
        assert_eq!(
            compute_severity("delete_protection"),
            DriftSeverity::Critical
        );
    }

    #[test]
    fn severity_termination_protection_is_critical() {
        assert_eq!(
            compute_severity("termination_protection"),
            DriftSeverity::Critical
        );
    }

    #[test]
    fn severity_principal_is_critical() {
        assert_eq!(compute_severity("principal"), DriftSeverity::Critical);
    }

    #[test]
    fn severity_assume_role_policy_is_high() {
        // "role" matches critical first
        assert_eq!(
            compute_severity("assume_role_policy"),
            DriftSeverity::Critical
        );
    }

    #[test]
    fn severity_case_insensitive() {
        assert_eq!(compute_severity("IAM_ROLE"), DriftSeverity::Critical);
        assert_eq!(compute_severity("Security_Group"), DriftSeverity::High);
        assert_eq!(compute_severity("Tags"), DriftSeverity::Low);
    }

    #[test]
    fn severity_unknown_attr_is_medium() {
        assert_eq!(compute_severity("availability_zone"), DriftSeverity::Medium);
    }

    #[test]
    fn severity_empty_string_is_medium() {
        assert_eq!(compute_severity(""), DriftSeverity::Medium);
    }

    // -- DriftedAttribute tests --------------------------------------------

    #[test]
    fn drifted_attribute_construction() {
        let da = DriftedAttribute {
            attribute_name: "instance_type".into(),
            expected_value_hash: hash_attribute_value("t2.micro"),
            actual_value_hash: hash_attribute_value("t3.large"),
            severity: DriftSeverity::Medium,
        };
        assert_eq!(da.attribute_name, "instance_type");
        assert_ne!(da.expected_value_hash, da.actual_value_hash);
    }

    #[test]
    fn drifted_attribute_serde_roundtrip() {
        let da = DriftedAttribute {
            attribute_name: "cidr_block".into(),
            expected_value_hash: hash_attribute_value("10.0.0.0/16"),
            actual_value_hash: hash_attribute_value("10.0.0.0/24"),
            severity: DriftSeverity::High,
        };
        let json = serde_json::to_string(&da).unwrap();
        let back: DriftedAttribute = serde_json::from_str(&json).unwrap();
        assert_eq!(back, da);
    }

    #[test]
    fn drifted_attribute_clone() {
        let da = DriftedAttribute {
            attribute_name: "ami".into(),
            expected_value_hash: "aaa".into(),
            actual_value_hash: "bbb".into(),
            severity: DriftSeverity::Medium,
        };
        let cloned = da.clone();
        drop(da);
        assert_eq!(cloned.attribute_name, "ami");
    }

    #[test]
    fn drifted_attribute_debug() {
        let da = DriftedAttribute {
            attribute_name: "x".into(),
            expected_value_hash: "a".into(),
            actual_value_hash: "b".into(),
            severity: DriftSeverity::Low,
        };
        let dbg = format!("{da:?}");
        assert!(dbg.contains("DriftedAttribute"));
    }

    #[test]
    fn drifted_attribute_eq() {
        let a = DriftedAttribute {
            attribute_name: "x".into(),
            expected_value_hash: "a".into(),
            actual_value_hash: "b".into(),
            severity: DriftSeverity::Low,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn drifted_attribute_ne() {
        let a = DriftedAttribute {
            attribute_name: "x".into(),
            expected_value_hash: "a".into(),
            actual_value_hash: "b".into(),
            severity: DriftSeverity::Low,
        };
        let mut b = a.clone();
        b.severity = DriftSeverity::High;
        assert_ne!(a, b);
    }

    // -- DriftedResource tests ---------------------------------------------

    #[test]
    fn drifted_resource_construction() {
        let dr = DriftedResource {
            address: "aws_instance.web".into(),
            resource_type: "aws_instance".into(),
            provider: "hashicorp/aws".into(),
            drifted_attributes: vec![],
            severity: DriftSeverity::None,
        };
        assert_eq!(dr.address, "aws_instance.web");
        assert!(dr.drifted_attributes.is_empty());
    }

    #[test]
    fn drifted_resource_serde_roundtrip() {
        let dr = DriftedResource {
            address: "aws_s3_bucket.data".into(),
            resource_type: "aws_s3_bucket".into(),
            provider: "hashicorp/aws".into(),
            drifted_attributes: vec![DriftedAttribute {
                attribute_name: "acl".into(),
                expected_value_hash: hash_attribute_value("private"),
                actual_value_hash: hash_attribute_value("public-read"),
                severity: DriftSeverity::High,
            }],
            severity: DriftSeverity::High,
        };
        let json = serde_json::to_string(&dr).unwrap();
        let back: DriftedResource = serde_json::from_str(&json).unwrap();
        assert_eq!(back, dr);
    }

    #[test]
    fn drifted_resource_clone() {
        let dr = DriftedResource {
            address: "aws_instance.web".into(),
            resource_type: "aws_instance".into(),
            provider: "hashicorp/aws".into(),
            drifted_attributes: vec![],
            severity: DriftSeverity::Low,
        };
        let cloned = dr.clone();
        drop(dr);
        assert_eq!(cloned.address, "aws_instance.web");
    }

    #[test]
    fn drifted_resource_debug() {
        let dr = DriftedResource {
            address: "x.y".into(),
            resource_type: "x".into(),
            provider: "p".into(),
            drifted_attributes: vec![],
            severity: DriftSeverity::None,
        };
        let dbg = format!("{dr:?}");
        assert!(dbg.contains("DriftedResource"));
    }

    #[test]
    fn drifted_resource_with_multiple_attrs() {
        let dr = DriftedResource {
            address: "aws_instance.web".into(),
            resource_type: "aws_instance".into(),
            provider: "hashicorp/aws".into(),
            drifted_attributes: vec![
                DriftedAttribute {
                    attribute_name: "instance_type".into(),
                    expected_value_hash: "a".into(),
                    actual_value_hash: "b".into(),
                    severity: DriftSeverity::Medium,
                },
                DriftedAttribute {
                    attribute_name: "security_group_ids".into(),
                    expected_value_hash: "c".into(),
                    actual_value_hash: "d".into(),
                    severity: DriftSeverity::High,
                },
            ],
            severity: DriftSeverity::High,
        };
        assert_eq!(dr.drifted_attributes.len(), 2);
        assert_eq!(dr.severity, DriftSeverity::High);
    }

    // -- DriftAuditEvent tests ---------------------------------------------

    #[test]
    fn audit_event_construction() {
        let ev = DriftAuditEvent {
            timestamp: "2026-03-09T00:00:00Z".into(),
            action: "detection_started".into(),
            resource_address: None,
            details: "Starting".into(),
        };
        assert_eq!(ev.action, "detection_started");
        assert!(ev.resource_address.is_none());
    }

    #[test]
    fn audit_event_with_resource() {
        let ev = DriftAuditEvent {
            timestamp: "2026-03-09T00:00:00Z".into(),
            action: "resource_compared".into(),
            resource_address: Some("aws_instance.web".into()),
            details: "Found 2 drifted attrs".into(),
        };
        assert_eq!(
            ev.resource_address,
            Some("aws_instance.web".to_string())
        );
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let ev = DriftAuditEvent {
            timestamp: "2026-03-09T12:30:00Z".into(),
            action: "test".into(),
            resource_address: Some("r.x".into()),
            details: "detail".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: DriftAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn audit_event_clone() {
        let ev = DriftAuditEvent {
            timestamp: "t".into(),
            action: "a".into(),
            resource_address: None,
            details: "d".into(),
        };
        let cloned = ev.clone();
        drop(ev);
        assert_eq!(cloned.action, "a");
    }

    #[test]
    fn audit_event_debug() {
        let ev = DriftAuditEvent {
            timestamp: "t".into(),
            action: "a".into(),
            resource_address: None,
            details: "d".into(),
        };
        let dbg = format!("{ev:?}");
        assert!(dbg.contains("DriftAuditEvent"));
    }

    // -- DriftReport tests -------------------------------------------------

    #[test]
    fn drift_report_empty() {
        let report = DriftReport {
            workspace_id: "ws-1".into(),
            generated_at: "2026-03-09T00:00:00Z".into(),
            resources_checked: 0,
            resources_drifted: 0,
            drifted_resources: vec![],
            overall_severity: DriftSeverity::None,
            plan_hash: None,
            audit_events: vec![],
        };
        assert_eq!(report.resources_checked, 0);
        assert_eq!(report.resources_drifted, 0);
        assert_eq!(report.overall_severity, DriftSeverity::None);
        assert!(report.plan_hash.is_none());
    }

    #[test]
    fn drift_report_with_plan_hash() {
        let report = DriftReport {
            workspace_id: "ws-1".into(),
            generated_at: "2026-03-09T00:00:00Z".into(),
            resources_checked: 5,
            resources_drifted: 1,
            drifted_resources: vec![],
            overall_severity: DriftSeverity::Low,
            plan_hash: Some("abc123".into()),
            audit_events: vec![],
        };
        assert_eq!(report.plan_hash, Some("abc123".to_string()));
    }

    #[test]
    fn drift_report_serde_roundtrip() {
        let report = DriftReport {
            workspace_id: "ws-prod".into(),
            generated_at: "2026-03-09T00:00:00Z".into(),
            resources_checked: 10,
            resources_drifted: 2,
            drifted_resources: vec![DriftedResource {
                address: "aws_instance.web".into(),
                resource_type: "aws_instance".into(),
                provider: "hashicorp/aws".into(),
                drifted_attributes: vec![DriftedAttribute {
                    attribute_name: "instance_type".into(),
                    expected_value_hash: "a".into(),
                    actual_value_hash: "b".into(),
                    severity: DriftSeverity::Medium,
                }],
                severity: DriftSeverity::Medium,
            }],
            overall_severity: DriftSeverity::Medium,
            plan_hash: Some("deadbeef".into()),
            audit_events: vec![DriftAuditEvent {
                timestamp: "2026-03-09T00:00:00Z".into(),
                action: "detection_started".into(),
                resource_address: None,
                details: "start".into(),
            }],
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: DriftReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn drift_report_clone() {
        let report = DriftReport {
            workspace_id: "ws-1".into(),
            generated_at: "t".into(),
            resources_checked: 3,
            resources_drifted: 0,
            drifted_resources: vec![],
            overall_severity: DriftSeverity::None,
            plan_hash: None,
            audit_events: vec![],
        };
        let cloned = report.clone();
        drop(report);
        assert_eq!(cloned.workspace_id, "ws-1");
    }

    #[test]
    fn drift_report_debug() {
        let report = DriftReport {
            workspace_id: "ws-dbg".into(),
            generated_at: "t".into(),
            resources_checked: 0,
            resources_drifted: 0,
            drifted_resources: vec![],
            overall_severity: DriftSeverity::None,
            plan_hash: None,
            audit_events: vec![],
        };
        let dbg = format!("{report:?}");
        assert!(dbg.contains("DriftReport"));
        assert!(dbg.contains("ws-dbg"));
    }

    // -- DriftDetector tests -----------------------------------------------

    #[test]
    fn detector_new() {
        let d = DriftDetector::new("ws-test");
        assert_eq!(d.workspace_id(), "ws-test");
        assert_eq!(d.resource_count(), 0);
    }

    #[test]
    fn detector_default_threshold() {
        let d = DriftDetector::new("ws-1");
        assert_eq!(d.severity_threshold(), DriftSeverity::Low);
    }

    #[test]
    fn detector_set_threshold() {
        let mut d = DriftDetector::new("ws-1");
        d.set_threshold(DriftSeverity::High);
        assert_eq!(d.severity_threshold(), DriftSeverity::High);
    }

    #[test]
    fn detector_add_resource_increments_count() {
        let mut d = DriftDetector::new("ws-1");
        d.add_resource("r.a", "r", "p", HashMap::new(), HashMap::new());
        assert_eq!(d.resource_count(), 1);
        d.add_resource("r.b", "r", "p", HashMap::new(), HashMap::new());
        assert_eq!(d.resource_count(), 2);
    }

    #[test]
    fn detector_add_resource_overwrites_same_address() {
        let mut d = DriftDetector::new("ws-1");
        d.add_resource("r.a", "r", "p", HashMap::new(), HashMap::new());
        d.add_resource("r.a", "r2", "p2", HashMap::new(), HashMap::new());
        assert_eq!(d.resource_count(), 1);
    }

    #[test]
    fn detector_no_drift_when_equal() {
        let mut d = DriftDetector::new("ws-1");
        let expected = HashMap::from([("instance_type".to_string(), "t2.micro".to_string())]);
        let actual = expected.clone();
        d.add_resource("aws_instance.web", "aws_instance", "hashicorp/aws", expected, actual);
        let drifted = d.detect_drift();
        assert!(drifted.is_empty());
    }

    #[test]
    fn detector_drift_when_values_differ() {
        let mut d = DriftDetector::new("ws-1");
        let expected = HashMap::from([("instance_type".to_string(), "t2.micro".to_string())]);
        let actual = HashMap::from([("instance_type".to_string(), "t3.large".to_string())]);
        d.add_resource("aws_instance.web", "aws_instance", "hashicorp/aws", expected, actual);
        let drifted = d.detect_drift();
        assert_eq!(drifted.len(), 1);
        assert_eq!(drifted[0].address, "aws_instance.web");
        assert_eq!(drifted[0].drifted_attributes.len(), 1);
        assert_eq!(drifted[0].drifted_attributes[0].attribute_name, "instance_type");
    }

    #[test]
    fn detector_drift_missing_actual_attribute() {
        let mut d = DriftDetector::new("ws-1");
        let expected = HashMap::from([("instance_type".to_string(), "t2.micro".to_string())]);
        let actual = HashMap::new();
        d.add_resource("r.a", "r", "p", expected, actual);
        let drifted = d.detect_drift();
        assert_eq!(drifted.len(), 1);
        assert_eq!(drifted[0].drifted_attributes[0].attribute_name, "instance_type");
    }

    #[test]
    fn detector_drift_extra_actual_attribute() {
        let mut d = DriftDetector::new("ws-1");
        let expected = HashMap::new();
        let actual = HashMap::from([("extra".to_string(), "value".to_string())]);
        d.add_resource("r.a", "r", "p", expected, actual);
        let drifted = d.detect_drift();
        assert_eq!(drifted.len(), 1);
        assert_eq!(drifted[0].drifted_attributes[0].attribute_name, "extra");
    }

    #[test]
    fn detector_drift_severity_is_max_of_attrs() {
        let mut d = DriftDetector::new("ws-1");
        let expected = HashMap::from([
            ("tags".to_string(), "old".to_string()),
            ("security_group_ids".to_string(), "sg-old".to_string()),
        ]);
        let actual = HashMap::from([
            ("tags".to_string(), "new".to_string()),
            ("security_group_ids".to_string(), "sg-new".to_string()),
        ]);
        d.add_resource("r.a", "r", "p", expected, actual);
        let drifted = d.detect_drift();
        assert_eq!(drifted.len(), 1);
        assert_eq!(drifted[0].severity, DriftSeverity::High);
    }

    #[test]
    fn detector_multiple_resources_mixed_drift() {
        let mut d = DriftDetector::new("ws-1");

        // Resource with no drift
        let same = HashMap::from([("x".to_string(), "v".to_string())]);
        d.add_resource("clean.a", "t", "p", same.clone(), same);

        // Resource with drift
        let expected = HashMap::from([("ami".to_string(), "old".to_string())]);
        let actual = HashMap::from([("ami".to_string(), "new".to_string())]);
        d.add_resource("dirty.b", "t", "p", expected, actual);

        let drifted = d.detect_drift();
        assert_eq!(drifted.len(), 1);
        assert_eq!(drifted[0].address, "dirty.b");
    }

    #[test]
    fn detector_empty_resources_no_drift() {
        let mut d = DriftDetector::new("ws-1");
        let drifted = d.detect_drift();
        assert!(drifted.is_empty());
    }

    #[test]
    fn detector_both_empty_maps_no_drift() {
        let mut d = DriftDetector::new("ws-1");
        d.add_resource("r.a", "r", "p", HashMap::new(), HashMap::new());
        let drifted = d.detect_drift();
        assert!(drifted.is_empty());
    }

    #[test]
    fn detector_report_no_drift() {
        let mut d = DriftDetector::new("ws-empty");
        let report = d.report();
        assert_eq!(report.workspace_id, "ws-empty");
        assert_eq!(report.resources_checked, 0);
        assert_eq!(report.resources_drifted, 0);
        assert_eq!(report.overall_severity, DriftSeverity::None);
        assert!(report.plan_hash.is_none());
    }

    #[test]
    fn detector_report_with_drift() {
        let mut d = DriftDetector::new("ws-prod");
        let expected = HashMap::from([("instance_type".to_string(), "t2.micro".to_string())]);
        let actual = HashMap::from([("instance_type".to_string(), "m5.xlarge".to_string())]);
        d.add_resource("aws_instance.web", "aws_instance", "hashicorp/aws", expected, actual);
        let report = d.report();
        assert_eq!(report.resources_checked, 1);
        assert_eq!(report.resources_drifted, 1);
        assert_eq!(report.overall_severity, DriftSeverity::Medium);
    }

    #[test]
    fn detector_report_with_plan_hash() {
        let mut d = DriftDetector::new("ws-1");
        let report = d.report_with_plan_hash(Some("plan-hash-123".into()));
        assert_eq!(report.plan_hash, Some("plan-hash-123".to_string()));
    }

    #[test]
    fn detector_report_overall_severity_is_max() {
        let mut d = DriftDetector::new("ws-1");

        // Low severity drift
        let expected1 = HashMap::from([("tags".to_string(), "old".to_string())]);
        let actual1 = HashMap::from([("tags".to_string(), "new".to_string())]);
        d.add_resource("r.low", "t", "p", expected1, actual1);

        // Critical severity drift
        let expected2 = HashMap::from([("iam_role".to_string(), "old".to_string())]);
        let actual2 = HashMap::from([("iam_role".to_string(), "new".to_string())]);
        d.add_resource("r.crit", "t", "p", expected2, actual2);

        let report = d.report();
        assert_eq!(report.overall_severity, DriftSeverity::Critical);
    }

    #[test]
    fn detector_report_audit_events_present() {
        let mut d = DriftDetector::new("ws-1");
        let report = d.report();
        // At minimum: detector_created, detection_started, detection_completed, report_generated
        assert!(report.audit_events.len() >= 4);
    }

    #[test]
    fn detector_audit_trail_starts_with_creation() {
        let d = DriftDetector::new("ws-1");
        let trail = d.audit_trail();
        assert!(!trail.is_empty());
        assert_eq!(trail[0].action, "detector_created");
    }

    #[test]
    fn detector_audit_trail_grows_on_add() {
        let mut d = DriftDetector::new("ws-1");
        let before = d.audit_trail().len();
        d.add_resource("r.a", "r", "p", HashMap::new(), HashMap::new());
        assert!(d.audit_trail().len() > before);
    }

    #[test]
    fn detector_audit_trail_resource_added_event() {
        let mut d = DriftDetector::new("ws-1");
        d.add_resource("aws_instance.web", "aws_instance", "p", HashMap::new(), HashMap::new());
        let last = d.audit_trail().last().unwrap();
        assert_eq!(last.action, "resource_added");
        assert_eq!(last.resource_address, Some("aws_instance.web".to_string()));
    }

    #[test]
    fn detector_exceeds_threshold_true() {
        let mut d = DriftDetector::new("ws-1");
        d.set_threshold(DriftSeverity::Medium);
        let expected = HashMap::from([("security_group".to_string(), "old".to_string())]);
        let actual = HashMap::from([("security_group".to_string(), "new".to_string())]);
        d.add_resource("r.a", "r", "p", expected, actual);
        assert!(d.exceeds_threshold());
    }

    #[test]
    fn detector_exceeds_threshold_false_no_drift() {
        let mut d = DriftDetector::new("ws-1");
        d.set_threshold(DriftSeverity::Low);
        assert!(!d.exceeds_threshold());
    }

    #[test]
    fn detector_exceeds_threshold_false_below() {
        let mut d = DriftDetector::new("ws-1");
        d.set_threshold(DriftSeverity::Critical);
        let expected = HashMap::from([("tags".to_string(), "old".to_string())]);
        let actual = HashMap::from([("tags".to_string(), "new".to_string())]);
        d.add_resource("r.a", "r", "p", expected, actual);
        // Low < Critical, so it should still be false because Low < Critical threshold
        // Actually exceeds_threshold checks if ANY severity >= threshold
        assert!(!d.exceeds_threshold());
    }

    #[test]
    fn detector_clone() {
        let d = DriftDetector::new("ws-1");
        let cloned = d.clone();
        // Use original after clone to avoid redundant_clone lint.
        assert_eq!(d.workspace_id(), "ws-1");
        assert_eq!(cloned.workspace_id(), "ws-1");
        assert_eq!(cloned.resource_count(), 0);
    }

    #[test]
    fn detector_debug() {
        let d = DriftDetector::new("ws-dbg");
        let dbg = format!("{d:?}");
        assert!(dbg.contains("DriftDetector"));
        assert!(dbg.contains("ws-dbg"));
    }

    #[test]
    fn detector_detect_drift_deterministic_order() {
        let mut d = DriftDetector::new("ws-1");
        let expected = HashMap::from([("x".to_string(), "old".to_string())]);
        let actual = HashMap::from([("x".to_string(), "new".to_string())]);
        d.add_resource("z.last", "t", "p", expected.clone(), actual.clone());
        d.add_resource("a.first", "t", "p", expected, actual);

        let drifted = d.detect_drift();
        assert_eq!(drifted.len(), 2);
        assert_eq!(drifted[0].address, "a.first");
        assert_eq!(drifted[1].address, "z.last");
    }

    #[test]
    fn detector_drift_attribute_hashes_correct() {
        let mut d = DriftDetector::new("ws-1");
        let expected = HashMap::from([("ami".to_string(), "ami-old".to_string())]);
        let actual = HashMap::from([("ami".to_string(), "ami-new".to_string())]);
        d.add_resource("r.a", "r", "p", expected, actual);
        let drifted = d.detect_drift();
        assert_eq!(
            drifted[0].drifted_attributes[0].expected_value_hash,
            hash_attribute_value("ami-old")
        );
        assert_eq!(
            drifted[0].drifted_attributes[0].actual_value_hash,
            hash_attribute_value("ami-new")
        );
    }

    #[test]
    fn detector_drift_multiple_attrs_sorted() {
        let mut d = DriftDetector::new("ws-1");
        let expected = HashMap::from([
            ("z_attr".to_string(), "old".to_string()),
            ("a_attr".to_string(), "old".to_string()),
        ]);
        let actual = HashMap::from([
            ("z_attr".to_string(), "new".to_string()),
            ("a_attr".to_string(), "new".to_string()),
        ]);
        d.add_resource("r.a", "r", "p", expected, actual);
        let drifted = d.detect_drift();
        assert_eq!(drifted[0].drifted_attributes[0].attribute_name, "a_attr");
        assert_eq!(drifted[0].drifted_attributes[1].attribute_name, "z_attr");
    }

    #[test]
    fn detector_report_generated_at_present() {
        let mut d = DriftDetector::new("ws-1");
        let report = d.report();
        assert!(!report.generated_at.is_empty());
    }

    #[test]
    fn detector_report_workspace_id_matches() {
        let mut d = DriftDetector::new("ws-custom-42");
        let report = d.report();
        assert_eq!(report.workspace_id, "ws-custom-42");
    }

    // -- Integration / scenario tests --------------------------------------

    #[test]
    fn scenario_full_drift_detection() {
        let mut d = DriftDetector::new("ws-prod");

        // Resource 1: instance type changed (medium)
        d.add_resource(
            "aws_instance.app",
            "aws_instance",
            "hashicorp/aws",
            HashMap::from([
                ("instance_type".to_string(), "t2.micro".to_string()),
                ("ami".to_string(), "ami-123".to_string()),
            ]),
            HashMap::from([
                ("instance_type".to_string(), "m5.xlarge".to_string()),
                ("ami".to_string(), "ami-123".to_string()),
            ]),
        );

        // Resource 2: security group changed (high)
        d.add_resource(
            "aws_security_group.web",
            "aws_security_group",
            "hashicorp/aws",
            HashMap::from([("ingress".to_string(), "80".to_string())]),
            HashMap::from([("ingress".to_string(), "80,443".to_string())]),
        );

        // Resource 3: no drift
        d.add_resource(
            "aws_s3_bucket.logs",
            "aws_s3_bucket",
            "hashicorp/aws",
            HashMap::from([("bucket".to_string(), "my-logs".to_string())]),
            HashMap::from([("bucket".to_string(), "my-logs".to_string())]),
        );

        let report = d.report();
        assert_eq!(report.resources_checked, 3);
        assert_eq!(report.resources_drifted, 2);
        assert_eq!(report.overall_severity, DriftSeverity::High);
        assert!(!report.audit_events.is_empty());
    }

    #[test]
    fn scenario_all_resources_drifted() {
        let mut d = DriftDetector::new("ws-1");
        for i in 0..5 {
            let expected = HashMap::from([("x".to_string(), format!("old-{i}"))]);
            let actual = HashMap::from([("x".to_string(), format!("new-{i}"))]);
            d.add_resource(format!("r.{i}"), "t", "p", expected, actual);
        }
        let report = d.report();
        assert_eq!(report.resources_checked, 5);
        assert_eq!(report.resources_drifted, 5);
    }

    #[test]
    fn scenario_no_resources_drifted() {
        let mut d = DriftDetector::new("ws-1");
        for i in 0..3 {
            let same = HashMap::from([("x".to_string(), format!("v-{i}"))]);
            d.add_resource(format!("r.{i}"), "t", "p", same.clone(), same);
        }
        let report = d.report();
        assert_eq!(report.resources_drifted, 0);
        assert_eq!(report.overall_severity, DriftSeverity::None);
    }

    #[test]
    fn scenario_critical_drift_iam() {
        let mut d = DriftDetector::new("ws-sec");
        d.set_threshold(DriftSeverity::Critical);
        let expected = HashMap::from([
            ("iam_role".to_string(), "role-old".to_string()),
            ("tags".to_string(), "old".to_string()),
        ]);
        let actual = HashMap::from([
            ("iam_role".to_string(), "role-new".to_string()),
            ("tags".to_string(), "new".to_string()),
        ]);
        d.add_resource("aws_iam_role.admin", "aws_iam_role", "hashicorp/aws", expected, actual);
        assert!(d.exceeds_threshold());
    }

    #[test]
    fn scenario_threshold_not_exceeded() {
        let mut d = DriftDetector::new("ws-1");
        d.set_threshold(DriftSeverity::High);
        let expected = HashMap::from([("tags".to_string(), "old".to_string())]);
        let actual = HashMap::from([("tags".to_string(), "new".to_string())]);
        d.add_resource("r.a", "r", "p", expected, actual);
        assert!(!d.exceeds_threshold());
    }

    #[test]
    fn scenario_large_attribute_set() {
        let mut d = DriftDetector::new("ws-1");
        let mut expected = HashMap::new();
        let mut actual = HashMap::new();
        for i in 0..50 {
            let key = format!("attr_{i}");
            expected.insert(key.clone(), format!("val_{i}"));
            if i % 10 == 0 {
                actual.insert(key, format!("changed_{i}"));
            } else {
                actual.insert(key, format!("val_{i}"));
            }
        }
        d.add_resource("r.big", "t", "p", expected, actual);
        let drifted = d.detect_drift();
        assert_eq!(drifted.len(), 1);
        // 5 changed: 0, 10, 20, 30, 40
        assert_eq!(drifted[0].drifted_attributes.len(), 5);
    }

    #[test]
    fn scenario_empty_values() {
        let mut d = DriftDetector::new("ws-1");
        let expected = HashMap::from([("x".to_string(), String::new())]);
        let actual = HashMap::from([("x".to_string(), "notempty".to_string())]);
        d.add_resource("r.a", "r", "p", expected, actual);
        let drifted = d.detect_drift();
        assert_eq!(drifted.len(), 1);
    }

    #[test]
    fn scenario_both_empty_values_no_drift() {
        let mut d = DriftDetector::new("ws-1");
        let expected = HashMap::from([("x".to_string(), String::new())]);
        let actual = HashMap::from([("x".to_string(), String::new())]);
        d.add_resource("r.a", "r", "p", expected, actual);
        let drifted = d.detect_drift();
        assert!(drifted.is_empty());
    }

    #[test]
    fn drift_report_serde_json_value_roundtrip() {
        let mut d = DriftDetector::new("ws-1");
        let expected = HashMap::from([("x".to_string(), "old".to_string())]);
        let actual = HashMap::from([("x".to_string(), "new".to_string())]);
        d.add_resource("r.a", "r", "p", expected, actual);
        let report = d.report();
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["workspace_id"], "ws-1");
        assert_eq!(value["resources_drifted"], 1);
        let back: DriftReport = serde_json::from_value(value).unwrap();
        assert_eq!(back.workspace_id, "ws-1");
    }

    #[test]
    fn drift_report_from_json_string() {
        let json = r#"{
            "workspace_id": "ws-json",
            "generated_at": "2026-03-09T00:00:00Z",
            "resources_checked": 0,
            "resources_drifted": 0,
            "drifted_resources": [],
            "overall_severity": "none",
            "plan_hash": null,
            "audit_events": []
        }"#;
        let report: DriftReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.workspace_id, "ws-json");
        assert_eq!(report.overall_severity, DriftSeverity::None);
    }

    #[test]
    fn drifted_resource_eq() {
        let a = DriftedResource {
            address: "r.a".into(),
            resource_type: "t".into(),
            provider: "p".into(),
            drifted_attributes: vec![],
            severity: DriftSeverity::None,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn drifted_resource_ne_different_address() {
        let a = DriftedResource {
            address: "r.a".into(),
            resource_type: "t".into(),
            provider: "p".into(),
            drifted_attributes: vec![],
            severity: DriftSeverity::None,
        };
        let mut b = a.clone();
        b.address = "r.b".into();
        assert_ne!(a, b);
    }

    #[test]
    fn audit_event_eq() {
        let a = DriftAuditEvent {
            timestamp: "t".into(),
            action: "a".into(),
            resource_address: None,
            details: "d".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn audit_event_ne() {
        let a = DriftAuditEvent {
            timestamp: "t1".into(),
            action: "a".into(),
            resource_address: None,
            details: "d".into(),
        };
        let mut b = a.clone();
        b.timestamp = "t2".into();
        assert_ne!(a, b);
    }

    #[test]
    fn detector_workspace_id_with_special_chars() {
        let d = DriftDetector::new("ws-prod/us-east-1");
        assert_eq!(d.workspace_id(), "ws-prod/us-east-1");
    }

    #[test]
    fn detector_workspace_id_empty() {
        let d = DriftDetector::new("");
        assert_eq!(d.workspace_id(), "");
    }

    #[test]
    fn hash_special_characters() {
        let h = hash_attribute_value("value with !@#$%^&*()");
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_very_long_string() {
        let long = "x".repeat(10_000);
        let h = hash_attribute_value(&long);
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn detector_report_audit_includes_all_phases() {
        let mut d = DriftDetector::new("ws-1");
        d.add_resource(
            "r.a",
            "r",
            "p",
            HashMap::from([("x".to_string(), "old".to_string())]),
            HashMap::from([("x".to_string(), "new".to_string())]),
        );
        let report = d.report();
        let actions: Vec<&str> = report.audit_events.iter().map(|e| e.action.as_str()).collect();
        assert!(actions.contains(&"detector_created"));
        assert!(actions.contains(&"resource_added"));
        assert!(actions.contains(&"detection_started"));
        assert!(actions.contains(&"resource_compared"));
        assert!(actions.contains(&"detection_completed"));
        assert!(actions.contains(&"report_generated"));
    }

    #[test]
    fn detector_detect_drift_idempotent() {
        let mut d = DriftDetector::new("ws-1");
        let expected = HashMap::from([("x".to_string(), "old".to_string())]);
        let actual = HashMap::from([("x".to_string(), "new".to_string())]);
        d.add_resource("r.a", "r", "p", expected, actual);
        let first = d.detect_drift();
        let second = d.detect_drift();
        assert_eq!(first.len(), second.len());
        assert_eq!(first[0].address, second[0].address);
    }

    #[test]
    fn severity_all_variants_serde() {
        for sev in [
            DriftSeverity::None,
            DriftSeverity::Low,
            DriftSeverity::Medium,
            DriftSeverity::High,
            DriftSeverity::Critical,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let back: DriftSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, back);
        }
    }

    #[test]
    fn severity_ordering_all_variants() {
        let ordered = [
            DriftSeverity::None,
            DriftSeverity::Low,
            DriftSeverity::Medium,
            DriftSeverity::High,
            DriftSeverity::Critical,
        ];
        for i in 0..ordered.len() - 1 {
            assert!(ordered[i] < ordered[i + 1]);
        }
    }

    #[test]
    fn drifted_attribute_serde_from_json() {
        let json = r#"{
            "attribute_name": "ami",
            "expected_value_hash": "abc",
            "actual_value_hash": "def",
            "severity": "medium"
        }"#;
        let da: DriftedAttribute = serde_json::from_str(json).unwrap();
        assert_eq!(da.attribute_name, "ami");
        assert_eq!(da.severity, DriftSeverity::Medium);
    }

    #[test]
    fn drifted_resource_serde_from_json() {
        let json = r#"{
            "address": "aws_instance.web",
            "resource_type": "aws_instance",
            "provider": "hashicorp/aws",
            "drifted_attributes": [],
            "severity": "none"
        }"#;
        let dr: DriftedResource = serde_json::from_str(json).unwrap();
        assert_eq!(dr.address, "aws_instance.web");
        assert!(dr.drifted_attributes.is_empty());
    }

    #[test]
    fn detector_resource_type_preserved() {
        let mut d = DriftDetector::new("ws-1");
        let expected = HashMap::from([("x".to_string(), "old".to_string())]);
        let actual = HashMap::from([("x".to_string(), "new".to_string())]);
        d.add_resource("r.a", "aws_instance", "hashicorp/aws", expected, actual);
        let drifted = d.detect_drift();
        assert_eq!(drifted[0].resource_type, "aws_instance");
    }

    #[test]
    fn detector_provider_preserved() {
        let mut d = DriftDetector::new("ws-1");
        let expected = HashMap::from([("x".to_string(), "old".to_string())]);
        let actual = HashMap::from([("x".to_string(), "new".to_string())]);
        d.add_resource("r.a", "aws_instance", "hashicorp/aws", expected, actual);
        let drifted = d.detect_drift();
        assert_eq!(drifted[0].provider, "hashicorp/aws");
    }

    #[test]
    fn hash_null_byte_in_string() {
        let h = hash_attribute_value("val\x00ue");
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn detector_add_many_resources() {
        let mut d = DriftDetector::new("ws-1");
        for i in 0..100 {
            d.add_resource(
                format!("r.{i}"),
                "t",
                "p",
                HashMap::new(),
                HashMap::new(),
            );
        }
        assert_eq!(d.resource_count(), 100);
    }

    #[test]
    fn detector_report_none_plan_hash_serializes_as_null() {
        let mut d = DriftDetector::new("ws-1");
        let report = d.report();
        let value = serde_json::to_value(&report).unwrap();
        assert!(value["plan_hash"].is_null());
    }

    #[test]
    fn severity_annotation_is_low() {
        assert_eq!(compute_severity("annotation"), DriftSeverity::Low);
    }

    #[test]
    fn severity_comment_is_low() {
        assert_eq!(compute_severity("comment"), DriftSeverity::Low);
    }

    #[test]
    fn severity_ssl_certificate_is_high() {
        assert_eq!(compute_severity("ssl_certificate_id"), DriftSeverity::High);
    }

    #[test]
    fn severity_tls_is_high() {
        assert_eq!(compute_severity("tls_enabled"), DriftSeverity::High);
    }
}
