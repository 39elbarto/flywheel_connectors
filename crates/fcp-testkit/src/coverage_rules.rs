//! Coverage rules for FCP3 subsystem testing.
//!
//! Defines which categories of testing are required (or recommended) for each
//! FCP3 subsystem.  The [`default_policy`] function returns a full set of rules
//! for a given [`SubsystemClass`], and [`validate_coverage`] checks a list of
//! actually-covered categories against a policy.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// SubsystemClass
// ─────────────────────────────────────────────────────────────────────────────

/// FCP3 subsystem classification for coverage rule assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubsystemClass {
    /// Runtime context, budgets, correlation.
    Kernel,
    /// Supervisor, enforcement, health, output.
    Host,
    /// Framed transport, CBOR codec, protocol.
    Abi,
    /// Connector SDK, harness adapters.
    Sdk,
    /// Schema, validation, versioning.
    Manifest,
    /// CUAL, capability, credential.
    Policy,
    /// WASI, remote, failover.
    Placement,
    /// Bootstrap, injection, rotation.
    Provisioning,
}

impl fmt::Display for SubsystemClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kernel => write!(f, "Kernel"),
            Self::Host => write!(f, "Host"),
            Self::Abi => write!(f, "Abi"),
            Self::Sdk => write!(f, "Sdk"),
            Self::Manifest => write!(f, "Manifest"),
            Self::Policy => write!(f, "Policy"),
            Self::Placement => write!(f, "Placement"),
            Self::Provisioning => write!(f, "Provisioning"),
        }
    }
}

/// All known subsystem classes.
const ALL_SUBSYSTEMS: [SubsystemClass; 8] = [
    SubsystemClass::Kernel,
    SubsystemClass::Host,
    SubsystemClass::Abi,
    SubsystemClass::Sdk,
    SubsystemClass::Manifest,
    SubsystemClass::Policy,
    SubsystemClass::Placement,
    SubsystemClass::Provisioning,
];

// ─────────────────────────────────────────────────────────────────────────────
// CoverageCategory
// ─────────────────────────────────────────────────────────────────────────────

/// Coverage rule category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoverageCategory {
    /// Happy-path, expected inputs.
    PositivePath,
    /// Invalid inputs, boundary violations.
    NegativePath,
    /// Drain, abort, timeout.
    Cancellation,
    /// Cold restart, warm resume.
    Restart,
    /// Fallback, degraded mode.
    Failover,
    /// Capability denied, policy block.
    Denial,
    /// Repair, self-heal, retry.
    Recovery,
    /// Malformed frames, injection, overflow.
    Adversarial,
    /// Quickcheck/proptest invariants.
    PropertyBased,
    /// Fault inject, chaos.
    FailureInjection,
}

impl fmt::Display for CoverageCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PositivePath => write!(f, "PositivePath"),
            Self::NegativePath => write!(f, "NegativePath"),
            Self::Cancellation => write!(f, "Cancellation"),
            Self::Restart => write!(f, "Restart"),
            Self::Failover => write!(f, "Failover"),
            Self::Denial => write!(f, "Denial"),
            Self::Recovery => write!(f, "Recovery"),
            Self::Adversarial => write!(f, "Adversarial"),
            Self::PropertyBased => write!(f, "PropertyBased"),
            Self::FailureInjection => write!(f, "FailureInjection"),
        }
    }
}

/// All known coverage categories.
const ALL_CATEGORIES: [CoverageCategory; 10] = [
    CoverageCategory::PositivePath,
    CoverageCategory::NegativePath,
    CoverageCategory::Cancellation,
    CoverageCategory::Restart,
    CoverageCategory::Failover,
    CoverageCategory::Denial,
    CoverageCategory::Recovery,
    CoverageCategory::Adversarial,
    CoverageCategory::PropertyBased,
    CoverageCategory::FailureInjection,
];

// ─────────────────────────────────────────────────────────────────────────────
// CoverageRule
// ─────────────────────────────────────────────────────────────────────────────

/// A single coverage rule: what kind of test, for which subsystem.
#[derive(Debug, Clone)]
pub struct CoverageRule {
    /// Which subsystem this rule applies to.
    pub subsystem: SubsystemClass,
    /// Which testing category.
    pub category: CoverageCategory,
    /// Human-readable description.
    pub description: String,
    /// Whether this rule is mandatory (true) or recommended (false).
    pub required: bool,
    /// Minimum test case count.
    pub min_cases: u32,
    /// Whether this rule needs host-backed integration tests.
    pub requires_host: bool,
    /// Whether this rule needs fuzz/property infrastructure.
    pub requires_fuzz: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// SubsystemCoveragePolicy
// ─────────────────────────────────────────────────────────────────────────────

/// Coverage policy for a subsystem.
#[derive(Debug, Clone)]
pub struct SubsystemCoveragePolicy {
    /// The subsystem this policy covers.
    pub subsystem: SubsystemClass,
    /// The set of coverage rules.
    pub rules: Vec<CoverageRule>,
}

impl SubsystemCoveragePolicy {
    /// Return the categories that appear in the policy rules.
    #[must_use]
    pub fn categories(&self) -> Vec<CoverageCategory> {
        let mut cats: Vec<CoverageCategory> = self.rules.iter().map(|r| r.category).collect();
        cats.sort_by_key(|c| *c as u32);
        cats.dedup();
        cats
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — build a rule
// ─────────────────────────────────────────────────────────────────────────────

fn rule(
    subsystem: SubsystemClass,
    category: CoverageCategory,
    description: &str,
    required: bool,
    min_cases: u32,
    requires_host: bool,
    requires_fuzz: bool,
) -> CoverageRule {
    CoverageRule {
        subsystem,
        category,
        description: description.to_string(),
        required,
        min_cases,
        requires_host,
        requires_fuzz,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the default set of required coverage rules for a given subsystem.
#[must_use]
pub fn default_policy(subsystem: SubsystemClass) -> SubsystemCoveragePolicy {
    let s = subsystem;
    let rules = match subsystem {
        SubsystemClass::Kernel => vec![
            rule(s, CoverageCategory::PositivePath, "happy-path context creation", true, 3, false, false),
            rule(s, CoverageCategory::NegativePath, "invalid budget / correlation inputs", true, 3, false, false),
            rule(s, CoverageCategory::Cancellation, "drain and abort during context ops", true, 2, false, false),
            rule(s, CoverageCategory::Recovery, "self-heal after partial context failure", true, 2, false, false),
            rule(s, CoverageCategory::PropertyBased, "budget invariant properties", false, 1, false, true),
            rule(s, CoverageCategory::FailureInjection, "fault injection in runtime context", false, 1, true, false),
        ],
        SubsystemClass::Host => vec![
            rule(s, CoverageCategory::PositivePath, "supervisor lifecycle happy path", true, 3, true, false),
            rule(s, CoverageCategory::NegativePath, "invalid enforcement pipeline inputs", true, 3, false, false),
            rule(s, CoverageCategory::Restart, "cold restart and warm resume", true, 2, true, false),
            rule(s, CoverageCategory::Failover, "fallback and degraded mode transitions", true, 2, true, false),
            rule(s, CoverageCategory::Cancellation, "drain in-flight operations", true, 2, true, false),
            rule(s, CoverageCategory::Recovery, "health check repair cycle", true, 2, true, false),
            rule(s, CoverageCategory::Adversarial, "malformed output capture", false, 1, false, true),
            rule(s, CoverageCategory::FailureInjection, "chaos in supervisor pipeline", false, 1, true, false),
        ],
        SubsystemClass::Abi => vec![
            rule(s, CoverageCategory::PositivePath, "well-formed frame round-trip", true, 3, false, false),
            rule(s, CoverageCategory::NegativePath, "truncated / oversized frames", true, 3, false, false),
            rule(s, CoverageCategory::Adversarial, "malformed CBOR, injection, overflow", true, 3, false, true),
            rule(s, CoverageCategory::PropertyBased, "codec encode/decode round-trip properties", true, 2, false, true),
            rule(s, CoverageCategory::Cancellation, "mid-frame abort", false, 1, false, false),
            rule(s, CoverageCategory::FailureInjection, "transport fault injection", false, 1, false, false),
        ],
        SubsystemClass::Sdk => vec![
            rule(s, CoverageCategory::PositivePath, "harness adapter happy path", true, 3, false, false),
            rule(s, CoverageCategory::NegativePath, "invalid SDK calls", true, 3, false, false),
            rule(s, CoverageCategory::Cancellation, "harness shutdown during SDK call", false, 1, false, false),
            rule(s, CoverageCategory::Recovery, "retry after transient SDK error", false, 1, false, false),
        ],
        SubsystemClass::Manifest => vec![
            rule(s, CoverageCategory::PositivePath, "valid schema + version acceptance", true, 3, false, false),
            rule(s, CoverageCategory::NegativePath, "invalid schema, version mismatch", true, 3, false, false),
            rule(s, CoverageCategory::PropertyBased, "schema validation invariants", false, 1, false, true),
            rule(s, CoverageCategory::Adversarial, "oversized manifest payloads", false, 1, false, false),
        ],
        SubsystemClass::Policy => vec![
            rule(s, CoverageCategory::PositivePath, "capability grant happy path", true, 3, false, false),
            rule(s, CoverageCategory::NegativePath, "invalid CUAL / capability format", true, 3, false, false),
            rule(s, CoverageCategory::Denial, "capability denied, policy block", true, 3, false, false),
            rule(s, CoverageCategory::Adversarial, "credential injection attempts", false, 2, false, true),
            rule(s, CoverageCategory::Recovery, "credential rotation recovery", false, 1, false, false),
        ],
        SubsystemClass::Placement => vec![
            rule(s, CoverageCategory::PositivePath, "WASI instantiation happy path", true, 3, true, false),
            rule(s, CoverageCategory::NegativePath, "invalid placement target", true, 3, false, false),
            rule(s, CoverageCategory::Failover, "failover to secondary placement", true, 2, true, false),
            rule(s, CoverageCategory::Cancellation, "mid-placement abort", false, 1, true, false),
            rule(s, CoverageCategory::FailureInjection, "remote placement fault inject", false, 1, true, false),
        ],
        SubsystemClass::Provisioning => vec![
            rule(s, CoverageCategory::PositivePath, "bootstrap injection happy path", true, 3, false, false),
            rule(s, CoverageCategory::NegativePath, "invalid bootstrap payload", true, 3, false, false),
            rule(s, CoverageCategory::Recovery, "credential rotation recovery", true, 2, false, false),
            rule(s, CoverageCategory::Cancellation, "abort during injection", false, 1, false, false),
            rule(s, CoverageCategory::FailureInjection, "fault inject in rotation pipeline", false, 1, false, false),
        ],
    };

    SubsystemCoveragePolicy { subsystem, rules }
}

/// Returns which coverage categories are mandatory for a subsystem.
#[must_use]
pub fn minimum_credible_coverage(subsystem: &SubsystemClass) -> Vec<CoverageCategory> {
    let policy = default_policy(*subsystem);
    let mut cats: Vec<CoverageCategory> = policy
        .rules
        .iter()
        .filter(|r| r.required)
        .map(|r| r.category)
        .collect();
    cats.sort_by_key(|c| *c as u32);
    cats.dedup();
    cats
}

/// Whether unit tests alone are insufficient for this subsystem (needs host
/// integration tests).
#[must_use]
pub const fn requires_host_integration(subsystem: &SubsystemClass) -> bool {
    matches!(
        subsystem,
        SubsystemClass::Host | SubsystemClass::Placement
    )
}

/// Whether adversarial/fuzz testing is required for this subsystem.
#[must_use]
pub const fn requires_fuzz_surface(subsystem: &SubsystemClass) -> bool {
    matches!(subsystem, SubsystemClass::Abi)
}

/// Validates actual coverage against a policy and returns missing coverage areas.
///
/// Each returned string describes a mandatory category that is not present in
/// `actual_categories`.
#[must_use]
pub fn validate_coverage(
    policy: &SubsystemCoveragePolicy,
    actual_categories: &[CoverageCategory],
) -> Vec<String> {
    let mut missing = Vec::new();

    for rule in &policy.rules {
        if !rule.required {
            continue;
        }
        if !actual_categories.contains(&rule.category) {
            missing.push(format!(
                "{}: missing required {} coverage - {}",
                policy.subsystem, rule.category, rule.description,
            ));
        }
    }

    // Deduplicate: same category may appear in multiple rules
    missing.sort();
    missing.dedup();
    missing
}

/// Returns every [`SubsystemClass`] variant.
#[must_use]
pub const fn all_subsystems() -> &'static [SubsystemClass] {
    &ALL_SUBSYSTEMS
}

/// Returns every [`CoverageCategory`] variant.
#[must_use]
pub const fn all_categories() -> &'static [CoverageCategory] {
    &ALL_CATEGORIES
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // 1. Each subsystem has a non-empty default policy
    #[test]
    fn every_subsystem_has_non_empty_default_policy() {
        for subsystem in all_subsystems() {
            let policy = default_policy(*subsystem);
            assert!(
                !policy.rules.is_empty(),
                "{subsystem} should have at least one coverage rule",
            );
        }
    }

    // 2. Kernel subsystem requires cancellation coverage
    #[test]
    fn kernel_requires_cancellation() {
        let cats = minimum_credible_coverage(&SubsystemClass::Kernel);
        assert!(
            cats.contains(&CoverageCategory::Cancellation),
            "Kernel mandatory categories should include Cancellation",
        );
    }

    // 3. ABI subsystem requires adversarial/fuzz coverage
    #[test]
    fn abi_requires_adversarial() {
        let cats = minimum_credible_coverage(&SubsystemClass::Abi);
        assert!(
            cats.contains(&CoverageCategory::Adversarial),
            "Abi mandatory categories should include Adversarial",
        );
    }

    // 4. Host subsystem requires restart and failover coverage
    #[test]
    fn host_requires_restart_and_failover() {
        let cats = minimum_credible_coverage(&SubsystemClass::Host);
        assert!(
            cats.contains(&CoverageCategory::Restart),
            "Host mandatory categories should include Restart",
        );
        assert!(
            cats.contains(&CoverageCategory::Failover),
            "Host mandatory categories should include Failover",
        );
    }

    // 5. Policy subsystem requires denial coverage
    #[test]
    fn policy_requires_denial() {
        let cats = minimum_credible_coverage(&SubsystemClass::Policy);
        assert!(
            cats.contains(&CoverageCategory::Denial),
            "Policy mandatory categories should include Denial",
        );
    }

    // 6. All subsystems require positive and negative path coverage
    #[test]
    fn all_subsystems_require_positive_and_negative_path() {
        for subsystem in all_subsystems() {
            let cats = minimum_credible_coverage(subsystem);
            assert!(
                cats.contains(&CoverageCategory::PositivePath),
                "{subsystem} should require PositivePath",
            );
            assert!(
                cats.contains(&CoverageCategory::NegativePath),
                "{subsystem} should require NegativePath",
            );
        }
    }

    // 7. validate_coverage detects missing mandatory categories
    #[test]
    fn validate_coverage_detects_missing() {
        let policy = default_policy(SubsystemClass::Policy);
        // Provide only PositivePath — should flag NegativePath and Denial
        let actual = [CoverageCategory::PositivePath];
        let missing = validate_coverage(&policy, &actual);
        assert!(
            !missing.is_empty(),
            "Should report missing categories",
        );
        let joined = missing.join("\n");
        assert!(joined.contains("NegativePath"), "Should mention NegativePath: {joined}");
        assert!(joined.contains("Denial"), "Should mention Denial: {joined}");
    }

    // 8. validate_coverage accepts complete coverage
    #[test]
    fn validate_coverage_accepts_complete() {
        let policy = default_policy(SubsystemClass::Sdk);
        let cats = minimum_credible_coverage(&SubsystemClass::Sdk);
        let missing = validate_coverage(&policy, &cats);
        assert!(
            missing.is_empty(),
            "Complete coverage should produce no missing items, got: {missing:?}",
        );
    }

    // 9. requires_host_integration returns true for Host/Placement
    #[test]
    fn host_and_placement_require_host_integration() {
        assert!(requires_host_integration(&SubsystemClass::Host));
        assert!(requires_host_integration(&SubsystemClass::Placement));
        assert!(!requires_host_integration(&SubsystemClass::Sdk));
        assert!(!requires_host_integration(&SubsystemClass::Kernel));
    }

    // 10. requires_fuzz_surface returns true for Abi
    #[test]
    fn abi_requires_fuzz_surface() {
        assert!(requires_fuzz_surface(&SubsystemClass::Abi));
        assert!(!requires_fuzz_surface(&SubsystemClass::Sdk));
        assert!(!requires_fuzz_surface(&SubsystemClass::Host));
    }

    // 11. Coverage rules have non-zero min_cases
    #[test]
    fn all_rules_have_non_zero_min_cases() {
        for subsystem in all_subsystems() {
            let policy = default_policy(*subsystem);
            for rule in &policy.rules {
                assert!(
                    rule.min_cases > 0,
                    "{}: rule for {} has min_cases == 0",
                    subsystem,
                    rule.category,
                );
            }
        }
    }

    // 12. SubsystemClass Display/Debug impl works
    #[test]
    fn subsystem_class_display_debug() {
        let kernel = SubsystemClass::Kernel;
        assert_eq!(format!("{kernel}"), "Kernel");
        let dbg = format!("{kernel:?}");
        assert!(dbg.contains("Kernel"));

        // Check all variants produce non-empty strings
        for s in all_subsystems() {
            let disp = format!("{s}");
            assert!(!disp.is_empty(), "Display should be non-empty for {s:?}");
            let dbg = format!("{s:?}");
            assert!(!dbg.is_empty(), "Debug should be non-empty for {s:?}");
        }
    }

    // 13. CoverageCategory Display/Debug impl works
    #[test]
    fn coverage_category_display_debug() {
        let pp = CoverageCategory::PositivePath;
        assert_eq!(format!("{pp}"), "PositivePath");
        let dbg = format!("{pp:?}");
        assert!(dbg.contains("PositivePath"));

        for c in all_categories() {
            let disp = format!("{c}");
            assert!(!disp.is_empty(), "Display should be non-empty for {c:?}");
            let dbg = format!("{c:?}");
            assert!(!dbg.is_empty(), "Debug should be non-empty for {c:?}");
        }
    }

    // 14. default_policy for Provisioning includes credential rotation
    #[test]
    fn provisioning_includes_credential_rotation() {
        let policy = default_policy(SubsystemClass::Provisioning);
        let has_rotation = policy
            .rules
            .iter()
            .any(|r| r.description.contains("credential rotation"));
        assert!(
            has_rotation,
            "Provisioning should have a credential rotation rule",
        );
    }

    // 15. minimum_credible_coverage is a subset of default_policy categories
    #[test]
    fn minimum_credible_is_subset_of_default_policy() {
        for subsystem in all_subsystems() {
            let min = minimum_credible_coverage(subsystem);
            let all = default_policy(*subsystem).categories();
            for cat in &min {
                assert!(
                    all.contains(cat),
                    "{subsystem}: minimum_credible category {cat} not in default_policy",
                );
            }
        }
    }

    // ── Additional tests ────────────────────────────────────────────────────

    #[test]
    fn subsystem_class_eq_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(SubsystemClass::Kernel);
        set.insert(SubsystemClass::Kernel); // duplicate
        assert_eq!(set.len(), 1);
        set.insert(SubsystemClass::Host);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn coverage_category_eq_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(CoverageCategory::PositivePath);
        set.insert(CoverageCategory::PositivePath); // duplicate
        assert_eq!(set.len(), 1);
        set.insert(CoverageCategory::NegativePath);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn subsystem_class_clone_copy() {
        let a = SubsystemClass::Abi;
        let b = a; // Copy
        let c = a.clone(); // Clone
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn coverage_category_clone_copy() {
        let a = CoverageCategory::Denial;
        let b = a; // Copy
        let c = a.clone(); // Clone
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn coverage_rule_clone() {
        let r = rule(
            SubsystemClass::Kernel,
            CoverageCategory::PositivePath,
            "test rule",
            true,
            5,
            false,
            false,
        );
        let cloned = r.clone();
        assert_eq!(cloned.subsystem, SubsystemClass::Kernel);
        assert_eq!(cloned.category, CoverageCategory::PositivePath);
        assert_eq!(cloned.description, "test rule");
        assert!(cloned.required);
        assert_eq!(cloned.min_cases, 5);
    }

    #[test]
    fn subsystem_coverage_policy_clone() {
        let policy = default_policy(SubsystemClass::Host);
        let cloned = policy.clone();
        assert_eq!(cloned.subsystem, SubsystemClass::Host);
        assert_eq!(cloned.rules.len(), policy.rules.len());
    }

    #[test]
    fn validate_coverage_empty_actual_reports_all_mandatory() {
        let policy = default_policy(SubsystemClass::Host);
        let missing = validate_coverage(&policy, &[]);
        // Host has multiple mandatory categories
        assert!(missing.len() >= 3, "Expected at least 3 missing, got {}", missing.len());
    }

    #[test]
    fn validate_coverage_with_extras_still_passes() {
        // Providing extra categories beyond what is required should not cause errors
        let policy = default_policy(SubsystemClass::Sdk);
        let mut cats = minimum_credible_coverage(&SubsystemClass::Sdk);
        cats.push(CoverageCategory::Adversarial);
        cats.push(CoverageCategory::FailureInjection);
        let missing = validate_coverage(&policy, &cats);
        assert!(missing.is_empty(), "Extra categories should not cause failures: {missing:?}");
    }

    #[test]
    fn all_subsystems_returns_eight() {
        assert_eq!(all_subsystems().len(), 8);
    }

    #[test]
    fn all_categories_returns_ten() {
        assert_eq!(all_categories().len(), 10);
    }

    #[test]
    fn abi_policy_has_fuzz_rules() {
        let policy = default_policy(SubsystemClass::Abi);
        let fuzz_rules: Vec<_> = policy.rules.iter().filter(|r| r.requires_fuzz).collect();
        assert!(
            !fuzz_rules.is_empty(),
            "Abi policy should have rules requiring fuzz infrastructure",
        );
    }

    #[test]
    fn host_policy_has_host_integration_rules() {
        let policy = default_policy(SubsystemClass::Host);
        let host_rules: Vec<_> = policy.rules.iter().filter(|r| r.requires_host).collect();
        assert!(
            !host_rules.is_empty(),
            "Host policy should have rules requiring host integration",
        );
    }

    #[test]
    fn subsystem_coverage_policy_categories_deduplicates() {
        let policy = default_policy(SubsystemClass::Host);
        let cats = policy.categories();
        let mut deduped = cats.clone();
        deduped.dedup();
        assert_eq!(cats.len(), deduped.len(), "categories() should return unique entries");
    }

    #[test]
    fn coverage_rule_debug_format() {
        let r = rule(
            SubsystemClass::Manifest,
            CoverageCategory::PropertyBased,
            "schema invariants",
            false,
            1,
            false,
            true,
        );
        let dbg = format!("{r:?}");
        assert!(dbg.contains("CoverageRule"));
        assert!(dbg.contains("Manifest"));
        assert!(dbg.contains("PropertyBased"));
    }

    #[test]
    fn subsystem_coverage_policy_debug_format() {
        let policy = default_policy(SubsystemClass::Provisioning);
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("SubsystemCoveragePolicy"));
        assert!(dbg.contains("Provisioning"));
    }

    #[test]
    fn validate_coverage_descriptions_include_subsystem_name() {
        let policy = default_policy(SubsystemClass::Placement);
        let missing = validate_coverage(&policy, &[]);
        for msg in &missing {
            assert!(
                msg.contains("Placement"),
                "Missing message should include subsystem name: {msg}",
            );
        }
    }

    #[test]
    fn kernel_does_not_require_host_integration() {
        assert!(!requires_host_integration(&SubsystemClass::Kernel));
    }

    #[test]
    fn provisioning_does_not_require_host_integration() {
        assert!(!requires_host_integration(&SubsystemClass::Provisioning));
    }

    #[test]
    fn manifest_does_not_require_fuzz_surface() {
        assert!(!requires_fuzz_surface(&SubsystemClass::Manifest));
    }

    #[test]
    fn placement_requires_failover() {
        let cats = minimum_credible_coverage(&SubsystemClass::Placement);
        assert!(
            cats.contains(&CoverageCategory::Failover),
            "Placement should require Failover coverage",
        );
    }
}
