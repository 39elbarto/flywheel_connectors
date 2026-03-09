//! Interop test suite for FCP2 conformance.
//!
//! This module provides tests that verify interoperability between implementations.
//! Tests are designed to be deterministic and runnable without a real tailnet.
//!
//! # Test Categories
//!
//! ## Sessions / Handshake
//! - `MeshSessionHello`/`Ack` transcript verification
//! - `HelloRetry` cookie flow
//! - `TransportLimits` negotiation and enforcement
//!
//! ## FCPS Data Plane
//! - `FCPS_DATAGRAM` envelope MAC computation and verification
//! - Bounded replay window behavior
//! - MTU enforcement
//! - Per-symbol AEAD verification
//!
//! ## FCPC Control Plane
//! - Frame parsing and ordering
//! - Bounded replay window
//! - `k_ctx` AEAD integrity
//!
//! ## Capability Tokens
//! - `COSE_Sign1` encoding/verification
//! - `grant_object_ids` subset enforcement
//! - `chk_id`/`chk_seq` freshness binding
//! - `holder_node` + `holder_proof` verification
//!
//! ## Cross-Zone Enforcement
//! - Deny cross-zone operations without `ApprovalToken`
//! - Allow with correct `ApprovalToken` evidence
//! - `DecisionReceipt` `reason_code` stability

pub mod capability;
pub mod cross_zone;
pub mod fcpc;
pub mod fcps;
pub mod session;

// Re-export main test runner
pub use capability::CapabilityInteropTests;
pub use cross_zone::CrossZoneInteropTests;
pub use fcpc::FcpcInteropTests;
pub use fcps::FcpsInteropTests;
pub use session::SessionInteropTests;

/// Run all interop tests.
///
/// Returns a summary of passed/failed tests.
#[must_use]
pub fn run_all() -> InteropTestSummary {
    let mut summary = InteropTestSummary::default();

    // Session tests
    summary.merge(session::run_tests());

    // FCPS data plane tests
    summary.merge(fcps::run_tests());

    // FCPC control plane tests
    summary.merge(fcpc::run_tests());

    // Capability token tests
    summary.merge(capability::run_tests());

    // Cross-zone enforcement tests
    summary.merge(cross_zone::run_tests());

    summary
}

/// Summary of interop test results.
#[derive(Debug, Default, Clone)]
pub struct InteropTestSummary {
    /// Total tests run.
    pub total: usize,
    /// Tests that passed.
    pub passed: usize,
    /// Tests that failed.
    pub failed: usize,
    /// Test failures with descriptions.
    pub failures: Vec<TestFailure>,
}

impl InteropTestSummary {
    /// Merge another summary into this one.
    pub fn merge(&mut self, other: Self) {
        self.total += other.total;
        self.passed += other.passed;
        self.failed += other.failed;
        self.failures.extend(other.failures);
    }

    /// Check if all tests passed.
    #[must_use]
    pub const fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

/// A single test failure.
#[derive(Debug, Clone)]
pub struct TestFailure {
    /// Test name.
    pub name: String,
    /// Category (session, fcps, fcpc, capability, `cross_zone`).
    pub category: String,
    /// Error message.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interop_test_summary_default() {
        let summary = InteropTestSummary::default();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 0);
        assert!(summary.failures.is_empty());
        assert!(summary.all_passed());
    }

    #[test]
    fn interop_test_summary_all_passed_with_zero_failed() {
        let summary = InteropTestSummary {
            total: 10,
            passed: 10,
            failed: 0,
            failures: vec![],
        };
        assert!(summary.all_passed());
    }

    #[test]
    fn interop_test_summary_not_all_passed() {
        let summary = InteropTestSummary {
            total: 10,
            passed: 9,
            failed: 1,
            failures: vec![TestFailure {
                name: "test1".to_string(),
                category: "cat".to_string(),
                message: "fail".to_string(),
            }],
        };
        assert!(!summary.all_passed());
    }

    #[test]
    fn interop_test_summary_merge() {
        let mut a = InteropTestSummary {
            total: 5,
            passed: 4,
            failed: 1,
            failures: vec![TestFailure {
                name: "a1".to_string(),
                category: "cat-a".to_string(),
                message: "err-a".to_string(),
            }],
        };
        let b = InteropTestSummary {
            total: 3,
            passed: 2,
            failed: 1,
            failures: vec![TestFailure {
                name: "b1".to_string(),
                category: "cat-b".to_string(),
                message: "err-b".to_string(),
            }],
        };
        a.merge(b);
        assert_eq!(a.total, 8);
        assert_eq!(a.passed, 6);
        assert_eq!(a.failed, 2);
        assert_eq!(a.failures.len(), 2);
    }

    #[test]
    fn interop_test_summary_merge_empty() {
        let mut a = InteropTestSummary {
            total: 5,
            passed: 5,
            failed: 0,
            failures: vec![],
        };
        let b = InteropTestSummary::default();
        a.merge(b);
        assert_eq!(a.total, 5);
        assert!(a.all_passed());
    }

    #[test]
    fn interop_test_summary_clone() {
        let summary = InteropTestSummary {
            total: 3,
            passed: 2,
            failed: 1,
            failures: vec![TestFailure {
                name: "t".to_string(),
                category: "c".to_string(),
                message: "m".to_string(),
            }],
        };
        let moved = summary;
        assert_eq!(moved.total, 3);
        assert_eq!(moved.failures.len(), 1);
    }

    #[test]
    fn test_failure_debug() {
        let failure = TestFailure {
            name: "test_name".to_string(),
            category: "session".to_string(),
            message: "expected X got Y".to_string(),
        };
        let dbg = format!("{failure:?}");
        assert!(dbg.contains("test_name"));
        assert!(dbg.contains("session"));
    }

    #[test]
    fn test_failure_clone() {
        let failure = TestFailure {
            name: "f1".to_string(),
            category: "c1".to_string(),
            message: "m1".to_string(),
        };
        let moved = failure;
        assert_eq!(moved.name, "f1");
        assert_eq!(moved.category, "c1");
        assert_eq!(moved.message, "m1");
    }

    #[test]
    fn run_all_interop_tests_pass() {
        let summary = run_all();
        for failure in &summary.failures {
            eprintln!(
                "FAIL [{}]: {} - {}",
                failure.category, failure.name, failure.message
            );
        }
        assert!(
            summary.all_passed(),
            "All interop tests should pass: {}/{} passed",
            summary.passed,
            summary.total
        );
        // Should have tests from all 5 categories
        assert!(summary.total >= 36);
    }

    // ── InteropTestSummary additional tests ──

    #[test]
    fn interop_test_summary_merge_preserves_failures() {
        let mut a = InteropTestSummary {
            total: 2,
            passed: 1,
            failed: 1,
            failures: vec![TestFailure {
                name: "f1".to_string(),
                category: "c1".to_string(),
                message: "m1".to_string(),
            }],
        };
        let b = InteropTestSummary {
            total: 3,
            passed: 1,
            failed: 2,
            failures: vec![
                TestFailure {
                    name: "f2".to_string(),
                    category: "c2".to_string(),
                    message: "m2".to_string(),
                },
                TestFailure {
                    name: "f3".to_string(),
                    category: "c3".to_string(),
                    message: "m3".to_string(),
                },
            ],
        };
        a.merge(b);
        assert_eq!(a.total, 5);
        assert_eq!(a.passed, 2);
        assert_eq!(a.failed, 3);
        assert_eq!(a.failures.len(), 3);
        assert_eq!(a.failures[0].name, "f1");
        assert_eq!(a.failures[1].name, "f2");
        assert_eq!(a.failures[2].name, "f3");
    }

    #[test]
    fn interop_test_summary_all_passed_zero_total() {
        let summary = InteropTestSummary {
            total: 0,
            passed: 0,
            failed: 0,
            failures: vec![],
        };
        assert!(summary.all_passed());
    }

    #[test]
    fn interop_test_summary_debug_format() {
        let summary = InteropTestSummary {
            total: 5,
            passed: 3,
            failed: 2,
            failures: vec![],
        };
        let dbg = format!("{summary:?}");
        assert!(dbg.contains("InteropTestSummary"));
        assert!(dbg.contains('5'));
    }

    #[test]
    fn interop_test_summary_clone_deep() {
        let summary = InteropTestSummary {
            total: 7,
            passed: 6,
            failed: 1,
            failures: vec![TestFailure {
                name: "deep".to_string(),
                category: "cat".to_string(),
                message: "msg".to_string(),
            }],
        };
        let cloned = summary.clone();
        assert_eq!(summary.total, cloned.total);
        assert_eq!(summary.failures.len(), cloned.failures.len());
        assert_eq!(cloned.failures[0].name, "deep");
    }

    // ── TestFailure additional tests ──

    #[test]
    fn test_failure_clone_independence() {
        let f = TestFailure {
            name: "orig".to_string(),
            category: "cat".to_string(),
            message: "msg".to_string(),
        };
        let cloned = f.clone();
        assert_eq!(f.name, cloned.name);
        assert_eq!(f.category, cloned.category);
        assert_eq!(f.message, cloned.message);
    }

    #[test]
    fn test_failure_empty_fields() {
        let f = TestFailure {
            name: String::new(),
            category: String::new(),
            message: String::new(),
        };
        assert!(f.name.is_empty());
        let dbg = format!("{f:?}");
        assert!(dbg.contains("TestFailure"));
    }

    #[test]
    fn interop_test_summary_merge_two_empties() {
        let mut a = InteropTestSummary::default();
        let b = InteropTestSummary::default();
        a.merge(b);
        assert_eq!(a.total, 0);
        assert!(a.all_passed());
    }

    #[test]
    fn interop_test_summary_merge_chain() {
        let mut summary = InteropTestSummary::default();
        for i in 0..5 {
            summary.merge(InteropTestSummary {
                total: 1,
                passed: usize::from(i % 2 == 0),
                failed: usize::from(i % 2 != 0),
                failures: if i % 2 == 0 {
                    vec![]
                } else {
                    vec![TestFailure {
                        name: format!("test_{i}"),
                        category: "chain".to_string(),
                        message: "err".to_string(),
                    }]
                },
            });
        }
        assert_eq!(summary.total, 5);
        assert_eq!(summary.passed, 3);
        assert_eq!(summary.failed, 2);
        assert!(!summary.all_passed());
    }
}
