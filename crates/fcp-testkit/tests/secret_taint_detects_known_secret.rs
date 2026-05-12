use fcp_testkit::secret_taint::SecretTaintTracker;
use serde_json::json;

#[test]
fn test_taint_tracker_detects_registered_secret() {
    let mut tracker = SecretTaintTracker::new();
    let secret = "sk-test-secret-material-123";
    let handle = tracker
        .register_secret("provider_api_key", secret)
        .expect("secret registration should work");

    let report = tracker.scan_json(
        "connector.log",
        &json!({
            "message": "request failed",
            "authorization": format!("Bearer {secret}")
        }),
    );

    assert!(report.has_leaks());
    assert_eq!(report.leak_count, 1);
    assert_eq!(report.leaks[0].secret_id, handle.id);
    assert_eq!(report.leaks[0].label_hash, handle.label_hash);
    assert!(!format!("{report:?}").contains(secret));
}

#[test]
fn test_taint_tracker_does_not_false_positive_on_random() {
    let mut tracker = SecretTaintTracker::new();
    tracker
        .register_secret("provider_api_key", "sk-test-secret-material-123")
        .expect("secret registration should work");

    let report = tracker.scan_text(
        "connector.log",
        "request_id=3df1a7 status=429 token_count=128 retryable=true",
    );

    assert!(!report.has_leaks());
    assert_eq!(report.leak_count, 0);
    assert!(report.leaks.is_empty());
}
