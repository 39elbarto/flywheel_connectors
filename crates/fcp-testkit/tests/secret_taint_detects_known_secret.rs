use fcp_testkit::secret_taint::SecretTaintTracker;
use serde_json::json;

#[test]
fn test_taint_tracker_detects_registered_secret() {
    let mut tracker = SecretTaintTracker::new();
    let secret = "sk-test-secret-material-123";
    assert!(tracker.register_secret("provider_api_key", secret));

    let alert = tracker
        .scan_json(&json!({
            "message": "request failed",
            "authorization": format!("Bearer {secret}")
        }))
        .expect("registered secret should be detected");

    assert_eq!(alert.label, "provider_api_key");
    assert_eq!(alert.secret_len, secret.len());
    assert!(alert.offset > 0);
    assert!(!alert.secret_fingerprint.is_empty());
    assert!(!format!("{alert:?}").contains(secret));
}

#[test]
fn test_taint_tracker_does_not_false_positive_on_random() {
    let mut tracker = SecretTaintTracker::new();
    assert!(tracker.register_secret("provider_api_key", "sk-test-secret-material-123"));

    let report = tracker.scan_str("request_id=3df1a7 status=429 token_count=128 retryable=true");

    assert!(report.is_none());
}
