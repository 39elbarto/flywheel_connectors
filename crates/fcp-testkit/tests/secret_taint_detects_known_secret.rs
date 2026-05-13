use fcp_testkit::SecretTaintTracker;

#[test]
fn test_taint_tracker_detects_registered_secret() {
    let mut tracker = SecretTaintTracker::new();
    assert!(tracker.register_secret("provider_api_key", b"sk-test-secret-value"));

    let alert = tracker
        .scan_str("provider returned sk-test-secret-value in an error")
        .expect("registered secret should be detected");

    assert_eq!(alert.label, "provider_api_key");
    assert_eq!(alert.secret_len, "sk-test-secret-value".len());
    assert_eq!(alert.offset, "provider returned ".len());
    assert!(!alert.secret_fingerprint.contains("sk-test-secret-value"));
}

#[test]
fn test_taint_tracker_does_not_false_positive_on_random() {
    let mut tracker = SecretTaintTracker::new();
    assert!(tracker.register_secret("provider_api_key", b"sk-test-secret-value"));

    assert!(
        tracker
            .scan_str("provider returned a normal structured error")
            .is_none()
    );
    assert_eq!(tracker.registered_count(), 1);
}
