#![forbid(unsafe_code)]

#[path = "setup_readiness_e2e.rs"]
mod setup_readiness_e2e;

#[test]
fn nextcloud_talk_local_non_mock_suite_class_marker() {
    const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
}
