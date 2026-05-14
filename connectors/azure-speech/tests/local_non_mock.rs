#![forbid(unsafe_code)]

#[path = "loopback.rs"]
mod loopback;

#[test]
fn azure_speech_local_non_mock_suite_class_marker() {
    const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
}
