#![allow(clippy::duplicate_mod)]

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";

include!("stream_mode_loopback_e2e.rs");

#[test]
fn local_non_mock_suite_class_is_declared() {
    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
}
