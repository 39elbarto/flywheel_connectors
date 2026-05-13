#![allow(clippy::duplicate_mod)]

const ACCEPTANCE_SUITE_CLASS: &str = "host_e2e";

include!("stdio_e2e.rs");

#[test]
fn subprocess_e2e_suite_class_is_declared() {
    assert_eq!(ACCEPTANCE_SUITE_CLASS, "host_e2e");
}
