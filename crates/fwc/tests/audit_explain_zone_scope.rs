//! Golden-vector CLI coverage for `fwc audit explain --zone --since`.

use std::process::{Command, Output};

fn run_fwc(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fwc"))
        .args(args)
        .output()
        .expect("fwc process should launch")
}

#[test]
fn test_golden_zone_work_24h_output_exact() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/audit_chain/canned_5zone.json"
    );
    let golden = include_str!("fixtures/audit_chain/golden_zone_work_24h.txt");

    let output = run_fwc(&[
        "audit", "explain", fixture, "--zone", "z:work", "--since", "24h", "--json",
    ]);

    assert!(
        output.status.success(),
        "fwc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert_eq!(stdout.trim_end(), golden.trim_end());
}
