//! Integration tests for `fcp new` command.
//!
//! Tests scaffold generation, safety guarantees, compliance checks, and output formats.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Get the `fcp` command for testing.
fn fcp_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fcp"));
    cmd.env("RUST_LOG", "error");
    cmd
}

/// Create a minimal workspace structure for scaffold tests.
fn create_workspace(tmp: &TempDir) {
    let workspace_cargo = r#"[workspace]
resolver = "2"
members = [
    "connectors/*",
]
"#;
    fs::write(tmp.path().join("Cargo.toml"), workspace_cargo).unwrap();
    fs::create_dir_all(tmp.path().join("connectors")).unwrap();
}

/// Create a minimal valid connector manifest for check tests.
fn minimal_valid_manifest(connector_id: &str, zone: &str) -> String {
    format!(
        r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "v2:00000000"

[connector]
id = "{connector_id}"
name = "Test Connector"
version = "0.1.0"
description = "Test connector"
archetypes = ["operational"]
format = "native"

[connector.state]
model = "stateless"
state_schema_version = "1"

[zones]
home = "{zone}"
allowed_sources = ["{zone}"]
allowed_targets = ["{zone}"]
forbidden = []

[capabilities]
required = []
forbidden = ["system.exec"]
optional = []

[provides]

[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 25
wall_clock_timeout_ms = 30000
fs_readonly_paths = []
fs_writable_paths = []
deny_exec = true
deny_ptrace = true
"#
    )
}

// ──────────────────────────────────────────────────────────────────────────────
// 1) Scaffold Creation Tests
// ──────────────────────────────────────────────────────────────────────────────

mod scaffold_creation {
    use super::*;

    #[test]
    fn creates_expected_directory_structure() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.testservice"])
            .assert()
            .success();

        let crate_dir = tmp.path().join("connectors/testservice");
        assert!(crate_dir.exists(), "connector crate directory should exist");
        assert!(
            crate_dir.join("Cargo.toml").exists(),
            "Cargo.toml should exist"
        );
        assert!(
            crate_dir.join("manifest.toml").exists(),
            "manifest.toml should exist"
        );
        assert!(
            crate_dir.join("src").is_dir(),
            "src/ directory should exist"
        );
        assert!(
            crate_dir.join("src/main.rs").exists(),
            "src/main.rs should exist"
        );
        assert!(
            crate_dir.join("src/lib.rs").exists(),
            "src/lib.rs should exist"
        );
        assert!(
            crate_dir.join("src/connector.rs").exists(),
            "src/connector.rs should exist"
        );
        assert!(
            crate_dir.join("src/limits.rs").exists(),
            "src/limits.rs should exist"
        );
        assert!(
            crate_dir.join("src/types.rs").exists(),
            "src/types.rs should exist"
        );
        assert!(
            crate_dir.join("tests").is_dir(),
            "tests/ directory should exist"
        );
    }

    #[test]
    fn generates_valid_manifest_with_single_zone_binding() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.singlezone", "--zone", "z:project:testapp"])
            .assert()
            .success();

        let manifest_path = tmp.path().join("connectors/singlezone/manifest.toml");
        let content = fs::read_to_string(&manifest_path).unwrap();

        // Verify single-zone binding: home == allowed_sources == allowed_targets
        assert!(
            content.contains("home = \"z:project:testapp\""),
            "manifest should have home zone binding"
        );
        assert!(
            content.contains("allowed_sources = [\"z:project:testapp\"]"),
            "manifest should have matching allowed_sources"
        );
        assert!(
            content.contains("allowed_targets = [\"z:project:testapp\"]"),
            "manifest should have matching allowed_targets"
        );
    }

    #[test]
    fn generates_manifest_with_default_deny_network_constraints() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.netdefaults"])
            .assert()
            .success();

        let manifest_path = tmp.path().join("connectors/netdefaults/manifest.toml");
        let content = fs::read_to_string(&manifest_path).unwrap();

        // Verify default-deny NetworkConstraints
        assert!(
            content.contains("deny_localhost = true"),
            "manifest should deny localhost"
        );
        assert!(
            content.contains("deny_private_ranges = true"),
            "manifest should deny private ranges"
        );
        assert!(
            content.contains("deny_tailnet_ranges = true"),
            "manifest should deny tailnet ranges"
        );
        assert!(
            content.contains("deny_ip_literals = true"),
            "manifest should deny IP literals"
        );
    }

    #[test]
    fn generated_manifest_has_no_secret_material() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.nosecrets"])
            .assert()
            .success();

        let manifest_path = tmp.path().join("connectors/nosecrets/manifest.toml");
        let content = fs::read_to_string(&manifest_path).unwrap();

        // No API keys, tokens, passwords, etc. in generated content
        let secret_patterns = [
            "api_key",
            "API_KEY",
            "secret_key",
            "SECRET_KEY",
            "password",
            "PASSWORD",
            "token = \"sk-",
            "Bearer ",
        ];
        for pattern in secret_patterns {
            assert!(
                !content.contains(pattern),
                "manifest should not contain secret pattern: {pattern}"
            );
        }
    }

    #[test]
    fn generated_limits_template_contains_placeholders() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.limits"])
            .assert()
            .success();

        let limits_path = tmp.path().join("connectors/limits/src/limits.rs");
        let content = fs::read_to_string(&limits_path).unwrap();

        assert!(
            content.contains("MAX_MESSAGE_CHARS"),
            "limits template should define MAX_MESSAGE_CHARS"
        );
        assert!(
            content.contains("MAX_PAYLOAD_BYTES"),
            "limits template should define MAX_PAYLOAD_BYTES"
        );
        assert!(
            content.contains("MAX_ATTACHMENT_BYTES"),
            "limits template should define MAX_ATTACHMENT_BYTES"
        );
    }

    #[test]
    fn generates_placeholder_operations() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.placeholders"])
            .assert()
            .success();

        let manifest_path = tmp.path().join("connectors/placeholders/manifest.toml");
        let content = fs::read_to_string(&manifest_path).unwrap();

        // Should have placeholder operation definitions
        assert!(
            content.contains("[provides.operations"),
            "manifest should have operations section"
        );
    }

    #[test]
    fn forbids_unsafe_code_in_generated_files() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.safecode"])
            .assert()
            .success();

        let main_rs =
            fs::read_to_string(tmp.path().join("connectors/safecode/src/main.rs")).unwrap();
        let lib_rs = fs::read_to_string(tmp.path().join("connectors/safecode/src/lib.rs")).unwrap();

        assert!(
            main_rs.contains("#![forbid(unsafe_code)]"),
            "main.rs should forbid unsafe code"
        );
        assert!(
            lib_rs.contains("#![forbid(unsafe_code)]"),
            "lib.rs should forbid unsafe code"
        );
    }

    #[test]
    fn all_archetypes_scaffold_successfully() {
        let archetypes = [
            "request-response",
            "streaming",
            "bidirectional",
            "polling",
            "webhook",
            "queue",
            "file",
            "database",
            "cli",
            "browser",
        ];

        for archetype in archetypes {
            let tmp = TempDir::new().unwrap();
            create_workspace(&tmp);

            let connector_id = format!("fcp.arch{}", archetype.replace('-', ""));

            fcp_cmd()
                .current_dir(tmp.path().join("connectors"))
                .args(["new", &connector_id, "--archetype", archetype])
                .assert()
                .success();
        }
    }

    #[test]
    fn no_e2e_flag_skips_e2e_test_file() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.noe2e", "--no-e2e"])
            .assert()
            .success();

        let e2e_test_path = tmp.path().join("connectors/noe2e/tests/e2e_tests.rs");
        assert!(
            !e2e_test_path.exists(),
            "E2E test file should not exist with --no-e2e"
        );
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 2) Safety / No-Overwrite Behavior Tests
// ──────────────────────────────────────────────────────────────────────────────

mod safety {
    use super::*;

    /// Tests that `fcp new` fails when the target directory already exists.
    /// This is desired safety behavior to prevent accidental overwrites.
    #[test]
    fn fails_when_target_directory_exists() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);
        let existing_dir = tmp.path().join("connectors/existing");
        fs::create_dir_all(&existing_dir).unwrap();
        fs::write(existing_dir.join("file.txt"), "existing content").unwrap();

        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.existing"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("already exists"));
    }

    /// Tests that existing files are preserved even if scaffold fails.
    /// This verifies no-delete behavior for safety.
    #[test]
    fn does_not_delete_files_on_failure() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);
        let existing_dir = tmp.path().join("connectors/protected");
        fs::create_dir_all(&existing_dir).unwrap();
        let protected_file = existing_dir.join("important.txt");
        fs::write(&protected_file, "critical data").unwrap();

        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.protected"])
            .assert()
            .failure();

        // Protected file should still exist
        assert!(
            protected_file.exists(),
            "existing file should not be deleted"
        );
        let content = fs::read_to_string(&protected_file).unwrap();
        assert_eq!(content, "critical data", "file content should be unchanged");
    }

    #[test]
    fn dry_run_does_not_write_files() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.drytest", "--dry-run"])
            .assert()
            .success()
            .stdout(predicate::str::contains("DRY RUN"));

        let crate_dir = tmp.path().join("connectors/drytest");
        assert!(
            !crate_dir.exists(),
            "directory should not be created in dry-run mode"
        );
    }

    #[test]
    fn dry_run_shows_intended_outputs() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.drypreview", "--dry-run"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Cargo.toml"))
            .stdout(predicate::str::contains("manifest.toml"))
            .stdout(predicate::str::contains("src/main.rs"));
    }

    /// Verifies that existing files are not destroyed when scaffold runs.
    #[test]
    fn existing_files_not_destroyed_when_scaffold_overwrites() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);
        let existing_dir = tmp.path().join("connectors/hasfiles");
        fs::create_dir_all(&existing_dir).unwrap();
        let custom_file = existing_dir.join("CUSTOM_FILE.txt");
        fs::write(&custom_file, "user-created content").unwrap();

        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.hasfiles"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("already exists"));

        assert!(custom_file.exists(), "custom file should be preserved");
        let content = fs::read_to_string(&custom_file).unwrap();
        assert_eq!(
            content, "user-created content",
            "content should be unchanged"
        );
        assert!(
            !existing_dir.join("Cargo.toml").exists(),
            "scaffold should not create new files when directory exists"
        );
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 3) --check Validation Tests
// ──────────────────────────────────────────────────────────────────────────────

mod check_validation {
    use super::*;

    #[test]
    fn detects_missing_manifest() {
        let tmp = TempDir::new().unwrap();
        let connector_dir = tmp.path().join("empty_connector");
        fs::create_dir_all(&connector_dir).unwrap();

        // Use --json to check for stable ID
        let output = fcp_cmd()
            .args(["new", "--check", connector_dir.to_str().unwrap(), "--json"])
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let checks = json["prechecks"]["checks"].as_array().unwrap();

        // Should have manifest.exists check that failed
        let manifest_check = checks
            .iter()
            .find(|c| c["id"].as_str() == Some("manifest.exists"))
            .expect("should have manifest.exists check");
        assert!(!manifest_check["passed"].as_bool().unwrap());
    }

    #[test]
    fn detects_malformed_manifest() {
        let tmp = TempDir::new().unwrap();
        let connector_dir = tmp.path().join("malformed");
        fs::create_dir_all(&connector_dir).unwrap();
        fs::write(
            connector_dir.join("manifest.toml"),
            "this is not valid { toml",
        )
        .unwrap();

        let output = fcp_cmd()
            .args(["new", "--check", connector_dir.to_str().unwrap(), "--json"])
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let checks = json["prechecks"]["checks"].as_array().unwrap();

        let manifest_check = checks
            .iter()
            .find(|c| c["id"].as_str() == Some("manifest.valid"))
            .expect("should have manifest.valid check");
        assert!(!manifest_check["passed"].as_bool().unwrap());
    }

    #[test]
    fn detects_missing_forbid_unsafe() {
        let tmp = TempDir::new().unwrap();
        let connector_dir = tmp.path().join("unsafe_connector");
        let src_dir = connector_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();

        // Create a minimal valid manifest with proper schema
        let manifest = minimal_valid_manifest("fcp.unsafetest", "z:project:test");
        fs::write(connector_dir.join("manifest.toml"), &manifest).unwrap();

        // Create main.rs and lib.rs without #![forbid(unsafe_code)]
        fs::write(src_dir.join("main.rs"), "fn main() {}").unwrap();
        fs::write(src_dir.join("lib.rs"), "// lib").unwrap();

        let output = fcp_cmd()
            .args(["new", "--check", connector_dir.to_str().unwrap(), "--json"])
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let checks = json["prechecks"]["checks"].as_array().unwrap();

        let unsafe_check = checks
            .iter()
            .find(|c| c["id"].as_str() == Some("code.forbid_unsafe"))
            .expect("should have code.forbid_unsafe check");
        assert!(!unsafe_check["passed"].as_bool().unwrap());
    }

    #[test]
    fn detects_missing_system_exec_forbidden() {
        let tmp = TempDir::new().unwrap();
        let connector_dir = tmp.path().join("exec_allowed");
        let src_dir = connector_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();

        // Create manifest without system.exec in forbidden list
        let manifest = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "v2:00000000"

[connector]
id = "fcp.exectest"
name = "Exec Test"
version = "0.1.0"
description = "Test connector"
archetypes = ["operational"]
format = "native"

[connector.state]
model = "stateless"
state_schema_version = "1"

[zones]
home = "z:project:test"
allowed_sources = ["z:project:test"]
allowed_targets = ["z:project:test"]
forbidden = []

[capabilities]
required = []
forbidden = []
optional = []

[provides]

[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 25
wall_clock_timeout_ms = 30000
fs_readonly_paths = []
fs_writable_paths = []
deny_exec = true
deny_ptrace = true
"#;
        fs::write(connector_dir.join("manifest.toml"), manifest).unwrap();
        fs::write(
            src_dir.join("main.rs"),
            "#![forbid(unsafe_code)]\nfn main() {}",
        )
        .unwrap();
        fs::write(src_dir.join("lib.rs"), "#![forbid(unsafe_code)]").unwrap();

        let output = fcp_cmd()
            .args(["new", "--check", connector_dir.to_str().unwrap(), "--json"])
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let checks = json["prechecks"]["checks"].as_array().unwrap();

        let exec_check = checks
            .iter()
            .find(|c| c["id"].as_str() == Some("manifest.forbidden_exec"))
            .expect("should have manifest.forbidden_exec check");
        assert!(!exec_check["passed"].as_bool().unwrap());
    }

    #[test]
    fn passes_for_compliant_connector() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        // First scaffold a compliant connector
        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.compliant"])
            .assert()
            .success();

        // Then check it passes validation
        let connector_dir = tmp.path().join("connectors/compliant");
        fcp_cmd()
            .args(["new", "--check", connector_dir.to_str().unwrap()])
            .assert()
            .success();
    }

    #[test]
    fn check_emits_stable_error_codes() {
        let tmp = TempDir::new().unwrap();
        let connector_dir = tmp.path().join("error_codes");
        fs::create_dir_all(&connector_dir).unwrap();

        let output = fcp_cmd()
            .args(["new", "--check", connector_dir.to_str().unwrap(), "--json"])
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let checks = json["prechecks"]["checks"].as_array().unwrap();

        // Verify stable error code format
        for check in checks {
            let id = check["id"].as_str().unwrap();
            // IDs should follow pattern: category.subcategory
            assert!(
                id.contains('.'),
                "check ID should follow category.subcategory format: {id}"
            );
        }
    }

    #[test]
    fn check_provides_suggested_fixes() {
        let tmp = TempDir::new().unwrap();
        let connector_dir = tmp.path().join("needs_fixes");
        fs::create_dir_all(&connector_dir).unwrap();

        let output = fcp_cmd()
            .args(["new", "--check", connector_dir.to_str().unwrap(), "--json"])
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();

        // Should have suggested fixes for failed checks
        assert!(
            json["suggested_fixes"].is_array(),
            "should have suggested_fixes array"
        );
    }

    #[test]
    fn check_fails_on_nonexistent_path() {
        fcp_cmd()
            .args(["new", "--check", "/nonexistent/path/to/connector"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("does not exist"));
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 4) Output + Logging Tests
// ──────────────────────────────────────────────────────────────────────────────

mod output_logging {
    use super::*;

    #[test]
    fn json_output_has_stable_schema() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        let output = fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.jsontest", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();

        // Verify required fields in ScaffoldResult
        assert!(json["connector_id"].is_string());
        assert!(json["crate_path"].is_string());
        assert!(json["files_created"].is_array());
        assert!(json["prechecks"].is_object());
        assert!(json["next_steps"].is_array());

        // Verify prechecks structure
        assert!(json["prechecks"]["passed"].is_boolean());
        assert!(json["prechecks"]["checks"].is_array());
        assert!(json["prechecks"]["summary"].is_object());
    }

    #[test]
    fn json_output_files_have_expected_fields() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        let output = fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.filefields", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let files = json["files_created"].as_array().unwrap();

        assert!(!files.is_empty(), "should have created files");
        for file in files {
            assert!(file["path"].is_string(), "file should have path");
            assert!(file["purpose"].is_string(), "file should have purpose");
            assert!(file["size"].is_number(), "file should have size");
        }
    }

    #[test]
    fn check_json_output_has_stable_schema() {
        let tmp = TempDir::new().unwrap();
        let connector_dir = tmp.path().join("checkjson");
        fs::create_dir_all(&connector_dir).unwrap();

        let output = fcp_cmd()
            .args(["new", "--check", connector_dir.to_str().unwrap(), "--json"])
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();

        // Verify CheckResult structure
        assert!(json["path"].is_string());
        assert!(json["prechecks"].is_object());
        assert!(json["suggested_fixes"].is_array());

        // connector_id may be null if manifest couldn't be parsed
        assert!(json["connector_id"].is_null() || json["connector_id"].is_string());
    }

    #[test]
    fn json_output_does_not_contain_secrets() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        let output = fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.nosecretjson", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let output_str = String::from_utf8(output).unwrap();

        let secret_patterns = [
            "sk-",
            "api_key",
            "secret_key",
            "password",
            "Bearer ",
            "AWS_SECRET",
        ];
        for pattern in secret_patterns {
            assert!(
                !output_str.to_lowercase().contains(&pattern.to_lowercase()),
                "JSON output should not contain secret pattern: {pattern}"
            );
        }
    }

    #[test]
    fn prechecks_summary_counts_are_correct() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        let output = fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.summarytest", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let checks = json["prechecks"]["checks"].as_array().unwrap();
        let summary = &json["prechecks"]["summary"];

        #[allow(clippy::cast_possible_truncation)] // Test values fit in usize
        let total = summary["total"].as_u64().unwrap() as usize;
        #[allow(clippy::cast_possible_truncation)]
        let passed = summary["passed"].as_u64().unwrap() as usize;

        assert_eq!(total, checks.len(), "total should match checks count");

        let actual_passed = checks
            .iter()
            .filter(|c| c["passed"].as_bool().unwrap())
            .count();
        assert_eq!(passed, actual_passed, "passed count should match");
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 5) Connector ID Validation Tests
// ──────────────────────────────────────────────────────────────────────────────

mod connector_id_validation {
    use super::*;

    #[test]
    fn rejects_id_without_fcp_prefix() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);
        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "myservice"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("fcp."));
    }

    #[test]
    fn rejects_empty_name_after_prefix() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);
        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp."])
            .assert()
            .failure();
    }

    #[test]
    fn rejects_consecutive_dots() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);
        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp..service"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("consecutive dots"));
    }

    #[test]
    fn accepts_nested_connector_id() {
        let tmp = TempDir::new().unwrap();
        create_workspace(&tmp);

        fcp_cmd()
            .current_dir(tmp.path().join("connectors"))
            .args(["new", "fcp.company.product.feature"])
            .assert()
            .success();
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 6) Help and Usage Tests
// ──────────────────────────────────────────────────────────────────────────────

mod help_usage {
    use super::*;

    #[test]
    fn help_shows_all_options() {
        fcp_cmd()
            .args(["new", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--archetype"))
            .stdout(predicate::str::contains("--zone"))
            .stdout(predicate::str::contains("--dry-run"))
            .stdout(predicate::str::contains("--check"))
            .stdout(predicate::str::contains("--json"))
            .stdout(predicate::str::contains("--no-e2e"));
    }

    #[test]
    fn help_lists_archetypes() {
        fcp_cmd()
            .args(["new", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("request-response"))
            .stdout(predicate::str::contains("streaming"));
    }

    #[test]
    fn requires_connector_id_without_check() {
        fcp_cmd().args(["new"]).assert().failure();
    }
}
