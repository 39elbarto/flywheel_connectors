use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("fwc crate should live under the workspace root")
        .to_path_buf()
}

fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(relative)
}

fn run_fwc(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fwc"))
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("fwc process should launch")
}

fn run_json(args: &[&str]) -> (i32, Value, String) {
    let output = run_fwc(args);
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be valid UTF-8");
    let payload = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!(
            "expected JSON output for {:?}: {error}\nstdout:\n{}\nstderr:\n{}",
            args, stdout, stderr
        )
    });
    (code, payload, stderr)
}

fn run_json_ok(args: &[&str]) -> Value {
    let (code, payload, stderr) = run_json(args);
    assert_eq!(code, 0, "expected success for {args:?}, stderr:\n{stderr}");
    payload
}

fn run_text_ok(args: &[&str]) -> String {
    let output = run_fwc(args);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be valid UTF-8");
    assert!(
        output.status.success(),
        "expected success for {args:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    stdout
}

#[test]
fn discovery_to_template_to_validate_offline_workflow() {
    // Setup.
    let valid_input = fixture_path("operation_inputs/valid_create_issue.json");
    let invalid_input = fixture_path("operation_inputs/invalid_create_issue.json");

    // Act: search for the operation through the real CLI.
    let search = run_json_ok(&["--json", "search", "github issue", "--offline"]);

    // Assert: discovery surfaces the expected operation.
    assert_eq!(search["command"], "search");
    assert_eq!(search["mode"], "offline-artifact");
    assert!(search["results"].as_array().is_some_and(|results| {
        results.iter().any(|result| {
            result["connector"] == "github" && result["operation"] == "github.create_issue"
        })
    }));

    // Act: inspect the schema and request template for the discovered operation.
    let schema = run_json_ok(&["--json", "schema", "github", "issues.create", "--offline"]);
    let template = run_json_ok(&[
        "--json",
        "scaffold",
        "github",
        "issues.create",
        "--offline",
        "--required-only",
    ]);

    // Assert: schema and template agree on the same operation contract.
    assert_eq!(schema["operation"]["canonical_id"], "github.create_issue");
    assert_eq!(
        schema["input_schema"]["properties"]["title"]["type"],
        "string"
    );
    assert_eq!(template["operation"]["canonical_id"], "github.create_issue");
    assert_eq!(template["required_only"], true);
    assert_eq!(template["template"]["title"], "<string:required>");
    assert!(template["template"].get("body").is_none());

    // Act: validate a good and a bad payload from the shared fixture corpus.
    let valid = run_json_ok(&[
        "--json",
        "validate",
        "github",
        "issues.create",
        "--offline",
        "--input-file",
        valid_input
            .to_str()
            .expect("valid fixture path should be UTF-8"),
    ]);
    let (invalid_code, invalid, invalid_stderr) = run_json(&[
        "--json",
        "validate",
        "github",
        "issues.create",
        "--offline",
        "--input-file",
        invalid_input
            .to_str()
            .expect("invalid fixture path should be UTF-8"),
    ]);

    // Assert: validation succeeds for the valid fixture and returns actionable errors for the invalid one.
    assert_eq!(valid["valid"], true);
    assert_eq!(valid["mode"], "offline-artifact");
    assert_ne!(
        invalid_code, 0,
        "invalid validation should fail, stderr:\n{invalid_stderr}"
    );
    assert_eq!(invalid["valid"], false);
    assert_eq!(invalid["error_count"], 1);
    assert_eq!(invalid["errors"][0]["path"], "title");
    assert!(
        invalid["errors"][0]["message"]
            .as_str()
            .is_some_and(|message| message.contains("required field missing"))
    );
    assert!(
        invalid["errors"][0]["suggestion"]
            .as_str()
            .is_some_and(|suggestion| suggestion.contains("title"))
    );
}

#[test]
fn recipe_export_then_pipeline_validate_and_estimate_workflow() {
    // Setup.
    let recipe_show = run_json_ok(&["--json", "recipe", "show", "github-pr-review-notify"]);
    let recipe_export = run_json_ok(&["--json", "recipe", "export", "github-pr-review-notify"]);
    let temp_dir = tempdir().expect("temp dir should be created");
    let pipeline_path = temp_dir.path().join("github-pr-review-notify.toml");
    let exported_toml = recipe_export
        .as_str()
        .expect("recipe export should be encoded as a JSON string");
    std::fs::write(&pipeline_path, exported_toml).expect("exported recipe should be written");
    let pipeline_path_str = pipeline_path
        .to_str()
        .expect("pipeline path should be valid UTF-8");

    // Act: validate and estimate the exported recipe as a standalone pipeline.
    let validation = run_json_ok(&["--json", "pipeline", "validate", pipeline_path_str]);
    let estimate = run_json_ok(&["--json", "pipeline", "estimate", pipeline_path_str]);

    // Assert: recipe metadata, exported TOML, and pipeline planning stay aligned.
    assert_eq!(recipe_show["recipe"]["slug"], "github-pr-review-notify");
    assert_eq!(
        recipe_show["definition"]["pipeline"]["name"],
        "github-pr-review-notify"
    );
    assert!(exported_toml.starts_with("[pipeline]"));
    assert!(exported_toml.contains("name = \"github-pr-review-notify\""));
    assert_eq!(validation["command"], "pipeline");
    assert_eq!(validation["subcommand"], "validate");
    assert_eq!(validation["validation"]["valid"], true);
    assert!(
        validation["validation"]["execution_order"]
            .as_array()
            .is_some_and(|order| !order.is_empty())
    );
    assert_eq!(estimate["command"], "pipeline");
    assert_eq!(estimate["subcommand"], "estimate");
    assert_eq!(
        estimate["estimate"]["step_count"],
        recipe_show["estimate"]["step_count"]
    );
    assert!(
        estimate["estimate"]["estimated_api_calls"]["summary"]
            .as_str()
            .is_some_and(|summary| summary.starts_with('~'))
    );
}

#[test]
fn output_rendering_stays_composable_over_offline_views() {
    // Setup + Act: render a connector detail view through the global Handlebars output layer.
    let show_text = run_text_ok(&[
        "--template",
        "{{connector.slug}} => {{connector.state}}",
        "show",
        "github",
        "--offline",
    ]);

    // Assert: the rendered connector detail preserves the underlying offline manifest truth.
    assert_eq!(show_text.trim(), "github => unknown");

    // Act: render the resolved canonical operation id from the schema command through the same layer.
    let schema_text = run_text_ok(&[
        "--template",
        "{{operation.canonical_id}}",
        "schema",
        "github",
        "issues.create",
        "--offline",
    ]);

    // Assert: output templating composes with schema resolution as well.
    assert_eq!(schema_text.trim(), "github.create_issue");
}
