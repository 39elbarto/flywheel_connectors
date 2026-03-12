use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use fcp_core::{CapabilityToken, ConnectorHealth, InvokeResponse, RequestId};
use fcp_host::PreflightResponse as HostPreflightResponse;
use serde_json::{Value, json};
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

fn run_fwc_in_home(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fwc"))
        .args(args)
        .env("HOME", home)
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
        panic!("expected JSON output for {args:?}: {error}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (code, payload, stderr)
}

fn run_json_ok(args: &[&str]) -> Value {
    let (code, payload, stderr) = run_json(args);
    assert_eq!(code, 0, "expected success for {args:?}, stderr:\n{stderr}");
    payload
}

fn run_json_in_home(home: &Path, args: &[&str]) -> (i32, Value, String) {
    let output = run_fwc_in_home(home, args);
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be valid UTF-8");
    let payload = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!("expected JSON output for {args:?}: {error}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (code, payload, stderr)
}

fn run_json_ok_in_home(home: &Path, args: &[&str]) -> Value {
    let (code, payload, stderr) = run_json_in_home(home, args);
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

fn spawn_mock_host_sequence(routes: Vec<(String, Value)>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock host should bind");
    listener
        .set_nonblocking(true)
        .expect("mock host should configure nonblocking accept");
    let endpoint = format!(
        "http://{}",
        listener.local_addr().expect("mock host address")
    );
    let expected_requests = routes.len();
    let responses = routes
        .into_iter()
        .map(|(key, value)| {
            (
                key,
                serde_json::to_string(&value).expect("mock response should serialize"),
            )
        })
        .collect::<Vec<_>>();

    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut served = 0usize;

        while served < expected_requests && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("mock host accept failed: {error}"),
            };

            stream
                .set_nonblocking(false)
                .expect("mock host stream should switch back to blocking mode");

            let mut reader =
                BufReader::new(stream.try_clone().expect("mock host should clone socket"));
            let mut request_line = String::new();
            reader
                .read_line(&mut request_line)
                .expect("mock host should read request line");
            assert!(
                !request_line.trim().is_empty(),
                "mock host received an empty request line"
            );

            let mut content_length = 0usize;
            loop {
                let mut header = String::new();
                reader
                    .read_line(&mut header)
                    .expect("mock host should read headers");
                if header == "\r\n" || header.is_empty() {
                    break;
                }
                if let Some((name, value)) = header.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    content_length = value
                        .trim()
                        .parse()
                        .expect("content-length should be numeric");
                }
            }

            if content_length > 0 {
                let mut body = vec![0u8; content_length];
                reader
                    .read_exact(&mut body)
                    .expect("mock host should read request body");
            }

            let mut parts = request_line.split_whitespace();
            let method = parts.next().expect("request method should exist");
            let path = parts.next().expect("request path should exist");
            let key = format!("{method} {path}");
            let Some((expected_key, body)) = responses.get(served) else {
                panic!("missing expected mock response for request {}", served + 1);
            };
            assert_eq!(
                &key,
                expected_key,
                "unexpected mock host request order at position {}",
                served + 1
            );

            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("mock host should write response");
            stream.flush().expect("mock host should flush response");
            served += 1;
        }

        assert_eq!(
            served, expected_requests,
            "mock host served {served} request(s), expected {expected_requests}"
        );
    });

    (endpoint, handle)
}

fn mock_connector_summary_json(
    id: &str,
    name: &str,
    tool_count: usize,
    max_safety_tier: &str,
) -> Value {
    let health = serde_json::to_value(ConnectorHealth::healthy()).expect("health should serialize");
    json!({
        "id": id,
        "name": name,
        "description": format!("{name} connector surfaced through fcp-host."),
        "version": "1.2.3",
        "categories": ["code", "dev-tools"],
        "tool_count": tool_count,
        "max_safety_tier": max_safety_tier,
        "enabled": true,
        "health": health,
        "last_health_check": "2026-03-10T00:00:00Z",
    })
}

fn mock_discovery_response_json(connectors: &[Value]) -> Value {
    json!({
        "connectors": connectors,
        "registry_version": 7,
        "supports_streaming": true,
        "supports_batching": true,
        "timestamp": "2026-03-10T00:00:00Z"
    })
}

fn mock_introspection_response_json(connector: &Value, tools: &[Value]) -> Value {
    json!({
        "connector": connector,
        "tools": tools,
        "rate_limits": {
            "limits": [],
            "tool_pool_map": BTreeMap::<String, Value>::new()
        },
        "archetype": "request_response",
        "introspection": {
            "operations": [],
            "events": [],
            "resource_types": [],
            "auth_caps": null,
            "event_caps": null
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn mock_tool_descriptor_json(
    name: &str,
    capability: &str,
    risk_level: &str,
    safety_tier: &str,
    idempotency: &str,
    approval_mode: Option<&str>,
    input_schema: &Value,
    output_schema: &Value,
) -> Value {
    json!({
        "name": name,
        "description": format!("Mock descriptor for {name}."),
        "input_schema": input_schema,
        "output_schema": output_schema,
        "capability": capability,
        "risk_level": risk_level,
        "safety_tier": safety_tier,
        "idempotency": idempotency,
        "approval_mode": approval_mode,
        "requires_confirmation": approval_mode.is_some(),
        "idempotent": matches!(idempotency, "strict" | "best_effort"),
        "supports_simulate": true,
    })
}

fn mock_preflight_response_json(allowed: bool) -> Value {
    serde_json::to_value(if allowed {
        HostPreflightResponse::allowed()
    } else {
        HostPreflightResponse::denied("connector policy denied the request")
    })
    .expect("preflight response should serialize")
}

fn mock_invoke_response_json(result: Value) -> Value {
    serde_json::to_value(InvokeResponse::ok(RequestId::random(), result))
        .expect("invoke response should serialize")
}

fn test_capability_token_arg() -> String {
    let token = CapabilityToken::test_token();
    base64::engine::general_purpose::STANDARD
        .encode(token.raw.to_cbor().expect("test token should encode"))
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
    let exported_toml = recipe_export["content"]
        .as_str()
        .expect("recipe export should include TOML content");
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
    assert_eq!(recipe_export["command"], "recipe");
    assert_eq!(recipe_export["subcommand"], "export");
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

#[allow(clippy::too_many_lines)]
#[test]
fn batch_file_dry_run_uses_shared_fixture_with_live_preflight_plan() {
    let capability_token = test_capability_token_arg();
    let batch_path = fixture_path("batch/dependent_batch.jsonl");
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 2, "risky");
    let slack_connector =
        mock_connector_summary_json("fcp.slack:team:v1", "Slack Team", 1, "risky");
    let github_create_issue = mock_tool_descriptor_json(
        "github.create_issue",
        "github.issue_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" },
                "body": { "type": "string" }
            },
            "required": ["owner", "repo", "title"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "number": { "type": "integer" }
            },
            "required": ["number"]
        }),
    );
    let github_add_comment = mock_tool_descriptor_json(
        "github.add_comment",
        "github.comment_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "number": { "type": "integer" },
                "body": { "type": "string" }
            },
            "required": ["owner", "repo", "number", "body"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" }
            }
        }),
    );
    let slack_send_message = mock_tool_descriptor_json(
        "slack.send_message",
        "slack.post_message",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "channel": { "type": "string" },
                "text": { "type": "string" }
            },
            "required": ["channel", "text"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" }
            }
        }),
    );
    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(&[github_connector.clone(), slack_connector.clone()]),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(
                &github_connector,
                &[github_create_issue, github_add_comment],
            ),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
        (
            "GET /rpc/introspect/fcp.slack:team:v1".to_owned(),
            mock_introspection_response_json(&slack_connector, &[slack_send_message]),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
    ]);

    let payload = run_json_ok(&[
        "--json",
        "--host",
        &host,
        "batch-file",
        batch_path
            .to_str()
            .expect("batch fixture path should be valid UTF-8"),
        "--dry-run",
        "--capability-token",
        &capability_token,
    ]);

    server.join().expect("mock host thread should complete");
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["command"], "batch-file");
    assert_eq!(payload["source"], "host-admin-api");
    assert_eq!(payload["dry_run"], true);
    assert_eq!(payload["plan"]["total_operations"], 3);
    assert_eq!(payload["plan"]["waves"].as_array().unwrap().len(), 3);
    assert_eq!(payload["plan"]["connectors"].as_array().unwrap().len(), 2);
    let preflights = payload["preflights"]
        .as_array()
        .expect("preflight results should be present");
    assert_eq!(preflights.len(), 3);
    assert_eq!(preflights[0]["id"], "create-issue");
    assert_eq!(preflights[0]["connector"], "github");
    assert_eq!(preflights[0]["operation"], "github.create_issue");
    assert_eq!(preflights[0]["allowed"], true);
    assert_eq!(preflights[1]["id"], "comment");
    assert_eq!(preflights[1]["connector"], "github");
    assert_eq!(preflights[1]["operation"], "github.add_comment");
    assert_eq!(preflights[1]["allowed"], true);
    assert_eq!(preflights[2]["id"], "announce");
    assert_eq!(preflights[2]["connector"], "slack");
    assert_eq!(preflights[2]["operation"], "slack.send_message");
    assert_eq!(preflights[2]["allowed"], true);
}

#[allow(clippy::too_many_lines)]
#[test]
fn pipeline_dry_run_records_history_entries_for_shared_fixture_workflow() {
    let capability_token = test_capability_token_arg();
    let home = tempdir().expect("temp home should be created");
    let pipeline_path = fixture_path("pipelines/simple_pipe.toml");
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "safe");
    let slack_connector =
        mock_connector_summary_json("fcp.slack:team:v1", "Slack Team", 1, "risky");
    let github_list_issues = mock_tool_descriptor_json(
        "github.list_issues",
        "github.issue_read",
        "low",
        "safe",
        "strict",
        None,
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" }
            },
            "required": ["owner", "repo"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "issues": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": { "type": "string" }
                        }
                    }
                }
            }
        }),
    );
    let slack_send_message = mock_tool_descriptor_json(
        "slack.send_message",
        "slack.post_message",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "channel": { "type": "string" },
                "text": { "type": "string" }
            },
            "required": ["channel", "text"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" }
            }
        }),
    );
    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(&[github_connector.clone(), slack_connector.clone()]),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(&github_connector, &[github_list_issues]),
        ),
        (
            "GET /rpc/introspect/fcp.slack:team:v1".to_owned(),
            mock_introspection_response_json(&slack_connector, &[slack_send_message]),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
        (
            "POST /rpc/invoke".to_owned(),
            mock_invoke_response_json(json!({
                "issues": [
                    { "title": "Bug report" }
                ]
            })),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
    ]);

    let payload = run_json_ok_in_home(
        home.path(),
        &[
            "--json",
            "--host",
            &host,
            "pipeline",
            "dry-run",
            pipeline_path
                .to_str()
                .expect("pipeline fixture path should be valid UTF-8"),
            "--capability-token",
            &capability_token,
            "--param",
            "owner=octocat",
            "--param",
            "repo=hello-world",
        ],
    );

    server.join().expect("mock host thread should complete");
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["command"], "pipeline");
    assert_eq!(payload["subcommand"], "dry-run");
    assert_eq!(payload["source"], "host-admin-api");
    assert_eq!(payload["execution"]["executed_steps"], 1);
    assert_eq!(payload["execution"]["preflight_only_steps"], 1);
    assert_eq!(
        payload["execution"]["outputs"]["fetch"]["issues"][0]["title"],
        "Bug report"
    );
    let steps = payload["execution"]["steps"]
        .as_array()
        .expect("execution steps should be present");
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0]["id"], "fetch");
    assert_eq!(steps[0]["mode"], "dry-run-read");
    assert_eq!(steps[1]["id"], "notify");
    assert_eq!(steps[1]["mode"], "preflight");
    assert_eq!(steps[1]["input"]["channel"], "#eng-alerts");
    assert_eq!(
        steps[1]["input"]["text"],
        "Open issues loaded for hello-world"
    );

    let history = run_json_ok_in_home(home.path(), &["--json", "history"]);
    assert_eq!(history["command"], "history");
    assert_eq!(history["scope"], "list");
    assert_eq!(history["total_entries"], 2);
    assert_eq!(history["returned"], 2);
    let entries = history["entries"]
        .as_array()
        .expect("history entries should be present");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["status"], "simulated");
    assert_eq!(entries[0]["connector_id"], "fcp.slack:team:v1");
    assert_eq!(entries[0]["operation_id"], "slack.send_message");
    assert_eq!(entries[1]["status"], "success");
    assert_eq!(entries[1]["connector_id"], "fcp.github:enterprise:v1");
    assert_eq!(entries[1]["operation_id"], "github.list_issues");

    let github_history = run_json_ok_in_home(
        home.path(),
        &[
            "--json",
            "history",
            "--connector",
            "github",
            "--status",
            "success",
        ],
    );
    assert_eq!(github_history["returned"], 1);
    assert_eq!(
        github_history["entries"][0]["connector_id"],
        "fcp.github:enterprise:v1"
    );
    assert_eq!(
        github_history["entries"][0]["operation_id"],
        "github.list_issues"
    );
    assert_eq!(github_history["entries"][0]["status"], "success");
}

#[test]
fn invoke_denial_records_history_and_suggests_recovery_actions() {
    let capability_token = test_capability_token_arg();
    let home = tempdir().expect("temp home should be created");
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "risky");
    let github_create_issue = mock_tool_descriptor_json(
        "github.create_issue",
        "github.issue_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" },
                "body": { "type": "string" }
            },
            "required": ["owner", "repo", "title"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "number": { "type": "integer" }
            },
            "required": ["number"]
        }),
    );
    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(&[github_connector.clone()]),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(&github_connector, &[github_create_issue]),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(false),
        ),
    ]);

    let (exit_code, payload, stderr) = run_json_in_home(
        home.path(),
        &[
            "--json",
            "--host",
            &host,
            "invoke",
            "github",
            "issues.create",
            "--input",
            "{\"owner\":\"octocat\",\"repo\":\"hello-world\",\"title\":\"Denied issue\"}",
            "--capability-token",
            &capability_token,
        ],
    );

    server.join().expect("mock host thread should complete");
    assert_ne!(
        exit_code, 0,
        "denied invoke should not report success, stderr:\n{stderr}"
    );
    assert_eq!(payload["command"], "invoke");
    assert_eq!(payload["status"], "denied");
    assert_eq!(payload["phase"], "preflight");
    assert_eq!(payload["error"]["type"], "policy-denied");
    assert_eq!(payload["preflight"]["allowed"], false);
    assert_eq!(
        payload["preflight"]["reason"],
        "connector policy denied the request"
    );
    let next_actions = payload["next_actions"]
        .as_array()
        .expect("denied invoke should include recovery actions");
    assert!(next_actions.iter().any(|action| {
        action
            .as_str()
            .is_some_and(|value| value.contains("fwc status github --host"))
    }));
    assert!(next_actions.iter().any(|action| {
        action
            .as_str()
            .is_some_and(|value| value.contains("fwc simulate github issues.create --host"))
    }));

    let history = run_json_ok_in_home(home.path(), &["--json", "history", "--status", "denied"]);
    assert_eq!(history["command"], "history");
    assert_eq!(history["scope"], "list");
    assert_eq!(history["returned"], 1);
    assert_eq!(history["entries"][0]["connector_id"], "fcp.github:enterprise:v1");
    assert_eq!(history["entries"][0]["operation_id"], "github.create_issue");
    assert_eq!(history["entries"][0]["status"], "denied");
    assert_eq!(
        history["entries"][0]["error_code"],
        "connector policy denied the request"
    );
}

#[allow(clippy::too_many_lines)]
#[test]
fn session_pipeline_history_workflow_persists_agent_context() {
    let capability_token = test_capability_token_arg();
    let home = tempdir().expect("temp home should be created");
    let pipeline_path = fixture_path("pipelines/simple_pipe.toml");

    let session_start = run_json_ok_in_home(
        home.path(),
        &[
            "--json",
            "session",
            "start",
            "--agent",
            "OrangeSummit",
            "--goal",
            "exercise cross-module integration coverage",
            "--zone",
            "z:work",
            "--context",
            "bead=\"flywheel_connectors-qnchs.15.2\"",
        ],
    );
    let session_id = session_start["session"]["id"]
        .as_str()
        .expect("session id should be present")
        .to_owned();
    assert_eq!(session_start["session"]["agent_name"], "OrangeSummit");
    assert_eq!(
        session_start["session"]["context"]["bead"],
        "flywheel_connectors-qnchs.15.2"
    );

    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "safe");
    let slack_connector =
        mock_connector_summary_json("fcp.slack:team:v1", "Slack Team", 1, "risky");
    let github_list_issues = mock_tool_descriptor_json(
        "github.list_issues",
        "github.issue_read",
        "low",
        "safe",
        "strict",
        None,
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" }
            },
            "required": ["owner", "repo"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "issues": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": { "type": "string" }
                        }
                    }
                }
            }
        }),
    );
    let slack_send_message = mock_tool_descriptor_json(
        "slack.send_message",
        "slack.post_message",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "channel": { "type": "string" },
                "text": { "type": "string" }
            },
            "required": ["channel", "text"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" }
            }
        }),
    );
    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(&[github_connector.clone(), slack_connector.clone()]),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(&github_connector, &[github_list_issues]),
        ),
        (
            "GET /rpc/introspect/fcp.slack:team:v1".to_owned(),
            mock_introspection_response_json(&slack_connector, &[slack_send_message]),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
        (
            "POST /rpc/invoke".to_owned(),
            mock_invoke_response_json(json!({
                "issues": [
                    { "title": "Bug report" }
                ]
            })),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
    ]);

    let payload = run_json_ok_in_home(
        home.path(),
        &[
            "--json",
            "--host",
            &host,
            "pipeline",
            "dry-run",
            pipeline_path
                .to_str()
                .expect("pipeline fixture path should be valid UTF-8"),
            "--capability-token",
            &capability_token,
            "--param",
            "owner=octocat",
            "--param",
            "repo=hello-world",
        ],
    );

    server.join().expect("mock host thread should complete");
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["command"], "pipeline");
    assert_eq!(payload["subcommand"], "dry-run");
    assert_eq!(payload["execution"]["executed_steps"], 1);
    assert_eq!(payload["execution"]["preflight_only_steps"], 1);

    let history = run_json_ok_in_home(home.path(), &["--json", "history"]);
    let entries = history["entries"]
        .as_array()
        .expect("history entries should be present");
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|entry| {
        entry["agent_session"].as_str() == Some(session_id.as_str())
    }));
    assert_eq!(entries[0]["status"], "simulated");
    assert_eq!(entries[1]["status"], "success");

    let session_show = run_json_ok_in_home(home.path(), &["--json", "session", "show"]);
    assert_eq!(session_show["session"]["id"], session_id);
    assert_eq!(session_show["session"]["status"], "active");
    assert_eq!(session_show["session"]["agent_name"], "OrangeSummit");
    assert_eq!(
        session_show["session"]["context"]["bead"],
        "flywheel_connectors-qnchs.15.2"
    );
    assert_eq!(session_show["session"]["operations_completed"], 2);
}
