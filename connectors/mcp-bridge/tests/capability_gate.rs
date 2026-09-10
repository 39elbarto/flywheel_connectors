//! Focused integration coverage for the policy-gated MCP tools/call route.

#![allow(
    clippy::cast_possible_truncation,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_host::{
    N8nApprovalIssueRequest, N8nApprovalServer, N8nLifecycleOperation,
    build_unsigned_n8n_approval_token, canonical_approval_token_bytes,
    n8n_typed_approval_plan_digest,
};
use fcp_prelude::{
    ApprovalScope, ApprovalToken, CapabilityToken, ExecutionScope, InputConstraint, InstanceId,
    ZoneId,
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use fcp_mcp_bridge::connector::McpBridgeConnector;
use fcp_mcp_bridge::protocol::{
    AuthMode, CapabilitySnapshot, ProtocolEra, ProtocolVersion, ServerId, ToolClass,
    ToolObservation,
};

const TEST_SERVER_ID: &str = "eec";

struct TestSequenceResponder(Arc<Mutex<VecDeque<ResponseTemplate>>>);

impl TestSequenceResponder {
    fn new(responses: Vec<ResponseTemplate>) -> Self {
        Self(Arc::new(Mutex::new(VecDeque::from(responses))))
    }
}

impl Respond for TestSequenceResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.0
            .lock()
            .expect("test sequence responder mutex poisoned")
            .pop_front()
            .unwrap_or_else(|| ResponseTemplate::new(599))
    }
}

fn test_signing_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[42_u8; 32]).expect("deterministic test signing key")
}

fn mcp_endpoint(mock_url: &str) -> String {
    format!("{mock_url}/mcp")
}

fn capability_for(operation: &str) -> &'static str {
    match operation {
        "mcp.tools.call" => "mcp.tools.write",
        "mcp.tools.list" => "mcp.tools.read",
        _ => "mcp.unknown",
    }
}

fn resource_for(operation: &str, input: &Value) -> String {
    resource_for_server(TEST_SERVER_ID, operation, input)
}

fn resource_for_server(server_id: &str, operation: &str, input: &Value) -> String {
    match operation {
        "mcp.tools.call" => format!(
            "fwc-mcp-bridge://{server_id}/tools/{}",
            utf8_percent_encode(
                input
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                NON_ALPHANUMERIC,
            )
        ),
        _ => format!("fwc-mcp-bridge://{server_id}"),
    }
}

fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_vec(value).expect("serialize scalar")
        }
        Value::Array(values) => {
            let mut output = vec![b'['];
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                output.extend(canonical_json_bytes(item));
            }
            output.push(b']');
            output
        }
        Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let mut output = vec![b'{'];
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                output.extend(serde_json::to_vec(key).expect("serialize key"));
                output.push(b':');
                output.extend(canonical_json_bytes(item));
            }
            output.push(b'}');
            output
        }
    }
}

fn payload_digest(input: &Value) -> [u8; 32] {
    let payload = json!({
        "name": input["name"],
        "arguments": if input["arguments"].is_null() {
            json!({})
        } else {
            input
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}))
        },
    });
    let mut hasher = Sha256::new();
    hasher.update(b"FCP/MCP-Bridge/approval-payload/v1\0");
    hasher.update(canonical_json_bytes(&payload));
    hasher.finalize().into()
}

fn approval_for(input: &Value) -> ApprovalToken {
    let resource_uri = resource_for("mcp.tools.call", input);
    let digest = payload_digest(input);
    let normalized = [
        ("server_id", json!(TEST_SERVER_ID)),
        ("resource_uri", json!(resource_uri)),
        ("operation", json!("mcp.tools.call")),
        ("provider", json!("mcp")),
        ("payload_sha256", json!(hex::encode(digest))),
        ("tool_name", input["name"].clone()),
    ];
    let input_constraints = normalized
        .into_iter()
        .map(|(field, expected)| InputConstraint {
            pointer: format!("/{field}"),
            expected,
        })
        .collect();
    let now = Utc::now();
    ApprovalToken::approved(
        "approval-test",
        u64::try_from(now.timestamp_millis()).expect("current timestamp"),
        u64::try_from((now + ChronoDuration::hours(1)).timestamp_millis())
            .expect("future timestamp"),
        "operator:test",
        ApprovalScope::Execution(ExecutionScope {
            connector_id: "fcp.mcp-bridge".into(),
            method_pattern: "mcp.tools.call".into(),
            request_object_id: None,
            input_hash: Some(digest),
            input_constraints,
        }),
        ZoneId::work(),
        Some(vec![1]),
    )
}

fn typed_n8n_approval_for(
    server_id: &str,
    action: &str,
    provider_input: &Value,
) -> (ApprovalToken, Value) {
    let (operation, tool_name) = match action {
        "publish" => (N8nLifecycleOperation::Publish, "publish_workflow"),
        "unpublish" => (N8nLifecycleOperation::Unpublish, "unpublish_workflow"),
        _ => panic!("unsupported lifecycle action"),
    };
    let workflow_id = "workflow-1";
    let high_level_input = if action == "publish" {
        json!({
            "id": workflow_id,
            "action": action,
            "versionId": "version-1",
            "guard": {
                "approvalRef": format!("typed-{server_id}-{action}"),
                "idempotencyKey": "11111111-2222-4333-8444-555555555555",
                "precondition": {
                    "versionId": "version-1",
                    "activeVersionId": null,
                    "active": false,
                    "isArchived": false,
                    "stateDigest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            }
        })
    } else {
        json!({
            "id": workflow_id,
            "action": action,
            "guard": {
                "approvalRef": format!("typed-{server_id}-{action}"),
                "idempotencyKey": "11111111-2222-4333-8444-555555555555",
                "precondition": {
                    "versionId": "version-1",
                    "activeVersionId": "version-1",
                    "active": true,
                    "isArchived": false,
                    "stateDigest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            }
        })
    };
    let resource_uri = format!("fwc-n8n://{server_id}/workflows/workflow%2D1");
    let parent_binding = fcp_crypto::canonicalize::to_deterministic_cbor(&json!({
        "server_id": server_id,
        "resource_uri": resource_uri,
        "operation": "n8n.workflows.lifecycle",
        "input": high_level_input,
    }))
    .expect("canonical n8n parent binding");
    let parent_binding_sha256 = hex::encode(blake3::hash(&parent_binding).as_bytes());
    let provider_payload_digest = payload_digest(provider_input);
    let provider_resource_uri = resource_for_server(server_id, "mcp.tools.call", provider_input);
    let now_ms = u64::try_from(Utc::now().timestamp_millis()).expect("current timestamp");
    let expires_at_ms = now_ms.saturating_add(50_000);
    let precondition = high_level_input
        .pointer("/guard/precondition")
        .expect("typed precondition");
    let idempotency_key = high_level_input
        .pointer("/guard/idempotencyKey")
        .and_then(Value::as_str)
        .expect("typed idempotency key");
    let provider_payload_digest_text = format!("sha256:{}", hex::encode(provider_payload_digest));
    let typed_plan = n8n_typed_approval_plan_digest(
        server_id,
        workflow_id,
        action,
        tool_name,
        &provider_payload_digest_text,
        &high_level_input,
        precondition,
        idempotency_key,
        expires_at_ms,
        now_ms,
    )
    .expect("independent typed plan digest");
    let issue_request = N8nApprovalIssueRequest {
        schema: "fwc.n8n.owner-approval-request.v1".to_string(),
        server: match server_id {
            "eec" => N8nApprovalServer::Eec,
            "hetzner" => N8nApprovalServer::Hetzner,
            _ => panic!("unsupported n8n server"),
        },
        workflow_id: workflow_id.to_string(),
        operation,
        input: high_level_input,
        official_mcp_tool: tool_name.to_string(),
        official_mcp_resource_uri: provider_resource_uri,
        official_mcp_payload_digest: provider_payload_digest_text,
        parent_binding_sha256: parent_binding_sha256.clone(),
        expires_at_ms,
    };
    let mut approval = build_unsigned_n8n_approval_token(&issue_request, now_ms)
        .expect("production n8n typed issuer token");
    let bytes = canonical_approval_token_bytes(&approval).expect("canonical approval bytes");
    approval.signature = Some(test_signing_key().sign(&bytes).to_bytes().to_vec());
    let ApprovalScope::Execution(scope) = &approval.scope else {
        panic!("issuer must produce execution approval");
    };
    assert!(scope.input_constraints.iter().any(|constraint| {
        constraint.pointer == "/typed_plan_sha256"
            && constraint.expected == json!(typed_plan.clone())
    }));
    (
        approval,
        json!({
            "request_tags": {
                "fcp.n8n.parent_binding_sha256": parent_binding_sha256,
                "fcp.n8n.typed_plan_sha256": typed_plan,
            }
        }),
    )
}

fn capability_token(input: &Value, instance_id: &str) -> CapabilityToken {
    capability_token_for_server(TEST_SERVER_ID, input, instance_id)
}

fn capability_token_for_server(
    server_id: &str,
    input: &Value,
    instance_id: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec![resource_for_server(server_id, "mcp.tools.call", input)],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_for("mcp.tools.call"))
        .zone_id("z:work")
        .principal("user:test")
        .operations(&["mcp.tools.call"])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints")
        .target_instance(instance_id)
        .sign(&test_signing_key())
        .expect("sign capability token");
    CapabilityToken::from_raw(raw)
}

fn handshake_params(instance_id: &str) -> Value {
    let key = test_signing_key();
    json!({
        "protocol_version": "2.0",
        "zone": "z:work",
        "host_public_key": key.verifying_key().to_bytes(),
        "nonce": vec![7_u8; 32],
        "capabilities_requested": ["mcp.tools.read", "mcp.tools.write"],
        "requested_instance_id": instance_id,
    })
}

async fn setup_connector_with_params(mock_url: &str, extra: Value) -> (McpBridgeConnector, String) {
    setup_connector_with_server_params(mock_url, TEST_SERVER_ID, extra).await
}

async fn setup_connector_with_server_params(
    mock_url: &str,
    server_id: &str,
    extra: Value,
) -> (McpBridgeConnector, String) {
    let mut params = json!({
        "server_id": server_id,
        "mcp_url": mcp_endpoint(mock_url),
        "api_key": "test-api-key",
    });
    let params_object = params.as_object_mut().expect("object test parameters");
    for (key, value) in extra.as_object().expect("object test parameters") {
        params_object.insert(key.clone(), value.clone());
    }

    let mut connector = McpBridgeConnector::new();
    let instance_id = InstanceId::new().to_string();
    connector
        .handle_configure(params)
        .await
        .expect("configure test connector");
    connector
        .handle_handshake(handshake_params(&instance_id))
        .await
        .expect("handshake test connector");
    (connector, instance_id)
}

fn schema_digests_for_server(
    server_id: ServerId,
    input_schema: &Value,
    output_schema: &Value,
) -> (String, String) {
    let observation = ToolObservation::from_schemas(
        "digest-probe",
        input_schema,
        output_schema,
        ToolClass::Execution,
    )
    .expect("valid test schemas");
    let snapshot = CapabilitySnapshot::from_observations(
        server_id,
        "1.0.0",
        ProtocolEra::Modern,
        vec![ProtocolVersion::V20260728],
        AuthMode::AccessToken,
        "scope-digest",
        vec![observation],
        None,
    )
    .expect("valid test capability snapshot");
    let tool = &snapshot.tools[0];
    (
        tool.input_schema_digest.clone(),
        tool.output_schema_digest.clone(),
    )
}

fn policy_for_tool(name: &str, input_schema: &Value, output_schema: &Value) -> Value {
    policy_for_tool_server(TEST_SERVER_ID, name, input_schema, output_schema)
}

fn policy_for_tool_server(
    server_id: &str,
    name: &str,
    input_schema: &Value,
    output_schema: &Value,
) -> Value {
    let parsed_server = match server_id {
        "eec" => ServerId::Eec,
        "hetzner" => ServerId::Hetzner,
        _ => panic!("unknown test server"),
    };
    let (input_schema_digest, output_schema_digest) =
        schema_digests_for_server(parsed_server, input_schema, output_schema);
    json!({
        "server_id": server_id,
        "capability_policy": {
            "n8n_version": "1.0.0",
            "auth_mode": "access_token",
            "api_scope_digest": "scope-digest",
            "approved_tools": [{
                "name": name,
                "class": "execution",
                "input_schema_digest": input_schema_digest,
                "output_schema_digest": output_schema_digest,
            }],
        },
    })
}

#[fcp_async_core::runtime::test]
async fn tools_call_policy_gated_loopback_success() {
    let server = MockServer::start().await;
    let input_schema = json!({"type": "object"});
    let output_schema = Value::Null;
    let input = json!({
        "name": "read_file",
        "arguments": {"path": "/tmp/data.txt"}
    });
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(TestSequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [{"name": "read_file", "inputSchema": input_schema}]
                }
            })),
            ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "content": [{"type": "text", "text": "file contents here"}]
                }
            })),
        ]))
        .mount(&server)
        .await;

    let (connector, instance_id) = setup_connector_with_params(
        &server.uri(),
        policy_for_tool("read_file", &json!({"type": "object"}), &output_schema),
    )
    .await;
    let result = connector
        .handle_invoke(json!({
            "operation": "mcp.tools.call",
            "input": input.clone(),
            "capability_token": capability_token(&input, &instance_id),
            "approval_tokens": [approval_for(&input)],
        }))
        .await
        .expect("policy-gated tools.call should reach the loopback provider");
    assert_eq!(result["content"][0]["text"], "file contents here");

    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 2);
    let methods: Vec<_> = requests
        .iter()
        .map(|request| {
            serde_json::from_slice::<Value>(&request.body).expect("JSON-RPC request")["method"]
                .as_str()
                .expect("JSON-RPC method")
                .to_owned()
        })
        .collect();
    assert_eq!(
        methods,
        vec!["tools/list".to_owned(), "tools/call".to_owned()]
    );
}

#[fcp_async_core::runtime::test]
async fn typed_n8n_owner_approval_reaches_eec_and_hetzner_once() {
    for (server_id, action, tool_name) in [
        ("eec", "publish", "publish_workflow"),
        ("eec", "unpublish", "unpublish_workflow"),
        ("hetzner", "publish", "publish_workflow"),
        ("hetzner", "unpublish", "unpublish_workflow"),
    ] {
        let server = MockServer::start().await;
        let input_schema = json!({"type": "object"});
        let output_schema = Value::Null;
        let provider_input = if action == "publish" {
            json!({
                "name": tool_name,
                "arguments": {"workflowId": "workflow-1", "versionId": "version-1"}
            })
        } else {
            json!({
                "name": tool_name,
                "arguments": {"workflowId": "workflow-1"}
            })
        };
        Mock::given(method("POST"))
            .and(path("/mcp"))
            .respond_with(TestSequenceResponder::new(vec![
                ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "tools": [{"name": tool_name, "inputSchema": input_schema}]
                    }
                })),
                ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {"content": [{"type": "text", "text": "n8n mutation accepted"}]}
                })),
            ]))
            .mount(&server)
            .await;

        let (connector, instance_id) = setup_connector_with_server_params(
            &server.uri(),
            server_id,
            policy_for_tool_server(server_id, tool_name, &input_schema, &output_schema),
        )
        .await;
        let (approval, context) = typed_n8n_approval_for(server_id, action, &provider_input);
        let result = connector
            .handle_invoke(json!({
                "operation": "mcp.tools.call",
                "input": provider_input.clone(),
                "capability_token": capability_token_for_server(server_id, &provider_input, &instance_id),
                "context": context,
                "approval_tokens": [approval],
            }))
            .await
            .expect("host-built typed approval should reach the real bridge provider");
        assert_eq!(result["content"][0]["text"], "n8n mutation accepted");

        let requests = server.received_requests().await.unwrap_or_default();
        let methods: Vec<_> = requests
            .iter()
            .map(|request| {
                serde_json::from_slice::<Value>(&request.body).expect("JSON-RPC request")["method"]
                    .as_str()
                    .expect("JSON-RPC method")
                    .to_owned()
            })
            .collect();
        assert_eq!(methods, vec!["tools/list", "tools/call"]);
        assert_eq!(
            methods
                .iter()
                .filter(|method| method.as_str() == "tools/call")
                .count(),
            1
        );
    }
}

#[fcp_async_core::runtime::test]
async fn typed_n8n_owner_approval_mismatch_denies_before_provider_call() {
    for server_id in ["eec", "hetzner"] {
        let server = MockServer::start().await;
        let input_schema = json!({"type": "object"});
        let output_schema = Value::Null;
        let provider_input = json!({
            "name": "publish_workflow",
            "arguments": {"workflowId": "workflow-1", "versionId": "version-1"}
        });
        let (connector, instance_id) = setup_connector_with_server_params(
            &server.uri(),
            server_id,
            policy_for_tool_server(server_id, "publish_workflow", &input_schema, &output_schema),
        )
        .await;
        let (approval, context) = typed_n8n_approval_for(server_id, "publish", &provider_input);

        let mut cases = Vec::new();
        let other_server = if server_id == "eec" { "hetzner" } else { "eec" };
        for (name, expected) in [
            ("server", json!(other_server)),
            (
                "resource",
                json!(format!("fwc-mcp-bridge://{server_id}/tools/other")),
            ),
            ("tool", json!("unpublish_workflow")),
            (
                "payload",
                json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ),
        ] {
            let mut mutated = approval.clone();
            let ApprovalScope::Execution(scope) = &mut mutated.scope else {
                panic!("typed issuer must produce execution scope");
            };
            let field = match name {
                "server" => "server_id",
                "resource" => "resource_uri",
                "tool" => "tool_name",
                "payload" => "payload_sha256",
                _ => unreachable!(),
            };
            let constraint = scope
                .input_constraints
                .iter_mut()
                .find(|constraint| constraint.pointer == format!("/{field}"))
                .expect("issuer constraint");
            constraint.expected = expected;
            if name == "payload" {
                scope.input_hash = Some([0; 32]);
            }
            cases.push((name, mutated, context.clone()));
        }
        let mut wrong_zone = approval.clone();
        wrong_zone.zone_id = ZoneId::private();
        cases.push(("zone", wrong_zone, context.clone()));
        let mut wrong_time = approval.clone();
        wrong_time.issued_at_ms = 0;
        wrong_time.expires_at_ms = 1;
        cases.push(("time", wrong_time, context.clone()));
        for (name, tag, value) in [
            (
                "parent",
                "fcp.n8n.parent_binding_sha256",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            (
                "plan",
                "fcp.n8n.typed_plan_sha256",
                "blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        ] {
            let mut mutated_context = context.clone();
            mutated_context["request_tags"][tag] = json!(value);
            cases.push((name, approval.clone(), mutated_context));
        }
        cases.push(("missing_context", approval.clone(), Value::Null));

        for (name, mutated_approval, mutated_context) in cases {
            let mut request = json!({
                "operation": "mcp.tools.call",
                "input": provider_input.clone(),
                "capability_token": capability_token_for_server(
                    server_id,
                    &provider_input,
                    &instance_id,
                ),
                "approval_tokens": [mutated_approval],
            });
            if !mutated_context.is_null() {
                request["context"] = mutated_context;
            }
            let error = connector
                .handle_invoke(request)
                .await
                .expect_err("typed approval mismatch must deny before egress");
            assert!(
                format!("{error:?}").contains("exactly one matching execution approval"),
                "{name}"
            );
            let requests = server.received_requests().await.unwrap_or_default();
            assert_eq!(requests.len(), 0, "{name} must make zero provider calls");
        }
    }
}

#[fcp_async_core::runtime::test]
async fn tools_call_schema_drift_denies_before_second_provider_request() {
    let server = MockServer::start().await;
    let reviewed_input_schema = json!({"type": "object"});
    let drifted_input_schema = json!({"type": "array"});
    let output_schema = Value::Null;
    let input = json!({
        "name": "read_file",
        "arguments": {"path": "/tmp/schema-drift.txt"}
    });
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{"name": "read_file", "inputSchema": drifted_input_schema}]
            }
        })))
        .mount(&server)
        .await;

    let (connector, instance_id) = setup_connector_with_params(
        &server.uri(),
        policy_for_tool("read_file", &reviewed_input_schema, &output_schema),
    )
    .await;
    let error = connector
        .handle_invoke(json!({
            "operation": "mcp.tools.call",
            "input": input.clone(),
            "capability_token": capability_token(&input, &instance_id),
            "approval_tokens": [approval_for(&input)],
        }))
        .await
        .expect_err("schema drift must fail closed after fresh discovery");
    assert!(format!("{error:?}").contains("not exactly approved"));

    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    let request: Value = serde_json::from_slice(&requests[0].body).expect("JSON-RPC request");
    assert_eq!(request["method"], "tools/list");
}
