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
    match operation {
        "mcp.tools.call" => format!(
            "fwc-mcp-bridge://{TEST_SERVER_ID}/tools/{}",
            utf8_percent_encode(
                input
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                NON_ALPHANUMERIC,
            )
        ),
        _ => format!("fwc-mcp-bridge://{TEST_SERVER_ID}"),
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

fn capability_token(input: &Value, instance_id: &str) -> CapabilityToken {
    let now = Utc::now();
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec![resource_for("mcp.tools.call", input)],
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
    let mut params = json!({
        "server_id": TEST_SERVER_ID,
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

fn schema_digests(input_schema: &Value, output_schema: &Value) -> (String, String) {
    let observation = ToolObservation::from_schemas(
        "digest-probe",
        input_schema,
        output_schema,
        ToolClass::Execution,
    )
    .expect("valid test schemas");
    let snapshot = CapabilitySnapshot::from_observations(
        ServerId::Eec,
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
    let (input_schema_digest, output_schema_digest) = schema_digests(input_schema, output_schema);
    json!({
        "server_id": TEST_SERVER_ID,
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
