//! Integration tests for the FCP n8n connector.

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

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use fcp_crypto::{
    canonicalize::to_deterministic_cbor, cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey,
};
use fcp_prelude::{
    ApprovalScope, ApprovalToken, CapabilityConstraints, CapabilityToken, ExecutionScope, FcpError,
    FcpResult, InputConstraint, ZoneId,
};
use fcp_sdk::ConnectorRuntimeConfig;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, body_string, header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use fcp_n8n::connector::N8nConnector;

const TEST_SERVER_ID: &str = "eec";
const TEST_INSTANCE_ID: &str = "inst_n8n_test";
const MAX_PROVIDER_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

fn test_signing_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[42_u8; 32]).expect("fixed test key should parse")
}

fn resource_uri(operation: &str, input: &Value) -> String {
    match operation {
        "n8n.workflows.list"
        | "n8n.executions.list"
        | "n8n.projects.list"
        | "n8n.credentials.list"
        | "n8n.tags.list"
        | "n8n.mcp_access.reconcile" => {
            format!("fwc-n8n://{TEST_SERVER_ID}")
        }
        "n8n.folders.list" => {
            let project_id = input["project_id"].as_str().unwrap_or("invalid-project");
            let project_id = utf8_percent_encode(project_id, NON_ALPHANUMERIC);
            format!("fwc-n8n://{TEST_SERVER_ID}/projects/{project_id}")
        }
        "n8n.folders.get" => {
            let folder_id = input["folder_id"].as_str().unwrap_or("invalid-folder");
            let folder_id = utf8_percent_encode(folder_id, NON_ALPHANUMERIC);
            format!("fwc-n8n://{TEST_SERVER_ID}/folders/{folder_id}")
        }
        "n8n.workflows.get"
        | "n8n.workflows.activate"
        | "n8n.workflows.lifecycle"
        | "n8n.workflows.delete_disposable" => {
            let id = input["id"].as_str().expect("workflow id for test token");
            let id = utf8_percent_encode(id, NON_ALPHANUMERIC);
            format!("fwc-n8n://{TEST_SERVER_ID}/workflows/{id}")
        }
        "n8n.workflows.create_draft" => input["project_id"].as_str().map_or_else(
            || format!("fwc-n8n://{TEST_SERVER_ID}"),
            |project_id| {
                let project_id = utf8_percent_encode(project_id, NON_ALPHANUMERIC);
                format!("fwc-n8n://{TEST_SERVER_ID}/projects/{project_id}")
            },
        ),
        "n8n.workflows.update_draft" => {
            let id = input["id"]
                .as_str()
                .expect("workflow id for draft approval");
            let id = utf8_percent_encode(id, NON_ALPHANUMERIC);
            format!("fwc-n8n://{TEST_SERVER_ID}/workflows/{id}")
        }
        "n8n.executions.get" => {
            let workflow_id = input["workflow_id"]
                .as_str()
                .expect("workflow id for execution test token");
            let execution_id = input["id"].as_str().expect("execution id for test token");
            let workflow_id = utf8_percent_encode(workflow_id, NON_ALPHANUMERIC);
            let execution_id = utf8_percent_encode(execution_id, NON_ALPHANUMERIC);
            format!("fwc-n8n://{TEST_SERVER_ID}/workflows/{workflow_id}/executions/{execution_id}")
        }
        _ => panic!("unknown operation in test token: {operation}"),
    }
}

fn capability_token(operation: &str, input: &Value) -> CapabilityToken {
    let now = chrono::Utc::now();
    capability_token_with_options(
        operation,
        &test_signing_key(),
        TEST_INSTANCE_ID,
        resource_uri(operation, input),
        now - chrono::Duration::seconds(1),
        now + chrono::Duration::hours(1),
    )
}

fn capability_token_with_options(
    operation: &str,
    key: &Ed25519SigningKey,
    target_instance: &str,
    resource_allow: String,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> CapabilityToken {
    let capability = match operation {
        "n8n.workflows.activate"
        | "n8n.workflows.create_draft"
        | "n8n.workflows.update_draft"
        | "n8n.workflows.delete_disposable" => "n8n.workflows.write",
        "n8n.workflows.lifecycle" => "n8n.workflows.lifecycle",
        "n8n.mcp_access.reconcile" => "n8n.mcp_access.write",
        "n8n.workflows.list" | "n8n.workflows.get" => "n8n.workflows.read",
        "n8n.executions.list" | "n8n.executions.get" => "n8n.executions.read",
        "n8n.projects.list" => "n8n.projects.read",
        "n8n.credentials.list" => "n8n.credentials.metadata.read",
        "n8n.tags.list" => "n8n.tags.read",
        "n8n.folders.list" | "n8n.folders.get" => "n8n.folders.read",
        _ => panic!("unknown operation in test token: {operation}"),
    };
    let constraints = CapabilityConstraints {
        resource_allow: vec![resource_allow],
        ..CapabilityConstraints::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("capability constraints should encode");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(target_instance)
        .validity(issued_at, expires_at)
        .try_constraints_cbor(&constraints_cbor)
        .expect("capability constraints should validate")
        .sign(key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

fn approval_token(input: &Value) -> ApprovalToken {
    let workflow_id = input["id"].as_str().expect("workflow id for approval");
    let active = input["active"].as_bool().expect("active for approval");
    let resource_uri = resource_uri("n8n.workflows.activate", input);
    let constraints = [
        ("/server_id", json!(TEST_SERVER_ID)),
        ("/resource_uri", json!(resource_uri)),
        ("/workflow_id", json!(workflow_id)),
        ("/active", json!(active)),
        ("/provider", json!("rest")),
    ]
    .into_iter()
    .map(|(pointer, expected)| InputConstraint {
        pointer: pointer.into(),
        expected,
    })
    .collect();
    let now = u64::try_from(chrono::Utc::now().timestamp_millis())
        .expect("current timestamp should fit in u64");
    ApprovalToken::approved(
        "approval-test",
        now.saturating_sub(1_000),
        now.saturating_add(60_000),
        "operator:test",
        ApprovalScope::Execution(ExecutionScope {
            connector_id: "fcp.n8n".into(),
            method_pattern: "n8n.workflows.activate".into(),
            request_object_id: None,
            input_hash: None,
            input_constraints: constraints,
        }),
        ZoneId::work(),
        Some(vec![1_u8]),
    )
}

fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(key, _)| *key);
            let mut canonical = serde_json::Map::new();
            for (key, child) in entries {
                canonical.insert(key.clone(), canonical_json(child));
            }
            Value::Object(canonical)
        }
        Value::Array(array) => Value::Array(array.iter().map(canonical_json).collect()),
        other => other.clone(),
    }
}

fn draft_graph_digest(input: &Value) -> String {
    let semantic_nodes = input["graph"]["nodes"]
        .as_array()
        .expect("draft graph nodes")
        .iter()
        .map(|node| {
            let mut node = node.clone();
            node.as_object_mut()
                .expect("draft graph node object")
                .remove("credentials");
            node
        })
        .collect::<Vec<_>>();
    let canonical = canonical_json(&json!({
        "nodes": semantic_nodes,
        "connections": input["graph"]["connections"],
    }));
    let bytes = serde_json::to_vec(&canonical).expect("graph digest JSON");
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fwc-n8n.graph-digest.v1");
    hasher.update(&[0]);
    hasher.update(&bytes);
    format!("blake3-256:{}", hasher.finalize().to_hex())
}

fn draft_mutation_digest(operation: &str, input: &Value) -> String {
    let graph = input["graph"].as_object().expect("draft graph object");
    let create = operation == "n8n.workflows.create_draft";
    let settings = match graph.get("settings") {
        None | Some(Value::Null) if create => json!({"availableInMCP": false}),
        None | Some(Value::Null) => json!({}),
        Some(Value::Object(settings)) => {
            let mut settings = settings.clone();
            if create {
                settings
                    .entry("availableInMCP")
                    .or_insert_with(|| Value::Bool(false));
            }
            Value::Object(settings)
        }
        Some(value) => value.clone(),
    };
    let canonical = canonical_json(&json!({
        "id": input.get("id").cloned().unwrap_or(Value::Null),
        "name": input.get("name").cloned().unwrap_or(Value::Null),
        "project_id": input.get("project_id").cloned().unwrap_or(Value::Null),
        "parent_folder_id": input
            .get("parent_folder_id")
            .cloned()
            .unwrap_or(Value::Null),
        "graph": {
            "nodes": graph.get("nodes").cloned().unwrap_or(Value::Null),
            "connections": graph.get("connections").cloned().unwrap_or(Value::Null),
            "settings": settings,
            "staticData": graph.get("staticData").cloned().unwrap_or(Value::Null),
            "pinData": graph.get("pinData").cloned().unwrap_or(Value::Null),
        },
    }));
    let bytes = serde_json::to_vec(&canonical).expect("mutation digest JSON");
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fwc-n8n.mutation-digest.v1");
    hasher.update(&[0]);
    hasher.update(&bytes);
    format!("blake3-256:{}", hasher.finalize().to_hex())
}

fn draft_approval_token(operation: &str, input: &Value) -> ApprovalToken {
    let guard = &input["guard"];
    let resource_uri = resource_uri(operation, input);
    let input_hash = approval_binding_hash(operation, &resource_uri, input);
    let now = u64::try_from(chrono::Utc::now().timestamp_millis())
        .expect("current timestamp should fit in u64");
    ApprovalToken::approved(
        guard["approvalRef"].as_str().expect("approval reference"),
        now.saturating_sub(1_000),
        now.saturating_add(60_000),
        "operator:test",
        ApprovalScope::Execution(ExecutionScope {
            connector_id: "fcp.n8n".into(),
            method_pattern: operation.into(),
            request_object_id: None,
            input_hash: Some(input_hash),
            input_constraints: Vec::new(),
        }),
        ZoneId::work(),
        Some(vec![1_u8]),
    )
}

fn approval_binding_hash(operation: &str, resource_uri: &str, input: &Value) -> [u8; 32] {
    let input_bytes = to_deterministic_cbor(&json!({
        "server_id": TEST_SERVER_ID,
        "resource_uri": resource_uri,
        "operation": operation,
        "input": input,
    }))
    .expect("approval binding CBOR");
    *blake3::hash(&input_bytes).as_bytes()
}

fn unrelated_approval_token(input: &Value) -> ApprovalToken {
    let mut token = approval_token(input);
    if let ApprovalScope::Execution(scope) = &mut token.scope {
        scope.connector_id = "fcp.other".into();
    }
    token
}

fn host_bound_input_hash_approval_token(input: &Value) -> ApprovalToken {
    let mut token = approval_token(input);
    if let ApprovalScope::Execution(scope) = &mut token.scope {
        scope.input_hash = Some([7_u8; 32]);
    }
    token
}

fn authorized_params(operation: &str, input: &Value) -> Value {
    let mut params = json!({
        "operation": operation,
        "input": input,
        "capability_token": capability_token(operation, input),
    });
    if operation == "n8n.workflows.activate" {
        params["approval_tokens"] = json!([approval_token(input)]);
    } else if matches!(
        operation,
        "n8n.workflows.create_draft"
            | "n8n.workflows.update_draft"
            | "n8n.workflows.lifecycle"
            | "n8n.workflows.delete_disposable"
            | "n8n.mcp_access.reconcile"
    ) && (operation != "n8n.mcp_access.reconcile" || input["dryRun"] == json!(false))
    {
        params["approval_tokens"] = json!([draft_approval_token(operation, input)]);
    }
    params
}

async fn invoke(connector: &N8nConnector, operation: &str, input: Value) -> FcpResult<Value> {
    connector
        .handle_invoke(authorized_params(operation, &input))
        .await
}

async fn invoke_with_approval(
    connector: &N8nConnector,
    operation: &str,
    input: Value,
    approval: ApprovalToken,
) -> FcpResult<Value> {
    let capability = capability_token(operation, &input);
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability,
            "approval_tokens": [approval],
        }))
        .await
}

async fn invoke_with_host_attribution(
    connector: &N8nConnector,
    operation: &str,
    input: Value,
    request_id: &str,
    correlation_id: &str,
) -> FcpResult<Value> {
    let mut params = authorized_params(operation, &input);
    params["id"] = json!(request_id);
    params["correlation_id"] = json!(correlation_id);
    connector.handle_invoke(params).await
}

async fn setup_connector(mock_url: &str) -> N8nConnector {
    setup_connector_with_config(json!({
        "api_key": "test-n8n-api-key-123",
        "server_id": TEST_SERVER_ID,
        "base_url": format!("{mock_url}/api/v1")
    }))
    .await
}

async fn setup_connector_with_config(config: Value) -> N8nConnector {
    setup_connector_with_runtime_config(
        config,
        ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
    )
    .await
}

async fn setup_connector_with_runtime_config(
    config: Value,
    runtime_config: ConnectorRuntimeConfig,
) -> N8nConnector {
    let mut c = N8nConnector::new_with_runtime_config(runtime_config);
    let key = test_signing_key();
    c.handle_configure(config).await.unwrap();
    c.handle_handshake(json!({
        "protocol_version": "1.0.0",
        "zone": "z:work",
        "host_public_key": key.verifying_key().to_bytes(),
        "nonce": vec![0_u8; 32],
        "capabilities_requested": [
            "n8n.workflows.read",
            "n8n.workflows.write",
            "n8n.executions.read",
            "n8n.projects.read",
            "n8n.credentials.metadata.read",
            "n8n.tags.read",
            "n8n.folders.read",
            "n8n.mcp_access.write",
            "n8n.workflows.lifecycle",
        ],
        "requested_instance_id": TEST_INSTANCE_ID
    }))
    .await
    .unwrap();
    c
}

async fn setup_mediated_connector(proxy_url: &str) -> N8nConnector {
    let runtime_config = ConnectorRuntimeConfig::default()
        .with_request_timeout(Duration::from_secs(30))
        .with_host_egress_proxy_url(proxy_url);
    let mut c = N8nConnector::new_with_runtime_config(runtime_config);
    let key = test_signing_key();
    c.handle_configure(json!({
        "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        "server_id": TEST_SERVER_ID,
        "base_url": "https://n8n.example.com/api/v1",
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({
        "protocol_version": "1.0.0",
        "zone": "z:work",
        "host_public_key": key.verifying_key().to_bytes(),
        "nonce": vec![0_u8; 32],
        "capabilities_requested": [
            "n8n.workflows.read",
            "n8n.executions.read",
            "n8n.projects.read",
            "n8n.credentials.metadata.read",
            "n8n.tags.read",
            "n8n.folders.read"
        ],
        "requested_instance_id": TEST_INSTANCE_ID
    }))
    .await
    .unwrap();
    c
}

#[derive(Clone)]
struct MediatedProjectsResponse {
    status: u16,
    body: Vec<u8>,
    retry_after: Option<&'static str>,
    malformed_decision: bool,
}

impl MediatedProjectsResponse {
    fn json(status: u16, body: &Value) -> Self {
        Self {
            status,
            body: serde_json::to_vec(&body).unwrap(),
            retry_after: None,
            malformed_decision: false,
        }
    }
}

impl Respond for MediatedProjectsResponse {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let envelope: Value = serde_json::from_slice(&request.body).unwrap();
        let context = &envelope["context"];
        let mut decision = json!({
            "connector_id": context["connector_id"],
            "operation_id": context["operation_id"],
            "zone_id": context["zone_id"],
            "request_id": context["request_id"],
            "execution_mode": "host_egress_proxy",
            "constraint_source": "managed_connector_config.operation_network_constraints",
            "decision": "allow",
            "resolved_host": "n8n.example.com",
            "resolved_port": 443,
            "credential_injected": true,
            "elapsed_ms": 1,
        });
        if let Some(correlation_id) = context.get("correlation_id") {
            decision["correlation_id"] = correlation_id.clone();
        }
        if self.malformed_decision {
            decision["operation_id"] = json!("n8n.tags.list");
        }
        let headers = self.retry_after.map_or_else(Vec::new, |value| {
            vec![json!({"name": "retry-after", "value": value})]
        });
        ResponseTemplate::new(200).set_body_json(json!({
            "status": self.status,
            "headers": headers,
            "body": format!(
                "base64:{}",
                base64::engine::general_purpose::STANDARD.encode(&self.body)
            ),
            "egress": decision,
        }))
    }
}

#[derive(Clone)]
struct DraftReply {
    status: u16,
    body: Value,
}

#[derive(Clone)]
struct MediatedDraftResponse {
    replies: Arc<Mutex<Vec<DraftReply>>>,
    requests: Arc<Mutex<Vec<Value>>>,
    empty_second_body: bool,
}

impl MediatedDraftResponse {
    fn new(replies: Vec<DraftReply>) -> (Self, Arc<Mutex<Vec<Value>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                replies: Arc::new(Mutex::new(replies)),
                requests: Arc::clone(&requests),
                empty_second_body: false,
            },
            requests,
        )
    }

    fn new_with_empty_second_body(replies: Vec<DraftReply>) -> (Self, Arc<Mutex<Vec<Value>>>) {
        let (mut responder, requests) = Self::new(replies);
        responder.empty_second_body = true;
        (responder, requests)
    }
}

impl Respond for MediatedDraftResponse {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let envelope: Value = serde_json::from_slice(&request.body).unwrap();
        let request_number = {
            let mut requests = self.requests.lock().unwrap();
            requests.push(envelope.clone());
            requests.len()
        };
        let reply = self.replies.lock().unwrap().remove(0);
        let context = &envelope["context"];
        let mut decision = json!({
            "connector_id": context["connector_id"],
            "operation_id": context["operation_id"],
            "zone_id": context["zone_id"],
            "request_id": context["request_id"],
            "execution_mode": "host_egress_proxy",
            "constraint_source": "managed_connector_config.operation_network_constraints",
            "decision": "allow",
            "resolved_host": "n8n.example.com",
            "resolved_port": 443,
            "credential_injected": true,
            "elapsed_ms": 1,
        });
        if let Some(correlation_id) = context.get("correlation_id") {
            decision["correlation_id"] = correlation_id.clone();
        }
        let body = if self.empty_second_body && request_number == 2 {
            Vec::new()
        } else {
            serde_json::to_vec(&reply.body).unwrap()
        };
        ResponseTemplate::new(200).set_body_json(json!({
            "status": reply.status,
            "headers": [],
            "body": format!(
                "base64:{}",
                base64::engine::general_purpose::STANDARD.encode(body)
            ),
            "egress": decision,
        }))
    }
}

#[derive(Clone)]
struct SequentialJsonResponse {
    replies: Arc<Mutex<Vec<Value>>>,
}

impl SequentialJsonResponse {
    fn new(replies: Vec<Value>) -> Self {
        Self {
            replies: Arc::new(Mutex::new(replies)),
        }
    }
}

impl Respond for SequentialJsonResponse {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let body = self
            .replies
            .lock()
            .expect("response sequence lock")
            .remove(0);
        ResponseTemplate::new(200).set_body_json(body)
    }
}

#[derive(Clone)]
struct DisposableDeleteResponse {
    baseline: Value,
    calls: Arc<Mutex<usize>>,
}

impl DisposableDeleteResponse {
    fn new(baseline: Value) -> Self {
        Self {
            baseline,
            calls: Arc::new(Mutex::new(0)),
        }
    }
}

impl Respond for DisposableDeleteResponse {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let mut calls = self.calls.lock().expect("delete response sequence lock");
        let call = *calls;
        *calls = calls.saturating_add(1);
        if call == 0 {
            ResponseTemplate::new(200).set_body_json(self.baseline.clone())
        } else if call == 1 {
            ResponseTemplate::new(404).set_body_json(json!({
                "message": "Workflow not found"
            }))
        } else {
            ResponseTemplate::new(500)
        }
    }
}

fn digest_domain(domain: &[u8], value: &Value) -> String {
    let canonical = canonical_json(value);
    let bytes = serde_json::to_vec(&canonical).expect("digest JSON");
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(&bytes);
    format!("blake3-256:{}", hasher.finalize().to_hex())
}

fn workflow_state_digest_for_fixture(workflow: &Value) -> String {
    let active_version = workflow["activeVersion"].clone();
    let published = active_version.as_object().map(|published| {
        json!({
            "versionId": published["versionId"],
            "nodes": published["nodes"],
            "connections": published["connections"],
        })
    });
    digest_domain(
        b"fwc-n8n.state-digest.v1",
        &json!({
            "schema": "fwc-n8n.workflow-state.v1",
            "id": workflow["id"],
            "name": workflow.get("name").cloned().unwrap_or(Value::Null),
            "description": workflow.get("description").cloned().unwrap_or(Value::Null),
            "projectId": workflow.get("projectId").cloned().unwrap_or(Value::Null),
            "folderId": workflow
                .get("parentFolderId")
                .cloned()
                .unwrap_or(Value::Null),
            "versionId": workflow["versionId"],
            "active": workflow["active"],
            "activeVersionId": workflow["activeVersionId"],
            "isArchived": workflow["isArchived"],
            "createdAt": workflow.get("createdAt").cloned().unwrap_or(Value::Null),
            "updatedAt": workflow.get("updatedAt").cloned().unwrap_or(Value::Null),
            "tags": workflow.get("tags").cloned().unwrap_or(Value::Null),
            "draft": {
                "nodes": workflow["nodes"],
                "connections": workflow["connections"],
            },
            "published": published,
        }),
    )
}

fn mediated_request_payload(envelope: &Value) -> Value {
    let encoded = envelope["body"].as_str().expect("mediated body");
    let encoded = encoded.strip_prefix("base64:").expect("base64 body");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("mediated body base64");
    serde_json::from_slice(&bytes).expect("mediated JSON body")
}

fn assert_no_untrusted_output(value: &Value) {
    let serialized = serde_json::to_string(value).expect("runtime view should serialize");
    for field in [
        "nodes",
        "connections",
        "activeVersion",
        "meta",
        "credentials",
        "code",
        "pinData",
        "data",
        "resultData",
        "unknownField",
        "users",
        "roles",
        "memberships",
        "workflow",
        "nextCursor",
    ] {
        assert!(
            value.get(field).is_none(),
            "untrusted field escaped: {field}"
        );
        let field_token = format!("\"{field}\"");
        assert!(
            !serialized.contains(&field_token),
            "untrusted field name escaped: {field}"
        );
    }
    for marker in [
        "marker.workflow.graph",
        "marker.workflow.code",
        "marker.workflow.credentials",
        "marker.workflow.pin",
        "marker.execution.data",
        "marker.execution.result",
        "marker.execution.credentials",
        "marker.execution.pin",
        "marker.project.users",
        "marker.project.memberships",
        "marker.project.credentials",
        "marker.project.workflow",
        "marker.project.provider-error",
        "marker.unknown",
    ] {
        assert!(
            !serialized.contains(marker),
            "untrusted marker escaped: {marker}"
        );
    }
}

fn assert_compact_tag_output(value: &Value) {
    let serialized = serde_json::to_string(value).expect("tag view should serialize");
    let object = value.as_object().expect("tag view should be an object");
    assert!(object.contains_key("id"));
    assert!(object.contains_key("name"));
    assert_eq!(object.len(), 2, "tag output must contain only id and name");
    for field in [
        "createdAt",
        "updatedAt",
        "users",
        "roles",
        "memberships",
        "credentials",
        "unknownField",
    ] {
        assert!(value.get(field).is_none(), "tag field leaked: {field}");
        assert!(
            !serialized.contains(&format!("\"{field}\"")),
            "tag field name escaped: {field}"
        );
    }
    for marker in [
        "marker.tag.created",
        "marker.tag.updated",
        "marker.tag.users",
        "marker.tag.unknown",
    ] {
        assert!(!serialized.contains(marker), "tag marker escaped: {marker}");
    }
}

// -- Lifecycle --

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = N8nConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
    assert_eq!(h["configured"], false);
    assert_eq!(h["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
    assert_eq!(h["configured"], true);
    assert_eq!(h["handshaken"], true);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configured_but_not_handshaken() {
    let server = MockServer::start().await;
    let mut c = N8nConnector::new();
    c.handle_configure(json!({
        "api_key": "test-key",
        "server_id": TEST_SERVER_ID,
        "base_url": format!("{}/api/v1", server.uri())
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = N8nConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "unconfigured");
    assert_eq!(health["handshaken"], false);
    assert!(
        c.handle_invoke(json!({"operation": "n8n.workflows.list"}))
            .await
            .is_err()
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_configured() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .and(query_param("limit", "1"))
        .and(query_param("excludePinnedData", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ok");
    assert!(check["details"]["provisioning"].is_object());
    assert_eq!(check["details"]["provisioning"]["auth_mode"], "api_key");
    assert_eq!(check["details"]["provisioning"]["network_ok"], true);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_unconfigured() {
    let c = N8nConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_healthy() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let d = c.handle_doctor().await.unwrap();
    assert_eq!(d["status"], "healthy");
    assert_eq!(d["checks"].as_array().unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unconfigured() {
    let c = N8nConnector::new();
    let d = c.handle_doctor().await.unwrap();
    assert_eq!(d["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    let ops = intro["operations"].as_array().expect("operations array");
    assert!(!ops.is_empty(), "introspect should list operations");
    assert!(ops[0]["id"].is_string());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_response() {
    let server = MockServer::start().await;
    let mut c = N8nConnector::new();
    c.handle_configure(json!({
        "api_key": "test-key",
        "server_id": TEST_SERVER_ID,
        "base_url": format!("{}/api/v1", server.uri())
    }))
    .await
    .unwrap();
    let key = test_signing_key();
    let h = c
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": key.verifying_key().to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": ["n8n.workflows.read"],
            "requested_instance_id": TEST_INSTANCE_ID
        }))
        .await
        .unwrap();
    assert_eq!(h["status"], "accepted");
    assert!(h["manifest_hash"].as_str().unwrap().starts_with("sha256:"));
    let caps = h["capabilities_granted"].as_array().unwrap();
    assert_eq!(caps.len(), 1);
}

// -- Workflows List --

#[fcp_async_core::runtime::test]
async fn workflows_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .and(query_param("limit", "50"))
        .and(query_param("excludePinnedData", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "1001", "name": "Daily Report", "active": true},
                {"id": "1002", "name": "Sync Contacts", "active": false},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.workflows.list", json!({})).await.unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn workflows_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.workflows.list", json!({})).await.unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn workflows_list_null_cursor_is_omitted() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [],
            "nextCursor": null
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.workflows.list", json!({})).await.unwrap();
    assert!(result.get("nextCursor").is_none());
}

#[fcp_async_core::runtime::test]
async fn workflows_list_accepts_bounded_limits_and_opaque_cursor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .and(query_param("limit", "1"))
        .and(query_param("excludePinnedData", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .and(query_param("limit", "200"))
        .and(query_param("cursor", "opaque cursor/%"))
        .and(query_param("excludePinnedData", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    invoke(&c, "n8n.workflows.list", json!({"limit": 1}))
        .await
        .unwrap();
    invoke(
        &c,
        "n8n.workflows.list",
        json!({"limit": 200, "cursor": "opaque cursor/%"}),
    )
    .await
    .unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

// -- Projects List --

#[fcp_async_core::runtime::test]
async fn projects_list_projects_are_safely_projected() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/projects"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .and(query_param("limit", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "id": "project-1",
                    "name": "Operations",
                    "type": "team",
                    "users": [{"id": "marker.project.users"}],
                    "roles": ["owner"],
                    "memberships": [{"id": "marker.project.memberships"}],
                    "credentials": {"api": "marker.project.credentials"},
                    "workflow": {"nodes": ["marker.project.workflow"]},
                    "unknownField": "marker.unknown"
                },
                {
                    "id": "project-2",
                    "name": "Personal",
                    "users": [{"id": "marker.project.users"}]
                }
            ],
            "nextCursor": "opaque-project-cursor"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.projects.list", json!({})).await.unwrap();
    let projects = result["data"].as_array().unwrap();
    assert_eq!(projects.len(), 2);
    assert_eq!(projects[0]["id"], "project-1");
    assert_eq!(projects[0]["name"], "Operations");
    assert_eq!(projects[0]["type"], "team");
    assert!(projects[1].get("type").is_none());
    assert_eq!(result["nextCursor"], "opaque-project-cursor");
    for project in projects {
        assert_no_untrusted_output(project);
        assert!(project.get("id").is_some());
        assert!(project.get("name").is_some());
        assert!(project.get("type").is_none() || project["type"].is_string());
    }
}

#[fcp_async_core::runtime::test]
async fn projects_list_uses_bounded_limit_and_opaque_cursor_encoding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/projects"))
        .and(query_param("limit", "200"))
        .and(query_param("cursor", "opaque cursor/%"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    invoke(
        &c,
        "n8n.projects.list",
        json!({"limit": 200, "cursor": "opaque cursor/%"}),
    )
    .await
    .unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn projects_list_missing_and_null_cursor_are_omitted() {
    for response in [json!({"data": []}), json!({"data": [], "nextCursor": null})] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;

        let c = setup_connector(&server.uri()).await;
        let result = invoke(&c, "n8n.projects.list", json!({})).await.unwrap();
        assert!(result.get("nextCursor").is_none());
    }
}

#[fcp_async_core::runtime::test]
async fn projects_list_rejects_invalid_input_without_http() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let mut invalid_inputs = vec![
        json!({"limit": 0}),
        json!({"limit": 201}),
        json!({"limit": -1}),
        json!({"limit": 1.5}),
        json!({"limit": "1"}),
        json!({"limit": true}),
        json!({"limit": null}),
        json!({"cursor": ""}),
        json!({"cursor": null}),
        json!({"cursor": 1}),
        json!({"cursor": "bad\ncursor"}),
        json!({"unknown": 1}),
    ];
    invalid_inputs.push(json!({"cursor": "x".repeat(4097)}));

    for input in invalid_inputs {
        assert!(invoke(&c, "n8n.projects.list", input).await.is_err());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn projects_list_rejects_malformed_provider_cursor() {
    for cursor in [json!(""), json!("bad\ncursor"), json!("x".repeat(4097))] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [],
                "nextCursor": cursor
            })))
            .mount(&server)
            .await;

        let c = setup_connector(&server.uri()).await;
        assert!(invoke(&c, "n8n.projects.list", json!({})).await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[fcp_async_core::runtime::test]
async fn projects_list_maps_provider_errors_without_leaking_body() {
    for status in [401, 403, 404, 429, 500, 503] {
        let server = MockServer::start().await;
        let mut response = ResponseTemplate::new(status).set_body_json(json!({
            "message": "marker.project.provider-error"
        }));
        if status == 429 {
            response = response.insert_header("retry-after", "30");
        }
        Mock::given(method("GET"))
            .and(path("/api/v1/projects"))
            .respond_with(response)
            .mount(&server)
            .await;

        let c = setup_connector(&server.uri()).await;
        let error = invoke(&c, "n8n.projects.list", json!({}))
            .await
            .expect_err("provider error should fail closed");
        assert!(!error.to_string().contains("marker.project.provider-error"));
    }
}

#[fcp_async_core::runtime::test]
async fn projects_list_rejects_bad_json() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/projects"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(invoke(&c, "n8n.projects.list", json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn credentials_list_uses_upstream_route_and_discards_secret_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/credentials"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .and(query_param("limit", "200"))
        .and(query_param("cursor", "opaque cursor/%"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{
                "id": "cred-1",
                "name": "GitHub",
                "type": "githubApi",
                "data": {"token": "marker.credential.secret"},
                "authHeader": "marker.credential.header",
                "config": {"password": "marker.credential.config"},
                "shared": [{"id": "project-1", "name": "Operations", "role": "credential:owner"}]
            }],
            "nextCursor": "opaque-next"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(
        &c,
        "n8n.credentials.list",
        json!({"limit": 200, "cursor": "opaque cursor/%"}),
    )
    .await
    .unwrap();
    assert_eq!(
        result,
        json!({
            "data": [{
                "resourceUri": "fwc-n8n://eec/credentials/cred%2D1",
                "id": "cred-1",
                "name": "GitHub",
                "type": "githubApi"
            }],
            "nextCursor": "opaque-next"
        })
    );
    let serialized = serde_json::to_string(&result).unwrap();
    for marker in [
        "marker.credential.secret",
        "marker.credential.header",
        "marker.credential.config",
        "shared",
    ] {
        assert!(!serialized.contains(marker));
    }
}

#[fcp_async_core::runtime::test]
async fn credentials_list_omits_missing_or_null_cursor_and_rejects_bad_provider_shape() {
    for response in [json!({"data": []}), json!({"data": [], "nextCursor": null})] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;
        let c = setup_connector(&server.uri()).await;
        let result = invoke(&c, "n8n.credentials.list", json!({})).await.unwrap();
        assert!(result.get("nextCursor").is_none());
    }

    for malformed in [
        json!({"data": [{"name": "missing-id", "type": "githubApi"}]}),
        json!({"data": [{"id": "cred1", "type": "githubApi"}]}),
        json!({"data": [{"id": "cred1", "name": "missing-type"}]}),
        json!({"data": [{"id": 42, "name": "wrong-id", "type": "githubApi"}]}),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(malformed))
            .mount(&server)
            .await;
        let c = setup_connector(&server.uri()).await;
        assert!(invoke(&c, "n8n.credentials.list", json!({})).await.is_err());
    }
}

#[fcp_async_core::runtime::test]
async fn credentials_list_classifies_invalid_provider_ids_as_malformed_without_echo() {
    for invalid_id in [
        "",
        " marker-id",
        "marker-id ",
        "marker/id",
        "marker\\id",
        "marker%id",
        "..",
        "marker\u{0001}id",
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [{
                    "id": invalid_id,
                    "name": "Safe credential",
                    "type": "githubApi"
                }]
            })))
            .mount(&server)
            .await;

        let c = setup_connector(&server.uri()).await;
        let error = invoke(&c, "n8n.credentials.list", json!({}))
            .await
            .expect_err("invalid provider credential ID must fail closed");
        assert!(matches!(
            &error,
            fcp_prelude::FcpError::External {
                service,
                status_code: None,
                retryable: false,
                ..
            } if service == "n8n"
        ));
        let rendered = error.to_string();
        assert!(rendered.contains("Malformed provider response"));
        if !invalid_id.is_empty() {
            assert!(!rendered.contains(invalid_id));
        }
    }
}

#[fcp_async_core::runtime::test]
async fn credentials_list_maps_statuses_and_bad_json_without_body_leaks() {
    for status in [401, 403, 404, 429, 500, 503] {
        let server = MockServer::start().await;
        let mut response = ResponseTemplate::new(status).set_body_json(json!({
            "message": "marker.credential.provider-error"
        }));
        if status == 429 {
            response = response.insert_header("retry-after", "30");
        }
        Mock::given(method("GET"))
            .and(path("/api/v1/credentials"))
            .respond_with(response)
            .mount(&server)
            .await;
        let c = setup_connector(&server.uri()).await;
        let error = invoke(&c, "n8n.credentials.list", json!({}))
            .await
            .expect_err("credential status must fail closed");
        assert!(
            !error
                .to_string()
                .contains("marker.credential.provider-error")
        );
    }

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
        .mount(&server)
        .await;
    let c = setup_connector(&server.uri()).await;
    assert!(invoke(&c, "n8n.credentials.list", json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn credentials_list_timeout_uses_shared_transport_error_mapping() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/credentials"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(100))
                .set_body_json(json!({"data": []})),
        )
        .mount(&server)
        .await;
    let c = setup_connector_with_runtime_config(
        json!({
            "api_key": "test-n8n-api-key-123",
            "server_id": TEST_SERVER_ID,
            "base_url": format!("{}/api/v1", server.uri()),
        }),
        ConnectorRuntimeConfig::default()
            .with_request_timeout(Duration::from_millis(20))
            .with_connect_timeout(Duration::from_secs(1)),
    )
    .await;
    let error = invoke(&c, "n8n.credentials.list", json!({}))
        .await
        .expect_err("credential timeout must fail closed");
    assert!(!error.to_string().contains("data"));
}

#[fcp_async_core::runtime::test]
async fn direct_provider_declared_oversized_success_fails_closed() {
    let server = MockServer::start().await;
    let marker = "marker.oversized.provider-body";
    let mut body = marker.as_bytes().to_vec();
    body.resize(MAX_PROVIDER_RESPONSE_BYTES + 1, b'x');
    Mock::given(method("GET"))
        .and(path("/api/v1/projects"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let error = invoke(&c, "n8n.projects.list", json!({}))
        .await
        .expect_err("declared oversized provider response must fail closed");
    assert!(!error.to_string().contains(marker));
}

#[fcp_async_core::runtime::test]
async fn direct_provider_chunked_oversized_success_fails_closed() {
    let server = MockServer::start().await;
    let marker = "marker.oversized.provider-body";
    let mut body = marker.as_bytes().to_vec();
    body.resize(MAX_PROVIDER_RESPONSE_BYTES + 1, b'x');
    Mock::given(method("GET"))
        .and(path("/api/v1/projects"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("transfer-encoding", "chunked")
                .set_body_bytes(body),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let error = invoke(&c, "n8n.projects.list", json!({}))
        .await
        .expect_err("chunked oversized provider response must fail closed");
    assert!(!error.to_string().contains(marker));
}

#[fcp_async_core::runtime::test]
async fn direct_provider_oversized_error_fails_closed_without_body() {
    let server = MockServer::start().await;
    let marker = "marker.oversized.provider-body";
    let mut body = marker.as_bytes().to_vec();
    body.resize(MAX_PROVIDER_RESPONSE_BYTES + 1, b'x');
    Mock::given(method("GET"))
        .and(path("/api/v1/projects"))
        .respond_with(ResponseTemplate::new(500).set_body_bytes(body))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let error = invoke(&c, "n8n.projects.list", json!({}))
        .await
        .expect_err("oversized provider error response must fail closed");
    assert!(!error.to_string().contains(marker));
}

#[fcp_async_core::runtime::test]
async fn direct_provider_response_at_safe_boundary_is_accepted() {
    let server = MockServer::start().await;
    let response = serde_json::to_vec(&json!({
        "data": [],
        "padding": "x".repeat(MAX_PROVIDER_RESPONSE_BYTES - 256),
    }))
    .expect("boundary response should serialize");
    assert!(response.len() <= MAX_PROVIDER_RESPONSE_BYTES);
    Mock::given(method("GET"))
        .and(path("/api/v1/projects"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(response))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.projects.list", json!({}))
        .await
        .expect("boundary-safe provider response should be accepted");
    assert_eq!(result["data"], json!([]));
}

#[fcp_async_core::runtime::test]
async fn projects_list_timeout_uses_shared_transport_error_mapping() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/projects"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(31))
                .set_body_json(json!({"data": []})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let error = invoke(&c, "n8n.projects.list", json!({}))
        .await
        .expect_err("provider timeout should fail closed");
    assert!(!error.to_string().contains("data"));
}

#[fcp_async_core::runtime::test]
async fn direct_provider_short_configured_timeout_fails_closed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/projects"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(100))
                .set_body_json(json!({"data": []})),
        )
        .mount(&server)
        .await;

    let c = setup_connector_with_runtime_config(
        json!({
            "api_key": "test-n8n-api-key-123",
            "server_id": TEST_SERVER_ID,
            "base_url": format!("{}/api/v1", server.uri()),
        }),
        ConnectorRuntimeConfig::default()
            .with_request_timeout(Duration::from_millis(20))
            .with_connect_timeout(Duration::from_secs(1)),
    )
    .await;
    let error = invoke(&c, "n8n.projects.list", json!({}))
        .await
        .expect_err("short configured request timeout must fail closed");
    assert!(!error.to_string().contains("data"));
}

#[fcp_async_core::runtime::test]
async fn mediated_projects_list_proxy_fixture_proves_wire_contract_and_safe_projection() {
    let request_id = "req_00000000000000000001";
    let correlation_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let proxy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rpc/egress/http"))
        .respond_with(MediatedProjectsResponse::json(
            200,
            &json!({
                "data": [{
                    "id": "project-mediated",
                    "name": "Mediated Operations",
                    "type": "team",
                    "users": [{"id": "marker.mediated.user"}],
                    "credentials": {"secret": "marker.mediated.secret"},
                    "unknown": "marker.mediated.unknown"
                }],
                "nextCursor": "next-mediated"
            }),
        ))
        .mount(&proxy)
        .await;

    let c = setup_mediated_connector(&proxy.uri()).await;
    let result = invoke_with_host_attribution(
        &c,
        "n8n.projects.list",
        json!({"limit": 200, "cursor": "opaque cursor/%"}),
        request_id,
        correlation_id,
    )
    .await
    .unwrap();

    assert_eq!(
        result,
        json!({
            "data": [{
                "id": "project-mediated",
                "name": "Mediated Operations",
                "type": "team"
            }],
            "nextCursor": "next-mediated"
        })
    );
    let requests = proxy.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "mediated read must be single-attempt");
    let envelope: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        envelope["url"],
        "https://n8n.example.com/api/v1/projects?limit=200&cursor=opaque+cursor%2F%25"
    );
    assert_eq!(envelope["method"], "GET");
    assert_eq!(
        envelope["headers"],
        json!([{"name": "Accept", "value": "application/json"}])
    );
    assert!(envelope.get("body").is_none());
    assert_eq!(
        envelope["credential_id"],
        "550e8400-e29b-41d4-a716-446655440000"
    );
    assert_eq!(envelope["context"]["connector_id"], "fcp.n8n");
    assert_eq!(envelope["context"]["operation_id"], "n8n.projects.list");
    assert_eq!(envelope["context"]["zone_id"], "z:work");
    let logical_resource = resource_uri("n8n.projects.list", &json!({}));
    assert_eq!(logical_resource, "fwc-n8n://eec");
    assert_eq!(envelope["context"]["resource_uri"], logical_resource);
    assert_ne!(envelope["url"], logical_resource);
    assert_eq!(envelope["context"]["request_id"], request_id);
    assert_eq!(envelope["context"]["correlation_id"], correlation_id);
    let capability_b64 = envelope["context"]["capability_token_cbor_b64"]
        .as_str()
        .unwrap();
    let capability_cbor = base64::engine::general_purpose::STANDARD
        .decode(capability_b64)
        .unwrap();
    assert!(!capability_cbor.is_empty());
    assert!(!capability_b64.starts_with("base64:"));
    let output = serde_json::to_string(&result).unwrap();
    for forbidden in [
        "capability_token",
        "550e8400-e29b-41d4-a716-446655440000",
        "fwc-n8n://eec",
        "marker.mediated",
    ] {
        assert!(!output.contains(forbidden));
    }
}

#[fcp_async_core::runtime::test]
async fn mediated_credential_reads_share_operation_resource_and_safe_get_contract() {
    let cases = vec![
        (
            "n8n.workflows.list",
            json!({}),
            json!({
                "data": [{"id": "w1", "name": "Safe workflow", "nodes": "marker.workflow"}]
            }),
            "https://n8n.example.com/api/v1/workflows?limit=50&excludePinnedData=true",
            "fwc-n8n://eec",
        ),
        (
            "n8n.workflows.get",
            json!({"id": "w1"}),
            json!({
                "id": "w1",
                "name": "Safe workflow",
                "active": false,
                "versionId": "draft-v1",
                "activeVersionId": null,
                "isArchived": false,
                "nodes": [{"id": "node-1", "parameters": {}}],
                "connections": {},
                "activeVersion": null,
                "pinData": "marker.workflow"
            }),
            "https://n8n.example.com/api/v1/workflows/w1",
            "fwc-n8n://eec/workflows/w1",
        ),
        (
            "n8n.executions.list",
            json!({}),
            json!({"data": [{"id": "e1", "finished": true, "data": "marker.execution"}]}),
            "https://n8n.example.com/api/v1/executions?limit=50&includeData=false&ignoreDataSizeLimit=false&redactExecutionData=true",
            "fwc-n8n://eec",
        ),
        (
            "n8n.executions.get",
            json!({"workflow_id": "w1", "id": "e1"}),
            json!({"id": "e1", "finished": true, "data": "marker.execution"}),
            "https://n8n.example.com/api/v1/executions/e1",
            "fwc-n8n://eec/workflows/w1/executions/e1",
        ),
        (
            "n8n.projects.list",
            json!({}),
            json!({"data": [{"id": "p1", "name": "Safe project", "credentials": "marker.project"}]}),
            "https://n8n.example.com/api/v1/projects?limit=50",
            "fwc-n8n://eec",
        ),
        (
            "n8n.credentials.list",
            json!({"limit": 200, "cursor": "opaque cursor/%"}),
            json!({
                "data": [{
                    "id": "cred-1",
                    "name": "Safe credential",
                    "type": "githubApi",
                    "data": {"token": "marker.credential.secret"},
                    "authHeader": "marker.credential.header",
                    "config": {"password": "marker.credential.config"}
                }],
                "nextCursor": null
            }),
            "https://n8n.example.com/api/v1/credentials?limit=200&cursor=opaque+cursor%2F%25",
            "fwc-n8n://eec",
        ),
        (
            "n8n.tags.list",
            json!({}),
            json!({"data": [{"id": "t1", "name": "Safe tag", "createdAt": "marker.tag"}]}),
            "https://n8n.example.com/api/v1/tags?limit=50",
            "fwc-n8n://eec",
        ),
        (
            "n8n.folders.list",
            json!({"project_id": "p1"}),
            json!({"count": 1, "data": [{"id": "f1", "name": "Safe folder", "parentFolder": null}]}),
            "https://n8n.example.com/api/v1/projects/p1/folders?select=%5B%22id%22%2C%22name%22%2C%22parentFolder%22%5D&skip=0&take=50",
            "fwc-n8n://eec/projects/p1",
        ),
        (
            "n8n.folders.get",
            json!({"project_id": "p1", "folder_id": "f1"}),
            json!({
                "id": "f1",
                "name": "Safe folder",
                "parentFolderId": null,
                "createdAt": "2024-01-01T00:00:00Z",
                "updatedAt": "2024-01-01T00:00:00Z",
                "totalSubFolders": 0,
                "totalWorkflows": 0,
                "unknown": "marker.folder"
            }),
            "https://n8n.example.com/api/v1/projects/p1/folders/f1",
            "fwc-n8n://eec/folders/f1",
        ),
    ];

    for (operation, input, body, expected_url, expected_resource) in cases {
        let proxy = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rpc/egress/http"))
            .respond_with(MediatedProjectsResponse::json(200, &body))
            .mount(&proxy)
            .await;

        let c = setup_mediated_connector(&proxy.uri()).await;
        let result = invoke(&c, operation, input).await.unwrap();
        let output = serde_json::to_string(&result).unwrap();
        assert!(
            !output.contains("marker."),
            "unsafe fields leaked for {operation}"
        );
        assert!(!output.contains("550e8400-e29b-41d4-a716-446655440000"));

        let requests = proxy.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "{operation} must be single-attempt");
        let envelope: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(envelope["context"]["operation_id"], operation);
        assert_eq!(envelope["context"]["resource_uri"], expected_resource);
        assert_eq!(envelope["url"], expected_url);
        assert_eq!(envelope["method"], "GET");
        assert_eq!(
            envelope["headers"],
            json!([{"name": "Accept", "value": "application/json"}])
        );
        assert!(envelope.get("body").is_none());
        assert_eq!(
            envelope["credential_id"],
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn mediated_draft_create_proves_exact_write_then_independent_readback() {
    let input = json!({
        "name": "Created workflow",
        "graph": {
            "nodes": [{"id": "node-1", "type": "n8n-nodes-base.noOp", "parameters": {}}],
            "connections": {}
        },
        "guard": {
            "approvalRef": "approval-create",
            "idempotencyKey": "00000000-0000-4000-8000-000000000101"
        }
    });
    let workflow = json!({
        "id": "wf-created",
        "name": "Created workflow",
        "active": false,
        "versionId": "draft-v1",
        "activeVersionId": null,
        "isArchived": false,
        "projectId": null,
        "nodes": input["graph"]["nodes"],
        "connections": {},
        "settings": {"availableInMCP": false, "callerPolicy": "workflowsFromSameOwner"},
        "activeVersion": null
    });
    let (responder, requests) = MediatedDraftResponse::new(vec![
        DraftReply {
            status: 200,
            body: json!({"id": "wf-created"}),
        },
        DraftReply {
            status: 200,
            body: workflow,
        },
    ]);
    let proxy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rpc/egress/http"))
        .respond_with(responder)
        .mount(&proxy)
        .await;

    let c = setup_mediated_connector(&proxy.uri()).await;
    let result = invoke(&c, "n8n.workflows.create_draft", input.clone())
        .await
        .unwrap();
    assert_eq!(result["status"], "verified");
    assert_eq!(result["id"], "wf-created");
    assert_eq!(result["provider"], "rest");
    assert_eq!(result["readback"], "independent_get");
    assert_eq!(result["active"], false);
    assert_eq!(result["activeVersionId"], Value::Null);
    assert_eq!(result["isArchived"], false);

    let requests = requests.lock().unwrap().clone();
    assert_eq!(
        requests.len(),
        2,
        "one write followed by one independent GET"
    );
    assert_eq!(requests[0]["method"], "POST");
    assert_eq!(
        requests[0]["url"],
        "https://n8n.example.com/api/v1/workflows"
    );
    assert_eq!(
        requests[0]["credential_id"],
        "550e8400-e29b-41d4-a716-446655440000"
    );
    assert_eq!(
        requests[0]["context"]["operation_id"],
        "n8n.workflows.create_draft"
    );
    assert_eq!(requests[0]["context"]["resource_uri"], "fwc-n8n://eec");
    assert_eq!(
        requests[0]["headers"],
        json!([
            {"name": "Accept", "value": "application/json"},
            {"name": "Content-Type", "value": "application/json"}
        ])
    );
    assert_eq!(
        mediated_request_payload(&requests[0]),
        json!({
            "name": "Created workflow",
            "nodes": input["graph"]["nodes"],
            "connections": {},
            "settings": {"availableInMCP": false}
        })
    );
    assert_eq!(requests[1]["method"], "GET");
    assert_eq!(
        requests[1]["url"],
        "https://n8n.example.com/api/v1/workflows/wf-created"
    );
    assert!(requests[1].get("body").is_none());
}

#[fcp_async_core::runtime::test]
async fn mediated_draft_create_canonicalizes_supplied_settings() {
    let input = json!({
        "name": "Settings workflow",
        "project_id": "project-1",
        "graph": {
            "nodes": [],
            "connections": {},
            "settings": {"executionOrder": "v1"}
        },
        "guard": {
            "approvalRef": "approval-settings",
            "idempotencyKey": "00000000-0000-4000-8000-000000000106"
        }
    });
    let workflow = json!({
        "id": "wf-settings",
        "name": "Settings workflow",
        "active": false,
        "versionId": "draft-v1",
        "activeVersionId": null,
        "isArchived": false,
        "projectId": "project-1",
        "nodes": [],
        "connections": {},
        "settings": {
            "executionOrder": "v1",
            "availableInMCP": false,
            "callerPolicy": "workflowsFromSameOwner"
        },
        "activeVersion": null
    });
    let (responder, requests) = MediatedDraftResponse::new(vec![
        DraftReply {
            status: 200,
            body: json!({"id": "wf-settings"}),
        },
        DraftReply {
            status: 200,
            body: workflow,
        },
    ]);
    let proxy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rpc/egress/http"))
        .respond_with(responder)
        .mount(&proxy)
        .await;

    let c = setup_mediated_connector(&proxy.uri()).await;
    invoke(&c, "n8n.workflows.create_draft", input)
        .await
        .expect("supplied settings create should verify");
    let requests = requests.lock().unwrap().clone();
    assert_eq!(
        mediated_request_payload(&requests[0])["settings"],
        json!({"executionOrder": "v1", "availableInMCP": false})
    );
}

#[fcp_async_core::runtime::test]
async fn mediated_draft_settings_rejection_stops_before_provider_dispatch() {
    let proxy = MockServer::start().await;
    let c = setup_mediated_connector(&proxy.uri()).await;
    for (index, setting) in [json!(true), json!("true"), json!({"nested": true})]
        .into_iter()
        .enumerate()
    {
        let input = json!({
            "name": "Rejected settings workflow",
            "project_id": "project-1",
            "graph": {"nodes": [], "connections": {}, "settings": {"availableInMCP": setting}},
            "guard": {
                "approvalRef": "approval-rejected-settings",
                "idempotencyKey": format!("00000000-0000-4000-8000-0000000001{:02}", index + 7)
            }
        });
        assert!(
            invoke(&c, "n8n.workflows.create_draft", input)
                .await
                .is_err()
        );
    }
    assert!(
        proxy.received_requests().await.unwrap().is_empty(),
        "rejected settings must not dispatch to provider"
    );
}

#[fcp_async_core::runtime::test]
async fn mediated_draft_credential_change_invalidates_prior_approval_without_raw_secret() {
    let original = json!({
        "name": "Credential-bound workflow",
        "project_id": "project-1",
        "graph": {
            "nodes": [{
                "id": "http-node",
                "type": "n8n-nodes-base.httpRequest",
                "credentials": {"httpBasicAuth": {"id": "credential-1"}}
            }],
            "connections": {}
        },
        "guard": {
            "approvalRef": "approval-credential-bound",
            "idempotencyKey": "00000000-0000-4000-8000-000000000105",
            "precondition": {}
        }
    });
    let approval = draft_approval_token("n8n.workflows.create_draft", &original);
    let mut changed = original.clone();
    changed["graph"]["nodes"][0]["credentials"]["httpBasicAuth"]["id"] = json!("credential-2");

    assert_eq!(draft_graph_digest(&original), draft_graph_digest(&changed));
    assert_ne!(
        draft_mutation_digest("n8n.workflows.create_draft", &original),
        draft_mutation_digest("n8n.workflows.create_draft", &changed)
    );
    let serialized_approval = serde_json::to_string(&approval).expect("approval JSON");
    assert!(!serialized_approval.contains("credential-1"));
    assert!(!serialized_approval.contains("credential-2"));
    let ApprovalScope::Execution(scope) = &approval.scope else {
        panic!("draft approval must use execution scope");
    };
    assert_eq!(
        scope.input_hash,
        Some(approval_binding_hash(
            "n8n.workflows.create_draft",
            &resource_uri("n8n.workflows.create_draft", &original),
            &original,
        ))
    );
    assert_ne!(
        scope.input_hash,
        Some(approval_binding_hash(
            "n8n.workflows.create_draft",
            &resource_uri("n8n.workflows.create_draft", &changed),
            &changed,
        ))
    );
    assert!(scope.input_constraints.is_empty());

    let proxy = MockServer::start().await;
    let c = setup_mediated_connector(&proxy.uri()).await;
    let result = invoke_with_approval(&c, "n8n.workflows.create_draft", changed, approval).await;
    assert!(matches!(result, Err(FcpError::CapabilityDenied { .. })));
    assert!(
        proxy.received_requests().await.unwrap().is_empty(),
        "credential-only approval mismatch must fail before provider dispatch"
    );
}

#[fcp_async_core::runtime::test]
async fn mediated_draft_update_preserves_lifecycle_and_published_state() {
    let published = json!({
        "versionId": "published-v1",
        "nodes": [{"id": "published-node"}],
        "connections": {}
    });
    let baseline = json!({
        "id": "wf-existing",
        "name": "Existing workflow",
        "settings": {
            "executionOrder": "v1",
            "saveDataErrorExecution": "all",
            "availableInMCP": true
        },
        "staticData": {"marker": "baseline-static"},
        "pinData": {"node-1": [{"json": {"marker": "baseline-pin"}}]},
        "active": true,
        "versionId": "draft-v1",
        "activeVersionId": "published-v1",
        "isArchived": false,
        "nodes": [{"id": "old-node"}],
        "connections": {},
        "activeVersion": published
    });
    let updated = json!({
        "id": "wf-existing",
        "name": "Existing workflow",
        "settings": {
            "executionOrder": "v1",
            "saveDataErrorExecution": "all",
            "availableInMCP": true
        },
        "staticData": {"marker": "baseline-static"},
        "pinData": {"node-1": [{"json": {"marker": "baseline-pin"}}]},
        "active": true,
        "versionId": "draft-v2",
        "activeVersionId": "published-v1",
        "isArchived": false,
        "nodes": [{"id": "new-node"}],
        "connections": {},
        "activeVersion": published
    });
    let input = json!({
        "id": "wf-existing",
        "graph": {
            "nodes": [{"id": "new-node"}],
            "connections": {}
        },
        "guard": {
            "approvalRef": "approval-update",
            "idempotencyKey": "00000000-0000-4000-8000-000000000102",
            "precondition": {
                "versionId": "draft-v1",
                "activeVersionId": "published-v1",
                "active": true,
                "isArchived": false,
                "stateDigest": workflow_state_digest_for_fixture(&baseline)
            }
        }
    });
    let (responder, requests) = MediatedDraftResponse::new_with_empty_second_body(vec![
        DraftReply {
            status: 200,
            body: baseline,
        },
        DraftReply {
            status: 200,
            body: json!({}),
        },
        DraftReply {
            status: 200,
            body: updated,
        },
    ]);
    let proxy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rpc/egress/http"))
        .respond_with(responder)
        .mount(&proxy)
        .await;

    let c = setup_mediated_connector(&proxy.uri()).await;
    let result = invoke(&c, "n8n.workflows.update_draft", input)
        .await
        .unwrap();
    assert_eq!(result["status"], "verified");
    assert_eq!(result["versionId"], "draft-v2");
    assert_eq!(result["active"], true);
    assert_eq!(result["activeVersionId"], "published-v1");
    assert_eq!(result["isArchived"], false);

    let requests = requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 3, "preflight GET, one PUT, independent GET");
    assert_eq!(requests[0]["method"], "GET");
    assert_eq!(requests[1]["method"], "PUT");
    assert_eq!(
        requests[1]["url"],
        "https://n8n.example.com/api/v1/workflows/wf-existing"
    );
    assert_eq!(
        requests[1]["context"]["operation_id"],
        "n8n.workflows.update_draft"
    );
    assert_eq!(
        requests[1]["context"]["resource_uri"],
        "fwc-n8n://eec/workflows/wf%2Dexisting"
    );
    assert_eq!(
        mediated_request_payload(&requests[1]),
        json!({
            "name": "Existing workflow",
            "settings": {
                "executionOrder": "v1",
                "saveDataErrorExecution": "all",
                "availableInMCP": true
            },
            "staticData": {"marker": "baseline-static"},
            "pinData": {"node-1": [{"json": {"marker": "baseline-pin"}}]},
            "nodes": [{"id": "new-node"}],
            "connections": {}
        })
    );
    for lifecycle_field in ["active", "activeVersionId", "isArchived", "versionId"] {
        assert!(
            mediated_request_payload(&requests[1])
                .get(lifecycle_field)
                .is_none(),
            "PUT must not infer lifecycle field {lifecycle_field}"
        );
    }
    assert!(requests[1]["body"].as_str().is_some());
    assert_eq!(requests[2]["method"], "GET");
    assert_eq!(
        requests[2]["url"],
        "https://n8n.example.com/api/v1/workflows/wf-existing"
    );
}

#[fcp_async_core::runtime::test]
async fn mediated_draft_update_canonicalizes_supplied_settings_and_preserves_lifecycle() {
    let published = json!({
        "versionId": "published-v1",
        "nodes": [{"id": "published-node"}],
        "connections": {}
    });
    let baseline = json!({
        "id": "wf-settings-update",
        "name": "Settings update workflow",
        "settings": {
            "executionOrder": "v1",
            "saveDataSuccessExecution": "all",
            "availableInMCP": true
        },
        "active": true,
        "versionId": "draft-v1",
        "activeVersionId": "published-v1",
        "isArchived": false,
        "nodes": [{"id": "old-node"}],
        "connections": {},
        "activeVersion": published
    });
    let updated = json!({
        "id": "wf-settings-update",
        "name": "Settings update workflow",
        "settings": {
            "executionOrder": "v2",
            "saveDataSuccessExecution": "all",
            "availableInMCP": true,
            "callerPolicy": "workflowsFromSameOwner"
        },
        "active": true,
        "versionId": "draft-v2",
        "activeVersionId": "published-v1",
        "isArchived": false,
        "nodes": [{"id": "new-node"}],
        "connections": {},
        "activeVersion": published
    });
    let input = json!({
        "id": "wf-settings-update",
        "graph": {
            "nodes": [{"id": "new-node"}],
            "connections": {},
            "settings": {"executionOrder": "v2"}
        },
        "guard": {
            "approvalRef": "approval-settings-update",
            "idempotencyKey": "00000000-0000-4000-8000-000000000110",
            "precondition": {
                "versionId": "draft-v1",
                "activeVersionId": "published-v1",
                "active": true,
                "isArchived": false,
                "stateDigest": workflow_state_digest_for_fixture(&baseline)
            }
        }
    });
    let (responder, requests) = MediatedDraftResponse::new(vec![
        DraftReply {
            status: 200,
            body: baseline,
        },
        DraftReply {
            status: 204,
            body: json!({}),
        },
        DraftReply {
            status: 200,
            body: updated,
        },
    ]);
    let proxy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rpc/egress/http"))
        .respond_with(responder)
        .mount(&proxy)
        .await;

    let c = setup_mediated_connector(&proxy.uri()).await;
    let result = invoke(&c, "n8n.workflows.update_draft", input)
        .await
        .expect("supplied settings update should verify");
    assert_eq!(result["active"], true);
    assert_eq!(result["activeVersionId"], "published-v1");
    assert_eq!(result["isArchived"], false);

    let requests = requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 3, "preflight GET, one PUT, independent GET");
    assert_eq!(
        mediated_request_payload(&requests[1])["settings"],
        json!({
            "executionOrder": "v2",
            "saveDataSuccessExecution": "all",
            "availableInMCP": true
        })
    );
    for lifecycle_field in ["active", "activeVersionId", "isArchived", "versionId"] {
        assert!(
            mediated_request_payload(&requests[1])
                .get(lifecycle_field)
                .is_none(),
            "PUT must not infer lifecycle field {lifecycle_field}"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn mediated_draft_stale_precondition_stops_before_write() {
    let baseline = json!({
        "id": "wf-stale",
        "name": "Stale workflow",
        "active": false,
        "versionId": "draft-v1",
        "activeVersionId": null,
        "isArchived": false,
        "nodes": [{"id": "old-node"}],
        "connections": {},
        "activeVersion": null
    });
    let input = json!({
        "id": "wf-stale",
        "graph": {"nodes": [{"id": "new-node"}], "connections": {}},
        "guard": {
            "approvalRef": "approval-stale",
            "idempotencyKey": "00000000-0000-4000-8000-000000000103",
            "precondition": {
                "versionId": "stale-version",
                "activeVersionId": null,
                "active": false,
                "isArchived": false,
                "stateDigest": workflow_state_digest_for_fixture(&baseline)
            }
        }
    });
    let (responder, requests) = MediatedDraftResponse::new(vec![DraftReply {
        status: 200,
        body: baseline,
    }]);
    let proxy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rpc/egress/http"))
        .respond_with(responder)
        .mount(&proxy)
        .await;

    let c = setup_mediated_connector(&proxy.uri()).await;
    assert!(
        invoke(&c, "n8n.workflows.update_draft", input)
            .await
            .is_err()
    );
    let requests = requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["method"], "GET");
    assert!(requests.iter().all(|request| request["method"] != "PUT"));
}

#[fcp_async_core::runtime::test]
async fn mediated_draft_readback_mismatch_stops_without_fallback() {
    let input = json!({
        "name": "Mismatch workflow",
        "project_id": "project-1",
        "graph": {"nodes": [{"id": "expected-node"}], "connections": {}},
        "guard": {
            "approvalRef": "approval-mismatch",
            "idempotencyKey": "00000000-0000-4000-8000-000000000104"
        }
    });
    let mismatched = json!({
        "id": "wf-mismatch",
        "name": "Mismatch workflow",
        "active": false,
        "versionId": "draft-v1",
        "activeVersionId": null,
        "isArchived": false,
        "nodes": [{"id": "different-node"}],
        "connections": {},
        "activeVersion": null
    });
    let (responder, requests) = MediatedDraftResponse::new(vec![
        DraftReply {
            status: 200,
            body: json!({"id": "wf-mismatch"}),
        },
        DraftReply {
            status: 200,
            body: mismatched,
        },
    ]);
    let proxy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rpc/egress/http"))
        .respond_with(responder)
        .mount(&proxy)
        .await;

    let c = setup_mediated_connector(&proxy.uri()).await;
    let error = invoke(&c, "n8n.workflows.create_draft", input)
        .await
        .expect_err("mismatched readback must fail closed");
    assert!(matches!(
        error,
        FcpError::External {
            retryable: false,
            ..
        }
    ));
    let requests = requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["method"], "POST");
    assert_eq!(requests[1]["method"], "GET");
}

#[fcp_async_core::runtime::test]
async fn mediated_draft_unknown_or_malformed_write_never_falls_back_or_retries() {
    let inputs = [
        (503, json!({"provider": "unavailable"})),
        (200, json!("malformed")),
    ];
    for (status, body) in inputs {
        let input = json!({
            "name": "Unknown workflow",
            "project_id": "project-1",
            "graph": {"nodes": [{"id": "node-1"}], "connections": {}},
            "guard": {
                "approvalRef": "approval-unknown",
                "idempotencyKey": format!("00000000-0000-4000-8000-000000000{}", status)
            }
        });
        let (responder, requests) = MediatedDraftResponse::new(vec![DraftReply { status, body }]);
        let proxy = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rpc/egress/http"))
            .respond_with(responder)
            .mount(&proxy)
            .await;

        let c = setup_mediated_connector(&proxy.uri()).await;
        let error = invoke(&c, "n8n.workflows.create_draft", input)
            .await
            .expect_err("ambiguous write must fail closed");
        assert!(matches!(
            error,
            FcpError::External {
                retryable: false,
                ..
            }
        ));
        let requests = requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 1, "no fallback GET or automatic retry");
    }
}

#[fcp_async_core::runtime::test]
async fn every_credential_read_fails_closed_without_proxy_or_on_proxy_rejection() {
    let cases = [
        ("n8n.workflows.list", json!({})),
        ("n8n.workflows.get", json!({"id": "w1"})),
        ("n8n.executions.list", json!({})),
        (
            "n8n.executions.get",
            json!({"workflow_id": "w1", "id": "e1"}),
        ),
        ("n8n.projects.list", json!({})),
        ("n8n.credentials.list", json!({})),
        ("n8n.tags.list", json!({})),
        ("n8n.folders.list", json!({"project_id": "p1"})),
        (
            "n8n.folders.get",
            json!({"project_id": "p1", "folder_id": "f1"}),
        ),
    ];

    for (operation, input) in &cases {
        let proxy = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rpc/egress/http"))
            .respond_with(
                ResponseTemplate::new(503)
                    .set_body_string("marker.proxy.rejection credential 550e8400"),
            )
            .mount(&proxy)
            .await;
        let c = setup_mediated_connector(&proxy.uri()).await;
        let error = invoke(&c, operation, input.clone())
            .await
            .expect_err(operation);
        assert!(!error.to_string().contains("marker.proxy.rejection"));
        assert!(!error.to_string().contains("550e8400"));
        assert_eq!(proxy.received_requests().await.unwrap().len(), 1);
    }

    for (operation, input) in &cases {
        let proxy = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rpc/egress/http"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
            .mount(&proxy)
            .await;
        let c = setup_mediated_connector(&proxy.uri()).await;
        let error = invoke(&c, operation, input.clone())
            .await
            .expect_err("malformed proxy response must fail closed");
        assert!(!error.to_string().contains("not-json"));
        assert_eq!(proxy.received_requests().await.unwrap().len(), 1);
    }

    for (operation, input) in &cases {
        let c = setup_connector_with_config(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "server_id": TEST_SERVER_ID,
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .await;
        assert!(invoke(&c, operation, input.clone()).await.is_err());
    }
}

#[fcp_async_core::runtime::test]
async fn mediated_projects_list_preserves_provider_status_taxonomy_without_body_leaks() {
    for status in [401, 403, 404, 429, 500, 503] {
        let proxy = MockServer::start().await;
        let mut response = MediatedProjectsResponse::json(
            status,
            &json!({"message": "marker.mediated.provider-error"}),
        );
        if status == 429 {
            response.retry_after = Some("30");
        }
        Mock::given(method("POST"))
            .and(path("/rpc/egress/http"))
            .respond_with(response)
            .mount(&proxy)
            .await;
        let c = setup_mediated_connector(&proxy.uri()).await;
        let error = invoke(&c, "n8n.projects.list", json!({}))
            .await
            .expect_err("provider status must fail closed");
        assert!(!error.to_string().contains("marker.mediated.provider-error"));
        assert_eq!(proxy.received_requests().await.unwrap().len(), 1);
    }
}

#[fcp_async_core::runtime::test]
async fn mediated_projects_list_host_rejections_and_malformed_payloads_fail_once() {
    for host_status in [401, 403, 404, 429, 500, 503] {
        let proxy = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rpc/egress/http"))
            .respond_with(
                ResponseTemplate::new(host_status)
                    .set_body_string("marker.host.rejection credential 550e8400"),
            )
            .mount(&proxy)
            .await;
        let c = setup_mediated_connector(&proxy.uri()).await;
        let error = invoke(&c, "n8n.projects.list", json!({}))
            .await
            .expect_err("host rejection must fail closed");
        assert!(!error.to_string().contains("marker.host.rejection"));
        let received = proxy.received_requests().await.unwrap();
        let request_shapes = received
            .iter()
            .map(|request| format!("{} {}", request.method, request.url.path()))
            .collect::<Vec<_>>();
        assert_eq!(
            received.len(),
            1,
            "host rejection status {host_status} must issue exactly one proxy request; received {request_shapes:?}"
        );
    }

    let malformed_json_proxy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rpc/egress/http"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
        .mount(&malformed_json_proxy)
        .await;
    let c = setup_mediated_connector(&malformed_json_proxy.uri()).await;
    assert!(invoke(&c, "n8n.projects.list", json!({})).await.is_err());
    assert_eq!(
        malformed_json_proxy
            .received_requests()
            .await
            .unwrap()
            .len(),
        1
    );

    let malformed_decision_proxy = MockServer::start().await;
    let mut response = MediatedProjectsResponse::json(200, &json!({"data": []}));
    response.malformed_decision = true;
    Mock::given(method("POST"))
        .and(path("/rpc/egress/http"))
        .respond_with(response)
        .mount(&malformed_decision_proxy)
        .await;
    let c = setup_mediated_connector(&malformed_decision_proxy.uri()).await;
    assert!(invoke(&c, "n8n.projects.list", json!({})).await.is_err());
    assert_eq!(
        malformed_decision_proxy
            .received_requests()
            .await
            .unwrap()
            .len(),
        1
    );

    let malformed_provider_body_proxy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rpc/egress/http"))
        .respond_with(MediatedProjectsResponse {
            status: 200,
            body: b"{not-provider-json".to_vec(),
            retry_after: None,
            malformed_decision: false,
        })
        .mount(&malformed_provider_body_proxy)
        .await;
    let c = setup_mediated_connector(&malformed_provider_body_proxy.uri()).await;
    assert!(invoke(&c, "n8n.projects.list", json!({})).await.is_err());
    assert_eq!(
        malformed_provider_body_proxy
            .received_requests()
            .await
            .unwrap()
            .len(),
        1
    );
}

#[fcp_async_core::runtime::test]
async fn mediated_projects_list_missing_or_failed_proxy_has_no_direct_fallback() {
    let no_proxy = setup_connector_with_config(json!({
        "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        "server_id": TEST_SERVER_ID,
        "base_url": "https://n8n.example.com/api/v1",
    }))
    .await;
    assert!(
        invoke(&no_proxy, "n8n.projects.list", json!({}))
            .await
            .is_err()
    );

    // Keep the transport-failure endpoint outside wiremock's ephemeral port
    // pool. Dropping a MockServer here lets another parallel test immediately
    // reuse the same port, turning this request into cross-test traffic.
    let c = setup_mediated_connector("http://127.0.0.1:1").await;
    assert!(invoke(&c, "n8n.projects.list", json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn mediated_projects_list_rejects_oversized_host_body() {
    let proxy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rpc/egress/http"))
        .respond_with(MediatedProjectsResponse {
            status: 200,
            body: vec![b'x'; 10 * 1024 * 1024 + 1],
            retry_after: None,
            malformed_decision: false,
        })
        .mount(&proxy)
        .await;
    let c = setup_mediated_connector(&proxy.uri()).await;
    assert!(invoke(&c, "n8n.projects.list", json!({})).await.is_err());
    assert_eq!(proxy.received_requests().await.unwrap().len(), 1);
}

// -- Folders List/Get --

#[fcp_async_core::runtime::test]
async fn folders_list_projects_parent_shapes_and_fixed_projection() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(query_param("select", r#"["id","name","parentFolder"]"#))
        .and(query_param(
            "filter",
            r#"{"parentFolderId":"parent folder"}"#,
        ))
        .and(query_param("skip", "7"))
        .and(query_param("take", "200"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "count": 2,
            "data": [
                {
                    "id": "folder root",
                    "name": "Root",
                    "parentFolder": null,
                    "secret": "marker.folder.secret"
                },
                {
                    "id": "folder child",
                    "name": "Child",
                    "parentFolder": {
                        "id": "parent folder",
                        "secret": "marker.parent.secret"
                    },
                    "createdAt": "marker.folder.created"
                }
            ],
            "unknownField": "marker.folder.unknown"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(
        &c,
        "n8n.folders.list",
        json!({
            "project_id": "project one",
            "parent_folder_id": "parent folder",
            "skip": 7,
            "take": 200
        }),
    )
    .await
    .unwrap();

    assert_eq!(result["count"], 2);
    let folders = result["data"].as_array().unwrap();
    assert_eq!(folders.len(), 2);
    assert_eq!(
        folders[0]["resourceUri"],
        "fwc-n8n://eec/folders/folder%20root"
    );
    assert_eq!(folders[0]["parentFolderId"], Value::Null);
    assert_eq!(folders[1]["parentFolderId"], "parent folder");
    assert_eq!(
        folders[1]["resourceUri"],
        "fwc-n8n://eec/folders/folder%20child"
    );
    for folder in folders {
        assert_no_untrusted_output(folder);
        assert_eq!(folder.as_object().unwrap().len(), 4);
    }

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url.path(),
        "/api/v1/projects/project%20one/folders"
    );
}

#[fcp_async_core::runtime::test]
async fn folders_list_defaults_and_root_filter_omission_are_exact() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(query_param("select", r#"["id","name","parentFolder"]"#))
        .and(query_param("skip", "0"))
        .and(query_param("take", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "count": 0,
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    invoke(&c, "n8n.folders.list", json!({"project_id": "project-1"}))
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/api/v1/projects/project-1/folders");
    assert!(!requests[0].url.query().unwrap().contains("filter="));
}

#[fcp_async_core::runtime::test]
async fn folders_get_is_strictly_projected_and_uses_folder_uri() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "folder one",
            "name": "Folder",
            "parentFolderId": null,
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-02T00:00:00Z",
            "totalSubFolders": 3,
            "totalWorkflows": 8,
            "credentials": "marker.folder.credentials",
            "unknownField": "marker.folder.unknown"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(
        &c,
        "n8n.folders.get",
        json!({"project_id": "project one", "folder_id": "folder one"}),
    )
    .await
    .unwrap();

    assert_eq!(result["resourceUri"], "fwc-n8n://eec/folders/folder%20one");
    assert_eq!(result["parentFolderId"], Value::Null);
    assert_eq!(result["totalSubFolders"], 3);
    assert_eq!(result["totalWorkflows"], 8);
    assert_eq!(result.as_object().unwrap().len(), 8);
    assert_no_untrusted_output(&result);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests[0].url.path(),
        "/api/v1/projects/project%20one/folders/folder%20one"
    );
}

#[fcp_async_core::runtime::test]
async fn folders_reject_invalid_input_and_ids_before_http() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    for input in [
        json!({}),
        json!({"project_id": "project-1", "unknown": true}),
        json!({"project_id": "project-1", "skip": -1}),
        json!({"project_id": "project-1", "take": 0}),
        json!({"project_id": "project-1", "take": 201}),
        json!({"project_id": "project-1", "take": "50"}),
        json!({"project_id": "project-1", "parent_folder_id": null}),
        json!({"project_id": "project/1"}),
        json!({"project_id": "project-1", "server_id": "eec"}),
    ] {
        let operation = if input.get("folder_id").is_some() {
            "n8n.folders.get"
        } else {
            "n8n.folders.list"
        };
        assert!(invoke(&c, operation, input).await.is_err());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn folders_get_rejects_invalid_ids_before_http() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    for folder_id in ["", "folder/id", "folder%2Fid", " folder", "folder\n"] {
        assert!(
            invoke(
                &c,
                "n8n.folders.get",
                json!({"project_id": "project-1", "folder_id": folder_id}),
            )
            .await
            .is_err()
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn folders_capability_resources_bind_project_for_list_and_folder_for_get() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let list_input = json!({"project_id": "project-1"});
    let get_input = json!({"project_id": "project-1", "folder_id": "folder-1"});
    for (operation, input, wrong_resource) in [
        (
            "n8n.folders.list",
            &list_input,
            "fwc-n8n://eec/folders/folder-1",
        ),
        (
            "n8n.folders.get",
            &get_input,
            "fwc-n8n://eec/projects/project-1",
        ),
    ] {
        let params = json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_token_with_options(
                operation,
                &test_signing_key(),
                TEST_INSTANCE_ID,
                wrong_resource.into(),
                chrono::Utc::now() - chrono::Duration::seconds(1),
                chrono::Utc::now() + chrono::Duration::hours(1),
            )
        });
        assert!(c.handle_invoke(params).await.is_err());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn credentials_capability_resource_binds_to_instance() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let params = json!({
        "operation": "n8n.credentials.list",
        "input": {},
        "capability_token": capability_token_with_options(
            "n8n.credentials.list",
            &test_signing_key(),
            TEST_INSTANCE_ID,
            "fwc-n8n://eec/projects/project-1".into(),
            chrono::Utc::now() - chrono::Duration::seconds(1),
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
    });
    assert!(c.handle_invoke(params).await.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn folders_get_missing_provider_fields_fails_closed() {
    let fields = [
        "id",
        "name",
        "parentFolderId",
        "createdAt",
        "updatedAt",
        "totalSubFolders",
        "totalWorkflows",
    ];
    for missing in fields {
        let server = MockServer::start().await;
        let mut body = json!({
            "id": "folder-1",
            "name": "Folder",
            "parentFolderId": null,
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-02T00:00:00Z",
            "totalSubFolders": 3,
            "totalWorkflows": 8
        });
        body.as_object_mut().unwrap().remove(missing);
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        let c = setup_connector(&server.uri()).await;
        assert!(
            invoke(
                &c,
                "n8n.folders.get",
                json!({"project_id": "project-1", "folder_id": "folder-1"}),
            )
            .await
            .is_err()
        );
    }
}

#[fcp_async_core::runtime::test]
async fn folders_get_rejects_provider_id_mismatch_without_leaking() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "provider-folder-id",
            "name": "Folder",
            "parentFolderId": null,
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-02T00:00:00Z",
            "totalSubFolders": 3,
            "totalWorkflows": 8,
            "unknownField": "marker.folder.mismatched-provider"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let error = invoke(
        &c,
        "n8n.folders.get",
        json!({"project_id": "project-1", "folder_id": "folder-1"}),
    )
    .await
    .expect_err("provider ID mismatch should fail closed");
    let error = error.to_string();
    assert!(!error.contains("provider-folder-id"));
    assert!(!error.contains("marker.folder.mismatched-provider"));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn folders_provider_errors_are_safe_and_non_leaking() {
    for status in [400, 401, 403, 404, 429, 500, 503] {
        let server = MockServer::start().await;
        let mut response = ResponseTemplate::new(status).set_body_json(json!({
            "message": "marker.folder.provider-error"
        }));
        if status == 429 {
            response = response.insert_header("retry-after", "30");
        }
        Mock::given(method("GET"))
            .respond_with(response)
            .mount(&server)
            .await;
        let c = setup_connector(&server.uri()).await;
        let error = invoke(
            &c,
            "n8n.folders.get",
            json!({"project_id": "project-1", "folder_id": "folder-1"}),
        )
        .await
        .expect_err("provider error should fail closed");
        assert!(!error.to_string().contains("marker.folder.provider-error"));
    }
}

#[fcp_async_core::runtime::test]
async fn folders_list_provider_errors_are_safe_and_non_leaking() {
    for status in [400, 401, 403, 404, 429, 500, 503] {
        let server = MockServer::start().await;
        let mut response = ResponseTemplate::new(status).set_body_json(json!({
            "message": "marker.folder.list-provider-error"
        }));
        if status == 429 {
            response = response.insert_header("retry-after", "30");
        }
        Mock::given(method("GET"))
            .respond_with(response)
            .mount(&server)
            .await;
        let c = setup_connector(&server.uri()).await;
        let error = invoke(&c, "n8n.folders.list", json!({"project_id": "project-1"}))
            .await
            .expect_err("provider error should fail closed");
        assert!(
            !error
                .to_string()
                .contains("marker.folder.list-provider-error")
        );
    }
}

#[fcp_async_core::runtime::test]
async fn folders_bad_json_and_timeout_fail_closed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
        .mount(&server)
        .await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        invoke(
            &c,
            "n8n.folders.get",
            json!({"project_id": "project-1", "folder_id": "folder-1"}),
        )
        .await
        .is_err()
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(31))
                .set_body_json(json!({
                    "id": "folder-1",
                    "name": "Folder",
                    "parentFolderId": null,
                    "createdAt": "2026-01-01T00:00:00Z",
                    "updatedAt": "2026-01-02T00:00:00Z",
                    "totalSubFolders": 0,
                    "totalWorkflows": 0
                })),
        )
        .mount(&server)
        .await;
    let c = setup_connector(&server.uri()).await;
    let error = invoke(
        &c,
        "n8n.folders.get",
        json!({"project_id": "project-1", "folder_id": "folder-1"}),
    )
    .await
    .expect_err("provider timeout should fail closed");
    assert!(!error.to_string().contains("marker.folder"));
}

#[fcp_async_core::runtime::test]
async fn folders_list_bad_json_and_timeout_fail_closed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
        .mount(&server)
        .await;
    let c = setup_connector(&server.uri()).await;
    let error = invoke(&c, "n8n.folders.list", json!({"project_id": "project-1"}))
        .await
        .expect_err("malformed provider JSON should fail closed");
    assert!(!error.to_string().contains("marker.folder.list"));

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(31))
                .set_body_json(json!({"count": 0, "data": []})),
        )
        .mount(&server)
        .await;
    let c = setup_connector(&server.uri()).await;
    let error = invoke(&c, "n8n.folders.list", json!({"project_id": "project-1"}))
        .await
        .expect_err("provider timeout should fail closed");
    assert!(!error.to_string().contains("marker.folder"));
}

// -- Tags List --

#[fcp_async_core::runtime::test]
async fn tags_list_returns_only_compact_safe_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/tags"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .and(query_param("limit", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "id": "tag-1",
                    "name": "production",
                    "createdAt": "marker.tag.created",
                    "updatedAt": "marker.tag.updated",
                    "users": [{"id": "marker.tag.users"}],
                    "unknownField": "marker.tag.unknown"
                },
                {
                    "id": "tag-2",
                    "name": "reporting",
                    "createdAt": "marker.tag.created",
                    "updatedAt": "marker.tag.updated"
                }
            ],
            "nextCursor": "opaque-tag-cursor"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.tags.list", json!({})).await.unwrap();
    let tags = result["data"].as_array().unwrap();
    assert_eq!(tags.len(), 2);
    assert_eq!(tags[0]["id"], "tag-1");
    assert_eq!(tags[0]["name"], "production");
    assert_eq!(result["nextCursor"], "opaque-tag-cursor");
    for tag in tags {
        assert_compact_tag_output(tag);
    }
}

#[fcp_async_core::runtime::test]
async fn tags_list_uses_bounded_limit_and_opaque_cursor_encoding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/tags"))
        .and(query_param("limit", "200"))
        .and(query_param("cursor", "opaque cursor/%"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    invoke(
        &c,
        "n8n.tags.list",
        json!({"limit": 200, "cursor": "opaque cursor/%"}),
    )
    .await
    .unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn tags_list_missing_and_null_cursor_are_omitted() {
    for response in [json!({"data": []}), json!({"data": [], "nextCursor": null})] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;

        let c = setup_connector(&server.uri()).await;
        let result = invoke(&c, "n8n.tags.list", json!({})).await.unwrap();
        assert!(result.get("nextCursor").is_none());
    }
}

#[fcp_async_core::runtime::test]
async fn tags_list_rejects_invalid_input_without_http() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let mut invalid_inputs = vec![
        json!({"limit": 0}),
        json!({"limit": 201}),
        json!({"limit": -1}),
        json!({"limit": 1.5}),
        json!({"limit": "1"}),
        json!({"limit": true}),
        json!({"limit": null}),
        json!({"cursor": ""}),
        json!({"cursor": null}),
        json!({"cursor": 1}),
        json!({"cursor": "bad\ncursor"}),
        json!({"unknown": 1}),
    ];
    invalid_inputs.push(json!({"cursor": "x".repeat(4097)}));

    for input in invalid_inputs {
        assert!(invoke(&c, "n8n.tags.list", input).await.is_err());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn tags_list_rejects_malformed_provider_cursor() {
    for cursor in [json!(""), json!("bad\ncursor"), json!("x".repeat(4097))] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [],
                "nextCursor": cursor
            })))
            .mount(&server)
            .await;

        let c = setup_connector(&server.uri()).await;
        assert!(invoke(&c, "n8n.tags.list", json!({})).await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[fcp_async_core::runtime::test]
async fn tags_list_maps_provider_errors_without_leaking_body() {
    for status in [401, 403, 404, 429, 500, 503] {
        let server = MockServer::start().await;
        let mut response = ResponseTemplate::new(status).set_body_json(json!({
            "message": "marker.tag.provider-error"
        }));
        if status == 429 {
            response = response.insert_header("retry-after", "30");
        }
        Mock::given(method("GET"))
            .and(path("/api/v1/tags"))
            .respond_with(response)
            .mount(&server)
            .await;

        let c = setup_connector(&server.uri()).await;
        let error = invoke(&c, "n8n.tags.list", json!({}))
            .await
            .expect_err("provider error should fail closed");
        assert!(!error.to_string().contains("marker.tag.provider-error"));
    }
}

#[fcp_async_core::runtime::test]
async fn tags_list_rejects_bad_json() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(invoke(&c, "n8n.tags.list", json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn tags_list_timeout_uses_shared_transport_error_mapping() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/tags"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(31))
                .set_body_json(json!({"data": []})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let error = invoke(&c, "n8n.tags.list", json!({}))
        .await
        .expect_err("provider timeout should fail closed");
    assert!(!error.to_string().contains("data"));
}

// -- Workflows Get --

#[fcp_async_core::runtime::test]
async fn mcp_access_dry_run_normalizes_rest_omitted_false() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/wf-rest-default-off"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "wf-rest-default-off",
            "name": "REST default-off MCP",
            "active": false,
            "versionId": "draft-v1",
            "activeVersionId": null,
            "isArchived": false,
            "nodes": [{"id": "manual"}],
            "connections": {},
            "settings": {"executionOrder": "v1"},
            "activeVersion": null
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(
        &c,
        "n8n.mcp_access.reconcile",
        json!({
            "scope": "workflow_ids",
            "workflowIds": ["wf-rest-default-off"],
            "desired": true,
            "dryRun": true
        }),
    )
    .await
    .expect("REST omitted false should be a planned change");

    assert_eq!(result["planned"][0]["id"], "wf-rest-default-off");
    assert_eq!(result["planned"][0]["availableInMCP"], false);
    assert!(result["exceptions"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn mcp_access_apply_preserves_workflow_payload_and_independent_readback() {
    let server = MockServer::start().await;
    let baseline = json!({
        "id": "wf-mcp",
        "name": "Disposable MCP test",
        "description": null,
        "active": false,
        "versionId": "draft-v1",
        "activeVersionId": null,
        "isArchived": false,
        "projectId": "project-test",
        "parentFolderId": null,
        "updatedAt": "2026-08-19T00:00:00Z",
        "nodes": [{"id": "manual", "type": "n8n-nodes-base.manualTrigger"}],
        "connections": {},
        "settings": {"availableInMCP": false},
        "activeVersion": null
    });
    let readback = json!({
        "id": "wf-mcp",
        "name": "Disposable MCP test",
        "description": null,
        "active": false,
        "versionId": "draft-v1",
        "activeVersionId": null,
        "isArchived": false,
        "projectId": "project-test",
        "parentFolderId": null,
        "updatedAt": "2026-08-19T00:00:01Z",
        "nodes": [{"id": "manual", "type": "n8n-nodes-base.manualTrigger"}],
        "connections": {},
        "settings": {"availableInMCP": true},
        "activeVersion": null
    });
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/wf-mcp"))
        .respond_with(SequentialJsonResponse::new(vec![
            baseline.clone(),
            baseline.clone(),
            baseline,
            readback,
        ]))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/workflows/wf-mcp"))
        .and(body_json(json!({
            "name": "Disposable MCP test",
            "nodes": [{"id": "manual", "type": "n8n-nodes-base.manualTrigger"}],
            "connections": {},
            "settings": {"availableInMCP": true}
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let dry_input = json!({
        "scope": "workflow_ids",
        "workflowIds": ["wf-mcp"],
        "desired": true,
        "dryRun": true
    });
    let dry_run = invoke(&c, "n8n.mcp_access.reconcile", dry_input)
        .await
        .expect("dry-run should succeed");
    assert_eq!(dry_run["planned"][0]["id"], "wf-mcp");
    let dry_run_digest = dry_run["readbackDigest"]
        .as_str()
        .expect("dry-run digest")
        .to_owned();

    let apply_input = json!({
        "scope": "workflow_ids",
        "workflowIds": ["wf-mcp"],
        "desired": true,
        "dryRun": false,
        "guard": {
            "approvalRef": "mcp-apply-test",
            "dryRunDigest": dry_run_digest,
            "idempotencyKey": "00000000-0000-4000-8000-000000000001"
        }
    });
    let applied = invoke(&c, "n8n.mcp_access.reconcile", apply_input)
        .await
        .expect("apply should succeed");
    assert_eq!(applied["changed"][0]["id"], "wf-mcp");
    assert_eq!(applied["changed"][0]["reason"], "updated_and_verified");
    assert!(applied["exceptions"].as_array().unwrap().is_empty());

    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        5,
        "dry-run GET, apply plan GET, recheck GET, PUT, independent GET"
    );
}

#[fcp_async_core::runtime::test]
async fn mcp_access_apply_rejects_stale_digest_before_workflow_read_or_write() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/wf-stale-mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "wf-stale-mcp",
            "name": "Stale MCP",
            "active": false,
            "versionId": "draft-v1",
            "activeVersionId": null,
            "isArchived": false,
            "nodes": [{"id": "manual"}],
            "connections": {},
            "settings": {"availableInMCP": false},
            "activeVersion": null
        })))
        .mount(&server)
        .await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({
        "scope": "workflow_ids",
        "workflowIds": ["wf-stale-mcp"],
        "desired": true,
        "dryRun": false,
        "guard": {
            "approvalRef": "mcp-stale",
            "dryRunDigest": format!("blake3-256:{}", "0".repeat(64)),
            "idempotencyKey": "00000000-0000-4000-8000-000000000002"
        }
    });
    let error = invoke(&c, "n8n.mcp_access.reconcile", input)
        .await
        .expect_err("stale digest must fail closed");
    assert!(error.to_string().contains("precondition"));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "only the guarded plan list is allowed");
}

#[fcp_async_core::runtime::test]
async fn mcp_access_apply_reports_readback_mismatch_without_retry() {
    let server = MockServer::start().await;
    let list_response = json!({
        "data": [{
            "id": "wf-mismatch-mcp",
            "active": false,
            "versionId": "draft-v1",
            "activeVersionId": null,
            "isArchived": false,
            "settings": {"availableInMCP": false}
        }]
    });
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_response))
        .mount(&server)
        .await;
    let detail = json!({
        "id": "wf-mismatch-mcp",
        "name": "Mismatch MCP",
        "active": false,
        "versionId": "draft-v1",
        "activeVersionId": null,
        "isArchived": false,
        "nodes": [{"id": "manual"}],
        "connections": {},
        "settings": {"availableInMCP": false},
        "activeVersion": null
    });
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/wf-mismatch-mcp"))
        .respond_with(SequentialJsonResponse::new(vec![
            detail.clone(),
            detail.clone(),
            detail.clone(),
            detail,
        ]))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/workflows/wf-mismatch-mcp"))
        .and(body_json(json!({
            "name": "Mismatch MCP",
            "nodes": [{"id": "manual"}],
            "connections": {},
            "settings": {"availableInMCP": true}
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let dry_input = json!({
        "scope": "workflow_ids",
        "workflowIds": ["wf-mismatch-mcp"],
        "desired": true,
        "dryRun": true
    });
    let digest = invoke(&c, "n8n.mcp_access.reconcile", dry_input)
        .await
        .unwrap()["readbackDigest"]
        .as_str()
        .unwrap()
        .to_owned();
    let apply_input = json!({
        "scope": "workflow_ids",
        "workflowIds": ["wf-mismatch-mcp"],
        "desired": true,
        "dryRun": false,
        "guard": {
            "approvalRef": "mcp-mismatch",
            "dryRunDigest": digest,
            "idempotencyKey": "00000000-0000-4000-8000-000000000003"
        }
    });
    let result = invoke(&c, "n8n.mcp_access.reconcile", apply_input)
        .await
        .expect("mismatch is a per-workflow exception");
    assert!(result["changed"].as_array().unwrap().is_empty());
    assert_eq!(result["exceptions"][0]["reason"], "readback_mismatch");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 5, "no second PUT after mismatched readback");
}

#[fcp_async_core::runtime::test]
async fn workflows_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/1001"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "1001",
            "name": "Daily Report",
            "active": true,
            "versionId": "draft-v3",
            "activeVersionId": "published-v2",
            "isArchived": false,
            "projectId": "project-1",
            "parentFolderId": "folder-1",
            "updatedAt": "2025-02-20T14:30:00.000Z",
            "nodes": [{"id": "node-1", "type": "n8n-nodes-base.code", "parameters": {"jsCode": "return items;"}}],
            "connections": {},
            "activeVersion": {
                "versionId": "published-v2",
                "nodes": [{"id": "node-1", "type": "n8n-nodes-base.code", "parameters": {"jsCode": "return [];"}}],
                "connections": {}
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.workflows.get", json!({"id": "1001"}))
        .await
        .unwrap();
    assert_eq!(result["id"], "1001");
    assert_eq!(result["name"], "Daily Report");
    assert_eq!(result["active"], true);
    assert_eq!(result["versionId"], "draft-v3");
    assert_eq!(result["draft"]["versionId"], "draft-v3");
    assert_eq!(result["published"]["versionId"], "published-v2");
    assert!(
        result["draft"]["graphDigest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("blake3-256:"))
    );
    assert!(
        result["stateDigest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("blake3-256:"))
    );
    assert_no_untrusted_output(&result);
}

#[fcp_async_core::runtime::test]
async fn workflow_handle_invoke_redacts_graphs_and_rejects_incomplete_state() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/1001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "1001",
            "name": "Safe workflow",
            "active": false,
            "versionId": "draft-v3",
            "activeVersionId": "published-v2",
            "isArchived": true,
            "nodes": [{
                "id": "node-1",
                "parameters": {"jsCode": "marker.workflow.code"},
                "credentials": {"api": {"id": "marker.workflow.credentials"}}
            }],
            "connections": {"marker.workflow.graph": {}},
            "activeVersion": {
                "versionId": "published-v2",
                "nodes": [],
                "connections": {}
            },
            "meta": {"value": "marker.workflow.graph"},
            "pinData": {"trigger": [{"json": "marker.workflow.pin"}]},
            "unknownField": "marker.unknown"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/1002"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "1002",
            "name": null,
            "active": false,
            "versionId": "draft-v1",
            "activeVersionId": null,
            "isArchived": false,
            "nodes": [{"id": "node-2", "parameters": {}}],
            "connections": {},
            "activeVersion": null
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/1003"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "1003",
            "name": "Incomplete",
            "active": false,
            "versionId": "draft-v1",
            "isArchived": false,
            "nodes": [],
            "connections": {},
            "activeVersion": null
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let full = invoke(&c, "n8n.workflows.get", json!({"id": "1001"}))
        .await
        .unwrap();
    assert_eq!(full["active"], false);
    assert_eq!(full["versionId"], "draft-v3");
    assert_eq!(full["activeVersionId"], "published-v2");
    assert_eq!(full["isArchived"], true);
    assert_no_untrusted_output(&full);

    let explicit_null = invoke(&c, "n8n.workflows.get", json!({"id": "1002"}))
        .await
        .unwrap();
    assert!(explicit_null["name"].is_null());
    assert!(
        explicit_null
            .get("activeVersionId")
            .is_some_and(serde_json::Value::is_null)
    );
    assert_no_untrusted_output(&explicit_null);

    let missing = invoke(&c, "n8n.workflows.get", json!({"id": "1003"}))
        .await
        .expect_err("missing activeVersionId must fail closed");
    assert!(!missing.to_string().contains("Incomplete"));
}

#[fcp_async_core::runtime::test]
async fn workflow_digests_separate_semantic_graph_from_credential_bound_state() {
    let first = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/same-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "same-id",
            "name": "Digest test",
            "active": false,
            "versionId": "draft-v1",
            "activeVersionId": null,
            "isArchived": false,
            "nodes": [{
                "id": "node-1",
                "type": "n8n-nodes-base.httpRequest",
                "parameters": {"method": "GET", "url": "https://example.com"},
                "credentials": {"httpHeaderAuth": {"id": "credential-a", "name": "A"}}
            }],
            "connections": {},
            "activeVersion": null
        })))
        .mount(&first)
        .await;

    let second = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/same-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "activeVersion": null,
            "connections": {},
            "nodes": [{
                "credentials": {"httpHeaderAuth": {"name": "B", "id": "credential-b"}},
                "parameters": {"url": "https://example.com", "method": "GET"},
                "type": "n8n-nodes-base.httpRequest",
                "id": "node-1"
            }],
            "isArchived": false,
            "activeVersionId": null,
            "versionId": "draft-v1",
            "active": false,
            "name": "Digest test",
            "id": "same-id"
        })))
        .mount(&second)
        .await;

    let third = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/same-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "same-id",
            "name": "Digest test",
            "active": false,
            "versionId": "draft-v1",
            "activeVersionId": null,
            "isArchived": false,
            "nodes": [{
                "id": "node-1",
                "type": "n8n-nodes-base.httpRequest",
                "parameters": {"method": "POST", "url": "https://example.com"},
                "credentials": {"httpHeaderAuth": {"id": "credential-b", "name": "B"}}
            }],
            "connections": {},
            "activeVersion": null
        })))
        .mount(&third)
        .await;

    let first_connector = setup_connector(&first.uri()).await;
    let second_connector = setup_connector(&second.uri()).await;
    let third_connector = setup_connector(&third.uri()).await;
    let first_result = invoke(
        &first_connector,
        "n8n.workflows.get",
        json!({"id": "same-id"}),
    )
    .await
    .unwrap();
    let second_result = invoke(
        &second_connector,
        "n8n.workflows.get",
        json!({"id": "same-id"}),
    )
    .await
    .unwrap();
    let third_result = invoke(
        &third_connector,
        "n8n.workflows.get",
        json!({"id": "same-id"}),
    )
    .await
    .unwrap();

    assert_eq!(
        first_result["draft"]["graphDigest"], second_result["draft"]["graphDigest"],
        "object key order and top-level node credential bindings are excluded from graphDigest"
    );
    assert_ne!(
        first_result["stateDigest"], second_result["stateDigest"],
        "credential bindings remain part of stateDigest"
    );
    assert_ne!(
        second_result["draft"]["graphDigest"], third_result["draft"]["graphDigest"],
        "semantic node parameter changes must change graphDigest"
    );
    for output in [&first_result, &second_result, &third_result] {
        let rendered = serde_json::to_string(output).unwrap();
        for forbidden in [
            "credential-a",
            "credential-b",
            "httpHeaderAuth",
            "https://example.com",
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }
}

#[fcp_async_core::runtime::test]
async fn workflow_get_rejects_contradictory_published_state() {
    let cases = [
        (
            "missing-object",
            json!({
                "id": "missing-object", "name": null, "active": true,
                "versionId": "draft-v2", "activeVersionId": "published-v1",
                "isArchived": false, "nodes": [], "connections": {},
                "activeVersion": null
            }),
        ),
        (
            "unexpected-object",
            json!({
                "id": "unexpected-object", "name": null, "active": false,
                "versionId": "draft-v2", "activeVersionId": null,
                "isArchived": false, "nodes": [], "connections": {},
                "activeVersion": {"versionId": "published-v1", "nodes": [], "connections": {}}
            }),
        ),
        (
            "mismatched-version",
            json!({
                "id": "mismatched-version", "name": null, "active": true,
                "versionId": "draft-v2", "activeVersionId": "published-v1",
                "isArchived": true, "nodes": [], "connections": {},
                "activeVersion": {"versionId": "published-other", "nodes": [], "connections": {}}
            }),
        ),
        (
            "mismatched-workflow-id",
            json!({
                "id": "different-provider-id", "name": null, "active": false,
                "versionId": "draft-v1", "activeVersionId": null,
                "isArchived": false, "nodes": [], "connections": {},
                "activeVersion": null
            }),
        ),
    ];

    let server = MockServer::start().await;
    for (id, body) in &cases {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/workflows/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
    }
    let c = setup_connector(&server.uri()).await;
    for (id, _) in &cases {
        let error = invoke(&c, "n8n.workflows.get", json!({"id": id}))
            .await
            .expect_err("contradictory published state must fail closed");
        assert!(!error.to_string().contains(*id));
    }
}

#[fcp_async_core::runtime::test]
async fn workflow_list_handle_invoke_redacts_items_and_preserves_cursor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "id": "1001",
                    "name": "one",
                    "nodes": [{"value": "marker.workflow.graph"}],
                    "code": "marker.workflow.code",
                    "credentials": {"api": "marker.workflow.credentials"},
                    "pinData": {"trigger": "marker.workflow.pin"},
                    "unknownField": "marker.unknown"
                },
                {
                    "id": "1002",
                    "activeVersion": {"value": "marker.workflow.graph"},
                    "connections": {"value": "marker.workflow.graph"}
                }
            ],
            "nextCursor": "opaque-workflow-cursor"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.workflows.list", json!({})).await.unwrap();
    let workflows = result["data"].as_array().unwrap();
    assert_eq!(workflows.len(), 2);
    assert!(
        workflows[1]
            .get("name")
            .is_some_and(serde_json::Value::is_null)
    );
    assert_eq!(result["nextCursor"], "opaque-workflow-cursor");
    for workflow in workflows {
        assert_no_untrusted_output(workflow);
    }
}

#[fcp_async_core::runtime::test]
async fn workflows_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation": "n8n.workflows.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn exact_object_inputs_reject_unknown_fields_before_egress() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let cases = [
        ("n8n.workflows.get", json!({"id": "1001", "unknown": true})),
        (
            "n8n.workflows.activate",
            json!({"id": "1001", "active": true, "unknown": true}),
        ),
        (
            "n8n.executions.get",
            json!({"workflow_id": "1001", "id": "50001", "unknown": true}),
        ),
        (
            "n8n.folders.get",
            json!({"project_id": "project-1", "folder_id": "folder-1", "unknown": true}),
        ),
    ];

    for (operation, input) in cases {
        let error = invoke(&c, operation, input)
            .await
            .expect_err("unknown exact-object input field must fail closed");
        assert!(
            error.to_string().contains("unsupported property"),
            "unexpected error for {operation}: {error}"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn capability_gate_denials_do_not_egress() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({});
    let now = chrono::Utc::now();

    let mut missing = authorized_params("n8n.workflows.list", &input);
    missing
        .as_object_mut()
        .expect("invoke params should be an object")
        .remove("capability_token");

    let mut invalid_signature = authorized_params("n8n.workflows.list", &input);
    invalid_signature["capability_token"] = json!(capability_token_with_options(
        "n8n.workflows.list",
        &Ed25519SigningKey::from_bytes(&[43_u8; 32]).expect("wrong test key should parse"),
        TEST_INSTANCE_ID,
        resource_uri("n8n.workflows.list", &input),
        now - chrono::Duration::seconds(1),
        now + chrono::Duration::hours(1),
    ));

    let mut expired = authorized_params("n8n.workflows.list", &input);
    expired["capability_token"] = json!(capability_token_with_options(
        "n8n.workflows.list",
        &test_signing_key(),
        TEST_INSTANCE_ID,
        resource_uri("n8n.workflows.list", &input),
        now - chrono::Duration::hours(2),
        now - chrono::Duration::hours(1),
    ));

    let mut wrong_instance = authorized_params("n8n.workflows.list", &input);
    wrong_instance["capability_token"] = json!(capability_token_with_options(
        "n8n.workflows.list",
        &test_signing_key(),
        "other-instance",
        resource_uri("n8n.workflows.list", &input),
        now - chrono::Duration::seconds(1),
        now + chrono::Duration::hours(1),
    ));

    let mut wrong_resource = authorized_params("n8n.workflows.list", &input);
    wrong_resource["capability_token"] = json!(capability_token_with_options(
        "n8n.workflows.list",
        &test_signing_key(),
        TEST_INSTANCE_ID,
        "fwc-n8n://hetzner".into(),
        now - chrono::Duration::seconds(1),
        now + chrono::Duration::hours(1),
    ));

    for (label, params) in [
        ("missing", missing),
        ("invalid signature", invalid_signature),
        ("expired", expired),
        ("wrong instance", wrong_instance),
        ("wrong resource", wrong_resource),
    ] {
        assert!(
            c.handle_invoke(params).await.is_err(),
            "capability denial should fail for {label}"
        );
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "capability denials must not reach provider"
    );
}

// -- Workflows Activate --

#[fcp_async_core::runtime::test]
async fn workflows_activate() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let err = invoke(
        &c,
        "n8n.workflows.activate",
        json!({"id": "1001", "active": true}),
    )
    .await
    .expect_err("activation must fail closed until mediated lifecycle support exists");
    assert!(matches!(
        err,
        fcp_prelude::FcpError::CapabilityDenied { reason, .. }
            if reason.contains("deferred")
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn workflows_activate_ignores_unrelated_approval_tokens() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({"id": "1001", "active": true});
    let mut params = authorized_params("n8n.workflows.activate", &input);
    params["approval_tokens"] = json!([unrelated_approval_token(&input), approval_token(&input),]);
    let err = c
        .handle_invoke(params)
        .await
        .expect_err("valid approval must still stop at the deferred lifecycle boundary");
    assert!(matches!(
        err,
        fcp_prelude::FcpError::CapabilityDenied { reason, .. }
            if reason.contains("deferred")
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn workflows_activate_rejects_multiple_matching_approval_tokens() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({"id": "1001", "active": true});
    let mut params = authorized_params("n8n.workflows.activate", &input);
    params["approval_tokens"] = json!([approval_token(&input), approval_token(&input)]);
    let err = c
        .handle_invoke(params)
        .await
        .expect_err("duplicate matching approvals must fail closed");
    assert!(matches!(
        err,
        fcp_prelude::FcpError::CapabilityDenied { .. }
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn workflows_activate_allows_host_bound_input_hash_for_semantic_gate() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({"id": "1001", "active": true});
    let mut params = authorized_params("n8n.workflows.activate", &input);
    params["approval_tokens"] = json!([host_bound_input_hash_approval_token(&input)]);
    let err = c
        .handle_invoke(params)
        .await
        .expect_err("host-bound input_hash approval must not enable direct lifecycle I/O");
    assert!(matches!(
        err,
        fcp_prelude::FcpError::CapabilityDenied { reason, .. }
            if reason.contains("deferred")
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn workflows_activate_rejects_malformed_approval_entry() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({"id": "1001", "active": true});
    let mut params = authorized_params("n8n.workflows.activate", &input);
    params["approval_tokens"] = json!([
        {"malformed": true},
        approval_token(&input),
    ]);
    let err = c
        .handle_invoke(params)
        .await
        .expect_err("malformed approval entries must fail closed");
    assert!(matches!(err, fcp_prelude::FcpError::InvalidRequest { .. }));
}

#[fcp_async_core::runtime::test]
async fn approval_gate_denials_do_not_egress_provider() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({"id": "1001", "active": true});

    let mut missing = authorized_params("n8n.workflows.activate", &input);
    missing
        .as_object_mut()
        .expect("invoke params should be an object")
        .remove("approval_tokens");

    let mut expired = authorized_params("n8n.workflows.activate", &input);
    let mut expired_token = approval_token(&input);
    expired_token.expires_at_ms = 0;
    expired["approval_tokens"] = json!([expired_token]);

    let mut wrong_zone = authorized_params("n8n.workflows.activate", &input);
    let mut wrong_zone_token = approval_token(&input);
    wrong_zone_token.zone_id = ZoneId::private();
    wrong_zone["approval_tokens"] = json!([wrong_zone_token]);

    let mut wrong_target = authorized_params("n8n.workflows.activate", &input);
    wrong_target["approval_tokens"] = json!([approval_token(&json!({
        "id": "1001",
        "active": false
    }))]);

    for (label, params) in [
        ("missing", missing),
        ("expired", expired),
        ("wrong zone", wrong_zone),
        ("wrong target", wrong_target),
    ] {
        assert!(
            c.handle_invoke(params).await.is_err(),
            "approval denial should fail for {label}"
        );
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "approval denials must not reach the provider"
    );
}

#[fcp_async_core::runtime::test]
async fn workflows_deactivate() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let err = invoke(
        &c,
        "n8n.workflows.activate",
        json!({"id": "1002", "active": false}),
    )
    .await
    .expect_err("deactivation must fail closed until mediated lifecycle support exists");
    assert!(matches!(
        err,
        fcp_prelude::FcpError::CapabilityDenied { reason, .. }
            if reason.contains("deferred")
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn workflows_activate_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation": "n8n.workflows.activate",
            "input": {"active": true}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn workflows_activate_missing_active() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation": "n8n.workflows.activate",
            "input": {"id": "1001"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn workflows_lifecycle_publishes_with_exact_route_and_readback() {
    let server = MockServer::start().await;
    let baseline = json!({
        "id": "1001",
        "name": "Lifecycle test",
        "active": false,
        "versionId": "draft-v1",
        "activeVersionId": null,
        "isArchived": false,
        "nodes": [{"id": "draft-node"}],
        "connections": {},
        "activeVersion": null
    });
    let published = json!({
        "versionId": "published-v1",
        "nodes": [{"id": "published-node"}],
        "connections": {}
    });
    let readback = json!({
        "id": "1001",
        "name": "Lifecycle test",
        "active": true,
        "versionId": "draft-v1",
        "activeVersionId": "published-v1",
        "isArchived": false,
        "nodes": [{"id": "draft-node"}],
        "connections": {},
        "activeVersion": published.clone()
    });
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/1001"))
        .respond_with(SequentialJsonResponse::new(vec![
            baseline.clone(),
            readback.clone(),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/workflows/1001/publish"))
        .and(body_json(json!({"versionId": "published-v1"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(readback))
        .mount(&server)
        .await;
    let state_digest = workflow_state_digest_for_fixture(&baseline);
    let c = setup_connector(&server.uri()).await;
    let input = json!({
        "id": "1001",
        "action": "publish",
        "versionId": "published-v1",
        "guard": {
            "approvalRef": "approval-test",
            "idempotencyKey": "00000000-0000-4000-8000-000000000003",
            "precondition": {
                "versionId": "draft-v1",
                "activeVersionId": null,
                "active": false,
                "isArchived": false,
                "stateDigest": state_digest
            }
        }
    });
    let result = invoke(&c, "n8n.workflows.lifecycle", input)
        .await
        .expect("publish should succeed");
    assert_eq!(result["status"], "verified");
    assert_eq!(result["after"]["active"], true);
    assert_eq!(result["after"]["activeVersionId"], "published-v1");
    assert_eq!(result["after"]["draft"]["versionId"], "draft-v1");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3, "baseline GET, one publish, readback GET");
}

#[fcp_async_core::runtime::test]
async fn workflows_lifecycle_requires_explicit_active_version_pointer() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({
        "id": "1001",
        "action": "unpublish",
        "guard": {
            "approvalRef": "approval-test",
            "idempotencyKey": "00000000-0000-4000-8000-000000000004",
            "precondition": {
                "versionId": "draft-v1",
                "active": true,
                "isArchived": false,
                "stateDigest": "blake3-256:0000000000000000000000000000000000000000000000000000000000000000"
            }
        }
    });
    assert!(invoke(&c, "n8n.workflows.lifecycle", input).await.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn workflows_lifecycle_unpublishes_without_a_request_body() {
    let server = MockServer::start().await;
    let published = json!({
        "versionId": "published-v1",
        "nodes": [{"id": "published-node"}],
        "connections": {}
    });
    let baseline = json!({
        "id": "1001",
        "name": "Lifecycle test",
        "active": true,
        "versionId": "draft-v1",
        "activeVersionId": "published-v1",
        "isArchived": false,
        "nodes": [{"id": "draft-node"}],
        "connections": {},
        "activeVersion": published
    });
    let readback = json!({
        "id": "1001",
        "name": "Lifecycle test",
        "active": false,
        "versionId": "draft-v1",
        "activeVersionId": null,
        "isArchived": false,
        "nodes": [{"id": "draft-node"}],
        "connections": {},
        "activeVersion": null
    });
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/1001"))
        .respond_with(SequentialJsonResponse::new(vec![
            baseline.clone(),
            readback.clone(),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/workflows/1001/unpublish"))
        .and(body_string(""))
        .respond_with(ResponseTemplate::new(200).set_body_json(readback))
        .mount(&server)
        .await;
    let state_digest = workflow_state_digest_for_fixture(&baseline);
    let c = setup_connector(&server.uri()).await;
    let input = json!({
        "id": "1001",
        "action": "unpublish",
        "guard": {
            "approvalRef": "approval-unpublish",
            "idempotencyKey": "00000000-0000-4000-8000-000000000005",
            "precondition": {
                "versionId": "draft-v1",
                "activeVersionId": "published-v1",
                "active": true,
                "isArchived": false,
                "stateDigest": state_digest
            }
        }
    });
    let result = invoke(&c, "n8n.workflows.lifecycle", input)
        .await
        .expect("unpublish should succeed");
    assert_eq!(result["after"]["active"], false);
    assert!(result["after"]["activeVersionId"].is_null());
    assert_eq!(result["after"]["draft"]["versionId"], "draft-v1");
}

#[fcp_async_core::runtime::test]
async fn workflows_lifecycle_publish_uses_provider_version_when_omitted() {
    let server = MockServer::start().await;
    let baseline = json!({
        "id": "1001",
        "name": "Lifecycle omitted",
        "active": false,
        "versionId": "draft-v1",
        "activeVersionId": null,
        "isArchived": false,
        "nodes": [{"id": "draft-node"}],
        "connections": {},
        "activeVersion": null
    });
    let published = json!({
        "versionId": "published-v2",
        "nodes": [{"id": "published-node"}],
        "connections": {}
    });
    let readback = json!({
        "id": "1001",
        "name": "Lifecycle omitted",
        "active": true,
        "versionId": "draft-v1",
        "activeVersionId": "published-v2",
        "isArchived": false,
        "nodes": [{"id": "draft-node"}],
        "connections": {},
        "activeVersion": published.clone()
    });
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/1001"))
        .respond_with(SequentialJsonResponse::new(vec![
            baseline.clone(),
            readback.clone(),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/workflows/1001/publish"))
        .and(body_string(""))
        .respond_with(ResponseTemplate::new(200).set_body_json(readback))
        .mount(&server)
        .await;
    let state_digest = workflow_state_digest_for_fixture(&baseline);
    let c = setup_connector(&server.uri()).await;
    let input = json!({
        "id": "1001",
        "action": "publish",
        "guard": {
            "approvalRef": "approval-omitted",
            "idempotencyKey": "00000000-0000-4000-8000-000000000006",
            "precondition": {
                "versionId": "draft-v1",
                "activeVersionId": null,
                "active": false,
                "isArchived": false,
                "stateDigest": state_digest
            }
        }
    });
    let result = invoke(&c, "n8n.workflows.lifecycle", input)
        .await
        .expect("omitted version publish should succeed");
    assert_eq!(result["after"]["activeVersionId"], "published-v2");
}

#[fcp_async_core::runtime::test]
async fn workflows_lifecycle_stale_precondition_makes_no_write() {
    let server = MockServer::start().await;
    let current = json!({
        "id": "1001",
        "name": "Stale lifecycle",
        "active": false,
        "versionId": "draft-v2",
        "activeVersionId": null,
        "isArchived": false,
        "nodes": [],
        "connections": {},
        "activeVersion": null
    });
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/1001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(current.clone()))
        .mount(&server)
        .await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({
        "id": "1001",
        "action": "publish",
        "guard": {
            "approvalRef": "approval-stale",
            "idempotencyKey": "00000000-0000-4000-8000-000000000007",
            "precondition": {
                "versionId": "draft-v1",
                "activeVersionId": null,
                "active": false,
                "isArchived": false,
                "stateDigest": workflow_state_digest_for_fixture(&current)
            }
        }
    });
    assert!(invoke(&c, "n8n.workflows.lifecycle", input).await.is_err());
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        1,
        "stale precondition must stop before POST"
    );
}

#[fcp_async_core::runtime::test]
async fn workflows_lifecycle_conflict_is_unknown_without_retry() {
    let server = MockServer::start().await;
    let baseline = json!({
        "id": "1001",
        "name": "Conflict lifecycle",
        "active": false,
        "versionId": "draft-v1",
        "activeVersionId": null,
        "isArchived": false,
        "nodes": [],
        "connections": {},
        "activeVersion": null
    });
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/1001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(baseline.clone()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/workflows/1001/publish"))
        .respond_with(ResponseTemplate::new(409))
        .mount(&server)
        .await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({
        "id": "1001",
        "action": "publish",
        "guard": {
            "approvalRef": "approval-conflict",
            "idempotencyKey": "00000000-0000-4000-8000-000000000008",
            "precondition": {
                "versionId": "draft-v1",
                "activeVersionId": null,
                "active": false,
                "isArchived": false,
                "stateDigest": workflow_state_digest_for_fixture(&baseline)
            }
        }
    });
    let error = invoke(&c, "n8n.workflows.lifecycle", input)
        .await
        .expect_err("409 must be unknown");
    assert!(error.to_string().contains("unknown"));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn workflows_lifecycle_timeout_is_unknown_without_retry() {
    let server = MockServer::start().await;
    let baseline = json!({
        "id": "1001", "name": "Timeout lifecycle", "active": false,
        "versionId": "draft-v1", "activeVersionId": null, "isArchived": false,
        "nodes": [], "connections": {}, "activeVersion": null
    });
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/1001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(baseline.clone()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/workflows/1001/publish"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(100))
                .set_body_json(baseline.clone()),
        )
        .mount(&server)
        .await;
    let c = setup_connector_with_runtime_config(
        json!({
            "api_key": "test-n8n-api-key-123",
            "server_id": TEST_SERVER_ID,
            "base_url": format!("{}/api/v1", server.uri())
        }),
        ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_millis(20)),
    )
    .await;
    let input = json!({
        "id": "1001", "action": "publish",
        "guard": {"approvalRef": "approval-timeout", "idempotencyKey": "00000000-0000-4000-8000-000000000011",
            "precondition": {"versionId": "draft-v1", "activeVersionId": null, "active": false,
                "isArchived": false, "stateDigest": workflow_state_digest_for_fixture(&baseline)}}
    });
    let error = invoke(&c, "n8n.workflows.lifecycle", input)
        .await
        .expect_err("timeout must be unknown");
    assert!(error.to_string().contains("unknown"));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn workflows_lifecycle_readback_mismatch_does_not_repeat_write() {
    let server = MockServer::start().await;
    let baseline = json!({
        "id": "1001", "name": "Mismatch lifecycle", "active": false,
        "versionId": "draft-v1", "activeVersionId": null, "isArchived": false,
        "nodes": [{"id": "draft"}], "connections": {}, "activeVersion": null
    });
    let published = json!({
        "versionId": "published-v1", "nodes": [{"id": "published"}], "connections": {}
    });
    let post_response = json!({
        "id": "1001", "name": "Mismatch lifecycle", "active": true,
        "versionId": "draft-v1", "activeVersionId": "published-v1", "isArchived": false,
        "nodes": [{"id": "draft"}], "connections": {}, "activeVersion": published
    });
    let mismatched = baseline.clone();
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/1001"))
        .respond_with(SequentialJsonResponse::new(vec![
            baseline.clone(),
            mismatched,
        ]))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/workflows/1001/publish"))
        .respond_with(ResponseTemplate::new(200).set_body_json(post_response))
        .mount(&server)
        .await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({
        "id": "1001", "action": "publish", "versionId": "published-v1",
        "guard": {"approvalRef": "approval-mismatch", "idempotencyKey": "00000000-0000-4000-8000-000000000009",
            "precondition": {"versionId": "draft-v1", "activeVersionId": null, "active": false,
                "isArchived": false, "stateDigest": workflow_state_digest_for_fixture(&baseline)}}
    });
    let error = invoke(&c, "n8n.workflows.lifecycle", input)
        .await
        .expect_err("readback mismatch must fail");
    assert!(error.to_string().contains("readback"));
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn workflows_lifecycle_rejects_unsupported_action_without_provider_call() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let input = json!({
        "id": "1001", "action": "archive",
        "guard": {"approvalRef": "approval-archive", "idempotencyKey": "00000000-0000-4000-8000-000000000010",
            "precondition": {"versionId": "draft-v1", "activeVersionId": null, "active": false,
                "isArchived": false, "stateDigest": format!("blake3-256:{}", "0".repeat(64))}}
    });
    assert!(invoke(&c, "n8n.workflows.lifecycle", input).await.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn workflows_delete_disposable_requires_receipt_and_verifies_404_readback() {
    let server = MockServer::start().await;
    let baseline = json!({
        "id": "1001",
        "name": "Disposable workflow",
        "active": false,
        "versionId": "draft-v1",
        "activeVersionId": null,
        "isArchived": false,
        "nodes": [{"id": "draft-node"}],
        "connections": {},
        "activeVersion": null
    });
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/1001"))
        .respond_with(DisposableDeleteResponse::new(baseline.clone()))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/workflows/1001"))
        .and(body_string(""))
        .respond_with(ResponseTemplate::new(200).set_body_json(baseline.clone()))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let input = json!({
        "id": "1001",
        "creationReceipt": format!("blake3-256:{}", "1".repeat(64)),
        "guard": {
            "approvalRef": "approval-delete-disposable",
            "idempotencyKey": "00000000-0000-4000-8000-000000000012",
            "precondition": {
                "versionId": "draft-v1",
                "activeVersionId": null,
                "active": false,
                "isArchived": false,
                "stateDigest": workflow_state_digest_for_fixture(&baseline)
            }
        }
    });
    let result = invoke(&c, "n8n.workflows.delete_disposable", input)
        .await
        .expect("disposable deletion should verify independent 404");
    assert_eq!(result["status"], "deleted");
    assert_eq!(result["readback"], "independent_get_404");
    assert!(result["workflowIdDigest"].as_str().is_some());
    assert!(result["creationReceiptDigest"].as_str().is_some());

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3, "baseline GET, one DELETE, readback GET");
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[1].method, "DELETE");
    assert_eq!(requests[2].method, "GET");
}

// -- Executions List --

#[fcp_async_core::runtime::test]
async fn executions_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/executions"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .and(query_param("limit", "50"))
        .and(query_param("includeData", "false"))
        .and(query_param("ignoreDataSizeLimit", "false"))
        .and(query_param("redactExecutionData", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "50001", "finished": true, "status": "success", "workflowId": "1001"},
                {"id": "50002", "finished": true, "status": "error", "workflowId": "1002"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.executions.list", json!({})).await.unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn executions_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/executions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.executions.list", json!({})).await.unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn executions_list_rejects_invalid_input_without_traffic() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let mut invalid_inputs = vec![
        json!({"limit": 0}),
        json!({"limit": 201}),
        json!({"limit": -1}),
        json!({"limit": 1.5}),
        json!({"limit": "1"}),
        json!({"limit": true}),
        json!({"limit": null}),
        json!({"cursor": ""}),
        json!({"cursor": null}),
        json!({"cursor": 1}),
        json!({"cursor": "bad\ncursor"}),
        json!({"unknown": 1}),
    ];
    invalid_inputs.push(json!({
        "cursor": "x".repeat(4097),
    }));

    for input in invalid_inputs {
        assert!(invoke(&c, "n8n.executions.list", input).await.is_err());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn executions_list_rejects_malformed_provider_cursors() {
    let malformed = vec![
        json!(""),
        json!("bad\ncursor"),
        json!(123),
        json!("x".repeat(4097)),
    ];

    for cursor in malformed {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/executions"))
            .and(query_param("limit", "50"))
            .and(query_param("includeData", "false"))
            .and(query_param("ignoreDataSizeLimit", "false"))
            .and(query_param("redactExecutionData", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [],
                "nextCursor": cursor
            })))
            .mount(&server)
            .await;

        let c = setup_connector(&server.uri()).await;
        assert!(invoke(&c, "n8n.executions.list", json!({})).await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

// -- Executions Get --

#[fcp_async_core::runtime::test]
async fn executions_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/executions/50001"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "50001",
            "finished": true,
            "mode": "trigger",
            "startedAt": "2025-03-01T08:00:00.000Z",
            "stoppedAt": "2025-03-01T08:00:05.000Z",
            "workflowId": "1001",
            "status": "success",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(
        &c,
        "n8n.executions.get",
        json!({"workflow_id": "1001", "id": "50001"}),
    )
    .await
    .unwrap();
    assert_eq!(result["id"], "50001");
    assert_eq!(result["finished"], true);
    assert_eq!(result["status"], "success");
}

#[fcp_async_core::runtime::test]
async fn execution_handle_invoke_redacts_untrusted_fields_and_missing_finished_is_null() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/executions/50001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "50001",
            "finished": true,
            "status": "success",
            "data": {"value": "marker.execution.data"},
            "resultData": {"value": "marker.execution.result"},
            "credentials": {"api": "marker.execution.credentials"},
            "pinData": {"trigger": "marker.execution.pin"},
            "unknownField": "marker.unknown"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/executions/50002"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "50002",
            "data": {"value": "marker.execution.data"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let full = invoke(
        &c,
        "n8n.executions.get",
        json!({"workflow_id": "1001", "id": "50001"}),
    )
    .await
    .unwrap();
    assert_eq!(full["finished"], true);
    assert_eq!(full["status"], "success");
    assert_no_untrusted_output(&full);

    let missing = invoke(
        &c,
        "n8n.executions.get",
        json!({"workflow_id": "1001", "id": "50002"}),
    )
    .await
    .unwrap();
    assert!(missing["finished"].is_null());
    assert_no_untrusted_output(&missing);
}

#[fcp_async_core::runtime::test]
async fn execution_list_handle_invoke_redacts_items_and_preserves_cursor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/executions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "id": "50001",
                    "finished": true,
                    "data": {"value": "marker.execution.data"},
                    "resultData": {"value": "marker.execution.result"},
                    "credentials": {"api": "marker.execution.credentials"},
                    "pinData": {"trigger": "marker.execution.pin"},
                    "unknownField": "marker.unknown"
                },
                {"id": "50002", "finished": false},
                {"id": "50003"}
            ],
            "nextCursor": "opaque-execution-cursor"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.executions.list", json!({})).await.unwrap();
    let executions = result["data"].as_array().unwrap();
    assert_eq!(executions.len(), 3);
    assert_eq!(executions[1]["finished"], false);
    assert!(
        executions[2]
            .get("finished")
            .is_some_and(serde_json::Value::is_null)
    );
    assert_eq!(result["nextCursor"], "opaque-execution-cursor");
    for execution in executions {
        assert_no_untrusted_output(execution);
    }
}

#[fcp_async_core::runtime::test]
async fn executions_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation": "n8n.executions.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn error_401_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({"message": "Invalid API key"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(invoke(&c, "n8n.workflows.list", json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn error_403_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Insufficient permissions"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(invoke(&c, "n8n.workflows.list", json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn error_404_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/99999"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"message": "Workflow not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        invoke(&c, "n8n.workflows.get", json!({"id": "99999"}))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429_rate_limited() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Rate limit exceeded"}))
                .insert_header("retry-after", "30"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(invoke(&c, "n8n.workflows.list", json!({})).await.is_err());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn error_500_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/executions"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(invoke(&c, "n8n.executions.list", json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn error_502_bad_gateway() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(502).set_body_string("Bad Gateway"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(invoke(&c, "n8n.workflows.list", json!({})).await.is_err());
}

// -- Unknown op / Simulate --

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation": "n8n.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_workflow_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation": "n8n.workflows.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_workflow_get() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation": "n8n.workflows.get"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_workflow_activate() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation": "n8n.workflows.activate"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_executions_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation": "n8n.executions.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_executions_get() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation": "n8n.executions.get"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_projects_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation": "n8n.projects.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_tags_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation": "n8n.tags.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_folder_operations() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    for operation in ["n8n.folders.list", "n8n.folders.get"] {
        assert!(
            c.handle_simulate(json!({"operation": operation}))
                .await
                .unwrap()["allowed"]
                .as_bool()
                .unwrap(),
            "{operation} should be in simulation catalog"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_simulate(json!({"operation": "n8n.nope"}))
        .await
        .unwrap();
    assert!(!result["allowed"].as_bool().unwrap());
    assert_eq!(result["reason"], "Unknown operation");
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn counters_increment_on_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    invoke(&c, "n8n.workflows.list", json!({})).await.unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_increment_on_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = invoke(&c, "n8n.workflows.list", json!({})).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

#[fcp_async_core::runtime::test]
async fn counters_multiple_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        invoke(&c, "n8n.workflows.list", json!({})).await.unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}

// -- Configuration --

#[fcp_async_core::runtime::test]
async fn configure_rejects_missing_base_url() {
    let mut c = N8nConnector::new();
    let result = c
        .handle_configure(json!({
            "api_key": "test-key",
            "server_id": TEST_SERVER_ID,
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_empty_base_url() {
    let mut c = N8nConnector::new();
    let result = c
        .handle_configure(json!({
            "api_key": "test-key",
            "server_id": TEST_SERVER_ID,
            "base_url": "",
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_no_auth() {
    let mut c = N8nConnector::new();
    let result = c
        .handle_configure(json!({
            "server_id": TEST_SERVER_ID,
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_with_credential_id() {
    let mut c = N8nConnector::new();
    let result = c
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "server_id": TEST_SERVER_ID,
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .await;
    assert!(result.is_ok());
}

#[fcp_async_core::runtime::test]
async fn credential_id_provider_egress_without_proxy_fails_closed_before_request() {
    let server = MockServer::start().await;
    let c = setup_connector_with_config(json!({
        "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        "server_id": TEST_SERVER_ID,
        "base_url": format!("{}/api/v1", server.uri()),
    }))
    .await;

    let err = invoke(&c, "n8n.workflows.list", json!({}))
        .await
        .expect_err("CredentialId must not use direct provider HTTP");
    assert!(
        err.to_string()
            .contains("trusted host egress proxy configuration")
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn production_provider_egress_fails_closed_before_network() {
    let c = setup_connector_with_config(json!({
        "api_key": "test-n8n-api-key-123",
        "server_id": TEST_SERVER_ID,
        "base_url": "https://n8n.example.com/api/v1",
    }))
    .await;

    let err = invoke(&c, "n8n.workflows.list", json!({}))
        .await
        .expect_err("production direct provider HTTP must be unavailable");
    assert!(
        err.to_string()
            .contains("host-mediated network enforcement")
    );

    let check = c
        .handle_self_check()
        .await
        .expect("self-check should report the unavailable provider path");
    assert_eq!(check["status"], "failed");
    assert_eq!(check["reason_code"], "provider_probe_failed");
}

// -- Invoke without configure --

#[fcp_async_core::runtime::test]
async fn invoke_before_configure_fails() {
    let c = N8nConnector::new();
    assert!(
        c.handle_invoke(json!({
            "operation": "n8n.workflows.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Empty response body handling --

#[fcp_async_core::runtime::test]
async fn valid_activation_fails_closed_before_provider() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let err = invoke(
        &c,
        "n8n.workflows.activate",
        json!({"id": "1001", "active": true}),
    )
    .await
    .expect_err("valid activation must fail closed before provider I/O");
    assert!(matches!(
        err,
        fcp_prelude::FcpError::CapabilityDenied { reason, .. }
            if reason.contains("deferred")
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

// -- Auth header verification --

#[fcp_async_core::runtime::test]
async fn auth_header_sent_correctly() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/workflows/1001"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "1001",
            "name": "Test Workflow",
            "active": false,
            "versionId": "draft-v1",
            "activeVersionId": null,
            "isArchived": false,
            "nodes": [],
            "connections": {},
            "activeVersion": null
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = invoke(&c, "n8n.workflows.get", json!({"id": "1001"}))
        .await
        .unwrap();
    assert_eq!(result["id"], "1001");
}

// -- Invoke with missing operation --

#[fcp_async_core::runtime::test]
async fn invoke_missing_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Reconfigure --

#[fcp_async_core::runtime::test]
async fn reconfigure_succeeds() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    // Reconfigure with new key
    let result = c
        .handle_configure(json!({
            "api_key": "new-api-key",
            "server_id": TEST_SERVER_ID,
            "base_url": format!("{}/api/v1", server.uri())
        }))
        .await;
    assert!(result.is_ok());
    let health = c.handle_health().await.unwrap();
    assert_eq!(health["configured"], true);
    assert_eq!(health["handshaken"], false);
    assert!(invoke(&c, "n8n.workflows.list", json!({})).await.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
}
