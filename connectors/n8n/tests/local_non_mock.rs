//! Local loopback acceptance coverage for the FCP `n8n` connector.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::{
    collections::VecDeque,
    fmt::Write as FmtWrite,
    io::{Read, Write as IoWrite},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

use fcp_crypto::{
    canonicalize::to_deterministic_cbor, cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey,
};
use fcp_n8n::connector::N8nConnector;
use fcp_prelude::{
    ApprovalScope, ApprovalToken, CapabilityConstraints, CapabilityToken, ExecutionScope, FcpError,
    ZoneId,
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};

const CONNECTOR: &str = "n8n";
const PACKAGE: &str = "fcp-n8n";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.25";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const LOOPBACK_API_KEY: &str = "n8n-local-non-mock-key";
const TEST_SERVER_ID: &str = "eec";
const TEST_INSTANCE_ID: &str = "inst_n8n_local_non_mock";
const OP_WORKFLOWS_LIST: &str = "n8n.workflows.list";
const OP_WORKFLOWS_ACTIVATE: &str = "n8n.workflows.activate";
const OP_EXECUTIONS_LIST: &str = "n8n.executions.list";
const OP_EXECUTIONS_DIAGNOSTICS: &str = "n8n.executions.diagnostics";

#[derive(Debug)]
struct CapturedRequest {
    head: String,
    body: Value,
}

#[derive(Clone, Copy)]
struct HttpResponse {
    status: &'static str,
    body: &'static str,
}

impl HttpResponse {
    const fn json(status: &'static str, body: &'static str) -> Self {
        Self { status, body }
    }
}

struct LoopbackServer {
    base_url: String,
    join: JoinHandle<Vec<CapturedRequest>>,
}

impl LoopbackServer {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .expect("loopback listener should bind to an ephemeral port");
        let base_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("loopback listener should expose its address")
        );
        let join = thread::spawn(move || {
            let mut responses = VecDeque::from(responses);
            let mut requests = Vec::new();
            while let Some(response) = responses.pop_front() {
                let (mut stream, _) = listener.accept().expect("accept loopback request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("set loopback read timeout");
                let request = read_complete_request(&mut stream);
                requests.push(request);
                write_response(&mut stream, response);
            }
            requests
        });

        Self { base_url, join }
    }

    fn join(self) -> Vec<CapturedRequest> {
        self.join
            .join()
            .expect("loopback server thread should finish")
    }
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_workflow_activate_and_executions_use_production_http_client() {
    let server = LoopbackServer::start(vec![
        HttpResponse::json(
            "200 OK",
            r#"{"data":[{"id":"1001","name":"Ops workflow","active":false}]}"#,
        ),
        HttpResponse::json(
            "200 OK",
            r#"{"id":"1001","name":"Ops workflow","active":false,"versionId":"draft-v1","activeVersionId":null,"isArchived":false,"nodes":[{"id":"draft-node"}],"connections":{},"activeVersion":null}"#,
        ),
        HttpResponse::json(
            "200 OK",
            r#"{"id":"1001","name":"Ops workflow","active":true,"versionId":"draft-v1","activeVersionId":"published-v1","isArchived":false,"nodes":[{"id":"draft-node"}],"connections":{},"activeVersion":{"versionId":"published-v1","nodes":[{"id":"published-node"}],"connections":{}}}"#,
        ),
        HttpResponse::json(
            "200 OK",
            r#"{"id":"1001","name":"Ops workflow","active":true,"versionId":"draft-v1","activeVersionId":"published-v1","isArchived":false,"nodes":[{"id":"draft-node"}],"connections":{},"activeVersion":{"versionId":"published-v1","nodes":[{"id":"published-node"}],"connections":{}}}"#,
        ),
        HttpResponse::json("200 OK", r#"{"data":[{"id":"5001","finished":true}]}"#),
        HttpResponse::json(
            "200 OK",
            r#"{"id":"5001","finished":true,"workflowId":"1001","data":{"resultData":{"runData":{}}}}"#,
        ),
    ]);
    let mut connector = setup_connector(&server.base_url).await;

    let workflows = connector
        .handle_invoke(authorized_params(OP_WORKFLOWS_LIST, &json!({})))
        .await
        .expect("workflows.list should invoke n8n client path");
    assert_eq!(workflows["data"][0]["id"], "1001");

    let baseline = json!({
        "id": "1001",
        "name": "Ops workflow",
        "active": false,
        "versionId": "draft-v1",
        "activeVersionId": null,
        "isArchived": false,
        "nodes": [{"id": "draft-node"}],
        "connections": {},
        "activeVersion": null
    });
    let activation_input =
        activation_input("1001", true, workflow_state_digest_for_fixture(&baseline));
    let activation = connector
        .handle_invoke(authorized_params(OP_WORKFLOWS_ACTIVATE, &activation_input))
        .await
        .expect("activation should publish and verify through the production HTTP client");
    assert_eq!(activation["status"], "verified");
    assert_eq!(activation["operation"], OP_WORKFLOWS_ACTIVATE);
    assert_eq!(activation["active"], true);
    assert_eq!(activation["after"]["activeVersionId"], "published-v1");

    let executions = connector
        .handle_invoke(authorized_params(OP_EXECUTIONS_LIST, &json!({})))
        .await
        .expect("executions.list should invoke n8n client path");
    assert_eq!(executions["data"][0]["id"], "5001");

    let diagnostics = connector
        .handle_invoke(authorized_params(
            OP_EXECUTIONS_DIAGNOSTICS,
            &json!({"workflow_id": "1001", "id": "5001"}),
        ))
        .await
        .expect("executions.diagnostics should invoke n8n client path");
    assert_eq!(diagnostics["id"], "5001");
    assert_eq!(diagnostics["diagnostics"], json!([]));

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector");
    let requests = server.join();
    assert_eq!(requests.len(), 6);
    assert_request(
        &requests[0],
        "GET /api/v1/workflows?limit=50&excludePinnedData=true HTTP/1.1",
    );
    assert_request(&requests[1], "GET /api/v1/workflows/1001 HTTP/1.1");
    assert_request(&requests[2], "POST /api/v1/workflows/1001/publish HTTP/1.1");
    assert_request(&requests[3], "GET /api/v1/workflows/1001 HTTP/1.1");
    assert_request(
        &requests[4],
        "GET /api/v1/executions?limit=50&includeData=false&ignoreDataSizeLimit=false&redactExecutionData=true HTTP/1.1",
    );
    assert_request(
        &requests[5],
        "GET /api/v1/executions/5001?includeData=true HTTP/1.1",
    );
    assert_eq!(requests[0].body, json!({}));
    assert_eq!(requests[1].body, json!({}));
    assert_eq!(requests[2].body, json!({"versionId": "published-v1"}));
    assert_eq!(requests[3].body, json!({}));
    assert_eq!(requests[4].body, json!({}));
    assert_eq!(requests[5].body, json!({}));

    let rendered = serde_json::to_string(&json!({
        "workflows": workflows,
        "executions": executions,
        "diagnostics": diagnostics,
    }))
    .expect("rendered result should serialize");
    assert!(!rendered.contains(LOOPBACK_API_KEY));

    let artifact = proof_artifact(&json!({
        "request_response_boundary": {
            "workflows_list": {
                "method": "GET",
                "path": "/api/v1/workflows",
                "status": 200
            },
            "workflows_activate": {
                "method": "POST",
                "path": "/api/v1/workflows/1001/publish",
                "status": 200,
                "readback_status": "verified"
            },
            "executions_list": {
                "method": "GET",
                "path": "/api/v1/executions",
                "status": 200
            },
            "executions_diagnostics": {
                "method": "GET",
                "path": "/api/v1/executions/5001",
                "query": "includeData=true",
                "status": 200
            }
        },
        "auth_gate": {
            "mode": "x_n8n_api_key",
            "api_key_header_verified": true
        },
        "write_operation_shape": {
            "workflow_activate_typed_rest": true,
            "workflow_id": "1001",
            "body": {"versionId": "published-v1"}
        },
        "redaction": {
            "api_key_redacted_from_output": true
        },
        "cleanup": {
            "connector_shutdown": true,
            "fixture_requests_joined": requests.len()
        },
        "result": "passed"
    }));
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_unauthorized_maps_non_retryable_external_error() {
    let server = LoopbackServer::start(vec![HttpResponse::json(
        "401 Unauthorized",
        r#"{"message":"Unauthorized"}"#,
    )]);
    let connector = setup_connector(&server.base_url).await;

    let err = connector
        .handle_invoke(authorized_params(OP_WORKFLOWS_LIST, &json!({})))
        .await
        .expect_err("401 should map to an FCP external error");
    assert!(
        matches!(
            &err,
            FcpError::External {
                service,
                status_code: Some(401),
                retryable: false,
                retry_after: None,
                ..
            } if service == "n8n"
        ),
        "unauthorized response should map to non-retryable n8n external error: {err:?}"
    );

    let requests = server.join();
    assert_eq!(requests.len(), 1);
    assert_request(
        &requests[0],
        "GET /api/v1/workflows?limit=50&excludePinnedData=true HTTP/1.1",
    );

    let artifact = proof_artifact(&json!({
        "request_response_boundary": {
            "method": "GET",
            "path": "/api/v1/workflows",
            "status": 401
        },
        "error_mapping": {
            "service": "n8n",
            "status_code": 401,
            "retryable": false
        },
        "cleanup": {
            "fixture_requests_joined": requests.len()
        },
        "result": "passed"
    }));
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rejects_workflow_path_traversal_before_egress() {
    let server = LoopbackServer::start(Vec::new());
    let connector = setup_connector(&server.base_url).await;

    let err = connector
        .handle_invoke(authorized_params(
            OP_WORKFLOWS_ACTIVATE,
            &activation_input(
                "../admin",
                true,
                "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .into(),
            ),
        ))
        .await
        .expect_err("path traversal workflow id should be rejected before egress");
    assert!(
        matches!(
            &err,
            FcpError::InvalidRequest {
                code: 1005,
                message,
            } if message.contains("workflow id") && message.contains("path traversal")
        ),
        "path traversal should map to invalid request: {err:?}"
    );

    let requests = server.join();
    assert_eq!(requests.len(), 0);

    let artifact = proof_artifact(&json!({
        "egress_gate": {
            "operation": OP_WORKFLOWS_ACTIVATE,
            "unsafe_workflow_id_rejected_before_http": true,
            "requests_sent": requests.len()
        },
        "cleanup": {
            "fixture_requests_joined": requests.len()
        },
        "result": "passed"
    }));
    println!("{artifact}");
}

async fn setup_connector(base_url: &str) -> N8nConnector {
    let mut connector = N8nConnector::new();
    connector
        .handle_configure(json!({
            "api_key": LOOPBACK_API_KEY,
            "server_id": TEST_SERVER_ID,
            "base_url": format!("{base_url}/api/v1")
        }))
        .await
        .expect("configure connector");
    let key = test_signing_key();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": key.verifying_key().to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": [
                "n8n.workflows.read",
                "n8n.workflows.write",
                "n8n.executions.read"
            ],
            "requested_instance_id": TEST_INSTANCE_ID
        }))
        .await
        .expect("handshake connector");
    connector
}

fn test_signing_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[42_u8; 32]).expect("fixed test key should parse")
}

fn activation_input(id: &str, active: bool, state_digest: String) -> Value {
    let mut input = json!({
        "id": id,
        "active": active,
        "guard": {
            "approvalRef": "approval-local-non-mock",
            "idempotencyKey": "00000000-0000-4000-8000-000000000101",
            "precondition": {
                "versionId": "draft-v1",
                "activeVersionId": null,
                "active": false,
                "isArchived": false,
                "stateDigest": state_digest
            }
        }
    });
    if active {
        input["versionId"] = json!("published-v1");
    }
    input
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

fn workflow_state_digest_for_fixture(workflow: &Value) -> String {
    let active_version = workflow["activeVersion"].clone();
    let published = active_version.as_object().map(|published| {
        json!({
            "versionId": published["versionId"],
            "nodes": published["nodes"],
            "connections": published["connections"],
        })
    });
    let canonical = canonical_json(&json!({
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
    }));
    let bytes = serde_json::to_vec(&canonical).expect("state digest JSON");
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fwc-n8n.state-digest.v1");
    hasher.update(&[0]);
    hasher.update(&bytes);
    format!("blake3-256:{}", hasher.finalize().to_hex())
}

fn resource_uri(operation: &str, input: &Value) -> String {
    match operation {
        OP_WORKFLOWS_LIST | OP_EXECUTIONS_LIST => format!("fwc-n8n://{TEST_SERVER_ID}"),
        OP_EXECUTIONS_DIAGNOSTICS => {
            let workflow_id = input["workflow_id"]
                .as_str()
                .expect("workflow id for execution diagnostics token");
            let execution_id = input["id"]
                .as_str()
                .expect("execution id for execution diagnostics token");
            let workflow_id = utf8_percent_encode(workflow_id, NON_ALPHANUMERIC);
            let execution_id = utf8_percent_encode(execution_id, NON_ALPHANUMERIC);
            format!("fwc-n8n://{TEST_SERVER_ID}/workflows/{workflow_id}/executions/{execution_id}")
        }
        OP_WORKFLOWS_ACTIVATE => {
            let id = input["id"].as_str().expect("workflow id for test token");
            let id = utf8_percent_encode(id, NON_ALPHANUMERIC);
            format!("fwc-n8n://{TEST_SERVER_ID}/workflows/{id}")
        }
        _ => panic!("unknown operation in test token: {operation}"),
    }
}

fn capability_token(operation: &str, input: &Value) -> CapabilityToken {
    let capability = match operation {
        OP_WORKFLOWS_ACTIVATE => "n8n.workflows.write",
        OP_WORKFLOWS_LIST => "n8n.workflows.read",
        OP_EXECUTIONS_LIST | OP_EXECUTIONS_DIAGNOSTICS => "n8n.executions.read",
        _ => panic!("unknown operation in test token: {operation}"),
    };
    let constraints = CapabilityConstraints {
        resource_allow: vec![resource_uri(operation, input)],
        ..CapabilityConstraints::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("capability constraints should encode");
    let now = chrono::Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(TEST_INSTANCE_ID)
        .validity(now, now + chrono::Duration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("capability constraints should validate")
        .sign(&test_signing_key())
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

fn approval_token(input: &Value) -> ApprovalToken {
    let resource_uri = resource_uri(OP_WORKFLOWS_ACTIVATE, input);
    let input_bytes = to_deterministic_cbor(&json!({
        "server_id": TEST_SERVER_ID,
        "resource_uri": resource_uri,
        "operation": OP_WORKFLOWS_ACTIVATE,
        "input": input,
    }))
    .expect("approval binding CBOR");
    let input_hash = *blake3::hash(&input_bytes).as_bytes();
    let now = u64::try_from(chrono::Utc::now().timestamp_millis())
        .expect("current timestamp should fit in u64");
    ApprovalToken::approved(
        "approval-local-non-mock",
        now.saturating_sub(1_000),
        now.saturating_add(60_000),
        "operator:test",
        ApprovalScope::Execution(ExecutionScope {
            connector_id: "fcp.n8n".into(),
            method_pattern: OP_WORKFLOWS_ACTIVATE.into(),
            request_object_id: None,
            input_hash: Some(input_hash),
            input_constraints: Vec::new(),
        }),
        ZoneId::work(),
        Some(vec![1_u8]),
    )
}

fn authorized_params(operation: &str, input: &Value) -> Value {
    let mut params = json!({
        "operation": operation,
        "input": input,
        "capability_token": capability_token(operation, input),
    });
    if operation == OP_WORKFLOWS_ACTIVATE {
        params["approval_tokens"] = json!([approval_token(input)]);
    }
    params
}

fn assert_request(captured: &CapturedRequest, request_line: &str) {
    assert_eq!(
        captured
            .head
            .lines()
            .next()
            .expect("captured request should include request line"),
        request_line
    );
    assert!(
        header_seen(&captured.head, "x-n8n-api-key", LOOPBACK_API_KEY),
        "request should carry configured n8n API key header; head={}",
        captured.head
    );
    assert!(
        header_seen(&captured.head, "accept", "application/json"),
        "request should accept JSON; head={}",
        captured.head
    );
}

fn read_complete_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream
            .read(&mut buffer)
            .expect("loopback request should be readable");
        assert_ne!(read, 0, "loopback request ended before headers completed");
        bytes.extend_from_slice(&buffer[..read]);

        if let Some(header_end) = find_header_end(&bytes) {
            let body_start = header_end + 4;
            let head = String::from_utf8(bytes[..header_end].to_vec())
                .expect("HTTP request headers should be UTF-8");
            let content_length = content_length(&head);
            while bytes.len() < body_start + content_length {
                let read = stream
                    .read(&mut buffer)
                    .expect("loopback request body should be readable");
                assert_ne!(read, 0, "loopback request body ended early");
                bytes.extend_from_slice(&buffer[..read]);
            }
            let body = if content_length == 0 {
                json!({})
            } else {
                serde_json::from_slice(&bytes[body_start..body_start + content_length])
                    .expect("request body should be JSON")
            };
            return CapturedRequest { head, body };
        }
    }
}

fn write_response(stream: &mut TcpStream, response: HttpResponse) {
    let mut raw = format!("HTTP/1.1 {}\r\n", response.status);
    raw.push_str("content-type: application/json\r\n");
    write!(&mut raw, "content-length: {}\r\n", response.body.len())
        .expect("content-length should format");
    raw.push_str("connection: close\r\n\r\n");
    raw.push_str(response.body);
    stream
        .write_all(raw.as_bytes())
        .expect("loopback response should be writable");
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| {
                value
                    .trim()
                    .parse::<usize>()
                    .expect("content-length number")
            })
        })
        .unwrap_or(0)
}

fn header_seen(head: &str, name: &str, expected: &str) -> bool {
    head.lines().any(|line| {
        let Some((header_name, value)) = line.split_once(':') else {
            return false;
        };
        header_name.eq_ignore_ascii_case(name) && value.trim() == expected
    })
}

fn proof_artifact(details: &Value) -> Value {
    json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-n8n --test local_non_mock -- --nocapture",
        "fixture_mode": "raw_tcp_loopback_http",
        "provider_class": "local_sufficient",
        "details": details
    })
}
