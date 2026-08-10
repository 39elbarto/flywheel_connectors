//! Local loopback acceptance coverage for the MCP Bridge connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_mcp_bridge::connector::McpBridgeConnector;
use fcp_prelude::{
    ApprovalScope, ApprovalToken, CapabilityToken, ExecutionScope, FcpResult, InputConstraint,
    InstanceId, ZoneId,
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.7.3";
const CONNECTOR_ID: &str = "mcp-bridge";
const LOOPBACK_CREDENTIAL: &str = "mcp-bridge-local-loopback-credential";
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
const SERVER_ID: &str = "mcp-local";

#[derive(Debug)]
struct CapturedRequest {
    request_line: String,
    headers: String,
    body: String,
}

#[derive(Debug)]
struct Exchange {
    response_status: &'static str,
    response_body: String,
    extra_headers: &'static str,
}

impl Exchange {
    fn json(response_status: &'static str, response_body: &Value) -> Self {
        Self {
            response_status,
            response_body: response_body.to_string(),
            extra_headers: "",
        }
    }
}

struct LoopbackServer {
    base_url: String,
    handle: Option<JoinHandle<Vec<CapturedRequest>>>,
}

impl LoopbackServer {
    fn start(exchanges: Vec<Exchange>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind MCP loopback listener");
        listener
            .set_nonblocking(true)
            .expect("set loopback listener nonblocking");
        let address = listener
            .local_addr()
            .expect("read MCP loopback listener address");
        let handle = thread::spawn(move || {
            exchanges
                .into_iter()
                .map(|exchange| {
                    let stream = accept_with_deadline(&listener);
                    handle_request(stream, &exchange)
                })
                .collect()
        });

        Self {
            base_url: format!("http://{address}/mcp"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> Vec<CapturedRequest> {
        self.handle
            .take()
            .expect("loopback thread present")
            .join()
            .expect("loopback thread completed")
    }
}

struct NoEgressProbe {
    base_url: String,
    listener: TcpListener,
}

impl NoEgressProbe {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind no-egress listener");
        listener
            .set_nonblocking(true)
            .expect("set no-egress listener nonblocking");
        let address = listener
            .local_addr()
            .expect("read no-egress listener address");
        Self {
            base_url: format!("http://{address}/mcp"),
            listener,
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn assert_no_connection(&self) {
        thread::sleep(Duration::from_millis(50));
        match self.listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok((_, address)) => panic!("sampling operation unexpectedly opened {address}"),
            Err(error) => panic!("unexpected no-egress listener error: {error}"),
        }
    }
}

fn accept_with_deadline(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for MCP connector request"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept MCP connector request: {error}"),
        }
    }
}

fn handle_request(mut stream: TcpStream, exchange: &Exchange) -> CapturedRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set MCP request read timeout");
    let request = read_http_request(&mut stream);
    write!(
        stream,
        "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n{}\r\n{}",
        exchange.response_status,
        exchange.response_body.len(),
        exchange.extra_headers,
        exchange.response_body
    )
    .expect("write MCP loopback response");
    request
}

fn read_http_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let bytes_read = stream.read(&mut buffer).expect("read MCP request");
        assert!(bytes_read > 0, "connector should send request bytes");
        request.extend_from_slice(&buffer[..bytes_read]);
        if let Some(header_end) = find_header_end(&request) {
            break header_end;
        }
        assert!(
            request.len() < 8192,
            "MCP request headers should stay bounded"
        );
    };

    let header_bytes = &request[..header_end + 4];
    let headers = String::from_utf8_lossy(header_bytes).to_string();
    let content_length = content_length_from_headers(&headers);
    let mut body = request[header_end + 4..].to_vec();
    while body.len() < content_length {
        let bytes_read = stream.read(&mut buffer).expect("read MCP request body");
        assert!(bytes_read > 0, "connector body should match content-length");
        body.extend_from_slice(&buffer[..bytes_read]);
        assert!(body.len() <= 8192, "MCP request body should stay bounded");
    }
    body.truncate(content_length);

    CapturedRequest {
        request_line: headers.lines().next().unwrap_or_default().to_string(),
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length_from_headers(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn header_value<'a>(headers: &'a str, expected_name: &str) -> &'a str {
    headers
        .lines()
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case(expected_name) {
                Some(value.trim())
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("missing header {expected_name} in {headers}"))
}

fn assert_http_boundary(request: &CapturedRequest) {
    let mut parts = request.request_line.split_whitespace();
    assert_eq!(parts.next(), Some("POST"));
    assert_eq!(parts.next(), Some("/mcp"));
    assert_eq!(parts.next(), Some("HTTP/1.1"));
    assert_eq!(parts.next(), None);
    assert!(header_value(&request.headers, "content-type").contains("application/json"));
    assert_eq!(
        header_value(&request.headers, "authorization"),
        format!("Bearer {LOOPBACK_CREDENTIAL}")
    );
    assert_eq!(
        header_value(&request.headers, "mcp-protocol-version"),
        MCP_PROTOCOL_VERSION
    );
    let accept = header_value(&request.headers, "accept");
    assert!(accept.contains("application/json"));
    assert!(accept.contains("text/event-stream"));
    assert!(
        header_value(&request.headers, "user-agent")
            .contains("fcp-mcp-bridge/0.1.0 (FCP connector)")
    );
}

fn assert_rpc_request(request: &CapturedRequest, expected_method: &str) -> Value {
    assert_http_boundary(request);
    let body = serde_json::from_str::<Value>(&request.body).expect("parse JSON-RPC request body");
    assert_eq!(body["jsonrpc"], "2.0");
    assert!(
        body["id"].as_u64().is_some(),
        "JSON-RPC request id should be numeric"
    );
    assert_eq!(body["method"], expected_method);
    body
}

fn signing_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[43_u8; 32]).expect("deterministic local signing key")
}

fn resource_for(operation: &str, input: &Value) -> String {
    match operation {
        "mcp.tools.call" => format!(
            "fwc-mcp-bridge://{SERVER_ID}/tools/{}",
            utf8_percent_encode(input["name"].as_str().unwrap_or_default(), NON_ALPHANUMERIC)
        ),
        "mcp.resources.read" => format!(
            "fwc-mcp-bridge://{SERVER_ID}/resources/{}",
            utf8_percent_encode(input["uri"].as_str().unwrap_or_default(), NON_ALPHANUMERIC)
        ),
        _ => format!("fwc-mcp-bridge://{SERVER_ID}"),
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

fn payload_digest(operation: &str, input: &Value) -> [u8; 32] {
    let payload = if operation == "mcp.tools.call" {
        json!({
            "name": input["name"],
            "arguments": input.get("arguments").cloned().unwrap_or_else(|| json!({})),
        })
    } else {
        let candidate = input.get("request").unwrap_or(input);
        let params = candidate
            .get("params")
            .cloned()
            .unwrap_or_else(|| candidate.clone());
        json!({"method": "sampling/createMessage", "params": params})
    };
    let mut hasher = Sha256::new();
    hasher.update(b"FCP/MCP-Bridge/approval-payload/v1\0");
    hasher.update(canonical_json_bytes(&payload));
    hasher.finalize().into()
}

fn approval_for(operation: &str, input: &Value) -> ApprovalToken {
    let digest = payload_digest(operation, input);
    let resource_uri = resource_for(operation, input);
    let mut values = vec![
        ("server_id", json!(SERVER_ID)),
        ("resource_uri", json!(resource_uri)),
        ("operation", json!(operation)),
        (
            "provider",
            json!(if operation == "mcp.sampling.handle" {
                "local"
            } else {
                "mcp"
            }),
        ),
        ("payload_sha256", json!(hex::encode(digest))),
    ];
    if operation == "mcp.tools.call" {
        values.push(("tool_name", input["name"].clone()));
    } else {
        values.push(("sampling_method", json!("sampling/createMessage")));
    }
    let constraints = values
        .into_iter()
        .map(|(field, expected)| InputConstraint {
            pointer: format!("/{field}"),
            expected,
        })
        .collect();
    let now = Utc::now();
    ApprovalToken::approved(
        "local-approval",
        u64::try_from(now.timestamp_millis()).expect("timestamp"),
        u64::try_from((now + ChronoDuration::hours(1)).timestamp_millis()).expect("timestamp"),
        "operator:local",
        ApprovalScope::Execution(ExecutionScope {
            connector_id: "fcp.mcp-bridge".into(),
            method_pattern: operation.into(),
            request_object_id: None,
            input_hash: Some(digest),
            input_constraints: constraints,
        }),
        ZoneId::work(),
        Some(vec![1]),
    )
}

fn capability_for(operation: &str) -> &'static str {
    match operation {
        "mcp.tools.call" => "mcp.tools.write",
        "mcp.tools.list" => "mcp.tools.read",
        "mcp.resources.list" | "mcp.resources.read" => "mcp.resources.read",
        "mcp.prompts.list" => "mcp.prompts.read",
        "mcp.sampling.handle" => "mcp.sampling.handle",
        "mcp.server.metrics" => "mcp.server.metrics",
        _ => "mcp.unknown",
    }
}

fn capability_token(operation: &str, input: &Value, instance_id: &str) -> CapabilityToken {
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec![resource_for(operation, input)],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_for(operation))
        .zone_id("z:work")
        .principal("user:local")
        .operations(&[operation])
        .issuer("node:local")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints")
        .target_instance(instance_id)
        .sign(&signing_key())
        .expect("sign capability token");
    CapabilityToken::from_raw(raw)
}

struct TestConnector {
    inner: McpBridgeConnector,
    instance_id: String,
}

impl TestConnector {
    async fn handle_invoke(&self, mut params: Value) -> FcpResult<Value> {
        if let Some(operation) = params.get("operation_id").cloned() {
            params["operation"] = operation;
        }
        let operation = params
            .get("operation")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(operation) = operation.as_deref() {
            let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
            if capability_for(operation) != "mcp.unknown"
                && params.get("capability_token").is_none()
                && !(operation == "mcp.tools.call"
                    && input.get("name").and_then(Value::as_str).is_none())
            {
                params["capability_token"] =
                    serde_json::to_value(capability_token(operation, &input, &self.instance_id))
                        .expect("serialize capability token");
            }
            if matches!(operation, "mcp.tools.call" | "mcp.sampling.handle")
                && params.get("approval_tokens").is_none()
                && (operation != "mcp.tools.call"
                    || input.get("name").and_then(Value::as_str).is_some())
            {
                params["approval_tokens"] = json!([approval_for(operation, &input)]);
            }
        }
        self.inner.handle_invoke(params).await
    }
}

async fn configured_connector(base_url: &str) -> TestConnector {
    configured_connector_with(base_url, json!({})).await
}

async fn configured_connector_with(base_url: &str, extra: Value) -> TestConnector {
    let mut params = json!({
        "server_id": SERVER_ID,
        "mcp_url": base_url,
        "api_key": LOOPBACK_CREDENTIAL,
    });
    let params_object = params
        .as_object_mut()
        .expect("connector params should be an object");
    for (key, value) in extra
        .as_object()
        .expect("extra connector params should be an object")
    {
        params_object.insert(key.clone(), value.clone());
    }

    let mut connector = McpBridgeConnector::new();
    let instance_id = InstanceId::new().to_string();
    connector
        .handle_configure(params)
        .await
        .expect("configure MCP Bridge connector");
    connector
        .handle_handshake({
            let key = signing_key();
            json!({
                "protocol_version": "2.0",
                "zone": "z:work",
                "host_public_key": key.verifying_key().to_bytes(),
                "nonce": vec![8_u8; 32],
                "capabilities_requested": [
                    "mcp.tools.read", "mcp.tools.write", "mcp.resources.read",
                    "mcp.prompts.read", "mcp.sampling.handle", "mcp.server.metrics"
                ],
                "requested_instance_id": instance_id,
            })
        })
        .await
        .expect("handshake MCP Bridge connector");
    TestConnector {
        inner: connector,
        instance_id,
    }
}

fn emit_acceptance_evidence(operation: &str, result: &str, detail: &Value) {
    println!(
        "{}",
        json!({
            "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
            "suite_class": ACCEPTANCE_SUITE_CLASS,
            "bead_id": BEAD_ID,
            "connector": CONNECTOR_ID,
            "operation": operation,
            "fixture_mode": "raw_loopback_http",
            "provider_class": "local_sufficient",
            "result": result,
            "detail": detail,
        })
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_tools_list_posts_streamable_http_boundary_and_scans_catalog() {
    let server = LoopbackServer::start(vec![Exchange::json(
        "200 OK",
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "search_workspace",
                        "description": "Search project documents and return ranked snippets.",
                        "inputSchema": {"type": "object"}
                    },
                    {
                        "name": "evaluate_expression",
                        "description": "Evaluate a user formula with eval(user_input).",
                        "inputSchema": {"type": "object"}
                    }
                ]
            }
        }),
    )]);
    let connector = configured_connector(server.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .expect("list MCP tools");
    let requests = server.join();
    let body = assert_rpc_request(&requests[0], "tools/list");

    assert_eq!(body["params"], json!({}));
    let tools = result["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0]["name"], "search_workspace");
    assert!(
        tools[0]["injection_findings"]
            .as_array()
            .expect("safe tool findings")
            .is_empty()
    );
    let suspicious_findings = tools[1]["injection_findings"]
        .as_array()
        .expect("suspicious tool findings");
    assert!(
        suspicious_findings
            .iter()
            .any(|finding| finding["pattern_id"] == "code_execution_reference")
    );

    let metrics = connector
        .handle_invoke(json!({"operation_id": "mcp.server.metrics", "input": {}}))
        .await
        .expect("read MCP bridge metrics");
    assert_eq!(metrics["requests"], 2);
    assert_eq!(metrics["injection_scans"], 2);
    assert!(metrics["injection_findings"].as_u64().unwrap_or(0) >= 1);

    emit_acceptance_evidence(
        "mcp.tools.list",
        "pass",
        &json!({
            "requests_observed": requests.len(),
            "catalog_entries": tools.len(),
            "scanner_findings": metrics["injection_findings"],
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_tools_call_is_deferred_before_http_effect() {
    let probe = NoEgressProbe::start();
    let connector = configured_connector(probe.base_url()).await;

    let error = connector
        .handle_invoke(json!({
            "operation_id": "mcp.tools.call",
            "input": {
                "name": "search_workspace",
                "arguments": {
                    "query": "release",
                    "limit": 3
                }
            }
        }))
        .await
        .expect_err("tools.call must remain deferred");
    assert!(format!("{error:?}").contains("deferred"));
    probe.assert_no_connection();

    emit_acceptance_evidence(
        "mcp.tools.call",
        "pass",
        &json!({
            "requests_observed": 0,
            "arguments_forwarded": false,
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_resources_read_and_prompts_list_use_json_rpc_boundary() {
    let server = LoopbackServer::start(vec![
        Exchange::json(
            "200 OK",
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "contents": [
                        {
                            "uri": "file:///workspace/README.md",
                            "mimeType": "text/markdown",
                            "text": "# Workspace"
                        }
                    ]
                }
            }),
        ),
        Exchange::json(
            "200 OK",
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "prompts": [
                        {
                            "name": "summarize_project",
                            "description": "Summarize project status with cited resources."
                        }
                    ]
                }
            }),
        ),
    ]);
    let connector = configured_connector(server.base_url()).await;

    let resource = connector
        .handle_invoke(json!({
            "operation_id": "mcp.resources.read",
            "input": {"uri": "file:///workspace/README.md"}
        }))
        .await
        .expect("read MCP resource");
    let prompts = connector
        .handle_invoke(json!({
            "operation_id": "mcp.prompts.list",
            "input": {}
        }))
        .await
        .expect("list MCP prompts");
    let requests = server.join();

    let resource_body = assert_rpc_request(&requests[0], "resources/read");
    assert_eq!(
        resource_body["params"]["uri"],
        "file:///workspace/README.md"
    );
    assert_eq!(resource["contents"][0]["text"], "# Workspace");

    let prompts_body = assert_rpc_request(&requests[1], "prompts/list");
    assert_eq!(prompts_body["params"], json!({}));
    assert_eq!(prompts["prompts"][0]["name"], "summarize_project");
    assert!(
        prompts["prompts"][0]["injection_findings"]
            .as_array()
            .expect("prompt findings")
            .is_empty()
    );

    emit_acceptance_evidence(
        "mcp.resources.read+mcp.prompts.list",
        "pass",
        &json!({
            "requests_observed": requests.len(),
            "resource_uri": resource_body["params"]["uri"],
            "prompt_entries": prompts["prompts"].as_array().map_or(0, Vec::len),
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_block_mode_rejects_suspicious_provider_descriptions() {
    let server = LoopbackServer::start(vec![Exchange::json(
        "200 OK",
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "unsafe_runner",
                        "description": "Execute operator text with eval(user_input)."
                    }
                ]
            }
        }),
    )]);
    let connector = configured_connector_with(
        server.base_url(),
        json!({
            "security": {"description_scan": "block"}
        }),
    )
    .await;

    let error = connector
        .handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .expect_err("suspicious MCP tool description should be blocked");
    let requests = server.join();
    assert_rpc_request(&requests[0], "tools/list");
    let error_text = format!("{error:?}");
    assert!(
        error_text.contains("LOCAL_POLICY: catalog description blocked by local scanner policy")
    );
    assert!(!error_text.contains("eval(user_input)"));
    assert!(!error_text.contains("unsafe_runner"));

    emit_acceptance_evidence(
        "mcp.tools.list.security",
        "pass",
        &json!({
            "requests_observed": requests.len(),
            "blocked": true,
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_provider_unauthorized_is_single_attempt_and_redacted() {
    let server = LoopbackServer::start(vec![Exchange::json(
        "401 Unauthorized",
        &json!({
            "error": format!("provider saw {LOOPBACK_CREDENTIAL}")
        }),
    )]);
    let connector = configured_connector(server.base_url()).await;

    let error = connector
        .handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .expect_err("provider auth failure should propagate as redacted FCP error");
    let requests = server.join();
    assert_eq!(requests.len(), 1);
    for request in &requests {
        assert_rpc_request(request, "tools/list");
        assert_eq!(
            header_value(&request.headers, "authorization"),
            format!("Bearer {LOOPBACK_CREDENTIAL}")
        );
    }

    let error_text = format!("{error:?}");
    assert!(error_text.contains("Authentication failed"));
    assert!(!error_text.contains(LOOPBACK_CREDENTIAL));
    assert!(!error_text.contains("provider saw"));

    let metrics = connector
        .handle_invoke(json!({"operation_id": "mcp.server.metrics", "input": {}}))
        .await
        .expect("read retry metrics");
    assert_eq!(metrics["requests"], 2);
    assert_eq!(metrics["errors"], 1);
    assert_eq!(metrics["auth_retries"], 0);

    emit_acceptance_evidence(
        "mcp.tools.list.auth_failure",
        "pass",
        &json!({
            "requests_observed": requests.len(),
            "auth_retries": metrics["auth_retries"],
            "secret_redacted": true,
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_sampling_handle_is_local_and_does_not_contact_provider() {
    let probe = NoEgressProbe::start();
    let connector = configured_connector_with(
        probe.base_url(),
        json!({
            "sampling": {
                "enabled": true,
                "llm_connector": "groq",
                "max_tokens_cap": 256,
                "allowed_models": ["llama-3.3"]
            }
        }),
    )
    .await;

    let result = connector
        .handle_invoke(json!({
            "operation_id": "mcp.sampling.handle",
            "input": {
                "request": {
                    "method": "sampling/createMessage",
                    "params": {
                        "messages": [
                            {
                                "role": "user",
                                "content": {"type": "text", "text": "summarize the local transcript"}
                            }
                        ],
                        "maxTokens": 128
                    }
                }
            }
        }))
        .await
        .expect("handle MCP sampling request locally");
    probe.assert_no_connection();

    assert_eq!(result["dispatch"], "agent_event");
    assert_eq!(result["host_orchestrated"], false);
    assert_eq!(result["requires_human_approval"], true);
    assert_eq!(result["llm_connector"], "groq");
    assert_eq!(result["redaction"]["prompt_logged"], false);

    let metrics = connector
        .handle_invoke(json!({"operation_id": "mcp.server.metrics", "input": {}}))
        .await
        .expect("read sampling metrics");
    assert_eq!(metrics["requests"], 2);
    assert_eq!(metrics["sampling_requests"], 1);

    emit_acceptance_evidence(
        "mcp.sampling.handle",
        "pass",
        &json!({
            "provider_egress": "none_observed",
            "sampling_requests": metrics["sampling_requests"],
            "requires_human_approval": result["requires_human_approval"],
        }),
    );
}
