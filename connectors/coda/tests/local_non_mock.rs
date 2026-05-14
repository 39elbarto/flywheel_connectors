use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_coda::CodaConnector;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use serde_json::{Value, json};

const API_TOKEN: &str = "tok_local_acceptance";
const WORKSPACE_ID: &str = "ws-local";
const DOC_ID: &str = "doc-1";
const OP_DOCS_LIST: &str = "coda.docs.list";
const OP_TABLES_LIST: &str = "coda.tables.list";
const OP_ROWS_LIST: &str = "coda.rows.list";

#[derive(Debug)]
struct CapturedRequest {
    head: String,
    body: Option<Value>,
}

struct LoopbackServer {
    base_url: String,
    received: Receiver<CapturedRequest>,
    join: JoinHandle<()>,
}

impl LoopbackServer {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .expect("loopback listener should bind to an ephemeral port");
        let base_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("loopback listener should expose its local address")
        );
        let (request_tx, received) = mpsc::channel();

        let join = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener
                    .accept()
                    .expect("loopback listener should accept the expected request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("loopback stream should set a read timeout");

                let request = read_complete_request(&mut stream);
                request_tx
                    .send(request)
                    .expect("captured request should be delivered to the test");

                let raw_response = format!(
                    "HTTP/1.1 {}\r\n\
                     content-type: application/json\r\n\
                     content-length: {}\r\n\
                     connection: close\r\n\
                     \r\n\
                     {}",
                    response.status,
                    response.body.len(),
                    response.body
                );
                stream
                    .write_all(raw_response.as_bytes())
                    .expect("loopback response should be writable");
            }
        });

        Self {
            base_url,
            received,
            join,
        }
    }

    fn take(&self) -> CapturedRequest {
        self.received
            .recv_timeout(Duration::from_secs(5))
            .expect("loopback request should arrive")
    }

    fn join(self) {
        self.join
            .join()
            .expect("loopback server thread should finish");
    }
}

struct HttpResponse {
    status: &'static str,
    body: &'static str,
}

fn read_complete_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    let mut header_end = None;
    let mut content_length = 0usize;

    loop {
        let read = stream
            .read(&mut buffer)
            .expect("loopback request should be readable");
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);

        if header_end.is_none() {
            header_end = bytes.windows(4).position(|window| window == b"\r\n\r\n");
            if let Some(end) = header_end {
                let head = String::from_utf8_lossy(&bytes[..end]).to_string();
                content_length = parse_content_length(&head);
            }
        }

        if let Some(end) = header_end {
            let body_start = end + 4;
            if bytes.len() >= body_start + content_length {
                let head = String::from_utf8(bytes[..end].to_vec())
                    .expect("request headers should be valid UTF-8");
                let body_slice = &bytes[body_start..body_start + content_length];
                let body = if body_slice.is_empty() {
                    None
                } else {
                    Some(
                        serde_json::from_slice(body_slice)
                            .expect("request body should be JSON when present"),
                    )
                };
                return CapturedRequest { head, body };
            }
        }
    }

    panic!("loopback request ended before complete headers/body were read");
}

fn parse_content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0)
}

fn assert_request(captured: &CapturedRequest, method: &str, target: &str) {
    let request_line = captured
        .head
        .lines()
        .next()
        .expect("captured request should include a request line");
    assert_eq!(request_line, format!("{method} {target} HTTP/1.1"));
    assert!(
        captured
            .head
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {API_TOKEN}")),
        "request should carry the configured bearer token; head={}",
        captured.head
    );
}

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [41u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("coda.account.read"),
            CapabilityId::from_static("coda.docs.read"),
            CapabilityId::from_static("coda.tables.read"),
            CapabilityId::from_static("coda.rows.read"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn capability_for(operation: &'static str) -> &'static str {
    match operation {
        OP_DOCS_LIST => "coda.docs.read",
        OP_TABLES_LIST => "coda.tables.read",
        OP_ROWS_LIST => "coda.rows.read",
        _ => panic!("unsupported Coda local acceptance operation: {operation}"),
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_for(operation))
        .zone_id("z:work")
        .principal("user:local-coda-acceptance")
        .operations(&[operation])
        .issuer("node:local-coda-acceptance")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should be valid")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn invoke_req(
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("coda-local-acceptance-1"),
        connector_id: ConnectorId::from_static("fcp.coda"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![],
    }
}

async fn setup_connector(base_url: &str) -> (CodaConnector, Ed25519SigningKey) {
    let mut connector = CodaConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "base_url": base_url,
            "workspace_id": WORKSPACE_ID,
            "allowed_doc_ids": [DOC_ID],
            "api_token": API_TOKEN,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            },
            "request_timeout_ms": 5_000,
            "mutation_poll_interval_ms": 1,
            "mutation_deadline_ms": 100
        }))
        .await
        .expect("Coda connector should configure against loopback");
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .expect("Coda connector should handshake with local host key");
    (connector, signing_key)
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_docs_list_preserves_workspace_query_and_scope_filter() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "200 OK",
        body: r#"{
            "items": [
                {"id":"doc-1","type":"doc","name":"Allowed Roadmap","workspaceId":"ws-local"},
                {"id":"doc-other","type":"doc","name":"Filtered Doc","workspaceId":"ws-local"}
            ],
            "nextPageToken": "next-docs",
            "nextPageLink": "https://coda.io/apis/v1/docs?pageToken=next-docs"
        }"#,
    }]);
    let (connector, signing_key) = setup_connector(&server.base_url).await;

    let response = connector
        .invoke(invoke_req(
            OP_DOCS_LIST,
            json!({
                "limit": 2,
                "page_token": "page-1",
                "query": "roadmap"
            }),
            generate_valid_token(&signing_key, OP_DOCS_LIST, connector.instance_id()),
        ))
        .await
        .expect("docs list should invoke against loopback");

    let captured = server.take();
    assert_request(
        &captured,
        "GET",
        "/docs?workspaceId=ws%2Dlocal&limit=2&pageToken=page%2D1&query=roadmap",
    );
    assert!(
        captured.body.is_none(),
        "docs list request should not send a JSON body"
    );
    server.join();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("docs list result");
    assert_eq!(result["items"].as_array().expect("items array").len(), 1);
    assert_eq!(result["items"][0]["id"], DOC_ID);
    assert_eq!(result["items"][0]["name"], "Allowed Roadmap");
    assert_eq!(result["nextPageToken"], "next-docs");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_tables_list_checks_doc_scope_then_fetches_tables() {
    let server = LoopbackServer::start(vec![
        HttpResponse {
            status: "200 OK",
            body: r#"{
                "id": "doc-1",
                "type": "doc",
                "name": "Allowed Roadmap",
                "workspaceId": "ws-local"
            }"#,
        },
        HttpResponse {
            status: "200 OK",
            body: r#"{
                "items": [
                    {
                        "id": "grid-tasks",
                        "type": "table",
                        "name": "Tasks",
                        "tableType": "table",
                        "rowCount": 3
                    }
                ],
                "nextPageToken": "next-tables"
            }"#,
        },
    ]);
    let (connector, signing_key) = setup_connector(&server.base_url).await;

    let response = connector
        .invoke(invoke_req(
            OP_TABLES_LIST,
            json!({
                "doc_id": DOC_ID,
                "limit": 1,
                "page_token": "table-page"
            }),
            generate_valid_token(&signing_key, OP_TABLES_LIST, connector.instance_id()),
        ))
        .await
        .expect("tables list should invoke against loopback");

    let doc_scope = server.take();
    assert_request(&doc_scope, "GET", "/docs/doc-1");
    assert!(
        doc_scope.body.is_none(),
        "doc scope check should not send a JSON body"
    );
    let tables = server.take();
    assert_request(
        &tables,
        "GET",
        "/docs/doc-1/tables?limit=1&pageToken=table%2Dpage",
    );
    assert!(
        tables.body.is_none(),
        "tables list request should not send a JSON body"
    );
    server.join();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("tables list result");
    assert_eq!(result["items"][0]["id"], "grid-tasks");
    assert_eq!(result["items"][0]["name"], "Tasks");
    assert_eq!(result["items"][0]["rowCount"], 3);
    assert_eq!(result["nextPageToken"], "next-tables");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rows_list_maps_provider_auth_denial() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "401 Unauthorized",
        body: r#"{"statusCode":401,"statusMessage":"Unauthorized","message":"bad token"}"#,
    }]);
    let (connector, signing_key) = setup_connector(&server.base_url).await;

    let error = connector
        .invoke(invoke_req(
            OP_ROWS_LIST,
            json!({
                "doc_id": DOC_ID,
                "table_id_or_name": "grid-tasks",
                "limit": 10
            }),
            generate_valid_token(&signing_key, OP_ROWS_LIST, connector.instance_id()),
        ))
        .await
        .expect_err("upstream auth denial should map to an FCP unauthorized error");

    let captured = server.take();
    assert_request(&captured, "GET", "/docs/doc-1");
    server.join();

    match error {
        FcpError::Unauthorized { code, message } => {
            assert_eq!(code, 2001);
            assert!(
                message.contains("Invalid API token"),
                "unexpected unauthorized message: {message}"
            );
        }
        other => panic!("expected unauthorized error, got {other:?}"),
    }
}
