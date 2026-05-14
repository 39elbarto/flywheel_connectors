#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_coda::connector::CodaConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InvokeRequest, OperationId, RequestId, ZoneId,
};
use serde_json::{Value, json};

const API_TOKEN: &str = "local-coda-token";
const OP_DOCS_LIST: &str = "coda.docs.list";
const CAP_DOCS_READ: &str = "coda.docs.read";

struct CapturedRequest {
    head: String,
}

struct LoopbackServer {
    base_url: String,
    received: Receiver<CapturedRequest>,
    join: JoinHandle<()>,
}

impl LoopbackServer {
    fn start(status: &'static str, body: &'static str) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .expect("loopback listener should bind to an ephemeral port");
        let base_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("loopback listener should expose its address")
        );
        let (request_tx, received) = mpsc::channel();

        let join = thread::spawn(move || {
            let (mut stream, _) = listener
                .accept()
                .expect("loopback listener should accept one request");
            stream
                .set_read_timeout(Some(StdDuration::from_secs(5)))
                .expect("loopback stream should set a read timeout");

            let request = read_request_head(&mut stream);
            request_tx
                .send(request)
                .expect("captured request should be delivered to the test");

            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("loopback response should be writable");
        });

        Self {
            base_url,
            received,
            join,
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn finish(self) -> CapturedRequest {
        let request = self
            .received
            .recv_timeout(StdDuration::from_secs(5))
            .expect("loopback server should capture one request");
        self.join
            .join()
            .expect("loopback server thread should finish cleanly");
        request
    }
}

fn read_request_head(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let count = stream
            .read(&mut buffer)
            .expect("loopback request should be readable");
        assert!(count > 0, "client closed before request head was complete");
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&bytes[..header_end + 4]).into_owned();
            return CapturedRequest { head };
        }
    }
}

fn request_target(head: &str) -> &str {
    head.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("request line should include target")
}

fn header_value<'a>(head: &'a str, wanted: &str) -> &'a str {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(wanted).then_some(value.trim())
        })
        .unwrap_or_else(|| panic!("missing expected header {wanted}"))
}

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [42_u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_DOCS_READ)],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn capability_token(signing_key: &Ed25519SigningKey, instance_id: &str) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("capability constraints should serialize");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_DOCS_READ)
        .zone_id("z:work")
        .principal("user:coda-local")
        .operations(&[OP_DOCS_LIST])
        .issuer("node:coda-local")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should be valid")
        .target_instance(instance_id)
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

async fn configured_connector(base_url: &str) -> (CodaConnector, Ed25519SigningKey) {
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = CodaConnector::new();
    connector
        .configure(json!({
            "base_url": base_url,
            "workspace_id": "ws-local",
            "allowed_doc_ids": ["doc-allowed"],
            "api_token": API_TOKEN,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            },
            "request_timeout_ms": 1_000,
            "mutation_poll_interval_ms": 1,
            "mutation_deadline_ms": 100
        }))
        .await
        .expect("Coda connector should configure against loopback");
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .expect("Coda connector should handshake after configuration");
    (connector, signing_key)
}

fn docs_list_request(connector: &CodaConnector, signing_key: &Ed25519SigningKey) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("coda-local-non-mock"),
        connector_id: ConnectorId::from_static("fcp.coda"),
        operation: OperationId::from_static(OP_DOCS_LIST),
        zone_id: ZoneId::work(),
        input: json!({
            "limit": 2,
            "query": "roadmap"
        }),
        capability_token: capability_token(signing_key, connector.instance_id().as_str()),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

fn docs_response_body() -> &'static str {
    r#"{
      "items": [
        {
          "id": "doc-allowed",
          "type": "doc",
          "name": "Local FCP Roadmap",
          "href": "https://coda.io/apis/v1/docs/doc-allowed",
          "browserLink": "https://coda.io/d/Local-FCP-Roadmap_doc-allowed",
          "workspaceId": "ws-local",
          "workspace": {"id": "ws-local", "type": "workspace"}
        },
        {
          "id": "doc-denied",
          "type": "doc",
          "name": "Outside Scope",
          "workspaceId": "ws-other"
        }
      ],
      "nextPageToken": "page-two"
    }"#
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_docs_list_uses_bearer_auth_workspace_query_and_filters_scope() {
    let server = LoopbackServer::start("200 OK", docs_response_body());
    let (connector, signing_key) = configured_connector(server.base_url()).await;

    let response = connector
        .invoke(docs_list_request(&connector, &signing_key))
        .await
        .expect("loopback Coda docs list should succeed");
    let captured = server.finish();
    let result = response
        .result
        .expect("successful invoke response should carry result JSON");

    let target = request_target(&captured.head);
    assert!(captured.head.starts_with("GET /docs?"));
    assert!(target.contains("workspaceId=ws%2Dlocal"));
    assert!(target.contains("limit=2"));
    assert!(target.contains("query=roadmap"));
    assert_eq!(
        header_value(&captured.head, "authorization"),
        format!("Bearer {API_TOKEN}")
    );

    assert_eq!(
        result["items"]
            .as_array()
            .expect("items should be array")
            .len(),
        1
    );
    assert_eq!(result["items"][0]["id"], json!("doc-allowed"));
    assert_eq!(result["nextPageToken"], json!("page-two"));

    let evidence = redaction_safe_evidence(&captured.head, target, &result);
    let evidence_text = evidence.to_string();
    assert_eq!(evidence["connector"], json!("coda"));
    assert_eq!(evidence["operation"], json!(OP_DOCS_LIST));
    assert!(!evidence_text.contains(API_TOKEN));
    assert!(evidence_text.contains("[REDACTED]"));
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_docs_list_maps_provider_auth_denial() {
    let server = LoopbackServer::start("401 Unauthorized", r#"{"message":"bad token"}"#);
    let (connector, signing_key) = configured_connector(server.base_url()).await;

    let error = connector
        .invoke(docs_list_request(&connector, &signing_key))
        .await
        .expect_err("401 loopback response should map to an auth denial");
    let captured = server.finish();

    assert!(captured.head.starts_with("GET /docs?"));
    assert_eq!(
        header_value(&captured.head, "authorization"),
        format!("Bearer {API_TOKEN}")
    );
    match error {
        FcpError::Unauthorized { code, message } => {
            assert_eq!(code, 2001);
            assert_eq!(message, "Invalid API token");
        }
        other => panic!("expected Coda auth denial, got {other:?}"),
    }
}

fn redaction_safe_evidence(head: &str, target: &str, result: &Value) -> Value {
    let mut headers = Vec::new();
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("authorization") {
            headers.push(json!({"name": name, "value": "[REDACTED]"}));
        } else {
            headers.push(json!({"name": name, "value": value.trim()}));
        }
    }

    json!({
        "connector": "coda",
        "operation": OP_DOCS_LIST,
        "transport": "local_tcp_http",
        "request": {
            "method": "GET",
            "target": target,
            "headers": headers,
        },
        "response": {
            "status_class": "success",
            "items_returned": result["items"].as_array().map_or(0, Vec::len),
            "next_page_token_present": result.get("nextPageToken").is_some(),
        }
    })
}
