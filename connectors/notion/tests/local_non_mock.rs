//! Local loopback acceptance coverage for the FCP Notion connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines
)]

use std::{
    fmt::Write as FmtWrite,
    io::{Read, Write as IoWrite},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::Duration as StdDuration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_notion::{client::DEFAULT_NOTION_VERSION, connector::NotionConnector};
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError, InstanceId};
use serde_json::{Value, json};

const CONNECTOR: &str = "notion";
const PACKAGE: &str = "fcp-notion";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.15";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const LOOPBACK_BEARER_VALUE: &str = "ntn_local_non_mock_marker";
const OP_SEARCH: &str = "notion.search";
const CAP_SEARCH: &str = "notion.search";
const CAP_READ: &str = "notion.read";
const EXPECTED_PATH: &str = "/v1/search";

#[derive(Debug)]
struct CapturedRequest {
    head: String,
    body: Value,
}

struct LoopbackServer {
    base_url: String,
    received: Receiver<CapturedRequest>,
    join: JoinHandle<()>,
}

impl LoopbackServer {
    fn start(response: HttpResponse) -> Self {
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
                .expect("loopback listener should accept expected request");
            stream
                .set_read_timeout(Some(StdDuration::from_secs(5)))
                .expect("loopback stream should set read timeout");

            let request = read_complete_request(&mut stream);
            request_tx
                .send(request)
                .expect("captured request should be delivered to test");

            let mut raw_response = format!("HTTP/1.1 {}\r\n", response.status);
            raw_response.push_str("content-type: application/json\r\n");
            write!(
                &mut raw_response,
                "content-length: {}\r\n",
                response.body.len()
            )
            .expect("content-length should format");
            raw_response.push_str("connection: close\r\n\r\n");
            raw_response.push_str(response.body);

            stream
                .write_all(raw_response.as_bytes())
                .expect("loopback response should be writable");
        });

        Self {
            base_url,
            received,
            join,
        }
    }

    fn notion_api_url(&self) -> String {
        format!("{}/v1", self.base_url)
    }

    fn take(&self) -> CapturedRequest {
        self.received
            .recv_timeout(StdDuration::from_secs(5))
            .expect("loopback request should arrive")
    }

    fn join(self) {
        self.join
            .join()
            .expect("loopback server thread should finish");
    }
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

fn read_complete_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    let mut header_end = None;
    let mut content_length = 0usize;

    loop {
        let read = stream
            .read(&mut buffer)
            .expect("loopback request should be readable");
        assert!(read > 0, "connector request should not close early");
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
                    .expect("request headers should be UTF-8");
                let body = serde_json::from_slice(&bytes[body_start..body_start + content_length])
                    .expect("request body should be JSON");
                return CapturedRequest { head, body };
            }
        }

        assert!(bytes.len() < 65_536, "loopback request should stay bounded");
    }
}

fn parse_content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .expect("request should carry content-length")
}

fn header_seen(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name) && value.trim() == expected_value
    })
}

fn assert_request(captured: &CapturedRequest) {
    let request_line = captured
        .head
        .lines()
        .next()
        .expect("captured request should include request line");
    assert_eq!(request_line, format!("POST {EXPECTED_PATH} HTTP/1.1"));
    assert!(
        header_seen(
            &captured.head,
            "authorization",
            &format!("Bearer {LOOPBACK_BEARER_VALUE}")
        ),
        "request should carry configured Notion bearer token; head={}",
        captured.head
    );
    assert!(
        header_seen(&captured.head, "notion-version", DEFAULT_NOTION_VERSION),
        "request should carry Notion-Version header; head={}",
        captured.head
    );
    assert!(
        header_seen(&captured.head, "content-type", "application/json"),
        "request should carry JSON content type; head={}",
        captured.head
    );
}

fn valid_capability_grant(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize capability constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:local-non-mock")
        .operations(&[operation])
        .issuer("node:local-non-mock")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

async fn setup_connector(
    api_url: &str,
    capabilities: &[&str],
) -> (NotionConnector, Ed25519SigningKey) {
    let mut connector = NotionConnector::new();
    connector
        .handle_configure(json!({
            "token": LOOPBACK_BEARER_VALUE,
            "api_url": api_url
        }))
        .await
        .expect("configure connector");

    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![7_u8; 32],
            "capabilities_requested": capabilities
        }))
        .await
        .expect("handshake connector");

    (connector, signing_key)
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_search_posts_body_headers_and_redacts_output() {
    let server = LoopbackServer::start(HttpResponse::json(
        "200 OK",
        r#"{
            "object": "list",
            "results": [{
                "object": "page",
                "id": "page-local-proof",
                "created_by": {
                    "object": "user",
                    "id": "user-created",
                    "type": "person",
                    "person": {"email": "owner@example.com"}
                },
                "last_edited_by": {
                    "object": "user",
                    "id": "user-edited",
                    "type": "person",
                    "person": {"email": "editor@example.com"}
                },
                "properties": {
                    "Owner": {
                        "id": "owner",
                        "type": "people",
                        "people": [{
                            "object": "user",
                            "id": "user-owner",
                            "type": "person",
                            "person": {"email": "workspace-owner@example.com"}
                        }]
                    }
                }
            }],
            "has_more": false,
            "next_cursor": null
        }"#,
    ));
    let (connector, signing_key) = setup_connector(&server.notion_api_url(), &[CAP_SEARCH]).await;
    let grant =
        valid_capability_grant(&signing_key, connector.instance_id(), CAP_SEARCH, OP_SEARCH);

    let result = connector
        .handle_invoke(json!({
            "operation": OP_SEARCH,
            "input": {
                "query": "FCP local proof",
                "filter": {"property": "object", "value": "page"}
            },
            "capability_token": grant
        }))
        .await
        .expect("search should succeed through loopback fixture");
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector");

    let captured = server.take();
    server.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert_request(&captured);
    assert_eq!(
        captured.body,
        json!({
            "query": "FCP local proof",
            "filter": {"property": "object", "value": "page"}
        })
    );
    assert_eq!(result["result_count"], 1);
    assert_eq!(result["sensitivity"], "workspace_wide");
    assert_eq!(result["provenance"]["source"], "notion.search");
    assert_eq!(
        result["results"][0]["created_by"]["person"]["email"],
        "[redacted]"
    );
    assert_eq!(
        result["results"][0]["last_edited_by"]["person"]["email"],
        "[redacted]"
    );
    assert_eq!(
        result["results"][0]["properties"]["Owner"]["people"][0]["person"]["email"],
        "[redacted]"
    );
    let rendered_result = result.to_string();
    assert!(!rendered_result.contains("owner@example.com"));
    assert!(!rendered_result.contains("editor@example.com"));
    assert!(!rendered_result.contains("workspace-owner@example.com"));
    assert!(!rendered_result.contains(LOOPBACK_BEARER_VALUE));

    let artifact = json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-notion --test local_non_mock -- --nocapture",
        "fixture_mode": "raw_tcp_loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundary": {
            "method": "POST",
            "path": EXPECTED_PATH
        },
        "auth_gate": {
            "mode": "bearer_and_capability_token",
            "authorization_header_verified": header_seen(
                &captured.head,
                "authorization",
                &format!("Bearer {LOOPBACK_BEARER_VALUE}")
            ),
            "notion_version_header_verified": header_seen(
                &captured.head,
                "notion-version",
                DEFAULT_NOTION_VERSION
            )
        },
        "request_body": captured.body,
        "redaction": {
            "email_fields_redacted": true,
            "token_redacted_from_output": true
        },
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_search_rejects_wrong_capability_token() {
    let (connector, signing_key) = setup_connector("http://127.0.0.1:1/v1", &[CAP_SEARCH]).await;
    let grant = valid_capability_grant(&signing_key, connector.instance_id(), CAP_READ, OP_SEARCH);

    let err = connector
        .handle_invoke(json!({
            "operation": OP_SEARCH,
            "input": {"query": "should not leave connector"},
            "capability_token": grant
        }))
        .await
        .expect_err("wrong capability must be rejected before HTTP egress");

    assert!(
        matches!(
            err,
            FcpError::Unauthorized { .. } | FcpError::OperationNotGranted { .. }
        ),
        "expected capability denial, got {err:?}"
    );

    let artifact = json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-notion --test local_non_mock -- --nocapture",
        "capability_token_gate": {
            "wrong_capability": CAP_READ,
            "required_capability": CAP_SEARCH,
            "http_egress_attempted": false
        },
        "result": "passed"
    });
    println!("{artifact}");
}
