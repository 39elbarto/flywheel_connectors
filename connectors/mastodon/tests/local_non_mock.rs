//! Local loopback acceptance coverage for the FCP `Mastodon` connector.

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
    io::{ErrorKind, Read, Write as IoWrite},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_mastodon::MastodonConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError, HandshakeRequest,
    InstanceId, InvokeRequest, OperationId, RequestId, ShutdownRequest, ZoneId,
};
use serde_json::{Value, json};

const CONNECTOR: &str = "mastodon";
const PACKAGE: &str = "fcp-mastodon";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.18";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const LOOPBACK_BEARER_VALUE: &str = "mastodon-local-non-mock-marker";
const OP_TIMELINE_HOME: &str = "mastodon.timeline.home";
const OP_STATUSES_POST: &str = "mastodon.statuses.post";
const OP_HEALTH: &str = "mastodon.health";
const CAP_READ: &str = "mastodon.read";
const CAP_WRITE: &str = "mastodon.write";

const TIMELINE_RESPONSE: &str = r#"[{
    "id": "status_home",
    "uri": "https://mastodon.local/users/alice/statuses/status_home",
    "url": "https://mastodon.local/@alice/status_home",
    "content": "<p>home</p>",
    "created_at": "2026-05-01T12:00:00.000Z",
    "account": {
        "id": "acct_1",
        "username": "alice",
        "acct": "alice",
        "display_name": "Alice",
        "note": "",
        "url": "https://mastodon.local/@alice",
        "avatar": "https://mastodon.local/avatar.png",
        "header": "https://mastodon.local/header.png",
        "followers_count": 12,
        "following_count": 7,
        "statuses_count": 5,
        "locked": false,
        "bot": false,
        "created_at": "2026-05-01T00:00:00.000Z"
    },
    "reblogs_count": 1,
    "favourites_count": 2,
    "replies_count": 3,
    "visibility": "public",
    "sensitive": false,
    "spoiler_text": "",
    "media_attachments": [],
    "reblog": null,
    "favourited": false,
    "reblogged": false,
    "application": null,
    "in_reply_to_id": null,
    "in_reply_to_account_id": null
}]"#;

const STATUS_RESPONSE: &str = r#"{
    "id": "status_created",
    "uri": "https://mastodon.local/users/alice/statuses/status_created",
    "url": "https://mastodon.local/@alice/status_created",
    "content": "<p>hello from fcp</p>",
    "created_at": "2026-05-01T12:05:00.000Z",
    "account": {
        "id": "acct_1",
        "username": "alice",
        "acct": "alice",
        "display_name": "Alice",
        "note": "",
        "url": "https://mastodon.local/@alice",
        "avatar": "https://mastodon.local/avatar.png",
        "header": "https://mastodon.local/header.png",
        "followers_count": 12,
        "following_count": 7,
        "statuses_count": 5,
        "locked": false,
        "bot": false,
        "created_at": "2026-05-01T00:00:00.000Z"
    },
    "reblogs_count": 0,
    "favourites_count": 0,
    "replies_count": 0,
    "visibility": "unlisted",
    "sensitive": true,
    "spoiler_text": "release notes",
    "media_attachments": [],
    "reblog": null,
    "favourited": false,
    "reblogged": false,
    "application": null,
    "in_reply_to_id": "status_parent",
    "in_reply_to_account_id": null
}"#;

const INSTANCE_RESPONSE: &str = r#"{
    "uri": "mastodon.local",
    "domain": "mastodon.local",
    "title": "FCP Mastodon",
    "version": "4.2.12"
}"#;

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

    const fn empty(status: &'static str) -> Self {
        Self { status, body: "" }
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

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(self) -> Vec<CapturedRequest> {
        self.join
            .join()
            .expect("loopback server thread should finish")
    }
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_read_and_write_use_production_http_client() {
    let server = LoopbackServer::start(vec![
        HttpResponse::json("200 OK", TIMELINE_RESPONSE),
        HttpResponse::json("200 OK", STATUS_RESPONSE),
    ]);
    let (mut connector, signing_key, instance_id) = setup_connector(server.base_url()).await;

    let home = connector
        .invoke(invoke_req(
            &connector,
            OP_TIMELINE_HOME,
            json!({"limit": 2}),
            capability_token(&signing_key, &instance_id, CAP_READ, OP_TIMELINE_HOME),
        ))
        .await
        .expect("home timeline should invoke Mastodon client path");
    assert_eq!(
        home.result
            .as_ref()
            .expect("home timeline should return result")[0]["id"],
        "status_home"
    );

    let posted = connector
        .invoke(invoke_req(
            &connector,
            OP_STATUSES_POST,
            json!({
                "status": "hello from fcp",
                "visibility": "unlisted",
                "in_reply_to_id": "status_parent",
                "sensitive": true,
                "spoiler_text": "release notes"
            }),
            capability_token(&signing_key, &instance_id, CAP_WRITE, OP_STATUSES_POST),
        ))
        .await
        .expect("status post should invoke Mastodon client path");
    assert_eq!(
        posted
            .result
            .as_ref()
            .expect("status post should return result")["id"],
        "status_created"
    );

    connector
        .shutdown(shutdown_req())
        .await
        .expect("shutdown connector");
    let requests = server.join();
    assert_eq!(requests.len(), 2);
    assert_request(&requests[0], "GET /api/v1/timelines/home?limit=2 HTTP/1.1");
    assert_request(&requests[1], "POST /api/v1/statuses HTTP/1.1");
    assert_eq!(requests[0].body, json!({}));
    assert_eq!(requests[1].body["status"], "hello from fcp");
    assert_eq!(requests[1].body["visibility"], "unlisted");
    assert_eq!(requests[1].body["sensitive"], true);

    let rendered = serde_json::to_string(&json!({
        "home": home.result,
        "posted": posted.result,
    }))
    .expect("rendered result should serialize");
    assert!(!rendered.contains(LOOPBACK_BEARER_VALUE));

    let artifact = proof_artifact(&json!({
        "request_response_boundary": {
            "timeline_home": {
                "method": "GET",
                "path": "/api/v1/timelines/home",
                "query": "limit=2",
                "status": 200
            },
            "statuses_post": {
                "method": "POST",
                "path": "/api/v1/statuses",
                "status": 200
            }
        },
        "auth_gate": {
            "mode": "bearer_header",
            "authorization_header_verified": true,
            "capability_tokens": ["mastodon.read", "mastodon.write"]
        },
        "redaction": {
            "auth_marker_redacted_from_output": true
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
async fn local_non_mock_health_uses_v2_then_v1_instance_fallback() {
    let server = LoopbackServer::start(vec![
        HttpResponse::empty("404 Not Found"),
        HttpResponse::json("200 OK", INSTANCE_RESPONSE),
    ]);
    let (mut connector, signing_key, instance_id) = setup_connector(server.base_url()).await;

    let health = connector
        .invoke(invoke_req(
            &connector,
            OP_HEALTH,
            json!({}),
            capability_token(&signing_key, &instance_id, CAP_READ, OP_HEALTH),
        ))
        .await
        .expect("health should fall back from v2 to v1 instance endpoint");
    assert_eq!(
        health.result.as_ref().expect("health should return result")["title"],
        "FCP Mastodon"
    );

    connector
        .shutdown(shutdown_req())
        .await
        .expect("shutdown connector");
    let requests = server.join();
    assert_eq!(requests.len(), 2);
    assert_request_line(&requests[0], "GET /api/v2/instance HTTP/1.1");
    assert_request_line(&requests[1], "GET /api/v1/instance HTTP/1.1");

    let artifact = proof_artifact(&json!({
        "request_response_boundary": {
            "first": {
                "method": "GET",
                "path": "/api/v2/instance",
                "status": 404
            },
            "fallback": {
                "method": "GET",
                "path": "/api/v1/instance",
                "status": 200
            }
        },
        "fallback": {
            "v2_instance_to_v1_instance": true
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
async fn local_non_mock_wrong_capability_fails_before_egress() {
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener should bind for no-egress");
    listener
        .set_nonblocking(true)
        .expect("no-egress listener should be nonblocking");
    let base_url = format!(
        "http://{}",
        listener
            .local_addr()
            .expect("loopback listener should expose its address")
    );
    let (mut connector, signing_key, instance_id) = setup_connector(&base_url).await;

    let err = connector
        .invoke(invoke_req(
            &connector,
            OP_STATUSES_POST,
            json!({"status": "should not leave process"}),
            capability_token(&signing_key, &instance_id, CAP_READ, OP_STATUSES_POST),
        ))
        .await
        .expect_err("write operation with read capability should be denied");
    assert!(
        matches!(
            err,
            FcpError::CapabilityDenied { .. }
                | FcpError::OperationNotGranted { .. }
                | FcpError::Unauthorized { .. }
        ),
        "wrong capability should fail at capability gate: {err:?}"
    );
    let no_request = listener
        .accept()
        .expect_err("capability denial should not reach loopback listener");
    assert_eq!(no_request.kind(), ErrorKind::WouldBlock);

    connector
        .shutdown(shutdown_req())
        .await
        .expect("shutdown connector");
    let artifact = proof_artifact(&json!({
        "capability_gate": {
            "operation": OP_STATUSES_POST,
            "provided_capability": CAP_READ,
            "required_capability": CAP_WRITE,
            "denied_before_egress": true
        },
        "cleanup": {
            "connector_shutdown": true
        },
        "result": "passed"
    }));
    println!("{artifact}");
}

async fn setup_connector(instance_url: &str) -> (MastodonConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = MastodonConnector::new();
    connector
        .configure(json!({
            "instance_url": instance_url,
            "access_token": LOOPBACK_BEARER_VALUE,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            },
            "request_timeout_ms": 500
        }))
        .await
        .expect("configure connector");

    let signing_key = Ed25519SigningKey::generate();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .expect("handshake connector");
    let instance_id = connector.instance_id().clone();

    (connector, signing_key, instance_id)
}

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "1.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [19_u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(CAP_READ),
            CapabilityId::from_static(CAP_WRITE),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("capability constraints should serialize");

    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:local-non-mock")
        .operations(&[operation])
        .issuer("node:local-non-mock")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(raw)
}

fn invoke_req(
    connector: &MastodonConnector,
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(format!("req-{operation}")),
        connector_id: connector.id().clone(),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: Some(format!("idem-{operation}")),
        lease_seq: None,
        deadline_ms: Some(1_000),
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

fn shutdown_req() -> ShutdownRequest {
    ShutdownRequest {
        r#type: "shutdown".into(),
        deadline_ms: 1_000,
        drain: true,
        reason: Some("local_non_mock complete".into()),
    }
}

fn assert_request(captured: &CapturedRequest, request_line: &str) {
    assert_request_line(captured, request_line);
    assert!(
        header_seen(
            &captured.head,
            "authorization",
            &format!("Bearer {LOOPBACK_BEARER_VALUE}")
        ),
        "request should carry configured bearer authorization; head={}",
        captured.head
    );
}

fn assert_request_line(captured: &CapturedRequest, request_line: &str) {
    assert_eq!(
        captured
            .head
            .lines()
            .next()
            .expect("captured request should include request line"),
        request_line
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
        "command": "cargo test -p fcp-mastodon --test local_non_mock -- --nocapture",
        "fixture_mode": "raw_tcp_loopback_http",
        "provider_class": "local_sufficient",
        "details": details
    })
}
