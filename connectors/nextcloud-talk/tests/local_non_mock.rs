//! Local loopback acceptance coverage for the Nextcloud Talk connector.

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
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_nextcloud_talk::NextcloudTalkConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.7.2";
const LOOPBACK_AUTH_VALUE: &str = "nextcloud-talk-local-loopback-token";
const CAP_READ: &str = "nextcloud_talk.read";
const CAP_WRITE: &str = "nextcloud_talk.write";
const CAP_MANAGE: &str = "nextcloud_talk.manage";
const CAP_WEBHOOK: &str = "nextcloud_talk.webhook";
const OP_LIST_CONVERSATIONS: &str = "nextcloud_talk.list_conversations";
const OP_CREATE_CONVERSATION: &str = "nextcloud_talk.create_conversation";
const OP_POLL_CONVERSATION_EVENTS: &str = "nextcloud_talk.poll_conversation_events";
const OP_SEND_MESSAGE: &str = "nextcloud_talk.send_message";
const EXPECTED_ROOM_PATH: &str = "/ocs/v2.php/apps/spreed/api/v4/room";
const EXPECTED_CHAT_PATH: &str = "/ocs/v2.php/apps/spreed/api/v1/chat/room123";
const ROOM_TOKEN: &str = "room123";

#[derive(Debug)]
struct CapturedRequest {
    request_line: String,
    headers: String,
    body: String,
}

struct LoopbackServer {
    base_url: String,
    handle: Option<JoinHandle<CapturedRequest>>,
}

impl LoopbackServer {
    fn start(
        response_status: &'static str,
        response_body: String,
        extra_headers: &'static str,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener
            .local_addr()
            .expect("read loopback listener address");
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connector request");
            handle_request(stream, response_status, &response_body, extra_headers)
        });

        Self {
            base_url: format!("http://{address}"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> CapturedRequest {
        self.handle
            .take()
            .expect("loopback thread present")
            .join()
            .expect("loopback thread completed")
    }
}

fn handle_request(
    mut stream: TcpStream,
    response_status: &str,
    response_body: &str,
    extra_headers: &str,
) -> CapturedRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set request read timeout");
    let request = read_http_request(&mut stream);
    write!(
        stream,
        "HTTP/1.1 {response_status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n{extra_headers}\r\n{response_body}",
        response_body.len()
    )
    .expect("write loopback response");
    request
}

fn read_http_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector should send request bytes");
        request.extend_from_slice(&buffer[..bytes_read]);
        if let Some(header_end) = find_header_end(&request) {
            break header_end;
        }
        assert!(request.len() < 8192, "request headers should stay bounded");
    };

    let header_bytes = &request[..header_end + 4];
    let headers = String::from_utf8_lossy(header_bytes).to_string();
    let content_length = content_length_from_headers(&headers);
    let mut body = request[header_end + 4..].to_vec();
    while body.len() < content_length {
        let bytes_read = stream
            .read(&mut buffer)
            .expect("read connector request body");
        assert!(bytes_read > 0, "connector body should match content-length");
        body.extend_from_slice(&buffer[..bytes_read]);
        assert!(body.len() <= 8192, "request body should stay bounded");
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

fn request_target(request_line: &str) -> &str {
    request_line
        .split_whitespace()
        .nth(1)
        .expect("request target should be present")
}

fn assert_request_boundary(request: &CapturedRequest, expected_method: &str, expected_path: &str) {
    let mut parts = request.request_line.split_whitespace();
    assert_eq!(parts.next(), Some(expected_method));
    let target = parts.next().expect("request target should be present");
    assert_eq!(parts.next(), Some("HTTP/1.1"));
    assert_eq!(parts.next(), None);
    assert_eq!(target.split('?').next().unwrap_or_default(), expected_path);
}

fn assert_query_value(request_line: &str, expected_name: &str, expected_value: &str) {
    let query = request_target(request_line)
        .split_once('?')
        .map_or("", |(_, query)| query);
    assert!(
        query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .any(|(name, value)| name == expected_name && value == expected_value),
        "missing query pair {expected_name}={expected_value} in {query}"
    );
}

fn header_seen(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name) && value.trim() == expected_value
    })
}

fn header_value_contains(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name)
            && value
                .to_ascii_lowercase()
                .contains(&expected_value.to_ascii_lowercase())
    })
}

fn assert_common_headers(request: &CapturedRequest) {
    assert!(header_seen(
        &request.headers,
        "authorization",
        &format!("Bearer {LOOPBACK_AUTH_VALUE}")
    ));
    assert!(header_seen(&request.headers, "ocs-apirequest", "true"));
    assert!(header_value_contains(
        &request.headers,
        "accept",
        "application/json"
    ));
    assert!(header_value_contains(
        &request.headers,
        "user-agent",
        "fcp-nextcloud-talk/0.1.0"
    ));
}

fn assert_form_value(body: &str, expected_name: &str, expected_value: &str) {
    assert!(
        body.split('&')
            .filter_map(|pair| pair.split_once('='))
            .any(|(name, value)| name == expected_name && value == expected_value),
        "missing form pair {expected_name}={expected_value} in {body}"
    );
}

fn test_instance_id() -> InstanceId {
    "inst_nextcloud_talk_local_non_mock"
        .parse()
        .expect("canonical test instance id")
}

fn base_handshake(host_public_key: [u8; 32], instance_id: &InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [17_u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(CAP_READ),
            CapabilityId::from_static(CAP_WRITE),
            CapabilityId::from_static(CAP_MANAGE),
            CapabilityId::from_static(CAP_WEBHOOK),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id.clone()),
    }
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operations: &[&str],
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .target_instance(instance_id.as_str())
        .principal("user:nextcloud-talk-local")
        .operations(operations)
        .issuer("node:nextcloud-talk-local")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(raw)
}

fn base_invoke(
    connector_id: &ConnectorId,
    operation: &'static str,
    capability_token: CapabilityToken,
    input: Value,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("req_nextcloud_talk_local_non_mock"),
        connector_id: connector_id.clone(),
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
        approval_tokens: Vec::new(),
    }
}

async fn setup_connector(
    base_url: &str,
) -> (NextcloudTalkConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = NextcloudTalkConnector::new();
    connector
        .configure(json!({
            "server_url": base_url,
            "auth": {
                "mode": "bearer_token",
                "access_token": LOOPBACK_AUTH_VALUE
            },
            "long_poll_timeout_secs": 5,
            "network": {
                "allow_private_networks": true
            }
        }))
        .await
        .expect("configure connector");

    let signing_key = Ed25519SigningKey::generate();
    let instance_id = test_instance_id();
    let handshake = base_handshake(signing_key.verifying_key().to_bytes(), &instance_id);
    connector
        .handshake(handshake)
        .await
        .expect("handshake connector");
    (connector, signing_key, instance_id)
}

fn conversation_response(name: &str) -> String {
    json!({
        "ocs": {
            "meta": {
                "status": "ok",
                "statuscode": 100,
                "message": "OK"
            },
            "data": {
                "token": ROOM_TOKEN,
                "type": 2,
                "displayName": name,
                "unreadMessages": 3
            }
        }
    })
    .to_string()
}

fn conversations_response() -> String {
    json!({
        "ocs": {
            "meta": {
                "status": "ok",
                "statuscode": 100,
                "message": "OK"
            },
            "data": [
                {
                    "token": ROOM_TOKEN,
                    "type": 2,
                    "displayName": "Engineering",
                    "unreadMessages": 3
                }
            ]
        }
    })
    .to_string()
}

fn chat_message_response(message_id: u64, message: &str) -> String {
    json!({
        "ocs": {
            "meta": {
                "status": "ok",
                "statuscode": 100,
                "message": "OK"
            },
            "data": {
                "id": message_id,
                "token": ROOM_TOKEN,
                "actorType": "users",
                "actorId": "alice",
                "actorDisplayName": "Alice",
                "timestamp": 1710000000_u64,
                "systemMessage": "",
                "messageType": "comment",
                "message": message,
                "messageParameters": {},
                "reactions": {},
                "reactionsSelf": []
            }
        }
    })
    .to_string()
}

fn chat_messages_response() -> String {
    json!({
        "ocs": {
            "meta": {
                "status": "ok",
                "statuscode": 100,
                "message": "OK"
            },
            "data": [
                {
                    "id": 41_u64,
                    "token": ROOM_TOKEN,
                    "actorType": "users",
                    "actorId": "alice",
                    "actorDisplayName": "Alice",
                    "timestamp": 1710000001_u64,
                    "systemMessage": "",
                    "messageType": "comment",
                    "message": "follow-up",
                    "messageParameters": {},
                    "reactions": {},
                    "reactionsSelf": []
                }
            ]
        }
    })
    .to_string()
}

fn unauthorized_response() -> String {
    json!({
        "ocs": {
            "meta": {
                "status": "failure",
                "statuscode": 997,
                "message": "token rejected"
            },
            "data": []
        }
    })
    .to_string()
}

fn emit_artifact(operation: &str, request: Option<&CapturedRequest>, extra: Value) {
    let mut artifact = json!({
        "connector": "nextcloud-talk",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": operation,
        "command": "cargo test -p fcp-nextcloud-talk --test local_non_mock -- --nocapture",
        "result": "passed"
    });
    if let Some(request) = request {
        artifact["request_line"] = json!(request.request_line.as_str());
    }
    artifact["details"] = extra;
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_list_conversations_uses_nextcloud_talk_request_boundary() {
    let server = LoopbackServer::start("200 OK", conversations_response(), "");
    let (connector, signing_key, instance_id) = setup_connector(server.base_url()).await;
    let response = connector
        .invoke(base_invoke(
            connector.id(),
            OP_LIST_CONVERSATIONS,
            capability_token(
                &signing_key,
                &instance_id,
                CAP_READ,
                &[OP_LIST_CONVERSATIONS],
            ),
            json!({ "include_status": true }),
        ))
        .await
        .expect("list conversations through connector");
    let request = server.join();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(result["conversations"][0]["token"], ROOM_TOKEN);
    assert_eq!(result["conversations"][0]["displayName"], "Engineering");
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));
    assert_request_boundary(&request, "GET", EXPECTED_ROOM_PATH);
    assert_query_value(&request.request_line, "includeStatus", "1");
    assert_query_value(&request.request_line, "format", "json");
    assert_common_headers(&request);

    emit_artifact(
        OP_LIST_CONVERSATIONS,
        Some(&request),
        json!({
            "method": "GET",
            "path": EXPECTED_ROOM_PATH,
            "include_status_query_verified": true,
            "authorization_header_verified": true
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_create_conversation_posts_form_boundary() {
    let server = LoopbackServer::start("200 OK", conversation_response("Incident Room"), "");
    let (connector, signing_key, instance_id) = setup_connector(server.base_url()).await;
    let response = connector
        .invoke(base_invoke(
            connector.id(),
            OP_CREATE_CONVERSATION,
            capability_token(
                &signing_key,
                &instance_id,
                CAP_MANAGE,
                &[OP_CREATE_CONVERSATION],
            ),
            json!({
                "room_type": 2,
                "room_name": "Incident Room"
            }),
        ))
        .await
        .expect("create conversation through connector");
    let request = server.join();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(result["conversation"]["token"], ROOM_TOKEN);
    assert_eq!(result["conversation"]["displayName"], "Incident Room");
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));
    assert_request_boundary(&request, "POST", EXPECTED_ROOM_PATH);
    assert_query_value(&request.request_line, "format", "json");
    assert_common_headers(&request);
    assert!(header_value_contains(
        &request.headers,
        "content-type",
        "application/x-www-form-urlencoded"
    ));
    assert_form_value(&request.body, "roomType", "2");
    assert_form_value(&request.body, "roomName", "Incident+Room");

    emit_artifact(
        OP_CREATE_CONVERSATION,
        Some(&request),
        json!({
            "method": "POST",
            "path": EXPECTED_ROOM_PATH,
            "form_body_verified": true,
            "capability": CAP_MANAGE
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_send_message_posts_form_and_coordination_audit() {
    let server = LoopbackServer::start("200 OK", chat_message_response(42, "hello world"), "");
    let (connector, signing_key, instance_id) = setup_connector(server.base_url()).await;
    let response = connector
        .invoke(base_invoke(
            connector.id(),
            OP_SEND_MESSAGE,
            capability_token(&signing_key, &instance_id, CAP_WRITE, &[OP_SEND_MESSAGE]),
            json!({
                "token": ROOM_TOKEN,
                "message": "hello world",
                "silent": true
            }),
        ))
        .await
        .expect("send message through connector");
    let request = server.join();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(result["message"]["id"], 42);
    assert_eq!(result["message"]["message"], "hello world");
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));
    let coordination = result["coordination"]
        .as_array()
        .expect("coordination audit records");
    assert_eq!(coordination[0]["event"], "claim_attempt");
    assert_eq!(coordination[1]["event"], "claim_outcome");
    assert_eq!(coordination[1]["outcome"], "granted");
    assert_eq!(coordination[2]["event"], "send_executed");
    assert_request_boundary(&request, "POST", EXPECTED_CHAT_PATH);
    assert_query_value(&request.request_line, "format", "json");
    assert_common_headers(&request);
    assert!(header_value_contains(
        &request.headers,
        "content-type",
        "application/x-www-form-urlencoded"
    ));
    assert_form_value(&request.body, "message", "hello+world");
    assert_form_value(&request.body, "silent", "1");

    emit_artifact(
        OP_SEND_MESSAGE,
        Some(&request),
        json!({
            "method": "POST",
            "path": EXPECTED_CHAT_PATH,
            "form_body_verified": true,
            "coordination_events": coordination.len()
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_poll_conversation_events_uses_long_poll_query_and_cursor() {
    let server = LoopbackServer::start(
        "200 OK",
        chat_messages_response(),
        "x-chat-last-given: 41\r\nx-chat-last-common-read: 30\r\n",
    );
    let (connector, signing_key, instance_id) = setup_connector(server.base_url()).await;
    let response = connector
        .invoke(base_invoke(
            connector.id(),
            OP_POLL_CONVERSATION_EVENTS,
            capability_token(
                &signing_key,
                &instance_id,
                CAP_READ,
                &[OP_POLL_CONVERSATION_EVENTS],
            ),
            json!({
                "token": ROOM_TOKEN,
                "look_into_future": true,
                "limit": 2,
                "last_known_message_id": 40,
                "timeout_secs": 5
            }),
        ))
        .await
        .expect("poll conversation events through connector");
    let request = server.join();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(result["events"][0]["type"], "chat_message");
    assert_eq!(result["events"][0]["message_id"], 41);
    assert_eq!(result["cursor"]["last_known_message_id"], 41);
    assert_eq!(result["cursor"]["last_common_read_id"], 30);
    assert_eq!(result["not_modified"], false);
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));
    assert_request_boundary(&request, "GET", EXPECTED_CHAT_PATH);
    assert_query_value(&request.request_line, "lookIntoFuture", "1");
    assert_query_value(&request.request_line, "setReadMarker", "0");
    assert_query_value(&request.request_line, "includeLastKnown", "0");
    assert_query_value(&request.request_line, "noStatusUpdate", "1");
    assert_query_value(&request.request_line, "markNotificationsAsRead", "0");
    assert_query_value(&request.request_line, "limit", "2");
    assert_query_value(&request.request_line, "lastKnownMessageId", "40");
    assert_query_value(&request.request_line, "timeout", "5");
    assert_query_value(&request.request_line, "format", "json");
    assert_common_headers(&request);

    emit_artifact(
        OP_POLL_CONVERSATION_EVENTS,
        Some(&request),
        json!({
            "method": "GET",
            "path": EXPECTED_CHAT_PATH,
            "passive_poll_flags_verified": true,
            "cursor_verified": true
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_unauthorized_provider_error_redacts_auth_material() {
    let server = LoopbackServer::start("401 Unauthorized", unauthorized_response(), "");
    let (connector, signing_key, instance_id) = setup_connector(server.base_url()).await;
    let error = connector
        .invoke(base_invoke(
            connector.id(),
            OP_LIST_CONVERSATIONS,
            capability_token(
                &signing_key,
                &instance_id,
                CAP_READ,
                &[OP_LIST_CONVERSATIONS],
            ),
            json!({}),
        ))
        .await
        .expect_err("401 should map to unauthorized");
    let request = server.join();

    assert_common_headers(&request);
    assert!(matches!(error, FcpError::Unauthorized { code: 2001, .. }));
    assert!(!error.to_string().contains(LOOPBACK_AUTH_VALUE));
    assert!(!error.to_string().contains("authorization"));

    emit_artifact(
        OP_LIST_CONVERSATIONS,
        Some(&request),
        json!({
            "error_mapping": "unauthorized",
            "auth_material_leaked": false
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_wrong_capability_fails_before_loopback_egress() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking listener");
    let base_url = format!(
        "http://{}",
        listener
            .local_addr()
            .expect("read loopback listener address")
    );
    let (connector, signing_key, instance_id) = setup_connector(&base_url).await;

    let error = connector
        .invoke(base_invoke(
            connector.id(),
            OP_LIST_CONVERSATIONS,
            capability_token(
                &signing_key,
                &instance_id,
                CAP_WRITE,
                &[OP_LIST_CONVERSATIONS],
            ),
            json!({ "include_status": true }),
        ))
        .await
        .expect_err("write capability should not authorize conversation listing");

    assert!(matches!(
        error,
        FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
    ));
    let accept_error = listener
        .accept()
        .expect_err("capability denial should happen before loopback egress");
    assert_eq!(accept_error.kind(), io::ErrorKind::WouldBlock);

    emit_artifact(
        OP_LIST_CONVERSATIONS,
        None,
        json!({
            "denial": "wrong_capability",
            "loopback_egress_attempted": false
        }),
    );
}
