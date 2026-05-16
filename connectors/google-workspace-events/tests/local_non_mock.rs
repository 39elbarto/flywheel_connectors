//! Local loopback acceptance coverage for the Google Workspace Events connector.

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
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use fcp_google_workspace_events::connector::WorkspaceEventsConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};

const LOOPBACK_AUTH_VALUE: &str = "workspace-events-local-loopback-token";
const OP_LIST_SUBSCRIPTIONS: &str = "workspace_events.list_subscriptions";
const OP_CREATE_SUBSCRIPTION: &str = "workspace_events.create_subscription";
const OP_PULL_EVENTS: &str = "workspace_events.pull_events";
const OP_ACK_EVENTS: &str = "workspace_events.ack_events";
const EXPECTED_SUBSCRIPTIONS_PATH: &str = "/v1/subscriptions";
const EXPECTED_PULL_PATH: &str = "/v1/projects/demo/subscriptions/workspace-events:pull";
const EXPECTED_ACK_PATH: &str = "/v1/projects/demo/subscriptions/workspace-events:acknowledge";
const ACCESS_TOKEN: &str = LOOPBACK_AUTH_VALUE;

const LIST_SUBSCRIPTIONS_RESPONSE: &str = r#"{
  "subscriptions": [
    {
      "name": "subscriptions/sub-1",
      "state": "ACTIVE",
      "targetResource": "//chat.googleapis.com/spaces/AAAA",
      "notificationEndpoint": {
        "pubsubTopic": "projects/demo/topics/workspace-events"
      }
    }
  ],
  "nextPageToken": "token-2"
}"#;

const CREATE_SUBSCRIPTION_RESPONSE: &str = r#"{
  "name": "operations/create-1",
  "done": false
}"#;

const ACK_RESPONSE: &str = "{}";

const UNAUTHORIZED_RESPONSE: &str = r#"{
  "error": {
    "code": 401,
    "message": "invalid credentials",
    "status": "UNAUTHENTICATED"
  }
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    authorization_seen: bool,
    user_agent_seen: bool,
    content_type_json_seen: bool,
    body: String,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

impl LoopbackFixture {
    fn start(response_status: impl Into<String>, response_body: impl Into<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let status = response_status.into();
        let body = response_body.into();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connector request");
            handle_request(stream, &status, &body)
        });

        Self {
            base_url: format!("http://{address}"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> FixtureObservation {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

struct HttpResponse {
    status: &'static str,
    body: String,
}

struct LoopbackServer {
    base_url: String,
    handle: Option<JoinHandle<Vec<FixtureObservation>>>,
}

impl LoopbackServer {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (stream, _) = listener.accept().expect("accept connector request");
                    handle_request(stream, response.status, &response.body)
                })
                .collect()
        });

        Self {
            base_url: format!("http://{address}"),
            handle: Some(handle),
        }
    }

    fn join(mut self) -> Vec<FixtureObservation> {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_request(
    mut stream: TcpStream,
    response_status: &str,
    response_body: &str,
) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let request = read_http_request(&mut stream);
    let authorization_seen = header_seen(
        &request.headers,
        "authorization",
        &format!("Bearer {LOOPBACK_AUTH_VALUE}"),
    );
    let user_agent_seen = header_value_contains(
        &request.headers,
        "user-agent",
        "fcp-google-workspace-events/0.1.0",
    );
    let content_type_json_seen =
        header_value_contains(&request.headers, "content-type", "application/json");

    write!(
        stream,
        "HTTP/1.1 {response_status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
        response_body.len()
    )
    .expect("write connector response");

    FixtureObservation {
        request_line: request.request_line,
        authorization_seen,
        user_agent_seen,
        content_type_json_seen,
        body: request.body,
    }
}

struct HttpRequest {
    request_line: String,
    headers: String,
    body: String,
}

fn read_http_request(stream: &mut TcpStream) -> HttpRequest {
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
        let bytes_read = stream.read(&mut buffer).expect("read connector body");
        assert!(bytes_read > 0, "connector body should match content-length");
        body.extend_from_slice(&buffer[..bytes_read]);
        assert!(body.len() <= 8192, "request body should stay bounded");
    }
    body.truncate(content_length);

    HttpRequest {
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

fn assert_request_boundary(
    request_line: &str,
    expected_method: &str,
    expected_path: &str,
) -> String {
    let mut parts = request_line.split_whitespace();
    assert_eq!(parts.next(), Some(expected_method));
    let target = parts.next().expect("request target should be present");
    assert_eq!(parts.next(), Some("HTTP/1.1"));
    assert_eq!(parts.next(), None);

    let target_without_empty_query = target.strip_suffix('?').unwrap_or(target);
    let path = target_without_empty_query
        .split_once('?')
        .map_or(target_without_empty_query, |(path, _)| path);
    assert_eq!(path, expected_path);
    target_without_empty_query.to_string()
}

fn request_body_json(observation: &FixtureObservation) -> Value {
    serde_json::from_str(&observation.body).expect("request body should be JSON")
}

async fn configured_connector(base_url: &str) -> WorkspaceEventsConnector {
    let mut connector = WorkspaceEventsConnector::new();
    connector
        .handle_configure(json!({
            "access_token": ACCESS_TOKEN,
            "required_scopes": ["https://www.googleapis.com/auth/chat.messages.readonly"],
            "events_base_url": format!("{base_url}/v1"),
            "pubsub_base_url": format!("{base_url}/v1"),
        }))
        .await
        .expect("connector should configure against loopback base URLs");
    connector
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_subscription_and_pubsub_delivery_flow_uses_loopback_http() {
    let event_payload = STANDARD.encode(br#"{"event":"chat_message_created","seq":7}"#);
    let pull_body = format!(
        r#"{{
            "receivedMessages": [
                {{
                    "ackId": "ack-local-1",
                    "deliveryAttempt": 2,
                    "message": {{
                        "data": "{event_payload}",
                        "messageId": "msg-local-1",
                        "publishTime": "2026-05-14T00:00:00Z",
                        "attributes": {{"eventType": "google.workspace.chat.message.v1.created"}}
                    }}
                }}
            ]
        }}"#
    );
    let server = LoopbackServer::start(vec![
        HttpResponse {
            status: "200 OK",
            body: LIST_SUBSCRIPTIONS_RESPONSE.to_string(),
        },
        HttpResponse {
            status: "200 OK",
            body: r#"{"name": "operations/create-local-1", "done": false}"#.to_string(),
        },
        HttpResponse {
            status: "200 OK",
            body: pull_body,
        },
        HttpResponse {
            status: "200 OK",
            body: r"{}".to_string(),
        },
    ]);
    let mut connector = configured_connector(&server.base_url).await;

    let listed = connector
        .handle_invoke(json!({
            "operation": "workspace_events.list_subscriptions",
            "input": {
                "page_size": 2,
                "page_token": "token-1"
            }
        }))
        .await
        .expect("list subscriptions through connector");
    let created = connector
        .handle_invoke(json!({
            "operation": OP_CREATE_SUBSCRIPTION,
            "input": {
                "target_resource": "//chat.googleapis.com/spaces/AAAA",
                "event_types": ["google.workspace.chat.message.v1.created"],
                "pubsub_topic": "projects/demo/topics/workspace-events",
                "ttl": "86400s",
                "include_resource": true
            }
        }))
        .await
        .expect("create subscription through connector");
    let pulled = connector
        .handle_invoke(json!({
            "operation": OP_PULL_EVENTS,
            "input": {
                "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
                "max_messages": 1
            }
        }))
        .await
        .expect("pull events through connector");
    let acked = connector
        .handle_invoke(json!({
            "operation": OP_ACK_EVENTS,
            "input": {
                "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
                "ack_ids": ["ack-local-1"]
            }
        }))
        .await
        .expect("ack events through connector");

    let observations = server.join();
    assert_eq!(observations.len(), 4);
    let list_observation = &observations[0];
    let create_observation = &observations[1];
    let pull_observation = &observations[2];
    let ack_observation = &observations[3];
    let target = assert_request_boundary(
        &list_observation.request_line,
        "GET",
        EXPECTED_SUBSCRIPTIONS_PATH,
    );

    assert!(target.contains("pageSize=2"));
    assert!(target.contains("pageToken=token%2D1"));
    assert!(list_observation.authorization_seen);
    assert!(list_observation.user_agent_seen);
    assert_eq!(listed["next_page_token"], "token-2");
    assert_eq!(listed["subscriptions"][0]["name"], "subscriptions/sub-1");
    assert_eq!(
        listed["subscriptions"][0]["notificationEndpoint"]["pubsubTopic"],
        "projects/demo/topics/workspace-events"
    );
    assert!(!listed.to_string().contains(LOOPBACK_AUTH_VALUE));
    assert_request_boundary(
        &create_observation.request_line,
        "POST",
        EXPECTED_SUBSCRIPTIONS_PATH,
    );
    assert_eq!(created["operation"]["name"], "operations/create-local-1");
    assert_request_boundary(&pull_observation.request_line, "POST", EXPECTED_PULL_PATH);
    assert_eq!(pulled["decoded_events"][0]["ack_id"], "ack-local-1");
    assert_eq!(
        pulled["decoded_events"][0]["decoded_json"]["event"],
        "chat_message_created"
    );
    assert_request_boundary(&ack_observation.request_line, "POST", EXPECTED_ACK_PATH);
    assert_eq!(acked["status"], "acked");
    assert_eq!(acked["acked_count"], 1);
    assert!(
        observations
            .iter()
            .all(|observation| observation.authorization_seen)
    );
    assert!(
        observations
            .iter()
            .all(|observation| observation.user_agent_seen)
    );

    let artifact = json!({
        "connector": "google-workspace-events",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.7.1",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_LIST_SUBSCRIPTIONS,
        "method": "GET",
        "path": EXPECTED_SUBSCRIPTIONS_PATH,
        "request_line": list_observation.request_line,
        "auth_gate": {
            "mode": "bearer",
            "authorization_header_verified": list_observation.authorization_seen
        },
        "headers": {
            "user_agent_seen": list_observation.user_agent_seen
        },
        "event_transcript": {
            "subscriptions_listed": 1,
            "subscription_created": created["operation"]["name"] == "operations/create-local-1",
            "messages_pulled": 1,
            "ack_count": 1
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_create_subscription_posts_workspace_events_payload() {
    let fixture = LoopbackFixture::start("200 OK", CREATE_SUBSCRIPTION_RESPONSE);
    let mut connector = configured_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation": OP_CREATE_SUBSCRIPTION,
            "input": {
                "target_resource": "//chat.googleapis.com/spaces/AAAA",
                "event_types": ["google.workspace.chat.message.v1.created"],
                "pubsub_topic": "projects/demo/topics/workspace-events",
                "ttl": "86400s",
                "include_resource": true,
                "field_mask": "message"
            }
        }))
        .await
        .expect("create subscription through connector");
    let observation = fixture.join();
    let body = request_body_json(&observation);

    assert_request_boundary(
        &observation.request_line,
        "POST",
        EXPECTED_SUBSCRIPTIONS_PATH,
    );
    assert!(observation.authorization_seen);
    assert!(observation.user_agent_seen);
    assert!(observation.content_type_json_seen);
    assert_eq!(body["targetResource"], "//chat.googleapis.com/spaces/AAAA");
    assert_eq!(
        body["eventTypes"][0],
        "google.workspace.chat.message.v1.created"
    );
    assert_eq!(
        body["notificationEndpoint"]["pubsubTopic"],
        "projects/demo/topics/workspace-events"
    );
    assert_eq!(body["payloadOptions"]["includeResource"], true);
    assert_eq!(body["payloadOptions"]["fieldMask"], "message");
    assert_eq!(body["ttl"], "86400s");
    assert_eq!(result["operation"]["name"], "operations/create-1");
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-workspace-events",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.7.1",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_CREATE_SUBSCRIPTION,
        "method": "POST",
        "path": EXPECTED_SUBSCRIPTIONS_PATH,
        "request_line": observation.request_line,
        "auth_gate": {
            "mode": "bearer",
            "authorization_header_verified": observation.authorization_seen
        },
        "headers": {
            "content_type_json_seen": observation.content_type_json_seen,
            "user_agent_seen": observation.user_agent_seen
        },
        "body": {
            "target_resource_verified": body["targetResource"] == "//chat.googleapis.com/spaces/AAAA",
            "pubsub_topic_verified": body["notificationEndpoint"]["pubsubTopic"] == "projects/demo/topics/workspace-events"
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_pull_events_uses_pubsub_delivery_boundary_and_decodes_payload() {
    let encoded_payload = STANDARD.encode(br#"{"event":"created","space":"spaces/AAAA"}"#);
    let response = json!({
        "receivedMessages": [
            {
                "ackId": "ack-1",
                "deliveryAttempt": 1,
                "message": {
                    "data": encoded_payload,
                    "messageId": "msg-1",
                    "publishTime": "2026-05-14T00:00:00Z",
                    "attributes": {
                        "eventType": "google.workspace.chat.message.v1.created"
                    }
                }
            }
        ]
    })
    .to_string();
    let fixture = LoopbackFixture::start("200 OK", response);
    let mut connector = configured_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation": OP_PULL_EVENTS,
            "input": {
                "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
                "max_messages": 1
            }
        }))
        .await
        .expect("pull events through connector");
    let observation = fixture.join();
    let body = request_body_json(&observation);

    assert_request_boundary(&observation.request_line, "POST", EXPECTED_PULL_PATH);
    assert!(observation.authorization_seen);
    assert!(observation.user_agent_seen);
    assert!(observation.content_type_json_seen);
    assert_eq!(body["maxMessages"], 1);
    assert_eq!(result["received_messages"][0]["ackId"], "ack-1");
    assert_eq!(result["decoded_events"][0]["ack_id"], "ack-1");
    assert_eq!(
        result["decoded_events"][0]["decoded_json"]["event"],
        "created"
    );
    assert_eq!(
        result["decoded_events"][0]["decoded_json"]["space"],
        "spaces/AAAA"
    );
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-workspace-events",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.7.1",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_PULL_EVENTS,
        "method": "POST",
        "path": EXPECTED_PULL_PATH,
        "request_line": observation.request_line,
        "auth_gate": {
            "mode": "bearer",
            "authorization_header_verified": observation.authorization_seen
        },
        "event_transcript": {
            "received_messages": 1,
            "decoded_payload": true,
            "ack_id_hash_class": "fixture"
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_ack_events_posts_pubsub_ack_ids() {
    let fixture = LoopbackFixture::start("200 OK", ACK_RESPONSE);
    let mut connector = configured_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation": OP_ACK_EVENTS,
            "input": {
                "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
                "ack_ids": ["ack-1", " ack-2 "]
            }
        }))
        .await
        .expect("ack events through connector");
    let observation = fixture.join();
    let body = request_body_json(&observation);

    assert_request_boundary(&observation.request_line, "POST", EXPECTED_ACK_PATH);
    assert!(observation.authorization_seen);
    assert!(observation.user_agent_seen);
    assert!(observation.content_type_json_seen);
    assert_eq!(body["ackIds"][0], "ack-1");
    assert_eq!(body["ackIds"][1], "ack-2");
    assert_eq!(result["status"], "acked");
    assert_eq!(result["acked_count"], 2);
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-workspace-events",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.7.1",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_ACK_EVENTS,
        "method": "POST",
        "path": EXPECTED_ACK_PATH,
        "request_line": observation.request_line,
        "auth_gate": {
            "mode": "bearer",
            "authorization_header_verified": observation.authorization_seen
        },
        "event_transcript": {
            "ack_count": 2,
            "ack_ids_redacted": true
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_unauthorized_provider_error_redacts_auth_material() {
    let fixture = LoopbackFixture::start("401 Unauthorized", UNAUTHORIZED_RESPONSE);
    let mut connector = configured_connector(fixture.base_url()).await;

    let error = connector
        .handle_invoke(json!({
            "operation": OP_PULL_EVENTS,
            "input": {
                "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
                "max_messages": 1
            }
        }))
        .await
        .expect_err("401 should map to unauthorized");
    let observation = fixture.join();

    assert_request_boundary(&observation.request_line, "POST", EXPECTED_PULL_PATH);
    assert!(observation.authorization_seen);
    assert!(matches!(error, FcpError::Unauthorized { .. }));
    assert!(!error.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-workspace-events",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.7.1",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_PULL_EVENTS,
        "error_mapping": "unauthorized",
        "authorization_header_verified": observation.authorization_seen,
        "auth_material_leaked": false,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
