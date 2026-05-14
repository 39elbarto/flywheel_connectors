#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use fcp_google_workspace_events::connector::WorkspaceEventsConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const ACCESS_TOKEN: &str = "google_workspace_events_local_non_mock_token";

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
            .expect("Workspace Events loopback listener should bind");
        let base_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("loopback listener should expose its address")
        );
        let (request_tx, received) = mpsc::channel();

        let join = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener
                    .accept()
                    .expect("loopback listener should accept expected request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("loopback stream should set read timeout");

                let request = read_complete_request(&mut stream);
                request_tx
                    .send(request)
                    .expect("captured request should be delivered");

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
    body: String,
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

    let lower_head = captured.head.to_ascii_lowercase();
    assert!(
        lower_head.contains(&format!("authorization: bearer {ACCESS_TOKEN}")),
        "request should carry redaction-safe bearer auth; head={}",
        captured.head
    );
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
            body: r#"{
                "subscriptions": [
                    {
                        "name": "subscriptions/local-1",
                        "state": "ACTIVE",
                        "targetResource": "//chat.googleapis.com/spaces/AAAA",
                        "notificationEndpoint": {
                            "pubsubTopic": "projects/demo/topics/workspace-events"
                        }
                    }
                ],
                "nextPageToken": "token-2"
            }"#
            .to_string(),
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
        .expect("subscription listing should succeed");
    assert_eq!(listed["next_page_token"], "token-2");
    assert_eq!(listed["subscriptions"][0]["name"], "subscriptions/local-1");

    let list_request = server.take();
    assert_request(
        &list_request,
        "GET",
        "/v1/subscriptions?pageSize=2&pageToken=token%2D1",
    );
    assert!(list_request.body.is_none());

    let created = connector
        .handle_invoke(json!({
            "operation": "workspace_events.create_subscription",
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
        .expect("subscription create should post the local control-plane request");
    assert_eq!(created["operation"]["name"], "operations/create-local-1");

    let create_request = server.take();
    assert_request(&create_request, "POST", "/v1/subscriptions");
    let create_body = create_request
        .body
        .expect("create request should include JSON");
    assert_eq!(
        create_body["targetResource"],
        "//chat.googleapis.com/spaces/AAAA"
    );
    assert_eq!(
        create_body["notificationEndpoint"]["pubsubTopic"],
        "projects/demo/topics/workspace-events"
    );
    assert_eq!(create_body["payloadOptions"]["fieldMask"], "message");

    let pulled = connector
        .handle_invoke(json!({
            "operation": "workspace_events.pull_events",
            "input": {
                "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
                "max_messages": 1
            }
        }))
        .await
        .expect("Pub/Sub pull should decode local delivery payload");
    assert_eq!(pulled["received_messages"][0]["ackId"], "ack-local-1");
    assert_eq!(pulled["decoded_events"][0]["ack_id"], "ack-local-1");
    assert_eq!(
        pulled["decoded_events"][0]["decoded_json"]["event"],
        "chat_message_created"
    );
    assert_eq!(pulled["decoded_events"][0]["decoded_json"]["seq"], 7);

    let pull_request = server.take();
    assert_request(
        &pull_request,
        "POST",
        "/v1/projects/demo/subscriptions/workspace-events:pull",
    );
    assert_eq!(
        pull_request.body.expect("pull request should include JSON")["maxMessages"],
        1
    );

    let acked = connector
        .handle_invoke(json!({
            "operation": "workspace_events.ack_events",
            "input": {
                "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
                "ack_ids": ["ack-local-1"]
            }
        }))
        .await
        .expect("Pub/Sub ack should post local ack request");
    assert_eq!(acked["status"], "acked");
    assert_eq!(acked["acked_count"], 1);

    let ack_request = server.take();
    assert_request(
        &ack_request,
        "POST",
        "/v1/projects/demo/subscriptions/workspace-events:acknowledge",
    );
    assert_eq!(
        ack_request.body.expect("ack request should include JSON")["ackIds"],
        json!(["ack-local-1"])
    );

    server.join();

    let evidence = json!({
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "connector": "google-workspace-events",
        "fixture_transport": "hand_rolled_loopback_tcp_http",
        "operations": [
            "workspace_events.list_subscriptions",
            "workspace_events.create_subscription",
            "workspace_events.pull_events",
            "workspace_events.ack_events"
        ],
        "streaming_boundary": "pubsub_pull_and_ack",
        "event_transcript": {
            "message_id": "msg-local-1",
            "ack_id": "ack-local-1",
            "delivery_attempt": 2
        },
        "cleanup": "loopback_server_joined"
    });
    assert_eq!(evidence["suite_class"], ACCEPTANCE_SUITE_CLASS);
    println!("GOOGLE_WORKSPACE_EVENTS_LOCAL_NON_MOCK_EVIDENCE {evidence}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_pubsub_auth_denial_maps_to_unauthorized() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "401 Unauthorized",
        body: r#"{"error": {"message": "invalid credentials"}}"#.to_string(),
    }]);
    let mut connector = configured_connector(&server.base_url).await;

    let error = connector
        .handle_invoke(json!({
            "operation": "workspace_events.pull_events",
            "input": {
                "pubsub_subscription": "projects/demo/subscriptions/auth-failed",
                "max_messages": 1
            }
        }))
        .await
        .expect_err("provider auth failure should map to Unauthorized");
    assert!(
        matches!(error, FcpError::Unauthorized { .. }),
        "expected Unauthorized, got {error:?}"
    );

    let request = server.take();
    assert_request(
        &request,
        "POST",
        "/v1/projects/demo/subscriptions/auth-failed:pull",
    );
    assert_eq!(
        request
            .body
            .expect("auth-denial request should include JSON")["maxMessages"],
        1
    );

    server.join();
}
