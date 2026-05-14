#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use chrono::Utc;
use fcp_crypto::{CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_google_calendar::connector::GoogleCalendarConnector;
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError, InstanceId};
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const ACCESS_TOKEN: &str = "google_calendar_local_non_mock_token";

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
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).expect("Calendar loopback listener should bind");
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
                let head = String::from_utf8_lossy(&bytes[..end]);
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
    let mut request_parts = request_line.split_whitespace();
    let actual_method = request_parts
        .next()
        .expect("captured request line should include method");
    let actual_target = request_parts
        .next()
        .expect("captured request line should include target");
    let actual_version = request_parts
        .next()
        .expect("captured request line should include HTTP version");

    assert_eq!(actual_method, method, "unexpected request method");
    assert_eq!(actual_version, "HTTP/1.1", "unexpected HTTP version");

    let (expected_path, expected_query) = split_target(target);
    let (actual_path, actual_query) = split_target(actual_target);
    assert_eq!(
        decoded_path(actual_path),
        decoded_path(expected_path),
        "unexpected request path in line {request_line:?}"
    );

    match expected_query {
        Some(expected) => assert_eq!(
            sorted_query_pairs(actual_query.unwrap_or_default()),
            sorted_query_pairs(expected),
            "unexpected query parameters in line {request_line:?}"
        ),
        None => assert!(
            actual_query.is_none_or(str::is_empty),
            "unexpected query string in line {request_line:?}"
        ),
    }

    let lower_head = captured.head.to_ascii_lowercase();
    assert!(
        lower_head.contains(&format!("authorization: bearer {ACCESS_TOKEN}")),
        "request should carry redaction-safe bearer auth; head={}",
        captured.head
    );
}

fn split_target(target: &str) -> (&str, Option<&str>) {
    target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)))
}

fn decoded_path(path: &str) -> String {
    percent_decode_str(path)
        .decode_utf8()
        .expect("loopback path should be valid percent-encoded UTF-8")
        .into_owned()
}

fn sorted_query_pairs(query: &str) -> Vec<(&str, &str)> {
    let mut pairs = query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| part.split_once('=').unwrap_or((part, "")))
        .collect::<Vec<_>>();
    pairs.sort_unstable();
    pairs
}

async fn configured_connector(
    base_url: &str,
    signing_key: &Ed25519SigningKey,
) -> (GoogleCalendarConnector, InstanceId) {
    let mut connector = GoogleCalendarConnector::new();
    connector
        .handle_configure(json!({
            "access_token": ACCESS_TOKEN,
            "required_scopes": ["https://www.googleapis.com/auth/calendar"],
            "base_url": base_url
        }))
        .await
        .expect("connector should configure against loopback base URL");
    let instance_id = setup_handshake(&mut connector, signing_key).await;
    (connector, instance_id)
}

async fn setup_handshake(
    connector: &mut GoogleCalendarConnector,
    signing_key: &Ed25519SigningKey,
) -> InstanceId {
    let instance_id = InstanceId::new();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": ["gcal.read", "gcal.write", "gcal.delete"],
            "requested_instance_id": instance_id.as_str()
        }))
        .await
        .expect("Google Calendar handshake should complete");
    instance_id
}

fn capability_for(operation: &str) -> &'static str {
    match operation {
        "gcal.create_event" | "gcal.update_event" | "gcal.quick_add" => "gcal.write",
        "gcal.delete_event" => "gcal.delete",
        _ => "gcal.read",
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    operation: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for(operation))
        .zone_id("z:work")
        .target_instance(instance_id.as_str())
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + chrono::Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &GoogleCalendarConnector,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    operation: &str,
    input: Value,
) -> Value {
    let token = generate_valid_token(signing_key, instance_id, operation);
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": token
        }))
        .await
        .expect("connector invoke should succeed")
}

fn event_response(id: &str, summary: &str) -> String {
    format!(
        r#"{{
            "id": "{id}",
            "summary": "{summary}",
            "status": "confirmed",
            "start": {{"dateTime": "2026-05-14T10:00:00Z"}},
            "end": {{"dateTime": "2026-05-14T11:00:00Z"}}
        }}"#
    )
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_calendar_sync_and_write_flow_uses_loopback_http() {
    let created = event_response("evt-created", "Planning call");
    let server = LoopbackServer::start(vec![
        HttpResponse {
            status: "200 OK",
            body: r#"{
                "items": [
                    {"id": "primary", "summary": "Primary Calendar"},
                    {"id": "work@example.com", "summary": "Work Calendar"}
                ]
            }"#
            .to_string(),
        },
        HttpResponse {
            status: "200 OK",
            body: r#"{
                "items": [
                    {
                        "id": "evt-sync-1",
                        "summary": "Synced event",
                        "status": "confirmed",
                        "start": {"dateTime": "2026-05-14T09:00:00Z"},
                        "end": {"dateTime": "2026-05-14T09:30:00Z"}
                    },
                    {
                        "id": "evt-cancelled",
                        "status": "cancelled"
                    }
                ],
                "nextSyncToken": "sync-next-local"
            }"#
            .to_string(),
        },
        HttpResponse {
            status: "200 OK",
            body: created,
        },
        HttpResponse {
            status: "200 OK",
            body: r#"{
                "kind": "calendar#freeBusy",
                "calendars": {
                    "primary": {
                        "busy": [
                            {"start": "2026-05-14T10:00:00Z", "end": "2026-05-14T11:00:00Z"}
                        ]
                    }
                }
            }"#
            .to_string(),
        },
        HttpResponse {
            status: "204 No Content",
            body: String::new(),
        },
    ]);
    let signing_key = Ed25519SigningKey::generate();
    let (connector, instance_id) = configured_connector(&server.base_url, &signing_key).await;

    let calendars = invoke(
        &connector,
        &signing_key,
        &instance_id,
        "gcal.list_calendars",
        json!({}),
    )
    .await;
    assert_eq!(calendars["calendars"].as_array().unwrap().len(), 2);
    let request = server.take();
    assert_request(&request, "GET", "/users/me/calendarList");
    assert!(request.body.is_none());

    let synced = invoke(
        &connector,
        &signing_key,
        &instance_id,
        "gcal.sync_events",
        json!({
            "calendar_id": "primary",
            "sync_token": "syncseed",
            "max_results": 2
        }),
    )
    .await;
    assert_eq!(synced["next_sync_token"], "sync-next-local");
    assert_eq!(synced["events"].as_array().unwrap().len(), 2);
    let request = server.take();
    assert_request(
        &request,
        "GET",
        "/calendars/primary/events?syncToken=syncseed&maxResults=2",
    );
    assert!(request.body.is_none());

    let created_event = invoke(
        &connector,
        &signing_key,
        &instance_id,
        "gcal.create_event",
        json!({
            "calendar_id": "primary",
            "summary": "Planning call",
            "start": "2026-05-14T10:00:00Z",
            "end": "2026-05-14T11:00:00Z",
            "attendees": [{"email": "teammate@example.com"}]
        }),
    )
    .await;
    assert_eq!(created_event["event"]["id"], "evt-created");
    let request = server.take();
    assert_request(&request, "POST", "/calendars/primary/events");
    let body = request.body.expect("create event should send JSON");
    assert_eq!(body["summary"], "Planning call");
    assert_eq!(body["attendees"][0]["email"], "teammate@example.com");

    let busy = invoke(
        &connector,
        &signing_key,
        &instance_id,
        "gcal.freebusy",
        json!({
            "time_min": "2026-05-14T00:00:00Z",
            "time_max": "2026-05-15T00:00:00Z",
            "items": [{"id": "primary"}]
        }),
    )
    .await;
    assert!(busy["calendars"]["primary"]["busy"].is_array());
    let request = server.take();
    assert_request(&request, "POST", "/freeBusy");
    let body = request.body.expect("freebusy should send JSON");
    assert_eq!(body["items"][0]["id"], "primary");

    let deleted = invoke(
        &connector,
        &signing_key,
        &instance_id,
        "gcal.delete_event",
        json!({
            "calendar_id": "primary",
            "event_id": "evt-delete"
        }),
    )
    .await;
    assert_eq!(deleted["status"], "deleted");
    let request = server.take();
    assert_request(&request, "DELETE", "/calendars/primary/events/evt-delete");
    assert!(request.body.is_none());

    server.join();

    println!(
        "GOOGLE_CALENDAR_LOCAL_NON_MOCK_EVIDENCE {}",
        json!({
            "suite": ACCEPTANCE_SUITE_CLASS,
            "connector": "google-calendar",
            "transport": "tcp_loopback_http",
            "operations": [
                "gcal.list_calendars",
                "gcal.sync_events",
                "gcal.create_event",
                "gcal.freebusy",
                "gcal.delete_event"
            ],
            "request_count": 5,
            "created_event_id": created_event["event"]["id"],
            "sync_token_seen": synced["next_sync_token"],
            "cleanup": "loopback listener joined"
        })
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_auth_denial_maps_to_unauthorized() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "401 Unauthorized",
        body: r#"{"error": {"code": 401, "message": "Invalid Credentials"}}"#.to_string(),
    }]);
    let signing_key = Ed25519SigningKey::generate();
    let (connector, instance_id) = configured_connector(&server.base_url, &signing_key).await;
    let token = generate_valid_token(&signing_key, &instance_id, "gcal.list_calendars");

    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.list_calendars",
            "input": {},
            "capability_token": token
        }))
        .await;

    let request = server.take();
    assert_request(&request, "GET", "/users/me/calendarList");
    server.join();
    assert!(matches!(
        result,
        Err(FcpError::Unauthorized { code: 2001, .. })
    ));
}
