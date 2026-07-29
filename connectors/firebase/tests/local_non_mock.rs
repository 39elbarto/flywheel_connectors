//! Local loopback acceptance coverage for the FCP Firebase connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
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

use fcp_firebase::connector::FirebaseConnector;
use serde_json::json;

const EXPECTED_PATH: &str = "/v1/projects/demo-project/databases/db1/documents/users/alice";
const RESPONSE_BODY: &str = r#"{
  "name": "projects/demo-project/databases/db1/documents/users/alice",
  "fields": {
    "displayName": { "stringValue": "Alice" },
    "active": { "booleanValue": true }
  },
  "createTime": "2026-05-12T00:00:00Z",
  "updateTime": "2026-05-12T00:00:00Z"
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    authorization_seen: bool,
    accept_seen: bool,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

impl LoopbackFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connector request");
            handle_request(stream)
        });

        Self {
            base_url: format!("http://{address}"),
            handle: Some(handle),
        }
    }

    fn firestore_base_url(&self) -> String {
        format!("{}/v1", self.base_url)
    }

    fn realtime_database_url(&self) -> &str {
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

fn handle_request(mut stream: TcpStream) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let mut buffer = [0_u8; 4096];
    let bytes_read = stream.read(&mut buffer).expect("read connector request");
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let request_line = request.lines().next().unwrap_or_default().to_string();
    let authorization_seen = request
        .lines()
        .any(|line| line.eq_ignore_ascii_case("authorization: Bearer ya29.local-token"));
    let accept_seen = request
        .lines()
        .any(|line| line.eq_ignore_ascii_case("accept: application/json"));

    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        RESPONSE_BODY.len(),
        RESPONSE_BODY
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        authorization_seen,
        accept_seen,
    }
}

async fn setup_connector(fixture: &LoopbackFixture) -> FirebaseConnector {
    let mut connector = FirebaseConnector::new();
    connector
        .handle_configure(json!({
            "project_id": "demo-project",
            "database_id": "db1",
            "access_token": "ya29.local-token",
            "firestore_base_url": fixture.firestore_base_url(),
            "realtime_database_url": fixture.realtime_database_url(),
            "request_timeout_ms": 1_000
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({"session_id": "local-non-mock"}))
        .await
        .expect("handshake connector");
    connector
}

#[fcp_async_core::runtime::test]
async fn loopback_firestore_get_uses_production_client_request() {
    let fixture = LoopbackFixture::start();
    let connector = setup_connector(&fixture).await;

    let result = connector
        .handle_invoke(json!({
            "operation_id": "firebase.firestore.get",
            "input": {
                "document_path": "users/alice"
            }
        }))
        .await
        .expect("get Firestore document through connector");
    let observation = fixture.join();

    assert_eq!(
        observation.request_line,
        format!("GET {EXPECTED_PATH} HTTP/1.1")
    );
    assert!(observation.authorization_seen);
    assert!(observation.accept_seen);
    assert_eq!(result["fields"]["displayName"], "Alice");
    assert_eq!(result["fields"]["active"], true);

    let artifact = json!({
        "connector": "firebase",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "fixture_mode": "loopback_http",
        "operation": "firebase.firestore.get",
        "method": "GET",
        "path": EXPECTED_PATH,
        "request_line": observation.request_line,
        "authorization_seen": observation.authorization_seen,
        "accept_seen": observation.accept_seen,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
