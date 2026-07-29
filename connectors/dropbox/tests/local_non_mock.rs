//! Local loopback acceptance coverage for the FCP Dropbox connector.

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

use fcp_dropbox::connector::DropboxConnector;
use serde_json::json;

const EXPECTED_PATH: &str = "/files/list_folder";
const EXPECTED_BODY_FRAGMENT: &str = r#""path":"/Documents""#;
const RESPONSE_BODY: &str = r#"{
  "entries": [
    {".tag": "file", "name": "alpha.txt", "path_display": "/Documents/alpha.txt", "size": 17},
    {".tag": "folder", "name": "archive", "path_display": "/Documents/archive"}
  ],
  "cursor": "local-cursor",
  "has_more": false
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    authorization_seen: bool,
    content_type_seen: bool,
    body_path_seen: bool,
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

fn handle_request(mut stream: TcpStream) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let request = read_http_request(&mut stream);
    let request_line = request.lines().next().unwrap_or_default().to_string();
    let authorization_seen = request
        .lines()
        .any(|line| line.eq_ignore_ascii_case("authorization: bearer test-dropbox-token"));
    let content_type_seen = request.lines().any(|line| {
        line.to_ascii_lowercase()
            .starts_with("content-type: application/json")
    });
    let body_path_seen = request.contains(EXPECTED_BODY_FRAGMENT);

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
        content_type_seen,
        body_path_seen,
    }
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let mut header_end = None;
    let mut content_length = 0;

    loop {
        let bytes_read = stream.read(&mut chunk).expect("read connector request");
        if bytes_read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);

        if header_end.is_none()
            && let Some(position) = buffer.windows(4).position(|bytes| bytes == b"\r\n\r\n")
        {
            let end = position + 4;
            let headers = String::from_utf8_lossy(&buffer[..end]);
            content_length = parse_content_length(&headers);
            header_end = Some(end);
        }

        if let Some(end) = header_end
            && buffer.len() >= end + content_length
        {
            break;
        }
    }

    String::from_utf8_lossy(&buffer).into_owned()
}

fn parse_content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

async fn setup_connector(base_url: &str) -> DropboxConnector {
    let mut connector = DropboxConnector::new();
    connector
        .handle_configure(json!({
            "access_token": "test-dropbox-token",
            "base_url": base_url,
            "content_url": base_url
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
async fn loopback_files_list_uses_production_client_request() {
    let fixture = LoopbackFixture::start();
    let connector = setup_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation_id": "dropbox.files.list",
            "input": {"path": "/Documents"}
        }))
        .await
        .expect("list files through connector");
    let observation = fixture.join();

    assert_eq!(
        observation.request_line,
        format!("POST {EXPECTED_PATH} HTTP/1.1")
    );
    assert!(observation.authorization_seen);
    assert!(observation.content_type_seen);
    assert!(observation.body_path_seen);
    assert_eq!(
        result["entries"].as_array().expect("entries array").len(),
        2
    );
    assert_eq!(result["entries"][0]["name"], "alpha.txt");
    assert_eq!(result["has_more"], false);

    let artifact = json!({
        "connector": "dropbox",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "fixture_mode": "loopback_http",
        "operation": "dropbox.files.list",
        "method": "POST",
        "path": EXPECTED_PATH,
        "request_line": observation.request_line,
        "authorization_seen": observation.authorization_seen,
        "content_type_seen": observation.content_type_seen,
        "body_path_seen": observation.body_path_seen,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
