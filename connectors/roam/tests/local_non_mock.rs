//! Local loopback acceptance coverage for the FCP Roam Research connector.

#![allow(
    clippy::future_not_send,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::struct_excessive_bools,
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

use fcp_prelude::FcpError;
use fcp_roam::connector::RoamConnector;
use serde_json::{Value, json};

const ACCESS_TOKEN: &str = "local-roam-token";
const GRAPH_NAME: &str = "local-graph";
const OP_PAGES_LIST: &str = "roam.pages.list";
const OP_BLOCKS_CREATE: &str = "roam.blocks.create";

const PAGES_RESPONSE: &str = r#"[
  [
    {
      "node/title": "Daily Notes",
      "block/uid": "page-local-1",
      "create/time": 1710000000000,
      "edit/time": 1710000001000
    }
  ]
]"#;

const CREATE_BLOCK_RESPONSE: &str = r#"{
  "uid": "block-local-1",
  "string": "Loopback block content"
}"#;

const RATE_LIMIT_RESPONSE: &str = r#"{
  "error": true,
  "message": "Too many requests"
}"#;

#[derive(Clone, Copy)]
struct HttpResponse {
    status: &'static str,
    body: &'static str,
    retry_after: Option<&'static str>,
}

#[derive(Debug)]
struct RequestObservation {
    request_line: String,
    authorization_seen: bool,
    accept_json_seen: bool,
    content_type_json_seen: bool,
    user_agent_seen: bool,
    body: Value,
}

struct LoopbackServer {
    base_url: String,
    handle: Option<JoinHandle<Vec<RequestObservation>>>,
}

impl LoopbackServer {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener
            .local_addr()
            .expect("read loopback listener address");
        let handle = thread::spawn(move || {
            responses
                .iter()
                .map(|response| {
                    let (stream, _) = listener.accept().expect("accept connector request");
                    handle_request(stream, *response)
                })
                .collect()
        });

        Self {
            base_url: format!("http://{address}/api/graph"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> Vec<RequestObservation> {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_request(mut stream: TcpStream, response: HttpResponse) -> RequestObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set request read timeout");
    let request = read_complete_request(&mut stream);
    let header_end = find_header_end(&request).expect("request contains complete headers");
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let body_start = header_end + b"\r\n\r\n".len();
    let body = if body_start < request.len() {
        serde_json::from_slice(&request[body_start..]).expect("request body is JSON")
    } else {
        Value::Null
    };

    let request_line = headers.lines().next().unwrap_or_default().to_string();
    let authorization_seen =
        header_equals(&headers, "authorization", &format!("Bearer {ACCESS_TOKEN}"));
    let accept_json_seen = header_contains(&headers, "accept", "application/json");
    let content_type_json_seen = header_contains(&headers, "content-type", "application/json");
    let user_agent_seen = header_contains(&headers, "user-agent", "fcp-roam/0.1.0");

    let retry_after = response
        .retry_after
        .map(|value| format!("retry-after: {value}\r\n"))
        .unwrap_or_default();
    let body_len = response.body.len();
    write!(
        stream,
        "HTTP/1.1 {}\r\ncontent-type: application/json\r\n{retry_after}content-length: {body_len}\r\nconnection: close\r\n\r\n{}",
        response.status, response.body
    )
    .expect("write connector response");

    RequestObservation {
        request_line,
        authorization_seen,
        accept_json_seen,
        content_type_json_seen,
        user_agent_seen,
        body,
    }
}

fn read_complete_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector closed before request completed");
        request.extend_from_slice(&buffer[..bytes_read]);
        assert!(request.len() < 64 * 1024, "request should stay bounded");

        if let Some(header_end) = find_header_end(&request) {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = parse_content_length(&headers).unwrap_or(0);
            let expected_len = header_end + b"\r\n\r\n".len() + content_length;
            if request.len() >= expected_len {
                request.truncate(expected_len);
                return request;
            }
        }
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().expect("content-length is numeric"))
    })
}

fn header_equals(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name) && value.trim() == expected_value
    })
}

fn header_contains(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    let expected_value = expected_value.to_ascii_lowercase();
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name)
            && value.to_ascii_lowercase().contains(&expected_value)
    })
}

async fn setup_connector(base_url: &str) -> RoamConnector {
    let mut connector = RoamConnector::new();
    connector
        .handle_configure(json!({
            "access_token": ACCESS_TOKEN,
            "base_url": base_url,
            "graph_name": GRAPH_NAME,
        }))
        .await
        .expect("configure Roam connector");
    connector
        .handle_handshake(json!({ "session_id": "local-non-mock" }))
        .await
        .expect("handshake Roam connector");
    connector
}

#[fcp_async_core::runtime::test]
async fn pages_list_posts_query_to_loopback_boundary() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "200 OK",
        body: PAGES_RESPONSE,
        retry_after: None,
    }]);
    let connector = setup_connector(server.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation_id": OP_PAGES_LIST,
            "input": {}
        }))
        .await
        .expect("list Roam pages through loopback boundary");

    assert_eq!(result["pages"][0]["node/title"], "Daily Notes");
    assert_eq!(result["pages"][0]["block/uid"], "page-local-1");
    let observations = server.join();
    let observation = observations.first().expect("one request observed");
    assert_eq!(
        observation.request_line,
        "POST /api/graph/local-graph/q HTTP/1.1"
    );
    assert!(observation.authorization_seen);
    assert!(observation.accept_json_seen);
    assert!(observation.content_type_json_seen);
    assert!(observation.user_agent_seen);
    assert!(
        observation.body["query"]
            .as_str()
            .is_some_and(|query| query.contains(":node/title"))
    );
    assert!(observation.body.get("args").is_none());
}

#[fcp_async_core::runtime::test]
async fn blocks_create_posts_json_body_to_loopback_boundary() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "200 OK",
        body: CREATE_BLOCK_RESPONSE,
        retry_after: None,
    }]);
    let connector = setup_connector(server.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation_id": OP_BLOCKS_CREATE,
            "input": {
                "page_uid": "page-local-1",
                "content": "Loopback block content"
            }
        }))
        .await
        .expect("create Roam block through loopback boundary");

    assert_eq!(result["uid"], "block-local-1");
    let observations = server.join();
    let observation = observations.first().expect("one request observed");
    assert_eq!(
        observation.request_line,
        "POST /api/graph/local-graph/write HTTP/1.1"
    );
    assert!(observation.authorization_seen);
    assert!(observation.accept_json_seen);
    assert!(observation.content_type_json_seen);
    assert!(observation.user_agent_seen);
    assert_eq!(observation.body["action"], "create-block");
    assert_eq!(observation.body["location"]["parent-uid"], "page-local-1");
    assert_eq!(observation.body["location"]["order"], "last");
    assert_eq!(
        observation.body["block"]["string"],
        "Loopback block content"
    );
}

#[fcp_async_core::runtime::test]
async fn rate_limit_error_preserves_retry_metadata_from_loopback_boundary() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "429 Too Many Requests",
        body: RATE_LIMIT_RESPONSE,
        retry_after: Some("11"),
    }]);
    let connector = setup_connector(server.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation_id": OP_PAGES_LIST,
            "input": {}
        }))
        .await;

    let Err(FcpError::External {
        service,
        message,
        status_code,
        retryable,
        retry_after,
    }) = result
    else {
        panic!("expected Roam rate-limit error, got {result:?}");
    };
    assert_eq!(service, "roam");
    assert!(message.contains("11000ms"));
    assert_eq!(status_code, Some(429));
    assert!(retryable);
    assert_eq!(retry_after, Some(Duration::from_secs(11)));

    let observations = server.join();
    let observation = observations.first().expect("one request observed");
    assert_eq!(
        observation.request_line,
        "POST /api/graph/local-graph/q HTTP/1.1"
    );
    assert!(observation.authorization_seen);
    assert!(observation.accept_json_seen);
    assert!(observation.content_type_json_seen);
    assert!(observation.user_agent_seen);
}
