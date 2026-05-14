//! Local loopback acceptance coverage for the FCP `Salesforce` connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fcp_prelude::FcpError;
use fcp_salesforce::{client::DEFAULT_API_PATH, connector::SalesforceConnector};
use serde_json::json;

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.42";
const ACCESS_SECRET: &str = "local_salesforce_acceptance_secret";
const OP_ACCOUNTS_GET: &str = "salesforce.accounts.get";
const OP_ACCOUNTS_LIST: &str = "salesforce.accounts.list";
const ACCOUNT_RESPONSE_BODY: &str = r#"{
  "Id": "001LOCAL000000001",
  "Name": "Local Loopback Account",
  "Industry": "Integration Testing"
}"#;
const ACCOUNT_LIST_RESPONSE_BODY: &str = r#"{
  "totalSize": 1,
  "done": true,
  "records": [
    {
      "Id": "001LOCAL000000001",
      "Name": "Local Loopback Account"
    }
  ]
}"#;
const RATE_LIMIT_BODY: &str = r#"[
  {
    "message": "Request limit exceeded",
    "errorCode": "REQUEST_LIMIT_EXCEEDED"
  }
]"#;

#[derive(Debug, Clone, Copy)]
struct ResponseSpec {
    status: u16,
    headers: &'static [(&'static str, &'static str)],
    body: &'static str,
}

impl ResponseSpec {
    const fn json(status: u16, body: &'static str) -> Self {
        Self {
            status,
            headers: &[],
            body,
        }
    }

    const fn with_headers(
        status: u16,
        headers: &'static [(&'static str, &'static str)],
        body: &'static str,
    ) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

#[derive(Debug)]
struct RequestObservation {
    request_line: String,
    headers: Vec<String>,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<Vec<RequestObservation>>>,
}

impl LoopbackFixture {
    fn start(responses: Vec<ResponseSpec>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (stream, _) = listener.accept().expect("accept connector request");
                    handle_request(stream, response)
                })
                .collect()
        });

        Self {
            base_url: format!("http://{address}"),
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

fn handle_request(mut stream: TcpStream, response: ResponseSpec) -> RequestObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let raw = read_http_message(&mut stream);
    let header_end = find_header_end(&raw).expect("request contains header terminator");
    let header_text = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_text.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers = lines.map(str::to_string).collect::<Vec<_>>();

    write!(
        stream,
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
        response.status,
        status_reason(response.status),
        response.body.len()
    )
    .expect("write response headers");
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n").expect("write extra response header");
    }
    write!(stream, "\r\n{}", response.body).expect("write response body");

    RequestObservation {
        request_line,
        headers,
    }
}

fn read_http_message(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];

    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);

        if let Some(header_end) = find_header_end(&request) {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let total_len = header_end + 4 + content_length(&headers);
            while request.len() < total_len {
                let bytes_read = stream
                    .read(&mut buffer)
                    .expect("read connector request body");
                assert!(bytes_read > 0, "connector body should not close early");
                request.extend_from_slice(&buffer[..bytes_read]);
                assert!(request.len() < 16384, "request body should stay bounded");
            }
            request.truncate(total_len);
            return request;
        }

        assert!(request.len() < 16384, "request headers should stay bounded");
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| {
                value
                    .trim()
                    .parse::<usize>()
                    .expect("content-length is usize")
            })
        })
        .unwrap_or(0)
}

const fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        429 => "Too Many Requests",
        _ => "Status",
    }
}

fn has_header(headers: &[String], name: &str, expected_value: &str) -> bool {
    headers.iter().any(|line| {
        let Some((actual_name, actual_value)) = line.split_once(':') else {
            return false;
        };
        actual_name.eq_ignore_ascii_case(name) && actual_value.trim() == expected_value
    })
}

async fn setup_connector(base_url: &str) -> SalesforceConnector {
    let mut connector = SalesforceConnector::new();
    connector
        .handle_configure(json!({
            "access_token": ACCESS_SECRET,
            "base_url": base_url,
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({ "session_id": "salesforce-local-non-mock" }))
        .await
        .expect("handshake connector");
    connector
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_account_read_paths_cross_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, ACCOUNT_RESPONSE_BODY),
        ResponseSpec::json(200, ACCOUNT_LIST_RESPONSE_BODY),
    ]);
    let mut connector = setup_connector(fixture.base_url()).await;

    let self_check = connector
        .handle_self_check()
        .await
        .expect("self check uses local endpoint policy");
    assert_eq!(self_check["status"], "ok");

    let account_result = connector
        .handle_invoke(json!({
            "operation_id": OP_ACCOUNTS_GET,
            "input": {
                "account_id": "001LOCAL000000001",
                "fields": ["Name", "Industry"]
            }
        }))
        .await
        .expect("get account through loopback");
    assert_eq!(account_result["account"]["Id"], "001LOCAL000000001");
    assert_eq!(account_result["account"]["Name"], "Local Loopback Account");

    let list_result = connector
        .handle_invoke(json!({
            "operation_id": OP_ACCOUNTS_LIST,
            "input": {
                "fields": ["Id", "Name"],
                "limit": 2
            }
        }))
        .await
        .expect("list accounts through loopback");
    assert_eq!(list_result["records"].as_array().expect("records").len(), 1);
    assert_eq!(list_result["total_size"], 1);

    let health = connector.handle_health().await.expect("health response");
    assert_eq!(health["requests"], 2);
    assert_eq!(health["errors"], 0);
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector");

    let observations = fixture.join();
    assert_eq!(observations.len(), 2);
    assert_eq!(
        observations[0].request_line,
        format!(
            "GET {DEFAULT_API_PATH}/sobjects/Account/001LOCAL000000001?fields=Name,Industry HTTP/1.1"
        )
    );
    assert!(
        observations[1]
            .request_line
            .starts_with(&format!("GET {DEFAULT_API_PATH}/query?"))
    );
    assert!(
        observations[1]
            .request_line
            .contains("q=SELECT+Id%2C+Name+FROM+Account+LIMIT+2")
    );
    for observation in &observations {
        assert!(has_header(
            &observation.headers,
            "authorization",
            &format!("Bearer {ACCESS_SECRET}")
        ));
        assert!(has_header(
            &observation.headers,
            "user-agent",
            "fcp-salesforce/0.1.0"
        ));
    }

    let artifact = json!({
        "connector": "salesforce",
        "connector_id": "fcp.salesforce",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-salesforce --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operations": [OP_ACCOUNTS_GET, OP_ACCOUNTS_LIST],
        "request_response_boundary": {
            "methods": ["GET"],
            "paths": [
                "/sobjects/Account/001LOCAL000000001?fields=Name,Industry",
                "/query?q=SELECT+Id%2C+Name+FROM+Account+LIMIT+2"
            ],
            "api_path": DEFAULT_API_PATH,
            "query_encoding_verified": true
        },
        "auth_gate": {
            "mode": "bearer_header",
            "authorization_header_verified": true,
            "upstream_credentials_used": false
        },
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rate_limit_maps_retryable_provider_error() {
    let fixture = LoopbackFixture::start(vec![ResponseSpec::with_headers(
        429,
        &[("retry-after", "11")],
        RATE_LIMIT_BODY,
    )]);
    let mut connector = setup_connector(fixture.base_url()).await;

    let error = connector
        .handle_invoke(json!({
            "operation_id": OP_ACCOUNTS_LIST,
            "input": {
                "fields": ["Id", "Name"],
                "limit": 2
            }
        }))
        .await
        .expect_err("rate limit response should map to FCP external error");
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector");
    let observations = fixture.join();

    match error {
        FcpError::External {
            service,
            status_code,
            retryable,
            retry_after,
            message,
        } => {
            assert_eq!(service, "salesforce");
            assert_eq!(status_code, Some(429));
            assert!(retryable);
            assert_eq!(
                retry_after.expect("retry-after duration").as_millis(),
                11000
            );
            assert!(message.contains("Rate limited"));
            assert!(!message.contains(ACCESS_SECRET));
        }
        other => panic!("unexpected provider error mapping: {other:?}"),
    }

    assert_eq!(observations.len(), 1);
    assert!(
        observations[0]
            .request_line
            .starts_with(&format!("GET {DEFAULT_API_PATH}/query?"))
    );
    assert!(has_header(
        &observations[0].headers,
        "authorization",
        &format!("Bearer {ACCESS_SECRET}")
    ));

    let artifact = json!({
        "connector": "salesforce",
        "connector_id": "fcp.salesforce",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-salesforce --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http_rate_limit",
        "provider_class": "local_sufficient",
        "operation": OP_ACCOUNTS_LIST,
        "request_response_boundary": {
            "method": "GET",
            "path": "/query?q=SELECT+Id%2C+Name+FROM+Account+LIMIT+2",
            "api_path": DEFAULT_API_PATH,
            "status": 429,
            "retry_after_ms": 11000
        },
        "auth_gate": {
            "mode": "bearer_header",
            "authorization_header_verified": true,
            "upstream_credentials_used": false
        },
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
