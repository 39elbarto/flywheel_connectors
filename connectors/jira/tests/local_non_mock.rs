//! Local loopback acceptance coverage for the FCP `Jira` connector.

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
    io::{Read, Write as IoWrite},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration as StdDuration,
};

use base64::Engine;
use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_jira::connector::JiraConnector;
use fcp_prelude::{CapabilityToken, FcpError, InstanceId};
use serde_json::{Value, json};

const CONNECTOR: &str = "jira";
const PACKAGE: &str = "fcp-jira";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.26";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const LOOPBACK_EMAIL: &str = "user@example.com";
const LOOPBACK_API_SECRET: &str = "jira-local-non-mock-secret";
const OP_CREATE_ISSUE: &str = "jira.create_issue";
const OP_GET_ISSUE: &str = "jira.get_issue";
const OP_SEARCH_JQL: &str = "jira.search_jql";

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
                    .set_read_timeout(Some(StdDuration::from_secs(5)))
                    .expect("set loopback read timeout");
                let request = read_complete_request(&mut stream);
                requests.push(request);
                write_response(&mut stream, response);
            }
            requests
        });

        Self { base_url, join }
    }

    fn join(self) -> Vec<CapturedRequest> {
        self.join
            .join()
            .expect("loopback server thread should finish")
    }
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_issues_and_search_use_production_http_client_and_capability_gate() {
    let server = LoopbackServer::start(vec![
        HttpResponse::json(
            "201 Created",
            r#"{"id":"10010","key":"PROJ-123","self":"http://jira.local/rest/api/3/issue/10010"}"#,
        ),
        HttpResponse::json(
            "200 OK",
            r#"{"id":"10010","key":"PROJ-123","self":"http://jira.local/rest/api/3/issue/10010","fields":{"summary":"Loopback issue","status":{"name":"Open"}}}"#,
        ),
        HttpResponse::json(
            "200 OK",
            r#"{"issues":[{"id":"10010","key":"PROJ-123","fields":{"summary":"Loopback issue"}}],"total":1,"maxResults":25,"startAt":0}"#,
        ),
    ]);
    let (mut connector, signing_key) = setup_connector(&server.base_url).await;

    let created = invoke(
        &mut connector,
        &signing_key,
        OP_CREATE_ISSUE,
        json!({
            "project_key": "PROJ",
            "issue_type": "Task",
            "summary": "Loopback issue",
            "description": "Created only against the loopback fixture",
            "labels": ["local-non-mock"]
        }),
    )
    .await
    .expect("create_issue should invoke Jira client path");
    assert_eq!(created["key"], "PROJ-123");

    let issue = invoke(
        &mut connector,
        &signing_key,
        OP_GET_ISSUE,
        json!({
            "issue_key": "PROJ-123",
            "fields": "summary,status"
        }),
    )
    .await
    .expect("get_issue should invoke Jira client path");
    assert_eq!(issue["key"], "PROJ-123");
    assert_eq!(issue["fields"]["summary"], "Loopback issue");

    let search = invoke(
        &mut connector,
        &signing_key,
        OP_SEARCH_JQL,
        json!({
            "jql": "project = PROJ ORDER BY created DESC",
            "fields": "summary,status",
            "max_results": 25,
            "start_at": 0
        }),
    )
    .await
    .expect("search_jql should invoke Jira client path");
    assert_eq!(search["issues"][0]["key"], "PROJ-123");
    assert_eq!(search["total"], 1);

    let requests = server.join();
    assert_eq!(requests.len(), 3);
    assert_request(&requests[0], "POST /rest/api/3/issue HTTP/1.1");
    assert_request(
        &requests[1],
        "GET /rest/api/3/issue/PROJ-123?fields=summary%2Cstatus HTTP/1.1",
    );
    assert_request(&requests[2], "POST /rest/api/3/search HTTP/1.1");
    assert_eq!(requests[0].body["fields"]["project"]["key"], "PROJ");
    assert_eq!(requests[0].body["fields"]["summary"], "Loopback issue");
    assert_eq!(
        requests[2].body["jql"],
        "project = PROJ ORDER BY created DESC"
    );
    assert_eq!(requests[2].body["fields"], json!(["summary", "status"]));
    assert_eq!(requests[2].body["maxResults"], 25);

    let rendered = serde_json::to_string(&json!({
        "created": created,
        "issue": issue,
        "search": search,
    }))
    .expect("rendered result should serialize");
    assert!(!rendered.contains(LOOPBACK_API_SECRET));

    let artifact = proof_artifact(&json!({
        "capability_gate": {
            "signed_tokens_verified": true,
            "operations": [OP_CREATE_ISSUE, OP_GET_ISSUE, OP_SEARCH_JQL]
        },
        "request_response_boundary": {
            "create_issue": {
                "method": "POST",
                "path": "/rest/api/3/issue",
                "status": 201
            },
            "get_issue": {
                "method": "GET",
                "path": "/rest/api/3/issue/PROJ-123",
                "status": 200
            },
            "search_jql": {
                "method": "POST",
                "path": "/rest/api/3/search",
                "status": 200
            }
        },
        "auth_gate": {
            "mode": "basic_auth",
            "authorization_header_verified": true
        },
        "write_operation_shape": {
            "create_issue_exercised_only_against_loopback": true,
            "project_key": "PROJ",
            "issue_type": "Task"
        },
        "redaction": {
            "api_secret_redacted_from_output": true
        },
        "cleanup": {
            "fixture_requests_joined": requests.len()
        },
        "result": "passed"
    }));
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_unauthorized_maps_to_fcp_unauthorized() {
    let server = LoopbackServer::start(vec![HttpResponse::json(
        "401 Unauthorized",
        r#"{"errorMessages":["Unauthorized"],"errors":{}}"#,
    )]);
    let (mut connector, signing_key) = setup_connector(&server.base_url).await;

    let err = invoke(
        &mut connector,
        &signing_key,
        OP_GET_ISSUE,
        json!({"issue_key": "PROJ-123"}),
    )
    .await
    .expect_err("401 should map to an FCP unauthorized error");
    assert!(
        matches!(
            &err,
            FcpError::Unauthorized {
                code: 2001,
                message,
            } if message.contains("Jira")
        ),
        "unauthorized response should map to Jira unauthorized: {err:?}"
    );

    let requests = server.join();
    assert_eq!(requests.len(), 1);
    assert_request(&requests[0], "GET /rest/api/3/issue/PROJ-123 HTTP/1.1");

    let artifact = proof_artifact(&json!({
        "request_response_boundary": {
            "method": "GET",
            "path": "/rest/api/3/issue/PROJ-123",
            "status": 401
        },
        "error_mapping": {
            "fcp_error": "Unauthorized",
            "code": 2001
        },
        "cleanup": {
            "fixture_requests_joined": requests.len()
        },
        "result": "passed"
    }));
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rejects_invalid_issue_key_before_egress() {
    let server = LoopbackServer::start(Vec::new());
    let (mut connector, signing_key) = setup_connector(&server.base_url).await;

    let err = invoke(
        &mut connector,
        &signing_key,
        OP_GET_ISSUE,
        json!({"issue_key": "../admin"}),
    )
    .await
    .expect_err("path traversal issue key should be rejected before egress");
    assert!(
        matches!(
            &err,
            FcpError::InvalidRequest {
                code: 1003,
                message,
            } if message.contains("Invalid issue key")
        ),
        "invalid issue key should map to invalid request: {err:?}"
    );

    let requests = server.join();
    assert_eq!(requests.len(), 0);

    let artifact = proof_artifact(&json!({
        "egress_gate": {
            "operation": OP_GET_ISSUE,
            "unsafe_issue_key_rejected_before_http": true,
            "requests_sent": requests.len()
        },
        "cleanup": {
            "fixture_requests_joined": requests.len()
        },
        "result": "passed"
    }));
    println!("{artifact}");
}

async fn setup_connector(base_url: &str) -> (JiraConnector, Ed25519SigningKey) {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let mut connector = JiraConnector::new();
    connector
        .handle_configure(json!({
            "domain": "acme",
            "email": LOOPBACK_EMAIL,
            "api_token": LOOPBACK_API_SECRET,
            "base_url": format!("{base_url}/rest/api/3")
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": ["jira.read", "jira.write"]
        }))
        .await
        .expect("handshake connector");
    (connector, signing_key)
}

async fn invoke(
    connector: &mut JiraConnector,
    signing_key: &Ed25519SigningKey,
    operation: &str,
    input: Value,
) -> Result<Value, FcpError> {
    let capability = signed_capability(signing_key, operation, connector.instance_id());
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability
        }))
        .await
}

fn signed_capability(
    signing_key: &Ed25519SigningKey,
    operation: &str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let capability = match operation {
        OP_CREATE_ISSUE => "jira.write",
        _ => "jira.read",
    };
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("capability constraints should encode as CBOR");

    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .target_instance(instance_id.as_str())
        .try_constraints_cbor(&constraints_cbor)
        .expect("capability constraints should attach")
        .sign(signing_key)
        .expect("capability should sign");
    CapabilityToken::from_raw(cose)
}

fn assert_request(captured: &CapturedRequest, request_line: &str) {
    assert_eq!(
        captured
            .head
            .lines()
            .next()
            .expect("captured request should include request line"),
        request_line
    );
    assert!(
        header_seen(
            &captured.head,
            "authorization",
            &expected_basic_authorization()
        ),
        "request should carry configured Jira basic auth; head={}",
        captured.head
    );
    assert!(
        header_seen(&captured.head, "accept", "application/json"),
        "request should accept JSON; head={}",
        captured.head
    );
}

fn expected_basic_authorization() -> String {
    let credentials = base64::engine::general_purpose::STANDARD
        .encode(format!("{LOOPBACK_EMAIL}:{LOOPBACK_API_SECRET}"));
    format!("Basic {credentials}")
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
        "command": "cargo test -p fcp-jira --test local_non_mock -- --nocapture",
        "fixture_mode": "raw_tcp_loopback_http",
        "provider_class": "local_sufficient",
        "details": details
    })
}
