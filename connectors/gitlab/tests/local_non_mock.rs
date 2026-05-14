#![allow(
    clippy::doc_markdown,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_gitlab::connector::GitLabConnector;
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError};
use serde_json::{Value, json};

const API_TOKEN: &str = "glpat-local-acceptance";
const OP_PROJECTS_LIST: &str = "gitlab.projects.list";
const OP_ISSUES_LIST: &str = "gitlab.issues.list";
const OP_ISSUES_CREATE: &str = "gitlab.issues.create";

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
            .expect("loopback listener should bind to an ephemeral port");
        let base_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("loopback listener should expose its local address")
        );
        let (request_tx, received) = mpsc::channel();

        let join = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener
                    .accept()
                    .expect("loopback listener should accept the expected request");
                stream
                    .set_read_timeout(Some(StdDuration::from_secs(5)))
                    .expect("loopback stream should set a read timeout");

                let request = read_complete_request(&mut stream);
                request_tx
                    .send(request)
                    .expect("captured request should be delivered to the test");

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
            .recv_timeout(StdDuration::from_secs(5))
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
    body: &'static str,
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
    assert!(
        captured
            .head
            .to_ascii_lowercase()
            .contains(&format!("private-token: {API_TOKEN}")),
        "request should carry the configured GitLab token; head={}",
        captured.head
    );
}

fn capability_for(operation: &'static str) -> &'static str {
    match operation {
        OP_PROJECTS_LIST => "gitlab.projects.read",
        OP_ISSUES_LIST => "gitlab.issues.read",
        OP_ISSUES_CREATE => "gitlab.issues.write",
        _ => panic!("unsupported GitLab local acceptance operation: {operation}"),
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    instance_id: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_for(operation))
        .zone_id("z:work")
        .principal("user:local-gitlab-acceptance")
        .operations(&[operation])
        .issuer("node:local-gitlab-acceptance")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should be valid")
        .target_instance(instance_id)
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

async fn setup_connector(base_url: &str) -> (GitLabConnector, Ed25519SigningKey, String) {
    let mut connector = GitLabConnector::new();
    connector
        .handle_configure(json!({
            "private_token": API_TOKEN,
            "base_url": base_url
        }))
        .await
        .expect("GitLab connector should configure against loopback");

    let signing_key = Ed25519SigningKey::generate();
    let handshake = connector
        .handle_handshake(json!({
            "session_id": "gitlab-local-acceptance",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes()
        }))
        .await
        .expect("GitLab connector should handshake with local host key");
    let instance_id = handshake["instance_id"]
        .as_str()
        .expect("GitLab handshake should return an instance_id")
        .to_string();

    (connector, signing_key, instance_id)
}

async fn invoke(
    connector: &GitLabConnector,
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    connector
        .handle_invoke(json!({
            "operation_id": operation,
            "input": input,
            "capability_token": generate_valid_token(signing_key, operation, instance_id)
        }))
        .await
}

#[fcp_async_core::test]
async fn local_non_mock_projects_list_uses_loopback_query_and_maps_output() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "200 OK",
        body: r#"[
            {"id": 11, "name": "platform", "path_with_namespace": "group/platform"},
            {"id": 12, "name": "sdk", "path_with_namespace": "group/sdk"}
        ]"#,
    }]);
    let (connector, signing_key, instance_id) = setup_connector(&server.base_url).await;

    let result = invoke(
        &connector,
        &signing_key,
        &instance_id,
        OP_PROJECTS_LIST,
        json!({ "per_page": 2 }),
    )
    .await
    .expect("project listing should invoke against loopback");

    let captured = server.take();
    assert_request(&captured, "GET", "/projects?per_page=2");
    assert!(
        captured.body.is_none(),
        "project listing should not send a JSON body"
    );
    server.join();

    assert_eq!(
        result["projects"].as_array().expect("projects array").len(),
        2
    );
    assert_eq!(result["projects"][0]["name"], "platform");
    assert_eq!(result["projects"][1]["path_with_namespace"], "group/sdk");
}

#[fcp_async_core::test]
async fn local_non_mock_issues_list_percent_encodes_project_paths() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "200 OK",
        body: r#"[
            {"id": 101, "iid": 7, "title": "Tighten admission policy", "state": "opened"}
        ]"#,
    }]);
    let (connector, signing_key, instance_id) = setup_connector(&server.base_url).await;

    let result = invoke(
        &connector,
        &signing_key,
        &instance_id,
        OP_ISSUES_LIST,
        json!({ "project_id": "group/subgroup/repo" }),
    )
    .await
    .expect("issue listing should invoke against loopback");

    let captured = server.take();
    assert_request(&captured, "GET", "/projects/group%2Fsubgroup%2Frepo/issues");
    assert!(
        captured.body.is_none(),
        "issue listing should not send a JSON body"
    );
    server.join();

    assert_eq!(result["issues"].as_array().expect("issues array").len(), 1);
    assert_eq!(result["issues"][0]["iid"], 7);
    assert_eq!(result["issues"][0]["state"], "opened");
}

#[fcp_async_core::test]
async fn local_non_mock_issues_create_posts_json_body() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "201 Created",
        body: r#"{"id": 201, "iid": 42, "title": "Local acceptance", "state": "opened"}"#,
    }]);
    let (connector, signing_key, instance_id) = setup_connector(&server.base_url).await;

    let result = invoke(
        &connector,
        &signing_key,
        &instance_id,
        OP_ISSUES_CREATE,
        json!({
            "project_id": "group/repo",
            "title": "Local acceptance",
            "description": "Loopback request/response proof"
        }),
    )
    .await
    .expect("issue creation should invoke against loopback");

    let captured = server.take();
    assert_request(&captured, "POST", "/projects/group%2Frepo/issues");
    assert_eq!(
        captured.body.expect("issue creation should send JSON"),
        json!({
            "title": "Local acceptance",
            "description": "Loopback request/response proof"
        })
    );
    server.join();

    assert_eq!(result["iid"], 42);
    assert_eq!(result["title"], "Local acceptance");
    assert_eq!(result["state"], "opened");
}

#[fcp_async_core::test]
async fn local_non_mock_projects_list_maps_provider_auth_denial() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "401 Unauthorized",
        body: r#"{"message":"401 Unauthorized"}"#,
    }]);
    let (connector, signing_key, instance_id) = setup_connector(&server.base_url).await;

    let error = invoke(
        &connector,
        &signing_key,
        &instance_id,
        OP_PROJECTS_LIST,
        json!({}),
    )
    .await
    .expect_err("upstream auth denial should map to a GitLab external error");

    let captured = server.take();
    assert_request(&captured, "GET", "/projects");
    server.join();

    match error {
        FcpError::External {
            service,
            message,
            status_code,
            retryable,
            ..
        } => {
            assert_eq!(service, "gitlab");
            assert_eq!(status_code, Some(401));
            assert!(!retryable);
            assert!(
                message.contains("Authentication failed"),
                "unexpected external error message: {message}"
            );
        }
        other => panic!("expected external error, got {other:?}"),
    }
}
