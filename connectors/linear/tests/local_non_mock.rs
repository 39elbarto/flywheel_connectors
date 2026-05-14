#![allow(
    clippy::doc_markdown,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use std::fmt::Write as FmtWrite;
use std::io::{Read, Write as IoWrite};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_linear::connector::LinearConnector;
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError, InstanceId};
use serde_json::{Value, json};

const API_KEY: &str = "lin_api_local_acceptance_key";
const OP_GET_ISSUE: &str = "linear.get_issue";
const OP_LIST_TEAMS: &str = "linear.list_teams";
const OP_SEARCH_ISSUES: &str = "linear.search_issues";

#[derive(Debug)]
struct CapturedRequest {
    head: String,
    body: Option<Value>,
}

struct LoopbackGraphqlServer {
    base_url: String,
    received: Receiver<CapturedRequest>,
    join: JoinHandle<()>,
}

impl LoopbackGraphqlServer {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .expect("loopback listener should bind to an ephemeral port");
        let addr = listener
            .local_addr()
            .expect("loopback listener should expose its local address");
        let base_url = format!("http://{addr}");
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

                let mut raw_response = format!("HTTP/1.1 {}\r\n", response.status);
                raw_response.push_str("content-type: application/json\r\n");
                write!(
                    &mut raw_response,
                    "content-length: {}\r\n",
                    response.body.len()
                )
                .expect("content-length header should format");
                raw_response.push_str("connection: close\r\n");
                for (name, value) in response.headers {
                    raw_response.push_str(name);
                    raw_response.push_str(": ");
                    raw_response.push_str(value);
                    raw_response.push_str("\r\n");
                }
                raw_response.push_str("\r\n");
                raw_response.push_str(response.body);

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

    fn graphql_url(&self) -> String {
        format!("{}/graphql", self.base_url)
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
    headers: Vec<(&'static str, &'static str)>,
    body: &'static str,
}

impl HttpResponse {
    const fn json(status: &'static str, body: &'static str) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
        }
    }
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

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    operation: &str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints should serialize as CBOR");
    let cose = CapabilityTokenBuilder::new()
        .capability_id("linear.read")
        .zone_id("z:work")
        .principal("user:local-linear-acceptance")
        .operations(&[operation])
        .issuer("node:local-linear-acceptance")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should be valid")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

async fn configure_and_handshake(
    connector: &mut LinearConnector,
    graphql_url: &str,
    capabilities: &[&str],
) -> Ed25519SigningKey {
    connector
        .handle_configure(json!({
            "api_key": API_KEY,
            "api_url": graphql_url
        }))
        .await
        .expect("Linear connector should configure against loopback GraphQL");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": capabilities
        }))
        .await
        .expect("Linear connector should establish verifier during handshake");

    signing_key
}

async fn invoke(
    connector: &LinearConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    let token = generate_valid_token(signing_key, operation, connector.instance_id());
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": token
        }))
        .await
}

fn assert_graphql_request(captured: &CapturedRequest) -> &Value {
    let request_line = captured
        .head
        .lines()
        .next()
        .expect("captured request should include a request line");
    assert_eq!(request_line, "POST /graphql HTTP/1.1");

    let lower_head = captured.head.to_ascii_lowercase();
    assert!(
        lower_head.contains("content-type: application/json"),
        "request should be JSON; head={}",
        captured.head
    );
    assert!(
        lower_head.contains(&format!("authorization: bearer {API_KEY}")),
        "request should carry the configured Linear bearer token; head={}",
        captured.head
    );

    captured
        .body
        .as_ref()
        .expect("GraphQL request should include a JSON body")
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_list_teams_posts_expected_graphql_and_maps_output() {
    let server = LoopbackGraphqlServer::start(vec![HttpResponse::json(
        "200 OK",
        r#"{
            "data": {
                "teams": {
                    "nodes": [
                        {
                            "id": "team-eng",
                            "name": "Engineering",
                            "key": "ENG",
                            "description": "Product engineering"
                        }
                    ]
                }
            }
        }"#,
    )]);
    let mut connector = LinearConnector::new();
    let signing_key =
        configure_and_handshake(&mut connector, &server.graphql_url(), &[OP_LIST_TEAMS]).await;

    let result = invoke(&connector, &signing_key, OP_LIST_TEAMS, json!({}))
        .await
        .expect("list teams should invoke against loopback GraphQL");

    let captured = server.take();
    let body = assert_graphql_request(&captured);
    let query = body["query"]
        .as_str()
        .expect("GraphQL request should include query text");
    assert!(query.contains("query ListTeams"));
    assert!(
        body.get("variables").is_none(),
        "list_teams should not send variables: {body}"
    );
    assert_eq!(result["teams"][0]["id"], "team-eng");
    assert_eq!(result["teams"][0]["key"], "ENG");
    assert_eq!(result["teams"][0]["description"], "Product engineering");
    server.join();
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_get_issue_posts_variables_and_maps_output() {
    let server = LoopbackGraphqlServer::start(vec![HttpResponse::json(
        "200 OK",
        r##"{
            "data": {
                "issue": {
                    "id": "issue-42",
                    "identifier": "LIN-42",
                    "title": "Loopback issue",
                    "description": "Loopback issue",
                    "priority": 2,
                    "priorityLabel": "High",
                    "state": {
                        "id": "state-started",
                        "name": "Started",
                        "color": "#f2c94c",
                        "type": "started"
                    },
                    "assignee": {
                        "id": "user-1",
                        "name": "Local Agent",
                        "displayName": "Local Agent",
                        "email": "agent@example.invalid"
                    },
                    "team": {
                        "id": "team-eng",
                        "name": "Engineering",
                        "key": "ENG"
                    },
                    "labels": {
                        "nodes": [
                            { "id": "label-bug", "name": "bug", "color": "#eb5757" }
                        ]
                    },
                    "createdAt": "2026-05-14T00:00:00Z",
                    "updatedAt": "2026-05-14T00:01:00Z",
                    "url": "https://linear.app/flywheel/issue/LIN-42"
                }
            }
        }"##,
    )]);
    let mut connector = LinearConnector::new();
    let signing_key =
        configure_and_handshake(&mut connector, &server.graphql_url(), &[OP_GET_ISSUE]).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_GET_ISSUE,
        json!({ "issue_id": "issue-42" }),
    )
    .await
    .expect("get issue should invoke against loopback GraphQL");

    let captured = server.take();
    let body = assert_graphql_request(&captured);
    let query = body["query"]
        .as_str()
        .expect("GraphQL request should include query text");
    assert!(query.contains("query GetIssue"));
    assert_eq!(body["variables"], json!({ "id": "issue-42" }));
    assert_eq!(result["issue"]["identifier"], "LIN-42");
    assert_eq!(result["issue"]["team"]["key"], "ENG");
    assert_eq!(result["issue"]["labels"]["nodes"][0]["name"], "bug");
    server.join();
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_search_issues_posts_query_variables_and_maps_output() {
    let server = LoopbackGraphqlServer::start(vec![HttpResponse::json(
        "200 OK",
        r##"{
            "data": {
                "searchIssues": {
                    "nodes": [
                        {
                            "id": "issue-1",
                            "identifier": "LIN-1",
                            "title": "First loopback bug",
                            "description": "Found locally",
                            "priority": 1,
                            "priorityLabel": "Urgent",
                            "state": {
                                "id": "state-triage",
                                "name": "Triage",
                                "color": "#2f80ed",
                                "type": "triage"
                            },
                            "assignee": null,
                            "team": {
                                "id": "team-eng",
                                "name": "Engineering",
                                "key": "ENG"
                            },
                            "labels": {
                                "nodes": []
                            },
                            "createdAt": "2026-05-14T00:00:00Z",
                            "updatedAt": "2026-05-14T00:01:00Z",
                            "url": "https://linear.app/flywheel/issue/LIN-1"
                        },
                        {
                            "id": "issue-2",
                            "identifier": "LIN-2",
                            "title": "Second loopback bug",
                            "description": null,
                            "priority": 3,
                            "priorityLabel": "Medium",
                            "state": null,
                            "assignee": null,
                            "team": {
                                "id": "team-ops",
                                "name": "Operations",
                                "key": "OPS"
                            },
                            "labels": {
                                "nodes": []
                            },
                            "createdAt": "2026-05-14T00:02:00Z",
                            "updatedAt": "2026-05-14T00:03:00Z",
                            "url": "https://linear.app/flywheel/issue/LIN-2"
                        }
                    ]
                }
            }
        }"##,
    )]);
    let mut connector = LinearConnector::new();
    let signing_key =
        configure_and_handshake(&mut connector, &server.graphql_url(), &[OP_SEARCH_ISSUES]).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_SEARCH_ISSUES,
        json!({ "query": "loopback bug" }),
    )
    .await
    .expect("search issues should invoke against loopback GraphQL");

    let captured = server.take();
    let body = assert_graphql_request(&captured);
    let query = body["query"]
        .as_str()
        .expect("GraphQL request should include query text");
    assert!(query.contains("query SearchIssues"));
    assert_eq!(body["variables"], json!({ "query": "loopback bug" }));
    assert_eq!(result["issues"][0]["identifier"], "LIN-1");
    assert_eq!(result["issues"][1]["team"]["key"], "OPS");
    server.join();
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_unauthorized_maps_to_fcp_error_without_leaking_key() {
    let server = LoopbackGraphqlServer::start(vec![HttpResponse::json(
        "401 Unauthorized",
        r#"{"errors":[{"message":"bad credentials"}]}"#,
    )]);
    let mut connector = LinearConnector::new();
    let signing_key =
        configure_and_handshake(&mut connector, &server.graphql_url(), &[OP_LIST_TEAMS]).await;

    let err = invoke(&connector, &signing_key, OP_LIST_TEAMS, json!({}))
        .await
        .expect_err("401 should map to an FCP authorization error");

    let captured = server.take();
    let body = assert_graphql_request(&captured);
    let query = body["query"]
        .as_str()
        .expect("GraphQL request should include query text");
    assert!(query.contains("query ListTeams"));
    assert!(
        matches!(err, FcpError::Unauthorized { code: 2001, .. }),
        "expected Unauthorized, got {err:?}"
    );
    assert!(
        !format!("{err:?}").contains(API_KEY),
        "FCP error should not include the Linear API key"
    );
    server.join();
}
