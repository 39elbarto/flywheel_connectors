use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_figma::connector::FigmaConnector;
use fcp_prelude::{CapabilityConstraints, FcpError};
use serde_json::{Value, json};

const API_TOKEN: &str = "figma_local_acceptance_token";
const TEST_INSTANCE_ID: &str = "inst_figma_local_acceptance";
const OP_LIST_TEAM_PROJECTS: &str = "figma.list_team_projects";
const OP_LIST_PROJECT_FILES: &str = "figma.list_project_files";
const OP_GET_FILE_META: &str = "figma.get_file_meta";

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
            .contains(&format!("x-figma-token: {API_TOKEN}")),
        "request should carry the configured Figma token; head={}",
        captured.head
    );
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id("figma.read")
        .zone_id("z:work")
        .principal("user:local-figma-acceptance")
        .operations(&[operation])
        .target_instance(TEST_INSTANCE_ID)
        .issuer("node:local-figma-acceptance")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should be valid")
        .sign(signing_key)
        .expect("capability token signing should succeed");
    fcp_core::CapabilityToken::from_raw(raw)
}

async fn setup_connector(base_url: &str) -> (FigmaConnector, Ed25519SigningKey) {
    let mut connector = FigmaConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["figma.read"],
            "requested_instance_id": TEST_INSTANCE_ID
        }))
        .await
        .expect("Figma connector should handshake with local host key");

    connector
        .handle_configure(json!({
            "token": API_TOKEN,
            "base_url": base_url
        }))
        .await
        .expect("Figma connector should configure against loopback");

    (connector, signing_key)
}

async fn invoke(
    connector: &FigmaConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": generate_valid_token(signing_key, operation)
        }))
        .await
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_list_team_projects_uses_loopback_and_maps_output() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "200 OK",
        body: r#"{
            "name": "Design Team",
            "projects": [
                {"id": 101, "name": "Mobile App"},
                {"id": 102, "name": "Design System"}
            ]
        }"#,
    }]);
    let (connector, signing_key) = setup_connector(&server.base_url).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_LIST_TEAM_PROJECTS,
        json!({ "team_id": "team-local" }),
    )
    .await
    .expect("team project listing should invoke against loopback");

    let captured = server.take();
    assert_request(&captured, "GET", "/teams/team-local/projects");
    assert!(
        captured.body.is_none(),
        "team project listing should not send a JSON body"
    );
    server.join();

    assert_eq!(result["name"], "Design Team");
    assert_eq!(
        result["projects"].as_array().expect("projects array").len(),
        2
    );
    assert_eq!(result["projects"][0]["id"], 101);
    assert_eq!(result["projects"][1]["name"], "Design System");
    assert_eq!(result["provenance"]["source"], "figma.teams");
    assert_eq!(result["provenance"]["scope"], "team");
    assert_eq!(result["taint"], json!(["external_input"]));
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_list_project_files_preserves_thumbnail_and_timestamps() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "200 OK",
        body: r#"{
            "name": "Project Alpha",
            "files": [{
                "key": "fileA",
                "name": "Landing Page",
                "thumbnail_url": "https://cdn.figma.com/thumb.png",
                "last_modified": "2026-01-15T10:00:00Z"
            }]
        }"#,
    }]);
    let (connector, signing_key) = setup_connector(&server.base_url).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_LIST_PROJECT_FILES,
        json!({ "project_id": "proj-local" }),
    )
    .await
    .expect("project file listing should invoke against loopback");

    let captured = server.take();
    assert_request(&captured, "GET", "/projects/proj-local/files");
    assert!(
        captured.body.is_none(),
        "project file listing should not send a JSON body"
    );
    server.join();

    assert_eq!(result["name"], "Project Alpha");
    assert_eq!(result["files"].as_array().expect("files array").len(), 1);
    assert_eq!(result["files"][0]["key"], "fileA");
    assert_eq!(
        result["files"][0]["thumbnail_url"],
        "https://cdn.figma.com/thumb.png"
    );
    assert_eq!(result["files"][0]["last_modified"], "2026-01-15T10:00:00Z");
    assert_eq!(result["provenance"]["source"], "figma.projects");
    assert_eq!(result["provenance"]["scope"], "project");
    assert_eq!(result["taint"], json!(["external_input"]));
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_get_file_meta_uses_depth_query_and_maps_metadata() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "200 OK",
        body: r#"{
            "name": "Component Library",
            "document": {"id": "0:0", "type": "DOCUMENT", "children": []},
            "lastModified": "2026-02-20T12:34:56Z",
            "version": "987654",
            "components": {},
            "styles": {}
        }"#,
    }]);
    let (connector, signing_key) = setup_connector(&server.base_url).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_GET_FILE_META,
        json!({ "file_key": "file-local" }),
    )
    .await
    .expect("file metadata should invoke against loopback");

    let captured = server.take();
    assert_request(&captured, "GET", "/files/file-local?depth=1");
    assert!(
        captured.body.is_none(),
        "file metadata request should not send a JSON body"
    );
    server.join();

    assert_eq!(result["name"], "Component Library");
    assert_eq!(result["lastModified"], "2026-02-20T12:34:56Z");
    assert_eq!(result["version"], "987654");
    assert_eq!(result["provenance"]["source"], "figma.files");
    assert_eq!(result["provenance"]["scope"], "file");
    assert_eq!(result["taint"], json!(["external_input"]));
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_list_team_projects_maps_provider_auth_denial() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "401 Unauthorized",
        body: r#"{"status": 401, "err": "bad token"}"#,
    }]);
    let (connector, signing_key) = setup_connector(&server.base_url).await;

    let error = invoke(
        &connector,
        &signing_key,
        OP_LIST_TEAM_PROJECTS,
        json!({ "team_id": "team-local" }),
    )
    .await
    .expect_err("upstream auth denial should map to an FCP unauthorized error");

    let captured = server.take();
    assert_request(&captured, "GET", "/teams/team-local/projects");
    server.join();

    match error {
        FcpError::Unauthorized { code, message } => {
            assert_eq!(code, 2001);
            assert!(
                message.contains("Invalid or expired Figma token"),
                "unexpected unauthorized message: {message}"
            );
        }
        other => panic!("expected unauthorized error, got {other:?}"),
    }
}
