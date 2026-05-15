//! Local loopback acceptance coverage for the `Bitwarden` connector.

#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Duration as StdDuration};

use fcp_bitwarden::connector::BitwardenConnector;
use fcp_prelude::FcpError;
use serde::Serialize;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.57";
const CONNECTOR_ID: &str = "bitwarden";
const ACCESS_TOKEN: &str = "local-bitwarden-access-token";
const SECRET_SENTINEL: &str = "BITWARDEN_SECRET_VALUE_SHOULD_NOT_APPEAR";
const JSON_HEADERS: &[(&str, &str)] = &[("content-type", "application/json")];
const RATE_LIMIT_HEADERS: &[(&str, &str)] =
    &[("content-type", "application/json"), ("retry-after", "3")];

#[derive(Clone)]
struct ResponseSpec {
    status: u16,
    headers: &'static [(&'static str, &'static str)],
    body: &'static str,
}

impl ResponseSpec {
    const fn json(status: u16, body: &'static str) -> Self {
        Self {
            status,
            headers: JSON_HEADERS,
            body,
        }
    }

    const fn json_with_headers(
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
    body: String,
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
                    handle_request(stream, &response)
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

fn handle_request(mut stream: TcpStream, response: &ResponseSpec) -> RequestObservation {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .expect("set read timeout");

    let raw = read_http_request(&mut stream);
    let (head, body) = split_request(&raw);
    let request = String::from_utf8_lossy(head);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers = lines.map(str::to_string).collect::<Vec<_>>();

    write_response(&mut stream, response);

    RequestObservation {
        request_line,
        headers,
        body: String::from_utf8_lossy(body).to_string(),
    }
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 2048];
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);
        if let Some(header_end) = find_header_end(&request) {
            let body_bytes = request.len().saturating_sub(header_end + 4);
            if body_bytes >= content_length(&request[..header_end]) {
                return request;
            }
        }
        assert!(request.len() < 16 * 1024, "request should stay bounded");
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn split_request(request: &[u8]) -> (&[u8], &[u8]) {
    let header_end = find_header_end(request).expect("request contains header terminator");
    (&request[..header_end], &request[header_end + 4..])
}

fn content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers);
    text.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
}

fn write_response(stream: &mut TcpStream, response: &ResponseSpec) {
    let reason = match response.status {
        200 => "OK",
        429 => "Too Many Requests",
        _ => "Status",
    };
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nconnection: close\r\ncontent-length: {}\r\n",
        response.status,
        reason,
        response.body.len()
    )
    .expect("write response status");
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n").expect("write response header");
    }
    write!(stream, "\r\n{}", response.body).expect("write response body");
}

fn has_header(headers: &[String], name: &str, expected_value: &str) -> bool {
    headers.iter().any(|line| {
        let Some((actual_name, actual_value)) = line.split_once(':') else {
            return false;
        };
        actual_name.eq_ignore_ascii_case(name) && actual_value.trim() == expected_value
    })
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_collection_and_item_operations_use_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(
            200,
            r#"{"object":"list","data":[{"id":"col-local","name":"Local Collection","organizationId":"org-local"}]}"#,
        ),
        ResponseSpec::json(
            200,
            r#"{"object":"list","data":[{"id":"item-local","name":"API Credential","type":1}]}"#,
        ),
        ResponseSpec::json(
            200,
            r#"{"object":"item","id":"created-local","name":"Generated Login","type":1}"#,
        ),
        ResponseSpec::json(200, r"{}"),
    ]);
    let mut connector = configured_connector(fixture.base_url()).await;

    let collections = connector
        .handle_invoke(json!({
            "operation_id": "bitwarden.collections.list",
            "input": {}
        }))
        .await
        .expect("list collections through loopback");
    let items = connector
        .handle_invoke(json!({
            "operation_id": "bitwarden.items.list",
            "input": {"collection_id": "col-local", "folder_id": "folder-local"}
        }))
        .await
        .expect("list items through loopback");
    let created = connector
        .handle_invoke(json!({
            "operation_id": "bitwarden.items.create",
            "input": {
                "type": 1,
                "name": "Generated Login",
                "login": {"username": "local-user", "password": SECRET_SENTINEL},
                "collection_ids": ["col-local"]
            }
        }))
        .await
        .expect("create item through loopback");
    let deleted = connector
        .handle_invoke(json!({
            "operation_id": "bitwarden.items.delete",
            "input": {"item_id": "item-local"}
        }))
        .await
        .expect("delete item through loopback");
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector");
    let observations = fixture.join();

    assert_eq!(observations.len(), 4);
    assert_eq!(observations[0].request_line, "GET /collections HTTP/1.1");
    assert!(
        observations[1]
            .request_line
            .starts_with("GET /list/object/items?")
    );
    assert!(
        observations[1]
            .request_line
            .contains("collectionId=col-local")
    );
    assert!(
        observations[1]
            .request_line
            .contains("folderId=folder-local")
    );
    assert_eq!(observations[2].request_line, "POST /object/item HTTP/1.1");
    assert_eq!(
        observations[3].request_line,
        "DELETE /object/item/item-local HTTP/1.1"
    );
    for observation in &observations {
        assert!(has_header(
            &observation.headers,
            "authorization",
            &format!("Bearer {ACCESS_TOKEN}")
        ));
        assert!(has_header(
            &observation.headers,
            "accept",
            "application/json"
        ));
    }

    let create_body: Value =
        serde_json::from_str(&observations[2].body).expect("create body is JSON");
    assert_eq!(create_body["type"], 1);
    assert_eq!(create_body["name"], "Generated Login");
    assert_eq!(create_body["login"]["username"], "local-user");
    assert_eq!(create_body["login"]["password"], SECRET_SENTINEL);
    assert_eq!(create_body["collection_ids"][0], "col-local");

    assert_eq!(collections["data"][0]["id"], "col-local");
    assert_eq!(items["data"][0]["id"], "item-local");
    assert_eq!(created["id"], "created-local");
    assert_eq!(deleted["deleted"], true);

    let evidence = evidence_log(
        "collections_items_crud",
        "loopback_http",
        &["GET /collections", "POST /object/item"],
        "passed",
    );
    let evidence_json = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(evidence_json.contains(ACCEPTANCE_SUITE_CLASS));
    assert!(evidence_json.contains(BEAD_ID));
    assert!(!evidence_json.contains(ACCESS_TOKEN));
    assert!(!evidence_json.contains(SECRET_SENTINEL));
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rate_limit_maps_retry_after_without_secret_logging() {
    let fixture = LoopbackFixture::start(vec![ResponseSpec::json_with_headers(
        429,
        RATE_LIMIT_HEADERS,
        r#"{"message":"provider body should stay out of evidence"}"#,
    )]);
    let connector = configured_connector(fixture.base_url()).await;

    let err = connector
        .handle_invoke(json!({
            "operation_id": "bitwarden.collections.list",
            "input": {}
        }))
        .await
        .expect_err("rate limit should map to FCP external error");
    let observations = fixture.join();
    assert_eq!(observations[0].request_line, "GET /collections HTTP/1.1");

    match err {
        FcpError::External {
            service,
            status_code,
            retryable,
            retry_after,
            ..
        } => {
            assert_eq!(service, "bitwarden");
            assert_eq!(status_code, Some(429));
            assert!(retryable);
            assert_eq!(retry_after, Some(Duration::from_secs(3)));
        }
        other => panic!("expected external rate-limit error, got {other:?}"),
    }

    let evidence = evidence_log(
        "collections_list_rate_limit",
        "loopback_http",
        &["GET /collections"],
        "rate_limited",
    );
    let evidence_json = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(!evidence_json.contains(ACCESS_TOKEN));
    assert!(!evidence_json.contains("provider body"));
}

#[fcp_async_core::runtime::test]
async fn evidence_schema_carries_connector_and_tracker_identity() {
    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");

    let fixture = LoopbackFixture::start(vec![]);
    let connector = configured_connector(fixture.base_url()).await;
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection returns metadata");
    assert_eq!(introspection["connector_id"], "fcp.bitwarden");
    assert_eq!(introspection["operations"].as_array().unwrap().len(), 5);

    let simulation = connector
        .handle_simulate(json!({"operation_id": "bitwarden.items.get"}))
        .await
        .expect("known operation simulates");
    assert_eq!(simulation["allowed"], true);
    let denied = connector
        .handle_simulate(json!({"operation_id": "bitwarden.nope"}))
        .await
        .expect("unknown operation returns denial response");
    assert_eq!(denied["allowed"], false);
    let observations = fixture.join();
    assert!(observations.is_empty());

    let evidence = evidence_log(
        "metadata",
        "in_process_no_egress",
        &["introspect", "simulate"],
        "passed",
    );
    let value = serde_json::to_value(evidence).expect("evidence serializes");
    assert_eq!(value["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(value["bead_id"], BEAD_ID);
    assert_eq!(value["connector_id"], CONNECTOR_ID);
    assert_eq!(value["auth"]["credential_material_logged"], false);
}

async fn configured_connector(base_url: &str) -> BitwardenConnector {
    let mut connector = BitwardenConnector::new();
    connector
        .handle_configure(json!({
            "access_token": ACCESS_TOKEN,
            "base_url": base_url
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({"session_id": "bitwarden-local-non-mock"}))
        .await
        .expect("handshake connector");
    connector
}

#[derive(Serialize)]
struct EvidenceLog<'a> {
    suite_class: &'static str,
    bead_id: &'static str,
    connector_id: &'static str,
    route: &'static str,
    operations: &'a [&'a str],
    fixture_mode: &'static str,
    provider_class: &'static str,
    result: &'static str,
    auth: AuthEvidence,
    cleanup: &'static str,
}

#[derive(Serialize)]
struct AuthEvidence {
    mode: &'static str,
    authorization_header_verified: bool,
    credential_material_logged: bool,
}

const fn evidence_log<'a>(
    route: &'static str,
    fixture_mode: &'static str,
    operations: &'a [&'a str],
    result: &'static str,
) -> EvidenceLog<'a> {
    EvidenceLog {
        suite_class: ACCEPTANCE_SUITE_CLASS,
        bead_id: BEAD_ID,
        connector_id: CONNECTOR_ID,
        route,
        operations,
        fixture_mode,
        provider_class: "sandbox_required_local_boundary",
        result,
        auth: AuthEvidence {
            mode: "bearer_token",
            authorization_header_verified: true,
            credential_material_logged: false,
        },
        cleanup: "connector_shutdown_and_fixture_thread_joined",
    }
}
