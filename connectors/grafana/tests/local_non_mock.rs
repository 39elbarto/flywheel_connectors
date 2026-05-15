//! Local loopback acceptance coverage for the Grafana connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use fcp_grafana::connector::GrafanaConnector;
use fcp_prelude::FcpError;
use serde::Serialize;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.4.6.2";
const CONNECTOR_ID: &str = "fcp.grafana";
const API_TOKEN: &str = "local-grafana-token";
const SECRET_SENTINEL: &str = "GRAFANA_SECRET_VALUE_SHOULD_NOT_APPEAR_IN_EVIDENCE";
const OP_DASHBOARDS_LIST: &str = "grafana.dashboards.list";
const OP_DASHBOARDS_CREATE: &str = "grafana.dashboards.create";
const OP_DASHBOARDS_DELETE: &str = "grafana.dashboards.delete";
const OP_DATASOURCES_LIST: &str = "grafana.datasources.list";

const DASHBOARDS_RESPONSE_BODY: &str = r#"[
  {
    "id": 1,
    "uid": "dash-local",
    "title": "Production Overview",
    "uri": "db/production-overview",
    "url": "/d/dash-local/production-overview"
  }
]"#;

const DATASOURCES_RESPONSE_BODY: &str = r#"[
  {
    "id": 1,
    "uid": "prometheus-local",
    "name": "Prometheus",
    "type": "prometheus"
  }
]"#;

const CREATE_RESPONSE_BODY: &str = r#"{
  "id": 2,
  "uid": "dash-created",
  "url": "/d/dash-created/fcp-created",
  "status": "success"
}"#;

const DELETE_RESPONSE_BODY: &str = r#"{"message":"Dashboard deleted"}"#;
const UNAUTHORIZED_BODY: &str = r#"{"message":"invalid token"}"#;
const JSON_HEADERS: &[(&str, &str)] = &[("content-type", "application/json")];

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
            headers: JSON_HEADERS,
            body,
        }
    }
}

#[derive(Debug)]
struct RequestObservation {
    request_line: String,
    headers: Vec<String>,
    body: String,
    response_status: u16,
    response_body_bytes: usize,
}

impl RequestObservation {
    fn method(&self) -> &str {
        self.request_line.split_whitespace().next().unwrap_or("")
    }

    fn target(&self) -> &str {
        self.request_line.split_whitespace().nth(1).unwrap_or("")
    }

    fn header_value(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<Vec<RequestObservation>>>,
}

impl LoopbackFixture {
    fn start(responses: Vec<ResponseSpec>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Grafana listener");
        let address = listener.local_addr().expect("read loopback address");
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
            .expect("loopback handle present")
            .join()
            .expect("loopback thread completed")
    }
}

fn handle_request(mut stream: TcpStream, response: ResponseSpec) -> RequestObservation {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .expect("set request read timeout");
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
        response_status: response.status,
        response_body_bytes: response.body.len(),
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
            let expected_body_len = content_length(&request[..header_end]);
            let body_bytes = request.len().saturating_sub(header_end + 4);
            if body_bytes >= expected_body_len {
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

fn write_response(stream: &mut TcpStream, response: ResponseSpec) {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nconnection: close\r\ncontent-length: {}\r\n",
        response.status,
        status_reason(response.status),
        response.body.len()
    )
    .expect("write response status");
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n").expect("write response header");
    }
    write!(stream, "\r\n{}", response.body).expect("write response body");
}

const fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        _ => "Status",
    }
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_dashboard_datasource_and_write_paths_use_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, DASHBOARDS_RESPONSE_BODY),
        ResponseSpec::json(200, DATASOURCES_RESPONSE_BODY),
        ResponseSpec::json(200, CREATE_RESPONSE_BODY),
        ResponseSpec::json(200, DELETE_RESPONSE_BODY),
    ]);
    let connector = configured_connector(fixture.base_url()).await;

    let dashboards = invoke(
        &connector,
        OP_DASHBOARDS_LIST,
        json!({"query": "prod", "limit": 2}),
    )
    .await
    .expect("dashboards.list should succeed");
    let datasources = invoke(&connector, OP_DATASOURCES_LIST, json!({}))
        .await
        .expect("datasources.list should succeed");
    let created = invoke(
        &connector,
        OP_DASHBOARDS_CREATE,
        json!({
            "dashboard": {
                "uid": "dash-created",
                "title": "FCP Created",
                "panels": [],
                "secret_marker": SECRET_SENTINEL
            },
            "folder_uid": "folder-local",
            "overwrite": true
        }),
    )
    .await
    .expect("dashboards.create should succeed");
    let deleted = invoke(
        &connector,
        OP_DASHBOARDS_DELETE,
        json!({"uid": "dash-created"}),
    )
    .await
    .expect("dashboards.delete should succeed");
    let observations = fixture.join();

    assert_eq!(observations.len(), 4);
    assert_eq!(
        observations[0].request_line,
        "GET /search?type=dash-db&query=prod&limit=2 HTTP/1.1"
    );
    assert_eq!(observations[1].request_line, "GET /datasources HTTP/1.1");
    assert_eq!(observations[2].request_line, "POST /dashboards/db HTTP/1.1");
    assert_eq!(
        observations[3].request_line,
        "DELETE /dashboards/uid/dash%2Dcreated HTTP/1.1"
    );
    for observation in &observations {
        assert_eq!(
            observation.header_value("authorization"),
            Some("Bearer local-grafana-token")
        );
    }

    let create_body: Value =
        serde_json::from_str(&observations[2].body).expect("create body is JSON");
    assert_eq!(create_body["dashboard"]["uid"], "dash-created");
    assert_eq!(create_body["folderUid"], "folder-local");
    assert_eq!(create_body["overwrite"], true);
    assert_eq!(
        create_body["dashboard"]["secret_marker"], SECRET_SENTINEL,
        "connector should forward the dashboard body while evidence redacts it"
    );

    assert_eq!(dashboards["dashboards"][0]["uid"], "dash-local");
    assert_eq!(datasources["datasources"][0]["uid"], "prometheus-local");
    assert_eq!(created["uid"], "dash-created");
    assert_eq!(deleted["deleted"], true);

    let logs = vec![
        evidence_log(OP_DASHBOARDS_LIST, Some(&observations[0]), "passed"),
        evidence_log(OP_DATASOURCES_LIST, Some(&observations[1]), "passed"),
        evidence_log(OP_DASHBOARDS_CREATE, Some(&observations[2]), "passed"),
        evidence_log(OP_DASHBOARDS_DELETE, Some(&observations[3]), "passed"),
    ];
    assert_redacted(&logs);
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_auth_denial_maps_unauthorized_without_secret_logging() {
    let fixture = LoopbackFixture::start(vec![ResponseSpec::json(401, UNAUTHORIZED_BODY)]);
    let connector = configured_connector(fixture.base_url()).await;

    let err = invoke(&connector, OP_DATASOURCES_LIST, json!({}))
        .await
        .expect_err("401 should map to FCP unauthorized");
    let observations = fixture.join();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].request_line, "GET /datasources HTTP/1.1");

    match err {
        FcpError::Unauthorized { code: 2001, .. } => {}
        other => panic!("expected unauthorized error, got {other:?}"),
    }

    let logs = vec![evidence_log(
        OP_DATASOURCES_LIST,
        Some(&observations[0]),
        "unauthorized",
    )];
    assert_redacted(&logs);
}

#[test]
fn evidence_schema_carries_connector_identity() {
    let log = evidence_log(OP_DASHBOARDS_LIST, None, "passed");
    let value = serde_json::to_value(log).expect("evidence JSON");
    assert_eq!(value["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(value["bead_id"], BEAD_ID);
    assert_eq!(value["connector_id"], CONNECTOR_ID);
    assert_eq!(value["operation"], OP_DASHBOARDS_LIST);
    assert_eq!(value["capability"], "grafana.dashboards.read");
    assert_eq!(value["zone"], "z:work");
}

async fn configured_connector(base_url: &str) -> GrafanaConnector {
    let mut connector = GrafanaConnector::new();
    connector
        .handle_configure(json!({
            "auth_token": API_TOKEN,
            "base_url": base_url,
        }))
        .await
        .expect("configure Grafana connector");
    connector
        .handle_handshake(json!({"session_id": "local-non-mock"}))
        .await
        .expect("handshake Grafana connector");
    connector
}

async fn invoke(
    connector: &GrafanaConnector,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    connector
        .handle_invoke(json!({
            "operation_id": operation,
            "input": input,
        }))
        .await
}

#[derive(Debug, Serialize)]
struct EvidenceLog {
    suite_class: &'static str,
    bead_id: &'static str,
    connector_id: &'static str,
    operation: &'static str,
    capability: &'static str,
    zone: &'static str,
    route: &'static str,
    method: String,
    outcome: &'static str,
    response_status: Option<u16>,
    response_body_bytes: Option<usize>,
    redaction: &'static str,
}

fn evidence_log(
    operation: &'static str,
    request: Option<&RequestObservation>,
    outcome: &'static str,
) -> EvidenceLog {
    EvidenceLog {
        suite_class: ACCEPTANCE_SUITE_CLASS,
        bead_id: BEAD_ID,
        connector_id: CONNECTOR_ID,
        operation,
        capability: capability_for_operation(operation),
        zone: "z:work",
        route: request.map_or("in_process_no_egress", route_label),
        method: request.map_or_else(
            || "IN_PROCESS".to_string(),
            |request| request.method().to_string(),
        ),
        outcome,
        response_status: request.map(|request| request.response_status),
        response_body_bytes: request.map(|request| request.response_body_bytes),
        redaction: "bearer_token_dashboard_uid_datasource_uid_query_and_provider_body_not_logged",
    }
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_DASHBOARDS_LIST => "grafana.dashboards.read",
        OP_DASHBOARDS_CREATE | OP_DASHBOARDS_DELETE => "grafana.dashboards.write",
        OP_DATASOURCES_LIST => "grafana.datasources.read",
        _ => "unknown",
    }
}

fn route_label(request: &RequestObservation) -> &'static str {
    match (request.method(), request.target()) {
        ("GET", target) if target.starts_with("/search?") => "dashboards.list",
        ("GET", "/datasources") => "datasources.list",
        ("POST", "/dashboards/db") => "dashboards.create",
        ("DELETE", target) if target.starts_with("/dashboards/uid/") => "dashboards.delete",
        _ => "unrecognized",
    }
}

fn assert_redacted(logs: &[EvidenceLog]) {
    let serialized = serde_json::to_string(logs).expect("serialize evidence logs");
    for forbidden in [
        API_TOKEN,
        SECRET_SENTINEL,
        "Production Overview",
        "Prometheus",
        "FCP Created",
        "/d/dash-created",
        "invalid token",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "evidence logs should not contain sensitive sentinel `{forbidden}`"
        );
    }
    for entry in logs {
        eprintln!(
            "{}",
            serde_json::to_string(entry).expect("emit JSONL evidence")
        );
    }
}
