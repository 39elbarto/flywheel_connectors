//! Local loopback acceptance coverage for the `Datadog` connector.

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

use fcp_datadog::connector::DatadogConnector;
use fcp_prelude::{ConnectorId, FcpError, OperationId, RequestId, ZoneId};
use serde::Serialize;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.61";
const CONNECTOR_ID: &str = "fcp.datadog";
const API_KEY: &str = "local-datadog-api-key";
const APP_KEY: &str = "local-datadog-app-key";
const METRIC_SENTINEL: &str = "custom.acceptance_secret_metric";
const LOG_QUERY_SENTINEL: &str = "service:api status:error secret:value";
const OP_EVENTS_LIST: &str = "datadog.events.list";
const OP_LOGS_SEARCH: &str = "datadog.logs.search";
const OP_METRICS_SUBMIT: &str = "datadog.metrics.submit";
const OP_MONITORS_LIST: &str = "datadog.monitors.list";

const EVENTS_RESPONSE_BODY: &str = r#"{
  "events": [
    {
      "id": 42,
      "title": "Deploy v2.0",
      "tags": ["env:prod", "service:api"]
    }
  ]
}"#;

const METRICS_RESPONSE_BODY: &str = r#"{"status":"ok"}"#;

const LOGS_RESPONSE_BODY: &str = r#"{
  "logs": [
    {
      "id": "log-1",
      "content": {
        "message": "provider log body should stay out of evidence",
        "service": "api"
      }
    }
  ]
}"#;

const UNAUTHORIZED_BODY: &str = r#"{"errors":["Unauthorized provider body"]}"#;
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
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Datadog listener");
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

    fn api_base_url(&self) -> String {
        format!("{}/api/v1", self.base_url)
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
        202 => "Accepted",
        401 => "Unauthorized",
        _ => "Status",
    }
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_events_metrics_and_logs_use_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, EVENTS_RESPONSE_BODY),
        ResponseSpec::json(202, METRICS_RESPONSE_BODY),
        ResponseSpec::json(200, LOGS_RESPONSE_BODY),
    ]);
    let connector = configured_connector(&fixture.api_base_url()).await;

    let events = invoke(
        &connector,
        OP_EVENTS_LIST,
        json!({
            "start": 1_709_251_200_i64,
            "end": 1_709_337_600_i64,
            "priority": "normal",
            "sources": "deploy",
            "tags": "env:prod"
        }),
    )
    .await
    .expect("events.list should succeed");
    let metrics = invoke(
        &connector,
        OP_METRICS_SUBMIT,
        json!({
            "series": [{
                "metric": METRIC_SENTINEL,
                "points": [[1_709_251_200.0, 42.0]],
                "type": "gauge"
            }]
        }),
    )
    .await
    .expect("metrics.submit should succeed");
    let logs = invoke(
        &connector,
        OP_LOGS_SEARCH,
        json!({
            "query": LOG_QUERY_SENTINEL,
            "from_ts": "now-1h",
            "to_ts": "now",
            "limit": 1
        }),
    )
    .await
    .expect("logs.search should succeed");
    let observations = fixture.join();

    assert_eq!(observations.len(), 3);
    assert_eq!(observations[0].method(), "GET");
    assert!(observations[0].target().starts_with("/api/v1/events?"));
    assert!(observations[0].target().contains("start=1709251200"));
    assert!(observations[0].target().contains("end=1709337600"));
    assert!(observations[0].target().contains("priority=normal"));
    assert!(observations[0].target().contains("sources=deploy"));
    assert!(observations[0].target().contains("tags=env%3Aprod"));
    assert_eq!(observations[1].request_line, "POST /api/v1/series HTTP/1.1");
    assert_eq!(
        observations[2].request_line,
        "POST /api/v1/logs-queries/list HTTP/1.1"
    );
    assert_auth_headers(&observations);

    let metrics_body: Value =
        serde_json::from_str(&observations[1].body).expect("metrics body is JSON");
    assert_eq!(metrics_body["series"][0]["metric"], METRIC_SENTINEL);
    assert_eq!(metrics_body["series"][0]["type"], "gauge");

    let logs_body: Value = serde_json::from_str(&observations[2].body).expect("logs body is JSON");
    assert_eq!(logs_body["query"]["query_string"], LOG_QUERY_SENTINEL);
    assert_eq!(logs_body["time"]["from"], "now-1h");
    assert_eq!(logs_body["time"]["to"], "now");
    assert_eq!(logs_body["limit"], 1);

    assert_eq!(events["events"].as_array().map_or(0, Vec::len), 1);
    assert_eq!(metrics["status"], "ok");
    assert_eq!(logs["logs"].as_array().map_or(0, Vec::len), 1);

    let evidence = vec![
        evidence_log(OP_EVENTS_LIST, Some(&observations[0]), "passed"),
        evidence_log(OP_METRICS_SUBMIT, Some(&observations[1]), "passed"),
        evidence_log(OP_LOGS_SEARCH, Some(&observations[2]), "passed"),
    ];
    assert_redacted(&evidence);
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_unauthorized_error_maps_without_secret_logging() {
    let fixture = LoopbackFixture::start(vec![ResponseSpec::json(401, UNAUTHORIZED_BODY)]);
    let connector = configured_connector(&fixture.api_base_url()).await;

    let err = invoke(
        &connector,
        OP_MONITORS_LIST,
        json!({"tags": "team:platform"}),
    )
    .await
    .expect_err("401 monitor list should map to FCP unauthorized");
    let observations = fixture.join();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].method(), "GET");
    assert!(observations[0].target().starts_with("/api/v1/monitor?"));
    assert!(observations[0].target().contains("tags=team%3Aplatform"));
    assert_auth_headers(&observations);

    match err {
        FcpError::Unauthorized { code: 2001, .. } => {}
        other => panic!("expected unauthorized error, got {other:?}"),
    }

    let evidence = vec![evidence_log(
        OP_MONITORS_LIST,
        Some(&observations[0]),
        "unauthorized",
    )];
    assert_redacted(&evidence);
}

#[fcp_async_core::runtime::test]
async fn evidence_schema_carries_connector_and_tracker_identity() {
    let log = evidence_log(OP_EVENTS_LIST, None, "passed");
    let value = serde_json::to_value(log).expect("evidence JSON");
    assert_eq!(value["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(value["bead_id"], BEAD_ID);
    assert_eq!(value["connector_id"], CONNECTOR_ID);
    assert_eq!(
        ConnectorId::from_static(CONNECTOR_ID).as_str(),
        CONNECTOR_ID
    );
    assert_eq!(
        OperationId::from_static(OP_EVENTS_LIST).as_str(),
        OP_EVENTS_LIST
    );
    assert_eq!(RequestId::new("datadog-local").to_string(), "datadog-local");
    assert_eq!(ZoneId::work().as_str(), "z:work");

    let introspection = DatadogConnector::new()
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    assert_eq!(
        introspection["operations"].as_array().map_or(0, Vec::len),
        8
    );
}

async fn configured_connector(base_url: &str) -> DatadogConnector {
    let mut connector = DatadogConnector::new();
    connector
        .handle_configure(json!({
            "api_key": API_KEY,
            "app_key": APP_KEY,
            "base_url": base_url
        }))
        .await
        .expect("configure Datadog connector");
    connector
        .handle_handshake(json!({"session_id": "datadog-local-session"}))
        .await
        .expect("handshake Datadog connector");
    connector
}

async fn invoke(
    connector: &DatadogConnector,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    connector
        .handle_invoke(json!({
            "operation_id": operation,
            "input": input
        }))
        .await
}

fn assert_auth_headers(observations: &[RequestObservation]) {
    for observation in observations {
        assert_eq!(observation.header_value("dd-api-key"), Some(API_KEY));
        assert_eq!(
            observation.header_value("dd-application-key"),
            Some(APP_KEY)
        );
    }
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_EVENTS_LIST => "datadog.events.read",
        OP_LOGS_SEARCH => "datadog.logs.read",
        OP_METRICS_SUBMIT => "datadog.metrics.write",
        OP_MONITORS_LIST => "datadog.monitors.read",
        _ => panic!("unsupported operation {operation}"),
    }
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
        redaction: "datadog_api_key_app_key_query_metric_and_provider_body_not_logged",
    }
}

fn route_label(request: &RequestObservation) -> &'static str {
    match (request.method(), request.target()) {
        ("GET", target) if target.starts_with("/api/v1/events?") => "events.list",
        ("POST", "/api/v1/series") => "metrics.submit",
        ("POST", "/api/v1/logs-queries/list") => "logs.search",
        ("GET", target) if target.starts_with("/api/v1/monitor?") => "monitors.list",
        _ => "unrecognized",
    }
}

fn assert_redacted(logs: &[EvidenceLog]) {
    let serialized = serde_json::to_string(logs).expect("serialize evidence logs");
    for forbidden in [
        API_KEY,
        APP_KEY,
        METRIC_SENTINEL,
        LOG_QUERY_SENTINEL,
        "provider log body",
        "Unauthorized provider body",
        "Deploy v2.0",
        "env:prod",
        "team:platform",
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
