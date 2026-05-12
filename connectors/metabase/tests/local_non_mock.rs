//! Local non-mock acceptance coverage for the FCP `Metabase` connector.

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
    time::{Duration, Instant},
};

use fcp_metabase::connector::MetabaseConnector;
use fcp_testkit::database_helpers::{
    CleanupVerificationResult, FixtureCleanupCheck, FixtureMutationRecord, FixtureSeedRecord,
    FixtureStartupProbe, FixtureStartupProbeKind, SeededStatefulFixturePack, StatefulFixtureFamily,
    assert_stateful_fixture_pack_complete,
};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "metabase";
const DASHBOARD_ID: i64 = 7;
const FIXTURE_ID: &str = "metabase-loopback-http-acceptance";
const QUESTION_ID: &str = "42";
const TEST_SESSION_TOKEN: &str = "metabase-local-non-mock-session-token";

#[derive(Debug)]
struct FixtureObservation {
    request_lines: Vec<String>,
    methods: Vec<String>,
    paths: Vec<String>,
    bodies: Vec<Value>,
    session_header_count: usize,
    accept_json_count: usize,
    query_runs: usize,
}

struct LoopbackMetabaseApi {
    api_base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

struct MetabaseFixtureState {
    dashboards: Vec<Value>,
    cards: Vec<Value>,
    query_runs: usize,
}

impl Default for MetabaseFixtureState {
    fn default() -> Self {
        Self {
            dashboards: vec![json!({
                "id": DASHBOARD_ID,
                "name": "Revenue Acceptance Dashboard",
                "description": "Seeded dashboard metadata",
                "collection_id": 3,
                "archived": false,
            })],
            cards: vec![json!({
                "id": QUESTION_ID.parse::<i64>().expect("question id is numeric"),
                "name": "Acceptance Revenue Question",
                "description": "Seeded saved question",
                "display": "table",
                "database_id": 1,
                "archived": false,
            })],
            query_runs: 0,
        }
    }
}

impl LoopbackMetabaseApi {
    fn start(expected_requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Metabase loopback listener");
        listener
            .set_nonblocking(true)
            .expect("set Metabase loopback listener nonblocking");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || run_server(&listener, expected_requests));

        Self {
            api_base_url: format!("http://{address}/api"),
            handle: Some(handle),
        }
    }

    fn api_base_url(&self) -> &str {
        &self.api_base_url
    }

    fn join(mut self) -> FixtureObservation {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn run_server(listener: &TcpListener, expected_requests: usize) -> FixtureObservation {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut state = MetabaseFixtureState::default();
    let mut observation = FixtureObservation {
        request_lines: Vec::with_capacity(expected_requests),
        methods: Vec::with_capacity(expected_requests),
        paths: Vec::with_capacity(expected_requests),
        bodies: Vec::with_capacity(expected_requests),
        session_header_count: 0,
        accept_json_count: 0,
        query_runs: 0,
    };

    while observation.request_lines.len() < expected_requests {
        match listener.accept() {
            Ok((stream, _)) => handle_request(stream, &mut state, &mut observation),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for Metabase connector request {} of {expected_requests}",
                    observation.request_lines.len() + 1
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept Metabase connector request: {error}"),
        }
    }

    observation.query_runs = state.query_runs;
    observation
}

fn handle_request(
    mut stream: TcpStream,
    state: &mut MetabaseFixtureState,
    observation: &mut FixtureObservation,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set Metabase read timeout");

    let request = read_http_request(&mut stream);
    let request_line = request.lines().next().unwrap_or_default().to_string();
    let (method, path) = parse_request_line(&request_line);
    let method = method.to_string();
    let path = path.to_string();
    let headers = request
        .split_once("\r\n\r\n")
        .map_or(request.as_str(), |(headers, _)| headers);

    if header_value_matches(headers, "x-metabase-session", TEST_SESSION_TOKEN) {
        observation.session_header_count += 1;
    }
    if headers.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("accept:") && lower.contains("application/json")
    }) {
        observation.accept_json_count += 1;
    }

    let body = request
        .split_once("\r\n\r\n")
        .map_or("", |(_, body)| body.trim_end_matches('\0'));
    let body_json = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body).expect("parse Metabase API request body")
    };
    let response = execute_api_request(state, &method, &path, &body_json);

    observation.request_lines.push(request_line);
    observation.methods.push(method);
    observation.paths.push(path);
    observation.bodies.push(body_json);
    write_json_response(&mut stream, &response);
}

fn header_value_matches(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case(expected_name) && value.trim() == expected_value
        })
    })
}

fn parse_request_line(request_line: &str) -> (&str, &str) {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    (method, path)
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut buffer = Vec::new();
    let mut scratch = [0_u8; 1024];

    loop {
        let bytes_read = stream.read(&mut scratch).expect("read connector request");
        if bytes_read == 0 {
            break;
        }
        buffer.extend_from_slice(&scratch[..bytes_read]);

        if let Some(headers_end) = find_subslice(&buffer, b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&buffer[..headers_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                })
                .unwrap_or(0);
            if buffer.len() >= headers_end + 4 + content_length {
                break;
            }
        }
    }

    String::from_utf8_lossy(&buffer).into_owned()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn write_json_response(stream: &mut TcpStream, body: &Value) {
    let body = body.to_string();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .expect("write Metabase fixture response");
}

fn execute_api_request(
    state: &mut MetabaseFixtureState,
    method: &str,
    path: &str,
    body: &Value,
) -> Value {
    match (method, path) {
        ("GET", "/api/dashboard") => json!(state.dashboards),
        ("GET", "/api/card") => json!(state.cards),
        ("POST", "/api/card/42/query") => {
            assert_eq!(
                *body,
                Value::Null,
                "Metabase questions.run sends an empty body"
            );
            state.query_runs += 1;
            json!({
                "data": {
                    "rows": [
                        [1, "Ada", 1250],
                        [2, "Grace", 1750]
                    ],
                    "cols": [
                        {"name": "id", "display_name": "ID", "base_type": "type/Integer"},
                        {"name": "name", "display_name": "Name", "base_type": "type/Text"},
                        {"name": "revenue", "display_name": "Revenue", "base_type": "type/Integer"}
                    ]
                },
                "database_id": 1,
                "row_count": 2,
                "running_time": 17,
                "status": "completed"
            })
        }
        _ => panic!("unexpected Metabase fixture request: {method} {path}"),
    }
}

fn fixture_contract() -> SeededStatefulFixturePack {
    SeededStatefulFixturePack::new(
        FIXTURE_ID,
        StatefulFixtureFamily::Relational,
        "metabase-loopback-http-api",
    )
    .with_startup_probe(FixtureStartupProbe::new(
        "metabase-rest-ready",
        FixtureStartupProbeKind::TcpConnect,
        "127.0.0.1:redacted-metabase-rest-port",
        10_000,
        "local Metabase HTTP fixture accepts connector requests before operations run",
    ))
    .with_seed(FixtureSeedRecord::new(
        "dashboards",
        "seed-dashboard",
        json!({
            "dashboard_id": DASHBOARD_ID,
            "name": "Revenue Acceptance Dashboard"
        }),
    ))
    .with_seed(FixtureSeedRecord::new(
        "cards",
        "seed-question",
        json!({
            "card_id": QUESTION_ID,
            "name": "Acceptance Revenue Question",
            "rows": 2
        }),
    ))
    .with_mutation(
        FixtureMutationRecord::new(
            "query_run",
            "saved_question_executions",
            "local-query-run",
            "connector questions.run creates exactly one disposable query execution in the loopback fixture",
        )
        .with_before(json!({"query_runs": 0}))
        .with_after(json!({"query_runs": 1})),
    )
    .with_cleanup_check(FixtureCleanupCheck::new(
        "cleanup-query-run",
        "saved_question_executions",
        "fixture_lifetime",
        "disposable query execution state is scoped to the loopback fixture lifetime",
    ))
}

async fn configured_connector(base_url: &str) -> MetabaseConnector {
    let mut connector = MetabaseConnector::new();
    connector
        .handle_configure(json!({
            "session_token": TEST_SESSION_TOKEN,
            "base_url": base_url,
        }))
        .await
        .expect("configure Metabase connector");
    connector
        .handle_handshake(json!({ "session_id": "metabase-local-non-mock" }))
        .await
        .expect("handshake Metabase connector");
    connector
}

async fn invoke(connector: &MetabaseConnector, operation_id: &str, input: Value) -> Value {
    connector
        .handle_invoke(json!({
            "operation_id": operation_id,
            "input": input,
        }))
        .await
        .expect("Metabase loopback fixture should satisfy operation")
}

#[fcp_async_core::runtime::test]
async fn metabase_connector_acceptance_exercises_loopback_http_boundary() {
    let fixture = LoopbackMetabaseApi::start(3);
    let connector = configured_connector(fixture.api_base_url()).await;
    let fixture_contract = fixture_contract();
    assert_stateful_fixture_pack_complete(&fixture_contract);

    let health = connector.handle_health().await.expect("health check");
    assert_eq!(health["status"], "healthy");
    let doctor = connector.handle_doctor().await.expect("doctor check");
    assert_eq!(doctor["status"], "healthy");
    let self_check = connector.handle_self_check().await.expect("self check");
    assert_eq!(self_check["status"], "ok");
    assert_eq!(
        self_check["details"]["provisioning"]["auth_mode"],
        "session_token"
    );

    let dashboards = invoke(&connector, "metabase.dashboards.list", json!({})).await;
    assert_eq!(dashboards["dashboards"].as_array().unwrap().len(), 1);
    assert_eq!(dashboards["dashboards"][0]["id"], DASHBOARD_ID);

    let questions = invoke(&connector, "metabase.questions.list", json!({})).await;
    assert_eq!(questions["questions"].as_array().unwrap().len(), 1);
    assert_eq!(questions["questions"][0]["id"], 42);

    let query = invoke(
        &connector,
        "metabase.questions.run",
        json!({"card_id": QUESTION_ID}),
    )
    .await;
    assert_eq!(query["status"], "completed");
    assert_eq!(query["data"]["rows"].as_array().unwrap().len(), 2);
    assert_eq!(query["data"]["rows"][0][1], "Ada");

    let observation = fixture.join();
    assert_eq!(observation.request_lines.len(), 3);
    assert_eq!(observation.session_header_count, 3);
    assert_eq!(observation.accept_json_count, 3);
    assert_eq!(observation.query_runs, 1);
    assert_eq!(observation.methods, ["GET", "GET", "POST"]);
    assert_eq!(
        observation.paths,
        ["/api/dashboard", "/api/card", "/api/card/42/query"]
    );
    assert_eq!(observation.bodies[2], Value::Null);

    let cleanup = CleanupVerificationResult::new(
        "cleanup-query-run",
        "saved_question_executions",
        "fixture_lifetime",
        "disposable query execution state is scoped to the loopback fixture lifetime",
        json!({"query_runs": observation.query_runs, "fixture_joined": true}),
        true,
    );
    let evidence = json!({
        "schema_version": "fcp-metabase-local-acceptance/v1",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "fixture_mode": "loopback_http",
        "transport": "metabase_http_api",
        "operations": [
            "metabase.dashboards.list",
            "metabase.questions.list",
            "metabase.questions.run"
        ],
        "request_lines": observation.request_lines,
        "session_header_seen_for_all_requests": observation.session_header_count == 3,
        "accept_json_seen_for_all_requests": observation.accept_json_count == 3,
        "query_runs": observation.query_runs,
        "fixture_contract": fixture_contract.to_json(),
        "cleanup": cleanup,
    });

    assert_eq!(evidence["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert!(evidence["cleanup"]["passed"].as_bool().unwrap());
    assert!(
        !serde_json::to_string(&evidence)
            .expect("serialize evidence")
            .contains(TEST_SESSION_TOKEN),
        "acceptance evidence must not expose Metabase session token"
    );
}
