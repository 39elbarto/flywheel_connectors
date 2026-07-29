//! Local non-mock acceptance coverage for the FCP `DuckDB` `MotherDuck` connector.

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

use fcp_duckdb::connector::DuckDbConnector;
use fcp_testkit::database_helpers::{
    CleanupVerificationResult, FixtureCleanupCheck, FixtureMutationRecord, FixtureSeedRecord,
    FixtureStartupProbe, FixtureStartupProbeKind, SeededStatefulFixturePack, StatefulFixtureFamily,
    assert_stateful_fixture_pack_complete,
};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "duckdb";
const DATABASE: &str = "analytics";
const FIXTURE_ID: &str = "duckdb-motherduck-loopback-acceptance";
const QUERY_ID: &str = "q-acceptance";
const TABLE: &str = "sales";
const TEST_SERVICE_TOKEN: &str = "duckdb-local-non-mock-service-token";

#[derive(Debug)]
struct FixtureObservation {
    request_lines: Vec<String>,
    methods: Vec<String>,
    paths: Vec<String>,
    bodies: Vec<Value>,
    authorization_count: usize,
    accept_json_count: usize,
    json_content_type_count: usize,
    query_executions: usize,
    share_creations: usize,
}

struct LoopbackMotherDuckApi {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

#[derive(Default)]
struct MotherDuckFixtureState {
    queries: usize,
    shares: usize,
}

impl LoopbackMotherDuckApi {
    fn start(expected_requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind MotherDuck loopback listener");
        listener
            .set_nonblocking(true)
            .expect("set MotherDuck loopback listener nonblocking");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || run_server(&listener, expected_requests));

        Self {
            base_url: format!("http://{address}/api/v0"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
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
    let mut state = MotherDuckFixtureState::default();
    let mut observation = FixtureObservation {
        request_lines: Vec::with_capacity(expected_requests),
        methods: Vec::with_capacity(expected_requests),
        paths: Vec::with_capacity(expected_requests),
        bodies: Vec::with_capacity(expected_requests),
        authorization_count: 0,
        accept_json_count: 0,
        json_content_type_count: 0,
        query_executions: 0,
        share_creations: 0,
    };

    while observation.request_lines.len() < expected_requests {
        match listener.accept() {
            Ok((stream, _)) => handle_request(stream, &mut state, &mut observation),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for DuckDB connector request {} of {expected_requests}",
                    observation.request_lines.len() + 1
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept DuckDB connector request: {error}"),
        }
    }

    observation.query_executions = state.queries;
    observation.share_creations = state.shares;
    observation
}

fn handle_request(
    mut stream: TcpStream,
    state: &mut MotherDuckFixtureState,
    observation: &mut FixtureObservation,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set MotherDuck read timeout");

    let request = read_http_request(&mut stream);
    let request_line = request.lines().next().unwrap_or_default().to_string();
    let (method, path) = parse_request_line(&request_line);
    let method = method.to_string();
    let path = path.to_string();
    let headers = request
        .split_once("\r\n\r\n")
        .map_or(request.as_str(), |(headers, _)| headers);

    if header_value_matches(
        headers,
        "authorization",
        &format!("Bearer {TEST_SERVICE_TOKEN}"),
    ) {
        observation.authorization_count += 1;
    }
    if headers.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("accept:") && lower.contains("application/json")
    }) {
        observation.accept_json_count += 1;
    }
    if headers.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("content-type:") && lower.contains("application/json")
    }) {
        observation.json_content_type_count += 1;
    }

    let body = request
        .split_once("\r\n\r\n")
        .map_or("", |(_, body)| body.trim_end_matches('\0'));
    let body_json = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body).expect("parse MotherDuck API request body")
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
    .expect("write MotherDuck fixture response");
}

fn execute_api_request(
    state: &mut MotherDuckFixtureState,
    method: &str,
    path: &str,
    body: &Value,
) -> Value {
    match (method, path) {
        ("POST", "/api/v0/sql") => sql_response(state, body),
        ("GET", "/api/v0/databases") => json!({
            "databases": [
                {"name": DATABASE, "size_bytes": 1_048_576},
                {"name": "staging", "size_bytes": 524_288}
            ]
        }),
        ("GET", "/api/v0/databases/analytics") => json!({
            "name": DATABASE,
            "size_bytes": 1_048_576,
            "created_at": "2026-05-12T00:00:00Z"
        }),
        ("GET", "/api/v0/databases/analytics/tables") => json!({
            "tables": [
                {"name": TABLE, "column_count": 3, "row_count": 2},
                {"name": "customers", "column_count": 2, "row_count": 1}
            ]
        }),
        ("GET", "/api/v0/databases/analytics/tables/sales") => json!({
            "name": TABLE,
            "column_count": 3,
            "row_count": 2,
            "schema": "main"
        }),
        ("GET", "/api/v0/databases/analytics/schemas") => json!({
            "schemas": [{"name": "main"}, {"name": "staging"}]
        }),
        ("GET", "/api/v0/queries/q-acceptance") => json!({
            "query_id": QUERY_ID,
            "status": "completed",
            "result": {"row_count": 2}
        }),
        ("GET", "/api/v0/shares") => json!({
            "shares": [{"name": "team_share", "database": DATABASE}]
        }),
        ("POST", "/api/v0/shares") => create_share_response(state, body),
        _ => panic!("unexpected DuckDB MotherDuck fixture request: {method} {path}"),
    }
}

fn sql_response(state: &mut MotherDuckFixtureState, body: &Value) -> Value {
    assert_eq!(
        body["sql"],
        "SELECT event_id, actor FROM acceptance_events ORDER BY event_id"
    );
    assert_eq!(body["database"], DATABASE);
    state.queries += 1;
    json!({
        "columns": [
            {"name": "event_id", "type_name": "VARCHAR"},
            {"name": "actor", "type_name": "VARCHAR"}
        ],
        "data": [
            ["evt-1", "Ada"],
            ["evt-2", "Grace"]
        ],
        "row_count": 2,
        "query_id": QUERY_ID
    })
}

fn create_share_response(state: &mut MotherDuckFixtureState, body: &Value) -> Value {
    assert_eq!(body["name"], "team_analytics");
    assert_eq!(body["database"], DATABASE);
    state.shares += 1;
    json!({
        "name": "team_analytics",
        "database": DATABASE,
        "created_at": "2026-05-12T00:00:00Z"
    })
}

fn fixture_contract() -> SeededStatefulFixturePack {
    SeededStatefulFixturePack::new(
        FIXTURE_ID,
        StatefulFixtureFamily::Relational,
        "motherduck-loopback-http-api",
    )
    .with_startup_probe(FixtureStartupProbe::new(
        "motherduck-api-ready",
        FixtureStartupProbeKind::TcpConnect,
        "127.0.0.1:redacted-motherduck-api-port",
        10_000,
        "local MotherDuck HTTP fixture accepts connector requests before operations run",
    ))
    .with_seed(FixtureSeedRecord::new(
        "acceptance_events",
        "seed-events",
        json!({
            "database": DATABASE,
            "table": TABLE,
            "rows": [
                {"event_id": "evt-1", "actor": "Ada"},
                {"event_id": "evt-2", "actor": "Grace"}
            ]
        }),
    ))
    .with_mutation(
        FixtureMutationRecord::new(
            "query_execution",
            "queries",
            QUERY_ID,
            "connector query.execute creates exactly one disposable MotherDuck query result",
        )
        .with_before(json!({"query_executions": 0}))
        .with_after(json!({"query_executions": 1})),
    )
    .with_mutation(
        FixtureMutationRecord::new(
            "share_create",
            "shares",
            "team_analytics",
            "connector shares.create creates exactly one disposable share record in the loopback fixture",
        )
        .with_before(json!({"share_creations": 0}))
        .with_after(json!({"share_creations": 1})),
    )
    .with_cleanup_check(FixtureCleanupCheck::new(
        "cleanup-query-results",
        "queries",
        "fixture_lifetime",
        "query results are scoped to the loopback fixture lifetime",
    ))
    .with_cleanup_check(FixtureCleanupCheck::new(
        "cleanup-created-shares",
        "shares",
        "fixture_lifetime",
        "created shares are scoped to the loopback fixture lifetime",
    ))
}

async fn configured_connector(base_url: &str) -> DuckDbConnector {
    let mut connector = DuckDbConnector::new();
    connector
        .handle_configure(json!({
            "service_token": TEST_SERVICE_TOKEN,
            "base_url": base_url,
            "database": DATABASE,
        }))
        .await
        .expect("configure DuckDB MotherDuck connector");
    connector
        .handle_handshake(json!({ "session_id": "duckdb-local-non-mock" }))
        .await
        .expect("handshake DuckDB MotherDuck connector");
    connector
}

async fn invoke(connector: &DuckDbConnector, operation_id: &str, input: Value) -> Value {
    connector
        .handle_invoke(json!({
            "operation_id": operation_id,
            "input": input,
        }))
        .await
        .expect("MotherDuck loopback fixture should satisfy operation")
}

#[fcp_async_core::runtime::test]
async fn duckdb_connector_acceptance_exercises_loopback_motherduck_http_boundary() {
    let fixture = LoopbackMotherDuckApi::start(9);
    let connector = configured_connector(fixture.base_url()).await;
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
        "service_token"
    );

    let query = invoke(
        &connector,
        "duckdb.query.execute",
        json!({"sql": "SELECT event_id, actor FROM acceptance_events ORDER BY event_id"}),
    )
    .await;
    assert_eq!(query["query_id"], QUERY_ID);
    assert_eq!(query["data"].as_array().unwrap().len(), 2);

    let databases = invoke(&connector, "duckdb.databases.list", json!({})).await;
    assert_eq!(databases["databases"].as_array().unwrap().len(), 2);
    assert_eq!(databases["databases"][0]["name"], DATABASE);

    let database = invoke(
        &connector,
        "duckdb.databases.get",
        json!({"database": DATABASE}),
    )
    .await;
    assert_eq!(database["database"]["name"], DATABASE);

    let tables = invoke(
        &connector,
        "duckdb.tables.list",
        json!({"database": DATABASE}),
    )
    .await;
    assert_eq!(tables["tables"].as_array().unwrap().len(), 2);

    let table = invoke(
        &connector,
        "duckdb.tables.get",
        json!({"database": DATABASE, "table": TABLE}),
    )
    .await;
    assert_eq!(table["table"]["name"], TABLE);

    let schemas = invoke(
        &connector,
        "duckdb.schemas.list",
        json!({"database": DATABASE}),
    )
    .await;
    assert_eq!(schemas["schemas"].as_array().unwrap().len(), 2);

    let status = invoke(
        &connector,
        "duckdb.queries.status",
        json!({"query_id": QUERY_ID}),
    )
    .await;
    assert_eq!(status["status"]["status"], "completed");

    let shares = invoke(&connector, "duckdb.shares.list", json!({})).await;
    assert_eq!(shares["shares"].as_array().unwrap().len(), 1);

    let share = invoke(
        &connector,
        "duckdb.shares.create",
        json!({"name": "team_analytics", "database": DATABASE}),
    )
    .await;
    assert_eq!(share["share"]["name"], "team_analytics");

    let observation = fixture.join();
    assert_eq!(observation.request_lines.len(), 9);
    assert_eq!(observation.authorization_count, 9);
    assert_eq!(observation.accept_json_count, 9);
    assert_eq!(observation.json_content_type_count, 2);
    assert_eq!(observation.query_executions, 1);
    assert_eq!(observation.share_creations, 1);
    assert_eq!(
        observation.methods,
        [
            "POST", "GET", "GET", "GET", "GET", "GET", "GET", "GET", "POST"
        ]
    );
    assert_eq!(
        observation.paths,
        [
            "/api/v0/sql",
            "/api/v0/databases",
            "/api/v0/databases/analytics",
            "/api/v0/databases/analytics/tables",
            "/api/v0/databases/analytics/tables/sales",
            "/api/v0/databases/analytics/schemas",
            "/api/v0/queries/q-acceptance",
            "/api/v0/shares",
            "/api/v0/shares"
        ]
    );
    assert_eq!(observation.bodies[0]["database"], DATABASE);
    assert_eq!(observation.bodies[8]["name"], "team_analytics");

    let cleanup_query_results = CleanupVerificationResult::new(
        "cleanup-query-results",
        "queries",
        "fixture_lifetime",
        "query results are scoped to the loopback fixture lifetime",
        json!({
            "query_executions": observation.query_executions,
            "fixture_joined": true
        }),
        true,
    );
    let cleanup_created_shares = CleanupVerificationResult::new(
        "cleanup-created-shares",
        "shares",
        "fixture_lifetime",
        "created shares are scoped to the loopback fixture lifetime",
        json!({
            "share_creations": observation.share_creations,
            "fixture_joined": true
        }),
        true,
    );
    let cleanup_passed = cleanup_query_results.passed && cleanup_created_shares.passed;

    let evidence = json!({
        "schema_version": "fcp-duckdb-local-acceptance/v1",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "fixture_mode": "loopback_http",
        "transport": "motherduck_http_api",
        "operations": [
            "duckdb.query.execute",
            "duckdb.databases.list",
            "duckdb.databases.get",
            "duckdb.tables.list",
            "duckdb.tables.get",
            "duckdb.schemas.list",
            "duckdb.queries.status",
            "duckdb.shares.list",
            "duckdb.shares.create"
        ],
        "request_lines": observation.request_lines,
        "authorization_seen_for_all_requests": observation.authorization_count == 9,
        "accept_json_seen_for_all_requests": observation.accept_json_count == 9,
        "json_content_type_seen_for_mutations": observation.json_content_type_count == 2,
        "fixture_contract": fixture_contract.to_json(),
        "cleanup": {
            "passed": cleanup_passed,
            "checks": [cleanup_query_results, cleanup_created_shares],
        },
    });

    assert_eq!(evidence["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert!(evidence["cleanup"]["passed"].as_bool().unwrap());
    assert!(
        !serde_json::to_string(&evidence)
            .expect("serialize evidence")
            .contains(TEST_SERVICE_TOKEN),
        "acceptance evidence must not expose DuckDB service token"
    );
}
