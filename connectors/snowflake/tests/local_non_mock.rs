//! Local non-mock acceptance coverage for the FCP `Snowflake` connector.

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

use fcp_snowflake::connector::SnowflakeConnector;
use fcp_testkit::database_helpers::{
    CleanupVerificationResult, FixtureCleanupCheck, FixtureMutationRecord, FixtureSeedRecord,
    FixtureStartupProbe, FixtureStartupProbeKind, SeededStatefulFixturePack, StatefulFixtureFamily,
    assert_stateful_fixture_pack_complete,
};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "snowflake";
const DATABASE: &str = "ANALYTICS";
const FIXTURE_ID: &str = "snowflake-loopback-sql-api-acceptance";
const SCHEMA: &str = "PUBLIC";
const TEST_ACCESS_TOKEN: &str = "snowflake-local-non-mock-token";
const WAREHOUSE: &str = "COMPUTE_WH";

#[derive(Debug)]
struct FixtureObservation {
    request_lines: Vec<String>,
    methods: Vec<String>,
    paths: Vec<String>,
    bodies: Vec<Value>,
    authorization_count: usize,
    accept_json_count: usize,
    json_content_type_count: usize,
    query_runs: usize,
    execute_runs: usize,
    table_list_runs: usize,
}

struct LoopbackSnowflakeApi {
    api_base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

#[derive(Default)]
struct SnowflakeFixtureState {
    queries: usize,
    executions: usize,
    table_lists: usize,
}

impl LoopbackSnowflakeApi {
    fn start(expected_requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Snowflake loopback listener");
        listener
            .set_nonblocking(true)
            .expect("set Snowflake loopback listener nonblocking");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || run_server(&listener, expected_requests));

        Self {
            api_base_url: format!("http://{address}/api/v2"),
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
    let mut state = SnowflakeFixtureState::default();
    let mut observation = FixtureObservation {
        request_lines: Vec::with_capacity(expected_requests),
        methods: Vec::with_capacity(expected_requests),
        paths: Vec::with_capacity(expected_requests),
        bodies: Vec::with_capacity(expected_requests),
        authorization_count: 0,
        accept_json_count: 0,
        json_content_type_count: 0,
        query_runs: 0,
        execute_runs: 0,
        table_list_runs: 0,
    };

    while observation.request_lines.len() < expected_requests {
        match listener.accept() {
            Ok((stream, _)) => handle_request(stream, &mut state, &mut observation),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for Snowflake connector request {} of {expected_requests}",
                    observation.request_lines.len() + 1
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept Snowflake connector request: {error}"),
        }
    }

    observation.query_runs = state.queries;
    observation.execute_runs = state.executions;
    observation.table_list_runs = state.table_lists;
    observation
}

fn handle_request(
    mut stream: TcpStream,
    state: &mut SnowflakeFixtureState,
    observation: &mut FixtureObservation,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set Snowflake read timeout");

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
        &format!("Bearer {TEST_ACCESS_TOKEN}"),
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
        serde_json::from_str(body).expect("parse Snowflake API request body")
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
    .expect("write Snowflake fixture response");
}

fn execute_api_request(
    state: &mut SnowflakeFixtureState,
    method: &str,
    path: &str,
    body: &Value,
) -> Value {
    match (method, path) {
        ("GET", "/api/v2/databases") => json!([
            {"name": DATABASE, "created_on": "2026-05-12T00:00:00Z", "owner": "SYSADMIN"},
            {"name": "DEV", "created_on": "2026-05-12T00:00:00Z", "owner": "SYSADMIN"}
        ]),
        ("GET", "/api/v2/warehouses") => json!([
            {"name": WAREHOUSE, "state": "STARTED", "size": "X-SMALL"}
        ]),
        ("POST", "/api/v2/statements") => statement_response(state, body),
        _ => panic!("unexpected Snowflake fixture request: {method} {path}"),
    }
}

fn statement_response(state: &mut SnowflakeFixtureState, body: &Value) -> Value {
    let statement = body["statement"]
        .as_str()
        .expect("Snowflake statement body includes statement");
    assert_eq!(body["timeout"], 60);

    if statement.starts_with("SELECT event_id, actor FROM ACCEPTANCE_EVENTS") {
        assert_eq!(body["warehouse"], WAREHOUSE);
        assert_eq!(body["database"], DATABASE);
        assert_eq!(body["schema"], SCHEMA);
        state.queries += 1;
        return json!({
            "statementHandle": "query-handle",
            "message": "Statement executed successfully.",
            "code": "000000",
            "resultSetMetaData": {
                "numRows": 2,
                "rowType": [
                    {"name": "EVENT_ID", "type": "text"},
                    {"name": "ACTOR", "type": "text"}
                ]
            },
            "data": [
                ["evt-1", "Ada"],
                ["evt-2", "Grace"]
            ]
        });
    }

    if statement.starts_with("CREATE TEMP TABLE ACCEPTANCE_STAGE") {
        assert_eq!(body["warehouse"], WAREHOUSE);
        assert_eq!(body["database"], DATABASE);
        state.executions += 1;
        return json!({
            "statementHandle": "execute-handle",
            "message": "Statement executed successfully.",
            "code": "000000"
        });
    }

    if statement == "SHOW TABLES IN SCHEMA ANALYTICS.PUBLIC" {
        assert_eq!(body["warehouse"], WAREHOUSE);
        assert_eq!(body["database"], DATABASE);
        assert_eq!(body["schema"], SCHEMA);
        state.table_lists += 1;
        return json!({
            "statementHandle": "tables-handle",
            "code": "000000",
            "resultSetMetaData": {
                "numRows": 2,
                "rowType": [
                    {"name": "name", "type": "text"},
                    {"name": "database_name", "type": "text"},
                    {"name": "schema_name", "type": "text"},
                    {"name": "kind", "type": "text"}
                ]
            },
            "data": [
                ["ACCEPTANCE_EVENTS", DATABASE, SCHEMA, "TABLE"],
                ["ACCEPTANCE_STAGE", DATABASE, SCHEMA, "TEMPORARY TABLE"]
            ]
        });
    }

    panic!("unexpected Snowflake statement: {statement}");
}

fn fixture_contract() -> SeededStatefulFixturePack {
    SeededStatefulFixturePack::new(
        FIXTURE_ID,
        StatefulFixtureFamily::Relational,
        "snowflake-loopback-sql-api",
    )
    .with_startup_probe(FixtureStartupProbe::new(
        "snowflake-sql-api-ready",
        FixtureStartupProbeKind::TcpConnect,
        "127.0.0.1:redacted-snowflake-sql-api-port",
        10_000,
        "local Snowflake SQL API fixture accepts connector requests before operations run",
    ))
    .with_seed(FixtureSeedRecord::new(
        "acceptance_events",
        "seed-events",
        json!({
            "database": DATABASE,
            "schema": SCHEMA,
            "rows": [
                {"event_id": "evt-1", "actor": "Ada"},
                {"event_id": "evt-2", "actor": "Grace"}
            ]
        }),
    ))
    .with_mutation(
        FixtureMutationRecord::new(
            "query_run",
            "statements",
            "query-handle",
            "connector sql.query creates exactly one disposable SELECT statement execution",
        )
        .with_before(json!({"query_runs": 0}))
        .with_after(json!({"query_runs": 1})),
    )
    .with_mutation(
        FixtureMutationRecord::new(
            "execute_run",
            "statements",
            "execute-handle",
            "connector sql.execute creates exactly one disposable DDL statement execution",
        )
        .with_before(json!({"execute_runs": 0}))
        .with_after(json!({"execute_runs": 1})),
    )
    .with_cleanup_check(FixtureCleanupCheck::new(
        "cleanup-statements",
        "statements",
        "fixture_lifetime",
        "disposable statement handles are scoped to the loopback fixture lifetime",
    ))
}

async fn configured_connector(base_url: &str) -> SnowflakeConnector {
    let mut connector = SnowflakeConnector::new();
    connector
        .handle_configure(json!({
            "access_token": TEST_ACCESS_TOKEN,
            "account_identifier": "local_account",
            "base_url": base_url,
            "warehouse": WAREHOUSE,
            "database": DATABASE,
            "schema": SCHEMA,
        }))
        .await
        .expect("configure Snowflake connector");
    connector
        .handle_handshake(json!({ "session_id": "snowflake-local-non-mock" }))
        .await
        .expect("handshake Snowflake connector");
    connector
}

async fn invoke(connector: &SnowflakeConnector, operation_id: &str, input: Value) -> Value {
    connector
        .handle_invoke(json!({
            "operation_id": operation_id,
            "input": input,
        }))
        .await
        .expect("Snowflake loopback fixture should satisfy operation")
}

#[fcp_async_core::runtime::test]
async fn snowflake_connector_acceptance_exercises_loopback_sql_api_boundary() {
    let fixture = LoopbackSnowflakeApi::start(5);
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
        "access_token"
    );

    let databases = invoke(&connector, "snowflake.databases.list", json!({})).await;
    assert_eq!(databases["databases"].as_array().unwrap().len(), 2);
    assert_eq!(databases["databases"][0]["name"], DATABASE);

    let warehouses = invoke(&connector, "snowflake.warehouses.list", json!({})).await;
    assert_eq!(warehouses["warehouses"][0]["name"], WAREHOUSE);

    let query = invoke(
        &connector,
        "snowflake.sql.query",
        json!({
            "statement": "SELECT event_id, actor FROM ACCEPTANCE_EVENTS ORDER BY event_id",
            "warehouse": WAREHOUSE,
            "database": DATABASE,
            "schema": SCHEMA
        }),
    )
    .await;
    assert_eq!(query["data"].as_array().unwrap().len(), 2);
    assert_eq!(query["data"][0][1], "Ada");
    assert_eq!(query["statement_handle"], "query-handle");

    let execute = invoke(
        &connector,
        "snowflake.sql.execute",
        json!({
            "statement": "CREATE TEMP TABLE ACCEPTANCE_STAGE (id NUMBER)",
            "warehouse": WAREHOUSE,
            "database": DATABASE
        }),
    )
    .await;
    assert_eq!(execute["status"], "Statement executed successfully.");
    assert_eq!(execute["statement_handle"], "execute-handle");

    let tables = invoke(
        &connector,
        "snowflake.tables.list",
        json!({"database": DATABASE, "schema": SCHEMA}),
    )
    .await;
    assert_eq!(tables["tables"].as_array().unwrap().len(), 2);
    assert_eq!(tables["tables"][0][0], "ACCEPTANCE_EVENTS");

    let observation = fixture.join();
    assert_eq!(observation.request_lines.len(), 5);
    assert_eq!(observation.authorization_count, 5);
    assert_eq!(observation.accept_json_count, 5);
    assert_eq!(observation.json_content_type_count, 3);
    assert_eq!(observation.query_runs, 1);
    assert_eq!(observation.execute_runs, 1);
    assert_eq!(observation.table_list_runs, 1);
    assert_eq!(observation.methods, ["GET", "GET", "POST", "POST", "POST"]);
    assert_eq!(
        observation.paths,
        [
            "/api/v2/databases",
            "/api/v2/warehouses",
            "/api/v2/statements",
            "/api/v2/statements",
            "/api/v2/statements"
        ]
    );
    assert_eq!(
        observation.bodies[4]["statement"],
        "SHOW TABLES IN SCHEMA ANALYTICS.PUBLIC"
    );

    let cleanup = CleanupVerificationResult::new(
        "cleanup-statements",
        "statements",
        "fixture_lifetime",
        "disposable statement handles are scoped to the loopback fixture lifetime",
        json!({
            "query_runs": observation.query_runs,
            "execute_runs": observation.execute_runs,
            "table_list_runs": observation.table_list_runs,
            "fixture_joined": true
        }),
        true,
    );
    let evidence = json!({
        "schema_version": "fcp-snowflake-local-acceptance/v1",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "fixture_mode": "loopback_http",
        "transport": "snowflake_sql_api",
        "operations": [
            "snowflake.databases.list",
            "snowflake.warehouses.list",
            "snowflake.sql.query",
            "snowflake.sql.execute",
            "snowflake.tables.list"
        ],
        "request_lines": observation.request_lines,
        "authorization_seen_for_all_requests": observation.authorization_count == 5,
        "accept_json_seen_for_all_requests": observation.accept_json_count == 5,
        "json_content_type_seen_for_statement_requests": observation.json_content_type_count == 3,
        "fixture_contract": fixture_contract.to_json(),
        "cleanup": cleanup,
    });

    assert_eq!(evidence["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert!(evidence["cleanup"]["passed"].as_bool().unwrap());
    assert!(
        !serde_json::to_string(&evidence)
            .expect("serialize evidence")
            .contains(TEST_ACCESS_TOKEN),
        "acceptance evidence must not expose Snowflake access token"
    );
}
