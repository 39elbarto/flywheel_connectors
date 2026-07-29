//! Local non-mock acceptance coverage for the FCP `MySQL` connector.

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
    collections::BTreeMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use fcp_mysql::connector::MysqlConnector;
use fcp_testkit::database_helpers::{
    CleanupVerificationResult, FixtureCleanupCheck, FixtureMutationRecord, FixtureSeedRecord,
    FixtureStartupProbe, FixtureStartupProbeKind, SeededStatefulFixturePack, StatefulFixtureFamily,
    assert_stateful_fixture_pack_complete,
};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "mysql";
const FIXTURE_ID: &str = "mysql-loopback-rest-proxy-acceptance";
const TEST_API_KEY: &str = "mysql-local-non-mock-token";
const TABLE_NAME: &str = "acceptance_users";

#[derive(Debug)]
struct FixtureObservation {
    request_lines: Vec<String>,
    paths: Vec<String>,
    bodies: Vec<Value>,
    authorization_count: usize,
    json_content_type_count: usize,
}

struct LoopbackMysqlProxy {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

#[derive(Debug, Clone)]
struct UserRow {
    id: i64,
    name: &'static str,
}

struct MysqlFixtureState {
    users: BTreeMap<i64, UserRow>,
}

impl Default for MysqlFixtureState {
    fn default() -> Self {
        Self {
            users: BTreeMap::from([
                (1, UserRow { id: 1, name: "Ada" }),
                (
                    2,
                    UserRow {
                        id: 2,
                        name: "Grace",
                    },
                ),
            ]),
        }
    }
}

impl LoopbackMysqlProxy {
    fn start(expected_requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        listener
            .set_nonblocking(true)
            .expect("set loopback listener nonblocking");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || run_server(&listener, expected_requests));

        Self {
            base_url: format!("http://{address}"),
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
    let mut state = MysqlFixtureState::default();
    let mut observation = FixtureObservation {
        request_lines: Vec::with_capacity(expected_requests),
        paths: Vec::with_capacity(expected_requests),
        bodies: Vec::with_capacity(expected_requests),
        authorization_count: 0,
        json_content_type_count: 0,
    };

    while observation.request_lines.len() < expected_requests {
        match listener.accept() {
            Ok((stream, _)) => handle_request(stream, &mut state, &mut observation),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for MySQL connector request {} of {expected_requests}",
                    observation.request_lines.len() + 1
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept MySQL connector request: {error}"),
        }
    }

    observation
}

fn handle_request(
    mut stream: TcpStream,
    state: &mut MysqlFixtureState,
    observation: &mut FixtureObservation,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let request = read_http_request(&mut stream);
    let request_line = request.lines().next().unwrap_or_default().to_string();
    let (method, path) = parse_request_line(&request_line);
    let method = method.to_string();
    let path = path.to_string();
    let headers = request
        .split_once("\r\n\r\n")
        .map_or(request.as_str(), |(headers, _)| headers);

    if headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("authorization: bearer mysql-local-non-mock-token"))
    {
        observation.authorization_count += 1;
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
        serde_json::from_str(body).expect("parse MySQL proxy request body")
    };
    let response = execute_proxy_request(state, &method, &path, &body_json);

    observation.request_lines.push(request_line);
    observation.paths.push(path);
    observation.bodies.push(body_json);
    write_json_response(&mut stream, &response);
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
    .expect("write MySQL fixture response");
}

fn execute_proxy_request(
    state: &mut MysqlFixtureState,
    method: &str,
    path: &str,
    body: &Value,
) -> Value {
    match (method, path) {
        ("GET", "/health") => json!({
            "status": "ok",
            "server": "mysql-loopback-proxy",
            "database": "fcp_mysql_local_acceptance",
        }),
        ("POST", "/query") => query_response(state, body),
        ("POST", "/execute") => execute_response(state, body),
        ("POST", "/explain") => json!({
            "plan": [{
                "select_type": "SIMPLE",
                "table": TABLE_NAME,
                "access_type": "const",
                "rows": 1
            }]
        }),
        ("GET", "/schema/tables") => json!([{
            "name": TABLE_NAME,
            "database": "fcp_mysql_local_acceptance",
            "engine": "InnoDB",
            "row_count_estimate": state.users.len()
        }]),
        ("GET", "/schema/columns/acceptance_users") => json!([
            {"name": "id", "data_type": "BIGINT", "nullable": false},
            {"name": "name", "data_type": "VARCHAR", "nullable": false}
        ]),
        ("GET", "/schema/indexes/acceptance_users") => json!([
            {"name": "PRIMARY", "columns": ["id"], "unique": true}
        ]),
        _ => json!({ "error": format!("unexpected {method} {path}") }),
    }
}

fn query_response(state: &MysqlFixtureState, body: &Value) -> Value {
    let requested_id = body["params"]
        .as_array()
        .and_then(|params| params.first())
        .and_then(Value::as_i64)
        .expect("query id parameter");
    let rows = state
        .users
        .get(&requested_id)
        .map(|row| vec![json!({"id": row.id, "name": row.name})])
        .unwrap_or_default();

    json!({
        "rows": rows,
        "columns": [{"name": "id"}, {"name": "name"}],
        "row_count": rows.len()
    })
}

fn execute_response(state: &mut MysqlFixtureState, body: &Value) -> Value {
    let requested_id = body["params"]
        .as_array()
        .and_then(|params| params.first())
        .and_then(Value::as_i64)
        .expect("execute id parameter");
    let affected_rows = i64::from(state.users.remove(&requested_id).is_some());
    json!({ "affected_rows": affected_rows })
}

fn fixture_contract() -> SeededStatefulFixturePack {
    SeededStatefulFixturePack::new(
        FIXTURE_ID,
        StatefulFixtureFamily::Relational,
        "mysql-loopback-http-proxy",
    )
    .with_startup_probe(FixtureStartupProbe::new(
        "mysql-proxy-health-ready",
        FixtureStartupProbeKind::SqlPing,
        "127.0.0.1:redacted-mysql-proxy-port/health",
        10_000,
        "local MySQL REST proxy fixture answers health probes before SQL operations",
    ))
    .with_seed(FixtureSeedRecord::new(
        TABLE_NAME,
        "seed-users",
        json!({
            "rows": [
                {"id": 1, "name": "Ada"},
                {"id": 2, "name": "Grace"}
            ]
        }),
    ))
    .with_mutation(
        FixtureMutationRecord::new(
            "delete-row",
            TABLE_NAME,
            "user-2",
            "connector delete through mysql.execute removes the disposable acceptance row",
        )
        .with_before(json!({"id": 2, "exists": true}))
        .with_after(json!({"id": 2, "exists": false})),
    )
    .with_cleanup_check(FixtureCleanupCheck::new(
        "cleanup-users",
        TABLE_NAME,
        "query_row_absence",
        "deleted acceptance row is absent from the disposable table",
    ))
}

fn configured_connector(base_url: &str) -> MysqlConnector {
    let mut connector = MysqlConnector::new();
    connector
        .handle_configure(&json!({
            "api_key": TEST_API_KEY,
            "base_url": base_url,
        }))
        .expect("configure MySQL connector");
    connector
        .handle_handshake(&json!({}))
        .expect("handshake MySQL connector");
    connector
}

async fn invoke(connector: &MysqlConnector, operation: &str, input: Value) -> Value {
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
        }))
        .await
        .expect("MySQL loopback fixture should satisfy operation")
}

#[fcp_async_core::runtime::test]
async fn mysql_connector_acceptance_exercises_loopback_proxy_boundary() {
    let fixture = LoopbackMysqlProxy::start(10);
    let connector = configured_connector(fixture.base_url());
    let fixture_contract = fixture_contract();
    assert_stateful_fixture_pack_complete(&fixture_contract);

    let health = connector.handle_health().await.expect("health check");
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["ready"], true);
    let doctor = connector.handle_doctor().expect("doctor check");
    assert_eq!(doctor["status"], "healthy");
    let self_check = connector.handle_self_check().await.expect("self check");
    assert_eq!(self_check["status"], "ready");

    let query = invoke(
        &connector,
        "mysql.query",
        json!({
            "sql": "SELECT id, name FROM acceptance_users WHERE id = ?",
            "params": [1]
        }),
    )
    .await;
    assert_eq!(query["row_count"], 1);
    assert_eq!(query["rows"][0]["name"], "Ada");

    let deleted = invoke(
        &connector,
        "mysql.execute",
        json!({
            "sql": "DELETE FROM acceptance_users WHERE id = ?",
            "params": [2]
        }),
    )
    .await;
    assert_eq!(deleted["affected_rows"], 1);

    let after_delete = invoke(
        &connector,
        "mysql.query",
        json!({
            "sql": "SELECT id, name FROM acceptance_users WHERE id = ?",
            "params": [2]
        }),
    )
    .await;
    assert_eq!(after_delete["row_count"], 0);

    let explain = invoke(
        &connector,
        "mysql.explain",
        json!({ "sql": "SELECT id, name FROM acceptance_users WHERE id = ?" }),
    )
    .await;
    assert_eq!(explain["plan"][0]["table"], TABLE_NAME);

    let tables = invoke(&connector, "mysql.schema.tables", json!({})).await;
    assert_eq!(tables[0]["name"], TABLE_NAME);
    let columns = invoke(
        &connector,
        "mysql.schema.columns",
        json!({ "table": TABLE_NAME }),
    )
    .await;
    assert_eq!(columns[0]["name"], "id");
    let indexes = invoke(
        &connector,
        "mysql.schema.indexes",
        json!({ "table": TABLE_NAME }),
    )
    .await;
    assert_eq!(indexes[0]["name"], "PRIMARY");

    let operation_health = invoke(&connector, "mysql.health", json!({})).await;
    assert_eq!(operation_health["healthy"], true);

    let observation = fixture.join();
    assert_eq!(observation.request_lines.len(), 10);
    assert_eq!(observation.authorization_count, 10);
    assert_eq!(observation.json_content_type_count, 4);
    assert_eq!(
        observation.paths,
        [
            "/health",
            "/health",
            "/query",
            "/execute",
            "/query",
            "/explain",
            "/schema/tables",
            "/schema/columns/acceptance_users",
            "/schema/indexes/acceptance_users",
            "/health"
        ]
    );

    let cleanup = CleanupVerificationResult::new(
        "cleanup-users",
        TABLE_NAME,
        "query_row_absence",
        "deleted acceptance row is absent from the disposable table",
        json!({ "deleted_row_query_count": 0 }),
        true,
    );
    let evidence = json!({
        "schema_version": "fcp-mysql-local-acceptance/v1",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "fixture_mode": "loopback_http",
        "transport": "mysql-rest-proxy",
        "operations": [
            "mysql.health:handle_health",
            "mysql.health:self_check",
            "mysql.query",
            "mysql.execute",
            "mysql.query:after_delete",
            "mysql.explain",
            "mysql.schema.tables",
            "mysql.schema.columns",
            "mysql.schema.indexes",
            "mysql.health"
        ],
        "request_lines": observation.request_lines,
        "authorization_seen_for_all_requests": observation.authorization_count == 10,
        "json_content_type_seen_for_mutating_requests": observation.json_content_type_count == 4,
        "fixture_contract": fixture_contract.to_json(),
        "cleanup": cleanup,
    });

    assert_eq!(evidence["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(evidence["cleanup"]["passed"], true);
    assert!(
        !serde_json::to_string(&evidence)
            .expect("serialize evidence")
            .contains(TEST_API_KEY),
        "acceptance evidence must not expose MySQL API key"
    );
}
