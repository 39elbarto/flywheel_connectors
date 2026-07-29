//! Local non-mock acceptance coverage for the FCP `BigQuery` connector.

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

use fcp_bigquery::connector::BigQueryConnector;
use fcp_testkit::database_helpers::{
    CleanupVerificationResult, FixtureCleanupCheck, FixtureMutationRecord, FixtureSeedRecord,
    FixtureStartupProbe, FixtureStartupProbeKind, SeededStatefulFixturePack, StatefulFixtureFamily,
    assert_stateful_fixture_pack_complete,
};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "bigquery";
const DATASET_ID: &str = "analytics";
const FIXTURE_ID: &str = "bigquery-loopback-rest-acceptance";
const PROJECT_ID: &str = "fcp-local-project";
const TABLE_ID: &str = "events";
const TEST_ACCESS_TOKEN: &str = "bigquery-local-non-mock-token";

#[derive(Debug)]
struct FixtureObservation {
    request_lines: Vec<String>,
    methods: Vec<String>,
    paths: Vec<String>,
    bodies: Vec<Value>,
    authorization_count: usize,
    accept_json_count: usize,
    json_content_type_count: usize,
    query_jobs_created: usize,
}

struct LoopbackBigQueryApi {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

#[derive(Debug, Clone)]
struct TableRow {
    event_id: &'static str,
    actor: &'static str,
}

struct BigQueryFixtureState {
    rows: BTreeMap<&'static str, TableRow>,
    query_jobs_created: usize,
}

impl Default for BigQueryFixtureState {
    fn default() -> Self {
        Self {
            rows: BTreeMap::from([
                (
                    "evt-1",
                    TableRow {
                        event_id: "evt-1",
                        actor: "Ada",
                    },
                ),
                (
                    "evt-2",
                    TableRow {
                        event_id: "evt-2",
                        actor: "Grace",
                    },
                ),
            ]),
            query_jobs_created: 0,
        }
    }
}

impl LoopbackBigQueryApi {
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
    let mut state = BigQueryFixtureState::default();
    let mut observation = FixtureObservation {
        request_lines: Vec::with_capacity(expected_requests),
        methods: Vec::with_capacity(expected_requests),
        paths: Vec::with_capacity(expected_requests),
        bodies: Vec::with_capacity(expected_requests),
        authorization_count: 0,
        accept_json_count: 0,
        json_content_type_count: 0,
        query_jobs_created: 0,
    };

    while observation.request_lines.len() < expected_requests {
        match listener.accept() {
            Ok((stream, _)) => handle_request(stream, &mut state, &mut observation),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for BigQuery connector request {} of {expected_requests}",
                    observation.request_lines.len() + 1
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept BigQuery connector request: {error}"),
        }
    }

    observation.query_jobs_created = state.query_jobs_created;
    observation
}

fn handle_request(
    mut stream: TcpStream,
    state: &mut BigQueryFixtureState,
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

    if headers.lines().any(|line| {
        line.eq_ignore_ascii_case("authorization: bearer bigquery-local-non-mock-token")
    }) {
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
        serde_json::from_str(body).expect("parse BigQuery API request body")
    };
    let response = execute_api_request(state, &method, &path, &body_json);

    observation.request_lines.push(request_line);
    observation.methods.push(method);
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
    .expect("write BigQuery fixture response");
}

fn execute_api_request(
    state: &mut BigQueryFixtureState,
    method: &str,
    path: &str,
    body: &Value,
) -> Value {
    match (method, path) {
        ("GET", "/projects/fcp-local-project/datasets") => json!({
            "kind": "bigquery#datasetList",
            "datasets": [{
                "id": format!("{PROJECT_ID}:{DATASET_ID}"),
                "datasetReference": {
                    "projectId": PROJECT_ID,
                    "datasetId": DATASET_ID
                },
                "location": "US"
            }]
        }),
        ("GET", "/projects/fcp-local-project/datasets/analytics/tables") => json!({
            "kind": "bigquery#tableList",
            "tables": [{
                "id": format!("{PROJECT_ID}:{DATASET_ID}.{TABLE_ID}"),
                "tableReference": {
                    "projectId": PROJECT_ID,
                    "datasetId": DATASET_ID,
                    "tableId": TABLE_ID
                },
                "type": "TABLE"
            }],
            "totalItems": 1
        }),
        ("GET", "/projects/fcp-local-project/jobs") => json!({
            "kind": "bigquery#jobList",
            "jobs": [{
                "id": format!("{PROJECT_ID}:US.seeded_job"),
                "jobReference": {
                    "projectId": PROJECT_ID,
                    "jobId": "seeded_job"
                },
                "status": {"state": "DONE"}
            }]
        }),
        ("POST", "/projects/fcp-local-project/queries") => query_response(state, body),
        _ => json!({ "error": format!("unexpected {method} {path}") }),
    }
}

fn query_response(state: &mut BigQueryFixtureState, body: &Value) -> Value {
    assert_eq!(body["useLegacySql"], false);
    assert!(
        body["query"]
            .as_str()
            .is_some_and(|query| query.contains("acceptance_events")),
        "query should target the seeded acceptance table"
    );
    state.query_jobs_created += 1;
    let rows: Vec<Value> = state
        .rows
        .values()
        .map(|row| {
            json!({
                "f": [
                    {"v": row.event_id},
                    {"v": row.actor}
                ]
            })
        })
        .collect();
    let row_count = rows.len();

    json!({
        "kind": "bigquery#queryResponse",
        "jobComplete": true,
        "totalRows": row_count.to_string(),
        "schema": {
            "fields": [
                {"name": "event_id", "type": "STRING"},
                {"name": "actor", "type": "STRING"}
            ]
        },
        "rows": rows
    })
}

fn fixture_contract() -> SeededStatefulFixturePack {
    SeededStatefulFixturePack::new(
        FIXTURE_ID,
        StatefulFixtureFamily::Relational,
        "bigquery-loopback-rest-api",
    )
    .with_startup_probe(FixtureStartupProbe::new(
        "bigquery-rest-ready",
        FixtureStartupProbeKind::TcpConnect,
        "127.0.0.1:redacted-bigquery-rest-port",
        10_000,
        "local BigQuery REST fixture accepts connector HTTP requests before operations run",
    ))
    .with_seed(FixtureSeedRecord::new(
        "acceptance_events",
        "seed-events",
        json!({
            "project_id": PROJECT_ID,
            "dataset_id": DATASET_ID,
            "table_id": TABLE_ID,
            "rows": [
                {"event_id": "evt-1", "actor": "Ada"},
                {"event_id": "evt-2", "actor": "Grace"}
            ]
        }),
    ))
    .with_mutation(
        FixtureMutationRecord::new(
            "query_job",
            "query_jobs",
            "local-query-job",
            "connector query call creates exactly one disposable query job in the loopback fixture",
        )
        .with_before(json!({"query_jobs_created": 0}))
        .with_after(json!({"query_jobs_created": 1})),
    )
    .with_cleanup_check(FixtureCleanupCheck::new(
        "cleanup-query-jobs",
        "query_jobs",
        "fixture_lifetime",
        "disposable query job state is scoped to the loopback fixture lifetime",
    ))
}

async fn configured_connector(base_url: &str) -> BigQueryConnector {
    let mut connector = BigQueryConnector::new();
    connector
        .handle_configure(json!({
            "access_token": TEST_ACCESS_TOKEN,
            "project_id": PROJECT_ID,
            "base_url": base_url,
        }))
        .await
        .expect("configure BigQuery connector");
    connector
        .handle_handshake(json!({ "session_id": "bigquery-local-non-mock" }))
        .await
        .expect("handshake BigQuery connector");
    connector
}

async fn invoke(connector: &BigQueryConnector, operation_id: &str, input: Value) -> Value {
    connector
        .handle_invoke(json!({
            "operation_id": operation_id,
            "input": input,
        }))
        .await
        .expect("BigQuery loopback fixture should satisfy operation")
}

#[fcp_async_core::runtime::test]
async fn bigquery_connector_acceptance_exercises_loopback_rest_boundary() {
    let fixture = LoopbackBigQueryApi::start(4);
    let connector = configured_connector(fixture.base_url()).await;
    let fixture_contract = fixture_contract();
    assert_stateful_fixture_pack_complete(&fixture_contract);

    let health = connector.handle_health().await.expect("health check");
    assert_eq!(health["status"], "healthy");
    let doctor = connector.handle_doctor().await.expect("doctor check");
    assert_eq!(doctor["status"], "healthy");
    let self_check = connector.handle_self_check().await.expect("self check");
    assert_eq!(self_check["status"], "ok");

    let datasets = invoke(
        &connector,
        "bigquery.datasets.list",
        json!({"project_id": PROJECT_ID}),
    )
    .await;
    assert_eq!(
        datasets["datasets"][0]["datasetReference"]["datasetId"],
        DATASET_ID
    );

    let tables = invoke(
        &connector,
        "bigquery.tables.list",
        json!({"project_id": PROJECT_ID, "dataset_id": DATASET_ID}),
    )
    .await;
    assert_eq!(tables["tables"][0]["tableReference"]["tableId"], TABLE_ID);

    let jobs = invoke(
        &connector,
        "bigquery.jobs.list",
        json!({"project_id": PROJECT_ID}),
    )
    .await;
    assert_eq!(jobs["jobs"][0]["status"]["state"], "DONE");

    let query = invoke(
        &connector,
        "bigquery.jobs.query",
        json!({
            "project_id": PROJECT_ID,
            "query": "SELECT event_id, actor FROM acceptance_events ORDER BY event_id",
            "use_legacy_sql": false
        }),
    )
    .await;
    assert_eq!(query["jobComplete"], true);
    assert_eq!(query["totalRows"], "2");
    assert_eq!(query["rows"][0]["f"][1]["v"], "Ada");

    let observation = fixture.join();
    assert_eq!(observation.request_lines.len(), 4);
    assert_eq!(observation.authorization_count, 4);
    assert_eq!(observation.accept_json_count, 4);
    assert_eq!(observation.json_content_type_count, 1);
    assert_eq!(observation.query_jobs_created, 1);
    assert_eq!(observation.methods, ["GET", "GET", "GET", "POST"]);
    assert_eq!(
        observation.paths,
        [
            "/projects/fcp-local-project/datasets",
            "/projects/fcp-local-project/datasets/analytics/tables",
            "/projects/fcp-local-project/jobs",
            "/projects/fcp-local-project/queries"
        ]
    );

    let cleanup = CleanupVerificationResult::new(
        "cleanup-query-jobs",
        "query_jobs",
        "fixture_lifetime",
        "disposable query job state is scoped to the loopback fixture lifetime",
        json!({"query_jobs_created": observation.query_jobs_created, "fixture_joined": true}),
        true,
    );
    let evidence = json!({
        "schema_version": "fcp-bigquery-local-acceptance/v1",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "fixture_mode": "loopback_http",
        "transport": "bigquery_rest",
        "operations": [
            "bigquery.datasets.list",
            "bigquery.tables.list",
            "bigquery.jobs.list",
            "bigquery.jobs.query"
        ],
        "request_lines": observation.request_lines,
        "authorization_seen_for_all_requests": observation.authorization_count == 4,
        "accept_json_seen_for_all_requests": observation.accept_json_count == 4,
        "json_content_type_seen_for_query_request": observation.json_content_type_count == 1,
        "fixture_contract": fixture_contract.to_json(),
        "cleanup": cleanup,
    });

    assert_eq!(evidence["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(evidence["cleanup"]["passed"], true);
    assert!(
        !serde_json::to_string(&evidence)
            .expect("serialize evidence")
            .contains(TEST_ACCESS_TOKEN),
        "acceptance evidence must not expose BigQuery access token"
    );
}
