//! Local non-mock acceptance coverage for the FCP `MongoDB` connector.

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

use fcp_mongodb::connector::MongoDbConnector;
use fcp_testkit::database_helpers::{
    CleanupVerificationResult, FixtureCleanupCheck, FixtureMutationRecord, FixtureSeedRecord,
    FixtureStartupProbe, FixtureStartupProbeKind, SeededStatefulFixturePack, StatefulFixtureFamily,
    assert_stateful_fixture_pack_complete,
};
use serde_json::{Map, Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const COLLECTION_NAME: &str = "users";
const CONNECTOR_ID: &str = "mongodb";
const DATA_SOURCE: &str = "LocalCluster";
const DATABASE_NAME: &str = "acceptance_db";
const FIXTURE_ID: &str = "mongodb-loopback-data-api-acceptance";
const TEST_API_KEY: &str = "mongodb-local-non-mock-token";

#[derive(Debug)]
struct FixtureObservation {
    request_lines: Vec<String>,
    paths: Vec<String>,
    bodies: Vec<Value>,
    api_key_count: usize,
    accept_json_count: usize,
    json_content_type_count: usize,
    remaining_user_ids: Vec<String>,
}

struct LoopbackMongoDataApi {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

struct MongoFixtureState {
    users: BTreeMap<String, Value>,
}

impl Default for MongoFixtureState {
    fn default() -> Self {
        Self {
            users: BTreeMap::from([
                (
                    "user-1".to_string(),
                    json!({"_id": "user-1", "name": "Ada", "status": "active"}),
                ),
                (
                    "user-2".to_string(),
                    json!({"_id": "user-2", "name": "Grace", "status": "pending"}),
                ),
            ]),
        }
    }
}

impl LoopbackMongoDataApi {
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
    let mut state = MongoFixtureState::default();
    let mut observation = FixtureObservation {
        request_lines: Vec::with_capacity(expected_requests),
        paths: Vec::with_capacity(expected_requests),
        bodies: Vec::with_capacity(expected_requests),
        api_key_count: 0,
        accept_json_count: 0,
        json_content_type_count: 0,
        remaining_user_ids: Vec::new(),
    };

    while observation.request_lines.len() < expected_requests {
        match listener.accept() {
            Ok((stream, _)) => handle_request(stream, &mut state, &mut observation),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for MongoDB connector request {} of {expected_requests}",
                    observation.request_lines.len() + 1
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept MongoDB connector request: {error}"),
        }
    }

    observation.remaining_user_ids = state.users.keys().cloned().collect();
    observation
}

fn handle_request(
    mut stream: TcpStream,
    state: &mut MongoFixtureState,
    observation: &mut FixtureObservation,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let request = read_http_request(&mut stream);
    let request_line = request.lines().next().unwrap_or_default().to_string();
    let (_, path) = parse_request_line(&request_line);
    let path = path.to_string();
    let headers = request
        .split_once("\r\n\r\n")
        .map_or(request.as_str(), |(headers, _)| headers);

    if headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("apikey: mongodb-local-non-mock-token"))
    {
        observation.api_key_count += 1;
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
    let body_json = serde_json::from_str(body).expect("parse MongoDB Data API request body");
    let response = execute_data_api_request(state, &path, &body_json);

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
    .expect("write MongoDB fixture response");
}

fn execute_data_api_request(state: &mut MongoFixtureState, path: &str, body: &Value) -> Value {
    assert_eq!(body["dataSource"], DATA_SOURCE);
    assert_eq!(body["database"], DATABASE_NAME);
    assert_eq!(body["collection"], COLLECTION_NAME);

    match path {
        "/action/findOne" => find_one_response(state, body),
        "/action/find" => find_response(state, body),
        "/action/insertOne" => insert_one_response(state, body),
        "/action/updateOne" => update_one_response(state, body),
        "/action/aggregate" => aggregate_response(state),
        "/action/deleteOne" => delete_one_response(state, body),
        _ => json!({ "error": format!("unexpected MongoDB action path: {path}") }),
    }
}

fn find_one_response(state: &MongoFixtureState, body: &Value) -> Value {
    let id = filter_id(body);
    json!({ "document": state.users.get(id).cloned().unwrap_or(Value::Null) })
}

fn find_response(state: &MongoFixtureState, body: &Value) -> Value {
    let expected_status = body["filter"]["status"].as_str();
    let documents: Vec<Value> = state
        .users
        .values()
        .filter(|document| {
            expected_status.is_none_or(|status| document["status"].as_str() == Some(status))
        })
        .cloned()
        .collect();

    json!({ "documents": documents })
}

fn insert_one_response(state: &mut MongoFixtureState, body: &Value) -> Value {
    let document = body["document"].clone();
    let id = document["_id"]
        .as_str()
        .expect("insert document should include _id")
        .to_string();
    state.users.insert(id.clone(), document);
    json!({ "insertedId": id })
}

fn update_one_response(state: &mut MongoFixtureState, body: &Value) -> Value {
    let id = filter_id(body);
    let update = body["update"]["$set"]
        .as_object()
        .expect("update should include $set object");
    let modified_count = if let Some(Value::Object(document)) = state.users.get_mut(id) {
        apply_update(document, update);
        1
    } else {
        0
    };

    json!({
        "matchedCount": modified_count,
        "modifiedCount": modified_count
    })
}

fn aggregate_response(state: &MongoFixtureState) -> Value {
    let active_count = state
        .users
        .values()
        .filter(|document| document["status"].as_str() == Some("active"))
        .count();
    json!({
        "documents": [{
            "_id": "active",
            "count": active_count
        }]
    })
}

fn delete_one_response(state: &mut MongoFixtureState, body: &Value) -> Value {
    let id = filter_id(body);
    let deleted_count = usize::from(state.users.remove(id).is_some());
    json!({ "deletedCount": deleted_count })
}

fn apply_update(document: &mut Map<String, Value>, update: &Map<String, Value>) {
    for (key, value) in update {
        document.insert(key.clone(), value.clone());
    }
}

fn filter_id(body: &Value) -> &str {
    body["filter"]["_id"]
        .as_str()
        .expect("filter should include string _id")
}

fn fixture_contract() -> SeededStatefulFixturePack {
    SeededStatefulFixturePack::new(
        FIXTURE_ID,
        StatefulFixtureFamily::KeyValue,
        "mongodb-loopback-data-api",
    )
    .with_startup_probe(FixtureStartupProbe::new(
        "mongodb-data-api-ready",
        FixtureStartupProbeKind::TcpConnect,
        "127.0.0.1:redacted-mongodb-data-api-port",
        10_000,
        "local MongoDB Data API fixture accepts connector HTTP requests before CRUD operations run",
    ))
    .with_seed(FixtureSeedRecord::new(
        COLLECTION_NAME,
        "seed-users",
        json!({
            "database": DATABASE_NAME,
            "collection": COLLECTION_NAME,
            "documents": [
                {"_id": "user-1", "name": "Ada", "status": "active"},
                {"_id": "user-2", "name": "Grace", "status": "pending"}
            ]
        }),
    ))
    .with_mutation(
        FixtureMutationRecord::new(
            "insert_one",
            COLLECTION_NAME,
            "user-3",
            "connector insert_one creates a disposable acceptance document",
        )
        .with_before(json!({"exists": false}))
        .with_after(json!({"exists": true, "status": "active"})),
    )
    .with_mutation(
        FixtureMutationRecord::new(
            "update_one",
            COLLECTION_NAME,
            "user-2",
            "connector update_one changes a seeded document field",
        )
        .with_before(json!({"status": "pending"}))
        .with_after(json!({"status": "active"})),
    )
    .with_mutation(
        FixtureMutationRecord::new(
            "delete_one",
            COLLECTION_NAME,
            "user-3",
            "connector delete_one removes the disposable acceptance document",
        )
        .with_before(json!({"exists": true}))
        .with_after(json!({"exists": false})),
    )
    .with_cleanup_check(FixtureCleanupCheck::new(
        "cleanup-users",
        COLLECTION_NAME,
        "find_one_absence",
        "disposable user-3 document is absent after delete_one",
    ))
}

async fn configured_connector(base_url: &str) -> MongoDbConnector {
    let mut connector = MongoDbConnector::new();
    connector
        .handle_configure(json!({
            "api_key": TEST_API_KEY,
            "base_url": base_url,
            "data_source": DATA_SOURCE,
        }))
        .await
        .expect("configure MongoDB connector");
    connector
        .handle_handshake(json!({ "session_id": "mongodb-local-non-mock" }))
        .await
        .expect("handshake MongoDB connector");
    connector
}

async fn invoke(connector: &MongoDbConnector, operation_id: &str, input: Value) -> Value {
    connector
        .handle_invoke(json!({
            "operation_id": operation_id,
            "input": input,
        }))
        .await
        .expect("MongoDB loopback fixture should satisfy operation")
}

#[fcp_async_core::runtime::test]
async fn mongodb_connector_acceptance_exercises_loopback_data_api_boundary() {
    let fixture = LoopbackMongoDataApi::start(7);
    let connector = configured_connector(fixture.base_url()).await;
    let fixture_contract = fixture_contract();
    assert_stateful_fixture_pack_complete(&fixture_contract);

    let health = connector.handle_health().await.expect("health check");
    assert_eq!(health["status"], "healthy");
    let doctor = connector.handle_doctor().await.expect("doctor check");
    assert_eq!(doctor["status"], "healthy");
    let self_check = connector.handle_self_check().await.expect("self check");
    assert_eq!(self_check["status"], "ok");

    let ada = invoke(
        &connector,
        "mongodb.find_one",
        json!({
            "database": DATABASE_NAME,
            "collection": COLLECTION_NAME,
            "filter": {"_id": "user-1"}
        }),
    )
    .await;
    assert_eq!(ada["document"]["name"], "Ada");

    let inserted = invoke(
        &connector,
        "mongodb.insert_one",
        json!({
            "database": DATABASE_NAME,
            "collection": COLLECTION_NAME,
            "document": {"_id": "user-3", "name": "Linus", "status": "active"}
        }),
    )
    .await;
    assert_eq!(inserted["insertedId"], "user-3");

    let active = invoke(
        &connector,
        "mongodb.find",
        json!({
            "database": DATABASE_NAME,
            "collection": COLLECTION_NAME,
            "filter": {"status": "active"},
            "sort": {"_id": 1}
        }),
    )
    .await;
    assert_eq!(
        active["documents"].as_array().expect("active docs").len(),
        2
    );

    let updated = invoke(
        &connector,
        "mongodb.update_one",
        json!({
            "database": DATABASE_NAME,
            "collection": COLLECTION_NAME,
            "filter": {"_id": "user-2"},
            "update": {"$set": {"status": "active"}}
        }),
    )
    .await;
    assert_eq!(updated["matchedCount"], 1);
    assert_eq!(updated["modifiedCount"], 1);

    let aggregate = invoke(
        &connector,
        "mongodb.aggregate",
        json!({
            "database": DATABASE_NAME,
            "collection": COLLECTION_NAME,
            "pipeline": [
                {"$match": {"status": "active"}},
                {"$group": {"_id": "$status", "count": {"$sum": 1}}}
            ]
        }),
    )
    .await;
    assert_eq!(aggregate["documents"][0]["count"], 3);

    let deleted = invoke(
        &connector,
        "mongodb.delete_one",
        json!({
            "database": DATABASE_NAME,
            "collection": COLLECTION_NAME,
            "filter": {"_id": "user-3"}
        }),
    )
    .await;
    assert_eq!(deleted["deletedCount"], 1);

    let after_delete = invoke(
        &connector,
        "mongodb.find_one",
        json!({
            "database": DATABASE_NAME,
            "collection": COLLECTION_NAME,
            "filter": {"_id": "user-3"}
        }),
    )
    .await;
    assert!(after_delete["document"].is_null());

    let observation = fixture.join();
    assert_eq!(observation.request_lines.len(), 7);
    assert_eq!(observation.api_key_count, 7);
    assert_eq!(observation.accept_json_count, 7);
    assert_eq!(observation.json_content_type_count, 7);
    assert_eq!(observation.remaining_user_ids, ["user-1", "user-2"]);
    assert_eq!(
        observation.paths,
        [
            "/action/findOne",
            "/action/insertOne",
            "/action/find",
            "/action/updateOne",
            "/action/aggregate",
            "/action/deleteOne",
            "/action/findOne"
        ]
    );

    let cleanup = CleanupVerificationResult::new(
        "cleanup-users",
        COLLECTION_NAME,
        "find_one_absence",
        "disposable user-3 document is absent after delete_one",
        json!({"remaining_user_ids": observation.remaining_user_ids}),
        true,
    );
    let evidence = json!({
        "schema_version": "fcp-mongodb-local-acceptance/v1",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "fixture_mode": "loopback_http",
        "transport": "mongodb_atlas_data_api",
        "operations": [
            "mongodb.find_one",
            "mongodb.insert_one",
            "mongodb.find",
            "mongodb.update_one",
            "mongodb.aggregate",
            "mongodb.delete_one",
            "mongodb.find_one:after_delete"
        ],
        "request_lines": observation.request_lines,
        "api_key_seen_for_all_requests": observation.api_key_count == 7,
        "accept_json_seen_for_all_requests": observation.accept_json_count == 7,
        "json_content_type_seen_for_all_requests": observation.json_content_type_count == 7,
        "fixture_contract": fixture_contract.to_json(),
        "cleanup": cleanup,
    });

    assert_eq!(evidence["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(evidence["cleanup"]["passed"], true);
    assert!(
        !serde_json::to_string(&evidence)
            .expect("serialize evidence")
            .contains(TEST_API_KEY),
        "acceptance evidence must not expose MongoDB API key"
    );
}
