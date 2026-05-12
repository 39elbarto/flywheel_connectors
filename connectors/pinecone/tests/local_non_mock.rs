//! Local non-mock acceptance coverage for the FCP `Pinecone` connector.

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

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_pinecone::connector::PineconeConnector;
use fcp_prelude::{CapabilityConstraints, CapabilityToken, InstanceId};
use fcp_testkit::database_helpers::{
    CleanupVerificationResult, FixtureCleanupCheck, FixtureMutationRecord, FixtureSeedRecord,
    FixtureStartupProbe, FixtureStartupProbeKind, SeededStatefulFixturePack, StatefulFixtureFamily,
    assert_stateful_fixture_pack_complete,
};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "pinecone";
const FIXTURE_ID: &str = "pinecone-loopback-control-data-plane-acceptance";
const INDEX_NAME: &str = "acceptance-index";
const NAMESPACE: &str = "acceptance";
const TEST_API_KEY: &str = "pinecone-local-non-mock-token";
const VECTOR_ID: &str = "vec-1";

#[derive(Debug)]
struct FixtureObservation {
    request_lines: Vec<String>,
    methods: Vec<String>,
    paths: Vec<String>,
    bodies: Vec<Value>,
    api_key_count: usize,
    json_content_type_count: usize,
    final_index_exists: bool,
    final_vector_count: usize,
}

struct LoopbackPineconeApi {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

#[derive(Default)]
struct PineconeFixtureState {
    index_exists: bool,
    vectors: BTreeMap<String, Value>,
}

impl LoopbackPineconeApi {
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
    let mut state = PineconeFixtureState::default();
    let mut observation = FixtureObservation {
        request_lines: Vec::with_capacity(expected_requests),
        methods: Vec::with_capacity(expected_requests),
        paths: Vec::with_capacity(expected_requests),
        bodies: Vec::with_capacity(expected_requests),
        api_key_count: 0,
        json_content_type_count: 0,
        final_index_exists: false,
        final_vector_count: 0,
    };

    while observation.request_lines.len() < expected_requests {
        match listener.accept() {
            Ok((stream, _)) => handle_request(stream, &mut state, &mut observation),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for Pinecone connector request {} of {expected_requests}",
                    observation.request_lines.len() + 1
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept Pinecone connector request: {error}"),
        }
    }

    observation.final_index_exists = state.index_exists;
    observation.final_vector_count = state.vectors.len();
    observation
}

fn handle_request(
    mut stream: TcpStream,
    state: &mut PineconeFixtureState,
    observation: &mut FixtureObservation,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let request = read_http_request(&mut stream);
    let request_line = request.lines().next().unwrap_or_default().to_string();
    let (method, raw_path) = parse_request_line(&request_line);
    let method = method.to_string();
    let raw_path = raw_path.to_string();
    let path = raw_path.split('?').next().unwrap_or_default().to_string();
    let headers = request
        .split_once("\r\n\r\n")
        .map_or(request.as_str(), |(headers, _)| headers);

    if headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("api-key: pinecone-local-non-mock-token"))
    {
        observation.api_key_count += 1;
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
        serde_json::from_str(body).expect("parse Pinecone request body")
    };
    let response = execute_pinecone_request(state, &method, &path, &raw_path, &body_json);

    observation.request_lines.push(request_line);
    observation.methods.push(method);
    observation.paths.push(raw_path);
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
    .expect("write Pinecone fixture response");
}

fn execute_pinecone_request(
    state: &mut PineconeFixtureState,
    method: &str,
    path: &str,
    raw_path: &str,
    body: &Value,
) -> Value {
    match (method, path) {
        ("GET", "/indexes") => list_indexes_response(state),
        ("POST", "/indexes") => create_index_response(state, body),
        ("GET", "/indexes/acceptance-index") => index_response(),
        ("DELETE", "/indexes/acceptance-index") => {
            state.index_exists = false;
            state.vectors.clear();
            json!({})
        }
        ("POST", "/vectors/upsert") => upsert_response(state, body),
        ("POST", "/query") => query_response(state, body),
        ("GET", "/vectors/fetch") => fetch_response(state, raw_path),
        ("POST", "/vectors/delete") => delete_vectors_response(state, body),
        ("POST", "/describe_index_stats") => index_stats_response(state),
        _ => json!({ "error": format!("unexpected Pinecone request: {method} {raw_path}") }),
    }
}

fn list_indexes_response(state: &PineconeFixtureState) -> Value {
    let indexes = if state.index_exists {
        vec![index_response()]
    } else {
        Vec::new()
    };
    json!({ "indexes": indexes })
}

fn create_index_response(state: &mut PineconeFixtureState, body: &Value) -> Value {
    assert_eq!(body["name"], INDEX_NAME);
    assert_eq!(body["dimension"], 3);
    assert_eq!(body["metric"], "cosine");
    state.index_exists = true;
    index_response()
}

fn index_response() -> Value {
    json!({
        "name": INDEX_NAME,
        "dimension": 3,
        "metric": "cosine",
        "host": "acceptance-index.svc.pinecone.local",
        "status": {"ready": true, "state": "Ready"},
        "spec": {"serverless": {"cloud": "aws", "region": "local"}}
    })
}

fn upsert_response(state: &mut PineconeFixtureState, body: &Value) -> Value {
    assert_eq!(body["namespace"], NAMESPACE);
    let vectors = body["vectors"].as_array().expect("upsert vectors array");
    for vector in vectors {
        let id = vector["id"].as_str().expect("vector id").to_string();
        state.vectors.insert(id, vector.clone());
    }
    json!({ "upserted_count": vectors.len() })
}

fn query_response(state: &PineconeFixtureState, body: &Value) -> Value {
    assert_eq!(body["topK"], 1);
    assert_eq!(body["namespace"], NAMESPACE);
    assert_eq!(body["includeMetadata"], true);
    assert_eq!(body["includeValues"], true);
    let matches = state
        .vectors
        .get(VECTOR_ID)
        .map(|vector| {
            vec![json!({
                "id": VECTOR_ID,
                "score": 0.99,
                "values": vector["values"],
                "metadata": vector["metadata"]
            })]
        })
        .unwrap_or_default();
    json!({ "matches": matches, "namespace": NAMESPACE })
}

fn fetch_response(state: &PineconeFixtureState, raw_path: &str) -> Value {
    let query = raw_path.split_once('?').map_or("", |(_, query)| query);
    let ids = query_values(query, "ids");
    assert_eq!(query_values(query, "namespace"), [NAMESPACE]);
    let mut vectors = serde_json::Map::new();
    for id in ids {
        if let Some(vector) = state.vectors.get(&id) {
            vectors.insert(id, vector.clone());
        }
    }
    json!({ "vectors": vectors, "namespace": NAMESPACE })
}

fn delete_vectors_response(state: &mut PineconeFixtureState, body: &Value) -> Value {
    assert_eq!(body["namespace"], NAMESPACE);
    let ids = body["ids"].as_array().expect("delete ids array");
    let mut deleted_count = 0;
    for id in ids {
        if let Some(id) = id.as_str() {
            deleted_count += usize::from(state.vectors.remove(id).is_some());
        }
    }
    json!({ "deleted_count": deleted_count })
}

fn index_stats_response(state: &PineconeFixtureState) -> Value {
    json!({
        "namespaces": {
            NAMESPACE: {"vector_count": state.vectors.len()}
        },
        "dimension": 3,
        "index_fullness": 0.0,
        "total_vector_count": state.vectors.len()
    })
}

fn query_values(query: &str, key: &str) -> Vec<String> {
    query
        .split('&')
        .filter_map(|part| {
            part.split_once('=')
                .filter(|(name, _)| *name == key)
                .map(|(_, value)| value.to_string())
        })
        .collect()
}

fn capability_for_operation(operation: &str) -> &'static str {
    match operation {
        "pinecone.create_index" | "pinecone.delete_index" => "pinecone.indexes.write",
        "pinecone.query" | "pinecone.fetch" => "pinecone.vectors.read",
        "pinecone.upsert" | "pinecone.delete" => "pinecone.vectors.write",
        _ => "pinecone.indexes.read",
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    operation: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose)
}

async fn setup_handshake(
    connector: &mut PineconeConnector,
    operations: &[&str],
) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let capabilities: Vec<&str> = operations
        .iter()
        .map(|operation| capability_for_operation(operation))
        .collect();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": capabilities
        }))
        .await
        .expect("handshake Pinecone connector");

    signing_key
}

async fn configured_connector(base_url: &str) -> (PineconeConnector, Ed25519SigningKey) {
    let mut connector = PineconeConnector::new();
    connector
        .handle_configure(json!({
            "api_key": TEST_API_KEY,
            "control_plane_url": base_url,
            "data_plane_url": base_url,
        }))
        .await
        .expect("configure Pinecone connector");
    let signing_key = setup_handshake(
        &mut connector,
        &[
            "pinecone.list_indexes",
            "pinecone.describe_index",
            "pinecone.describe_index_stats",
            "pinecone.create_index",
            "pinecone.delete_index",
            "pinecone.query",
            "pinecone.fetch",
            "pinecone.upsert",
            "pinecone.delete",
        ],
    )
    .await;
    (connector, signing_key)
}

async fn invoke(
    connector: &PineconeConnector,
    signing_key: &Ed25519SigningKey,
    operation: &str,
    input: Value,
) -> Value {
    let token = generate_valid_token(signing_key, connector.instance_id(), operation);
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": token,
        }))
        .await
        .expect("Pinecone loopback fixture should satisfy operation")
}

fn fixture_contract() -> SeededStatefulFixturePack {
    SeededStatefulFixturePack::new(
        FIXTURE_ID,
        StatefulFixtureFamily::KeyValue,
        "pinecone-loopback-control-data-plane",
    )
    .with_startup_probe(FixtureStartupProbe::new(
        "pinecone-api-ready",
        FixtureStartupProbeKind::TcpConnect,
        "127.0.0.1:redacted-pinecone-api-port",
        10_000,
        "local Pinecone control/data-plane fixture accepts connector HTTP requests",
    ))
    .with_seed(FixtureSeedRecord::new(
        INDEX_NAME,
        "empty-index-fixture",
        json!({
            "index_exists": false,
            "namespace": NAMESPACE,
            "vectors": []
        }),
    ))
    .with_mutation(
        FixtureMutationRecord::new(
            "create_index",
            INDEX_NAME,
            INDEX_NAME,
            "connector create_index materializes the disposable acceptance index",
        )
        .with_before(json!({"index_exists": false}))
        .with_after(json!({"index_exists": true})),
    )
    .with_mutation(
        FixtureMutationRecord::new(
            "upsert",
            INDEX_NAME,
            VECTOR_ID,
            "connector upsert stores one disposable vector in the acceptance namespace",
        )
        .with_before(json!({"exists": false}))
        .with_after(json!({"exists": true, "namespace": NAMESPACE})),
    )
    .with_mutation(
        FixtureMutationRecord::new(
            "delete_vector",
            INDEX_NAME,
            VECTOR_ID,
            "connector delete removes the disposable vector",
        )
        .with_before(json!({"exists": true}))
        .with_after(json!({"exists": false})),
    )
    .with_mutation(
        FixtureMutationRecord::new(
            "delete_index",
            INDEX_NAME,
            INDEX_NAME,
            "connector delete_index removes the disposable acceptance index",
        )
        .with_before(json!({"index_exists": true}))
        .with_after(json!({"index_exists": false})),
    )
    .with_cleanup_check(FixtureCleanupCheck::new(
        "cleanup-index",
        INDEX_NAME,
        "index_and_vector_absence",
        "acceptance index is deleted and vector state is empty after teardown",
    ))
}

#[fcp_async_core::runtime::test]
async fn pinecone_connector_acceptance_exercises_loopback_control_and_data_planes() {
    let fixture = LoopbackPineconeApi::start(10);
    let (connector, signing_key) = configured_connector(fixture.base_url()).await;
    let fixture_contract = fixture_contract();
    assert_stateful_fixture_pack_complete(&fixture_contract);

    let health = connector.handle_health().await.expect("health check");
    assert_eq!(health["status"], "healthy");
    let doctor = connector.handle_doctor().await.expect("doctor check");
    assert_eq!(doctor["status"], "healthy");
    let self_check = connector.handle_self_check().await.expect("self check");
    assert_eq!(self_check["status"], "ok");

    let indexes = invoke(&connector, &signing_key, "pinecone.list_indexes", json!({})).await;
    assert_eq!(indexes["indexes"].as_array().expect("indexes").len(), 0);

    let created = invoke(
        &connector,
        &signing_key,
        "pinecone.create_index",
        json!({
            "name": INDEX_NAME,
            "dimension": 3,
            "metric": "cosine",
            "spec": {"serverless": {"cloud": "aws", "region": "local"}}
        }),
    )
    .await;
    assert_eq!(created["name"], INDEX_NAME);

    let described = invoke(
        &connector,
        &signing_key,
        "pinecone.describe_index",
        json!({"index_name": INDEX_NAME}),
    )
    .await;
    assert_eq!(described["status"]["ready"], true);

    let upserted = invoke(
        &connector,
        &signing_key,
        "pinecone.upsert",
        json!({
            "index_name": INDEX_NAME,
            "namespace": NAMESPACE,
            "vectors": [{
                "id": VECTOR_ID,
                "values": [0.1, 0.2, 0.3],
                "metadata": {"kind": "acceptance"}
            }]
        }),
    )
    .await;
    assert_eq!(upserted["upserted_count"], 1);

    let query = invoke(
        &connector,
        &signing_key,
        "pinecone.query",
        json!({
            "index_name": INDEX_NAME,
            "namespace": NAMESPACE,
            "vector": [0.1, 0.2, 0.3],
            "top_k": 1,
            "include_metadata": true,
            "include_values": true
        }),
    )
    .await;
    assert_eq!(query["matches"][0]["id"], VECTOR_ID);
    assert_eq!(query["matches"][0]["metadata"]["kind"], "acceptance");

    let fetched = invoke(
        &connector,
        &signing_key,
        "pinecone.fetch",
        json!({
            "index_name": INDEX_NAME,
            "namespace": NAMESPACE,
            "ids": [VECTOR_ID]
        }),
    )
    .await;
    assert_eq!(
        fetched["vectors"][VECTOR_ID]["metadata"]["kind"],
        "acceptance"
    );

    let deleted = invoke(
        &connector,
        &signing_key,
        "pinecone.delete",
        json!({
            "index_name": INDEX_NAME,
            "namespace": NAMESPACE,
            "ids": [VECTOR_ID]
        }),
    )
    .await;
    assert_eq!(deleted["deleted_count"], 1);

    let stats = invoke(
        &connector,
        &signing_key,
        "pinecone.describe_index_stats",
        json!({"index_name": INDEX_NAME}),
    )
    .await;
    assert_eq!(stats["total_vector_count"], 0);

    let deleted_index = invoke(
        &connector,
        &signing_key,
        "pinecone.delete_index",
        json!({"index_name": INDEX_NAME}),
    )
    .await;
    assert_eq!(deleted_index["deleted"], true);

    let observation = fixture.join();
    assert_eq!(observation.request_lines.len(), 10);
    assert_eq!(observation.api_key_count, 10);
    assert_eq!(observation.json_content_type_count, 5);
    assert!(!observation.final_index_exists);
    assert_eq!(observation.final_vector_count, 0);
    assert_eq!(
        observation.methods,
        [
            "GET", "GET", "POST", "GET", "POST", "POST", "GET", "POST", "POST", "DELETE"
        ]
    );
    assert_eq!(
        observation.paths,
        [
            "/indexes",
            "/indexes",
            "/indexes",
            "/indexes/acceptance-index",
            "/vectors/upsert",
            "/query",
            "/vectors/fetch?ids=vec-1&namespace=acceptance",
            "/vectors/delete",
            "/describe_index_stats",
            "/indexes/acceptance-index"
        ]
    );

    let cleanup = CleanupVerificationResult::new(
        "cleanup-index",
        INDEX_NAME,
        "index_and_vector_absence",
        "acceptance index is deleted and vector state is empty after teardown",
        json!({
            "index_exists": observation.final_index_exists,
            "vector_count": observation.final_vector_count
        }),
        true,
    );
    let evidence = json!({
        "schema_version": "fcp-pinecone-local-acceptance/v1",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "fixture_mode": "loopback_http",
        "transport": "pinecone_control_and_data_plane",
        "operations": [
            "pinecone.self_check:list_indexes",
            "pinecone.list_indexes",
            "pinecone.create_index",
            "pinecone.describe_index",
            "pinecone.upsert",
            "pinecone.query",
            "pinecone.fetch",
            "pinecone.delete",
            "pinecone.describe_index_stats",
            "pinecone.delete_index"
        ],
        "request_lines": observation.request_lines,
        "api_key_seen_for_all_requests": observation.api_key_count == 10,
        "json_content_type_seen_for_post_requests": observation.json_content_type_count == 5,
        "fixture_contract": fixture_contract.to_json(),
        "cleanup": cleanup,
    });

    assert_eq!(evidence["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(evidence["cleanup"]["passed"], true);
    assert!(
        !serde_json::to_string(&evidence)
            .expect("serialize evidence")
            .contains(TEST_API_KEY),
        "acceptance evidence must not expose Pinecone API key"
    );
}
