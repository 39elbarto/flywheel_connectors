//! Local loopback acceptance coverage for the Voyage connector.

#![allow(
    clippy::future_not_send,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError, InstanceId,
};
use fcp_voyage::{
    DEFAULT_EMBEDDING_MODEL, DEFAULT_RERANK_MODEL, VoyageConnector,
    connector::{test_handshake_request, test_invoke_request},
};
use serde_json::{Value, json};

const CONNECTOR: &str = "voyage";
const PACKAGE: &str = "fcp-voyage";
const BEAD_ID: &str = "flywheel_connectors-4kw5f.12";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const API_KEY: &str = "local_voyage_api_key";

const OP_EMBEDDINGS: &str = "voyage.embeddings.create";
const OP_RERANK: &str = "voyage.rerank";

const CAP_EMBEDDINGS: &str = "voyage.embeddings";
const CAP_RERANK: &str = "voyage.rerank";
const CAP_MODELS: &str = "voyage.models.read";

const EMBEDDINGS_RESPONSE: &str = r#"{
  "object": "list",
  "model": "voyage-3.5",
  "data": [
    {
      "object": "embedding",
      "index": 0,
      "embedding": [0.11, 0.22, 0.33]
    }
  ],
  "usage": {
    "prompt_tokens": 6,
    "total_tokens": 6
  }
}"#;

const RERANK_RESPONSE: &str = r#"{
  "object": "list",
  "model": "rerank-2.5",
  "data": [
    {
      "index": 1,
      "relevance_score": 0.91
    }
  ],
  "usage": {
    "total_tokens": 8
  }
}"#;

#[derive(Clone, Copy)]
struct HttpResponse {
    status: &'static str,
    body: &'static str,
}

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    authorization_seen: bool,
    accept_json_seen: bool,
    content_type_json_seen: bool,
    user_agent_seen: bool,
    body: Value,
}

struct LoopbackServer {
    base_url: String,
    handle: Option<JoinHandle<Vec<FixtureObservation>>>,
}

impl LoopbackServer {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            responses
                .iter()
                .map(|response| {
                    let (stream, _) = listener.accept().expect("accept connector request");
                    handle_request(stream, *response)
                })
                .collect()
        });

        Self {
            base_url: format!("http://{address}/v1"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> Vec<FixtureObservation> {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_request(mut stream: TcpStream, response: HttpResponse) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let request = read_complete_request(&mut stream);
    let header_end = find_header_end(&request).expect("request contains complete headers");
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let body_start = header_end + b"\r\n\r\n".len();
    let body = if body_start < request.len() {
        serde_json::from_slice(&request[body_start..]).expect("request body is JSON")
    } else {
        Value::Null
    };
    let request_line = headers.lines().next().unwrap_or_default().to_string();
    let authorization_seen = header_equals(&headers, "authorization", &format!("Bearer {API_KEY}"));
    let accept_json_seen = header_contains(&headers, "accept", "application/json");
    let content_type_json_seen = header_contains(&headers, "content-type", "application/json");
    let user_agent_seen = header_contains(&headers, "user-agent", "fcp-voyage/0.1.0");

    write!(
        stream,
        "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response.status,
        response.body.len(),
        response.body
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        authorization_seen,
        accept_json_seen,
        content_type_json_seen,
        user_agent_seen,
        body,
    }
}

fn read_complete_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector closed before request completed");
        request.extend_from_slice(&buffer[..bytes_read]);
        assert!(request.len() < 64 * 1024, "request should stay bounded");

        if let Some(header_end) = find_header_end(&request) {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = parse_content_length(&headers).unwrap_or(0);
            let expected_len = header_end + b"\r\n\r\n".len() + content_length;
            if request.len() >= expected_len {
                request.truncate(expected_len);
                return request;
            }
        }
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().expect("content-length is numeric"))
    })
}

fn header_equals(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name) && value.trim() == expected_value
    })
}

fn header_contains(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name)
            && value
                .to_ascii_lowercase()
                .contains(&expected_value.to_ascii_lowercase())
    })
}

async fn setup_connector(base_url: &str, capabilities: &[&'static str]) -> ConfiguredVoyage {
    let mut connector = VoyageConnector::new();
    connector
        .handle_configure(json!({
            "api_key": API_KEY,
            "base_url": base_url,
            "request_timeout_ms": 5_000
        }))
        .await
        .expect("configure Voyage connector");
    let signing_key = Ed25519SigningKey::generate();
    let requested = capabilities
        .iter()
        .map(|capability| CapabilityId::from_static(capability))
        .collect();
    connector
        .handshake(test_handshake_request(
            requested,
            signing_key.verifying_key().to_bytes(),
        ))
        .await
        .expect("handshake Voyage connector");

    ConfiguredVoyage {
        connector,
        signing_key,
    }
}

struct ConfiguredVoyage {
    connector: VoyageConnector,
    signing_key: Ed25519SigningKey,
}

async fn invoke(
    connector: &VoyageConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let grant = valid_grant(signing_key, connector.instance_id(), capability, operation);
    let response = connector
        .invoke(test_invoke_request(
            "voyage-local-non-mock",
            operation,
            input,
            grant,
        ))
        .await?;
    if let Some(error) = response.error {
        Err(error)
    } else {
        response.result.ok_or_else(|| FcpError::Internal {
            message: "Voyage invoke response had neither result nor error".into(),
        })
    }
}

fn valid_grant(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints serialize");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:voyage-local-non-mock")
        .operations(&[operation])
        .issuer("node:voyage-local-non-mock")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability grant should sign");
    CapabilityToken::from_raw(cose)
}

fn assert_number_array(actual: &Value, expected: &[f64]) {
    let actual = actual.as_array().expect("numeric result field is an array");
    assert_eq!(actual.len(), expected.len());
    for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
        let actual = actual.as_f64().expect("result component is numeric");
        assert!(
            (actual - expected).abs() < 1.0e-6,
            "result component {index} differs: {actual} != {expected}"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_embeddings_posts_body_and_maps_output() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "200 OK",
        body: EMBEDDINGS_RESPONSE,
    }]);
    let configured = setup_connector(server.base_url(), &[CAP_EMBEDDINGS]).await;

    let result = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({
            "input": ["local acceptance document"],
            "input_type": "document",
            "output_dimension": 512
        }),
    )
    .await
    .expect("embeddings invoke should succeed");
    let observations = server.join();
    let observation = observations
        .first()
        .expect("one embeddings request observed");

    assert_eq!(observation.request_line, "POST /v1/embeddings HTTP/1.1");
    assert!(observation.authorization_seen);
    assert!(observation.accept_json_seen);
    assert!(observation.content_type_json_seen);
    assert!(observation.user_agent_seen);
    assert_eq!(observation.body["model"], DEFAULT_EMBEDDING_MODEL);
    assert_eq!(
        observation.body["input"],
        json!(["local acceptance document"])
    );
    assert_eq!(observation.body["input_type"], "document");
    assert_eq!(observation.body["output_dimension"], 512);
    assert_eq!(result["model"], DEFAULT_EMBEDDING_MODEL);
    assert_eq!(result["data"][0]["index"], 0);
    assert_number_array(&result["data"][0]["embedding"], &[0.11, 0.22, 0.33]);

    let input_count = observation.body["input"]
        .as_array()
        .map_or(0, std::vec::Vec::len);
    let artifact = json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "bead_id": BEAD_ID,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "case": "embeddings",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_EMBEDDINGS,
        "request_response_boundary": {
            "method": "POST",
            "path": "/v1/embeddings",
            "input_count": input_count,
            "input_type": observation.body["input_type"].as_str().unwrap_or("<missing>"),
            "output_dimension": observation.body["output_dimension"].as_u64().unwrap_or_default(),
            "model": observation.body["model"].as_str().unwrap_or("<missing>"),
            "raw_input_logged": false
        },
        "auth_gate": {
            "mode": "bearer_api_key",
            "credentials_used": true,
            "authorization_header_verified": observation.authorization_seen,
            "secret_material_logged": false
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    let rendered = artifact.to_string();
    assert!(!rendered.contains(API_KEY));
    assert!(!rendered.contains("local acceptance document"));
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rerank_posts_body_and_maps_output() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "200 OK",
        body: RERANK_RESPONSE,
    }]);
    let configured = setup_connector(server.base_url(), &[CAP_RERANK]).await;

    let result = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_RERANK,
        CAP_RERANK,
        json!({
            "query": "local query",
            "documents": ["first document", "second document"],
            "top_k": 1,
            "return_documents": false
        }),
    )
    .await
    .expect("rerank invoke should succeed");
    let observations = server.join();
    let observation = observations.first().expect("one rerank request observed");

    assert_eq!(observation.request_line, "POST /v1/rerank HTTP/1.1");
    assert!(observation.authorization_seen);
    assert!(observation.accept_json_seen);
    assert!(observation.content_type_json_seen);
    assert!(observation.user_agent_seen);
    assert_eq!(observation.body["model"], DEFAULT_RERANK_MODEL);
    assert_eq!(observation.body["query"], "local query");
    assert_eq!(
        observation.body["documents"],
        json!(["first document", "second document"])
    );
    assert_eq!(observation.body["top_k"], 1);
    assert_eq!(observation.body["return_documents"], false);
    assert_eq!(result["model"], DEFAULT_RERANK_MODEL);
    assert_eq!(result["result_count"], 1);
    assert_eq!(result["raw"]["data"][0]["index"], 1);
    assert_eq!(result["raw"]["data"][0]["relevance_score"], 0.91);

    let document_count = observation.body["documents"]
        .as_array()
        .map_or(0, std::vec::Vec::len);
    let artifact = json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "bead_id": BEAD_ID,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "case": "rerank",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_RERANK,
        "request_response_boundary": {
            "method": "POST",
            "path": "/v1/rerank",
            "document_count": document_count,
            "top_k": observation.body["top_k"].as_u64().unwrap_or_default(),
            "return_documents": observation.body["return_documents"].as_bool().unwrap_or_default(),
            "model": observation.body["model"].as_str().unwrap_or("<missing>"),
            "raw_query_logged": false,
            "raw_documents_logged": false
        },
        "auth_gate": {
            "mode": "bearer_api_key",
            "credentials_used": true,
            "authorization_header_verified": observation.authorization_seen,
            "secret_material_logged": false
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    let rendered = artifact.to_string();
    assert!(!rendered.contains(API_KEY));
    assert!(!rendered.contains("local query"));
    assert!(!rendered.contains("first document"));
    assert!(!rendered.contains("second document"));
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_wrong_capability_fails_before_egress() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind no-egress listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let base_url = format!(
        "http://{}/v1",
        listener.local_addr().expect("read listener address")
    );
    let configured = setup_connector(&base_url, &[CAP_MODELS]).await;

    let error = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_EMBEDDINGS,
        CAP_MODELS,
        json!({"input": "should never reach loopback"}),
    )
    .await
    .expect_err("wrong capability should fail before egress");

    assert!(
        matches!(
            error,
            FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
        ),
        "expected capability denial, got {error:?}"
    );
    let accept_result = listener.accept();
    assert!(
        matches!(accept_result, Err(ref err) if err.kind() == ErrorKind::WouldBlock),
        "connector should not have opened a loopback connection; got {accept_result:?}"
    );

    let artifact = json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "bead_id": BEAD_ID,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "case": "wrong_capability_no_egress",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_EMBEDDINGS,
        "wrong_capability": CAP_MODELS,
        "request_response_boundary": {
            "method": "none",
            "path": "none",
            "egress_observed": false
        },
        "result": "passed"
    });
    let rendered = artifact.to_string();
    assert!(!rendered.contains("should never reach loopback"));
    println!("{artifact}");
}
