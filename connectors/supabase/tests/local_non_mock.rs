//! Local loopback acceptance coverage for the FCP Supabase connector.

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
    time::Duration,
};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InvokeRequest, OperationId, RequestId, ZoneId,
};
use fcp_supabase::connector::SupabaseConnector;
use serde_json::json;

const OP_STORAGE_UPLOAD: &str = "supabase.storage.upload";
const EXPECTED_PATH_PREFIX: &str = "/storage/v1/object/artifacts/reports/out";
const RESPONSE_BODY: &str = r#"{"Key":"artifacts/reports/out.txt"}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    authorization_seen: bool,
    api_key_seen: bool,
    content_type_seen: bool,
    upsert_seen: bool,
    body_seen: bool,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

impl LoopbackFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connector request");
            handle_request(stream)
        });

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

fn handle_request(mut stream: TcpStream) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let request = read_http_request(&mut stream);
    let request_line = request.lines().next().unwrap_or_default().to_string();
    let authorization_seen = request
        .lines()
        .any(|line| line.eq_ignore_ascii_case("authorization: bearer sb_secret_local"));
    let api_key_seen = request
        .lines()
        .any(|line| line.eq_ignore_ascii_case("apikey: sb_secret_local"));
    let content_type_seen = request
        .lines()
        .any(|line| line.eq_ignore_ascii_case("content-type: text/plain"));
    let upsert_seen = request
        .lines()
        .any(|line| line.eq_ignore_ascii_case("x-upsert: true"));
    let body_seen = request.ends_with("hello");

    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        RESPONSE_BODY.len(),
        RESPONSE_BODY
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        authorization_seen,
        api_key_seen,
        content_type_seen,
        upsert_seen,
        body_seen,
    }
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let mut header_end = None;
    let mut content_length = 0;

    loop {
        let bytes_read = stream.read(&mut chunk).expect("read connector request");
        if bytes_read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);

        if header_end.is_none()
            && let Some(position) = buffer.windows(4).position(|bytes| bytes == b"\r\n\r\n")
        {
            let end = position + 4;
            let headers = String::from_utf8_lossy(&buffer[..end]);
            content_length = parse_content_length(&headers);
            header_end = Some(end);
        }

        if let Some(end) = header_end
            && buffer.len() >= end + content_length
        {
            break;
        }
    }

    String::from_utf8_lossy(&buffer).into_owned()
}

fn parse_content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [19_u8; 32],
        capabilities_requested: vec![CapabilityId::from_static("supabase.storage")],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn capability_token(signing_key: &Ed25519SigningKey) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id("supabase.storage")
        .zone_id("z:work")
        .principal("user:local-non-mock")
        .operations(&[OP_STORAGE_UPLOAD])
        .issuer("node:local-non-mock")
        .validity(now, now + ChronoDuration::hours(1))
        .constraints_cbor(&cbor)
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

async fn setup_connector(base_url: &str) -> (SupabaseConnector, Ed25519SigningKey) {
    let mut connector = SupabaseConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "project_url": base_url,
            "api_key": "sb_secret_local",
            "schema": "public",
            "request_timeout_ms": 1_000
        }))
        .await
        .expect("configure connector");
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .expect("handshake connector");
    (connector, signing_key)
}

#[fcp_async_core::runtime::test]
async fn loopback_storage_upload_uses_production_client_request() {
    let fixture = LoopbackFixture::start();
    let (connector, signing_key) = setup_connector(fixture.base_url()).await;

    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("supabase-local-non-mock"),
            connector_id: ConnectorId::from_static("fcp.supabase"),
            operation: OperationId::from_static(OP_STORAGE_UPLOAD),
            zone_id: ZoneId::work(),
            input: json!({
                "bucket": "artifacts",
                "path": "reports/out.txt",
                "content_base64": BASE64_STANDARD.encode("hello"),
                "content_type": "text/plain",
                "upsert": true
            }),
            capability_token: capability_token(&signing_key),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        })
        .await
        .expect("upload storage object through connector");
    let observation = fixture.join();
    let result = response.result.expect("storage upload result");

    assert!(observation.request_line.starts_with("POST "));
    assert!(observation.request_line.contains(EXPECTED_PATH_PREFIX));
    assert!(observation.authorization_seen);
    assert!(observation.api_key_seen);
    assert!(observation.content_type_seen);
    assert!(observation.upsert_seen);
    assert!(observation.body_seen);
    assert_eq!(result["object"]["Key"], "artifacts/reports/out.txt");

    let artifact = json!({
        "connector": "supabase",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "fixture_mode": "loopback_http",
        "operation": OP_STORAGE_UPLOAD,
        "method": "POST",
        "path_prefix": EXPECTED_PATH_PREFIX,
        "request_line": observation.request_line,
        "authorization_seen": observation.authorization_seen,
        "api_key_seen": observation.api_key_seen,
        "content_type_seen": observation.content_type_seen,
        "upsert_seen": observation.upsert_seen,
        "body_seen": observation.body_seen,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
