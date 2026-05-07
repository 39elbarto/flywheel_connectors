#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration as StdDuration, Instant},
};

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_google_meet::{
    client::{GoogleMeetClient, GoogleMeetSpaceConfig},
    connector::GoogleMeetConnector,
    error::GoogleMeetError,
};
use fcp_prelude::{
    CapabilityConstraints, CapabilityToken, ConnectorId, FcpError, InstanceId, OperationId,
    RequestId, SimulateRequest, ZoneId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const CONNECTOR_ID: &str = "google-meet";
const CONNECTOR_MANIFEST_ID: &str = "fcp.google-meet";
const BEAD_ID: &str = "flywheel_connectors-4kw5f.11.4";
const FIXTURE_ACCESS_TOKEN: &str = "fixture-google-meet-oauth-token";
const SPACE_GET_OP: &str = "gmeet.space.get";
const SPACE_CREATE_OP: &str = "gmeet.space.create";
const SPACE_END_OP: &str = "gmeet.space.end_active_conference";
const READ_CAP: &str = "meet.space.read";
const CREATE_CAP: &str = "meet.space.create";
const END_CAP: &str = "meet.space.end";
const READONLY_SCOPE: &str = "https://www.googleapis.com/auth/meetings.space.readonly";
const CREATED_SCOPE: &str = "https://www.googleapis.com/auth/meetings.space.created";

#[derive(Debug, Clone)]
struct StubResponse {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: String,
}

#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    target: String,
    authorization: Option<String>,
    body: String,
    response_status: u16,
    response_body_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoogleMeetEvidenceLog {
    schema_version: String,
    bead_id: String,
    command_line: String,
    git_revision: String,
    connector_id: String,
    operation_id: String,
    capability: String,
    zone: String,
    instance_id: String,
    provider_fixture_id: String,
    meeting_id_hash: String,
    lifecycle_phase: String,
    latency_ms: u64,
    result: String,
    error_code: Option<String>,
    audit_receipt_id: String,
    cleanup_result: String,
    skip_reason: Option<String>,
    redaction: String,
}

fn json_response(body: impl Serialize) -> StubResponse {
    StubResponse {
        status: 200,
        headers: vec![("content-type", "application/json".to_string())],
        body: serde_json::to_string(&body).expect("serialize JSON response"),
    }
}

fn error_response(status: u16, body: impl Serialize) -> StubResponse {
    StubResponse {
        status,
        headers: vec![("content-type", "application/json".to_string())],
        body: serde_json::to_string(&body).expect("serialize error response"),
    }
}

fn rate_limited_response(retry_after_secs: u64) -> StubResponse {
    StubResponse {
        status: 429,
        headers: vec![
            ("content-type", "application/json".to_string()),
            ("retry-after", retry_after_secs.to_string()),
        ],
        body: serde_json::to_string(&json!({
            "error": { "message": "rate limit exceeded" }
        }))
        .expect("serialize rate limit response"),
    }
}

fn invalid_json_response() -> StubResponse {
    StubResponse {
        status: 200,
        headers: vec![("content-type", "application/json".to_string())],
        body: "{not-json".to_string(),
    }
}

fn spawn_loopback(
    responses: Vec<StubResponse>,
) -> (
    String,
    Arc<Mutex<Vec<RecordedRequest>>>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback HTTP listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let addr = listener.local_addr().expect("loopback listener address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);

    let handle = thread::spawn(move || {
        let deadline = Instant::now() + StdDuration::from_secs(5);
        let mut responses = responses.into_iter();
        while Instant::now() < deadline {
            let Some(response) = responses.next() else {
                return;
            };
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _peer)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "timed out waiting for request");
                        thread::sleep(StdDuration::from_millis(10));
                    }
                    Err(error) => {
                        assert_eq!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock,
                            "accept loopback request: {error}"
                        );
                    }
                }
            };
            stream.set_nonblocking(false).expect("set stream blocking");
            stream
                .set_read_timeout(Some(StdDuration::from_secs(1)))
                .expect("set stream read timeout");

            let mut buffer = [0_u8; 8192];
            let mut received = Vec::new();
            loop {
                let count = stream.read(&mut buffer).expect("read request");
                if count == 0 {
                    break;
                }
                received.extend_from_slice(&buffer[..count]);
                if received.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            let header_end = received
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
                .expect("request headers terminator");
            let header_bytes = &received[..header_end];
            let mut body = received[header_end..].to_vec();
            let request = String::from_utf8_lossy(header_bytes);
            let mut request_line = request
                .lines()
                .next()
                .expect("request line")
                .split_whitespace();
            let method = request_line.next().expect("request method").to_string();
            let target = request_line.next().expect("request target").to_string();
            let authorization = request.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("authorization")
                    .then(|| value.trim().to_string())
            });
            let content_length = request
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("content-length"))
                })
                .unwrap_or(0);
            while body.len() < content_length {
                let count = stream.read(&mut buffer).expect("read request body");
                if count == 0 {
                    break;
                }
                body.extend_from_slice(&buffer[..count]);
            }

            let response_status = response.status;
            let response_body_bytes = response.body.len();
            recorded
                .lock()
                .expect("record requests")
                .push(RecordedRequest {
                    method,
                    target,
                    authorization,
                    body: String::from_utf8_lossy(&body[..content_length.min(body.len())])
                        .to_string(),
                    response_status,
                    response_body_bytes,
                });

            let reason = match response.status {
                200 => "OK",
                401 => "Unauthorized",
                429 => "Too Many Requests",
                500 | 503 => "Provider Error",
                _ => "Stubbed",
            };
            let mut headers = String::new();
            for (name, value) in response.headers {
                headers.push_str(name);
                headers.push_str(": ");
                headers.push_str(&value);
                headers.push_str("\r\n");
            }
            let wire = format!(
                "HTTP/1.1 {} {}\r\n{}content-length: {}\r\nconnection: close\r\n\r\n{}",
                response.status,
                reason,
                headers,
                response.body.len(),
                response.body
            );
            stream
                .write_all(wire.as_bytes())
                .expect("write loopback response");
        }
        assert!(
            responses.next().is_none(),
            "loopback server did not receive every expected request"
        );
    });

    (format!("http://{addr}/v2"), requests, handle)
}

fn finish_loopback(handle: thread::JoinHandle<()>) {
    handle.join().expect("loopback server finished");
}

fn git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown-git-revision".to_string())
}

fn stable_hash(input: &str) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("fnv64:{hash:016x}")
}

fn elapsed_millis(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn evidence_log(
    operation_id: &str,
    capability: &str,
    meeting_id: &str,
    latency_ms: u64,
    result: &str,
    error_code: Option<String>,
    cleanup_result: &str,
    skip_reason: Option<&str>,
) -> GoogleMeetEvidenceLog {
    GoogleMeetEvidenceLog {
        schema_version: "google_meet_connector_local_evidence.v1".to_string(),
        bead_id: BEAD_ID.to_string(),
        command_line: "cargo test -p fcp-google-meet --test integration".to_string(),
        git_revision: git_revision(),
        connector_id: CONNECTOR_MANIFEST_ID.to_string(),
        operation_id: operation_id.to_string(),
        capability: capability.to_string(),
        zone: "z:work".to_string(),
        instance_id: stable_hash("google-meet-loopback-instance"),
        provider_fixture_id: "google-workspace-loopback-fixture.v1".to_string(),
        meeting_id_hash: stable_hash(meeting_id),
        lifecycle_phase: "invoke".to_string(),
        latency_ms,
        result: result.to_string(),
        error_code,
        audit_receipt_id: format!("audit:{BEAD_ID}:{operation_id}"),
        cleanup_result: cleanup_result.to_string(),
        skip_reason: skip_reason.map(str::to_string),
        redaction: "oauth_token_meeting_text_attendees_provider_body_paths_not_logged".to_string(),
    }
}

fn assert_log_shape_and_redaction(logs: &[GoogleMeetEvidenceLog]) {
    assert!(!logs.is_empty(), "expected at least one evidence log");
    for entry in logs {
        let value = serde_json::to_value(entry).expect("evidence log JSON");
        for field in [
            "command_line",
            "git_revision",
            "connector_id",
            "operation_id",
            "capability",
            "zone",
            "instance_id",
            "provider_fixture_id",
            "meeting_id_hash",
            "lifecycle_phase",
            "latency_ms",
            "result",
            "error_code",
            "audit_receipt_id",
            "cleanup_result",
            "skip_reason",
        ] {
            assert!(value.get(field).is_some(), "missing evidence field {field}");
        }
        eprintln!("{}", serde_json::to_string(entry).expect("log JSONL"));
    }

    let serialized = serde_json::to_string(logs).expect("serialize evidence logs");
    for forbidden in [
        FIXTURE_ACCESS_TOKEN,
        "Secret planning meeting",
        "alice@example.com",
        "bob@example.com",
        "provider raw body",
        "/Users/",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "evidence logs should not contain sensitive sentinel `{forbidden}`"
        );
    }
}

fn direct_auth_config(base_url: &str) -> Value {
    json!({
        "access_token": FIXTURE_ACCESS_TOKEN,
        "required_scopes": [READONLY_SCOPE, CREATED_SCOPE],
        "base_url": base_url,
        "drive_base_url": base_url,
    })
}

async fn configure_and_handshake(
    connector: &mut GoogleMeetConnector,
    signing_key: &Ed25519SigningKey,
    base_url: &str,
) {
    connector
        .handle_configure(direct_auth_config(base_url))
        .await
        .expect("configure should accept loopback base URL");
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": [READ_CAP, CREATE_CAP, END_CAP],
        }))
        .await
        .expect("handshake should complete");
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operation: &str,
    zone: &str,
    target_instance: Option<&str>,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let now = Utc::now();
    let mut builder = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone)
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints cbor");
    if let Some(instance) = target_instance {
        builder = builder.target_instance(instance);
    }
    CapabilityToken::from_raw(builder.sign(signing_key).expect("sign token"))
}

fn simulate_request_json(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operation: &str,
    zone: &str,
    target_instance: Option<&str>,
) -> Value {
    serde_json::to_value(SimulateRequest {
        r#type: "simulate".into(),
        id: RequestId::new(format!("sim-{operation}")),
        connector_id: ConnectorId::from_static(CONNECTOR_ID),
        operation: OperationId::new(operation).expect("valid operation id"),
        zone_id: ZoneId::work(),
        input: json!({}),
        capability_token: capability_token(
            signing_key,
            capability,
            operation,
            zone,
            target_instance,
        ),
        estimate_cost: false,
        check_availability: false,
        context: None,
        correlation_id: None,
    })
    .expect("serialize simulate request")
}

#[fcp_async_core::runtime::test]
async fn connector_lifecycle_uses_oauth_fixture_without_leaking_token() {
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = GoogleMeetConnector::new();

    let before = connector
        .handle_health()
        .await
        .expect("health before config");
    assert_eq!(before["status"], "not_configured");

    configure_and_handshake(&mut connector, &signing_key, "http://127.0.0.1:1/v2").await;
    let health = connector
        .handle_health()
        .await
        .expect("health after config");
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["service_identity"], "meet:v2");
    assert_eq!(health["metrics"]["requests_total"], 0);
    let self_check = connector
        .handle_self_check()
        .await
        .expect("self-check after config");
    assert_eq!(self_check["status"], "degraded");
    assert_eq!(self_check["reason_code"], "api_probe_deferred");

    let shutdown = connector
        .handle_shutdown(json!({ "reason": "connector-local integration test" }))
        .await
        .expect("shutdown should complete");
    assert_eq!(shutdown["status"], "shutdown");
    assert_eq!(
        shutdown["live_session_cleanup"]["no_orphan_supervised_tasks"],
        true
    );

    let wire = serde_json::to_string(&json!([health, self_check, shutdown]))
        .expect("serialize lifecycle results");
    assert!(!wire.contains(FIXTURE_ACCESS_TOKEN));
}

#[fcp_async_core::runtime::test]
async fn capability_tokens_deny_wrong_zone_or_instance_before_execution() {
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = GoogleMeetConnector::new();
    configure_and_handshake(&mut connector, &signing_key, "http://127.0.0.1:1/v2").await;

    let wrong_instance = InstanceId::new();
    let instance_denied = connector
        .handle_simulate(simulate_request_json(
            &signing_key,
            READ_CAP,
            SPACE_GET_OP,
            "z:work",
            Some(wrong_instance.as_str()),
        ))
        .await
        .expect("simulate wrong instance should return policy result");
    assert_eq!(instance_denied["would_succeed"], false);
    assert!(
        instance_denied["failure_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("Token instance mismatch"))
    );

    let wrong_zone = connector
        .handle_simulate(simulate_request_json(
            &signing_key,
            READ_CAP,
            SPACE_GET_OP,
            "z:private",
            Some(wrong_instance.as_str()),
        ))
        .await
        .expect("simulate wrong zone should return policy result");
    assert_eq!(wrong_zone["would_succeed"], false);
}

#[fcp_async_core::runtime::test]
async fn loopback_meeting_state_create_get_and_end_emits_redacted_jsonl() {
    let (base_url, requests, server) = spawn_loopback(vec![
        json_response(json!({
            "name": "spaces/abc-defg-hij",
            "meetingUri": "https://meet.google.com/abc-defg-hij",
            "meetingCode": "abc-defg-hij",
            "config": {
                "accessType": "TRUSTED",
                "entryPointAccess": "CREATOR_APP_ONLY"
            }
        })),
        json_response(json!({
            "name": "spaces/abc-defg-hij",
            "meetingUri": "https://meet.google.com/abc-defg-hij",
            "meetingCode": "abc-defg-hij",
            "activeConference": {
                "conferenceRecord": "conferenceRecords/rec-active"
            }
        })),
        json_response(json!({})),
    ]);
    let client = GoogleMeetClient::new(FIXTURE_ACCESS_TOKEN)
        .expect("client")
        .with_base_url(&base_url);
    let mut logs = Vec::new();

    let start = Instant::now();
    let created = client
        .create_space(Some(GoogleMeetSpaceConfig {
            access_type: Some("TRUSTED".to_string()),
            entry_point_access: Some("CREATOR_APP_ONLY".to_string()),
        }))
        .await
        .expect("create space through loopback");
    logs.push(evidence_log(
        SPACE_CREATE_OP,
        CREATE_CAP,
        &created.name,
        elapsed_millis(start),
        "ok",
        None,
        "space_created",
        None,
    ));
    assert_eq!(created.name, "spaces/abc-defg-hij");

    let start = Instant::now();
    let fetched = client
        .get_space("https://meet.google.com/abc-defg-hij")
        .await
        .expect("get space through loopback");
    logs.push(evidence_log(
        SPACE_GET_OP,
        READ_CAP,
        &fetched.name,
        elapsed_millis(start),
        "ok",
        None,
        "active_conference_observed",
        None,
    ));
    assert_eq!(
        fetched
            .active_conference
            .expect("active conference")
            .conference_record
            .as_deref(),
        Some("conferenceRecords/rec-active")
    );

    let start = Instant::now();
    let ended: Value = client
        .end_active_conference("spaces/abc-defg-hij")
        .await
        .expect("end active conference through loopback");
    logs.push(evidence_log(
        SPACE_END_OP,
        END_CAP,
        "spaces/abc-defg-hij",
        elapsed_millis(start),
        "ok",
        None,
        "active_conference_end_requested",
        None,
    ));
    assert!(ended.is_object());

    finish_loopback(server);
    let recorded = requests.lock().expect("requests").clone();
    assert_eq!(recorded.len(), 3);
    assert_eq!(recorded[0].method, "POST");
    assert_eq!(recorded[0].target, "/v2/spaces");
    assert!(recorded[0].body.contains("TRUSTED"));
    assert_eq!(recorded[1].method, "GET");
    assert!(
        recorded[1]
            .target
            .starts_with("/v2/spaces/abc%2Ddefg%2Dhij"),
        "unexpected get target: {}",
        recorded[1].target
    );
    assert_eq!(recorded[2].method, "POST");
    assert!(recorded[2].target.contains(":endActiveConference"));
    assert!(
        recorded
            .iter()
            .all(|request| request.authorization.is_some()),
        "all loopback requests should carry OAuth auth headers"
    );
    assert_log_shape_and_redaction(&logs);
}

#[fcp_async_core::runtime::test]
async fn loopback_errors_cover_auth_rate_provider_network_timeout_and_malformed_shapes() {
    let (base_url, requests, server) = spawn_loopback(vec![
        error_response(401, json!({ "error": { "message": "bad credentials" } })),
        rate_limited_response(7),
        error_response(503, json!({ "error": { "message": "provider raw body" } })),
        invalid_json_response(),
    ]);
    let client = GoogleMeetClient::new(FIXTURE_ACCESS_TOKEN)
        .expect("client")
        .with_base_url(&base_url);
    let mut logs = Vec::new();

    let start = Instant::now();
    let unauthorized = client.get_space("spaces/unauthorized").await.unwrap_err();
    logs.push(evidence_log(
        SPACE_GET_OP,
        READ_CAP,
        "spaces/unauthorized",
        elapsed_millis(start),
        "error",
        Some(unauthorized.to_fcp_error().error_code()),
        "no_cleanup_required",
        None,
    ));
    assert!(matches!(
        unauthorized.to_fcp_error(),
        FcpError::Unauthorized { code: 2001, .. }
    ));

    let start = Instant::now();
    let rate_limited = client.get_space("spaces/rate-limited").await.unwrap_err();
    logs.push(evidence_log(
        SPACE_GET_OP,
        READ_CAP,
        "spaces/rate-limited",
        elapsed_millis(start),
        "error",
        Some(rate_limited.to_fcp_error().error_code()),
        "retry_after_recorded",
        None,
    ));
    assert!(matches!(
        rate_limited,
        GoogleMeetError::RateLimited {
            retry_after_secs: 7,
        }
    ));

    let start = Instant::now();
    let provider = client.get_space("spaces/provider-error").await.unwrap_err();
    logs.push(evidence_log(
        SPACE_GET_OP,
        READ_CAP,
        "spaces/provider-error",
        elapsed_millis(start),
        "error",
        Some(provider.to_fcp_error().error_code()),
        "provider_error_mapped",
        None,
    ));
    assert!(provider.is_retryable());
    assert!(matches!(provider, GoogleMeetError::Api { code: 503, .. }));

    let start = Instant::now();
    let malformed = client.get_space("spaces/malformed-json").await.unwrap_err();
    logs.push(evidence_log(
        SPACE_GET_OP,
        READ_CAP,
        "spaces/malformed-json",
        elapsed_millis(start),
        "error",
        Some(malformed.to_fcp_error().error_code()),
        "malformed_response_rejected",
        None,
    ));
    assert!(matches!(malformed, GoogleMeetError::Json(_)));

    finish_loopback(server);
    let recorded = requests.lock().expect("requests").clone();
    assert_eq!(recorded.len(), 4);
    assert!(
        recorded
            .iter()
            .any(|request| request.response_status == 429)
    );
    assert!(
        recorded
            .iter()
            .any(|request| request.response_body_bytes > 0)
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind dropped network fixture");
    let dropped_addr = listener.local_addr().expect("dropped listener addr");
    drop(listener);
    let network_client = GoogleMeetClient::new(FIXTURE_ACCESS_TOKEN)
        .expect("network client")
        .with_base_url(format!("http://{dropped_addr}/v2"));
    let start = Instant::now();
    let network = network_client
        .get_space("spaces/network")
        .await
        .unwrap_err();
    logs.push(evidence_log(
        SPACE_GET_OP,
        READ_CAP,
        "spaces/network",
        elapsed_millis(start),
        "error",
        Some(network.to_fcp_error().error_code()),
        "network_error_mapped",
        None,
    ));
    assert!(matches!(network, GoogleMeetError::Http(_)));

    let timeout = GoogleMeetError::AsyncCheckpoint {
        checkpoint: "Google Meet request timeout budget".to_string(),
        message: "deadline elapsed".to_string(),
    };
    logs.push(evidence_log(
        SPACE_GET_OP,
        READ_CAP,
        "spaces/timeout",
        0,
        "error",
        Some(timeout.to_fcp_error().error_code()),
        "timeout_error_mapped",
        None,
    ));
    assert!(matches!(
        timeout.to_fcp_error(),
        FcpError::External {
            retryable: true,
            ..
        }
    ));

    assert_log_shape_and_redaction(&logs);
}

#[test]
fn absent_live_google_credentials_emit_structured_skip_artifact() {
    let skip_reason = if std::env::var("GOOGLE_MEET_LIVE_VERIFICATION").is_ok() {
        "live verification intentionally not executed by connector-local deterministic test"
    } else {
        "GOOGLE_MEET_LIVE_VERIFICATION not set"
    };
    let logs = vec![evidence_log(
        "gmeet.live_verification",
        "meeting.live_join",
        "https://meet.google.com/redacted-fixture",
        0,
        "skip",
        None,
        "no_live_cleanup_needed",
        Some(skip_reason),
    )];

    assert_eq!(logs[0].skip_reason.as_deref(), Some(skip_reason));
    assert_log_shape_and_redaction(&logs);
}
