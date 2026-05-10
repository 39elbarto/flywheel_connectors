//! Slack secretless connector E2E evidence for `flywheel_connectors-e99o6.1.5`.

#![cfg(feature = "slack")]
#![allow(clippy::similar_names, clippy::too_many_lines)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use fcp_crypto::test_utils::InMemorySecretRegistry;
use fcp_crypto::{CredentialIdHash, SecretFetchError, SecretFetchHook, ZeroizingSecret};
use fcp_host::{
    RuntimeEgressDecisionContext, RuntimeNetworkEnforcement, authorize_runtime_http_egress,
};
use fcp_manifest::NetworkConstraints;
use fcp_prelude::CredentialId;
use fcp_sandbox::{EgressHttpRequest, HttpHeader, SecretFetchCredentialInjector};
use fcp_slack::client::{SlackAuth, SlackClient};
use fcp_slack::connector::SlackConnector;
use fcp_testkit::{MockApiServer, RedactedReplayBundle, RedactedReplaySecret};
use serde_json::{Value, json};
use tracing::Subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

const PRIMARY_SLACK_BEARER: &str = "xoxb-b5-primary-secretless-fixture";
const ROTATED_SLACK_BEARER: &str = "xoxb-b5-rotated-secretless-fixture";
const OTHER_CONNECTOR_BEARER: &str = "ghp_b5_cross_connector_fixture";
const SLACK_AUTH_TEST_PATH: &str = "/auth.test";
const SLACK_POST_MESSAGE_PATH: &str = "/chat.postMessage";

#[derive(Clone, Default)]
struct CapturedEvents(Arc<Mutex<String>>);

impl CapturedEvents {
    fn snapshot(&self) -> String {
        self.0.lock().expect("captured events lock").clone()
    }
}

impl std::io::Write for CapturedEvents {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("captured events lock")
            .push_str(&String::from_utf8_lossy(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedEvents {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn install_capture() -> (CapturedEvents, tracing::subscriber::DefaultGuard) {
    let captured = CapturedEvents::default();
    let layer = fmt::layer()
        .with_writer(captured.clone())
        .with_target(true)
        .with_ansi(false);
    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::new("trace"))
        .with(layer);
    let guard = (Box::new(subscriber) as Box<dyn Subscriber + Send + Sync>).set_default();
    (captured, guard)
}

fn slack_auth_test_response() -> Value {
    json!({
        "ok": true,
        "url": "https://fcp-test.slack.com/",
        "team": "FCP Test",
        "user": "fcp-bot",
        "team_id": "T123",
        "user_id": "U123",
        "bot_id": "B123",
        "is_enterprise_install": false
    })
}

fn slack_post_message_response() -> Value {
    json!({
        "ok": true,
        "channel": "C123",
        "ts": "1710000000.000100",
        "message": {
            "type": "message",
            "user": "U123",
            "text": "hello from secretless slack",
            "ts": "1710000000.000100"
        }
    })
}

fn constraints_for(host: &str, port: u16) -> NetworkConstraints {
    NetworkConstraints {
        host_allow: vec![host.to_string()],
        port_allow: vec![port],
        ip_allow: vec![],
        cidr_deny: vec![],
        deny_localhost: false,
        deny_private_ranges: false,
        deny_tailnet_ranges: false,
        require_sni: false,
        spki_pins: vec![],
        deny_ip_literals: false,
        require_host_canonicalization: true,
        dns_max_ips: 16,
        max_redirects: 5,
        connect_timeout_ms: 10_000,
        total_timeout_ms: 60_000,
        max_response_bytes: 1_048_576,
    }
}

fn runtime_context<'a>(
    operation: &'a str,
    credential_allow: &'a [String],
) -> RuntimeEgressDecisionContext<'a> {
    RuntimeEgressDecisionContext {
        connector_id: "fcp.slack",
        operation,
        zone_id: "z:work",
        request_id: "req-secretless-slack-b5",
        correlation_id: Some("corr-secretless-slack-b5"),
        execution_mode: RuntimeNetworkEnforcement::HostEgressProxy,
        constraint_source: "secretless-slack-b5-e2e",
        credential_allow,
    }
}

fn connector_visible_request(base_url: &str, credential_id: &str) -> EgressHttpRequest {
    EgressHttpRequest {
        url: format!("{base_url}{SLACK_POST_MESSAGE_PATH}"),
        method: "POST".into(),
        headers: vec![
            HttpHeader {
                name: "X-FCP-Credential-ID".into(),
                value: credential_id.into(),
            },
            HttpHeader {
                name: "Content-Type".into(),
                value: "application/json".into(),
            },
        ],
        body: Some(br#"{"channel":"C123","text":"hello from secretless slack"}"#.to_vec()),
        credential_id: Some(credential_id.into()),
    }
}

async fn send_authorized_request(request: &EgressHttpRequest) -> reqwest::StatusCode {
    let method = reqwest::Method::from_bytes(request.method.as_bytes()).expect("valid method");
    let mut outbound = reqwest::Client::new().request(method, &request.url);
    for header in &request.headers {
        outbound = outbound.header(&header.name, &header.value);
    }
    if let Some(body) = &request.body {
        outbound = outbound.body(body.clone());
    }
    let response = outbound.send().await.expect("authorized request sent");
    let status = response.status();
    let _ = response.bytes().await.expect("response body drained");
    status
}

fn unique_replay_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("fcp-secretless-b5-slack-{nanos}"))
}

fn find_file_containing(dir: &Path, needle: &[u8]) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let metadata = entry.metadata().ok()?;
        if metadata.is_dir() {
            if let Some(hit) = find_file_containing(&path, needle) {
                return Some(hit);
            }
        } else if std::fs::read(&path).ok().is_some_and(|contents| {
            contents
                .windows(needle.len())
                .any(|window| window == needle)
        }) {
            return Some(path);
        }
    }
    None
}

fn request_header(request: &wiremock::Request, name: &str) -> Option<String> {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn assert_secret_absent(haystack: &str, secret: &str, evidence_name: &str) {
    assert!(
        !haystack.contains(secret),
        "{evidence_name} leaked raw secret {secret:?}: {haystack}"
    );
}

#[fcp_async_core::runtime::test]
async fn slack_secretless_gauntlet_records_redacted_replay() {
    let (captured, _guard) = install_capture();
    let replay_root = unique_replay_root();
    let credential_id = CredentialId::new();
    let credential_id_string = credential_id.to_string();
    let other_credential_id = CredentialId::new().to_string();
    let credential_hash = CredentialIdHash::from_credential_id(&credential_id_string).to_string();
    let other_credential_hash =
        CredentialIdHash::from_credential_id(&other_credential_id).to_string();
    let primary_secret = ZeroizingSecret::new(PRIMARY_SLACK_BEARER.as_bytes().to_vec());
    let rotated_secret = ZeroizingSecret::new(ROTATED_SLACK_BEARER.as_bytes().to_vec());
    let other_secret = ZeroizingSecret::new(OTHER_CONNECTOR_BEARER.as_bytes().to_vec());
    let redactions = [
        RedactedReplaySecret::new(&credential_hash, &primary_secret),
        RedactedReplaySecret::new(&credential_hash, &rotated_secret),
        RedactedReplaySecret::new(&other_credential_hash, &other_secret),
    ];
    let mut replay = RedactedReplayBundle::new_with_credentials(&replay_root, &redactions);

    let connector_mock = MockApiServer::start().await;
    connector_mock
        .expect_with_header(
            SLACK_AUTH_TEST_PATH,
            "X-FCP-Credential-ID",
            &credential_id_string,
            slack_auth_test_response(),
        )
        .await;
    let mut connector = SlackConnector::new();
    let configure_result = connector
        .handle_configure(json!({
            "credential_id": credential_id_string,
            "base_url": connector_mock.base_url()
        }))
        .await
        .expect("slack configure accepts credential_id");
    let client = SlackClient::new_with_auth(SlackAuth::CredentialId(credential_id))
        .expect("slack client builds")
        .with_base_url(connector_mock.base_url());
    let (auth_info, scopes) = client
        .auth_test()
        .await
        .expect("slack client can call credential-id mode");
    assert_eq!(auth_info.team_id, "T123");
    assert!(scopes.is_empty());
    let connector_requests = connector_mock.received_requests().await;
    assert_eq!(connector_requests.len(), 1);
    assert_eq!(
        request_header(&connector_requests[0], "x-fcp-credential-id").as_deref(),
        Some(credential_id_string.as_str())
    );
    assert_eq!(
        request_header(&connector_requests[0], "authorization"),
        None
    );
    replay.record_state(
        "slack_connector_blindness",
        json!({
            "configure_result": configure_result,
            "credential_id_hash": credential_hash,
            "connector_request_headers": format!("{:?}", connector_requests[0].headers),
            "raw_secret_control": PRIMARY_SLACK_BEARER
        }),
    );

    let registry = Arc::new(InMemorySecretRegistry::new());
    registry.insert(
        credential_id_string.clone(),
        PRIMARY_SLACK_BEARER.as_bytes().to_vec(),
    );
    registry.insert(
        other_credential_id.clone(),
        OTHER_CONNECTOR_BEARER.as_bytes().to_vec(),
    );
    let injector = SecretFetchCredentialInjector::new(registry.clone())
        .with_allowed_hosts(credential_id_string.clone(), ["127.0.0.1"])
        .with_allowed_hosts(other_credential_id.clone(), ["127.0.0.1"]);
    let host_mock = MockApiServer::start().await;
    host_mock
        .expect_with_header(
            SLACK_POST_MESSAGE_PATH,
            "Authorization",
            &format!("Bearer {PRIMARY_SLACK_BEARER}"),
            slack_post_message_response(),
        )
        .await;
    host_mock
        .expect_with_header(
            SLACK_POST_MESSAGE_PATH,
            "Authorization",
            &format!("Bearer {ROTATED_SLACK_BEARER}"),
            slack_post_message_response(),
        )
        .await;

    let constraints = constraints_for("127.0.0.1", host_mock.address().port());
    let credential_allow = vec![credential_id_string.clone()];
    let context = runtime_context("slack.post_message", &credential_allow);
    let mut first_request = connector_visible_request(&host_mock.base_url(), &credential_id_string);
    assert!(
        !first_request
            .headers
            .iter()
            .any(|header| header.value == PRIMARY_SLACK_BEARER),
        "connector-visible host request must not contain raw secret bytes"
    );
    let first_decision =
        authorize_runtime_http_egress(&context, &constraints, &mut first_request, &injector)
            .expect("primary slack egress request is authorized");
    assert!(first_decision.credential_injected);
    assert!(first_request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("authorization")
            && header.value == format!("Bearer {PRIMARY_SLACK_BEARER}")
    }));
    assert!(
        !first_request
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("x-fcp-credential-id"))
    );
    assert_eq!(
        send_authorized_request(&first_request).await,
        reqwest::StatusCode::OK
    );

    registry
        .rotate(
            &credential_id_string,
            ZeroizingSecret::new(ROTATED_SLACK_BEARER.as_bytes().to_vec()),
        )
        .expect("credential rotates");
    let mut rotated_request =
        connector_visible_request(&host_mock.base_url(), &credential_id_string);
    let rotated_decision =
        authorize_runtime_http_egress(&context, &constraints, &mut rotated_request, &injector)
            .expect("rotated slack egress request is authorized");
    assert!(rotated_decision.credential_injected);
    assert!(rotated_request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("authorization")
            && header.value == format!("Bearer {ROTATED_SLACK_BEARER}")
    }));
    assert_eq!(
        send_authorized_request(&rotated_request).await,
        reqwest::StatusCode::OK
    );
    assert_eq!(registry.fetch_count_for(&credential_id_string), 2);
    replay.record_event(
        "fcp.test.secretless.slack.wire_and_rotation.pass",
        json!({
            "credential_id_hash": credential_hash,
            "primary_wire_authorization": format!("Bearer {PRIMARY_SLACK_BEARER}"),
            "rotated_wire_authorization": format!("Bearer {ROTATED_SLACK_BEARER}"),
            "fetch_count": registry.fetch_count_for(&credential_id_string),
            "host_decisions": [
                format!("{first_decision:?}"),
                format!("{rotated_decision:?}")
            ]
        }),
    );

    let mut denied_request = connector_visible_request(&host_mock.base_url(), &other_credential_id);
    let denied_error =
        authorize_runtime_http_egress(&context, &constraints, &mut denied_request, &injector)
            .expect_err("cross-connector credential id is not authorized for slack operation")
            .to_string();
    assert_eq!(registry.fetch_count_for(&other_credential_id), 0);
    assert_secret_absent(
        &denied_error,
        OTHER_CONNECTOR_BEARER,
        "cross-connector denial",
    );
    replay.record_event(
        "fcp.test.secretless.slack.cross_connector_bleed.pass",
        json!({
            "other_credential_id_hash": other_credential_hash,
            "other_secret_control": OTHER_CONNECTOR_BEARER,
            "denied_error": denied_error,
            "other_fetch_count": registry.fetch_count_for(&other_credential_id)
        }),
    );

    let not_found = SecretFetchError::not_found(&credential_id_string);
    let not_found_again = SecretFetchError::not_found(&credential_id_string);
    assert_eq!(not_found, not_found_again);
    let not_found_display = not_found.to_string();
    let not_found_debug = format!("{not_found:?}");
    assert_secret_absent(&not_found_display, PRIMARY_SLACK_BEARER, "error Display");
    assert_secret_absent(&not_found_debug, PRIMARY_SLACK_BEARER, "error Debug");
    assert!(
        !not_found_display.contains(&credential_id_string),
        "SecretFetchError Display must redact credential id"
    );
    assert!(not_found_display.contains(&credential_hash));
    let registry_debug = format!("{registry:?}");
    let injector_debug = format!("{injector:?}");
    for evidence in [&registry_debug, &injector_debug, &not_found_debug] {
        assert_secret_absent(evidence, PRIMARY_SLACK_BEARER, "debug evidence");
        assert_secret_absent(evidence, ROTATED_SLACK_BEARER, "debug evidence");
        assert_secret_absent(evidence, OTHER_CONNECTOR_BEARER, "debug evidence");
    }
    replay.record_event(
        "fcp.test.secretless.slack.error_debug_eq_redaction.pass",
        json!({
            "not_found_display": not_found_display,
            "not_found_debug": not_found_debug,
            "registry_debug": registry_debug,
            "injector_debug": injector_debug,
            "eq_redaction_checked": true
        }),
    );

    let trace_snapshot = captured.snapshot();
    assert!(
        trace_snapshot.contains("runtime_egress_policy_decision"),
        "host egress audit trace must be emitted"
    );
    assert_secret_absent(&trace_snapshot, PRIMARY_SLACK_BEARER, "trace output");
    assert_secret_absent(&trace_snapshot, ROTATED_SLACK_BEARER, "trace output");
    assert_secret_absent(&trace_snapshot, OTHER_CONNECTOR_BEARER, "trace output");
    replay.record_event(
        "fcp.test.secretless.slack.tracing_and_audit.pass",
        json!({
            "trace_snapshot": trace_snapshot,
            "process_memory_best_effort": {
                "portable_scan": "not_available",
                "os": std::env::consts::OS,
                "evidence": "secret lifetime bounded to ZeroizingSecret fetch scope plus trace/disk/debug scans"
            }
        }),
    );

    let rendered = replay.redacted_jsonl();
    for secret in [
        PRIMARY_SLACK_BEARER,
        ROTATED_SLACK_BEARER,
        OTHER_CONNECTOR_BEARER,
    ] {
        assert_secret_absent(&rendered, secret, "pre-commit replay JSONL");
    }
    let replay_path = replay.commit().expect("redacted replay commits to disk");
    let persisted = std::fs::read_to_string(&replay_path).expect("replay evidence readable");
    for secret in [
        PRIMARY_SLACK_BEARER,
        ROTATED_SLACK_BEARER,
        OTHER_CONNECTOR_BEARER,
    ] {
        assert_secret_absent(&persisted, secret, "persisted replay JSONL");
        let disk_hit = find_file_containing(&replay_root, secret.as_bytes());
        assert!(
            disk_hit.is_none(),
            "raw secret appeared on disk at {}",
            disk_hit.unwrap().display()
        );
    }
    assert!(
        persisted.contains("<REDACTED:"),
        "replay evidence must include explicit redaction markers"
    );
}
