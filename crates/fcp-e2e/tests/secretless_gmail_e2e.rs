//! Gmail secretless connector E2E evidence for `flywheel_connectors-e99o6.1.5`.

#![cfg(feature = "gmail")]
#![allow(clippy::similar_names, clippy::too_many_lines)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{Duration, Utc};
use fcp_crypto::test_utils::InMemorySecretRegistry;
use fcp_crypto::{
    CredentialIdHash, SecretFetchError, SecretFetchHook, ZeroizingSecret,
    cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey,
};
use fcp_gmail::connector::GmailConnector;
use fcp_host::{
    RuntimeEgressDecisionContext, RuntimeNetworkEnforcement, authorize_runtime_http_egress,
};
use fcp_manifest::NetworkConstraints;
use fcp_prelude::{CapabilityConstraints, CapabilityToken, CredentialId};
use fcp_sandbox::{EgressHttpRequest, HttpHeader, SecretFetchCredentialInjector};
use fcp_testkit::{MockApiServer, RedactedReplayBundle, RedactedReplaySecret};
use serde_json::{Value, json};
use tracing::Subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

const PRIMARY_GMAIL_ACCESS_TOKEN: &str = "ya29.b5-primary-secretless-access-token";
const ROTATED_GMAIL_ACCESS_TOKEN: &str = "ya29.b5-rotated-secretless-access-token";
const GMAIL_REFRESH_TOKEN: &str = "1//b5-gmail-refresh-token-secret";
const OTHER_CONNECTOR_BEARER: &str = "xoxb-b5-cross-connector-fixture";
const GMAIL_LABELS_PATH: &str = "/users/me/labels";

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

fn gmail_labels_response() -> Value {
    json!({
        "labels": [
            {
                "id": "INBOX",
                "name": "INBOX",
                "type": "system",
                "messagesTotal": 1,
                "messagesUnread": 0,
                "threadsTotal": 1,
                "threadsUnread": 0
            }
        ]
    })
}

fn capability_for_operation(operation: &str) -> &str {
    match operation {
        "gmail.send_message" | "gmail.send_draft" => "gmail.send",
        "gmail.sync_history" => "gmail.history.read",
        "gmail.modify_message" | "gmail.get_draft" | "gmail.create_draft" => "gmail.write",
        "gmail.trash_message" => "gmail.delete",
        _ => "gmail.read",
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    connector: &GmailConnector,
    operation: &str,
) -> CapabilityToken {
    let capability = capability_for_operation(operation);
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(connector.instance_id().as_str())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints are valid CBOR")
        .sign(signing_key)
        .expect("capability token signs");
    CapabilityToken::from_raw(cose)
}

async fn setup_handshake(
    connector: &mut GmailConnector,
    capabilities: &[&str],
) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let mapped: Vec<&str> = capabilities
        .iter()
        .map(|capability| capability_for_operation(capability))
        .collect();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": mapped
        }))
        .await
        .expect("gmail handshake should succeed");

    signing_key
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
        connector_id: "fcp.gmail",
        operation,
        zone_id: "z:work",
        request_id: "req-secretless-gmail-b5",
        correlation_id: Some("corr-secretless-gmail-b5"),
        execution_mode: RuntimeNetworkEnforcement::HostEgressProxy,
        constraint_source: "secretless-gmail-b5-e2e",
        credential_allow,
    }
}

fn connector_visible_request(base_url: &str, credential_id: &str) -> EgressHttpRequest {
    EgressHttpRequest {
        url: format!("{base_url}{GMAIL_LABELS_PATH}"),
        method: "GET".into(),
        headers: vec![HttpHeader {
            name: "X-FCP-Credential-ID".into(),
            value: credential_id.into(),
        }],
        body: None,
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
    std::env::temp_dir().join(format!("fcp-secretless-b5-gmail-{nanos}"))
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
async fn gmail_secretless_gauntlet_records_redacted_replay() {
    let (captured, _guard) = install_capture();
    let replay_root = unique_replay_root();
    let credential_id = CredentialId::new();
    let credential_id_string = credential_id.to_string();
    let other_credential_id = CredentialId::new().to_string();
    let credential_hash = CredentialIdHash::from_credential_id(&credential_id_string).to_string();
    let other_credential_hash =
        CredentialIdHash::from_credential_id(&other_credential_id).to_string();
    let primary_secret = ZeroizingSecret::new(PRIMARY_GMAIL_ACCESS_TOKEN.as_bytes().to_vec());
    let rotated_secret = ZeroizingSecret::new(ROTATED_GMAIL_ACCESS_TOKEN.as_bytes().to_vec());
    let refresh_secret = ZeroizingSecret::new(GMAIL_REFRESH_TOKEN.as_bytes().to_vec());
    let other_secret = ZeroizingSecret::new(OTHER_CONNECTOR_BEARER.as_bytes().to_vec());
    let redactions = [
        RedactedReplaySecret::new(&credential_hash, &primary_secret),
        RedactedReplaySecret::new(&credential_hash, &rotated_secret),
        RedactedReplaySecret::new(&credential_hash, &refresh_secret),
        RedactedReplaySecret::new(&other_credential_hash, &other_secret),
    ];
    let mut replay = RedactedReplayBundle::new_with_credentials(&replay_root, &redactions);

    let connector_mock = MockApiServer::start().await;
    connector_mock
        .expect_with_header(
            GMAIL_LABELS_PATH,
            "X-FCP-Credential-ID",
            &credential_id_string,
            gmail_labels_response(),
        )
        .await;
    let mut connector = GmailConnector::new();
    let configure_result = connector
        .handle_configure(json!({
            "credential_id": credential_id_string,
            "base_url": connector_mock.base_url()
        }))
        .await
        .expect("gmail configure accepts credential_id");
    let signing_key = setup_handshake(&mut connector, &["gmail.read"]).await;
    let capability_token = generate_valid_token(&signing_key, &connector, "gmail.list_labels");
    let invoke_result = connector
        .handle_invoke(json!({
            "operation": "gmail.list_labels",
            "input": {},
            "capability_token": capability_token
        }))
        .await
        .expect("gmail connector can invoke credential-id mode");
    assert_eq!(
        invoke_result["labels"]
            .as_array()
            .expect("labels array")
            .len(),
        1
    );
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
        "gmail_connector_blindness",
        json!({
            "configure_result": configure_result,
            "invoke_result": invoke_result,
            "credential_id_hash": credential_hash,
            "connector_request_headers": format!("{:?}", connector_requests[0].headers),
            "raw_access_token_control": PRIMARY_GMAIL_ACCESS_TOKEN,
            "raw_refresh_token_control": GMAIL_REFRESH_TOKEN
        }),
    );

    let registry = Arc::new(InMemorySecretRegistry::new());
    registry.insert(
        credential_id_string.clone(),
        PRIMARY_GMAIL_ACCESS_TOKEN.as_bytes().to_vec(),
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
            GMAIL_LABELS_PATH,
            "Authorization",
            &format!("Bearer {PRIMARY_GMAIL_ACCESS_TOKEN}"),
            gmail_labels_response(),
        )
        .await;
    host_mock
        .expect_with_header(
            GMAIL_LABELS_PATH,
            "Authorization",
            &format!("Bearer {ROTATED_GMAIL_ACCESS_TOKEN}"),
            gmail_labels_response(),
        )
        .await;

    let constraints = constraints_for("127.0.0.1", host_mock.address().port());
    let credential_allow = vec![credential_id_string.clone()];
    let context = runtime_context("gmail.list_labels", &credential_allow);
    let mut first_request = connector_visible_request(&host_mock.base_url(), &credential_id_string);
    assert!(
        !first_request
            .headers
            .iter()
            .any(|header| header.value == PRIMARY_GMAIL_ACCESS_TOKEN),
        "connector-visible host request must not contain raw secret bytes"
    );
    let first_decision =
        authorize_runtime_http_egress(&context, &constraints, &mut first_request, &injector)
            .expect("primary gmail egress request is authorized");
    assert!(first_decision.credential_injected);
    assert!(first_request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("authorization")
            && header.value == format!("Bearer {PRIMARY_GMAIL_ACCESS_TOKEN}")
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
            ZeroizingSecret::new(ROTATED_GMAIL_ACCESS_TOKEN.as_bytes().to_vec()),
        )
        .expect("credential rotates");
    let mut rotated_request =
        connector_visible_request(&host_mock.base_url(), &credential_id_string);
    let rotated_decision =
        authorize_runtime_http_egress(&context, &constraints, &mut rotated_request, &injector)
            .expect("rotated gmail egress request is authorized");
    assert!(rotated_decision.credential_injected);
    assert!(rotated_request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("authorization")
            && header.value == format!("Bearer {ROTATED_GMAIL_ACCESS_TOKEN}")
    }));
    assert_eq!(
        send_authorized_request(&rotated_request).await,
        reqwest::StatusCode::OK
    );
    assert_eq!(registry.fetch_count_for(&credential_id_string), 2);
    replay.record_event(
        "fcp.test.secretless.gmail.wire_and_rotation.pass",
        json!({
            "credential_id_hash": credential_hash,
            "primary_wire_authorization": format!("Bearer {PRIMARY_GMAIL_ACCESS_TOKEN}"),
            "rotated_wire_authorization": format!("Bearer {ROTATED_GMAIL_ACCESS_TOKEN}"),
            "refresh_token_redaction_hash": credential_hash,
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
            .expect_err("cross-connector credential id is not authorized for gmail operation")
            .to_string();
    assert_eq!(registry.fetch_count_for(&other_credential_id), 0);
    assert_secret_absent(
        &denied_error,
        OTHER_CONNECTOR_BEARER,
        "cross-connector denial",
    );
    replay.record_event(
        "fcp.test.secretless.gmail.cross_connector_bleed.pass",
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
    assert_secret_absent(
        &not_found_display,
        PRIMARY_GMAIL_ACCESS_TOKEN,
        "error Display",
    );
    assert_secret_absent(&not_found_debug, PRIMARY_GMAIL_ACCESS_TOKEN, "error Debug");
    assert!(
        !not_found_display.contains(&credential_id_string),
        "SecretFetchError Display must redact credential id"
    );
    assert!(not_found_display.contains(&credential_hash));
    let registry_debug = format!("{registry:?}");
    let injector_debug = format!("{injector:?}");
    for evidence in [&registry_debug, &injector_debug, &not_found_debug] {
        assert_secret_absent(evidence, PRIMARY_GMAIL_ACCESS_TOKEN, "debug evidence");
        assert_secret_absent(evidence, ROTATED_GMAIL_ACCESS_TOKEN, "debug evidence");
        assert_secret_absent(evidence, GMAIL_REFRESH_TOKEN, "debug evidence");
        assert_secret_absent(evidence, OTHER_CONNECTOR_BEARER, "debug evidence");
    }
    replay.record_event(
        "fcp.test.secretless.gmail.error_debug_eq_redaction.pass",
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
    assert_secret_absent(&trace_snapshot, PRIMARY_GMAIL_ACCESS_TOKEN, "trace output");
    assert_secret_absent(&trace_snapshot, ROTATED_GMAIL_ACCESS_TOKEN, "trace output");
    assert_secret_absent(&trace_snapshot, GMAIL_REFRESH_TOKEN, "trace output");
    assert_secret_absent(&trace_snapshot, OTHER_CONNECTOR_BEARER, "trace output");
    replay.record_event(
        "fcp.test.secretless.gmail.tracing_and_audit.pass",
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
        PRIMARY_GMAIL_ACCESS_TOKEN,
        ROTATED_GMAIL_ACCESS_TOKEN,
        GMAIL_REFRESH_TOKEN,
        OTHER_CONNECTOR_BEARER,
    ] {
        assert_secret_absent(&rendered, secret, "pre-commit replay JSONL");
    }
    let replay_path = replay.commit().expect("redacted replay commits to disk");
    let persisted = std::fs::read_to_string(&replay_path).expect("replay evidence readable");
    for secret in [
        PRIMARY_GMAIL_ACCESS_TOKEN,
        ROTATED_GMAIL_ACCESS_TOKEN,
        GMAIL_REFRESH_TOKEN,
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
