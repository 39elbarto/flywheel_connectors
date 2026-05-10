//! GitHub secretless connector E2E evidence for `flywheel_connectors-e99o6.1.5`.
//!
//! This test keeps the connector side and host side explicit:
//! - the real GitHub connector/client is configured with only a `CredentialId`;
//! - the host egress proxy materializes the bearer at the boundary;
//! - trace, error, debug, disk, and replay evidence are checked for raw-secret
//!   absence.

#![cfg(feature = "github")]
#![allow(clippy::similar_names, clippy::too_many_lines)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use fcp_crypto::test_utils::InMemorySecretRegistry;
use fcp_crypto::{CredentialIdHash, SecretFetchError, SecretFetchHook, ZeroizingSecret};
use fcp_github::client::{GitHubAuth, GitHubClient};
use fcp_github::connector::GitHubConnector;
use fcp_host::{
    RuntimeEgressDecisionContext, RuntimeNetworkEnforcement, authorize_runtime_http_egress,
};
use fcp_manifest::NetworkConstraints;
use fcp_prelude::CredentialId;
use fcp_sandbox::{EgressHttpRequest, HttpHeader, SecretFetchCredentialInjector};
use fcp_testkit::{MockApiServer, RedactedReplayBundle, RedactedReplaySecret};
use serde_json::{Value, json};
use tracing::Subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

const PRIMARY_GITHUB_BEARER: &str = "ghp_b5_primary_secretless_fixture";
const ROTATED_GITHUB_BEARER: &str = "ghp_b5_rotated_secretless_fixture";
const OTHER_CONNECTOR_BEARER: &str = "xoxb_b5_cross_connector_fixture";
const GITHUB_REPO_PATH: &str = "/repos/octocat/hello-world";

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

fn github_repo_response() -> Value {
    json!({
        "id": 1296269,
        "name": "hello-world",
        "full_name": "octocat/hello-world",
        "owner": {
            "login": "octocat",
            "id": 1,
            "type": "User"
        },
        "private": false,
        "fork": false,
        "html_url": "https://github.com/octocat/hello-world",
        "default_branch": "main",
        "created_at": "2011-01-26T19:01:12Z",
        "updated_at": "2024-01-01T00:00:00Z",
        "language": "Rust",
        "stargazers_count": 80,
        "forks_count": 9,
        "open_issues_count": 0
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
        connector_id: "fcp.github",
        operation,
        zone_id: "z:work",
        request_id: "req-secretless-github-b5",
        correlation_id: Some("corr-secretless-github-b5"),
        execution_mode: RuntimeNetworkEnforcement::HostEgressProxy,
        constraint_source: "secretless-github-b5-e2e",
        credential_allow,
    }
}

fn connector_visible_request(base_url: &str, credential_id: &str) -> EgressHttpRequest {
    EgressHttpRequest {
        url: format!("{base_url}{GITHUB_REPO_PATH}"),
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
    std::env::temp_dir().join(format!("fcp-secretless-b5-github-{nanos}"))
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
async fn github_secretless_gauntlet_records_redacted_replay() {
    let (captured, _guard) = install_capture();
    let replay_root = unique_replay_root();
    let credential_id = CredentialId::new();
    let credential_id_string = credential_id.to_string();
    let other_credential_id = CredentialId::new().to_string();
    let credential_hash = CredentialIdHash::from_credential_id(&credential_id_string).to_string();
    let other_credential_hash =
        CredentialIdHash::from_credential_id(&other_credential_id).to_string();
    let primary_secret = ZeroizingSecret::new(PRIMARY_GITHUB_BEARER.as_bytes().to_vec());
    let rotated_secret = ZeroizingSecret::new(ROTATED_GITHUB_BEARER.as_bytes().to_vec());
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
            GITHUB_REPO_PATH,
            "X-FCP-Credential-ID",
            &credential_id_string,
            github_repo_response(),
        )
        .await;
    let mut connector = GitHubConnector::new();
    let configure_result = connector
        .handle_configure(json!({
            "credential_id": credential_id_string,
            "base_url": connector_mock.base_url()
        }))
        .await
        .expect("github configure accepts credential_id");
    let client = GitHubClient::new_with_auth(GitHubAuth::CredentialId(credential_id))
        .expect("github client builds")
        .with_base_url(connector_mock.base_url());
    let repo = client
        .get_repo("octocat", "hello-world")
        .await
        .expect("github client can call credential-id mode");
    assert_eq!(repo.full_name, "octocat/hello-world");
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
        "github_connector_blindness",
        json!({
            "configure_result": configure_result,
            "credential_id_hash": credential_hash,
            "connector_request_headers": format!("{:?}", connector_requests[0].headers),
            "raw_secret_control": PRIMARY_GITHUB_BEARER
        }),
    );

    let registry = Arc::new(InMemorySecretRegistry::new());
    registry.insert(
        credential_id_string.clone(),
        PRIMARY_GITHUB_BEARER.as_bytes().to_vec(),
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
            GITHUB_REPO_PATH,
            "Authorization",
            &format!("Bearer {PRIMARY_GITHUB_BEARER}"),
            github_repo_response(),
        )
        .await;
    host_mock
        .expect_with_header(
            GITHUB_REPO_PATH,
            "Authorization",
            &format!("Bearer {ROTATED_GITHUB_BEARER}"),
            github_repo_response(),
        )
        .await;

    let constraints = constraints_for("127.0.0.1", host_mock.address().port());
    let credential_allow = vec![credential_id_string.clone()];
    let context = runtime_context("github.get_repo", &credential_allow);
    let mut first_request = connector_visible_request(&host_mock.base_url(), &credential_id_string);
    assert!(
        !first_request
            .headers
            .iter()
            .any(|header| header.value == PRIMARY_GITHUB_BEARER),
        "connector-visible host request must not contain raw secret bytes"
    );
    let first_decision =
        authorize_runtime_http_egress(&context, &constraints, &mut first_request, &injector)
            .expect("primary github egress request is authorized");
    assert!(first_decision.credential_injected);
    assert!(first_request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("authorization")
            && header.value == format!("Bearer {PRIMARY_GITHUB_BEARER}")
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
            ZeroizingSecret::new(ROTATED_GITHUB_BEARER.as_bytes().to_vec()),
        )
        .expect("credential rotates");
    let mut rotated_request =
        connector_visible_request(&host_mock.base_url(), &credential_id_string);
    let rotated_decision =
        authorize_runtime_http_egress(&context, &constraints, &mut rotated_request, &injector)
            .expect("rotated github egress request is authorized");
    assert!(rotated_decision.credential_injected);
    assert!(rotated_request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("authorization")
            && header.value == format!("Bearer {ROTATED_GITHUB_BEARER}")
    }));
    assert_eq!(
        send_authorized_request(&rotated_request).await,
        reqwest::StatusCode::OK
    );
    assert_eq!(registry.fetch_count_for(&credential_id_string), 2);
    replay.record_event(
        "fcp.test.secretless.github.wire_and_rotation.pass",
        json!({
            "credential_id_hash": credential_hash,
            "primary_wire_authorization": format!("Bearer {PRIMARY_GITHUB_BEARER}"),
            "rotated_wire_authorization": format!("Bearer {ROTATED_GITHUB_BEARER}"),
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
            .expect_err("cross-connector credential id is not authorized for github operation")
            .to_string();
    assert_eq!(registry.fetch_count_for(&other_credential_id), 0);
    assert_secret_absent(
        &denied_error,
        OTHER_CONNECTOR_BEARER,
        "cross-connector denial",
    );
    replay.record_event(
        "fcp.test.secretless.github.cross_connector_bleed.pass",
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
    assert_secret_absent(&not_found_display, PRIMARY_GITHUB_BEARER, "error Display");
    assert_secret_absent(&not_found_debug, PRIMARY_GITHUB_BEARER, "error Debug");
    assert!(
        !not_found_display.contains(&credential_id_string),
        "SecretFetchError Display must redact credential id"
    );
    assert!(not_found_display.contains(&credential_hash));
    let registry_debug = format!("{registry:?}");
    let injector_debug = format!("{injector:?}");
    for evidence in [&registry_debug, &injector_debug, &not_found_debug] {
        assert_secret_absent(evidence, PRIMARY_GITHUB_BEARER, "debug evidence");
        assert_secret_absent(evidence, ROTATED_GITHUB_BEARER, "debug evidence");
        assert_secret_absent(evidence, OTHER_CONNECTOR_BEARER, "debug evidence");
    }
    replay.record_event(
        "fcp.test.secretless.github.error_debug_eq_redaction.pass",
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
    assert_secret_absent(&trace_snapshot, PRIMARY_GITHUB_BEARER, "trace output");
    assert_secret_absent(&trace_snapshot, ROTATED_GITHUB_BEARER, "trace output");
    assert_secret_absent(&trace_snapshot, OTHER_CONNECTOR_BEARER, "trace output");
    replay.record_event(
        "fcp.test.secretless.github.tracing_and_audit.pass",
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
        PRIMARY_GITHUB_BEARER,
        ROTATED_GITHUB_BEARER,
        OTHER_CONNECTOR_BEARER,
    ] {
        assert_secret_absent(&rendered, secret, "pre-commit replay JSONL");
    }
    let replay_path = replay.commit().expect("redacted replay commits to disk");
    let persisted = std::fs::read_to_string(&replay_path).expect("replay evidence readable");
    for secret in [
        PRIMARY_GITHUB_BEARER,
        ROTATED_GITHUB_BEARER,
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
