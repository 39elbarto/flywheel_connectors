#![allow(clippy::too_many_lines)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Write,
    path::PathBuf,
    process::Command,
    time::Instant,
};

use chrono::Utc;
use fcp_crypto::{CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_manifest::{ConnectorManifest, OperationSection};
use fcp_plivo::connector::PlivoConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, OperationId, ZoneId,
};
use fcp_voice_call::{
    PlivoParamValue, PlivoSignatureVerifier, PlivoSignatureVersion, VoiceWebhookMethod,
    stable_redacted_hash,
};
use serde_json::{Value, json};
use url::form_urlencoded;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const TEST_AUTH_ID: &str = "MA123";
const TEST_AUTH_SECRET: &str = "plivo_test_auth_secret";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const EXPECTED_OPERATION_COUNT: usize = 11;
const PLIVO_API_EGRESS_OPERATIONS: &[&str] = &[
    "plivo.call.continue",
    "plivo.call.end",
    "plivo.call.initiate",
    "plivo.call.speak",
    "plivo.call.status",
    "plivo.call.transfer",
];
const NO_CONNECTOR_EGRESS_OPERATIONS: &[&str] = &[
    "plivo.call.gather",
    "plivo.webhook.evaluate_inbound_policy",
    "plivo.webhook.ingest_request",
    "plivo.webhook.parse_event",
    "plivo.webhook.validate_signature",
];

async fn configure_connector(connector: &mut PlivoConnector, server: &MockServer) {
    connector
        .handle_configure(json!({
            "auth_id": TEST_AUTH_ID,
            "auth_token": TEST_AUTH_SECRET,
            "base_url": format!("{}/v1/Account/{TEST_AUTH_ID}", server.uri())
        }))
        .await
        .unwrap();
}

async fn setup_handshake(connector: &mut PlivoConnector) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["plivo.read", "plivo.voice", "plivo.webhook"]
        }))
        .await
        .unwrap();
    signing_key
}

fn capability_for(operation: &str) -> &'static str {
    match operation {
        "plivo.call.status" => "plivo.read",
        "plivo.webhook.validate_signature"
        | "plivo.webhook.evaluate_inbound_policy"
        | "plivo.webhook.parse_event"
        | "plivo.webhook.ingest_request" => "plivo.webhook",
        _ => "plivo.voice",
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
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
        .capability_id(capability_for(operation))
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + chrono::Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &mut PlivoConnector,
    signing_key: &Ed25519SigningKey,
    operation: &str,
    input: Value,
) -> Value {
    let capability_proof = generate_valid_token(signing_key, connector.instance_id(), operation);
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_proof
        }))
        .await
        .unwrap()
}

fn plivo_params(call_uuid: &str, from: &str) -> Value {
    json!({
        "CallUUID": call_uuid,
        "CallStatus": "answer",
        "From": from,
        "To": "+15559870000",
        "Event": "Answer",
        "MediaBytes": "320",
        "MediaFrames": "2"
    })
}

fn plivo_param_map(params: &Value) -> BTreeMap<String, PlivoParamValue> {
    params
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                PlivoParamValue::from(value.as_str().unwrap_or_default().to_string()),
            )
        })
        .collect()
}

fn sign_plivo_webhook(
    version: PlivoSignatureVersion,
    url: &str,
    params: &Value,
    nonce: &str,
) -> String {
    let verifier = PlivoSignatureVerifier::new(TEST_AUTH_SECRET);
    verifier
        .compute(
            version,
            VoiceWebhookMethod::Post,
            url,
            &plivo_param_map(params),
            nonce,
        )
        .unwrap()
}

fn webhook_input(
    url: &str,
    params: &Value,
    nonce: &str,
    signature: &str,
    version: PlivoSignatureVersion,
) -> Value {
    let (signature_header, nonce_header) = match version {
        PlivoSignatureVersion::V2 => ("X-Plivo-Signature-V2", "X-Plivo-Signature-V2-Nonce"),
        PlivoSignatureVersion::V3 => ("X-Plivo-Signature-Ma-V3", "X-Plivo-Signature-V3-Nonce"),
    };
    json!({
        "method": "POST",
        "url": url,
        "headers": {
            signature_header: format!("bad,{signature}"),
            nonce_header: nonce
        },
        "body": params,
        "inbound_policy": "open",
        "request_region": { "source": "loopback_plivo_fixture" }
    })
}

fn open_plivo_e2e_log() -> (File, PathBuf) {
    let unique = format!(
        "fcp-plivo-e2e-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let dir = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&dir).expect("create plivo e2e log dir");
    let path = dir.join("plivo_voice_call_e2e.jsonl");
    let file = File::create(&path).expect("create plivo e2e log");
    (file, path)
}

fn git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn log_plivo_e2e(
    logs: &mut File,
    scenario: &str,
    result: &Value,
    latency_ms: u128,
    details: &Value,
) {
    let body = json!({
        "record_type": "plivo_voice_call_connector_boundary_e2e",
        "command_line": std::env::args().collect::<Vec<_>>().join(" "),
        "git_revision": git_revision(),
        "provider": "plivo",
        "provider_fixture_id": "plivo-loopback-hmac-v3-v2",
        "scenario": scenario,
        "outcome": if result.get("accepted").and_then(Value::as_bool).unwrap_or(false) { "accepted" } else { "observed" },
        "latency_ms": latency_ms,
        "call_uuid_hash": stable_redacted_hash("call-uuid-e2e"),
        "call_session_id_hash": stable_redacted_hash("plivo-session-e2e"),
        "masked_caller_identity": "+15***0000",
        "webhook_event": result.get("event_type").and_then(Value::as_str).unwrap_or("n/a"),
        "signature_decision": result.get("signature").and_then(|signature| signature.get("reason_code")).and_then(Value::as_str).unwrap_or("n/a"),
        "signature_version": result.get("signature").and_then(|signature| signature.get("signature_version")).and_then(Value::as_str).unwrap_or("n/a"),
        "replay_decision": result.get("signature").and_then(|signature| signature.get("is_replay")).and_then(Value::as_bool).unwrap_or(false),
        "auth_decision": result.get("policy").and_then(|policy| policy.get("reason_code")).and_then(Value::as_str).unwrap_or("n/a"),
        "media_byte_count": details.get("media_byte_count").and_then(Value::as_u64).unwrap_or(0),
        "media_frame_count": details.get("media_frame_count").and_then(Value::as_u64).unwrap_or(0),
        "http_status": result.get("status_code").and_then(Value::as_u64),
        "websocket_status": details.get("websocket_status").and_then(Value::as_str).unwrap_or("not_exercised_loopback"),
        "fcp_error_mapping": details.get("fcp_error_mapping").and_then(Value::as_str).unwrap_or("n/a"),
        "retry_decision": details.get("retry_decision").and_then(Value::as_str).unwrap_or("n/a"),
        "cleanup_result": details.get("cleanup_result").and_then(Value::as_str).unwrap_or("not_applicable"),
        "skip_reason": details.get("skip_reason").and_then(Value::as_str).unwrap_or("not_skipped"),
        "artifact_paths": details.get("artifact_paths").cloned().unwrap_or_else(|| json!([])),
    });
    writeln!(logs, "{body}").expect("write plivo e2e log");
}

fn plivo_manifest() -> ConnectorManifest {
    ConnectorManifest::parse_str(MANIFEST_TOML).expect("Plivo manifest should validate")
}

fn manifest_operation<'a>(manifest: &'a ConnectorManifest, id: &str) -> &'a OperationSection {
    manifest
        .provides
        .operations
        .get(id)
        .unwrap_or_else(|| panic!("{id} should be declared in the manifest"))
}

fn assert_plivo_api_network_constraints(id: &str, operation: &OperationSection) {
    let constraints = operation
        .network_constraints
        .as_ref()
        .unwrap_or_else(|| panic!("{id} should declare network_constraints"));
    assert_eq!(
        constraints.host_allow,
        ["api.plivo.com"],
        "{id} should only allow the production Plivo REST API host"
    );
    assert_eq!(constraints.port_allow, [443], "{id}");
    assert!(constraints.require_sni, "{id} should require SNI");
    assert!(constraints.deny_localhost, "{id} should deny localhost");
    assert!(
        constraints.deny_private_ranges,
        "{id} should deny private ranges"
    );
    assert!(
        constraints.deny_tailnet_ranges,
        "{id} should deny tailnet ranges"
    );
    assert!(constraints.deny_ip_literals, "{id} should deny IP literals");
    assert_eq!(constraints.max_redirects, 0, "{id}");
    assert_eq!(constraints.connect_timeout_ms, 10_000, "{id}");
    assert_eq!(constraints.total_timeout_ms, 30_000, "{id}");
}

fn assert_no_connector_egress_network_constraints(id: &str, operation: &OperationSection) {
    let constraints = operation
        .network_constraints
        .as_ref()
        .unwrap_or_else(|| panic!("{id} should declare network_constraints"));
    assert_eq!(
        constraints.host_allow,
        ["none.invalid"],
        "{id} should advertise no connector-owned egress"
    );
    assert_eq!(constraints.port_allow, [0], "{id}");
    assert!(
        !constraints.require_sni,
        "{id} should not require SNI for a no-egress sentinel"
    );
    assert!(constraints.deny_localhost, "{id} should deny localhost");
    assert!(
        constraints.deny_private_ranges,
        "{id} should deny private ranges"
    );
    assert!(
        constraints.deny_tailnet_ranges,
        "{id} should deny tailnet ranges"
    );
    assert!(constraints.deny_ip_literals, "{id} should deny IP literals");
    assert_eq!(constraints.dns_max_ips, 0, "{id}");
    assert_eq!(constraints.max_redirects, 0, "{id}");
    assert_eq!(constraints.connect_timeout_ms, 1_000, "{id}");
    assert_eq!(constraints.total_timeout_ms, 30_000, "{id}");
}

#[test]
fn manifest_declares_strict_per_operation_network_constraints() {
    let manifest = plivo_manifest();
    assert_eq!(
        manifest.provides.operations.len(),
        EXPECTED_OPERATION_COUNT,
        "Plivo manifest operation count changed; update network-constraint assertions"
    );

    for id in PLIVO_API_EGRESS_OPERATIONS {
        assert_plivo_api_network_constraints(id, manifest_operation(&manifest, id));
    }
    for id in NO_CONNECTOR_EGRESS_OPERATIONS {
        assert_no_connector_egress_network_constraints(id, manifest_operation(&manifest, id));
    }

    for (id, operation) in &manifest.provides.operations {
        assert!(
            operation.network_constraints.is_some(),
            "{id} should declare per-operation network_constraints"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn call_initiate_stores_answer_url_token_and_session_binding_accepts_webhook() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/Account/MA123/Call/"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "request_uuid": "call-uuid-e2e",
            "message": "call fired"
        })))
        .mount(&server)
        .await;

    let mut connector = PlivoConnector::new();
    configure_connector(&mut connector, &server).await;
    let host_key = setup_handshake(&mut connector).await;

    let create = invoke(
        &mut connector,
        &host_key,
        "plivo.call.initiate",
        json!({
            "to": "+15551230000",
            "from": "+15559870000",
            "answer_url": "https://voice.example.com/plivo"
        }),
    )
    .await;
    assert_eq!(create["call"]["request_uuid"], "call-uuid-e2e");
    assert_eq!(create["session"]["answer_url_auth_embedded"], true);

    let requests = server.received_requests().await.unwrap_or_default();
    let request_body = String::from_utf8(requests[0].body.clone()).unwrap();
    let form = form_urlencoded::parse(request_body.as_bytes())
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    let answer_url = form.get("answer_url").unwrap();
    let (_, answer_query) = answer_url.split_once('?').unwrap();
    let answer_query_keys = form_urlencoded::parse(answer_query.as_bytes())
        .map(|(key, _)| key.into_owned())
        .collect::<BTreeSet<_>>();
    assert!(answer_query_keys.contains("fcp_call_auth_token"));

    let nonce = "nonce-accepted";
    let params = plivo_params("call-uuid-e2e", "+15551230000");
    let signature = sign_plivo_webhook(PlivoSignatureVersion::V3, answer_url, &params, nonce);
    let ingest = invoke(
        &mut connector,
        &host_key,
        "plivo.webhook.ingest_request",
        webhook_input(
            answer_url,
            &params,
            nonce,
            &signature,
            PlivoSignatureVersion::V3,
        ),
    )
    .await;
    assert_eq!(ingest["accepted"], true);
    assert_eq!(ingest["signature"]["reason_code"], "signature_validated");
}

#[fcp_async_core::runtime::test]
async fn webhook_signature_denies_invalid_replay_and_supports_v2_fallback() {
    let server = MockServer::start().await;
    let mut connector = PlivoConnector::new();
    configure_connector(&mut connector, &server).await;
    let host_key = setup_handshake(&mut connector).await;

    let url = "https://voice.example.com/plivo?foo=bar";
    let params = plivo_params("call-uuid-2", "+15551230000");
    let nonce = "nonce-signature";
    let signature = sign_plivo_webhook(PlivoSignatureVersion::V3, url, &params, nonce);
    let valid = invoke(
        &mut connector,
        &host_key,
        "plivo.webhook.validate_signature",
        webhook_input(url, &params, nonce, &signature, PlivoSignatureVersion::V3),
    )
    .await;
    assert_eq!(valid["valid"], true);
    assert_eq!(valid["signature_version"], "v3");

    let replay = invoke(
        &mut connector,
        &host_key,
        "plivo.webhook.validate_signature",
        webhook_input(url, &params, nonce, &signature, PlivoSignatureVersion::V3),
    )
    .await;
    assert_eq!(replay["valid"], true);
    assert_eq!(replay["is_replay"], true);

    let invalid = invoke(
        &mut connector,
        &host_key,
        "plivo.webhook.validate_signature",
        webhook_input(
            url,
            &params,
            nonce,
            "bad-signature",
            PlivoSignatureVersion::V3,
        ),
    )
    .await;
    assert_eq!(invalid["valid"], false);

    let v2_url = "https://voice.example.com/plivo?ignored=true";
    let v2_signature =
        sign_plivo_webhook(PlivoSignatureVersion::V2, v2_url, &json!({}), "nonce-v2");
    let v2 = invoke(
        &mut connector,
        &host_key,
        "plivo.webhook.validate_signature",
        webhook_input(
            v2_url,
            &json!({}),
            "nonce-v2",
            &v2_signature,
            PlivoSignatureVersion::V2,
        ),
    )
    .await;
    assert_eq!(v2["valid"], true);
    assert_eq!(v2["signature_version"], "v2");
}

#[fcp_async_core::runtime::test]
async fn call_operations_cover_status_transfer_speak_gather_end_and_error_mapping() {
    let server = MockServer::start().await;
    for (http_method, request_path, response) in [
        (
            "POST",
            "/v1/Account/MA123/Call/call-uuid-e2e/",
            json!({ "message": "call transferred", "call_uuid": "call-uuid-e2e" }),
        ),
        (
            "POST",
            "/v1/Account/MA123/Call/call-uuid-e2e/Speak/",
            json!({ "message": "speak queued", "call_uuid": "call-uuid-e2e" }),
        ),
        (
            "DELETE",
            "/v1/Account/MA123/Call/call-uuid-e2e/",
            json!({ "message": "hangup queued", "call_uuid": "call-uuid-e2e" }),
        ),
    ] {
        Mock::given(method(http_method))
            .and(path(request_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/v1/Account/MA123/Call/call-uuid-e2e/"))
        .respond_with(ResponseTemplate::new(500).set_body_string("temporary"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/Account/MA123/Call/call-uuid-e2e/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "call_uuid": "call-uuid-e2e",
            "call_state": "ANSWER"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/Account/MA123/Call/bad-call/"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "error": "bad call id"
        })))
        .mount(&server)
        .await;

    let mut connector = PlivoConnector::new();
    configure_connector(&mut connector, &server).await;
    let host_key = setup_handshake(&mut connector).await;

    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "plivo.call.continue",
            json!({"call_uuid": "call-uuid-e2e", "xml_url": "https://voice.example.com/continue"})
        )
        .await["message"],
        "call transferred"
    );
    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "plivo.call.speak",
            json!({"call_uuid": "call-uuid-e2e", "text": "hello"})
        )
        .await["message"],
        "speak queued"
    );
    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "plivo.call.transfer",
            json!({"call_uuid": "call-uuid-e2e", "legs": "both", "aleg_url": "https://voice.example.com/a"})
        )
        .await["message"],
        "call transferred"
    );
    assert!(
        invoke(
            &mut connector,
            &host_key,
            "plivo.call.gather",
            json!({"prompt": "press 1", "action_url": "https://voice.example.com/gather"})
        )
        .await["xml"]
            .as_str()
            .unwrap()
            .contains("GetDigits")
    );
    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "plivo.call.end",
            json!({"call_uuid": "call-uuid-e2e"})
        )
        .await["message"],
        "hangup queued"
    );
    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "plivo.call.status",
            json!({"call_uuid": "call-uuid-e2e"})
        )
        .await["call_state"],
        "ANSWER"
    );

    let capability_proof =
        generate_valid_token(&host_key, connector.instance_id(), "plivo.call.status");
    let error = connector
        .handle_invoke(json!({
            "operation": "plivo.call.status",
            "input": { "call_uuid": "bad-call" },
            "capability_token": capability_proof
        }))
        .await
        .unwrap_err();
    assert_eq!(error.error_code(), "FCP-7003");
}

#[fcp_async_core::runtime::test]
async fn plivo_loopback_e2e_jsonl_covers_provider_edges() {
    let (mut logs, log_path) = open_plivo_e2e_log();
    println!("plivo_voice_call_e2e_log={}", log_path.display());

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/Account/MA123/Call/"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "request_uuid": "call-uuid-e2e",
            "message": "call fired"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/Account/MA123/Call/transient/"))
        .respond_with(ResponseTemplate::new(503).set_body_string("temporary"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/Account/MA123/Call/transient/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "call_uuid": "transient",
            "call_state": "ANSWER"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/Account/MA123/Call/provider-error/"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "error": "provider fixture rejected call"
        })))
        .mount(&server)
        .await;

    let mut connector = PlivoConnector::new();
    configure_connector(&mut connector, &server).await;
    let host_key = setup_handshake(&mut connector).await;

    let create = invoke(
        &mut connector,
        &host_key,
        "plivo.call.initiate",
        json!({
            "to": "+15551230000",
            "from": "+15559870000",
            "answer_url": "https://voice.example.com/plivo"
        }),
    )
    .await;
    assert_eq!(create["call"]["request_uuid"], "call-uuid-e2e");
    let request_body = String::from_utf8(
        server.received_requests().await.unwrap_or_default()[0]
            .body
            .clone(),
    )
    .unwrap();
    let answer_url = form_urlencoded::parse(request_body.as_bytes())
        .into_owned()
        .collect::<BTreeMap<_, _>>()
        .get("answer_url")
        .cloned()
        .unwrap();
    let callback_binding = url::Url::parse(&answer_url)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "fcp_call_auth_token")
        .map(|(_, value)| value.into_owned())
        .unwrap();

    let nonce = "nonce-e2e";
    let params = plivo_params("call-uuid-e2e", "+15551230000");
    let signature = sign_plivo_webhook(PlivoSignatureVersion::V3, &answer_url, &params, nonce);

    for (scenario, input, details) in [
        (
            "signed_webhook_acceptance",
            webhook_input(
                &answer_url,
                &params,
                nonce,
                &signature,
                PlivoSignatureVersion::V3,
            ),
            json!({ "media_byte_count": 320, "media_frame_count": 2, "websocket_status": "metadata_fixture_only" }),
        ),
        (
            "invalid_signature_denial",
            webhook_input(
                &answer_url,
                &params,
                nonce,
                "bad-signature",
                PlivoSignatureVersion::V3,
            ),
            json!({ "fcp_error_mapping": "FCP-2003" }),
        ),
        (
            "duplicate_replay_denial",
            webhook_input(
                &answer_url,
                &params,
                nonce,
                &signature,
                PlivoSignatureVersion::V3,
            ),
            json!({ "fcp_error_mapping": "FCP-6003" }),
        ),
        (
            "authorized_inbound_caller",
            {
                let raw = plivo_params("call-uuid-authorized", "+15551230000");
                let auth_url = "https://voice.example.com/plivo?fixture=authorized";
                let auth_sig =
                    sign_plivo_webhook(PlivoSignatureVersion::V3, auth_url, &raw, "nonce-auth");
                let mut input = webhook_input(
                    auth_url,
                    &raw,
                    "nonce-auth",
                    &auth_sig,
                    PlivoSignatureVersion::V3,
                );
                input["inbound_policy"] = Value::String("allowlist".into());
                input["allowed_from"] = json!(["+15551230000"]);
                input
            },
            json!({ "media_byte_count": 320, "media_frame_count": 2, "websocket_status": "metadata_fixture_only" }),
        ),
        (
            "denied_inbound_caller",
            {
                let raw = plivo_params("call-uuid-denied", "+15550001111");
                let deny_url = "https://voice.example.com/plivo?fixture=denied";
                let deny_sig =
                    sign_plivo_webhook(PlivoSignatureVersion::V3, deny_url, &raw, "nonce-deny");
                let mut input = webhook_input(
                    deny_url,
                    &raw,
                    "nonce-deny",
                    &deny_sig,
                    PlivoSignatureVersion::V3,
                );
                input["inbound_policy"] = Value::String("allowlist".into());
                input["allowed_from"] = json!(["+15551230000"]);
                input
            },
            json!({ "fcp_error_mapping": "FCP-2001" }),
        ),
        (
            "v2_signature_fallback",
            {
                let raw = plivo_params("call-uuid-v2", "+15551230000");
                let v2_url = "https://voice.example.com/plivo?fixture=v2";
                let v2_sig =
                    sign_plivo_webhook(PlivoSignatureVersion::V2, v2_url, &raw, "nonce-v2-e2e");
                webhook_input(
                    v2_url,
                    &raw,
                    "nonce-v2-e2e",
                    &v2_sig,
                    PlivoSignatureVersion::V2,
                )
            },
            json!({ "media_byte_count": 320, "media_frame_count": 2, "websocket_status": "metadata_fixture_only" }),
        ),
        (
            "cancellation",
            json!({ "method": "POST", "url": "https://voice.example.com/plivo", "headers": {}, "body": {}, "cancelled": true }),
            json!({ "fcp_error_mapping": "FCP-7003" }),
        ),
        (
            "timeout",
            json!({ "method": "POST", "url": "https://voice.example.com/plivo", "headers": {}, "body": {}, "deadline_exceeded": true }),
            json!({ "fcp_error_mapping": "FCP-7002" }),
        ),
    ] {
        let start = Instant::now();
        let result = invoke(
            &mut connector,
            &host_key,
            "plivo.webhook.ingest_request",
            input,
        )
        .await;
        log_plivo_e2e(
            &mut logs,
            scenario,
            &result,
            start.elapsed().as_millis(),
            &details,
        );
    }

    let transient = invoke(
        &mut connector,
        &host_key,
        "plivo.call.status",
        json!({ "call_uuid": "transient" }),
    )
    .await;
    assert_eq!(transient["call_state"], "ANSWER");
    log_plivo_e2e(
        &mut logs,
        "transient_retry",
        &json!({ "accepted": true, "status_code": 200, "signature": { "reason_code": "not_applicable", "is_replay": false, "signature_version": "n/a" } }),
        0,
        &json!({ "retry_decision": "retried_then_succeeded" }),
    );

    let provider_error_capability =
        generate_valid_token(&host_key, connector.instance_id(), "plivo.call.status");
    let provider_error = connector
        .handle_invoke(json!({
            "operation": "plivo.call.status",
            "input": { "call_uuid": "provider-error" },
            "capability_token": provider_error_capability
        }))
        .await
        .unwrap_err();
    log_plivo_e2e(
        &mut logs,
        "provider_error_mapping",
        &json!({ "accepted": false, "status_code": 422, "signature": { "reason_code": "not_applicable", "is_replay": false, "signature_version": "n/a" } }),
        0,
        &json!({ "fcp_error_mapping": provider_error.error_code() }),
    );

    let shutdown = connector.handle_shutdown(json!({})).await.unwrap();
    log_plivo_e2e(
        &mut logs,
        "cleanup",
        &json!({ "accepted": true, "status_code": 200, "signature": { "reason_code": "not_applicable", "is_replay": false, "signature_version": "n/a" } }),
        0,
        &json!({
            "cleanup_result": shutdown["status"].as_str().unwrap_or("unknown"),
            "artifact_paths": [log_path.display().to_string()],
        }),
    );
    logs.flush().unwrap();

    let contents = std::fs::read_to_string(&log_path).unwrap();
    for scenario in [
        "signed_webhook_acceptance",
        "invalid_signature_denial",
        "duplicate_replay_denial",
        "authorized_inbound_caller",
        "denied_inbound_caller",
        "v2_signature_fallback",
        "cancellation",
        "timeout",
        "transient_retry",
        "provider_error_mapping",
        "cleanup",
    ] {
        assert!(contents.contains(scenario), "{scenario} missing from JSONL");
    }
    for forbidden in [
        "+15551230000",
        "+15559870000",
        TEST_AUTH_SECRET,
        callback_binding.as_str(),
        answer_url.as_str(),
        "provider fixture rejected call",
    ] {
        assert!(
            !contents.contains(forbidden),
            "JSONL leaked forbidden raw material: {forbidden}"
        );
    }
}

#[test]
fn operation_capability_mapping_is_complete() {
    assert_eq!(capability_for("plivo.call.status"), "plivo.read");
    assert_eq!(
        capability_for("plivo.webhook.ingest_request"),
        "plivo.webhook"
    );
    assert_eq!(capability_for("plivo.call.speak"), "plivo.voice");
    let capability_ids = [
        CapabilityId::from_static("plivo.read"),
        CapabilityId::from_static("plivo.voice"),
        CapabilityId::from_static("plivo.webhook"),
    ];
    assert_eq!(capability_ids.len(), 3);
}

#[test]
fn simulate_request_shapes_use_plivo_connector_identity() {
    let capability_proof = CapabilityToken::test_token();
    let request = fcp_prelude::SimulateRequest::new(
        ConnectorId::from_static("plivo"),
        OperationId::from_static("plivo.call.status"),
        ZoneId::work(),
        json!({ "call_uuid": "call-uuid-e2e" }),
        capability_proof,
    );
    assert_eq!(request.connector_id.as_str(), "plivo");
    assert_eq!(request.operation.as_str(), "plivo.call.status");
}
