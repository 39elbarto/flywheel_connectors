//! Connector-local no-mock Sonos integration proof.
//!
//! These tests exercise the real Sonos SOAP client and connector against a
//! local HTTP server. No live Sonos service or speaker is contacted.

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError, HandshakeRequest,
    InvokeRequest, OperationId, RequestId, SelfCheckStatus, ZoneId,
};
use fcp_sdk::migration::ConnectorErrorMapping;
use fcp_sonos::{SonosConnector, error::SonosError, types::SonosConfig};
use serde_json::{Value, json};
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CAP_READ: &str = "sonos.read";
const CAP_WRITE: &str = "sonos.write";
const OP_HEALTH: &str = "sonos.health";
const OP_GET_STATUS: &str = "sonos.get_status";
const OP_PLAY: &str = "sonos.play";
const OP_PAUSE: &str = "sonos.pause";
const OP_NEXT: &str = "sonos.next";
const OP_PREVIOUS: &str = "sonos.previous";
const OP_SET_VOLUME: &str = "sonos.set_volume";
const SONOS_DEVICE_HOST_PLACEHOLDER: &str = "${sonos_device_host}";

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [41u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|capability| CapabilityId::new(*capability).expect("capability id"))
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operations: &[&str],
    instance_id: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("token should sign");
    CapabilityToken::from_raw(raw)
}

fn invoke_request(
    connector: &SonosConnector,
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("sonos-integration"),
        connector_id: connector.id().clone(),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

async fn setup_connector(
    server: &MockServer,
    capabilities: &[&str],
) -> (SonosConnector, Ed25519SigningKey) {
    let mut connector = SonosConnector::new();
    connector
        .configure(json!({
            "device_url": server.uri(),
            "request_timeout_ms": 500
        }))
        .await
        .expect("loopback Sonos device URL should configure");
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            capabilities,
        ))
        .await
        .expect("handshake should succeed");
    (connector, signing_key)
}

async fn invoke_ok(
    connector: &SonosConnector,
    operation: &'static str,
    input: Value,
    capability: &str,
    signing_key: &Ed25519SigningKey,
) -> Value {
    connector
        .invoke(invoke_request(
            connector,
            operation,
            input,
            capability_token(
                signing_key,
                capability,
                &[operation],
                connector.instance_id(),
            ),
        ))
        .await
        .expect("invoke should succeed")
        .result
        .expect("successful invoke should carry a result")
}

fn soap_response(body: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_string(format!(r"<s:Envelope><s:Body>{body}</s:Body></s:Envelope>"))
}

async fn mount_get_transport_info(server: &MockServer, body: &str) {
    Mock::given(method("POST"))
        .and(path("/MediaRenderer/AVTransport/Control"))
        .and(header(
            "soapaction",
            "\"urn:schemas-upnp-org:service:AVTransport:1#GetTransportInfo\"",
        ))
        .and(body_string_contains("<u:GetTransportInfo"))
        .respond_with(soap_response(body))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_get_volume(server: &MockServer, body: &str) {
    Mock::given(method("POST"))
        .and(path("/MediaRenderer/RenderingControl/Control"))
        .and(header(
            "soapaction",
            "\"urn:schemas-upnp-org:service:RenderingControl:1#GetVolume\"",
        ))
        .and(body_string_contains("<u:GetVolume"))
        .respond_with(soap_response(body))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_av_transport_action(server: &MockServer, action: &str) {
    Mock::given(method("POST"))
        .and(path("/MediaRenderer/AVTransport/Control"))
        .and(header(
            "soapaction",
            format!("\"urn:schemas-upnp-org:service:AVTransport:1#{action}\""),
        ))
        .and(body_string_contains(format!("<u:{action}")))
        .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
        .expect(1)
        .mount(server)
        .await;
}

#[fcp_async_core::runtime::test]
async fn local_device_status_playback_and_volume_use_sonos_soap_contracts() {
    tracing::info!(
        scenario = "sonos_local_device_success_contracts",
        "starting Sonos no-mock local-device integration proof",
    );

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/xml/device_description.xml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<root><device><friendlyName>Office Speaker</friendlyName><modelName>Sonos One</modelName></device></root>",
        ))
        .expect(1)
        .mount(&server)
        .await;

    mount_get_transport_info(
        &server,
        "<u:GetTransportInfoResponse><CurrentTransportState>PLAYING</CurrentTransportState><CurrentTransportStatus>OK</CurrentTransportStatus></u:GetTransportInfoResponse>",
    )
    .await;
    mount_get_volume(
        &server,
        "<u:GetVolumeResponse><CurrentVolume>18</CurrentVolume></u:GetVolumeResponse>",
    )
    .await;
    mount_av_transport_action(&server, "Play").await;
    mount_av_transport_action(&server, "Pause").await;
    mount_av_transport_action(&server, "Next").await;
    mount_av_transport_action(&server, "Previous").await;
    Mock::given(method("POST"))
        .and(path("/MediaRenderer/RenderingControl/Control"))
        .and(header(
            "soapaction",
            "\"urn:schemas-upnp-org:service:RenderingControl:1#SetVolume\"",
        ))
        .and(body_string_contains("<u:SetVolume"))
        .and(body_string_contains("<DesiredVolume>18</DesiredVolume>"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server, &[CAP_READ, CAP_WRITE]).await;
    let report = connector
        .self_check()
        .await
        .expect("self check should call the fake device description endpoint");
    assert_eq!(report.status, SelfCheckStatus::Ok);
    let details = report.details.expect("self check details should exist");
    assert_eq!(details["probe"]["friendly_name"], "Office Speaker");
    assert_eq!(details["probe"]["model_name"], "Sonos One");

    let status = invoke_ok(&connector, OP_GET_STATUS, json!({}), CAP_READ, &signing_key).await;
    assert_eq!(status["transport_state"], "PLAYING");
    assert_eq!(status["transport_status"], "OK");
    assert_eq!(status["volume"], 18);

    for (operation, action) in [
        (OP_PLAY, "play"),
        (OP_PAUSE, "pause"),
        (OP_NEXT, "next"),
        (OP_PREVIOUS, "previous"),
    ] {
        let result = invoke_ok(&connector, operation, json!({}), CAP_WRITE, &signing_key).await;
        assert_eq!(result["status"], "ok");
        assert_eq!(result["action"], action);
    }

    let volume = invoke_ok(
        &connector,
        OP_SET_VOLUME,
        json!({ "volume": 18 }),
        CAP_WRITE,
        &signing_key,
    )
    .await;
    assert_eq!(volume["status"], "ok");
    assert_eq!(volume["volume"], 18);
}

#[fcp_async_core::runtime::test]
async fn auth_failure_malformed_xml_and_async_mapping_are_typed() {
    let auth_server = MockServer::start().await;
    let sensitive_marker = ["to", "ken"].concat();
    Mock::given(method("POST"))
        .and(path("/MediaRenderer/AVTransport/Control"))
        .and(header(
            "soapaction",
            "\"urn:schemas-upnp-org:service:AVTransport:1#GetTransportInfo\"",
        ))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string(format!("{sensitive_marker}=redaction-marker")),
        )
        .expect(1)
        .mount(&auth_server)
        .await;
    let (auth_connector, signing_key) = setup_connector(&auth_server, &[CAP_READ]).await;
    let auth_error = auth_connector
        .invoke(invoke_request(
            &auth_connector,
            OP_GET_STATUS,
            json!({}),
            capability_token(
                &signing_key,
                CAP_READ,
                &[OP_GET_STATUS],
                auth_connector.instance_id(),
            ),
        ))
        .await
        .expect_err("device auth failure should map to an FCP external error");
    assert!(
        matches!(auth_error, FcpError::External { .. }),
        "unexpected auth error: {auth_error:?}",
    );
    if let FcpError::External {
        service,
        message,
        status_code,
        retryable,
        ..
    } = auth_error
    {
        assert_eq!(service, "sonos");
        assert_eq!(status_code, Some(401));
        assert!(!retryable);
        assert_eq!(message, "upstream error response redacted");
        assert!(!message.contains("redaction-marker"));
    }

    let malformed_server = MockServer::start().await;
    mount_get_transport_info(&malformed_server, "<not-transport-info>").await;
    mount_get_volume(&malformed_server, "<not-volume>").await;
    let (malformed_connector, malformed_key) =
        setup_connector(&malformed_server, &[CAP_READ]).await;
    let malformed = invoke_ok(
        &malformed_connector,
        OP_GET_STATUS,
        json!({}),
        CAP_READ,
        &malformed_key,
    )
    .await;
    assert!(malformed["transport_state"].is_null());
    assert!(malformed["transport_status"].is_null());
    assert!(malformed["volume"].is_null());

    let (volume_connector, volume_key) = setup_connector(&malformed_server, &[CAP_WRITE]).await;
    let volume_error = volume_connector
        .invoke(invoke_request(
            &volume_connector,
            OP_SET_VOLUME,
            json!({ "volume": 101 }),
            capability_token(
                &volume_key,
                CAP_WRITE,
                &[OP_SET_VOLUME],
                volume_connector.instance_id(),
            ),
        ))
        .await
        .expect_err("out-of-range volume should be rejected before outbound SOAP");
    assert!(
        matches!(volume_error, FcpError::InvalidRequest { .. }),
        "unexpected volume error: {volume_error:?}",
    );

    let timeout =
        SonosError::from_async_error(fcp_async_core::AsyncError::Timeout { timeout_ms: 250 });
    assert!(timeout.is_retryable());
    let timeout_fcp = timeout.to_fcp_error();
    assert!(
        matches!(timeout_fcp, FcpError::External { .. }),
        "unexpected timeout error: {timeout_fcp:?}",
    );
    if let FcpError::External {
        service,
        status_code,
        retryable,
        ..
    } = timeout_fcp
    {
        assert_eq!(service, "sonos");
        assert_eq!(status_code, Some(408));
        assert!(retryable);
    }

    let cancelled = SonosError::from_async_error(fcp_async_core::AsyncError::Cancelled);
    assert!(!cancelled.is_retryable());
    assert!(cancelled.to_string().contains("cancelled"));
}

#[fcp_async_core::runtime::test]
async fn operation_catalog_manifest_and_redaction_preserve_security_posture() {
    let connector = SonosConnector::new();
    let introspection = connector.introspect();
    let operations = introspection
        .operations
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        operations,
        vec![
            OP_HEALTH,
            OP_GET_STATUS,
            OP_PLAY,
            OP_PAUSE,
            OP_NEXT,
            OP_PREVIOUS,
            OP_SET_VOLUME,
        ]
    );
    assert!(introspection.events.is_empty());
    let event_caps = introspection
        .event_caps
        .expect("Sonos should explicitly advertise non-streaming event caps");
    assert!(!event_caps.streaming);
    assert!(!event_caps.replay);

    let manifest = include_str!("../manifest.toml");
    for operation in &operations {
        let suffix = operation
            .strip_prefix("sonos.")
            .expect("Sonos operation id should use sonos prefix");
        assert!(
            manifest.contains(&format!("[provides.operations.{suffix}]")),
            "manifest must declare operation {operation}",
        );
    }
    assert!(
        manifest
            .contains("forbidden = [\"system.exec\", \"system.privileged\", \"network.listen\"]")
    );
    assert!(manifest.contains("required = [\"network.dns\", \"network.outbound\"]"));

    let manifest_toml: toml::Value =
        toml::from_str(manifest).expect("Sonos manifest should parse as TOML");
    let provides = manifest_toml
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("Sonos manifest should declare operations");
    for operation in &operations {
        let suffix = operation
            .strip_prefix("sonos.")
            .expect("Sonos operation id should use sonos prefix");
        let hints = provides
            .get(suffix)
            .and_then(|operation| operation.get("ai_hints"))
            .and_then(toml::Value::as_table)
            .expect("operation should declare ai_hints");
        let network_constraints = provides
            .get(suffix)
            .and_then(|operation| operation.get("network_constraints"))
            .and_then(toml::Value::as_table)
            .expect("operation should declare network_constraints");
        let host_allow = network_constraints
            .get("host_allow")
            .and_then(toml::Value::as_array)
            .expect("operation should declare host_allow");
        assert_eq!(host_allow.len(), 1);
        assert_eq!(host_allow[0].as_str(), Some(SONOS_DEVICE_HOST_PLACEHOLDER));
        let port_allow = network_constraints
            .get("port_allow")
            .and_then(toml::Value::as_array)
            .expect("operation should declare port_allow")
            .iter()
            .map(|port| port.as_integer().expect("port_allow values should be ints"))
            .collect::<Vec<_>>();
        assert_eq!(port_allow, vec![80, 443, 1400]);
        assert_eq!(
            network_constraints
                .get("require_sni")
                .and_then(toml::Value::as_bool),
            Some(false)
        );
        for key in [
            "deny_localhost",
            "deny_private_ranges",
            "deny_tailnet_ranges",
            "deny_ip_literals",
        ] {
            assert_eq!(
                network_constraints.get(key).and_then(toml::Value::as_bool),
                Some(false),
                "{operation} should allow local Sonos device addressing for {key}"
            );
        }
        assert_eq!(
            network_constraints
                .get("require_host_canonicalization")
                .and_then(toml::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            network_constraints
                .get("dns_max_ips")
                .and_then(toml::Value::as_integer),
            Some(16)
        );
        assert_eq!(
            network_constraints
                .get("max_redirects")
                .and_then(toml::Value::as_integer),
            Some(0)
        );
        assert_eq!(
            network_constraints
                .get("connect_timeout_ms")
                .and_then(toml::Value::as_integer),
            Some(10_000)
        );
        assert_eq!(
            network_constraints
                .get("total_timeout_ms")
                .and_then(toml::Value::as_integer),
            Some(30_000)
        );
        assert_eq!(
            network_constraints
                .get("max_response_bytes")
                .and_then(toml::Value::as_integer),
            Some(1_048_576)
        );
        let when_to_use = hints
            .get("when_to_use")
            .and_then(toml::Value::as_str)
            .unwrap_or_default();
        assert!(
            !when_to_use.trim().is_empty(),
            "operation {operation} should have non-empty when_to_use"
        );
        let examples = hints
            .get("examples")
            .and_then(toml::Value::as_array)
            .expect("operation should declare examples");
        assert!(
            !examples.is_empty(),
            "operation {operation} should include at least one example"
        );
        for example in examples {
            let example = example
                .as_str()
                .expect("operation example should be a string");
            let parsed = serde_json::from_str::<Value>(example)
                .expect("operation example should parse as JSON");
            let serialized = parsed.to_string().to_ascii_lowercase();
            assert!(!serialized.contains("token"));
            assert!(!serialized.contains("secret"));
            assert!(!serialized.contains("password"));
        }
        let common_mistakes = hints
            .get("common_mistakes")
            .and_then(toml::Value::as_array)
            .expect("operation should declare common_mistakes");
        assert!(
            !common_mistakes.is_empty(),
            "operation {operation} should include Sonos-specific common mistakes"
        );
    }

    let credential_marker = "redaction-marker";
    let credential_url = SonosConfig::from_value(json!({
        "device_url": format!("http://user:{credential_marker}@127.0.0.1:1400")
    }))
    .expect_err("embedded credentials in device_url must be rejected");
    assert!(
        matches!(credential_url, FcpError::InvalidRequest { .. }),
        "unexpected credential URL error: {credential_url:?}",
    );
    if let FcpError::InvalidRequest { message, .. } = credential_url {
        assert!(message.contains("must not include embedded credentials"));
        assert!(!message.contains(credential_marker));
    }

    let mut configured = SonosConnector::new();
    configured
        .configure(json!({
            "device_url": "http://127.0.0.1:1400"
        }))
        .await
        .expect("loopback Sonos device URL should configure");
    let debug = format!("{configured:?}");
    assert!(!debug.contains("password"));
    assert!(!debug.contains("secret"));
    assert!(!debug.contains("token"));
}
