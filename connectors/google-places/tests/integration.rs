//! Integration tests for the Google Places connector.

use chrono::Utc;
use fcp_core::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, HandshakeRequest,
    IdempotencyClass, InvokeRequest, OperationId, RequestId, RiskLevel, SafetyTier, ZoneId,
};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_google_places::{
    GooglePlacesConnector,
    types::{
        DEFAULT_AUTOCOMPLETE_FIELD_MASK, DEFAULT_PLACE_DETAILS_FIELD_MASK,
        DEFAULT_SEARCH_TEXT_FIELD_MASK,
    },
};
use fcp_sdk::prelude::*;
use serde_json::json;
use wiremock::matchers::{header, header_regex, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Build a regex that matches a field-mask value exactly. wiremock 0.6's
/// `header()` exact matcher silently fails on comma-separated header values
/// because hyper/http may fold them per RFC 7230 §3.2.6. `header_regex` is
/// immune to this and matches the raw value correctly.
fn fieldmask_regex(mask: &str) -> String {
    format!("^{}$", mask.replace('.', r"\."))
}

fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &str) -> CapabilityToken {
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id("google_places.read")
        .zone_id("z:private")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + chrono::Duration::hours(1))
        .constraints_cbor(&cbor)
        .sign(signing_key)
        .expect("token should sign");
    CapabilityToken::from_raw(cose)
}

async fn setup_handshake(
    connector: &mut GooglePlacesConnector,
    signing_key: &Ed25519SigningKey,
    _capabilities: &[&str],
) {
    let verifying_key = signing_key.verifying_key();
    connector
        .handshake(HandshakeRequest {
            protocol_version: "1.0.0".into(),
            zone: ZoneId::private(),
            zone_dir: None,
            host_public_key: verifying_key.to_bytes(),
            nonce: [0u8; 32],
            capabilities_requested: vec![CapabilityId::from_static("google_places.read")],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake should succeed");
}

async fn setup_configure(connector: &mut GooglePlacesConnector, api_url: &str) {
    connector
        .configure(json!({
            "api_key": "test-key",
            "base_url": api_url,
        }))
        .await
        .expect("configure should succeed");
}

#[test]
fn introspection_exposes_required_operations_with_truthful_metadata() {
    let connector = GooglePlacesConnector::new();
    let introspection = connector.introspect();
    let op_ids: Vec<&str> = introspection
        .operations
        .iter()
        .map(|operation| operation.id.as_str())
        .collect();

    for op in [
        "google_places.search_text",
        "google_places.autocomplete",
        "google_places.get_place",
        "google_places.health",
    ] {
        assert!(
            op_ids.contains(&op),
            "missing required Google Places operation: {op}"
        );
    }

    let search = introspection
        .operations
        .iter()
        .find(|operation| operation.id.as_str() == "google_places.search_text")
        .expect("search_text op should exist");
    assert_eq!(search.capability.as_str(), "google_places.read");
    assert_eq!(search.risk_level, RiskLevel::Low);
    assert_eq!(search.safety_tier, SafetyTier::Safe);
    assert_eq!(search.idempotency, IdempotencyClass::Strict);
}

#[fcp_async_core::runtime::test]
async fn invoke_search_text_uses_default_operation_field_mask() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/places:searchText"))
        .and(header("x-goog-api-key", "test-key"))
        .and(header_regex("x-goog-fieldmask", &fieldmask_regex(DEFAULT_SEARCH_TEXT_FIELD_MASK)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "places": [
                {
                    "id": "abc123",
                    "name": "places/abc123",
                    "displayName": { "text": "Coffee Shop" },
                    "formattedAddress": "123 Main St"
                }
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = GooglePlacesConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &signing_key, &["google_places.search_text"]).await;

    let token = generate_valid_token(&signing_key, "google_places.search_text");
    let result = connector
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("places-search-text"),
            connector_id: ConnectorId::from_static("fcp.google-places"),
            operation: OperationId::from_static("google_places.search_text"),
            zone_id: ZoneId::private(),
            input: json!({
                "query": "coffee near bryant park",
                "max_result_count": 5
            }),
            capability_token: token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .await
        .expect("invoke should succeed");

    let output = result.result.expect("result should be present");
    assert_eq!(output["places"][0]["name"], "places/abc123");
    assert_eq!(output["places"][0]["displayName"]["text"], "Coffee Shop");
}

#[fcp_async_core::runtime::test]
async fn invoke_autocomplete_uses_autocomplete_specific_field_mask() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/places:autocomplete"))
        .and(header("x-goog-api-key", "test-key"))
        .and(header_regex("x-goog-fieldmask", &fieldmask_regex(DEFAULT_AUTOCOMPLETE_FIELD_MASK)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "suggestions": [
                {
                    "placePrediction": {
                        "place": "places/def456",
                        "placeId": "def456",
                        "text": { "text": "Coffee Roasters" }
                    }
                }
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = GooglePlacesConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(
        &mut connector,
        &signing_key,
        &["google_places.autocomplete"],
    )
    .await;

    let token = generate_valid_token(&signing_key, "google_places.autocomplete");
    let result = connector
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("places-autocomplete"),
            connector_id: ConnectorId::from_static("fcp.google-places"),
            operation: OperationId::from_static("google_places.autocomplete"),
            zone_id: ZoneId::private(),
            input: json!({
                "input": "coffee ro",
                "session_token": "session-123"
            }),
            capability_token: token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .await
        .expect("invoke should succeed");

    let output = result.result.expect("result should be present");
    assert_eq!(
        output["suggestions"][0]["placePrediction"]["place"],
        "places/def456"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_get_place_uses_place_details_field_mask_and_language_code() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/places/ghi789"))
        .and(query_param("languageCode", "en"))
        .and(header("x-goog-api-key", "test-key"))
        .and(header_regex("x-goog-fieldmask", &fieldmask_regex(DEFAULT_PLACE_DETAILS_FIELD_MASK)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "ghi789",
            "name": "places/ghi789",
            "displayName": { "text": "Museum" },
            "formattedAddress": "1 History Way"
        })))
        .mount(&server)
        .await;

    let mut connector = GooglePlacesConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &signing_key, &["google_places.get_place"]).await;

    let token = generate_valid_token(&signing_key, "google_places.get_place");
    let result = connector
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("places-get-place"),
            connector_id: ConnectorId::from_static("fcp.google-places"),
            operation: OperationId::from_static("google_places.get_place"),
            zone_id: ZoneId::private(),
            input: json!({
                "place": "/places/ghi789",
                "language_code": "en"
            }),
            capability_token: token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .await
        .expect("invoke should succeed");

    let output = result.result.expect("result should be present");
    assert_eq!(output["name"], "places/ghi789");
    assert_eq!(output["formattedAddress"], "1 History Way");
}

/// Regression: wiremock 0.6's `header()` exact matcher fails on comma-separated
/// values like `x-goog-fieldmask`. The value is byte-identical in
/// `received_requests()`, but `header(name, value)` returns 404.
/// `header_regex()` works correctly. All fieldmask tests above use the
/// `fieldmask_regex()` helper as a workaround.
#[fcp_async_core::runtime::test]
async fn wiremock_header_exact_fails_on_comma_separated_fieldmask() {
    let server = MockServer::start().await;
    // Exact matcher — known to fail with wiremock 0.6 + hyper for comma values
    Mock::given(method("POST"))
        .and(path("/exact"))
        .and(header("x-goog-fieldmask", DEFAULT_SEARCH_TEXT_FIELD_MASK))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    // Regex matcher — works correctly
    Mock::given(method("POST"))
        .and(path("/regex"))
        .and(header_regex(
            "x-goog-fieldmask",
            &fieldmask_regex(DEFAULT_SEARCH_TEXT_FIELD_MASK),
        ))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let exact = client
        .post(format!("{}/exact", server.uri()))
        .header("X-Goog-FieldMask", DEFAULT_SEARCH_TEXT_FIELD_MASK)
        .send()
        .await
        .expect("send");
    let regex = client
        .post(format!("{}/regex", server.uri()))
        .header("X-Goog-FieldMask", DEFAULT_SEARCH_TEXT_FIELD_MASK)
        .send()
        .await
        .expect("send");

    // Document the bug: exact returns 404, regex returns 200
    assert_eq!(exact.status().as_u16(), 404, "wiremock header() bug: exact match should 404");
    assert_eq!(regex.status().as_u16(), 200, "header_regex workaround must succeed");
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_blank_place_details_field_mask() {
    let mut connector = GooglePlacesConnector::new();
    let result = connector
        .configure(json!({
            "api_key": "test-key",
            "place_details_field_mask": "   "
        }))
        .await;
    assert!(result.is_err(), "blank place_details_field_mask must fail");
}
