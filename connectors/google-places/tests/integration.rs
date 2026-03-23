//! Integration tests for the Google Places connector.

use chrono::Utc;
use fcp_core::{CapabilityToken, IdempotencyClass, RiskLevel, SafetyTier};
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
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &str) -> CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id("google_places.read")
        .zone_id("z:private")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + chrono::Duration::hours(1))
        .sign(signing_key)
        .expect("token should sign");
    CapabilityToken { raw: cose }
}

async fn setup_handshake(
    connector: &mut GooglePlacesConnector,
    signing_key: &Ed25519SigningKey,
    capabilities: &[&str],
) {
    let verifying_key = signing_key.verifying_key();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:private",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": capabilities,
        }))
        .await
        .expect("handshake should succeed");
}

async fn setup_configure(connector: &mut GooglePlacesConnector, api_url: &str) {
    connector
        .handle_configure(json!({
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
        .and(header("x-goog-fieldmask", DEFAULT_SEARCH_TEXT_FIELD_MASK))
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
        .handle_invoke(json!({
            "operation": "google_places.search_text",
            "input": {
                "query": "coffee near bryant park",
                "max_result_count": 5
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["places"][0]["name"], "places/abc123");
    assert_eq!(result["places"][0]["displayName"]["text"], "Coffee Shop");
}

#[fcp_async_core::runtime::test]
async fn invoke_autocomplete_uses_autocomplete_specific_field_mask() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/places:autocomplete"))
        .and(header("x-goog-api-key", "test-key"))
        .and(header("x-goog-fieldmask", DEFAULT_AUTOCOMPLETE_FIELD_MASK))
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
        .handle_invoke(json!({
            "operation": "google_places.autocomplete",
            "input": {
                "input": "coffee ro",
                "session_token": "session-123"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(
        result["suggestions"][0]["placePrediction"]["place"],
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
        .and(header("x-goog-fieldmask", DEFAULT_PLACE_DETAILS_FIELD_MASK))
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
        .handle_invoke(json!({
            "operation": "google_places.get_place",
            "input": {
                "place": "/places/ghi789",
                "language_code": "en"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["name"], "places/ghi789");
    assert_eq!(result["formattedAddress"], "1 History Way");
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_blank_place_details_field_mask() {
    let mut connector = GooglePlacesConnector::new();
    let result = connector
        .handle_configure(json!({
            "api_key": "test-key",
            "place_details_field_mask": "   "
        }))
        .await;
    assert!(result.is_err(), "blank place_details_field_mask must fail");
}
