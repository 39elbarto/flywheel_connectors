use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_google_places::GooglePlacesConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, HandshakeRequest,
    InvokeRequest, OperationId, RequestId, ZoneId,
};
use fcp_sdk::prelude::FcpConnector;
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_READ";
const API_KEY_ENV: &str = "GOOGLE_PLACES_API_KEY";
const OPERATION: &str = "google_places.search_text";

fn live_gate_enabled() -> bool {
    std::env::var(LIVE_GATE_ENV)
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn generate_valid_token(signing_key: &Ed25519SigningKey) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id("google_places.read")
        .zone_id("z:private")
        .principal("user:live-smoke")
        .operations(&[OPERATION])
        .issuer("node:live-smoke")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("token should sign");
    CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut GooglePlacesConnector, signing_key: &Ed25519SigningKey) {
    connector
        .handshake(HandshakeRequest {
            protocol_version: "1.0.0".into(),
            zone: ZoneId::private(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [0u8; 32],
            capabilities_requested: vec![CapabilityId::from_static("google_places.read")],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("Google Places handshake should succeed");
}

fn emit_live_jsonl(status: &str, reason: &str, result_count: usize) {
    println!(
        "GOOGLE_PLACES_LIVE_JSONL {}",
        json!({
            "event": "google_places_live_read_smoke",
            "fixture_mode": "live",
            "suite_class": "live_read_only",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": API_KEY_ENV,
            "operation": OPERATION,
            "status": status,
            "provider": "Google Places API New",
            "resource_class": "text_search_read",
            "result_count": result_count,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one Places Text Search request with max_result_count=1.",
            "mutation_expected": false,
            "cleanup_result": "not_required",
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
        })
    );
}

#[fcp_async_core::runtime::test]
async fn google_places_live_read_text_search_or_structured_skip_jsonl() {
    if !live_gate_enabled() {
        emit_live_jsonl("skipped", &format!("{LIVE_GATE_ENV} is not set to 1"), 0);
        return;
    }

    let Some(api_key) = env_value(API_KEY_ENV) else {
        emit_live_jsonl("skipped", &format!("{API_KEY_ENV} is not set"), 0);
        return;
    };

    let mut connector = GooglePlacesConnector::new();
    connector
        .configure(json!({
            "api_key": api_key,
            "request_timeout_ms": 10_000,
        }))
        .await
        .expect("configure Google Places API key");

    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(&mut connector, &signing_key).await;
    let capability = generate_valid_token(&signing_key);

    match connector
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("google-places-live-read"),
            connector_id: ConnectorId::from_static("fcp.google-places"),
            operation: OperationId::from_static(OPERATION),
            zone_id: ZoneId::private(),
            input: json!({
                "query": "coffee near Bryant Park",
                "max_result_count": 1,
            }),
            capability_token: capability,
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
    {
        Ok(response) => {
            let output = response.result.unwrap_or_else(|| json!({}));
            let result_count = output
                .get("places")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            assert!(
                result_count <= 1,
                "live smoke caps Google Places result count"
            );
            emit_live_jsonl("passed", "", result_count);
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0);
            panic!("Google Places live read smoke failed: {error}");
        }
    }
}
