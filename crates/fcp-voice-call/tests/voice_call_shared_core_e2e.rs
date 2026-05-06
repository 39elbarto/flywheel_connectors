#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Duration};
use ed25519_dalek::{Signer as _, SigningKey};
use fcp_voice_call::{
    CallCleanupResult, CallShutdownReason, MockVoiceProviderFixture, PlivoParamValue,
    PlivoSignatureVerifier, PlivoSignatureVersion, PlivoVerificationRequest, ProviderHeaders,
    SignatureVerification, TelnyxSignatureVerifier, TwilioSignatureVerifier, VoiceCallError,
    VoiceEvidenceEvent, VoiceProvider, VoiceWebhookMethod, WebhookReplayCache,
    compute_twilio_signature, stable_redacted_hash,
};
use serde_json::json;

const TEST_HMAC_KEY: &str = "fixture_hmac_key_for_voice_call_e2e_tests";

struct JsonlHarness {
    file: File,
    path: std::path::PathBuf,
}

impl JsonlHarness {
    fn new(name: &str) -> std::io::Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix("fcp-voice-call-shared-core-")
            .tempdir()?
            .keep();
        let path = dir.join(format!("{name}.jsonl"));
        let file = File::create(&path)?;
        Ok(Self { file, path })
    }

    fn log(&mut self, event: &VoiceEvidenceEvent) -> Result<(), Box<dyn std::error::Error>> {
        writeln!(self.file, "{}", event.to_jsonl_line()?)?;
        self.file.flush()?;
        Ok(())
    }

    fn log_step(
        &mut self,
        event: &str,
        provider: VoiceProvider,
        outcome: &str,
        fields: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let redacted_fields = fields
            .as_object()
            .map(|object| {
                object
                    .iter()
                    .map(|(key, value)| (key.clone(), value.to_string()))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let event = VoiceEvidenceEvent {
            event: event.into(),
            provider,
            outcome: outcome.into(),
            request_key_preview: None,
            fields: redacted_fields,
        };
        self.log(&event)
    }
}

#[test]
fn voice_call_shared_core_provider_e2e_logs_redaction_safe_jsonl()
-> Result<(), Box<dyn std::error::Error>> {
    let now = DateTime::from_timestamp(1_700_000_000, 0).expect("fixed timestamp");
    let mut harness = JsonlHarness::new("voice_call_shared_core_e2e")?;
    let mut replay_cache = WebhookReplayCache::default();
    let command_line = std::env::args().collect::<Vec<_>>().join(" ");
    let harness_start = json!({
        "command_line": command_line,
        "git_revision": option_env!("GIT_REVISION").unwrap_or("unknown"),
        "skip_reason": "not_skipped",
    });
    harness.log_step(
        "harness_start",
        VoiceProvider::Twilio,
        "running",
        &harness_start,
    )?;

    let twilio_params = vec![
        ("CallSid".to_string(), "CAe2e".to_string()),
        ("From".to_string(), "+15551234567".to_string()),
        ("To".to_string(), "+15557654321".to_string()),
    ];
    let twilio_url = "https://voice.example.com/twilio";
    let twilio_fixture = MockVoiceProviderFixture::new(
        "twilio-signature-replay",
        VoiceProvider::Twilio,
        twilio_url,
        "CAe2e",
    );
    let twilio_signature = compute_twilio_signature(TEST_HMAC_KEY, twilio_url, &twilio_params)?;
    let twilio_verifier = TwilioSignatureVerifier::new(TEST_HMAC_KEY)
        .with_allowed_hosts(["voice.example.com".to_string()]);
    let twilio = twilio_verifier.verify(
        twilio_url,
        &twilio_params,
        &twilio_signature,
        &mut replay_cache,
        now,
    )?;
    harness.log(
        &VoiceEvidenceEvent::from_verification("twilio_signature", &twilio)
            .with_field("fixture_id", &twilio_fixture.id)
            .with_field("request_hash", &twilio_fixture.request_hash)
            .with_field("session_hash", &twilio_fixture.session_hash)
            .with_field("from", "+15551234567")
            .with_field("to", "+15557654321")
            .with_field("call_sid", "CAe2e"),
    )?;

    let telnyx_signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    let telnyx_public_key = STANDARD.encode(telnyx_signing_key.verifying_key().to_bytes());
    let telnyx_verifier = TelnyxSignatureVerifier::new(&telnyx_public_key, Duration::minutes(5))?;
    let telnyx_payload =
        br#"{"data":{"event_type":"call.initiated","payload":{"from":"+15551234567"}}}"#;
    let telnyx_fixture = MockVoiceProviderFixture::new(
        "telnyx-ed25519-valid",
        VoiceProvider::Telnyx,
        std::str::from_utf8(telnyx_payload)?,
        "telnyx-session",
    );
    let timestamp = now.timestamp().to_string();
    let mut signed_payload = timestamp.as_bytes().to_vec();
    signed_payload.push(b'|');
    signed_payload.extend_from_slice(telnyx_payload);
    let telnyx_signature = STANDARD.encode(telnyx_signing_key.sign(&signed_payload).to_bytes());
    let telnyx_headers = ProviderHeaders::new([
        ("Telnyx-Timestamp".to_string(), timestamp),
        ("Telnyx-Signature-Ed25519".to_string(), telnyx_signature),
    ]);
    let telnyx = telnyx_verifier.verify(&telnyx_headers, telnyx_payload, &mut replay_cache, now)?;
    harness.log(
        &VoiceEvidenceEvent::from_verification("telnyx_signature", &telnyx)
            .with_field("fixture_id", &telnyx_fixture.id)
            .with_field("request_hash", &telnyx_fixture.request_hash)
            .with_field("session_hash", &telnyx_fixture.session_hash)
            .with_field("event_type", "call.initiated")
            .with_field("from", "+15551234567"),
    )?;

    let plivo_verifier = PlivoSignatureVerifier::new(TEST_HMAC_KEY);
    let plivo_url = "https://voice.example.com/plivo?foo=bar";
    let plivo_fixture = MockVoiceProviderFixture::new(
        "plivo-v3-callback",
        VoiceProvider::Plivo,
        plivo_url,
        "plivo-session",
    );
    let plivo_nonce = "kjsdhfsd87sd7yisud2";
    let mut plivo_params = BTreeMap::new();
    plivo_params.insert("CallUUID".into(), PlivoParamValue::from("4vbcpem8"));
    plivo_params.insert("From".into(), PlivoParamValue::from("+15551234567"));
    plivo_params.insert("To".into(), PlivoParamValue::from("+15557654321"));
    let plivo_signature = plivo_verifier.compute(
        PlivoSignatureVersion::V3,
        VoiceWebhookMethod::Post,
        plivo_url,
        &plivo_params,
        plivo_nonce,
    )?;
    let plivo_headers = ProviderHeaders::new([
        ("X-Plivo-Signature-V3".to_string(), plivo_signature),
        (
            "X-Plivo-Signature-V3-Nonce".to_string(),
            plivo_nonce.to_string(),
        ),
    ]);
    let plivo = plivo_verifier.verify(
        PlivoVerificationRequest {
            version: PlivoSignatureVersion::V3,
            method: VoiceWebhookMethod::Post,
            url: plivo_url,
            params: &plivo_params,
            headers: &plivo_headers,
            now,
        },
        &mut replay_cache,
    )?;
    harness.log(
        &VoiceEvidenceEvent::from_verification("plivo_signature", &plivo)
            .with_field("fixture_id", &plivo_fixture.id)
            .with_field("request_hash", &plivo_fixture.request_hash)
            .with_field("session_hash", &plivo_fixture.session_hash)
            .with_field("call_uuid", "4vbcpem8")
            .with_field("from", "+15551234567"),
    )?;

    let replay = twilio_verifier.verify(
        twilio_url,
        &twilio_params,
        &twilio_signature,
        &mut replay_cache,
        now,
    )?;
    harness.log(&VoiceEvidenceEvent::from_verification(
        "twilio_replay",
        &replay,
    ))?;

    let invalid = SignatureVerification {
        provider: VoiceProvider::Telnyx,
        valid: false,
        reason_code: "invalid_signature".into(),
        reason: "fixture invalid signature event".into(),
        is_replay: false,
        verified_request_key: None,
    };
    harness.log(&VoiceEvidenceEvent::from_verification(
        "invalid_signature_contract",
        &invalid,
    ))?;
    let mapped_error = VoiceCallError::InvalidSignature("fixture invalid signature".into())
        .to_fcp_error()
        .error_code();
    let error_mapping = json!({
        "fcp_error_code": mapped_error,
        "request_hash": stable_redacted_hash("invalid-signature-fixture"),
    });
    harness.log_step(
        "fcp_error_mapping",
        VoiceProvider::Telnyx,
        "mapped",
        &error_mapping,
    )?;

    let cleanup = CallCleanupResult::completed(
        VoiceProvider::Twilio,
        "CAe2e",
        CallShutdownReason::ProviderCompleted,
    );
    let cleanup_event = serde_json::to_value(cleanup)?;
    harness.log_step(
        "cleanup_result",
        VoiceProvider::Twilio,
        "cleanup_ok",
        &cleanup_event,
    )?;
    let path_event = json!({ "path": harness.path.display().to_string() });
    harness.log_step("jsonl_path", VoiceProvider::Twilio, "written", &path_event)?;

    let contents = std::fs::read_to_string(&harness.path)?;
    println!(
        "voice_call_shared_core_e2e_jsonl={}",
        harness.path.display()
    );
    assert!(twilio.valid);
    assert!(telnyx.valid);
    assert!(plivo.valid);
    assert!(replay.valid);
    assert!(replay.is_replay);
    assert!(contents.contains("\"event\":\"twilio_signature\""));
    assert!(contents.contains("\"event\":\"telnyx_signature\""));
    assert!(contents.contains("\"event\":\"plivo_signature\""));
    assert!(contents.contains("\"is_replay\":\"true\""));
    assert!(!contents.contains("+15551234567"));
    assert!(!contents.contains(TEST_HMAC_KEY));
    assert!(!contents.contains(&twilio_signature));
    Ok(())
}
