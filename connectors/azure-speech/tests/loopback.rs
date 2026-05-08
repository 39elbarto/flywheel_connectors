use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fcp_azure_speech::AzureSpeechConnector;
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn configured_connector(server: &MockServer) -> AzureSpeechConnector {
    let mut connector = AzureSpeechConnector::new();
    connector
        .handle_configure(json!({
            "subscription_key": "loopback-secret",
            "region": "eastus",
            "token_url": format!("{}/sts/v1.0/issueToken", server.uri()),
            "tts_base_url": server.uri(),
            "stt_base_url": server.uri(),
            "inline_audio_max_bytes": 4,
        }))
        .await
        .expect("configure should succeed");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake should succeed");
    connector
}

#[fcp_async_core::runtime::test]
async fn voices_and_tts_use_issued_token_and_redact_large_audio() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/sts/v1.0/issueToken"))
        .and(header("ocp-apim-subscription-key", "loopback-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_string("token-1"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/cognitiveservices/voices/list"))
        .and(header("authorization", "Bearer token-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"Name": "en-US-ChristopherNeural", "Locale": "en-US"}
        ])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/cognitiveservices/v1"))
        .and(header("authorization", "Bearer token-1"))
        .and(header(
            "x-microsoft-outputformat",
            "riff-24khz-16bit-mono-pcm",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "audio/wav")
                .set_body_bytes(vec![1_u8, 2, 3, 4, 5, 6]),
        )
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let voices = connector
        .handle_invoke(json!({"operation_id": "azure.speech.voices.list"}))
        .await
        .expect("voices list should succeed");
    assert_eq!(voices["voices"][0]["Name"], "en-US-ChristopherNeural");

    let tts = connector
        .handle_invoke(json!({
            "operation_id": "azure.speech.tts.synthesize",
            "input": {
                "text": "hello",
                "voice": "en-US-ChristopherNeural",
                "locale": "en-US"
            }
        }))
        .await
        .expect("tts should succeed");
    assert_eq!(tts["mode"], "artifact_reference");
    assert_eq!(tts["audio_base64"], Value::Null);
    assert_eq!(tts["artifact"]["byte_count"], 6);
}

#[fcp_async_core::runtime::test]
async fn fast_transcription_posts_2025_10_15_multipart_and_preserves_result_shape() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/speechtotext/transcriptions:transcribe"))
        .and(query_param("api-version", "2025-10-15"))
        .and(header("ocp-apim-subscription-key", "loopback-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "durationMilliseconds": 2000,
            "combinedPhrases": [{"channel": 0, "text": "Weather"}],
            "phrases": [{
                "channel": 0,
                "text": "Weather",
                "confidence": 0.789,
                "words": [{"text": "weather", "confidence": 0.8}]
            }]
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "azure.speech.stt.transcribe_fast",
            "input": {
                "audio_base64": BASE64_STANDARD.encode([1_u8, 2, 3, 4]),
                "content_type": "audio/wav",
                "locales": ["en-US"],
                "phrase_list": {"phrases": ["Weather"], "biasingWeight": 1.4},
                "channels": [0]
            }
        }))
        .await
        .expect("transcription should succeed");
    assert_eq!(result["text"], "Weather");
    assert_eq!(result["api_version"], "2025-10-15");
    assert_eq!(
        result["provider_result"]["phrases"][0]["words"][0]["confidence"],
        0.8
    );
}
