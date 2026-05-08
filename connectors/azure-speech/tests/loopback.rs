use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fcp_azure_speech::AzureSpeechConnector;
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_RESOURCE_ID: &str = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/speech";

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

async fn configured_entra_connector(
    server: &MockServer,
    token_format: &str,
) -> AzureSpeechConnector {
    let mut connector = AzureSpeechConnector::new();
    let mut params = json!({
        "entra_access_token": "aad-secret",
        "entra_token_format": token_format,
        "entra_token_source": "managed_identity",
        "region": "eastus",
        "token_url": format!("{}/sts/v1.0/issueToken", server.uri()),
        "tts_base_url": server.uri(),
        "stt_base_url": server.uri(),
        "inline_audio_max_bytes": 4,
    });
    if token_format == "aad_resource_token" {
        params["entra_resource_id"] = json!(TEST_RESOURCE_ID);
    }
    let configured = connector
        .handle_configure(params)
        .await
        .expect("configure should succeed");
    assert_eq!(configured["auth_mode"], "entra_access_token");
    assert_eq!(configured["auth_token_source"], "managed_identity");
    assert!(
        !serde_json::to_string(&configured)
            .expect("configure result should serialize")
            .contains("aad-secret")
    );
    assert!(
        !serde_json::to_string(&configured)
            .expect("configure result should serialize")
            .contains(TEST_RESOURCE_ID)
    );
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
async fn entra_aad_resource_token_uses_authorization_without_issue_token() {
    let server = MockServer::start().await;
    let expected_authorization = format!("Bearer aad#{TEST_RESOURCE_ID}#aad-secret");
    Mock::given(method("GET"))
        .and(path("/cognitiveservices/voices/list"))
        .and(header("authorization", expected_authorization.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"Name": "en-US-ChristopherNeural", "Locale": "en-US"}
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_entra_connector(&server, "aad_resource_token").await;
    let self_check = connector
        .handle_self_check()
        .await
        .expect("self-check should validate the configured Entra header");
    assert_eq!(self_check["status"], "ok");
    assert_eq!(self_check["auth_token_format"], "aad_resource_token");
    assert!(self_check["entra_resource_id_hash"].as_str().is_some());
    assert!(
        !serde_json::to_string(&self_check)
            .expect("self-check should serialize")
            .contains(TEST_RESOURCE_ID)
    );

    let voices = connector
        .handle_invoke(json!({"operation_id": "azure.speech.voices.list"}))
        .await
        .expect("voices list should succeed with Entra auth");
    assert_eq!(voices["voices"][0]["Name"], "en-US-ChristopherNeural");
}

#[fcp_async_core::runtime::test]
async fn entra_bearer_token_authenticates_2025_10_15_fast_transcription() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/speechtotext/transcriptions:transcribe"))
        .and(query_param("api-version", "2025-10-15"))
        .and(header("authorization", "Bearer aad-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "durationMilliseconds": 1000,
            "combinedPhrases": [{"text": "Hello"}],
            "phrases": [{"text": "Hello", "confidence": 0.9}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_entra_connector(&server, "bearer_token").await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "azure.speech.stt.transcribe_fast",
            "input": {
                "audio_base64": BASE64_STANDARD.encode([1_u8, 2, 3, 4]),
                "content_type": "audio/wav",
                "locale": "en-US"
            }
        }))
        .await
        .expect("fast transcription should succeed with raw Entra bearer auth");
    assert_eq!(result["text"], "Hello");
    assert_eq!(result["api_version"], "2025-10-15");
}

#[fcp_async_core::runtime::test]
async fn credential_id_mode_allows_host_injected_auth_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cognitiveservices/voices/list"))
        .and(header(
            "x-fcp-credential-id",
            "11223344-5566-7788-99aa-bbccddeeff00",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"Name": "en-US-AvaNeural", "Locale": "en-US"}
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = AzureSpeechConnector::new();
    connector
        .handle_configure(json!({
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "region": "eastus",
            "token_url": format!("{}/sts/v1.0/issueToken", server.uri()),
            "tts_base_url": server.uri(),
            "stt_base_url": server.uri(),
        }))
        .await
        .expect("credential_id config should succeed");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake should succeed");
    let health = connector
        .handle_health()
        .await
        .expect("health should serialize");
    assert_eq!(health["status"], "degraded");
    assert_eq!(health["live_requests_supported"], true);
    assert_eq!(health["direct_live_auth_supported"], false);

    let voices = connector
        .handle_invoke(json!({"operation_id": "azure.speech.voices.list"}))
        .await
        .expect("host-injected credential_id request should be allowed");
    assert_eq!(voices["voices"][0]["Name"], "en-US-AvaNeural");
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

#[fcp_async_core::runtime::test]
async fn batch_transcription_submit_get_and_files_redact_provider_urls() {
    let server = MockServer::start().await;
    let transcription_id = "ba7ea6f5-3065-40b7-b49a-a90f48584683";
    Mock::given(method("POST"))
        .and(path("/speechtotext/transcriptions:submit"))
        .and(query_param("api-version", "2025-10-15"))
        .and(header("ocp-apim-subscription-key", "loopback-secret"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header(
                    "location",
                    format!(
                        "{}/speechtotext/transcriptions/{transcription_id}?api-version=2025-10-15",
                        server.uri()
                    ),
                )
                .set_body_json(json!({
                    "self": format!("{}/speechtotext/transcriptions/{transcription_id}?api-version=2025-10-15", server.uri()),
                    "displayName": "nightly support calls",
                    "locale": "en-US",
                    "links": {
                        "files": format!("{}/speechtotext/transcriptions/{transcription_id}/files?api-version=2025-10-15&sig=SECRET", server.uri())
                    },
                    "status": "Running"
                })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/speechtotext/transcriptions/{transcription_id}")))
        .and(query_param("api-version", "2025-10-15"))
        .and(header("ocp-apim-subscription-key", "loopback-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "self": format!("{}/speechtotext/transcriptions/{transcription_id}?api-version=2025-10-15", server.uri()),
            "status": "Succeeded",
            "links": {
                "files": format!("{}/speechtotext/transcriptions/{transcription_id}/files?api-version=2025-10-15", server.uri())
            },
            "properties": {
                "durationMilliseconds": 42000
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/speechtotext/transcriptions/{transcription_id}/files"
        )))
        .and(query_param("api-version", "2025-10-15"))
        .and(query_param("sasValidityInSeconds", "300"))
        .and(query_param("top", "2"))
        .and(header("ocp-apim-subscription-key", "loopback-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "values": [{
                "name": "audio.wav.json",
                "kind": "Transcription",
                "links": {
                    "contentUrl": "https://storage.example/transcript.json?sig=SECRET&se=2030-01-01"
                }
            }]
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let submit = connector
        .handle_invoke(json!({
            "operation_id": "azure.speech.stt.batch.submit",
            "input": {
                "display_name": "nightly support calls",
                "locale": "en-US",
                "content_urls": ["https://storage.example/audio.wav?sig=SECRET"],
                "time_to_live_hours": 48,
                "profanity_filter_mode": "Masked"
            }
        }))
        .await
        .expect("batch submit should succeed");
    assert_eq!(submit["api_version"], "2025-10-15");
    assert_eq!(submit["content_source"]["mode"], "content_urls");
    assert!(submit["transcription_id_hash"].as_str().is_some());
    assert!(
        !serde_json::to_string(&submit)
            .expect("submit JSON should serialize")
            .contains("SECRET")
    );

    let status = connector
        .handle_invoke(json!({
            "operation_id": "azure.speech.stt.batch.get",
            "input": {
                "transcription_id": transcription_id
            }
        }))
        .await
        .expect("batch status should succeed");
    assert_eq!(status["transcription"]["status"], "Succeeded");

    let files = connector
        .handle_invoke(json!({
            "operation_id": "azure.speech.stt.batch.files",
            "input": {
                "transcription_id": transcription_id,
                "sas_validity_seconds": 300,
                "top": 2
            }
        }))
        .await
        .expect("batch files should succeed");
    assert_eq!(files["files"]["values"][0]["name"], "audio.wav.json");
    assert_eq!(
        files["files"]["values"][0]["links"]["contentUrl"]["redacted"],
        true
    );
    assert!(
        !serde_json::to_string(&files)
            .expect("files JSON should serialize")
            .contains("SECRET")
    );
}
