use asupersync::Cx;
use asupersync::io::{AsyncRead, ReadBuf};
use asupersync::net::websocket::{
    CloseReason, Message as ServerWsMessage, ServerWebSocket, WebSocketAcceptor,
};
use base64::Engine;
use fcp_async_core::net::{TcpListener, TcpStream};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_elevenlabs::ElevenlabsConnector;
use fcp_prelude::{
    AgentHint, CapabilityGrant, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, SessionId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use serde_json::json;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::Poll;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const OP_VOICES_LIST: &str = "elevenlabs.voices.list";
const CAP_VOICES: &str = "elevenlabs.voices";
const MAX_HEADERS: usize = 16 * 1024;
type TestServerWebSocket = ServerWebSocket<TcpStream>;

struct ElevenlabsSuiteAdapter {
    connector: ElevenlabsConnector,
    id: ConnectorId,
}

impl ElevenlabsSuiteAdapter {
    fn new() -> Self {
        Self {
            connector: ElevenlabsConnector::new(),
            id: ConnectorId::from_static("fcp.elevenlabs"),
        }
    }
}

fcp_core::impl_fcp_sealed!(ElevenlabsSuiteAdapter);

#[fcp_core::async_trait]
impl FcpConnector for ElevenlabsSuiteAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        self.connector
            .handle_handshake(json!({ "session_id": "elevenlabs-connector-suite" }))
            .await?;

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: "sha256:elevenlabs-connector-suite".into(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.handle_health().await {
            Ok(payload) => match payload.get("status").and_then(serde_json::Value::as_str) {
                Some("healthy") => HealthSnapshot::ready(),
                Some(other) => HealthSnapshot::degraded(format!("elevenlabs_status:{other}")),
                None => HealthSnapshot::error("elevenlabs_status:missing"),
            },
            Err(error) => HealthSnapshot::error(error.to_string()),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.connector.handle_shutdown(json!({})).await.map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static(OP_VOICES_LIST),
                summary: "List ElevenLabs voices".into(),
                description: None,
                input_schema: json!({ "type": "object", "properties": {} }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_VOICES),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use for read-only voice catalog discovery.".into(),
                    common_mistakes: Vec::new(),
                    examples: vec![r"{}".into()],
                    related: Vec::new(),
                },
                rate_limit: None,
                requires_approval: None,
            }],
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        let request_id = req.id;
        let operation_id = req.operation.as_str().to_string();
        let value = self
            .connector
            .handle_invoke(json!({
                "operation_id": operation_id,
                "input": req.input,
            }))
            .await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let request_id = req.id;
        let operation_id = req.operation.as_str().to_string();
        let value = self
            .connector
            .handle_simulate(json!({
                "operation_id": operation_id,
                "input": req.input,
            }))
            .await?;
        if value
            .get("allowed")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            Ok(SimulateResponse::allowed(request_id))
        } else {
            Ok(SimulateResponse::denied(
                request_id,
                "operation is not supported",
                "FCP-3010",
            ))
        }
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> fcp_core::FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }
}

fn handshake_request() -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key: [23u8; 32],
        nonce: [17u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_VOICES)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn voices_invoke(id: &'static str) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static("fcp.elevenlabs"),
        operation: OperationId::from_static(OP_VOICES_LIST),
        zone_id: ZoneId::work(),
        input: json!({}),
        capability_token: CapabilityToken::test_token(),
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

fn suite(server: &MockServer) -> ConnectorSuite {
    ConnectorSuite {
        test_name: "elevenlabs_voices_connector_suite_happy_path".into(),
        config: json!({
            "api_key": "elevenlabs_test_key",
            "base_url": server.uri()
        }),
        handshake: handshake_request(),
        invoke: Some(voices_invoke("elevenlabs-voices-suite")),
        invoke_expectations: InvokeExpectations::default(),
    }
}

async fn read_http_headers<R>(stream: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut temp = [0_u8; 1024];
    loop {
        let read = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut *stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before websocket handshake completed",
            ));
        }

        let filled = temp.get(..read).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket handshake read exceeded buffer",
            )
        })?;
        buf.extend_from_slice(filled);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket handshake headers too large",
            ));
        }
    }
}

async fn accept_elevenlabs_test_websocket(mut stream: TcpStream) -> (TestServerWebSocket, String) {
    let request = read_http_headers(&mut stream)
        .await
        .expect("read websocket handshake");
    let headers = String::from_utf8_lossy(&request).into_owned();
    let ws = WebSocketAcceptor::new()
        .accept(&Cx::for_testing(), &request, stream)
        .await
        .expect("accept websocket");
    (ws, headers)
}

async fn send_json_frame(ws: &mut TestServerWebSocket, value: serde_json::Value, context: &str) {
    ws.send(&Cx::for_testing(), ServerWsMessage::text(value.to_string()))
        .await
        .expect(context);
}

async fn recv_text_frame(ws: &mut TestServerWebSocket, context: &str) -> Result<String, String> {
    match ws.recv(&Cx::for_testing()).await {
        Ok(Some(ServerWsMessage::Text(text))) => Ok(text),
        Ok(Some(other)) => Err(format!("expected text frame for {context}, got {other:?}")),
        Ok(None) => Err(format!("websocket closed before {context}")),
        Err(err) => Err(format!("{context}: {err}")),
    }
}

async fn close_test_websocket(ws: &mut TestServerWebSocket) {
    let _ = ws.close(&Cx::for_testing(), CloseReason::normal()).await;
}

#[fcp_async_core::runtime::test]
async fn connector_suite_voices_happy_path_uses_mock_server() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/voices"))
        .and(header("xi-api-key", "elevenlabs_test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "voices": [{
                "voice_id": "voice-suite",
                "name": "Suite Voice"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = ElevenlabsSuiteAdapter::new();
    let mut runner = E2eRunner::new("fcp-elevenlabs");
    let report = runner
        .run_connector_suite(&mut connector, suite(&server))
        .await
        .expect("connector suite run");

    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "structured logs should be present");
}

#[fcp_async_core::runtime::test]
async fn realtime_transcription_loopback_websocket_session() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket listener");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("listener local addr")
    );
    let expected_audio = base64::engine::general_purpose::STANDARD.encode(b"ulaw-audio");

    let ws_task = fcp_async_core::task::spawn({
        let expected_audio = expected_audio.clone();
        async move {
            let (tcp_stream, _) = listener.accept().await.expect("accept websocket client");
            let (mut ws, headers) = accept_elevenlabs_test_websocket(tcp_stream).await;
            assert!(
                headers.starts_with(
                    "GET /v1/speech-to-text/realtime?model_id=scribe_v2_realtime&audio_format=ulaw_8000&commit_strategy=vad&include_timestamps=false&include_language_detection=false&language_code=en HTTP/1.1"
                ),
                "unexpected realtime websocket request: {headers}"
            );
            assert!(
                headers.contains("xi-api-key: test-api-key-xyz"),
                "missing xi-api-key header: {headers}"
            );

            send_json_frame(
                &mut ws,
                json!({
                    "message_type": "session_started",
                    "session_id": "elevenlabs-rt-loopback",
                    "config": {
                        "sample_rate": 8000,
                        "audio_format": "ulaw_8000",
                        "language_code": "en",
                        "model_id": "scribe_v2_realtime",
                        "include_timestamps": false,
                        "include_language_detection": false
                    }
                }),
                "send session_started",
            )
            .await;

            let chunk = recv_text_frame(&mut ws, "receive audio chunk").await?;
            let chunk: serde_json::Value = serde_json::from_str(&chunk).expect("chunk json");
            assert_eq!(chunk["message_type"], "input_audio_chunk");
            assert_eq!(chunk["audio_base_64"], expected_audio);
            assert_eq!(chunk["sample_rate"], 8000);
            assert!(chunk.get("commit").is_none());

            let close = recv_text_frame(&mut ws, "receive close commit").await?;
            let close: serde_json::Value = serde_json::from_str(&close).expect("close json");
            assert_eq!(close["message_type"], "input_audio_chunk");
            assert_eq!(close["audio_base_64"], "");
            assert_eq!(close["sample_rate"], 8000);
            assert_eq!(close["commit"], true);

            send_json_frame(
                &mut ws,
                json!({
                    "message_type": "partial_transcript",
                    "text": "hello from"
                }),
                "send partial transcript",
            )
            .await;
            send_json_frame(
                &mut ws,
                json!({
                    "message_type": "committed_transcript_with_timestamps",
                    "text": "hello from elevenlabs realtime",
                    "language_code": "en",
                    "words": []
                }),
                "send committed transcript",
            )
            .await;
            close_test_websocket(&mut ws).await;
            Ok::<(), String>(())
        }
    });

    let mut connector = ElevenlabsConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "test-api-key-xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
    connector
        .handle_handshake(json!({ "session_id": "elevenlabs-loopback-session" }))
        .await
        .expect("handshake should succeed");

    let result = connector
        .handle_invoke(json!({
            "operation_id": "elevenlabs.scribe.realtime.transcribe",
            "input": {
                "audio_base64": expected_audio,
                "language_code": "en",
                "timeout_ms": 2_000,
                "connect_timeout_ms": 1_000,
                "max_reconnect_attempts": 0
            }
        }))
        .await
        .expect("realtime invoke should succeed");

    assert!(
        result["session_id"]
            .as_str()
            .expect("session id string")
            .starts_with("fcp-elevenlabs-rt-")
    );
    assert_eq!(result["provider_session_id"], "elevenlabs-rt-loopback");
    assert_eq!(result["model_id"], "scribe_v2_realtime");
    assert_eq!(result["audio_format"]["encoding"], "ulaw_8000");
    assert_eq!(result["audio_format"]["sample_rate"], 8000);
    assert_eq!(result["commit_strategy"], "vad");
    assert_eq!(result["language_code"], "en");
    assert_eq!(result["text"], "hello from elevenlabs realtime");
    assert_eq!(result["partials"].as_array().expect("partials").len(), 1);
    assert_eq!(result["committed"].as_array().expect("committed").len(), 1);
    assert_eq!(result["stats"]["audio_chunks_sent"], 1);
    assert_eq!(result["stats"]["audio_bytes_sent"], 10);
    assert_eq!(result["stats"]["reconnect_attempts"], 0);
    assert_eq!(
        result["provenance"]["source"],
        "elevenlabs.scribe.realtime.transcribe"
    );

    ws_task
        .await
        .expect("websocket task")
        .expect("websocket proof");
}
