use asupersync::Cx;
use asupersync::io::{AsyncRead, ReadBuf};
use asupersync::net::websocket::{
    CloseReason, Message as ServerWsMessage, ServerWebSocket, WebSocketAcceptor,
};
use base64::Engine;
use fcp_async_core::net::{TcpListener, TcpStream};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_mistral::MistralConnector;
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

const OP_MODELS_LIST: &str = "mistral.models.list";
const CAP_MODELS: &str = "mistral.models";
type TestServerWebSocket = ServerWebSocket<TcpStream>;

struct MistralSuiteAdapter {
    connector: MistralConnector,
    id: ConnectorId,
}

impl MistralSuiteAdapter {
    fn new() -> Self {
        Self {
            connector: MistralConnector::new(),
            id: ConnectorId::from_static("fcp.mistral"),
        }
    }
}

fcp_core::impl_fcp_sealed!(MistralSuiteAdapter);

#[fcp_core::async_trait]
impl FcpConnector for MistralSuiteAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        self.connector
            .handle_handshake(json!({ "session_id": "mistral-connector-suite" }))
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
            manifest_hash: "sha256:mistral-connector-suite".into(),
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
                Some(other) => HealthSnapshot::degraded(format!("mistral_status:{other}")),
                None => HealthSnapshot::error("mistral_status:missing"),
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
                id: OperationId::from_static(OP_MODELS_LIST),
                summary: "List Mistral models".into(),
                description: None,
                input_schema: json!({ "type": "object", "properties": {} }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_MODELS),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use to discover Mistral model identifiers.".into(),
                    common_mistakes: Vec::new(),
                    examples: vec!["{}".into()],
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
        host_public_key: [41u8; 32],
        nonce: [43u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_MODELS)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn models_invoke(id: &'static str) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static("fcp.mistral"),
        operation: OperationId::from_static(OP_MODELS_LIST),
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

fn suite(server: &MockServer, test_name: &'static str, expect_error: bool) -> ConnectorSuite {
    ConnectorSuite {
        test_name: test_name.into(),
        config: json!({
            "api_key": "mistral_test_key",
            "base_url": server.uri()
        }),
        handshake: handshake_request(),
        invoke: Some(models_invoke(test_name)),
        invoke_expectations: InvokeExpectations {
            expect_error,
            ..InvokeExpectations::default()
        },
    }
}

async fn read_http_headers<IO: AsyncRead + Unpin>(io: &mut IO) -> io::Result<Vec<u8>> {
    const MAX_HEADERS: usize = 16 * 1024;

    let mut buf = Vec::with_capacity(1024);
    let mut temp = [0_u8; 256];

    loop {
        let read = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut *io).poll_read(cx, &mut read_buf) {
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

async fn accept_mistral_test_websocket(mut stream: TcpStream) -> (TestServerWebSocket, String) {
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
async fn connector_suite_models_happy_path_uses_mock_server() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .and(header("Authorization", "Bearer mistral_test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "mistral-small-latest", "name": "Mistral Small"}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = MistralSuiteAdapter::new();
    let mut runner = E2eRunner::new("fcp-mistral");
    let report = runner
        .run_connector_suite(
            &mut connector,
            suite(&server, "mistral_models_connector_suite_happy_path", false),
        )
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
    let expected_audio = base64::engine::general_purpose::STANDARD.encode(b"mulaw-audio");

    let ws_task = fcp_async_core::task::spawn({
        let expected_audio = expected_audio.clone();
        async move {
            let (tcp_stream, _) = listener.accept().await.expect("accept websocket client");
            let (mut ws, headers) = accept_mistral_test_websocket(tcp_stream).await;
            assert!(
                headers.starts_with(
                    "GET /v1/audio/transcriptions/realtime?model=voxtral-mini-transcribe-realtime-2602&target_streaming_delay_ms=800 HTTP/1.1"
                ),
                "unexpected realtime websocket request: {headers}"
            );
            assert!(
                headers.contains("Authorization: Bearer test-api-key-xyz"),
                "missing authorization header: {headers}"
            );

            send_json_frame(
                &mut ws,
                json!({
                    "type": "session.created",
                    "session": {
                        "request_id": "mistral-rt-loopback",
                        "model": "voxtral-mini-transcribe-realtime-2602",
                        "audio_format": {
                            "encoding": "pcm_mulaw",
                            "sample_rate": 8000
                        },
                        "target_streaming_delay_ms": 800
                    }
                }),
                "send session.created",
            )
            .await;

            let update = recv_text_frame(&mut ws, "receive session update").await?;
            let update: serde_json::Value =
                serde_json::from_str(&update).expect("session update json");
            assert_eq!(update["type"], "session.update");
            assert_eq!(update["session"]["audio_format"]["encoding"], "pcm_mulaw");
            assert_eq!(update["session"]["audio_format"]["sample_rate"], 8000);
            assert_eq!(update["session"]["target_streaming_delay_ms"], 800);

            let append = recv_text_frame(&mut ws, "receive audio append").await?;
            let append: serde_json::Value = serde_json::from_str(&append).expect("append json");
            assert_eq!(append["type"], "input_audio.append");
            assert_eq!(append["audio"], expected_audio);

            let flush = recv_text_frame(&mut ws, "receive audio flush").await?;
            let flush: serde_json::Value = serde_json::from_str(&flush).expect("flush json");
            assert_eq!(flush["type"], "input_audio.flush");

            let end = recv_text_frame(&mut ws, "receive audio end").await?;
            let end: serde_json::Value = serde_json::from_str(&end).expect("end json");
            assert_eq!(end["type"], "input_audio.end");

            send_json_frame(
                &mut ws,
                json!({
                    "type": "transcription.text.delta",
                    "text": "Hello "
                }),
                "send text delta",
            )
            .await;
            send_json_frame(
                &mut ws,
                json!({
                    "type": "transcription.segment",
                    "text": "Hello from Voxtral",
                    "start": 0.0,
                    "end": 1.25
                }),
                "send segment",
            )
            .await;
            send_json_frame(
                &mut ws,
                json!({
                    "type": "transcription.done"
                }),
                "send done",
            )
            .await;
            close_test_websocket(&mut ws).await;
            Ok::<(), String>(())
        }
    });

    let mut connector = MistralConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "test-api-key-xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
    connector
        .handle_handshake(json!({ "session_id": "mistral-loopback-session" }))
        .await
        .expect("handshake should succeed");

    let result = connector
        .handle_invoke(json!({
            "operation_id": "mistral.audio.realtime.transcribe",
            "input": {
                "audio_base64": expected_audio,
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
            .starts_with("fcp-mistral-rt-")
    );
    assert_eq!(result["provider_session_id"], "mistral-rt-loopback");
    assert_eq!(result["model"], "voxtral-mini-transcribe-realtime-2602");
    assert_eq!(result["audio_format"]["encoding"], "pcm_mulaw");
    assert_eq!(result["audio_format"]["sample_rate"], 8000);
    assert_eq!(result["target_streaming_delay_ms"], 800);
    assert_eq!(result["text"], "Hello from Voxtral");
    assert_eq!(result["partials"].as_array().expect("partials").len(), 1);
    assert_eq!(result["segments"].as_array().expect("segments").len(), 1);
    assert_eq!(result["stats"]["reconnect_attempts"], 0);
    assert_eq!(
        result["provenance"]["source"],
        "mistral.audio.realtime.transcribe"
    );

    ws_task
        .await
        .expect("websocket task")
        .expect("websocket proof");
}

#[fcp_async_core::runtime::test]
async fn connector_suite_models_error_path_is_expected() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .and(header("Authorization", "Bearer mistral_test_key"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_json(json!({
                    "message": "rate limited"
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = MistralSuiteAdapter::new();
    let mut runner = E2eRunner::new("fcp-mistral");
    let report = runner
        .run_connector_suite(
            &mut connector,
            suite(&server, "mistral_models_connector_suite_error_path", true),
        )
        .await
        .expect("connector suite run");

    assert!(report.passed, "expected upstream error should pass suite");
}
