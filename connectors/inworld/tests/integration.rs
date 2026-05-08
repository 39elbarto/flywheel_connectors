#![allow(clippy::too_many_lines)]

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::Poll;

use asupersync::net::websocket::{
    CloseReason, Message as ServerWsMessage, ServerWebSocket, WebSocketAcceptor,
};
use chrono::{Duration as ChronoDuration, Utc};
use fcp_async_core::Cx;
use fcp_async_core::io::{AsyncRead, ReadBuf};
use fcp_async_core::net::{TcpListener, TcpStream};
use fcp_async_core::task;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_inworld::InworldConnector;
use fcp_inworld::connector::{
    CAP_REALTIME, CAP_ROUTER, CAP_TTS, OP_REALTIME_AUDIO, OP_REALTIME_TEXT, OP_ROUTER_CHAT,
    OP_TTS_CONTEXT, test_handshake_request,
};
use fcp_inworld::types::stable_hash;
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector, FcpError, InstanceId};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

type TestServerWebSocket = ServerWebSocket<TcpStream>;

fn valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> fcp_prelude::CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability grant should sign");
    fcp_prelude::CapabilityToken::from_raw(cose)
}

async fn configured_connector(
    realtime_ws_url: &str,
    tts_ws_url: &str,
    router_base_url: &str,
    capabilities: &[&'static str],
) -> (InworldConnector, Ed25519SigningKey) {
    let mut connector = InworldConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "test-basic",
            "realtime_ws_url": realtime_ws_url,
            "tts_ws_url": tts_ws_url,
            "router_base_url": router_base_url,
            "request_timeout_ms": 5000
        }))
        .await
        .expect("configure should succeed");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let caps = capabilities
        .iter()
        .map(|capability| CapabilityId::from_static(capability))
        .collect();
    connector
        .handshake(test_handshake_request(caps, verifying_key.to_bytes()))
        .await
        .expect("handshake should succeed");
    (connector, signing_key)
}

async fn invoke(
    connector: &InworldConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> Value {
    let grant = valid_token(signing_key, connector.instance_id(), capability, operation);
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": grant,
        }))
        .await
        .expect("invoke should succeed")
}

fn emit_fixture(
    event: &str,
    instance_id: &InstanceId,
    operation_id: &str,
    capability: &str,
    payload: &Value,
) {
    let mut object = serde_json::Map::new();
    object.insert("event".into(), json!(event));
    object.insert("command_line".into(), json!("cargo test -p fcp-inworld"));
    object.insert("connector_id".into(), json!("fcp.inworld"));
    object.insert("operation_id".into(), json!(operation_id));
    object.insert("capability".into(), json!(capability));
    object.insert("zone".into(), json!("z:work"));
    object.insert(
        "instance_id_hash".into(),
        json!(stable_hash(instance_id.as_str())),
    );
    object.insert("fixture_mode".into(), json!("loopback"));
    object.insert("lifecycle_phase".into(), json!("fixture_assertion"));
    object.insert("result".into(), json!("ok"));
    object.insert("error_code".into(), Value::Null);
    object.insert("retry_backoff_decision".into(), json!("none"));
    object.insert(
        "audit_receipt_id".into(),
        json!(stable_hash(&format!(
            "{event}:{operation_id}:{}",
            instance_id.as_str()
        ))),
    );
    object.insert("cleanup_result".into(), json!("fixture_server_closed"));
    object.insert("skip_reason".into(), Value::Null);
    object.insert(
        "git_revision".into(),
        json!(option_env!("GIT_REVISION").unwrap_or("unknown")),
    );
    if let Some(payload) = payload.as_object() {
        object.extend(payload.clone());
    }
    let line = Value::Object(object).to_string();
    assert!(!line.contains("test-basic"));
    assert!(!line.contains("secret user text"));
    assert!(!line.contains("provider secret"));
    eprintln!("INWORLD_FIXTURE_JSONL {line}");
}

async fn read_http_headers<IO>(io: &mut IO) -> io::Result<Vec<u8>>
where
    IO: AsyncRead + Unpin,
{
    const MAX_HEADERS: usize = 16 * 1024;
    let mut buf = Vec::with_capacity(1024);
    let mut temp = [0_u8; 512];

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

        let read_bytes = temp.get(..read).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "websocket header read overflow")
        })?;
        buf.extend_from_slice(read_bytes);
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

async fn accept_test_websocket(mut stream: TcpStream) -> (TestServerWebSocket, String) {
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

async fn send_json_frame(ws: &mut TestServerWebSocket, value: Value, context: &str) {
    ws.send(&Cx::for_testing(), ServerWsMessage::text(value.to_string()))
        .await
        .expect(context);
}

async fn recv_json_frame(ws: &mut TestServerWebSocket, context: &str) -> Result<Value, String> {
    let message = ws
        .recv(&Cx::for_testing())
        .await
        .map_err(|err| format!("{context}: {err}"))?
        .ok_or_else(|| format!("websocket closed before {context}"))?;
    match message {
        ServerWsMessage::Text(text) => {
            serde_json::from_str(&text).map_err(|err| format!("{context}: {err}"))
        }
        other => Err(format!("expected text frame for {context}, got {other:?}")),
    }
}

async fn close_test_websocket(ws: &mut TestServerWebSocket) {
    let _ = ws.close(&Cx::for_testing(), CloseReason::normal()).await;
}

#[fcp_async_core::runtime::test]
async fn realtime_text_turn_uses_loopback_websocket_and_redacts_output() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind realtime listener");
    let address = listener.local_addr().expect("realtime listener addr");

    let server_task = task::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept realtime client");
        let (mut ws, headers) = accept_test_websocket(stream).await;
        assert!(headers.contains("Authorization: Basic test-basic"));
        assert!(headers.contains("GET /api/v1/realtime/session?key=session-123&protocol=realtime"));

        send_json_frame(
            &mut ws,
            json!({ "type": "session.created", "session": { "id": "provider-session" } }),
            "send session.created",
        )
        .await;

        let session_update = recv_json_frame(&mut ws, "receive session.update")
            .await
            .expect("receive session.update");
        assert_eq!(session_update["type"], "session.update");
        assert_eq!(
            session_update["session"]["metadata"]["character_id"],
            "char-1"
        );

        let item_create = recv_json_frame(&mut ws, "receive conversation item")
            .await
            .expect("receive conversation item");
        assert_eq!(item_create["type"], "conversation.item.create");
        assert_eq!(
            item_create["item"]["content"][0]["text"],
            "secret user text"
        );

        let response_create = recv_json_frame(&mut ws, "receive response.create")
            .await
            .expect("receive response.create");
        assert_eq!(response_create["type"], "response.create");

        send_json_frame(
            &mut ws,
            json!({ "type": "response.output_text.delta", "delta": "provider secret" }),
            "send text delta",
        )
        .await;
        send_json_frame(
            &mut ws,
            json!({
                "type": "conversation.item.done",
                "item": { "id": "provider-item-secret" }
            }),
            "send item done",
        )
        .await;
        send_json_frame(
            &mut ws,
            json!({ "type": "response.done" }),
            "send response done",
        )
        .await;
        close_test_websocket(&mut ws).await;
    });

    let router = MockServer::start().await;
    let realtime_url = format!("ws://{address}");
    let tts_url = format!("ws://{address}/tts");
    let (connector, signing_key) =
        configured_connector(&realtime_url, &tts_url, &router.uri(), &[CAP_REALTIME]).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_REALTIME_TEXT,
        CAP_REALTIME,
        json!({
            "session_id": "session-123",
            "character_id": "char-1",
            "output_modalities": ["text"],
            "text": "secret user text",
            "max_events": 8
        }),
    )
    .await;
    server_task.await.expect("realtime server task");

    assert_eq!(result["mode"], "realtime_websocket");
    assert_eq!(result["operation_result"], "ok");
    assert_eq!(result["input_text_bytes"], "secret user text".len());
    assert_eq!(
        result["events"]["text_output_bytes"],
        "provider secret".len()
    );
    let serialized = result.to_string();
    assert!(!serialized.contains("secret user text"));
    assert!(!serialized.contains("provider secret"));
    assert!(!serialized.contains("provider-item-secret"));
    emit_fixture(
        "realtime_text_turn",
        connector.instance_id(),
        OP_REALTIME_TEXT,
        CAP_REALTIME,
        &json!({
            "operation_result": result["operation_result"],
            "session_id_hash": result["session_id_hash"],
            "event_types": result["events"]["event_types"],
            "text_output_bytes": result["events"]["text_output_bytes"]
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn tts_context_roundtrip_uses_current_close_context_frame() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tts listener");
    let address = listener.local_addr().expect("tts listener addr");

    let server_task = task::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept tts client");
        let (mut ws, headers) = accept_test_websocket(stream).await;
        assert!(headers.contains("Authorization: Basic test-basic"));
        assert!(headers.contains("GET /tts/v1/voice:streamBidirectional"));

        let create = recv_json_frame(&mut ws, "receive create context")
            .await
            .expect("receive create context");
        assert_eq!(create["create"]["voiceId"], "Dennis");
        assert_eq!(create["contextId"], "ctx-test");

        let send_text = recv_json_frame(&mut ws, "receive send text")
            .await
            .expect("receive send text");
        assert_eq!(send_text["send_text"]["text"], "secret user text");

        let close = recv_json_frame(&mut ws, "receive close context")
            .await
            .expect("receive close context");
        assert!(close.get("close_context").is_some());
        assert!(close.get("close").is_none());
        assert_eq!(close["contextId"], "ctx-test");

        send_json_frame(
            &mut ws,
            json!({
                "result": {
                    "contextId": "ctx-test",
                    "contextCreated": {}
                }
            }),
            "send context created",
        )
        .await;
        send_json_frame(
            &mut ws,
            json!({
                "result": {
                    "contextId": "ctx-test",
                    "audioChunk": { "audioContent": "AQIDBA==" }
                }
            }),
            "send audio chunk",
        )
        .await;
        send_json_frame(
            &mut ws,
            json!({
                "result": {
                    "contextId": "ctx-test",
                    "contextClosed": {}
                }
            }),
            "send context closed",
        )
        .await;
        close_test_websocket(&mut ws).await;
    });

    let router = MockServer::start().await;
    let realtime_url = format!("ws://{address}/realtime");
    let tts_url = format!("ws://{address}");
    let (connector, signing_key) =
        configured_connector(&realtime_url, &tts_url, &router.uri(), &[CAP_TTS]).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_TTS_CONTEXT,
        CAP_TTS,
        json!({
            "context_id": "ctx-test",
            "text": "secret user text",
            "close": true,
            "max_events": 8
        }),
    )
    .await;
    server_task.await.expect("tts server task");

    assert_eq!(result["mode"], "tts_websocket");
    assert_eq!(result["events"]["audio_output_bytes"], 4);
    assert_eq!(result["events"]["stream_chunk_count"], 1);
    let serialized = result.to_string();
    assert!(!serialized.contains("secret user text"));
    assert!(!serialized.contains("AQIDBA=="));
    emit_fixture(
        "tts_context_roundtrip",
        connector.instance_id(),
        OP_TTS_CONTEXT,
        CAP_TTS,
        &json!({
            "operation_result": result["operation_result"],
            "context_id_hash": result["context_id_hash"],
            "audio_output_bytes": result["events"]["audio_output_bytes"]
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn realtime_audio_turn_uses_loopback_websocket_and_redacts_audio() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind realtime audio listener");
    let address = listener.local_addr().expect("realtime audio addr");

    let server_task = task::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("accept realtime audio client");
        let (mut ws, headers) = accept_test_websocket(stream).await;
        assert!(headers.contains("Authorization: Basic test-basic"));
        assert!(
            headers.contains("GET /api/v1/realtime/session?key=session-audio&protocol=realtime")
        );

        send_json_frame(
            &mut ws,
            json!({ "type": "session.created", "session": { "id": "provider-session" } }),
            "send session.created",
        )
        .await;

        let session_update = recv_json_frame(&mut ws, "receive session.update")
            .await
            .expect("receive session.update");
        assert_eq!(session_update["type"], "session.update");
        assert_eq!(
            session_update["session"]["audio"]["output"]["voice"],
            "Dennis"
        );

        let clear = recv_json_frame(&mut ws, "receive audio clear")
            .await
            .expect("receive audio clear");
        assert_eq!(clear["type"], "input_audio_buffer.clear");

        let append = recv_json_frame(&mut ws, "receive audio append")
            .await
            .expect("receive audio append");
        assert_eq!(append["type"], "input_audio_buffer.append");
        assert_eq!(append["audio"], "AQID");

        let commit = recv_json_frame(&mut ws, "receive audio commit")
            .await
            .expect("receive audio commit");
        assert_eq!(commit["type"], "input_audio_buffer.commit");

        let response_create = recv_json_frame(&mut ws, "receive response.create")
            .await
            .expect("receive response.create");
        assert_eq!(response_create["type"], "response.create");

        send_json_frame(
            &mut ws,
            json!({ "type": "response.output_audio.delta", "delta": "BAUG" }),
            "send audio delta",
        )
        .await;
        send_json_frame(
            &mut ws,
            json!({ "type": "response.done" }),
            "send response done",
        )
        .await;
        close_test_websocket(&mut ws).await;
    });

    let router = MockServer::start().await;
    let realtime_url = format!("ws://{address}");
    let tts_url = format!("ws://{address}/tts");
    let (connector, signing_key) =
        configured_connector(&realtime_url, &tts_url, &router.uri(), &[CAP_REALTIME]).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_REALTIME_AUDIO,
        CAP_REALTIME,
        json!({
            "session_id": "session-audio",
            "voice_id": "Dennis",
            "audio_chunks_base64": ["AQID"],
            "clear_before_append": true,
            "commit": true,
            "max_events": 8
        }),
    )
    .await;
    server_task.await.expect("realtime audio server task");

    assert_eq!(result["mode"], "realtime_websocket");
    assert_eq!(result["operation_result"], "ok");
    assert_eq!(result["input_audio_bytes"], 3);
    assert_eq!(result["events"]["audio_output_bytes"], 3);
    let serialized = result.to_string();
    assert!(!serialized.contains("AQID"));
    assert!(!serialized.contains("BAUG"));
    emit_fixture(
        "realtime_audio_turn",
        connector.instance_id(),
        OP_REALTIME_AUDIO,
        CAP_REALTIME,
        &json!({
            "operation_result": result["operation_result"],
            "session_id_hash": result["session_id_hash"],
            "input_audio_bytes": result["input_audio_bytes"],
            "audio_output_bytes": result["events"]["audio_output_bytes"],
            "event_types": result["events"]["event_types"]
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn router_chat_completion_uses_wiremock_and_redacts_provider_text() {
    let router = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("Authorization", "Basic test-basic"))
        .and(body_partial_json(json!({
            "model": "auto",
            "messages": [{ "role": "user", "content": "secret user text" }]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "router-provider-id-secret",
            "model": "auto",
            "choices": [
                { "message": { "role": "assistant", "content": "provider secret" } }
            ],
            "usage": { "prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6 },
            "metadata": { "attempts": [{ "model": "inworld" }] }
        })))
        .mount(&router)
        .await;

    let realtime_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind unused realtime listener");
    let address = realtime_listener.local_addr().expect("unused addr");
    let realtime_url = format!("ws://{address}/realtime");
    let tts_url = format!("ws://{address}/tts");
    let (connector, signing_key) =
        configured_connector(&realtime_url, &tts_url, &router.uri(), &[CAP_ROUTER]).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_ROUTER_CHAT,
        CAP_ROUTER,
        json!({
            "model": "auto",
            "messages": [{ "role": "user", "content": "secret user text" }],
            "stream": false
        }),
    )
    .await;

    assert_eq!(result["mode"], "router_chat_completion");
    assert_eq!(result["operation_result"], "ok");
    assert_eq!(result["choice_count"], 1);
    assert_eq!(result["metadata_attempt_count"], 1);
    let serialized = result.to_string();
    assert!(!serialized.contains("secret user text"));
    assert!(!serialized.contains("provider secret"));
    assert!(!serialized.contains("router-provider-id-secret"));
    emit_fixture(
        "router_chat_completion",
        connector.instance_id(),
        OP_ROUTER_CHAT,
        CAP_ROUTER,
        &json!({
            "operation_result": result["operation_result"],
            "id_hash": result["id_hash"],
            "choice_count": result["choice_count"]
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn capability_denial_happens_before_provider_io() {
    let realtime_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind unused realtime listener");
    let address = realtime_listener.local_addr().expect("unused addr");
    let router = MockServer::start().await;
    let (connector, signing_key) = configured_connector(
        &format!("ws://{address}/realtime"),
        &format!("ws://{address}/tts"),
        &router.uri(),
        &[CAP_REALTIME],
    )
    .await;
    let wrong_instance = InstanceId::new();
    let grant = valid_token(
        &signing_key,
        &wrong_instance,
        CAP_REALTIME,
        OP_REALTIME_TEXT,
    );

    let error = connector
        .handle_invoke(json!({
            "operation": OP_REALTIME_TEXT,
            "input": {
                "session_id": "session-123",
                "text": "secret user text"
            },
            "capability_token": grant
        }))
        .await
        .expect_err("wrong-instance grant must be denied before network I/O");

    assert!(!format!("{error:?}").contains("secret user text"));
}

#[fcp_async_core::runtime::test]
async fn malformed_text_turn_is_rejected_before_provider_io() {
    let realtime_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind unused realtime listener");
    let address = realtime_listener.local_addr().expect("unused addr");
    let router = MockServer::start().await;
    let (connector, signing_key) = configured_connector(
        &format!("ws://{address}/realtime"),
        &format!("ws://{address}/tts"),
        &router.uri(),
        &[CAP_REALTIME],
    )
    .await;
    let grant = valid_token(
        &signing_key,
        connector.instance_id(),
        CAP_REALTIME,
        OP_REALTIME_TEXT,
    );

    let error = connector
        .handle_invoke(json!({
            "operation": OP_REALTIME_TEXT,
            "input": {
                "session_id": "session-123",
                "text": " "
            },
            "capability_token": grant
        }))
        .await
        .expect_err("blank text must be rejected before websocket egress");

    assert!(matches!(
        error,
        FcpError::InvalidRequest {
            code: 1003,
            message: _
        }
    ));
}

#[fcp_async_core::runtime::test]
async fn realtime_error_event_returns_redacted_provider_error() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind realtime listener");
    let address = listener.local_addr().expect("realtime listener addr");

    let server_task = task::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept realtime client");
        let (mut ws, _) = accept_test_websocket(stream).await;

        send_json_frame(
            &mut ws,
            json!({ "type": "session.created", "session": { "id": "provider-session" } }),
            "send session.created",
        )
        .await;
        let _ = recv_json_frame(&mut ws, "receive session.update")
            .await
            .expect("receive session.update");
        let _ = recv_json_frame(&mut ws, "receive conversation item")
            .await
            .expect("receive conversation item");
        let _ = recv_json_frame(&mut ws, "receive response.create")
            .await
            .expect("receive response.create");
        send_json_frame(
            &mut ws,
            json!({
                "type": "error",
                "error": {
                    "code": "rate_limit_exceeded",
                    "message": "provider secret"
                }
            }),
            "send redacted error event",
        )
        .await;
        close_test_websocket(&mut ws).await;
    });

    let router = MockServer::start().await;
    let (connector, signing_key) = configured_connector(
        &format!("ws://{address}"),
        &format!("ws://{address}/tts"),
        &router.uri(),
        &[CAP_REALTIME],
    )
    .await;
    let grant = valid_token(
        &signing_key,
        connector.instance_id(),
        CAP_REALTIME,
        OP_REALTIME_TEXT,
    );

    let error = connector
        .handle_invoke(json!({
            "operation": OP_REALTIME_TEXT,
            "input": {
                "session_id": "session-123",
                "text": "secret user text",
                "max_events": 8
            },
            "capability_token": grant
        }))
        .await
        .expect_err("provider error event must fail the invocation");
    server_task.await.expect("realtime error server task");

    let error_text = format!("{error:?}");
    assert!(error_text.contains("rate_limit_exceeded"));
    assert!(!error_text.contains("provider secret"));
    assert!(!error_text.contains("secret user text"));
}

#[fcp_async_core::runtime::test]
async fn router_unauthorized_and_rate_limit_errors_are_redacted() {
    let router = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({ "model": "unauthorized" })))
        .respond_with(ResponseTemplate::new(401).set_body_string("provider secret"))
        .expect(1)
        .mount(&router)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({ "model": "rate-limited" })))
        .respond_with(ResponseTemplate::new(429).set_body_string("provider secret"))
        .expect(1)
        .mount(&router)
        .await;

    let realtime_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind unused realtime listener");
    let address = realtime_listener.local_addr().expect("unused addr");
    let (connector, signing_key) = configured_connector(
        &format!("ws://{address}/realtime"),
        &format!("ws://{address}/tts"),
        &router.uri(),
        &[CAP_ROUTER],
    )
    .await;

    for (model, expected_status) in [("unauthorized", 401_u16), ("rate-limited", 429_u16)] {
        let grant = valid_token(
            &signing_key,
            connector.instance_id(),
            CAP_ROUTER,
            OP_ROUTER_CHAT,
        );
        let error = connector
            .handle_invoke(json!({
                "operation": OP_ROUTER_CHAT,
                "input": {
                    "model": model,
                    "messages": [{ "role": "user", "content": "secret user text" }],
                    "stream": false
                },
                "capability_token": grant
            }))
            .await
            .expect_err("router error must fail the invocation");
        let error_debug = format!("{error:?}");
        match error {
            FcpError::External {
                status_code,
                message,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(expected_status));
                assert!(!message.contains("provider secret"));
                assert_eq!(retryable, expected_status == 429);
            }
            _ => assert!(
                error_debug.contains("External"),
                "unexpected router error mapping: {error_debug}"
            ),
        }
    }
}

#[test]
fn live_provider_verification_is_explicitly_opt_in() {
    let reason = if std::env::var_os("INWORLD_API_KEY").is_some()
        && std::env::var_os("INWORLD_REALTIME_SESSION_ID").is_some()
    {
        "live provider proof is not part of the default deterministic suite"
    } else {
        "set INWORLD_API_KEY and INWORLD_REALTIME_SESSION_ID for live provider proof"
    };
    eprintln!(
        "INWORLD_FIXTURE_JSONL {}",
        json!({
            "event": "live_verification_skipped",
            "command_line": "cargo test -p fcp-inworld",
            "git_revision": option_env!("GIT_REVISION").unwrap_or("unknown"),
            "connector_id": "fcp.inworld",
            "operation_id": "inworld.live.smoke",
            "capability": CAP_REALTIME,
            "zone": "z:work",
            "instance_id_hash": Value::Null,
            "fixture_mode": "live",
            "lifecycle_phase": "credential_gate",
            "latency_ms": 0,
            "result": "skipped",
            "error_code": Value::Null,
            "retry_backoff_decision": "none",
            "audit_receipt_id": stable_hash(reason),
            "cleanup_result": "not_started",
            "skip_reason": reason
        })
    );
}
