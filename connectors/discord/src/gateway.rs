//! Discord Gateway (WebSocket) client.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fcp_async_core::channel::mpsc;
use fcp_async_core::net::TcpStream;
use fcp_async_core::sync::Mutex;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async, tungstenite::protocol::Message as WsMessage,
};
use tracing::{debug, error, info, instrument, warn};

use crate::{
    api::DiscordApiClient,
    config::DiscordConfig,
    error::{DiscordError, DiscordResult},
    types::{
        GatewayHello, GatewayIdentify, GatewayPayload, GatewayProperties, GatewayReady,
        GatewayResume,
    },
};

/// Discord Gateway opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum GatewayOpcode {
    /// Receive: An event was dispatched.
    Dispatch = 0,
    /// Send/Receive: Fired periodically to keep the connection alive.
    Heartbeat = 1,
    /// Send: Starts a new session.
    Identify = 2,
    /// Send: Update presence.
    PresenceUpdate = 3,
    /// Send: Join/leave or move between voice channels.
    VoiceStateUpdate = 4,
    /// Send: Resume a previous session.
    Resume = 6,
    /// Receive: Reconnect to the gateway.
    Reconnect = 7,
    /// Send: Request guild members.
    RequestGuildMembers = 8,
    /// Receive: Session invalidated.
    InvalidSession = 9,
    /// Receive: Sent after connecting.
    Hello = 10,
    /// Receive: Heartbeat acknowledged.
    HeartbeatAck = 11,
}

const GATEWAY_EVENT_BUFFER_CAPACITY: usize = 256;
pub const DISCORD_GATEWAY_STATE_FILE: &str = "discord_gateway_state.json";

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_async_core::net::TcpListener;
    use fcp_async_core::time::sleep;
    use serde_json::json;
    use tokio_tungstenite::accept_async;

    fn parse_payload(msg: WsMessage) -> GatewayPayload {
        match msg {
            WsMessage::Text(text) => serde_json::from_str(&text).expect("valid gateway payload"),
            other => panic!("expected text payload, got {other:?}"),
        }
    }

    fn hello_payload(interval_ms: u64) -> WsMessage {
        WsMessage::Text(
            json!({
                "op": GatewayOpcode::Hello as i32,
                "d": { "heartbeat_interval": interval_ms },
                "s": null,
                "t": null,
            })
            .to_string()
            .into(),
        )
    }

    fn dispatch_payload(event_name: &str, sequence: u64, data: &serde_json::Value) -> WsMessage {
        WsMessage::Text(
            json!({
                "op": GatewayOpcode::Dispatch as i32,
                "d": data,
                "s": sequence,
                "t": event_name,
            })
            .to_string()
            .into(),
        )
    }

    fn test_config(gateway_url: String) -> DiscordConfig {
        DiscordConfig {
            bot_credential: "test_token".into(),
            api_url: "https://discord.com/api/v10".into(),
            gateway_url: Some(gateway_url),
            intents: 513,
            ..Default::default()
        }
    }

    fn unique_state_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!(
            "fcp-discord-gateway-{label}-{}-{nanos}.json",
            std::process::id()
        ))
    }

    #[test]
    fn gateway_opcode_try_from_known_values() {
        assert_eq!(GatewayOpcode::try_from(0), Ok(GatewayOpcode::Dispatch));
        assert_eq!(GatewayOpcode::try_from(10), Ok(GatewayOpcode::Hello));
        assert_eq!(GatewayOpcode::try_from(11), Ok(GatewayOpcode::HeartbeatAck));
    }

    #[test]
    fn gateway_opcode_try_from_unknown_is_err() {
        assert!(GatewayOpcode::try_from(42).is_err());
    }

    #[test]
    fn dispatch_event_updates_state_on_ready() {
        let mut state = GatewayState::default();
        let data = json!({
            "v": 10,
            "user": { "id": "123", "username": "bot" },
            "session_id": "sess-1",
            "resume_gateway_url": "wss://gateway.discord.gg"
        });

        let event = dispatch_event("READY".to_string(), data, &mut state).unwrap();

        match event {
            GatewayEvent::Ready(ready) => {
                assert_eq!(ready.session_id, "sess-1");
            }
            _ => panic!("expected READY event"),
        }

        assert_eq!(state.session_id.as_deref(), Some("sess-1"));
        assert_eq!(
            state.resume_url.as_deref(),
            Some("wss://gateway.discord.gg")
        );
    }

    #[test]
    fn dispatch_event_maps_message_create() {
        let mut state = GatewayState::default();
        let data = json!({ "id": "msg-1" });

        let event = dispatch_event("MESSAGE_CREATE".to_string(), data.clone(), &mut state).unwrap();

        match event {
            GatewayEvent::MessageCreate(payload) => {
                assert_eq!(payload, data);
            }
            _ => panic!("expected MESSAGE_CREATE event"),
        }
    }

    #[test]
    fn dispatch_event_unknown_passthrough() {
        let mut state = GatewayState::default();
        let data = json!({ "foo": "bar" });

        let event = dispatch_event("SOMETHING_ELSE".to_string(), data.clone(), &mut state).unwrap();

        match event {
            GatewayEvent::Unknown {
                event_name,
                data: payload,
            } => {
                assert_eq!(event_name, "SOMETHING_ELSE");
                assert_eq!(payload, data);
            }
            _ => panic!("expected Unknown event"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_loop_identifies_emits_events_and_updates_state() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let ws_url = format!("ws://{addr}");

        let server = fcp_async_core::task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let mut ws = accept_async(socket).await.expect("accept websocket");

            ws.send(hello_payload(1_000)).await.expect("send hello");

            let identify = parse_payload(
                ws.next()
                    .await
                    .expect("client identify frame")
                    .expect("identify frame ok"),
            );
            assert_eq!(identify.op, GatewayOpcode::Identify as i32);

            ws.send(dispatch_payload(
                "READY",
                1,
                &json!({
                    "v": 10,
                    "user": { "id": "123", "username": "bot" },
                    "session_id": "sess-identify",
                    "resume_gateway_url": "wss://gateway.discord.gg"
                }),
            ))
            .await
            .expect("send ready");

            ws.send(dispatch_payload(
                "MESSAGE_CREATE",
                2,
                &json!({ "id": "msg-1", "content": "hello" }),
            ))
            .await
            .expect("send message create");

            ws.close(None).await.expect("close websocket");
        });

        let (client_ws, _) = connect_async(&ws_url).await.expect("connect websocket");
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let mut state = GatewayState::default();

        run_gateway_loop_inner(client_ws, test_config(ws_url), &event_tx, &mut state, None)
            .await
            .expect("gateway loop success");

        match event_rx.recv().await.expect("ready event") {
            GatewayEvent::Ready(ready) => assert_eq!(ready.session_id, "sess-identify"),
            other => panic!("expected Ready event, got {other:?}"),
        }

        match event_rx.recv().await.expect("message create event") {
            GatewayEvent::MessageCreate(message) => assert_eq!(message["id"], "msg-1"),
            other => panic!("expected MessageCreate event, got {other:?}"),
        }

        assert_eq!(state.session_id.as_deref(), Some("sess-identify"));
        assert_eq!(
            state.resume_url.as_deref(),
            Some("wss://gateway.discord.gg")
        );
        assert_eq!(state.sequence, Some(2));

        server.await.expect("server task should complete");
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_loop_uses_resume_when_session_state_is_complete() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let ws_url = format!("ws://{addr}");

        let server = fcp_async_core::task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let mut ws = accept_async(socket).await.expect("accept websocket");

            ws.send(hello_payload(1_000)).await.expect("send hello");

            let resume = parse_payload(
                ws.next()
                    .await
                    .expect("client resume frame")
                    .expect("resume frame ok"),
            );
            assert_eq!(resume.op, GatewayOpcode::Resume as i32);
            let payload = resume.d.expect("resume payload");
            assert_eq!(payload["session_id"], "sess-resume");
            assert_eq!(payload["seq"], 7);

            ws.send(dispatch_payload("RESUMED", 8, &json!({})))
                .await
                .expect("send resumed");
            ws.close(None).await.expect("close websocket");
        });

        let (client_ws, _) = connect_async(&ws_url).await.expect("connect websocket");
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let mut state = GatewayState {
            session_id: Some("sess-resume".into()),
            resume_url: Some("wss://gateway.discord.gg".into()),
            sequence: Some(7),
        };

        run_gateway_loop_inner(client_ws, test_config(ws_url), &event_tx, &mut state, None)
            .await
            .expect("gateway loop success");

        match event_rx.recv().await.expect("resumed event") {
            GatewayEvent::Resumed => {}
            other => panic!("expected Resumed event, got {other:?}"),
        }
        assert_eq!(state.sequence, Some(8));

        server.await.expect("server task should complete");
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_loop_ignores_malformed_dispatch_frames() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let ws_url = format!("ws://{addr}");

        let server = fcp_async_core::task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let mut ws = accept_async(socket).await.expect("accept websocket");

            ws.send(hello_payload(1_000)).await.expect("send hello");
            let _ = ws
                .next()
                .await
                .expect("identify frame")
                .expect("identify frame ok");

            ws.send(WsMessage::Text("{ this is not json".into()))
                .await
                .expect("send malformed frame");
            ws.send(dispatch_payload(
                "MESSAGE_DELETE",
                9,
                &json!({ "id": "msg-delete-1" }),
            ))
            .await
            .expect("send valid dispatch");
            ws.close(None).await.expect("close websocket");
        });

        let (client_ws, _) = connect_async(&ws_url).await.expect("connect websocket");
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let mut state = GatewayState::default();

        run_gateway_loop_inner(client_ws, test_config(ws_url), &event_tx, &mut state, None)
            .await
            .expect("gateway loop success");

        match event_rx.recv().await.expect("message delete event") {
            GatewayEvent::MessageDelete(payload) => assert_eq!(payload["id"], "msg-delete-1"),
            other => panic!("expected MessageDelete event, got {other:?}"),
        }
        assert_eq!(state.sequence, Some(9));

        server.await.expect("server task should complete");
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_loop_clears_incomplete_resume_state_and_identifies() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let ws_url = format!("ws://{addr}");

        let server = fcp_async_core::task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let mut ws = accept_async(socket).await.expect("accept websocket");

            ws.send(hello_payload(1_000)).await.expect("send hello");

            let first_payload = parse_payload(
                ws.next()
                    .await
                    .expect("client frame")
                    .expect("client frame ok"),
            );
            assert_eq!(first_payload.op, GatewayOpcode::Identify as i32);
            ws.close(None).await.expect("close websocket");
        });

        let (client_ws, _) = connect_async(&ws_url).await.expect("connect websocket");
        let (event_tx, _event_rx) = mpsc::channel(8);
        let mut state = GatewayState {
            session_id: Some("sess-incomplete".into()),
            resume_url: Some("wss://stale.gateway.discord.gg".into()),
            sequence: None,
        };

        run_gateway_loop_inner(client_ws, test_config(ws_url), &event_tx, &mut state, None)
            .await
            .expect("gateway loop success");

        assert_eq!(state.session_id, None);
        assert_eq!(state.resume_url, None);
        assert_eq!(state.sequence, None);

        server.await.expect("server task should complete");
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_connection_enforces_single_active_connection() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let ws_url = format!("ws://{addr}");

        let server = fcp_async_core::task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let mut ws = accept_async(socket).await.expect("accept websocket");

            ws.send(hello_payload(1_000)).await.expect("send hello");
            let _ = ws
                .next()
                .await
                .expect("identify frame")
                .expect("identify frame ok");

            sleep(Duration::from_millis(50)).await;
            ws.close(None).await.expect("close websocket");
        });

        let config = test_config(ws_url);
        let api_client = Arc::new(DiscordApiClient::new(&config).expect("create api client"));
        let connection = GatewayConnection::new(config, api_client);

        let stream = connection
            .connect_once()
            .await
            .expect("first connection should succeed");

        let second_attempt = connection.connect_once().await;
        assert!(second_attempt.is_err());
        match second_attempt.unwrap_err() {
            DiscordError::Gateway(message) => {
                assert!(message.contains("already active"));
            }
            other => panic!("expected gateway error, got {other:?}"),
        }

        let _ = stream.join_handle.await.expect("gateway loop task join");
        server.await.expect("server task should complete");
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_connection_persists_resume_state_to_disk() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let ws_url = format!("ws://{addr}");
        let state_path = unique_state_path("persist");

        let server = fcp_async_core::task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let mut ws = accept_async(socket).await.expect("accept websocket");
            ws.send(hello_payload(1_000)).await.expect("send hello");
            let _ = ws
                .next()
                .await
                .expect("identify frame")
                .expect("identify frame ok");

            ws.send(dispatch_payload(
                "READY",
                1,
                &json!({
                    "v": 10,
                    "user": { "id": "321", "username": "persist-bot" },
                    "session_id": "sess-persist",
                    "resume_gateway_url": "wss://gateway.discord.gg"
                }),
            ))
            .await
            .expect("send ready");
            ws.send(dispatch_payload(
                "MESSAGE_CREATE",
                2,
                &json!({ "id": "msg-persist" }),
            ))
            .await
            .expect("send message");
            ws.close(None).await.expect("close websocket");
        });

        let config = test_config(ws_url);
        let api_client = Arc::new(DiscordApiClient::new(&config).expect("create api client"));
        let connection = GatewayConnection::new(config, api_client);
        let mut stream = connection
            .connect_once_with_state_path(Some(state_path.clone()))
            .await
            .expect("connect with state path");

        let _ = stream.events.recv().await.expect("ready event");
        let _ = stream.events.recv().await.expect("message event");
        stream
            .join_handle
            .await
            .expect("join")
            .expect("loop success");
        server.await.expect("server task");

        let persisted = read_json_file_if_exists::<GatewayStateRecord>(&state_path)
            .expect("state file read")
            .expect("state file exists");
        assert_eq!(persisted.session_id.as_deref(), Some("sess-persist"));
        assert_eq!(persisted.sequence, Some(2));
        let _ = fs::remove_file(state_path);
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_connection_loads_persisted_state_and_resumes() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let ws_url = format!("ws://{addr}");
        let state_path = unique_state_path("resume");
        write_json_file_atomic(
            &state_path,
            &GatewayStateRecord {
                session_id: Some("sess-resume-file".into()),
                resume_url: Some(ws_url.clone()),
                sequence: Some(7),
                updated_at: current_unix_timestamp_secs(),
            },
        )
        .expect("write persisted state");

        let server = fcp_async_core::task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let mut ws = accept_async(socket).await.expect("accept websocket");
            ws.send(hello_payload(1_000)).await.expect("send hello");

            let resume = parse_payload(
                ws.next()
                    .await
                    .expect("client resume frame")
                    .expect("resume frame ok"),
            );
            assert_eq!(resume.op, GatewayOpcode::Resume as i32);
            let payload = resume.d.expect("resume payload");
            assert_eq!(payload["session_id"], "sess-resume-file");
            assert_eq!(payload["seq"], 7);

            ws.send(dispatch_payload("RESUMED", 8, &json!({})))
                .await
                .expect("send resumed");
            ws.close(None).await.expect("close websocket");
        });

        let config = test_config(ws_url);
        let api_client = Arc::new(DiscordApiClient::new(&config).expect("create api client"));
        let connection = GatewayConnection::new(config, api_client);
        let mut stream = connection
            .connect_once_with_state_path(Some(state_path.clone()))
            .await
            .expect("connect with persisted state");

        match stream.events.recv().await.expect("resumed event") {
            GatewayEvent::Resumed => {}
            other => panic!("expected Resumed event, got {other:?}"),
        }
        stream
            .join_handle
            .await
            .expect("join")
            .expect("loop success");
        server.await.expect("server task");

        let persisted = read_json_file_if_exists::<GatewayStateRecord>(&state_path)
            .expect("state file read")
            .expect("state file exists");
        assert_eq!(persisted.sequence, Some(8));
        let _ = fs::remove_file(state_path);
    }

    #[fcp_async_core::runtime::test]
    async fn gateway_connection_fails_closed_on_incomplete_persisted_state() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let ws_url = format!("ws://{addr}");
        let state_path = unique_state_path("fail-closed");
        write_json_file_atomic(
            &state_path,
            &GatewayStateRecord {
                session_id: Some("sess-incomplete".into()),
                resume_url: Some("wss://stale.gateway.discord.gg".into()),
                sequence: None,
                updated_at: current_unix_timestamp_secs(),
            },
        )
        .expect("write persisted state");

        let server = fcp_async_core::task::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let mut ws = accept_async(socket).await.expect("accept websocket");
            ws.send(hello_payload(1_000)).await.expect("send hello");

            let first_payload = parse_payload(
                ws.next()
                    .await
                    .expect("client frame")
                    .expect("client frame ok"),
            );
            assert_eq!(first_payload.op, GatewayOpcode::Identify as i32);
            ws.close(None).await.expect("close websocket");
        });

        let config = test_config(ws_url);
        let api_client = Arc::new(DiscordApiClient::new(&config).expect("create api client"));
        let connection = GatewayConnection::new(config, api_client);
        let stream = connection
            .connect_once_with_state_path(Some(state_path.clone()))
            .await
            .expect("connect should succeed with identify fallback");
        stream
            .join_handle
            .await
            .expect("join")
            .expect("loop success");
        server.await.expect("server task");

        let persisted = read_json_file_if_exists::<GatewayStateRecord>(&state_path)
            .expect("state file read")
            .expect("state file exists");
        assert_eq!(persisted.session_id, None);
        assert_eq!(persisted.sequence, None);
        let _ = fs::remove_file(state_path);
    }
}

impl TryFrom<i32> for GatewayOpcode {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Dispatch),
            1 => Ok(Self::Heartbeat),
            2 => Ok(Self::Identify),
            3 => Ok(Self::PresenceUpdate),
            4 => Ok(Self::VoiceStateUpdate),
            6 => Ok(Self::Resume),
            7 => Ok(Self::Reconnect),
            8 => Ok(Self::RequestGuildMembers),
            9 => Ok(Self::InvalidSession),
            10 => Ok(Self::Hello),
            11 => Ok(Self::HeartbeatAck),
            _ => Err(()),
        }
    }
}

/// A gateway event received from Discord.
#[derive(Debug, Clone)]
pub enum GatewayEvent {
    /// Ready event - we're connected.
    Ready(GatewayReady),
    /// Resumed event - session successfully resumed.
    Resumed,
    /// Message created.
    MessageCreate(serde_json::Value),
    /// Message updated.
    MessageUpdate(serde_json::Value),
    /// Message deleted.
    MessageDelete(serde_json::Value),
    /// Guild created (we joined or became available).
    GuildCreate(serde_json::Value),
    /// Guild updated.
    GuildUpdate(serde_json::Value),
    /// Channel created.
    ChannelCreate(serde_json::Value),
    /// Channel updated.
    ChannelUpdate(serde_json::Value),
    /// Typing started.
    TypingStart(serde_json::Value),
    /// Unknown or unhandled event.
    Unknown {
        event_name: String,
        data: serde_json::Value,
    },
}

/// Discord Gateway connection.
pub struct GatewayConnection {
    config: DiscordConfig,
    api_client: Arc<DiscordApiClient>,
    state: Arc<Mutex<GatewayState>>,
    active_connection: Arc<AtomicBool>,
}

impl GatewayConnection {
    /// Create a new gateway connection.
    pub fn new(config: DiscordConfig, api_client: Arc<DiscordApiClient>) -> Self {
        Self {
            config,
            api_client,
            state: Arc::new(Mutex::new(GatewayState::default())),
            active_connection: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Connect to the gateway once and return the event stream handle.
    /// If we have a previous session, will attempt to resume.
    #[instrument(skip(self))]
    pub async fn connect_once(&self) -> DiscordResult<GatewayStream> {
        self.connect_once_with_state_path(None).await
    }

    /// Connect to the gateway once with optional persisted gateway state.
    #[instrument(skip(self))]
    pub async fn connect_once_with_state_path(
        &self,
        state_path: Option<PathBuf>,
    ) -> DiscordResult<GatewayStream> {
        if self
            .active_connection
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(DiscordError::Gateway(
                "Gateway connection already active".into(),
            ));
        }

        let (event_tx, event_rx) = mpsc::channel(GATEWAY_EVENT_BUFFER_CAPACITY);

        let config = self.config.clone();
        let api_client = self.api_client.clone();
        let state_store = Arc::clone(&self.state);

        let mut state_snapshot = {
            let state = state_store.lock().await;
            state.clone()
        };

        if let Some(path) = state_path.as_deref()
            && let Some(persisted) = load_persisted_gateway_state(path)?
            && (!state_snapshot.is_resume_ready()
                || state_snapshot.sequence.unwrap_or_default()
                    < persisted.sequence.unwrap_or_default())
        {
            state_snapshot = persisted;
        }

        // Determine gateway URL
        let gateway_url = if let Some(ref url) = state_snapshot.resume_url {
            url.clone()
        } else if let Some(url) = &config.gateway_url {
            url.clone()
        } else {
            match api_client.get_gateway().await {
                Ok(url) => url,
                Err(e) => {
                    self.active_connection.store(false, Ordering::Release);
                    return Err(e);
                }
            }
        };

        let ws_url = format!("{gateway_url}/?v=10&encoding=json");
        info!(
            url = %ws_url,
            resuming = state_snapshot.session_id.is_some(),
            "Connecting to Discord gateway"
        );

        let (ws_stream, _) = match connect_async(&ws_url).await {
            Ok(pair) => pair,
            Err(e) => {
                self.active_connection.store(false, Ordering::Release);
                return Err(DiscordError::Gateway(format!("Failed to connect WS: {e}")));
            }
        };

        let active_connection = Arc::clone(&self.active_connection);
        let join_handle = fcp_async_core::task::spawn(async move {
            let result = run_gateway_loop(
                ws_stream,
                config,
                event_tx,
                state_snapshot,
                state_store,
                state_path,
            )
            .await;
            active_connection.store(false, Ordering::Release);
            result
        });

        Ok(GatewayStream {
            events: event_rx,
            join_handle,
        })
    }
}

#[derive(Clone, Debug, Default)]
struct GatewayState {
    session_id: Option<String>,
    resume_url: Option<String>,
    sequence: Option<u64>,
}

impl GatewayState {
    const fn is_resume_ready(&self) -> bool {
        self.session_id.is_some() && self.sequence.is_some()
    }

    fn clear_resume(&mut self) {
        self.session_id = None;
        self.resume_url = None;
        self.sequence = None;
    }

    fn from_record(record: GatewayStateRecord) -> Self {
        Self {
            session_id: record.session_id,
            resume_url: record.resume_url,
            sequence: record.sequence,
        }
    }

    fn to_record(&self) -> GatewayStateRecord {
        GatewayStateRecord {
            session_id: self.session_id.clone(),
            resume_url: self.resume_url.clone(),
            sequence: self.sequence,
            updated_at: current_unix_timestamp_secs(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct GatewayStateRecord {
    session_id: Option<String>,
    resume_url: Option<String>,
    sequence: Option<u64>,
    updated_at: u64,
}

fn current_unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn write_json_file_atomic<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension(format!("tmp-{}", std::process::id()));
    let payload = serde_json::to_vec(value).map_err(io::Error::other)?;
    fs::write(&tmp_path, payload)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

fn read_json_file_if_exists<T>(path: &Path) -> io::Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    match fs::read(path) {
        Ok(bytes) => {
            let value = serde_json::from_slice::<T>(&bytes).map_err(io::Error::other)?;
            Ok(Some(value))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn persist_gateway_state(path: &Path, state: &GatewayState) -> DiscordResult<()> {
    let record = state.to_record();
    write_json_file_atomic(path, &record).map_err(|err| {
        DiscordError::Gateway(format!(
            "Failed to persist gateway state file '{}': {err}",
            path.display()
        ))
    })?;
    Ok(())
}

fn persist_gateway_state_if_configured(
    state_path: Option<&Path>,
    state: &GatewayState,
) -> DiscordResult<()> {
    if let Some(path) = state_path {
        persist_gateway_state(path, state)?;
    }
    Ok(())
}

fn load_persisted_gateway_state(path: &Path) -> DiscordResult<Option<GatewayState>> {
    let Some(record) = read_json_file_if_exists::<GatewayStateRecord>(path).map_err(|err| {
        DiscordError::Gateway(format!(
            "Failed to read gateway state file '{}': {err}",
            path.display()
        ))
    })?
    else {
        return Ok(None);
    };

    let mut state = GatewayState::from_record(record);
    if state.session_id.is_some() ^ state.sequence.is_some() {
        warn!(
            path = %path.display(),
            "Incomplete persisted gateway resume state detected; clearing state and re-identifying"
        );
        state.clear_resume();
        persist_gateway_state(path, &state)?;
    }

    Ok(Some(state))
}

fn dispatch_event(
    event_name: String,
    data: serde_json::Value,
    state: &mut GatewayState,
) -> DiscordResult<GatewayEvent> {
    let event = match event_name.as_str() {
        "READY" => {
            let ready: GatewayReady = serde_json::from_value(data)?;
            state.session_id = Some(ready.session_id.clone());
            state.resume_url = Some(ready.resume_gateway_url.clone());
            info!(
                user = ?ready.user.username,
                session_id = %ready.session_id,
                "Gateway ready"
            );
            GatewayEvent::Ready(ready)
        }
        "RESUMED" => {
            info!("Session resumed successfully");
            GatewayEvent::Resumed
        }
        "MESSAGE_CREATE" => GatewayEvent::MessageCreate(data),
        "MESSAGE_UPDATE" => GatewayEvent::MessageUpdate(data),
        "MESSAGE_DELETE" => GatewayEvent::MessageDelete(data),
        "GUILD_CREATE" => GatewayEvent::GuildCreate(data),
        "GUILD_UPDATE" => GatewayEvent::GuildUpdate(data),
        "CHANNEL_CREATE" => GatewayEvent::ChannelCreate(data),
        "CHANNEL_UPDATE" => GatewayEvent::ChannelUpdate(data),
        "TYPING_START" => GatewayEvent::TypingStart(data),
        _ => GatewayEvent::Unknown { event_name, data },
    };

    Ok(event)
}

/// Handle for a single gateway connection attempt.
pub struct GatewayStream {
    pub events: mpsc::Receiver<GatewayEvent>,
    pub join_handle: fcp_async_core::task::JoinHandle<DiscordResult<()>>,
}

impl std::fmt::Debug for GatewayStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayStream").finish_non_exhaustive()
    }
}

/// Run the gateway event loop.
async fn run_gateway_loop(
    ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    config: DiscordConfig,
    event_tx: mpsc::Sender<GatewayEvent>,
    mut state: GatewayState,
    state_store: Arc<Mutex<GatewayState>>,
    state_path: Option<PathBuf>,
) -> DiscordResult<()> {
    let result = run_gateway_loop_inner(
        ws_stream,
        config,
        &event_tx,
        &mut state,
        state_path.as_deref(),
    )
    .await;
    let persisted_state = state.clone();
    let mut store = state_store.lock().await;
    *store = state;
    drop(store);
    persist_gateway_state_if_configured(state_path.as_deref(), &persisted_state)?;
    result
}

async fn run_gateway_loop_inner(
    ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    config: DiscordConfig,
    event_tx: &mpsc::Sender<GatewayEvent>,
    state: &mut GatewayState,
    state_path: Option<&Path>,
) -> DiscordResult<()> {
    let (mut write, mut read) = ws_stream.split();

    // Wait for Hello
    let hello = match read.next().await {
        Some(Ok(WsMessage::Text(text))) => match serde_json::from_str::<GatewayPayload>(&text) {
            Ok(payload) => {
                if payload.op != GatewayOpcode::Hello as i32 {
                    return Err(DiscordError::Gateway("Expected Hello opcode".into()));
                }
                match serde_json::from_value::<GatewayHello>(payload.d.unwrap_or_default()) {
                    Ok(h) => h,
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        },
        Some(Ok(msg)) => {
            return Err(DiscordError::Gateway(format!(
                "Unexpected message: {msg:?}"
            )));
        }
        Some(Err(e)) => {
            return Err(DiscordError::Gateway(format!("WebSocket error: {e}")));
        }
        None => {
            return Err(DiscordError::Gateway(
                "Connection closed before Hello".into(),
            ));
        }
    };

    let heartbeat_interval = Duration::from_millis(hello.heartbeat_interval);
    debug!(interval_ms = hello.heartbeat_interval, "Received Hello");

    if state.session_id.is_some() ^ state.sequence.is_some() {
        warn!("Incomplete resume state detected; clearing state and re-identifying");
        state.clear_resume();
        persist_gateway_state_if_configured(state_path, state)?;
    }

    // Send Resume if we have a session, otherwise Identify
    if let (Some(sess_id), Some(seq)) = (&state.session_id, state.sequence) {
        // We have a session to resume
        info!(session_id = %sess_id, sequence = seq, "Attempting to resume session");

        let resume = GatewayResume {
            token: config.bot_credential.clone(),
            session_id: sess_id.clone(),
            seq,
        };

        let resume_payload = GatewayPayload {
            op: GatewayOpcode::Resume as i32,
            d: Some(match serde_json::to_value(&resume) {
                Ok(v) => v,
                Err(e) => return Err(e.into()),
            }),
            s: None,
            t: None,
        };

        if let Err(e) = write
            .send(WsMessage::Text(
                match serde_json::to_string(&resume_payload) {
                    Ok(s) => s.into(),
                    Err(e) => return Err(e.into()),
                },
            ))
            .await
        {
            return Err(DiscordError::Gateway(format!("Failed to send Resume: {e}")));
        }
    } else {
        // Fresh connection - send Identify
        let identify = GatewayIdentify {
            token: config.bot_credential.clone(),
            intents: config.intents,
            properties: GatewayProperties {
                os: std::env::consts::OS.into(),
                browser: "fcp-discord".into(),
                device: "fcp-discord".into(),
            },
            shard: config.shard.as_ref().map(|s| [s.shard_id, s.shard_count]),
        };

        let identify_payload = GatewayPayload {
            op: GatewayOpcode::Identify as i32,
            d: Some(match serde_json::to_value(&identify) {
                Ok(v) => v,
                Err(e) => return Err(e.into()),
            }),
            s: None,
            t: None,
        };

        if let Err(e) = write
            .send(WsMessage::Text(
                match serde_json::to_string(&identify_payload) {
                    Ok(s) => s.into(),
                    Err(e) => return Err(e.into()),
                },
            ))
            .await
        {
            return Err(DiscordError::Gateway(format!(
                "Failed to send Identify: {e}"
            )));
        }
    }

    // Main event loop
    let mut heartbeat_acked = true;
    let mut heartbeat_interval_timer = fcp_async_core::time::interval(heartbeat_interval);
    // Skip the first tick which fires immediately
    heartbeat_interval_timer.tick().await;

    loop {
        fcp_async_core::select! {
            // Handle heartbeat timer
            _ = heartbeat_interval_timer.tick() => {
                if !heartbeat_acked {
                    warn!("Heartbeat not acknowledged, connection zombied");
                    return Err(DiscordError::Gateway("Heartbeat timeout (zombied)".into()));
                }
                let heartbeat = json!({
                    "op": GatewayOpcode::Heartbeat as i32,
                    "d": state.sequence
                });
                if let Err(e) = write.send(WsMessage::Text(heartbeat.to_string().into())).await {
                    error!(error = %e, "Failed to send heartbeat");
                    return Err(DiscordError::Gateway(format!("Failed to send heartbeat: {e}")));
                }
                heartbeat_acked = false;
                debug!("Sent heartbeat");
            }

            // Handle incoming messages
            msg = read.next() => {
                match msg {
                    Some(Ok(WsMessage::Text(text))) => {
                        let payload: GatewayPayload = match serde_json::from_str(&text) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!(error = %e, "Failed to parse gateway payload");
                                continue;
                            }
                        };

                        // Update sequence
                        if let Some(s) = payload.s {
                            state.sequence = Some(s);
                            persist_gateway_state_if_configured(state_path, state)?;
                        }

                        match GatewayOpcode::try_from(payload.op) {
                            Ok(GatewayOpcode::Dispatch) => {
                                let event_name = payload.t.clone().unwrap_or_default();
                                let data = payload.d.clone().unwrap_or_default();
                                let event = dispatch_event(event_name, data, state)?;
                                persist_gateway_state_if_configured(state_path, state)?;

                                if event_tx.send(event).await.is_err() {
                                    info!("Event receiver dropped, closing gateway");
                                    return Ok(());
                                }
                            }
                            Ok(GatewayOpcode::HeartbeatAck) => {
                                heartbeat_acked = true;
                                debug!("Heartbeat acknowledged");
                            }
                            Ok(GatewayOpcode::Reconnect) => {
                                info!("Received reconnect request");
                                return Ok(());
                            }
                            Ok(GatewayOpcode::InvalidSession) => {
                                let resumable = payload.d.and_then(|v| v.as_bool()).unwrap_or(false);
                                warn!(resumable, "Session invalidated");
                                if !resumable {
                                    // Clear session state - must re-identify
                                    state.clear_resume();
                                    persist_gateway_state_if_configured(state_path, state)?;
                                }
                                return Ok(());
                            }
                            Ok(GatewayOpcode::Heartbeat) => {
                                // Immediately send heartbeat
                                let heartbeat = json!({
                                    "op": GatewayOpcode::Heartbeat as i32,
                                    "d": state.sequence
                                });
                                if let Err(e) = write.send(WsMessage::Text(heartbeat.to_string().into())).await {
                                    error!(error = %e, "Failed to send heartbeat response");
                                    return Err(DiscordError::Gateway(format!("Failed to send heartbeat: {e}")));
                                }
                            }
                            _ => {
                                debug!(op = payload.op, "Unhandled opcode");
                            }
                        }
                    }
                    Some(Ok(WsMessage::Close(frame))) => {
                        info!(frame = ?frame, "Gateway connection closed");
                        return Ok(());
                    }
                    Some(Ok(_)) => {
                        // Ignore other message types (ping, pong, binary)
                    }
                    Some(Err(e)) => {
                        error!(error = %e, "WebSocket error");
                        return Err(DiscordError::Gateway(format!("WebSocket error: {e}")));
                    }
                    None => {
                        info!("Gateway connection ended");
                        return Ok(());
                    }
                }
            }
        }
    }
}
