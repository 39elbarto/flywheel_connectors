//! GraphQL over WebSocket subscriptions.

use std::collections::HashMap;
use std::time::Duration;

use fcp_async_core::{channel::mpsc, task, time};
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::ReceiverStream;
use tracing::debug;

use fcp_streaming::{
    ReconnectConfig, ReconnectHandler, StreamError, WsClient, WsConfig, WsConnection, WsMessage,
};

use crate::error::{GraphqlClientError, GraphqlError};
use crate::operation::{GraphqlOperation, GraphqlResponse};

/// GraphQL WebSocket message types (graphql-transport-ws).
#[derive(Debug, Serialize, Deserialize)]
struct GraphqlWsMessage {
    #[serde(rename = "type")]
    message_type: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    payload: Option<serde_json::Value>,
}

const SUBSCRIPTION_ID: &str = "1";

/// Subscription configuration.
#[derive(Debug, Clone)]
pub struct GraphqlSubscriptionConfig {
    /// WebSocket configuration.
    pub ws: WsConfig,
    /// Initial payload for connection_init.
    pub init_payload: Option<serde_json::Value>,
    /// Time to wait for connection_ack.
    pub ack_timeout: Duration,
}

impl Default for GraphqlSubscriptionConfig {
    fn default() -> Self {
        Self {
            ws: WsConfig::default(),
            init_payload: None,
            ack_timeout: Duration::from_secs(10),
        }
    }
}

/// Subscription stream type.
pub type GraphqlSubscriptionStream<T> =
    ReceiverStream<Result<GraphqlResponse<T>, GraphqlClientError>>;

/// GraphQL subscription client.
#[derive(Debug, Clone)]
pub struct GraphqlSubscriptionClient {
    url: String,
    service_name: String,
    config: GraphqlSubscriptionConfig,
    headers: HashMap<String, String>,
}

impl GraphqlSubscriptionClient {
    /// Create a new subscription client.
    #[must_use]
    pub fn new(url: impl Into<String>, service_name: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            service_name: service_name.into(),
            config: GraphqlSubscriptionConfig::default(),
            headers: HashMap::new(),
        }
    }

    /// Set configuration.
    #[must_use]
    pub fn with_config(mut self, config: GraphqlSubscriptionConfig) -> Self {
        self.config = config;
        self
    }

    /// Add a header to the WebSocket handshake.
    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Subscribe to a typed GraphQL operation.
    pub async fn subscribe<O: GraphqlOperation>(
        &self,
        variables: O::Variables,
    ) -> Result<GraphqlSubscriptionStream<O::ResponseData>, GraphqlClientError>
    where
        O::ResponseData: 'static,
    {
        let mut ws_config = self.config.ws.clone();
        for (key, value) in &self.headers {
            ws_config.headers.insert(key.clone(), value.clone());
        }
        let client = WsClient::with_config(self.url.clone(), ws_config);
        let payload = serde_json::json!({
            "query": O::QUERY,
            "operationName": O::OPERATION_NAME,
            "variables": variables,
        });
        let connection = establish_subscription(
            &client,
            &self.service_name,
            self.config.init_payload.clone(),
            self.config.ack_timeout,
            &payload,
        )
        .await?;

        let (tx, rx) = mpsc::channel(16);
        let service_name = self.service_name.clone();
        let init_payload = self.config.init_payload.clone();
        let ack_timeout = self.config.ack_timeout;
        let reconnect_config = reconnect_config_from_ws(client.config());

        task::spawn(async move {
            let mut conn = connection;
            let mut reconnect_handler = ReconnectHandler::new(reconnect_config);
            loop {
                fcp_async_core::select! {
                    () = tx.closed() => {
                        send_complete_and_close(&mut conn).await;
                        break;
                    }
                    recv = conn.recv() => {
                        let message = match recv {
                            Ok(Some(message)) => message,
                            Ok(None) => {
                                match reconnect_connection(
                                    &client,
                                    &service_name,
                                    init_payload.clone(),
                                    ack_timeout,
                                    &payload,
                                    &mut reconnect_handler,
                                    "connection closed",
                                )
                                .await
                                {
                                    Ok(new_conn) => {
                                        conn = new_conn;
                                        continue;
                                    }
                                    Err(err) => {
                                        let _ = tx.send(Err(err)).await;
                                        break;
                                    }
                                }
                            }
                            Err(err) => {
                                match reconnect_connection(
                                    &client,
                                    &service_name,
                                    init_payload.clone(),
                                    ack_timeout,
                                    &payload,
                                    &mut reconnect_handler,
                                    &format!("connection error: {err}"),
                                )
                                .await
                                {
                                    Ok(new_conn) => {
                                        conn = new_conn;
                                        continue;
                                    }
                                    Err(reconnect_err) => {
                                        let _ = tx.send(Err(reconnect_err)).await;
                                        break;
                                    }
                                }
                            }
                        };

                match message {
                    WsMessage::Ping(payload) => {
                        let _ = conn.send(WsMessage::Pong(payload)).await;
                        continue;
                    }
                    WsMessage::Pong(_) => continue,
                    WsMessage::Close(frame) => {
                        let close_detail = frame
                            .map_or_else(|| "close frame".to_string(), |f| {
                                format!("close frame {} {}", f.code, f.reason)
                            });
                        match reconnect_connection(
                            &client,
                            &service_name,
                            init_payload.clone(),
                            ack_timeout,
                            &payload,
                            &mut reconnect_handler,
                            &close_detail,
                        )
                        .await
                        {
                            Ok(new_conn) => {
                                conn = new_conn;
                                continue;
                            }
                            Err(err) => {
                                let _ = tx.send(Err(err)).await;
                                break;
                            }
                        }
                    }
                    WsMessage::Text(_) | WsMessage::Binary(_) => {}
                }

                match decode_ws_message(message) {
                    Ok(ws_msg) => match ws_msg.message_type.as_str() {
                        "next" => {
                            if let Some(payload) = ws_msg.payload {
                                let parsed: Result<GraphqlResponse<O::ResponseData>, _> =
                                    serde_json::from_value(payload);
                                match parsed {
                                    Ok(response) => {
                                        if tx.send(Ok(response)).await.is_err() {
                                            send_complete_and_close(&mut conn).await;
                                            break;
                                        }
                                    }
                                    Err(err) => {
                                        if tx
                                            .send(Err(GraphqlClientError::Json(err.to_string())))
                                            .await
                                            .is_err()
                                        {
                                            send_complete_and_close(&mut conn).await;
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        "error" => {
                            let errors = ws_msg
                                .payload
                                .and_then(|value| {
                                    if value.is_array() {
                                        serde_json::from_value::<Vec<GraphqlError>>(value).ok()
                                    } else {
                                        serde_json::from_value::<GraphqlError>(value)
                                            .ok()
                                            .map(|err| vec![err])
                                    }
                                })
                                .unwrap_or_default();
                            let _ = tx
                                .send(Err(GraphqlClientError::GraphqlErrors { errors }))
                                .await;
                            break;
                        }
                        "complete" => break,
                        "ping" => {
                            let pong = GraphqlWsMessage {
                                message_type: "pong".to_string(),
                                id: ws_msg.id.clone(),
                                payload: ws_msg.payload.clone(),
                            };
                            let _ = conn.send_json(&pong).await;
                        }
                        _ => {
                            let _ = tx
                                .send(Err(GraphqlClientError::Protocol {
                                    message: format!(
                                        "unexpected websocket message: {}",
                                        ws_msg.message_type
                                    ),
                                }))
                                .await;
                            break;
                        }
                    },
                    Err(err) => {
                        let _ = tx
                            .send(Err(GraphqlClientError::Protocol {
                                message: format!("decode failed: {err}"),
                            }))
                            .await;
                        break;
                    }
                }
                    }
                }
            }
        });

        Ok(ReceiverStream::new(rx))
    }
}

fn reconnect_config_from_ws(config: &WsConfig) -> ReconnectConfig {
    let reconnect_config = ReconnectConfig::new().with_initial_delay(config.reconnect_delay);
    if !config.auto_reconnect {
        return reconnect_config.with_max_attempts(0);
    }
    match config.max_reconnect_attempts {
        Some(max_attempts) => reconnect_config.with_max_attempts(max_attempts),
        None => reconnect_config.with_unlimited_attempts(),
    }
}

async fn establish_subscription(
    client: &WsClient,
    service_name: &str,
    init_payload: Option<serde_json::Value>,
    ack_timeout: Duration,
    payload: &serde_json::Value,
) -> Result<WsConnection, GraphqlClientError> {
    let mut connection = client
        .connect()
        .await
        .map_err(|err| GraphqlClientError::Protocol {
            message: format!("{service_name} websocket connect failed: {err}"),
        })?;

    let init = GraphqlWsMessage {
        message_type: "connection_init".to_string(),
        id: None,
        payload: init_payload,
    };
    connection
        .send_json(&init)
        .await
        .map_err(|err| GraphqlClientError::Protocol {
            message: format!("{service_name} connection_init failed: {err}"),
        })?;

    let ack = time::timeout(ack_timeout, connection.recv()).await;
    match ack {
        Ok(Ok(Some(message))) => {
            let ack_msg = decode_ws_message(message)?;
            if ack_msg.message_type != "connection_ack" {
                return Err(GraphqlClientError::Protocol {
                    message: format!("expected connection_ack, got {}", ack_msg.message_type),
                });
            }
        }
        Ok(Ok(None)) => {
            return Err(GraphqlClientError::Protocol {
                message: "connection closed before ack".to_string(),
            });
        }
        Ok(Err(err)) => {
            return Err(GraphqlClientError::Protocol {
                message: format!("{service_name} connection error: {err}"),
            });
        }
        Err(_) => {
            return Err(GraphqlClientError::Protocol {
                message: format!("{service_name} connection_ack timeout"),
            });
        }
    }

    let subscribe = GraphqlWsMessage {
        message_type: "subscribe".to_string(),
        id: Some(SUBSCRIPTION_ID.to_string()),
        payload: Some(payload.clone()),
    };
    connection
        .send_json(&subscribe)
        .await
        .map_err(|err| GraphqlClientError::Protocol {
            message: format!("{service_name} subscribe failed: {err}"),
        })?;

    Ok(connection)
}

async fn reconnect_connection(
    client: &WsClient,
    service_name: &str,
    init_payload: Option<serde_json::Value>,
    ack_timeout: Duration,
    payload: &serde_json::Value,
    reconnect_handler: &mut ReconnectHandler,
    disconnect_reason: &str,
) -> Result<WsConnection, GraphqlClientError> {
    loop {
        if !reconnect_handler.can_reconnect() {
            return Err(GraphqlClientError::Protocol {
                message: format!(
                    "{service_name} subscription disconnected ({disconnect_reason}); reconnect exhausted after {} attempts",
                    reconnect_handler.attempts()
                ),
            });
        }

        reconnect_handler
            .wait_for_reconnect()
            .await
            .map_err(GraphqlClientError::from)?;

        match establish_subscription(
            client,
            service_name,
            init_payload.clone(),
            ack_timeout,
            payload,
        )
        .await
        {
            Ok(connection) => {
                reconnect_handler.reset();
                debug!(service = service_name, "graphql subscription reconnected");
                return Ok(connection);
            }
            Err(err) => {
                debug!(
                    service = service_name,
                    attempt = reconnect_handler.attempts(),
                    error = %err,
                    "graphql subscription reconnect attempt failed"
                );
                if !reconnect_handler.can_reconnect() {
                    return Err(err);
                }
            }
        }
    }
}

async fn send_complete_and_close(connection: &mut WsConnection) {
    let complete = GraphqlWsMessage {
        message_type: "complete".to_string(),
        id: Some(SUBSCRIPTION_ID.to_string()),
        payload: None,
    };
    let _ = connection.send_json(&complete).await;
    let _ = connection.close().await;
}

fn decode_ws_message(message: WsMessage) -> Result<GraphqlWsMessage, GraphqlClientError> {
    match message {
        WsMessage::Text(text) => {
            serde_json::from_str(&text).map_err(|err| GraphqlClientError::Json(err.to_string()))
        }
        WsMessage::Binary(binary) => {
            serde_json::from_slice(&binary).map_err(|err| GraphqlClientError::Json(err.to_string()))
        }
        WsMessage::Ping(_) | WsMessage::Pong(_) => Err(GraphqlClientError::Protocol {
            message: "unexpected websocket ping/pong".to_string(),
        }),
        WsMessage::Close(_) => Err(GraphqlClientError::Protocol {
            message: "websocket closed".to_string(),
        }),
    }
}

impl From<StreamError> for GraphqlClientError {
    fn from(err: StreamError) -> Self {
        Self::Protocol {
            message: err.to_string(),
        }
    }
}
