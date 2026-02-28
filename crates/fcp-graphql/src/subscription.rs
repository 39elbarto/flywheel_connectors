//! GraphQL over WebSocket subscriptions.

use std::collections::HashMap;
use std::time::Duration;

use fcp_async_core::{channel::mpsc, task, time};
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::ReceiverStream;

use fcp_streaming::{StreamError, WsClient, WsConfig, WsMessage};

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
        let mut connection =
            client
                .connect()
                .await
                .map_err(|err| GraphqlClientError::Protocol {
                    message: format!("{} websocket connect failed: {err}", self.service_name),
                })?;

        let init = GraphqlWsMessage {
            message_type: "connection_init".to_string(),
            id: None,
            payload: self.config.init_payload.clone(),
        };
        connection
            .send_json(&init)
            .await
            .map_err(|err| GraphqlClientError::Protocol {
                message: format!("{} connection_init failed: {err}", self.service_name),
            })?;

        let ack_timeout = self.config.ack_timeout;
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
                    message: format!("{} connection error: {err}", self.service_name),
                });
            }
            Err(_) => {
                return Err(GraphqlClientError::Protocol {
                    message: format!("{} connection_ack timeout", self.service_name),
                });
            }
        }

        let payload = serde_json::json!({
            "query": O::QUERY,
            "operationName": O::OPERATION_NAME,
            "variables": variables,
        });
        let subscribe = GraphqlWsMessage {
            message_type: "subscribe".to_string(),
            id: Some("1".to_string()),
            payload: Some(payload),
        };
        connection
            .send_json(&subscribe)
            .await
            .map_err(|err| GraphqlClientError::Protocol {
                message: format!("{} subscribe failed: {err}", self.service_name),
            })?;

        let (tx, rx) = mpsc::channel(16);

        task::spawn(async move {
            let mut conn = connection;
            while let Ok(Some(message)) = conn.recv().await {
                match message {
                    WsMessage::Ping(payload) => {
                        let _ = conn.send(WsMessage::Pong(payload)).await;
                        continue;
                    }
                    WsMessage::Pong(_) => continue,
                    WsMessage::Close(_) => break,
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
                                            break;
                                        }
                                    }
                                    Err(err) => {
                                        let _ = tx
                                            .send(Err(GraphqlClientError::Json(err.to_string())))
                                            .await;
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
        });

        Ok(ReceiverStream::new(rx))
    }
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
