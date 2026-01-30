//! Twitter filtered stream client.
//!
//! Handles connection to Twitter's filtered stream API (v2).
//! Uses Server-Sent Events (SSE) style streaming.

use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::{
    config::TwitterConfig,
    error::{TwitterError, TwitterResult},
    types::StreamTweet,
};

/// A stream event from Twitter's filtered stream.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// A tweet matching the filter rules.
    Tweet(StreamTweet),

    /// Stream connected successfully.
    Connected,

    /// Stream disconnected (will attempt reconnection).
    Disconnected { reason: String },

    /// Keep-alive heartbeat received.
    Heartbeat,

    /// Error event.
    Error(String),
}

/// Twitter filtered stream connection.
#[derive(Debug)]
pub struct FilteredStream {
    config: TwitterConfig,
    bearer_token: String,
}

/// Handle for a single stream connection attempt.
pub struct StreamHandle {
    pub events: mpsc::Receiver<StreamEvent>,
    pub join_handle: tokio::task::JoinHandle<TwitterResult<()>>,
}

impl FilteredStream {
    /// Create a new filtered stream connection.
    pub fn new(config: TwitterConfig) -> TwitterResult<Self> {
        let bearer_token = config
            .bearer_token
            .clone()
            .ok_or_else(|| TwitterError::Config("Bearer token required for streaming".into()))?;

        Ok(Self {
            config,
            bearer_token,
        })
    }

    /// Connect to the filtered stream once and return a handle for stream events.
    pub async fn connect_once(&self) -> TwitterResult<StreamHandle> {
        let (event_tx, event_rx) = mpsc::channel(256);

        let config = self.config.clone();
        let bearer_token = self.bearer_token.clone();

        let join_handle =
            tokio::spawn(async move { run_stream_once(config, bearer_token, event_tx).await });

        Ok(StreamHandle {
            events: event_rx,
            join_handle,
        })
    }
}

/// Run a single stream connection attempt.
async fn run_stream_once(
    config: TwitterConfig,
    bearer_token: String,
    event_tx: mpsc::Sender<StreamEvent>,
) -> TwitterResult<()> {
    let url = format!(
        "{}/2/tweets/search/stream?tweet.fields=id,text,author_id,created_at,public_metrics,entities&expansions=author_id&user.fields=id,name,username,profile_image_url",
        config.api_url.trim_end_matches('/')
    );

    info!(url = %url, "Connecting to Twitter filtered stream");

    let response = match connect_stream(&url, &bearer_token).await {
        Ok(response) => response,
        Err(err) => {
            let _ = event_tx.send(StreamEvent::Error(err.to_string())).await;
            return Err(err);
        }
    };

    if event_tx.send(StreamEvent::Connected).await.is_err() {
        info!("Event receiver dropped, stopping stream");
        return Ok(());
    }

    if let Err(e) = process_stream(response, &event_tx).await {
        warn!(error = %e, "Stream processing error");
        let _ = event_tx
            .send(StreamEvent::Disconnected {
                reason: e.to_string(),
            })
            .await;
        return Err(e);
    }

    Ok(())
}

/// Connect to the stream endpoint.
async fn connect_stream(url: &str, bearer_token: &str) -> TwitterResult<reqwest::Response> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(90)) // Long timeout for streaming
        .build()?;

    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {bearer_token}"))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();

        return Err(TwitterError::Api {
            status,
            message: body,
            error_code: None,
            retry_after: None,
        });
    }

    Ok(response)
}

/// Process incoming stream data.
async fn process_stream(
    response: reqwest::Response,
    event_tx: &mpsc::Sender<StreamEvent>,
) -> TwitterResult<()> {
    let mut stream = response.bytes_stream();
    let mut buffer = Vec::new();

    while let Some(chunk_result) = stream.next().await {
        let chunk: Bytes = chunk_result?;

        // Handle empty chunks (heartbeats)
        if is_heartbeat_chunk(&chunk) {
            debug!("Received heartbeat");
            if event_tx.send(StreamEvent::Heartbeat).await.is_err() {
                return Ok(());
            }
            continue;
        }

        // Accumulate data
        buffer.extend_from_slice(&chunk);

        // Process complete lines
        while let Some(newline_pos) = buffer.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buffer.drain(..=newline_pos).collect();
            let line_str = String::from_utf8_lossy(&line).trim().to_string();

            match parse_stream_line(&line_str) {
                Ok(Some(event)) => {
                    if let StreamEvent::Tweet(tweet) = &event {
                        debug!(tweet_id = %tweet.data.id, "Received stream tweet");
                    }
                    if event_tx.send(event).await.is_err() {
                        return Ok(());
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    // Could be an error response or malformed data
                    warn!(error = %e, data = %line_str, "Failed to parse stream data");
                }
            }
        }
    }

    Ok(())
}

fn parse_stream_line(line_str: &str) -> Result<Option<StreamEvent>, serde_json::Error> {
    if line_str.is_empty() {
        return Ok(None);
    }

    match serde_json::from_str::<StreamTweet>(line_str) {
        Ok(tweet) => Ok(Some(StreamEvent::Tweet(tweet))),
        Err(err) => {
            if let Some(msg) = extract_stream_error(line_str) {
                return Ok(Some(StreamEvent::Error(msg)));
            }
            Err(err)
        }
    }
}

fn extract_stream_error(line_str: &str) -> Option<String> {
    let error = serde_json::from_str::<serde_json::Value>(line_str).ok()?;
    if error.get("errors").is_some() || error.get("title").is_some() {
        Some(
            error
                .get("detail")
                .or_else(|| error.get("title"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown stream error")
                .to_string(),
        )
    } else {
        None
    }
}

fn is_heartbeat_chunk(chunk: &Bytes) -> bool {
    chunk.is_empty() || (chunk.len() == 2 && chunk[..] == b"\r\n"[..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_event_variants() {
        // Ensure all variants can be created
        let connected = StreamEvent::Connected;
        assert!(matches!(connected, StreamEvent::Connected));

        let disconnected = StreamEvent::Disconnected {
            reason: "test".into(),
        };
        assert!(matches!(disconnected, StreamEvent::Disconnected { .. }));

        let heartbeat = StreamEvent::Heartbeat;
        assert!(matches!(heartbeat, StreamEvent::Heartbeat));

        let error = StreamEvent::Error("test error".into());
        assert!(matches!(error, StreamEvent::Error(_)));
    }

    #[test]
    fn test_filtered_stream_requires_bearer_token() {
        let config = TwitterConfig {
            bearer_token: None,
            ..Default::default()
        };

        let result = FilteredStream::new(config);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TwitterError::Config(_)));
    }

    #[test]
    fn test_filtered_stream_creation() {
        let config = TwitterConfig {
            bearer_token: Some("test_token".into()),
            ..Default::default()
        };

        let result = FilteredStream::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_stream_line_tweet() {
        let payload = serde_json::json!({
            "data": {
                "id": "123",
                "text": "hello"
            }
        })
        .to_string();

        let event = parse_stream_line(&payload).unwrap();
        let tweet = match event {
            Some(StreamEvent::Tweet(tweet)) => tweet,
            other => panic!("expected tweet event, got {other:?}"),
        };

        assert_eq!(tweet.data.id, "123");
        assert_eq!(tweet.data.text, "hello");
    }

    #[test]
    fn test_parse_stream_line_error() {
        let payload = serde_json::json!({
            "title": "Unauthorized",
            "detail": "bad token"
        })
        .to_string();

        let event = parse_stream_line(&payload).unwrap();
        assert!(matches!(event, Some(StreamEvent::Error(msg)) if msg == "bad token"));
    }

    #[test]
    fn test_parse_stream_line_invalid_json() {
        let payload = "not-json";
        assert!(parse_stream_line(payload).is_err());
    }

    #[test]
    fn test_is_heartbeat_chunk() {
        assert!(is_heartbeat_chunk(&Bytes::from("")));
        assert!(is_heartbeat_chunk(&Bytes::from("\r\n")));
        assert!(!is_heartbeat_chunk(&Bytes::from("data")));
    }
}
