//! No-mock integration tests for fcp-streaming.
//!
//! Cross-module composition, async timeout behavior, SSE streaming via
//! wiremock, reconnection lifecycle, error propagation, and WebSocket
//! message workflows.

use std::time::{Duration, Instant};

use futures_util::pin_mut;
use futures_util::stream::{self, StreamExt};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_streaming::{
    BatchStream, CountingStream, DEFAULT_BUFFER_SIZE, DEFAULT_RECONNECT_DELAY, MAX_RECONNECT_DELAY,
    RateLimitedStream, ReconnectConfig, ReconnectHandler, SseClient, SseConfig, SseEvent,
    StreamError, StreamResult, TimeoutStream, WsClient, WsCloseFrame, WsConfig, WsMessage,
    with_retry,
};

/// Helper: run an async block inside the shared sync test runtime.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    fcp_async_core::runtime::block_on_sync(f).expect("build sync test runtime")
}

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn constants_are_reasonable() {
    assert_eq!(DEFAULT_RECONNECT_DELAY, Duration::from_secs(1));
    assert_eq!(MAX_RECONNECT_DELAY, Duration::from_secs(60));
    assert_eq!(DEFAULT_BUFFER_SIZE, 8192);
    assert!(MAX_RECONNECT_DELAY > DEFAULT_RECONNECT_DELAY);
}

#[test]
fn default_buffer_size_is_power_of_two() {
    assert!(DEFAULT_BUFFER_SIZE.is_power_of_two());
}

#[test]
fn config_defaults_reference_constants() {
    let sse = SseConfig::default();
    assert_eq!(sse.reconnect_delay, DEFAULT_RECONNECT_DELAY);

    let ws = WsConfig::default();
    assert_eq!(ws.reconnect_delay, DEFAULT_RECONNECT_DELAY);

    let rc = ReconnectConfig::default();
    assert_eq!(rc.initial_delay, DEFAULT_RECONNECT_DELAY);
    assert_eq!(rc.max_delay, MAX_RECONNECT_DELAY);
}

// ═══════════════════════════════════════════════════════════════════════════
// Stream Composition
// ═══════════════════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn timeout_wrapping_rate_limited() {
    let stream = stream::iter(vec![1, 2, 3]);
    let rate_limited = RateLimitedStream::new(stream, Duration::from_millis(1));
    let timeout = TimeoutStream::new(rate_limited, Duration::from_secs(5));
    pin_mut!(timeout);

    let mut items = Vec::new();
    while let Some(result) = timeout.next().await {
        items.push(result.unwrap());
    }
    assert_eq!(items, vec![1, 2, 3]);
}

#[fcp_async_core::runtime::test]
async fn rate_limited_wrapping_timeout() {
    let stream = stream::iter(vec![10, 20, 30]);
    let timeout = TimeoutStream::new(stream, Duration::from_secs(5));
    let rate_limited = RateLimitedStream::new(timeout, Duration::from_millis(1));
    pin_mut!(rate_limited);

    let mut items = Vec::new();
    while let Some(result) = rate_limited.next().await {
        items.push(result.unwrap());
    }
    assert_eq!(items, vec![10, 20, 30]);
}

#[fcp_async_core::runtime::test]
async fn batch_wrapping_rate_limited() {
    let stream = stream::iter(vec![1, 2, 3, 4, 5, 6]);
    let rate_limited = RateLimitedStream::new(stream, Duration::from_millis(1));
    let batched = BatchStream::new(rate_limited, 3, Duration::from_secs(10));
    pin_mut!(batched);

    let batch1 = batched.next().await.unwrap();
    assert_eq!(batch1, vec![1, 2, 3]);
    let batch2 = batched.next().await.unwrap();
    assert_eq!(batch2, vec![4, 5, 6]);
    assert!(batched.next().await.is_none());
}

#[fcp_async_core::runtime::test]
async fn timeout_wrapping_batch() {
    let stream = stream::iter(vec![1, 2, 3, 4]);
    let batched = BatchStream::new(stream, 2, Duration::from_secs(10));
    let timeout = TimeoutStream::new(batched, Duration::from_secs(5));
    pin_mut!(timeout);

    let batch1 = timeout.next().await.unwrap().unwrap();
    assert_eq!(batch1, vec![1, 2]);
    let batch2 = timeout.next().await.unwrap().unwrap();
    assert_eq!(batch2, vec![3, 4]);
    assert!(timeout.next().await.is_none());
}

#[fcp_async_core::runtime::test]
async fn counting_stream_lifecycle() {
    let stream = stream::iter(vec![100, 200, 300]);
    let mut counting = CountingStream::new(stream);

    assert_eq!(counting.items_count(), 0);
    assert_eq!(counting.next().await, Some(100));
    assert_eq!(counting.items_count(), 1);
    assert_eq!(counting.next().await, Some(200));
    assert_eq!(counting.items_count(), 2);
    assert_eq!(counting.next().await, Some(300));
    assert_eq!(counting.items_count(), 3);
    assert!(counting.next().await.is_none());
    assert_eq!(counting.items_count(), 3);
}

#[fcp_async_core::runtime::test]
async fn stream_ext_with_timeout_via_trait() {
    use fcp_streaming::StreamExt as _;
    let stream = stream::iter(vec![1, 2, 3]);
    let ts = stream.with_timeout(Duration::from_secs(5));
    pin_mut!(ts);

    let mut results = Vec::new();
    while let Some(result) = ts.next().await {
        results.push(result.unwrap());
    }
    assert_eq!(results, vec![1, 2, 3]);
}

#[fcp_async_core::runtime::test]
async fn stream_ext_buffered_batches_via_trait() {
    use fcp_streaming::StreamExt as _;
    let stream = stream::iter(vec![1, 2, 3, 4, 5]);
    let batched = stream.buffered_batches(2, Duration::from_secs(10));
    pin_mut!(batched);

    assert_eq!(batched.next().await.unwrap(), vec![1, 2]);
    assert_eq!(batched.next().await.unwrap(), vec![3, 4]);
    assert_eq!(batched.next().await.unwrap(), vec![5]);
    assert!(batched.next().await.is_none());
}

#[fcp_async_core::runtime::test]
async fn rate_limited_timeout_large_pipeline() {
    let items: Vec<i32> = (0..50).collect();
    let stream = stream::iter(items.clone());
    let rate_limited = RateLimitedStream::new(stream, Duration::from_millis(1));
    let timeout = TimeoutStream::new(rate_limited, Duration::from_secs(30));
    pin_mut!(timeout);

    let mut results = Vec::new();
    while let Some(result) = timeout.next().await {
        results.push(result.unwrap());
    }
    assert_eq!(results, items);
}

// ═══════════════════════════════════════════════════════════════════════════
// Timeout Behavior
// ═══════════════════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn timeout_fires_on_pending_stream() {
    let stream = stream::pending::<i32>();
    let timeout = TimeoutStream::new(stream, Duration::from_millis(50));
    pin_mut!(timeout);

    let start = Instant::now();
    let result = timeout.next().await;
    let elapsed = start.elapsed();

    assert!(result.is_some());
    let err = result.unwrap();
    assert!(err.is_err());
    assert!(
        matches!(err.unwrap_err(), StreamError::Timeout(_)),
        "expected Timeout error"
    );
    assert!(
        elapsed >= Duration::from_millis(40),
        "expected >= 40ms, got {elapsed:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn timeout_resets_between_items() {
    let items: Vec<i32> = (0..10).collect();
    let stream = stream::iter(items.clone());
    let timeout = TimeoutStream::new(stream, Duration::from_millis(100));
    pin_mut!(timeout);

    let mut results = Vec::new();
    while let Some(result) = timeout.next().await {
        results.push(result.unwrap());
    }
    assert_eq!(results, items);
}

#[fcp_async_core::runtime::test]
async fn timeout_stream_empty_returns_none_immediately() {
    let stream = stream::empty::<i32>();
    let timeout = TimeoutStream::new(stream, Duration::from_millis(100));
    pin_mut!(timeout);
    assert!(timeout.next().await.is_none());
}

#[fcp_async_core::runtime::test]
async fn timeout_error_contains_configured_duration() {
    let stream = stream::pending::<i32>();
    let dur = Duration::from_millis(25);
    let timeout = TimeoutStream::new(stream, dur);
    pin_mut!(timeout);

    let err = timeout.next().await.unwrap().unwrap_err();
    if let StreamError::Timeout(d) = err {
        assert_eq!(d, dur);
    } else {
        panic!("expected Timeout variant, got {err:?}");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SSE via wiremock (uses block_on for Tokio reactor)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sse_client_receives_single_event() {
    block_on(async {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/events"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/event-stream")
                    .set_body_string("data: hello world\n\n"),
            )
            .mount(&mock_server)
            .await;

        let client = SseClient::new(format!("{}/events", mock_server.uri()));
        let mut stream = client.connect().await.unwrap();

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.data, "hello world");
        assert_eq!(event.event, None);
    });
}

#[test]
fn sse_client_receives_multiple_events() {
    block_on(async {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/events"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/event-stream")
                    .set_body_string("data: event1\n\ndata: event2\n\ndata: event3\n\n"),
            )
            .mount(&mock_server)
            .await;

        let client = SseClient::new(format!("{}/events", mock_server.uri()));
        let mut stream = client.connect().await.unwrap();

        let e1 = stream.next().await.unwrap().unwrap();
        assert_eq!(e1.data, "event1");
        let e2 = stream.next().await.unwrap().unwrap();
        assert_eq!(e2.data, "event2");
        let e3 = stream.next().await.unwrap().unwrap();
        assert_eq!(e3.data, "event3");
    });
}

#[test]
fn sse_client_typed_events() {
    block_on(async {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/events"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/event-stream")
                    .set_body_string(
                        "event: message\ndata: hello\n\nevent: update\ndata: world\n\n",
                    ),
            )
            .mount(&mock_server)
            .await;

        let client = SseClient::new(format!("{}/events", mock_server.uri()));
        let mut stream = client.connect().await.unwrap();

        let e1 = stream.next().await.unwrap().unwrap();
        assert!(e1.is_event("message"));
        assert_eq!(e1.data, "hello");

        let e2 = stream.next().await.unwrap().unwrap();
        assert!(e2.is_event("update"));
        assert_eq!(e2.data, "world");
    });
}

#[test]
fn sse_client_json_events() {
    block_on(async {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/events"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/event-stream")
                    .set_body_string("data: {\"key\":\"value\",\"count\":42}\n\n"),
            )
            .mount(&mock_server)
            .await;

        let client = SseClient::new(format!("{}/events", mock_server.uri()));
        let mut stream = client.connect().await.unwrap();

        let event = stream.next().await.unwrap().unwrap();
        let parsed: serde_json::Value = event.json().unwrap();
        assert_eq!(parsed["key"], "value");
        assert_eq!(parsed["count"], 42);
    });
}

#[test]
fn sse_client_multiline_data() {
    block_on(async {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/events"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/event-stream")
                    .set_body_string("data: line1\ndata: line2\ndata: line3\n\n"),
            )
            .mount(&mock_server)
            .await;

        let client = SseClient::new(format!("{}/events", mock_server.uri()));
        let mut stream = client.connect().await.unwrap();

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.data, "line1\nline2\nline3");
    });
}

#[test]
fn sse_client_event_with_id_and_retry() {
    block_on(async {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/events"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/event-stream")
                    .set_body_string("id: 42\nretry: 5000\nevent: ping\ndata: pong\n\n"),
            )
            .mount(&mock_server)
            .await;

        let client = SseClient::new(format!("{}/events", mock_server.uri()));
        let mut stream = client.connect().await.unwrap();

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.id, Some("42".to_string()));
        assert_eq!(event.retry, Some(5000));
        assert!(event.is_event("ping"));
        assert_eq!(event.data, "pong");
        assert_eq!(stream.last_event_id(), Some("42"));
    });
}

#[test]
fn sse_client_sends_accept_header() {
    block_on(async {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/events"))
            .and(header("Accept", "text/event-stream"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/event-stream")
                    .set_body_string("data: ok\n\n"),
            )
            .mount(&mock_server)
            .await;

        let client = SseClient::new(format!("{}/events", mock_server.uri()));
        let mut stream = client.connect().await.unwrap();

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.data, "ok");
    });
}

#[test]
fn sse_client_with_custom_headers() {
    block_on(async {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/events"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/event-stream")
                    .set_body_string("data: authorized\n\n"),
            )
            .mount(&mock_server)
            .await;

        let config = SseConfig::new().with_header("Authorization", "Bearer test-token");
        let client = SseClient::with_config(format!("{}/events", mock_server.uri()), config);
        let mut stream = client.connect().await.unwrap();

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.data, "authorized");
    });
}

#[test]
fn sse_client_with_last_event_id() {
    block_on(async {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/events"))
            .and(header("Last-Event-ID", "prev-42"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/event-stream")
                    .set_body_string("data: resumed\n\n"),
            )
            .mount(&mock_server)
            .await;

        let client = SseClient::new(format!("{}/events", mock_server.uri()));
        let mut stream = client.connect_with_last_id(Some("prev-42")).await.unwrap();

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.data, "resumed");
    });
}

#[test]
fn sse_client_handles_http_503() {
    block_on(async {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/events"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let client = SseClient::new(format!("{}/events", mock_server.uri()));
        let result = client.connect().await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, StreamError::HttpError { status: 503, .. }));
    });
}

#[test]
fn sse_client_handles_http_404() {
    block_on(async {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/events"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let client = SseClient::new(format!("{}/events", mock_server.uri()));
        let result = client.connect().await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, StreamError::HttpError { status: 404, .. }));
    });
}

#[test]
fn sse_client_connection_refused() {
    block_on(async {
        let client = SseClient::new("http://127.0.0.1:1");
        let result = client.connect().await;
        assert!(result.is_err());
    });
}

#[test]
fn sse_client_buffer_overflow() {
    block_on(async {
        let mock_server = MockServer::start().await;
        let large_data = "x".repeat(1000);
        Mock::given(method("GET"))
            .and(path("/events"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/event-stream")
                    .set_body_string(format!("data: {large_data}\n\n")),
            )
            .mount(&mock_server)
            .await;

        let config = SseConfig::new().with_max_buffer_size(100);
        let client = SseClient::with_config(format!("{}/events", mock_server.uri()), config);
        let mut stream = client.connect().await.unwrap();

        let result = stream.next().await;
        assert!(result.is_some());
        let event_result = result.unwrap();
        assert!(event_result.is_err());
        assert!(matches!(
            event_result.unwrap_err(),
            StreamError::BufferOverflow { .. }
        ));
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Reconnection Integration
// ═══════════════════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn reconnect_handler_full_lifecycle() {
    let config = ReconnectConfig::new()
        .with_max_attempts(5)
        .with_initial_delay(Duration::from_millis(1))
        .with_jitter(false);
    let mut handler = ReconnectHandler::new(config);

    // Phase 1: fail 3 times
    for i in 0..3 {
        assert!(handler.can_reconnect());
        handler.record_failure();
        assert_eq!(handler.attempts(), i + 1);
    }

    // Phase 2: reset on "success"
    handler.reset();
    assert_eq!(handler.attempts(), 0);
    assert!(handler.can_reconnect());

    // Phase 3: exhaust attempts
    for _ in 0..5 {
        handler.record_failure();
    }
    assert!(!handler.can_reconnect());

    // Phase 4: reset recovers
    handler.reset();
    assert!(handler.can_reconnect());
}

#[fcp_async_core::runtime::test]
async fn with_retry_eventual_success() {
    let config = ReconnectConfig::new()
        .with_max_attempts(5)
        .with_initial_delay(Duration::from_millis(1))
        .with_jitter(false);

    let mut attempt = 0;
    let result = with_retry(config, || {
        attempt += 1;
        async move {
            if attempt < 4 {
                Err(StreamError::ConnectionFailed(format!("attempt {attempt}")))
            } else {
                Ok("success")
            }
        }
    })
    .await;

    assert_eq!(result.unwrap(), "success");
    assert_eq!(attempt, 4);
}

#[fcp_async_core::runtime::test]
async fn with_retry_exhaustion_returns_limit_exceeded() {
    let config = ReconnectConfig::new()
        .with_max_attempts(3)
        .with_initial_delay(Duration::from_millis(1))
        .with_jitter(false);

    let result: StreamResult<i32> = with_retry(config, || async {
        Err(StreamError::ConnectionFailed("always fails".into()))
    })
    .await;

    assert!(matches!(
        result,
        Err(StreamError::ReconnectLimitExceeded { .. })
    ));
}

#[fcp_async_core::runtime::test]
async fn reconnect_handler_wait_lifecycle() {
    let config = ReconnectConfig::new()
        .with_max_attempts(3)
        .with_initial_delay(Duration::from_millis(1))
        .with_jitter(false);
    let mut handler = ReconnectHandler::new(config);

    handler.wait_for_reconnect().await.unwrap();
    assert_eq!(handler.attempts(), 1);
    handler.wait_for_reconnect().await.unwrap();
    assert_eq!(handler.attempts(), 2);
    handler.wait_for_reconnect().await.unwrap();
    assert_eq!(handler.attempts(), 3);

    let result = handler.wait_for_reconnect().await;
    assert!(matches!(
        result,
        Err(StreamError::ReconnectLimitExceeded { attempts: 3 })
    ));
}

#[fcp_async_core::runtime::test]
async fn reconnect_operation_with_mixed_error_types() {
    let config = ReconnectConfig::new()
        .with_max_attempts(10)
        .with_initial_delay(Duration::from_millis(1))
        .with_jitter(false);
    let mut handler = ReconnectHandler::new(config);

    let mut call = 0;
    let result = handler
        .reconnect(|| {
            call += 1;
            async move {
                match call {
                    1 => Err(StreamError::ConnectionFailed("timeout".into())),
                    2 => Err(StreamError::WebSocketError("protocol".into())),
                    3 => Err(StreamError::InvalidState("not ready".into())),
                    _ => Ok(call),
                }
            }
        })
        .await;

    assert_eq!(result.unwrap(), 4);
    assert_eq!(handler.attempts(), 0);
    assert_eq!(call, 4);
}

#[test]
fn reconnect_config_exponential_backoff() {
    let config = ReconnectConfig::new()
        .with_initial_delay(Duration::from_millis(100))
        .with_max_delay(Duration::from_secs(10))
        .with_backoff_multiplier(2.0)
        .with_jitter(false);

    assert_eq!(config.delay_for_attempt(0), Duration::from_millis(100));
    assert_eq!(config.delay_for_attempt(1), Duration::from_millis(200));
    assert_eq!(config.delay_for_attempt(2), Duration::from_millis(400));
    assert_eq!(config.delay_for_attempt(3), Duration::from_millis(800));
    assert_eq!(config.delay_for_attempt(4), Duration::from_millis(1600));
    assert_eq!(config.delay_for_attempt(20), Duration::from_secs(10));
}

#[test]
fn reconnect_config_jitter_stays_in_bounds() {
    let config = ReconnectConfig::new()
        .with_initial_delay(Duration::from_secs(1))
        .with_max_delay(Duration::from_secs(60))
        .with_backoff_multiplier(1.0)
        .with_jitter(true);

    for _ in 0..100 {
        let delay = config.delay_for_attempt(0);
        assert!(
            delay >= Duration::from_millis(500),
            "delay {delay:?} below lower bound"
        );
        assert!(
            delay <= Duration::from_millis(1500),
            "delay {delay:?} above upper bound"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn with_retry_measures_timing() {
    let config = ReconnectConfig::new()
        .with_max_attempts(3)
        .with_initial_delay(Duration::from_millis(50))
        .with_backoff_multiplier(1.0)
        .with_jitter(false);

    let start = Instant::now();
    let mut attempt = 0;
    let result = with_retry(config, || {
        attempt += 1;
        async move {
            if attempt < 3 {
                Err(StreamError::ConnectionFailed("fail".into()))
            } else {
                Ok(42)
            }
        }
    })
    .await;
    let elapsed = start.elapsed();

    assert_eq!(result.unwrap(), 42);
    // 2 failures × 50ms delay = ~100ms minimum
    assert!(
        elapsed >= Duration::from_millis(80),
        "expected >= 80ms, got {elapsed:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Error Chain Tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn error_io_source_chain() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
    let stream_err = StreamError::IoError(io_err);
    let source = std::error::Error::source(&stream_err);
    assert!(source.is_some());
    assert!(source.unwrap().to_string().contains("refused"));
}

#[test]
fn error_variants_all_produce_nonempty_display() {
    let errors: Vec<StreamError> = vec![
        StreamError::ConnectionFailed("host unreachable".into()),
        StreamError::ConnectionClosed {
            reason: "server shutdown".into(),
            code: Some(1001),
        },
        StreamError::HttpError {
            status: 429,
            message: "Too Many Requests".into(),
        },
        StreamError::ParseError("invalid JSON".into()),
        StreamError::Timeout(Duration::from_secs(30)),
        StreamError::ReconnectLimitExceeded { attempts: 10 },
        StreamError::BufferOverflow {
            size: 2_000_000,
            limit: 1_000_000,
        },
        StreamError::InvalidState("closed".into()),
        StreamError::WebSocketError("protocol violation".into()),
        StreamError::SseError("malformed event".into()),
    ];

    for error in &errors {
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.is_empty(), "empty display for {error:?}");
        assert!(!debug.is_empty());
    }
}

#[test]
fn error_connection_closed_with_and_without_code() {
    let with_code = StreamError::ConnectionClosed {
        reason: "done".into(),
        code: Some(1000),
    };
    let without_code = StreamError::ConnectionClosed {
        reason: "eof".into(),
        code: None,
    };

    assert!(with_code.to_string().contains("done"));
    assert!(without_code.to_string().contains("eof"));
}

#[test]
fn error_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<StreamError>();
}

// ═══════════════════════════════════════════════════════════════════════════
// WebSocket Message Integration
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[allow(clippy::similar_names)]
fn ws_message_all_type_checks() {
    let text = WsMessage::text("hello");
    let binary = WsMessage::binary(vec![1, 2, 3]);
    let ws_ping = WsMessage::Ping(vec![]);
    let ws_pong = WsMessage::Pong(vec![]);
    let close_none = WsMessage::Close(None);
    let close_frame = WsMessage::Close(Some(WsCloseFrame::normal()));

    assert!(text.is_text() && !text.is_binary() && !text.is_close());
    assert!(!binary.is_text() && binary.is_binary() && !binary.is_close());
    assert!(!ws_ping.is_text() && !ws_ping.is_binary() && !ws_ping.is_close());
    assert!(!ws_pong.is_text() && !ws_pong.is_binary() && !ws_pong.is_close());
    assert!(close_none.is_close());
    assert!(close_frame.is_close());
}

#[test]
fn ws_message_json_roundtrip_complex_type() {
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct Payload {
        action: String,
        count: u32,
        nested: Vec<String>,
    }

    let original = Payload {
        action: "update".to_string(),
        count: 42,
        nested: vec!["a".to_string(), "b".to_string()],
    };

    let json_str = serde_json::to_string(&original).unwrap();
    let msg = WsMessage::text(json_str);
    let parsed: Payload = msg.json().unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn ws_message_binary_json_roundtrip() {
    let data = serde_json::json!({"type": "binary", "payload": [1, 2, 3]});
    let bytes = serde_json::to_vec(&data).unwrap();
    let msg = WsMessage::binary(bytes);
    let parsed: serde_json::Value = msg.json().unwrap();
    assert_eq!(parsed["type"], "binary");
    assert_eq!(parsed["payload"], serde_json::json!([1, 2, 3]));
}

#[test]
#[allow(clippy::similar_names)]
fn ws_message_json_fails_on_non_data_types() {
    let ws_ping = WsMessage::Ping(vec![]);
    let ws_pong = WsMessage::Pong(vec![]);
    let close = WsMessage::Close(None);

    assert!(ws_ping.json::<serde_json::Value>().is_err());
    assert!(ws_pong.json::<serde_json::Value>().is_err());
    assert!(close.json::<serde_json::Value>().is_err());
}

#[test]
fn ws_close_frame_standard_codes() {
    let normal = WsCloseFrame::normal();
    assert_eq!(normal.code, 1000);
    assert_eq!(normal.reason, "Normal closure");

    let going_away = WsCloseFrame::going_away();
    assert_eq!(going_away.code, 1001);
    assert_eq!(going_away.reason, "Going away");

    let custom = WsCloseFrame::new(4000, "Application error");
    assert_eq!(custom.code, 4000);
    assert_eq!(custom.reason, "Application error");
}

#[test]
fn ws_client_invalid_url_returns_connection_failed() {
    block_on(async {
        let client = WsClient::new("not-a-valid-url");
        let result = client.connect().await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, StreamError::ConnectionFailed(_)));
    });
}

#[test]
fn ws_client_connection_refused() {
    block_on(async {
        let client = WsClient::with_config(
            "ws://127.0.0.1:1",
            WsConfig::new().with_connect_timeout(Duration::from_millis(200)),
        );
        let result = client.connect().await;
        assert!(result.is_err());
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Config Interop
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sse_event_builder_full_chain() {
    let event = SseEvent::new("payload")
        .with_event("message")
        .with_id("123");

    assert_eq!(event.data, "payload");
    assert_eq!(event.event, Some("message".to_string()));
    assert_eq!(event.id, Some("123".to_string()));
    assert!(event.is_event("message"));
    assert!(!event.is_event("other"));
}

#[test]
fn ws_config_comprehensive_builder() {
    let config = WsConfig::new()
        .with_connect_timeout(Duration::from_secs(60))
        .with_ping_interval(Some(Duration::from_secs(15)))
        .with_max_message_size(1024 * 1024)
        .with_header("Authorization", "Bearer token")
        .with_header("X-Custom", "value")
        .with_auto_reconnect(false);

    assert_eq!(config.connect_timeout, Duration::from_secs(60));
    assert_eq!(config.ping_interval, Some(Duration::from_secs(15)));
    assert_eq!(config.max_message_size, 1024 * 1024);
    assert_eq!(config.headers.len(), 2);
    assert!(!config.auto_reconnect);
}

#[test]
fn sse_config_comprehensive_builder() {
    let config = SseConfig::new()
        .with_timeout(Duration::from_secs(30))
        .with_max_buffer_size(2048)
        .with_header("Authorization", "Bearer abc")
        .with_auto_reconnect(false)
        .with_max_reconnect_attempts(5)
        .with_reconnect_delay(Duration::from_millis(500));

    assert_eq!(config.timeout, Some(Duration::from_secs(30)));
    assert_eq!(config.max_buffer_size, 2048);
    assert!(!config.auto_reconnect);
    assert_eq!(config.max_reconnect_attempts, Some(5));
    assert_eq!(config.reconnect_delay, Duration::from_millis(500));
}

#[test]
fn ws_client_accessors() {
    let config = WsConfig::new().with_connect_timeout(Duration::from_secs(60));
    let client = WsClient::with_config("ws://localhost:8080", config);
    assert_eq!(client.url(), "ws://localhost:8080");
    assert_eq!(client.config().connect_timeout, Duration::from_secs(60));
}

#[test]
fn sse_client_accessors() {
    let config = SseConfig::new().with_max_buffer_size(4096);
    let client = SseClient::with_config("https://example.com/events", config);
    assert_eq!(client.url(), "https://example.com/events");
    assert_eq!(client.config().max_buffer_size, 4096);
}

// ═══════════════════════════════════════════════════════════════════════════
// ReconnectHandler & ReconnectConfig Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn reconnect_handler_reset_clears_attempts() {
    let config = ReconnectConfig::new().with_max_attempts(5);
    let mut handler = ReconnectHandler::new(config);

    handler.record_failure();
    handler.record_failure();
    assert_eq!(handler.attempts(), 2);

    handler.reset();
    assert_eq!(handler.attempts(), 0);
    assert!(handler.can_reconnect());
}

#[test]
fn reconnect_handler_config_accessor() {
    let config = ReconnectConfig::new()
        .with_max_attempts(3)
        .with_initial_delay(Duration::from_millis(200))
        .with_backoff_multiplier(1.5);
    let handler = ReconnectHandler::new(config);

    assert_eq!(handler.config().max_attempts, Some(3));
    assert_eq!(handler.config().initial_delay, Duration::from_millis(200));
    assert!((handler.config().backoff_multiplier - 1.5).abs() < f64::EPSILON);
}

#[test]
fn reconnect_config_unlimited_attempts() {
    let config = ReconnectConfig::new().with_unlimited_attempts();
    assert!(config.max_attempts.is_none());

    let handler = ReconnectHandler::new(config);
    // Should always be able to reconnect
    for _ in 0..1000 {
        assert!(handler.can_reconnect());
    }
}

#[test]
fn reconnect_config_default_values() {
    let config = ReconnectConfig::default();
    assert_eq!(config.initial_delay, Duration::from_secs(1));
    assert_eq!(config.max_delay, Duration::from_secs(60));
    assert!((config.backoff_multiplier - 2.0).abs() < f64::EPSILON);
    assert!(config.jitter);
    assert_eq!(config.max_attempts, Some(10));
}

#[test]
fn reconnect_handler_exhaustion() {
    let config = ReconnectConfig::new().with_max_attempts(2);
    let mut handler = ReconnectHandler::new(config);

    assert!(handler.can_reconnect());
    handler.record_failure();
    assert!(handler.can_reconnect());
    handler.record_failure();
    assert!(!handler.can_reconnect());
}

#[test]
fn reconnect_config_backoff_clamped_to_max() {
    let config = ReconnectConfig::new()
        .with_initial_delay(Duration::from_secs(1))
        .with_max_delay(Duration::from_secs(5))
        .with_backoff_multiplier(10.0)
        .with_jitter(false);

    // Even with 10x multiplier, delay should be clamped to max_delay
    let delay = config.delay_for_attempt(5);
    assert!(delay <= Duration::from_secs(5));
}

// ═══════════════════════════════════════════════════════════════════════════
// WsMessage Accessor Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn ws_message_as_text_returns_content() {
    let msg = WsMessage::text("hello world");
    assert_eq!(msg.as_text(), Some("hello world"));
    assert!(msg.as_binary().is_none());
}

#[test]
fn ws_message_as_binary_returns_content() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let msg = WsMessage::binary(data.clone());
    assert_eq!(msg.as_binary(), Some(data.as_slice()));
    assert!(msg.as_text().is_none());
}

#[test]
fn ws_message_accessors_on_control_frames() {
    assert!(WsMessage::Ping(vec![1]).as_text().is_none());
    assert!(WsMessage::Ping(vec![1]).as_binary().is_none());
    assert!(WsMessage::Pong(vec![2]).as_text().is_none());
    assert!(WsMessage::Close(None).as_text().is_none());
    assert!(WsMessage::Close(None).as_binary().is_none());
}

#[test]
fn ws_close_frame_custom_reason() {
    let frame = WsCloseFrame::new(4001, "custom protocol error");
    assert_eq!(frame.code, 4001);
    assert_eq!(frame.reason, "custom protocol error");

    let msg = WsMessage::Close(Some(frame));
    assert!(msg.is_close());
    assert!(!msg.is_text());
    assert!(!msg.is_binary());
}

// ═══════════════════════════════════════════════════════════════════════════
// SseEvent Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sse_event_json_deserialize() {
    #[derive(serde::Deserialize, Debug, PartialEq)]
    struct EventData {
        kind: String,
        value: i32,
    }

    let event = SseEvent::new(r#"{"kind":"update","value":42}"#);
    let parsed: EventData = event.json().unwrap();
    assert_eq!(parsed.kind, "update");
    assert_eq!(parsed.value, 42);
}

#[test]
fn sse_event_json_invalid_returns_err() {
    let event = SseEvent::new("not valid json");
    let result = event.json::<serde_json::Value>();
    assert!(result.is_err());
}

#[test]
fn sse_event_is_event_with_no_type() {
    let event = SseEvent::new("data only");
    assert!(!event.is_event("message"));
    assert!(!event.is_event(""));
}

#[test]
fn sse_event_empty_data() {
    let event = SseEvent::new("");
    assert_eq!(event.data, "");
    assert!(event.event.is_none());
    assert!(event.id.is_none());
    assert!(event.retry.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// Stream Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn counting_stream_empty() {
    let stream = stream::empty::<i32>();
    let mut counting = CountingStream::new(stream);
    assert_eq!(counting.items_count(), 0);
    assert!(counting.next().await.is_none());
    assert_eq!(counting.items_count(), 0);
}

#[fcp_async_core::runtime::test]
async fn batch_stream_single_item() {
    let stream = stream::iter(vec![42]);
    let batched = BatchStream::new(stream, 10, Duration::from_secs(10));
    pin_mut!(batched);

    let batch = batched.next().await.unwrap();
    assert_eq!(batch, vec![42]);
    assert!(batched.next().await.is_none());
}

#[fcp_async_core::runtime::test]
async fn batch_stream_exact_multiple() {
    let stream = stream::iter(vec![1, 2, 3, 4]);
    let batched = BatchStream::new(stream, 2, Duration::from_secs(10));
    pin_mut!(batched);

    assert_eq!(batched.next().await.unwrap(), vec![1, 2]);
    assert_eq!(batched.next().await.unwrap(), vec![3, 4]);
    assert!(batched.next().await.is_none());
}

#[fcp_async_core::runtime::test]
async fn batch_stream_empty() {
    let stream = stream::empty::<i32>();
    let batched = BatchStream::new(stream, 5, Duration::from_secs(10));
    pin_mut!(batched);
    assert!(batched.next().await.is_none());
}

#[fcp_async_core::runtime::test]
async fn rate_limited_preserves_order() {
    let items = vec![5, 4, 3, 2, 1];
    let stream = stream::iter(items.clone());
    let rate_limited = RateLimitedStream::new(stream, Duration::from_millis(1));
    pin_mut!(rate_limited);

    let mut collected = Vec::new();
    while let Some(item) = rate_limited.next().await {
        collected.push(item);
    }
    assert_eq!(collected, items);
}

// ═══════════════════════════════════════════════════════════════════════════
// Error Edge Cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn error_is_sync() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<StreamError>();
}

#[test]
fn error_buffer_overflow_contains_details() {
    let err = StreamError::BufferOverflow {
        size: 2_000_000,
        limit: 1_000_000,
    };
    let display = err.to_string();
    assert!(
        display.contains("2000000") || display.contains("2_000_000") || display.contains("buffer")
    );
}

#[test]
fn error_http_error_contains_status() {
    let err = StreamError::HttpError {
        status: 503,
        message: "Service Unavailable".into(),
    };
    let display = err.to_string();
    assert!(display.contains("503") || display.contains("Service Unavailable"));
}

#[test]
fn error_reconnect_limit_contains_attempts() {
    let err = StreamError::ReconnectLimitExceeded { attempts: 10 };
    let display = err.to_string();
    assert!(display.contains("10") || display.contains("reconnect"));
}

#[test]
fn stream_result_type_alias_works() {
    let ok: StreamResult<i32> = Ok(42);
    assert!(ok.is_ok());

    let err: StreamResult<i32> = Err(StreamError::InvalidState("test".into()));
    assert!(err.is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// Cross-Module: SSE Event + JSON + Config (no network)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sse_event_json_roundtrip_complex() {
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct Update {
        id: u32,
        status: String,
        tags: Vec<String>,
    }

    let original = Update {
        id: 1,
        status: "active".to_string(),
        tags: vec!["a".to_string(), "b".to_string()],
    };

    let json = serde_json::to_string(&original).unwrap();
    let event = SseEvent::new(json).with_event("update").with_id("evt-1");

    assert!(event.is_event("update"));
    assert_eq!(event.id, Some("evt-1".to_string()));
    let parsed: Update = event.json().unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn sse_config_with_ws_config_both_customized() {
    // Validate SSE and WS configs can be built independently with same patterns
    let sse = SseConfig::new()
        .with_timeout(Duration::from_secs(30))
        .with_header("Authorization", "Bearer sse-token")
        .with_auto_reconnect(true)
        .with_max_reconnect_attempts(3)
        .with_reconnect_delay(Duration::from_millis(500));

    let ws = WsConfig::new()
        .with_connect_timeout(Duration::from_secs(30))
        .with_header("Authorization", "Bearer ws-token")
        .with_auto_reconnect(true);

    assert_eq!(sse.timeout, Some(Duration::from_secs(30)));
    assert_eq!(ws.connect_timeout, Duration::from_secs(30));
    assert!(sse.auto_reconnect);
    assert!(ws.auto_reconnect);
    assert_eq!(sse.headers["Authorization"], "Bearer sse-token");
    assert_eq!(ws.headers["Authorization"], "Bearer ws-token");
}

#[test]
fn ws_message_to_sse_event_crossover() {
    // A WebSocket text message carrying SSE-style JSON can be parsed as SseEvent
    let json_str = r#"{"kind":"heartbeat","seq":42}"#;
    let ws_msg = WsMessage::text(json_str);
    assert!(ws_msg.is_text());

    // Same JSON can be deserialized from either WsMessage or SseEvent
    let from_ws: serde_json::Value = ws_msg.json().unwrap();
    let sse_event = SseEvent::new(json_str);
    let from_sse: serde_json::Value = sse_event.json().unwrap();
    assert_eq!(from_ws, from_sse);
    assert_eq!(from_ws["kind"], "heartbeat");
    assert_eq!(from_ws["seq"], 42);
}

// ═══════════════════════════════════════════════════════════════════════════
// Cross-Module: Reconnect + Retry Patterns
// ═══════════════════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn with_retry_immediate_success() {
    let config = ReconnectConfig::new().with_max_attempts(3);
    let result = with_retry(config, || async { Ok::<_, StreamError>(99) }).await;
    assert_eq!(result.unwrap(), 99);
}

#[fcp_async_core::runtime::test]
async fn reconnect_handler_reset_after_success() {
    let config = ReconnectConfig::new()
        .with_max_attempts(3)
        .with_initial_delay(Duration::from_millis(1))
        .with_jitter(false);
    let mut handler = ReconnectHandler::new(config);

    // Simulate: fail twice, succeed, then fail again
    handler.record_failure();
    handler.record_failure();
    assert_eq!(handler.attempts(), 2);
    assert!(handler.can_reconnect());

    // Success resets
    handler.reset();
    assert_eq!(handler.attempts(), 0);

    // Can fail again from scratch
    handler.record_failure();
    assert_eq!(handler.attempts(), 1);
    assert!(handler.can_reconnect());
}
