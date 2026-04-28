//! `flywheel_connectors-w7ipj` — pin fcp-streaming receive-buffer
//! overflow policy.
//!
//! ## Documented policy: ERROR RETURNED at the stream level
//!
//! When the SseStream's parser-retained byte count plus the next
//! inbound chunk would exceed the configured `max_buffer_size`
//! (clamped at `MAX_SSE_BUFFER_SIZE = 64 MiB`), `poll_next` yields
//! `Err(StreamError::BufferOverflow { size, limit })` and the
//! stream STOPS producing events.
//!
//! This is the documented behaviour in
//! `fcp_streaming::sse::retained_buffer_overflow` and the SseStream
//! poll implementation. The connector observes a structured error
//! and is expected to disconnect / reset the upstream.
//!
//! Other candidate policies considered + REJECTED by the code:
//! - **Oldest dropped**: would silently lose earliest data.
//! - **Newest blocked**: would back-pressure the upstream
//!   indefinitely (no provision for it in the poll model).
//! - **Silent overflow**: would let a malicious server exhaust
//!   client memory.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **Stream-level overflow surfaces `StreamError::BufferOverflow`**
//!    via integration test against a wiremock server (matches the
//!    existing test in `no_mock_integration.rs` but pinned here as
//!    the policy ANCHOR).
//! 2. **`StreamError::BufferOverflow { size, limit }`** — wire shape
//!    of the error, payload accessible.
//! 3. **`Display` for BufferOverflow includes 'Buffer overflow' +
//!    size + limit** — operator log greps depend on the literal.
//! 4. **`MAX_SSE_BUFFER_SIZE = 64 MiB` ceiling** — `with_max_buffer_size`
//!    clamps requests above 64 MiB to 64 MiB (DoS protection).
//! 5. **`SseConfig::default().max_buffer_size = 1 MiB`** — the
//!    documented small-but-safe default.
//! 6. **`std::error::Error::source()` returns None for
//!    BufferOverflow** — it's a leaf error, no inner cause.

use fcp_streaming::{SseClient, SseConfig, StreamError};
use futures_util::stream::StreamExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const MAX_SSE_BUFFER_SIZE: usize = 64 * 1024 * 1024;

// ─── Documented wire shape: BufferOverflow { size, limit } ────────

#[test]
fn buffer_overflow_error_carries_size_and_limit_fields() {
    let err = StreamError::BufferOverflow {
        size: 4_096,
        limit: 1_024,
    };
    match err {
        StreamError::BufferOverflow { size, limit } => {
            assert_eq!(size, 4_096);
            assert_eq!(limit, 1_024);
        }
        other => panic!("expected BufferOverflow, got {other:?}"),
    }
}

#[test]
fn buffer_overflow_display_includes_keyword_and_byte_counts() {
    // Operator log greps depend on this literal.
    let err = StreamError::BufferOverflow {
        size: 2_048,
        limit: 1_024,
    };
    let s = format!("{err}");
    assert!(s.contains("Buffer overflow"), "got {s}");
    assert!(s.contains("2048"), "got {s}");
    assert!(s.contains("1024"), "got {s}");
}

#[test]
fn buffer_overflow_is_leaf_error_no_source() {
    let err = StreamError::BufferOverflow {
        size: 100,
        limit: 50,
    };
    let src = std::error::Error::source(&err);
    assert!(
        src.is_none(),
        "BufferOverflow MUST be a leaf error — no inner source to chain into"
    );
}

// ─── MAX_SSE_BUFFER_SIZE ceiling clamp ────────────────────────────

#[test]
fn with_max_buffer_size_clamps_above_sixty_four_mib() {
    let c = SseConfig::new().with_max_buffer_size(usize::MAX);
    assert_eq!(
        c.max_buffer_size, MAX_SSE_BUFFER_SIZE,
        "max_buffer_size MUST clamp at 64 MiB ceiling regardless of caller request"
    );
}

#[test]
fn with_max_buffer_size_below_ceiling_is_preserved() {
    let c = SseConfig::new().with_max_buffer_size(8 * 1024);
    assert_eq!(
        c.max_buffer_size,
        8 * 1024,
        "below-ceiling values MUST be preserved verbatim"
    );
}

#[test]
fn sse_config_default_max_buffer_size_is_one_mib() {
    let c = SseConfig::default();
    assert_eq!(
        c.max_buffer_size,
        1024 * 1024,
        "default SSE max_buffer_size MUST be 1 MiB"
    );
}

// ─── Stream-level integration: error-returned policy via wiremock ─

#[fcp_async_core::runtime::test]
async fn stream_with_tiny_buffer_emits_buffer_overflow_error_when_chunk_exceeds_limit() {
    // POLICY ANCHOR: when a server sends data larger than
    // max_buffer_size in a single chunk, the stream MUST yield
    // Err(BufferOverflow), NOT silently drop oldest, NOT block
    // upstream, NOT panic.

    let mock_server = MockServer::start().await;

    // Construct a >100-byte SSE event so the first chunk exceeds
    // the 100-byte buffer cap.
    let oversized_data: String = "x".repeat(500);
    let body = format!("data: {oversized_data}\n\n");

    Mock::given(method("GET"))
        .and(path("/events"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(&mock_server)
        .await;

    let config = SseConfig::new().with_max_buffer_size(100);
    let client = SseClient::with_config(format!("{}/events", mock_server.uri()), config);
    let mut stream = client.connect().await.expect("connect");

    let first = stream
        .next()
        .await
        .expect("stream MUST yield at least one item");
    let err = first.expect_err(
        "documented policy is ERROR RETURNED — first poll on an oversized chunk MUST yield Err",
    );
    assert!(
        matches!(err, StreamError::BufferOverflow { .. }),
        "stream MUST yield StreamError::BufferOverflow when buffer is exceeded; got {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn stream_within_buffer_capacity_yields_event_normally() {
    // Counter-test: a payload comfortably within max_buffer_size
    // does NOT trigger the overflow error — the policy fires ONLY
    // when the limit is breached.
    let mock_server = MockServer::start().await;
    let body = "data: hello\n\n";

    Mock::given(method("GET"))
        .and(path("/events"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(&mock_server)
        .await;

    let config = SseConfig::new().with_max_buffer_size(64 * 1024);
    let client = SseClient::with_config(format!("{}/events", mock_server.uri()), config);
    let mut stream = client.connect().await.expect("connect");

    let first = stream.next().await.expect("at least one event");
    let event = first.expect("normal payload MUST yield Ok event, not BufferOverflow");
    assert_eq!(event.data, "hello");
}

#[fcp_async_core::runtime::test]
async fn stream_does_not_silently_drop_oldest_data_on_overflow() {
    // Negative pin: rule out the OLDEST-DROPPED candidate policy.
    // If the policy were oldest-dropped, the overall payload would
    // come through (truncated). The error-returned policy means we
    // observe Err(BufferOverflow) instead of any partial event.

    let mock_server = MockServer::start().await;
    let body = format!(
        "data: {}\n\ndata: short\n\n",
        "X".repeat(1_000) // First event blows past 100-byte cap.
    );

    Mock::given(method("GET"))
        .and(path("/events"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(&mock_server)
        .await;

    let config = SseConfig::new().with_max_buffer_size(100);
    let client = SseClient::with_config(format!("{}/events", mock_server.uri()), config);
    let mut stream = client.connect().await.expect("connect");

    let first = stream.next().await.expect("first item");
    let err = first.expect_err(
        "OLDEST-DROPPED policy would deliver the second event; ERROR-RETURNED policy yields Err",
    );
    assert!(
        matches!(err, StreamError::BufferOverflow { .. }),
        "non-overflow error variant {err:?} would be a different bug; the policy is BufferOverflow"
    );
}
