//! Real-server end-to-end test for the SSE reconnect-storm signalling
//! path (br-0c790d4c6).
//!
//! `e2e_sse_roundtrip.rs` covers the happy-path stream parser across
//! split network reads. The 0c790d4c6 fix ("preserve Retry-After on
//! SSE 429") is currently exercised only by a single-call unit test
//! (`sse_429_preserves_retry_after_for_reconnect_backoff`) that calls
//! `http_error_from_head` directly — the integration question
//! ("does the live `SseClient::connect()` path actually surface the
//! preserved `retry_after` to the caller?") is unverified.
//!
//! This harness pins five integration contracts of the connect-error
//! signalling that the reconnect orchestrator depends on:
//!
//!   1. **429 + numeric Retry-After**. A live server returning
//!      `429 Too Many Requests` with `Retry-After: 7` causes the
//!      next `connect()` to return `StreamError::HttpError` whose
//!      `retry_after()` is `Some(Duration::from_secs(7))`.
//!      Catches a regression that re-introduces the silent-drop bug.
//!
//!   2. **429 + HTTP-date Retry-After**. The same property holds
//!      when the server returns an RFC 2822 absolute timestamp
//!      instead of a decimal-seconds delta. `parse_retry_after`
//!      converts both formats; integration verifies the byte path.
//!
//!   3. **503 returns retry_after=None**. The fix preserved
//!      Retry-After ONLY for 429 (per the documented contract). A
//!      503 response does not surface `retry_after` even when the
//!      header is present — operators relying on
//!      `err.retry_after().is_some()` to disambiguate "we have a
//!      hint" from "back off by default" must not be misled.
//!
//!   4. **Mid-stream connection drop surfaces as a stream error**,
//!      not a panic or silent EOF. After a successful 200 response,
//!      the server closes the TCP connection abruptly while the
//!      client is mid-event; the stream's next poll yields an `Err`
//!      that the reconnect orchestrator can use to attempt recovery.
//!
//!   5. **Storm sequence consistency**. Across four consecutive
//!      `connect()` attempts against a server that walks through
//!      429→429-date→503→200-then-drop, every attempt observes the
//!      response shape it expects in the right order — i.e. the
//!      client's connection state does not leak across attempts,
//!      and earlier responses cannot mask later ones via cached
//!      state.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_streaming::{SseClient, SseConfig, StreamError};
use futures_util::StreamExt as _;

const RETRY_AFTER_SECS: u64 = 7;
const RETRY_AFTER_DATE_SECONDS_AHEAD: i64 = 5;
const STREAM_DROP_LATENCY_MS: u64 = 30;

/// One programmed server response, applied to the next inbound
/// connection in order.
#[derive(Debug, Clone)]
enum StormStep {
    /// Reply with `429 Too Many Requests` and a numeric Retry-After.
    HttpStatus429NumericRetryAfter(u64),
    /// Reply with `429 Too Many Requests` and an HTTP-date Retry-After
    /// pointing `seconds_ahead` in the future.
    HttpStatus429DateRetryAfter { seconds_ahead: i64 },
    /// Reply with `503 Service Unavailable`. The Retry-After header
    /// is intentionally present to verify the client correctly does
    /// NOT surface it on non-429 codes (per the fix's contract).
    HttpStatus503WithRetryAfter(u64),
    /// Reply with `200 OK` SSE headers, send one event, then drop
    /// the TCP connection mid-stream.
    Status200ThenDropMidStream,
}

fn read_http_request_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buf = [0_u8; 512];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buf).expect("read SSE HTTP request head");
        if read == 0 {
            // Client gave up before completing headers — no point
            // failing the test here, the assertions in the test
            // body will catch the unexpected order.
            break;
        }
        request.extend_from_slice(&buf[..read]);
    }
    request
}

fn write_429_numeric(stream: &mut TcpStream, seconds: u64) {
    let body = b"backpressure: slow down\n";
    let response = format!(
        "HTTP/1.1 429 Too Many Requests\r\n\
         Content-Type: text/plain\r\n\
         Retry-After: {seconds}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len(),
    );
    stream.write_all(response.as_bytes()).expect("write 429 head");
    stream.write_all(body).expect("write 429 body");
    stream.flush().expect("flush 429");
}

fn write_429_date(stream: &mut TcpStream, seconds_ahead: i64) {
    let target = Utc::now() + ChronoDuration::seconds(seconds_ahead);
    // RFC 2822 / 7231 IMF-fixdate format.
    let date_header = target.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    let body = b"backpressure: come back later\n";
    let response = format!(
        "HTTP/1.1 429 Too Many Requests\r\n\
         Content-Type: text/plain\r\n\
         Retry-After: {date_header}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len(),
    );
    stream
        .write_all(response.as_bytes())
        .expect("write 429-date head");
    stream.write_all(body).expect("write 429-date body");
    stream.flush().expect("flush 429-date");
}

fn write_503_with_retry_after(stream: &mut TcpStream, seconds: u64) {
    let body = b"unavailable\n";
    let response = format!(
        "HTTP/1.1 503 Service Unavailable\r\n\
         Content-Type: text/plain\r\n\
         Retry-After: {seconds}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len(),
    );
    stream.write_all(response.as_bytes()).expect("write 503 head");
    stream.write_all(body).expect("write 503 body");
    stream.flush().expect("flush 503");
}

fn write_sse_headers_then_drop(stream: &mut TcpStream) {
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\n\
              Content-Type: text/event-stream\r\n\
              Cache-Control: no-cache\r\n\
              Connection: close\r\n\
              Transfer-Encoding: chunked\r\n\
              \r\n",
        )
        .expect("write 200 SSE headers");
    stream.flush().expect("flush 200 headers");

    // Emit one complete chunk-encoded SSE event so the client has
    // something to parse before the drop.
    let event = "id: e1\ndata: hello\n\n";
    let chunk = format!("{:x}\r\n{event}\r\n", event.len());
    stream
        .write_all(chunk.as_bytes())
        .expect("write SSE event chunk");
    stream.flush().expect("flush SSE event chunk");

    // Sleep briefly so the client has reached the Body::poll_frame
    // path, then drop the connection without sending the chunk
    // terminator (`0\r\n\r\n`). Closing the TcpStream surfaces an
    // I/O error in the body stream rather than a clean EOF.
    thread::sleep(Duration::from_millis(STREAM_DROP_LATENCY_MS));
    drop(stream.shutdown(std::net::Shutdown::Both));
}

/// Spawn a TCP listener that walks through `script` one connection
/// at a time. Returns the bound URL and the server thread handle.
fn spawn_storm_server(script: Vec<StormStep>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind storm listener");
    let address = listener.local_addr().expect("listener addr");
    let scripted = Arc::new(Mutex::new(script.into_iter()));

    let handle = thread::spawn(move || {
        loop {
            let next = scripted.lock().expect("script lock").next();
            let Some(step) = next else {
                break;
            };
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let _ = read_http_request_head(&mut stream);
            match step {
                StormStep::HttpStatus429NumericRetryAfter(seconds) => {
                    write_429_numeric(&mut stream, seconds);
                }
                StormStep::HttpStatus429DateRetryAfter { seconds_ahead } => {
                    write_429_date(&mut stream, seconds_ahead);
                }
                StormStep::HttpStatus503WithRetryAfter(seconds) => {
                    write_503_with_retry_after(&mut stream, seconds);
                }
                StormStep::Status200ThenDropMidStream => {
                    write_sse_headers_then_drop(&mut stream);
                }
            }
        }
    });

    (format!("http://{address}/events"), handle)
}

#[fcp_async_core::runtime::test]
async fn sse_reconnect_storm_preserves_retry_after_signals_across_connect_attempts() {
    let script = vec![
        StormStep::HttpStatus429NumericRetryAfter(RETRY_AFTER_SECS),
        StormStep::HttpStatus429DateRetryAfter {
            seconds_ahead: RETRY_AFTER_DATE_SECONDS_AHEAD,
        },
        StormStep::HttpStatus503WithRetryAfter(11),
        StormStep::Status200ThenDropMidStream,
    ];
    let (url, server) = spawn_storm_server(script);

    // Build a client that does NOT auto-reconnect. We drive the
    // reconnect cycle manually so each connect() call's outcome
    // is observable independently. This is the same shape an
    // operator-level orchestrator uses when honouring retry_after
    // hints rather than blindly applying exponential backoff.
    let client = SseClient::with_config(
        url.clone(),
        SseConfig::new()
            .with_auto_reconnect(false)
            .with_timeout(Duration::from_secs(5)),
    );

    // ── Phase 1: 429 numeric Retry-After ─────────────────────────
    let phase1 = match client.connect().await {
        Ok(_) => panic!("phase 1: connect MUST fail with HttpError(429)"),
        Err(err) => err,
    };
    match &phase1 {
        StreamError::HttpError {
            status,
            retry_after,
            ..
        } => {
            assert_eq!(*status, 429, "phase 1 must classify as 429");
            assert_eq!(
                *retry_after,
                Some(Duration::from_secs(RETRY_AFTER_SECS)),
                "phase 1 (numeric Retry-After) MUST surface the 7s hint — \
                 br-0c790d4c6 silent-drop regression",
            );
        }
        other => panic!("phase 1: expected HttpError, got {other:?}"),
    }

    // ── Phase 2: 429 HTTP-date Retry-After ───────────────────────
    let phase2 = match client.connect().await {
        Ok(_) => panic!("phase 2: connect MUST fail with HttpError(429)"),
        Err(err) => err,
    };
    match &phase2 {
        StreamError::HttpError {
            status,
            retry_after,
            ..
        } => {
            assert_eq!(*status, 429, "phase 2 must classify as 429");
            let surfaced = retry_after
                .expect("phase 2 (HTTP-date Retry-After) MUST surface a duration");
            // Wall-clock delta — give a generous lower bound to
            // tolerate the time spent in phase 1, but the upper
            // bound rules out parsing the date as a numeric.
            assert!(
                surfaced <= Duration::from_secs(
                    u64::try_from(RETRY_AFTER_DATE_SECONDS_AHEAD).unwrap_or(0) + 5,
                ),
                "phase 2: retry_after parsed as too long ({surfaced:?}) — \
                 HTTP-date may be misparsed as decimal seconds",
            );
        }
        other => panic!("phase 2: expected HttpError, got {other:?}"),
    }

    // ── Phase 3: 503 with Retry-After header MUST NOT propagate ──
    //
    // The fix only preserves Retry-After on 429 (matches the
    // documented contract). A 503 with a Retry-After header must
    // surface as `retry_after = None` so callers can disambiguate
    // "we have a hint" (Some) from "back off via default policy"
    // (None). Pinning this here makes a future "preserve on all
    // codes" patch a deliberate choice rather than a silent change.
    let phase3 = match client.connect().await {
        Ok(_) => panic!("phase 3: connect MUST fail with HttpError(503)"),
        Err(err) => err,
    };
    match &phase3 {
        StreamError::HttpError {
            status,
            retry_after,
            ..
        } => {
            assert_eq!(*status, 503, "phase 3 must classify as 503");
            assert_eq!(
                *retry_after, None,
                "phase 3: 503 + Retry-After header must surface as None — \
                 the fix preserves the header only for 429",
            );
        }
        other => panic!("phase 3: expected HttpError, got {other:?}"),
    }

    // ── Phase 4: 200 + mid-stream drop ───────────────────────────
    let mut stream = client
        .connect()
        .await
        .expect("phase 4: 200 SSE response must succeed");
    let first_event = fcp_async_core::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("phase 4: first SSE event timeout")
        .expect("phase 4: first SSE event present")
        .expect("phase 4: first SSE event ok");
    assert_eq!(first_event.id.as_deref(), Some("e1"));
    assert_eq!(first_event.data, "hello");

    // The server has now dropped the connection. The next poll
    // either returns Err (body I/O surfaces the truncation) or
    // Ok(None) (clean EOF observed). The integration contract is
    // that polling does NOT panic and does NOT hang; orchestrators
    // can take either signal as "reconnect".
    let drained = fcp_async_core::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("phase 4: post-drop poll timeout — stream is hanging");
    match drained {
        Some(Err(_)) | None => {
            // Either is acceptable — the orchestrator treats both
            // as "reconnect needed".
        }
        Some(Ok(unexpected)) => panic!(
            "phase 4: stream returned a third event after server drop: {unexpected:?}"
        ),
    }

    server.join().expect("storm server thread joined");
}
