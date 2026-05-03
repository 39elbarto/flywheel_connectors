//! Golden vector for the SSE Retry-After parsing + propagation
//! matrix (br-0c790d4c6).
//!
//! `e2e_sse_reconnect_storm.rs` (br-87544f4d5) drives a 4-phase
//! sequence and asserts specific retry_after values per phase.
//! That harness verifies *behavior* but doesn't pin the *byte
//! contract* — the rendered shape of the StreamError variant +
//! its retry_after field that operator tooling reads off
//! `err.retry_after()` and `err.is_terminal_backpressure()`.
//!
//! This golden walks an 8-cell server-response matrix through a
//! live `SseClient::connect()` and freezes the resulting
//! StreamError classification for each cell:
//!
//!   - 200 OK → connect succeeds (rendered as "<connected>")
//!   - 429 + numeric Retry-After: 7 → HttpError(429, retry=Some(7s))
//!   - 429 with no Retry-After → HttpError(429, retry=None)
//!   - 503 with Retry-After: 11 → HttpError(503, retry=None)
//!     (the fix preserves Retry-After ONLY for 429; 503 must not lie)
//!   - 503 + FCP backpressure budget-exhausted → HostBackpressure
//!     (terminal_backpressure=true)
//!   - 503 + FCP backpressure transient + retry-after-30 →
//!     HostBackpressure (terminal_backpressure=false, retry_after=Some(30s))
//!   - 404 → HttpError(404, retry=None)
//!
//! The golden is hand-rolled (no insta dev-dep on fcp-streaming) so
//! it lives as a single string compared via `assert_eq!`. Update
//! flow: edit the EXPECTED constant in this file directly, run the
//! test, commit the diff. Reviewer eyeballs the change.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use fcp_streaming::{SseClient, SseConfig, StreamError};

#[derive(Debug, Clone)]
enum ServerStep {
    Status200OkSse,
    Status429NumericRetryAfter(u64),
    Status429NoRetryAfter,
    Status503WithRetryAfter(u64),
    Status503BackpressureBudgetExhausted,
    Status503BackpressureTransient { retry_after: u64 },
    Status404,
}

const FCP_BACKPRESSURE_REASON_HEADER: &str = "X-FCP-Backpressure-Reason";
const FCP_BACKPRESSURE_RETRY_AFTER_HEADER: &str = "X-FCP-Backpressure-Retry-After";
const FCP_BACKPRESSURE_BUDGET_EXHAUSTED: &str = "budget-exhausted";

fn read_request_head(stream: &mut TcpStream) {
    let mut buf = [0_u8; 1024];
    let mut accumulated = Vec::new();
    while !accumulated.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut buf).expect("read request head");
        if n == 0 {
            break;
        }
        accumulated.extend_from_slice(&buf[..n]);
    }
}

fn write_response(stream: &mut TcpStream, response: &str) {
    stream
        .write_all(response.as_bytes())
        .expect("write response");
    stream.flush().expect("flush response");
}

fn write_step(stream: &mut TcpStream, step: &ServerStep) {
    match step {
        ServerStep::Status200OkSse => {
            write_response(
                stream,
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/event-stream\r\n\
                 Cache-Control: no-cache\r\n\
                 Connection: close\r\n\
                 Content-Length: 0\r\n\
                 \r\n",
            );
        }
        ServerStep::Status429NumericRetryAfter(seconds) => {
            let response = format!(
                "HTTP/1.1 429 Too Many Requests\r\n\
                 Content-Type: text/plain\r\n\
                 Retry-After: {seconds}\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\
                 \r\n",
            );
            write_response(stream, &response);
        }
        ServerStep::Status429NoRetryAfter => {
            write_response(
                stream,
                "HTTP/1.1 429 Too Many Requests\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\
                 \r\n",
            );
        }
        ServerStep::Status503WithRetryAfter(seconds) => {
            let response = format!(
                "HTTP/1.1 503 Service Unavailable\r\n\
                 Content-Type: text/plain\r\n\
                 Retry-After: {seconds}\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\
                 \r\n",
            );
            write_response(stream, &response);
        }
        ServerStep::Status503BackpressureBudgetExhausted => {
            let response = format!(
                "HTTP/1.1 503 Service Unavailable\r\n\
                 Content-Type: text/plain\r\n\
                 {FCP_BACKPRESSURE_REASON_HEADER}: {FCP_BACKPRESSURE_BUDGET_EXHAUSTED}\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\
                 \r\n",
            );
            write_response(stream, &response);
        }
        ServerStep::Status503BackpressureTransient { retry_after } => {
            let response = format!(
                "HTTP/1.1 503 Service Unavailable\r\n\
                 Content-Type: text/plain\r\n\
                 {FCP_BACKPRESSURE_REASON_HEADER}: transient-saturation\r\n\
                 {FCP_BACKPRESSURE_RETRY_AFTER_HEADER}: {retry_after}\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\
                 \r\n",
            );
            write_response(stream, &response);
        }
        ServerStep::Status404 => {
            write_response(
                stream,
                "HTTP/1.1 404 Not Found\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\
                 \r\n",
            );
        }
    }
}

fn spawn_matrix_server(
    script: Vec<ServerStep>,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind matrix listener");
    let address = listener.local_addr().expect("addr");
    let scripted = Arc::new(Mutex::new(script.into_iter()));
    let handle = thread::spawn(move || loop {
        let next = scripted.lock().expect("script lock").next();
        let Some(step) = next else { break };
        let (mut stream, _) = match listener.accept() {
            Ok(p) => p,
            Err(_) => return,
        };
        read_request_head(&mut stream);
        write_step(&mut stream, &step);
    });
    (format!("http://{address}/events"), handle)
}

/// Render a (cell-label, outcome) row for the golden.
fn render_outcome(label: &str, result: Result<bool, StreamError>) -> String {
    match result {
        Ok(true) => format!("{label:<48} | <connected>"),
        Ok(false) => format!("{label:<48} | <connected, no event observed>"),
        Err(StreamError::HttpError {
            status,
            retry_after,
            ..
        }) => {
            let r = match retry_after {
                Some(d) => format!("Some({}s)", d.as_secs()),
                None => "None".to_string(),
            };
            format!("{label:<48} | HttpError(status={status}, retry_after={r})")
        }
        Err(StreamError::HostBackpressure { status, signal, .. }) => {
            let r = match signal.retry_after() {
                Some(d) => format!("Some({}s)", d.as_secs()),
                None => "None".to_string(),
            };
            let budget = signal.is_budget_exhausted();
            format!(
                "{label:<48} | HostBackpressure(status={status}, retry_after={r}, budget_exhausted={budget})"
            )
        }
        Err(other) => format!("{label:<48} | OtherError({other:?})"),
    }
}

/// Run one cell against a freshly-started single-shot server (so the
/// HTTP/1.1 connection lifecycle is identical to the production
/// path) and return the rendered outcome.
async fn run_cell(label: &str, step: ServerStep) -> String {
    let (url, server) = spawn_matrix_server(vec![step]);
    let client = SseClient::with_config(
        url,
        SseConfig::new()
            .with_auto_reconnect(false)
            .with_timeout(Duration::from_secs(5)),
    );
    let outcome = match client.connect().await {
        Ok(_stream) => Ok(true),
        Err(e) => Err(e),
    };
    server.join().expect("server thread join");
    render_outcome(label, outcome)
}

const EXPECTED_GOLDEN: &str = "\
# Golden vector — SSE Retry-After matrix
# br-0c790d4c6 (preserve Retry-After on 429) +
# br-87544f4d5 (CrimsonWolf reconnect-storm e2e)
# Format:
#   <cell-label>  | <rendered-outcome>
# Notes:
#   - 200 OK → <connected>
#   - 429 + numeric Retry-After → HttpError(retry_after=Some)
#   - 429 without Retry-After → HttpError(retry_after=None)
#   - 503 with Retry-After header → HttpError(retry_after=None)
#     (fix preserves Retry-After ONLY for 429)
#   - 503 + budget-exhausted → HostBackpressure(budget_exhausted=true)
#   - 503 + transient-backpressure + retry-after → HostBackpressure(retry_after=Some, budget_exhausted=false)
#   - 404 → HttpError(retry_after=None)
# HTTP-date Retry-After parsing covered by e2e_sse_reconnect_storm.rs
# (wall-clock dependent — not appropriate for a frozen golden).

200_ok                                           | <connected>
429_numeric_retry_after_7s                       | HttpError(status=429, retry_after=Some(7s))
429_no_retry_after_header                        | HttpError(status=429, retry_after=None)
503_with_retry_after_11s_NOT_PROPAGATED          | HttpError(status=503, retry_after=None)
503_backpressure_budget_exhausted                | HostBackpressure(status=503, retry_after=None, budget_exhausted=true)
503_backpressure_transient_retry_after_30s       | HostBackpressure(status=503, retry_after=Some(30s), budget_exhausted=false)
404_not_found                                    | HttpError(status=404, retry_after=None)
";

#[fcp_async_core::runtime::test]
async fn golden_sse_retry_after_matrix_canonical_cells() {
    // Run each cell in sequence so each gets its own fresh server.
    // We collect the rendered rows into a single golden string.
    let cells: Vec<(&'static str, ServerStep)> = vec![
        ("200_ok", ServerStep::Status200OkSse),
        (
            "429_numeric_retry_after_7s",
            ServerStep::Status429NumericRetryAfter(7),
        ),
        ("429_no_retry_after_header", ServerStep::Status429NoRetryAfter),
        (
            "503_with_retry_after_11s_NOT_PROPAGATED",
            ServerStep::Status503WithRetryAfter(11),
        ),
        (
            "503_backpressure_budget_exhausted",
            ServerStep::Status503BackpressureBudgetExhausted,
        ),
        (
            "503_backpressure_transient_retry_after_30s",
            ServerStep::Status503BackpressureTransient { retry_after: 30 },
        ),
        ("404_not_found", ServerStep::Status404),
    ];

    let mut rows = Vec::new();
    for (label, step) in cells {
        rows.push(run_cell(label, step).await);
    }

    // Assemble the golden body. We compare the body — not the
    // header preamble — because the header_only-bytes that operator
    // tooling reads are the rows themselves; the preamble is for
    // the human reader. To keep the diff readable we still include
    // the preamble in EXPECTED_GOLDEN and assert against the full
    // string.
    let preamble = "\
# Golden vector — SSE Retry-After matrix
# br-0c790d4c6 (preserve Retry-After on 429) +
# br-87544f4d5 (CrimsonWolf reconnect-storm e2e)
# Format:
#   <cell-label>  | <rendered-outcome>
# Notes:
#   - 200 OK → <connected>
#   - 429 + numeric Retry-After → HttpError(retry_after=Some)
#   - 429 without Retry-After → HttpError(retry_after=None)
#   - 503 with Retry-After header → HttpError(retry_after=None)
#     (fix preserves Retry-After ONLY for 429)
#   - 503 + budget-exhausted → HostBackpressure(budget_exhausted=true)
#   - 503 + transient-backpressure + retry-after → HostBackpressure(retry_after=Some, budget_exhausted=false)
#   - 404 → HttpError(retry_after=None)
# HTTP-date Retry-After parsing covered by e2e_sse_reconnect_storm.rs
# (wall-clock dependent — not appropriate for a frozen golden).

";
    let mut actual = String::new();
    actual.push_str(preamble);
    for row in &rows {
        actual.push_str(row);
        actual.push('\n');
    }

    if actual.trim() != EXPECTED_GOLDEN.trim() {
        // Render a side-by-side diff for easy debugging.
        eprintln!("---- expected ----\n{EXPECTED_GOLDEN}");
        eprintln!("---- actual ----\n{actual}");
        panic!(
            "SSE retry-after matrix golden mismatch — update EXPECTED_GOLDEN \
             in this file if the change is intentional"
        );
    }
}
