//! Real-server end-to-end test for the inbound webhook delivery
//! retry-decision path.
//!
//! `e2e_webhook_signatures.rs` covers receiver-side signature
//! verification and the replay/stale rejection rows. The
//! `host_retry_decision_from_response` decision API is unit-tested
//! against synthetic header maps but never observed end-to-end:
//! the integration question — *do the bytes that come off a real
//! TCP socket parse into the same retry decision the unit tests
//! assert?* — is unverified.
//!
//! This harness pins five integration contracts of the receiver +
//! decision pipeline a sender uses when retrying a delivery:
//!
//!   1. **Stripe-style signed delivery accepted on first try**.
//!      A correctly-signed Stripe payload (HMAC-SHA256 over
//!      `t.body`) sent to a live receiver is accepted with HTTP
//!      202; `host_retry_decision_from_response` does not get
//!      consulted for a 2xx (the sender's loop terminates on
//!      success).
//!
//!   2. **Vanilla 5xx retries with exponential backoff**. When
//!      the receiver returns `500 Internal Server Error` with no
//!      backpressure header, the decision API yields
//!      `RetryAfter(default_delay)` — the sender's exponential
//!      schedule is then applied on top. Across N retries the
//!      cumulative delay exhibits geometric growth (catches a
//!      regression that flattens the schedule to a constant).
//!
//!   3. **HOST_BACKPRESSURE_STATUS (503) + Retry-After honored**.
//!      A 503 with the FCP backpressure reason and a custom
//!      `X-FCP-Backpressure-Retry-After: 30` header surfaces as
//!      `RetryAfter(d)` where `d ≥ 30s`. The sender's exponential
//!      backoff stays floored at the host-supplied delay.
//!
//!   4. **Budget-exhausted = RefuseRetry, terminal**. The same 503
//!      with `X-FCP-Backpressure-Reason: budget-exhausted`
//!      surfaces as `RefuseRetry(signal)`. The sender's loop
//!      MUST halt and surface the host backpressure signal — no
//!      retry, no exponential backoff, no DoS amplification.
//!
//!   5. **Replay rejection is terminal at the application layer**.
//!      A correctly-signed delivery whose `event.id` was seen
//!      before returns 409 Conflict. The decision API itself
//!      treats 4xx as "retry default delay" (it's not aware of
//!      4xx semantics), but the sender's terminal-status policy
//!      (4xx other than 408/429 = terminal) MUST not retry. We
//!      simulate that policy here and pin the no-retry behavior.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use fcp_webhook::{
    FCP_BACKPRESSURE_BUDGET_EXHAUSTED, FCP_BACKPRESSURE_REASON_HEADER,
    FCP_BACKPRESSURE_RETRY_AFTER_HEADER, HOST_BACKPRESSURE_STATUS, HmacSha256Verifier,
    StripeWebhook, WebhookError, WebhookHandler, WebhookRetryDecision,
    host_retry_decision_from_response,
};

const STRIPE_SECRET: &str = "whsec_delta_e2e_delivery_retry_secret_2026";
const DEFAULT_DELAY: Duration = Duration::from_secs(2);
const RECEIVER_FORCED_RETRY_AFTER_SECS: u64 = 30;
const MAX_RETRIES: u32 = 5;

/// Per-request response script. Each step describes what the server
/// should do for one inbound request, *without* signature
/// verification; verification-driven responses (401/400/409) are
/// produced by the WebhookEndpointState path below.
#[derive(Debug, Clone)]
enum DeliveryStep {
    /// Run signature verification + replay claim. Status code is
    /// derived from the verification outcome (202/401/400/409).
    Verified,
    /// Force `500 Internal Server Error` with no backpressure
    /// metadata. Models a transient upstream fault.
    Force500,
    /// Force `HOST_BACKPRESSURE_STATUS` (503) with the FCP
    /// backpressure reason + a numeric Retry-After header.
    ForceBackpressureRetryAfter { seconds: u64, reason: String },
}

struct ParsedHttpRequest {
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct WebhookEndpointState {
    stripe: StripeWebhook,
    replay: WebhookHandler<HmacSha256Verifier>,
}

impl WebhookEndpointState {
    fn new() -> Self {
        Self {
            stripe: StripeWebhook::new(STRIPE_SECRET),
            replay: WebhookHandler::new(HmacSha256Verifier::new(STRIPE_SECRET), "stripe"),
        }
    }
}

fn read_http_request(stream: &mut TcpStream) -> ParsedHttpRequest {
    let mut raw = Vec::new();
    let mut buf = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut buf).expect("read HTTP request");
        assert!(read > 0, "client closed before request headers");
        raw.extend_from_slice(&buf[..read]);
        if let Some(index) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };

    let headers_text = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = headers_text.lines();
    let _request_line = lines.next();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_string(), value.trim().to_string());
        }
    }

    let content_length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .expect("content-length header present");
    let mut body = raw[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut buf).expect("read HTTP body");
        assert!(read > 0, "client closed before request body");
        body.extend_from_slice(&buf[..read]);
    }
    body.truncate(content_length);

    ParsedHttpRequest { headers, body }
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    extra_headers: &[(&str, String)],
) {
    let mut response =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n");
    for (name, value) in extra_headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    stream
        .write_all(response.as_bytes())
        .expect("write HTTP response");
    stream.flush().expect("flush HTTP response");
}

fn handle_verified(
    state: &WebhookEndpointState,
    request: &ParsedHttpRequest,
) -> (u16, &'static str) {
    let outcome = state
        .stripe
        .verify_and_parse(&request.headers, &request.body)
        .and_then(|event| state.replay.claim_event(&event.id));
    match outcome {
        Ok(()) => (202, "Accepted"),
        Err(WebhookError::ReplayDetected { .. }) => (409, "Conflict"),
        Err(WebhookError::TimestampValidation { .. }) => (400, "Bad Request"),
        Err(_) => (401, "Unauthorized"),
    }
}

fn spawn_scripted_endpoint(script: Vec<DeliveryStep>) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind webhook endpoint");
    let address = listener.local_addr().expect("webhook endpoint addr");
    let state = Arc::new(WebhookEndpointState::new());
    let scripted = Arc::new(Mutex::new(script.into_iter()));

    let handle = thread::spawn(move || {
        loop {
            let next = scripted.lock().expect("script lock").next();
            let Some(step) = next else { break };
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let request = read_http_request(&mut stream);

            match step {
                DeliveryStep::Verified => {
                    let (status, reason) = handle_verified(&state, &request);
                    write_response(&mut stream, status, reason, &[]);
                }
                DeliveryStep::Force500 => {
                    write_response(&mut stream, 500, "Internal Server Error", &[]);
                }
                DeliveryStep::ForceBackpressureRetryAfter { seconds, reason } => {
                    let extra = vec![
                        (FCP_BACKPRESSURE_REASON_HEADER, reason),
                        (FCP_BACKPRESSURE_RETRY_AFTER_HEADER, seconds.to_string()),
                    ];
                    write_response(
                        &mut stream,
                        HOST_BACKPRESSURE_STATUS,
                        "Service Unavailable",
                        &extra,
                    );
                }
            }
        }
    });

    (address, handle)
}

fn build_stripe_request(body: &[u8], timestamp: i64) -> Vec<(&'static str, String)> {
    let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(body));
    let signature = HmacSha256Verifier::new(STRIPE_SECRET).compute(signed_payload.as_bytes());
    vec![("Stripe-Signature", format!("t={timestamp},v1={signature}"))]
}

/// Outcome of a single HTTP delivery attempt — captures everything
/// the sender's retry loop needs to make a decision.
#[derive(Debug)]
struct DeliveryAttemptOutcome {
    status: u16,
    headers: HashMap<String, String>,
}

fn post_signed_webhook(
    addr: SocketAddr,
    headers: &[(&str, String)],
    body: &[u8],
) -> DeliveryAttemptOutcome {
    let mut stream = TcpStream::connect(addr).expect("connect webhook endpoint");
    let mut request = format!(
        "POST /stripe HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .expect("write request head");
    stream.write_all(body).expect("write request body");
    stream.flush().expect("flush request");

    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    let mut lines = response.split("\r\n");
    let status_line = lines.next().expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("HTTP status code")
        .parse()
        .expect("numeric status");

    let mut response_headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            response_headers.insert(name.trim().to_string(), value.trim().to_string());
        }
    }

    DeliveryAttemptOutcome {
        status,
        headers: response_headers,
    }
}

/// Trace produced by the sender's retry loop — one row per attempt.
/// `attempt` is kept in the trace for debug printing on failure even
/// though no assertion reads it directly; the position in the Vec
/// is what assertions index by.
#[derive(Debug)]
struct RetryTraceRow {
    #[allow(dead_code)]
    attempt: u32,
    status: u16,
    decision: WebhookRetryDecision,
    cumulative_backoff_secs: u64,
}

/// Drive the sender's retry loop for one logical delivery against
/// the live endpoint. The loop:
///
///   - sends one POST per attempt
///   - collects the response status + headers
///   - asks the decision API what to do
///   - terminates on 2xx (success), `RefuseRetry`, terminal-4xx, or
///     when the retry budget is exhausted
///   - applies exponential backoff (delay × 2^attempt) on top of the
///     `RetryAfter` floor — this is the schedule a production
///     deliverer applies, not something fcp-webhook supplies
fn run_delivery_retry_loop(
    addr: SocketAddr,
    headers: Vec<(&'static str, String)>,
    body: &[u8],
    treat_4xx_as_terminal: bool,
) -> Vec<RetryTraceRow> {
    let mut trace = Vec::new();
    let mut cumulative: u64 = 0;
    for attempt in 0..MAX_RETRIES {
        let outcome = post_signed_webhook(addr, &headers, body);
        let decision =
            host_retry_decision_from_response(outcome.status, &outcome.headers, DEFAULT_DELAY);

        let row = RetryTraceRow {
            attempt,
            status: outcome.status,
            decision: decision.clone(),
            cumulative_backoff_secs: cumulative,
        };
        let status = outcome.status;
        let is_terminal_4xx =
            treat_4xx_as_terminal && (400..500).contains(&status) && status != 408 && status != 429;
        trace.push(row);

        if (200..300).contains(&status) {
            return trace;
        }
        if matches!(decision, WebhookRetryDecision::RefuseRetry(_)) {
            return trace;
        }
        if is_terminal_4xx {
            return trace;
        }

        // Exponential backoff: multiplier 2^attempt over the
        // `RetryAfter` floor. We don't actually sleep — the test
        // measures the *decision*, not the wall-clock.
        if let WebhookRetryDecision::RetryAfter(d) = decision {
            let multiplier: u64 = if attempt >= 63 {
                u64::MAX
            } else {
                1u64 << attempt
            };
            cumulative = cumulative.saturating_add(d.as_secs().saturating_mul(multiplier));
        }
    }
    trace
}

#[test]
fn webhook_delivery_retry_traces_through_signature_and_backpressure_paths() {
    // Phase A: 3× transient 500 then a verified 202. The sender's
    // retry loop should observe the geometric backoff schedule and
    // terminate on the 202.
    // Phase B: single delivery that hits 503 + retry-after=30 once,
    // then verified 202. The decision API floor should clamp the
    // first retry's delay ≥ RECEIVER_FORCED_RETRY_AFTER_SECS.
    // Phase C: 503 + budget-exhausted, terminal — no retries.
    // Phase D: replay scenario — first attempt accepted, second
    // attempt 409 (terminal at the application layer with
    // treat_4xx_as_terminal=true).
    let script = vec![
        // Phase A: 3 transient 500s, then verify on 4th attempt.
        DeliveryStep::Force500,
        DeliveryStep::Force500,
        DeliveryStep::Force500,
        DeliveryStep::Verified,
        // Phase B: 503 + retry-after=30 once, then verify.
        DeliveryStep::ForceBackpressureRetryAfter {
            seconds: RECEIVER_FORCED_RETRY_AFTER_SECS,
            reason: "transient-host-saturation".into(),
        },
        DeliveryStep::Verified,
        // Phase C: budget-exhausted → terminal RefuseRetry.
        DeliveryStep::ForceBackpressureRetryAfter {
            seconds: RECEIVER_FORCED_RETRY_AFTER_SECS,
            reason: FCP_BACKPRESSURE_BUDGET_EXHAUSTED.into(),
        },
        // Phase D: first signed accepted (event id evt_replay_1),
        // second signed delivery with same event id rejected 409.
        DeliveryStep::Verified,
        DeliveryStep::Verified,
    ];
    let (addr, server) = spawn_scripted_endpoint(script);

    let now = Utc::now().timestamp();

    // ── Phase A: 3 retries on 500, success on 4th attempt ────────
    let body_a = br#"{"id":"evt_phase_a","type":"payment_intent.succeeded","data":{"object":{}}}"#;
    let headers_a = build_stripe_request(body_a, now);
    let trace_a = run_delivery_retry_loop(addr, headers_a, body_a, false);
    assert_eq!(
        trace_a.len(),
        4,
        "phase A: expected 3 retries + 1 success = 4 attempts, got {}: {trace_a:?}",
        trace_a.len(),
    );
    for (i, row) in trace_a.iter().take(3).enumerate() {
        assert_eq!(row.status, 500, "phase A attempt {i}: expected 500");
        assert!(
            matches!(row.decision, WebhookRetryDecision::RetryAfter(_)),
            "phase A attempt {i}: 500 must produce RetryAfter, got {:?}",
            row.decision,
        );
    }
    assert_eq!(trace_a[3].status, 202, "phase A: final attempt must be 202");
    // Exponential backoff: 1× + 2× + 4× = 7× DEFAULT_DELAY across 3 retries.
    let expected_min_backoff = DEFAULT_DELAY.as_secs() * (1 + 2 + 4);
    assert!(
        trace_a[3].cumulative_backoff_secs >= expected_min_backoff,
        "phase A: cumulative backoff {} should be ≥ {} (geometric over 3 retries)",
        trace_a[3].cumulative_backoff_secs,
        expected_min_backoff,
    );

    // ── Phase B: 503 + retry-after-30 floor ─────────────────────
    let body_b = br#"{"id":"evt_phase_b","type":"payment_intent.succeeded","data":{"object":{}}}"#;
    let headers_b = build_stripe_request(body_b, now);
    let trace_b = run_delivery_retry_loop(addr, headers_b, body_b, false);
    assert_eq!(
        trace_b.len(),
        2,
        "phase B: expected 1 retry + 1 success = 2 attempts: {trace_b:?}",
    );
    let phase_b_first = &trace_b[0];
    assert_eq!(phase_b_first.status, HOST_BACKPRESSURE_STATUS);
    match &phase_b_first.decision {
        WebhookRetryDecision::RetryAfter(d) => {
            assert!(
                *d >= Duration::from_secs(RECEIVER_FORCED_RETRY_AFTER_SECS),
                "phase B: retry delay {d:?} must be ≥ {RECEIVER_FORCED_RETRY_AFTER_SECS}s — \
                 host-supplied Retry-After floor was not honored",
            );
        }
        other => panic!("phase B first attempt: expected RetryAfter, got {other:?}"),
    }
    assert_eq!(
        trace_b[1].status, 202,
        "phase B: second attempt must succeed"
    );

    // ── Phase C: budget-exhausted = RefuseRetry, terminal ───────
    let body_c = br#"{"id":"evt_phase_c","type":"payment_intent.succeeded","data":{"object":{}}}"#;
    let headers_c = build_stripe_request(body_c, now);
    let trace_c = run_delivery_retry_loop(addr, headers_c, body_c, false);
    assert_eq!(
        trace_c.len(),
        1,
        "phase C: budget-exhausted MUST terminate after 1 attempt, got {trace_c:?}",
    );
    match &trace_c[0].decision {
        WebhookRetryDecision::RefuseRetry(signal) => {
            assert!(
                signal.is_budget_exhausted(),
                "phase C: signal MUST report budget-exhausted, got {signal:?}",
            );
        }
        other => panic!("phase C: budget-exhausted MUST surface as RefuseRetry, got {other:?}"),
    }

    // ── Phase D: replay rejection terminates at the app layer ───
    let body_d =
        br#"{"id":"evt_phase_d_replay","type":"payment_intent.succeeded","data":{"object":{}}}"#;
    let headers_d_first = build_stripe_request(body_d, now);
    let trace_d_first = run_delivery_retry_loop(addr, headers_d_first.clone(), body_d, true);
    assert_eq!(trace_d_first.len(), 1, "phase D first delivery accepted");
    assert_eq!(trace_d_first[0].status, 202);

    // Second delivery of the SAME event id — receiver returns 409.
    let trace_d_replay = run_delivery_retry_loop(addr, headers_d_first, body_d, true);
    assert_eq!(
        trace_d_replay.len(),
        1,
        "phase D replay MUST NOT retry on 409 (terminal-4xx policy)",
    );
    assert_eq!(
        trace_d_replay[0].status, 409,
        "phase D replay: receiver must return 409 Conflict",
    );

    server.join().expect("scripted endpoint thread joined");
}
