use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use chrono::Utc;
use fcp_webhook::{
    GitHubWebhook, HmacSha256Verifier, SlackWebhook, StripeWebhook, WebhookError, WebhookHandler,
};
use tracing::Level;

type TraceSteps = Arc<Mutex<Vec<&'static str>>>;

fn record_step(steps: &TraceSteps, step: &'static str) {
    let mut guard = steps.lock().expect("trace steps lock");
    let order = guard.len();
    let span = tracing::span!(
        Level::INFO,
        "delta_e2e_step",
        crate_name = "fcp-webhook",
        step,
        order
    );
    let _entered = span.enter();
    guard.push(step);
}

fn assert_step_order(steps: &TraceSteps, expected: &[&'static str]) {
    let observed = {
        let guard = steps.lock().expect("trace steps lock");
        guard.clone()
    };
    let mut cursor = 0;
    for expected_step in expected {
        let relative = observed[cursor..]
            .iter()
            .position(|step| step == expected_step);
        assert!(
            relative.is_some(),
            "missing trace step {expected_step}; observed {observed:?}"
        );
        let relative = relative.unwrap_or(0);
        cursor += relative + 1;
    }
}

struct ParsedHttpRequest {
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct WebhookEndpointState {
    github: GitHubWebhook,
    github_replay: WebhookHandler<HmacSha256Verifier>,
    stripe: StripeWebhook,
    stripe_replay: WebhookHandler<HmacSha256Verifier>,
    slack: SlackWebhook,
    slack_replay: WebhookHandler<HmacSha256Verifier>,
}

impl WebhookEndpointState {
    fn new() -> Self {
        Self {
            github: GitHubWebhook::new(GITHUB_SECRET),
            github_replay: WebhookHandler::new(HmacSha256Verifier::new(GITHUB_SECRET), "github"),
            stripe: StripeWebhook::new(STRIPE_SECRET),
            stripe_replay: WebhookHandler::new(HmacSha256Verifier::new(STRIPE_SECRET), "stripe"),
            slack: SlackWebhook::new(SLACK_SECRET),
            slack_replay: WebhookHandler::new(HmacSha256Verifier::new(SLACK_SECRET), "slack"),
        }
    }
}

const GITHUB_SECRET: &str = "github_delta_webhook_secret_2026";
const STRIPE_SECRET: &str = "whsec_delta_stripe_secret_2026";
const SLACK_SECRET: &str = "slack_delta_signing_secret_2026";

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
    let request_line = lines.next().expect("request line");
    let path = request_line
        .split_whitespace()
        .nth(1)
        .expect("request path")
        .to_string();

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
        .expect("content-length header");
    let mut body = raw[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut buf).expect("read HTTP body");
        assert!(read > 0, "client closed before request body");
        body.extend_from_slice(&buf[..read]);
    }
    body.truncate(content_length);

    ParsedHttpRequest {
        path,
        headers,
        body,
    }
}

fn write_status(stream: &mut TcpStream, status: u16, reason: &str) {
    let response =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream
        .write_all(response.as_bytes())
        .expect("write HTTP response");
    stream.flush().expect("flush HTTP response");
}

fn provider_response(
    state: &WebhookEndpointState,
    request: &ParsedHttpRequest,
) -> (u16, &'static str) {
    let result = match request.path.as_str() {
        "/github" => state
            .github
            .verify_and_parse(&request.headers, &request.body)
            .and_then(|event| state.github_replay.claim_event(&event.id)),
        "/stripe" => state
            .stripe
            .verify_and_parse(&request.headers, &request.body)
            .and_then(|event| state.stripe_replay.claim_event(&event.id)),
        "/slack" => state
            .slack
            .verify_and_parse(&request.headers, &request.body)
            .and_then(|event| state.slack_replay.claim_event(&event.id)),
        _ => return (404, "Not Found"),
    };

    match result {
        Ok(()) => (202, "Accepted"),
        Err(WebhookError::ReplayDetected { .. }) => (409, "Conflict"),
        Err(WebhookError::TimestampValidation { .. }) => (400, "Bad Request"),
        Err(_) => (401, "Unauthorized"),
    }
}

fn spawn_webhook_endpoint(
    steps: TraceSteps,
    requests: usize,
) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind webhook endpoint");
    let address = listener.local_addr().expect("webhook endpoint addr");
    let state = Arc::new(WebhookEndpointState::new());

    let handle = thread::spawn(move || {
        record_step(&steps, "server_accept_loop");
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().expect("accept webhook request");
            let request = read_http_request(&mut stream);
            let (status, reason) = provider_response(&state, &request);
            write_status(&mut stream, status, reason);
        }
        record_step(&steps, "server_done");
    });

    (address, handle)
}

fn post(addr: SocketAddr, path: &str, headers: &[(&str, String)], body: &[u8]) -> u16 {
    let mut stream = TcpStream::connect(addr).expect("connect webhook endpoint");
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n",
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
        .expect("write webhook request headers");
    stream.write_all(body).expect("write webhook request body");
    stream.flush().expect("flush webhook request");

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read webhook response");
    response
        .split_whitespace()
        .nth(1)
        .expect("HTTP status")
        .parse()
        .expect("numeric status")
}

fn github_headers(body: &[u8], delivery: &str) -> Vec<(&'static str, String)> {
    let signature = HmacSha256Verifier::new(GITHUB_SECRET).compute(body);
    vec![
        ("X-Hub-Signature-256", format!("sha256={signature}")),
        ("X-GitHub-Event", "push".to_string()),
        ("X-GitHub-Delivery", delivery.to_string()),
    ]
}

fn stripe_headers(body: &[u8], timestamp: i64) -> Vec<(&'static str, String)> {
    let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(body));
    let signature = HmacSha256Verifier::new(STRIPE_SECRET).compute(signed_payload.as_bytes());
    vec![("Stripe-Signature", format!("t={timestamp},v1={signature}"))]
}

fn slack_headers(body: &[u8], timestamp: i64) -> Vec<(&'static str, String)> {
    let base = format!("v0:{timestamp}:{}", String::from_utf8_lossy(body));
    let signature = HmacSha256Verifier::new(SLACK_SECRET).compute(base.as_bytes());
    vec![
        ("X-Slack-Signature", format!("v0={signature}")),
        ("X-Slack-Request-Timestamp", timestamp.to_string()),
    ]
}

#[test]
fn e2e_provider_signatures_and_replay_windows_over_http() {
    let steps = Arc::new(Mutex::new(Vec::new()));
    record_step(&steps, "server_start");
    let (addr, server) = spawn_webhook_endpoint(Arc::clone(&steps), 8);

    let github_body = br#"{"ref":"refs/heads/main","commits":[]}"#;
    let github_headers = github_headers(github_body, "delivery-delta-1");
    assert_eq!(post(addr, "/github", &github_headers, github_body), 202);
    record_step(&steps, "github_accept");
    assert_eq!(post(addr, "/github", &github_headers, github_body), 409);
    record_step(&steps, "github_replay");

    let now = Utc::now().timestamp();
    let stripe_body =
        br#"{"id":"evt_delta_e2e_1","type":"payment_intent.succeeded","data":{"object":{}}}"#;
    let stripe_request_headers = stripe_headers(stripe_body, now);
    assert_eq!(
        post(addr, "/stripe", &stripe_request_headers, stripe_body),
        202
    );
    record_step(&steps, "stripe_accept");
    assert_eq!(
        post(addr, "/stripe", &stripe_request_headers, stripe_body),
        409
    );
    record_step(&steps, "stripe_replay");
    let stale_stripe_headers = stripe_headers(stripe_body, now - 600);
    assert_eq!(
        post(addr, "/stripe", &stale_stripe_headers, stripe_body),
        400
    );
    record_step(&steps, "stripe_stale");

    let slack_body =
        br#"{"type":"event_callback","event":{"type":"message"},"event_id":"EvDeltaE2E1"}"#;
    let slack_request_headers = slack_headers(slack_body, now);
    assert_eq!(
        post(addr, "/slack", &slack_request_headers, slack_body),
        202
    );
    record_step(&steps, "slack_accept");
    assert_eq!(
        post(addr, "/slack", &slack_request_headers, slack_body),
        409
    );
    record_step(&steps, "slack_replay");
    let stale_slack_headers = slack_headers(slack_body, now - 600);
    assert_eq!(post(addr, "/slack", &stale_slack_headers, slack_body), 400);
    record_step(&steps, "slack_stale");

    server.join().expect("webhook endpoint thread");
    record_step(&steps, "verify");

    assert_step_order(
        &steps,
        &[
            "server_start",
            "github_accept",
            "github_replay",
            "stripe_accept",
            "stripe_replay",
            "stripe_stale",
            "slack_accept",
            "slack_replay",
            "slack_stale",
            "verify",
        ],
    );
    assert_step_order(
        &steps,
        &[
            "server_start",
            "server_accept_loop",
            "server_done",
            "verify",
        ],
    );
}
