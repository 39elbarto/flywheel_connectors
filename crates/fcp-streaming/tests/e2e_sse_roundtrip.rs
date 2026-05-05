use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use fcp_streaming::{SseClient, SseConfig};
use futures_util::StreamExt as _;
use tracing::Level;

type TraceSteps = Arc<Mutex<Vec<&'static str>>>;

fn record_step(steps: &TraceSteps, step: &'static str) {
    let mut guard = steps.lock().expect("trace steps lock");
    let order = guard.len();
    let span = tracing::span!(
        Level::INFO,
        "delta_e2e_step",
        crate_name = "fcp-streaming",
        step,
        order
    );
    let _entered = span.enter();
    guard.push(step);
}

fn assert_step_order(steps: &TraceSteps, expected: &[&'static str]) {
    let observed = steps.lock().expect("trace steps lock").clone();
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

fn read_http_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buf = [0_u8; 512];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buf).expect("read SSE HTTP request");
        assert!(read > 0, "client closed before sending headers");
        request.extend_from_slice(&buf[..read]);
    }
    request
}

fn spawn_split_sse_server(steps: TraceSteps) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind SSE listener");
    let address = listener.local_addr().expect("SSE listener addr");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept SSE client");
        record_step(&steps, "server_accept");

        let request = read_http_headers(&mut stream);
        let request_text = String::from_utf8_lossy(&request);
        assert!(request_text.starts_with("GET /events "));
        assert!(request_text.contains("Accept: text/event-stream"));

        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: text/event-stream\r\n\
                  Cache-Control: no-cache\r\n\
                  Connection: close\r\n\
                  \r\n",
            )
            .expect("write SSE response headers");
        stream.flush().expect("flush SSE headers");
        record_step(&steps, "server_headers");

        for chunk in [
            b"id: eve".as_slice(),
            b"nt-1\nevent: de".as_slice(),
            b"lta\ndata: hello ".as_slice(),
            b"from\n".as_slice(),
            b"data: split transport\n\n".as_slice(),
        ] {
            stream.write_all(chunk).expect("write split SSE chunk");
            stream.flush().expect("flush split SSE chunk");
            thread::sleep(Duration::from_millis(10));
        }
        record_step(&steps, "server_emit");
    });

    (format!("http://{address}/events"), handle)
}

#[fcp_async_core::runtime::test]
async fn e2e_sse_round_trip_spans_network_read_boundaries() {
    let steps = Arc::new(Mutex::new(Vec::new()));
    record_step(&steps, "server_start");
    let (url, server) = spawn_split_sse_server(Arc::clone(&steps));

    let client = SseClient::with_config(
        url,
        SseConfig::new()
            .with_auto_reconnect(false)
            .with_timeout(Duration::from_secs(5)),
    );

    record_step(&steps, "client_connect");
    let mut stream = client.connect().await.expect("connect SSE stream");
    record_step(&steps, "client_connected");

    let event = fcp_async_core::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("SSE event timeout")
        .expect("SSE stream item")
        .expect("SSE event ok");
    record_step(&steps, "client_parse");

    assert_eq!(event.id.as_deref(), Some("event-1"));
    assert_eq!(event.event.as_deref(), Some("delta"));
    assert_eq!(event.data, "hello from\nsplit transport");
    assert_eq!(stream.last_event_id(), Some("event-1"));

    server.join().expect("SSE server thread");
    record_step(&steps, "verify");

    assert_step_order(
        &steps,
        &[
            "server_start",
            "client_connect",
            "client_connected",
            "client_parse",
            "verify",
        ],
    );
    assert_step_order(
        &steps,
        &[
            "server_start",
            "server_accept",
            "server_headers",
            "server_emit",
            "verify",
        ],
    );
}
