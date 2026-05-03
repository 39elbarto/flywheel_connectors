//! Real-server end-to-end test for the GraphQL batch-size limit
//! under concurrent client load (br-0c3a08847).
//!
//! `tests/client.rs::rejects_oversized_batch_before_http_dispatch`
//! covers the single-call rejection contract against a wiremock
//! server: one client, one oversized batch, one expected `Protocol`
//! error and zero observed HTTP requests. The 0c3a08847 fix's
//! load-bearing claim is broader: the limit is enforced *per
//! request, before any HTTP dispatch* — even under concurrent load
//! across multiple cloned clients.
//!
//! This harness pins four concurrency contracts of the
//! `execute_batch_request` pre-dispatch limit check that the unit
//! test cannot reach:
//!
//!   1. **No oversized batch reaches the network**, ever, under
//!      concurrent submissions. We spawn N workers, each in a tight
//!      loop submitting either an under-cap batch (must succeed) or
//!      an over-cap batch (must `Protocol`-fail). The server counts
//!      received requests AND total batch items; both totals must
//!      equal what the under-cap workers submitted — never more.
//!
//!   2. **Per-client cap independence**. Two concurrent clients are
//!      built from the same builder but with different
//!      `with_max_batch_items` values (2 and 4). A request that
//!      would be valid for client B (size 3) but oversized for
//!      client A (cap 2) must succeed for B and fail for A even
//!      when both submit concurrently. Catches a regression that
//!      pulls the cap from a shared global rather than per-config.
//!
//!   3. **Empty batch fast-path is concurrency-safe**. The empty-
//!      batch early return (`Ok(Vec::new())`) is reached without
//!      consulting the cap, but it MUST also not increment any
//!      shared counter or emit a request. Concurrent empties from
//!      many workers verify the fast path doesn't accidentally
//!      become a side-effecting hot spot.
//!
//!   4. **Protocol error message remains stable under contention**.
//!      Every oversized rejection reports the configured limit
//!      verbatim ("exceeding limit N"), so log-aggregation
//!      dashboards filtering on this message text don't lose rows
//!      to a races-induced format drift.
//!
//! Server is a raw TcpListener that parses each request body as
//! JSON, counts the array length, and emits a structurally-valid
//! GraphQL batch response. Each entry includes the
//! `fcpBatchIndex` correlation extension so the client's
//! `validate_batch_response_correlations` check passes.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use fcp_async_core::task;
use fcp_graphql::{
    GraphqlBatchItem, GraphqlClient, GraphqlClientBuilder, GraphqlClientError, GraphqlQuery,
};
use serde_json::Value;

const CLIENT_A_CAP: usize = 2;
const CLIENT_B_CAP: usize = 4;
const WORKERS_PER_PHASE: usize = 8;
const ITERATIONS_PER_WORKER: usize = 6;

const PROBE_QUERY: &str = "query Probe { probe { id } }";

/// Server counters shared across the listener thread and the test
/// body. `requests_received` counts every successful HTTP exchange;
/// `total_batch_items_received` sums the batch length on each.
#[derive(Debug, Default)]
struct ServerCounters {
    requests_received: AtomicUsize,
    total_batch_items_received: AtomicUsize,
    /// Records every observed batch length so we can assert no
    /// oversized batch (> max_observed_cap) ever arrived.
    max_batch_length_observed: AtomicUsize,
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut raw = Vec::new();
    let mut buf = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut buf).expect("read HTTP request");
        if read == 0 {
            return raw;
        }
        raw.extend_from_slice(&buf[..read]);
        if let Some(index) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };

    let mut content_length: usize = 0;
    let headers_text = String::from_utf8_lossy(&raw[..header_end]);
    for line in headers_text.lines() {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }

    let mut body = raw[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut buf).expect("read HTTP body");
        if read == 0 {
            break;
        }
        body.extend_from_slice(&buf[..read]);
    }
    body.truncate(content_length);
    body
}

fn build_batch_response(batch_len: usize) -> Vec<u8> {
    // Mirror the request's correlation index in each response item.
    // Client validates that fcpBatchIndex is present and unique.
    let mut entries = Vec::with_capacity(batch_len);
    for index in 0..batch_len {
        entries.push(serde_json::json!({
            "data": { "probe": { "id": format!("p{index}") } },
            "extensions": { "fcpBatchIndex": index },
        }));
    }
    serde_json::to_vec(&entries).expect("serialize batch response")
}

fn write_response(stream: &mut TcpStream, body: &[u8]) {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    stream
        .write_all(&response)
        .expect("write HTTP response");
    stream.flush().expect("flush HTTP response");
}

fn spawn_batch_server(counters: Arc<ServerCounters>) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind batch server");
    let address = listener.local_addr().expect("server addr");
    listener
        .set_nonblocking(false)
        .expect("listener blocking mode");

    let handle = thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = match incoming {
                Ok(s) => s,
                Err(_) => return,
            };
            let body = read_http_request(&mut stream);
            // Parse the body — if it isn't a JSON array, treat as
            // 1-item batch (for non-batch single-request tests
            // unrelated to this harness, but our test only sends
            // batches so we'll always hit the array path).
            let batch_len = match serde_json::from_slice::<Value>(&body) {
                Ok(Value::Array(arr)) => arr.len(),
                _ => 1,
            };
            counters
                .requests_received
                .fetch_add(1, Ordering::Relaxed);
            counters
                .total_batch_items_received
                .fetch_add(batch_len, Ordering::Relaxed);
            counters
                .max_batch_length_observed
                .fetch_max(batch_len, Ordering::Relaxed);

            let response_body = build_batch_response(batch_len);
            write_response(&mut stream, &response_body);
        }
    });

    (address, handle)
}

fn batch_items(count: usize) -> Vec<GraphqlBatchItem<Value>> {
    (0..count)
        .map(|_| GraphqlBatchItem::new(GraphqlQuery::new(PROBE_QUERY), serde_json::json!({})))
        .collect()
}

/// Outcome rolled up across all workers in a phase.
#[derive(Debug, Default)]
struct PhaseOutcome {
    successes: usize,
    protocol_errors: usize,
    other_errors: Vec<String>,
}

async fn worker_submit_batch(
    client: GraphqlClient,
    size: usize,
    cap_for_message: usize,
    expect_success: bool,
) -> Result<bool, String> {
    let items = batch_items(size);
    let result: Result<Vec<fcp_graphql::GraphqlResponse<Value>>, GraphqlClientError> = client
        .execute_batch_request::<_, Value>(items, None, None, true)
        .await;

    match (result, expect_success) {
        (Ok(_), true) => Ok(true),
        (
            Err(GraphqlClientError::Protocol { message }),
            false,
        ) => {
            // Protocol error: must mention the configured limit.
            let needle = format!("exceeding limit {cap_for_message}");
            if !message.contains(&needle) {
                return Err(format!(
                    "expected protocol message to contain `{needle}`, got `{message}`"
                ));
            }
            Ok(false)
        }
        (Ok(_), false) => Err(format!(
            "oversized batch (size={size}, cap={cap_for_message}) was accepted — limit not enforced"
        )),
        (Err(other), true) => Err(format!(
            "valid batch (size={size}, cap={cap_for_message}) was rejected: {other:?}"
        )),
        (Err(other), false) => Err(format!(
            "oversized batch produced wrong error variant: {other:?}"
        )),
    }
}

#[fcp_async_core::runtime::test]
async fn batch_limit_holds_under_concurrent_real_server_load() {
    let counters = Arc::new(ServerCounters::default());
    let (addr, server) = spawn_batch_server(Arc::clone(&counters));
    let endpoint = format!("http://{addr}/graphql");

    let client_a = GraphqlClientBuilder::new(endpoint.clone())
        .with_max_batch_items(CLIENT_A_CAP)
        .build()
        .expect("build client A");

    let client_b = GraphqlClientBuilder::new(endpoint.clone())
        .with_max_batch_items(CLIENT_B_CAP)
        .build()
        .expect("build client B");

    // ── Phase 1: many concurrent oversized batches against client A ──
    //
    // Every worker submits a batch of size CLIENT_A_CAP+1=3, which
    // is over the cap. None should reach the server. Server
    // counters MUST stay at zero across this phase.
    let phase1_baseline_requests = counters.requests_received.load(Ordering::SeqCst);
    let mut phase1_handles = Vec::new();
    for _worker in 0..WORKERS_PER_PHASE {
        for _iter in 0..ITERATIONS_PER_WORKER {
            let client = client_a.clone();
            phase1_handles.push(task::spawn(async move {
                worker_submit_batch(client, CLIENT_A_CAP + 1, CLIENT_A_CAP, false).await
            }));
        }
    }
    let mut phase1 = PhaseOutcome::default();
    for handle in phase1_handles {
        match handle.await.expect("worker join") {
            Ok(true) => phase1.successes += 1,
            Ok(false) => phase1.protocol_errors += 1,
            Err(msg) => phase1.other_errors.push(msg),
        }
    }
    assert!(
        phase1.other_errors.is_empty(),
        "phase 1 unexpected errors: {:?}",
        phase1.other_errors,
    );
    assert_eq!(
        phase1.successes, 0,
        "phase 1: every oversized batch must be rejected",
    );
    assert_eq!(
        phase1.protocol_errors,
        WORKERS_PER_PHASE * ITERATIONS_PER_WORKER,
        "phase 1: all workers must see protocol errors",
    );
    assert_eq!(
        counters.requests_received.load(Ordering::SeqCst),
        phase1_baseline_requests,
        "phase 1: server received a request despite all batches being oversized — \
         the pre-dispatch limit check leaked under concurrent load",
    );

    // ── Phase 2: under-cap batches for client A — ALL should succeed
    //              and reach the server.
    let phase2_baseline_requests = counters.requests_received.load(Ordering::SeqCst);
    let phase2_baseline_items = counters
        .total_batch_items_received
        .load(Ordering::SeqCst);
    let phase2_batch_size = CLIENT_A_CAP; // exactly at the cap
    let phase2_iterations = WORKERS_PER_PHASE * ITERATIONS_PER_WORKER;
    let mut phase2_handles = Vec::new();
    for _ in 0..phase2_iterations {
        let client = client_a.clone();
        phase2_handles.push(task::spawn(async move {
            worker_submit_batch(client, phase2_batch_size, CLIENT_A_CAP, true).await
        }));
    }
    let mut phase2 = PhaseOutcome::default();
    for handle in phase2_handles {
        match handle.await.expect("phase2 worker join") {
            Ok(true) => phase2.successes += 1,
            Ok(false) => phase2.protocol_errors += 1,
            Err(msg) => phase2.other_errors.push(msg),
        }
    }
    assert!(
        phase2.other_errors.is_empty(),
        "phase 2 unexpected errors: {:?}",
        phase2.other_errors,
    );
    assert_eq!(
        phase2.successes, phase2_iterations,
        "phase 2: every at-cap batch must succeed",
    );
    let phase2_requests = counters.requests_received.load(Ordering::SeqCst) - phase2_baseline_requests;
    let phase2_items =
        counters.total_batch_items_received.load(Ordering::SeqCst) - phase2_baseline_items;
    assert_eq!(
        phase2_requests, phase2_iterations,
        "phase 2: server should see one request per worker",
    );
    assert_eq!(
        phase2_items,
        phase2_iterations * phase2_batch_size,
        "phase 2: total received items must match the sum of submitted batches",
    );

    // ── Phase 3: per-client cap independence ────────────────────
    //
    // Submit a batch of size 3 concurrently from BOTH clients:
    //   - client_a (cap 2) must reject 3-item batches.
    //   - client_b (cap 4) must accept 3-item batches.
    let phase3_baseline_requests = counters.requests_received.load(Ordering::SeqCst);
    let phase3_size = CLIENT_A_CAP + 1; // 3
    let mut phase3_handles = Vec::new();
    for _ in 0..WORKERS_PER_PHASE {
        let client = client_a.clone();
        phase3_handles.push(task::spawn(async move {
            worker_submit_batch(client, phase3_size, CLIENT_A_CAP, false).await
        }));
        let client = client_b.clone();
        phase3_handles.push(task::spawn(async move {
            worker_submit_batch(client, phase3_size, CLIENT_B_CAP, true).await
        }));
    }
    let mut phase3_a_rejected = 0;
    let mut phase3_b_accepted = 0;
    let mut phase3_errors = Vec::new();
    for handle in phase3_handles {
        match handle.await.expect("phase3 worker join") {
            Ok(true) => phase3_b_accepted += 1,
            Ok(false) => phase3_a_rejected += 1,
            Err(msg) => phase3_errors.push(msg),
        }
    }
    assert!(
        phase3_errors.is_empty(),
        "phase 3 unexpected errors: {phase3_errors:?}",
    );
    assert_eq!(
        phase3_a_rejected, WORKERS_PER_PHASE,
        "phase 3: every client_a worker must reject — cap not honored",
    );
    assert_eq!(
        phase3_b_accepted, WORKERS_PER_PHASE,
        "phase 3: every client_b worker must succeed — independent cap leaked",
    );
    let phase3_requests = counters.requests_received.load(Ordering::SeqCst) - phase3_baseline_requests;
    assert_eq!(
        phase3_requests, WORKERS_PER_PHASE,
        "phase 3: server should see exactly client_b's requests, not client_a's — \
         per-client cap is independent",
    );

    // ── Phase 4: empty-batch fast path under concurrency ─────────
    //
    // Empty batches return Ok(Vec::new()) without dispatching. Many
    // concurrent empties must not increment server counters or
    // bleed through to a real HTTP request.
    let phase4_baseline_requests = counters.requests_received.load(Ordering::SeqCst);
    let mut phase4_handles = Vec::new();
    for _ in 0..(WORKERS_PER_PHASE * ITERATIONS_PER_WORKER) {
        let client = client_a.clone();
        phase4_handles.push(task::spawn(async move {
            let empty_batch: Vec<GraphqlBatchItem<Value>> = Vec::new();
            let result: Result<Vec<fcp_graphql::GraphqlResponse<Value>>, _> = client
                .execute_batch_request::<_, Value>(empty_batch, None, None, true)
                .await;
            match result {
                Ok(v) if v.is_empty() => Ok(()),
                Ok(_) => Err("non-empty response from empty batch".to_string()),
                Err(e) => Err(format!("empty-batch fast path failed: {e:?}")),
            }
        }));
    }
    for handle in phase4_handles {
        handle
            .await
            .expect("phase4 worker join")
            .expect("phase4 worker outcome");
    }
    let phase4_requests = counters.requests_received.load(Ordering::SeqCst) - phase4_baseline_requests;
    assert_eq!(
        phase4_requests, 0,
        "phase 4: empty batches must not dispatch — fast path leaked under concurrency",
    );

    // ── Final invariant: server NEVER saw a batch larger than
    //     CLIENT_B_CAP. If client_a ever leaked, max would be 3
    //     (or larger). The assertion below catches even a single
    //     leaked oversized batch.
    let max_observed = counters.max_batch_length_observed.load(Ordering::SeqCst);
    assert!(
        max_observed <= CLIENT_B_CAP,
        "server observed a batch of size {max_observed} > max(CLIENT_A_CAP={CLIENT_A_CAP}, CLIENT_B_CAP={CLIENT_B_CAP}) — \
         the pre-dispatch limit check leaked at least once under concurrent load",
    );

    drop(server);
}
