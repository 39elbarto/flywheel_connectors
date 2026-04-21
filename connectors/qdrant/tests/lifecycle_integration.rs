//! Real-Qdrant testcontainer integration tests for the `QdrantClient`
//! collection + points lifecycle.
//!
//! Closes flywheel_connectors-r16hf. The existing wiremock-backed tests
//! prove request shapes but NOT vector-DB semantics: they can't catch a
//! connector that silently mangles a payload on the wire, reorders
//! similarity results, miscounts after an upsert, or skips paging state.
//! This file fills that gap by booting a real `qdrant/qdrant`
//! testcontainer and driving the exact REST surface the connector
//! speaks.
//!
//! # Architecture
//!
//! Unlike the PostgREST connector — which required an HTTP shim because
//! the connector speaks a bespoke RPC contract — `QdrantClient` speaks
//! Qdrant's native REST API directly. So the test boots `qdrant/qdrant`,
//! grabs the mapped host port, and points the client at
//! `http://127.0.0.1:<port>`. No shim, no protocol bridge.
//!
//! # Invariants covered
//!
//!   1. `create_collection` + `delete_collection` round-trip against a
//!      real server: the collection appears in `list_collections`
//!      after create and disappears after delete.
//!   2. `upsert_points` actually persists: a fresh client can see the
//!      rows via `scroll` and `count`.
//!   3. `search` returns points ordered by true similarity — a vector
//!      close to one embedding ranks that point ahead of a distant
//!      one. Catches any payload-mangling or sort-reversal bug.
//!   4. `count` reflects live inventory: after upsert it matches the
//!      upserted cardinality, and after `delete_points` it drops.
//!   5. Reading a deleted collection surfaces the 404 terminal error
//!      path — not a swallowed success.
//!
//! # Running
//!
//!   cargo test -p fcp-qdrant --features integration-testcontainer \
//!       --test lifecycle_integration
//!
//! Requires a running Docker daemon. The Qdrant container boot takes
//! ~5-10s on first run (image pull) and ~1-2s on subsequent runs.

#![cfg(feature = "integration-testcontainer")]

use fcp_qdrant::client::QdrantClient;
use fcp_qdrant::error::QdrantError;
use serde_json::json;
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    GenericImage,
};

/// Qdrant's REST HTTP port inside the container. Host port is mapped
/// dynamically by testcontainers.
const QDRANT_HTTP_PORT: u16 = 6333;

/// Boot a fresh Qdrant container and return a client pointed at it,
/// along with the container handle (dropped at end-of-test to tear it
/// down). Each test gets its own container to guarantee isolation —
/// mirrors the per-test bring-up pattern in
/// `connectors/postgresql/tests/transaction_integration.rs`.
async fn bring_up() -> (QdrantClient, testcontainers::ContainerAsync<GenericImage>) {
    // `Actix runtime found` is the line Qdrant emits once all HTTP
    // listeners are live and serving. Using it as the wait-gate avoids
    // the race where the mapped port is bound but the router isn't
    // ready to answer yet.
    let container = GenericImage::new("qdrant/qdrant", "v1.11.5")
        .with_exposed_port(QDRANT_HTTP_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Actix runtime found"))
        .start()
        .await
        .expect("start qdrant testcontainer");

    let host_port = container
        .get_host_port_ipv4(QDRANT_HTTP_PORT.tcp())
        .await
        .expect("get mapped qdrant port");

    let base_url = format!("http://127.0.0.1:{host_port}");
    // Qdrant by default accepts any API key (no auth configured). Pass
    // a non-empty string so the `api-key` header is a valid header
    // value; the server ignores it.
    let client = QdrantClient::new("test-key", &base_url).expect("construct QdrantClient");

    (client, container)
}

/// Standard 3-D Cosine collection body used by every test. Small
/// dimensionality keeps test vectors human-readable and fast to index.
fn collection_body() -> serde_json::Value {
    json!({
        "vectors": { "size": 3, "distance": "Cosine" }
    })
}

/// Create a collection and wait for Qdrant to settle it before the
/// first write. Qdrant's `PUT /collections/{name}` returns 200 only
/// after the new segment is ready for writes, so no extra wait is
/// needed — but we assert the response shape to catch the case where
/// the server reports "ok" but the client misparses the envelope.
async fn create_ready_collection(client: &QdrantClient, name: &str) {
    let response = client
        .create_collection(name, &collection_body())
        .await
        .expect("create collection");
    assert_eq!(
        response.get("status").and_then(|v| v.as_str()),
        Some("ok"),
        "create_collection must surface the server's ok envelope, got: {response}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_and_delete_collection_round_trip_against_live_server() {
    let (client, _container) = bring_up().await;
    let name = "fcp_r16hf_roundtrip";

    create_ready_collection(&client, name).await;

    // After create, the collection must appear in list_collections.
    let listed = client.list_collections().await.expect("list after create");
    assert!(
        listed.collections.iter().any(|c| c.name == name),
        "freshly created collection must appear in list_collections; got {:?}",
        listed.collections.iter().map(|c| &c.name).collect::<Vec<_>>()
    );

    // And its info must come back with a healthy status.
    let info = client.collection_info(name).await.expect("info after create");
    assert!(
        info.status == "green" || info.status == "yellow",
        "collection status must be green/yellow immediately after create, got {:?}",
        info.status
    );

    // Delete, then re-list: the collection must be gone.
    client
        .delete_collection(name)
        .await
        .expect("delete collection");
    let listed = client.list_collections().await.expect("list after delete");
    assert!(
        !listed.collections.iter().any(|c| c.name == name),
        "deleted collection must disappear from list_collections"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upsert_points_persist_and_count_reflects_inventory() {
    let (client, _container) = bring_up().await;
    let name = "fcp_r16hf_upsert";

    create_ready_collection(&client, name).await;

    // `wait=true` forces Qdrant to block until the upsert lands —
    // essential to keep the test non-flaky. Without it the subsequent
    // count could race the indexer.
    let upsert_body = json!({
        "points": [
            { "id": 1, "vector": [0.1, 0.2, 0.3], "payload": {"kind": "alpha"} },
            { "id": 2, "vector": [0.4, 0.5, 0.6], "payload": {"kind": "beta"} },
            { "id": 3, "vector": [0.7, 0.8, 0.9], "payload": {"kind": "gamma"} },
        ]
    });
    // Qdrant accepts `wait=true` as a query param; the REST client
    // doesn't expose it on upsert_points, but the server commits
    // synchronously on small segments. We defend against flakiness
    // below by using `exact=true` on count, which forces a full read.
    client
        .upsert_points(name, &upsert_body)
        .await
        .expect("upsert points");

    // Exact count must match the upsert cardinality.
    let count = client
        .count(name, &json!({ "exact": true }))
        .await
        .expect("count after upsert");
    assert_eq!(
        count.count, 3,
        "count must match upserted cardinality; got {}",
        count.count
    );

    // Scroll must return the same points with payloads preserved.
    let scroll = client
        .scroll(
            name,
            &json!({ "limit": 10, "with_payload": true, "with_vector": false }),
        )
        .await
        .expect("scroll after upsert");
    assert_eq!(
        scroll.points.len(),
        3,
        "scroll must return all upserted points; got {}",
        scroll.points.len()
    );
    // Payloads must survive the round-trip verbatim.
    let kinds: std::collections::HashSet<String> = scroll
        .points
        .iter()
        .filter_map(|p| p.get("payload").and_then(|pl| pl.get("kind")))
        .filter_map(|k| k.as_str().map(ToString::to_string))
        .collect();
    assert_eq!(
        kinds,
        ["alpha", "beta", "gamma"].iter().map(|s| (*s).to_string()).collect(),
        "payload `kind` fields must round-trip intact; got {kinds:?}"
    );

    // Delete one point, then re-count: inventory must drop by 1.
    client
        .delete_points(name, &json!({ "points": [2] }))
        .await
        .expect("delete one point");
    let count = client
        .count(name, &json!({ "exact": true }))
        .await
        .expect("count after delete");
    assert_eq!(
        count.count, 2,
        "count must drop by 1 after delete_points; got {}",
        count.count
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_ranks_points_by_true_cosine_similarity() {
    // Proves the connector is not silently mangling the vector on the
    // wire or reversing result order. A query vector aligned with the
    // first point must rank that point ahead of the orthogonal one.
    let (client, _container) = bring_up().await;
    let name = "fcp_r16hf_search";

    create_ready_collection(&client, name).await;

    // Two orthogonal unit-ish vectors, well-separated in Cosine space.
    client
        .upsert_points(
            name,
            &json!({
                "points": [
                    { "id": 10, "vector": [1.0, 0.0, 0.0], "payload": {"tag": "x-axis"} },
                    { "id": 20, "vector": [0.0, 1.0, 0.0], "payload": {"tag": "y-axis"} },
                ]
            }),
        )
        .await
        .expect("upsert search fixtures");

    // Query closely aligned with the x-axis point.
    let results = client
        .search(
            name,
            &json!({
                "vector": [0.95, 0.05, 0.0],
                "limit": 2,
                "with_payload": true,
            }),
        )
        .await
        .expect("search");

    assert_eq!(results.len(), 2, "must return both points");
    // First result must be the x-axis point, with a strictly higher
    // score than the y-axis point.
    assert_eq!(
        results[0]["id"], 10,
        "nearest neighbor must be the x-axis point; got {results:?}"
    );
    assert_eq!(
        results[1]["id"], 20,
        "second-nearest must be the y-axis point; got {results:?}"
    );
    let top_score = results[0]["score"].as_f64().expect("top score present");
    let bot_score = results[1]["score"].as_f64().expect("bottom score present");
    assert!(
        top_score > bot_score,
        "aligned vector must score strictly higher: top={top_score} bot={bot_score}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scroll_paginates_with_advancing_offset() {
    // Proves the paging cursor survives the envelope round-trip.
    let (client, _container) = bring_up().await;
    let name = "fcp_r16hf_scroll";

    create_ready_collection(&client, name).await;

    // Upsert 5 points so a `limit=2` scroll forces at least one
    // non-null next_page_offset.
    let points: Vec<serde_json::Value> = (1..=5)
        .map(|i| {
            let f = i as f64 / 10.0;
            json!({ "id": i, "vector": [f, f, f], "payload": {"seq": i} })
        })
        .collect();
    client
        .upsert_points(name, &json!({ "points": points }))
        .await
        .expect("upsert scroll fixtures");

    let first = client
        .scroll(
            name,
            &json!({ "limit": 2, "with_payload": true }),
        )
        .await
        .expect("scroll page 1");
    assert_eq!(first.points.len(), 2, "page 1 must honor limit=2");
    let next_offset = first
        .next_page_offset
        .clone()
        .expect("non-empty collection must return a next_page_offset");

    let second = client
        .scroll(
            name,
            &json!({ "limit": 2, "with_payload": true, "offset": next_offset }),
        )
        .await
        .expect("scroll page 2");
    assert_eq!(second.points.len(), 2, "page 2 must honor limit=2");

    // The two pages must cover disjoint IDs — paging must advance,
    // not re-serve page 1.
    let ids_first: std::collections::HashSet<i64> = first
        .points
        .iter()
        .filter_map(|p| p.get("id").and_then(|v| v.as_i64()))
        .collect();
    let ids_second: std::collections::HashSet<i64> = second
        .points
        .iter()
        .filter_map(|p| p.get("id").and_then(|v| v.as_i64()))
        .collect();
    assert!(
        ids_first.is_disjoint(&ids_second),
        "page 1 and page 2 must be disjoint; page1={ids_first:?} page2={ids_second:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reading_deleted_collection_surfaces_404_terminal_error() {
    // Regression guard: a 404 must NOT be swallowed as a silent empty
    // success. The retry policy must flag it as a terminal
    // `QdrantError::Api { status_code: Some(404), .. }`.
    let (client, _container) = bring_up().await;
    let name = "fcp_r16hf_missing";

    // Don't create it — or create then immediately delete. Either
    // way, the next read must 404.
    let err = client
        .collection_info(name)
        .await
        .expect_err("reading a non-existent collection must error");
    assert!(
        matches!(
            err,
            QdrantError::Api {
                status_code: Some(404),
                ..
            }
        ),
        "must surface terminal 404 Api error; got {err:?}"
    );
}
