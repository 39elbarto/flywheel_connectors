use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fcp_oauth::{OAuth2Client, OAuth2Config, OAuthTokens, TokenResponse, TokenStore};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN_KEY: &str = "bench-user";

fn refreshable_tokens() -> OAuthTokens {
    OAuthTokens::from_response(TokenResponse {
        access_token: "shared-access-old".into(),
        token_type: "Bearer".into(),
        expires_in: Some(1),
        refresh_token: Some("shared-refresh".into()),
        scope: None,
        id_token: None,
    })
    .expect("bench token fixture must construct")
}

fn oauth_client(server_uri: &str) -> OAuth2Client {
    let config = OAuth2Config::new(
        "bench-client",
        "bench-secret",
        format!("{server_uri}/authorize"),
        format!("{server_uri}/token"),
    )
    .with_redirect_uri("https://localhost:3000/callback");
    OAuth2Client::new(config).expect("bench OAuth client must construct")
}

async fn refresh_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(2))
                .set_body_json(serde_json::json!({
                    "access_token": "shared-access-new",
                    "token_type": "Bearer",
                    "refresh_token": "shared-refresh-new",
                    "expires_in": 3600
                })),
        )
        .mount(&server)
        .await;
    server
}

async fn singleflight_waiter_wakeup(server_uri: &str, waiter_count: usize) -> Duration {
    let client = Arc::new(oauth_client(server_uri));
    let store = Arc::new(TokenStore::new());
    store.store(TOKEN_KEY, refreshable_tokens());

    let (start_tx, start_rx) = fcp_async_core::channel::watch::channel(false);
    let mut joins = Vec::with_capacity(waiter_count);
    for _ in 0..waiter_count {
        let mut start_rx = start_rx.clone();
        let client = Arc::clone(&client);
        let store = Arc::clone(&store);
        joins.push(fcp_async_core::task::spawn(async move {
            while !*start_rx.borrow_and_update() {
                start_rx
                    .changed()
                    .await
                    .expect("start gate sender should remain open");
            }

            let started = Instant::now();
            let tokens = store
                .get_or_refresh(TOKEN_KEY, &client)
                .await
                .expect("single-flight refresh must succeed");
            assert_eq!(tokens.access_token(), "shared-access-new");
            started.elapsed()
        }));
    }

    let started = Instant::now();
    start_tx
        .send(true)
        .expect("start gate receivers should remain open");

    let mut max_waiter_elapsed = Duration::ZERO;
    for join in joins {
        let waiter_elapsed = join.await.expect("waiter task should join");
        max_waiter_elapsed = max_waiter_elapsed.max(waiter_elapsed);
    }

    black_box(max_waiter_elapsed);
    started.elapsed()
}

fn bench_refresh_waiter_wakeup(c: &mut Criterion) {
    let runtime = fcp_async_core::runtime::Runtime::new().expect("bench runtime must construct");
    let server = runtime.block_on(refresh_server());
    let server_uri = server.uri();

    let mut group = c.benchmark_group("oauth_refresh_singleflight_waiter_wakeup");
    for waiter_count in [1_usize, 10, 100, 1000] {
        group.throughput(Throughput::Elements(
            u64::try_from(waiter_count).expect("waiter count fits u64"),
        ));
        group.bench_with_input(
            BenchmarkId::from_parameter(waiter_count),
            &waiter_count,
            |b, &waiter_count| {
                b.iter_custom(|iters| {
                    runtime.block_on(async {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            total += singleflight_waiter_wakeup(&server_uri, waiter_count).await;
                        }
                        total
                    })
                });
            },
        );
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_millis(500));
    targets = bench_refresh_waiter_wakeup
}
criterion_main!(benches);
