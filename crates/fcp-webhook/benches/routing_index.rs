use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fcp_webhook::{
    EventRouter, EventSubscription, HmacSha256Verifier, WebhookConfig, WebhookEvent, WebhookHandler,
};

fn router_with_exact_routes(route_count: usize) -> EventRouter {
    let mut router = EventRouter::new();
    for i in 0..route_count {
        router.subscribe(
            EventSubscription::for_types(vec![format!("event_{i}")]).with_provider("github"),
            format!("handler_{i}"),
        );
    }
    router
}

fn handler_with_allowlist(allowlist_size: usize) -> WebhookHandler<HmacSha256Verifier> {
    let allowlist = (0..allowlist_size).map(|i| format!("10.0.0.{i}")).collect();
    let config = WebhookConfig::new()
        .with_ip_allowlist(allowlist)
        .with_idempotency_ttl(Duration::from_secs(60));
    WebhookHandler::with_config(
        HmacSha256Verifier::new("webhook-routing-bench-secret"),
        "github",
        config,
    )
}

fn bench_routing_index(c: &mut Criterion) {
    let mut group = c.benchmark_group("webhook_routing_index_exact_lookup");
    for route_count in [10_usize, 100, 1000] {
        let router = router_with_exact_routes(route_count);
        let event = WebhookEvent::new(
            "bench-event",
            format!("event_{}", route_count - 1),
            "github",
        );
        group.throughput(Throughput::Elements(
            u64::try_from(route_count).expect("route count fits u64"),
        ));
        group.bench_with_input(
            BenchmarkId::from_parameter(route_count),
            &route_count,
            |b, _| {
                b.iter(|| {
                    let handlers = router.route(black_box(&event));
                    black_box(handlers);
                });
            },
        );
    }
    group.finish();
}

fn bench_ip_allowlist(c: &mut Criterion) {
    let mut group = c.benchmark_group("webhook_ip_allowlist_lookup");
    for allowlist_size in [10_usize, 100, 1000] {
        let handler = handler_with_allowlist(allowlist_size);
        let allowed_ip = format!("10.0.0.{}", allowlist_size - 1);
        group.throughput(Throughput::Elements(
            u64::try_from(allowlist_size).expect("allowlist size fits u64"),
        ));
        group.bench_with_input(
            BenchmarkId::from_parameter(allowlist_size),
            &allowlist_size,
            |b, _| {
                b.iter(|| {
                    let result = handler.check_ip(black_box(&allowed_ip));
                    let _ = black_box(result);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_routing_index, bench_ip_allowlist);
criterion_main!(benches);
