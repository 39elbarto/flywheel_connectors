use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fcp_graphql::__bench::SchemaCache;
use fcp_graphql::{GraphqlBatchItem, GraphqlQuery, GraphqlQueryLimits, GraphqlRequest};
use serde_json::{Value, json};

const RESPONSE_SCHEMA: &str = r#"{
    "type": "object",
    "required": ["viewer"],
    "properties": {
        "viewer": {
            "type": "object",
            "required": ["id", "name", "repositories"],
            "properties": {
                "id": {"type": "string"},
                "name": {"type": "string"},
                "repositories": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name", "stars"],
                        "properties": {
                            "name": {"type": "string"},
                            "stars": {"type": "integer", "minimum": 0}
                        }
                    }
                }
            }
        }
    }
}"#;

fn representative_query() -> &'static str {
    "query Viewer($login: String!, $limit: Int!) { viewer(login: $login) { id name repositories(first: $limit) { name stars } } }"
}

fn deep_query(depth: usize) -> String {
    let mut query = String::from("query Deep ");
    for index in 0..depth {
        write!(&mut query, "{{ level{index} ").expect("write to string");
    }
    query.push_str("id");
    for _ in 0..depth {
        query.push_str(" }");
    }
    query
}

fn alias_query(alias_count: usize) -> String {
    let mut query = String::from("query AliasBomb { ");
    for index in 0..alias_count {
        write!(&mut query, "alias{index}: viewer {{ id }} ").expect("write to string");
    }
    query.push('}');
    query
}

fn root_field_query(root_field_count: usize) -> String {
    let mut query = String::from("query RootFields { ");
    for index in 0..root_field_count {
        write!(&mut query, "rootField{index} ").expect("write to string");
    }
    query.push('}');
    query
}

fn oversized_query() -> String {
    let mut query = String::from("query Oversized { viewer { id } } # ");
    query.push_str(&"x".repeat(GraphqlQueryLimits::default().max_query_bytes + 1));
    query
}

fn request_payload() -> GraphqlRequest<Value> {
    GraphqlRequest::new(
        GraphqlQuery::new(representative_query()),
        json!({"login": "delta-user", "limit": 25}),
    )
    .with_operation_name("Viewer")
}

fn batch_payload(item_count: usize) -> Vec<GraphqlBatchItem<Value>> {
    (0..item_count)
        .map(|index| {
            GraphqlBatchItem::new(
                GraphqlQuery::new(representative_query()),
                json!({"login": format!("delta-user-{index}"), "limit": 25}),
            )
            .with_operation_name("Viewer")
        })
        .collect()
}

fn response_value() -> Value {
    json!({
        "viewer": {
            "id": "user-1",
            "name": "Delta User",
            "repositories": [
                {"name": "fcp-streaming", "stars": 13},
                {"name": "fcp-graphql", "stars": 21},
                {"name": "fcp-oauth", "stars": 34}
            ]
        }
    })
}

fn bench_query_limit_validation(c: &mut Criterion) {
    let limits = GraphqlQueryLimits::default();
    let cases = [
        ("representative", representative_query().to_string()),
        ("max_depth", deep_query(limits.max_depth)),
        ("max_aliases", alias_query(limits.max_aliases)),
        ("max_root_fields", root_field_query(limits.max_root_fields)),
        ("oversized_reject", oversized_query()),
    ];

    let mut group = c.benchmark_group("graphql_query_limit_validation");
    for (label, query) in cases {
        group.throughput(Throughput::Bytes(
            u64::try_from(query.len()).expect("query length fits u64"),
        ));
        group.bench_with_input(BenchmarkId::from_parameter(label), &query, |b, query| {
            b.iter(|| {
                black_box(limits.validate(black_box(query.as_str())).is_ok());
            });
        });
    }
    group.finish();
}

fn bench_request_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("graphql_request_serialization");
    group.bench_function("single_request", |b| {
        b.iter_batched(
            request_payload,
            |request| black_box(serde_json::to_vec(&request).expect("request serializes")),
            BatchSize::SmallInput,
        );
    });

    for item_count in [1_usize, 10, 100] {
        group.throughput(Throughput::Elements(
            u64::try_from(item_count).expect("item count fits u64"),
        ));
        group.bench_with_input(
            BenchmarkId::new("batch_request", item_count),
            &item_count,
            |b, &item_count| {
                b.iter_batched(
                    || batch_payload(item_count),
                    |batch| black_box(serde_json::to_vec(&batch).expect("batch serializes")),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_schema_validation(c: &mut Criterion) {
    let value = response_value();
    let cached_cache = SchemaCache::default();
    cached_cache
        .get_or_compile(RESPONSE_SCHEMA)
        .expect("schema compiles");

    let mut group = c.benchmark_group("graphql_schema_validation");
    group.bench_function("cached_response_schema", |b| {
        b.iter(|| {
            black_box(
                cached_cache
                    .validate(RESPONSE_SCHEMA, black_box(&value))
                    .is_ok(),
            );
        });
    });
    group.bench_function("cold_compile_and_validate", |b| {
        b.iter_batched(
            SchemaCache::default,
            |cache| {
                black_box(cache.validate(RESPONSE_SCHEMA, black_box(&value)).is_ok());
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_millis(500));
    targets =
        bench_query_limit_validation,
        bench_request_serialization,
        bench_schema_validation
}
criterion_main!(benches);
