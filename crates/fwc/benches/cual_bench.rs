//! Performance benchmarks for latency-sensitive CUAL operations.
//!
//! Establishes baselines and detects regressions for search, schema validation,
//! pipeline planning, and MCP server state construction.

use std::fmt::Write as _;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::json;

use fwc::readiness::{
    ConnectorDetail, ConnectorState, ConnectorSummary, DiscoveredConnector, DiscoveredOperation,
    MetadataField, OperationSummary,
};
use fwc::schema_nav;
use fwc::search::{SearchFilters, search_operations};

// ── Fixture builders ──────────────────────────────────────────────────────

fn stub_operation(id: &str, desc: &str) -> DiscoveredOperation {
    DiscoveredOperation {
        actual_id: id.to_owned(),
        local_id: id.rsplit('.').next().unwrap_or(id).to_owned(),
        preferred_selector: id.rsplit('.').next().unwrap_or(id).to_owned(),
        aliases: vec![],
        description: desc.to_owned(),
        summary: OperationSummary {
            id: id.to_owned(),
            summary: desc.to_owned(),
            capability: "read".to_owned(),
            risk_level: "low".to_owned(),
            safety_tier: "safe".to_owned(),
            idempotency: "strict".to_owned(),
            requires_approval: false,
            supports_simulate: fwc::readiness::MetadataField::Known(true),
        },
        input_schema: json!({"type": "object", "properties": {"q": {"type": "string"}}}),
        output_schema: json!({"type": "object"}),
        approval_mode: "none".to_owned(),
        when_to_use: format!("Use {id} to perform this operation."),
        common_mistakes: vec![],
        examples: vec![],
        related: vec![],
        network_constraints: None,
        rate_limits: Some(vec![]),
        search_actual_id_lower: String::new(),
        search_local_id_lower: String::new(),
        search_aliases_lower: Vec::new(),
        search_summary_lower: String::new(),
        search_when_to_use_lower: String::new(),
        search_capability_lower: String::new(),
        search_common_mistakes_lower: Vec::new(),
        search_related_lower: Vec::new(),
    }
}

fn stub_connector(slug: &str, op_count: usize) -> DiscoveredConnector {
    let ops: Vec<DiscoveredOperation> = (0..op_count)
        .map(|i| {
            stub_operation(
                &format!("{slug}.op_{i}"),
                &format!("Operation {i} for {slug}"),
            )
        })
        .collect();
    let op_summaries: Vec<OperationSummary> = ops.iter().map(|o| o.summary.clone()).collect();
    DiscoveredConnector {
        slug: slug.to_owned(),
        manifest_path: format!("connectors/{slug}/manifest.toml"),
        cohort: "dev-tools".to_owned(),
        manifest_status: None,
        hidden_by_default: false,
        non_live_rationale: None,
        graduation_guidance: None,
        runtime_format: "wasi".to_owned(),
        state_model: MetadataField::Unknown,
        supported_zones: vec!["z:work".to_owned()],
        detail: ConnectorDetail {
            summary: ConnectorSummary {
                id: format!("fcp.{slug}"),
                name: format!("{slug} Connector"),
                version: "1.0.0".to_owned(),
                description: format!("FCP connector for {slug}"),
                archetypes: MetadataField::Known(vec!["operational".to_owned()]),
                state: ConnectorState::Unknown,
                operation_count: ops.len(),
                max_risk: "medium".to_owned(),
                has_events: MetadataField::Known(false),
            },
            operations: op_summaries,
            config_schema: MetadataField::Unknown,
            health: MetadataField::Unknown,
            rate_limits: MetadataField::Known(vec![]),
        },
        zones: json!({}),
        capabilities: json!({}),
        connector_schema: json!({}),
        operations: ops,
        search_slug_lower: String::new(),
        search_name_lower: String::new(),
        search_cohort_lower: String::new(),
    }
}

fn make_connectors(count: usize, ops_per: usize) -> Vec<DiscoveredConnector> {
    (0..count)
        .map(|i| stub_connector(&format!("connector_{i}"), ops_per))
        .collect()
}

// ── Search benchmarks ─────────────────────────────────────────────────────

fn bench_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("search");

    // 100 operations (10 connectors x 10 ops)
    let connectors_100 = make_connectors(10, 10);
    group.bench_function("search_100_ops_keyword", |b| {
        let filters = SearchFilters::default();
        b.iter(|| search_operations(black_box(&connectors_100), black_box("operation"), &filters));
    });

    // 500 operations (50 connectors x 10 ops)
    let connectors_500 = make_connectors(50, 10);
    group.bench_function("search_500_ops_keyword", |b| {
        let filters = SearchFilters::default();
        b.iter(|| search_operations(black_box(&connectors_500), black_box("connector"), &filters));
    });

    // 1000 operations (100 connectors x 10 ops)
    let connectors_1000 = make_connectors(100, 10);
    group.bench_function("search_1000_ops_keyword", |b| {
        let filters = SearchFilters::default();
        b.iter(|| {
            search_operations(
                black_box(&connectors_1000),
                black_box("operation 5"),
                &filters,
            )
        });
    });

    // Faceted search (filter by capability)
    group.bench_function("search_500_ops_faceted", |b| {
        let filters = SearchFilters {
            capability: Some("read".to_owned()),
            ..Default::default()
        };
        b.iter(|| search_operations(black_box(&connectors_500), black_box("list"), &filters));
    });

    group.finish();
}

// ── Schema validation benchmarks ──────────────────────────────────────────

fn bench_schema_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("schema_validation");

    let simple_schema = json!({
        "type": "object",
        "required": ["name"],
        "properties": {
            "name": {"type": "string"},
            "count": {"type": "integer"}
        }
    });
    let simple_valid = json!({"name": "test", "count": 42});
    let simple_invalid = json!({"count": "not a number"});

    group.bench_function("validate_simple_valid", |b| {
        b.iter(|| schema_nav::validate_input(black_box(&simple_schema), black_box(&simple_valid)));
    });

    group.bench_function("validate_simple_invalid", |b| {
        b.iter(|| {
            schema_nav::validate_input(black_box(&simple_schema), black_box(&simple_invalid))
        });
    });

    // Deeply nested schema
    let nested_schema = json!({
        "type": "object",
        "required": ["data"],
        "properties": {
            "data": {
                "type": "object",
                "required": ["items"],
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["id", "value"],
                            "properties": {
                                "id": {"type": "string"},
                                "value": {"type": "number"},
                                "tags": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    let nested_valid = json!({
        "data": {
            "items": [
                {"id": "a", "value": 1.0, "tags": ["x", "y"]},
                {"id": "b", "value": 2.0, "tags": ["z"]},
            ]
        }
    });

    group.bench_function("validate_nested_valid", |b| {
        b.iter(|| schema_nav::validate_input(black_box(&nested_schema), black_box(&nested_valid)));
    });

    group.finish();
}

// ── Pipeline benchmarks ──────────────────────────────────────────────────

fn bench_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline");

    // Simple 2-step pipeline
    let two_step = r##"
name = "two-step"
[[steps]]
connector = "github"
operation = "list_issues"
[steps.input]
repo = "org/repo"
[[steps]]
connector = "slack"
operation = "send_message"
[steps.input]
channel = "#dev"
"##;

    group.bench_function("parse_2_step", |b| {
        b.iter(|| fwc::pipe::parse_pipeline_definition(black_box(two_step)));
    });

    // 10-step pipeline
    let mut ten_step = String::from("name = \"ten-step\"\n");
    for i in 0..10 {
        write!(
            &mut ten_step,
            r#"[[steps]]
connector = "conn_{i}"
operation = "op_{i}"
[steps.input]
key = "value_{i}"
"#,
        )
        .expect("writing benchmark fixture should not fail");
    }

    group.bench_function("parse_10_step", |b| {
        b.iter(|| fwc::pipe::parse_pipeline_definition(black_box(&ten_step)));
    });

    // 20-step pipeline
    let mut twenty_step = String::from("name = \"twenty-step\"\n");
    for i in 0..20 {
        write!(
            &mut twenty_step,
            r#"[[steps]]
connector = "conn_{i}"
operation = "op_{i}"
[steps.input]
key = "value_{i}"
"#,
        )
        .expect("writing benchmark fixture should not fail");
    }

    group.bench_function("parse_20_step", |b| {
        b.iter(|| fwc::pipe::parse_pipeline_definition(black_box(&twenty_step)));
    });

    group.finish();
}

// ── Criterion harness ─────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_search,
    bench_schema_validation,
    bench_pipeline
);
criterion_main!(benches);
