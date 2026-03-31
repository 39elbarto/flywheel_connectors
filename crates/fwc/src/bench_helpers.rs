//! Performance benchmark helpers for CUAL operations.
//!
//! Measures latency of search, batch, pipeline, schema validation, and recovery
//! operations using `std::time::Instant`.  Each benchmark runs 1000 iterations
//! and reports mean/median/p95 timing.  Tests always pass -- they measure and
//! print results rather than asserting on timing thresholds.

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    use serde_json::{Value, json};

    use crate::batch::{BatchInputs, BatchPlan, BatchSummary, ItemResult, ItemStatus, OnError};
    use crate::e2e_scenario::{ScenarioStep, topological_sort_steps};
    use crate::pipe::{
        apply_mapping, parse_map_expression, parse_pipeline_definition,
        validate_pipeline_definition,
    };
    use crate::pipeline_cond::{PipelineContext, evaluate_condition, parse_condition};
    use crate::readiness::{
        ConnectorDetail, ConnectorState, ConnectorSummary, DiscoveredConnector,
        DiscoveredOperation, MetadataField, OperationSummary,
    };
    use crate::recovery::{
        closest_matches, command_alias, levenshtein, resolve_command, typo_correction,
    };
    use crate::schema_nav;
    use crate::search::{SearchFilters, search_operations};

    // ── Target thresholds (informational) ─────────────────────────────────

    /// Target for search operations: < 5ms across 85+ connectors.
    const TARGET_SEARCH_MS: f64 = 5.0;
    /// Target for batch operations: < 10ms for 50-operation batch.
    const TARGET_BATCH_MS: f64 = 10.0;
    /// Target for pipeline operations: < 10ms for 10-step pipeline.
    const TARGET_PIPELINE_MS: f64 = 10.0;
    /// Target for schema validation: < 1ms for typical schemas.
    const TARGET_SCHEMA_MS: f64 = 1.0;
    /// Target for recovery/resolution: < 1ms.
    const TARGET_RECOVERY_MS: f64 = 1.0;

    /// Number of iterations per benchmark.
    const ITERATIONS: usize = 1000;
    /// Number of warmup iterations (not measured).
    const WARMUP: usize = 50;

    // ── Statistics helper ─────────────────────────────────────────────────

    struct BenchStats {
        name: &'static str,
        mean: Duration,
        median: Duration,
        p95: Duration,
        min: Duration,
        max: Duration,
        target_ms: f64,
    }

    impl BenchStats {
        #[allow(clippy::cast_precision_loss)]
        fn report(&self) {
            let mean_us = self.mean.as_nanos() as f64 / 1_000.0;
            let median_us = self.median.as_nanos() as f64 / 1_000.0;
            let p95_us = self.p95.as_nanos() as f64 / 1_000.0;
            let min_us = self.min.as_nanos() as f64 / 1_000.0;
            let max_us = self.max.as_nanos() as f64 / 1_000.0;
            let target_us = self.target_ms * 1_000.0;
            let status = if (self.p95.as_nanos() as f64 / 1_000_000.0) <= self.target_ms {
                "OK"
            } else {
                "OVER"
            };
            eprintln!(
                "[BENCH] {name:<45} mean={mean_us:>9.1}us  median={median_us:>9.1}us  \
                 p95={p95_us:>9.1}us  min={min_us:>9.1}us  max={max_us:>9.1}us  \
                 target={target_us:>9.1}us  [{status}]",
                name = self.name,
            );
        }
    }

    /// Run `f` for WARMUP+ITERATIONS times, returning statistics.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]
    fn run_bench<F, R>(name: &'static str, target_ms: f64, mut f: F) -> BenchStats
    where
        F: FnMut() -> R,
    {
        // Warmup (not measured).
        for _ in 0..WARMUP {
            black_box(f());
        }

        // Measured iterations.
        let mut durations: Vec<Duration> = Vec::with_capacity(ITERATIONS);
        for _ in 0..ITERATIONS {
            let start = Instant::now();
            black_box(f());
            durations.push(start.elapsed());
        }

        durations.sort();

        let sum: Duration = durations.iter().sum();
        let mean = sum / ITERATIONS as u32;
        let median = durations[ITERATIONS / 2];
        let p95 = durations[(ITERATIONS as f64 * 0.95) as usize];
        let min = durations[0];
        let max = durations[ITERATIONS - 1];

        BenchStats {
            name,
            mean,
            median,
            p95,
            min,
            max,
            target_ms,
        }
    }

    // ── Fixture builders ──────────────────────────────────────────────────

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
                supports_simulate: MetadataField::Unknown,
            },
            input_schema: json!({"type": "object", "properties": {"q": {"type": "string"}}}),
            output_schema: json!({"type": "object"}),
            approval_mode: String::new(),
            when_to_use: format!("Use {id} to perform this operation."),
            common_mistakes: vec![],
            examples: vec![],
            related: vec![],
            network_constraints: None,
            rate_limits: None,
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
            runtime_format: "wasi".to_owned(),
            state_model: MetadataField::Unknown,
            supported_zones: vec!["z:work".to_owned()],
            detail: ConnectorDetail {
                summary: ConnectorSummary {
                    id: format!("fcp.{slug}"),
                    name: format!("{slug} Connector"),
                    version: "1.0.0".to_owned(),
                    description: format!("FCP connector for {slug}"),
                    archetypes: MetadataField::Unknown,
                    state: ConnectorState::Unknown,
                    operation_count: ops.len(),
                    max_risk: "medium".to_owned(),
                    has_events: MetadataField::Unknown,
                },
                operations: op_summaries,
                config_schema: MetadataField::Unknown,
                health: MetadataField::Unknown,
                rate_limits: MetadataField::Unknown,
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

    /// Build a valid pipeline TOML string with `n` steps.
    fn pipeline_toml(name: &str, n: usize) -> String {
        let mut s = format!("[pipeline]\nname = \"{name}\"\ndescription = \"bench pipeline\"\n\n");
        for i in 0..n {
            let _ = write!(
                s,
                "[[steps]]\nid = \"step_{i}\"\noperation = \"connector_{i}.op_0\"\n"
            );
            if i > 0 {
                let _ = writeln!(s, "depends_on = [\"step_{}\"]", i - 1);
            }
            let _ = write!(s, "[steps.input]\nkey = \"value_{i}\"\n\n");
        }
        s
    }

    /// Build a pipeline TOML with conditional steps.
    fn pipeline_toml_with_conditions(n: usize) -> String {
        let mut s = String::from(
            "[pipeline]\nname = \"conditional-bench\"\ndescription = \"bench conditions\"\n\n",
        );
        for i in 0..n {
            let _ = write!(
                s,
                "[[steps]]\nid = \"step_{i}\"\noperation = \"connector_{i}.op_0\"\n"
            );
            if i > 0 {
                let _ = writeln!(s, "depends_on = [\"step_{}\"]", i - 1);
                let _ = writeln!(
                    s,
                    "condition = \"{{{{steps.step_{}.output.status}}}} == 'ok'\"",
                    i - 1
                );
            }
            let _ = write!(s, "[steps.input]\nkey = \"value_{i}\"\n\n");
        }
        s
    }

    /// Build scenario steps for topological sort benchmarking.
    fn make_scenario_steps(n: usize) -> Vec<ScenarioStep> {
        (0..n)
            .map(|i| ScenarioStep {
                id: format!("step_{i}"),
                command: format!("fwc invoke connector_{i}.op_0"),
                expected_exit_code: 0,
                expected_output_contains: vec![],
                expected_output_not_contains: vec![],
                depends_on: if i > 0 {
                    vec![format!("step_{}", i - 1)]
                } else {
                    vec![]
                },
                capture_as: None,
            })
            .collect()
    }

    // ======================================================================
    // 1. SEARCH BENCHMARKS
    // ======================================================================

    #[test]
    fn bench_search_single_keyword() {
        // 85+ connectors with 10 ops each = 850+ operations
        let connectors = make_connectors(90, 10);
        let filters = SearchFilters::default();
        let stats = run_bench("search_single_keyword_90x10", TARGET_SEARCH_MS, || {
            search_operations(&connectors, "operation", &filters)
        });
        stats.report();
    }

    #[test]
    fn bench_search_multi_keyword() {
        let connectors = make_connectors(90, 10);
        let filters = SearchFilters::default();
        let stats = run_bench("search_multi_keyword_90x10", TARGET_SEARCH_MS, || {
            search_operations(&connectors, "connector 5 operation", &filters)
        });
        stats.report();
    }

    #[test]
    fn bench_search_with_filters() {
        let connectors = make_connectors(90, 10);
        let filters = SearchFilters {
            capability: Some("read".to_owned()),
            zone: Some("z:work".to_owned()),
            connector: Some("connector_42".to_owned()),
            ..Default::default()
        };
        let stats = run_bench(
            "search_with_zone_connector_filter_90x10",
            TARGET_SEARCH_MS,
            || search_operations(&connectors, "operation", &filters),
        );
        stats.report();
    }

    // ======================================================================
    // 2. BATCH BENCHMARKS
    // ======================================================================

    #[test]
    fn bench_batch_plan_small() {
        // Build 5 batch items
        let json_array: Vec<Value> = (0..5)
            .map(|i| json!({"repo": format!("org/repo-{i}"), "state": "open"}))
            .collect();
        let json_str = serde_json::to_string(&json_array).unwrap();

        let stats = run_bench("batch_plan_small_5_items", TARGET_BATCH_MS, || {
            let inputs = BatchInputs::from_json_array(&json_str).unwrap();
            let plan = BatchPlan {
                operation: "github.list_issues".to_owned(),
                input_count: inputs.len(),
                concurrency: 4,
                on_error: OnError::Continue,
                preview_inputs: inputs.items[..2.min(inputs.len())].to_vec(),
            };
            // Also compute a summary from mock results
            let results: Vec<ItemResult> = (0..inputs.len())
                .map(|i| ItemResult {
                    index: i,
                    status: ItemStatus::Success,
                    result: Some(json!({"count": i})),
                    error: None,
                })
                .collect();
            let _summary = BatchSummary::from_results(&results);
            (plan, results)
        });
        stats.report();
    }

    #[test]
    fn bench_batch_plan_large() {
        // Build 50 batch items
        let json_array: Vec<Value> = (0..50)
            .map(|i| json!({"repo": format!("org/repo-{i}"), "state": "open", "labels": ["bug", "p1"]}))
            .collect();
        let json_str = serde_json::to_string(&json_array).unwrap();

        let stats = run_bench("batch_plan_large_50_items", TARGET_BATCH_MS, || {
            let inputs = BatchInputs::from_json_array(&json_str).unwrap();
            let plan = BatchPlan {
                operation: "github.list_issues".to_owned(),
                input_count: inputs.len(),
                concurrency: 8,
                on_error: OnError::Continue,
                preview_inputs: inputs.items[..5.min(inputs.len())].to_vec(),
            };
            let results: Vec<ItemResult> = (0..inputs.len())
                .map(|i| ItemResult {
                    index: i,
                    status: if i % 10 == 0 {
                        ItemStatus::Error
                    } else {
                        ItemStatus::Success
                    },
                    result: if i % 10 != 0 {
                        Some(json!({"count": i}))
                    } else {
                        None
                    },
                    error: if i % 10 == 0 {
                        Some(json!({"message": "rate limited"}))
                    } else {
                        None
                    },
                })
                .collect();
            let _summary = BatchSummary::from_results(&results);
            (plan, results)
        });
        stats.report();
    }

    #[test]
    fn bench_batch_topo_sort() {
        // Topological sort of 50 scenario steps with linear dependencies
        let steps = make_scenario_steps(50);
        let stats = run_bench("batch_topo_sort_50_steps", TARGET_BATCH_MS, || {
            topological_sort_steps(&steps)
        });
        stats.report();
    }

    // ======================================================================
    // 3. PIPELINE BENCHMARKS
    // ======================================================================

    #[test]
    fn bench_pipeline_two_step() {
        let toml_str = pipeline_toml("two-step-bench", 2);
        let stats = run_bench("pipeline_parse_validate_2_step", TARGET_PIPELINE_MS, || {
            let def = parse_pipeline_definition(&toml_str).unwrap();
            let validation = validate_pipeline_definition(&def);
            (def, validation)
        });
        stats.report();
    }

    #[test]
    fn bench_pipeline_ten_step() {
        let toml_str = pipeline_toml("ten-step-bench", 10);
        let stats = run_bench(
            "pipeline_parse_validate_10_step",
            TARGET_PIPELINE_MS,
            || {
                let def = parse_pipeline_definition(&toml_str).unwrap();
                let validation = validate_pipeline_definition(&def);
                (def, validation)
            },
        );
        stats.report();
    }

    #[test]
    fn bench_pipeline_with_conditions() {
        let toml_str = pipeline_toml_with_conditions(10);
        let stats = run_bench(
            "pipeline_parse_validate_10_step_cond",
            TARGET_PIPELINE_MS,
            || {
                let def = parse_pipeline_definition(&toml_str).unwrap();
                let validation = validate_pipeline_definition(&def);
                // Also parse the condition expressions
                let conditions: Vec<_> = def
                    .steps
                    .iter()
                    .filter_map(|step| step.condition.as_deref())
                    .map(parse_condition)
                    .collect();
                (def, validation, conditions)
            },
        );
        stats.report();
    }

    // ======================================================================
    // 4. SCHEMA VALIDATION BENCHMARKS
    // ======================================================================

    #[test]
    fn bench_schema_validate_simple() {
        let schema = json!({
            "type": "object",
            "required": ["name", "count"],
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "integer"},
                "active": {"type": "boolean"}
            }
        });
        let input = json!({"name": "test", "count": 42, "active": true});

        let stats = run_bench("schema_validate_simple_flat", TARGET_SCHEMA_MS, || {
            schema_nav::validate_input(&schema, &input)
        });
        stats.report();
    }

    #[test]
    fn bench_schema_validate_nested() {
        let schema = json!({
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
                                    "metadata": {
                                        "type": "object",
                                        "properties": {
                                            "tags": {
                                                "type": "array",
                                                "items": {"type": "string"}
                                            },
                                            "priority": {"type": "integer"},
                                            "nested": {
                                                "type": "object",
                                                "properties": {
                                                    "deep": {"type": "string"},
                                                    "deeper": {
                                                        "type": "object",
                                                        "properties": {
                                                            "deepest": {"type": "boolean"}
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let input = json!({
            "data": {
                "items": [
                    {
                        "id": "a",
                        "value": 1.0,
                        "metadata": {
                            "tags": ["x", "y"],
                            "priority": 1,
                            "nested": {
                                "deep": "hello",
                                "deeper": {"deepest": true}
                            }
                        }
                    },
                    {
                        "id": "b",
                        "value": 2.5,
                        "metadata": {
                            "tags": ["z"],
                            "priority": 2,
                            "nested": {
                                "deep": "world",
                                "deeper": {"deepest": false}
                            }
                        }
                    },
                    {"id": "c", "value": 3.0}
                ]
            }
        });

        let stats = run_bench("schema_validate_deeply_nested", TARGET_SCHEMA_MS, || {
            schema_nav::validate_input(&schema, &input)
        });
        stats.report();
    }

    #[test]
    fn bench_template_generate() {
        let schema = json!({
            "type": "object",
            "required": ["repo", "title", "body"],
            "properties": {
                "repo": {"type": "string", "description": "Repository slug"},
                "title": {"type": "string", "description": "Issue title"},
                "body": {"type": "string", "description": "Issue body"},
                "labels": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Labels to apply"
                },
                "assignees": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Users to assign"
                },
                "milestone": {"type": "integer", "description": "Milestone number"},
                "draft": {"type": "boolean", "default": false}
            }
        });

        let stats = run_bench("template_generate_from_schema", TARGET_SCHEMA_MS, || {
            let template = schema_nav::scaffold_template(&schema);
            let fields = schema_nav::walk_schema(&schema, &[]);
            (template, fields)
        });
        stats.report();
    }

    // ======================================================================
    // 5. RECOVERY BENCHMARKS
    // ======================================================================

    #[test]
    fn bench_command_resolution() {
        let tokens = [
            "ls",
            "find",
            "grep",
            "info",
            "inspect",
            "run",
            "execute",
            "call",
            "exec",
            "send",
            "preview",
            "dry-run",
            "healthcheck",
            "diagnose",
            "budgets",
            "caps",
            "add",
            "upgrade",
            "lock",
        ];
        let stats = run_bench("command_resolution_19_aliases", TARGET_RECOVERY_MS, || {
            let mut resolved = Vec::with_capacity(tokens.len());
            for token in &tokens {
                resolved.push((
                    command_alias(token),
                    typo_correction(token),
                    resolve_command(token),
                ));
            }
            resolved
        });
        stats.report();
    }

    #[test]
    fn bench_typo_suggestion() {
        let candidates: &[&str] = &[
            "list",
            "search",
            "show",
            "ops",
            "schema",
            "invoke",
            "simulate",
            "health",
            "status",
            "doctor",
            "budget",
            "capabilities",
            "install",
            "update",
            "pin",
            "unpin",
            "config",
            "pipeline",
            "guide",
            "task",
            "plan",
            "explain",
            "history",
            "events",
            "watch",
            "batch",
        ];
        let typos = [
            "lisst",
            "serch",
            "shwo",
            "opss",
            "schma",
            "invok",
            "simualte",
            "helth",
            "statsu",
            "doctr",
            "buget",
            "capabilites",
            "instal",
            "updte",
            "piin",
            "unpn",
            "confg",
            "pipelne",
            "gude",
            "tsk",
        ];

        let stats = run_bench(
            "typo_suggestion_20_typos_26_candidates",
            TARGET_RECOVERY_MS,
            || {
                let mut suggestions = Vec::with_capacity(typos.len());
                for typo in &typos {
                    suggestions.push(closest_matches(typo, candidates, 3, 3));
                }
                suggestions
            },
        );
        stats.report();
    }

    // ======================================================================
    // ADDITIONAL BENCHMARKS
    // ======================================================================

    #[test]
    fn bench_levenshtein_distance() {
        let pairs = [
            ("kubernetes", "kuberentes"),
            ("elasticsearch", "elastcsearch"),
            ("list_repositories", "list_repostories"),
            ("send_message", "send_mesage"),
            ("create_deployment", "creat_deployment"),
            ("invoke", "invok"),
            ("simulate", "simualte"),
            ("pipeline", "pipelne"),
            ("configure", "confgure"),
            ("authenticate", "authenicate"),
        ];
        let stats = run_bench("levenshtein_10_pairs", TARGET_RECOVERY_MS, || {
            let mut results = Vec::with_capacity(pairs.len());
            for (a, b) in &pairs {
                results.push(levenshtein(a, b));
            }
            results
        });
        stats.report();
    }

    #[test]
    fn bench_mapping_parse_and_apply() {
        let mapping_expr = "issues[0].title -> title, issues[0].number -> issue_id, \
                            issues[0].labels -> tags, issues[0].state -> status";
        let source_output = json!({
            "issues": [
                {
                    "title": "Fix CI pipeline",
                    "number": 42,
                    "labels": ["bug", "ci"],
                    "state": "open"
                }
            ]
        });

        let stats = run_bench("mapping_parse_and_apply", TARGET_PIPELINE_MS, || {
            let spec = parse_map_expression(mapping_expr).unwrap();
            let result = apply_mapping(&source_output, &spec);
            (spec, result)
        });
        stats.report();
    }

    #[test]
    fn bench_batch_jsonl_parse() {
        // Build a 100-line JSONL string
        let mut jsonl = String::with_capacity(100 * 80);
        for i in 0..100 {
            let _ = writeln!(
                jsonl,
                r#"{{"repo": "org/repo-{i}", "state": "open", "page": {i}}}"#
            );
        }

        let stats = run_bench("batch_jsonl_parse_100_lines", TARGET_BATCH_MS, || {
            BatchInputs::from_jsonl(&jsonl).unwrap()
        });
        stats.report();
    }

    #[test]
    fn bench_batch_template_expand() {
        let template = r#"{"repo": "org/{{item}}", "state": "open"}"#;
        let items = (0..50)
            .map(|i| format!("repo-{i}"))
            .collect::<Vec<_>>()
            .join(",");

        let stats = run_bench("batch_template_expand_50_items", TARGET_BATCH_MS, || {
            BatchInputs::from_template(template, &items).unwrap()
        });
        stats.report();
    }

    #[test]
    fn bench_schema_walk_complex() {
        let schema = json!({
            "type": "object",
            "required": ["name", "spec"],
            "properties": {
                "name": {"type": "string"},
                "namespace": {"type": "string", "default": "default"},
                "spec": {
                    "type": "object",
                    "required": ["containers"],
                    "properties": {
                        "replicas": {"type": "integer", "minimum": 1, "maximum": 100},
                        "containers": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["name", "image"],
                                "properties": {
                                    "name": {"type": "string"},
                                    "image": {"type": "string"},
                                    "ports": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "containerPort": {"type": "integer"},
                                                "protocol": {
                                                    "type": "string",
                                                    "enum": ["TCP", "UDP"]
                                                }
                                            }
                                        }
                                    },
                                    "env": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "name": {"type": "string"},
                                                "value": {"type": "string"}
                                            }
                                        }
                                    },
                                    "resources": {
                                        "type": "object",
                                        "properties": {
                                            "limits": {
                                                "type": "object",
                                                "properties": {
                                                    "cpu": {"type": "string"},
                                                    "memory": {"type": "string"}
                                                }
                                            },
                                            "requests": {
                                                "type": "object",
                                                "properties": {
                                                    "cpu": {"type": "string"},
                                                    "memory": {"type": "string"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "metadata": {
                    "type": "object",
                    "properties": {
                        "labels": {"type": "object"},
                        "annotations": {"type": "object"}
                    }
                }
            }
        });

        let stats = run_bench("schema_walk_k8s_like_complex", TARGET_SCHEMA_MS, || {
            let fields = schema_nav::walk_schema(&schema, &[]);
            let _template = schema_nav::scaffold_template(&schema);
            let _required = schema_nav::required_only_fields(&fields);
            let _summary = schema_nav::schema_summary(&fields);
            fields
        });
        stats.report();
    }

    #[test]
    fn bench_condition_parse_and_evaluate() {
        let conditions = [
            "{{steps.fetch.output.status}} == 'ok'",
            "{{steps.check.output.count}} > 0",
            "{{steps.validate.output.valid}} == true",
            "{{steps.fetch.output.items}} != null",
            "{{steps.a.output.x}} == 'ok' && {{steps.b.output.y}} > 10",
        ];

        let mut ctx = PipelineContext::new();
        ctx.set_output("fetch", json!({"status": "ok", "items": [1, 2, 3]}));
        ctx.set_output("check", json!({"count": 5}));
        ctx.set_output("validate", json!({"valid": true}));
        ctx.set_output("a", json!({"x": "ok"}));
        ctx.set_output("b", json!({"y": 20}));

        let stats = run_bench(
            "condition_parse_evaluate_5_exprs",
            TARGET_PIPELINE_MS,
            || {
                let mut results = Vec::with_capacity(conditions.len());
                for cond_str in &conditions {
                    let cond = parse_condition(cond_str);
                    if let Ok(ref c) = cond {
                        results.push(evaluate_condition(&c.parsed, &ctx));
                    }
                }
                results
            },
        );
        stats.report();
    }

    #[test]
    fn bench_search_empty_query() {
        // Edge case: empty/whitespace query should still be fast
        let connectors = make_connectors(90, 10);
        let filters = SearchFilters::default();
        let stats = run_bench("search_empty_query_90x10", TARGET_SEARCH_MS, || {
            search_operations(&connectors, "", &filters)
        });
        stats.report();
    }

    #[test]
    fn bench_topo_sort_wide_dag() {
        // Wide DAG: 50 steps, each depending on step_0 (fan-out pattern)
        let mut steps: Vec<ScenarioStep> = Vec::with_capacity(50);
        steps.push(ScenarioStep {
            id: "step_0".to_owned(),
            command: "fwc invoke root.op_0".to_owned(),
            expected_exit_code: 0,
            expected_output_contains: vec![],
            expected_output_not_contains: vec![],
            depends_on: vec![],
            capture_as: None,
        });
        for i in 1..50 {
            steps.push(ScenarioStep {
                id: format!("step_{i}"),
                command: format!("fwc invoke connector_{i}.op_0"),
                expected_exit_code: 0,
                expected_output_contains: vec![],
                expected_output_not_contains: vec![],
                depends_on: vec!["step_0".to_owned()],
                capture_as: None,
            });
        }
        let stats = run_bench("topo_sort_wide_fan_out_50", TARGET_BATCH_MS, || {
            topological_sort_steps(&steps)
        });
        stats.report();
    }
}
