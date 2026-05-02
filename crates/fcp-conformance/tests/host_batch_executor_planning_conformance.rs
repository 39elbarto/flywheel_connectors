//! `fcp_host::BatchExecutor` validation + planning + execution
//! contract conformance.
//!
//! `host_batch_invoke_contract_conformance.rs` already pins the
//! JSON wire format. This file pins the EXECUTION semantics every
//! batch invocation flows through:
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`BatchExecutor::validate` rejection contract**:
//!    - empty operations → `InvalidFilter("batch has no operations")`
//!    - duplicate operation id → `InvalidFilter("duplicate operation id: <id>")`
//!    - max_parallelism=0 → `InvalidFilter("max_parallelism must be > 0")`
//!    - unknown depends_on → `InvalidFilter("operation '<a>' depends on unknown operation '<b>'")`
//!    - self-dependency → `InvalidFilter("operation '<a>' depends on itself")`
//!    - dependency cycle → `InvalidFilter("dependency cycle detected ...")`
//! 2. **`plan` topological tiering** — independent ops in tier 0;
//!    A→B chain produces depth=2; diamond A→{B,C}→D produces
//!    depth=3, max_width=2.
//! 3. **`ExecutionPlan::depth`/`max_width`** — depth=tier count;
//!    max_width=largest tier; empty plan max_width=0.
//! 4. **`execute_sync` happy path** — handler returns success → all
//!    operations complete in topological order; final BatchStatus is
//!    Success; completed=N, failed=0, skipped=0.
//! 5. **`execute_sync` stop_on_first_error** — first failure aborts;
//!    downstream tiers Skipped; final BatchStatus=Aborted.
//! 6. **`execute_sync` continue-on-failure** (default) — partial
//!    failures yield BatchStatus::PartialSuccess.
//! 7. **`ZoneRegistry`** — register/get_zone round-trip; absent tool
//!    returns None.

use fcp_prelude::ZoneId;
use fcp_host::{
    BatchExecutor, BatchInvokeRequest, BatchOperation, BatchOperationError, BatchOptions,
    BatchStatus, ExecutionPlan, ExecutionTier, OperationResultStatus, ZoneRegistry,
};

fn op(id: &str, depends_on: Vec<&str>) -> BatchOperation {
    BatchOperation {
        id: id.into(),
        tool: "fcp.test.noop".into(),
        input: serde_json::json!({}),
        depends_on: depends_on.into_iter().map(String::from).collect(),
        zone: None,
    }
}

fn req(operations: Vec<BatchOperation>, options: BatchOptions) -> BatchInvokeRequest {
    BatchInvokeRequest {
        operations,
        options,
    }
}

// ─── validate rejection contract ────────────────────────────────────

#[test]
fn validate_rejects_empty_operations() {
    let exec = BatchExecutor::new();
    let r = exec.validate(&req(vec![], BatchOptions::default()));
    let err = r.expect_err("empty MUST fail");
    let s = err.to_string();
    assert!(
        s.contains("batch has no operations"),
        "Display MUST mention empty-batch reason; got {s}"
    );
}

#[test]
fn validate_rejects_duplicate_operation_id() {
    let exec = BatchExecutor::new();
    let r = exec.validate(&req(
        vec![op("a", vec![]), op("a", vec![])],
        BatchOptions::default(),
    ));
    let err = r.expect_err("dup MUST fail");
    let s = err.to_string();
    assert!(s.contains("duplicate operation id"), "got {s}");
    assert!(s.contains('a'), "got {s}");
}

#[test]
fn validate_rejects_zero_max_parallelism() {
    let exec = BatchExecutor::new();
    let mut opts = BatchOptions::default();
    opts.max_parallelism = 0;
    let r = exec.validate(&req(vec![op("a", vec![])], opts));
    let err = r.expect_err("zero parallelism MUST fail");
    assert!(err.to_string().contains("max_parallelism must be > 0"));
}

#[test]
fn validate_rejects_unknown_depends_on() {
    let exec = BatchExecutor::new();
    let r = exec.validate(&req(
        vec![op("a", vec!["nonexistent"])],
        BatchOptions::default(),
    ));
    let err = r.expect_err("unknown dep MUST fail");
    let s = err.to_string();
    assert!(s.contains("'a'"), "got {s}");
    assert!(s.contains("nonexistent"), "got {s}");
    assert!(s.contains("depends on unknown operation"), "got {s}");
}

#[test]
fn validate_rejects_self_dependency() {
    let exec = BatchExecutor::new();
    let r = exec.validate(&req(vec![op("a", vec!["a"])], BatchOptions::default()));
    let err = r.expect_err("self-dep MUST fail");
    let s = err.to_string();
    assert!(s.contains("depends on itself"), "got {s}");
}

#[test]
fn validate_rejects_dependency_cycle() {
    let exec = BatchExecutor::new();
    // a → b → a cycle.
    let r = exec.validate(&req(
        vec![op("a", vec!["b"]), op("b", vec!["a"])],
        BatchOptions::default(),
    ));
    let err = r.expect_err("cycle MUST fail");
    assert!(err.to_string().contains("dependency cycle"));
}

#[test]
fn validate_accepts_legal_batch_with_chain() {
    let exec = BatchExecutor::new();
    // a → b → c (chain)
    let r = exec.validate(&req(
        vec![op("a", vec![]), op("b", vec!["a"]), op("c", vec!["b"])],
        BatchOptions::default(),
    ));
    assert!(r.is_ok(), "legal chain MUST validate; got {r:?}");
}

// ─── plan: topological tiering ──────────────────────────────────────

#[test]
fn plan_independent_ops_form_single_tier() {
    let exec = BatchExecutor::new();
    let plan = exec
        .plan(&req(
            vec![op("a", vec![]), op("b", vec![]), op("c", vec![])],
            BatchOptions::default(),
        ))
        .expect("plan");
    assert_eq!(plan.depth(), 1, "all-independent MUST be depth 1");
    assert_eq!(plan.max_width(), 3, "all-independent MUST be max_width=3");
    assert_eq!(plan.total_operations, 3);
}

#[test]
fn plan_chain_produces_sequential_tiers() {
    let exec = BatchExecutor::new();
    // a → b → c
    let plan = exec
        .plan(&req(
            vec![op("a", vec![]), op("b", vec!["a"]), op("c", vec!["b"])],
            BatchOptions::default(),
        ))
        .expect("plan");
    assert_eq!(plan.depth(), 3, "3-chain MUST produce 3 tiers");
    assert_eq!(plan.max_width(), 1, "chain has width 1");
    // First tier MUST contain only "a".
    let tier0 = plan
        .tiers
        .first()
        .expect("at least one tier")
        .operation_ids
        .clone();
    assert_eq!(tier0, vec!["a".to_string()], "first tier is the root");
}

#[test]
fn plan_diamond_produces_depth_three_max_width_two() {
    let exec = BatchExecutor::new();
    // A → {B, C} → D
    let plan = exec
        .plan(&req(
            vec![
                op("a", vec![]),
                op("b", vec!["a"]),
                op("c", vec!["a"]),
                op("d", vec!["b", "c"]),
            ],
            BatchOptions::default(),
        ))
        .expect("plan");
    assert_eq!(plan.depth(), 3, "diamond MUST have 3 tiers");
    assert_eq!(plan.max_width(), 2, "middle tier MUST hold both B and C");
}

#[test]
fn execution_plan_max_width_handles_empty_plan() {
    let plan = ExecutionPlan {
        tiers: vec![],
        total_operations: 0,
    };
    assert_eq!(plan.depth(), 0);
    assert_eq!(
        plan.max_width(),
        0,
        "empty plan max_width MUST be 0 (no panic from .max() on empty iterator)"
    );
}

#[test]
fn execution_tier_independent_ops_grouped_in_first_tier() {
    let exec = BatchExecutor::new();
    let plan = exec
        .plan(&req(
            vec![op("x", vec![]), op("y", vec![]), op("z", vec![])],
            BatchOptions::default(),
        ))
        .expect("plan");
    let tier0_ids: std::collections::HashSet<_> = plan
        .tiers
        .first()
        .expect("tier 0")
        .operation_ids
        .iter()
        .cloned()
        .collect();
    assert_eq!(
        tier0_ids,
        ["x", "y", "z"]
            .iter()
            .map(|s| (*s).to_string())
            .collect::<std::collections::HashSet<_>>(),
        "all 3 independent ops MUST be in tier 0 (order not specified)"
    );
}

// ─── execute_sync semantics ─────────────────────────────────────────

#[test]
fn execute_sync_all_success_yields_batchstatus_success() {
    let exec = BatchExecutor::new();
    let request = req(
        vec![op("a", vec![]), op("b", vec!["a"])],
        BatchOptions::default(),
    );
    let resp = exec
        .execute_sync(&request, |_op| Ok(serde_json::json!("ok")))
        .expect("execute");
    assert_eq!(resp.status, BatchStatus::Success);
    assert_eq!(resp.completed, 2);
    assert_eq!(resp.failed, 0);
    assert_eq!(resp.skipped, 0);
    assert_eq!(resp.results.len(), 2);
    for r in &resp.results {
        assert_eq!(r.status, OperationResultStatus::Success);
        assert!(r.output.is_some());
    }
}

#[test]
fn execute_sync_stop_on_first_error_aborts_downstream_tiers() {
    let exec = BatchExecutor::new();
    let mut opts = BatchOptions::default();
    opts.stop_on_first_error = true;
    // a (fail) → b (would-run-after-a) → c (depends on b)
    let request = req(
        vec![op("a", vec![]), op("b", vec!["a"]), op("c", vec!["b"])],
        opts,
    );
    let resp = exec
        .execute_sync(&request, |o| {
            if o.id == "a" {
                Err(BatchOperationError {
                    code: "boom".into(),
                    message: "simulated failure".into(),
                    retry_after_ms: None,
                })
            } else {
                Ok(serde_json::json!("ok"))
            }
        })
        .expect("execute");
    assert_eq!(
        resp.status,
        BatchStatus::Aborted,
        "stop_on_first_error MUST yield BatchStatus::Aborted when first op fails"
    );
    assert_eq!(resp.failed, 1);
    assert_eq!(
        resp.skipped, 2,
        "downstream tiers MUST be skipped after first failure"
    );
    let a = resp.results.iter().find(|r| r.id == "a").expect("a");
    assert_eq!(a.status, OperationResultStatus::Error);
    let b = resp.results.iter().find(|r| r.id == "b").expect("b");
    assert_eq!(b.status, OperationResultStatus::Skipped);
    let c = resp.results.iter().find(|r| r.id == "c").expect("c");
    assert_eq!(c.status, OperationResultStatus::Skipped);
}

#[test]
fn execute_sync_continue_on_failure_yields_partial_success() {
    let exec = BatchExecutor::new();
    // Two independent ops; one fails. continue_on_failure (default).
    let request = req(
        vec![op("a", vec![]), op("b", vec![])],
        BatchOptions::default(),
    );
    let resp = exec
        .execute_sync(&request, |o| {
            if o.id == "a" {
                Err(BatchOperationError {
                    code: "x".into(),
                    message: "fail".into(),
                    retry_after_ms: None,
                })
            } else {
                Ok(serde_json::json!("ok"))
            }
        })
        .expect("execute");
    assert_eq!(
        resp.status,
        BatchStatus::PartialSuccess,
        "1 success + 1 fail with stop=false MUST yield PartialSuccess"
    );
    assert_eq!(resp.completed, 1);
    assert_eq!(resp.failed, 1);
}

#[test]
fn execute_sync_results_carry_duration_ms_field() {
    let exec = BatchExecutor::new();
    let request = req(vec![op("a", vec![])], BatchOptions::default());
    let resp = exec
        .execute_sync(&request, |_| Ok(serde_json::json!(true)))
        .expect("execute");
    let result = resp.results.first().expect("result");
    // duration_ms is u64; assert the field exists and is well-formed.
    let _: u64 = result.duration_ms;
}

// ─── ZoneRegistry ───────────────────────────────────────────────────

#[test]
fn zone_registry_register_and_lookup_round_trip() {
    let mut r = ZoneRegistry::new();
    r.register("fcp.discord.send_message", ZoneId::work());
    let z = r.get_zone("fcp.discord.send_message").expect("registered");
    assert_eq!(z, &ZoneId::work());
}

#[test]
fn zone_registry_returns_none_for_unregistered_tool() {
    let r = ZoneRegistry::new();
    assert!(r.get_zone("never-registered").is_none());
}

// ─── ExecutionTier struct sanity ───────────────────────────────────

#[test]
fn execution_tier_struct_is_constructible_with_op_ids() {
    let t = ExecutionTier {
        operation_ids: vec!["a".into(), "b".into()],
    };
    assert_eq!(t.operation_ids.len(), 2);
}
