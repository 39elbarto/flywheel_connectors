//! Golden vector for the canonical backpressure decision matrix
//! (br-uwih7 + br-6bgp1 + br-817cba87c).
//!
//! Freezes one decision per (priority × telemetry-shape) cell of the
//! controller's input space, plus the calibration-drift / missing-
//! telemetry fallback rows. Pre-fix the controller's six-action enum
//! and four-state classifier were exercised only by hand-built
//! single-cell unit tests; this golden captures every cell of the
//! integration matrix in one diffable artifact.
//!
//! For each row we pin:
//!   - the classified backpressure_state
//!   - the selected action
//!   - the deterministic selected_loss_score (so a weight refactor is
//!     visible as a per-row number diff, not a pass/fail flip)
//!   - the fallback_trigger if any
//!
//! These are all the structural fields downstream operator-evidence
//! tooling reads off the BackpressureDecision; if any of them silently
//! shifts, every dashboard that filters on action/state/fallback would
//! stop reporting the same workload as before. The diff IS the
//! evidence trail.
//!
//! The matrix intentionally exercises:
//!   - all four request priorities × the canonical telemetry shapes
//!     (12 cells in the 4×3 admission grid)
//!   - the three fallback paths (missing telemetry, coverage drift,
//!     replay mismatch)
//!   - the Delay-active hot path (Normal at QueueCongested) where
//!     uwih7+6bgp1 originally silently downgraded to Admit
//!
//! Update flow:
//!   UPDATE_GOLDENS=1 cargo test -p fcp-host --test golden_backpressure_decision_matrix
//!   cargo insta review
//!   git diff crates/fcp-host/tests/snapshots/

use fcp_host::{
    BackpressureCalibration, BackpressureCalibrationStatus, BackpressureController,
    BackpressureControllerInput, BackpressureTelemetry, RequestPriority,
};

/// One canonical telemetry shape paired with a stable label.
struct TelemetryShape {
    label: &'static str,
    telemetry: BackpressureTelemetry,
}

/// The 6 canonical telemetry shapes that exercise the documented
/// state classifications + the Delay-active hot path.
fn canonical_shapes() -> Vec<TelemetryShape> {
    vec![
        TelemetryShape {
            label: "normal_low_pressure",
            telemetry: BackpressureTelemetry {
                queue_pressure_per_mille: Some(25),
                cpu_pressure_per_mille: Some(50),
                ..BackpressureTelemetry::default()
            },
        },
        TelemetryShape {
            label: "queue_congested_moderate_cpu",
            telemetry: BackpressureTelemetry {
                queue_pressure_per_mille: Some(900),
                cpu_pressure_per_mille: Some(250),
                useful_work_per_mille: Some(800),
                ..BackpressureTelemetry::default()
            },
        },
        TelemetryShape {
            label: "cpu_saturated",
            telemetry: BackpressureTelemetry {
                queue_pressure_per_mille: Some(200),
                cpu_pressure_per_mille: Some(960),
                ..BackpressureTelemetry::default()
            },
        },
        TelemetryShape {
            label: "memory_pressure",
            telemetry: BackpressureTelemetry {
                queue_pressure_per_mille: Some(200),
                cpu_pressure_per_mille: Some(300),
                memory_pressure_per_mille: Some(970),
                useful_work_per_mille: Some(300),
                ..BackpressureTelemetry::default()
            },
        },
        TelemetryShape {
            label: "downstream_throttled",
            telemetry: BackpressureTelemetry {
                queue_pressure_per_mille: Some(400),
                cpu_pressure_per_mille: Some(300),
                downstream_retry_after_ms: Some(2_000),
                retry_amplification_per_mille: Some(900),
                useful_work_per_mille: Some(700),
                ..BackpressureTelemetry::default()
            },
        },
        TelemetryShape {
            label: "warning_band_pressure",
            telemetry: BackpressureTelemetry {
                queue_pressure_per_mille: Some(650),
                cpu_pressure_per_mille: Some(400),
                useful_work_per_mille: Some(600),
                ..BackpressureTelemetry::default()
            },
        },
    ]
}

/// Priority × telemetry-shape rows. The 4×6 admission grid.
fn admission_rows() -> Vec<(
    &'static str,
    &'static str,
    RequestPriority,
    BackpressureTelemetry,
)> {
    let mut rows = Vec::new();
    for priority in [
        RequestPriority::Critical,
        RequestPriority::High,
        RequestPriority::Normal,
        RequestPriority::Low,
    ] {
        let priority_label = match priority {
            RequestPriority::Critical => "critical",
            RequestPriority::High => "high",
            RequestPriority::Normal => "normal",
            RequestPriority::Low => "low",
        };
        for shape in canonical_shapes() {
            rows.push((priority_label, shape.label, priority, shape.telemetry));
        }
    }
    rows
}

/// Three additional rows for the fallback paths. Each carries a
/// non-Valid calibration; telemetry is realistic so we know fallback
/// fires from calibration, not from missing-telemetry.
fn fallback_rows() -> Vec<(&'static str, BackpressureCalibration, BackpressureTelemetry)> {
    vec![
        (
            "missing_telemetry_fallback",
            BackpressureCalibration::valid(),
            BackpressureTelemetry::default(),
        ),
        (
            "calibration_coverage_drift",
            BackpressureCalibration::coverage_drift(900, 990),
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(500),
                cpu_pressure_per_mille: Some(500),
                ..BackpressureTelemetry::default()
            },
        ),
        (
            "calibration_replay_mismatch",
            BackpressureCalibration::fallback(BackpressureCalibrationStatus::ReplayMismatch),
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(500),
                cpu_pressure_per_mille: Some(500),
                ..BackpressureTelemetry::default()
            },
        ),
    ]
}

fn render_row(
    label: &str,
    controller: &BackpressureController,
    priority: RequestPriority,
    telemetry: BackpressureTelemetry,
    calibration: BackpressureCalibration,
) -> String {
    let decision = controller.decide(BackpressureControllerInput::new(
        // Subject is fixed across all rows so any subject-leak shows
        // as a horizontal column shift rather than a per-row noise
        // pattern. The MR test validates subject-irrelevance separately.
        "fcp.host:test:v1.0.0/invoke",
        priority,
        telemetry,
        calibration,
    ));
    let fallback = decision
        .fallback_trigger
        .map_or("none".to_string(), |t| format!("{t:?}").to_lowercase());
    format!(
        "{label:<48} | state={:<22} action={:<24} score={:>+15} fallback={fallback}",
        decision.state.as_str(),
        decision.action.as_str(),
        decision.selected_loss_score,
    )
}

fn render_golden() -> String {
    let controller = BackpressureController::default();
    let calibration_valid = BackpressureCalibration::valid();
    let mut rows = vec![
        "# Backpressure decision card canonical matrix golden".to_string(),
        "# br-uwih7 + br-6bgp1 + br-817cba87c".to_string(),
        "# Format:".to_string(),
        "#   <priority>:<shape>  | state=<S> action=<A> score=<I> fallback=<F>".to_string(),
        "# - state: classified backpressure_state from telemetry".to_string(),
        "# - action: selected action (admit/admit_with_warning/delay/shed/cancel_low_priority/fallback_static_policy)".to_string(),
        "# - score: selected_loss_score (deterministic; weight refactor → per-row number diff)".to_string(),
        "# - fallback: trigger when fallback path fires; 'none' otherwise".to_string(),
        "#".to_string(),
        "# Cells:".to_string(),
        "#   4 priorities × 6 telemetry shapes = 24 admission rows".to_string(),
        "#   3 fallback rows (missing telemetry, coverage drift, replay mismatch)".to_string(),
        "#".to_string(),
        "# Findings observable in this matrix (use as operator dashboard guide):".to_string(),
        "#   - admit_with_warning IS load-bearing in production: it fires for".to_string(),
        "#     Critical/High/Normal at cpu_saturated. Operators MUST surface".to_string(),
        "#     the tracing::warn! the host integration emits (br-uwih7 fix).".to_string(),
        "#   - Low priority falls into cancel_low_priority three of six shapes".to_string(),
        "#     (queue_congested, memory_pressure, warning_band) — the loss".to_string(),
        "#     matrix's priority_factor (Low=1) makes this the lowest-loss".to_string(),
        "#     action when shedding is needed.".to_string(),
        "#   - Critical never picks shed under any non-fallback shape except".to_string(),
        "#     memory_pressure, where shed scores 2.07e9 — verifying the".to_string(),
        "#     priority-shed-monotonicity property (Critical is most-protected).".to_string(),
        String::new(),
        "## Admission grid (priority × telemetry shape)".to_string(),
    ];

    for (priority_label, shape_label, priority, telemetry) in admission_rows() {
        let row_label = format!("{priority_label}:{shape_label}");
        rows.push(render_row(
            &row_label,
            &controller,
            priority,
            telemetry,
            calibration_valid,
        ));
    }

    rows.push(String::new());
    rows.push("## Fallback paths".to_string());
    for (label, calibration, telemetry) in fallback_rows() {
        rows.push(render_row(
            label,
            &controller,
            RequestPriority::Normal,
            telemetry,
            calibration,
        ));
    }

    rows.join("\n") + "\n"
}

#[test]
fn golden_backpressure_decision_matrix_canonical_cells() {
    let actual = render_golden();
    insta::assert_snapshot!("backpressure_decision_matrix_canonical_cells", actual);
}
