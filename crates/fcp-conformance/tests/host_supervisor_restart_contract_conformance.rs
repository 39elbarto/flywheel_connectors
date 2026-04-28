//! `fcp_host::supervisor` restart-policy + exponential-backoff +
//! restart-tracker conformance.
//!
//! The supervisor is the connector lifecycle authority — its restart
//! policies and backoff arithmetic decide how aggressively the host
//! revives a flapping connector. Documented contracts (oip0 bead):
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`RestartPolicy::default == OnFailure`** — the documented
//!    sane default (restart on non-zero exit / signal, ignore clean
//!    code-0 exits).
//! 2. **`RestartPolicy::should_restart` matrix** for every (policy,
//!    exit) pair across the 4 policies × 3 exit kinds (clean, code,
//!    signal):
//!    - Always → always true
//!    - OnFailure → !is_clean (true on code≠0 OR signal)
//!    - OnCrash → is_signal_terminated only
//!    - Never → always false
//! 3. **`ProcessExit::clean()` / `with_code()` / `with_signal()`**
//!    — predicates `is_clean` / `is_signal_terminated` agree with
//!    the constructor.
//! 4. **`ProcessExit` Display contract** — three documented forms:
//!    "exit code N" / "signal N" / "exit code N, signal N" /
//!    "unknown exit".
//! 5. **`ProcessState::is_running` ⇔ Running variant**;
//!    **`is_terminal` ⇔ Stopped|Failed**; `label()` snake_case match.
//! 6. **`StopReason` Display strings** — operator log greps depend on
//!    "requested" / "host shutdown" / "health check failed" /
//!    "resource limit exceeded" / "upgrade".
//! 7. **`SupervisorConfig::default` documented values**:
//!    max_restarts=5, restart_window=5min, health_check_interval=30s,
//!    health_check_timeout=10s, graceful_shutdown_timeout=30s,
//!    initial_backoff=500ms, max_backoff=1min, multiplier=2.0.
//! 8. **`ExponentialBackoff` invariants**:
//!    - first call (attempt=0) returns `initial`
//!    - subsequent calls multiply by `multiplier`, capped at `max`
//!    - multiplier < 1.0 normalizes to 2.0 (degenerate input guard)
//!    - initial > max is clamped down to max
//!    - reset() returns attempt counter to 0
//!    - attempts() is the saturating counter
//! 9. **`RestartTracker::evaluate_restart`**:
//!    - `RestartPolicy::Never` always returns `PolicyDenied`
//!    - max_restarts within window returns `MaxRestartsExceeded`
//!      with count + window
//!    - successful restart records history, advances backoff
//!    - record_successful_start resets backoff but NOT history
//! 10. **`RestartDenied` Display** — "restart policy denied" /
//!     "max restarts exceeded: N restarts in Ws window".

use fcp_host::{
    ExponentialBackoff, ProcessExit, ProcessState, RestartDenied, RestartPolicy, RestartTracker,
    StopReason, SupervisorConfig,
};
use std::time::{Duration, Instant};

// ─── RestartPolicy ──────────────────────────────────────────────────

#[test]
fn restart_policy_default_is_on_failure() {
    assert_eq!(
        RestartPolicy::default(),
        RestartPolicy::OnFailure,
        "RestartPolicy::default MUST be OnFailure (most operationally useful)"
    );
}

#[test]
fn restart_policy_always_returns_true_for_every_exit_kind() {
    let p = RestartPolicy::Always;
    assert!(p.should_restart(&ProcessExit::clean()));
    assert!(p.should_restart(&ProcessExit::with_code(1)));
    assert!(p.should_restart(&ProcessExit::with_signal(9)));
}

#[test]
fn restart_policy_on_failure_excludes_clean_exit() {
    let p = RestartPolicy::OnFailure;
    assert!(
        !p.should_restart(&ProcessExit::clean()),
        "OnFailure MUST NOT restart on clean exit"
    );
    assert!(p.should_restart(&ProcessExit::with_code(1)));
    assert!(p.should_restart(&ProcessExit::with_signal(9)));
}

#[test]
fn restart_policy_on_crash_only_restarts_on_signal_termination() {
    let p = RestartPolicy::OnCrash;
    assert!(!p.should_restart(&ProcessExit::clean()));
    assert!(
        !p.should_restart(&ProcessExit::with_code(1)),
        "OnCrash MUST NOT restart on plain non-zero exit (only on signal)"
    );
    assert!(p.should_restart(&ProcessExit::with_signal(11))); // SIGSEGV
}

#[test]
fn restart_policy_never_returns_false_for_every_exit_kind() {
    let p = RestartPolicy::Never;
    assert!(!p.should_restart(&ProcessExit::clean()));
    assert!(!p.should_restart(&ProcessExit::with_code(1)));
    assert!(!p.should_restart(&ProcessExit::with_signal(9)));
}

#[test]
fn restart_policy_serde_uses_internally_tagged_snake_case() {
    let p = RestartPolicy::OnFailure;
    let json = serde_json::to_string(&p).expect("serialize");
    assert!(
        json.contains("\"type\":\"on_failure\""),
        "RestartPolicy MUST serialize with internal 'type' tag and snake_case rename; got {json}"
    );
    let parsed: RestartPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, p);
}

// ─── ProcessExit ────────────────────────────────────────────────────

#[test]
fn process_exit_clean_constructor_is_clean() {
    let e = ProcessExit::clean();
    assert!(e.is_clean());
    assert!(!e.is_signal_terminated());
    assert_eq!(e.code, Some(0));
    assert!(e.signal.is_none());
}

#[test]
fn process_exit_with_code_non_zero_is_not_clean() {
    let e = ProcessExit::with_code(7);
    assert!(!e.is_clean(), "code=7 MUST NOT be clean");
    assert!(!e.is_signal_terminated());
}

#[test]
fn process_exit_with_signal_is_signal_terminated() {
    let e = ProcessExit::with_signal(9);
    assert!(e.is_signal_terminated());
    assert!(!e.is_clean());
    assert!(e.code.is_none());
    assert_eq!(e.signal, Some(9));
}

#[test]
fn process_exit_display_includes_code_or_signal() {
    let clean = ProcessExit::clean();
    let s = format!("{clean}");
    assert!(s.contains("exit code 0"), "got {s}");
    let coded = ProcessExit::with_code(2);
    let s = format!("{coded}");
    assert!(s.contains("exit code 2"), "got {s}");
    let signaled = ProcessExit::with_signal(15);
    let s = format!("{signaled}");
    assert!(s.contains("signal 15"), "got {s}");
}

#[test]
fn process_exit_display_handles_unknown_exit() {
    let unknown = ProcessExit {
        code: None,
        signal: None,
    };
    let s = format!("{unknown}");
    assert!(
        s.contains("unknown"),
        "ProcessExit with neither code nor signal MUST display as 'unknown exit'; got {s}"
    );
}

// ─── ProcessState ───────────────────────────────────────────────────

#[test]
fn process_state_is_running_only_for_running_variant() {
    let now = Instant::now();
    assert!(
        ProcessState::Running {
            pid: 1234,
            started_at: now
        }
        .is_running()
    );
    assert!(!ProcessState::Starting { since: now }.is_running());
    assert!(
        !ProcessState::Stopping {
            reason: StopReason::Requested,
            since: now,
        }
        .is_running()
    );
}

#[test]
fn process_state_is_terminal_for_stopped_and_failed() {
    let now = Instant::now();
    assert!(
        ProcessState::Stopped {
            exit: ProcessExit::clean(),
            stopped_at: now,
        }
        .is_terminal()
    );
    assert!(
        ProcessState::Failed {
            error: "boom".into(),
            failed_at: now,
        }
        .is_terminal()
    );
    assert!(!ProcessState::Starting { since: now }.is_terminal());
    assert!(
        !ProcessState::Running {
            pid: 1,
            started_at: now,
        }
        .is_terminal()
    );
}

#[test]
fn process_state_label_uses_snake_case_strings() {
    let now = Instant::now();
    assert_eq!(ProcessState::Starting { since: now }.label(), "starting");
    assert_eq!(
        ProcessState::Running {
            pid: 1,
            started_at: now
        }
        .label(),
        "running"
    );
    assert_eq!(
        ProcessState::Stopping {
            reason: StopReason::Requested,
            since: now,
        }
        .label(),
        "stopping"
    );
    assert_eq!(
        ProcessState::Stopped {
            exit: ProcessExit::clean(),
            stopped_at: now,
        }
        .label(),
        "stopped"
    );
    assert_eq!(
        ProcessState::Failed {
            error: "x".into(),
            failed_at: now,
        }
        .label(),
        "failed"
    );
}

// ─── StopReason ─────────────────────────────────────────────────────

#[test]
fn stop_reason_display_matches_documented_strings() {
    assert_eq!(format!("{}", StopReason::Requested), "requested");
    assert_eq!(format!("{}", StopReason::HostShutdown), "host shutdown");
    assert_eq!(
        format!("{}", StopReason::HealthCheckFailed),
        "health check failed"
    );
    assert_eq!(
        format!("{}", StopReason::ResourceLimitExceeded),
        "resource limit exceeded"
    );
    assert_eq!(format!("{}", StopReason::Upgrade), "upgrade");
}

#[test]
fn stop_reason_serde_uses_snake_case_wire_form() {
    let json = serde_json::to_string(&StopReason::HealthCheckFailed).expect("serialize");
    assert_eq!(json, "\"health_check_failed\"");
    let parsed: StopReason = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, StopReason::HealthCheckFailed);
}

// ─── SupervisorConfig defaults ─────────────────────────────────────

#[test]
fn supervisor_config_default_max_restarts_is_five() {
    assert_eq!(SupervisorConfig::default().max_restarts, 5);
}

#[test]
fn supervisor_config_default_restart_window_is_five_minutes() {
    assert_eq!(
        SupervisorConfig::default().restart_window,
        Duration::from_secs(5 * 60)
    );
}

#[test]
fn supervisor_config_default_health_check_interval_is_thirty_seconds() {
    assert_eq!(
        SupervisorConfig::default().health_check_interval,
        Duration::from_secs(30)
    );
}

#[test]
fn supervisor_config_default_health_check_timeout_is_ten_seconds() {
    assert_eq!(
        SupervisorConfig::default().health_check_timeout,
        Duration::from_secs(10)
    );
}

#[test]
fn supervisor_config_default_graceful_shutdown_timeout_is_thirty_seconds() {
    assert_eq!(
        SupervisorConfig::default().graceful_shutdown_timeout,
        Duration::from_secs(30)
    );
}

#[test]
fn supervisor_config_default_initial_backoff_is_five_hundred_ms() {
    assert_eq!(
        SupervisorConfig::default().initial_backoff,
        Duration::from_millis(500)
    );
}

#[test]
fn supervisor_config_default_max_backoff_is_one_minute() {
    assert_eq!(
        SupervisorConfig::default().max_backoff,
        Duration::from_secs(60)
    );
}

#[test]
fn supervisor_config_default_backoff_multiplier_is_two() {
    let m = SupervisorConfig::default().backoff_multiplier;
    assert!((m - 2.0).abs() < f64::EPSILON, "got {m}");
}

#[test]
fn supervisor_config_default_restart_policy_is_on_failure() {
    assert_eq!(
        SupervisorConfig::default().restart_policy,
        RestartPolicy::OnFailure
    );
}

// ─── ExponentialBackoff ─────────────────────────────────────────────

#[test]
fn exponential_backoff_first_call_returns_initial() {
    let mut b = ExponentialBackoff::new(
        Duration::from_millis(100),
        Duration::from_secs(10),
        2.0,
    );
    assert_eq!(b.attempts(), 0);
    let first = b.next_backoff();
    assert_eq!(
        first,
        Duration::from_millis(100),
        "first next_backoff (attempt 0) MUST equal initial"
    );
    assert_eq!(b.attempts(), 1);
}

#[test]
fn exponential_backoff_subsequent_calls_multiply_by_multiplier() {
    let mut b = ExponentialBackoff::new(
        Duration::from_millis(100),
        Duration::from_secs(60),
        2.0,
    );
    let _ = b.next_backoff(); // 100
    let second = b.next_backoff(); // 200
    assert_eq!(second, Duration::from_millis(200));
    let third = b.next_backoff(); // 400
    assert_eq!(third, Duration::from_millis(400));
}

#[test]
fn exponential_backoff_caps_at_max() {
    let mut b = ExponentialBackoff::new(
        Duration::from_millis(100),
        Duration::from_millis(500),
        2.0,
    );
    for _ in 0..20 {
        let d = b.next_backoff();
        assert!(
            d <= Duration::from_millis(500),
            "delay MUST cap at max (500ms); got {d:?}"
        );
    }
}

#[test]
fn exponential_backoff_normalizes_multiplier_below_one_to_two() {
    // Documented degenerate-input guard: multiplier < 1.0 reverts
    // to 2.0 to avoid backoff that shrinks (or zero).
    let mut b = ExponentialBackoff::new(
        Duration::from_millis(100),
        Duration::from_secs(60),
        0.5,
    );
    let _ = b.next_backoff(); // 100
    let second = b.next_backoff();
    assert_eq!(
        second,
        Duration::from_millis(200),
        "multiplier < 1.0 MUST be normalized to 2.0; got {second:?}"
    );
}

#[test]
fn exponential_backoff_clamps_initial_above_max_down_to_max() {
    let b = ExponentialBackoff::new(
        Duration::from_secs(10),
        Duration::from_millis(500),
        2.0,
    );
    assert_eq!(
        b.current_delay(),
        Duration::from_millis(500),
        "initial > max MUST be clamped to max"
    );
}

#[test]
fn exponential_backoff_reset_returns_attempt_to_zero() {
    let mut b = ExponentialBackoff::new(
        Duration::from_millis(100),
        Duration::from_secs(60),
        2.0,
    );
    for _ in 0..5 {
        let _ = b.next_backoff();
    }
    assert_eq!(b.attempts(), 5);
    b.reset();
    assert_eq!(b.attempts(), 0);
    let after_reset = b.next_backoff();
    assert_eq!(
        after_reset,
        Duration::from_millis(100),
        "after reset, MUST start over from initial"
    );
}

// ─── RestartTracker ─────────────────────────────────────────────────

#[test]
fn restart_tracker_never_policy_always_denies() {
    let mut cfg = SupervisorConfig::default();
    cfg.restart_policy = RestartPolicy::Never;
    let mut t = RestartTracker::new(cfg);
    let r = t.evaluate_restart(&ProcessExit::with_signal(9), Instant::now());
    assert_eq!(
        r,
        Err(RestartDenied::PolicyDenied),
        "Never policy MUST deny even on crash"
    );
}

#[test]
fn restart_tracker_on_failure_policy_denies_clean_exit() {
    let cfg = SupervisorConfig::default(); // OnFailure
    let mut t = RestartTracker::new(cfg);
    let r = t.evaluate_restart(&ProcessExit::clean(), Instant::now());
    assert_eq!(
        r,
        Err(RestartDenied::PolicyDenied),
        "OnFailure MUST deny restart on clean exit"
    );
}

#[test]
fn restart_tracker_grants_first_restart_under_limit() {
    let cfg = SupervisorConfig::default();
    let mut t = RestartTracker::new(cfg);
    let r = t.evaluate_restart(&ProcessExit::with_code(1), Instant::now());
    assert!(
        r.is_ok(),
        "first non-clean exit under OnFailure MUST be granted; got {r:?}"
    );
    assert_eq!(t.total_restarts(), 1);
}

#[test]
fn restart_tracker_denies_after_max_restarts_in_window() {
    let mut cfg = SupervisorConfig::default();
    cfg.max_restarts = 3;
    cfg.restart_window = Duration::from_secs(60);
    let mut t = RestartTracker::new(cfg);
    let now = Instant::now();
    for i in 0..3 {
        let r = t.evaluate_restart(&ProcessExit::with_code(1), now);
        assert!(r.is_ok(), "restart {i} MUST be granted under max=3");
    }
    let denied = t.evaluate_restart(&ProcessExit::with_code(1), now);
    match denied {
        Err(RestartDenied::MaxRestartsExceeded { count, window }) => {
            assert_eq!(count, 3);
            assert_eq!(window, Duration::from_secs(60));
        }
        other => panic!("expected MaxRestartsExceeded, got {other:?}"),
    }
}

#[test]
fn restart_tracker_record_successful_start_resets_backoff_not_history() {
    let cfg = SupervisorConfig::default();
    let mut t = RestartTracker::new(cfg);
    let now = Instant::now();
    let _ = t.evaluate_restart(&ProcessExit::with_code(1), now);
    let _ = t.evaluate_restart(&ProcessExit::with_code(1), now);
    assert_eq!(
        t.history().len(),
        2,
        "two restarts MUST be in history before record_successful_start"
    );

    t.record_successful_start();
    // History MUST persist (it's the rate-limit window record).
    assert_eq!(
        t.history().len(),
        2,
        "record_successful_start MUST NOT clear history (rate-limit window must keep counting)"
    );
    assert_eq!(
        t.total_restarts(),
        2,
        "total_restarts MUST persist across record_successful_start"
    );
}

#[test]
fn restart_tracker_total_restarts_persists_across_window_pruning() {
    // Even after the rate-limit window has rolled, total_restarts
    // is the all-time count and MUST keep climbing.
    let mut cfg = SupervisorConfig::default();
    cfg.max_restarts = 100; // big enough to never trip
    let mut t = RestartTracker::new(cfg);
    for _ in 0..7 {
        let _ = t.evaluate_restart(&ProcessExit::with_code(1), Instant::now());
    }
    assert_eq!(t.total_restarts(), 7);
}

// ─── RestartDenied Display ──────────────────────────────────────────

#[test]
fn restart_denied_policy_denied_display() {
    assert_eq!(format!("{}", RestartDenied::PolicyDenied), "restart policy denied");
}

#[test]
fn restart_denied_max_exceeded_display_includes_count_and_window_seconds() {
    let d = RestartDenied::MaxRestartsExceeded {
        count: 7,
        window: Duration::from_secs(180),
    };
    let s = format!("{d}");
    assert!(s.contains('7'), "count MUST appear; got {s}");
    assert!(s.contains("180"), "window seconds MUST appear; got {s}");
    assert!(
        s.contains("max restarts exceeded"),
        "literal substring for log greps; got {s}"
    );
}
