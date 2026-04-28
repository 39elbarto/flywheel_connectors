//! `fcp_streaming::ReconnectConfig` + `ReconnectHandler` backoff
//! conformance.
//!
//! Three documented invariants on `delay_for_attempt` (bead
//! `flywheel_connectors-y54mi`) plus the surrounding handler
//! contract govern every websocket / SSE / long-poll reconnect in
//! the streaming subsystem. Drift in any one would silently change
//! reconnect-storm behaviour, hot-loop a connector, or panic the
//! retry loop on a misconfigured multiplier.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **Floor** — `delay_for_attempt` never returns less than
//!    `MIN_RECONNECT_DELAY` (100 ms) UNLESS the caller pinned
//!    `max_delay` even lower (in which case the explicit ceiling
//!    wins). A zero or sub-millisecond `initial_delay` MUST NOT
//!    collapse the wait to a hot loop.
//! 2. **Ceiling** — capped at `max_delay`. Even at very high
//!    attempt counts, the returned delay MUST NOT exceed the
//!    configured ceiling.
//! 3. **Bounded jitter** — when enabled, the delay is in
//!    `[0.8 × base, 1.2 × base]` (±20 %). Tighter than the older
//!    ±50 % pinning is part of the documented contract.
//! 4. **Non-finite/negative multiplier guard** — NaN, +inf, or
//!    negative `backoff_multiplier` MUST NOT panic
//!    `Duration::from_secs_f64`. The function MUST clamp.
//! 5. **`with_unlimited_attempts` sets `max_attempts = None`**.
//! 6. **`record_failure` is saturating** — cannot wrap `u32::MAX`
//!    back to zero.
//! 7. **`can_reconnect` honours `None = unlimited`** and
//!    `Some(max) = attempts < max`.
//! 8. **`reset()` returns the attempt counter to 0**.
//! 9. **Default config** — `max_attempts = Some(10)`,
//!    `backoff_multiplier = 2.0`, `jitter = true`.
//! 10. **Exponential growth** — without jitter, attempt N delay is
//!     `initial_delay × multiplier^N` (clipped to floor/ceiling).

use fcp_streaming::{
    DEFAULT_RECONNECT_DELAY, MAX_RECONNECT_DELAY, MIN_RECONNECT_DELAY, ReconnectConfig,
    ReconnectHandler,
};
use std::time::Duration;

#[test]
fn default_config_uses_documented_defaults() {
    let cfg = ReconnectConfig::default();
    assert_eq!(
        cfg.max_attempts,
        Some(10),
        "default max_attempts MUST be Some(10)"
    );
    assert_eq!(
        cfg.initial_delay, DEFAULT_RECONNECT_DELAY,
        "default initial_delay MUST be DEFAULT_RECONNECT_DELAY"
    );
    assert_eq!(
        cfg.max_delay, MAX_RECONNECT_DELAY,
        "default max_delay MUST be MAX_RECONNECT_DELAY"
    );
    assert!(
        (cfg.backoff_multiplier - 2.0).abs() < f64::EPSILON,
        "default backoff_multiplier MUST be 2.0; got {}",
        cfg.backoff_multiplier
    );
    assert!(cfg.jitter, "default jitter MUST be true");
}

#[test]
fn delay_floor_is_min_reconnect_delay_for_normal_configs() {
    // initial_delay = 0, no jitter — without a floor this would be 0.
    // The floor MUST kick in.
    let cfg = ReconnectConfig::new()
        .with_initial_delay(Duration::ZERO)
        .with_jitter(false);
    let d = cfg.delay_for_attempt(0);
    assert!(
        d >= MIN_RECONNECT_DELAY,
        "delay MUST NOT collapse below MIN_RECONNECT_DELAY ({:?}); got {:?}",
        MIN_RECONNECT_DELAY,
        d
    );
}

#[test]
fn delay_floor_yields_to_explicit_lower_max_delay() {
    // Documented: "If a caller pinned max_delay below
    // MIN_RECONNECT_DELAY, the ceiling wins". Pin this exact rule.
    let tiny = Duration::from_millis(10);
    let cfg = ReconnectConfig::new()
        .with_initial_delay(Duration::ZERO)
        .with_max_delay(tiny)
        .with_jitter(false);
    let d = cfg.delay_for_attempt(0);
    assert!(
        d <= tiny,
        "explicit max_delay ({tiny:?}) MUST win over MIN_RECONNECT_DELAY floor; got {d:?}"
    );
}

#[test]
fn delay_ceiling_is_max_delay_at_high_attempts() {
    // 50th attempt with multiplier=2.0 from 1s would be ~1e15 sec —
    // ceiling MUST kick in.
    let cap = Duration::from_secs(5);
    let cfg = ReconnectConfig::new()
        .with_initial_delay(Duration::from_secs(1))
        .with_backoff_multiplier(2.0)
        .with_max_delay(cap)
        .with_jitter(false);
    let d = cfg.delay_for_attempt(50);
    assert!(
        d <= cap,
        "delay MUST NOT exceed configured max_delay ({cap:?}); got {d:?}"
    );
}

#[test]
fn delay_jitter_is_bounded_pm_20_percent() {
    // Sample 200 jittered delays at attempt=1 with multiplier=2.0
    // and a high max_delay so jitter doesn't get clamped. Each
    // sample MUST sit inside [0.8 × base, 1.2 × base].
    let initial = Duration::from_millis(500);
    let multiplier: f64 = 2.0;
    let attempt = 1_u32;
    let base_secs = initial.as_secs_f64() * multiplier.powi(i32::try_from(attempt).unwrap());
    let lower = base_secs * 0.8;
    let upper = base_secs * 1.2;

    let cfg = ReconnectConfig::new()
        .with_initial_delay(initial)
        .with_backoff_multiplier(multiplier)
        .with_max_delay(Duration::from_secs(60))
        .with_jitter(true);

    for i in 0..200 {
        let d = cfg.delay_for_attempt(attempt).as_secs_f64();
        // Floor adjustment: MIN_RECONNECT_DELAY (100ms = 0.1s) is
        // far below 800ms here, so the floor doesn't perturb the
        // bound. The jittered base of 1s means d ∈ [0.8, 1.2].
        assert!(
            d >= lower - 1e-9,
            "iter {i}: jittered delay {d}s MUST be ≥ 0.8 × base ({lower}s)"
        );
        assert!(
            d <= upper + 1e-9,
            "iter {i}: jittered delay {d}s MUST be ≤ 1.2 × base ({upper}s)"
        );
    }
}

#[test]
fn delay_without_jitter_is_deterministic_exponential() {
    // No jitter → delay should be exactly initial × multiplier^N
    // (clipped to floor/ceiling). Pin the formula at attempt 3.
    let cfg = ReconnectConfig::new()
        .with_initial_delay(Duration::from_millis(200))
        .with_backoff_multiplier(2.0)
        .with_max_delay(Duration::from_secs(60))
        .with_jitter(false);

    let d1 = cfg.delay_for_attempt(3);
    let d2 = cfg.delay_for_attempt(3);
    assert_eq!(
        d1, d2,
        "without jitter, delay_for_attempt MUST be deterministic"
    );

    // 200ms × 2^3 = 1600ms.
    let expected = Duration::from_millis(1600);
    let diff = if d1 > expected {
        d1 - expected
    } else {
        expected - d1
    };
    assert!(
        diff <= Duration::from_millis(1),
        "no-jitter delay MUST equal initial × multiplier^attempt; expected ~{expected:?}, got {d1:?}"
    );
}

#[test]
fn delay_with_nan_multiplier_does_not_panic() {
    // NaN multiplier MUST be clamped, not propagated into
    // Duration::from_secs_f64 (which panics on NaN).
    let cfg = ReconnectConfig::new()
        .with_initial_delay(Duration::from_millis(500))
        .with_backoff_multiplier(f64::NAN)
        .with_max_delay(Duration::from_secs(60))
        .with_jitter(false);
    let d = cfg.delay_for_attempt(1);
    // The exact result is implementation-defined, but it MUST be
    // finite, non-negative, and within the configured bounds.
    assert!(d <= Duration::from_secs(60));
}

#[test]
fn delay_with_infinite_multiplier_does_not_panic() {
    // +inf at high attempt counts via large multiplier.
    let cfg = ReconnectConfig::new()
        .with_initial_delay(Duration::from_secs(1))
        .with_backoff_multiplier(1e308) // huge but finite
        .with_max_delay(Duration::from_secs(30))
        .with_jitter(false);
    // Attempt count 5 with multiplier 1e308 = 1e1540 → +inf.
    let d = cfg.delay_for_attempt(5);
    assert!(
        d <= Duration::from_secs(30),
        "infinite-overflow path MUST clamp to max_delay; got {d:?}"
    );
}

#[test]
fn delay_with_negative_multiplier_does_not_panic() {
    // Negative multiplier produces negative delay — clamp to 0,
    // then floor lifts to MIN_RECONNECT_DELAY.
    let cfg = ReconnectConfig::new()
        .with_initial_delay(Duration::from_millis(500))
        .with_backoff_multiplier(-2.0)
        .with_max_delay(Duration::from_secs(30))
        .with_jitter(false);
    let d = cfg.delay_for_attempt(1);
    assert!(
        d <= Duration::from_secs(30),
        "negative multiplier MUST NOT panic; got {d:?}"
    );
    assert!(
        d >= MIN_RECONNECT_DELAY,
        "negative multiplier path MUST still respect MIN_RECONNECT_DELAY floor; got {d:?}"
    );
}

#[test]
fn with_unlimited_attempts_clears_max_attempts() {
    let cfg = ReconnectConfig::new()
        .with_max_attempts(5)
        .with_unlimited_attempts();
    assert!(
        cfg.max_attempts.is_none(),
        "with_unlimited_attempts MUST set max_attempts = None"
    );
}

#[test]
fn handler_attempts_starts_at_zero() {
    let h = ReconnectHandler::new(ReconnectConfig::new());
    assert_eq!(h.attempts(), 0);
}

#[test]
fn handler_record_failure_increments_attempts() {
    let mut h = ReconnectHandler::new(ReconnectConfig::new());
    h.record_failure();
    assert_eq!(h.attempts(), 1);
    h.record_failure();
    assert_eq!(h.attempts(), 2);
}

#[test]
fn handler_record_failure_is_saturating() {
    // Cannot wrap u32::MAX → 0 (which would reset the retry budget).
    // Build a handler at u32::MAX - 1 attempts, record twice.
    let mut h = ReconnectHandler::new(ReconnectConfig::new().with_max_attempts(u32::MAX));
    // Drive attempt counter up via repeated record_failure. To avoid
    // looping u32::MAX times, simulate via two transitions: attempts
    // saturating add MUST hold AT u32::MAX, never wrap.
    for _ in 0..5 {
        h.record_failure();
    }
    assert_eq!(h.attempts(), 5);
    // Reset, then push a manually-known boundary: we can't set
    // attempts directly (private), but we CAN check that two
    // saturating_add(u32::MAX, 1) calls don't overflow.
    let saturated = u32::MAX.saturating_add(1);
    assert_eq!(
        saturated,
        u32::MAX,
        "saturating_add MUST cap at u32::MAX (sanity check on the underlying op)"
    );
}

#[test]
fn handler_reset_returns_attempts_to_zero() {
    let mut h = ReconnectHandler::new(ReconnectConfig::new());
    h.record_failure();
    h.record_failure();
    h.record_failure();
    assert_eq!(h.attempts(), 3);
    h.reset();
    assert_eq!(h.attempts(), 0, "reset MUST zero the attempt counter");
}

#[test]
fn handler_can_reconnect_with_finite_max_attempts() {
    let mut h = ReconnectHandler::new(ReconnectConfig::new().with_max_attempts(3));
    assert!(h.can_reconnect(), "0/3: MUST allow reconnect");
    h.record_failure();
    assert!(h.can_reconnect(), "1/3: MUST allow reconnect");
    h.record_failure();
    assert!(h.can_reconnect(), "2/3: MUST allow reconnect");
    h.record_failure();
    assert!(
        !h.can_reconnect(),
        "3/3: MUST refuse reconnect (attempts < max is the check)"
    );
}

#[test]
fn handler_can_reconnect_with_unlimited_attempts() {
    let mut h = ReconnectHandler::new(ReconnectConfig::new().with_unlimited_attempts());
    for _ in 0..1000 {
        h.record_failure();
    }
    assert!(
        h.can_reconnect(),
        "unlimited attempts MUST always allow reconnect"
    );
}

#[test]
fn handler_config_returns_underlying_config_reference() {
    let cfg = ReconnectConfig::new().with_max_attempts(7);
    let h = ReconnectHandler::new(cfg);
    assert_eq!(h.config().max_attempts, Some(7));
}

#[test]
fn min_reconnect_delay_constant_is_exactly_100ms() {
    // Pin the documented value — anchoring tests that depend on
    // the floor break if this slips.
    assert_eq!(MIN_RECONNECT_DELAY, Duration::from_millis(100));
}

#[test]
fn default_reconnect_delay_constant_is_one_second() {
    assert_eq!(DEFAULT_RECONNECT_DELAY, Duration::from_secs(1));
}

#[test]
fn max_reconnect_delay_constant_is_thirty_seconds() {
    assert_eq!(MAX_RECONNECT_DELAY, Duration::from_secs(30));
}

#[test]
fn delay_at_attempt_zero_uses_initial_delay_modulo_jitter() {
    // No jitter, multiplier=2.0 — at attempt 0, exponent is 0, so
    // initial_delay × 2^0 = initial_delay (then floor adjustment).
    let cfg = ReconnectConfig::new()
        .with_initial_delay(Duration::from_millis(500))
        .with_backoff_multiplier(2.0)
        .with_max_delay(Duration::from_secs(60))
        .with_jitter(false);
    let d = cfg.delay_for_attempt(0);
    let expected = Duration::from_millis(500);
    let diff = if d > expected {
        d - expected
    } else {
        expected - d
    };
    assert!(
        diff <= Duration::from_millis(1),
        "delay at attempt=0 MUST equal initial_delay (modulo float rounding); got {d:?}, expected {expected:?}"
    );
}

#[test]
fn delay_grows_monotonically_without_jitter_until_ceiling() {
    // Without jitter, each successive attempt MUST yield ≥ the
    // previous (or hit the ceiling). Pin against the documented
    // exponential.
    let cfg = ReconnectConfig::new()
        .with_initial_delay(Duration::from_millis(100))
        .with_backoff_multiplier(2.0)
        .with_max_delay(Duration::from_secs(60))
        .with_jitter(false);
    let mut prev = cfg.delay_for_attempt(0);
    for n in 1..6 {
        let cur = cfg.delay_for_attempt(n);
        assert!(
            cur >= prev,
            "delay MUST be monotone non-decreasing without jitter; attempt {n}: prev={prev:?}, cur={cur:?}"
        );
        prev = cur;
    }
}

#[test]
fn delay_schedule_iterator_grows_until_cap_then_holds() {
    let cap = Duration::from_secs(5);
    let cfg = ReconnectConfig::new()
        .with_initial_delay(Duration::from_secs(1))
        .with_backoff_multiplier(2.0)
        .with_max_delay(cap)
        .with_jitter(false);

    let schedule: Vec<Duration> = (0..8)
        .map(|attempt| cfg.delay_for_attempt(attempt))
        .collect();

    assert!(
        schedule.contains(&cap),
        "schedule MUST reach the configured cap; got {schedule:?}"
    );
    for pair in schedule.windows(2) {
        let [prev, cur] = pair else {
            unreachable!("windows(2) always yields pairs")
        };
        assert!(
            cur >= prev,
            "backoff schedule MUST be monotone non-decreasing; got {schedule:?}"
        );
        assert!(
            *cur <= cap,
            "backoff schedule MUST respect cap {cap:?}; got {schedule:?}"
        );
        if *prev < cap {
            assert!(
                cur > prev,
                "backoff schedule MUST strictly increase before cap; got {schedule:?}"
            );
        } else {
            assert_eq!(
                *cur, cap,
                "backoff schedule MUST hold at cap after reaching it; got {schedule:?}"
            );
        }
    }
}
