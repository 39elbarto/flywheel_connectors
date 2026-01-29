//! Retry policy helpers tests.

use std::time::Duration;

use fcp_sdk::retry::{RetryDecision, RetryPolicy};

#[test]
fn retry_policy_backoff_respects_retry_after_hint() {
    let policy = RetryPolicy::new()
        .with_jitter_enabled(false)
        .with_base_backoff_ms(1_000)
        .with_max_backoff_ms(60_000)
        .with_max_attempts(None);

    let delay = policy
        .next_delay(0, RetryDecision::Backoff, Some(Duration::from_secs(10)))
        .expect("delay");
    assert_eq!(delay, Duration::from_secs(10));

    let delay = policy
        .next_delay(0, RetryDecision::Backoff, Some(Duration::from_millis(200)))
        .expect("delay");
    assert_eq!(delay, Duration::from_secs(1));
}

#[test]
fn retry_policy_immediate_returns_zero_delay() {
    let policy = RetryPolicy::new().with_jitter_enabled(false);
    let delay = policy
        .next_delay(0, RetryDecision::Immediate, None)
        .expect("delay");
    assert_eq!(delay, Duration::from_millis(0));
}

#[test]
fn retry_policy_terminal_returns_none() {
    let policy = RetryPolicy::new();
    let delay = policy.next_delay(0, RetryDecision::Terminal, None);
    assert!(delay.is_none());
}

#[test]
fn retry_policy_respects_max_attempts() {
    let policy = RetryPolicy::new()
        .with_jitter_enabled(false)
        .with_max_attempts(Some(1));

    let delay = policy
        .next_delay(0, RetryDecision::Backoff, None)
        .expect("delay");
    assert_eq!(delay, Duration::from_secs(1));

    let delay = policy.next_delay(1, RetryDecision::Backoff, None);
    assert!(delay.is_none());
}
