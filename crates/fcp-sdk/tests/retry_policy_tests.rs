//! Retry policy helpers tests.

use std::time::Duration;

use fcp_sdk::FcpError;
use fcp_sdk::retry::{
    DEFAULT_RATE_LIMIT_RETRY_AFTER, RetryDecision, RetryPolicy, decision_from_error_message,
    decision_from_http_status, map_external_error,
};

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

#[test]
fn retry_decision_from_http_statuses() {
    let decision = decision_from_http_status(429, None);
    assert_eq!(
        decision,
        RetryDecision::After(DEFAULT_RATE_LIMIT_RETRY_AFTER)
    );

    let decision = decision_from_http_status(503, None);
    assert_eq!(decision, RetryDecision::Backoff);

    let decision = decision_from_http_status(404, None);
    assert_eq!(decision, RetryDecision::Terminal);
}

#[test]
fn retry_decision_from_parse_error_message() {
    let decision = decision_from_error_message("Can't parse entities: invalid Markdown");
    assert_eq!(decision, RetryDecision::Terminal);
}

#[test]
fn map_external_error_handles_rate_limit_and_transient() {
    let (decision, err) = map_external_error(
        "test-service",
        Some(429),
        "Too Many Requests",
        Some(Duration::from_secs(5)),
    );
    assert_eq!(decision, RetryDecision::After(Duration::from_secs(5)));
    assert!(
        matches!(&err, FcpError::RateLimited { retry_after_ms, .. } if *retry_after_ms == 5_000),
        "expected rate limited error, got {err:?}"
    );

    let (decision, err) =
        map_external_error("test-service", Some(503), "Service Unavailable", None);
    assert_eq!(decision, RetryDecision::Backoff);
    assert!(
        matches!(&err, FcpError::External { retryable, .. } if *retryable),
        "expected external error, got {err:?}"
    );
}

#[test]
fn map_external_error_handles_terminal_message() {
    let (decision, err) = map_external_error(
        "test-service",
        None,
        "Can't parse entities: invalid Markdown",
        None,
    );
    assert_eq!(decision, RetryDecision::Terminal);
    assert!(
        matches!(&err, FcpError::External { retryable, .. } if !*retryable),
        "expected external error, got {err:?}"
    );
}
