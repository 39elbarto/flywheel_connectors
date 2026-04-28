use std::time::Duration;

use fcp_core::{BackoffPolicy, RetryConfig};

fn capped_policy(max_retries: u32) -> BackoffPolicy {
    BackoffPolicy::new(
        max_retries,
        Duration::from_millis(100),
        Duration::from_millis(250),
        2.0,
    )
}

#[test]
fn zero_retries_yields_no_delays_and_returns_immediately() {
    let policy = capped_policy(0);
    let mut delays = policy.retry_delays();

    assert_eq!(policy.max_retries(), 0);
    assert_eq!(delays.len(), 0);
    assert_eq!(delays.next(), None);
    assert_eq!(policy.delay_for_retry(0), None);
}

#[test]
fn n_retries_iterator_yields_exactly_n_delays() {
    let delays = capped_policy(3).retry_delays().collect::<Vec<_>>();

    assert_eq!(
        delays,
        vec![
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(250),
        ]
    );
}

#[test]
fn exhausted_iterator_stays_exhausted() {
    let mut delays = capped_policy(2).retry_delays();

    assert_eq!(delays.size_hint(), (2, Some(2)));
    assert_eq!(delays.next(), Some(Duration::from_millis(100)));
    assert_eq!(delays.size_hint(), (1, Some(1)));
    assert_eq!(delays.next(), Some(Duration::from_millis(200)));
    assert_eq!(delays.size_hint(), (0, Some(0)));
    assert_eq!(delays.next(), None);
    assert_eq!(delays.next(), None);
    assert_eq!(delays.len(), 0);
}

#[test]
fn last_retry_attempt_is_allowed_before_max_retries_exhausts() {
    let policy = capped_policy(3);

    assert_eq!(policy.delay_for_retry(2), Some(Duration::from_millis(250)));
    assert_eq!(policy.delay_for_retry(3), None);
}

#[test]
fn max_delay_caps_backoff_without_ending_retry_budget() {
    let delays = capped_policy(5).retry_delays().collect::<Vec<_>>();

    assert_eq!(
        delays,
        vec![
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(250),
            Duration::from_millis(250),
            Duration::from_millis(250),
        ]
    );
}

#[test]
fn retry_config_max_attempts_converts_to_initial_attempt_plus_retries() {
    let no_retry_config = RetryConfig {
        max_attempts: 1,
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_millis(250),
        multiplier: 2.0,
    };
    let no_retry_policy = BackoffPolicy::from(&no_retry_config);

    assert_eq!(no_retry_policy.max_retries(), 0);
    assert_eq!(no_retry_policy.retry_delays().next(), None);

    let retrying_config = RetryConfig {
        max_attempts: 4,
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_millis(250),
        multiplier: 2.0,
    };
    let retrying_policy = BackoffPolicy::from(&retrying_config);

    assert_eq!(retrying_policy.max_retries(), 3);
    assert_eq!(
        retrying_policy.retry_delays().collect::<Vec<_>>(),
        vec![
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(250),
        ]
    );
}
