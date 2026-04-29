use std::time::Duration;

use fcp_core::{BackoffPolicy, BackoffSchedule};

fn schedule() -> BackoffSchedule {
    BackoffPolicy::new(
        4,
        Duration::from_millis(75),
        Duration::from_millis(300),
        2.0,
    )
    .retry_delays()
}

#[test]
fn backoff_schedule_yields_deterministic_next_delays() {
    let mut delays = schedule();

    assert_eq!(delays.size_hint(), (4, Some(4)));
    assert_eq!(delays.next(), Some(Duration::from_millis(75)));
    assert_eq!(delays.size_hint(), (3, Some(3)));
    assert_eq!(delays.next(), Some(Duration::from_millis(150)));
    assert_eq!(delays.size_hint(), (2, Some(2)));
    assert_eq!(delays.next(), Some(Duration::from_millis(300)));
    assert_eq!(delays.size_hint(), (1, Some(1)));
    assert_eq!(delays.next(), Some(Duration::from_millis(300)));
    assert_eq!(delays.size_hint(), (0, Some(0)));
}

#[test]
fn backoff_schedule_exhaustion_is_fused() {
    let mut delays = schedule();

    assert_eq!(
        delays.by_ref().collect::<Vec<_>>(),
        vec![
            Duration::from_millis(75),
            Duration::from_millis(150),
            Duration::from_millis(300),
            Duration::from_millis(300),
        ]
    );

    assert_eq!(delays.len(), 0);
    assert_eq!(delays.next(), None);
    assert_eq!(delays.next(), None);
}

#[test]
fn backoff_schedule_reset_restarts_from_first_delay() {
    let mut delays = schedule();

    assert_eq!(delays.next(), Some(Duration::from_millis(75)));
    assert_eq!(delays.next(), Some(Duration::from_millis(150)));

    delays.reset();

    assert_eq!(delays.len(), 4);
    assert_eq!(delays.next(), Some(Duration::from_millis(75)));
    assert_eq!(
        delays.collect::<Vec<_>>(),
        vec![
            Duration::from_millis(150),
            Duration::from_millis(300),
            Duration::from_millis(300),
        ]
    );
}
