use std::cmp::Ordering;

use fcp_core::EventSeverity;

#[test]
fn event_severity_ordering_is_pinned() {
    let ascending = [
        EventSeverity::Info,
        EventSeverity::Notice,
        EventSeverity::Warning,
        EventSeverity::Error,
        EventSeverity::Critical,
    ];

    assert_eq!(
        ascending,
        [
            EventSeverity::Info,
            EventSeverity::Notice,
            EventSeverity::Warning,
            EventSeverity::Error,
            EventSeverity::Critical,
        ]
    );

    for pair in ascending.windows(2) {
        assert!(pair[0] < pair[1]);
        assert_eq!(pair[0].partial_cmp(&pair[1]), Some(Ordering::Less));
        assert_eq!(pair[1].partial_cmp(&pair[0]), Some(Ordering::Greater));
    }

    for severity in ascending {
        assert_eq!(severity.partial_cmp(&severity), Some(Ordering::Equal));
    }
}
