use std::cmp::Ordering;

use fcp_core::OrderingPolicy as SchedulePolicy;

#[test]
fn schedule_policy_display_tokens_are_pinned() {
    let cases = [
        (SchedulePolicy::Unordered, "unordered"),
        (SchedulePolicy::PerKey, "per_key"),
        (SchedulePolicy::Gateway, "gateway"),
    ];

    for (policy, expected) in cases {
        assert_eq!(policy.as_str(), expected);
        assert_eq!(policy.to_string(), expected);
    }
}

#[test]
fn schedule_policy_display_matches_json_tag() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (SchedulePolicy::Unordered, "\"unordered\""),
        (SchedulePolicy::PerKey, "\"per_key\""),
        (SchedulePolicy::Gateway, "\"gateway\""),
    ];

    for (policy, expected_json) in cases {
        assert_eq!(serde_json::to_string(&policy)?, expected_json);
    }

    Ok(())
}

#[test]
fn schedule_policy_comparison_orders_by_delivery_guarantee_strength() {
    assert!(SchedulePolicy::Unordered < SchedulePolicy::PerKey);
    assert!(SchedulePolicy::PerKey < SchedulePolicy::Gateway);
    assert_eq!(
        SchedulePolicy::Gateway.partial_cmp(&SchedulePolicy::Gateway),
        Some(Ordering::Equal)
    );
}

#[test]
fn schedule_policy_sort_order_is_stable() {
    let mut policies = [
        SchedulePolicy::Gateway,
        SchedulePolicy::Unordered,
        SchedulePolicy::PerKey,
        SchedulePolicy::Gateway,
    ];

    policies.sort();

    assert_eq!(
        policies,
        [
            SchedulePolicy::Unordered,
            SchedulePolicy::PerKey,
            SchedulePolicy::Gateway,
            SchedulePolicy::Gateway,
        ]
    );
}
