use fcp_core::CheckOutcome;

struct PredicateCase {
    outcome: CheckOutcome,
    is_allow: bool,
    is_deny: bool,
    is_skip: bool,
}

#[test]
fn check_outcome_predicates_are_mutually_exclusive() {
    let cases = [
        PredicateCase {
            outcome: CheckOutcome::Allow,
            is_allow: true,
            is_deny: false,
            is_skip: false,
        },
        PredicateCase {
            outcome: CheckOutcome::Deny {
                reason_code: String::from("zone_violation"),
                explanation: String::from("principal is not a member of the zone"),
            },
            is_allow: false,
            is_deny: true,
            is_skip: false,
        },
        PredicateCase {
            outcome: CheckOutcome::Skip {
                reason: String::from("not applicable to this request"),
            },
            is_allow: false,
            is_deny: false,
            is_skip: true,
        },
    ];

    for case in cases {
        assert_eq!(case.outcome.is_allow(), case.is_allow);
        assert_eq!(case.outcome.is_deny(), case.is_deny);
        assert_eq!(case.outcome.is_skip(), case.is_skip);
    }
}
