//! Pin the fcp-core isolation-level ordering contract.
//!
//! There is no public type literally named `IsolationLevel` in fcp-core. The
//! public isolation lattice is represented by `IntegrityLevel` and
//! `ConfidentialityLevel` in the provenance module: integrity orders data from
//! least to most trusted, while confidentiality orders data from least to most
//! restricted.

use std::cmp::Ordering;

use fcp_core::{ConfidentialityLevel, IntegrityLevel, ZoneId};

const INTEGRITY_ASCENDING: [IntegrityLevel; 5] = [
    IntegrityLevel::Untrusted,
    IntegrityLevel::Community,
    IntegrityLevel::Work,
    IntegrityLevel::Private,
    IntegrityLevel::Owner,
];

const CONFIDENTIALITY_ASCENDING: [ConfidentialityLevel; 5] = [
    ConfidentialityLevel::Public,
    ConfidentialityLevel::Community,
    ConfidentialityLevel::Work,
    ConfidentialityLevel::Private,
    ConfidentialityLevel::Owner,
];

#[test]
fn integrity_level_ordering_matches_documented_lattice() {
    assert_ordered_chain(&INTEGRITY_ASCENDING);

    assert_eq!(IntegrityLevel::Untrusted.as_u8(), 0);
    assert_eq!(IntegrityLevel::Community.as_u8(), 1);
    assert_eq!(IntegrityLevel::Work.as_u8(), 2);
    assert_eq!(IntegrityLevel::Private.as_u8(), 3);
    assert_eq!(IntegrityLevel::Owner.as_u8(), 4);

    let mut shuffled = [
        IntegrityLevel::Owner,
        IntegrityLevel::Untrusted,
        IntegrityLevel::Private,
        IntegrityLevel::Community,
        IntegrityLevel::Work,
    ];
    shuffled.sort();
    assert_eq!(shuffled, INTEGRITY_ASCENDING);
}

#[test]
fn confidentiality_level_ordering_matches_documented_lattice() {
    assert_ordered_chain(&CONFIDENTIALITY_ASCENDING);

    assert_eq!(ConfidentialityLevel::Public.as_u8(), 0);
    assert_eq!(ConfidentialityLevel::Community.as_u8(), 1);
    assert_eq!(ConfidentialityLevel::Work.as_u8(), 2);
    assert_eq!(ConfidentialityLevel::Private.as_u8(), 3);
    assert_eq!(ConfidentialityLevel::Owner.as_u8(), 4);

    let mut shuffled = [
        ConfidentialityLevel::Owner,
        ConfidentialityLevel::Public,
        ConfidentialityLevel::Private,
        ConfidentialityLevel::Community,
        ConfidentialityLevel::Work,
    ];
    shuffled.sort();
    assert_eq!(shuffled, CONFIDENTIALITY_ASCENDING);
}

#[test]
fn zone_default_isolation_levels_follow_the_same_order() {
    let zones = [
        (
            ZoneId::public(),
            IntegrityLevel::Untrusted,
            ConfidentialityLevel::Public,
        ),
        (
            ZoneId::community(),
            IntegrityLevel::Community,
            ConfidentialityLevel::Community,
        ),
        (
            ZoneId::work(),
            IntegrityLevel::Work,
            ConfidentialityLevel::Work,
        ),
        (
            ZoneId::private(),
            IntegrityLevel::Private,
            ConfidentialityLevel::Private,
        ),
        (
            ZoneId::owner(),
            IntegrityLevel::Owner,
            ConfidentialityLevel::Owner,
        ),
    ];

    for (zone, expected_integrity, expected_confidentiality) in zones {
        assert_eq!(IntegrityLevel::from_zone(&zone), expected_integrity);
        assert_eq!(
            ConfidentialityLevel::from_zone(&zone),
            expected_confidentiality
        );
    }
}

fn assert_ordered_chain<T>(ascending: &[T])
where
    T: Copy + Ord + std::fmt::Debug,
{
    for (left_index, &left) in ascending.iter().enumerate() {
        for (right_index, &right) in ascending.iter().enumerate() {
            let expected = left_index.cmp(&right_index);
            assert_eq!(left.cmp(&right), expected, "cmp({left:?}, {right:?})");
            assert_eq!(
                left.partial_cmp(&right),
                Some(expected),
                "partial_cmp({left:?}, {right:?})"
            );
        }
    }

    for adjacent in ascending.windows(2) {
        assert_eq!(adjacent[0].cmp(&adjacent[1]), Ordering::Less);
        assert_eq!(adjacent[1].cmp(&adjacent[0]), Ordering::Greater);
    }
}
