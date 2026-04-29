//! Pin `ZoneId` parse errors for malformed inputs.

use fcp_core::{ZoneId, ZoneIdError};

struct ZoneIdParseErrorCase {
    input: &'static str,
    expected: ZoneIdError,
}

const CASES: &[ZoneIdParseErrorCase] = &[
    ZoneIdParseErrorCase {
        input: "",
        expected: ZoneIdError::Empty,
    },
    ZoneIdParseErrorCase {
        input: "work",
        expected: ZoneIdError::MissingPrefix,
    },
    ZoneIdParseErrorCase {
        input: "zone:work",
        expected: ZoneIdError::MissingPrefix,
    },
    ZoneIdParseErrorCase {
        input: "Z:work",
        expected: ZoneIdError::MissingPrefix,
    },
    ZoneIdParseErrorCase {
        input: "z:",
        expected: ZoneIdError::EmptySegment { index: 2 },
    },
    ZoneIdParseErrorCase {
        input: "z:work:",
        expected: ZoneIdError::EmptySegment { index: 7 },
    },
    ZoneIdParseErrorCase {
        input: "z:project:",
        expected: ZoneIdError::EmptySegment { index: 10 },
    },
    ZoneIdParseErrorCase {
        input: "z:project::alpha",
        expected: ZoneIdError::EmptySegment { index: 10 },
    },
    ZoneIdParseErrorCase {
        input: "z:proj-alpha",
        expected: ZoneIdError::ReservedPrefix { prefix: "z:proj-" },
    },
    ZoneIdParseErrorCase {
        input: "z:work@home",
        expected: ZoneIdError::InvalidChar { ch: '@', index: 6 },
    },
    ZoneIdParseErrorCase {
        input: "z:Work",
        expected: ZoneIdError::InvalidChar { ch: 'W', index: 2 },
    },
    ZoneIdParseErrorCase {
        input: "z:project:-alpha",
        expected: ZoneIdError::InvalidChar { ch: '-', index: 10 },
    },
    ZoneIdParseErrorCase {
        input: "z:project:alpha-",
        expected: ZoneIdError::InvalidChar { ch: '-', index: 15 },
    },
    ZoneIdParseErrorCase {
        input: "z:project:alpha_team",
        expected: ZoneIdError::InvalidChar { ch: '_', index: 15 },
    },
    ZoneIdParseErrorCase {
        input: "z:project:alpha:team",
        expected: ZoneIdError::InvalidChar { ch: ':', index: 15 },
    },
    ZoneIdParseErrorCase {
        input: "z:alpha beta",
        expected: ZoneIdError::InvalidChar { ch: ' ', index: 7 },
    },
];

#[test]
fn malformed_zone_ids_return_stable_parse_error_variants() {
    for case in CASES {
        let parsed = case.input.parse::<ZoneId>();
        assert_eq!(
            parsed,
            Err(case.expected),
            "{} should fail with {:?}",
            case.input,
            case.expected
        );

        let tried = ZoneId::try_from(case.input.to_owned());
        assert_eq!(
            tried,
            Err(case.expected),
            "{} should fail with {:?}",
            case.input,
            case.expected
        );
    }
}

#[test]
fn zone_id_parse_length_and_ascii_guards_run_before_shape_checks() {
    let too_long = format!("z:{}", "a".repeat(63));
    assert_eq!(
        too_long.parse::<ZoneId>(),
        Err(ZoneIdError::TooLong { len: 65, max: 64 })
    );

    assert_eq!("z:worké".parse::<ZoneId>(), Err(ZoneIdError::NonAscii));
    assert_eq!("é".parse::<ZoneId>(), Err(ZoneIdError::NonAscii));
}

#[test]
fn tailscale_tag_prefix_error_is_not_a_zone_id_parse_variant() {
    assert_eq!(
        ZoneId::from_tailscale_tag("tag:wrong-work"),
        Err(ZoneIdError::InvalidTailscaleTagPrefix)
    );
    assert_eq!(
        "tag:wrong-work".parse::<ZoneId>(),
        Err(ZoneIdError::MissingPrefix)
    );
}
