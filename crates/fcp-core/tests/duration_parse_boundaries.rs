use std::{str::FromStr, time::Duration};

use fcp_core::util::{CanonicalDuration, MAX_CANONICAL_DURATION};

#[test]
fn duration_boundaries_roundtrip_through_display_and_from_str() {
    let cases = [
        ("0s", Duration::ZERO),
        ("1ms", Duration::from_millis(1)),
        ("1s", Duration::from_secs(1)),
        ("60s", Duration::from_secs(60)),
        ("3600s", Duration::from_secs(3_600)),
        ("86400s", Duration::from_secs(86_400)),
    ];

    for (text, expected_duration) in cases {
        let parsed = CanonicalDuration::from_str(text).unwrap();
        assert_eq!(parsed.as_duration(), expected_duration);

        let displayed = parsed.to_string();
        assert_eq!(displayed, text);

        let reparsed = CanonicalDuration::from_str(&displayed).unwrap();
        assert_eq!(reparsed, parsed);
    }
}

#[test]
fn configured_maximum_roundtrips_through_display_and_from_str() {
    let maximum = CanonicalDuration::try_from(MAX_CANONICAL_DURATION).unwrap();

    assert_eq!(maximum.as_duration(), MAX_CANONICAL_DURATION);
    assert_eq!(maximum.to_string(), "86400s");
    assert_eq!(
        CanonicalDuration::from_str(&maximum.to_string()).unwrap(),
        maximum
    );
}

#[test]
fn duration_above_configured_maximum_is_rejected() {
    assert!(CanonicalDuration::from_str("86401s").is_err());
    assert!(CanonicalDuration::try_from(Duration::from_secs(86_401)).is_err());
}
