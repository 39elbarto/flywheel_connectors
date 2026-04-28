use std::str::FromStr;

use fcp_core::{DateTime, Utc};

#[test]
fn timestamp_display_strings_roundtrip_through_from_str() -> Result<(), chrono::ParseError> {
    let cases = [
        (
            DateTime::<Utc>::from_str("1970-01-01T00:00:00Z")?,
            "1970-01-01 00:00:00 UTC",
        ),
        (
            DateTime::<Utc>::from_str("2024-01-01T00:00:00Z")?,
            "2024-01-01 00:00:00 UTC",
        ),
        (
            DateTime::<Utc>::from_str("2016-12-31T23:59:60Z")?,
            "2016-12-31 23:59:60 UTC",
        ),
    ];

    for (value, expected_display) in cases {
        let displayed = value.to_string();

        assert_eq!(displayed, expected_display);
        assert_eq!(DateTime::<Utc>::from_str(&displayed)?, value);
    }

    Ok(())
}

#[test]
fn timestamp_ordering_pins_epoch_and_leap_second_boundaries() -> Result<(), chrono::ParseError> {
    let before_epoch = DateTime::<Utc>::from_str("1969-12-31T23:59:59Z")?;
    let epoch = DateTime::<Utc>::from_str("1970-01-01T00:00:00Z")?;
    let after_epoch = DateTime::<Utc>::from_str("1970-01-01T00:00:01Z")?;
    let leap_second = DateTime::<Utc>::from_str("2016-12-31T23:59:60Z")?;
    let after_leap_second = DateTime::<Utc>::from_str("2017-01-01T00:00:00Z")?;

    assert!(before_epoch < epoch);
    assert!(epoch < after_epoch);
    assert!(leap_second < after_leap_second);
    assert_eq!(leap_second.to_rfc3339(), "2016-12-31T23:59:60+00:00");

    Ok(())
}
