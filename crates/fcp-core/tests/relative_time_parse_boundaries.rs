use std::{str::FromStr, time::Duration};

use fcp_core::util::RelativeTime;

#[test]
fn relative_time_inputs_roundtrip_through_display_and_from_str()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        ("5s", Duration::from_secs(5)),
        ("1m", Duration::from_secs(60)),
        ("30s", Duration::from_secs(30)),
        ("1h", Duration::from_secs(60 * 60)),
        ("1d", Duration::from_secs(24 * 60 * 60)),
        ("1w", Duration::from_secs(7 * 24 * 60 * 60)),
    ];

    for (text, expected_duration) in cases {
        let parsed = RelativeTime::from_str(text)?;
        assert_eq!(parsed.as_duration(), expected_duration);

        let displayed = parsed.to_string();
        assert_eq!(displayed, text);

        let reparsed = RelativeTime::from_str(&displayed)?;
        assert_eq!(reparsed, parsed);
    }

    Ok(())
}

#[test]
fn relative_time_display_uses_largest_exact_unit() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        ("60s", "1m"),
        ("3600s", "1h"),
        ("86400s", "1d"),
        ("604800s", "1w"),
    ];

    for (input, expected_display) in cases {
        let parsed = RelativeTime::from_str(input)?;
        assert_eq!(parsed.to_string(), expected_display);

        let reparsed = RelativeTime::from_str(expected_display)?;
        assert_eq!(reparsed, parsed);
    }

    Ok(())
}
