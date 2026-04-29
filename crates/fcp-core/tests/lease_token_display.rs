use std::str::FromStr;

use fcp_core::{LeaseToken, LeaseTokenParseError};

#[test]
fn lease_token_roundtrips_display_and_from_str() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        "lease:operation_execution:z-work:000001",
        "lease:connector_state_write:state_abc-123",
        "lease:node.01.seq_00042",
        "lease:A0b1C2d3_E4f5-G6h7",
    ];

    for token_text in cases {
        let parsed = LeaseToken::from_str(token_text)?;
        assert_eq!(parsed.as_str(), token_text);
        assert_eq!(parsed.to_string(), token_text);
        assert_eq!(token_text.parse::<LeaseToken>()?, parsed);
    }

    Ok(())
}

#[test]
fn lease_token_accepts_maximum_length_value() -> Result<(), Box<dyn std::error::Error>> {
    let token_text = format!("lease:{}", "a".repeat(250));
    let parsed = LeaseToken::new(token_text.clone())?;

    assert_eq!(token_text.len(), 256);
    assert_eq!(parsed.to_string(), token_text);
    assert_eq!(token_text.parse::<LeaseToken>()?, parsed);

    Ok(())
}

#[test]
fn lease_token_rejects_non_canonical_formats() {
    let too_long = format!("lease:{}", "a".repeat(251));

    let cases = [
        ("", LeaseTokenParseError::Empty),
        ("not-lease:abc", LeaseTokenParseError::MissingPrefix),
        ("lease:", LeaseTokenParseError::MissingIdentifier),
        (
            "lease:-leading-separator",
            LeaseTokenParseError::InvalidChar { ch: '-', index: 6 },
        ),
        (
            "lease:with space",
            LeaseTokenParseError::InvalidChar { ch: ' ', index: 10 },
        ),
        (
            "lease:slash/path",
            LeaseTokenParseError::InvalidChar { ch: '/', index: 11 },
        ),
        (
            "lease:unicode-\u{2603}",
            LeaseTokenParseError::InvalidChar {
                ch: '\u{2603}',
                index: 14,
            },
        ),
    ];

    for (raw, expected) in cases {
        assert_eq!(raw.parse::<LeaseToken>(), Err(expected));
    }

    assert_eq!(
        too_long.parse::<LeaseToken>(),
        Err(LeaseTokenParseError::TooLong { len: 257, max: 256 })
    );
}
