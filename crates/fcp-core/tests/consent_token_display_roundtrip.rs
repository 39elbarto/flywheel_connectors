use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    error::Error,
    hash::{Hash, Hasher},
};

use fcp_core::ConsentToken;

const CONSENT_TOKENS: &[&str] = &[
    "consent:google-calendar.readonly",
    "oauth_consent-2026.04",
    "A0b1C2d3_E4f5-G6h7",
    "ct_0123456789abcdef",
];

#[test]
fn consent_token_display_from_str_roundtrips() -> Result<(), Box<dyn Error>> {
    for canonical in CONSENT_TOKENS {
        let consent = canonical.parse::<ConsentToken>()?;

        assert_eq!(consent.as_str(), *canonical);
        assert_eq!(consent.to_string(), *canonical);
        assert_eq!(format!("{consent}"), *canonical);

        let displayed = consent.to_string();
        let reparsed = displayed.parse::<ConsentToken>()?;

        assert_eq!(reparsed, consent);
    }

    Ok(())
}

#[test]
fn consent_token_hash_is_deterministic_across_display_roundtrips() -> Result<(), Box<dyn Error>> {
    for canonical in CONSENT_TOKENS {
        let consent = ConsentToken::new(*canonical)?;
        let display_roundtrip = consent.to_string().parse::<ConsentToken>()?;
        let cloned = consent.clone();

        let expected_hash = hash_value(&consent);

        assert_eq!(hash_value(&display_roundtrip), expected_hash);
        assert_eq!(hash_value(&cloned), expected_hash);
        assert_eq!(display_roundtrip, consent);
    }

    Ok(())
}

#[test]
fn consent_token_hashmap_lookup_survives_display_roundtrip() -> Result<(), Box<dyn Error>> {
    let consent = "consent:github.repo".parse::<ConsentToken>()?;
    let display_roundtrip = consent.to_string().parse::<ConsentToken>()?;
    let via_new = ConsentToken::new("consent:github.repo")?;
    let mut decisions = HashMap::new();

    decisions.insert(consent, "approved");

    assert_eq!(decisions.get(&display_roundtrip), Some(&"approved"));
    assert_eq!(decisions.get(&via_new), Some(&"approved"));

    Ok(())
}

#[test]
fn consent_token_rejects_non_display_safe_inputs() {
    for invalid in ["", "with space", "line\nbreak", "unicode-\u{2603}"] {
        assert!(
            invalid.parse::<ConsentToken>().is_err(),
            "ConsentToken accepted invalid input {invalid:?}"
        );
    }
}

fn hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}
