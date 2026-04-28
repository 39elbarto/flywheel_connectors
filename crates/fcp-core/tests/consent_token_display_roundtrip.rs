use std::{
    collections::{HashMap, hash_map::DefaultHasher},
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
fn consent_token_display_from_str_roundtrips() {
    for canonical in CONSENT_TOKENS {
        let token = canonical
            .parse::<ConsentToken>()
            .unwrap_or_else(|err| panic!("parse({canonical:?}): {err}"));

        assert_eq!(token.as_str(), *canonical);
        assert_eq!(token.to_string(), *canonical);
        assert_eq!(format!("{token}"), *canonical);

        let displayed = token.to_string();
        let reparsed = displayed
            .parse::<ConsentToken>()
            .expect("displayed ConsentToken parses");

        assert_eq!(reparsed, token);
    }
}

#[test]
fn consent_token_hash_is_deterministic_across_display_roundtrips() {
    for canonical in CONSENT_TOKENS {
        let token = ConsentToken::new(*canonical).expect("canonical ConsentToken");
        let display_roundtrip = token
            .to_string()
            .parse::<ConsentToken>()
            .expect("displayed ConsentToken parses");
        let cloned = token.clone();

        let expected_hash = hash_value(&token);

        assert_eq!(hash_value(&display_roundtrip), expected_hash);
        assert_eq!(hash_value(&cloned), expected_hash);
        assert_eq!(display_roundtrip, token);
    }
}

#[test]
fn consent_token_hashmap_lookup_survives_display_roundtrip() {
    let token = "consent:github.repo".parse::<ConsentToken>().unwrap();
    let display_roundtrip = token
        .to_string()
        .parse::<ConsentToken>()
        .expect("displayed ConsentToken parses");
    let via_new = ConsentToken::new("consent:github.repo").expect("new ConsentToken");
    let mut decisions = HashMap::new();

    decisions.insert(token, "approved");

    assert_eq!(decisions.get(&display_roundtrip), Some(&"approved"));
    assert_eq!(decisions.get(&via_new), Some(&"approved"));
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
