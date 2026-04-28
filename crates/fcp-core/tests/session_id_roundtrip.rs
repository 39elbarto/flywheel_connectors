use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
};

use fcp_core::SessionId;
use uuid::Uuid;

const CANONICAL_SESSION_ID: &str = "01234567-89ab-cdef-0123-456789abcdef";

#[test]
fn session_id_display_from_str_roundtrips() {
    let parsed = CANONICAL_SESSION_ID
        .parse::<SessionId>()
        .expect("canonical UUID parses as SessionId");

    assert_eq!(parsed.to_string(), CANONICAL_SESSION_ID);

    let displayed = parsed.to_string();
    let reparsed = displayed
        .parse::<SessionId>()
        .expect("displayed SessionId parses");
    let constructed = SessionId(Uuid::parse_str(CANONICAL_SESSION_ID).expect("UUID parses"));

    assert_eq!(parsed, reparsed);
    assert_eq!(parsed, constructed);
    assert_eq!(format!("{parsed}"), CANONICAL_SESSION_ID);
}

#[test]
fn session_id_hash_is_deterministic_across_display_roundtrips() {
    let parsed = CANONICAL_SESSION_ID
        .parse::<SessionId>()
        .expect("canonical UUID parses as SessionId");
    let display_roundtrip = parsed
        .to_string()
        .parse::<SessionId>()
        .expect("displayed SessionId parses");
    let clone = parsed.clone();

    let expected_hash = hash_value(&parsed);

    assert_eq!(hash_value(&display_roundtrip), expected_hash);
    assert_eq!(hash_value(&clone), expected_hash);
    assert_eq!(hash_value(&SessionId(parsed.0)), expected_hash);
}

#[test]
fn session_id_hash_lookup_survives_display_roundtrip() {
    let parsed = CANONICAL_SESSION_ID
        .parse::<SessionId>()
        .expect("canonical UUID parses as SessionId");
    let display_roundtrip = parsed
        .to_string()
        .parse::<SessionId>()
        .expect("displayed SessionId parses");
    let mut sessions = HashMap::new();

    sessions.insert(parsed, "session");

    assert_eq!(sessions.get(&display_roundtrip), Some(&"session"));
}

fn hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}
