//! `CredentialId` UUID contract + `CredentialApplication`
//! wire-format conformance.
//!
//! `fcp_core::CredentialId` is the UUID-backed handle used to
//! reference stored credentials. `fcp_core::CredentialApplication`
//! is the 8-variant NORMATIVE enum that tells the egress proxy
//! HOW to apply a credential to outbound traffic. The serde tag
//! format and per-variant payloads are wire contracts every
//! credential consumer depends on.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **CredentialId is serde-transparent.** Serializes as a bare
//!    UUID string — no wrapping object. Forward compat with bare-
//!    UUID JSON readers.
//! 2. **CredentialId::from_uuid round-trips with as_uuid.**
//! 3. **CredentialId::parse rejects non-UUID strings.**
//! 4. **Default == new() (random UUIDs)** — two `Default::default`
//!    calls MUST produce distinct ids (collision rate ≈ 2⁻¹²²).
//! 5. **Display + parse round-trip.**
//! 6. **CredentialApplication tag format.** `{"type":"<variant>"}`
//!    in JSON, with snake_case rename.
//! 7. **HttpHeader.prefix is optional and omitted when None.**
//! 8. **Each variant round-trips cleanly via JSON.**

use fcp_core::{CredentialApplication, CredentialId};
use uuid::Uuid;

#[test]
fn credential_id_serde_transparent_via_uuid_string() {
    let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid");
    let id = CredentialId::from_uuid(uuid);
    let json = serde_json::to_string(&id).expect("serialize");
    assert_eq!(
        json, "\"550e8400-e29b-41d4-a716-446655440000\"",
        "CredentialId MUST serialize transparently as a bare UUID string; got {json}"
    );

    let parsed: CredentialId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(*parsed.as_uuid(), uuid);
}

#[test]
fn credential_id_from_uuid_round_trips_with_as_uuid() {
    let uuid = Uuid::new_v4();
    let id = CredentialId::from_uuid(uuid);
    assert_eq!(*id.as_uuid(), uuid);
}

#[test]
fn credential_id_parse_accepts_valid_uuid_string() {
    let s = "550e8400-e29b-41d4-a716-446655440000";
    let id = CredentialId::parse(s).expect("valid uuid string must parse");
    assert_eq!(format!("{id}"), s);
}

#[test]
fn credential_id_parse_rejects_non_uuid_string() {
    assert!(CredentialId::parse("not-a-uuid").is_err());
    assert!(CredentialId::parse("").is_err());
    assert!(CredentialId::parse("550e8400-e29b-41d4").is_err());
}

#[test]
fn credential_id_default_yields_distinct_random_ids() {
    let a = CredentialId::default();
    let b = CredentialId::default();
    assert_ne!(
        a, b,
        "Default::default MUST yield random UUIDs — two calls MUST produce distinct ids \
         (collision rate ≈ 2⁻¹²²)"
    );
}

#[test]
fn credential_id_new_yields_distinct_random_ids() {
    let a = CredentialId::new();
    let b = CredentialId::new();
    assert_ne!(a, b, "CredentialId::new MUST be random");
}

#[test]
fn credential_id_display_round_trips_with_parse() {
    let original = CredentialId::new();
    let s = format!("{original}");
    let parsed = CredentialId::parse(&s).expect("display output must parse");
    assert_eq!(parsed, original);
}

#[test]
fn credential_id_debug_includes_uuid_string() {
    let id = CredentialId::from_uuid(
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
    );
    let dbg = format!("{id:?}");
    assert!(
        dbg.contains("550e8400"),
        "Debug MUST include the UUID for observability; got {dbg}"
    );
}

#[test]
fn credential_application_http_bearer_serde_format() {
    let app = CredentialApplication::HttpAuthorizationBearer;
    let json = serde_json::to_string(&app).expect("serialize");
    assert_eq!(
        json, "{\"type\":\"http_authorization_bearer\"}",
        "HttpAuthorizationBearer MUST serialize with snake_case 'type' tag"
    );
    let parsed: CredentialApplication = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, app);
}

#[test]
fn credential_application_http_basic_serde_format() {
    let app = CredentialApplication::HttpAuthorizationBasic;
    let json = serde_json::to_string(&app).expect("serialize");
    assert_eq!(json, "{\"type\":\"http_authorization_basic\"}");
}

#[test]
fn credential_application_http_header_with_prefix_serde() {
    let app = CredentialApplication::HttpHeader {
        name: "X-API-Key".into(),
        prefix: Some("ApiKey ".into()),
    };
    let json = serde_json::to_string(&app).expect("serialize");
    assert!(json.contains("\"type\":\"http_header\""));
    assert!(json.contains("\"name\":\"X-API-Key\""));
    assert!(json.contains("\"prefix\":\"ApiKey \""));

    let parsed: CredentialApplication = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, app);
}

#[test]
fn credential_application_http_header_omits_prefix_when_none() {
    // Forward compat: pre-prefix readers expect no `prefix` field.
    let app = CredentialApplication::HttpHeader {
        name: "X-API-Key".into(),
        prefix: None,
    };
    let json = serde_json::to_string(&app).expect("serialize");
    assert!(
        !json.contains("prefix"),
        "HttpHeader.prefix=None MUST be omitted from JSON for forward compat with \
         pre-prefix readers; got {json}"
    );
}

#[test]
fn credential_application_query_parameter_serde() {
    let app = CredentialApplication::QueryParameter {
        name: "api_key".into(),
    };
    let json = serde_json::to_string(&app).expect("serialize");
    assert!(json.contains("\"type\":\"query_parameter\""));
    assert!(json.contains("\"name\":\"api_key\""));

    let parsed: CredentialApplication = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, app);
}

#[test]
fn credential_application_unit_variants_round_trip() {
    // Each unit variant (no payload) MUST serialize+deserialize
    // cleanly so consumers can match on the type tag without
    // worrying about extra fields.
    let unit_variants = [
        CredentialApplication::HttpAuthorizationBearer,
        CredentialApplication::HttpAuthorizationBasic,
        CredentialApplication::TlsClientCertificate,
        CredentialApplication::SshKey,
        CredentialApplication::DatabaseConnection,
        CredentialApplication::WebSocketAuth,
    ];
    for app in unit_variants {
        let json = serde_json::to_string(&app).expect("serialize");
        let parsed: CredentialApplication =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, app, "round-trip failed for {app:?}");
    }
}

#[test]
fn credential_application_generic_variant_serde() {
    let app = CredentialApplication::Generic {
        config: "kv:foo=bar".into(),
    };
    let json = serde_json::to_string(&app).expect("serialize");
    assert!(json.contains("\"type\":\"generic\""));
    assert!(json.contains("\"config\":\"kv:foo=bar\""));

    let parsed: CredentialApplication = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, app);
}

#[test]
fn credential_application_unknown_variant_in_json_is_rejected() {
    // Defensive: a JSON payload with an unknown 'type' MUST NOT
    // silently match a known variant. Consumers must see the
    // error and route it through their fallback path.
    let bogus = "{\"type\":\"definitely_not_a_real_variant\"}";
    let result = serde_json::from_str::<CredentialApplication>(bogus);
    assert!(
        result.is_err(),
        "unknown CredentialApplication variant MUST fail to deserialize; got Ok({result:?})"
    );
}

#[test]
fn credential_id_ordering_is_total() {
    // CredentialId derives Ord — this lets callers store ids in
    // BTreeSets/BTreeMaps for deterministic enumeration. Pin the
    // total-order property indirectly: any pair compares
    // consistently.
    let a = CredentialId::from_uuid(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap());
    let b = CredentialId::from_uuid(Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap());
    assert!(a < b);
    assert!(b > a);
    assert_ne!(a, b);
}
