use std::fs;
use std::path::PathBuf;

fn host_bin_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bin/fcp-host.rs");
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read host binary source '{}': {error}",
            path.display()
        )
    })
}

#[test]
fn test_empty_zone_set_rejects_invoke() {
    let source = host_bin_source();
    assert!(
        source.contains("HostError::ZoneEnvelopeRequired")
            && source.contains("require_allowed_zones_configured(&request.connector_id"),
        "invoke verification must reject an empty allowed_zones set with ZoneEnvelopeRequired"
    );
    assert!(
        !source.contains("empty + !enforce_empty -> back-compat permissive path"),
        "invoke verification must not retain the old empty-zone permissive branch"
    );
}

#[test]
fn test_empty_zone_set_rejects_health_check() {
    let source = host_bin_source();
    assert!(
        source.contains("first_zone_envelope_error")
            && source.contains("rejecting host health before connector health RPC"),
        "health handling must reject missing zone envelopes before connector health RPC"
    );
}

#[test]
fn test_empty_zone_set_rejects_introspect() {
    let source = host_bin_source();
    assert!(
        source.contains("zone_envelope_status(&connector_id)")
            && source.contains("rejecting introspection before connector RPC"),
        "introspection handling must reject missing zone envelopes before connector introspection RPC"
    );
}

#[test]
fn test_one_zone_works() {
    let source = host_bin_source();
    assert!(
        source.contains("!allowed.iter().any(|zone| zone == request.zone_id.as_str())"),
        "non-empty allowed_zones must keep the explicit zone membership check"
    );
}
