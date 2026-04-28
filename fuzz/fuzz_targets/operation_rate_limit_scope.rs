#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::OperationRateLimitScope;
use libfuzzer_sys::fuzz_target;
use std::str::FromStr;
use std::sync::Once;

const MAX_INPUT_BYTES: usize = 256;
const ACCEPTED: &[(&str, OperationRateLimitScope)] = &[
    ("per_connector", OperationRateLimitScope::PerConnector),
    ("per_zone", OperationRateLimitScope::PerZone),
    ("per_principal", OperationRateLimitScope::PerPrincipal),
];

static ANCHORS: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    raw: Vec<u8>,
}

fn bounded_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_INPUT_BYTES)]).into_owned()
}

fn expected_scope(value: &str) -> Option<OperationRateLimitScope> {
    ACCEPTED
        .iter()
        .find_map(|(name, scope)| (*name == value).then_some(*scope))
}

fuzz_target!(|data: &[u8]| {
    ANCHORS.call_once(assert_anchors);

    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    let candidate = bounded_lossy(&input.raw);
    let parsed = OperationRateLimitScope::from_str(&candidate);

    assert_eq!(
        parsed.ok(),
        expected_scope(&candidate),
        "OperationRateLimitScope parser accepted or rejected a non-canonical spelling"
    );

    if let Some(scope) = expected_scope(&candidate) {
        assert_eq!(
            scope.to_string(),
            candidate,
            "Display output must preserve canonical parser spelling"
        );
        assert_eq!(
            OperationRateLimitScope::from_str(&scope.to_string())
                .expect("Display output must parse"),
            scope
        );

        let json = serde_json::to_string(&scope).expect("scope must serialize");
        assert_eq!(
            serde_json::from_str::<OperationRateLimitScope>(&json)
                .expect("serialized scope must parse"),
            scope
        );
    }
});

fn assert_anchors() {
    for (name, scope) in ACCEPTED {
        assert_eq!(
            OperationRateLimitScope::from_str(name).expect("anchor parses"),
            *scope
        );
        assert_eq!(scope.to_string(), *name);
    }

    for rejected in [
        "",
        "per-connector",
        "per_connector ",
        " per_connector",
        "PER_CONNECTOR",
        "per_project",
    ] {
        assert!(
            OperationRateLimitScope::from_str(rejected).is_err(),
            "anchor spelling must stay rejected: {rejected:?}"
        );
    }
}
