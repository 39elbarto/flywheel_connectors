use fcp_core::ConnectorRoute;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct ConnectorRouteCase {
    value: ConnectorRoute,
    json_tag: &'static str,
    cbor_hex: &'static str,
}

const CASES: &[ConnectorRouteCase] = &[
    ConnectorRouteCase {
        value: ConnectorRoute::RequestResponse,
        json_tag: r#""request-response""#,
        cbor_hex: "70726571756573742d726573706f6e7365",
    },
    ConnectorRouteCase {
        value: ConnectorRoute::Streaming,
        json_tag: r#""streaming""#,
        cbor_hex: "6973747265616d696e67",
    },
    ConnectorRouteCase {
        value: ConnectorRoute::Bidirectional,
        json_tag: r#""bidirectional""#,
        cbor_hex: "6d6269646972656374696f6e616c",
    },
    ConnectorRouteCase {
        value: ConnectorRoute::Polling,
        json_tag: r#""polling""#,
        cbor_hex: "67706f6c6c696e67",
    },
    ConnectorRouteCase {
        value: ConnectorRoute::Webhook,
        json_tag: r#""webhook""#,
        cbor_hex: "67776562686f6f6b",
    },
    ConnectorRouteCase {
        value: ConnectorRoute::Queue,
        json_tag: r#""queue""#,
        cbor_hex: "657175657565",
    },
    ConnectorRouteCase {
        value: ConnectorRoute::File,
        json_tag: r#""file""#,
        cbor_hex: "6466696c65",
    },
    ConnectorRouteCase {
        value: ConnectorRoute::Database,
        json_tag: r#""database""#,
        cbor_hex: "686461746162617365",
    },
    ConnectorRouteCase {
        value: ConnectorRoute::Cli,
        json_tag: r#""cli""#,
        cbor_hex: "63636c69",
    },
    ConnectorRouteCase {
        value: ConnectorRoute::Browser,
        json_tag: r#""browser""#,
        cbor_hex: "6762726f77736572",
    },
];

#[test]
fn connector_route_json_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let encoded = serde_json::to_string(&case.value)?;
        assert_eq!(encoded, case.json_tag);
        assert_eq!(case.value.as_str(), case.json_tag.trim_matches('"'));

        let decoded: ConnectorRoute = serde_json::from_str(case.json_tag)?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn connector_route_display_matches_canonical_serde_tag_for_each_variant() {
    for case in CASES {
        let tag = case.json_tag.trim_matches('"');
        assert_eq!(case.value.as_str(), tag);
        assert_eq!(case.value.to_string(), tag);
    }
}

#[test]
fn connector_route_cbor_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let mut encoded = Vec::new();
        ciborium::into_writer(&case.value, &mut encoded)?;
        assert_eq!(hex::encode(&encoded), case.cbor_hex);

        let decoded: ConnectorRoute = ciborium::from_reader(encoded.as_slice())?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn connector_route_rejects_undocumented_tags() {
    for invalid in [
        r#""request_response""#,
        r#""REQUEST-RESPONSE""#,
        r#""event-driven""#,
        r#""unknown""#,
    ] {
        assert!(
            serde_json::from_str::<ConnectorRoute>(invalid).is_err(),
            "{invalid}"
        );
    }
}
