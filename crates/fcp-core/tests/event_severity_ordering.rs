use std::cmp::Ordering;

use ciborium::value::Value as CborValue;
use fcp_core::EventSeverity;

const ASCENDING: [EventSeverity; 5] = [
    EventSeverity::Info,
    EventSeverity::Notice,
    EventSeverity::Warning,
    EventSeverity::Error,
    EventSeverity::Critical,
];

const CASES: [(EventSeverity, &str); 5] = [
    (EventSeverity::Info, "info"),
    (EventSeverity::Notice, "notice"),
    (EventSeverity::Warning, "warning"),
    (EventSeverity::Error, "error"),
    (EventSeverity::Critical, "critical"),
];

#[test]
fn event_severity_ordering_is_pinned() {
    assert_eq!(
        ASCENDING,
        [
            EventSeverity::Info,
            EventSeverity::Notice,
            EventSeverity::Warning,
            EventSeverity::Error,
            EventSeverity::Critical,
        ]
    );

    for pair in ASCENDING.windows(2) {
        assert!(pair[0] < pair[1]);
        assert_eq!(pair[0].partial_cmp(&pair[1]), Some(Ordering::Less));
        assert_eq!(pair[1].partial_cmp(&pair[0]), Some(Ordering::Greater));
    }

    for severity in ASCENDING {
        assert_eq!(severity.partial_cmp(&severity), Some(Ordering::Equal));
    }
}

#[test]
fn event_severity_display_matches_json_tag() {
    for (severity, tag) in CASES {
        assert_eq!(severity.to_string(), tag);
        assert_eq!(
            serde_json::to_string(&severity).expect("serialize"),
            format!("\"{tag}\"")
        );

        let from_json: EventSeverity =
            serde_json::from_str(&format!("\"{tag}\"")).expect("deserialize");
        assert_eq!(from_json, severity);
    }
}

#[test]
fn event_severity_cbor_tag_is_text_and_roundtrips() {
    for (severity, tag) in CASES {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&severity, &mut encoded).expect("encode");

        let value: CborValue = ciborium::de::from_reader(encoded.as_slice()).expect("decode value");
        assert_eq!(value, CborValue::Text(tag.to_string()));

        let decoded: EventSeverity =
            ciborium::de::from_reader(encoded.as_slice()).expect("decode severity");
        assert_eq!(decoded, severity);
    }
}

#[test]
fn event_severity_rejects_noncanonical_json_tags() {
    for bad in ["Info", "WARNING", "warn", "critical_alert", ""] {
        assert!(serde_json::from_str::<EventSeverity>(&format!("\"{bad}\"")).is_err());
    }
}
