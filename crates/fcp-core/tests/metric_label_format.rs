use std::str::FromStr;

use fcp_core::{MAX_METRIC_LABEL_LEN, MetricLabel, MetricLabelValidationError};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn metric_label_accepts_lowercase_dotted_namespace() -> TestResult {
    for raw in [
        "connector.requests",
        "connector_1.requests_2.total3",
        "fcp.connector.invoke.count",
    ] {
        let label = MetricLabel::from_str(raw)?;

        assert_eq!(label.as_str(), raw);
        assert_eq!(label.to_string(), raw);
        assert_eq!(MetricLabel::from_static(raw).as_str(), raw);

        let json = serde_json::to_string(&label)?;
        assert_eq!(json, format!("\"{raw}\""));
        assert_eq!(serde_json::from_str::<MetricLabel>(&json)?, label);
    }

    Ok(())
}

#[test]
fn metric_label_rejects_non_lowercase_forms() {
    assert_eq!(
        MetricLabel::from_str("Connector.requests"),
        Err(MetricLabelValidationError::UppercaseNotAllowed)
    );
    assert_eq!(
        MetricLabel::from_str("connector.Requests"),
        Err(MetricLabelValidationError::UppercaseNotAllowed)
    );
}

#[test]
fn metric_label_requires_dotted_namespace_segments() {
    assert_eq!(
        MetricLabel::from_str("requests"),
        Err(MetricLabelValidationError::MissingNamespaceSeparator)
    );
    assert_eq!(
        MetricLabel::from_str(".requests"),
        Err(MetricLabelValidationError::EmptySegment { index: 0 })
    );
    assert_eq!(
        MetricLabel::from_str("connector..requests"),
        Err(MetricLabelValidationError::EmptySegment { index: 10 })
    );
    assert_eq!(
        MetricLabel::from_str("connector.requests."),
        Err(MetricLabelValidationError::EmptySegment { index: 19 })
    );
    assert_eq!(
        MetricLabel::from_str("connector.1requests"),
        Err(MetricLabelValidationError::InvalidSegmentStart { ch: '1', index: 10 })
    );
}

#[test]
fn metric_label_enforces_length_cap() -> TestResult {
    let max_len = format!("{}.{}", "a".repeat(63), "b".repeat(64));
    assert_eq!(max_len.len(), MAX_METRIC_LABEL_LEN);
    assert_eq!(MetricLabel::from_str(&max_len)?.as_str(), max_len);

    let too_long = format!("{}.{}", "a".repeat(63), "b".repeat(65));
    assert_eq!(too_long.len(), MAX_METRIC_LABEL_LEN + 1);
    assert_eq!(
        MetricLabel::from_str(&too_long),
        Err(MetricLabelValidationError::TooLong {
            len: MAX_METRIC_LABEL_LEN + 1,
            max: MAX_METRIC_LABEL_LEN,
        })
    );

    Ok(())
}

#[test]
fn metric_label_pins_allowed_character_set() {
    assert!(MetricLabel::from_str("connector.requests_total.v2").is_ok());

    for (raw, expected) in [
        (
            "connector-requests.total",
            MetricLabelValidationError::InvalidChar { ch: '-', index: 9 },
        ),
        (
            "connector:requests.total",
            MetricLabelValidationError::InvalidChar { ch: ':', index: 9 },
        ),
        (
            "connector/requests.total",
            MetricLabelValidationError::InvalidChar { ch: '/', index: 9 },
        ),
        (
            "connector requests.total",
            MetricLabelValidationError::InvalidChar { ch: ' ', index: 9 },
        ),
        (
            "connector.requests\n",
            MetricLabelValidationError::InvalidChar {
                ch: '\n',
                index: 18,
            },
        ),
    ] {
        assert_eq!(MetricLabel::from_str(raw), Err(expected), "raw: {raw:?}");
    }

    assert_eq!(
        MetricLabel::from_str("connectør.requests"),
        Err(MetricLabelValidationError::NonAscii)
    );
    assert_eq!(
        MetricLabel::from_str(""),
        Err(MetricLabelValidationError::Empty)
    );
}
