use std::str::FromStr;

use fcp_core::{ConnectorId, IdValidationError};

#[test]
fn same_case_connector_id_literals_compare_equal() -> Result<(), IdValidationError> {
    let literal = "github:fcp2:v1";
    let from_static = ConnectorId::from_static(literal);
    let from_str = ConnectorId::from_str(literal)?;
    let from_try_from = ConnectorId::try_from(literal.to_owned())?;
    let from_parts = ConnectorId::new("github", "fcp2", "v1")?;

    assert_eq!(from_static, from_str);
    assert_eq!(from_str, from_try_from);
    assert_eq!(from_try_from, from_parts);
    assert_eq!(from_static.as_str(), literal);

    Ok(())
}

#[test]
fn connector_id_case_differences_are_rejected_not_normalized() {
    let uppercase_inputs = [
        "Github:fcp2:v1",
        "github:FCP2:v1",
        "github:fcp2:V1",
        "GITHUB:FCP2:V1",
    ];

    for input in uppercase_inputs {
        assert_eq!(
            input.parse::<ConnectorId>(),
            Err(IdValidationError::UppercaseNotAllowed),
            "{input} must not be case-normalized"
        );
        assert_eq!(
            ConnectorId::try_from(input.to_owned()),
            Err(IdValidationError::UppercaseNotAllowed),
            "{input} must not be accepted through TryFrom<String>"
        );
    }

    assert_eq!(
        ConnectorId::new("Github", "fcp2", "v1"),
        Err(IdValidationError::UppercaseNotAllowed)
    );
}

#[test]
fn connector_id_from_str_display_roundtrip_preserves_exact_case() -> Result<(), IdValidationError> {
    for literal in [
        "github:fcp2:v1",
        "github:fcp2:1.0",
        "git-hub:fcp_2:v1",
        "vendor.connector:fcp2:2026-04",
    ] {
        let parsed = ConnectorId::from_str(literal)?;
        let displayed = parsed.to_string();

        assert_eq!(displayed, literal);
        assert_eq!(ConnectorId::from_str(&displayed)?, parsed);
        assert_eq!(String::from(parsed), literal);
    }

    Ok(())
}
