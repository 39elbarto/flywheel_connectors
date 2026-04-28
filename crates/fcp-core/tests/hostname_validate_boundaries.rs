use fcp_core::util::hostname::{HostnameValidationError, validate_hostname};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn assert_valid(raw: &str, expected: &str) -> TestResult {
    assert_eq!(validate_hostname(raw)?, expected);
    Ok(())
}

#[test]
fn hostname_validator_accepts_single_char_and_idn_punycode() -> TestResult {
    assert_valid("a", "a")?;
    assert_valid("münchen.example", "xn--mnchen-3ya.example")?;
    assert_valid("xn--mnchen-3ya.example", "xn--mnchen-3ya.example")?;

    Ok(())
}

#[test]
fn hostname_validator_accepts_max_length_hostname() -> TestResult {
    let max_length = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );

    assert_eq!(max_length.len(), 253);
    assert_valid(&max_length, &max_length)
}

#[test]
fn hostname_validator_canonicalizes_trailing_dot() -> TestResult {
    assert_valid("api.example.com", "api.example.com")?;
    assert_valid("api.example.com.", "api.example.com")?;

    Ok(())
}

#[test]
fn hostname_validator_rejects_empty_and_too_long() {
    assert_eq!(validate_hostname(""), Err(HostnameValidationError::Empty));

    let too_long = format!(
        "{}.{}.{}.{}.e",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );

    assert_eq!(too_long.len(), 255);
    assert!(matches!(
        validate_hostname(&too_long),
        Err(HostnameValidationError::TooLong { len: 255, max: 253 })
    ));
}

#[test]
fn hostname_validator_rejects_leading_dash_and_invalid_chars() {
    assert_eq!(
        validate_hostname("-api.example.com"),
        Err(HostnameValidationError::InvalidLabel {
            label: "-api".to_string()
        })
    );
    assert_eq!(
        validate_hostname("api.-example.com"),
        Err(HostnameValidationError::InvalidLabel {
            label: "-example".to_string()
        })
    );

    assert!(validate_hostname("bad host.example.com").is_err());
    assert!(validate_hostname("bad_host.example.com").is_err());
}

#[test]
fn hostname_validator_rejects_all_numeric_labels() {
    assert_eq!(
        validate_hostname("123.456.789"),
        Err(HostnameValidationError::AllNumericLabels)
    );
}
