use std::{error::Error, fmt};

const MAX_HOSTNAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Validate and canonicalize a DNS hostname.
///
/// The returned hostname is lowercase ASCII/Punycode without a trailing root
/// dot. IP literals are rejected; callers that accept IPs should model those
/// separately from hostnames.
///
/// # Errors
///
/// Returns [`HostnameValidationError`] when the input is empty, cannot be
/// IDNA-encoded as a domain, exceeds hostname or label length limits, contains
/// malformed labels, or is made only of numeric labels.
pub fn validate_hostname(input: &str) -> Result<String, HostnameValidationError> {
    let without_trailing_dot = input.strip_suffix('.').unwrap_or(input);
    if without_trailing_dot.is_empty() {
        return Err(HostnameValidationError::Empty);
    }

    if without_trailing_dot
        .split('.')
        .all(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(HostnameValidationError::AllNumericLabels);
    }

    let host = url::Host::parse(without_trailing_dot).map_err(HostnameValidationError::Invalid)?;
    let url::Host::Domain(canonical) = host else {
        return Err(HostnameValidationError::IpLiteral);
    };

    if canonical.len() > MAX_HOSTNAME_LEN {
        return Err(HostnameValidationError::TooLong {
            len: canonical.len(),
            max: MAX_HOSTNAME_LEN,
        });
    }

    for label in canonical.split('.') {
        validate_label(label)?;
    }

    Ok(canonical)
}

fn validate_label(label: &str) -> Result<(), HostnameValidationError> {
    if label.is_empty() {
        return Err(HostnameValidationError::EmptyLabel);
    }

    if label.len() > MAX_LABEL_LEN {
        return Err(HostnameValidationError::LabelTooLong {
            label: label.to_string(),
            len: label.len(),
            max: MAX_LABEL_LEN,
        });
    }

    let starts_alnum = label
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric);
    let ends_alnum = label
        .as_bytes()
        .last()
        .is_some_and(u8::is_ascii_alphanumeric);
    let allowed_chars = label
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');

    if starts_alnum && ends_alnum && allowed_chars {
        Ok(())
    } else {
        Err(HostnameValidationError::InvalidLabel {
            label: label.to_string(),
        })
    }
}

/// Hostname validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostnameValidationError {
    /// Hostname was empty after removing an optional trailing root dot.
    Empty,
    /// Hostname could not be parsed or IDNA-encoded as a domain name.
    Invalid(url::ParseError),
    /// Hostname parsed as an IP literal instead of a DNS name.
    IpLiteral,
    /// Canonical hostname exceeds the DNS hostname length limit.
    TooLong {
        /// Observed canonical hostname length.
        len: usize,
        /// Maximum accepted canonical hostname length.
        max: usize,
    },
    /// Hostname contains an empty label.
    EmptyLabel,
    /// A canonical hostname label exceeds the DNS label length limit.
    LabelTooLong {
        /// Offending label.
        label: String,
        /// Observed label length.
        len: usize,
        /// Maximum accepted label length.
        max: usize,
    },
    /// A canonical hostname label has an invalid start, end, or character.
    InvalidLabel {
        /// Offending label.
        label: String,
    },
    /// Every hostname label is numeric, making the input IP-like rather than a
    /// DNS hostname.
    AllNumericLabels,
}

impl fmt::Display for HostnameValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("hostname is empty"),
            Self::Invalid(err) => write!(f, "hostname is invalid: {err}"),
            Self::IpLiteral => f.write_str("hostname must not be an IP literal"),
            Self::TooLong { len, max } => {
                write!(f, "hostname length {len} exceeds maximum {max}")
            }
            Self::EmptyLabel => f.write_str("hostname contains an empty label"),
            Self::LabelTooLong { label, len, max } => {
                write!(
                    f,
                    "hostname label {label:?} length {len} exceeds maximum {max}"
                )
            }
            Self::InvalidLabel { label } => {
                write!(f, "hostname label {label:?} is invalid")
            }
            Self::AllNumericLabels => f.write_str("hostname must not contain only numeric labels"),
        }
    }
}

impl Error for HostnameValidationError {}
