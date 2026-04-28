//! PEM block parsing and emission helpers.

use base64::{Engine as _, engine::general_purpose::STANDARD};

/// Standard PEM body line width.
pub const PEM_LINE_WRAP: usize = 64;

/// PEM label for raw FCP Ed25519 public keys.
pub const ED25519_PUBLIC_KEY_PEM_LABEL: &str = "FCP ED25519 PUBLIC KEY";

/// PEM label for raw FCP X25519 public keys.
pub const X25519_PUBLIC_KEY_PEM_LABEL: &str = "FCP X25519 PUBLIC KEY";

/// PEM label for FROST public key packages.
pub const FROST_PUBLIC_KEY_PACKAGE_PEM_LABEL: &str = "FCP FROST PUBLIC KEY PACKAGE";

/// Parsed PEM block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemBlock {
    label: String,
    body: Vec<u8>,
}

impl PemBlock {
    /// Build a PEM block from a label and raw body bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the label is empty or contains a line break.
    pub fn new(label: impl Into<String>, body: impl Into<Vec<u8>>) -> Result<Self, PemError> {
        let label = label.into();
        validate_label(&label)?;
        Ok(Self {
            label,
            body: body.into(),
        })
    }

    /// Return the PEM block label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Return the raw decoded body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Emit the PEM block with 64-character body lines.
    #[must_use]
    pub fn to_pem(&self) -> String {
        let encoded = STANDARD.encode(&self.body);
        let mut pem = String::new();
        pem.push_str("-----BEGIN ");
        pem.push_str(&self.label);
        pem.push_str("-----\n");

        for start in (0..encoded.len()).step_by(PEM_LINE_WRAP) {
            let end = (start + PEM_LINE_WRAP).min(encoded.len());
            pem.push_str(&encoded[start..end]);
            pem.push('\n');
        }

        pem.push_str("-----END ");
        pem.push_str(&self.label);
        pem.push_str("-----\n");
        pem
    }
}

/// Parse a PEM block.
///
/// # Errors
///
/// Returns an error if the block markers are malformed, the END label does not
/// match the BEGIN label, or the body is not valid standard base64.
pub fn parse_pem(input: &str) -> Result<PemBlock, PemError> {
    let input = input.trim_end_matches(['\r', '\n']);
    let mut lines = input.lines();
    let begin = lines.next().ok_or(PemError::MissingBegin)?;
    let label = marker_label(begin, "BEGIN").ok_or(PemError::MissingBegin)?;
    validate_label(label)?;

    let mut body = String::new();
    for line in lines.by_ref() {
        if let Some(end_label) = marker_label(line, "END") {
            if end_label != label {
                return Err(PemError::LabelMismatch {
                    begin: label.to_owned(),
                    end: end_label.to_owned(),
                });
            }

            if lines.next().is_some() {
                return Err(PemError::TrailingData);
            }

            let decoded = STANDARD.decode(body.as_bytes())?;
            return Ok(PemBlock {
                label: label.to_owned(),
                body: decoded,
            });
        }

        if line.is_empty() || line.len() > PEM_LINE_WRAP {
            return Err(PemError::InvalidBodyLine);
        }
        body.push_str(line);
    }

    Err(PemError::MissingEnd)
}

fn marker_label<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.strip_prefix("-----")?
        .strip_prefix(marker)?
        .strip_prefix(' ')?
        .strip_suffix("-----")
}

fn validate_label(label: &str) -> Result<(), PemError> {
    if label.is_empty() || label.contains(['\r', '\n']) {
        return Err(PemError::InvalidLabel);
    }
    Ok(())
}

/// PEM parse or emission error.
#[derive(Debug, thiserror::Error)]
pub enum PemError {
    /// The block does not start with a BEGIN marker.
    #[error("missing PEM BEGIN marker")]
    MissingBegin,
    /// The block does not contain an END marker.
    #[error("missing PEM END marker")]
    MissingEnd,
    /// The BEGIN or END label is invalid.
    #[error("invalid PEM label")]
    InvalidLabel,
    /// The END marker label does not match the BEGIN marker label.
    #[error("PEM label mismatch: BEGIN {begin}, END {end}")]
    LabelMismatch {
        /// Label from the BEGIN marker.
        begin: String,
        /// Label from the END marker.
        end: String,
    },
    /// The base64 body has an empty line or a line longer than 64 characters.
    #[error("invalid PEM body line")]
    InvalidBodyLine,
    /// The block has data after the END marker.
    #[error("trailing data after PEM END marker")]
    TrailingData,
    /// The PEM body is not valid standard base64.
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
}
