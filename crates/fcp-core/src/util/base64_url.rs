use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// Encode bytes as unpadded URL-safe base64.
#[must_use]
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode unpadded URL-safe base64 bytes.
///
/// # Errors
///
/// Returns a base64 decode error when `input` is not valid URL-safe base64.
pub fn decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(input)
}
