//! Bounded FCPK/v1 credential framing shared by host and connector code.

use std::fmt;
use std::io::{self, Read};

use crate::ZeroizingSecret;

/// Fixed FCPK frame header size (`FCPK`, version, big-endian length).
pub const HEADER_BYTES: usize = 9;
/// Maximum credential bytes carried by one FCPK frame.
pub const MAX_SECRET_BYTES: usize = 4096;

const MAGIC: &[u8; 4] = b"FCPK";
const VERSION: u8 = 1;

/// Redacted failures for FCPK/v1 parsing and encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialFrameError {
    /// The fixed magic or version was not accepted.
    InvalidFrame,
    /// The frame ended before its header or payload completed.
    Truncated,
    /// The declared payload exceeded the protocol bound.
    Oversized,
    /// The payload was empty.
    Empty,
    /// The payload was not valid UTF-8.
    InvalidUtf8,
    /// The payload is not a conservative ASCII header value.
    InvalidHeaderValue,
    /// Bytes remained after one complete frame.
    TrailingData,
    /// The underlying reader failed.
    Io,
}

impl fmt::Display for CredentialFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFrame => "credential frame is invalid",
            Self::Truncated => "credential frame is truncated",
            Self::Oversized => "credential frame is oversized",
            Self::Empty => "credential frame is empty",
            Self::InvalidUtf8 => "credential frame is not valid UTF-8",
            Self::InvalidHeaderValue => "credential frame is not a valid header value",
            Self::TrailingData => "credential frame has trailing data",
            Self::Io => "credential frame could not be read",
        })
    }
}

impl std::error::Error for CredentialFrameError {}

/// Validate secret material without copying or exposing it.
///
/// # Errors
///
/// Returns a bounded, redacted [`CredentialFrameError`] when the secret is
/// empty, oversized, non-UTF-8, or unsuitable for an HTTP header value.
pub fn validate_secret(secret: &ZeroizingSecret) -> Result<(), CredentialFrameError> {
    secret.with_bytes(|bytes| {
        if bytes.is_empty() {
            return Err(CredentialFrameError::Empty);
        }
        if bytes.len() > MAX_SECRET_BYTES {
            return Err(CredentialFrameError::Oversized);
        }
        let value = std::str::from_utf8(bytes).map_err(|_| CredentialFrameError::InvalidUtf8)?;
        if value.trim() != value
            || bytes
                .iter()
                .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
        {
            return Err(CredentialFrameError::InvalidHeaderValue);
        }
        Ok(())
    })
}

/// Encode one validated secret as a zeroizing FCPK/v1 frame.
///
/// # Errors
///
/// Returns a redacted [`CredentialFrameError`] when validation fails or the
/// secret length cannot be represented by the frame format.
pub fn encode(secret: &ZeroizingSecret) -> Result<ZeroizingSecret, CredentialFrameError> {
    validate_secret(secret)?;
    let mut frame = Vec::with_capacity(HEADER_BYTES + secret.len());
    frame.extend_from_slice(MAGIC);
    frame.push(VERSION);
    frame.extend_from_slice(
        &u32::try_from(secret.len())
            .map_err(|_| CredentialFrameError::Oversized)?
            .to_be_bytes(),
    );
    secret.with_bytes(|bytes| frame.extend_from_slice(bytes));
    Ok(ZeroizingSecret::with_zeroize_drop(frame))
}

/// Parse exactly one FCPK/v1 frame from an in-memory buffer.
///
/// # Errors
///
/// Returns a redacted [`CredentialFrameError`] when the frame is malformed,
/// truncated, oversized, contains trailing bytes, or carries an invalid secret.
pub fn parse(frame: &[u8]) -> Result<ZeroizingSecret, CredentialFrameError> {
    if frame.len() < HEADER_BYTES {
        return Err(CredentialFrameError::Truncated);
    }
    if &frame[..MAGIC.len()] != MAGIC || frame[MAGIC.len()] != VERSION {
        return Err(CredentialFrameError::InvalidFrame);
    }
    let length = u32::from_be_bytes(
        frame[5..HEADER_BYTES]
            .try_into()
            .map_err(|_| CredentialFrameError::InvalidFrame)?,
    ) as usize;
    if length == 0 {
        return Err(CredentialFrameError::Empty);
    }
    if length > MAX_SECRET_BYTES {
        return Err(CredentialFrameError::Oversized);
    }
    if frame.len() < HEADER_BYTES + length {
        return Err(CredentialFrameError::Truncated);
    }
    if frame.len() != HEADER_BYTES + length {
        return Err(CredentialFrameError::TrailingData);
    }
    let secret = ZeroizingSecret::with_zeroize_drop(frame[HEADER_BYTES..].to_vec());
    validate_secret(&secret)?;
    Ok(secret)
}

/// Read exactly one FCPK/v1 frame and require EOF immediately afterwards.
///
/// # Errors
///
/// Returns a redacted [`CredentialFrameError`] for malformed or invalid frame
/// data and for failures from the underlying reader.
pub fn read<R: Read>(reader: &mut R) -> Result<ZeroizingSecret, CredentialFrameError> {
    let mut header = [0_u8; HEADER_BYTES];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(CredentialFrameError::Truncated);
        }
        Err(_) => return Err(CredentialFrameError::Io),
    }
    if &header[..MAGIC.len()] != MAGIC || header[MAGIC.len()] != VERSION {
        return Err(CredentialFrameError::InvalidFrame);
    }
    let length = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    if length == 0 {
        return Err(CredentialFrameError::Empty);
    }
    if length > MAX_SECRET_BYTES {
        return Err(CredentialFrameError::Oversized);
    }
    let mut payload = vec![0_u8; length];
    match reader.read_exact(&mut payload) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            drop(ZeroizingSecret::with_zeroize_drop(payload));
            return Err(CredentialFrameError::Truncated);
        }
        Err(_) => {
            drop(ZeroizingSecret::with_zeroize_drop(payload));
            return Err(CredentialFrameError::Io);
        }
    }
    let secret = ZeroizingSecret::with_zeroize_drop(payload);
    validate_secret(&secret)?;
    let mut trailing = [0_u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => Ok(secret),
        Ok(_) => Err(CredentialFrameError::TrailingData),
        Err(_) => Err(CredentialFrameError::Io),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trip_requires_exact_eof() {
        let secret = ZeroizingSecret::with_zeroize_drop(b"api-key".to_vec());
        let frame = encode(&secret).expect("encode");
        let bytes = frame.with_bytes(|bytes| bytes.to_vec());
        assert_eq!(
            parse(&bytes)
                .expect("parse")
                .with_bytes(|bytes| bytes.to_vec()),
            b"api-key"
        );
        assert_eq!(
            read(&mut Cursor::new(bytes))
                .expect("read")
                .with_bytes(|bytes| bytes.to_vec()),
            b"api-key"
        );
    }

    #[test]
    fn rejects_trailing_and_invalid_material() {
        let secret = ZeroizingSecret::with_zeroize_drop(b"api-key".to_vec());
        let frame = encode(&secret).expect("encode");
        let mut bytes = frame.with_bytes(|bytes| bytes.to_vec());
        bytes.push(b'x');
        let error = match parse(&bytes) {
            Err(error) => error,
            Ok(_) => panic!("trailing frame accepted"),
        };
        assert_eq!(error, CredentialFrameError::TrailingData);
        assert_eq!(
            validate_secret(&ZeroizingSecret::with_zeroize_drop(b" bad".to_vec()))
                .expect_err("header"),
            CredentialFrameError::InvalidHeaderValue
        );
    }
}
