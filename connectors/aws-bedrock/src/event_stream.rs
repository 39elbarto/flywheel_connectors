use std::collections::BTreeMap;

const PRELUDE_LEN: usize = 8;
const PRELUDE_CRC_LEN: usize = 4;
const MESSAGE_CRC_LEN: usize = 4;
const MESSAGE_OVERHEAD_LEN: usize = PRELUDE_LEN + PRELUDE_CRC_LEN + MESSAGE_CRC_LEN;
const MAX_EVENT_STREAM_MESSAGE_BYTES: usize = 25 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum HeaderValue {
    Bool(bool),
    Byte(i8),
    Short(i16),
    Int(i32),
    Long(i64),
    ByteArray(Vec<u8>),
    String(String),
    Timestamp(i64),
    Uuid([u8; 16]),
}

impl HeaderValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EventStreamMessage {
    pub headers: BTreeMap<String, HeaderValue>,
    pub payload: Vec<u8>,
}

impl EventStreamMessage {
    pub fn event_type(&self) -> Option<&str> {
        self.headers
            .get(":event-type")
            .and_then(HeaderValue::as_str)
            .or_else(|| {
                self.headers
                    .get(":message-type")
                    .and_then(HeaderValue::as_str)
            })
    }

    pub fn payload_json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.payload).ok()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EventStreamError {
    #[error("event-stream message too small")]
    TooSmall,

    #[error("event-stream message exceeds maximum size")]
    TooLarge,

    #[error("event-stream frame length is inconsistent")]
    InvalidLength,

    #[error("event-stream prelude CRC mismatch")]
    PreludeCrcMismatch,

    #[error("event-stream message CRC mismatch")]
    MessageCrcMismatch,

    #[error("event-stream header is malformed")]
    MalformedHeader,

    #[error("event-stream header uses unsupported value type {0}")]
    UnsupportedHeaderType(u8),

    #[error("event-stream header is not valid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

#[derive(Debug, Default)]
pub struct EventStreamDecoder {
    buffer: Vec<u8>,
}

impl EventStreamDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<EventStreamMessage>, EventStreamError> {
        self.buffer.extend_from_slice(bytes);
        let mut messages = Vec::new();

        loop {
            if self.buffer.len() < MESSAGE_OVERHEAD_LEN {
                break;
            }
            let total_len = read_u32(&self.buffer[0..4]) as usize;
            let headers_len = read_u32(&self.buffer[4..8]) as usize;
            if total_len < MESSAGE_OVERHEAD_LEN {
                return Err(EventStreamError::InvalidLength);
            }
            if total_len > MAX_EVENT_STREAM_MESSAGE_BYTES {
                return Err(EventStreamError::TooLarge);
            }
            if headers_len > total_len - MESSAGE_OVERHEAD_LEN {
                return Err(EventStreamError::InvalidLength);
            }
            if self.buffer.len() < total_len {
                break;
            }

            let frame = self.buffer[..total_len].to_vec();
            validate_crc(&frame)?;
            messages.push(decode_complete_frame(&frame, headers_len)?);
            self.buffer.drain(..total_len);
        }

        Ok(messages)
    }

    pub fn finish(self) -> Result<(), EventStreamError> {
        if self.buffer.is_empty() {
            Ok(())
        } else {
            Err(EventStreamError::TooSmall)
        }
    }
}

pub fn decode_event_stream(bytes: &[u8]) -> Result<Vec<EventStreamMessage>, EventStreamError> {
    let mut decoder = EventStreamDecoder::new();
    let messages = decoder.push(bytes)?;
    decoder.finish()?;
    Ok(messages)
}

pub fn encode_event_stream_message(headers: &BTreeMap<String, String>, payload: &[u8]) -> Vec<u8> {
    let mut encoded_headers = Vec::new();
    for (name, value) in headers {
        let name_bytes = name.as_bytes();
        let value_bytes = value.as_bytes();
        encoded_headers.push(u8::try_from(name_bytes.len()).expect("header name too long"));
        encoded_headers.extend_from_slice(name_bytes);
        encoded_headers.push(7);
        encoded_headers.extend_from_slice(
            &u16::try_from(value_bytes.len())
                .expect("header value too long")
                .to_be_bytes(),
        );
        encoded_headers.extend_from_slice(value_bytes);
    }

    let total_len = MESSAGE_OVERHEAD_LEN + encoded_headers.len() + payload.len();
    let mut frame = Vec::with_capacity(total_len);
    frame.extend_from_slice(
        &u32::try_from(total_len)
            .expect("event-stream frame too large")
            .to_be_bytes(),
    );
    frame.extend_from_slice(
        &u32::try_from(encoded_headers.len())
            .expect("event-stream headers too large")
            .to_be_bytes(),
    );
    let prelude_crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&prelude_crc.to_be_bytes());
    frame.extend_from_slice(&encoded_headers);
    frame.extend_from_slice(payload);
    let message_crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&message_crc.to_be_bytes());
    frame
}

fn validate_crc(frame: &[u8]) -> Result<(), EventStreamError> {
    let expected_prelude_crc = read_u32(&frame[8..12]);
    let actual_prelude_crc = crc32fast::hash(&frame[0..8]);
    if expected_prelude_crc != actual_prelude_crc {
        return Err(EventStreamError::PreludeCrcMismatch);
    }

    let expected_message_crc = read_u32(&frame[frame.len() - 4..frame.len()]);
    let actual_message_crc = crc32fast::hash(&frame[..frame.len() - 4]);
    if expected_message_crc != actual_message_crc {
        return Err(EventStreamError::MessageCrcMismatch);
    }
    Ok(())
}

fn decode_complete_frame(
    frame: &[u8],
    headers_len: usize,
) -> Result<EventStreamMessage, EventStreamError> {
    let headers_start = PRELUDE_LEN + PRELUDE_CRC_LEN;
    let headers_end = headers_start + headers_len;
    if headers_end > frame.len() - MESSAGE_CRC_LEN {
        return Err(EventStreamError::InvalidLength);
    }
    let payload_end = frame.len() - MESSAGE_CRC_LEN;
    Ok(EventStreamMessage {
        headers: decode_headers(&frame[headers_start..headers_end])?,
        payload: frame[headers_end..payload_end].to_vec(),
    })
}

fn decode_headers(bytes: &[u8]) -> Result<BTreeMap<String, HeaderValue>, EventStreamError> {
    let mut headers = BTreeMap::new();
    let mut index = 0;
    while index < bytes.len() {
        let name_len = *bytes.get(index).ok_or(EventStreamError::MalformedHeader)? as usize;
        index += 1;
        let name_end = index + name_len;
        let name = std::str::from_utf8(
            bytes
                .get(index..name_end)
                .ok_or(EventStreamError::MalformedHeader)?,
        )?
        .to_string();
        index = name_end;
        let value_type = *bytes.get(index).ok_or(EventStreamError::MalformedHeader)?;
        index += 1;
        let value = decode_header_value(value_type, bytes, &mut index)?;
        headers.insert(name, value);
    }
    Ok(headers)
}

fn decode_header_value(
    value_type: u8,
    bytes: &[u8],
    index: &mut usize,
) -> Result<HeaderValue, EventStreamError> {
    match value_type {
        0 => Ok(HeaderValue::Bool(true)),
        1 => Ok(HeaderValue::Bool(false)),
        2 => {
            let raw = *bytes.get(*index).ok_or(EventStreamError::MalformedHeader)?;
            *index += 1;
            Ok(HeaderValue::Byte(i8::from_be_bytes([raw])))
        }
        3 => {
            let raw = take(bytes, index, 2)?;
            Ok(HeaderValue::Short(i16::from_be_bytes([raw[0], raw[1]])))
        }
        4 => {
            let raw = take(bytes, index, 4)?;
            Ok(HeaderValue::Int(i32::from_be_bytes([
                raw[0], raw[1], raw[2], raw[3],
            ])))
        }
        5 | 8 => {
            let raw = take(bytes, index, 8)?;
            let value = i64::from_be_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ]);
            if value_type == 5 {
                Ok(HeaderValue::Long(value))
            } else {
                Ok(HeaderValue::Timestamp(value))
            }
        }
        6 => {
            let len = read_len(bytes, index)?;
            Ok(HeaderValue::ByteArray(take(bytes, index, len)?.to_vec()))
        }
        7 => {
            let len = read_len(bytes, index)?;
            let raw = take(bytes, index, len)?;
            Ok(HeaderValue::String(std::str::from_utf8(raw)?.to_string()))
        }
        9 => {
            let raw = take(bytes, index, 16)?;
            let mut uuid = [0_u8; 16];
            uuid.copy_from_slice(raw);
            Ok(HeaderValue::Uuid(uuid))
        }
        other => Err(EventStreamError::UnsupportedHeaderType(other)),
    }
}

fn read_len(bytes: &[u8], index: &mut usize) -> Result<usize, EventStreamError> {
    let raw = take(bytes, index, 2)?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]) as usize)
}

fn take<'a>(bytes: &'a [u8], index: &mut usize, len: usize) -> Result<&'a [u8], EventStreamError> {
    let end = *index + len;
    let slice = bytes
        .get(*index..end)
        .ok_or(EventStreamError::MalformedHeader)?;
    *index = end;
    Ok(slice)
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_complete_message_with_crc_checks() {
        let mut headers = BTreeMap::new();
        headers.insert(":message-type".into(), "event".into());
        headers.insert(":event-type".into(), "chunk".into());
        let frame = encode_event_stream_message(&headers, br#"{"delta":"hello"}"#);

        let messages = decode_event_stream(&frame).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].event_type(), Some("chunk"));
        assert_eq!(messages[0].payload_json().unwrap()["delta"], "hello");
    }

    #[test]
    fn decodes_partial_frames_incrementally() {
        let mut headers = BTreeMap::new();
        headers.insert(":event-type".into(), "contentBlockDelta".into());
        let frame = encode_event_stream_message(&headers, br#"{"text":"hi"}"#);
        let split_at = frame.len() / 2;
        let mut decoder = EventStreamDecoder::new();

        assert!(decoder.push(&frame[..split_at]).unwrap().is_empty());
        let messages = decoder.push(&frame[split_at..]).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].event_type(), Some("contentBlockDelta"));
        decoder.finish().unwrap();
    }

    #[test]
    fn rejects_bad_message_crc() {
        let headers = BTreeMap::new();
        let mut frame = encode_event_stream_message(&headers, b"{}");
        let last_payload_byte = frame.len() - MESSAGE_CRC_LEN - 1;
        frame[last_payload_byte] ^= 0x01;

        let err = decode_event_stream(&frame).unwrap_err();

        assert!(matches!(err, EventStreamError::MessageCrcMismatch));
    }

    #[test]
    fn rejects_bad_prelude_crc() {
        let headers = BTreeMap::new();
        let mut frame = encode_event_stream_message(&headers, b"{}");
        frame[8] ^= 0x01;

        let err = decode_event_stream(&frame).unwrap_err();

        assert!(matches!(err, EventStreamError::PreludeCrcMismatch));
    }
}
