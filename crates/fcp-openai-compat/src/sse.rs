//! OpenAI-compatible SSE decoding.

use std::collections::VecDeque;

use bytes::{Buf as _, Bytes, BytesMut};

use crate::{ChatChunk, NetworkError, OpenAiError, StreamingError, redact_sensitive_text};

/// Decoded stream event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenAiStreamEvent {
    /// Chat chunk.
    Chunk(ChatChunk),
    /// Provider sent `data: [DONE]`.
    Done,
}

/// Incremental SSE decoder for OpenAI-compatible chat streams.
#[derive(Debug, Default)]
pub struct OpenAiSseDecoder {
    buffer: BytesMut,
    parse_cursor: usize,
    event_type: Option<String>,
    data_lines: Vec<String>,
    done: bool,
    saw_chunk: bool,
}

impl OpenAiSseDecoder {
    /// Create an empty decoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a chunk of bytes and return all complete stream events.
    pub fn feed(&mut self, bytes: &Bytes) -> Vec<Result<OpenAiStreamEvent, OpenAiError>> {
        self.buffer.extend_from_slice(bytes);
        let mut output = Vec::new();

        while let Some(line_end) = self.find_line_end() {
            let line = self.buffer.split_to(line_end);
            if self.buffer.starts_with(b"\r\n") {
                self.buffer.advance(2);
            } else if self.buffer.starts_with(b"\n") || self.buffer.starts_with(b"\r") {
                self.buffer.advance(1);
            }
            self.parse_cursor = 0;

            let line = String::from_utf8_lossy(&line);
            if line.is_empty() {
                if let Some(event) = self.dispatch_event() {
                    output.push(event);
                }
            } else if !line.starts_with(':') {
                self.process_field(&line);
            }
        }

        output
    }

    /// Finish decoding and report a network drop if `[DONE]` was not observed.
    pub fn finish(&mut self) -> Option<Result<OpenAiStreamEvent, OpenAiError>> {
        if self.done {
            return None;
        }
        if !self.buffer.is_empty() || !self.data_lines.is_empty() || self.saw_chunk {
            return Some(Err(OpenAiError::Network(NetworkError::ConnectionDropped)));
        }
        None
    }

    /// Whether a terminal `[DONE]` was observed.
    pub const fn is_done(&self) -> bool {
        self.done
    }

    fn find_line_end(&mut self) -> Option<usize> {
        let start = self.parse_cursor.min(self.buffer.len());
        for (offset, byte) in self.buffer[start..].iter().enumerate() {
            if *byte == b'\n' || *byte == b'\r' {
                return Some(start + offset);
            }
        }
        self.parse_cursor = self.buffer.len();
        None
    }

    fn process_field(&mut self, line: &str) {
        let (field, value) = line.find(':').map_or((line, ""), |colon| {
            let field = &line[..colon];
            let value = line[colon + 1..]
                .strip_prefix(' ')
                .unwrap_or_else(|| &line[colon + 1..]);
            (field, value)
        });

        match field {
            "event" => self.event_type = Some(value.to_string()),
            "data" => self.data_lines.push(value.to_string()),
            _ => {}
        }
    }

    fn dispatch_event(&mut self) -> Option<Result<OpenAiStreamEvent, OpenAiError>> {
        if self.data_lines.is_empty() {
            self.event_type = None;
            return None;
        }

        let event_type = self.event_type.take();
        let data = self.data_lines.join("\n");
        self.data_lines.clear();

        if data.trim() == "[DONE]" {
            self.done = true;
            return Some(Ok(OpenAiStreamEvent::Done));
        }

        if event_type.as_deref() == Some("error") {
            return Some(Err(OpenAiError::Streaming(StreamingError::ProviderEvent {
                message: redact_sensitive_text(&data),
            })));
        }

        match serde_json::from_str::<ChatChunk>(&data) {
            Ok(chunk) => {
                self.saw_chunk = true;
                Some(Ok(OpenAiStreamEvent::Chunk(chunk)))
            }
            Err(err) => Some(Err(OpenAiError::Streaming(
                StreamingError::MalformedPayload {
                    message: redact_sensitive_text(&format!("{err}: {data}")),
                },
            ))),
        }
    }
}

/// Accumulate streamed content and tool-call argument deltas for tests and
/// callers that need whole-message materialization.
pub fn accumulate_chunks(chunks: &[ChatChunk]) -> (String, Vec<String>) {
    let (content, _reasoning_content, tool_arguments) = accumulate_chunks_with_reasoning(chunks);
    (content, tool_arguments)
}

/// Accumulate streamed final content, reasoning content, and tool-call argument
/// deltas while preserving the distinction between reasoning and final answer.
pub fn accumulate_chunks_with_reasoning(chunks: &[ChatChunk]) -> (String, String, Vec<String>) {
    let mut content = String::new();
    let mut reasoning_content = String::new();
    let mut tool_arguments: VecDeque<String> = VecDeque::new();
    for chunk in chunks {
        for choice in &chunk.choices {
            if let Some(delta) = &choice.delta.content {
                content.push_str(delta);
            }
            if let Some(delta) = &choice.delta.reasoning_content {
                reasoning_content.push_str(delta);
            }
            if let Some(tool_calls) = &choice.delta.tool_calls {
                for tool_call in tool_calls {
                    let index = usize::try_from(tool_call.index).unwrap_or(usize::MAX);
                    while tool_arguments.len() <= index {
                        tool_arguments.push_back(String::new());
                    }
                    if let Some(function) = &tool_call.function {
                        if let Some(arguments) = &function.arguments {
                            if let Some(slot) = tool_arguments.get_mut(index) {
                                slot.push_str(arguments);
                            }
                        }
                    }
                }
            }
        }
    }
    (
        content,
        reasoning_content,
        tool_arguments.into_iter().collect(),
    )
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use serde_json::json;

    use super::*;

    fn decode_all(chunks: &[&str]) -> Vec<Result<OpenAiStreamEvent, OpenAiError>> {
        let mut decoder = OpenAiSseDecoder::new();
        let mut output = Vec::new();
        for chunk in chunks {
            output.extend(decoder.feed(&Bytes::copy_from_slice(chunk.as_bytes())));
        }
        if let Some(event) = decoder.finish() {
            output.push(event);
        }
        output
    }

    fn chunk_json(content: Option<&str>, finish_reason: Option<&str>) -> String {
        json!({
            "id": "chatcmpl-1",
            "object": "chat.completion.chunk",
            "created": 1,
            "model": "test",
            "choices": [{
                "index": 0,
                "delta": {"content": content},
                "finish_reason": finish_reason
            }]
        })
        .to_string()
    }

    #[test]
    fn decodes_single_chunk_and_done() {
        let frame = format!("data: {}\n\ndata: [DONE]\n\n", chunk_json(Some("hi"), None));
        let output = decode_all(&[&frame]);
        assert_eq!(output.len(), 2);
        assert!(matches!(output[0], Ok(OpenAiStreamEvent::Chunk(_))));
        assert!(matches!(output[1], Ok(OpenAiStreamEvent::Done)));
    }

    #[test]
    fn buffers_split_frames() {
        let frame = format!("data: {}\n\n", chunk_json(Some("split"), None));
        let midpoint = frame.len() / 2;
        let output = decode_all(&[&frame[..midpoint], &frame[midpoint..], "data: [DONE]\n\n"]);
        assert!(matches!(output[0], Ok(OpenAiStreamEvent::Chunk(_))));
        assert!(matches!(output[1], Ok(OpenAiStreamEvent::Done)));
    }

    #[test]
    fn ignores_heartbeat_comments() {
        let frame = format!(
            ": heartbeat\n\ndata: {}\n\ndata: [DONE]\n\n",
            chunk_json(Some("x"), None)
        );
        let output = decode_all(&[&frame]);
        assert_eq!(output.len(), 2);
    }

    #[test]
    fn event_error_maps_to_streaming_error() {
        let output = decode_all(&["event: error\ndata: {\"error\":{\"message\":\"bad\"}}\n\n"]);
        assert!(matches!(
            &output[0],
            Err(OpenAiError::Streaming(StreamingError::ProviderEvent { .. }))
        ));
    }

    #[test]
    fn malformed_json_payload_is_rejected() {
        let output = decode_all(&["data: {not-json}\n\ndata: [DONE]\n\n"]);
        assert!(matches!(
            &output[0],
            Err(OpenAiError::Streaming(
                StreamingError::MalformedPayload { .. }
            ))
        ));
    }

    #[test]
    fn network_drop_without_done_is_error() {
        let frame = format!("data: {}\n\n", chunk_json(Some("partial"), None));
        let output = decode_all(&[&frame]);
        assert!(matches!(
            output.last(),
            Some(Err(OpenAiError::Network(NetworkError::ConnectionDropped)))
        ));
    }

    #[test]
    fn accumulates_content_and_tool_call_arguments() {
        let chunks: Vec<ChatChunk> = [
            json!({
                "id": "chatcmpl-1",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "test",
                "choices": [{
                    "index": 0,
                    "delta": {
                        "content": "he",
                        "tool_calls": [{
                            "index": 0,
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "lookup", "arguments": "{\"q\""}
                        }]
                    },
                    "finish_reason": null
                }]
            }),
            json!({
                "id": "chatcmpl-1",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "test",
                "choices": [{
                    "index": 0,
                    "delta": {
                        "content": "llo",
                        "tool_calls": [{
                            "index": 0,
                            "function": {"arguments": ":\"x\"}"}
                        }]
                    },
                    "finish_reason": "tool_calls"
                }]
            }),
        ]
        .into_iter()
        .map(|value| serde_json::from_value(value).expect("chunk fixture is valid"))
        .collect();

        let (content, tool_args) = accumulate_chunks(&chunks);
        assert_eq!(content, "hello");
        assert_eq!(tool_args, vec!["{\"q\":\"x\"}".to_string()]);
    }

    #[test]
    fn accumulates_reasoning_content_separately_from_final_content() {
        let chunks: Vec<ChatChunk> = [
            json!({
                "id": "chunk-1",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "deepseek-v4-pro",
                "choices": [{
                    "index": 0,
                    "delta": {"reasoning_content": "think "},
                    "finish_reason": null
                }]
            }),
            json!({
                "id": "chunk-2",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "deepseek-v4-pro",
                "choices": [{
                    "index": 0,
                    "delta": {"content": "answer"},
                    "finish_reason": "stop"
                }]
            }),
        ]
        .into_iter()
        .map(|value| serde_json::from_value(value).expect("chunk fixture is valid"))
        .collect();

        let (content, reasoning_content, tool_args) = accumulate_chunks_with_reasoning(&chunks);
        assert_eq!(content, "answer");
        assert_eq!(reasoning_content, "think ");
        assert!(tool_args.is_empty());

        let (legacy_content, legacy_tool_args) = accumulate_chunks(&chunks);
        assert_eq!(legacy_content, "answer");
        assert!(legacy_tool_args.is_empty());
    }
}
