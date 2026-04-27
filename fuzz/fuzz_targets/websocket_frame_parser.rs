#![no_main]
//! WebSocket frame parser fuzz target (`flywheel_connectors-q4kuy`).
//!
//! Drives the real websocket receive path used by `fcp-streaming` over
//! adversarial post-upgrade wire bytes:
//! - arbitrary opcode / FIN / RSV / length combinations,
//! - partial reads that split frame headers and payloads,
//! - fragmented data/control sequences,
//! - malformed close payloads and oversized control frames.
//!
//! Invariants:
//! 1. The parser never panics on hostile wire input.
//! 2. Accepted messages round-trip stably through `fcp-streaming::WsMessage`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use arbitrary::{Arbitrary, Unstructured};
use fcp_async_core::{
    compatibility_cx,
    io::{AsyncRead, AsyncWrite, ReadBuf},
    runtime::block_on_sync,
    websocket::{Message, WebSocket, WebSocketConfig},
};
use fcp_streaming::WsMessage;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_FRAME_SIZE_CAP: usize = 64 * 1024;
const MAX_MESSAGE_SIZE_CAP: usize = 256 * 1024;
const MAX_READ_CHUNK_CAP: usize = 256;
const MAX_MESSAGES_PER_INPUT: usize = 128;

#[derive(Arbitrary, Debug)]
struct FuzzInput<'a> {
    max_frame_size_raw: u32,
    max_message_size_raw: u32,
    read_chunk_raw: u16,
    wire: &'a [u8],
}

struct FuzzIo {
    read_data: Vec<u8>,
    read_pos: usize,
    max_read_chunk: usize,
    written: Vec<u8>,
}

impl FuzzIo {
    fn new(read_data: Vec<u8>, max_read_chunk: usize) -> Self {
        Self {
            read_data,
            read_pos: 0,
            max_read_chunk,
            written: Vec::new(),
        }
    }
}

impl AsyncRead for FuzzIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let remaining = &self.read_data[self.read_pos..];
        let to_read = remaining
            .len()
            .min(self.max_read_chunk)
            .min(buf.remaining());
        buf.put_slice(&remaining[..to_read]);
        self.read_pos += to_read;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FuzzIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.written.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn bounded_nonzero(raw: usize, cap: usize) -> usize {
    raw % cap.max(1) + 1
}

fn assert_message_roundtrip(message: Message) {
    let streaming: WsMessage = message.clone().into();
    let wire_roundtrip: Message = streaming.clone().into();
    let streaming_roundtrip: WsMessage = wire_roundtrip.into();
    assert_eq!(
        streaming_roundtrip, streaming,
        "accepted websocket messages must round-trip through WsMessage",
    );
}

fn exercise_wire(
    wire: &[u8],
    max_frame_size: usize,
    max_message_size: usize,
    max_read_chunk: usize,
) {
    let config = WebSocketConfig::new()
        .max_frame_size(max_frame_size)
        .max_message_size(max_message_size)
        .ping_interval(None);
    let cx = compatibility_cx();
    let mut socket = WebSocket::from_upgraded(FuzzIo::new(wire.to_vec(), max_read_chunk), config);

    let _ = block_on_sync(async move {
        for _ in 0..MAX_MESSAGES_PER_INPUT {
            match socket.recv(&cx).await {
                Ok(Some(message)) => assert_message_roundtrip(message),
                Ok(None) | Err(_) => break,
            }
        }
    });
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };

    if input.wire.len() > MAX_INPUT_BYTES {
        return;
    }

    let max_frame_size = bounded_nonzero(input.max_frame_size_raw as usize, MAX_FRAME_SIZE_CAP);
    let max_message_size =
        bounded_nonzero(input.max_message_size_raw as usize, MAX_MESSAGE_SIZE_CAP)
            .max(max_frame_size);
    let max_read_chunk = bounded_nonzero(input.read_chunk_raw as usize, MAX_READ_CHUNK_CAP);

    exercise_wire(input.wire, max_frame_size, max_message_size, max_read_chunk);

    // Tight, deterministic boundary configs so small corpora still hit:
    // - single-byte partial reads (fragmented header/payload parsing),
    // - the RFC 6455 125-byte control-frame ceiling,
    // - small message reassembly limits for continuation paths.
    exercise_wire(input.wire, 125, 125, 1);
    exercise_wire(input.wire, 1024, 1024, max_read_chunk);
});
