//! Twilio Media Streams parsing and deterministic pacing helpers.

use std::collections::{HashMap, HashSet, VecDeque};

use base64::Engine;
use fcp_prelude::{FcpError, FcpResult};
use fcp_sdk::runtime::SupervisorConfig;
use fcp_voice_call::CallAuthToken;
use serde::Serialize;
use serde_json::{Value, json};

const TELEPHONY_SAMPLE_RATE_HZ: usize = 8_000;
const TELEPHONY_CHUNK_BYTES: usize = 160;
const DEFAULT_MAX_FRAME_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_MEDIA_PAYLOAD_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_QUEUED_AUDIO_BYTES: usize = TELEPHONY_SAMPLE_RATE_HZ * 120;
const DEFAULT_STREAM_TOKEN_TTL_MS: u64 = 30_000;
const DEFAULT_DISCONNECT_GRACE_MS: u64 = 2_000;
const DEFAULT_RECONNECT_ATTEMPTS: u32 = 0;
const DEFAULT_BASE_BACKOFF_MS: u64 = 100;
const DEFAULT_MAX_BACKOFF_MS: u64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamMode {
    Bidirectional,
    Unidirectional,
}

impl StreamMode {
    fn parse(value: Option<&Value>) -> FcpResult<Self> {
        match value.and_then(Value::as_str).unwrap_or("bidirectional") {
            "bidirectional" => Ok(Self::Bidirectional),
            "unidirectional" => Ok(Self::Unidirectional),
            other => Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Unsupported media stream mode: {other}"),
            }),
        }
    }
}

#[derive(Debug, Clone)]
struct MediaStreamConfig {
    mode: StreamMode,
    max_frame_bytes: usize,
    max_media_payload_bytes: usize,
    max_queued_audio_bytes: usize,
    stream_token_ttl_ms: u64,
    disconnect_grace_ms: u64,
    base_backoff_ms: u64,
    max_backoff_ms: u64,
    reconnect_attempts: u32,
    max_reconnect_attempts: u32,
    expected_stream_token: Option<CallAuthToken>,
    stream_token_issued_at_ms: Option<u64>,
    now_ms: Option<u64>,
    allowed_call_sids: HashSet<String>,
    simulate_send_failure_after: Option<usize>,
}

impl MediaStreamConfig {
    fn from_input(input: &Value) -> FcpResult<Self> {
        let max_reconnect_attempts = optional_u32(
            input,
            "max_reconnect_attempts",
            SupervisorConfig::default().max_consecutive_failures,
        )?;
        Ok(Self {
            mode: StreamMode::parse(input.get("mode"))?,
            max_frame_bytes: optional_usize(input, "max_frame_bytes", DEFAULT_MAX_FRAME_BYTES)?,
            max_media_payload_bytes: optional_usize(
                input,
                "max_media_payload_bytes",
                DEFAULT_MAX_MEDIA_PAYLOAD_BYTES,
            )?,
            max_queued_audio_bytes: optional_usize(
                input,
                "max_queued_audio_bytes",
                DEFAULT_MAX_QUEUED_AUDIO_BYTES,
            )?,
            stream_token_ttl_ms: optional_u64(
                input,
                "stream_token_ttl_ms",
                DEFAULT_STREAM_TOKEN_TTL_MS,
            )?,
            disconnect_grace_ms: optional_u64(
                input,
                "disconnect_grace_ms",
                DEFAULT_DISCONNECT_GRACE_MS,
            )?,
            base_backoff_ms: optional_u64(input, "base_backoff_ms", DEFAULT_BASE_BACKOFF_MS)?,
            max_backoff_ms: optional_u64(input, "max_backoff_ms", DEFAULT_MAX_BACKOFF_MS)?,
            reconnect_attempts: optional_u32(
                input,
                "reconnect_attempts",
                DEFAULT_RECONNECT_ATTEMPTS,
            )?,
            max_reconnect_attempts,
            expected_stream_token: optional_call_auth_token(input, "expected_stream_token")?,
            stream_token_issued_at_ms: optional_u64_value(input, "stream_token_issued_at_ms")?,
            now_ms: optional_u64_value(input, "now_ms")?,
            allowed_call_sids: string_set(input.get("allowed_call_sids"))?,
            simulate_send_failure_after: optional_usize_value(
                input,
                "simulate_send_failure_after",
            )?,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
struct MediaStreamLogEntry {
    phase: String,
    outcome: String,
    code: String,
    message: String,
    stream_sid: Option<String>,
    call_sid: Option<String>,
    sequence_number: Option<u64>,
    queue_depth: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct PacingDecision {
    kind: String,
    code: String,
    payload_bytes: usize,
    scheduled_after_ms: u64,
    duration_ms: u64,
    queue_depth_before: usize,
    queue_depth_after: usize,
    sent: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ReconnectDecision {
    attempt: u32,
    delay_ms: u64,
    capped: bool,
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct MediaStreamProcessResult {
    accepted: bool,
    status_code: u16,
    reason_code: String,
    reason: String,
    event_type: Option<String>,
    stream_sid: Option<String>,
    call_sid: Option<String>,
    frames_received: usize,
    media_frames: usize,
    duplicate_frames: usize,
    suppressed_frames: usize,
    inbound_audio_bytes: usize,
    dtmf_digits: Vec<String>,
    marks_received: Vec<String>,
    outbound_messages: Vec<Value>,
    pacing_decisions: Vec<PacingDecision>,
    reconnect_plan: Vec<ReconnectDecision>,
    queue_depth: usize,
    max_queue_depth: usize,
    queued_audio_bytes: usize,
    backpressure: bool,
    request_region: Value,
    supervision: Value,
    logs: Vec<MediaStreamLogEntry>,
    tainted: bool,
    clean_shutdown: bool,
}

#[derive(Debug)]
struct Denial {
    status_code: u16,
    reason_code: &'static str,
    reason: String,
}

#[derive(Debug, Default)]
struct MediaStreamState {
    stream_sid: Option<String>,
    call_sid: Option<String>,
    started: bool,
    stopped: bool,
    frames_received: usize,
    media_frames: usize,
    duplicate_frames: usize,
    suppressed_frames: usize,
    inbound_audio_bytes: usize,
    seen_sequences: HashSet<u64>,
    last_sequence: Option<u64>,
    last_chunk_by_track: HashMap<String, u64>,
    last_timestamp_ms: Option<i64>,
    dtmf_digits: Vec<String>,
    marks_received: Vec<String>,
}

impl MediaStreamState {
    fn event_type(&self) -> Option<String> {
        if self.stopped {
            Some("twilio.media_stream.stopped".into())
        } else if self.started {
            Some("twilio.media_stream.active".into())
        } else {
            None
        }
    }
}

enum SequenceDisposition {
    Fresh,
    Duplicate,
}

#[derive(Debug)]
enum OutboundAction {
    Audio {
        payload: String,
        mark: Option<String>,
    },
    Mark {
        name: String,
    },
    Clear,
}

#[derive(Debug)]
struct QueuedOutbound {
    kind: &'static str,
    message: Value,
    payload_bytes: usize,
    duration_ms: u64,
}

#[derive(Debug)]
struct MediaStreamPacer {
    stream_sid: String,
    max_queued_audio_bytes: usize,
    simulate_send_failure_after: Option<usize>,
    queue: VecDeque<QueuedOutbound>,
    queued_audio_bytes: usize,
    max_queue_depth: usize,
    scheduled_after_ms: u64,
    sent_messages: usize,
    outbound_messages: Vec<Value>,
    pacing_decisions: Vec<PacingDecision>,
    backpressure: bool,
}

impl MediaStreamPacer {
    fn new(
        stream_sid: String,
        max_queued_audio_bytes: usize,
        simulate_send_failure_after: Option<usize>,
    ) -> Self {
        Self {
            stream_sid,
            max_queued_audio_bytes,
            simulate_send_failure_after,
            queue: VecDeque::new(),
            queued_audio_bytes: 0,
            max_queue_depth: 0,
            scheduled_after_ms: 0,
            sent_messages: 0,
            outbound_messages: Vec::new(),
            pacing_decisions: Vec::new(),
            backpressure: false,
        }
    }

    fn enqueue_audio(&mut self, payload: &str) -> Result<(), Denial> {
        let audio = decode_base64(payload)
            .map_err(|message| denial(400, "invalid_media_payload", message))?;
        if audio.is_empty() {
            return Err(denial(
                400,
                "empty_media_payload",
                "Outbound media payload must not be empty",
            ));
        }
        if audio.starts_with(b"RIFF") {
            return Err(denial(
                400,
                "media_header_bytes",
                "Outbound media.payload must be raw mu-law/8000 bytes without file headers",
            ));
        }

        for chunk in audio.chunks(TELEPHONY_CHUNK_BYTES) {
            if self.queued_audio_bytes + chunk.len() > self.max_queued_audio_bytes {
                self.backpressure = true;
                self.queue.clear();
                self.queued_audio_bytes = 0;
                return Err(denial(
                    429,
                    "audio_backpressure",
                    "Queued outbound media exceeded the bounded audio queue",
                ));
            }
            self.queue.push_back(QueuedOutbound {
                kind: "media",
                message: json!({
                    "event": "media",
                    "streamSid": self.stream_sid,
                    "media": {
                        "payload": base64::engine::general_purpose::STANDARD.encode(chunk)
                    }
                }),
                payload_bytes: chunk.len(),
                duration_ms: audio_duration_ms(chunk.len()),
            });
            self.queued_audio_bytes += chunk.len();
            self.max_queue_depth = self.max_queue_depth.max(self.queue.len());
        }
        Ok(())
    }

    fn enqueue_mark(&mut self, name: &str) {
        self.queue.push_back(QueuedOutbound {
            kind: "mark",
            message: json!({
                "event": "mark",
                "streamSid": self.stream_sid,
                "mark": { "name": name }
            }),
            payload_bytes: 0,
            duration_ms: 0,
        });
        self.max_queue_depth = self.max_queue_depth.max(self.queue.len());
    }

    fn clear_audio(&mut self) {
        self.queue.clear();
        self.queued_audio_bytes = 0;
        self.outbound_messages.push(json!({
            "event": "clear",
            "streamSid": self.stream_sid
        }));
        self.pacing_decisions.push(PacingDecision {
            kind: "clear".into(),
            code: "audio_cleared".into(),
            payload_bytes: 0,
            scheduled_after_ms: self.scheduled_after_ms,
            duration_ms: 0,
            queue_depth_before: 0,
            queue_depth_after: 0,
            sent: true,
        });
    }

    fn flush(&mut self) {
        while let Some(item) = self.queue.pop_front() {
            let queue_depth_before = self.queue.len() + 1;
            if let Some(limit) = self.simulate_send_failure_after {
                if self.sent_messages >= limit {
                    self.queue.clear();
                    self.queued_audio_bytes = 0;
                    self.pacing_decisions.push(PacingDecision {
                        kind: item.kind.into(),
                        code: "send_failed".into(),
                        payload_bytes: item.payload_bytes,
                        scheduled_after_ms: self.scheduled_after_ms,
                        duration_ms: item.duration_ms,
                        queue_depth_before,
                        queue_depth_after: 0,
                        sent: false,
                    });
                    break;
                }
            }

            self.sent_messages += 1;
            if item.kind == "media" {
                self.queued_audio_bytes =
                    self.queued_audio_bytes.saturating_sub(item.payload_bytes);
            }
            let queue_depth_after = self.queue.len();
            self.outbound_messages.push(item.message);
            self.pacing_decisions.push(PacingDecision {
                kind: item.kind.into(),
                code: "sent".into(),
                payload_bytes: item.payload_bytes,
                scheduled_after_ms: self.scheduled_after_ms,
                duration_ms: item.duration_ms,
                queue_depth_before,
                queue_depth_after,
                sent: true,
            });
            self.scheduled_after_ms = self.scheduled_after_ms.saturating_add(item.duration_ms);
        }
    }
}

/// Process host-forwarded Twilio Media Streams frames and deterministic outbound pacing.
pub fn process_media_stream_events(input: &Value) -> FcpResult<Value> {
    let config = MediaStreamConfig::from_input(input)?;
    let request_region = media_stream_request_region(input);
    let supervision = media_stream_supervision_metadata(&config);
    let reconnect_plan = reconnect_plan(&config);
    let mut state = MediaStreamState::default();
    let mut logs = vec![
        log_entry(
            "request_region",
            "ok",
            "request_region_attached",
            "FCP request-region metadata attached to media stream ingress",
            &state,
            None,
            None,
        ),
        log_entry(
            "supervision",
            "ok",
            "supervisor_declared",
            "Media stream session is bound to a child scope with bounded queue, shutdown, config, and status watches",
            &state,
            None,
            None,
        ),
    ];

    if optional_bool(input, "cancelled")? {
        logs.push(log_entry(
            "request_region",
            "denied",
            "request_cancelled",
            "Media stream request was cancelled before connector processing",
            &state,
            None,
            None,
        ));
        return serialize_result(build_result(
            false,
            408,
            "request_cancelled",
            "Media stream request was cancelled before connector processing",
            &state,
            Vec::new(),
            Vec::new(),
            reconnect_plan,
            logs,
            false,
            request_region,
            supervision,
            0,
            0,
            0,
        ));
    }

    if optional_bool(input, "deadline_exceeded")? {
        logs.push(log_entry(
            "timeout",
            "denied",
            "request_timeout",
            "Media stream deadline was exceeded before connector processing",
            &state,
            None,
            None,
        ));
        return serialize_result(build_result(
            false,
            408,
            "request_timeout",
            "Media stream deadline was exceeded before connector processing",
            &state,
            Vec::new(),
            Vec::new(),
            reconnect_plan,
            logs,
            false,
            request_region,
            supervision,
            0,
            0,
            0,
        ));
    }

    if optional_bool(input, "rate_limited")? {
        logs.push(log_entry(
            "admission",
            "denied",
            "rate_limited",
            "Media stream request was shed by host rate-limit policy",
            &state,
            None,
            None,
        ));
        return serialize_result(build_result(
            false,
            429,
            "rate_limited",
            "Media stream request was shed by host rate-limit policy",
            &state,
            Vec::new(),
            Vec::new(),
            reconnect_plan,
            logs,
            false,
            request_region,
            supervision,
            0,
            0,
            0,
        ));
    }

    let frames = media_stream_frames(input)?;
    if frames.is_empty() {
        logs.push(log_entry(
            "parse",
            "denied",
            "missing_frames",
            "Media stream input must include at least one Twilio WebSocket frame",
            &state,
            None,
            None,
        ));
        return serialize_result(build_result(
            false,
            400,
            "missing_frames",
            "Media stream input must include at least one Twilio WebSocket frame",
            &state,
            Vec::new(),
            Vec::new(),
            reconnect_plan,
            logs,
            false,
            request_region,
            supervision,
            0,
            0,
            0,
        ));
    }

    for frame in frames {
        match process_frame(frame, &config, &mut state, &mut logs) {
            Ok(()) => {}
            Err(denial) => {
                logs.push(log_entry(
                    "session",
                    "denied",
                    denial.reason_code,
                    &denial.reason,
                    &state,
                    None,
                    None,
                ));
                return serialize_result(build_result(
                    false,
                    denial.status_code,
                    denial.reason_code,
                    &denial.reason,
                    &state,
                    Vec::new(),
                    Vec::new(),
                    reconnect_plan,
                    logs,
                    false,
                    request_region,
                    supervision,
                    0,
                    0,
                    0,
                ));
            }
        }
    }

    let actions = outbound_actions(input)?;
    let mut pacer = MediaStreamPacer::new(
        state.stream_sid.clone().unwrap_or_default(),
        config.max_queued_audio_bytes,
        config.simulate_send_failure_after,
    );

    if !actions.is_empty() {
        if !state.started || state.stopped {
            let reason = "Outbound media requires an active started stream";
            logs.push(log_entry(
                "outbound",
                "denied",
                "no_active_stream",
                reason,
                &state,
                None,
                None,
            ));
            return serialize_result(build_result(
                false,
                409,
                "no_active_stream",
                reason,
                &state,
                Vec::new(),
                Vec::new(),
                reconnect_plan,
                logs,
                false,
                request_region,
                supervision,
                0,
                0,
                0,
            ));
        }
        if config.mode == StreamMode::Unidirectional {
            let reason = "Unidirectional Twilio Media Streams cannot receive connector media, mark, or clear messages";
            logs.push(log_entry(
                "outbound",
                "denied",
                "outbound_not_allowed",
                reason,
                &state,
                None,
                None,
            ));
            return serialize_result(build_result(
                false,
                400,
                "outbound_not_allowed",
                reason,
                &state,
                Vec::new(),
                Vec::new(),
                reconnect_plan,
                logs,
                false,
                request_region,
                supervision,
                0,
                0,
                0,
            ));
        }

        for action in actions {
            if let Err(denial) = apply_outbound_action(&mut pacer, action) {
                logs.push(log_entry(
                    "outbound",
                    "denied",
                    denial.reason_code,
                    &denial.reason,
                    &state,
                    None,
                    Some(pacer.queue.len()),
                ));
                return serialize_result(build_result(
                    false,
                    denial.status_code,
                    denial.reason_code,
                    &denial.reason,
                    &state,
                    pacer.outbound_messages,
                    pacer.pacing_decisions,
                    reconnect_plan,
                    logs,
                    pacer.backpressure,
                    request_region,
                    supervision,
                    pacer.queue.len(),
                    pacer.max_queue_depth,
                    pacer.queued_audio_bytes,
                ));
            }
        }
        pacer.flush();
    }

    let (reason_code, reason) = if state.stopped {
        (
            "stream_stopped",
            "Twilio media stream stopped cleanly with no orphan connector work",
        )
    } else {
        (
            "stream_active",
            "Twilio media stream frames accepted with bounded connector work",
        )
    };

    logs.push(log_entry(
        "cleanup",
        "ok",
        "clean_shutdown",
        "Media stream processing completed without orphan workers",
        &state,
        None,
        Some(pacer.queue.len()),
    ));

    serialize_result(build_result(
        true,
        200,
        reason_code,
        reason,
        &state,
        pacer.outbound_messages,
        pacer.pacing_decisions,
        reconnect_plan,
        logs,
        pacer.backpressure,
        request_region,
        supervision,
        pacer.queue.len(),
        pacer.max_queue_depth,
        pacer.queued_audio_bytes,
    ))
}

fn process_frame(
    frame: &Value,
    config: &MediaStreamConfig,
    state: &mut MediaStreamState,
    logs: &mut Vec<MediaStreamLogEntry>,
) -> Result<(), Denial> {
    state.frames_received += 1;
    let frame_bytes = serde_json::to_vec(frame)
        .map_err(|error| {
            denial(
                400,
                "malformed_frame",
                format!("Failed to measure frame: {error}"),
            )
        })?
        .len();
    if frame_bytes > config.max_frame_bytes {
        return Err(denial(
            413,
            "frame_too_large",
            "Twilio media stream frame exceeds configured ingress maximum",
        ));
    }

    let event =
        required_str(frame, "event").map_err(|message| denial(400, "malformed_frame", message))?;
    match event {
        "connected" => {
            logs.push(log_entry(
                "parse",
                "ok",
                "connected",
                "Twilio media stream connected frame accepted",
                state,
                None,
                None,
            ));
            Ok(())
        }
        "start" => process_start_frame(frame, config, state, logs),
        "media" => process_media_frame(frame, config, state, logs),
        "dtmf" => process_dtmf_frame(frame, state, logs),
        "mark" => process_mark_frame(frame, state, logs),
        "stop" => process_stop_frame(frame, state, logs),
        "clear" => Err(denial(
            400,
            "unsupported_inbound_clear",
            "Twilio sends clear only as a connector-to-Twilio control message",
        )),
        other => Err(denial(
            400,
            "unknown_event",
            format!("Unsupported Twilio media stream event: {other}"),
        )),
    }
}

fn process_start_frame(
    frame: &Value,
    config: &MediaStreamConfig,
    state: &mut MediaStreamState,
    logs: &mut Vec<MediaStreamLogEntry>,
) -> Result<(), Denial> {
    let sequence = required_u64(frame, "sequenceNumber")
        .map_err(|message| denial(400, "malformed_sequence", message))?;
    if matches!(
        observe_sequence(sequence, state, logs),
        SequenceDisposition::Duplicate
    ) {
        return Ok(());
    }
    if state.started {
        return Err(denial(
            409,
            "duplicate_start",
            "Media stream start was received after the session was already started",
        ));
    }
    let start = frame
        .get("start")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            denial(
                400,
                "malformed_start",
                "start frame must include a start object",
            )
        })?;
    let root_stream_sid = optional_str(frame, "streamSid");
    let start_stream_sid = start
        .get("streamSid")
        .and_then(Value::as_str)
        .or(root_stream_sid)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            denial(
                400,
                "missing_stream_sid",
                "start frame must include streamSid",
            )
        })?;
    let call_sid = start
        .get("callSid")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| denial(400, "missing_call_sid", "start frame must include callSid"))?;

    if !config.allowed_call_sids.is_empty() && !config.allowed_call_sids.contains(call_sid) {
        return Err(denial(
            403,
            "call_not_allowed",
            "Twilio media stream callSid was not authorized for this connector session",
        ));
    }
    validate_stream_token(start, config)?;
    validate_media_format(start)?;
    validate_tracks(start, config.mode)?;

    state.stream_sid = Some(start_stream_sid.into());
    state.call_sid = Some(call_sid.into());
    state.started = true;
    logs.push(log_entry(
        "start",
        "ok",
        "stream_started",
        "Twilio media stream start accepted and bound to actor-owned session state",
        state,
        Some(sequence),
        None,
    ));
    Ok(())
}

fn process_media_frame(
    frame: &Value,
    config: &MediaStreamConfig,
    state: &mut MediaStreamState,
    logs: &mut Vec<MediaStreamLogEntry>,
) -> Result<(), Denial> {
    if !state.started {
        return Err(denial(
            400,
            "media_before_start",
            "Twilio media frame arrived before a valid start frame",
        ));
    }
    if state.stopped {
        state.suppressed_frames += 1;
        logs.push(log_entry(
            "media",
            "suppressed",
            "media_after_stop",
            "Media frame after stop was suppressed",
            state,
            None,
            None,
        ));
        return Ok(());
    }
    let sequence = required_u64(frame, "sequenceNumber")
        .map_err(|message| denial(400, "malformed_sequence", message))?;
    if matches!(
        observe_sequence(sequence, state, logs),
        SequenceDisposition::Duplicate
    ) {
        return Ok(());
    }
    ensure_stream_sid(frame, state)?;
    let media = frame
        .get("media")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            denial(
                400,
                "malformed_media",
                "media frame must include a media object",
            )
        })?;
    let track = media
        .get("track")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| denial(400, "missing_track", "media frame must include media.track"))?;
    validate_track(track, config.mode)?;
    let chunk = object_required_u64(media, "chunk")
        .map_err(|message| denial(400, "malformed_chunk", message))?;
    let timestamp = object_required_i64(media, "timestamp")
        .map_err(|message| denial(400, "malformed_timestamp", message))?;
    if let Some(previous_chunk) = state.last_chunk_by_track.get(track) {
        if chunk <= *previous_chunk {
            state.duplicate_frames += 1;
            state.suppressed_frames += 1;
            logs.push(log_entry(
                "media",
                "suppressed",
                "duplicate_chunk",
                "Duplicate or out-of-order media chunk was suppressed",
                state,
                Some(sequence),
                None,
            ));
            return Ok(());
        }
    }
    if let Some(previous_timestamp) = state.last_timestamp_ms {
        let gap_ms = timestamp - previous_timestamp;
        if !(0..=120).contains(&gap_ms) {
            logs.push(log_entry(
                "media",
                "warn",
                "timestamp_gap",
                "Media timestamp gap exceeded realtime pacing expectations",
                state,
                Some(sequence),
                None,
            ));
        }
    }
    let payload = media
        .get("payload")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            denial(
                400,
                "missing_media_payload",
                "media frame must include media.payload",
            )
        })?;
    let audio =
        decode_base64(payload).map_err(|message| denial(400, "invalid_media_payload", message))?;
    if audio.is_empty() {
        return Err(denial(
            400,
            "empty_media_payload",
            "Inbound media payload must not be empty",
        ));
    }
    if audio.len() > config.max_media_payload_bytes {
        return Err(denial(
            413,
            "media_payload_too_large",
            "Inbound media payload exceeds configured maximum",
        ));
    }

    state.last_chunk_by_track.insert(track.into(), chunk);
    state.last_timestamp_ms = Some(timestamp);
    state.media_frames += 1;
    state.inbound_audio_bytes += audio.len();
    logs.push(log_entry(
        "media",
        "ok",
        "media_frame_accepted",
        "Twilio media frame accepted in sequence",
        state,
        Some(sequence),
        None,
    ));
    Ok(())
}

fn process_dtmf_frame(
    frame: &Value,
    state: &mut MediaStreamState,
    logs: &mut Vec<MediaStreamLogEntry>,
) -> Result<(), Denial> {
    if !state.started {
        return Err(denial(
            400,
            "dtmf_before_start",
            "DTMF frame arrived before a valid start frame",
        ));
    }
    let sequence = required_u64(frame, "sequenceNumber")
        .map_err(|message| denial(400, "malformed_sequence", message))?;
    if matches!(
        observe_sequence(sequence, state, logs),
        SequenceDisposition::Duplicate
    ) {
        return Ok(());
    }
    ensure_stream_sid(frame, state)?;
    let dtmf = frame
        .get("dtmf")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            denial(
                400,
                "malformed_dtmf",
                "dtmf frame must include a dtmf object",
            )
        })?;
    let digit = dtmf
        .get("digit")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            denial(
                400,
                "missing_dtmf_digit",
                "dtmf frame must include dtmf.digit",
            )
        })?;
    state.dtmf_digits.push(digit.into());
    logs.push(log_entry(
        "dtmf",
        "ok",
        "dtmf_accepted",
        "Inbound DTMF frame accepted",
        state,
        Some(sequence),
        None,
    ));
    Ok(())
}

fn process_mark_frame(
    frame: &Value,
    state: &mut MediaStreamState,
    logs: &mut Vec<MediaStreamLogEntry>,
) -> Result<(), Denial> {
    if !state.started {
        return Err(denial(
            400,
            "mark_before_start",
            "Mark frame arrived before a valid start frame",
        ));
    }
    let sequence = required_u64(frame, "sequenceNumber")
        .map_err(|message| denial(400, "malformed_sequence", message))?;
    if matches!(
        observe_sequence(sequence, state, logs),
        SequenceDisposition::Duplicate
    ) {
        return Ok(());
    }
    ensure_stream_sid(frame, state)?;
    let mark = frame
        .get("mark")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            denial(
                400,
                "malformed_mark",
                "mark frame must include a mark object",
            )
        })?;
    let name = mark
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            denial(
                400,
                "missing_mark_name",
                "mark frame must include mark.name",
            )
        })?;
    state.marks_received.push(name.into());
    logs.push(log_entry(
        "mark",
        "ok",
        "mark_acknowledged",
        "Twilio mark frame acknowledged outbound audio progress",
        state,
        Some(sequence),
        None,
    ));
    Ok(())
}

fn process_stop_frame(
    frame: &Value,
    state: &mut MediaStreamState,
    logs: &mut Vec<MediaStreamLogEntry>,
) -> Result<(), Denial> {
    if !state.started {
        return Err(denial(
            400,
            "stop_before_start",
            "Stop frame arrived before a valid start frame",
        ));
    }
    let sequence = required_u64(frame, "sequenceNumber")
        .map_err(|message| denial(400, "malformed_sequence", message))?;
    if matches!(
        observe_sequence(sequence, state, logs),
        SequenceDisposition::Duplicate
    ) {
        return Ok(());
    }
    ensure_stream_sid(frame, state)?;
    state.stopped = true;
    logs.push(log_entry(
        "stop",
        "ok",
        "stream_stopped",
        "Twilio media stream stop accepted and session state drained",
        state,
        Some(sequence),
        None,
    ));
    Ok(())
}

fn observe_sequence(
    sequence: u64,
    state: &mut MediaStreamState,
    logs: &mut Vec<MediaStreamLogEntry>,
) -> SequenceDisposition {
    if !state.seen_sequences.insert(sequence) {
        state.duplicate_frames += 1;
        state.suppressed_frames += 1;
        logs.push(log_entry(
            "sequence",
            "suppressed",
            "duplicate_sequence",
            "Duplicate sequenceNumber was suppressed",
            state,
            Some(sequence),
            None,
        ));
        return SequenceDisposition::Duplicate;
    }
    if let Some(last) = state.last_sequence {
        if sequence <= last {
            state.duplicate_frames += 1;
            state.suppressed_frames += 1;
            logs.push(log_entry(
                "sequence",
                "suppressed",
                "out_of_order_sequence",
                "Out-of-order sequenceNumber was suppressed",
                state,
                Some(sequence),
                None,
            ));
            return SequenceDisposition::Duplicate;
        }
        if sequence != last + 1 {
            logs.push(log_entry(
                "sequence",
                "warn",
                "sequence_gap",
                "Media stream sequenceNumber gap detected",
                state,
                Some(sequence),
                None,
            ));
        }
    }
    state.last_sequence = Some(sequence);
    SequenceDisposition::Fresh
}

fn validate_stream_token(
    start: &serde_json::Map<String, Value>,
    config: &MediaStreamConfig,
) -> Result<(), Denial> {
    let provided_stream_parameter = start
        .get("customParameters")
        .and_then(Value::as_object)
        .and_then(|params| params.get("token"))
        .and_then(Value::as_str);
    if let Some(expected) = &config.expected_stream_token {
        if !provided_stream_parameter.is_some_and(|provided| expected.verify(provided)) {
            return Err(denial(
                403,
                "stream_token_mismatch",
                "Media stream token did not match the connector-issued token",
            ));
        }
    }
    if let (Some(issued_at), Some(now)) = (config.stream_token_issued_at_ms, config.now_ms) {
        if now.saturating_sub(issued_at) > config.stream_token_ttl_ms {
            return Err(denial(
                403,
                "stale_stream_token",
                "Media stream token is older than the accepted start window",
            ));
        }
    }
    Ok(())
}

fn validate_media_format(start: &serde_json::Map<String, Value>) -> Result<(), Denial> {
    let media_format = start
        .get("mediaFormat")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            denial(
                400,
                "missing_media_format",
                "start frame must include mediaFormat",
            )
        })?;
    let encoding = media_format
        .get("encoding")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let sample_rate = object_required_u64(media_format, "sampleRate")
        .map_err(|message| denial(400, "unsupported_media_format", message))?;
    let channels = object_required_u64(media_format, "channels")
        .map_err(|message| denial(400, "unsupported_media_format", message))?;
    if encoding != "audio/x-mulaw" || sample_rate != 8_000 || channels != 1 {
        return Err(denial(
            415,
            "unsupported_media_format",
            "Twilio media stream must be audio/x-mulaw, 8000 Hz, mono",
        ));
    }
    Ok(())
}

fn validate_tracks(start: &serde_json::Map<String, Value>, mode: StreamMode) -> Result<(), Denial> {
    let tracks = start
        .get("tracks")
        .and_then(Value::as_array)
        .ok_or_else(|| denial(400, "missing_tracks", "start frame must include tracks"))?;
    let mut has_inbound = false;
    for track in tracks {
        let Some(track) = track.as_str() else {
            return Err(denial(400, "malformed_tracks", "tracks must be strings"));
        };
        match track {
            "inbound" | "inbound_track" => has_inbound = true,
            "outbound" | "outbound_track" => {
                if mode == StreamMode::Bidirectional {
                    return Err(denial(
                        400,
                        "unsupported_bidirectional_track",
                        "Bidirectional Twilio Media Streams can receive only the inbound track",
                    ));
                }
            }
            _ => {
                return Err(denial(
                    400,
                    "unsupported_track",
                    format!("Unsupported Twilio media stream track: {track}"),
                ));
            }
        }
    }
    if mode == StreamMode::Bidirectional && !has_inbound {
        return Err(denial(
            400,
            "missing_inbound_track",
            "Bidirectional Twilio Media Streams require an inbound track",
        ));
    }
    Ok(())
}

fn validate_track(track: &str, mode: StreamMode) -> Result<(), Denial> {
    match track {
        "inbound" | "inbound_track" => Ok(()),
        "outbound" | "outbound_track" if mode == StreamMode::Unidirectional => Ok(()),
        "outbound" | "outbound_track" => Err(denial(
            400,
            "unsupported_bidirectional_track",
            "Bidirectional Twilio Media Streams can receive only the inbound track",
        )),
        _ => Err(denial(
            400,
            "unsupported_track",
            format!("Unsupported Twilio media stream track: {track}"),
        )),
    }
}

fn ensure_stream_sid(frame: &Value, state: &MediaStreamState) -> Result<(), Denial> {
    let stream_sid = required_str(frame, "streamSid")
        .map_err(|message| denial(400, "missing_stream_sid", message))?;
    if state.stream_sid.as_deref() != Some(stream_sid) {
        return Err(denial(
            409,
            "stream_sid_mismatch",
            "Media stream frame streamSid did not match the active session",
        ));
    }
    Ok(())
}

fn apply_outbound_action(
    pacer: &mut MediaStreamPacer,
    action: OutboundAction,
) -> Result<(), Denial> {
    match action {
        OutboundAction::Audio { payload, mark } => {
            pacer.enqueue_audio(&payload)?;
            if let Some(mark) = mark {
                pacer.enqueue_mark(&mark);
            }
        }
        OutboundAction::Mark { name } => pacer.enqueue_mark(&name),
        OutboundAction::Clear => pacer.clear_audio(),
    }
    Ok(())
}

fn outbound_actions(input: &Value) -> FcpResult<Vec<OutboundAction>> {
    if let Some(actions) = input.get("outbound") {
        let actions = actions.as_array().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "outbound must be an array".into(),
        })?;
        return actions.iter().map(outbound_action).collect();
    }

    let mut actions = Vec::new();
    if let Some(audio_items) = input.get("outbound_audio") {
        let audio_items = audio_items.as_array().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "outbound_audio must be an array".into(),
        })?;
        for item in audio_items {
            match item {
                Value::String(payload) => actions.push(OutboundAction::Audio {
                    payload: payload.to_owned(),
                    mark: None,
                }),
                Value::Object(object) => {
                    let payload = object.get("payload").and_then(Value::as_str).ok_or(
                        FcpError::InvalidRequest {
                            code: 1003,
                            message: "outbound_audio item must include payload".into(),
                        },
                    )?;
                    let mark = object
                        .get("mark")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned);
                    actions.push(OutboundAction::Audio {
                        payload: payload.into(),
                        mark,
                    });
                }
                _ => {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "outbound_audio entries must be strings or objects".into(),
                    });
                }
            }
        }
    }
    if let Some(marks) = input.get("outbound_marks") {
        for name in string_vec(marks, "outbound_marks")? {
            actions.push(OutboundAction::Mark { name });
        }
    }
    if optional_bool(input, "send_clear")? {
        actions.push(OutboundAction::Clear);
    }
    Ok(actions)
}

fn outbound_action(value: &Value) -> FcpResult<OutboundAction> {
    let object = value.as_object().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "outbound entries must be objects".into(),
    })?;
    let action_type =
        object
            .get("type")
            .and_then(Value::as_str)
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "outbound action missing type".into(),
            })?;
    match action_type {
        "audio" => {
            let payload =
                object
                    .get("payload")
                    .and_then(Value::as_str)
                    .ok_or(FcpError::InvalidRequest {
                        code: 1003,
                        message: "audio outbound action missing payload".into(),
                    })?;
            let mark = object
                .get("mark")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            Ok(OutboundAction::Audio {
                payload: payload.into(),
                mark,
            })
        }
        "mark" => {
            let name =
                object
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or(FcpError::InvalidRequest {
                        code: 1003,
                        message: "mark outbound action missing name".into(),
                    })?;
            Ok(OutboundAction::Mark { name: name.into() })
        }
        "clear" => Ok(OutboundAction::Clear),
        other => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Unsupported outbound action type: {other}"),
        }),
    }
}

fn build_result(
    accepted: bool,
    status_code: u16,
    reason_code: &str,
    reason: &str,
    state: &MediaStreamState,
    outbound_messages: Vec<Value>,
    pacing_decisions: Vec<PacingDecision>,
    reconnect_plan: Vec<ReconnectDecision>,
    logs: Vec<MediaStreamLogEntry>,
    backpressure: bool,
    request_region: Value,
    supervision: Value,
    queue_depth: usize,
    max_queue_depth: usize,
    queued_audio_bytes: usize,
) -> MediaStreamProcessResult {
    let send_failed = pacing_decisions.iter().any(|decision| !decision.sent);
    let clean_shutdown =
        accepted && queue_depth == 0 && queued_audio_bytes == 0 && !backpressure && !send_failed;
    let tainted = !accepted || backpressure || !clean_shutdown;

    MediaStreamProcessResult {
        accepted,
        status_code,
        reason_code: reason_code.into(),
        reason: reason.into(),
        event_type: state.event_type(),
        stream_sid: state.stream_sid.clone(),
        call_sid: state.call_sid.clone(),
        frames_received: state.frames_received,
        media_frames: state.media_frames,
        duplicate_frames: state.duplicate_frames,
        suppressed_frames: state.suppressed_frames,
        inbound_audio_bytes: state.inbound_audio_bytes,
        dtmf_digits: state.dtmf_digits.clone(),
        marks_received: state.marks_received.clone(),
        outbound_messages,
        pacing_decisions,
        reconnect_plan,
        queue_depth,
        max_queue_depth,
        queued_audio_bytes,
        backpressure,
        request_region,
        supervision,
        logs,
        tainted,
        clean_shutdown,
    }
}

fn media_stream_request_region(input: &Value) -> Value {
    let supplied = input
        .get("request_region")
        .cloned()
        .unwrap_or_else(|| json!({}));
    json!({
        "surface": "fcp.media_stream.request_region",
        "transport": "websocket",
        "source": supplied.get("source").and_then(Value::as_str).unwrap_or("host_forwarded"),
        "cancelled": optional_bool(input, "cancelled").unwrap_or(false),
        "deadline_exceeded": optional_bool(input, "deadline_exceeded").unwrap_or(false),
    })
}

fn media_stream_supervision_metadata(config: &MediaStreamConfig) -> Value {
    let supervisor = SupervisorConfig::default()
        .with_base_backoff_ms(config.base_backoff_ms)
        .with_max_backoff_ms(config.max_backoff_ms)
        .with_max_consecutive_failures(config.max_reconnect_attempts)
        .with_jitter(false);
    json!({
        "builder": "fcp_sdk::runtime::SupervisorConfig",
        "config": supervisor,
        "app_spec": {
            "id": "twilio.media_stream",
            "child_scope": "twilio.media_stream.session",
            "runtime": "fcp-async-core",
            "restart_policy": "on_failure"
        },
        "watches": ["shutdown", "config", "status"],
        "disconnect_grace_ms": config.disconnect_grace_ms,
        "queue_policy": {
            "chunk_bytes": TELEPHONY_CHUNK_BYTES,
            "sample_rate_hz": TELEPHONY_SAMPLE_RATE_HZ,
            "max_queued_audio_bytes": config.max_queued_audio_bytes
        }
    })
}

fn reconnect_plan(config: &MediaStreamConfig) -> Vec<ReconnectDecision> {
    let attempts = config.reconnect_attempts.min(config.max_reconnect_attempts);
    let capacity = usize::try_from(attempts).unwrap_or(usize::MAX);
    let mut plan = Vec::with_capacity(capacity);
    for attempt in 1..=attempts {
        let shift = attempt.saturating_sub(1).min(31);
        let factor = 1_u64.checked_shl(shift).unwrap_or(u64::MAX);
        let raw_delay = config.base_backoff_ms.saturating_mul(factor);
        let delay_ms = raw_delay.min(config.max_backoff_ms);
        plan.push(ReconnectDecision {
            attempt,
            delay_ms,
            capped: raw_delay > config.max_backoff_ms,
        });
    }
    plan
}

fn log_entry(
    phase: &str,
    outcome: &str,
    code: &str,
    message: &str,
    state: &MediaStreamState,
    sequence_number: Option<u64>,
    queue_depth: Option<usize>,
) -> MediaStreamLogEntry {
    MediaStreamLogEntry {
        phase: phase.into(),
        outcome: outcome.into(),
        code: code.into(),
        message: message.into(),
        stream_sid: state.stream_sid.clone(),
        call_sid: state.call_sid.clone(),
        sequence_number,
        queue_depth,
    }
}

fn denial(status_code: u16, reason_code: &'static str, reason: impl Into<String>) -> Denial {
    Denial {
        status_code,
        reason_code,
        reason: reason.into(),
    }
}

fn serialize_result<T: Serialize>(value: T) -> FcpResult<Value> {
    serde_json::to_value(value).map_err(|error| FcpError::Internal {
        message: format!("Serialization error: {error}"),
    })
}

fn media_stream_frames(input: &Value) -> FcpResult<&[Value]> {
    input
        .get("frames")
        .or_else(|| input.get("events"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required array field: frames".into(),
        })
}

fn decode_base64(payload: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(payload)
        .map_err(|error| format!("media.payload is not valid base64: {error}"))
}

fn audio_duration_ms(bytes: usize) -> u64 {
    let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
    let rate = u64::try_from(TELEPHONY_SAMPLE_RATE_HZ).unwrap_or(8_000);
    let rounded = bytes.saturating_mul(1_000).saturating_add(rate - 1) / rate;
    rounded.max(1)
}

fn required_str<'a>(input: &'a Value, field: &str) -> Result<&'a str, String> {
    input
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("Missing required field: {field}"))
}

fn optional_str<'a>(input: &'a Value, field: &str) -> Option<&'a str> {
    input
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn required_u64(input: &Value, field: &str) -> Result<u64, String> {
    input
        .get(field)
        .ok_or_else(|| format!("Missing required field: {field}"))
        .and_then(|value| value_as_u64(value, field))
}

fn object_required_u64(input: &serde_json::Map<String, Value>, field: &str) -> Result<u64, String> {
    input
        .get(field)
        .ok_or_else(|| format!("Missing required field: {field}"))
        .and_then(|value| value_as_u64(value, field))
}

fn object_required_i64(input: &serde_json::Map<String, Value>, field: &str) -> Result<i64, String> {
    input
        .get(field)
        .ok_or_else(|| format!("Missing required field: {field}"))
        .and_then(|value| value_as_i64(value, field))
}

fn value_as_u64(value: &Value, field: &str) -> Result<u64, String> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    value
        .as_str()
        .ok_or_else(|| format!("{field} must be a non-negative integer or integer string"))
        .and_then(|raw| {
            raw.parse::<u64>()
                .map_err(|error| format!("{field} must be a valid integer: {error}"))
        })
}

fn value_as_i64(value: &Value, field: &str) -> Result<i64, String> {
    if let Some(number) = value.as_i64() {
        return Ok(number);
    }
    value
        .as_str()
        .ok_or_else(|| format!("{field} must be an integer or integer string"))
        .and_then(|raw| {
            raw.parse::<i64>()
                .map_err(|error| format!("{field} must be a valid integer: {error}"))
        })
}

fn optional_bool(input: &Value, field: &str) -> FcpResult<bool> {
    input.get(field).map_or(Ok(false), |value| {
        value.as_bool().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be a boolean"),
        })
    })
}

fn optional_trimmed_string(input: &Value, field: &str) -> Option<String> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn optional_call_auth_token(input: &Value, field: &str) -> FcpResult<Option<CallAuthToken>> {
    optional_trimmed_string(input, field)
        .map(CallAuthToken::from_callback_parameter)
        .transpose()
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: error.to_string(),
        })
}

fn optional_u64(input: &Value, field: &str, default: u64) -> FcpResult<u64> {
    optional_u64_value(input, field).map(|value| value.unwrap_or(default))
}

fn optional_u64_value(input: &Value, field: &str) -> FcpResult<Option<u64>> {
    input.get(field).map_or(Ok(None), |value| {
        value_as_u64(value, field)
            .map(Some)
            .map_err(|message| FcpError::InvalidRequest {
                code: 1003,
                message,
            })
    })
}

fn optional_u32(input: &Value, field: &str, default: u32) -> FcpResult<u32> {
    let value = optional_u64(input, field, u64::from(default))?;
    u32::try_from(value).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} is too large for u32: {error}"),
    })
}

fn optional_usize(input: &Value, field: &str, default: usize) -> FcpResult<usize> {
    optional_usize_value(input, field).map(|value| value.unwrap_or(default))
}

fn optional_usize_value(input: &Value, field: &str) -> FcpResult<Option<usize>> {
    optional_u64_value(input, field).and_then(|value| {
        value
            .map(|value| {
                usize::try_from(value).map_err(|error| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("{field} is too large for usize: {error}"),
                })
            })
            .transpose()
    })
}

fn string_set(value: Option<&Value>) -> FcpResult<HashSet<String>> {
    match value {
        None => Ok(HashSet::new()),
        Some(value) => {
            string_vec(value, "allowed_call_sids").map(|values| values.into_iter().collect())
        }
    }
}

fn string_vec(value: &Value, field: &str) -> FcpResult<Vec<String>> {
    let values = value.as_array().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be an array"),
    })?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("{field} entries must be non-empty strings"),
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start_frame() -> Value {
        json!({
            "event": "start",
            "sequenceNumber": "1",
            "streamSid": "MZ-test",
            "start": {
                "streamSid": "MZ-test",
                "accountSid": "AC-test",
                "callSid": "CA-test",
                "tracks": ["inbound"],
                "customParameters": { "token": "AAAAAAAAAAAAAAAAAAAAAA" },
                "mediaFormat": {
                    "encoding": "audio/x-mulaw",
                    "sampleRate": 8000,
                    "channels": 1
                }
            }
        })
    }

    fn media_frame(sequence: u64, chunk: u64, timestamp: u64, byte: u8) -> Value {
        json!({
            "event": "media",
            "sequenceNumber": sequence.to_string(),
            "streamSid": "MZ-test",
            "media": {
                "track": "inbound",
                "chunk": chunk.to_string(),
                "timestamp": timestamp.to_string(),
                "payload": base64::engine::general_purpose::STANDARD.encode(vec![byte; TELEPHONY_CHUNK_BYTES])
            }
        })
    }

    #[test]
    fn accepts_ordered_media_and_stop() {
        let result = process_media_stream_events(&json!({
            "frames": [
                { "event": "connected", "protocol": "Call", "version": "1.0.0" },
                start_frame(),
                media_frame(2, 1, 0, 0x7f),
                media_frame(3, 2, 20, 0x7f),
                {
                    "event": "stop",
                    "sequenceNumber": "4",
                    "streamSid": "MZ-test",
                    "stop": { "accountSid": "AC-test", "callSid": "CA-test" }
                }
            ],
            "expected_stream_token": "AAAAAAAAAAAAAAAAAAAAAA",
            "stream_token_issued_at_ms": 1000,
            "now_ms": 1200
        }))
        .expect("media stream should process");

        assert_eq!(result["accepted"], true);
        assert_eq!(result["reason_code"], "stream_stopped");
        assert_eq!(result["media_frames"], 2);
        assert_eq!(result["inbound_audio_bytes"], TELEPHONY_CHUNK_BYTES * 2);
        assert_eq!(result["clean_shutdown"], true);
        assert_eq!(result["tainted"], false);
    }

    #[test]
    fn suppresses_duplicate_sequences() {
        let result = process_media_stream_events(&json!({
            "frames": [
                start_frame(),
                media_frame(2, 1, 0, 0x7f),
                media_frame(2, 1, 0, 0x7f),
                media_frame(3, 2, 20, 0x7f)
            ]
        }))
        .expect("media stream should process");

        assert_eq!(result["accepted"], true);
        assert_eq!(result["media_frames"], 2);
        assert_eq!(result["duplicate_frames"], 1);
        assert_eq!(result["suppressed_frames"], 1);
    }

    #[test]
    fn rejects_stale_stream_token() {
        let result = process_media_stream_events(&json!({
            "frames": [start_frame()],
            "expected_stream_token": "AAAAAAAAAAAAAAAAAAAAAA",
            "stream_token_issued_at_ms": 1000,
            "now_ms": 40_000,
            "stream_token_ttl_ms": 30_000
        }))
        .expect("stale token should be structured");

        assert_eq!(result["accepted"], false);
        assert_eq!(result["status_code"], 403);
        assert_eq!(result["reason_code"], "stale_stream_token");
    }

    #[test]
    fn paces_outbound_audio_and_marks() {
        let payload = base64::engine::general_purpose::STANDARD.encode(vec![0x7f; 320]);
        let result = process_media_stream_events(&json!({
            "frames": [start_frame()],
            "outbound": [
                { "type": "audio", "payload": payload, "mark": "audio-1" }
            ]
        }))
        .expect("outbound audio should process");

        assert_eq!(result["accepted"], true);
        assert_eq!(result["outbound_messages"].as_array().unwrap().len(), 3);
        assert_eq!(result["outbound_messages"][0]["event"], "media");
        assert_eq!(result["outbound_messages"][1]["event"], "media");
        assert_eq!(result["outbound_messages"][2]["event"], "mark");
        assert_eq!(result["pacing_decisions"][0]["scheduled_after_ms"], 0);
        assert_eq!(result["pacing_decisions"][1]["scheduled_after_ms"], 20);
        assert_eq!(result["pacing_decisions"][2]["scheduled_after_ms"], 40);
        assert_eq!(result["clean_shutdown"], true);
        assert_eq!(result["tainted"], false);
    }

    #[test]
    fn rejects_unbounded_outbound_audio_queue() {
        let payload = base64::engine::general_purpose::STANDARD.encode(vec![0x7f; 480]);
        let result = process_media_stream_events(&json!({
            "frames": [start_frame()],
            "max_queued_audio_bytes": 200,
            "outbound": [{ "type": "audio", "payload": payload }]
        }))
        .expect("backpressure should be structured");

        assert_eq!(result["accepted"], false);
        assert_eq!(result["status_code"], 429);
        assert_eq!(result["reason_code"], "audio_backpressure");
        assert_eq!(result["backpressure"], true);
        assert_eq!(result["clean_shutdown"], false);
        assert_eq!(result["tainted"], true);
    }

    #[test]
    fn caps_reconnect_backoff() {
        let result = process_media_stream_events(&json!({
            "frames": [start_frame()],
            "reconnect_attempts": 4,
            "max_reconnect_attempts": 4,
            "base_backoff_ms": 100,
            "max_backoff_ms": 250
        }))
        .expect("reconnect plan should process");

        let plan = result["reconnect_plan"].as_array().unwrap();
        assert_eq!(plan.len(), 4);
        assert_eq!(plan[0]["delay_ms"], 100);
        assert_eq!(plan[1]["delay_ms"], 200);
        assert_eq!(plan[2]["delay_ms"], 250);
        assert_eq!(plan[2]["capped"], true);
        assert_eq!(plan[3]["delay_ms"], 250);
    }

    #[test]
    fn send_failure_marks_session_tainted() {
        let payload = base64::engine::general_purpose::STANDARD.encode(vec![0x7f; 320]);
        let result = process_media_stream_events(&json!({
            "frames": [start_frame()],
            "simulate_send_failure_after": 1,
            "outbound": [{ "type": "audio", "payload": payload, "mark": "audio-1" }]
        }))
        .expect("send failure should be structured");

        assert_eq!(result["accepted"], true);
        assert_eq!(result["pacing_decisions"][0]["code"], "sent");
        assert_eq!(result["pacing_decisions"][1]["code"], "send_failed");
        assert_eq!(result["outbound_messages"].as_array().unwrap().len(), 1);
        assert_eq!(result["clean_shutdown"], false);
        assert_eq!(result["tainted"], true);
    }
}
