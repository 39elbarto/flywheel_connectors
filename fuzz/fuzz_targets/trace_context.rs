#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_telemetry::TraceContext;
use libfuzzer_sys::fuzz_target;

const MAX_TEXT_BYTES: usize = 512;
const MAX_JSON_BYTES: usize = 4096;

#[derive(Arbitrary, Debug)]
struct Input {
    raw: Vec<u8>,
    trace_id: [u8; 16],
    span_id: [u8; 8],
    trace_flags: u8,
    sampled: bool,
    trace_state: Option<Vec<u8>>,
}

fn bounded_lossy(bytes: &[u8], max: usize) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(max)]).into_owned()
}

fn assert_context_invariants(ctx: &TraceContext) {
    assert_ne!(ctx.trace_id, [0u8; 16]);
    assert_ne!(ctx.span_id, [0u8; 8]);
    assert_eq!(ctx.trace_id_hex().len(), 32);
    assert_eq!(ctx.span_id_hex().len(), 16);
    assert!(
        ctx.trace_id_hex()
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert!(
        ctx.span_id_hex()
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );

    let traceparent = ctx.to_traceparent();
    let parsed = TraceContext::from_traceparent(&traceparent)
        .expect("TraceContext::to_traceparent output must parse");
    assert_eq!(parsed.trace_id, ctx.trace_id);
    assert_eq!(parsed.span_id, ctx.span_id);
    assert_eq!(parsed.trace_flags, ctx.trace_flags);
    assert!(parsed.trace_state.is_none());
    assert_eq!(parsed.to_traceparent(), traceparent);

    let encoded = serde_json::to_string(ctx).expect("TraceContext must serialize");
    let decoded: TraceContext =
        serde_json::from_str(&encoded).expect("serialized TraceContext must parse");
    assert_eq!(decoded, *ctx);
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    let mut ctx = TraceContext::new(input.trace_id, input.span_id).with_sampled(input.sampled);
    ctx.trace_flags = input.trace_flags;
    if let Some(trace_state) = input.trace_state.as_deref() {
        ctx = ctx.with_trace_state(bounded_lossy(trace_state, MAX_TEXT_BYTES));
    }
    assert_context_invariants(&ctx);

    let raw_json = &input.raw[..input.raw.len().min(MAX_JSON_BYTES)];
    if let Ok(parsed) = serde_json::from_slice::<TraceContext>(raw_json) {
        assert_context_invariants(&parsed);
    }

    let candidate = bounded_lossy(&input.raw, MAX_TEXT_BYTES);
    if let Ok(parsed) = TraceContext::from_traceparent(&candidate) {
        assert_context_invariants(&parsed);
    }
});
