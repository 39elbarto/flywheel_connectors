//! Focused FCPC control-plane frame parser fuzz target.
//!
//! This target keeps the Phase P parser gauntlet name stable while the older
//! `fuzz_fcpc_frame` target continues to carry deeper round-trip invariants.

#![no_main]

use fcp_protocol::{FcpcFrame, FcpcFrameFlags, FcpcFrameHeader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = FcpcFrameHeader::decode(data);
    for limit in [0, 64, 256, 1024, 4096, 65_536] {
        let _ = FcpcFrame::decode_with_limit(data, limit);
    }
    if data.len() >= 2 {
        let bits = u16::from_le_bytes([data[0], data[1]]);
        let flags = FcpcFrameFlags::from_bits_truncate(bits);
        let _ = FcpcFrameFlags::from_bits_truncate(flags.bits());
    }
});
