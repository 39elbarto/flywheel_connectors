//! Focused FCPS symbol-plane frame parser fuzz target.
//!
//! This target pins the Phase P parser-gauntlet name; the older
//! `fuzz_fcps_frame` target remains the stronger semantic invariant target.

#![no_main]

use fcp_protocol::{FCPS_HEADER_LEN, FcpsFrame, FcpsFrameHeader, FrameFlags, SymbolRecord};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = FcpsFrameHeader::decode(data);
    for symbol_size in [1u16, 64, 128, 256, 512, 1024, 2048] {
        let _ = SymbolRecord::decode(data, symbol_size);
    }
    for mtu in [0usize, 64, FCPS_HEADER_LEN, 4096, 65_536] {
        let _ = FcpsFrame::decode(data, mtu);
    }
    if data.len() >= 2 {
        let bits = u16::from_le_bytes([data[0], data[1]]);
        let flags = FrameFlags::from_bits_truncate(bits);
        let _ = FrameFlags::from_bits_truncate(flags.bits());
    }
});
