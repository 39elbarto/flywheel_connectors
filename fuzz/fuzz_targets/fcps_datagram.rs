//! FCPS Datagram Fuzz Target (flywheel_connectors-1n78.12 / br-h2tn5)
//!
//! Fuzzes FCPS datagram parsing (session layer):
//! - FcpsDatagram decode with various MTU limits
//! - Boundary conditions at various transport limits
//!
//! Goals:
//!   1. Ensure no panics on arbitrary input.
//!   2. Assert semantic invariants on accepted datagrams:
//!      - encode/decode round-trips preserve bytes and struct identity
//!      - MTU gates behave monotonically at key boundary values
//!      - decoded payload length agrees with the on-wire datagram length

#![no_main]

use fcp_protocol::{FCPS_DATAGRAM_HEADER_LEN, FcpsDatagram, SessionError};
use libfuzzer_sys::fuzz_target;

const MTU_BOUNDARIES: [usize; 7] = [0, 1, 1280, 1500, 9000, 65535, 65536];

fuzz_target!(|data: &[u8]| {
    // Exercise the decoder at the requested MTU boundaries. For the
    // u16 API limit, 65536 is represented as an explicit conversion
    // failure so the type boundary is covered too.
    for mtu in MTU_BOUNDARIES {
        match u16::try_from(mtu) {
            Ok(limit) => {
                let result = FcpsDatagram::decode(data, limit);
                if data.len() < FCPS_DATAGRAM_HEADER_LEN {
                    assert!(
                        matches!(result, Err(SessionError::DatagramTooShort { len }) if len == data.len()),
                        "inputs shorter than the datagram header must always fail with DatagramTooShort",
                    );
                } else if data.len() > mtu {
                    assert!(
                        matches!(result, Err(SessionError::DatagramTooLarge { len, max }) if len == data.len() && max == mtu),
                        "inputs exceeding the active MTU must fail with DatagramTooLarge",
                    );
                } else {
                    let datagram =
                        result.expect("input within MTU and above header size must decode");

                    // Successful decode must preserve the raw bytes through
                    // encode and must keep the implicit payload length
                    // consistent with the on-wire suffix length.
                    let re_encoded = datagram.encode();
                    assert_eq!(
                        re_encoded, data,
                        "accepted datagrams must round-trip to byte-identical output",
                    );
                    assert_eq!(
                        datagram.frame_bytes.len(),
                        data.len() - FCPS_DATAGRAM_HEADER_LEN,
                        "decoded frame_bytes length must match the datagram suffix length",
                    );

                    let redecoded = FcpsDatagram::decode(&re_encoded, limit)
                        .expect("re-encoded datagram must decode under the same MTU");
                    assert_eq!(
                        redecoded, datagram,
                        "decode(encode(datagram)) must preserve the datagram struct",
                    );

                    let larger_limits = [1280u16, 1500, 9000, 65535];
                    for larger_limit in larger_limits {
                        if usize::from(larger_limit) >= data.len() && larger_limit >= limit {
                            let larger = FcpsDatagram::decode(data, larger_limit)
                                .expect("loosening the MTU must not flip success into failure");
                            assert_eq!(
                                larger, datagram,
                                "successful decode must be monotonic across larger MTU limits",
                            );
                        }
                    }
                }
            }
            Err(_) => {
                assert_eq!(
                    mtu, 65536,
                    "only the explicit u16 overflow boundary should fail conversion",
                );
                assert!(
                    u16::try_from(65536usize).is_err(),
                    "65536 must remain outside the decode API's u16 MTU range",
                );
            }
        }
    }
});
