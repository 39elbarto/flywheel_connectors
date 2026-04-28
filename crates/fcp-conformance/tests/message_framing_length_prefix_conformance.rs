//! FCPC/FCPS length-prefix wire-format conformance.

use fcp_core::{ObjectId, ZoneIdHash, ZoneKeyId};
use fcp_protocol::{
    FcpcFrame, FcpcFrameFlags, FcpsFrame, FcpsFrameHeader, FrameFlags, MeshSessionId,
    SessionDirection, SymbolRecord, DEFAULT_MAX_FCPC_PAYLOAD_LEN, FCPC_HEADER_LEN, FCPC_MAGIC,
    FCPC_TAG_LEN, FCPC_VERSION, FCPS_HEADER_LEN, FCPS_MAGIC, FCPS_VERSION, SYMBOL_RECORD_OVERHEAD,
};

const MAX_MESSAGE_SIZE: usize = DEFAULT_MAX_FCPC_PAYLOAD_LEN;
const LENGTH_PREFIX_BOUNDARIES: [usize; 5] = [0, 1, 255, 4 * 1024, MAX_MESSAGE_SIZE];
const FCPC_KEY: [u8; 32] = [0x2A; 32];

#[test]
fn fcpc_message_frame_length_prefix_boundaries_roundtrip() {
    let session_id = MeshSessionId([0xA5; 16]);
    let direction = SessionDirection::InitiatorToResponder;

    for (case_index, payload_len) in LENGTH_PREFIX_BOUNDARIES.into_iter().enumerate() {
        let plaintext = deterministic_bytes(payload_len, case_index);
        let frame = FcpcFrame::seal(
            session_id,
            0x1000 + u64::try_from(case_index).expect("case index fits u64"),
            direction,
            FcpcFrameFlags::default(),
            &plaintext,
            &FCPC_KEY,
        )
        .expect("FCPC frame must seal");

        let encoded = frame.encode();
        let payload_len_u32 = u32::try_from(payload_len).expect("payload length fits u32");

        assert_eq!(&encoded[0..4], FCPC_MAGIC.as_slice());
        assert_eq!(
            u16::from_le_bytes(encoded[4..6].try_into().expect("version slice")),
            FCPC_VERSION
        );
        assert_eq!(
            encoded[32..36]
                .try_into()
                .map(u32::from_le_bytes)
                .expect("length-prefix slice"),
            payload_len_u32,
            "FCPC length prefix must be ciphertext length for payload size {payload_len}"
        );
        assert_eq!(
            &encoded[32..36],
            payload_len_u32.to_le_bytes().as_slice(),
            "FCPC length prefix must be little-endian"
        );
        assert_eq!(frame.header.len, payload_len_u32);
        assert_eq!(frame.ciphertext.len(), payload_len);
        assert_eq!(encoded.len(), FCPC_HEADER_LEN + payload_len + FCPC_TAG_LEN);

        let decoded = FcpcFrame::decode_with_limit(&encoded, payload_len)
            .expect("FCPC frame must decode at its exact payload limit");
        assert_eq!(decoded.header, frame.header);
        assert_eq!(decoded.encode(), encoded);
        assert_eq!(
            decoded
                .open(direction, &FCPC_KEY)
                .expect("FCPC frame must open"),
            plaintext
        );
    }
}

#[test]
fn fcps_header_length_prefix_boundaries_roundtrip() {
    for (case_index, total_payload_len) in LENGTH_PREFIX_BOUNDARIES.into_iter().enumerate() {
        let header = fcps_header(case_index, total_payload_len, 0, 1);
        let encoded = header.encode();
        let total_payload_len_u32 =
            u32::try_from(total_payload_len).expect("FCPS payload length fits u32");

        assert_eq!(&encoded[0..4], FCPS_MAGIC.as_slice());
        assert_eq!(
            u16::from_le_bytes(encoded[4..6].try_into().expect("version slice")),
            FCPS_VERSION
        );
        assert_eq!(
            encoded[12..16]
                .try_into()
                .map(u32::from_le_bytes)
                .expect("length-prefix slice"),
            total_payload_len_u32,
            "FCPS total-payload length prefix mismatch for {total_payload_len}"
        );
        assert_eq!(
            &encoded[12..16],
            total_payload_len_u32.to_le_bytes().as_slice(),
            "FCPS total-payload length prefix must be little-endian"
        );

        let decoded = FcpsFrameHeader::decode(&encoded).expect("FCPS header must decode");
        assert_eq!(decoded, header);
    }
}

#[test]
fn fcps_message_frame_length_prefix_boundaries_roundtrip() {
    let cases = [
        FcpsFrameCase {
            name: "empty",
            symbol_count: 0,
            symbol_size: 1,
            expected_total_payload_len: 0,
        },
        FcpsFrameCase {
            name: "one_byte_symbol",
            symbol_count: 1,
            symbol_size: 1,
            expected_total_payload_len: SYMBOL_RECORD_OVERHEAD + 1,
        },
        FcpsFrameCase {
            name: "255_byte_wire_payload",
            symbol_count: 5,
            symbol_size: 29,
            expected_total_payload_len: 255,
        },
        FcpsFrameCase {
            name: "4kb_wire_payload",
            symbol_count: 4,
            symbol_size: 1002,
            expected_total_payload_len: 4 * 1024,
        },
        FcpsFrameCase {
            name: "max_message_size_wire_payload",
            symbol_count: 4096,
            symbol_size: 1002,
            expected_total_payload_len: MAX_MESSAGE_SIZE,
        },
    ];

    for (case_index, case) in cases.into_iter().enumerate() {
        let symbols = fcps_symbols(case.symbol_count, case.symbol_size, case_index);
        let frame = FcpsFrame {
            header: fcps_header(
                case_index,
                case.expected_total_payload_len,
                case.symbol_count,
                case.symbol_size,
            ),
            symbols,
        };

        let encoded = frame.encode().expect("FCPS frame must encode");
        let expected_total_payload_len_u32 =
            u32::try_from(case.expected_total_payload_len).expect("FCPS payload length fits u32");
        let expected_symbol_count_u32 =
            u32::try_from(case.symbol_count).expect("symbol count fits u32");

        assert_eq!(&encoded[0..4], FCPS_MAGIC.as_slice(), "{}", case.name);
        assert_eq!(
            &encoded[8..12],
            expected_symbol_count_u32.to_le_bytes().as_slice(),
            "FCPS symbol-count prefix mismatch for {}",
            case.name
        );
        assert_eq!(
            &encoded[12..16],
            expected_total_payload_len_u32.to_le_bytes().as_slice(),
            "FCPS total-payload length prefix mismatch for {}",
            case.name
        );
        assert_eq!(
            encoded.len(),
            FCPS_HEADER_LEN + case.expected_total_payload_len,
            "FCPS encoded length mismatch for {}",
            case.name
        );

        let decoded = FcpsFrame::decode(&encoded, encoded.len()).expect("FCPS frame must decode");
        assert_eq!(decoded, frame, "FCPS frame mismatch for {}", case.name);
        assert_eq!(
            decoded.encode().expect("FCPS frame must re-encode"),
            encoded,
            "FCPS round-trip bytes changed for {}",
            case.name
        );
    }
}

#[derive(Clone, Copy)]
struct FcpsFrameCase {
    name: &'static str,
    symbol_count: usize,
    symbol_size: u16,
    expected_total_payload_len: usize,
}

fn fcps_header(
    case_index: usize,
    total_payload_len: usize,
    symbol_count: usize,
    symbol_size: u16,
) -> FcpsFrameHeader {
    let seed = u8::try_from((case_index + 1) & 0xff).expect("masked byte fits");
    FcpsFrameHeader {
        version: FCPS_VERSION,
        flags: FrameFlags::default(),
        symbol_count: u32::try_from(symbol_count).expect("symbol count fits u32"),
        total_payload_len: u32::try_from(total_payload_len).expect("payload length fits u32"),
        object_id: ObjectId::from_bytes([seed; 32]),
        symbol_size,
        zone_key_id: ZoneKeyId::from_bytes([seed.wrapping_add(0x10); 8]),
        zone_id_hash: ZoneIdHash::from_bytes([seed.wrapping_add(0x20); 32]),
        epoch_id: 0x0102_0304_0506_0708 + u64::try_from(case_index).expect("case index fits u64"),
        sender_instance_id: 0x1112_1314_1516_1718
            + u64::try_from(case_index).expect("case index fits u64"),
        frame_seq: 0x2122_2324_2526_2728 + u64::try_from(case_index).expect("case index fits u64"),
    }
}

fn fcps_symbols(symbol_count: usize, symbol_size: u16, case_index: usize) -> Vec<SymbolRecord> {
    let k = u16::try_from(symbol_count.max(1)).expect("symbol count fits u16");
    (0..symbol_count)
        .map(|symbol_index| SymbolRecord {
            esi: u32::try_from(symbol_index).expect("symbol index fits u32"),
            k,
            data: deterministic_bytes(usize::from(symbol_size), case_index + symbol_index),
            auth_tag: deterministic_tag(case_index, symbol_index),
        })
        .collect()
}

fn deterministic_bytes(len: usize, seed: usize) -> Vec<u8> {
    (0..len)
        .map(|offset| {
            let byte = seed.wrapping_mul(131).wrapping_add(offset) & 0xff;
            u8::try_from(byte)
                .expect("masked byte fits")
                .wrapping_mul(31)
                .wrapping_add(17)
        })
        .collect()
}

fn deterministic_tag(case_index: usize, symbol_index: usize) -> [u8; 16] {
    let byte = case_index.wrapping_mul(17).wrapping_add(symbol_index) & 0xff;
    [u8::try_from(byte)
        .expect("masked byte fits")
        .wrapping_add(0x40); 16]
}
