#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{ObjectId, ZoneId, ZoneKey, ZoneKeyAlgorithm, ZoneKeyId};
use fcp_raptorq::{SymbolEnvelope, SymbolEnvelopeError};
use fcp_tailscale::NodeId;
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const AUTH_TAG_SIZE: usize = 16;
const MAX_PLAINTEXT_LEN: usize = 4096;

#[derive(Arbitrary, Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AlgorithmChoice {
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl AlgorithmChoice {
    fn to_zone_key_algorithm(self) -> ZoneKeyAlgorithm {
        match self {
            Self::ChaCha20Poly1305 => ZoneKeyAlgorithm::ChaCha20Poly1305,
            Self::XChaCha20Poly1305 => ZoneKeyAlgorithm::XChaCha20Poly1305,
        }
    }
}

#[derive(Arbitrary, Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MutationKind {
    Identity,
    CiphertextBitflip,
    CiphertextTruncate,
    AuthTagBitflip,
    ObjectIdBitflip,
    KBitflip,
    EpochIdBitflip,
    EsiBitflip,
    FrameSeqBitflip,
    SenderInstanceIdBitflip,
    WrongZoneKey,
}

#[derive(Arbitrary, Debug, Deserialize)]
struct EnvelopeDecryptInput {
    key_seed: [u8; 32],
    zone_key_id: [u8; 8],
    object_id: [u8; 32],
    algorithm: AlgorithmChoice,
    mutation: MutationKind,
    mutation_index: u16,
    plaintext_len: u16,
    plaintext_fill: u8,
    esi: u32,
    k: u16,
    epoch_id: u64,
    sender_instance_id: u64,
    frame_seq: u64,
    source_suffix: u16,
}

fn derive_zone_key(seed: [u8; 32], domain: &[u8]) -> ZoneKey {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(seed);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    ZoneKey::from_bytes(bytes)
}

fn build_plaintext(input: &EnvelopeDecryptInput) -> Vec<u8> {
    let len = usize::from(input.plaintext_len).min(MAX_PLAINTEXT_LEN);
    (0..len)
        .map(|i| input.plaintext_fill.wrapping_add(u8::try_from(i & 0xFF).unwrap_or(0)))
        .collect()
}

fn build_source_id(suffix: u16) -> NodeId {
    NodeId::new(&format!("fuzz-node-{suffix:04x}"))
}

fn mutation_mask(index: usize) -> u8 {
    1u8.rotate_left((index % 8) as u32)
}

fn flip_ciphertext_byte(ciphertext: &mut Vec<u8>, mutation_index: usize) {
    if ciphertext.is_empty() {
        ciphertext.push(mutation_mask(mutation_index));
        return;
    }

    let offset = mutation_index % ciphertext.len();
    ciphertext[offset] ^= mutation_mask(mutation_index);
}

fn mutate_object_id(object_id: &mut ObjectId, mutation_index: usize) {
    let mut bytes = *object_id.as_bytes();
    let offset = mutation_index % bytes.len();
    bytes[offset] ^= mutation_mask(mutation_index);
    *object_id = ObjectId::from_bytes(bytes);
}

fn mutate_u16(value: &mut u16, mutation_index: usize) {
    *value ^= 1u16 << (mutation_index % u16::BITS as usize);
}

fn mutate_u32(value: &mut u32, mutation_index: usize) {
    *value ^= 1u32 << (mutation_index % u32::BITS as usize);
}

fn mutate_u64(value: &mut u64, mutation_index: usize) {
    *value ^= 1u64 << (mutation_index % u64::BITS as usize);
}

fuzz_target!(|data: &[u8]| {
    let input = if let Ok(seed) = serde_json::from_slice::<EnvelopeDecryptInput>(data) {
        seed
    } else {
        let mut unstructured = Unstructured::new(data);
        let Ok(seed) = EnvelopeDecryptInput::arbitrary(&mut unstructured) else {
            return;
        };
        seed
    };

    let plaintext = build_plaintext(&input);
    let algorithm = input.algorithm.to_zone_key_algorithm();
    let zone_key = derive_zone_key(input.key_seed, b"fcp-fuzz-raptorq-envelope-valid");
    let decrypt_key = if input.mutation == MutationKind::WrongZoneKey {
        derive_zone_key(input.key_seed, b"fcp-fuzz-raptorq-envelope-wrong")
    } else {
        zone_key
    };
    let zone_key_id = ZoneKeyId::from_bytes(input.zone_key_id);
    let source_id = build_source_id(input.source_suffix);
    let k = input.k.max(1);

    let mut envelope = match SymbolEnvelope::encrypt(
        ObjectId::from_bytes(input.object_id),
        input.esi,
        k,
        &plaintext,
        ZoneId::work(),
        zone_key_id,
        input.epoch_id,
        source_id,
        input.sender_instance_id,
        input.frame_seq,
        &zone_key,
        algorithm,
    ) {
        Ok(envelope) => envelope,
        Err(SymbolEnvelopeError::EncryptFailed) => return,
        Err(other) => panic!("valid encrypt path unexpectedly failed: {other:?}"),
    };

    let mutation_index = usize::from(input.mutation_index);
    match input.mutation {
        MutationKind::Identity => {}
        MutationKind::CiphertextBitflip => {
            flip_ciphertext_byte(&mut envelope.data, mutation_index);
        }
        MutationKind::CiphertextTruncate => {
            if envelope.data.is_empty() {
                envelope.data.push(mutation_mask(mutation_index));
            } else {
                envelope.data.truncate(envelope.data.len().saturating_sub(1));
            }
        }
        MutationKind::AuthTagBitflip => {
            let offset = mutation_index % AUTH_TAG_SIZE;
            envelope.auth_tag[offset] ^= mutation_mask(mutation_index);
        }
        MutationKind::ObjectIdBitflip => {
            mutate_object_id(&mut envelope.object_id, mutation_index);
        }
        MutationKind::KBitflip => {
            mutate_u16(&mut envelope.k, mutation_index);
        }
        MutationKind::EpochIdBitflip => {
            mutate_u64(&mut envelope.epoch_id, mutation_index);
        }
        MutationKind::EsiBitflip => {
            mutate_u32(&mut envelope.esi, mutation_index);
        }
        MutationKind::FrameSeqBitflip => {
            mutate_u64(&mut envelope.frame_seq, mutation_index);
        }
        MutationKind::SenderInstanceIdBitflip => {
            mutate_u64(&mut envelope.sender_instance_id, mutation_index);
        }
        MutationKind::WrongZoneKey => {}
    }

    let result = envelope.decrypt(&decrypt_key, algorithm, zone_key_id);
    if input.mutation == MutationKind::Identity {
        let decrypted = result.expect("identity mutation must round-trip the original plaintext");
        assert_eq!(
            decrypted, plaintext,
            "identity mutation must preserve the original plaintext"
        );
    } else {
        assert!(
            matches!(result, Err(SymbolEnvelopeError::DecryptFailed)),
            "tampered decrypt must fail authentication, got {result:?}"
        );
    }
});
