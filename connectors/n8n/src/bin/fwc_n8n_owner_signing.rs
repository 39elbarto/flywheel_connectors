//! Signing-only implementation for `fwc-n8n-owner-sign`.
//!
//! This module is included only by the feature-gated owner binary. The normal
//! `fwc-n8n` target, including its `--all-features` build, never compiles this
//! module and never links Ed25519 private-key handling.

use std::{io, io::Read};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use fcp_crypto::ed25519::{Ed25519SigningKey, SECRET_KEY_SIZE, SIGNATURE_SIZE};
use zeroize::Zeroizing;

use super::fwc_n8n_provision as provision;

const MAX_SEED_INPUT_BYTES: usize = 45; // 44 Base64 bytes plus one LF.

pub(crate) fn sign_staged_provision_receipt(
    release_id: &str,
    git_revision: &str,
    bindings: Vec<provision::OfficialMcpBinding>,
    seed: &[u8; SECRET_KEY_SIZE],
) -> Result<Vec<u8>, provision::ProvisionError> {
    #[cfg(not(unix))]
    {
        let _ = (release_id, git_revision, bindings, seed);
        return Err(provision::ProvisionError::new(
            provision::ProvisionErrorCode::UnsupportedPlatform,
        ));
    }

    #[cfg(unix)]
    {
        if !provision::is_git_revision(git_revision) {
            return Err(provision::ProvisionError::new(
                provision::ProvisionErrorCode::InvalidRequest,
            ));
        }
        let stage_root = provision::fixed_staging_path(release_id)?;
        let release_root = provision::fixed_release_path(release_id)?;
        let expected_owner = rustix::process::geteuid().as_raw();
        provision::validate_binding_shape(&bindings)?;
        provision::validate_unsigned_release_tree(
            &stage_root,
            release_id,
            git_revision,
            &bindings,
            expected_owner,
            &release_root,
        )?;

        let owner_verification =
            provision::OwnerVerificationConfig::from_immutable_production_config()?;
        let signing_key = Ed25519SigningKey::from_bytes(seed).map_err(|_| {
            provision::ProvisionError::new(provision::ProvisionErrorCode::Signature)
        })?;
        let verifying_key = signing_key.verifying_key();
        if !owner_verification.matches_verifying_key(&verifying_key)? {
            return Err(provision::ProvisionError::new(
                provision::ProvisionErrorCode::Signature,
            ));
        }

        let mut signed = provision::ProvisionReceipt {
            schema: provision::PROVISION_RECEIPT_SCHEMA.to_owned(),
            release_id: release_id.to_owned(),
            git_revision: git_revision.to_owned(),
            bindings,
            artifacts: provision::staged_provision_artifacts(&stage_root)?,
            signature: provision::ReleaseSignature {
                algorithm: "ed25519".to_owned(),
                key_id: signing_key.key_id().to_string(),
                signature: "00".repeat(SIGNATURE_SIZE),
            },
        };
        provision::validate_provision_receipt(&signed, release_id, git_revision, &signed.bindings)?;
        let receipt_digest = provision::hash_file(&stage_root.join(provision::RECEIPT_FILE))?;
        let unsigned = provision::unsigned_provision_receipt_bytes(&signed)?;
        let provision_digest = blake3::hash(&unsigned).to_hex().to_string();
        let payload =
            provision::release_signing_payload(&signed, &receipt_digest, &provision_digest)?;
        signed.signature.signature = signing_key
            .sign_with_context(provision::RELEASE_SIGNATURE_CONTEXT, &payload)
            .to_hex();
        provision::verify_release_signature(&signed, &receipt_digest, &owner_verification)?;
        serde_json::to_vec(&signed)
            .map_err(|_| provision::ProvisionError::new(provision::ProvisionErrorCode::Receipt))
    }
}

pub(crate) fn read_seed_from_stdin() -> Result<Zeroizing<[u8; SECRET_KEY_SIZE]>, ()> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(MAX_SEED_INPUT_BYTES));
    io::stdin()
        .take(u64::try_from(MAX_SEED_INPUT_BYTES + 1).map_err(|_| ())?)
        .read_to_end(&mut encoded)
        .map_err(|_| ())?;
    decode_seed_input(&encoded)
}

fn decode_seed_input(input: &[u8]) -> Result<Zeroizing<[u8; SECRET_KEY_SIZE]>, ()> {
    let mut encoded = Zeroizing::new(input.to_vec());
    if encoded.len() == MAX_SEED_INPUT_BYTES {
        match encoded.pop() {
            Some(b'\n') => {}
            _ => return Err(()),
        }
    } else if encoded.len() != MAX_SEED_INPUT_BYTES - 1 {
        return Err(());
    }
    if encoded.iter().any(|byte| !byte.is_ascii_graphic()) {
        return Err(());
    }
    let decoded = Zeroizing::new(STANDARD.decode(&*encoded).map_err(|_| ())?);
    let seed: [u8; SECRET_KEY_SIZE] = decoded.as_slice().try_into().map_err(|_| ())?;
    Ok(Zeroizing::new(seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_input_requires_exact_base64_framing() {
        let encoded = STANDARD.encode([7_u8; SECRET_KEY_SIZE]);
        assert!(decode_seed_input(encoded.as_bytes()).is_ok());
        let with_one_newline = format!("{encoded}\n");
        assert!(decode_seed_input(with_one_newline.as_bytes()).is_ok());
        assert!(decode_seed_input(format!("{encoded}\n\n").as_bytes()).is_err());
        assert!(decode_seed_input(format!(" {encoded}").as_bytes()).is_err());
        assert!(decode_seed_input(format!("{encoded}x").as_bytes()).is_err());
    }

    #[test]
    fn fixed_staging_path_rejects_arbitrary_or_aliased_release_ids() {
        assert!(provision::fixed_staging_path("../outside").is_err());
        assert!(provision::fixed_staging_path(".").is_err());
        assert!(provision::fixed_staging_path("release/child").is_err());
    }
}
