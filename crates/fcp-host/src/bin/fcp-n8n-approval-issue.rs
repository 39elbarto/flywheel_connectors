//! Isolated, one-shot owner issuer for typed n8n lifecycle approvals.
//!
//! The non-secret request is read from one descriptor-safe file. The raw
//! 32-byte Ed25519 seed is accepted only on stdin and is zeroized on drop.

use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use fcp_crypto::ed25519::{Ed25519SigningKey, SECRET_KEY_SIZE};
use fcp_host::{
    N8nApprovalIssueRequest, build_unsigned_n8n_approval_token, canonical_approval_token_bytes,
    n8n_runtime_approval_verifying_key,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const REQUEST_ROOT: &str = "/var/lib/fwc-n8n/approval-requests";

fn main() -> ExitCode {
    match run() {
        Ok(token) => {
            let mut stdout = io::stdout().lock();
            if stdout.write_all(&token).is_err() || stdout.write_all(b"\n").is_err() {
                emit_error("output_failed")
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(code) => emit_error(code),
    }
}

fn emit_error(code: &'static str) -> ExitCode {
    eprintln!("fcp-n8n-approval-issue: {code}");
    ExitCode::from(1)
}

fn run() -> Result<Vec<u8>, &'static str> {
    let request_path = parse_request_path(std::env::args_os())?;
    validate_request_root().map_err(|_| "invalid_request")?;
    let request_bytes = Zeroizing::new(
        read_bounded_nofollow_file(&request_path, MAX_REQUEST_BYTES)
            .map_err(|_| "invalid_request")?,
    );
    let request: N8nApprovalIssueRequest =
        serde_json::from_slice(&request_bytes).map_err(|_| "invalid_request")?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock_failed")?
        .as_millis()
        .try_into()
        .map_err(|_| "clock_failed")?;
    let mut token =
        build_unsigned_n8n_approval_token(&request, now_ms).map_err(|_| "invalid_request")?;
    let seed = read_exact_seed(io::stdin().lock()).map_err(|_| "invalid_seed")?;
    let signing_key = Ed25519SigningKey::from_bytes(&seed).map_err(|_| "invalid_seed")?;
    let trusted_key =
        n8n_runtime_approval_verifying_key().map_err(|_| "trusted_key_unavailable")?;
    let derived_key = signing_key.verifying_key().to_bytes();
    let trusted_key_bytes = trusted_key.to_bytes();
    if !bool::from(derived_key.ct_eq(&trusted_key_bytes)) {
        return Err("untrusted_seed");
    }
    let bytes = canonical_approval_token_bytes(&token).map_err(|_| "signing_failed")?;
    let signature = signing_key.sign(&bytes);
    trusted_key
        .verify(&bytes, &signature)
        .map_err(|_| "signing_failed")?;
    token.signature = Some(signature.to_bytes().to_vec());
    serde_json::to_vec(&token).map_err(|_| "output_failed")
}

fn parse_request_path<I>(mut args: I) -> Result<PathBuf, &'static str>
where
    I: Iterator<Item = OsString>,
{
    let _program = args.next();
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--request-file")) {
        return Err("invalid_arguments");
    }
    let relative = args.next().map(PathBuf::from).ok_or("invalid_arguments")?;
    if args.next().is_some()
        || relative.is_absolute()
        || relative.components().count() != 1
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err("invalid_arguments");
    }
    Ok(Path::new(REQUEST_ROOT).join(relative))
}

#[cfg(unix)]
fn validate_request_root() -> Result<(), ()> {
    use std::os::unix::fs::MetadataExt;

    let mut current = PathBuf::from("/");
    for component in Path::new(REQUEST_ROOT).components() {
        let Component::Normal(name) = component else {
            continue;
        };
        current.push(name);
        let metadata = fs::symlink_metadata(&current).map_err(|_| ())?;
        if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(());
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_request_root() -> Result<(), ()> {
    Err(())
}

#[cfg(unix)]
fn read_bounded_nofollow_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, ()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let before = fs::symlink_metadata(path).map_err(|_| ())?;
    if !before.file_type().is_file() || before.len() > max_bytes {
        return Err(());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ())?;
    let after = file.metadata().map_err(|_| ())?;
    if !after.is_file()
        || after.len() > max_bytes
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || after.uid() != 0
        || after.mode() & 0o022 != 0
        || after.nlink() != 1
    {
        return Err(());
    }
    let capacity = usize::try_from(after.len()).map_err(|_| ())?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if u64::try_from(bytes.len()).map_err(|_| ())? > max_bytes {
        return Err(());
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_bounded_nofollow_file(_path: &Path, _max_bytes: u64) -> Result<Vec<u8>, ()> {
    Err(())
}

fn read_exact_seed<R: Read>(mut reader: R) -> Result<Zeroizing<[u8; SECRET_KEY_SIZE]>, ()> {
    let mut seed = Zeroizing::new([0_u8; SECRET_KEY_SIZE]);
    reader.read_exact(&mut *seed).map_err(|_| ())?;
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra).map_err(|_| ())? != 0 {
        return Err(());
    }
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_contract_rejects_short_and_extra_bytes() {
        assert!(read_exact_seed(&[7_u8; SECRET_KEY_SIZE][..]).is_ok());
        assert!(read_exact_seed(&[7_u8; SECRET_KEY_SIZE - 1][..]).is_err());
        assert!(read_exact_seed(&[7_u8; SECRET_KEY_SIZE + 1][..]).is_err());
    }

    #[test]
    fn request_path_is_one_component_under_fixed_owner_root() {
        assert_eq!(
            parse_request_path(
                [
                    OsString::from("issuer"),
                    OsString::from("--request-file"),
                    OsString::from("request.json"),
                ]
                .into_iter()
            )
            .expect("valid request path"),
            Path::new(REQUEST_ROOT).join("request.json")
        );
        for name in [
            "/tmp/request.json",
            "../request.json",
            "nested/request.json",
        ] {
            assert!(
                parse_request_path(
                    [
                        OsString::from("issuer"),
                        OsString::from("--request-file"),
                        OsString::from(name),
                    ]
                    .into_iter()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn issuer_is_feature_gated_out_of_the_default_target_set() {
        let manifest = include_str!("../../Cargo.toml");
        assert!(manifest.contains("required-features = [\"n8n-approval-issuer\"]"));
        assert!(manifest.contains("name = \"fcp-n8n-approval-issue\""));
    }

    #[test]
    fn error_output_is_constant_and_redacted() {
        for code in [
            "invalid_arguments",
            "invalid_request",
            "invalid_seed",
            "trusted_key_unavailable",
            "untrusted_seed",
            "signing_failed",
            "output_failed",
        ] {
            assert!(!code.contains("token"));
            assert!(!code.contains("workflow"));
            assert!(!code.contains("public_key"));
        }
    }

    #[test]
    fn imported_signature_type_accepts_exact_signatures() {
        let key = Ed25519SigningKey::generate();
        let signature = key.sign(b"offline-test");
        let parsed = fcp_crypto::ed25519::Ed25519Signature::try_from_slice(&signature.to_bytes())
            .expect("signature");
        key.verifying_key()
            .verify(b"offline-test", &parsed)
            .expect("valid signature");
    }
}
