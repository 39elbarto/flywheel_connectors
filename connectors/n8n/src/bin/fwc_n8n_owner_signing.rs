//! Signing-only implementation for `fwc-n8n-owner-sign`.
//!
//! Only the feature-gated owner binary includes this module. Custody retrieval
//! belongs to the separately admitted controller; this signer reads only stdin.

use std::{io, io::Read};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use fcp_crypto::ed25519::{Ed25519SigningKey, SECRET_KEY_SIZE, SIGNATURE_SIZE};
use zeroize::Zeroizing;

use super::fwc_n8n_provision as provision;

const MAX_SEED_INPUT_BYTES: usize = 45; // 44 Base64 bytes plus at most one LF.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedReadError {
    DumpProtectionUnavailable,
    InvalidSeed,
}

impl SeedReadError {
    pub const fn redacted_code(self) -> &'static str {
        match self {
            Self::DumpProtectionUnavailable => "seed_dump_protection_unavailable",
            Self::InvalidSeed => "invalid_seed",
        }
    }
}

#[cfg(target_os = "linux")]
fn verify_seed_dump_protection(
    dumpable: rustix::process::DumpableBehavior,
    core_limit: rustix::process::Rlimit,
) -> Result<(), SeedReadError> {
    if dumpable != rustix::process::DumpableBehavior::NotDumpable
        || core_limit.current != Some(0)
        || core_limit.maximum != Some(0)
    {
        return Err(SeedReadError::DumpProtectionUnavailable);
    }
    Ok(())
}

fn protect_seed_process() -> Result<(), SeedReadError> {
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{
            DumpableBehavior, Resource, Rlimit, dumpable_behavior, getrlimit,
            set_dumpable_behavior, setrlimit,
        };

        // Exec resets dumpability. Re-establish protection before stdin opens
        // and before allocating any buffer that can contain seed bytes.
        set_dumpable_behavior(DumpableBehavior::NotDumpable)
            .map_err(|_| SeedReadError::DumpProtectionUnavailable)?;
        setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .map_err(|_| SeedReadError::DumpProtectionUnavailable)?;
        verify_seed_dump_protection(
            dumpable_behavior().map_err(|_| SeedReadError::DumpProtectionUnavailable)?,
            getrlimit(Resource::Core),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(SeedReadError::DumpProtectionUnavailable)
    }
}

pub fn validate_staged_signing_request(
    release_id: &str,
    git_revision: &str,
    bindings: &[provision::OfficialMcpBinding],
) -> Result<(), provision::ProvisionError> {
    if !provision::is_git_revision(git_revision) {
        return Err(provision::ProvisionError::new(
            provision::ProvisionErrorCode::InvalidRequest,
        ));
    }
    #[cfg(unix)]
    {
        let stage = provision::fixed_staging_path(release_id)?;
        let release = provision::fixed_release_path(release_id)?;
        provision::validate_binding_shape(bindings)?;
        provision::validate_unsigned_release_tree(
            &stage,
            release_id,
            git_revision,
            bindings,
            rustix::process::geteuid().as_raw(),
            &release,
        )?;
        provision::OwnerVerificationConfig::from_immutable_production_config()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (release_id, bindings);
        Err(provision::ProvisionError::new(
            provision::ProvisionErrorCode::UnsupportedPlatform,
        ))
    }
}

// Private fixed receipt purpose; never accepts a caller-selected context.
fn sign_receipt_payload(
    key: &Ed25519SigningKey,
    payload: &[u8],
) -> Result<fcp_crypto::ed25519::Ed25519Signature, SeedReadError> {
    protect_seed_process()?;
    Ok(key.sign_with_context(provision::RELEASE_SIGNATURE_CONTEXT, payload))
}

pub fn sign_staged_provision_receipt(
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
        validate_staged_signing_request(release_id, git_revision, &bindings)?;
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
        if !owner_verification.matches_active_verifying_key(&verifying_key)? {
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
            signature: fcp_host::N8nReleaseSignature {
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
        signed.signature.signature = sign_receipt_payload(&signing_key, &payload)
            .map_err(|_| provision::ProvisionError::new(provision::ProvisionErrorCode::Signature))?
            .to_hex();
        provision::verify_release_signature(&signed, &receipt_digest, &owner_verification)?;
        serde_json::to_vec(&signed)
            .map_err(|_| provision::ProvisionError::new(provision::ProvisionErrorCode::Receipt))
    }
}

pub fn read_seed_from_stdin() -> Result<Zeroizing<[u8; SECRET_KEY_SIZE]>, SeedReadError> {
    read_seed_with_guard(io::stdin, protect_seed_process)
}

fn read_seed_with_guard<R: Read>(
    open_reader: impl FnOnce() -> R,
    protect: impl FnOnce() -> Result<(), SeedReadError>,
) -> Result<Zeroizing<[u8; SECRET_KEY_SIZE]>, SeedReadError> {
    protect()?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(MAX_SEED_INPUT_BYTES));
    open_reader()
        .take(u64::try_from(MAX_SEED_INPUT_BYTES + 1).map_err(|_| SeedReadError::InvalidSeed)?)
        .read_to_end(&mut encoded)
        .map_err(|_| SeedReadError::InvalidSeed)?;
    decode_seed_input(&encoded).map_err(|()| SeedReadError::InvalidSeed)
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
    fn guard_failure_never_opens_seed_reader() {
        assert!(matches!(
            read_seed_with_guard(
                || -> io::Empty { panic!("guard failure must not open reader") },
                || Err(SeedReadError::DumpProtectionUnavailable),
            ),
            Err(SeedReadError::DumpProtectionUnavailable)
        ));
    }

    #[test]
    fn seed_input_requires_exact_base64_framing() {
        let encoded = STANDARD.encode([7_u8; SECRET_KEY_SIZE]);
        assert!(decode_seed_input(encoded.as_bytes()).is_ok());
        assert!(decode_seed_input(format!("{encoded}\n").as_bytes()).is_ok());
        for malformed in [
            format!("{encoded}\n\n"),
            format!(" {encoded}"),
            format!("{encoded}x"),
            format!("{encoded}\r\n"),
            "!".repeat(44),
            STANDARD.encode([7_u8; SECRET_KEY_SIZE - 1]),
        ] {
            assert!(decode_seed_input(malformed.as_bytes()).is_err());
        }
    }

    #[test]
    fn guarded_reader_is_bounded_and_preserves_io_failure() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("synthetic reader failure"))
            }
        }
        let mut reader = io::Cursor::new(vec![b'A'; 1_024]);
        assert!(matches!(
            read_seed_with_guard(|| &mut reader, || Ok(())),
            Err(SeedReadError::InvalidSeed)
        ));
        assert_eq!(reader.position(), 46);
        assert!(matches!(
            read_seed_with_guard(|| FailingReader, || Ok(())),
            Err(SeedReadError::InvalidSeed)
        ));
    }

    #[test]
    fn fixed_staging_path_rejects_arbitrary_or_aliased_release_ids() {
        for release in ["../outside", ".", "release/child"] {
            assert!(provision::fixed_staging_path(release).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seed_guard_rejects_dumpability_or_limit_readback_drift() {
        use rustix::process::{DumpableBehavior, Rlimit};

        let zero = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        assert!(verify_seed_dump_protection(DumpableBehavior::NotDumpable, zero).is_ok());
        for dumpable in [
            DumpableBehavior::Dumpable,
            DumpableBehavior::DumpableReadableOnlyByRoot,
        ] {
            assert!(matches!(
                read_seed_with_guard(
                    || -> io::Empty { panic!("dumpability drift must not open reader") },
                    || verify_seed_dump_protection(dumpable, zero),
                ),
                Err(SeedReadError::DumpProtectionUnavailable)
            ));
        }
        for limits in [
            Rlimit {
                current: Some(1),
                maximum: Some(1),
            },
            Rlimit {
                current: Some(0),
                maximum: Some(1),
            },
            Rlimit {
                current: None,
                maximum: None,
            },
        ] {
            assert!(matches!(
                read_seed_with_guard(
                    || -> io::Empty { panic!("limit drift must not open reader") },
                    || verify_seed_dump_protection(DumpableBehavior::NotDumpable, limits),
                ),
                Err(SeedReadError::DumpProtectionUnavailable)
            ));
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn seed_guard_unsupported_platform_never_opens_reader() {
        assert!(matches!(
            read_seed_with_guard(
                || -> io::Empty { panic!("unsupported platform must not read") },
                protect_seed_process,
            ),
            Err(SeedReadError::DumpProtectionUnavailable)
        ));
    }

    #[cfg(target_os = "linux")]
    mod native_stdin {
        use super::*;
        use std::{
            os::unix::process::{CommandExt, ExitStatusExt},
            process::{Command, Stdio},
            time::{Duration, Instant},
        };

        const TEST_PAYLOAD: &[u8] =
            b"PUBLIC SYNTHETIC stdin signer regression, not an owner receipt";

        fn assert_guard() {
            use rustix::process::{Resource, dumpable_behavior, getrlimit};
            assert!(
                verify_seed_dump_protection(
                    dumpable_behavior().expect("dump readback"),
                    getrlimit(Resource::Core),
                )
                .is_ok()
            );
        }

        fn synthetic_seed() -> Zeroizing<[u8; SECRET_KEY_SIZE]> {
            read_seed_with_guard(
                || {
                    assert_guard();
                    io::Cursor::new(
                        format!("{}\n", STANDARD.encode([7_u8; SECRET_KEY_SIZE])).into_bytes(),
                    )
                },
                protect_seed_process,
            )
            .expect("guarded synthetic stdin frame")
        }

        fn signature_regression() {
            let seed = synthetic_seed();
            let key = Ed25519SigningKey::from_bytes(&seed).expect("synthetic key");
            let signature = sign_receipt_payload(&key, TEST_PAYLOAD).expect("same guarded signer");
            let verifying = key.verifying_key();
            assert!(
                verifying
                    .verify_with_context(
                        provision::RELEASE_SIGNATURE_CONTEXT,
                        TEST_PAYLOAD,
                        &signature,
                    )
                    .is_ok()
            );
            assert!(
                verifying
                    .verify_with_context(
                        provision::RELEASE_SIGNATURE_CONTEXT,
                        b"changed payload",
                        &signature,
                    )
                    .is_err()
            );
            assert!(
                verifying
                    .verify_with_context(b"wrong context", TEST_PAYLOAD, &signature)
                    .is_err()
            );
            let other =
                Ed25519SigningKey::from_bytes(&[8; SECRET_KEY_SIZE]).expect("other synthetic key");
            assert!(
                other
                    .verifying_key()
                    .verify_with_context(
                        provision::RELEASE_SIGNATURE_CONTEXT,
                        TEST_PAYLOAD,
                        &signature,
                    )
                    .is_err()
            );
            let mut changed = signature.to_bytes();
            changed[0] ^= 1;
            let changed = fcp_crypto::ed25519::Ed25519Signature::from_bytes(&changed);
            assert!(
                verifying
                    .verify_with_context(
                        provision::RELEASE_SIGNATURE_CONTEXT,
                        TEST_PAYLOAD,
                        &changed,
                    )
                    .is_err()
            );
            assert_guard();
        }

        // Self-exec selects only fixed synthetic phases; no custody path/seed
        // argument, parent secret relay or production receipt is involved.
        fn spawn(phase: &str, owns_group: bool) -> std::process::Child {
            assert!(matches!(
                phase,
                "before_exec" | "after_exec" | "sign" | "abort" | "io_error" | "hang" | "failure"
            ));
            let mut command = Command::new(std::env::current_exe().expect("test executable"));
            command
                .args([
                    "--exact",
                    "fwc_n8n_owner_signing::tests::native_stdin::child_entry",
                    "--test-threads=1",
                ])
                .env_clear()
                .env("FWC_OWNER_STDIN_TEST_PHASE", phase)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if owns_group {
                command.process_group(0);
            }
            command.spawn().expect("fixed synthetic child")
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum WaitMode {
            Natural,
            Timeout,
            Cancel,
            WaitFailure,
        }

        fn wait_child(
            child: &mut std::process::Child,
            mode: WaitMode,
        ) -> Result<std::process::ExitStatus, WaitMode> {
            if mode == WaitMode::WaitFailure {
                return Err(mode);
            }
            let budget = if mode == WaitMode::Natural {
                Duration::from_secs(10)
            } else {
                Duration::from_millis(50)
            };
            let deadline = Instant::now() + budget;
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => return Ok(status),
                    Ok(None) => {}
                    Err(_) => return Err(WaitMode::WaitFailure),
                }
                if Instant::now() >= deadline {
                    return Err(if mode == WaitMode::Cancel {
                        WaitMode::Cancel
                    } else {
                        WaitMode::Timeout
                    });
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn finish(
            mut child: std::process::Child,
            mode: WaitMode,
            owns_group: bool,
        ) -> (std::process::ExitStatus, Option<WaitMode>) {
            let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).expect("PID bound"))
                .expect("positive PID");
            let (status, primary) = match wait_child(&mut child, mode) {
                Ok(status) => (status, None),
                Err(primary) => {
                    // Child is unreaped. Signal its owned group only when the
                    // current group identity matches; otherwise target child.
                    let sent = if owns_group && rustix::process::getpgid(Some(pid)) == Ok(pid) {
                        rustix::process::kill_process_group(pid, rustix::process::Signal::KILL)
                            .is_ok()
                    } else {
                        child.kill().is_ok()
                    };
                    let deadline = Instant::now() + Duration::from_secs(2);
                    let status = loop {
                        if let Ok(Some(status)) = child.try_wait() {
                            break status;
                        }
                        assert!(Instant::now() < deadline, "unknown synthetic reap");
                        std::thread::sleep(Duration::from_millis(10));
                    };
                    assert!(sent, "owned termination failed");
                    (status, Some(primary))
                }
            };
            if owns_group {
                assert_eq!(
                    rustix::process::test_kill_process_group(pid),
                    Err(rustix::io::Errno::SRCH)
                );
            }
            (status, primary)
        }

        fn assert_child_success(phase: &str, owns_group: bool) {
            let (status, primary) = finish(spawn(phase, owns_group), WaitMode::Natural, owns_group);
            assert!(status.success());
            assert_eq!(primary, None);
        }

        #[test]
        fn child_entry() {
            assert_ne!(rustix::process::geteuid().as_raw(), 0, "root forbidden");
            match std::env::var("FWC_OWNER_STDIN_TEST_PHASE").as_deref() {
                Err(std::env::VarError::NotPresent) => {
                    assert_child_success("before_exec", true);
                }
                Ok("before_exec") => {
                    protect_seed_process().expect("native guard");
                    assert_guard();
                    assert_child_success("after_exec", false);
                }
                Ok("after_exec") => {
                    assert_eq!(
                        rustix::process::dumpable_behavior().expect("exec readback"),
                        rustix::process::DumpableBehavior::Dumpable
                    );
                    assert!(matches!(
                        read_seed_from_stdin(),
                        Err(SeedReadError::InvalidSeed)
                    ));
                    assert_guard();
                }
                Ok("sign") => signature_regression(),
                Ok("abort") => {
                    let seed = synthetic_seed();
                    assert_guard();
                    std::hint::black_box(&*seed);
                    rustix::process::kill_process(
                        rustix::process::getpid(),
                        rustix::process::Signal::ABORT,
                    )
                    .expect("guarded abort");
                    panic!("abort did not terminate");
                }
                Ok("io_error") => {
                    struct FailingReader;
                    impl Read for FailingReader {
                        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                            Err(io::Error::other("synthetic I/O"))
                        }
                    }
                    protect_seed_process().expect("native guard");
                    assert_guard();
                    assert!(matches!(
                        read_seed_with_guard(|| FailingReader, protect_seed_process),
                        Err(SeedReadError::InvalidSeed)
                    ));
                    assert_guard();
                }
                Ok("hang") => {
                    protect_seed_process().expect("native guard");
                    assert_guard();
                    std::thread::sleep(Duration::from_secs(30));
                }
                Ok("failure") => {
                    protect_seed_process().expect("native guard");
                    assert_guard();
                    std::process::exit(9);
                }
                _ => panic!("closed phase required"),
            }
        }

        #[test]
        fn actual_guarded_stdin_seed_sign_verify_and_tamper_rejection() {
            assert_child_success("sign", true);
        }

        #[test]
        fn actual_guarded_reader_io_error() {
            assert_child_success("io_error", true);
        }

        #[test]
        fn guarded_own_abort_has_no_core_wait_bit() {
            let (status, primary) = finish(spawn("abort", true), WaitMode::Natural, true);
            assert_eq!(primary, None);
            assert_eq!(
                status.signal(),
                Some(rustix::process::Signal::ABORT.as_raw())
            );
            assert!(!status.core_dumped());
        }

        #[test]
        fn synthetic_failure_and_owned_cancellation_are_reaped() {
            let (status, primary) = finish(spawn("failure", true), WaitMode::Natural, true);
            assert_eq!(status.code(), Some(9));
            assert_eq!(primary, None);
            for mode in [WaitMode::Timeout, WaitMode::Cancel, WaitMode::WaitFailure] {
                let (status, primary) = finish(spawn("hang", true), mode, true);
                assert_eq!(primary, Some(mode));
                assert_eq!(
                    status.signal(),
                    Some(rustix::process::Signal::KILL.as_raw())
                );
            }
        }
    }
}
