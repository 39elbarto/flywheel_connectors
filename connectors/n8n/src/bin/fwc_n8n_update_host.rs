//! Host-owned persistence primitives for review-first connector updates.
//!
//! This module is intentionally absent from the public CLI. The update owner
//! decision adapter will use it to consume a decision exactly once before an
//! activation can be authorized.

use std::path::PathBuf;

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(unix)]
use std::fs::Metadata;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};

use fcp_n8n::update::{DecisionLedger, UpdateError};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use uuid::Uuid;

const DECISION_LEDGER_ROOT: &str = "/var/lib/fwc-n8n/update-ledger/consumed";
const LEDGER_SCHEMA: &str = "fwc.n8n.update-decision-consumption.v1";
const MAX_RECORD_BYTES: u64 = 4 * 1024;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ConsumptionRecord {
    schema: String,
    decision_id: String,
    review_digest: String,
}

/// Append-only, cross-process decision ledger.
///
/// One `create_new` record is the atomic consume operation. Records are never
/// rewritten or removed by the runtime.
pub struct DurableDecisionLedger {
    root: PathBuf,
    expected_owner: u32,
}

impl std::fmt::Debug for DurableDecisionLedger {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableDecisionLedger")
            .field("root", &"<fixed-host-path>")
            .field("expected_owner", &self.expected_owner)
            .finish()
    }
}

impl DurableDecisionLedger {
    /// Open the fixed root-owned production ledger. The updater never creates
    /// this trust root; installation must provision it before use.
    #[cfg(target_os = "linux")]
    pub fn production() -> Result<Self, UpdateError> {
        let ledger = Self {
            root: PathBuf::from(DECISION_LEDGER_ROOT),
            expected_owner: 0,
        };
        ledger.verify_root()?;
        Ok(ledger)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn production() -> Result<Self, UpdateError> {
        Err(UpdateError::DecisionLedgerUnavailable)
    }

    #[cfg(test)]
    fn for_test(root: PathBuf, expected_owner: u32) -> Result<Self, UpdateError> {
        let ledger = Self {
            root,
            expected_owner,
        };
        ledger.verify_root()?;
        Ok(ledger)
    }

    #[cfg(target_os = "linux")]
    fn open_verified_root(&self) -> Result<File, UpdateError> {
        use rustix::fs::{Mode, OFlags, ResolveFlags, open, openat2};

        let relative = self
            .root
            .strip_prefix("/")
            .map_err(|_| UpdateError::DecisionLedgerUnavailable)?;
        let filesystem_root = open("/", OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
            .map_err(|_| UpdateError::DecisionLedgerUnavailable)?;
        let root = File::from(
            openat2(
                &filesystem_root,
                relative,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
            )
            .map_err(|_| UpdateError::DecisionLedgerUnavailable)?,
        );
        verify_directory_metadata(
            &root
                .metadata()
                .map_err(|_| UpdateError::DecisionLedgerUnavailable)?,
            self.expected_owner,
        )?;
        Ok(root)
    }

    #[cfg(target_os = "linux")]
    fn verify_root(&self) -> Result<(), UpdateError> {
        self.open_verified_root().map(|_| ())
    }

    #[cfg(not(target_os = "linux"))]
    fn verify_root(&self) -> Result<(), UpdateError> {
        Err(UpdateError::DecisionLedgerUnavailable)
    }

    #[cfg(target_os = "linux")]
    fn record_name(decision_id: &str) -> Result<String, UpdateError> {
        let parsed =
            Uuid::parse_str(decision_id).map_err(|_| UpdateError::DecisionLedgerCorrupt)?;
        if parsed.to_string() != decision_id {
            return Err(UpdateError::DecisionLedgerCorrupt);
        }
        Ok(format!("{decision_id}.json"))
    }

    #[cfg(target_os = "linux")]
    fn existing_record_matches(
        &self,
        root: &File,
        name: &str,
        expected: &ConsumptionRecord,
    ) -> Result<bool, UpdateError> {
        use rustix::fs::{Mode, OFlags, openat};

        let mut file = File::from(
            openat(
                root,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| UpdateError::DecisionLedgerCorrupt)?,
        );
        let metadata = file
            .metadata()
            .map_err(|_| UpdateError::DecisionLedgerCorrupt)?;
        verify_record_metadata(&metadata, self.expected_owner)?;
        if metadata.len() > MAX_RECORD_BYTES {
            return Err(UpdateError::DecisionLedgerCorrupt);
        }
        let capacity =
            usize::try_from(MAX_RECORD_BYTES).map_err(|_| UpdateError::DecisionLedgerCorrupt)?;
        let mut bytes = Vec::with_capacity(capacity);
        (&mut file)
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| UpdateError::DecisionLedgerCorrupt)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(UpdateError::DecisionLedgerCorrupt);
        }
        let final_metadata = file
            .metadata()
            .map_err(|_| UpdateError::DecisionLedgerCorrupt)?;
        verify_record_metadata(&final_metadata, self.expected_owner)?;
        if final_metadata.len() != bytes.len() as u64 {
            return Err(UpdateError::DecisionLedgerCorrupt);
        }
        let actual: ConsumptionRecord =
            serde_json::from_slice(&bytes).map_err(|_| UpdateError::DecisionLedgerCorrupt)?;
        if &actual != expected {
            return Err(UpdateError::DecisionLedgerCorrupt);
        }
        Ok(false)
    }
}

#[cfg(target_os = "linux")]
impl DecisionLedger for DurableDecisionLedger {
    fn consume_once(
        &mut self,
        decision_id: &str,
        review_digest: &str,
    ) -> Result<bool, UpdateError> {
        use rustix::fs::{
            AtFlags, Mode, OFlags, RenameFlags, fsync, openat, renameat_with, unlinkat,
        };
        use rustix::io::Errno;

        let root = self.open_verified_root()?;
        validate_review_digest(review_digest)?;
        let record_name = Self::record_name(decision_id)?;
        let record = ConsumptionRecord {
            schema: LEDGER_SCHEMA.to_string(),
            decision_id: decision_id.to_string(),
            review_digest: review_digest.to_string(),
        };
        let mut bytes =
            serde_json::to_vec(&record).map_err(|_| UpdateError::DecisionLedgerUnavailable)?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(UpdateError::DecisionLedgerCorrupt);
        }

        let pending_name = format!(".{decision_id}.pending-{}", Uuid::new_v4());
        let mut file = File::from(
            openat(
                &root,
                &pending_name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| UpdateError::DecisionLedgerUnavailable)?,
        );
        if file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            drop(file);
            let _ = unlinkat(&root, &pending_name, AtFlags::empty());
            return Err(UpdateError::DecisionLedgerUnavailable);
        }
        let Ok(metadata) = file.metadata() else {
            drop(file);
            let _ = unlinkat(&root, &pending_name, AtFlags::empty());
            return Err(UpdateError::DecisionLedgerUnavailable);
        };
        if let Err(error) = verify_record_metadata(&metadata, self.expected_owner) {
            drop(file);
            let _ = unlinkat(&root, &pending_name, AtFlags::empty());
            return Err(error);
        }
        drop(file);
        match renameat_with(
            &root,
            &pending_name,
            &root,
            &record_name,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {}
            Err(Errno::EXIST) => {
                let _ = unlinkat(&root, &pending_name, AtFlags::empty());
                return self.existing_record_matches(&root, &record_name, &record);
            }
            Err(_) => {
                let _ = unlinkat(&root, &pending_name, AtFlags::empty());
                return Err(UpdateError::DecisionLedgerUnavailable);
            }
        }
        fsync(&root).map_err(|_| UpdateError::DecisionLedgerUnavailable)?;
        Ok(true)
    }
}

#[cfg(not(target_os = "linux"))]
impl DecisionLedger for DurableDecisionLedger {
    fn consume_once(
        &mut self,
        _decision_id: &str,
        _review_digest: &str,
    ) -> Result<bool, UpdateError> {
        Err(UpdateError::DecisionLedgerUnavailable)
    }
}

#[cfg(unix)]
fn verify_directory_metadata(metadata: &Metadata, expected_owner: u32) -> Result<(), UpdateError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o7000 != 0
    {
        return Err(UpdateError::DecisionLedgerUnavailable);
    }
    Ok(())
}

#[cfg(unix)]
fn verify_record_metadata(metadata: &Metadata, expected_owner: u32) -> Result<(), UpdateError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_file()
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o7000 != 0
        || metadata.nlink() != 1
    {
        return Err(UpdateError::DecisionLedgerCorrupt);
    }
    Ok(())
}

fn validate_review_digest(value: &str) -> Result<(), UpdateError> {
    let Some(hex) = value.strip_prefix("blake3-256:") else {
        return Err(UpdateError::DecisionLedgerCorrupt);
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(UpdateError::DecisionLedgerCorrupt);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    const REVIEW_DIGEST: &str =
        "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn ledger_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("temporary ledger root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("private ledger root");
        root
    }

    #[test]
    fn first_consumer_wins_and_matching_replay_is_rejected() {
        let root = ledger_root();
        let owner = fs::metadata(root.path()).expect("metadata").uid();
        let mut first =
            DurableDecisionLedger::for_test(root.path().to_path_buf(), owner).expect("ledger");
        let mut second =
            DurableDecisionLedger::for_test(root.path().to_path_buf(), owner).expect("ledger");
        let decision_id = Uuid::new_v4().to_string();

        assert!(first.consume_once(&decision_id, REVIEW_DIGEST).unwrap());
        assert!(!second.consume_once(&decision_id, REVIEW_DIGEST).unwrap());
    }

    #[test]
    fn mismatched_existing_record_fails_closed() {
        let root = ledger_root();
        let owner = fs::metadata(root.path()).expect("metadata").uid();
        let mut ledger =
            DurableDecisionLedger::for_test(root.path().to_path_buf(), owner).expect("ledger");
        let decision_id = Uuid::new_v4().to_string();
        assert!(ledger.consume_once(&decision_id, REVIEW_DIGEST).unwrap());

        let other_digest =
            "blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert_eq!(
            ledger.consume_once(&decision_id, other_digest),
            Err(UpdateError::DecisionLedgerCorrupt)
        );
    }

    #[test]
    fn orphaned_partial_pending_record_does_not_consume_decision() {
        let root = ledger_root();
        let owner = fs::metadata(root.path()).expect("metadata").uid();
        let mut ledger =
            DurableDecisionLedger::for_test(root.path().to_path_buf(), owner).expect("ledger");
        let decision_id = Uuid::new_v4().to_string();
        fs::write(
            root.path().join(format!(".{decision_id}.pending-orphan")),
            b"partial",
        )
        .expect("orphaned pending record");

        assert!(ledger.consume_once(&decision_id, REVIEW_DIGEST).unwrap());
        assert!(root.path().join(format!("{decision_id}.json")).is_file());
    }

    #[test]
    fn oversized_committed_record_fails_closed() {
        let root = ledger_root();
        let owner = fs::metadata(root.path()).expect("metadata").uid();
        let mut ledger =
            DurableDecisionLedger::for_test(root.path().to_path_buf(), owner).expect("ledger");
        let decision_id = Uuid::new_v4().to_string();
        let record_path = root.path().join(format!("{decision_id}.json"));
        fs::write(&record_path, vec![b'x'; MAX_RECORD_BYTES as usize + 1])
            .expect("oversized record");
        fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600))
            .expect("private record");

        assert_eq!(
            ledger.consume_once(&decision_id, REVIEW_DIGEST),
            Err(UpdateError::DecisionLedgerCorrupt)
        );
    }

    #[test]
    fn writable_or_symlinked_roots_are_rejected() {
        let root = ledger_root();
        let owner = fs::metadata(root.path()).expect("metadata").uid();
        let real_root = root.path().join("real");
        fs::create_dir(&real_root).expect("real ledger root");
        fs::set_permissions(&real_root, fs::Permissions::from_mode(0o700))
            .expect("private real root");
        let linked_root = root.path().join("linked");
        std::os::unix::fs::symlink(&real_root, &linked_root).expect("ledger symlink");
        assert!(matches!(
            DurableDecisionLedger::for_test(linked_root, owner),
            Err(UpdateError::DecisionLedgerUnavailable)
        ));

        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o770))
            .expect("make root unsafe");
        assert!(matches!(
            DurableDecisionLedger::for_test(root.path().to_path_buf(), owner),
            Err(UpdateError::DecisionLedgerUnavailable)
        ));
    }
}
