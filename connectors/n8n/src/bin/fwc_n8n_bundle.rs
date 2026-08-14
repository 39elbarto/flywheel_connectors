//! Immutable, host-derived release-bundle verification for `fwc-n8n status`.
//!
//! The verifier deliberately has no configurable path or release lookup.  It
//! starts at the canonical current executable, derives its fixed `bin/` and
//! release-root parents, and validates one exact receipt plus eight exact
//! sibling artifacts.  Root ownership and non-writable group/other modes are
//! the current local trust root; this module does not claim signature
//! verification.

use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

const RECEIPT_SCHEMA: &str = "fwc.n8n.bundle.v1";
const RECEIPT_FILE: &str = "receipt.json";
const MAX_RECEIPT_BYTES: usize = 128 * 1024;
const EXPECTED_ARTIFACTS: [&str; 8] = [
    "bin/fwc-n8n",
    "bin/fcp-host",
    "bin/fcp-n8n",
    "bin/secret-get",
    "manifests/fcp-n8n.toml",
    "inventory/eec.json",
    "inventory/hetzner.json",
    "policy/zone-policies.json",
];
const EXECUTABLE_ARTIFACTS: [&str; 4] = [
    "bin/fwc-n8n",
    "bin/fcp-host",
    "bin/fcp-n8n",
    "bin/secret-get",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum BundleErrorCode {
    #[cfg(not(unix))]
    UnsupportedPlatform,
    NotBundleExecutable,
    Layout,
    Metadata,
    Permissions,
    Receipt,
    ReleaseId,
    ArtifactSet,
    ArtifactPath,
    Digest,
}

impl BundleErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            #[cfg(not(unix))]
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::NotBundleExecutable => "not_bundle_executable",
            Self::Layout => "invalid_layout",
            Self::Metadata => "invalid_metadata",
            Self::Permissions => "invalid_permissions",
            Self::Receipt => "invalid_receipt",
            Self::ReleaseId => "invalid_release_id",
            Self::ArtifactSet => "invalid_artifact_set",
            Self::ArtifactPath => "invalid_artifact_path",
            Self::Digest => "digest_mismatch",
        }
    }
}

impl fmt::Debug for BundleErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BundleError {
    code: BundleErrorCode,
}

impl BundleError {
    const fn new(code: BundleErrorCode) -> Self {
        Self { code }
    }

    #[cfg(test)]
    const fn code(self) -> BundleErrorCode {
        self.code
    }
}

impl fmt::Debug for BundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BundleError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for BundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "fwc-n8n bundle unavailable: {}",
            self.code.as_str()
        )
    }
}

impl std::error::Error for BundleError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleReceipt {
    schema: String,
    release_id: String,
    artifacts: Vec<BundleArtifact>,
}

impl fmt::Debug for BundleReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BundleReceipt")
            .field("schema", &"<redacted>")
            .field("release_id", &"<redacted>")
            .field("artifact_count", &self.artifacts.len())
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleArtifact {
    path: String,
    digest: String,
}

impl fmt::Debug for BundleArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BundleArtifact")
            .field("path", &"<redacted>")
            .field("digest", &"<redacted>")
            .finish()
    }
}

/// The only bundle facts that the internal host runner may consume.
///
/// Every path is derived from the canonical current executable and every
/// digest was checked against the immutable receipt before this value was
/// constructed.  This type intentionally exposes no release-root or caller
/// supplied path and never reveals its contents through `Debug`.
pub(super) struct VerifiedBundle {
    fcp_host_path: PathBuf,
    fcp_host_digest: String,
    inventory_eec_path: PathBuf,
    inventory_eec_digest: String,
    inventory_hetzner_path: PathBuf,
    inventory_hetzner_digest: String,
    zone_policy_path: PathBuf,
    zone_policy_digest: String,
}

impl fmt::Debug for VerifiedBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBundle")
            .field("artifact_count", &4)
            .field("digests", &"<redacted>")
            .finish()
    }
}

impl VerifiedBundle {
    pub(super) fn fcp_host(&self) -> (&Path, &str) {
        (&self.fcp_host_path, &self.fcp_host_digest)
    }

    pub(super) fn inventory_eec(&self) -> (&Path, &str) {
        (&self.inventory_eec_path, &self.inventory_eec_digest)
    }

    pub(super) fn inventory_hetzner(&self) -> (&Path, &str) {
        (&self.inventory_hetzner_path, &self.inventory_hetzner_digest)
    }

    pub(super) fn zone_policy(&self) -> (&Path, &str) {
        (&self.zone_policy_path, &self.zone_policy_digest)
    }

    #[cfg(test)]
    pub(super) fn test_fixture() -> Self {
        Self {
            fcp_host_path: PathBuf::from("/release/bin/fcp-host"),
            fcp_host_digest: "a".repeat(64),
            inventory_eec_path: PathBuf::from("/release/inventory/eec.json"),
            inventory_eec_digest: "b".repeat(64),
            inventory_hetzner_path: PathBuf::from("/release/inventory/hetzner.json"),
            inventory_hetzner_digest: "c".repeat(64),
            zone_policy_path: PathBuf::from("/release/policy/zone-policies.json"),
            zone_policy_digest: "d".repeat(64),
        }
    }
}

/// Verify the fixed release bundle selected by the canonical current binary.
pub fn verify_current_release_bundle() -> Result<(), BundleError> {
    verify_current_release_bundle_for_bridge().map(|_| ())
}

/// Verify and return the fixed facts needed by the internal host runner.
pub(super) fn verify_current_release_bundle_for_bridge() -> Result<VerifiedBundle, BundleError> {
    #[cfg(not(unix))]
    {
        Err(BundleError::new(BundleErrorCode::UnsupportedPlatform))
    }

    #[cfg(unix)]
    {
        let executable =
            std::env::current_exe().map_err(|_| BundleError::new(BundleErrorCode::Metadata))?;
        verify_release_bundle(&executable, 0)
    }
}

#[cfg(unix)]
fn verify_release_bundle(
    executable: &Path,
    expected_owner: u32,
) -> Result<VerifiedBundle, BundleError> {
    let executable = verify_file(executable, expected_owner, true)?;
    if executable.file_name().and_then(|name| name.to_str()) != Some("fwc-n8n") {
        return Err(BundleError::new(BundleErrorCode::NotBundleExecutable));
    }

    let bin = executable
        .parent()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some("bin"))
        .ok_or_else(|| BundleError::new(BundleErrorCode::Layout))?;
    let root = bin
        .parent()
        .ok_or_else(|| BundleError::new(BundleErrorCode::Layout))?;
    verify_directory(root, expected_owner)?;
    verify_directory(bin, expected_owner)?;
    for directory in ["manifests", "inventory", "policy"] {
        verify_directory(&root.join(directory), expected_owner)?;
    }

    let receipt_path = root.join(RECEIPT_FILE);
    verify_file(&receipt_path, expected_owner, false)?;
    let receipt = read_receipt(&receipt_path)?;
    validate_receipt_shape(&receipt, root)?;

    let mut verified_artifacts = Vec::with_capacity(EXPECTED_ARTIFACTS.len());
    for relative_path in EXPECTED_ARTIFACTS {
        let artifact_path = root.join(relative_path);
        let artifact = verify_file(
            &artifact_path,
            expected_owner,
            EXECUTABLE_ARTIFACTS.contains(&relative_path),
        )?;
        if !artifact.starts_with(root) {
            return Err(BundleError::new(BundleErrorCode::ArtifactPath));
        }
        let expected_digest = receipt
            .artifacts
            .iter()
            .find(|entry| entry.path == relative_path)
            .map(|entry| entry.digest.as_str())
            .ok_or_else(|| BundleError::new(BundleErrorCode::ArtifactSet))?;
        let actual_digest = hash_file(&artifact)?;
        if actual_digest != expected_digest {
            return Err(BundleError::new(BundleErrorCode::Digest));
        }
        verified_artifacts.push((relative_path, artifact, actual_digest));
    }

    let artifact = |relative_path: &str| {
        verified_artifacts
            .iter()
            .find(|(path, _, _)| *path == relative_path)
            .map(|(_, path, digest)| (path.clone(), digest.clone()))
            .ok_or_else(|| BundleError::new(BundleErrorCode::ArtifactSet))
    };
    let (fcp_host_path, fcp_host_digest) = artifact("bin/fcp-host")?;
    let (inventory_eec_path, inventory_eec_digest) = artifact("inventory/eec.json")?;
    let (inventory_hetzner_path, inventory_hetzner_digest) = artifact("inventory/hetzner.json")?;
    let (zone_policy_path, zone_policy_digest) = artifact("policy/zone-policies.json")?;
    Ok(VerifiedBundle {
        fcp_host_path,
        fcp_host_digest,
        inventory_eec_path,
        inventory_eec_digest,
        inventory_hetzner_path,
        inventory_hetzner_digest,
        zone_policy_path,
        zone_policy_digest,
    })
}

#[cfg(not(unix))]
#[allow(dead_code)]
fn verify_release_bundle(
    _executable: &Path,
    _expected_owner: u32,
) -> Result<VerifiedBundle, BundleError> {
    Err(BundleError::new(BundleErrorCode::UnsupportedPlatform))
}

#[cfg(test)]
#[allow(dead_code)]
fn verify_release_bundle_for_owner(
    executable: &Path,
    expected_owner: u32,
) -> Result<VerifiedBundle, BundleError> {
    verify_release_bundle(executable, expected_owner)
}

#[cfg(unix)]
fn verify_directory(path: &Path, expected_owner: u32) -> Result<(), BundleError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| BundleError::new(BundleErrorCode::Layout))?;
    if !metadata.file_type().is_dir() {
        return Err(BundleError::new(BundleErrorCode::Layout));
    }
    verify_metadata(&metadata, expected_owner, false)?;
    let canonical =
        fs::canonicalize(path).map_err(|_| BundleError::new(BundleErrorCode::Layout))?;
    if canonical != path {
        return Err(BundleError::new(BundleErrorCode::Layout));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_file(
    path: &Path,
    expected_owner: u32,
    require_owner_executable: bool,
) -> Result<PathBuf, BundleError> {
    use std::os::unix::fs::MetadataExt;

    let metadata =
        fs::symlink_metadata(path).map_err(|_| BundleError::new(BundleErrorCode::Layout))?;
    if !metadata.file_type().is_file() {
        return Err(BundleError::new(BundleErrorCode::Layout));
    }
    verify_metadata(&metadata, expected_owner, true)?;
    if require_owner_executable && metadata.mode() & 0o100 == 0 {
        return Err(BundleError::new(BundleErrorCode::Permissions));
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| BundleError::new(BundleErrorCode::Layout))?;
    if canonical != path {
        return Err(BundleError::new(BundleErrorCode::Layout));
    }
    Ok(canonical)
}

#[cfg(unix)]
fn verify_metadata(
    metadata: &Metadata,
    expected_owner: u32,
    require_single_link: bool,
) -> Result<(), BundleError> {
    use std::os::unix::fs::MetadataExt;

    if metadata.uid() != expected_owner {
        return Err(BundleError::new(BundleErrorCode::Permissions));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(BundleError::new(BundleErrorCode::Permissions));
    }
    if metadata.mode() & 0o7000 != 0 {
        return Err(BundleError::new(BundleErrorCode::Permissions));
    }
    if require_single_link && metadata.nlink() != 1 {
        return Err(BundleError::new(BundleErrorCode::Metadata));
    }
    Ok(())
}

fn read_receipt(path: &Path) -> Result<BundleReceipt, BundleError> {
    let metadata = fs::metadata(path).map_err(|_| BundleError::new(BundleErrorCode::Receipt))?;
    if metadata.len() > MAX_RECEIPT_BYTES as u64 {
        return Err(BundleError::new(BundleErrorCode::Receipt));
    }
    let mut file = File::open(path).map_err(|_| BundleError::new(BundleErrorCode::Receipt))?;
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| BundleError::new(BundleErrorCode::Receipt))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|_| BundleError::new(BundleErrorCode::Receipt))?;
    serde_json::from_slice(&bytes).map_err(|_| BundleError::new(BundleErrorCode::Receipt))
}

fn validate_receipt_shape(receipt: &BundleReceipt, root: &Path) -> Result<(), BundleError> {
    if receipt.schema != RECEIPT_SCHEMA
        || !is_safe_release_id(&receipt.release_id)
        || root.file_name().and_then(|name| name.to_str()) != Some(receipt.release_id.as_str())
    {
        return Err(BundleError::new(BundleErrorCode::ReleaseId));
    }
    if receipt.artifacts.len() != EXPECTED_ARTIFACTS.len() {
        return Err(BundleError::new(BundleErrorCode::ArtifactSet));
    }

    for artifact in &receipt.artifacts {
        if !EXPECTED_ARTIFACTS.contains(&artifact.path.as_str())
            || !is_exact_relative_path(&artifact.path)
            || receipt
                .artifacts
                .iter()
                .filter(|entry| entry.path == artifact.path)
                .count()
                != 1
            || !is_blake3_digest(&artifact.digest)
        {
            return Err(BundleError::new(BundleErrorCode::ArtifactPath));
        }
    }
    Ok(())
}

fn is_safe_release_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn is_exact_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && !value.contains('\\')
        && !value.contains("://")
}

fn is_blake3_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(unix)]
fn hash_file(path: &Path) -> Result<String, BundleError> {
    let mut file = File::open(path).map_err(|_| BundleError::new(BundleErrorCode::Digest))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let bytes = file
            .read(&mut buffer)
            .map_err(|_| BundleError::new(BundleErrorCode::Digest))?;
        if bytes == 0 {
            break;
        }
        hasher.update(&buffer[..bytes]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    #[cfg(unix)]
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[cfg(unix)]
    struct ReleaseFixture {
        root: PathBuf,
        executable: PathBuf,
        owner: u32,
    }

    #[cfg(unix)]
    impl ReleaseFixture {
        fn new() -> Self {
            let parent = fs::canonicalize(std::env::temp_dir()).expect("canonical temp dir");
            let root = loop {
                let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let release_id = format!("fwc-n8n-test-{}-{sequence}", std::process::id());
                let root = parent.join(&release_id);
                match fs::create_dir(&root) {
                    Ok(()) => break root,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("create release fixture root: {error}"),
                }
            };
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("restrict release fixture root");
            for directory in ["bin", "manifests", "inventory", "policy"] {
                let path = root.join(directory);
                fs::create_dir(&path).expect("create release fixture directory");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("restrict release fixture directory");
            }
            for relative_path in EXPECTED_ARTIFACTS {
                let path = root.join(relative_path);
                fs::write(&path, relative_path.as_bytes()).expect("write release fixture artifact");
                let mode = if EXECUTABLE_ARTIFACTS.contains(&relative_path) {
                    0o700
                } else {
                    0o600
                };
                fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                    .expect("restrict release fixture artifact");
            }
            let owner = fs::symlink_metadata(&root)
                .expect("release fixture metadata")
                .uid();
            let executable = root.join("bin/fwc-n8n");
            let fixture = Self {
                root,
                executable,
                owner,
            };
            fixture.write_receipt(None);
            fixture
        }

        fn artifact(&self, relative_path: &str) -> PathBuf {
            self.root.join(relative_path)
        }

        fn write_receipt(&self, digest_override: Option<(&str, &str)>) {
            let artifacts: Vec<Value> = EXPECTED_ARTIFACTS
                .iter()
                .map(|relative_path| {
                    let digest = digest_override
                        .filter(|(path, _)| path == relative_path)
                        .map_or_else(
                            || hash_file(&self.artifact(relative_path)).expect("artifact digest"),
                            |(_, digest)| digest.to_owned(),
                        );
                    serde_json::json!({"path": relative_path, "digest": digest})
                })
                .collect();
            let release_id = self
                .root
                .file_name()
                .and_then(|name| name.to_str())
                .expect("release fixture id");
            fs::write(
                self.root.join(RECEIPT_FILE),
                serde_json::to_vec(&serde_json::json!({
                    "schema": RECEIPT_SCHEMA,
                    "release_id": release_id,
                    "artifacts": artifacts,
                }))
                .expect("encode release fixture receipt"),
            )
            .expect("write release fixture receipt");
            fs::set_permissions(
                self.root.join(RECEIPT_FILE),
                fs::Permissions::from_mode(0o600),
            )
            .expect("restrict release fixture receipt");
        }
    }

    #[cfg(unix)]
    impl Drop for ReleaseFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn receipt(root: &str) -> BundleReceipt {
        BundleReceipt {
            schema: RECEIPT_SCHEMA.to_owned(),
            release_id: root.to_owned(),
            artifacts: EXPECTED_ARTIFACTS
                .iter()
                .map(|path| BundleArtifact {
                    path: (*path).to_owned(),
                    digest: "a".repeat(64),
                })
                .collect(),
        }
    }

    #[test]
    fn receipt_shape_accepts_only_exact_release_artifacts() {
        let root = Path::new("release-20260814");
        validate_receipt_shape(&receipt("release-20260814"), root).expect("exact receipt");
    }

    #[test]
    fn receipt_shape_rejects_release_and_artifact_tampering() {
        let root = Path::new("release-20260814");
        for release_id in ["", "../release-20260814", "release/other", "release:latest"] {
            let mut value = receipt("release-20260814");
            value.release_id = release_id.to_owned();
            assert_eq!(
                validate_receipt_shape(&value, root)
                    .expect_err("release id must fail")
                    .code(),
                BundleErrorCode::ReleaseId
            );
        }

        for path in [
            "/tmp/fwc-n8n",
            "../bin/fwc-n8n",
            "bin/./fwc-n8n",
            "https://example.invalid/fwc-n8n",
        ] {
            let mut value = receipt("release-20260814");
            value.artifacts[0].path = path.to_owned();
            assert!(validate_receipt_shape(&value, root).is_err());
        }

        let mut duplicate = receipt("release-20260814");
        duplicate.artifacts[1].path = duplicate.artifacts[0].path.clone();
        assert_eq!(
            validate_receipt_shape(&duplicate, root)
                .expect_err("duplicate artifact must fail")
                .code(),
            BundleErrorCode::ArtifactPath
        );

        let mut digest = receipt("release-20260814");
        digest.artifacts[0].digest = "A".repeat(64);
        assert!(validate_receipt_shape(&digest, root).is_err());
    }

    #[test]
    fn receipt_and_artifact_debug_are_redacted() {
        let value = receipt("release-20260814");
        let receipt_debug = format!("{value:?}");
        let artifact_debug = format!("{:?}", value.artifacts[0]);
        assert!(!receipt_debug.contains("release-20260814"));
        assert!(!receipt_debug.contains("bin/fwc-n8n"));
        assert!(!artifact_debug.contains("bin/fwc-n8n"));
        assert!(!artifact_debug.contains(&"a".repeat(64)));
    }

    #[cfg(unix)]
    #[test]
    fn dev_test_executable_is_not_a_production_bundle() {
        let executable = std::env::current_exe().expect("test executable");
        let owner = fs::symlink_metadata(&executable)
            .expect("test executable metadata")
            .uid();
        let error = verify_release_bundle_for_owner(&executable, owner)
            .expect_err("test executable is not named fwc-n8n");
        assert_eq!(error.code(), BundleErrorCode::NotBundleExecutable);
        assert!(!format!("{error:?}").contains(executable.to_string_lossy().as_ref()));
    }

    #[cfg(unix)]
    #[test]
    fn complete_release_fixture_verifies_and_tampering_fails_closed() {
        let valid = ReleaseFixture::new();
        verify_release_bundle_for_owner(&valid.executable, valid.owner)
            .expect("complete immutable release fixture");

        let wrong_digest = ReleaseFixture::new();
        wrong_digest.write_receipt(Some(("bin/fcp-host", &"0".repeat(64))));
        assert_eq!(
            verify_release_bundle_for_owner(&wrong_digest.executable, wrong_digest.owner)
                .expect_err("wrong digest")
                .code(),
            BundleErrorCode::Digest
        );
    }

    #[cfg(unix)]
    #[test]
    fn release_metadata_tampering_fails_closed() {
        let writable = ReleaseFixture::new();
        fs::set_permissions(
            writable.artifact("bin/fcp-host"),
            fs::Permissions::from_mode(0o666),
        )
        .expect("make artifact writable");
        assert_eq!(
            verify_release_bundle_for_owner(&writable.executable, writable.owner)
                .expect_err("writable artifact")
                .code(),
            BundleErrorCode::Permissions
        );

        let non_executable = ReleaseFixture::new();
        fs::set_permissions(
            non_executable.artifact("bin/fcp-host"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("remove executable bit");
        assert_eq!(
            verify_release_bundle_for_owner(&non_executable.executable, non_executable.owner)
                .expect_err("non-executable host binary")
                .code(),
            BundleErrorCode::Permissions
        );

        let special_mode = ReleaseFixture::new();
        fs::set_permissions(
            special_mode.artifact("bin/fcp-host"),
            fs::Permissions::from_mode(0o4700),
        )
        .expect("set privileged mode bit");
        assert_eq!(
            verify_release_bundle_for_owner(&special_mode.executable, special_mode.owner)
                .expect_err("special executable mode")
                .code(),
            BundleErrorCode::Permissions
        );

        let writable_receipt = ReleaseFixture::new();
        fs::set_permissions(
            writable_receipt.root.join(RECEIPT_FILE),
            fs::Permissions::from_mode(0o620),
        )
        .expect("make receipt group-writable");
        assert_eq!(
            verify_release_bundle_for_owner(&writable_receipt.executable, writable_receipt.owner,)
                .expect_err("writable receipt")
                .code(),
            BundleErrorCode::Permissions
        );

        let linked = ReleaseFixture::new();
        fs::remove_file(linked.artifact("bin/fcp-host")).expect("remove link target");
        symlink("fcp-n8n", linked.artifact("bin/fcp-host")).expect("create artifact symlink");
        assert_eq!(
            verify_release_bundle_for_owner(&linked.executable, linked.owner)
                .expect_err("symlinked artifact")
                .code(),
            BundleErrorCode::Layout
        );

        let hard_linked = ReleaseFixture::new();
        fs::remove_file(hard_linked.artifact("bin/fcp-host")).expect("remove hard-link target");
        fs::hard_link(
            hard_linked.artifact("bin/fcp-n8n"),
            hard_linked.artifact("bin/fcp-host"),
        )
        .expect("create artifact hard link");
        assert_eq!(
            verify_release_bundle_for_owner(&hard_linked.executable, hard_linked.owner)
                .expect_err("hard-linked artifact")
                .code(),
            BundleErrorCode::Metadata
        );

        let missing = ReleaseFixture::new();
        fs::remove_file(missing.artifact("inventory/eec.json")).expect("remove artifact");
        assert_eq!(
            verify_release_bundle_for_owner(&missing.executable, missing.owner)
                .expect_err("missing artifact")
                .code(),
            BundleErrorCode::Layout
        );

        let wrong_owner = ReleaseFixture::new();
        let unexpected_owner = if wrong_owner.owner == u32::MAX {
            0
        } else {
            wrong_owner.owner + 1
        };
        assert_eq!(
            verify_release_bundle_for_owner(&wrong_owner.executable, unexpected_owner,)
                .expect_err("unexpected owner")
                .code(),
            BundleErrorCode::Permissions
        );
    }
}
