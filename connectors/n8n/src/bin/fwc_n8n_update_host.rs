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
use serde_json::{Value, json};
#[cfg(target_os = "linux")]
use uuid::Uuid;

const DECISION_LEDGER_ROOT: &str = "/var/lib/fwc-n8n/update-ledger/consumed";
const LEDGER_SCHEMA: &str = "fwc.n8n.update-decision-consumption.v1";
const MAX_RECORD_BYTES: u64 = 4 * 1024;
const MCP_ACCESS_LEDGER_ROOT: &str = "/var/lib/fwc-n8n/mcp-access-ledger/receipts";
const MCP_ACCESS_LEDGER_SCHEMA: &str = "fwc.n8n.mcp-access-ledger.v1";
const MCP_ACCESS_RECEIPT_SCHEMA: &str = "fwc.n8n.mcp-access-receipt.v1";
const MCP_ACCESS_RECEIPT_OPERATION: &str = "n8n.mcp_access.reconcile";
const MCP_ACCESS_RECEIPT_DIGEST_DOMAIN: &[u8] = b"fwc-n8n.mcp-access-receipt.v1";
const MCP_ACCESS_IDEMPOTENCY_KEY_DOMAIN: &[u8] = b"fwc-n8n.mcp-access-idempotency-key.v1";
const MCP_ACCESS_BINDING_DOMAIN: &[u8] = b"fwc-n8n.mcp-access-ledger-binding.v1";
const MCP_ACCESS_RECEIPT_BINDING_DOMAIN: &[u8] = b"fwc-n8n.mcp-access-binding.v1";
const MCP_ACCESS_LEDGER_MAX_RECORD_BYTES: u64 = 384 * 1024;
const MCP_ACCESS_LEDGER_MAX_RECORDS: usize = 1024;
const MCP_ACCESS_LEDGER_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const MCP_ACCESS_RECEIPT_MAX_ITEMS: usize = 1_000;
const MCP_ACCESS_RECEIPT_MAX_BYTES: usize = 256 * 1024;
const MCP_ACCESS_RECEIPT_MAX_OUTCOME_LENGTH: usize = 96;
const MCP_ACCESS_RECEIPT_MAX_DIGEST_LENGTH: usize = 75;
const MCP_ACCESS_RECEIPT_MAX_SERVER_ID_LENGTH: usize = 128;
const MCP_ACCESS_RECEIPT_MAX_SCOPE_LENGTH: usize = 32;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ConsumptionRecord {
    schema: String,
    decision_id: String,
    review_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct McpAccessLedgerReceiptItem {
    resource_digest: String,
    #[serde(rename = "availableInMCP")]
    available_in_mcp: Option<bool>,
    desired: bool,
    outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct McpAccessLedgerReceipt {
    schema: String,
    operation: String,
    server_id: String,
    scope: String,
    desired: bool,
    dry_run: bool,
    status: String,
    plan_digest: String,
    readback_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    idempotency_digest: Option<String>,
    items: Vec<McpAccessLedgerReceiptItem>,
    receipt_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct McpAccessLedgerRecord {
    schema: String,
    key_digest: String,
    binding_digest: String,
    state: String,
    created_at_ms: u64,
    expires_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<McpAccessLedgerReceipt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpAccessLedgerError {
    Unavailable,
    Corrupt,
    Collision,
    RequestMismatch,
    Unknown,
    Expired,
}

impl McpAccessLedgerError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "mcp_access_ledger_unavailable",
            Self::Corrupt => "mcp_access_ledger_corrupt",
            Self::Collision => "mcp_access_idempotency_collision",
            Self::RequestMismatch => "mcp_access_receipt_request_mismatch",
            Self::Unknown => "mcp_access_unknown_outcome",
            Self::Expired => "mcp_access_ledger_expired",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpAccessLedgerBinding {
    pub key_digest: String,
    pub binding_digest: String,
}

/// Request fields that the host can prove before accepting a provider receipt.
/// The binding digest ties this expectation to the exact normalized request;
/// the receipt itself is never treated as its own authorization source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpAccessReceiptExpectation {
    pub binding_digest: String,
    pub server_id: String,
    pub scope: String,
    pub desired: bool,
    pub dry_run: bool,
    pub plan_digest: Option<String>,
    pub approval_digest: Option<String>,
    pub idempotency_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpAccessLedgerBegin {
    Claimed,
    Replayed(Value),
}

/// Host-owned append-only receipt ledger for MCP access reconciliation.
///
/// The runtime never creates the production trust root. Installation owns the
/// fixed root and its ownership/mode policy. Records are immutable within the
/// bounded retention window; a pending claim is intentionally left behind on
/// an interrupted provider call so a retry fails closed as unknown.
pub struct McpAccessReconciliationLedger {
    root: PathBuf,
    expected_owner: u32,
}

impl std::fmt::Debug for McpAccessReconciliationLedger {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpAccessReconciliationLedger")
            .field("root", &"<fixed-host-path>")
            .field("expected_owner", &self.expected_owner)
            .finish()
    }
}

impl McpAccessReconciliationLedger {
    #[cfg(target_os = "linux")]
    pub fn production() -> Result<Self, McpAccessLedgerError> {
        let ledger = Self {
            root: PathBuf::from(MCP_ACCESS_LEDGER_ROOT),
            expected_owner: current_effective_uid()?,
        };
        ledger.open_verified_root()?;
        Ok(ledger)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn production() -> Result<Self, McpAccessLedgerError> {
        Err(McpAccessLedgerError::Unavailable)
    }

    #[cfg(test)]
    fn for_test(root: PathBuf, expected_owner: u32) -> Result<Self, McpAccessLedgerError> {
        let ledger = Self {
            root,
            expected_owner,
        };
        ledger.open_verified_root()?;
        Ok(ledger)
    }

    #[cfg(target_os = "linux")]
    fn open_verified_root(&self) -> Result<File, McpAccessLedgerError> {
        let root = open_verified_root_path(&self.root, self.expected_owner)?;
        let metadata = root
            .metadata()
            .map_err(|_| McpAccessLedgerError::Unavailable)?;
        verify_private_directory_metadata(&metadata, self.expected_owner)?;
        Ok(root)
    }

    #[cfg(not(target_os = "linux"))]
    fn open_verified_root(&self) -> Result<File, McpAccessLedgerError> {
        Err(McpAccessLedgerError::Unavailable)
    }

    #[cfg(target_os = "linux")]
    pub fn begin(
        &mut self,
        binding: &McpAccessLedgerBinding,
    ) -> Result<McpAccessLedgerBegin, McpAccessLedgerError> {
        self.begin_for_request(binding, None)
    }

    #[cfg(target_os = "linux")]
    pub fn begin_for_request(
        &mut self,
        binding: &McpAccessLedgerBinding,
        expectation: Option<&McpAccessReceiptExpectation>,
    ) -> Result<McpAccessLedgerBegin, McpAccessLedgerError> {
        use rustix::fs::{FlockOperation, flock};

        validate_digest(&binding.key_digest)?;
        validate_digest(&binding.binding_digest)?;
        validate_request_expectation(binding, expectation)?;
        let root = self.open_verified_root()?;
        flock(&root, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| McpAccessLedgerError::Unavailable)?;
        let result = self.begin_locked(&root, binding, expectation);
        let _ = flock(&root, FlockOperation::NonBlockingUnlock);
        result
    }

    #[cfg(not(target_os = "linux"))]
    pub fn begin(
        &mut self,
        _binding: &McpAccessLedgerBinding,
    ) -> Result<McpAccessLedgerBegin, McpAccessLedgerError> {
        Err(McpAccessLedgerError::Unavailable)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn begin_for_request(
        &mut self,
        _binding: &McpAccessLedgerBinding,
        _expectation: Option<&McpAccessReceiptExpectation>,
    ) -> Result<McpAccessLedgerBegin, McpAccessLedgerError> {
        Err(McpAccessLedgerError::Unavailable)
    }

    #[cfg(target_os = "linux")]
    fn begin_locked(
        &self,
        root: &File,
        binding: &McpAccessLedgerBinding,
        expectation: Option<&McpAccessReceiptExpectation>,
    ) -> Result<McpAccessLedgerBegin, McpAccessLedgerError> {
        reap_expired_committed_records(root, self.expected_owner)?;
        let pending_name = pending_name(&binding.key_digest)?;
        if let Some(record) = read_mcp_access_record(root, &pending_name, self.expected_owner)? {
            return if record.state == "pending"
                && record.key_digest == binding.key_digest
                && record.binding_digest == binding.binding_digest
            {
                Err(McpAccessLedgerError::Unknown)
            } else {
                Err(McpAccessLedgerError::Collision)
            };
        }
        let final_name = record_name(&binding.key_digest)?;
        if let Some(record) = read_mcp_access_record(root, &final_name, self.expected_owner)? {
            validate_record_freshness(&record)?;
            return match record.state.as_str() {
                "committed" if record.binding_digest == binding.binding_digest => {
                    remove_pending_record(root, &binding.key_digest)?;
                    let receipt = record.receipt.ok_or(McpAccessLedgerError::Corrupt)?;
                    validate_receipt_request_binding(&receipt, binding, expectation)?;
                    Ok(McpAccessLedgerBegin::Replayed(
                        serde_json::to_value(receipt).map_err(|_| McpAccessLedgerError::Corrupt)?,
                    ))
                }
                "pending" if record.binding_digest == binding.binding_digest => {
                    Err(McpAccessLedgerError::Unknown)
                }
                "committed" | "pending" => Err(McpAccessLedgerError::Collision),
                _ => Err(McpAccessLedgerError::Corrupt),
            };
        }

        if scan_mcp_access_records(root, self.expected_owner)? >= MCP_ACCESS_LEDGER_MAX_RECORDS {
            return Err(McpAccessLedgerError::Unavailable);
        }
        let now = now_unix_ms()?;
        let record = McpAccessLedgerRecord {
            schema: MCP_ACCESS_LEDGER_SCHEMA.to_owned(),
            key_digest: binding.key_digest.clone(),
            binding_digest: binding.binding_digest.clone(),
            state: "pending".to_owned(),
            created_at_ms: now,
            expires_at_ms: now
                .checked_add(MCP_ACCESS_LEDGER_RETENTION_MS)
                .ok_or(McpAccessLedgerError::Unavailable)?,
            receipt: None,
        };
        write_mcp_access_record(root, &pending_name, &record, self.expected_owner)?;
        rustix::fs::fsync(root).map_err(|_| McpAccessLedgerError::Unavailable)?;
        Ok(McpAccessLedgerBegin::Claimed)
    }

    #[cfg(target_os = "linux")]
    pub fn commit(
        &mut self,
        binding: &McpAccessLedgerBinding,
        receipt: &Value,
    ) -> Result<(), McpAccessLedgerError> {
        self.commit_for_request(binding, receipt, None)
    }

    #[cfg(target_os = "linux")]
    pub fn commit_for_request(
        &mut self,
        binding: &McpAccessLedgerBinding,
        receipt: &Value,
        expectation: Option<&McpAccessReceiptExpectation>,
    ) -> Result<(), McpAccessLedgerError> {
        use rustix::fs::{
            AtFlags, FlockOperation, RenameFlags, flock, fsync, renameat_with, unlinkat,
        };
        use rustix::io::Errno;

        let receipt = validate_mcp_access_receipt(receipt)?;
        validate_request_expectation(binding, expectation)?;
        validate_receipt_request_binding(&receipt, binding, expectation)?;
        let root = self.open_verified_root()?;
        flock(&root, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| McpAccessLedgerError::Unavailable)?;
        reap_expired_committed_records(&root, self.expected_owner)?;
        let pending = pending_name(&binding.key_digest)?;
        let pending_record = read_mcp_access_record(&root, &pending, self.expected_owner)?
            .ok_or(McpAccessLedgerError::Unknown)?;
        if pending_record.state != "pending"
            || pending_record.key_digest != binding.key_digest
            || pending_record.binding_digest != binding.binding_digest
        {
            let _ = flock(&root, FlockOperation::NonBlockingUnlock);
            return Err(McpAccessLedgerError::Collision);
        }
        validate_record_freshness(&pending_record)?;
        let committed = McpAccessLedgerRecord {
            schema: MCP_ACCESS_LEDGER_SCHEMA.to_owned(),
            key_digest: binding.key_digest.clone(),
            binding_digest: binding.binding_digest.clone(),
            state: "committed".to_owned(),
            created_at_ms: pending_record.created_at_ms,
            expires_at_ms: pending_record.expires_at_ms,
            receipt: Some(receipt),
        };
        if let Some(existing) = read_mcp_access_record(
            &root,
            &record_name(&binding.key_digest)?,
            self.expected_owner,
        )? {
            let matches = existing.state == "committed"
                && existing.binding_digest == binding.binding_digest
                && existing.receipt == committed.receipt;
            if matches {
                remove_pending_record(&root, &binding.key_digest)?;
                fsync(&root).map_err(|_| McpAccessLedgerError::Unavailable)?;
            } else {
                let _ = flock(&root, FlockOperation::NonBlockingUnlock);
                return Err(McpAccessLedgerError::Collision);
            };
            let _ = flock(&root, FlockOperation::NonBlockingUnlock);
            return Ok(());
        }

        let temp_name = format!(
            ".{}.outcome-{}",
            binding.key_digest.trim_start_matches("blake3-256:"),
            Uuid::new_v4()
        );
        write_mcp_access_record(&root, &temp_name, &committed, self.expected_owner)?;
        match renameat_with(
            &root,
            &temp_name,
            &root,
            &record_name(&binding.key_digest)?,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {}
            Err(Errno::EXIST) => {
                cleanup_temporary_record(&root, &temp_name)?;
                let _ = flock(&root, FlockOperation::NonBlockingUnlock);
                return Err(McpAccessLedgerError::Collision);
            }
            Err(_) => {
                cleanup_temporary_record(&root, &temp_name)?;
                let _ = flock(&root, FlockOperation::NonBlockingUnlock);
                return Err(McpAccessLedgerError::Unavailable);
            }
        }
        fsync(&root).map_err(|_| McpAccessLedgerError::Unavailable)?;
        unlinkat(&root, &pending, AtFlags::empty())
            .map_err(|_| McpAccessLedgerError::Unavailable)?;
        fsync(&root).map_err(|_| McpAccessLedgerError::Unavailable)?;
        let _ = flock(&root, FlockOperation::NonBlockingUnlock);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn commit(
        &mut self,
        _binding: &McpAccessLedgerBinding,
        _receipt: &Value,
    ) -> Result<(), McpAccessLedgerError> {
        Err(McpAccessLedgerError::Unavailable)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn commit_for_request(
        &mut self,
        _binding: &McpAccessLedgerBinding,
        _receipt: &Value,
        _expectation: Option<&McpAccessReceiptExpectation>,
    ) -> Result<(), McpAccessLedgerError> {
        Err(McpAccessLedgerError::Unavailable)
    }

    #[cfg(target_os = "linux")]
    pub fn append_receipt(
        &mut self,
        binding: &McpAccessLedgerBinding,
        receipt: &Value,
    ) -> Result<(), McpAccessLedgerError> {
        self.append_receipt_for_request(binding, receipt, None)
    }

    #[cfg(target_os = "linux")]
    pub fn append_receipt_for_request(
        &mut self,
        binding: &McpAccessLedgerBinding,
        receipt: &Value,
        expectation: Option<&McpAccessReceiptExpectation>,
    ) -> Result<(), McpAccessLedgerError> {
        use rustix::fs::{FlockOperation, RenameFlags, flock, fsync, renameat_with};
        use rustix::io::Errno;

        let receipt = validate_mcp_access_receipt(receipt)?;
        validate_request_expectation(binding, expectation)?;
        validate_receipt_request_binding(&receipt, binding, expectation)?;
        let root = self.open_verified_root()?;
        flock(&root, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| McpAccessLedgerError::Unavailable)?;
        reap_expired_committed_records(&root, self.expected_owner)?;
        let final_name = record_name(&binding.key_digest)?;
        if let Some(existing) = read_mcp_access_record(&root, &final_name, self.expected_owner)? {
            let matches = existing.state == "committed"
                && existing.binding_digest == binding.binding_digest
                && existing.receipt == Some(receipt.clone());
            let _ = flock(&root, FlockOperation::NonBlockingUnlock);
            return if matches {
                Ok(())
            } else {
                Err(McpAccessLedgerError::Collision)
            };
        }
        if scan_mcp_access_records(&root, self.expected_owner)? >= MCP_ACCESS_LEDGER_MAX_RECORDS {
            let _ = flock(&root, FlockOperation::NonBlockingUnlock);
            return Err(McpAccessLedgerError::Unavailable);
        }
        let now = now_unix_ms()?;
        let record = McpAccessLedgerRecord {
            schema: MCP_ACCESS_LEDGER_SCHEMA.to_owned(),
            key_digest: binding.key_digest.clone(),
            binding_digest: binding.binding_digest.clone(),
            state: "committed".to_owned(),
            created_at_ms: now,
            expires_at_ms: now
                .checked_add(MCP_ACCESS_LEDGER_RETENTION_MS)
                .ok_or(McpAccessLedgerError::Unavailable)?,
            receipt: Some(receipt),
        };
        let temp_name = format!(
            ".{}.outcome-{}",
            binding.key_digest.trim_start_matches("blake3-256:"),
            Uuid::new_v4()
        );
        write_mcp_access_record(&root, &temp_name, &record, self.expected_owner)?;
        match renameat_with(
            &root,
            &temp_name,
            &root,
            &final_name,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {}
            Err(Errno::EXIST) => {
                cleanup_temporary_record(&root, &temp_name)?;
                let _ = flock(&root, FlockOperation::NonBlockingUnlock);
                return Err(McpAccessLedgerError::Collision);
            }
            Err(_) => {
                cleanup_temporary_record(&root, &temp_name)?;
                let _ = flock(&root, FlockOperation::NonBlockingUnlock);
                return Err(McpAccessLedgerError::Unavailable);
            }
        }
        fsync(&root).map_err(|_| McpAccessLedgerError::Unavailable)?;
        let _ = flock(&root, FlockOperation::NonBlockingUnlock);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn append_receipt(
        &mut self,
        _binding: &McpAccessLedgerBinding,
        _receipt: &Value,
    ) -> Result<(), McpAccessLedgerError> {
        Err(McpAccessLedgerError::Unavailable)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn append_receipt_for_request(
        &mut self,
        _binding: &McpAccessLedgerBinding,
        _receipt: &Value,
        _expectation: Option<&McpAccessReceiptExpectation>,
    ) -> Result<(), McpAccessLedgerError> {
        Err(McpAccessLedgerError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
fn open_verified_root_path(
    path: &std::path::Path,
    expected_owner: u32,
) -> Result<File, McpAccessLedgerError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, open, openat2};

    let relative = path
        .strip_prefix("/")
        .map_err(|_| McpAccessLedgerError::Unavailable)?;
    let filesystem_root = open("/", OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|_| McpAccessLedgerError::Unavailable)?;
    let root = File::from(
        openat2(
            &filesystem_root,
            relative,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| McpAccessLedgerError::Unavailable)?,
    );
    let metadata = root
        .metadata()
        .map_err(|_| McpAccessLedgerError::Unavailable)?;
    verify_private_directory_metadata(&metadata, expected_owner)?;
    Ok(root)
}

#[cfg(unix)]
fn verify_private_directory_metadata(
    metadata: &Metadata,
    expected_owner: u32,
) -> Result<(), McpAccessLedgerError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o7000 != 0
    {
        return Err(McpAccessLedgerError::Unavailable);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn record_name(key_digest: &str) -> Result<String, McpAccessLedgerError> {
    validate_digest(key_digest)?;
    Ok(format!(
        "{}.json",
        key_digest
            .strip_prefix("blake3-256:")
            .ok_or(McpAccessLedgerError::Corrupt)?
    ))
}

#[cfg(target_os = "linux")]
fn pending_name(key_digest: &str) -> Result<String, McpAccessLedgerError> {
    validate_digest(key_digest)?;
    Ok(format!(
        ".{}.pending",
        key_digest
            .strip_prefix("blake3-256:")
            .ok_or(McpAccessLedgerError::Corrupt)?
    ))
}

fn validate_digest(value: &str) -> Result<(), McpAccessLedgerError> {
    let Some(hex) = value.strip_prefix("blake3-256:") else {
        return Err(McpAccessLedgerError::Corrupt);
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(McpAccessLedgerError::Corrupt);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn record_key_digest_from_name(name: &str) -> Result<String, McpAccessLedgerError> {
    let (hex, nonce) = if let Some(hex) = name.strip_suffix(".json") {
        (hex, None)
    } else if let Some(value) = name.strip_prefix('.') {
        if let Some(hex) = value.strip_suffix(".pending") {
            (hex, None)
        } else if let Some((hex, nonce)) = value.split_once(".outcome-") {
            (hex, Some(nonce))
        } else {
            return Err(McpAccessLedgerError::Corrupt);
        }
    } else {
        return Err(McpAccessLedgerError::Corrupt);
    };
    if let Some(nonce) = nonce {
        Uuid::parse_str(nonce).map_err(|_| McpAccessLedgerError::Corrupt)?;
    }
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(McpAccessLedgerError::Corrupt);
    }
    Ok(format!("blake3-256:{hex}"))
}

fn now_unix_ms() -> Result<u64, McpAccessLedgerError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| McpAccessLedgerError::Unavailable)
        .and_then(|duration| {
            u64::try_from(duration.as_millis()).map_err(|_| McpAccessLedgerError::Unavailable)
        })
}

#[cfg(target_os = "linux")]
fn current_effective_uid() -> Result<u32, McpAccessLedgerError> {
    u32::try_from(rustix::process::geteuid().as_raw())
        .map_err(|_| McpAccessLedgerError::Unavailable)
}

fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(key, _)| *key);
            let mut canonical = serde_json::Map::new();
            for (key, child) in entries {
                canonical.insert(key.clone(), canonical_json(child));
            }
            Value::Object(canonical)
        }
        Value::Array(array) => Value::Array(array.iter().map(canonical_json).collect()),
        scalar => scalar.clone(),
    }
}

fn digest_json(domain: &[u8], value: &Value) -> Result<String, McpAccessLedgerError> {
    let bytes =
        serde_json::to_vec(&canonical_json(value)).map_err(|_| McpAccessLedgerError::Corrupt)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(&bytes);
    Ok(format!("blake3-256:{}", hasher.finalize().to_hex()))
}

pub fn derive_mcp_access_binding(
    operation: &str,
    server_id: &str,
    input: &Value,
) -> Result<Option<McpAccessLedgerBinding>, McpAccessLedgerError> {
    if operation != MCP_ACCESS_RECEIPT_OPERATION {
        return Ok(None);
    }
    let idempotency_key = input
        .get("guard")
        .and_then(Value::as_object)
        .and_then(|guard| guard.get("idempotencyKey"))
        .and_then(Value::as_str);
    let key_digest = match idempotency_key {
        Some(idempotency_key) if !idempotency_key.is_empty() && idempotency_key.len() <= 256 => {
            digest_json(
                MCP_ACCESS_IDEMPOTENCY_KEY_DOMAIN,
                &json!({"idempotencyKey": idempotency_key}),
            )?
        }
        Some(_) => return Err(McpAccessLedgerError::Corrupt),
        None => digest_json(
            MCP_ACCESS_IDEMPOTENCY_KEY_DOMAIN,
            &json!({
                "operation": operation,
                "serverId": server_id,
                "input": input,
            }),
        )?,
    };
    let binding_digest = digest_json(
        MCP_ACCESS_BINDING_DOMAIN,
        &json!({
            "operation": operation,
            "serverId": server_id,
            "input": input,
        }),
    )?;
    Ok(Some(McpAccessLedgerBinding {
        key_digest,
        binding_digest,
    }))
}

/// Derive the receipt fields that are fixed by the normalized host request.
/// Apply receipts must echo the dry-run/approval/idempotency binding exactly;
/// dry-run receipts are explicitly unguarded and must remain `planned`.
pub fn derive_mcp_access_receipt_expectation(
    server_id: &str,
    input: &Value,
) -> Result<McpAccessReceiptExpectation, McpAccessLedgerError> {
    let binding = derive_mcp_access_binding(MCP_ACCESS_RECEIPT_OPERATION, server_id, input)?
        .ok_or(McpAccessLedgerError::Corrupt)?;
    let object = input.as_object().ok_or(McpAccessLedgerError::Corrupt)?;
    let scope = object
        .get("scope")
        .and_then(Value::as_str)
        .ok_or(McpAccessLedgerError::Corrupt)?;
    if !matches!(scope, "workflow_ids" | "project" | "folder" | "all_current") {
        return Err(McpAccessLedgerError::Corrupt);
    }
    let desired = object
        .get("desired")
        .and_then(Value::as_bool)
        .ok_or(McpAccessLedgerError::Corrupt)?;
    let dry_run = object
        .get("dryRun")
        .and_then(Value::as_bool)
        .ok_or(McpAccessLedgerError::Corrupt)?;
    let guard = object.get("guard").and_then(Value::as_object);
    let (plan_digest, approval_digest, idempotency_digest) = if dry_run {
        if guard.is_some() {
            return Err(McpAccessLedgerError::RequestMismatch);
        }
        (None, None, None)
    } else {
        let guard = guard.ok_or(McpAccessLedgerError::RequestMismatch)?;
        let approval_ref = guard
            .get("approvalRef")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 256 && value.trim() == *value)
            .ok_or(McpAccessLedgerError::RequestMismatch)?;
        let dry_run_digest = guard
            .get("dryRunDigest")
            .and_then(Value::as_str)
            .ok_or(McpAccessLedgerError::RequestMismatch)?;
        validate_digest(dry_run_digest)?;
        let idempotency_key = guard
            .get("idempotencyKey")
            .and_then(Value::as_str)
            .filter(|value| uuid::Uuid::parse_str(value).is_ok())
            .ok_or(McpAccessLedgerError::RequestMismatch)?;
        let approval_digest = digest_json(
            MCP_ACCESS_RECEIPT_BINDING_DOMAIN,
            &json!({
                "kind": "approval",
                "serverId": server_id,
                "value": approval_ref,
            }),
        )?;
        let idempotency_digest = digest_json(
            MCP_ACCESS_RECEIPT_BINDING_DOMAIN,
            &json!({
                "kind": "idempotency",
                "serverId": server_id,
                "value": idempotency_key,
            }),
        )?;
        (
            Some(dry_run_digest.to_owned()),
            Some(approval_digest),
            Some(idempotency_digest),
        )
    };
    Ok(McpAccessReceiptExpectation {
        binding_digest: binding.binding_digest,
        server_id: server_id.to_owned(),
        scope: scope.to_owned(),
        desired,
        dry_run,
        plan_digest,
        approval_digest,
        idempotency_digest,
    })
}

fn validate_request_expectation(
    binding: &McpAccessLedgerBinding,
    expectation: Option<&McpAccessReceiptExpectation>,
) -> Result<(), McpAccessLedgerError> {
    if let Some(expectation) = expectation {
        validate_digest(&expectation.binding_digest)?;
        if expectation.binding_digest != binding.binding_digest {
            return Err(McpAccessLedgerError::RequestMismatch);
        }
        if !matches!(expectation.server_id.as_str(), "eec" | "hetzner")
            || !matches!(
                expectation.scope.as_str(),
                "workflow_ids" | "project" | "folder" | "all_current"
            )
            || expectation
                .plan_digest
                .as_deref()
                .is_some_and(|digest| validate_digest(digest).is_err())
            || expectation
                .approval_digest
                .as_deref()
                .is_some_and(|digest| validate_digest(digest).is_err())
            || expectation
                .idempotency_digest
                .as_deref()
                .is_some_and(|digest| validate_digest(digest).is_err())
        {
            return Err(McpAccessLedgerError::RequestMismatch);
        }
        if expectation.dry_run
            && (expectation.plan_digest.is_some()
                || expectation.approval_digest.is_some()
                || expectation.idempotency_digest.is_some())
        {
            return Err(McpAccessLedgerError::RequestMismatch);
        }
        if !expectation.dry_run
            && (expectation.plan_digest.is_none()
                || expectation.approval_digest.is_none()
                || expectation.idempotency_digest.is_none())
        {
            return Err(McpAccessLedgerError::RequestMismatch);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_mcp_access_receipt(
    value: &Value,
) -> Result<McpAccessLedgerReceipt, McpAccessLedgerError> {
    use std::collections::BTreeSet;

    let receipt: McpAccessLedgerReceipt =
        serde_json::from_value(value.clone()).map_err(|_| McpAccessLedgerError::Corrupt)?;
    if receipt.schema != MCP_ACCESS_RECEIPT_SCHEMA
        || receipt.operation != MCP_ACCESS_RECEIPT_OPERATION
        || !matches!(receipt.server_id.as_str(), "eec" | "hetzner")
        || receipt.server_id.len() > MCP_ACCESS_RECEIPT_MAX_SERVER_ID_LENGTH
        || receipt.scope.len() > MCP_ACCESS_RECEIPT_MAX_SCOPE_LENGTH
        || !matches!(
            receipt.scope.as_str(),
            "workflow_ids" | "project" | "folder" | "all_current"
        )
        || receipt.items.len() > MCP_ACCESS_RECEIPT_MAX_ITEMS
        || receipt.plan_digest.len() > MCP_ACCESS_RECEIPT_MAX_DIGEST_LENGTH
        || receipt.readback_digest.len() > MCP_ACCESS_RECEIPT_MAX_DIGEST_LENGTH
        || receipt.receipt_digest.len() > MCP_ACCESS_RECEIPT_MAX_DIGEST_LENGTH
        || !validate_digest(&receipt.plan_digest).is_ok()
        || !validate_digest(&receipt.readback_digest).is_ok()
        || !validate_digest(&receipt.receipt_digest).is_ok()
        || receipt.approval_digest.as_deref().is_some_and(|digest| {
            digest.len() > MCP_ACCESS_RECEIPT_MAX_DIGEST_LENGTH || validate_digest(digest).is_err()
        })
        || receipt.idempotency_digest.as_deref().is_some_and(|digest| {
            digest.len() > MCP_ACCESS_RECEIPT_MAX_DIGEST_LENGTH || validate_digest(digest).is_err()
        })
    {
        return Err(McpAccessLedgerError::Corrupt);
    }
    let mut resource_digests = BTreeSet::new();
    let mut has_exception = false;
    let mut has_unknown_outcome = false;
    for item in &receipt.items {
        if validate_digest(&item.resource_digest).is_err()
            || item.resource_digest.len() > MCP_ACCESS_RECEIPT_MAX_DIGEST_LENGTH
            || !resource_digests.insert(&item.resource_digest)
            || item.outcome.is_empty()
            || item.outcome.len() > MCP_ACCESS_RECEIPT_MAX_OUTCOME_LENGTH
            || !validate_receipt_outcome(&item.outcome, receipt.dry_run)
        {
            return Err(McpAccessLedgerError::Corrupt);
        }
        if item.outcome.starts_with("exception:") {
            has_exception = true;
            has_unknown_outcome |= matches!(
                item.outcome.as_str(),
                "exception:provider_unknown_outcome" | "exception:readback_unknown"
            );
        }
    }
    match receipt.status.as_str() {
        "planned" if !receipt.dry_run || has_unknown_outcome => {
            return Err(McpAccessLedgerError::Corrupt);
        }
        "planned" if receipt.approval_digest.is_some() || receipt.idempotency_digest.is_some() => {
            return Err(McpAccessLedgerError::Corrupt);
        }
        "applied" if receipt.dry_run || has_exception => {
            return Err(McpAccessLedgerError::Corrupt);
        }
        "partial" if receipt.dry_run || !has_exception || has_unknown_outcome => {
            return Err(McpAccessLedgerError::Corrupt);
        }
        "unknown" if receipt.dry_run || !has_unknown_outcome => {
            return Err(McpAccessLedgerError::Corrupt);
        }
        "applied" | "partial" | "unknown"
            if receipt.approval_digest.is_none() || receipt.idempotency_digest.is_none() =>
        {
            return Err(McpAccessLedgerError::Corrupt);
        }
        "planned" | "applied" | "partial" | "unknown" => {}
        _ => return Err(McpAccessLedgerError::Corrupt),
    }
    let mut digest_value =
        serde_json::to_value(&receipt).map_err(|_| McpAccessLedgerError::Corrupt)?;
    digest_value["receiptDigest"] = Value::Null;
    let expected_digest = digest_json(MCP_ACCESS_RECEIPT_DIGEST_DOMAIN, &digest_value)?;
    if expected_digest != receipt.receipt_digest {
        return Err(McpAccessLedgerError::Corrupt);
    }
    if serde_json::to_vec(&receipt)
        .map_err(|_| McpAccessLedgerError::Corrupt)?
        .len()
        > MCP_ACCESS_RECEIPT_MAX_BYTES
    {
        return Err(McpAccessLedgerError::Corrupt);
    }
    Ok(receipt)
}

#[cfg(target_os = "linux")]
fn validate_receipt_outcome(outcome: &str, dry_run: bool) -> bool {
    const PLANNED: &[&str] = &["requires_change"];
    const SKIPPED: &[&str] = &["archived", "already_desired", "already_desired_on_recheck"];
    const CHANGED: &[&str] = &["updated_and_verified"];
    const EXCEPTIONS: &[&str] = &[
        "archive_state_unknown",
        "availability_state_unknown",
        "not_found",
        "lock_conflict",
        "id_mismatch",
        "lifecycle_changed",
        "state_changed_since_dry_run",
        "provider_unknown_outcome",
        "readback_unknown",
        "readback_malformed",
        "readback_mismatch",
        "readback_lifecycle_or_graph_mismatch",
        "provider_unauthorized",
        "provider_forbidden",
        "provider_not_found",
        "provider_rate_limited",
        "provider_error",
        "provider_malformed",
    ];
    let Some((kind, reason)) = outcome.split_once(':') else {
        return false;
    };
    match kind {
        "planned" => dry_run && PLANNED.contains(&reason),
        "skipped" => SKIPPED.contains(&reason),
        "changed" => !dry_run && CHANGED.contains(&reason),
        "exception" => EXCEPTIONS.contains(&reason),
        _ => false,
    }
}

fn validate_receipt_request_binding(
    receipt: &McpAccessLedgerReceipt,
    binding: &McpAccessLedgerBinding,
    expectation: Option<&McpAccessReceiptExpectation>,
) -> Result<(), McpAccessLedgerError> {
    let Some(expectation) = expectation else {
        return Ok(());
    };
    validate_request_expectation(binding, Some(expectation))?;
    if receipt.server_id != expectation.server_id
        || receipt.scope != expectation.scope
        || receipt.desired != expectation.desired
        || receipt.dry_run != expectation.dry_run
        || receipt.approval_digest != expectation.approval_digest
        || receipt.idempotency_digest != expectation.idempotency_digest
    {
        return Err(McpAccessLedgerError::RequestMismatch);
    }
    if let Some(plan_digest) = &expectation.plan_digest {
        if &receipt.plan_digest != plan_digest {
            return Err(McpAccessLedgerError::RequestMismatch);
        }
    } else if receipt.plan_digest != receipt.readback_digest {
        return Err(McpAccessLedgerError::RequestMismatch);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_record_freshness(record: &McpAccessLedgerRecord) -> Result<(), McpAccessLedgerError> {
    if record.schema != MCP_ACCESS_LEDGER_SCHEMA
        || !matches!(record.state.as_str(), "pending" | "committed")
        || record.state == "committed" && record.receipt.is_none()
        || record.state == "pending" && record.receipt.is_some()
        || record.expires_at_ms < record.created_at_ms
        || record.expires_at_ms.saturating_sub(record.created_at_ms)
            != MCP_ACCESS_LEDGER_RETENTION_MS
    {
        return Err(McpAccessLedgerError::Corrupt);
    }
    validate_digest(&record.key_digest)?;
    validate_digest(&record.binding_digest)?;
    if let Some(receipt) = &record.receipt {
        let value = serde_json::to_value(receipt).map_err(|_| McpAccessLedgerError::Corrupt)?;
        validate_mcp_access_receipt(&value)?;
    }
    if record.expires_at_ms < now_unix_ms()? {
        return Err(if record.state == "pending" {
            McpAccessLedgerError::Unknown
        } else {
            McpAccessLedgerError::Expired
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_mcp_access_record(
    root: &File,
    name: &str,
    expected_owner: u32,
) -> Result<Option<McpAccessLedgerRecord>, McpAccessLedgerError> {
    use rustix::fs::{Mode, OFlags, openat};
    use rustix::io::Errno;

    let fd = match openat(
        root,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(_) => return Err(McpAccessLedgerError::Corrupt),
    };
    let mut file = File::from(fd);
    let metadata = file.metadata().map_err(|_| McpAccessLedgerError::Corrupt)?;
    verify_mcp_record_metadata(&metadata, expected_owner)?;
    if metadata.len() > MCP_ACCESS_LEDGER_MAX_RECORD_BYTES {
        return Err(McpAccessLedgerError::Corrupt);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(MCP_ACCESS_LEDGER_MAX_RECORD_BYTES)
            .map_err(|_| McpAccessLedgerError::Corrupt)?,
    );
    (&mut file)
        .take(MCP_ACCESS_LEDGER_MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| McpAccessLedgerError::Corrupt)?;
    if bytes.len() as u64 > MCP_ACCESS_LEDGER_MAX_RECORD_BYTES {
        return Err(McpAccessLedgerError::Corrupt);
    }
    let final_metadata = file.metadata().map_err(|_| McpAccessLedgerError::Corrupt)?;
    verify_mcp_record_metadata(&final_metadata, expected_owner)?;
    if final_metadata.len() != bytes.len() as u64 {
        return Err(McpAccessLedgerError::Corrupt);
    }
    let record: McpAccessLedgerRecord =
        serde_json::from_slice(&bytes).map_err(|_| McpAccessLedgerError::Corrupt)?;
    if record.key_digest != record_key_digest_from_name(name)? {
        return Err(McpAccessLedgerError::Corrupt);
    }
    validate_record_freshness(&record)?;
    Ok(Some(record))
}

#[cfg(target_os = "linux")]
fn write_mcp_access_record(
    root: &File,
    name: &str,
    record: &McpAccessLedgerRecord,
    expected_owner: u32,
) -> Result<(), McpAccessLedgerError> {
    use rustix::fs::{Mode, OFlags, openat};

    let mut bytes = serde_json::to_vec(record).map_err(|_| McpAccessLedgerError::Corrupt)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MCP_ACCESS_LEDGER_MAX_RECORD_BYTES {
        return Err(McpAccessLedgerError::Unavailable);
    }
    let fd = openat(
        root,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| McpAccessLedgerError::Unavailable)?;
    let mut file = File::from(fd);
    if file
        .write_all(&bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        drop(file);
        let _ = cleanup_temporary_record(root, name);
        return Err(McpAccessLedgerError::Unavailable);
    }
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => {
            drop(file);
            let _ = cleanup_temporary_record(root, name);
            return Err(McpAccessLedgerError::Unavailable);
        }
    };
    if let Err(error) = verify_mcp_record_metadata(&metadata, expected_owner) {
        drop(file);
        let _ = cleanup_temporary_record(root, name);
        return Err(error);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_temporary_record(root: &File, name: &str) -> Result<(), McpAccessLedgerError> {
    use rustix::fs::{AtFlags, fsync, unlinkat};
    unlinkat(root, name, AtFlags::empty()).map_err(|_| McpAccessLedgerError::Unavailable)?;
    fsync(root).map_err(|_| McpAccessLedgerError::Unavailable)
}

#[cfg(target_os = "linux")]
fn scan_mcp_access_records(
    root: &File,
    expected_owner: u32,
) -> Result<usize, McpAccessLedgerError> {
    use rustix::fs::Dir;

    let mut directory = Dir::read_from(root).map_err(|_| McpAccessLedgerError::Corrupt)?;
    let mut count = 0_usize;
    while let Some(entry) = directory.next() {
        let entry = entry.map_err(|_| McpAccessLedgerError::Corrupt)?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| McpAccessLedgerError::Corrupt)?;
        if name == "." || name == ".." {
            continue;
        }
        let _ = record_key_digest_from_name(name)?;
        count = count
            .checked_add(1)
            .ok_or(McpAccessLedgerError::Unavailable)?;
        if count > MCP_ACCESS_LEDGER_MAX_RECORDS {
            return Err(McpAccessLedgerError::Unavailable);
        }
        let _ = read_mcp_access_record(root, name, expected_owner)?;
    }
    Ok(count)
}

#[cfg(target_os = "linux")]
fn reap_expired_committed_records(
    root: &File,
    expected_owner: u32,
) -> Result<(), McpAccessLedgerError> {
    use rustix::fs::{AtFlags, Dir, unlinkat};

    let mut directory = Dir::read_from(root).map_err(|_| McpAccessLedgerError::Corrupt)?;
    let mut expired = Vec::new();
    let mut count = 0_usize;
    while let Some(entry) = directory.next() {
        let entry = entry.map_err(|_| McpAccessLedgerError::Corrupt)?;
        count = count
            .checked_add(1)
            .ok_or(McpAccessLedgerError::Unavailable)?;
        if count > MCP_ACCESS_LEDGER_MAX_RECORDS {
            return Err(McpAccessLedgerError::Unavailable);
        }
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| McpAccessLedgerError::Corrupt)?;
        if name == "." || name == ".." {
            continue;
        }
        let _ = record_key_digest_from_name(name)?;
        match read_mcp_access_record(root, name, expected_owner) {
            Ok(Some(_)) => {}
            Ok(None) => return Err(McpAccessLedgerError::Corrupt),
            Err(McpAccessLedgerError::Expired)
                if name.ends_with(".json") || name.contains(".outcome-") =>
            {
                expired.push(name.to_owned());
            }
            Err(McpAccessLedgerError::Expired) => {
                return Err(McpAccessLedgerError::Corrupt);
            }
            Err(McpAccessLedgerError::Unknown) => {}
            Err(error) => return Err(error),
        }
    }
    let had_expired = !expired.is_empty();
    for name in expired {
        unlinkat(root, &name, AtFlags::empty()).map_err(|_| McpAccessLedgerError::Unavailable)?;
    }
    if had_expired {
        rustix::fs::fsync(root).map_err(|_| McpAccessLedgerError::Unavailable)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_pending_record(root: &File, key_digest: &str) -> Result<(), McpAccessLedgerError> {
    use rustix::fs::{AtFlags, unlinkat};
    use rustix::io::Errno;

    match unlinkat(root, &pending_name(key_digest)?, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(_) => Err(McpAccessLedgerError::Unavailable),
    }
}

#[cfg(unix)]
fn verify_mcp_record_metadata(
    metadata: &Metadata,
    expected_owner: u32,
) -> Result<(), McpAccessLedgerError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_file()
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o7000 != 0
        || metadata.nlink() != 1
    {
        return Err(McpAccessLedgerError::Corrupt);
    }
    Ok(())
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

    fn mcp_binding(seed: &str) -> McpAccessLedgerBinding {
        McpAccessLedgerBinding {
            key_digest: digest_json(
                MCP_ACCESS_IDEMPOTENCY_KEY_DOMAIN,
                &json!({"idempotencyKey": seed}),
            )
            .expect("key digest"),
            binding_digest: digest_json(MCP_ACCESS_BINDING_DOMAIN, &json!({"binding": seed}))
                .expect("binding digest"),
        }
    }

    fn mcp_receipt(marker: &str) -> Value {
        let status = if matches!(
            marker,
            "exception:provider_unknown_outcome" | "exception:readback_unknown"
        ) {
            "unknown"
        } else if marker.starts_with("exception:") {
            "partial"
        } else {
            "applied"
        };
        let mut receipt = json!({
            "schema": MCP_ACCESS_RECEIPT_SCHEMA,
            "operation": MCP_ACCESS_RECEIPT_OPERATION,
            "serverId": "eec",
            "scope": "workflow_ids",
            "desired": true,
            "dryRun": false,
            "status": status,
            "planDigest": REVIEW_DIGEST,
            "readbackDigest": REVIEW_DIGEST,
            "approvalDigest": REVIEW_DIGEST,
            "idempotencyDigest": REVIEW_DIGEST,
            "items": [{
                "resourceDigest": REVIEW_DIGEST,
                "availableInMCP": true,
                "desired": true,
                "outcome": marker,
            }],
            "receiptDigest": Value::Null,
        });
        let digest_value = receipt.clone();
        receipt["receiptDigest"] = Value::String(
            digest_json(MCP_ACCESS_RECEIPT_DIGEST_DOMAIN, &digest_value).expect("receipt digest"),
        );
        receipt
    }

    #[test]
    fn mcp_access_ledger_claim_commit_replay_and_collision_are_atomic() {
        let root = ledger_root();
        let owner = fs::metadata(root.path()).expect("metadata").uid();
        let mut ledger = McpAccessReconciliationLedger::for_test(root.path().to_path_buf(), owner)
            .expect("ledger");
        let binding = mcp_binding("00000000-0000-4000-8000-000000000101");
        let receipt = mcp_receipt("changed:updated_and_verified");

        assert_eq!(
            ledger.begin(&binding).expect("claim"),
            McpAccessLedgerBegin::Claimed
        );
        assert!(
            root.path()
                .join(pending_name(&binding.key_digest).unwrap())
                .is_file()
        );
        ledger.commit(&binding, &receipt).expect("atomic commit");
        assert!(
            !root
                .path()
                .join(pending_name(&binding.key_digest).unwrap())
                .exists()
        );
        assert!(
            root.path()
                .join(record_name(&binding.key_digest).unwrap())
                .is_file()
        );

        let replay = ledger.begin(&binding).expect("replay");
        assert_eq!(replay, McpAccessLedgerBegin::Replayed(receipt.clone()));

        let collision = McpAccessLedgerBinding {
            key_digest: binding.key_digest.clone(),
            binding_digest: mcp_binding("different-binding").binding_digest,
        };
        assert_eq!(
            ledger.begin(&collision),
            Err(McpAccessLedgerError::Collision)
        );
    }

    #[test]
    fn mcp_access_ledger_pending_claim_is_unknown_and_not_retried() {
        let root = ledger_root();
        let owner = fs::metadata(root.path()).expect("metadata").uid();
        let mut ledger = McpAccessReconciliationLedger::for_test(root.path().to_path_buf(), owner)
            .expect("ledger");
        let binding = mcp_binding("00000000-0000-4000-8000-000000000102");
        assert_eq!(
            ledger.begin(&binding).expect("claim"),
            McpAccessLedgerBegin::Claimed
        );
        assert_eq!(ledger.begin(&binding), Err(McpAccessLedgerError::Unknown));
    }

    #[test]
    fn mcp_access_ledger_rejects_malformed_tail_and_redacts_receipt() {
        let root = ledger_root();
        let owner = fs::metadata(root.path()).expect("metadata").uid();
        let mut ledger = McpAccessReconciliationLedger::for_test(root.path().to_path_buf(), owner)
            .expect("ledger");
        let binding = mcp_binding("00000000-0000-4000-8000-000000000103");
        let receipt = mcp_receipt("exception:provider_unknown_outcome");
        ledger
            .commit(&binding, &receipt)
            .expect_err("missing claim");
        assert_eq!(
            ledger.begin(&binding).expect("claim"),
            McpAccessLedgerBegin::Claimed
        );
        ledger.commit(&binding, &receipt).expect("commit");
        let encoded =
            fs::read_to_string(root.path().join(record_name(&binding.key_digest).unwrap()))
                .expect("record");
        assert!(!encoded.contains("workflow-id"));
        assert!(!encoded.contains("PRIVATE-NAME"));
        assert!(!encoded.contains("credentials"));

        fs::write(
            root.path().join(record_name(&binding.key_digest).unwrap()),
            b"{truncated",
        )
        .expect("truncate tail");
        assert_eq!(
            ledger.begin(&mcp_binding("00000000-0000-4000-8000-000000000104")),
            Err(McpAccessLedgerError::Corrupt)
        );
    }

    #[test]
    fn mcp_access_ledger_rejects_untrusted_server_id() {
        let mut receipt = mcp_receipt("skipped:already_desired");
        receipt["serverId"] = json!("operator@example.invalid");
        receipt["receiptDigest"] = Value::Null;
        receipt["receiptDigest"] = Value::String(
            digest_json(MCP_ACCESS_RECEIPT_DIGEST_DOMAIN, &receipt).expect("receipt digest"),
        );
        assert_eq!(
            validate_mcp_access_receipt(&receipt),
            Err(McpAccessLedgerError::Corrupt)
        );
    }

    #[test]
    fn mcp_access_receipt_is_bound_to_exact_request_fields() {
        let input = json!({
            "scope": "all_current",
            "desired": true,
            "dryRun": false,
            "guard": {
                "approvalRef": "chat-approval-1",
                "dryRunDigest": REVIEW_DIGEST,
                "idempotencyKey": "00000000-0000-4000-8000-000000000107"
            }
        });
        let binding = derive_mcp_access_binding(MCP_ACCESS_RECEIPT_OPERATION, "eec", &input)
            .expect("binding result")
            .expect("binding");
        let expectation =
            derive_mcp_access_receipt_expectation("eec", &input).expect("request expectation");
        let mut receipt = validate_mcp_access_receipt(&mcp_receipt("changed:updated_and_verified"))
            .expect("receipt fixture");
        receipt.plan_digest = REVIEW_DIGEST.into();
        receipt.scope = "all_current".into();
        receipt.approval_digest = expectation.approval_digest.clone();
        receipt.idempotency_digest = expectation.idempotency_digest.clone();
        assert!(validate_receipt_request_binding(&receipt, &binding, Some(&expectation)).is_ok());

        receipt.desired = false;
        assert_eq!(
            validate_receipt_request_binding(&receipt, &binding, Some(&expectation)),
            Err(McpAccessLedgerError::RequestMismatch)
        );
    }

    #[test]
    fn mcp_access_receipt_rejects_duplicate_or_unlisted_outcomes() {
        let mut duplicate = mcp_receipt("skipped:already_desired");
        let item = duplicate["items"][0].clone();
        duplicate["items"] = json!([item.clone(), item]);
        duplicate["receiptDigest"] = Value::Null;
        duplicate["receiptDigest"] = Value::String(
            digest_json(MCP_ACCESS_RECEIPT_DIGEST_DOMAIN, &duplicate).expect("digest"),
        );
        assert_eq!(
            validate_mcp_access_receipt(&duplicate),
            Err(McpAccessLedgerError::Corrupt)
        );

        let mut unlisted = mcp_receipt("skipped:untrusted_provider_reason");
        unlisted["receiptDigest"] = Value::Null;
        unlisted["receiptDigest"] = Value::String(
            digest_json(MCP_ACCESS_RECEIPT_DIGEST_DOMAIN, &unlisted).expect("digest"),
        );
        assert_eq!(
            validate_mcp_access_receipt(&unlisted),
            Err(McpAccessLedgerError::Corrupt)
        );
    }

    #[test]
    fn mcp_access_ledger_binds_record_to_filename_digest() {
        let root = ledger_root();
        let owner = fs::metadata(root.path()).expect("metadata").uid();
        let ledger = McpAccessReconciliationLedger::for_test(root.path().to_path_buf(), owner)
            .expect("ledger");
        let root_fd = ledger.open_verified_root().expect("root fd");
        let binding = mcp_binding("00000000-0000-4000-8000-000000000105");
        let now = now_unix_ms().expect("clock");
        let record = McpAccessLedgerRecord {
            schema: MCP_ACCESS_LEDGER_SCHEMA.to_owned(),
            key_digest: binding.key_digest.clone(),
            binding_digest: binding.binding_digest,
            state: "pending".to_owned(),
            created_at_ms: now,
            expires_at_ms: now + MCP_ACCESS_LEDGER_RETENTION_MS,
            receipt: None,
        };
        write_mcp_access_record(
            &root_fd,
            ".aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.pending",
            &record,
            owner,
        )
        .expect("forged filename fixture");
        drop(root_fd);

        let mut ledger = ledger;
        assert_eq!(
            ledger.begin(&mcp_binding("00000000-0000-4000-8000-000000000106")),
            Err(McpAccessLedgerError::Corrupt)
        );
    }

    #[test]
    fn mcp_access_ledger_enforces_record_bound_and_retention() {
        let root = ledger_root();
        let owner = fs::metadata(root.path()).expect("metadata").uid();
        let ledger = McpAccessReconciliationLedger::for_test(root.path().to_path_buf(), owner)
            .expect("ledger");
        let root_fd = ledger.open_verified_root().expect("root fd");
        let now = now_unix_ms().expect("clock");
        let receipt =
            validate_mcp_access_receipt(&mcp_receipt("skipped:already_desired")).expect("receipt");
        for index in 0..MCP_ACCESS_LEDGER_MAX_RECORDS {
            let binding = mcp_binding(&format!("00000000-0000-4000-8000-{index:012}"));
            let record = McpAccessLedgerRecord {
                schema: MCP_ACCESS_LEDGER_SCHEMA.to_owned(),
                key_digest: binding.key_digest.clone(),
                binding_digest: binding.binding_digest,
                state: "committed".to_owned(),
                created_at_ms: now,
                expires_at_ms: now + MCP_ACCESS_LEDGER_RETENTION_MS,
                receipt: Some(receipt.clone()),
            };
            write_mcp_access_record(
                &root_fd,
                &record_name(&binding.key_digest).unwrap(),
                &record,
                owner,
            )
            .expect("bounded fixture record");
        }
        drop(root_fd);
        let mut ledger = ledger;
        assert_eq!(
            ledger.append_receipt(
                &mcp_binding("00000000-0000-4000-8000-000000009999"),
                &mcp_receipt("changed:updated_and_verified"),
            ),
            Err(McpAccessLedgerError::Unavailable)
        );
    }

    #[test]
    fn mcp_access_ledger_reaps_expired_committed_record() {
        let root = ledger_root();
        let owner = fs::metadata(root.path()).expect("metadata").uid();
        let ledger = McpAccessReconciliationLedger::for_test(root.path().to_path_buf(), owner)
            .expect("ledger");
        let root_fd = ledger.open_verified_root().expect("root fd");
        let binding = mcp_binding("00000000-0000-4000-8000-000000009998");
        let now = now_unix_ms().expect("clock");
        let created_at_ms = now.saturating_sub(MCP_ACCESS_LEDGER_RETENTION_MS + 1);
        let record = McpAccessLedgerRecord {
            schema: MCP_ACCESS_LEDGER_SCHEMA.to_owned(),
            key_digest: binding.key_digest.clone(),
            binding_digest: binding.binding_digest,
            state: "committed".to_owned(),
            created_at_ms,
            expires_at_ms: created_at_ms + MCP_ACCESS_LEDGER_RETENTION_MS,
            receipt: Some(
                validate_mcp_access_receipt(&mcp_receipt("skipped:already_desired"))
                    .expect("receipt"),
            ),
        };
        write_mcp_access_record(
            &root_fd,
            &record_name(&binding.key_digest).expect("record name"),
            &record,
            owner,
        )
        .expect("expired fixture");
        drop(root_fd);

        let mut ledger = ledger;
        let replacement = mcp_binding("00000000-0000-4000-8000-000000009997");
        assert_eq!(
            ledger.begin(&replacement),
            Ok(McpAccessLedgerBegin::Claimed)
        );
        assert!(
            !root
                .path()
                .join(record_name(&binding.key_digest).expect("record name"))
                .exists()
        );
    }

    #[test]
    fn mcp_access_ledger_retains_expired_pending_claim_as_unknown() {
        let root = ledger_root();
        let owner = fs::metadata(root.path()).expect("metadata").uid();
        let ledger = McpAccessReconciliationLedger::for_test(root.path().to_path_buf(), owner)
            .expect("ledger");
        let root_fd = ledger.open_verified_root().expect("root fd");
        let binding = mcp_binding("00000000-0000-4000-8000-000000009996");
        let now = now_unix_ms().expect("clock");
        let created_at_ms = now.saturating_sub(MCP_ACCESS_LEDGER_RETENTION_MS + 1);
        let record = McpAccessLedgerRecord {
            schema: MCP_ACCESS_LEDGER_SCHEMA.to_owned(),
            key_digest: binding.key_digest.clone(),
            binding_digest: binding.binding_digest.clone(),
            state: "pending".to_owned(),
            created_at_ms,
            expires_at_ms: created_at_ms + MCP_ACCESS_LEDGER_RETENTION_MS,
            receipt: None,
        };
        let pending = pending_name(&binding.key_digest).expect("pending name");
        write_mcp_access_record(&root_fd, &pending, &record, owner).expect("pending fixture");
        drop(root_fd);

        let mut ledger = ledger;
        assert_eq!(ledger.begin(&binding), Err(McpAccessLedgerError::Unknown));
        assert!(root.path().join(pending).is_file());
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
