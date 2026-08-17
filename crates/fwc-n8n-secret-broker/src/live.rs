//! Feature-gated fixed-path KeePass backend.
//!
//! This module has no shell, helper, plugin, prompt, or caller-selected path.
//! The binary must obtain a verified Unix peer UID before constructing
//! `LiveBackend`; `new()` intentionally has no peer and therefore fails closed.

use std::fs::File;
use std::io::{BufReader, Cursor, Read};

use age::{Decryptor, IdentityFile, NoCallbacks};
use fcp_n8n_broker_protocol::{ZeroizingSecret, validate_credential_secret};
use keepass::{Database, DatabaseKey, db::fields};

use crate::{
    BrokerCredentialPurpose, BrokerError, BrokerRequest, BrokerServer, CredentialBackend,
    SOCKET_PATH,
};

const AGE_IDENTITY_PATH: &str = "/etc/homelab/secrets/age-keys/keepass-master.key";
const ENCRYPTED_MASTER_PATH: &str = "/etc/homelab/secrets/keepass-master.age";
const KDBX_PATH: &str = "/home/ubuntu/.secrets/keepass/homelab-secrets.kdbx";
const MAX_IDENTITY_BYTES: usize = 1 << 20;
const MAX_ENCRYPTED_BYTES: usize = 8 << 20;
const MAX_PLAINTEXT_BYTES: usize = 1 << 20;
const MAX_KDBX_BYTES: usize = 64 << 20;

/// Fixed service/entry mapping.
const fn service_name(request: BrokerRequest) -> &'static str {
    match (request.server, request.purpose) {
        (BrokerServer::Eec, BrokerCredentialPurpose::RestApi) => "n8n-eec",
        (BrokerServer::Hetzner, BrokerCredentialPurpose::RestApi) => "n8n-hetzner",
        (BrokerServer::Eec, BrokerCredentialPurpose::OfficialMcp) => "n8n-eec-mcp",
        (BrokerServer::Hetzner, BrokerCredentialPurpose::OfficialMcp) => "n8n-hetzner-mcp",
    }
}

/// Live backend state. A missing peer UID is a deliberate fail-closed state.
pub struct LiveBackend {
    peer_uid: Option<u32>,
}

impl LiveBackend {
    /// Construct a backend that cannot read until a verified peer is supplied.
    #[must_use]
    pub const fn new() -> Self {
        Self { peer_uid: None }
    }

    const fn with_peer_uid(peer_uid: u32) -> Self {
        Self {
            peer_uid: Some(peer_uid),
        }
    }

    /// Construct only from a connected Unix socket whose peer is authenticated
    /// by the kernel. Callers cannot substitute an arbitrary UID.
    #[cfg(target_os = "linux")]
    pub fn from_connected_socket(
        socket: &std::os::unix::net::UnixStream,
    ) -> Result<Self, BrokerError> {
        use std::os::fd::AsFd;

        let credentials = rustix::net::sockopt::socket_peercred(socket.as_fd())
            .map_err(|_| BrokerError::new(crate::BrokerErrorCode::SocketRejected))?;
        let peer_uid = credentials.uid.as_raw();
        Ok(Self::with_peer_uid(peer_uid))
    }
}

impl Default for LiveBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialBackend for LiveBackend {
    fn fetch(&mut self, request: BrokerRequest) -> Result<ZeroizingSecret, BrokerError> {
        let peer_uid = self
            .peer_uid
            .ok_or_else(|| BrokerError::new(crate::BrokerErrorCode::SocketRejected))?;
        let master_key = read_fixed_file(AGE_IDENTITY_PATH, MAX_IDENTITY_BYTES, 0)?;
        let encrypted_master = read_fixed_file(ENCRYPTED_MASTER_PATH, MAX_ENCRYPTED_BYTES, 0)?;
        let database = open_fixed_file(KDBX_PATH, MAX_KDBX_BYTES, peer_uid)?;
        let master = decrypt_master(master_key, encrypted_master)?;
        let mut limited_database = database.take((MAX_KDBX_BYTES as u64) + 1);
        let db = master
            .with_bytes(|bytes| {
                let password = std::str::from_utf8(bytes).map_err(|_| ())?;
                Database::open(
                    &mut limited_database,
                    DatabaseKey::new().with_password(password),
                )
                .map_err(|_| ())
            })
            .map_err(|_| BrokerError::new(crate::BrokerErrorCode::BackendFailed))?;
        let secret = find_password(&db, service_name(request))?;
        drop(db);
        validate_credential_secret(&secret)
            .map_err(|_| BrokerError::new(crate::BrokerErrorCode::InvalidSecret))?;
        Ok(secret)
    }
}

fn find_password(database: &Database, service: &str) -> Result<ZeroizingSecret, BrokerError> {
    let root = database.root();
    let services: Vec<_> = root
        .groups()
        .filter(|group| group.name == "services")
        .collect();
    if services.len() != 1 {
        return Err(BrokerError::new(crate::BrokerErrorCode::BackendFailed));
    }
    let entries: Vec<_> = services[0]
        .entries()
        .filter(|entry| entry.get_title() == Some(service))
        .collect();
    if entries.len() != 1 {
        return Err(BrokerError::new(crate::BrokerErrorCode::BackendFailed));
    }
    let field = entries[0]
        .fields
        .get(fields::PASSWORD)
        .ok_or_else(|| BrokerError::new(crate::BrokerErrorCode::BackendFailed))?;
    if !field.is_protected() {
        return Err(BrokerError::new(crate::BrokerErrorCode::BackendFailed));
    }
    Ok(ZeroizingSecret::with_zeroize_drop(
        field.get().as_bytes().to_vec(),
    ))
}

fn read_fixed_file(
    path: &str,
    max_bytes: usize,
    expected_uid: u32,
) -> Result<ZeroizingSecret, BrokerError> {
    let file = open_fixed_file(path, max_bytes, expected_uid)?;
    let mut bytes = Vec::new();
    let read_result = file.take((max_bytes as u64) + 1).read_to_end(&mut bytes);
    let bytes = ZeroizingSecret::with_zeroize_drop(bytes);
    read_result.map_err(|_| BrokerError::new(crate::BrokerErrorCode::BackendFailed))?;
    if bytes.len() > max_bytes {
        return Err(BrokerError::new(crate::BrokerErrorCode::BackendFailed));
    }
    Ok(bytes)
}

fn decrypt_master(
    identity_bytes: ZeroizingSecret,
    encrypted_bytes: ZeroizingSecret,
) -> Result<ZeroizingSecret, BrokerError> {
    let identity_file: IdentityFile<NoCallbacks> = identity_bytes
        .with_bytes(|bytes| IdentityFile::from_buffer(BufReader::new(Cursor::new(bytes))))
        .map_err(|_| BrokerError::new(crate::BrokerErrorCode::BackendFailed))?;
    let identities = identity_file
        .into_identities()
        .map_err(|_| BrokerError::new(crate::BrokerErrorCode::BackendFailed))?;
    if identities.len() != 1 {
        return Err(BrokerError::new(crate::BrokerErrorCode::BackendFailed));
    }
    encrypted_bytes.with_bytes(|ciphertext| {
        let decryptor = Decryptor::new(ciphertext)
            .map_err(|_| BrokerError::new(crate::BrokerErrorCode::BackendFailed))?;
        let identity_refs = identities
            .iter()
            .map(|identity| identity.as_ref() as &dyn age::Identity);
        let reader = decryptor
            .decrypt(identity_refs)
            .map_err(|_| BrokerError::new(crate::BrokerErrorCode::BackendFailed))?;
        let mut plaintext = Vec::new();
        let read_result = reader
            .take((MAX_PLAINTEXT_BYTES as u64) + 1)
            .read_to_end(&mut plaintext);
        let mut plaintext = ZeroizingSecret::with_zeroize_drop(plaintext);
        read_result.map_err(|_| BrokerError::new(crate::BrokerErrorCode::BackendFailed))?;
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(BrokerError::new(crate::BrokerErrorCode::BackendFailed));
        }
        let trimmed = plaintext.with_bytes(|bytes| {
            if bytes.ends_with(b"\r\n") {
                bytes[..bytes.len() - 2].to_vec()
            } else if bytes.ends_with(b"\n") {
                bytes[..bytes.len() - 1].to_vec()
            } else {
                bytes.to_vec()
            }
        });
        plaintext = ZeroizingSecret::with_zeroize_drop(trimmed);
        Ok(plaintext)
    })
}

#[cfg(target_os = "linux")]
fn open_fixed_file(path: &str, max_bytes: usize, expected_uid: u32) -> Result<File, BrokerError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, fstat, open, openat2};

    let root = open("/", OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|_| BrokerError::new(crate::BrokerErrorCode::BackendFailed))?;
    let relative = path
        .strip_prefix('/')
        .ok_or_else(|| BrokerError::new(crate::BrokerErrorCode::BackendFailed))?;
    let fd = openat2(
        &root,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| BrokerError::new(crate::BrokerErrorCode::BackendFailed))?;
    let stat = fstat(&fd).map_err(|_| BrokerError::new(crate::BrokerErrorCode::BackendFailed))?;
    let regular = stat.st_mode & 0o170000 == 0o100000;
    if !regular
        || stat.st_nlink != 1
        || stat.st_uid != expected_uid
        || stat.st_mode & 0o777 != 0o600
        || stat.st_size < 0
        || stat.st_size as usize > max_bytes
    {
        return Err(BrokerError::new(crate::BrokerErrorCode::BackendFailed));
    }
    Ok(File::from(fd))
}

#[cfg(not(target_os = "linux"))]
fn open_fixed_file(
    _path: &str,
    _max_bytes: usize,
    _expected_uid: u32,
) -> Result<File, BrokerError> {
    Err(BrokerError::new(crate::BrokerErrorCode::BackendUnavailable))
}

/// Reject inherited descriptors other than stdin/stdout/stderr before file access.
pub fn reject_unexpected_inherited_fds() -> Result<(), BrokerError> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    use rustix::fs::{Mode, OFlags, RawDir, open};

    let directory = open(
        "/proc/self/fd",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BrokerError::new(crate::BrokerErrorCode::SocketRejected))?;
    let enumeration_fd = directory.as_raw_fd() as u32;
    let mut buffer = [MaybeUninit::uninit(); 2048];
    let mut entries = RawDir::new(&directory, &mut buffer);
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|_| BrokerError::new(crate::BrokerErrorCode::SocketRejected))?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let fd = std::str::from_utf8(name)
            .map_err(|_| BrokerError::new(crate::BrokerErrorCode::SocketRejected))?
            .parse::<u32>()
            .map_err(|_| BrokerError::new(crate::BrokerErrorCode::SocketRejected))?;
        if fd > 2 && fd != enumeration_fd {
            return Err(BrokerError::new(crate::BrokerErrorCode::SocketRejected));
        }
    }
    let _ = SOCKET_PATH;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database_with_service(
        service: &str,
        protected_password: Option<bool>,
        matching_entries: usize,
    ) -> Database {
        let mut database = Database::new();
        {
            let mut root = database.root_mut();
            let mut services = root.add_group();
            services.name = "services".into();
            for index in 0..matching_entries {
                let mut entry = services.add_entry();
                entry.set_unprotected(fields::TITLE, service);
                match protected_password {
                    Some(true) => entry.set_protected(fields::PASSWORD, format!("key-{index}")),
                    Some(false) => entry.set_unprotected(fields::PASSWORD, format!("key-{index}")),
                    None => {}
                }
            }
        }
        database
    }

    #[test]
    fn fixed_service_mapping_is_closed() {
        assert_eq!(
            service_name(BrokerRequest {
                server: BrokerServer::Eec,
                purpose: BrokerCredentialPurpose::RestApi,
            }),
            "n8n-eec"
        );
        assert_eq!(
            service_name(BrokerRequest {
                server: BrokerServer::Hetzner,
                purpose: BrokerCredentialPurpose::RestApi,
            }),
            "n8n-hetzner"
        );
        assert_eq!(
            service_name(BrokerRequest {
                server: BrokerServer::Eec,
                purpose: BrokerCredentialPurpose::OfficialMcp,
            }),
            "n8n-eec-mcp"
        );
        assert_eq!(
            service_name(BrokerRequest {
                server: BrokerServer::Hetzner,
                purpose: BrokerCredentialPurpose::OfficialMcp,
            }),
            "n8n-hetzner-mcp"
        );
    }

    #[test]
    fn password_requires_one_exact_entry_and_protected_field() {
        let valid = database_with_service("n8n-eec", Some(true), 1);
        let secret = find_password(&valid, "n8n-eec").expect("protected password");
        assert!(secret.ct_eq_bytes(b"key-0"));

        for database in [
            database_with_service("n8n-eec", None, 1),
            database_with_service("n8n-eec", Some(false), 1),
            database_with_service("n8n-eec", Some(true), 0),
            database_with_service("n8n-eec", Some(true), 2),
        ] {
            assert_eq!(
                find_password(&database, "n8n-eec")
                    .expect_err("ambiguous or unprotected data must fail")
                    .code(),
                "backend_failed"
            );
        }
    }

    #[test]
    fn duplicate_service_groups_fail_closed() {
        let mut database = database_with_service("n8n-eec", Some(true), 1);
        {
            let mut root = database.root_mut();
            let mut second_services = root.add_group();
            second_services.name = "services".into();
        }
        assert_eq!(
            find_password(&database, "n8n-eec")
                .expect_err("duplicate services")
                .code(),
            "backend_failed"
        );
    }

    #[test]
    fn peer_uid_is_derived_from_a_connected_socket() {
        let (server, _client) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        assert!(LiveBackend::from_connected_socket(&server).is_ok());
        assert!(LiveBackend::new().peer_uid.is_none());
    }

    #[test]
    fn plugin_like_identity_material_is_rejected_without_callbacks() {
        let identity =
            ZeroizingSecret::with_zeroize_drop(b"AGE-PLUGIN-IDENTITY-1TEST-UNTRUSTED\n".to_vec());
        let encrypted = ZeroizingSecret::with_zeroize_drop(b"not-an-age-file".to_vec());
        assert_eq!(
            decrypt_master(identity, encrypted)
                .expect_err("plugin-like material must fail closed")
                .code(),
            "backend_failed"
        );
    }
}
