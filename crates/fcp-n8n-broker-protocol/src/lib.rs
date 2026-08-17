//! Fixed, one-shot n8n credential broker protocol.
//!
//! This crate contains only the bounded protocol, synthetic backend seam, and
//! fixed-socket client seam. The live `KeePass` backend is owned by the separate
//! feature-gated broker package.

use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub use fcp_secret::credential_frame;
pub use fcp_secret::{
    CredentialFrameError, ZeroizingSecret, encode as encode_credential_frame,
    parse as parse_credential_frame, validate_secret as validate_credential_secret,
};

/// Fixed broker socket path.
pub const SOCKET_PATH: &str = "/run/fwc/fwc-n8n-secret-broker.sock";
const LEGACY_REQUEST_FRAME_BYTES: usize = 1;
const PURPOSE_BOUND_REQUEST_FRAME_BYTES: usize = 3;
const MAX_REQUEST_BYTES: usize = PURPOSE_BOUND_REQUEST_FRAME_BYTES;
const PURPOSE_BOUND_REQUEST_PREFIX: u8 = 0xf2;
const MAX_RESPONSE_BYTES: usize =
    fcp_secret::credential_frame::HEADER_BYTES + fcp_secret::credential_frame::MAX_SECRET_BYTES;
const MAX_ERROR_BYTES: usize = 64;
const ERROR_MAGIC: &[u8] = b"FCPB/v1/ERR:";

/// Closed server selector; no caller-provided service, field, or path exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerServer {
    /// EEC n8n instance.
    Eec,
    /// Hetzner n8n instance.
    Hetzner,
}

impl BrokerServer {
    const fn wire(self) -> u8 {
        match self {
            Self::Eec => 1,
            Self::Hetzner => 2,
        }
    }

    const fn from_wire(value: u8) -> Result<Self, BrokerError> {
        match value {
            1 => Ok(Self::Eec),
            2 => Ok(Self::Hetzner),
            _ => Err(BrokerError::new(BrokerErrorCode::InvalidRequest)),
        }
    }
}

/// Closed credential purpose. REST API keys and official MCP access tokens are
/// separate credentials and cannot be substituted for one another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerCredentialPurpose {
    /// n8n public REST API key used by `fcp.n8n`.
    RestApi,
    /// Personal official n8n MCP access token used by `fcp.mcp-bridge`.
    OfficialMcp,
}

impl BrokerCredentialPurpose {
    const fn wire(self) -> Option<u8> {
        match self {
            // Preserve the established one-byte REST request so a newly built
            // wrapper remains compatible with the currently installed broker.
            Self::RestApi => None,
            Self::OfficialMcp => Some(1),
        }
    }

    const fn from_wire(value: u8) -> Result<Self, BrokerError> {
        match value {
            1 => Ok(Self::OfficialMcp),
            _ => Err(BrokerError::new(BrokerErrorCode::InvalidRequest)),
        }
    }
}

/// One fixed broker request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrokerRequest {
    /// Selected fixed n8n server.
    pub server: BrokerServer,
    /// Fixed credential purpose for that server.
    pub purpose: BrokerCredentialPurpose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerErrorCode {
    InvalidRequest,
    RequestOversized,
    BackendUnavailable,
    BackendFailed,
    EmptySecret,
    OversizedSecret,
    InvalidSecret,
    ResponseInvalid,
    ResponseOversized,
    DeadlineExceeded,
    Io,
    SocketRejected,
}

impl BrokerErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::RequestOversized => "request_oversized",
            Self::BackendUnavailable => "backend_unavailable",
            Self::BackendFailed => "backend_failed",
            Self::EmptySecret => "empty_secret",
            Self::OversizedSecret => "oversized_secret",
            Self::InvalidSecret => "invalid_secret",
            Self::ResponseInvalid => "response_invalid",
            Self::ResponseOversized => "response_oversized",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Io => "io",
            Self::SocketRejected => "socket_rejected",
        }
    }

    const fn wire(self) -> u8 {
        match self {
            Self::InvalidRequest => 1,
            Self::RequestOversized => 2,
            Self::BackendUnavailable => 3,
            Self::BackendFailed => 4,
            Self::EmptySecret => 5,
            Self::OversizedSecret => 6,
            Self::InvalidSecret => 7,
            Self::ResponseInvalid => 8,
            Self::ResponseOversized => 9,
            Self::DeadlineExceeded => 10,
            Self::Io => 11,
            Self::SocketRejected => 12,
        }
    }

    const fn from_wire(value: u8) -> Result<Self, BrokerError> {
        match value {
            1 => Ok(Self::InvalidRequest),
            2 => Ok(Self::RequestOversized),
            3 => Ok(Self::BackendUnavailable),
            4 => Ok(Self::BackendFailed),
            5 => Ok(Self::EmptySecret),
            6 => Ok(Self::OversizedSecret),
            7 => Ok(Self::InvalidSecret),
            8 => Ok(Self::ResponseInvalid),
            9 => Ok(Self::ResponseOversized),
            10 => Ok(Self::DeadlineExceeded),
            11 => Ok(Self::Io),
            12 => Ok(Self::SocketRejected),
            _ => Err(BrokerError::new(Self::ResponseInvalid)),
        }
    }
}

/// Redacted protocol error; no path, selector, or secret is retained.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BrokerError {
    code: BrokerErrorCode,
}

impl BrokerError {
    /// Construct a redacted broker error from its closed code.
    #[must_use]
    pub const fn new(code: BrokerErrorCode) -> Self {
        Self { code }
    }

    /// Stable redacted error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.code.as_str()
    }

    /// Construct the fixed unavailable-backend error for a fail-closed seam.
    #[must_use]
    pub const fn backend_unavailable() -> Self {
        Self::new(BrokerErrorCode::BackendUnavailable)
    }

    /// Construct the fixed backend-failure error without exposing details.
    #[must_use]
    pub const fn backend_failed() -> Self {
        Self::new(BrokerErrorCode::BackendFailed)
    }
}

impl fmt::Debug for BrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for BrokerError {}

/// Backend seam. A live implementation must use only the closed request.
pub trait CredentialBackend {
    /// Fetch the selected server's fixed API key.
    ///
    /// # Errors
    ///
    /// Returns a redacted broker error when the fixed credential cannot be
    /// fetched or validated.
    fn fetch(&mut self, request: BrokerRequest) -> Result<ZeroizingSecret, BrokerError>;
}

/// Default fail-closed backend used unless the reviewed live feature is enabled.
pub struct UnavailableBackend;

impl CredentialBackend for UnavailableBackend {
    fn fetch(&mut self, _request: BrokerRequest) -> Result<ZeroizingSecret, BrokerError> {
        Err(BrokerError::new(BrokerErrorCode::BackendUnavailable))
    }
}

enum BrokerResponse {
    Credential(ZeroizingSecret),
    Error(BrokerError),
}

/// Encode one closed server-and-purpose request.
///
/// REST keeps its legacy one-byte representation. Official MCP uses a separate
/// versioned three-byte frame (`prefix`, `server`, `purpose`), so a legacy
/// request plus trailing bytes cannot be reinterpreted as a different
/// credential class. Arbitrary service names, fields, or paths remain
/// impossible to express on the wire.
#[must_use]
pub fn encode_request(request: BrokerRequest) -> Vec<u8> {
    request.purpose.wire().map_or_else(
        || vec![request.server.wire()],
        |purpose| vec![PURPOSE_BOUND_REQUEST_PREFIX, request.server.wire(), purpose],
    )
}

fn decode_request(frame: &[u8]) -> Result<BrokerRequest, BrokerError> {
    if frame.len() > MAX_REQUEST_BYTES {
        return Err(BrokerError::new(BrokerErrorCode::RequestOversized));
    }
    let (server, purpose) = match frame.len() {
        LEGACY_REQUEST_FRAME_BYTES => (frame[0], BrokerCredentialPurpose::RestApi),
        PURPOSE_BOUND_REQUEST_FRAME_BYTES if frame[0] == PURPOSE_BOUND_REQUEST_PREFIX => {
            (frame[1], BrokerCredentialPurpose::from_wire(frame[2])?)
        }
        _ => return Err(BrokerError::new(BrokerErrorCode::InvalidRequest)),
    };
    Ok(BrokerRequest {
        server: BrokerServer::from_wire(server)?,
        purpose,
    })
}

const fn map_frame_error(error: CredentialFrameError) -> BrokerError {
    let code = match error {
        CredentialFrameError::Empty => BrokerErrorCode::EmptySecret,
        CredentialFrameError::Oversized => BrokerErrorCode::OversizedSecret,
        CredentialFrameError::InvalidUtf8 | CredentialFrameError::InvalidHeaderValue => {
            BrokerErrorCode::InvalidSecret
        }
        CredentialFrameError::InvalidFrame
        | CredentialFrameError::Truncated
        | CredentialFrameError::TrailingData
        | CredentialFrameError::Io => BrokerErrorCode::ResponseInvalid,
    };
    BrokerError::new(code)
}

fn process_request<B: CredentialBackend>(frame: &[u8], backend: &mut B) -> BrokerResponse {
    let request = match decode_request(frame) {
        Ok(request) => request,
        Err(error) => return BrokerResponse::Error(error),
    };
    match backend.fetch(request) {
        Ok(secret) => match encode_credential_frame(&secret) {
            Ok(frame) => BrokerResponse::Credential(frame),
            Err(error) => BrokerResponse::Error(map_frame_error(error)),
        },
        Err(error) => BrokerResponse::Error(error),
    }
}

fn encode_error(error: BrokerError) -> [u8; ERROR_MAGIC.len() + 1] {
    let mut frame = [0_u8; ERROR_MAGIC.len() + 1];
    frame[..ERROR_MAGIC.len()].copy_from_slice(ERROR_MAGIC);
    frame[ERROR_MAGIC.len()] = error.code.wire();
    frame
}

fn write_response<W: Write>(writer: &mut W, response: BrokerResponse) -> Result<(), BrokerError> {
    match response {
        BrokerResponse::Credential(frame) => frame
            .with_bytes(|bytes| writer.write_all(bytes))
            .map_err(|_| BrokerError::new(BrokerErrorCode::Io)),
        BrokerResponse::Error(error) => writer
            .write_all(&encode_error(error))
            .map_err(|_| BrokerError::new(BrokerErrorCode::Io)),
    }
}

fn read_bounded<R: Read>(reader: &mut R) -> Result<Vec<u8>, BrokerError> {
    let mut input = Vec::new();
    let mut buffer = [0_u8; 32];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| BrokerError::new(BrokerErrorCode::Io))?;
        if count == 0 {
            return Ok(input);
        }
        if input.len().saturating_add(count) > MAX_REQUEST_BYTES {
            return Err(BrokerError::new(BrokerErrorCode::RequestOversized));
        }
        input.extend_from_slice(&buffer[..count]);
    }
}

/// Serve exactly one bounded request and one response, then return.
///
/// # Errors
///
/// Returns a redacted broker error when request framing, credential retrieval,
/// response framing, or transport I/O fails.
pub fn serve_once<R: Read, W: Write, B: CredentialBackend>(
    reader: &mut R,
    writer: &mut W,
    backend: &mut B,
) -> Result<(), BrokerError> {
    let response = match read_bounded(reader) {
        Ok(frame) => process_request(&frame, backend),
        Err(error) => BrokerResponse::Error(error),
    };
    let failure = match &response {
        BrokerResponse::Error(error) => Some(*error),
        BrokerResponse::Credential(_) => None,
    };
    write_response(writer, response)?;
    failure.map_or(Ok(()), Err)
}

/// Transport seam for a fixed-socket client; production wiring supplies the OS transport later.
pub trait BrokerTransport {
    /// Write one request before the supplied absolute deadline.
    ///
    /// # Errors
    ///
    /// Returns a redacted broker error on timeout or transport failure.
    fn write_request(&mut self, frame: &[u8], deadline: Instant) -> Result<(), BrokerError>;
    /// Read one response before the same absolute deadline.
    ///
    /// # Errors
    ///
    /// Returns a redacted broker error on timeout, invalid size, or transport
    /// failure.
    fn read_response(&mut self, deadline: Instant) -> Result<ZeroizingSecret, BrokerError>;
}

/// Fixed-path broker client with no caller-selected service or path.
pub struct BrokerClient {
    socket_path: PathBuf,
}

impl BrokerClient {
    /// Construct the only production socket target.
    #[must_use]
    pub fn fixed() -> Self {
        Self {
            socket_path: PathBuf::from(SOCKET_PATH),
        }
    }

    /// Borrow the fixed socket path for transport setup.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Send and parse one request under one absolute deadline.
    ///
    /// # Errors
    ///
    /// Returns a redacted broker error when the deadline has elapsed, transport
    /// I/O fails, or the broker response is invalid.
    pub fn request<T: BrokerTransport>(
        &self,
        transport: &mut T,
        request: BrokerRequest,
        deadline: Instant,
    ) -> Result<ZeroizingSecret, BrokerError> {
        if Instant::now() >= deadline {
            return Err(BrokerError::new(BrokerErrorCode::DeadlineExceeded));
        }
        transport.write_request(&encode_request(request), deadline)?;
        if Instant::now() >= deadline {
            return Err(BrokerError::new(BrokerErrorCode::DeadlineExceeded));
        }
        parse_response(transport.read_response(deadline)?)
    }

    /// Connect to the fixed Unix socket with the same absolute deadline used
    /// for the request and response.
    ///
    /// # Errors
    ///
    /// Returns a redacted broker error when socket metadata, peer identity,
    /// connection setup, or the deadline check fails.
    #[cfg(unix)]
    pub fn connect(&self, deadline: Instant) -> Result<FixedUnixTransport, BrokerError> {
        FixedUnixTransport::connect(self, deadline)
    }
}

/// Deadline-aware Unix transport for the fixed broker socket.
#[cfg(unix)]
pub struct FixedUnixTransport {
    stream: std::os::unix::net::UnixStream,
}

#[cfg(unix)]
impl FixedUnixTransport {
    #[allow(unreachable_code)]
    fn connect(client: &BrokerClient, deadline: Instant) -> Result<Self, BrokerError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (client, deadline);
            return Err(BrokerError::new(BrokerErrorCode::SocketRejected));
        }
        if Instant::now() >= deadline {
            return Err(BrokerError::new(BrokerErrorCode::DeadlineExceeded));
        }
        validate_socket_metadata(client.socket_path())?;
        let socket = rustix::net::socket_with(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::NONBLOCK | rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|_| BrokerError::new(BrokerErrorCode::Io))?;
        let address = rustix::net::SocketAddrUnix::new(client.socket_path())
            .map_err(|_| BrokerError::new(BrokerErrorCode::SocketRejected))?;
        match rustix::net::connect(&socket, &address) {
            Ok(()) => {}
            Err(error)
                if error == rustix::io::Errno::INPROGRESS
                    || error == rustix::io::Errno::WOULDBLOCK =>
            {
                wait_for_connect(&socket, deadline)?;
            }
            Err(_) => return Err(BrokerError::new(BrokerErrorCode::Io)),
        }
        let stream = std::os::unix::net::UnixStream::from(socket);
        if Instant::now() >= deadline {
            return Err(BrokerError::new(BrokerErrorCode::DeadlineExceeded));
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd;
            let credentials = rustix::net::sockopt::socket_peercred(stream.as_fd())
                .map_err(|_| BrokerError::new(BrokerErrorCode::SocketRejected))?;
            verify_broker_peer_uid(credentials.uid.as_raw())?;
        }
        stream
            .set_nonblocking(true)
            .map_err(|_| BrokerError::new(BrokerErrorCode::Io))?;
        Ok(Self { stream })
    }

    fn wait(deadline: Instant) -> Result<(), BrokerError> {
        if Instant::now() >= deadline {
            return Err(BrokerError::new(BrokerErrorCode::DeadlineExceeded));
        }
        std::thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(std::time::Duration::from_millis(1)),
        );
        if Instant::now() >= deadline {
            Err(BrokerError::new(BrokerErrorCode::DeadlineExceeded))
        } else {
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_for_connect(socket: &rustix::fd::OwnedFd, deadline: Instant) -> Result<(), BrokerError> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(BrokerError::new(BrokerErrorCode::DeadlineExceeded));
        }
        let timeout = rustix::event::Timespec::try_from(remaining)
            .map_err(|_| BrokerError::new(BrokerErrorCode::DeadlineExceeded))?;
        let mut descriptors = [rustix::event::PollFd::new(
            socket,
            rustix::event::PollFlags::OUT,
        )];
        match rustix::event::poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => return Err(BrokerError::new(BrokerErrorCode::DeadlineExceeded)),
            Ok(_) => match rustix::net::sockopt::socket_error(socket) {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(_)) | Err(_) => return Err(BrokerError::new(BrokerErrorCode::Io)),
            },
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(BrokerError::new(BrokerErrorCode::Io)),
        }
    }
}

#[cfg(unix)]
impl BrokerTransport for FixedUnixTransport {
    fn write_request(&mut self, frame: &[u8], deadline: Instant) -> Result<(), BrokerError> {
        use std::io::Write;

        let mut offset = 0;
        while offset < frame.len() {
            if Instant::now() >= deadline {
                return Err(BrokerError::new(BrokerErrorCode::DeadlineExceeded));
            }
            match self.stream.write(&frame[offset..]) {
                Ok(0) => return Err(BrokerError::new(BrokerErrorCode::Io)),
                Ok(written) => offset += written,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    Self::wait(deadline)?;
                }
                Err(_) => return Err(BrokerError::new(BrokerErrorCode::Io)),
            }
        }
        self.stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| BrokerError::new(BrokerErrorCode::Io))
    }

    fn read_response(&mut self, deadline: Instant) -> Result<ZeroizingSecret, BrokerError> {
        use std::io::Read;

        let max = MAX_RESPONSE_BYTES.max(MAX_ERROR_BYTES);
        let mut response = Vec::new();
        let mut buffer = ZeroizingSecret::with_zeroize_drop(vec![0_u8; 512]);
        loop {
            if Instant::now() >= deadline {
                drop(ZeroizingSecret::with_zeroize_drop(response));
                return Err(BrokerError::new(BrokerErrorCode::DeadlineExceeded));
            }
            match buffer.with_bytes_mut(|bytes| self.stream.read(bytes)) {
                Ok(0) => return Ok(ZeroizingSecret::with_zeroize_drop(response)),
                Ok(read) => {
                    if response.len().saturating_add(read) > max {
                        drop(ZeroizingSecret::with_zeroize_drop(response));
                        return Err(BrokerError::new(BrokerErrorCode::ResponseOversized));
                    }
                    buffer.with_bytes(|bytes| response.extend_from_slice(&bytes[..read]));
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if let Err(error) = Self::wait(deadline) {
                        drop(ZeroizingSecret::with_zeroize_drop(response));
                        return Err(error);
                    }
                }
                Err(_) => {
                    drop(ZeroizingSecret::with_zeroize_drop(response));
                    return Err(BrokerError::new(BrokerErrorCode::Io));
                }
            }
        }
    }
}

// Taking ownership guarantees that the secret-bearing response frame is
// zeroized as soon as this parse operation returns on every path.
#[allow(clippy::needless_pass_by_value)]
fn parse_response(response: ZeroizingSecret) -> Result<ZeroizingSecret, BrokerError> {
    response.with_bytes(|bytes| {
        if bytes.len() > MAX_RESPONSE_BYTES.max(MAX_ERROR_BYTES) {
            return Err(BrokerError::new(BrokerErrorCode::ResponseOversized));
        }
        if bytes.starts_with(ERROR_MAGIC) {
            if bytes.len() != ERROR_MAGIC.len() + 1 {
                return Err(BrokerError::new(BrokerErrorCode::ResponseInvalid));
            }
            let code = BrokerErrorCode::from_wire(bytes[ERROR_MAGIC.len()])?;
            return Err(BrokerError::new(code));
        }
        parse_credential_frame(bytes).map_err(map_frame_error)
    })
}

/// Verify that a broker peer is the root-owned server (client-side check).
///
/// # Errors
///
/// Returns a redacted socket-rejected error unless the peer UID is root.
pub const fn verify_broker_peer_uid(peer_uid: u32) -> Result<(), BrokerError> {
    if peer_uid == 0 {
        Ok(())
    } else {
        Err(BrokerError::new(BrokerErrorCode::SocketRejected))
    }
}

/// Verify that the fixed KDBX owner is the connecting peer.
///
/// # Errors
///
/// Returns a redacted socket-rejected error when the two UIDs differ.
pub const fn verify_database_owner(peer_uid: u32, database_uid: u32) -> Result<(), BrokerError> {
    if peer_uid == database_uid {
        Ok(())
    } else {
        Err(BrokerError::new(BrokerErrorCode::SocketRejected))
    }
}

/// Validate fixed socket metadata without opening a caller-selected path.
///
/// # Errors
///
/// Returns a redacted socket-rejected error when the path, ownership, mode,
/// group, parent chain, or file type differs from the fixed contract.
#[cfg(unix)]
pub fn validate_socket_metadata(path: &Path) -> Result<(), BrokerError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    if path != Path::new(SOCKET_PATH) {
        return Err(BrokerError::new(BrokerErrorCode::SocketRejected));
    }
    let runtime_directory = path
        .parent()
        .ok_or_else(|| BrokerError::new(BrokerErrorCode::SocketRejected))?;
    let runtime_metadata = std::fs::symlink_metadata(runtime_directory)
        .map_err(|_| BrokerError::new(BrokerErrorCode::SocketRejected))?;
    let runtime_gid = runtime_metadata.gid();
    let mut parent = runtime_directory;
    loop {
        let metadata = std::fs::symlink_metadata(parent)
            .map_err(|_| BrokerError::new(BrokerErrorCode::SocketRejected))?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || (parent == Path::new("/run/fwc") && metadata.mode() & 0o777 != 0o750)
        {
            return Err(BrokerError::new(BrokerErrorCode::SocketRejected));
        }
        if parent == Path::new("/") {
            break;
        }
        parent = parent
            .parent()
            .ok_or_else(|| BrokerError::new(BrokerErrorCode::SocketRejected))?;
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| BrokerError::new(BrokerErrorCode::SocketRejected))?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != runtime_gid
        || metadata.mode() & 0o777 != 0o660
    {
        return Err(BrokerError::new(BrokerErrorCode::SocketRejected));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn validate_socket_metadata(_path: &Path) -> Result<(), BrokerError> {
    Err(BrokerError::new(BrokerErrorCode::SocketRejected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::time::Duration;

    struct FakeBackend {
        seen: Vec<BrokerRequest>,
        result: Result<ZeroizingSecret, BrokerError>,
    }

    impl CredentialBackend for FakeBackend {
        fn fetch(&mut self, request: BrokerRequest) -> Result<ZeroizingSecret, BrokerError> {
            self.seen.push(request);
            self.result.as_ref().map_or_else(
                |error| Err(*error),
                |secret| {
                    Ok(secret
                        .with_bytes(|bytes| ZeroizingSecret::with_zeroize_drop(bytes.to_vec())))
                },
            )
        }
    }

    struct FakeTransport {
        requests: Vec<Vec<u8>>,
        responses: VecDeque<ZeroizingSecret>,
        deadline: Option<Instant>,
    }

    impl BrokerTransport for FakeTransport {
        fn write_request(&mut self, frame: &[u8], deadline: Instant) -> Result<(), BrokerError> {
            self.requests.push(frame.to_vec());
            self.deadline = Some(deadline);
            Ok(())
        }

        fn read_response(&mut self, _deadline: Instant) -> Result<ZeroizingSecret, BrokerError> {
            self.responses
                .pop_front()
                .ok_or_else(|| BrokerError::new(BrokerErrorCode::Io))
        }
    }

    #[test]
    fn exact_enum_frame_and_trailing_second_request_rejection() {
        let request = BrokerRequest {
            server: BrokerServer::Eec,
            purpose: BrokerCredentialPurpose::RestApi,
        };
        assert_eq!(encode_request(request), b"\x01");
        assert_eq!(decode_request(&encode_request(request)), Ok(request));
        for collision in [b"\x01\x01".as_slice(), b"\x02\x01".as_slice()] {
            assert_eq!(
                decode_request(collision)
                    .expect_err("legacy trailing selector must not change credential purpose")
                    .code(),
                "invalid_request"
            );
        }
        let official_mcp = BrokerRequest {
            server: BrokerServer::Hetzner,
            purpose: BrokerCredentialPurpose::OfficialMcp,
        };
        assert_eq!(encode_request(official_mcp), b"\xf2\x02\x01");
        assert_eq!(
            decode_request(&encode_request(official_mcp)),
            Ok(official_mcp)
        );
        assert_eq!(
            decode_request(b"\xf2\x02\x02")
                .expect_err("unknown purpose")
                .code(),
            "invalid_request"
        );
        assert_eq!(
            decode_request(b"\xf3\x02\x01")
                .expect_err("unknown prefix")
                .code(),
            "invalid_request"
        );
        assert_eq!(
            decode_request(b"\x03").expect_err("bad server").code(),
            "invalid_request"
        );
    }

    #[test]
    fn synthetic_backend_is_bounded_and_redacted() {
        let mut backend = FakeBackend {
            seen: Vec::new(),
            result: Ok(ZeroizingSecret::with_zeroize_drop(b"EEC-KEY".to_vec())),
        };
        let mut request = encode_request(BrokerRequest {
            server: BrokerServer::Eec,
            purpose: BrokerCredentialPurpose::RestApi,
        });
        request.extend_from_slice(b"second");
        let mut output = Vec::new();
        let error = serve_once(&mut request.as_slice(), &mut output, &mut backend)
            .expect_err("second request rejected");
        assert_eq!(error.code(), "request_oversized");
        assert!(!format!("{error:?}").contains("EEC-KEY"));
        assert!(output.starts_with(ERROR_MAGIC));
    }

    #[test]
    fn empty_backend_secret_is_rejected_without_secret_output() {
        let mut backend = FakeBackend {
            seen: Vec::new(),
            result: Ok(ZeroizingSecret::with_zeroize_drop(Vec::new())),
        };
        let request = encode_request(BrokerRequest {
            server: BrokerServer::Hetzner,
            purpose: BrokerCredentialPurpose::RestApi,
        });
        let mut output = Vec::new();
        let error = serve_once(&mut request.as_slice(), &mut output, &mut backend)
            .expect_err("empty secret rejected");
        assert_eq!(error.code(), "empty_secret");
        assert_eq!(backend.seen.len(), 1);
        assert!(!output.windows(3).any(|window| window == b"key"));
    }

    #[test]
    fn client_propagates_one_absolute_deadline() {
        let client = BrokerClient::fixed();
        assert_eq!(client.socket_path(), Path::new(SOCKET_PATH));
        let secret = ZeroizingSecret::with_zeroize_drop(b"key".to_vec());
        let frame = encode_credential_frame(&secret).expect("frame");
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut transport = FakeTransport {
            requests: Vec::new(),
            responses: VecDeque::from([frame]),
            deadline: None,
        };
        let parsed = client
            .request(
                &mut transport,
                BrokerRequest {
                    server: BrokerServer::Hetzner,
                    purpose: BrokerCredentialPurpose::RestApi,
                },
                deadline,
            )
            .expect("response");
        assert_eq!(transport.deadline, Some(deadline));
        assert_eq!(parsed.with_bytes(|bytes| bytes.to_vec()), b"key");
        assert_eq!(
            verify_broker_peer_uid(1)
                .expect_err("untrusted peer")
                .code(),
            "socket_rejected"
        );
        assert!(verify_database_owner(7, 7).is_ok());
    }
}
