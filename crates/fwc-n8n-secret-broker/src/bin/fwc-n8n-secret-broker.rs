//! Live broker entry point. The binary is feature-gated so default connector
//! builds cannot link KeePass or age.

#[cfg(any(
    not(feature = "live-backend"),
    all(feature = "live-backend", not(target_os = "linux"))
))]
use std::io;
#[cfg(all(feature = "live-backend", target_os = "linux"))]
use std::io;

#[cfg(all(feature = "live-backend", target_os = "linux"))]
const SOCKET_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(all(feature = "live-backend", target_os = "linux"))]
use fwc_n8n_secret_broker::serve_once;

#[cfg(all(feature = "live-backend", target_os = "linux"))]
fn serve_connection<B: fwc_n8n_secret_broker::CredentialBackend>(
    mut connection: std::os::unix::net::UnixStream,
    timeout: std::time::Duration,
    backend: &mut B,
) -> Result<(), fwc_n8n_secret_broker::BrokerError> {
    let mut reader = connection
        .try_clone()
        .map_err(|_| fwc_n8n_secret_broker::BrokerError::backend_failed())?;
    reader
        .set_read_timeout(Some(timeout))
        .map_err(|_| fwc_n8n_secret_broker::BrokerError::backend_failed())?;
    connection
        .set_write_timeout(Some(timeout))
        .map_err(|_| fwc_n8n_secret_broker::BrokerError::backend_failed())?;
    serve_once(&mut reader, &mut connection, backend)
}

#[cfg(all(feature = "live-backend", target_os = "linux"))]
fn main() {
    if fwc_n8n_secret_broker::live::reject_unexpected_inherited_fds().is_err()
        || fwc_n8n_secret_broker::validate_socket_metadata(std::path::Path::new(
            fwc_n8n_secret_broker::SOCKET_PATH,
        ))
        .is_err()
    {
        std::process::exit(1);
    }
    use std::os::fd::AsFd;

    let stdin = io::stdin();
    let Ok(connection_fd) = rustix::io::dup(stdin.as_fd()) else {
        std::process::exit(1);
    };
    let connection = std::os::unix::net::UnixStream::from(connection_fd);
    let Ok(mut backend) =
        fwc_n8n_secret_broker::live::LiveBackend::from_connected_socket(&connection)
    else {
        std::process::exit(1);
    };
    let result = serve_connection(connection, SOCKET_IO_TIMEOUT, &mut backend);
    if result.is_err() {
        std::process::exit(1);
    }
}

#[cfg(any(
    not(feature = "live-backend"),
    all(feature = "live-backend", not(target_os = "linux"))
))]
fn main() {
    let _ = (io::stdin(), io::stdout());
    std::process::exit(1);
}

#[cfg(all(test, feature = "live-backend", target_os = "linux"))]
mod tests {
    use super::*;
    use fwc_n8n_secret_broker::{BrokerError, BrokerRequest, CredentialBackend, ZeroizingSecret};
    use std::io::Write;

    struct NeverCalled;

    impl CredentialBackend for NeverCalled {
        fn fetch(&mut self, _request: BrokerRequest) -> Result<ZeroizingSecret, BrokerError> {
            panic!("incomplete request must not reach backend")
        }
    }

    #[test]
    fn incomplete_client_cannot_pin_broker_read() {
        let (server, mut client) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        client.write_all(b"\x01").expect("request byte");
        let started = std::time::Instant::now();
        let error = serve_connection(
            server,
            std::time::Duration::from_millis(20),
            &mut NeverCalled,
        )
        .expect_err("missing EOF must time out");
        assert_eq!(error.code(), "io");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
}
