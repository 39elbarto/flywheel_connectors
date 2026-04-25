//! IRC session management: connect, register, `PING`/`PONG`, and message operations.

use fcp_async_core::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    tls::TlsConnectorBuilder,
};
use fcp_core::{FcpError, FcpResult};

use crate::error::IrcError;
use crate::types::{IrcConfig, validate_irc_atom, validate_irc_value};
use std::time::Duration;

// ── Stream abstraction ──

/// Trait alias for any async read/write stream (TCP or TLS).
pub(crate) trait IrcStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> IrcStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

// ── IRC Session ──

/// A short-lived IRC session over a single TCP (or TLS) connection.
///
/// Each operation opens a fresh session, performs registration (`NICK`/`USER`,
/// optional `PASS`, await 001 welcome), executes the operation, then quits.
pub struct IrcSession {
    stream: BufReader<Box<dyn IrcStream>>,
    timeout: Duration,
    /// Lines received during this session (transcript).
    pub lines: Vec<String>,
}

impl IrcSession {
    /// Send a raw IRC line (appends `\r\n`).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying write or flush fails.
    pub async fn send_line(&mut self, line: &str) -> FcpResult<()> {
        self.stream
            .get_mut()
            .write_all(line.as_bytes())
            .await
            .map_err(|ref e| IrcError::io("irc write", e).to_fcp_error())?;
        self.stream
            .get_mut()
            .write_all(b"\r\n")
            .await
            .map_err(|ref e| IrcError::io("irc write", e).to_fcp_error())?;
        self.stream
            .get_mut()
            .flush()
            .await
            .map_err(|ref e| IrcError::io("irc flush", e).to_fcp_error())?;
        Ok(())
    }

    /// Read a single line from the IRC connection.
    ///
    /// Automatically handles `PING`/`PONG`. Returns `None` on EOF.
    ///
    /// # Errors
    ///
    /// Returns an error on I/O failure or timeout.
    pub async fn read_line(&mut self) -> FcpResult<Option<String>> {
        let mut line = String::new();
        let bytes = fcp_async_core::time::timeout(self.timeout, self.stream.read_line(&mut line))
            .await
            .map_err(|_| FcpError::UpstreamTimeout {
                service: "irc".into(),
            })?
            .map_err(|ref e| IrcError::io("irc read", e).to_fcp_error())?;
        if bytes == 0 {
            return Ok(None);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
        // Handle PING from the server: both "PING :payload" and "PING payload"
        // formats, as well as prefixed forms like ":server PING :payload".
        let ping_source = trimmed
            .strip_prefix("PING :")
            .or_else(|| trimmed.strip_prefix("PING "))
            .or_else(|| {
                // Handle prefixed PING: ":server PING :payload" or ":server PING payload"
                if trimmed.starts_with(':') {
                    let after_prefix = trimmed.split_once(' ').map(|(_, rest)| rest)?;
                    after_prefix
                        .strip_prefix("PING :")
                        .or_else(|| after_prefix.strip_prefix("PING "))
                } else {
                    None
                }
            });
        if let Some(payload) = ping_source {
            self.send_line(&format!("PONG :{payload}")).await?;
        }
        self.lines.push(trimmed.clone());
        Ok(Some(trimmed))
    }

    /// Wait for IRC 001 (`RPL_WELCOME`) after registration.
    ///
    /// # Errors
    ///
    /// Returns an error if the server closes the connection before welcome,
    /// or if the nickname is already in use (433).
    pub async fn await_welcome(&mut self) -> FcpResult<()> {
        loop {
            let Some(line) = self.read_line().await? else {
                return Err(FcpError::External {
                    service: "irc".into(),
                    message: "IRC server closed connection before welcome".into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            };
            if line.contains(" 001 ") {
                return Ok(());
            }
            if line.contains(" 433 ") {
                return Err(FcpError::External {
                    service: "irc".into(),
                    message: "IRC nickname already in use".into(),
                    status_code: None,
                    retryable: false,
                    retry_after: None,
                });
            }
        }
    }

    /// Join an IRC channel, optionally with a key.
    ///
    /// # Errors
    ///
    /// Returns an error if sending the JOIN command fails.
    pub async fn join(
        &mut self,
        channel: &str,
        channel_key: Option<&str>,
        response_lines: usize,
    ) -> FcpResult<()> {
        validate_irc_atom("channel", channel, false)?;
        let cmd = if let Some(key) = channel_key {
            validate_irc_atom("channel_key", key, false)?;
            format!("JOIN {channel} {key}")
        } else {
            format!("JOIN {channel}")
        };
        self.send_line(&cmd).await?;
        self.read_up_to(response_lines).await?;
        Ok(())
    }

    /// Send a `PRIVMSG` to a target (channel or nick).
    ///
    /// # Errors
    ///
    /// Returns an error if sending the message fails.
    pub async fn send_privmsg(&mut self, target: &str, message: &str) -> FcpResult<()> {
        validate_irc_atom("target", target, false)?;
        validate_irc_value("message", message)?;
        self.send_line(&format!("PRIVMSG {target} :{message}"))
            .await
    }

    /// Read up to an additional bounded number of lines from the server.
    ///
    /// Quiet channels are common after `JOIN`, so a read timeout ends the
    /// bounded read instead of surfacing a hard error.
    ///
    /// # Errors
    ///
    /// Returns an error if reading a line fails for reasons other than timeout.
    pub async fn read_up_to(&mut self, sample_lines: usize) -> FcpResult<()> {
        let target_len = self.lines.len().saturating_add(sample_lines);
        while self.lines.len() < target_len {
            match self.read_line().await {
                Ok(Some(_)) => {}
                Ok(None) | Err(FcpError::UpstreamTimeout { .. }) => break,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Send `QUIT` command and close the session.
    ///
    /// # Errors
    ///
    /// Returns an error if sending the QUIT command or shutting down the
    /// underlying writer fails.
    pub async fn quit(&mut self) -> FcpResult<()> {
        self.send_line("QUIT :fcp").await?;
        self.stream
            .get_mut()
            .shutdown()
            .await
            .map_err(|ref e| IrcError::io("irc shutdown", e).to_fcp_error())
    }
}

/// Open a short-lived IRC session, perform registration, execute `f`, and return
/// the transcript lines.
///
/// # Errors
///
/// Returns an error if connection, TLS handshake, or registration fails.
pub async fn with_irc_session<F, Fut>(config: &IrcConfig, f: F) -> FcpResult<Vec<String>>
where
    F: FnOnce(IrcSession) -> Fut,
    Fut: std::future::Future<Output = FcpResult<Vec<String>>>,
{
    config.validate()?;
    let address = config.address();
    let tcp = fcp_async_core::time::timeout(config.timeout(), TcpStream::connect(address))
        .await
        .map_err(|_| FcpError::UpstreamTimeout {
            service: "irc".into(),
        })?
        .map_err(|ref e| IrcError::io("irc connect", e).to_fcp_error())?;
    let _ = tcp.set_nodelay(true);

    let stream: Box<dyn IrcStream> = if config.tls {
        let connector = TlsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|error| FcpError::Internal {
                message: format!("failed to initialize IRC TLS roots: {error}"),
            })?
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("failed to build IRC TLS connector: {error}"),
            })?;
        let tls =
            fcp_async_core::time::timeout(config.timeout(), connector.connect(&config.server, tcp))
                .await
                .map_err(|_| FcpError::UpstreamTimeout {
                    service: "irc".into(),
                })?
                .map_err(|error| FcpError::External {
                    service: "irc".into(),
                    message: format!("IRC TLS handshake failed: {error}"),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                })?;
        Box::new(tls)
    } else {
        Box::new(tcp)
    };

    let mut session = IrcSession {
        stream: BufReader::new(stream),
        timeout: config.timeout(),
        lines: Vec::new(),
    };

    if let Some(password) = config.password.as_deref() {
        validate_irc_value("password", password)?;
        session.send_line(&format!("PASS :{password}")).await?;
    }
    session.send_line(&format!("NICK {}", config.nick)).await?;
    session
        .send_line(&format!(
            "USER {} 0 * :{}",
            config.username, config.realname
        ))
        .await?;
    session.await_welcome().await?;
    f(session).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_async_core::io::ReadBuf;
    use serde_json::json;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    fn test_config() -> IrcConfig {
        serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "testbot",
            "tls": false,
            "request_timeout_ms": 5000
        }))
        .unwrap()
    }

    #[test]
    fn test_config_validates() {
        let config = test_config();
        config.validate().expect("test config should be valid");
    }

    #[test]
    fn test_config_address() {
        let config = test_config();
        assert_eq!(config.address(), "irc.example.com:6667");
    }

    #[test]
    fn test_config_tls_address() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "testbot",
            "tls": true
        }))
        .unwrap();
        assert_eq!(config.address(), "irc.example.com:6697");
    }

    #[test]
    fn config_validation_rejects_bad_command_atoms() {
        let bad_nick: IrcConfig = serde_json::from_value(json!({
            "server": "irc.example.com",
            "nick": "bad nick",
            "tls": false
        }))
        .unwrap();
        assert!(bad_nick.validate().is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn with_irc_session_connection_refused() {
        let config: IrcConfig = serde_json::from_value(json!({
            "server": "127.0.0.1",
            "nick": "testbot",
            "tls": false,
            "port": 1,
            "request_timeout_ms": 500
        }))
        .unwrap();

        let result = with_irc_session(&config, |mut session| async move {
            session.quit().await?;
            Ok(session.lines)
        })
        .await;

        assert!(result.is_err());
    }

    struct PendingStream;

    impl AsyncRead for PendingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[fcp_async_core::runtime::test]
    async fn read_up_to_stops_cleanly_on_quiet_timeout() {
        let mut session = IrcSession {
            stream: BufReader::new(Box::new(PendingStream)),
            timeout: Duration::from_millis(10),
            lines: vec!["existing".into()],
        };

        session
            .read_up_to(3)
            .await
            .expect("quiet timeout should end sampling cleanly");

        assert_eq!(session.lines, vec!["existing"]);
    }

    #[fcp_async_core::runtime::test]
    async fn send_privmsg_rejects_multi_target_fanout() {
        let mut session = IrcSession {
            stream: BufReader::new(Box::new(PendingStream)),
            timeout: Duration::from_millis(10),
            lines: Vec::new(),
        };

        let error = session
            .send_privmsg("#rust,#ops", "hello")
            .await
            .expect_err("multiple targets should be rejected");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }
}
