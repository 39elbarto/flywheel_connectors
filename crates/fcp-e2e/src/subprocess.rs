//! Subprocess runner stub for connector binaries.
//!
//! This is a minimal IPC shim for connectors that speak JSON lines over
//! stdin/stdout. It is intentionally lightweight and deterministic.

use std::io;
use std::process::Stdio;
use std::sync::Arc;

use fcp_async_core::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use fcp_async_core::process::{Child, ChildStdin, ChildStdout, Command};
use fcp_async_core::sync::Mutex;
use fcp_async_core::task::JoinHandle;

/// Subprocess runner for connector binaries using JSONL IPC.
pub struct ConnectorProcessRunner {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr_lines: Arc<Mutex<Vec<String>>>,
    _stderr_task: JoinHandle<()>,
}

impl ConnectorProcessRunner {
    /// Spawn a connector subprocess with JSONL stdin/stdout.
    ///
    /// # Errors
    /// Returns an IO error if the process fails to spawn or pipes cannot be opened.
    #[allow(clippy::unused_async)] // Async for API consistency with other subprocess methods
    pub async fn spawn(command: &str, args: &[&str], env: &[(&str, &str)]) -> io::Result<Self> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for (key, value) in env {
            cmd.env(key, value);
        }

        let mut child = cmd.spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("connector stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("connector stdout unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("connector stderr unavailable"))?;

        let stderr_lines = Arc::new(Mutex::new(Vec::new()));
        let stderr_lines_task = Arc::clone(&stderr_lines);
        let stderr_task = fcp_async_core::task::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let trimmed = line.trim_end();
                        if !trimmed.is_empty() {
                            let mut buffer = stderr_lines_task.lock().await;
                            buffer.push(trimmed.to_string());
                        }
                    }
                }
            }
        });

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            stderr_lines,
            _stderr_task: stderr_task,
        })
    }

    /// Send a JSON request to the connector.
    ///
    /// # Errors
    /// Returns an IO error if the request cannot be serialized or written.
    pub async fn send_json(&mut self, value: &serde_json::Value) -> io::Result<()> {
        let line = serde_json::to_string(value)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        Ok(())
    }

    /// Read a JSON response from the connector.
    ///
    /// # Errors
    /// Returns an IO error if the response cannot be read or parsed.
    pub async fn read_json(&mut self) -> io::Result<serde_json::Value> {
        let mut line = String::new();
        let bytes = self.stdout.read_line(&mut line).await?;
        if bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connector closed stdout",
            ));
        }
        serde_json::from_str::<serde_json::Value>(line.trim())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
    }

    /// Send a JSON request and wait for the next JSON response.
    ///
    /// # Errors
    /// Returns an IO error if IO or parsing fails.
    pub async fn request(&mut self, value: &serde_json::Value) -> io::Result<serde_json::Value> {
        self.send_json(value).await?;
        self.read_json().await
    }

    /// Terminate the connector subprocess.
    ///
    /// # Errors
    /// Returns an IO error if the process cannot be terminated.
    pub async fn terminate(&mut self) -> io::Result<()> {
        self.child.kill().await
    }

    /// Drain captured stderr lines since the last call.
    pub async fn drain_stderr_lines(&self) -> Vec<String> {
        let mut buffer = self.stderr_lines.lock().await;
        std::mem::take(&mut *buffer)
    }
}
