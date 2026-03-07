//! Subprocess runner stub for connector binaries.
//!
//! This is a minimal IPC shim for connectors that speak JSON lines over
//! stdin/stdout. It is intentionally lightweight and deterministic.

use std::io;
use std::sync::Arc;

use fcp_async_core::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use fcp_async_core::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
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
            .stdin()
            .ok_or_else(|| io::Error::other("connector stdin unavailable"))?;
        let stdout = child
            .stdout()
            .ok_or_else(|| io::Error::other("connector stdout unavailable"))?;
        let stderr = child
            .stderr()
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
    pub fn terminate(&mut self) -> io::Result<()> {
        self.child.kill().map_err(Into::into)
    }

    /// Drain captured stderr lines since the last call.
    pub async fn drain_stderr_lines(&self) -> Vec<String> {
        let mut buffer = self.stderr_lines.lock().await;
        std::mem::take(&mut *buffer)
    }

    pub async fn stderr_lines(&self) -> Vec<String> {
        let lines = self.stderr_lines.lock().await;
        lines.clone()
    }
}

impl Drop for ConnectorProcessRunner {
    fn drop(&mut self) {
        // Prevent zombie processes from accumulating during test runs
        let _ = self.child.start_kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Use `cat` as a JSONL echo subprocess (reads stdin, writes to stdout).

    #[fcp_async_core::runtime::test]
    async fn spawn_and_terminate() {
        let mut runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .expect("cat should spawn");
        runner.terminate().expect("should terminate");
    }

    #[fcp_async_core::runtime::test]
    async fn send_and_read_json_roundtrip() {
        let mut runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .unwrap();
        let msg = json!({"method": "ping", "id": 1});
        runner.send_json(&msg).await.unwrap();
        let response = runner.read_json().await.unwrap();
        assert_eq!(response, msg);
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn request_roundtrip() {
        let mut runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .unwrap();
        let msg = json!({"jsonrpc": "2.0", "method": "test", "params": [1, 2, 3]});
        let response = runner.request(&msg).await.unwrap();
        assert_eq!(response, msg);
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn multiple_requests() {
        let mut runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .unwrap();
        for i in 0..5 {
            let msg = json!({"id": i, "data": format!("msg-{i}")});
            let response = runner.request(&msg).await.unwrap();
            assert_eq!(response["id"], i);
        }
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn read_json_after_eof_returns_error() {
        let mut runner = ConnectorProcessRunner::spawn("echo", &[], &[])
            .await
            .unwrap();
        // echo writes nothing to stdout (no args) and exits immediately.
        // Wait for exit, then read should get EOF.
        // Give it a moment to finish.
        fcp_async_core::time::sleep(std::time::Duration::from_millis(50)).await;
        let result = runner.read_json().await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn spawn_nonexistent_binary_fails() {
        let result = ConnectorProcessRunner::spawn("__nonexistent_binary_xyz_42__", &[], &[]).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn spawn_with_env_vars() {
        // Use `sh -c 'echo ...'` to echo a JSON object containing an env var.
        let mut runner = ConnectorProcessRunner::spawn(
            "sh",
            &["-c", r#"echo "{\"var\":\"$FCP_TEST_VAR\"}""#],
            &[("FCP_TEST_VAR", "hello_42")],
        )
        .await
        .unwrap();
        let response = runner.read_json().await.unwrap();
        assert_eq!(response["var"], "hello_42");
    }

    #[fcp_async_core::runtime::test]
    async fn drain_stderr_lines_initially_empty() {
        let runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .unwrap();
        let lines = runner.drain_stderr_lines().await;
        assert!(lines.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn drain_stderr_captures_output() {
        // Use sh -c to write to stderr
        let mut runner = ConnectorProcessRunner::spawn(
            "sh",
            &[
                "-c",
                "echo 'error line 1' >&2; echo 'error line 2' >&2; cat",
            ],
            &[],
        )
        .await
        .unwrap();
        // Give stderr time to be captured
        fcp_async_core::time::sleep(std::time::Duration::from_millis(100)).await;
        let lines = runner.drain_stderr_lines().await;
        assert!(
            lines.len() >= 2,
            "expected at least 2 stderr lines, got {}",
            lines.len()
        );
        assert!(lines[0].contains("error line 1"));
        assert!(lines[1].contains("error line 2"));
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn drain_stderr_clears_buffer() {
        let mut runner = ConnectorProcessRunner::spawn("sh", &["-c", "echo 'msg' >&2; cat"], &[])
            .await
            .unwrap();
        fcp_async_core::time::sleep(std::time::Duration::from_millis(100)).await;
        let first = runner.drain_stderr_lines().await;
        assert!(!first.is_empty());
        let second = runner.drain_stderr_lines().await;
        assert!(second.is_empty(), "drain should clear buffer");
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn send_json_complex_value() {
        let mut runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .unwrap();
        let msg = json!({
            "method": "invoke",
            "params": {
                "connector": "test",
                "operation": "get",
                "zone": "z:work",
                "nested": {"a": [1, 2, 3], "b": null, "c": true}
            }
        });
        let response = runner.request(&msg).await.unwrap();
        assert_eq!(response["params"]["nested"]["a"], json!([1, 2, 3]));
        assert!(response["params"]["nested"]["b"].is_null());
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn stderr_lines_returns_snapshot() {
        let mut runner = ConnectorProcessRunner::spawn(
            "sh",
            &["-c", "echo 'line1' >&2; echo 'line2' >&2; cat"],
            &[],
        )
        .await
        .unwrap();
        fcp_async_core::time::sleep(std::time::Duration::from_millis(100)).await;
        let snapshot = runner.stderr_lines().await;
        assert!(snapshot.len() >= 2);
        // stderr_lines doesn't drain, so calling again returns same content
        let snapshot2 = runner.stderr_lines().await;
        assert_eq!(snapshot.len(), snapshot2.len());
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn send_json_empty_object() {
        let mut runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .unwrap();
        let msg = json!({});
        let response = runner.request(&msg).await.unwrap();
        assert!(response.as_object().unwrap().is_empty());
        runner.terminate().unwrap();
    }
}
