#![cfg(feature = "connector-http")]

use std::io::{Error, ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::fs::{self, Permissions};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStringExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixListener;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use chrono::{SecondsFormat, Utc};
use fcp_manifest::{
    Base64Bytes, HostEgressContext, HostEgressDecisionMetadata, HostEgressHttpHeader,
    HostEgressHttpRequest, HostEgressHttpResponse, HostEgressTcpRequest, HostEgressTcpResponse,
};
use fcp_sdk::migration::{
    HOST_EGRESS_WIRE_SCHEMA_VERSION, HostEgressProxyClient, HostEgressProxyConfigError,
    HostEgressProxyError, HostEgressProxyLimits, HostEgressTransport, HostEgressWireRequest,
    HostEgressWireRequestPayload, HostEgressWireResponse, HostEgressWireResponseBody,
    HostEgressWireRoute,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::{Value, json};

const CONNECTOR_ID: &str = "fcp.test.b0qqv-sdk:utility:1.0.0";
const ZONE_ID: &str = "z:work";
const CAPABILITY_MATERIAL_SENTINEL: &str = "capability-material-b0qqv-redaction-sentinel";
const CREDENTIAL_ID_SENTINEL: &str = "credential-b0qqv-redaction-sentinel";
const HEADER_SENTINEL: &str = "header-b0qqv-redaction-sentinel";
const BODY_SENTINEL: &str = "body-b0qqv-redaction-sentinel";
const URL_SENTINEL: &str = "url-b0qqv-redaction-sentinel";
const TARGET_URL: &str =
    "https://api.example.test/v1/messages?proof_marker=url-b0qqv-redaction-sentinel";
const TARGET_HOST: &str = "api.example.test";
#[cfg(target_os = "linux")]
const AUTH_TOKEN_SENTINEL: &str = "host-auth-b0qqv-secret-token";
#[cfg(target_os = "linux")]
static NEXT_UNIX_PROXY_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct CapturedProxyRequest {
    method: String,
    path: String,
    auth_header: Option<String>,
    body: Value,
}

struct OneShotProxy {
    base_url: String,
    receiver: Receiver<Result<CapturedProxyRequest, String>>,
    handle: JoinHandle<()>,
}

impl OneShotProxy {
    fn start(status: u16, body: String, content_type: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback proxy");
        let base_url = format!("http://{}", listener.local_addr().expect("proxy address"));
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let result = serve_one_proxy_request(&listener, status, &body, content_type)
                .map_err(|error| error.to_string());
            let _ = sender.send(result);
        });
        Self {
            base_url,
            receiver,
            handle,
        }
    }

    fn start_json(status: u16, body: &Value) -> Self {
        Self::start(
            status,
            serde_json::to_string(body).expect("serialize proxy response JSON"),
            "application/json",
        )
    }

    fn start_text(status: u16, body: String) -> Self {
        Self::start(status, body, "text/plain; charset=utf-8")
    }

    fn start_delayed(status: u16, body: String, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind delayed loopback proxy");
        let base_url = format!("http://{}", listener.local_addr().expect("proxy address"));
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let result = (|| {
                let (mut stream, _) = listener.accept()?;
                let captured = read_proxy_request(&mut stream)?;
                thread::sleep(delay);
                write_proxy_response(&mut stream, status, &body, "application/json")?;
                Ok(captured)
            })()
            .map_err(|error: std::io::Error| error.to_string());
            let _ = sender.send(result);
        });
        Self {
            base_url,
            receiver,
            handle,
        }
    }

    fn start_without_content_length(status: u16, body: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind streaming loopback proxy");
        let base_url = format!("http://{}", listener.local_addr().expect("proxy address"));
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let result = (|| {
                let (mut stream, _) = listener.accept()?;
                let captured = read_proxy_request(&mut stream)?;
                let response = format!(
                    "HTTP/1.1 {status} {}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{body}",
                    reason_phrase(status)
                );
                stream.write_all(response.as_bytes())?;
                stream.flush()?;
                Ok(captured)
            })()
            .map_err(|error: std::io::Error| error.to_string());
            let _ = sender.send(result);
        });
        Self {
            base_url,
            receiver,
            handle,
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn capture(self) -> CapturedProxyRequest {
        let captured = self
            .receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("proxy must capture a request")
            .expect("proxy request must parse");
        self.handle.join().expect("proxy thread must finish");
        captured
    }

    fn finish(self) {
        let _ = self.receiver.recv_timeout(Duration::from_secs(5));
        self.handle.join().expect("proxy thread must finish");
    }
}

#[cfg(target_os = "linux")]
struct OneShotUnixProxy {
    socket_path: PathBuf,
    parent_path: PathBuf,
    receiver: Receiver<Result<CapturedProxyRequest, String>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl OneShotUnixProxy {
    fn start_json(status: u16, body: &Value) -> Self {
        Self::start(
            status,
            serde_json::to_string(body).expect("serialize Unix proxy response JSON"),
            true,
            None,
        )
    }

    fn start_malformed(body: String) -> Self {
        Self::start(200, body, true, None)
    }

    fn start_oversized(body: String) -> Self {
        Self::start(200, body, true, None)
    }

    fn start_delayed(body: String, delay: Duration) -> Self {
        Self::start(200, body, true, Some(delay))
    }

    fn start(status: u16, body: String, content_length: bool, delay: Option<Duration>) -> Self {
        let id = NEXT_UNIX_PROXY_ID.fetch_add(1, Ordering::Relaxed);
        let parent_path = std::env::temp_dir().join(format!("fhe-{}-{id}", std::process::id()));
        fs::create_dir(&parent_path).expect("create private Unix proxy directory");
        fs::set_permissions(&parent_path, Permissions::from_mode(0o700))
            .expect("make Unix proxy directory private");
        let socket_path = parent_path.join("proxy.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind Unix proxy socket");
        fs::set_permissions(&socket_path, Permissions::from_mode(0o600))
            .expect("make Unix proxy socket private");
        listener
            .set_nonblocking(true)
            .expect("set Unix proxy listener nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let (sender, receiver) = mpsc::channel();
        let thread_handle = thread::spawn(move || {
            let result = (|| {
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            if thread_stop.load(Ordering::Relaxed) {
                                return Err(Error::new(
                                    ErrorKind::Interrupted,
                                    "Unix proxy stopped before accepting a request",
                                ));
                            }
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => return Err(error),
                    }
                };
                let captured = read_proxy_request(&mut stream)?;
                if let Some(delay) = delay {
                    thread::sleep(delay);
                }
                if content_length {
                    write_proxy_response(&mut stream, status, &body, "application/json")?;
                } else {
                    let response = format!(
                        "HTTP/1.1 {status} {}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{body}",
                        reason_phrase(status)
                    );
                    stream.write_all(response.as_bytes())?;
                    stream.flush()?;
                }
                Ok(captured)
            })()
            .map_err(|error: std::io::Error| error.to_string());
            let _ = sender.send(result);
        });
        Self {
            socket_path,
            parent_path,
            receiver,
            stop,
            handle: Some(thread_handle),
        }
    }

    fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    fn capture(mut self) -> CapturedProxyRequest {
        let captured = self
            .receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("Unix proxy must capture a request")
            .expect("Unix proxy request must parse");
        self.stop.store(true, Ordering::Relaxed);
        self.handle
            .take()
            .expect("Unix proxy thread handle")
            .join()
            .expect("Unix proxy thread must finish");
        captured
    }

    fn finish(mut self) {
        let _ = self.receiver.recv_timeout(Duration::from_secs(5));
        self.stop.store(true, Ordering::Relaxed);
        self.handle
            .take()
            .expect("Unix proxy thread handle")
            .join()
            .expect("Unix proxy thread must finish");
    }
}

#[cfg(target_os = "linux")]
impl Drop for OneShotUnixProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        let _ = fs::remove_file(&self.socket_path);
        let _ = fs::remove_dir(&self.parent_path);
    }
}

#[cfg(target_os = "linux")]
fn validation_socket(parent_mode: u32, socket_mode: u32) -> (UnixListener, PathBuf, PathBuf) {
    let id = NEXT_UNIX_PROXY_ID.fetch_add(1, Ordering::Relaxed);
    let parent_path = std::env::temp_dir().join(format!("fhv-{}-{id}", std::process::id()));
    fs::create_dir(&parent_path).expect("create validation socket directory");
    fs::set_permissions(&parent_path, Permissions::from_mode(parent_mode))
        .expect("set validation socket directory mode");
    let socket_path = parent_path.join("validation.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind validation Unix socket");
    fs::set_permissions(&socket_path, Permissions::from_mode(socket_mode))
        .expect("set validation socket mode");
    (listener, socket_path, parent_path)
}

#[cfg(target_os = "linux")]
fn cleanup_validation_socket(socket_path: &Path, parent_path: &Path) {
    let _ = fs::remove_file(socket_path);
    let _ = fs::remove_dir(parent_path);
}

fn serve_one_proxy_request(
    listener: &TcpListener,
    status: u16,
    response_body: &str,
    content_type: &str,
) -> std::io::Result<CapturedProxyRequest> {
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let captured = read_proxy_request(&mut stream)?;
    write_proxy_response(&mut stream, status, response_body, content_type)?;
    Ok(captured)
}

fn read_proxy_request<R: Read>(stream: &mut R) -> std::io::Result<CapturedProxyRequest> {
    let mut header_bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while !header_bytes.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "connection closed before HTTP headers completed",
            ));
        }
        header_bytes.push(byte[0]);
        if header_bytes.len() > 16_384 {
            return Err(Error::new(ErrorKind::InvalidData, "HTTP headers too large"));
        }
    }

    let headers = String::from_utf8(header_bytes)
        .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
    let request_line = headers
        .lines()
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing HTTP method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing HTTP path"))?
        .to_string();
    let auth_header = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("x-fcp-host-egress-auth")
            .then(|| value.trim().to_string())
    });
    let content_length = content_length_from_headers(&headers)?;
    let mut body_bytes = vec![0_u8; content_length];
    stream.read_exact(&mut body_bytes)?;
    let raw_body = String::from_utf8_lossy(&body_bytes).into_owned();
    let body = serde_json::from_str(&raw_body)
        .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;

    Ok(CapturedProxyRequest {
        method,
        path,
        auth_header,
        body,
    })
}

fn content_length_from_headers(headers: &str) -> std::io::Result<usize> {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>())
        })
        .transpose()
        .map_err(|error| Error::new(ErrorKind::InvalidData, error))?
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing content-length header"))
}

fn write_proxy_response<W: Write>(
    stream: &mut W,
    status: u16,
    body: &str,
    content_type: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        reason_phrase(status),
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        403 => "Forbidden",
        413 => "Payload Too Large",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

fn context(operation_id: &str, request_id: &str, correlation_id: &str) -> HostEgressContext {
    HostEgressContext {
        connector_id: CONNECTOR_ID.to_string(),
        operation_id: operation_id.to_string(),
        resource_uri: format!("fcp-test://host-egress/{operation_id}"),
        zone_id: ZONE_ID.to_string(),
        request_id: request_id.to_string(),
        correlation_id: Some(correlation_id.to_string()),
        capability_token_cbor_b64: CAPABILITY_MATERIAL_SENTINEL.to_string(),
    }
}

fn http_request(request_id: &str, correlation_id: &str) -> HostEgressHttpRequest {
    HostEgressHttpRequest {
        context: context("messages.create", request_id, correlation_id),
        url: TARGET_URL.to_string(),
        method: "POST".to_string(),
        headers: vec![
            HostEgressHttpHeader {
                name: "authorization".to_string(),
                value: format!("Bearer {HEADER_SENTINEL}"),
            },
            HostEgressHttpHeader {
                name: "x-fcp-correlation".to_string(),
                value: correlation_id.to_string(),
            },
        ],
        body: Some(Base64Bytes::from_vec(BODY_SENTINEL.as_bytes().to_vec())),
        credential_id: Some(CREDENTIAL_ID_SENTINEL.to_string()),
    }
}

fn tcp_request(request_id: &str, correlation_id: &str) -> HostEgressTcpRequest {
    HostEgressTcpRequest {
        context: context("socket.exchange", request_id, correlation_id),
        host: TARGET_HOST.to_string(),
        port: 443,
        tls: true,
        sni_override: Some(TARGET_HOST.to_string()),
        write: Some(Base64Bytes::from_vec(BODY_SENTINEL.as_bytes().to_vec())),
        read_limit_bytes: Some(4096),
        credential_id: Some(CREDENTIAL_ID_SENTINEL.to_string()),
    }
}

fn decision_metadata(
    context: &HostEgressContext,
    resolved_host: &str,
    resolved_port: u16,
) -> HostEgressDecisionMetadata {
    HostEgressDecisionMetadata {
        connector_id: context.connector_id.clone(),
        operation_id: context.operation_id.clone(),
        zone_id: context.zone_id.clone(),
        request_id: context.request_id.clone(),
        correlation_id: context.correlation_id.clone(),
        execution_mode: "host_egress_proxy".to_string(),
        constraint_source: "manifest.network_constraints".to_string(),
        decision: "allow".to_string(),
        resolved_host: resolved_host.to_string(),
        resolved_port,
        credential_injected: true,
        elapsed_ms: 3,
    }
}

fn http_response(request: &HostEgressHttpRequest) -> Value {
    serde_json::to_value(HostEgressHttpResponse {
        status: 202,
        headers: vec![HostEgressHttpHeader {
            name: "content-type".to_string(),
            value: "application/json".to_string(),
        }],
        body: Base64Bytes::from_vec(br#"{"accepted":true}"#.to_vec()),
        egress: decision_metadata(&request.context, TARGET_HOST, 443),
    })
    .expect("serialize HTTP response contract")
}

fn tcp_response(request: &HostEgressTcpRequest) -> Value {
    serde_json::to_value(HostEgressTcpResponse {
        bytes_written: request
            .write
            .as_ref()
            .map_or(0, |payload| payload.as_bytes().len() as u64),
        bytes_read: 4,
        read: Base64Bytes::from_vec(b"PONG".to_vec()),
        egress: decision_metadata(&request.context, &request.host, request.port),
    })
    .expect("serialize TCP response contract")
}

fn runtime_for_proxy(proxy: &OneShotProxy) -> ConnectorRuntime {
    ConnectorRuntime::new(
        ConnectorRuntimeConfig::default().with_host_egress_proxy_url(proxy.base_url()),
    )
}

fn assert_no_secret_material(text: &str) {
    for secret in [
        CAPABILITY_MATERIAL_SENTINEL,
        CREDENTIAL_ID_SENTINEL,
        HEADER_SENTINEL,
        BODY_SENTINEL,
        URL_SENTINEL,
        TARGET_URL,
    ] {
        assert!(!text.contains(secret), "secret material leaked: {secret}");
    }
}

fn emit_jsonl_record(record: &Value) {
    let line = serde_json::to_string(&record).expect("serialize SDK e2e JSONL record");
    assert_no_secret_material(&line);
    println!("RUNTIME_NETWORK_POLICY_E2E_JSONL {line}");
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn elapsed_ms(started_at: Instant) -> u128 {
    started_at.elapsed().as_millis()
}

#[test]
#[allow(clippy::too_many_lines)]
fn host_egress_proxy_sdk_loopback_e2e_jsonl_matrix() {
    fcp_async_core::runtime::block_on_sync(async {
        let http_started_at = Instant::now();
        let http_request = http_request("req-b0qqv-sdk-http", "corr-b0qqv-sdk-http");
        let http_proxy = OneShotProxy::start_json(200, &http_response(&http_request));
        let http_runtime = runtime_for_proxy(&http_proxy);
        let http_client = http_runtime
            .host_egress_proxy_client()
            .expect("valid HTTP host egress proxy configuration")
            .expect("configured HTTP host egress client");
        let http_response = http_client
            .http(&http_request)
            .await
            .expect("HTTP helper must route through proxy");
        let http_capture = http_proxy.capture();

        assert_eq!(http_capture.method, "POST");
        assert_eq!(http_capture.path, "/rpc/egress/http");
        assert_eq!(http_capture.body["url"], TARGET_URL);
        assert_eq!(http_capture.body["method"], "POST");
        assert_eq!(http_capture.body["credential_id"], CREDENTIAL_ID_SENTINEL);
        assert_eq!(
            http_capture.body["context"]["request_id"],
            "req-b0qqv-sdk-http"
        );
        assert_eq!(
            http_capture.body["context"]["correlation_id"],
            "corr-b0qqv-sdk-http"
        );
        assert_eq!(
            http_capture.body["context"]["resource_uri"],
            "fcp-test://host-egress/messages.create"
        );
        assert_eq!(
            http_capture.body["body"],
            "base64:Ym9keS1iMHFxdi1yZWRhY3Rpb24tc2VudGluZWw="
        );
        assert_eq!(http_response.status, 202);
        assert_eq!(http_response.egress.request_id, "req-b0qqv-sdk-http");
        assert_eq!(
            http_response.egress.correlation_id.as_deref(),
            Some("corr-b0qqv-sdk-http")
        );

        emit_jsonl_record(&json!({
            "timestamp": timestamp(),
            "test_name": "br_b0qqv_sdk_host_egress_proxy_e2e_jsonl_matrix",
            "module": "fcp-sdk",
            "phase": "sdk_host_egress_proxy",
            "scenario_id": "sdk_https_proxy_routing",
            "correlation_id": "corr-b0qqv-sdk-http",
            "result": "pass",
            "duration_ms": elapsed_ms(http_started_at),
            "assertions": {"passed": 12, "failed": 0},
            "details": {
                "connector_id": CONNECTOR_ID,
                "operation": "messages.create",
                "zone_id": ZONE_ID,
                "request_id": "req-b0qqv-sdk-http",
                "host": TARGET_HOST,
                "port": 443,
                "transport": "https",
                "decision": "allow",
                "deny_reason": null,
                "elapsed_ms": http_response.egress.elapsed_ms,
                "proxy_endpoint_path": http_capture.path,
                "captured_proxy_requests": 1,
                "target_reached_directly": false,
                "runtime_network_enforcement": "host_egress_proxy",
                "serialized_fields": {
                    "credential_id_present": true,
                    "request_id_preserved": true,
                    "correlation_id_preserved": true,
                    "headers_preserved": true,
                    "body_base64_preserved": true
                },
                "redaction_checks": {
                    "raw_body_logged": false,
                    "credential_secret_leaked": false,
                    "token_leaked": false,
                    "pii_leaked": false
                }
            }
        }));

        let tcp_started_at = Instant::now();
        let tcp_request = tcp_request("req-b0qqv-sdk-tcp", "corr-b0qqv-sdk-tcp");
        let tcp_proxy = OneShotProxy::start_json(200, &tcp_response(&tcp_request));
        let tcp_runtime = runtime_for_proxy(&tcp_proxy);
        let tcp_client = tcp_runtime
            .host_egress_proxy_client()
            .expect("valid TCP host egress proxy configuration")
            .expect("configured TCP host egress client");
        let tcp_response = tcp_client
            .tcp(&tcp_request)
            .await
            .expect("TCP helper must route through proxy");
        let tcp_capture = tcp_proxy.capture();

        assert_eq!(tcp_capture.method, "POST");
        assert_eq!(tcp_capture.path, "/rpc/egress/tcp");
        assert_eq!(tcp_capture.body["host"], TARGET_HOST);
        assert_eq!(tcp_capture.body["port"], 443);
        assert_eq!(tcp_capture.body["tls"], true);
        assert_eq!(tcp_capture.body["sni_override"], TARGET_HOST);
        assert_eq!(tcp_capture.body["read_limit_bytes"], 4096);
        assert_eq!(tcp_capture.body["credential_id"], CREDENTIAL_ID_SENTINEL);
        assert_eq!(
            tcp_capture.body["context"]["request_id"],
            "req-b0qqv-sdk-tcp"
        );
        assert_eq!(
            tcp_capture.body["context"]["correlation_id"],
            "corr-b0qqv-sdk-tcp"
        );
        assert_eq!(
            tcp_capture.body["context"]["resource_uri"],
            "fcp-test://host-egress/socket.exchange"
        );
        assert_eq!(
            tcp_capture.body["write"],
            "base64:Ym9keS1iMHFxdi1yZWRhY3Rpb24tc2VudGluZWw="
        );
        assert_eq!(tcp_response.read.as_bytes(), b"PONG");
        assert_eq!(tcp_response.egress.request_id, "req-b0qqv-sdk-tcp");

        emit_jsonl_record(&json!({
            "timestamp": timestamp(),
            "test_name": "br_b0qqv_sdk_host_egress_proxy_e2e_jsonl_matrix",
            "module": "fcp-sdk",
            "phase": "sdk_host_egress_proxy",
            "scenario_id": "sdk_tls_tcp_proxy_routing",
            "correlation_id": "corr-b0qqv-sdk-tcp",
            "result": "pass",
            "duration_ms": elapsed_ms(tcp_started_at),
            "assertions": {"passed": 13, "failed": 0},
            "details": {
                "connector_id": CONNECTOR_ID,
                "operation": "socket.exchange",
                "zone_id": ZONE_ID,
                "request_id": "req-b0qqv-sdk-tcp",
                "host": TARGET_HOST,
                "port": 443,
                "transport": "tcp_tls",
                "decision": "allow",
                "deny_reason": null,
                "elapsed_ms": tcp_response.egress.elapsed_ms,
                "proxy_endpoint_path": tcp_capture.path,
                "captured_proxy_requests": 1,
                "target_reached_directly": false,
                "runtime_network_enforcement": "host_egress_proxy",
                "serialized_fields": {
                    "sni_preserved": true,
                    "request_id_preserved": true,
                    "correlation_id_preserved": true,
                    "read_limit_preserved": true,
                    "binary_write_base64_preserved": true
                },
                "redaction_checks": {
                    "raw_write_logged": false,
                    "credential_secret_leaked": false,
                    "token_leaked": false,
                    "pii_leaked": false
                }
            }
        }));
    })
    .expect("SDK host-egress proxy loopback matrix must complete");
}

struct DenialCase {
    reason: &'static str,
    status: u16,
    use_tcp: bool,
}

#[test]
fn host_egress_proxy_endpoint_validation_accepts_only_literal_loopback_origins() {
    for endpoint in [
        "http://127.0.0.1",
        "http://127.42.0.9:7878/",
        "https://[::1]",
        "https://[::1]:9443/",
    ] {
        HostEgressProxyClient::new(endpoint).expect("literal loopback origin must be accepted");
    }

    for endpoint in [
        "not a url",
        "ftp://127.0.0.1",
        "http://localhost:7878",
        "http://192.0.2.10:7878",
        "http://127.0.0.1:7878/path",
        "http://127.0.0.1:7878?query=value",
        "http://127.0.0.1:7878#fragment",
        "http://user@127.0.0.1:7878",
        "http://user:password@127.0.0.1:7878",
    ] {
        let error = HostEgressProxyClient::new(endpoint)
            .expect_err("unsafe or malformed proxy endpoint must be rejected");
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(endpoint));
        assert!(matches!(
            error,
            HostEgressProxyConfigError::InvalidEndpoint
                | HostEgressProxyConfigError::NonLoopbackEndpoint
        ));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn host_egress_inherited_wire_envelopes_are_typed_and_redacted() {
    let request = HostEgressWireRequest {
        schema_version: HOST_EGRESS_WIRE_SCHEMA_VERSION,
        request_id: 41,
        auth_token: AUTH_TOKEN_SENTINEL.to_string(),
        route: HostEgressWireRoute::Http,
        payload: HostEgressWireRequestPayload::Http(http_request(
            "req-b0qqv-wire",
            "corr-b0qqv-wire",
        )),
    };
    let encoded = serde_json::to_value(&request).expect("serialize inherited wire request");
    assert_eq!(encoded["schema_version"], HOST_EGRESS_WIRE_SCHEMA_VERSION);
    assert_eq!(encoded["request_id"], 41);
    assert_eq!(encoded["route"], "HTTP");
    assert_eq!(encoded["auth_token"], AUTH_TOKEN_SENTINEL);
    assert_eq!(encoded["payload"]["kind"], "HTTP");
    let debug = format!("{request:?}");
    assert!(!debug.contains(AUTH_TOKEN_SENTINEL));
    assert!(!debug.contains(TARGET_URL));

    let response = HostEgressWireResponse {
        schema_version: HOST_EGRESS_WIRE_SCHEMA_VERSION,
        request_id: 41,
        route: HostEgressWireRoute::Http,
        status: 200,
        body: Some(HostEgressWireResponseBody::Http(HostEgressHttpResponse {
            status: 200,
            headers: Vec::new(),
            body: Base64Bytes::from_vec(b"ok".to_vec()),
            egress: decision_metadata(&http_request("op", "req").context, TARGET_HOST, 443),
        })),
        error: None,
    };
    let response_encoded =
        serde_json::to_value(response).expect("serialize inherited wire response");
    assert_eq!(response_encoded["body"]["kind"], "HTTP");
    let decoded: HostEgressWireResponse =
        serde_json::from_value(response_encoded).expect("decode inherited wire response");
    assert_eq!(decoded.request_id, 41);
    assert_eq!(decoded.route, HostEgressWireRoute::Http);

    let tcp = HostEgressWireRequest {
        schema_version: HOST_EGRESS_WIRE_SCHEMA_VERSION,
        request_id: 42,
        auth_token: AUTH_TOKEN_SENTINEL.to_string(),
        route: HostEgressWireRoute::Tcp,
        payload: HostEgressWireRequestPayload::Tcp(tcp_request(
            "req-b0qqv-wire-tcp",
            "corr-b0qqv-wire-tcp",
        )),
    };
    let mut tcp_encoded = serde_json::to_value(&tcp).expect("serialize TCP wire request");
    assert_eq!(tcp_encoded["route"], "TCP");
    assert_eq!(tcp_encoded["payload"]["kind"], "TCP");
    assert!(tcp_encoded["payload"]["value"]["host"].is_string());
    tcp_encoded["unexpected"] = json!(true);
    assert!(serde_json::from_value::<HostEgressWireRequest>(tcp_encoded).is_err());
    let tcp_debug = format!("{tcp:?}");
    assert!(!tcp_debug.contains(AUTH_TOKEN_SENTINEL));
}

#[cfg(target_os = "linux")]
#[test]
fn host_egress_proxy_unix_socket_routes_http_and_tcp_with_auth_header() {
    fcp_async_core::runtime::block_on_sync(async {
        let http_request = http_request("req-b0qqv-uds-http", "corr-b0qqv-uds-http");
        let http_proxy = OneShotUnixProxy::start_json(200, &http_response(&http_request));
        let socket_path = http_proxy.socket_path().to_path_buf();
        let http_client = HostEgressProxyClient::from_unix_socket(
            socket_path.clone(),
            AUTH_TOKEN_SENTINEL,
            HostEgressProxyLimits::default(),
        )
        .expect("valid Unix host egress client");
        assert_eq!(
            http_client.transport(),
            HostEgressTransport::UnixDomainSocket
        );
        assert_eq!(
            http_client.http_endpoint(),
            "http://fcp-host-egress.invalid/rpc/egress/http"
        );
        let rendered = format!("{http_client:?}");
        assert!(!rendered.contains(AUTH_TOKEN_SENTINEL));
        assert!(!rendered.contains(socket_path.to_string_lossy().as_ref()));
        let http_response = http_client
            .http(&http_request)
            .await
            .expect("UDS HTTP request must succeed");
        let http_capture = http_proxy.capture();
        assert_eq!(http_capture.path, "/rpc/egress/http");
        assert_eq!(
            http_capture.auth_header.as_deref(),
            Some(AUTH_TOKEN_SENTINEL)
        );
        assert_eq!(http_response.status, 202);

        let tcp_request = tcp_request("req-b0qqv-uds-tcp", "corr-b0qqv-uds-tcp");
        let tcp_proxy = OneShotUnixProxy::start_json(200, &tcp_response(&tcp_request));
        let tcp_client = HostEgressProxyClient::from_unix_socket(
            tcp_proxy.socket_path().to_path_buf(),
            AUTH_TOKEN_SENTINEL,
            HostEgressProxyLimits::default(),
        )
        .expect("valid Unix host egress TCP client");
        assert_eq!(
            tcp_client.tcp_endpoint(),
            "http://fcp-host-egress.invalid/rpc/egress/tcp"
        );
        let tcp_response = tcp_client
            .tcp(&tcp_request)
            .await
            .expect("UDS TCP request must succeed");
        let tcp_capture = tcp_proxy.capture();
        assert_eq!(tcp_capture.path, "/rpc/egress/tcp");
        assert_eq!(
            tcp_capture.auth_header.as_deref(),
            Some(AUTH_TOKEN_SENTINEL)
        );
        assert_eq!(tcp_response.read.as_bytes(), b"PONG");
    })
    .expect("UDS host-egress success matrix must complete");
}

#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::too_many_lines)]
fn host_egress_proxy_unix_socket_rejects_unsafe_paths_and_tokens() {
    let relative = HostEgressProxyClient::from_unix_socket(
        PathBuf::from("relative.sock"),
        AUTH_TOKEN_SENTINEL,
        HostEgressProxyLimits::default(),
    )
    .expect_err("relative socket path must fail");
    assert!(matches!(
        relative,
        HostEgressProxyConfigError::InvalidSocketPath
    ));

    let nul_path = PathBuf::from(std::ffi::OsString::from_vec(
        b"/tmp/fcp-sdk-egress\0.sock".to_vec(),
    ));
    let nul = HostEgressProxyClient::from_unix_socket(
        nul_path,
        AUTH_TOKEN_SENTINEL,
        HostEgressProxyLimits::default(),
    )
    .expect_err("NUL socket path must fail");
    assert!(matches!(nul, HostEgressProxyConfigError::InvalidSocketPath));

    let (listener, socket_path, parent_path) = validation_socket(0o700, 0o600);
    let missing_path = parent_path.join("missing.sock");
    let missing = HostEgressProxyClient::from_unix_socket(
        missing_path,
        AUTH_TOKEN_SENTINEL,
        HostEgressProxyLimits::default(),
    )
    .expect_err("missing socket must fail");
    assert!(matches!(
        missing,
        HostEgressProxyConfigError::SocketNotFound
    ));

    let symlink_path = parent_path.join("symlink.sock");
    std::os::unix::fs::symlink(&socket_path, &symlink_path).expect("create socket symlink");
    let symlink = HostEgressProxyClient::from_unix_socket(
        symlink_path.clone(),
        AUTH_TOKEN_SENTINEL,
        HostEgressProxyLimits::default(),
    )
    .expect_err("socket symlink must fail");
    assert!(matches!(symlink, HostEgressProxyConfigError::SocketSymlink));
    let _ = fs::remove_file(&symlink_path);

    let regular_path = parent_path.join("regular-file");
    fs::write(&regular_path, b"not a socket").expect("create regular validation file");
    fs::set_permissions(&regular_path, Permissions::from_mode(0o600))
        .expect("set regular validation file mode");
    let regular = HostEgressProxyClient::from_unix_socket(
        regular_path.clone(),
        AUTH_TOKEN_SENTINEL,
        HostEgressProxyLimits::default(),
    )
    .expect_err("regular file must fail as a Unix socket");
    assert!(matches!(
        regular,
        HostEgressProxyConfigError::SocketNotSocket
    ));
    let _ = fs::remove_file(&regular_path);

    fs::set_permissions(&socket_path, Permissions::from_mode(0o666))
        .expect("make socket mode unsafe");
    let wrong_mode = HostEgressProxyClient::from_unix_socket(
        socket_path.clone(),
        AUTH_TOKEN_SENTINEL,
        HostEgressProxyLimits::default(),
    )
    .expect_err("unsafe socket mode must fail");
    assert!(matches!(
        wrong_mode,
        HostEgressProxyConfigError::SocketPermissions
    ));
    drop(listener);
    cleanup_validation_socket(&socket_path, &parent_path);

    let (listener, socket_path, parent_path) = validation_socket(0o755, 0o600);
    let wrong_parent_mode = HostEgressProxyClient::from_unix_socket(
        socket_path.clone(),
        AUTH_TOKEN_SENTINEL,
        HostEgressProxyLimits::default(),
    )
    .expect_err("public socket parent must fail");
    assert!(matches!(
        wrong_parent_mode,
        HostEgressProxyConfigError::SocketPermissions
    ));
    drop(listener);
    cleanup_validation_socket(&socket_path, &parent_path);

    let (listener, valid_socket, valid_parent) = validation_socket(0o700, 0o600);
    let empty_token = HostEgressProxyClient::from_unix_socket(
        valid_socket.clone(),
        "",
        HostEgressProxyLimits::default(),
    )
    .expect_err("empty auth token must fail");
    assert!(matches!(
        empty_token,
        HostEgressProxyConfigError::InvalidAuthToken
    ));
    let control_token = HostEgressProxyClient::from_unix_socket(
        valid_socket.clone(),
        "token\nwith-control",
        HostEgressProxyLimits::default(),
    )
    .expect_err("control auth token must fail");
    assert!(matches!(
        control_token,
        HostEgressProxyConfigError::InvalidAuthToken
    ));
    let oversized_token = "x".repeat(4097);
    let oversized_token_error = HostEgressProxyClient::from_unix_socket(
        valid_socket.clone(),
        &oversized_token,
        HostEgressProxyLimits::default(),
    )
    .expect_err("oversized auth token must fail");
    let rendered = format!("{oversized_token_error:?} {oversized_token_error}");
    assert!(!rendered.contains(&oversized_token));
    drop(listener);
    cleanup_validation_socket(&valid_socket, &valid_parent);
}

#[cfg(target_os = "linux")]
#[test]
fn host_egress_proxy_unix_socket_bounds_and_redacts_transport_errors() {
    fcp_async_core::runtime::block_on_sync(async {
        let request = http_request("req-b0qqv-uds-bounds", "corr-b0qqv-uds-bounds");
        let limits = HostEgressProxyLimits {
            request_timeout: Duration::from_millis(25),
            max_outer_envelope_bytes: 128,
        };

        let malformed = OneShotUnixProxy::start_malformed("not-json".to_string());
        let malformed_path = malformed.socket_path().to_path_buf();
        let client =
            HostEgressProxyClient::from_unix_socket(malformed_path, AUTH_TOKEN_SENTINEL, limits)
                .expect("valid malformed-response UDS client");
        let error = client
            .http(&request)
            .await
            .expect_err("malformed JSON must fail");
        assert!(matches!(error, HostEgressProxyError::MalformedEnvelope));
        malformed.capture();

        let oversized = OneShotUnixProxy::start_oversized("x".repeat(129));
        let client = HostEgressProxyClient::from_unix_socket(
            oversized.socket_path().to_path_buf(),
            AUTH_TOKEN_SENTINEL,
            limits,
        )
        .expect("valid oversized-response UDS client");
        let error = client
            .http(&request)
            .await
            .expect_err("oversized body must fail");
        assert!(matches!(error, HostEgressProxyError::EnvelopeTooLarge));
        oversized.capture();

        let delayed = OneShotUnixProxy::start_delayed(
            serde_json::to_string(&http_response(&request)).expect("serialize delayed response"),
            Duration::from_millis(100),
        );
        let socket_path = delayed.socket_path().to_path_buf();
        let client = HostEgressProxyClient::from_unix_socket(
            socket_path.clone(),
            AUTH_TOKEN_SENTINEL,
            limits,
        )
        .expect("valid delayed-response UDS client");
        let error = client
            .http(&request)
            .await
            .expect_err("delayed response must time out");
        assert!(matches!(error, HostEgressProxyError::Transport(_)));
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(AUTH_TOKEN_SENTINEL));
        assert!(!rendered.contains(socket_path.to_string_lossy().as_ref()));
        delayed.finish();
    })
    .expect("UDS bound-error matrix must complete");
}

#[test]
fn host_egress_proxy_enforces_timeout_and_outer_envelope_limits() {
    fcp_async_core::runtime::block_on_sync(async {
        let request = http_request("req-b0qqv-bounds", "corr-b0qqv-bounds");
        let limits = HostEgressProxyLimits {
            request_timeout: Duration::from_millis(25),
            max_outer_envelope_bytes: 128,
        };

        let delayed = OneShotProxy::start_delayed(
            200,
            serde_json::to_string(&http_response(&request)).expect("serialize response"),
            Duration::from_millis(100),
        );
        let client = HostEgressProxyClient::with_limits(delayed.base_url(), limits)
            .expect("valid bounded client");
        let timeout = client
            .http(&request)
            .await
            .expect_err("proxy wait budget must be enforced");
        assert!(matches!(timeout, HostEgressProxyError::Transport(_)));
        delayed.finish();

        for status in [200, 403] {
            let oversized = OneShotProxy::start(status, "x".repeat(129), "application/json");
            let client = HostEgressProxyClient::with_limits(oversized.base_url(), limits)
                .expect("valid bounded client");
            let error = client
                .http(&request)
                .await
                .expect_err("Content-Length above outer-envelope limit must fail");
            assert!(matches!(error, HostEgressProxyError::EnvelopeTooLarge));
            oversized.capture();
        }

        let streamed = OneShotProxy::start_without_content_length(200, "x".repeat(129));
        let client = HostEgressProxyClient::with_limits(streamed.base_url(), limits)
            .expect("valid bounded client");
        let error = client
            .http(&request)
            .await
            .expect_err("streamed body above outer-envelope limit must fail");
        assert!(matches!(error, HostEgressProxyError::EnvelopeTooLarge));
        streamed.capture();
    })
    .expect("bounded proxy tests must complete");
}

#[test]
fn host_egress_proxy_rejects_oversized_request_before_transport() {
    fcp_async_core::runtime::block_on_sync(async {
        let mut request = http_request("req-b0qqv-request-bound", "corr-b0qqv-request-bound");
        request.body = Some(Base64Bytes::from_vec(vec![b'x'; 12 * 1024 * 1024]));
        let client = HostEgressProxyClient::new("http://127.0.0.1:9")
            .expect("literal loopback compatibility client");
        let error = client
            .http(&request)
            .await
            .expect_err("oversized request must fail before transport");
        assert!(matches!(
            error,
            HostEgressProxyError::RequestEnvelopeTooLarge
        ));
    })
    .expect("request-envelope bound test must complete");
}

#[test]
#[allow(clippy::too_many_lines)]
fn host_egress_proxy_denied_decision_matrix_surfaces_structured_redacted_errors() {
    fcp_async_core::runtime::block_on_sync(async {
        let started_at = Instant::now();
        let cases = [
            DenialCase {
                reason: "denied_host",
                status: 403,
                use_tcp: false,
            },
            DenialCase {
                reason: "denied_port",
                status: 403,
                use_tcp: false,
            },
            DenialCase {
                reason: "denied_private_ip",
                status: 403,
                use_tcp: false,
            },
            DenialCase {
                reason: "denied_sni_spki",
                status: 403,
                use_tcp: true,
            },
            DenialCase {
                reason: "credential_denied",
                status: 403,
                use_tcp: false,
            },
            DenialCase {
                reason: "timeout",
                status: 504,
                use_tcp: false,
            },
            DenialCase {
                reason: "response_size",
                status: 413,
                use_tcp: false,
            },
        ];
        let mut statuses = Vec::new();
        let mut reasons = Vec::new();
        let mut paths = Vec::new();

        for case in cases {
            let body = if case.use_tcp {
                format!(
                    "deny_reason={}; capability_material={CAPABILITY_MATERIAL_SENTINEL}; credential={CREDENTIAL_ID_SENTINEL}; payload={BODY_SENTINEL}",
                    case.reason
                )
            } else {
                format!(
                    "deny_reason={}; capability_material={CAPABILITY_MATERIAL_SENTINEL}; credential={CREDENTIAL_ID_SENTINEL}; header={HEADER_SENTINEL}; payload={BODY_SENTINEL}; url={TARGET_URL}",
                    case.reason
                )
            };
            let proxy = OneShotProxy::start_text(case.status, body);
            let runtime = runtime_for_proxy(&proxy);
            let client = runtime
                .host_egress_proxy_client()
                .expect("valid denial proxy configuration")
                .expect("configured denial proxy client");

            let error = if case.use_tcp {
                let request = tcp_request("req-b0qqv-denied-tcp", "corr-b0qqv-denied");
                client
                    .tcp(&request)
                    .await
                    .expect_err("TCP denial must surface as proxy rejection")
            } else {
                let request = http_request("req-b0qqv-denied-http", "corr-b0qqv-denied");
                client
                    .http(&request)
                    .await
                    .expect_err("HTTP denial must surface as proxy rejection")
            };
            let captured = proxy.capture();
            let rejection_body = assert_rejected(&error, case.status, case.reason);
            assert_no_secret_material(&rejection_body);
            statuses.push(json!({"reason": case.reason, "status": case.status}));
            reasons.push(case.reason);
            paths.push(captured.path);
        }

        emit_jsonl_record(&json!({
            "timestamp": timestamp(),
            "test_name": "br_b0qqv_sdk_host_egress_proxy_e2e_jsonl_matrix",
            "module": "fcp-sdk",
            "phase": "sdk_host_egress_proxy",
            "scenario_id": "sdk_denied_structured_error",
            "correlation_id": "corr-b0qqv-denied",
            "result": "pass",
            "duration_ms": elapsed_ms(started_at),
            "assertions": {"passed": 28, "failed": 0},
            "details": {
                "connector_id": CONNECTOR_ID,
                "operation": "messages.create",
                "zone_id": ZONE_ID,
                "request_id": "req-b0qqv-denied-http",
                "host": TARGET_HOST,
                "port": 443,
                "transport": "https_and_tcp_tls",
                "decision": "deny",
                "deny_reason": "matrix",
                "denied_cases": reasons,
                "statuses": statuses,
                "proxy_endpoint_paths": paths,
                "elapsed_ms": elapsed_ms(started_at),
                "structured_error_fields": ["status", "redacted_body"],
                "runtime_network_enforcement": "host_egress_proxy"
            }
        }));

        emit_jsonl_record(&json!({
            "timestamp": timestamp(),
            "test_name": "br_b0qqv_sdk_host_egress_proxy_e2e_jsonl_matrix",
            "module": "fcp-sdk",
            "phase": "sdk_host_egress_proxy",
            "scenario_id": "sdk_redaction_scan",
            "correlation_id": "corr-b0qqv-redaction-scan",
            "result": "pass",
            "duration_ms": elapsed_ms(started_at),
            "assertions": {"passed": 7, "failed": 0},
            "details": {
                "connector_id": CONNECTOR_ID,
                "operation": "messages.create",
                "zone_id": ZONE_ID,
                "request_id": "req-b0qqv-denied-http",
                "host": TARGET_HOST,
                "port": 443,
                "transport": "https_and_tcp_tls",
                "decision": "deny",
                "deny_reason": "redaction_scan",
                "secret_sentinels_absent": true,
                "checked_error_count": 7,
                "checked_fields": [
                    "capability_token",
                    "credential_id",
                    "authorization_header",
                    "request_body",
                    "base64_body",
                    "target_url",
                    "query_token"
                ],
                "elapsed_ms": elapsed_ms(started_at)
            }
        }));
    })
    .expect("SDK host-egress denial matrix must complete");
}

fn assert_rejected(error: &HostEgressProxyError, status: u16, reason: &str) -> String {
    assert_eq!(error.status(), Some(status));
    let body = error
        .rejection_body()
        .expect("rejection body must be present")
        .to_string();
    assert!(
        body.contains(&format!("deny_reason={reason}")),
        "rejection body should keep actionable reason {reason}: {body}"
    );
    body
}
