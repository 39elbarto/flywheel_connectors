use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fcp_crypto::{SecretFetchError, SecretFetchHook, ZeroizingSecret};
use fcp_host::{
    RuntimeEgressDecisionContext, RuntimeNetworkEnforcement, authorize_runtime_http_egress,
};
use fcp_manifest::NetworkConstraints;
use fcp_sandbox::{EgressHttpRequest, HttpHeader, SecretFetchCredentialInjector};

struct MockOrigin {
    addr: SocketAddr,
    observed: Receiver<Result<String, String>>,
    handle: JoinHandle<()>,
}

impl MockOrigin {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind gmail mock origin");
        let addr = listener.local_addr().expect("mock origin address");
        let (sender, observed) = mpsc::channel();
        let handle = thread::spawn(move || {
            let result = serve_one_origin(&listener).map_err(|error| error.to_string());
            let _ = sender.send(result);
        });
        Self {
            addr,
            observed,
            handle,
        }
    }

    fn url(&self) -> String {
        format!(
            "http://127.0.0.1:{}/gmail/v1/users/me/messages",
            self.addr.port()
        )
    }

    fn observed_request(self) -> String {
        let observed = self
            .observed
            .recv_timeout(Duration::from_secs(5))
            .expect("gmail mock origin must capture a request")
            .expect("gmail mock origin request must parse");
        self.handle.join().expect("mock origin thread must finish");
        observed
    }
}

fn serve_one_origin(listener: &TcpListener) -> std::io::Result<String> {
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let observed = read_http_request(&mut stream)?;
    let body = br#"{"messages":[]}"#;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(observed)
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut header_bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while !header_bytes.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        header_bytes.push(byte[0]);
        assert!(
            header_bytes.len() <= 16_384,
            "HTTP request headers too large"
        );
    }
    let headers = String::from_utf8_lossy(&header_bytes).into_owned();
    let content_length = content_length_from_headers(&headers);
    let mut body = vec![0_u8; content_length];
    stream.read_exact(&mut body)?;
    Ok(format!("{}{}", headers, String::from_utf8_lossy(&body)))
}

fn content_length_from_headers(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("valid content-length"))
        })
        .unwrap_or(0)
}

struct SingleSecretHook {
    credential_id: &'static str,
    secret: &'static str,
    fetch_count: AtomicU64,
}

impl SingleSecretHook {
    fn new(credential_id: &'static str, secret: &'static str) -> Self {
        Self {
            credential_id,
            secret,
            fetch_count: AtomicU64::new(0),
        }
    }

    fn fetch_count(&self) -> u64 {
        self.fetch_count.load(Ordering::Relaxed)
    }
}

impl SecretFetchHook for SingleSecretHook {
    fn fetch(&self, credential_id: &str) -> Result<ZeroizingSecret, SecretFetchError> {
        self.fetch_count.fetch_add(1, Ordering::Relaxed);
        if credential_id == self.credential_id {
            Ok(ZeroizingSecret::from(self.secret))
        } else {
            Err(SecretFetchError::not_found(credential_id))
        }
    }

    fn rotate(
        &self,
        _credential_id: &str,
        _new_secret: ZeroizingSecret,
    ) -> Result<(), SecretFetchError> {
        Err(SecretFetchError::backend("read-only smoke hook"))
    }

    fn revoke(&self, _credential_id: &str) -> Result<(), SecretFetchError> {
        Err(SecretFetchError::backend("read-only smoke hook"))
    }
}

fn constraints_for(host: &str, port: u16) -> NetworkConstraints {
    NetworkConstraints {
        host_allow: vec![host.to_string()],
        port_allow: vec![port],
        ip_allow: vec![],
        cidr_deny: vec![],
        deny_localhost: false,
        deny_private_ranges: false,
        deny_tailnet_ranges: false,
        require_sni: false,
        spki_pins: vec![],
        deny_ip_literals: false,
        require_host_canonicalization: true,
        dns_max_ips: 16,
        max_redirects: 5,
        connect_timeout_ms: 10_000,
        total_timeout_ms: 60_000,
        max_response_bytes: 1_048_576,
    }
}

fn send_authorized_request(request: &EgressHttpRequest) {
    let method = reqwest::Method::from_bytes(request.method.as_bytes()).expect("valid HTTP method");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let mut outbound = client.request(method, &request.url);
    for header in &request.headers {
        outbound = outbound.header(&header.name, &header.value);
    }
    if let Some(body) = &request.body {
        outbound = outbound.body(body.clone());
    }
    let response = outbound
        .send()
        .expect("authorized gmail request reaches mock origin");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

fn runtime_context<'a>(
    operation: &'a str,
    credential_allow: &'a [String],
) -> RuntimeEgressDecisionContext<'a> {
    RuntimeEgressDecisionContext {
        connector_id: "fcp.gmail",
        operation,
        zone_id: "z:work",
        request_id: "req-secretless-gmail",
        correlation_id: Some("corr-secretless-gmail"),
        execution_mode: RuntimeNetworkEnforcement::HostEgressProxy,
        constraint_source: "secretless-gmail-smoke",
        credential_allow,
    }
}

#[test]
fn gmail_credential_id_request_gets_oauth_bearer_at_egress_boundary() {
    let origin = MockOrigin::start();
    let credential_id = "00000000-0000-0000-0000-000000000042";
    let secret = "ya29.secretless-smoke";
    let hook = Arc::new(SingleSecretHook::new(credential_id, secret));
    let injector = SecretFetchCredentialInjector::new(hook.clone())
        .with_allowed_hosts(credential_id, ["127.0.0.1"]);
    let mut request = EgressHttpRequest {
        url: origin.url(),
        method: "GET".into(),
        headers: vec![HttpHeader {
            name: "x-fcp-credential-id".into(),
            value: credential_id.into(),
        }],
        body: None,
        credential_id: Some(credential_id.into()),
    };

    assert!(
        !request.headers.iter().any(|header| header.value == secret),
        "connector-visible request must not contain raw secret bytes"
    );

    let constraints = constraints_for("127.0.0.1", origin.addr.port());
    let credential_allow = vec![credential_id.into()];
    let context = runtime_context("gmail.list_messages", &credential_allow);
    let decision = authorize_runtime_http_egress(&context, &constraints, &mut request, &injector)
        .expect("gmail egress request is authorized");

    assert!(decision.credential_injected);
    assert_eq!(hook.fetch_count(), 1);
    assert!(request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("authorization")
            && header.value == format!("Bearer {secret}")
    }));
    assert!(
        !request
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("x-fcp-credential-id")),
        "egress boundary must strip connector-local credential id header before origin transport"
    );

    send_authorized_request(&request);
    let observed = origin.observed_request();
    let observed_lower = observed.to_ascii_lowercase();
    assert!(observed_lower.contains("authorization: bearer ya29.secretless-smoke"));
    assert!(!observed_lower.contains("x-fcp-credential-id"));
}
