//! Local loopback acceptance coverage for the `Mixpanel` HTTP boundary.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fcp_mixpanel::client::{MixpanelAuth, MixpanelClient};
use serde_json::json;

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const USERNAME: &str = "svc_local";
const SECRET: &str = "secret_local";
const AUTH_HEADER: &str = "Basic c3ZjX2xvY2FsOnNlY3JldF9sb2NhbA==";
const PROJECT_ID: &str = "12345";
const RESPONSE_BODY: &str = r#"[
  {
    "funnel_id": 101,
    "name": "Local Acceptance Funnel"
  }
]"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    headers: Vec<String>,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

impl LoopbackFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connector request");
            handle_request(stream)
        });

        Self {
            base_url: format!("http://{address}"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> FixtureObservation {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_request(mut stream: TcpStream) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let raw = read_http_headers(&mut stream);
    let request = String::from_utf8_lossy(&raw);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers = lines.map(str::to_string).collect::<Vec<_>>();

    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        RESPONSE_BODY.len(),
        RESPONSE_BODY
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        headers,
    }
}

fn read_http_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return request;
        }
        assert!(request.len() < 8192, "request should stay bounded");
    }
}

fn has_header(headers: &[String], name: &str, expected_value: &str) -> bool {
    headers.iter().any(|line| {
        let Some((actual_name, actual_value)) = line.split_once(':') else {
            return false;
        };
        actual_name.eq_ignore_ascii_case(name) && actual_value.trim() == expected_value
    })
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_list_funnels_uses_loopback_api_boundary() {
    let fixture = LoopbackFixture::start();
    let client = MixpanelClient::new(
        MixpanelAuth::ServiceAccount {
            username: USERNAME.into(),
            secret: SECRET.into(),
        },
        PROJECT_ID,
        Some(fixture.base_url()),
    )
    .expect("construct Mixpanel client");

    let response = client
        .list_funnels()
        .await
        .expect("list funnels through loopback fixture");
    client.shutdown();
    let observation = fixture.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert_eq!(
        observation.request_line,
        "GET /funnels/list?project_id=12345 HTTP/1.1"
    );
    assert!(has_header(
        &observation.headers,
        "authorization",
        AUTH_HEADER
    ));
    assert!(has_header(
        &observation.headers,
        "accept",
        "application/json"
    ));
    assert!(has_header(
        &observation.headers,
        "user-agent",
        "fcp-mixpanel/0.1.0 (FCP connector)"
    ));
    assert_eq!(response[0]["funnel_id"], 101);
    assert_eq!(response[0]["name"], "Local Acceptance Funnel");

    let artifact = json!({
        "connector": "mixpanel",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": "flywheel_connectors-bky21.4.6.2",
        "command": "cargo test -p fcp-mixpanel --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "sandbox_required",
        "request_response_boundary": {
            "method": "GET",
            "path": "/funnels/list",
            "query": ["project_id=12345"]
        },
        "auth_gate": {
            "mode": "basic_service_account",
            "credentials_used": true,
            "authorization_header_verified": true
        },
        "cleanup": "client_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
