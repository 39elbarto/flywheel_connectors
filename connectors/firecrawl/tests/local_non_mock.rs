//! Local loopback acceptance coverage for the Firecrawl connector.

#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fcp_firecrawl::FirecrawlConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};

const CONNECTOR: &str = "firecrawl";
const PACKAGE: &str = "fcp-firecrawl";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.6";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const OP_SEARCH: &str = "firecrawl.search";
const OP_SCRAPE: &str = "firecrawl.scrape";

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    headers: Vec<String>,
    body: Value,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

impl LoopbackFixture {
    fn start(status: u16, response_body: &Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let response_body = response_body.to_string();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connector request");
            handle_request(stream, status, &response_body)
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

fn handle_request(mut stream: TcpStream, status: u16, response_body: &str) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let request = read_http_request(&mut stream);
    let request_text = String::from_utf8_lossy(&request);
    let (head, body) = request_text
        .split_once("\r\n\r\n")
        .expect("request contains header terminator");
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers = lines.map(str::to_string).collect::<Vec<_>>();
    let body = serde_json::from_str(body).expect("request body is JSON");

    write!(
        stream,
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        status,
        reason_phrase(status),
        response_body.len(),
        response_body
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        headers,
        body,
    }
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];

    loop {
        let bytes_read = stream.read(&mut buffer).expect("read request headers");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        assert!(
            request.len() < 16_384,
            "request headers should stay bounded"
        );
    }

    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header terminator present")
        + 4;
    let header_text = String::from_utf8_lossy(&request[..header_end]);
    let content_length = header_text
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("valid content-length"))
        })
        .unwrap_or(0);

    while request.len() - header_end < content_length {
        let bytes_read = stream.read(&mut buffer).expect("read request body");
        assert!(bytes_read > 0, "connector body should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);
        assert!(request.len() < 65_536, "request body should stay bounded");
    }

    request
}

const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        _ => "Status",
    }
}

fn has_header(headers: &[String], name: &str, value: &str) -> bool {
    let expected = format!("{name}: {value}");
    headers
        .iter()
        .any(|header| header.eq_ignore_ascii_case(&expected))
}

async fn configured_connector(base_url: &str, api_key: &str) -> FirecrawlConnector {
    let mut connector = FirecrawlConnector::new();
    connector
        .handle_configure(json!({
            "api_key": api_key,
            "base_url": base_url,
            "request_timeout_ms": 5_000
        }))
        .await
        .expect("configure Firecrawl connector against loopback fixture");
    connector
        .handle_handshake(json!({ "session_id": "firecrawl-local-non-mock" }))
        .await
        .expect("handshake Firecrawl connector");
    connector
}

fn print_artifact(case_name: &str, request_response_boundary: &Value, auth_gate: &Value) {
    let artifact = json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "case": case_name,
        "command": "cargo test -p fcp-firecrawl --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundary": request_response_boundary,
        "auth_gate": auth_gate,
        "cleanup": "loopback_fixture_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_search_posts_v2_body_and_returns_results() {
    let fixture = LoopbackFixture::start(
        200,
        &json!({
            "success": true,
            "data": {
                "web": [
                    {
                        "url": "https://docs.firecrawl.dev",
                        "title": "Firecrawl Docs",
                        "description": "Firecrawl documentation"
                    }
                ],
                "news": []
            },
            "warning": null,
            "id": "search-local-001",
            "creditsUsed": 1
        }),
    );

    let connector = configured_connector(fixture.base_url(), "fc-local-firecrawl-key").await;
    let response = connector
        .handle_invoke(json!({
            "operation_id": OP_SEARCH,
            "input": {
                "query": " firecrawl docs ",
                "limit": 3,
                "sources": ["web", "", "news"],
                "categories": ["github"],
                "scrape_results": true,
                "timeout": 30_000,
                "country": "us",
                "location": "San Francisco,California,United States",
                "ignore_invalid_urls": true,
                "enterprise": ["anon"]
            }
        }))
        .await
        .expect("search through loopback Firecrawl boundary");
    let observation = fixture.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert_eq!(observation.request_line, "POST /v2/search HTTP/1.1");
    assert!(has_header(
        &observation.headers,
        "authorization",
        "Bearer fc-local-firecrawl-key"
    ));
    assert_eq!(observation.body["query"], "firecrawl docs");
    assert_eq!(observation.body["limit"], 3);
    assert_eq!(observation.body["sources"], json!(["web", "news"]));
    assert_eq!(observation.body["categories"], json!(["github"]));
    assert_eq!(
        observation.body["scrapeOptions"]["formats"],
        json!(["markdown"])
    );
    assert_eq!(observation.body["timeout"], 30_000);
    assert_eq!(observation.body["country"], "US");
    assert_eq!(
        observation.body["location"],
        "San Francisco,California,United States"
    );
    assert_eq!(observation.body["ignoreInvalidURLs"], true);
    assert_eq!(observation.body["enterprise"], json!(["anon"]));

    assert_eq!(response["operation"], OP_SEARCH);
    assert_eq!(response["output"]["success"], true);
    assert_eq!(response["output"]["id"], "search-local-001");
    assert_eq!(
        response["output"]["data"]["web"][0]["url"],
        "https://docs.firecrawl.dev"
    );
    assert_eq!(response["output"]["creditsUsed"], 1);

    print_artifact(
        "search_success",
        &json!({
            "method": "POST",
            "path": "/v2/search",
            "body_fields": [
                "query",
                "limit",
                "sources",
                "categories",
                "scrapeOptions",
                "timeout",
                "country",
                "location",
                "ignoreInvalidURLs",
                "enterprise"
            ],
            "response_fields": ["success", "data", "id", "creditsUsed"]
        }),
        &json!({
            "mode": "bearer",
            "credential_source": "local_fixture",
            "credential_logged": false
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_scrape_posts_v2_body_and_returns_markdown() {
    let fixture = LoopbackFixture::start(
        200,
        &json!({
            "success": true,
            "data": {
                "markdown": "# Example Domain",
                "metadata": {
                    "title": "Example Domain",
                    "sourceURL": "https://example.com",
                    "statusCode": 200
                }
            }
        }),
    );

    let connector = configured_connector(fixture.base_url(), "fc-local-firecrawl-key").await;
    let response = connector
        .handle_invoke(json!({
            "operation_id": OP_SCRAPE,
            "input": {
                "url": "https://example.com",
                "formats": ["markdown"],
                "only_main_content": false,
                "include_tags": ["main"],
                "exclude_tags": ["nav"],
                "wait_for": 50,
                "timeout": 5_000,
                "max_age_ms": 172_800_000,
                "proxy": "auto",
                "store_in_cache": false
            }
        }))
        .await
        .expect("scrape through loopback Firecrawl boundary");
    let observation = fixture.join();

    assert_eq!(observation.request_line, "POST /v2/scrape HTTP/1.1");
    assert!(has_header(
        &observation.headers,
        "authorization",
        "Bearer fc-local-firecrawl-key"
    ));
    assert_eq!(observation.body["url"], "https://example.com");
    assert_eq!(observation.body["formats"], json!(["markdown"]));
    assert_eq!(observation.body["onlyMainContent"], false);
    assert_eq!(observation.body["includeTags"], json!(["main"]));
    assert_eq!(observation.body["excludeTags"], json!(["nav"]));
    assert_eq!(observation.body["waitFor"], 50);
    assert_eq!(observation.body["timeout"], 5_000);
    assert_eq!(observation.body["maxAge"], 172_800_000);
    assert_eq!(observation.body["proxy"], "auto");
    assert_eq!(observation.body["storeInCache"], false);
    assert_eq!(response["operation"], OP_SCRAPE);
    assert_eq!(response["output"]["success"], true);
    assert_eq!(response["output"]["data"]["markdown"], "# Example Domain");
    assert_eq!(
        response["output"]["data"]["metadata"]["sourceURL"],
        "https://example.com"
    );

    print_artifact(
        "scrape_success",
        &json!({
            "method": "POST",
            "path": "/v2/scrape",
            "body_fields": [
                "url",
                "formats",
                "onlyMainContent",
                "includeTags",
                "excludeTags",
                "waitFor",
                "timeout",
                "maxAge",
                "proxy",
                "storeInCache"
            ],
            "response_fields": ["success", "data.markdown", "data.metadata"]
        }),
        &json!({
            "mode": "bearer",
            "credential_source": "local_fixture",
            "credential_logged": false
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_search_maps_provider_auth_denial_without_secret_leak() {
    let fixture = LoopbackFixture::start(
        401,
        &json!({
            "success": false,
            "error": "invalid api key"
        }),
    );

    let connector = configured_connector(fixture.base_url(), "fc-denied-firecrawl-key").await;
    let error = connector
        .handle_invoke(json!({
            "operation_id": OP_SEARCH,
            "input": {
                "query": "firecrawl docs"
            }
        }))
        .await
        .expect_err("provider auth denial should map to unauthorized");
    let observation = fixture.join();

    assert_eq!(observation.request_line, "POST /v2/search HTTP/1.1");
    assert!(has_header(
        &observation.headers,
        "authorization",
        "Bearer fc-denied-firecrawl-key"
    ));
    assert_eq!(observation.body["query"], "firecrawl docs");
    match error {
        FcpError::Unauthorized { code, message } => {
            assert_eq!(code, 2001);
            assert!(message.contains("HTTP 401"));
            assert!(!message.contains("fc-denied-firecrawl-key"));
            assert!(!message.contains("invalid api key"));
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }

    print_artifact(
        "auth_denial",
        &json!({
            "method": "POST",
            "path": "/v2/search",
            "body_fields": ["query"],
            "provider_status": 401,
            "error_mapping": "FcpError::Unauthorized"
        }),
        &json!({
            "mode": "bearer",
            "credential_source": "local_fixture",
            "credential_logged": false,
            "denial_verified": true
        }),
    );
}
