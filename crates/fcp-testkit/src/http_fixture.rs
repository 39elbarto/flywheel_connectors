//! Real local HTTP fixture harnesses for non-mock acceptance tests.
//!
//! Unlike [`crate::MockApiServer`], these fixtures run a real TCP listener and
//! speak HTTP over the network stack. That makes them useful for deterministic
//! connector acceptance tests that need real redirects, retries, uploads,
//! downloads, and timeout behavior without depending on an external `SaaS`.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Stable artifact kind for the canonical HTTP fixture contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpFixtureArtifactKind {
    /// Structured JSON payload.
    Json,
    /// JSON Lines event stream.
    Jsonl,
    /// Plain-text summary or stderr capture.
    Text,
    /// Replay script or equivalent command recipe.
    Replay,
}

/// Artifact descriptor for HTTP fixture acceptance runs.
///
/// The field names intentionally mirror `fcp-e2e`'s `E2eArtifactRecord`
/// vocabulary so downstream harnesses can map this contract without inventing a
/// second schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpFixtureArtifactDescriptor {
    /// Stable artifact label within a run report.
    pub label: String,
    /// Artifact kind (`jsonl`, `json`, `text`, `replay`, etc.).
    pub kind: HttpFixtureArtifactKind,
    /// Expected file name or bundle-relative path hint.
    pub path_hint: String,
    /// Operator-facing description of the artifact.
    pub description: String,
}

impl HttpFixtureArtifactDescriptor {
    /// Build a canonical artifact descriptor.
    #[must_use]
    pub fn new(
        label: &str,
        kind: HttpFixtureArtifactKind,
        path_hint: &str,
        description: &str,
    ) -> Self {
        Self {
            label: label.to_string(),
            kind,
            path_hint: path_hint.to_string(),
            description: description.to_string(),
        }
    }
}

/// Existing helper seam that downstream HTTP acceptance work should promote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpFixtureHelperReference {
    /// Module or crate path that already owns the behavior.
    pub symbol: String,
    /// Short explanation of why this helper should be reused.
    pub responsibility: String,
}

impl HttpFixtureHelperReference {
    /// Build a helper reference entry.
    #[must_use]
    pub fn new(symbol: &str, responsibility: &str) -> Self {
        Self {
            symbol: symbol.to_string(),
            responsibility: responsibility.to_string(),
        }
    }
}

/// Canonical scenario category for request-response acceptance coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpFixtureScenarioKind {
    /// Bearer token or header-gated access control over real HTTP.
    AuthBearer,
    /// Query-driven page or cursor traversal.
    PaginationPage,
    /// Retry-after or backoff-aware retry flow.
    RetryRateLimit,
    /// Upstream error envelope and status mapping.
    ErrorServer,
    /// Redirect handling over the real client stack.
    RedirectTemporary,
    /// Binary or opaque upload request body handling.
    UploadBinary,
    /// Binary or opaque download response handling.
    DownloadBinary,
    /// Delayed response to exercise timeout behavior.
    TimeoutDelayedResponse,
}

impl HttpFixtureScenarioKind {
    /// All canonical request-response scenarios required by the HTTP fixture contract.
    pub const ALL: [Self; 8] = [
        Self::AuthBearer,
        Self::PaginationPage,
        Self::RetryRateLimit,
        Self::ErrorServer,
        Self::RedirectTemporary,
        Self::UploadBinary,
        Self::DownloadBinary,
        Self::TimeoutDelayedResponse,
    ];

    /// Stable scenario identifier.
    #[must_use]
    pub const fn scenario_id(self) -> &'static str {
        match self {
            Self::AuthBearer => "http.auth.bearer_required",
            Self::PaginationPage => "http.pagination.query_page",
            Self::RetryRateLimit => "http.retry.rate_limit_then_success",
            Self::ErrorServer => "http.error.upstream_server_failure",
            Self::RedirectTemporary => "http.redirect.temporary_follow",
            Self::UploadBinary => "http.upload.binary_body",
            Self::DownloadBinary => "http.download.binary_body",
            Self::TimeoutDelayedResponse => "http.timeout.delayed_response",
        }
    }

    /// Canonical request method for the scenario.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::UploadBinary => "POST",
            _ => "GET",
        }
    }

    /// Stable route or route template for the scenario.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::AuthBearer => "/v1/protected",
            Self::PaginationPage => "/v1/items",
            Self::RetryRateLimit => "/v1/jobs",
            Self::ErrorServer => "/v1/failure",
            Self::RedirectTemporary => "/legacy",
            Self::UploadBinary => "/v1/upload",
            Self::DownloadBinary => "/v1/download",
            Self::TimeoutDelayedResponse => "/v1/slow",
        }
    }

    /// Short operator-facing summary for the scenario.
    #[must_use]
    pub const fn summary(self) -> &'static str {
        match self {
            Self::AuthBearer => {
                "verify header-gated auth denial and success over a real TCP listener"
            }
            Self::PaginationPage => "verify page or cursor traversal through query parameters",
            Self::RetryRateLimit => "verify retry-after handling and eventual success sequencing",
            Self::ErrorServer => "verify non-2xx status and error envelope mapping",
            Self::RedirectTemporary => {
                "verify temporary redirect following over the client transport"
            }
            Self::UploadBinary => {
                "verify opaque upload bodies and content-type-sensitive request capture"
            }
            Self::DownloadBinary => "verify opaque download bodies without JSON-only assumptions",
            Self::TimeoutDelayedResponse => {
                "verify caller timeout behavior against a deliberately delayed response"
            }
        }
    }

    const fn assertions(self) -> &'static [&'static str] {
        match self {
            Self::AuthBearer => &[
                "missing or incorrect auth is denied truthfully",
                "expected authorization header reaches the fixture unchanged",
            ],
            Self::PaginationPage => &[
                "query parameters remain observable in request order",
                "subsequent pages can return different scripted payloads",
            ],
            Self::RetryRateLimit => &[
                "429 or equivalent retry hints are observable",
                "subsequent retry succeeds without restarting the fixture",
            ],
            Self::ErrorServer => &[
                "non-2xx status codes stay visible to the caller",
                "error payloads remain available for connector-side mapping tests",
            ],
            Self::RedirectTemporary => &[
                "redirect status and location are served over real HTTP",
                "the follow-up request reaches the redirected path",
            ],
            Self::UploadBinary => &[
                "request body bytes are recorded losslessly",
                "header-sensitive upload routes can be asserted without mocks",
            ],
            Self::DownloadBinary => &[
                "binary response bodies remain intact end-to-end",
                "non-JSON downloads use the real client decoding path",
            ],
            Self::TimeoutDelayedResponse => &[
                "the request reaches the server before the caller budget expires",
                "timeout handling is exercised without sleeping fake clocks",
            ],
        }
    }
}

/// Serializable scenario manifest entry for canonical HTTP acceptance coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpFixtureScenarioDefinition {
    /// Stable scenario identifier used by reports and playbooks.
    pub scenario_id: String,
    /// Canonical scenario kind.
    pub kind: HttpFixtureScenarioKind,
    /// Canonical request method.
    pub method: String,
    /// Canonical route or route template.
    pub path: String,
    /// Operator-facing summary of the behavior being covered.
    pub summary: String,
    /// Stable assertions this scenario must prove.
    pub assertions: Vec<String>,
}

impl From<HttpFixtureScenarioKind> for HttpFixtureScenarioDefinition {
    fn from(kind: HttpFixtureScenarioKind) -> Self {
        Self {
            scenario_id: kind.scenario_id().to_string(),
            kind,
            method: kind.method().to_string(),
            path: kind.path().to_string(),
            summary: kind.summary().to_string(),
            assertions: kind
                .assertions()
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        }
    }
}

/// Canonical request-response HTTP fixture contract for local non-mock suites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpFixtureContract {
    /// Version marker for the contract itself.
    pub contract_version: String,
    /// Required suite class from the acceptance taxonomy.
    pub suite_class: String,
    /// Transport truth being exercised.
    pub transport: String,
    /// Existing helpers that should be promoted rather than replaced.
    pub promoted_helpers: Vec<HttpFixtureHelperReference>,
    /// Run-level artifacts every compliant harness should emit.
    pub artifacts: Vec<HttpFixtureArtifactDescriptor>,
    /// Canonical required scenarios for request-response connectors.
    pub scenarios: Vec<HttpFixtureScenarioDefinition>,
}

/// Return the stable scenario inventory for canonical request-response HTTP coverage.
#[must_use]
pub fn canonical_http_fixture_inventory() -> Vec<HttpFixtureScenarioDefinition> {
    HttpFixtureScenarioKind::ALL
        .into_iter()
        .map(HttpFixtureScenarioDefinition::from)
        .collect()
}

/// Return the canonical HTTP fixture contract for local non-mock acceptance suites.
#[must_use]
pub fn canonical_http_fixture_contract() -> HttpFixtureContract {
    HttpFixtureContract {
        contract_version: "http-fixture-contract/v1".to_string(),
        suite_class: "local_non_mock".to_string(),
        transport: "real_http_tcp".to_string(),
        promoted_helpers: vec![
            HttpFixtureHelperReference::new(
                "fcp_testkit::HttpFixtureServer",
                "real TCP listener and request recorder for deterministic local acceptance runs",
            ),
            HttpFixtureHelperReference::new(
                "fcp_testkit::HttpFixtureRoute",
                "stable route matcher with queued real-network responses",
            ),
            HttpFixtureHelperReference::new(
                "fcp_testkit::HttpFixtureResponse",
                "status/header/body/delay response builder for retries, redirects, and timeouts",
            ),
            HttpFixtureHelperReference::new(
                "fcp_testkit::RecordedHttpRequest",
                "post-run request assertions without downgrading to an in-memory fake client",
            ),
            HttpFixtureHelperReference::new(
                "fcp_testkit::LogRedactionScanner",
                "artifact secret and PII scan for acceptance evidence",
            ),
            HttpFixtureHelperReference::new(
                "fcp_e2e::E2eRunReport",
                "machine-readable run envelope already used by shared E2E reporting",
            ),
            HttpFixtureHelperReference::new(
                "fcp_e2e::E2eArtifactRecord",
                "stable label/kind/description artifact vocabulary for report emission",
            ),
        ],
        artifacts: vec![
            HttpFixtureArtifactDescriptor::new(
                "logs-jsonl",
                HttpFixtureArtifactKind::Jsonl,
                "logs.jsonl",
                "schema-valid event stream for the HTTP acceptance run",
            ),
            HttpFixtureArtifactDescriptor::new(
                "logs-stable-jsonl",
                HttpFixtureArtifactKind::Jsonl,
                "logs.stable.jsonl",
                "stable normalized event stream for deterministic diffs",
            ),
            HttpFixtureArtifactDescriptor::new(
                "report-json",
                HttpFixtureArtifactKind::Json,
                "report.json",
                "machine-readable run report with scenario, artifacts, and failure metadata",
            ),
            HttpFixtureArtifactDescriptor::new(
                "summary-txt",
                HttpFixtureArtifactKind::Text,
                "summary.txt",
                "human-readable triage summary for operators",
            ),
            HttpFixtureArtifactDescriptor::new(
                "scan-report",
                HttpFixtureArtifactKind::Json,
                "scan-report.json",
                "secret and PII scan results for the emitted evidence bundle",
            ),
            HttpFixtureArtifactDescriptor::new(
                "environment-json",
                HttpFixtureArtifactKind::Json,
                "environment.json",
                "redacted prerequisite and environment snapshot for replay",
            ),
            HttpFixtureArtifactDescriptor::new(
                "scenario-manifest",
                HttpFixtureArtifactKind::Json,
                "scenario-manifest.json",
                "scenario id, route setup, and deterministic replay contract",
            ),
            HttpFixtureArtifactDescriptor::new(
                "replay-sh",
                HttpFixtureArtifactKind::Replay,
                "replay.sh",
                "deterministic replay command sequence, including any required rch prefix",
            ),
        ],
        scenarios: canonical_http_fixture_inventory(),
    }
}

/// Recorded HTTP request observed by the fixture server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedHttpRequest {
    /// Request method.
    pub method: String,
    /// Raw request target from the request line.
    pub target: String,
    /// Path component without the query string.
    pub path: String,
    /// Parsed query pairs in arrival order.
    pub query: Vec<(String, String)>,
    /// Request headers in arrival order.
    pub headers: Vec<(String, String)>,
    /// Raw request body bytes.
    pub body: Vec<u8>,
}

impl RecordedHttpRequest {
    /// Return the first header value with a case-insensitive name match.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Return the first query value for the given key.
    #[must_use]
    pub fn query_value(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Decode the request body as UTF-8 text.
    #[must_use]
    pub fn body_text(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
    }

    /// Decode the request body as JSON.
    ///
    /// # Errors
    ///
    /// Returns a parse error if the body is not valid JSON.
    pub fn body_json(&self) -> serde_json::Result<serde_json::Value> {
        serde_json::from_slice(&self.body)
    }
}

/// Response body for a scripted HTTP fixture response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpFixtureBody {
    /// Empty body.
    Empty,
    /// JSON body serialized on write.
    Json(serde_json::Value),
    /// UTF-8 text response body.
    Text(String),
    /// Arbitrary bytes.
    Binary(Vec<u8>),
}

/// Scripted HTTP response served by the fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpFixtureResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: HttpFixtureBody,
    delay: Option<Duration>,
}

impl HttpFixtureResponse {
    /// Build an empty response with the given status.
    #[must_use]
    pub const fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: HttpFixtureBody::Empty,
            delay: None,
        }
    }

    /// Build a JSON response with status 200.
    #[must_use]
    pub fn json(body: serde_json::Value) -> Self {
        Self {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: HttpFixtureBody::Json(body),
            delay: None,
        }
    }

    /// Build a plain-text response with the given status.
    #[must_use]
    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), "text/plain; charset=utf-8".into())],
            body: HttpFixtureBody::Text(body.into()),
            delay: None,
        }
    }

    /// Build a binary download response.
    #[must_use]
    pub fn binary(body: Vec<u8>, content_type: &str) -> Self {
        Self {
            status: 200,
            headers: vec![("Content-Type".into(), content_type.to_string())],
            body: HttpFixtureBody::Binary(body),
            delay: None,
        }
    }

    /// Build a redirect response.
    #[must_use]
    pub fn redirect(status: u16, location: &str) -> Self {
        Self::empty(status).with_header("Location", location)
    }

    /// Build a rate-limited response with a `Retry-After` header.
    #[must_use]
    pub fn rate_limited(retry_after_secs: u64, body: serde_json::Value) -> Self {
        Self::json(body)
            .with_status(429)
            .with_header("Retry-After", retry_after_secs.to_string())
    }

    /// Override the response status.
    #[must_use]
    pub const fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    /// Append a response header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    /// Delay the response to exercise timeout/retry behavior.
    #[must_use]
    pub const fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    fn body_bytes(&self) -> Vec<u8> {
        match &self.body {
            HttpFixtureBody::Empty => Vec::new(),
            HttpFixtureBody::Json(value) => serde_json::to_vec(value).unwrap_or_default(),
            HttpFixtureBody::Text(text) => text.as_bytes().to_vec(),
            HttpFixtureBody::Binary(bytes) => bytes.clone(),
        }
    }
}

/// Scripted route matcher plus one or more responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpFixtureRoute {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    required_headers: Vec<(String, String)>,
    responses: Vec<HttpFixtureResponse>,
}

impl HttpFixtureRoute {
    /// Build a route for the given method and path.
    #[must_use]
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_ascii_uppercase(),
            path: path.to_string(),
            query: Vec::new(),
            required_headers: Vec::new(),
            responses: Vec::new(),
        }
    }

    /// Match a `GET` request.
    #[must_use]
    pub fn get(path: &str) -> Self {
        Self::new("GET", path)
    }

    /// Match a `POST` request.
    #[must_use]
    pub fn post(path: &str) -> Self {
        Self::new("POST", path)
    }

    /// Match a `PUT` request.
    #[must_use]
    pub fn put(path: &str) -> Self {
        Self::new("PUT", path)
    }

    /// Match a `PATCH` request.
    #[must_use]
    pub fn patch(path: &str) -> Self {
        Self::new("PATCH", path)
    }

    /// Match a `DELETE` request.
    #[must_use]
    pub fn delete(path: &str) -> Self {
        Self::new("DELETE", path)
    }

    /// Require a specific query parameter.
    #[must_use]
    pub fn with_query(mut self, name: &str, value: &str) -> Self {
        self.query.push((name.to_string(), value.to_string()));
        self
    }

    /// Require a specific header value.
    #[must_use]
    pub fn require_header(mut self, name: &str, value: &str) -> Self {
        self.required_headers
            .push((name.to_string(), value.to_string()));
        self
    }

    /// Require an `Authorization: Bearer ...` header.
    #[must_use]
    pub fn require_bearer(self, token: &str) -> Self {
        self.require_header("Authorization", &format!("Bearer {token}"))
    }

    /// Append a response to the route's response sequence.
    #[must_use]
    pub fn respond_with(mut self, response: HttpFixtureResponse) -> Self {
        self.responses.push(response);
        self
    }
}

#[derive(Debug)]
struct MountedRoute {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    required_headers: Vec<(String, String)>,
    responses: VecDeque<HttpFixtureResponse>,
}

impl MountedRoute {
    fn from_route(route: HttpFixtureRoute) -> Self {
        Self {
            method: route.method,
            path: route.path,
            query: route.query,
            required_headers: route.required_headers,
            responses: route.responses.into(),
        }
    }

    fn matches(&self, request: &RecordedHttpRequest) -> bool {
        if request.method != self.method || request.path != self.path {
            return false;
        }
        if !self.query.iter().all(|(name, value)| {
            request
                .query
                .iter()
                .any(|(request_name, request_value)| request_name == name && request_value == value)
        }) {
            return false;
        }
        self.required_headers.iter().all(|(name, value)| {
            request
                .header(name)
                .is_some_and(|header_value| header_value == value)
        })
    }
}

#[derive(Debug, Default)]
struct FixtureState {
    routes: Vec<MountedRoute>,
    requests: Vec<RecordedHttpRequest>,
}

/// Real local HTTP fixture server for non-mock request-response acceptance tests.
#[derive(Debug)]
pub struct HttpFixtureServer {
    address: SocketAddr,
    state: Arc<Mutex<FixtureState>>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl HttpFixtureServer {
    /// Start a new local fixture server bound to `127.0.0.1:0`.
    ///
    /// # Errors
    ///
    /// Returns an IO error if the listener cannot be bound.
    pub fn start() -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let state = Arc::new(Mutex::new(FixtureState::default()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let state_for_thread = Arc::clone(&state);
        let shutdown_for_thread = Arc::clone(&shutdown);
        let thread = thread::spawn(move || {
            run_accept_loop(
                &listener,
                state_for_thread.as_ref(),
                shutdown_for_thread.as_ref(),
            );
        });

        Ok(Self {
            address,
            state,
            shutdown,
            thread: Some(thread),
        })
    }

    /// Base URL for the fixture server.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// Bound socket address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Mount a scripted route with one or more queued responses.
    pub fn mount(&self, route: HttpFixtureRoute) {
        let mut state = lock_fixture_state(&self.state);
        state.routes.push(MountedRoute::from_route(route));
    }

    /// Convenience helper for a simple `GET` JSON response.
    pub fn expect_get(&self, path: &str, response: serde_json::Value) {
        self.mount(HttpFixtureRoute::get(path).respond_with(HttpFixtureResponse::json(response)));
    }

    /// Convenience helper for a simple `POST` JSON response.
    pub fn expect_post(&self, path: &str, response: serde_json::Value) {
        self.mount(HttpFixtureRoute::post(path).respond_with(HttpFixtureResponse::json(response)));
    }

    /// Reset routes and recorded requests.
    pub fn reset(&self) {
        let mut state = lock_fixture_state(&self.state);
        state.routes.clear();
        state.requests.clear();
    }

    /// Return all recorded requests.
    #[must_use]
    pub fn recorded_requests(&self) -> Vec<RecordedHttpRequest> {
        let state = lock_fixture_state(&self.state);
        state.requests.clone()
    }

    /// Drain and return all recorded requests.
    #[must_use]
    pub fn drain_requests(&self) -> Vec<RecordedHttpRequest> {
        let mut state = lock_fixture_state(&self.state);
        std::mem::take(&mut state.requests)
    }

    /// Assert that the fixture recorded the expected number of requests.
    ///
    /// # Panics
    ///
    /// Panics if the count does not match.
    pub fn assert_request_count(&self, expected: usize) {
        let requests = self.recorded_requests();
        assert_eq!(
            requests.len(),
            expected,
            "expected {expected} request(s) but observed {}",
            requests.len()
        );
    }

    /// Assert that at least one request hit the given path.
    ///
    /// # Panics
    ///
    /// Panics if no request matched the path.
    pub fn assert_received(&self, path: &str) {
        let requests = self.recorded_requests();
        assert!(
            requests.iter().any(|request| request.path == path),
            "expected at least one request to path '{path}', observed paths: {:?}",
            requests
                .iter()
                .map(|request| request.path.clone())
                .collect::<Vec<_>>()
        );
    }
}

impl Drop for HttpFixtureServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run_accept_loop(listener: &TcpListener, state: &Mutex<FixtureState>, shutdown: &AtomicBool) {
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

                let request = match read_http_request(&mut stream) {
                    Ok(request) => request,
                    Err(_) if shutdown.load(Ordering::SeqCst) => break,
                    Err(err) => {
                        let _ = write_response(
                            &mut stream,
                            &HttpFixtureResponse::text(
                                400,
                                format!("fixture request parse error: {err}"),
                            ),
                        );
                        continue;
                    }
                };

                let response = {
                    let mut state = lock_fixture_state(state);
                    state.requests.push(request.clone());
                    let mut matched_exhausted_route = false;
                    if let Some(response) = state.routes.iter_mut().find_map(|route| {
                        if !route.matches(&request) {
                            return None;
                        }
                        route.responses.pop_front().map_or_else(
                            || {
                                matched_exhausted_route = true;
                                None
                            },
                            Some,
                        )
                    }) {
                        response
                    } else if matched_exhausted_route {
                        HttpFixtureResponse::text(500, "fixture route exhausted")
                    } else {
                        HttpFixtureResponse::text(
                            404,
                            format!(
                                "no scripted response for {} {}",
                                request.method, request.target
                            ),
                        )
                    }
                };

                if let Some(delay) = response.delay {
                    thread::sleep(delay);
                }
                let _ = write_response(&mut stream, &response);
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) if shutdown.load(Ordering::SeqCst) => break,
            Err(_) => {
                thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

fn lock_fixture_state(state: &Mutex<FixtureState>) -> MutexGuard<'_, FixtureState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn read_http_request(stream: &mut TcpStream) -> io::Result<RecordedHttpRequest> {
    const MAX_HEADER_BYTES: usize = 64 * 1024;

    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before request headers arrived",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers exceeded fixture limit",
            ));
        }
        if let Some(index) = find_header_end(&buffer) {
            break index;
        }
    };

    let header_bytes = &buffer[..header_end];
    let header_text = std::str::from_utf8(header_bytes).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("request headers were not valid UTF-8: {err}"),
        )
    })?;

    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP method"))?
        .to_ascii_uppercase();
    let target = request_parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request target"))?
        .to_string();

    let headers = lines
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        })
        .collect::<Vec<_>>();

    let content_length = match headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        None => 0,
        Some((_, value)) => value.parse::<usize>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid content-length header: {error}"),
            )
        })?,
    };

    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    let (path, query) = split_request_target(&target);
    Ok(RecordedHttpRequest {
        method,
        target,
        path,
        query,
        headers,
        body,
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn split_request_target(target: &str) -> (String, Vec<(String, String)>) {
    let (path, query) = target
        .split_once('?')
        .map_or((target, ""), |(path, query)| (path, query));
    let query_pairs = if query.is_empty() {
        Vec::new()
    } else {
        query
            .split('&')
            .filter(|segment| !segment.is_empty())
            .map(|segment| {
                let (name, value) = segment
                    .split_once('=')
                    .map_or((segment, ""), |(name, value)| (name, value));
                (name.to_string(), value.to_string())
            })
            .collect()
    };
    (path.to_string(), query_pairs)
}

fn write_response(stream: &mut TcpStream, response: &HttpFixtureResponse) -> io::Result<()> {
    let body = response.body_bytes();
    write!(
        stream,
        "HTTP/1.1 {} {}\r\n",
        response.status,
        reason_phrase(response.status)
    )?;

    let mut has_content_length = false;
    let mut has_connection = false;
    for (name, value) in &response.headers {
        if name.eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
        if name.eq_ignore_ascii_case("connection") {
            has_connection = true;
        }
        write!(stream, "{name}: {value}\r\n")?;
    }

    if !has_content_length {
        write!(stream, "Content-Length: {}\r\n", body.len())?;
    }
    if !has_connection {
        write!(stream, "Connection: close\r\n")?;
    }
    write!(stream, "\r\n")?;
    stream.write_all(&body)?;
    stream.flush()
}

const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Fixture Response",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpStream as StdTcpStream;

    #[test]
    fn canonical_http_fixture_inventory_has_stable_required_scenarios() {
        let inventory = canonical_http_fixture_inventory();
        let scenario_ids = inventory
            .iter()
            .map(|scenario| scenario.scenario_id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            scenario_ids,
            vec![
                "http.auth.bearer_required",
                "http.pagination.query_page",
                "http.retry.rate_limit_then_success",
                "http.error.upstream_server_failure",
                "http.redirect.temporary_follow",
                "http.upload.binary_body",
                "http.download.binary_body",
                "http.timeout.delayed_response",
            ]
        );
    }

    #[test]
    fn canonical_http_fixture_contract_uses_shared_artifact_vocabulary() {
        let contract = canonical_http_fixture_contract();
        let artifact_labels = contract
            .artifacts
            .iter()
            .map(|artifact| artifact.label.as_str())
            .collect::<Vec<_>>();

        assert_eq!(contract.contract_version, "http-fixture-contract/v1");
        assert_eq!(contract.suite_class, "local_non_mock");
        assert_eq!(contract.transport, "real_http_tcp");
        assert_eq!(
            artifact_labels,
            vec![
                "logs-jsonl",
                "logs-stable-jsonl",
                "report-json",
                "summary-txt",
                "scan-report",
                "environment-json",
                "scenario-manifest",
                "replay-sh",
            ]
        );
    }

    #[test]
    fn canonical_http_fixture_contract_tracks_promoted_helpers() {
        let contract = canonical_http_fixture_contract();
        let symbols = contract
            .promoted_helpers
            .iter()
            .map(|helper| helper.symbol.as_str())
            .collect::<Vec<_>>();

        assert!(symbols.contains(&"fcp_testkit::HttpFixtureServer"));
        assert!(symbols.contains(&"fcp_testkit::HttpFixtureRoute"));
        assert!(symbols.contains(&"fcp_testkit::HttpFixtureResponse"));
        assert!(symbols.contains(&"fcp_testkit::RecordedHttpRequest"));
        assert!(symbols.contains(&"fcp_testkit::LogRedactionScanner"));
        assert!(symbols.contains(&"fcp_e2e::E2eRunReport"));
        assert!(symbols.contains(&"fcp_e2e::E2eArtifactRecord"));
    }

    #[test]
    fn canonical_http_fixture_contract_serializes_with_snake_case_kinds() {
        let contract = canonical_http_fixture_contract();
        let value = serde_json::to_value(&contract).expect("contract should serialize");

        assert_eq!(value["artifacts"][0]["kind"], "jsonl");
        assert_eq!(value["scenarios"][0]["kind"], "auth_bearer");
        assert_eq!(value["scenarios"][0]["method"], "GET");
    }

    #[test]
    fn split_request_target_parses_query_pairs() {
        let (path, query) = split_request_target("/v1/items?page=2&cursor=abc");
        assert_eq!(path, "/v1/items");
        assert_eq!(
            query,
            vec![
                ("page".to_string(), "2".to_string()),
                ("cursor".to_string(), "abc".to_string())
            ]
        );
    }

    #[fcp_async_core::runtime::test]
    async fn fixture_serves_json_over_real_http() {
        let fixture = HttpFixtureServer::start().expect("fixture should bind");
        fixture.expect_get("/v1/messages", json!({ "messages": [] }));

        let response = reqwest::get(format!("{}/v1/messages", fixture.base_url()))
            .await
            .expect("GET should succeed");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response
                .json::<serde_json::Value>()
                .await
                .expect("JSON body"),
            json!({ "messages": [] })
        );
        fixture.assert_request_count(1);
        fixture.assert_received("/v1/messages");
    }

    #[fcp_async_core::runtime::test]
    async fn fixture_requires_bearer_header() {
        let fixture = HttpFixtureServer::start().expect("fixture should bind");
        fixture.mount(
            HttpFixtureRoute::get("/v1/protected")
                .require_bearer("test-token")
                .respond_with(HttpFixtureResponse::json(json!({ "ok": true }))),
        );

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/v1/protected", fixture.base_url()))
            .bearer_auth("test-token")
            .send()
            .await
            .expect("authorized request should succeed");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let request = fixture
            .recorded_requests()
            .into_iter()
            .last()
            .expect("recorded request");
        assert_eq!(request.header("authorization"), Some("Bearer test-token"));
    }

    #[fcp_async_core::runtime::test]
    async fn fixture_supports_retry_sequences() {
        let fixture = HttpFixtureServer::start().expect("fixture should bind");
        fixture.mount(
            HttpFixtureRoute::get("/v1/jobs")
                .respond_with(HttpFixtureResponse::rate_limited(
                    1,
                    json!({ "error": "slow down" }),
                ))
                .respond_with(HttpFixtureResponse::json(json!({ "jobs": [] }))),
        );

        let client = reqwest::Client::new();
        let first = client
            .get(format!("{}/v1/jobs", fixture.base_url()))
            .send()
            .await
            .expect("first request should complete");
        assert_eq!(first.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(first.headers()["retry-after"], "1");

        let second = client
            .get(format!("{}/v1/jobs", fixture.base_url()))
            .send()
            .await
            .expect("second request should complete");
        assert_eq!(second.status(), reqwest::StatusCode::OK);
        fixture.assert_request_count(2);
    }

    #[fcp_async_core::runtime::test]
    async fn fixture_surfaces_route_exhaustion_instead_of_fake_404() {
        let fixture = HttpFixtureServer::start().expect("fixture should bind");
        fixture.mount(
            HttpFixtureRoute::get("/v1/once")
                .respond_with(HttpFixtureResponse::json(json!({ "ok": true }))),
        );

        let client = reqwest::Client::new();
        let first = client
            .get(format!("{}/v1/once", fixture.base_url()))
            .send()
            .await
            .expect("first request should succeed");
        assert_eq!(first.status(), reqwest::StatusCode::OK);

        let second = client
            .get(format!("{}/v1/once", fixture.base_url()))
            .send()
            .await
            .expect("second request should still receive a fixture response");
        assert_eq!(second.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            second
                .text()
                .await
                .expect("exhaustion response body should be readable"),
            "fixture route exhausted"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn fixture_uses_later_matching_route_before_reporting_exhaustion() {
        let fixture = HttpFixtureServer::start().expect("fixture should bind");
        fixture.mount(
            HttpFixtureRoute::get("/v1/once")
                .respond_with(HttpFixtureResponse::json(json!({ "source": "first" }))),
        );
        fixture.mount(
            HttpFixtureRoute::get("/v1/once")
                .respond_with(HttpFixtureResponse::json(json!({ "source": "second" }))),
        );

        let client = reqwest::Client::new();
        let first = client
            .get(format!("{}/v1/once", fixture.base_url()))
            .send()
            .await
            .expect("first request should succeed");
        assert_eq!(first.status(), reqwest::StatusCode::OK);
        assert_eq!(
            first
                .json::<serde_json::Value>()
                .await
                .expect("first body should decode"),
            json!({ "source": "first" })
        );

        let second = client
            .get(format!("{}/v1/once", fixture.base_url()))
            .send()
            .await
            .expect("second request should use the later matching route");
        assert_eq!(second.status(), reqwest::StatusCode::OK);
        assert_eq!(
            second
                .json::<serde_json::Value>()
                .await
                .expect("second body should decode"),
            json!({ "source": "second" })
        );

        let third = client
            .get(format!("{}/v1/once", fixture.base_url()))
            .send()
            .await
            .expect("third request should still receive a fixture response");
        assert_eq!(third.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            third
                .text()
                .await
                .expect("exhaustion response body should be readable"),
            "fixture route exhausted"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn fixture_supports_query_scoped_pagination() {
        let fixture = HttpFixtureServer::start().expect("fixture should bind");
        fixture.mount(
            HttpFixtureRoute::get("/v1/items")
                .with_query("page", "1")
                .respond_with(HttpFixtureResponse::json(
                    json!({ "items": [1, 2], "next_page": "2" }),
                )),
        );
        fixture.mount(
            HttpFixtureRoute::get("/v1/items")
                .with_query("page", "2")
                .respond_with(HttpFixtureResponse::json(
                    json!({ "items": [3], "next_page": null }),
                )),
        );

        let client = reqwest::Client::new();
        let page_one = client
            .get(format!("{}/v1/items?page=1", fixture.base_url()))
            .send()
            .await
            .expect("page 1 should succeed")
            .json::<serde_json::Value>()
            .await
            .expect("page 1 JSON");
        let page_two = client
            .get(format!("{}/v1/items?page=2", fixture.base_url()))
            .send()
            .await
            .expect("page 2 should succeed")
            .json::<serde_json::Value>()
            .await
            .expect("page 2 JSON");

        assert_eq!(page_one["items"], json!([1, 2]));
        assert_eq!(page_two["items"], json!([3]));
        let requests = fixture.recorded_requests();
        assert_eq!(requests[0].query_value("page"), Some("1"));
        assert_eq!(requests[1].query_value("page"), Some("2"));
    }

    #[fcp_async_core::runtime::test]
    async fn fixture_supports_redirects() {
        let fixture = HttpFixtureServer::start().expect("fixture should bind");
        fixture.mount(
            HttpFixtureRoute::get("/legacy")
                .respond_with(HttpFixtureResponse::redirect(302, "/v1/current")),
        );
        fixture.mount(
            HttpFixtureRoute::get("/v1/current")
                .respond_with(HttpFixtureResponse::json(json!({ "migrated": true }))),
        );

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/legacy", fixture.base_url()))
            .send()
            .await
            .expect("redirect request should succeed");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response
                .json::<serde_json::Value>()
                .await
                .expect("redirect JSON"),
            json!({ "migrated": true })
        );
        fixture.assert_request_count(2);
    }

    #[fcp_async_core::runtime::test]
    async fn fixture_records_uploads_and_serves_downloads() {
        let fixture = HttpFixtureServer::start().expect("fixture should bind");
        fixture.mount(
            HttpFixtureRoute::post("/v1/upload")
                .require_header("Content-Type", "application/octet-stream")
                .respond_with(HttpFixtureResponse::empty(201)),
        );
        fixture.mount(HttpFixtureRoute::get("/v1/download").respond_with(
            HttpFixtureResponse::binary(b"fixture-bytes".to_vec(), "application/octet-stream"),
        ));

        let client = reqwest::Client::new();
        let upload_body = b"upload-payload".to_vec();
        let upload_response = client
            .post(format!("{}/v1/upload", fixture.base_url()))
            .header("Content-Type", "application/octet-stream")
            .body(upload_body.clone())
            .send()
            .await
            .expect("upload request should succeed");
        assert_eq!(upload_response.status(), reqwest::StatusCode::CREATED);

        let download_body = client
            .get(format!("{}/v1/download", fixture.base_url()))
            .send()
            .await
            .expect("download request should succeed")
            .bytes()
            .await
            .expect("download bytes");
        assert_eq!(&download_body[..], b"fixture-bytes");

        let requests = fixture.recorded_requests();
        assert_eq!(requests[0].body, upload_body);
        assert_eq!(requests[1].path, "/v1/download");
    }

    #[fcp_async_core::runtime::test]
    async fn fixture_can_trigger_caller_timeouts() {
        let fixture = HttpFixtureServer::start().expect("fixture should bind");
        fixture.mount(
            HttpFixtureRoute::get("/v1/slow").respond_with(
                HttpFixtureResponse::json(json!({ "slow": true }))
                    .with_delay(Duration::from_millis(250)),
            ),
        );

        let client = reqwest::Client::new();
        let url = format!("{}/v1/slow", fixture.base_url());
        let request_task = fcp_async_core::task::spawn(async move {
            fcp_async_core::time::timeout(Duration::from_millis(50), client.get(url).send()).await
        });

        let mut observed_request = false;
        for _ in 0..50 {
            if fixture.recorded_requests().len() == 1 {
                observed_request = true;
                break;
            }
            fcp_async_core::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            observed_request,
            "slow request should reach the fixture before the caller timeout fires"
        );

        let result = request_task
            .await
            .expect("timeout request task should join");
        assert!(
            matches!(result, Err(fcp_async_core::AsyncError::Timeout { .. })),
            "delayed response should exceed caller timeout budget: {result:?}"
        );
        fixture.assert_request_count(1);
    }

    #[test]
    fn fixture_rejects_invalid_content_length_header() {
        let fixture = HttpFixtureServer::start().expect("fixture should bind");
        let mut stream = StdTcpStream::connect(fixture.address()).expect("connect to fixture");
        stream
            .write_all(
                b"POST /v1/upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: nope\r\n\r\npayload",
            )
            .expect("write malformed request");
        stream.flush().expect("flush malformed request");

        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("read fixture response");

        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(response.contains("invalid content-length header"));
    }
}
