//! Apps Script API v1 client built on the shared Google REST executor.

use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use fcp_google_discovery::executor::{
    GoogleApiError, GoogleExecuteRequest, GoogleExecuteResponse, GoogleResponseBody,
    GoogleResponseMode, GoogleRestError, GoogleRestExecutor,
};
use fcp_google_discovery::{DiscoveryMethod, DiscoveryParameter, auth::GoogleMaterializedAuth};
use fcp_sdk::{
    ConnectorRuntime, ConnectorRuntimeConfig,
    migration::{AttemptOutcome, HttpRetryConfig, RetryLoop},
};
use reqwest::{Client, Url, header};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use crate::{
    error::{ScriptError, ScriptResult},
    types::{
        Content, Deployment, DeploymentConfig, DeploymentsPage, ExecutionOperation,
        ExecutionRequest, FileInventoryEntry, Metrics, ProcessFilter, ProcessesPage, Project,
        ScriptFile, Version, VersionsPage,
    },
};

const DEFAULT_BASE_URL: &str = "https://script.googleapis.com/v1";

pub struct AppsScriptClient {
    executor: GoogleRestExecutor,
    auth: GoogleMaterializedAuth,
    base_url: String,
    total_requests: AtomicU64,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl AppsScriptClient {
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> ScriptResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );
        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-apps-script/0.1.0")
            .build()?;
        Ok(Self {
            executor: GoogleRestExecutor::new().with_client(client),
            auth,
            base_url: DEFAULT_BASE_URL.into(),
            total_requests: AtomicU64::new(0),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                initial_delay_ms: 500,
                max_delay_ms: 30_000,
                jitter_enabled: true,
            },
        })
    }

    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').into();
        self
    }

    #[must_use]
    pub fn auth_redacted_label(&self) -> String {
        match &self.auth {
            GoogleMaterializedAuth::BearerToken { source, .. } => source.to_string(),
            GoogleMaterializedAuth::CredentialReference { credential_id, .. } => {
                format!("credential_id:{credential_id}")
            }
        }
    }

    pub async fn get_project(&self, script_id: &str) -> ScriptResult<Project> {
        self.get(&format!(
            "{}/projects/{}",
            self.base_url,
            segment(script_id, "script_id")?
        ))
        .await
    }

    pub async fn get_content(
        &self,
        script_id: &str,
        version: Option<i32>,
    ) -> ScriptResult<Content> {
        let base = format!(
            "{}/projects/{}/content",
            self.base_url,
            segment(script_id, "script_id")?
        );
        let url = if let Some(version) = version {
            if version < 1 {
                return Err(bad("version_number must be positive"));
            }
            let version = version.to_string();
            query_url(&base, &[("versionNumber", version.as_str())])?
        } else {
            base
        };
        self.get(&url).await
    }

    pub async fn create_project(
        &self,
        title: &str,
        parent_id: Option<&str>,
    ) -> ScriptResult<Project> {
        let mut body = serde_json::json!({"title": bounded_text(title, "title", 256)?});
        if let Some(parent) = parent_id {
            body["parentId"] = segment(parent, "parent_id")?.into();
        }
        self.send(
            "POST",
            &format!("{}/projects", self.base_url),
            Some(&body),
            false,
        )
        .await
    }

    pub async fn update_content(
        &self,
        script_id: &str,
        files: &[ScriptFile],
    ) -> ScriptResult<Content> {
        validate_files(files)?;
        let body = serde_json::json!({"files": files});
        self.send(
            "PUT",
            &format!(
                "{}/projects/{}/content",
                self.base_url,
                segment(script_id, "script_id")?
            ),
            Some(&body),
            false,
        )
        .await
    }

    pub async fn get_metrics(
        &self,
        script_id: &str,
        granularity: &str,
        deployment_id: Option<&str>,
    ) -> ScriptResult<Metrics> {
        if !matches!(granularity, "WEEKLY" | "DAILY") {
            return Err(bad("metrics_granularity must be WEEKLY or DAILY"));
        }
        let base = format!(
            "{}/projects/{}/metrics",
            self.base_url,
            segment(script_id, "script_id")?
        );
        let deployment_id = segment(deployment_id.unwrap_or("HEAD"), "deployment_id")?;
        let url = query_url(
            &base,
            &[
                ("metricsFilter.deploymentId", deployment_id),
                ("metricsGranularity", granularity),
            ],
        )?;
        self.get(&url).await
    }

    pub async fn create_version(
        &self,
        script_id: &str,
        description: Option<&str>,
    ) -> ScriptResult<Version> {
        let body = match description {
            Some(v) => serde_json::json!({"description": bounded_text(v, "description", 512)?}),
            None => serde_json::json!({}),
        };
        self.send(
            "POST",
            &format!(
                "{}/projects/{}/versions",
                self.base_url,
                segment(script_id, "script_id")?
            ),
            Some(&body),
            false,
        )
        .await
    }

    pub async fn get_version(&self, script_id: &str, version: i32) -> ScriptResult<Version> {
        if version < 1 {
            return Err(bad("version_number must be positive"));
        }
        self.get(&format!(
            "{}/projects/{}/versions/{version}",
            self.base_url,
            segment(script_id, "script_id")?
        ))
        .await
    }

    pub async fn list_versions(
        &self,
        script_id: &str,
        page_size: u16,
        page_token: Option<&str>,
    ) -> ScriptResult<VersionsPage> {
        let url = page_url(
            &format!(
                "{}/projects/{}/versions",
                self.base_url,
                segment(script_id, "script_id")?
            ),
            page_size,
            page_token,
        )?;
        self.get(&url).await
    }

    pub async fn get_deployment(
        &self,
        script_id: &str,
        deployment_id: &str,
    ) -> ScriptResult<Deployment> {
        self.get(&format!(
            "{}/projects/{}/deployments/{}",
            self.base_url,
            segment(script_id, "script_id")?,
            segment(deployment_id, "deployment_id")?
        ))
        .await
    }

    pub async fn list_deployments(
        &self,
        script_id: &str,
        page_size: u16,
        page_token: Option<&str>,
    ) -> ScriptResult<DeploymentsPage> {
        let url = page_url(
            &format!(
                "{}/projects/{}/deployments",
                self.base_url,
                segment(script_id, "script_id")?
            ),
            page_size,
            page_token,
        )?;
        self.get(&url).await
    }

    pub async fn create_deployment(
        &self,
        script_id: &str,
        config: &DeploymentConfig,
    ) -> ScriptResult<Deployment> {
        validate_deployment_config(script_id, config)?;
        let body = serde_json::json!({"deploymentConfig": config});
        self.send(
            "POST",
            &format!(
                "{}/projects/{}/deployments",
                self.base_url,
                segment(script_id, "script_id")?
            ),
            Some(&body),
            false,
        )
        .await
    }

    pub async fn update_deployment(
        &self,
        script_id: &str,
        deployment_id: &str,
        config: &DeploymentConfig,
    ) -> ScriptResult<Deployment> {
        validate_deployment_config(script_id, config)?;
        let body = serde_json::json!({"deploymentConfig": config});
        self.send(
            "PUT",
            &format!(
                "{}/projects/{}/deployments/{}",
                self.base_url,
                segment(script_id, "script_id")?,
                segment(deployment_id, "deployment_id")?
            ),
            Some(&body),
            false,
        )
        .await
    }

    pub async fn list_processes(
        &self,
        script_id: Option<&str>,
        filter: &ProcessFilter,
        page_size: u16,
        page_token: Option<&str>,
    ) -> ScriptResult<ProcessesPage> {
        let base = match script_id {
            Some(_) => format!("{}/processes:listScriptProcesses", self.base_url),
            None => format!("{}/processes", self.base_url),
        };
        let mut pairs = Vec::new();
        if let Some(id) = script_id {
            pairs.push(("scriptId".into(), segment(id, "script_id")?.into()));
        }
        append_process_filters(&mut pairs, script_id.is_some(), filter)?;
        pairs.push(("pageSize".into(), checked_page_size(page_size)?.to_string()));
        if let Some(token) = page_token {
            pairs.push(("pageToken".into(), validate_page_token(token)?.into()));
        }
        let url = query_url_owned(&base, &pairs)?;
        self.get(&url).await
    }

    pub async fn run_script(
        &self,
        deployment_id: &str,
        function: &str,
        parameters: &[serde_json::Value],
    ) -> ScriptResult<ExecutionOperation> {
        let body = serde_json::to_value(ExecutionRequest {
            function,
            parameters,
            dev_mode: false,
        })?;
        self.send(
            "POST",
            &format!(
                "{}/scripts/{}:run",
                self.base_url,
                segment(deployment_id, "deployment_id")?
            ),
            Some(&body),
            false,
        )
        .await
    }

    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    async fn get<T: DeserializeOwned>(&self, url: &str) -> ScriptResult<T> {
        self.send("GET", url, None, true).await
    }
    async fn send<T: DeserializeOwned>(
        &self,
        method: &'static str,
        url: &str,
        body: Option<&serde_json::Value>,
        replay_safe: bool,
    ) -> ScriptResult<T> {
        let response = self
            .execute_with_retry(method, url, body, replay_safe)
            .await?;
        match response.body {
            GoogleResponseBody::Json(v) => Ok(serde_json::from_value(v)?),
            GoogleResponseBody::Binary(v) => Ok(serde_json::from_slice(&v)?),
            GoogleResponseBody::Empty => Err(bad("expected JSON response")),
        }
    }

    async fn execute_with_retry(
        &self,
        method: &'static str,
        url: &str,
        body: Option<&serde_json::Value>,
        replay_safe: bool,
    ) -> ScriptResult<GoogleExecuteResponse> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        RetryLoop::execute(&ctx, &policy, |_: u32| async move {
            match self.execute_once(method, url, body).await {
                Ok(v) => AttemptOutcome::Success(v),
                Err(e) if e.is_retryable() => {
                    let can_replay = replay_safe || e.replay_is_safe();
                    let delay = e.retry_after();
                    AttemptOutcome::retryable_if_replayable(e, delay, can_replay)
                }
                Err(e) => AttemptOutcome::Terminal(e),
            }
        })
        .await
    }

    async fn execute_once(
        &self,
        method: &'static str,
        raw_url: &str,
        body: Option<&serde_json::Value>,
    ) -> ScriptResult<GoogleExecuteResponse> {
        let parsed = Url::parse(raw_url).map_err(|e| bad(&format!("invalid request URL: {e}")))?;
        let mut parameters: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (k, v) in parsed.query_pairs() {
            parameters
                .entry(k.into_owned())
                .or_default()
                .push(v.into_owned());
        }
        let method_parameters = parameters
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    DiscoveryParameter {
                        location: Some("query".into()),
                        required: false,
                        repeated: true,
                        type_name: Some("string".into()),
                        format: None,
                        description: None,
                    },
                )
            })
            .collect();
        let path = parsed.path().trim_start_matches('/').to_string();
        let discovered = DiscoveryMethod {
            key: format!("script.transport.{}", method.to_ascii_lowercase()),
            id: format!("script.transport.{}", method.to_ascii_lowercase()),
            http_method: method.into(),
            path: path.clone(),
            flat_path: None,
            canonical_path: path,
            resource_path: vec![],
            description: None,
            scopes: vec![],
            request_ref: None,
            response_ref: None,
            parameters: method_parameters,
            supports_media_download: false,
            supports_media_upload: false,
            media_upload: None,
        };
        let mut base = parsed.origin().ascii_serialization();
        base.push('/');
        let schemas = BTreeMap::new();
        let mut request = GoogleExecuteRequest::new(&discovered, &schemas, &base);
        request.parameters = parameters;
        request.body = body.cloned();
        request.response_mode = GoogleResponseMode::Json;
        request.auth = Some(&self.auth);
        self.executor
            .execute(&request)
            .await
            .map_err(map_rest_error)
    }
}

fn bad(message: &str) -> ScriptError {
    ScriptError::Api {
        status_code: 400,
        message: message.into(),
    }
}
fn bounded_text<'a>(value: &'a str, field: &str, max: usize) -> ScriptResult<&'a str> {
    let v = value.trim();
    if v.is_empty() || v.len() > max {
        Err(bad(&format!("{field} must contain 1..={max} bytes")))
    } else {
        Ok(v)
    }
}
fn segment<'a>(value: &'a str, field: &str) -> ScriptResult<&'a str> {
    let value = bounded_text(value, field, 512)?;
    let lower = value.to_ascii_lowercase();
    if ['/', '\\', '?', '#', '%']
        .iter()
        .any(|c| value.contains(*c))
        || value.contains("..")
        || ["%2f", "%5c", "%3f", "%23", "%25"]
            .iter()
            .any(|x| lower.contains(x))
    {
        Err(bad(&format!("{field} contains path characters")))
    } else {
        Ok(value)
    }
}
fn page_url(base: &str, size: u16, token: Option<&str>) -> ScriptResult<String> {
    let page_size_string = checked_page_size(size)?.to_string();
    let mut pairs = vec![("pageSize", page_size_string.as_str())];
    if let Some(token) = token {
        pairs.push(("pageToken", validate_page_token(token)?));
    }
    query_url(base, &pairs)
}

fn checked_page_size(size: u16) -> ScriptResult<u16> {
    if (1..=50).contains(&size) {
        Ok(size)
    } else {
        Err(bad("page_size must be 1..=50"))
    }
}

fn validate_page_token(value: &str) -> ScriptResult<&str> {
    let value = bounded_text(value, "page_token", 4096)?;
    if value.chars().any(char::is_control) {
        Err(bad("page_token must not contain control characters"))
    } else {
        Ok(value)
    }
}

fn query_url(base: &str, pairs: &[(&str, &str)]) -> ScriptResult<String> {
    let mut url =
        Url::parse(base).map_err(|error| bad(&format!("invalid request URL: {error}")))?;
    url.query_pairs_mut().extend_pairs(pairs.iter().copied());
    Ok(url.into())
}
fn query_url_owned(base: &str, pairs: &[(String, String)]) -> ScriptResult<String> {
    let mut url =
        Url::parse(base).map_err(|error| bad(&format!("invalid request URL: {error}")))?;
    url.query_pairs_mut().extend_pairs(
        pairs
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );
    Ok(url.into())
}
fn validate_deployment_config(script_id: &str, config: &DeploymentConfig) -> ScriptResult<()> {
    if segment(script_id, "script_id")?
        != segment(&config.script_id, "deployment_config.script_id")?
    {
        return Err(bad("deployment config script_id must match target"));
    }
    if config.version_number < 1 {
        return Err(bad("version_number must be positive"));
    }
    bounded_text(&config.manifest_file_name, "manifest_file_name", 128)?;
    Ok(())
}
fn append_process_filters(
    pairs: &mut Vec<(String, String)>,
    script_scoped: bool,
    filter: &ProcessFilter,
) -> ScriptResult<()> {
    let prefix = if script_scoped {
        "scriptProcessFilter."
    } else {
        "userProcessFilter."
    };
    let function_key = if script_scoped {
        "scriptProcessFilter.functionName"
    } else {
        "userProcessFilter.functionName"
    };
    let deployment_key = if script_scoped {
        "scriptProcessFilter.deploymentId"
    } else {
        "userProcessFilter.deploymentId"
    };
    if let Some(value) = filter.function_name.as_deref() {
        pairs.push((
            function_key.into(),
            bounded_text(value, "function_name", 256)?.into(),
        ));
    }
    if let Some(value) = filter.deployment_id.as_deref() {
        pairs.push((
            deployment_key.into(),
            segment(value, "deployment_id")?.into(),
        ));
    }
    for (suffix, values, allowed) in [
        ("types", &filter.types, PROCESS_TYPES),
        ("statuses", &filter.statuses, PROCESS_STATUSES),
        (
            "userAccessLevels",
            &filter.user_access_levels,
            USER_ACCESS_LEVELS,
        ),
    ] {
        let key = match (prefix, suffix) {
            ("scriptProcessFilter.", "types") => "scriptProcessFilter.types",
            ("scriptProcessFilter.", "statuses") => "scriptProcessFilter.statuses",
            ("scriptProcessFilter.", _) => "scriptProcessFilter.userAccessLevels",
            ("userProcessFilter.", "types") => "userProcessFilter.types",
            ("userProcessFilter.", "statuses") => "userProcessFilter.statuses",
            _ => "userProcessFilter.userAccessLevels",
        };
        if values.len() > 10 {
            return Err(bad("process filter list may contain at most 10 values"));
        }
        for value in values {
            if !allowed.contains(&value.as_str()) {
                return Err(bad("process filter contains an unsupported enum value"));
            }
            pairs.push((key.into(), value.clone()));
        }
    }
    for (suffix, value) in [
        ("startTime", filter.start_time.as_deref()),
        ("endTime", filter.end_time.as_deref()),
    ] {
        if let Some(value) = value {
            chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|_| bad("process timestamps must be RFC3339"))?;
            let key = match (prefix, suffix) {
                ("scriptProcessFilter.", "startTime") => "scriptProcessFilter.startTime",
                ("scriptProcessFilter.", _) => "scriptProcessFilter.endTime",
                ("userProcessFilter.", "startTime") => "userProcessFilter.startTime",
                _ => "userProcessFilter.endTime",
            };
            pairs.push((key.into(), value.into()));
        }
    }
    Ok(())
}

const PROCESS_TYPES: &[&str] = &[
    "ADD_ON",
    "EXECUTION_API",
    "TIME_DRIVEN",
    "TRIGGER",
    "WEBAPP",
    "EDITOR",
    "SIMPLE_TRIGGER",
    "MENU",
    "BATCH_TASK",
];
const PROCESS_STATUSES: &[&str] = &[
    "RUNNING",
    "PAUSED",
    "COMPLETED",
    "CANCELED",
    "FAILED",
    "TIMED_OUT",
    "UNKNOWN",
    "DELAYED",
    "EXECUTION_DISABLED",
];
const USER_ACCESS_LEVELS: &[&str] = &["NONE", "READ", "WRITE", "OWNER"];
pub fn validate_files(files: &[ScriptFile]) -> ScriptResult<()> {
    use std::collections::BTreeSet;
    if files.is_empty() || files.len() > 200 {
        return Err(ScriptError::UnsafeSourceReplacement(
            "files must contain 1..=200 entries".into(),
        ));
    }
    let mut names = BTreeSet::new();
    let mut manifests = 0;
    let mut bytes = 0usize;
    for file in files {
        bounded_text(&file.name, "file.name", 128)?;
        if !names.insert(file.name.as_str()) {
            return Err(ScriptError::UnsafeSourceReplacement(
                "duplicate file name".into(),
            ));
        }
        if file.file_type == crate::types::FileType::Json {
            manifests += 1;
            if file.name != "appsscript" {
                return Err(ScriptError::UnsafeSourceReplacement(
                    "JSON manifest must be named appsscript".into(),
                ));
            }
        }
        bytes = bytes
            .checked_add(file.source.len())
            .ok_or_else(|| ScriptError::UnsafeSourceReplacement("source size overflow".into()))?;
    }
    if manifests != 1 {
        return Err(ScriptError::UnsafeSourceReplacement(
            "exactly one appsscript JSON manifest is required".into(),
        ));
    }
    if bytes > 5 * 1024 * 1024 {
        return Err(ScriptError::UnsafeSourceReplacement(
            "source exceeds 5 MiB".into(),
        ));
    }
    Ok(())
}
pub fn source_inventory(files: &[ScriptFile]) -> ScriptResult<(Vec<FileInventoryEntry>, String)> {
    validate_files(files)?;
    let mut entries = files
        .iter()
        .map(|file| FileInventoryEntry {
            name: file.name.clone(),
            file_type: file.file_type,
            sha256: hex::encode(Sha256::digest(file.source.as_bytes())),
            bytes: file.source.len(),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let encoded = serde_json::to_vec(&entries)?;
    let digest = hex::encode(Sha256::digest(encoded));
    Ok((entries, digest))
}
fn map_rest_error(error: GoogleRestError) -> ScriptError {
    match error {
        GoogleRestError::Http { source } => ScriptError::Http(source),
        GoogleRestError::JsonDecode { source } => ScriptError::Json(source),
        GoogleRestError::Api { error, .. } => map_api(&error),
        _ => ScriptError::Api {
            status_code: 500,
            message: "Apps Script transport contract failure".into(),
        },
    }
}
fn map_api(error: &GoogleApiError) -> ScriptError {
    match error.status_code {
        401 => ScriptError::Unauthorized,
        403 => ScriptError::Forbidden,
        404 => ScriptError::NotFound,
        429 => ScriptError::RateLimited {
            retry_after_ms: error.retry_after_ms.unwrap_or(60_000),
        },
        status_code => ScriptError::Api {
            status_code,
            message: "Apps Script API request failed".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FileType;
    #[test]
    fn complete_source_requires_manifest() {
        let files = vec![ScriptFile {
            name: "Code".into(),
            file_type: FileType::ServerJs,
            source: "x".into(),
        }];
        assert!(validate_files(&files).is_err());
    }
    #[test]
    fn path_segments_reject_encoded_separator() {
        assert!(segment("abc%2Fdef", "id").is_err());
    }
    #[test]
    fn provider_statuses_map_to_stable_retry_classes() {
        let api = |status_code, retry_after_ms| GoogleApiError {
            status_code,
            status: None,
            message: "provider-body-canary".into(),
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms,
        };
        assert!(matches!(
            map_api(&api(401, None)),
            ScriptError::Unauthorized
        ));
        assert!(matches!(map_api(&api(403, None)), ScriptError::Forbidden));
        assert!(matches!(map_api(&api(404, None)), ScriptError::NotFound));
        assert!(matches!(
            map_api(&api(429, Some(250))),
            ScriptError::RateLimited {
                retry_after_ms: 250
            }
        ));
        assert!(map_api(&api(503, None)).is_retryable());
        assert!(!map_api(&api(400, None)).is_retryable());
        assert!(
            !map_api(&api(400, None))
                .to_string()
                .contains("provider-body-canary")
        );
    }
    #[test]
    fn process_filters_are_allowlisted_and_time_bounded() {
        let filter = ProcessFilter {
            start_time: Some("2026-08-04T00:00:00Z".into()),
            end_time: Some("2026-08-04T01:00:00Z".into()),
            types: vec!["TRIGGER".into()],
            statuses: vec!["FAILED".into()],
            user_access_levels: vec!["OWNER".into()],
            ..ProcessFilter::default()
        };
        let mut pairs = Vec::new();
        append_process_filters(&mut pairs, true, &filter).expect("valid process filters");
        assert!(pairs.contains(&("scriptProcessFilter.types".into(), "TRIGGER".into())));
        let invalid = ProcessFilter {
            statuses: vec!["NOT_A_GOOGLE_STATUS".into()],
            ..ProcessFilter::default()
        };
        assert!(append_process_filters(&mut Vec::new(), false, &invalid).is_err());
    }
}
