//! Shared Google Discovery snapshot substrate for FCP connectors.
//!
//! This crate provides three core capabilities:
//! - deterministic service resolution (`alias` and explicit `service:version`)
//! - Discovery document fetching with standard + alternate endpoint support
//! - normalized, stable snapshot types for generation and testing
//! - generator-consumable Google policy/capability mapping metadata
//! - generation artifacts for manifest fragments + FCP introspection + MCP tools + agent skills
//! - shared Google auth precedence/materialization rules for connectors
//! - generic Google REST execution substrate for request validation and transport

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

pub mod auth;
pub mod executor;
pub mod generator;
pub mod policy;

/// Default Google Discovery endpoint base for standard service lookups.
pub const DEFAULT_STANDARD_DISCOVERY_BASE: &str = "https://www.googleapis.com/discovery/v1/apis";
/// Default alternate endpoint template used by some Google APIs.
///
/// Supported placeholders:
/// - `{api_name}`
/// - `{api_version}`
pub const DEFAULT_ALTERNATE_DISCOVERY_TEMPLATE: &str =
    "https://{api_name}.googleapis.com/$discovery/rest?version={api_version}";

const MAX_SCHEMA_DEPTH: usize = 64;

/// Errors emitted by the Google Discovery substrate.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// Invalid `api_name`/`api_version` component.
    #[error("invalid {field} component `{value}`")]
    InvalidComponent {
        /// Component field name.
        field: &'static str,
        /// Rejected component value.
        value: String,
    },

    /// Invalid service selector.
    #[error("invalid service selector `{selector}` (expected alias or service:version)")]
    InvalidServiceSelector {
        /// Selector string provided by the caller.
        selector: String,
    },

    /// Unknown alias in the curated registry.
    #[error("unknown service alias `{alias}`")]
    UnknownServiceAlias {
        /// Alias that could not be resolved.
        alias: String,
    },

    /// Request transport failed.
    #[error("request failed for `{url}`: {source}")]
    RequestFailed {
        /// Requested URL.
        url: String,
        /// Upstream reqwest error.
        source: reqwest::Error,
    },

    /// Endpoint returned a non-success status.
    #[error("endpoint `{url}` returned status {status}")]
    HttpStatus {
        /// Requested URL.
        url: String,
        /// Response status.
        status: StatusCode,
    },

    /// Response body could not be parsed as JSON.
    #[error("failed to parse discovery JSON from `{url}`: {source}")]
    JsonDecode {
        /// Requested URL.
        url: String,
        /// JSON parser error.
        source: serde_json::Error,
    },

    /// Both standard and alternate endpoints failed.
    #[error(
        "failed to fetch discovery for `{service}` via both endpoints (standard: {standard}; alternate: {alternate})"
    )]
    AllEndpointsFailed {
        /// Service identity.
        service: String,
        /// Standard endpoint error summary.
        standard: String,
        /// Alternate endpoint error summary.
        alternate: String,
    },

    /// Discovery schema tree exceeded the supported recursion depth.
    #[error("schema depth exceeds limit {max_depth}")]
    SchemaDepthExceeded {
        /// Configured max depth.
        max_depth: usize,
    },
}

/// Canonical Google API identity.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct DiscoveryServiceId {
    /// Discovery API name (for example `gmail`, `calendar`).
    pub api_name: String,
    /// Discovery API version (for example `v1`, `v3`, `v1beta`).
    pub api_version: String,
}

impl DiscoveryServiceId {
    /// Build a canonical service identity.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::InvalidComponent`] when `api_name` or `api_version`
    /// is empty or contains unsupported characters.
    pub fn new(
        api_name: impl Into<String>,
        api_version: impl Into<String>,
    ) -> Result<Self, DiscoveryError> {
        let api_name = normalize_component("api_name", &api_name.into())?;
        let api_version = normalize_component("api_version", &api_version.into())?;
        Ok(Self {
            api_name,
            api_version,
        })
    }

    /// Parse an explicit `service:version` selector.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::InvalidServiceSelector`] when the selector does
    /// not contain exactly one `:` separator.
    pub fn parse_explicit(selector: &str) -> Result<Self, DiscoveryError> {
        let selector = selector.trim();
        let (api_name, api_version) =
            selector
                .split_once(':')
                .ok_or_else(|| DiscoveryError::InvalidServiceSelector {
                    selector: selector.to_string(),
                })?;
        Self::new(api_name, api_version)
    }

    /// Canonical `api_name:api_version` identity string.
    #[must_use]
    pub fn identity(&self) -> String {
        format!("{}:{}", self.api_name, self.api_version)
    }
}

impl std::fmt::Display for DiscoveryServiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.api_name, self.api_version)
    }
}

/// Tiny curated alias registry for high-value Google APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAliasRegistry {
    aliases: BTreeMap<String, DiscoveryServiceId>,
}

impl ServiceAliasRegistry {
    /// Resolve a selector as either alias or explicit `service:version`.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::InvalidServiceSelector`] for malformed explicit
    /// selectors and [`DiscoveryError::UnknownServiceAlias`] for unresolved aliases.
    pub fn resolve(&self, selector: &str) -> Result<DiscoveryServiceId, DiscoveryError> {
        let selector = selector.trim();
        if selector.is_empty() {
            return Err(DiscoveryError::InvalidServiceSelector {
                selector: selector.to_string(),
            });
        }

        if selector.contains(':') {
            return DiscoveryServiceId::parse_explicit(selector);
        }

        let alias = normalize_component("alias", selector)?;
        self.aliases
            .get(&alias)
            .cloned()
            .ok_or(DiscoveryError::UnknownServiceAlias { alias })
    }

    /// Insert/replace a curated alias entry.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::InvalidComponent`] when the alias is invalid.
    pub fn insert(
        &mut self,
        alias: impl Into<String>,
        service: DiscoveryServiceId,
    ) -> Result<(), DiscoveryError> {
        let alias = normalize_component("alias", &alias.into())?;
        self.aliases.insert(alias, service);
        Ok(())
    }

    /// Read-only map view of alias entries.
    #[must_use]
    pub const fn aliases(&self) -> &BTreeMap<String, DiscoveryServiceId> {
        &self.aliases
    }
}

impl Default for ServiceAliasRegistry {
    fn default() -> Self {
        let mut aliases = BTreeMap::new();
        aliases.insert(
            "gmail".to_string(),
            DiscoveryServiceId::new("gmail", "v1").expect("static alias must be valid"),
        );
        aliases.insert(
            "calendar".to_string(),
            DiscoveryServiceId::new("calendar", "v3").expect("static alias must be valid"),
        );
        aliases.insert(
            "gcal".to_string(),
            DiscoveryServiceId::new("calendar", "v3").expect("static alias must be valid"),
        );
        aliases.insert(
            "youtube".to_string(),
            DiscoveryServiceId::new("youtube", "v3").expect("static alias must be valid"),
        );
        aliases.insert(
            "bigquery".to_string(),
            DiscoveryServiceId::new("bigquery", "v2").expect("static alias must be valid"),
        );
        aliases.insert(
            "drive".to_string(),
            DiscoveryServiceId::new("drive", "v3").expect("static alias must be valid"),
        );
        aliases.insert(
            "docs".to_string(),
            DiscoveryServiceId::new("docs", "v1").expect("static alias must be valid"),
        );
        aliases.insert(
            "sheets".to_string(),
            DiscoveryServiceId::new("sheets", "v4").expect("static alias must be valid"),
        );
        aliases.insert(
            "google-ai".to_string(),
            DiscoveryServiceId::new("generativelanguage", "v1beta")
                .expect("static alias must be valid"),
        );
        aliases.insert(
            "generativelanguage".to_string(),
            DiscoveryServiceId::new("generativelanguage", "v1beta")
                .expect("static alias must be valid"),
        );
        Self { aliases }
    }
}

/// Discovery endpoint source used for a successful fetch.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryEndpointKind {
    /// Standard Google Discovery API endpoint.
    Standard,
    /// Alternate `$discovery/rest` endpoint.
    Alternate,
}

/// Snapshot fetch output (document + provenance metadata).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FetchedDiscoverySnapshot {
    /// Normalized deterministic snapshot.
    pub snapshot: DiscoverySnapshot,
    /// Endpoint that produced the snapshot.
    pub endpoint: DiscoveryEndpointKind,
    /// Source URL used for successful retrieval.
    pub source_url: String,
    /// BLAKE3 digest of the raw response bytes.
    pub source_digest: String,
}

/// Shared HTTP fetcher for Google Discovery documents.
#[derive(Debug, Clone)]
pub struct DiscoveryFetcher {
    client: reqwest::Client,
    standard_base: String,
    alternate_template: String,
}

impl Default for DiscoveryFetcher {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
            standard_base: DEFAULT_STANDARD_DISCOVERY_BASE.to_string(),
            alternate_template: DEFAULT_ALTERNATE_DISCOVERY_TEMPLATE.to_string(),
        }
    }
}

impl DiscoveryFetcher {
    /// Construct a fetcher with default endpoint configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the reqwest client.
    #[must_use]
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Override the standard endpoint base.
    #[must_use]
    pub fn with_standard_base(mut self, standard_base: impl Into<String>) -> Self {
        self.standard_base = standard_base.into();
        self
    }

    /// Override the alternate endpoint template.
    #[must_use]
    pub fn with_alternate_template(mut self, alternate_template: impl Into<String>) -> Self {
        self.alternate_template = alternate_template.into();
        self
    }

    /// Build the standard and alternate URL candidates for a service.
    #[must_use]
    pub fn candidate_urls(&self, service: &DiscoveryServiceId) -> [String; 2] {
        let standard = format!(
            "{}/{}/{}/rest",
            trim_trailing_slash(&self.standard_base),
            service.api_name,
            service.api_version
        );
        let alternate = self
            .alternate_template
            .replace("{api_name}", &service.api_name)
            .replace("{api_version}", &service.api_version);
        [standard, alternate]
    }

    /// Fetch and normalize a Discovery snapshot for a service identity.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError`] when both standard and alternate endpoint
    /// retrieval/parsing paths fail.
    pub async fn fetch_snapshot(
        &self,
        service: &DiscoveryServiceId,
    ) -> Result<FetchedDiscoverySnapshot, DiscoveryError> {
        let [standard_url, alternate_url] = self.candidate_urls(service);

        match self
            .try_fetch_one(service, DiscoveryEndpointKind::Standard, &standard_url)
            .await
        {
            Ok(snapshot) => Ok(snapshot),
            Err(standard_err) => {
                match self
                    .try_fetch_one(service, DiscoveryEndpointKind::Alternate, &alternate_url)
                    .await
                {
                    Ok(snapshot) => Ok(snapshot),
                    Err(alternate_err) => Err(DiscoveryError::AllEndpointsFailed {
                        service: service.identity(),
                        standard: standard_err.to_string(),
                        alternate: alternate_err.to_string(),
                    }),
                }
            }
        }
    }

    async fn try_fetch_one(
        &self,
        service: &DiscoveryServiceId,
        endpoint: DiscoveryEndpointKind,
        url: &str,
    ) -> Result<FetchedDiscoverySnapshot, DiscoveryError> {
        let resp =
            self.client
                .get(url)
                .send()
                .await
                .map_err(|source| DiscoveryError::RequestFailed {
                    url: url.to_string(),
                    source,
                })?;

        let status = resp.status();
        if !status.is_success() {
            return Err(DiscoveryError::HttpStatus {
                url: url.to_string(),
                status,
            });
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|source| DiscoveryError::RequestFailed {
                url: url.to_string(),
                source,
            })?;
        let snapshot = normalize_snapshot_bytes(service, &bytes, endpoint, url)?;

        Ok(snapshot)
    }
}

/// Build a deterministic snapshot storage key.
#[must_use]
pub fn snapshot_storage_key(service: &DiscoveryServiceId, source_digest: &str) -> String {
    format!(
        "google-discovery/{}/{}/{}",
        service.api_name.trim(),
        service.api_version.trim(),
        source_digest.trim()
    )
}

/// Deterministic normalized Discovery snapshot.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoverySnapshot {
    /// Canonical service identity.
    pub service: DiscoveryServiceId,
    /// Discovery document `name` field.
    pub name: Option<String>,
    /// Service title.
    pub title: Option<String>,
    /// Service description.
    pub description: Option<String>,
    /// Discovery revision.
    pub revision: Option<String>,
    /// Root URL for API requests.
    pub root_url: Option<String>,
    /// Service path suffix.
    pub service_path: Option<String>,
    /// Full base URL.
    pub base_url: Option<String>,
    /// Batch path if provided.
    pub batch_path: Option<String>,
    /// OAuth scopes available for the service.
    pub auth_scopes: Vec<DiscoveryScope>,
    /// Named schema map.
    pub schemas: BTreeMap<String, DiscoverySchema>,
    /// Flattened method catalog keyed by normalized method key.
    pub methods: BTreeMap<String, DiscoveryMethod>,
    /// Resource hierarchy from the source document.
    pub resources: BTreeMap<String, DiscoveryResource>,
}

/// OAuth scope entry from Discovery auth metadata.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct DiscoveryScope {
    /// Scope URI.
    pub id: String,
    /// Optional human description.
    pub description: Option<String>,
}

/// Normalized Discovery resource node.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryResource {
    /// Resource-local methods.
    pub methods: BTreeMap<String, DiscoveryMethod>,
    /// Nested resources.
    pub resources: BTreeMap<String, Self>,
}

/// Normalized method metadata.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryMethod {
    /// Method key (`users.messages.list`, etc).
    pub key: String,
    /// Discovery method ID (for example `gmail.users.messages.list`).
    pub id: String,
    /// HTTP method verb.
    pub http_method: String,
    /// Method path from Discovery (`path` field).
    pub path: String,
    /// Optional `flatPath`.
    pub flat_path: Option<String>,
    /// Chosen canonical path (`flatPath` when present, otherwise `path`).
    pub canonical_path: String,
    /// Resource path prefix for this method.
    pub resource_path: Vec<String>,
    /// Optional description.
    pub description: Option<String>,
    /// Required OAuth scopes at method level.
    pub scopes: Vec<String>,
    /// Request schema reference (`$ref`) when available.
    pub request_ref: Option<String>,
    /// Response schema reference (`$ref`) when available.
    pub response_ref: Option<String>,
    /// Method parameter metadata.
    pub parameters: BTreeMap<String, DiscoveryParameter>,
    /// Discovery flag.
    pub supports_media_download: bool,
    /// Discovery flag.
    pub supports_media_upload: bool,
    /// Upload protocol details when present.
    pub media_upload: Option<DiscoveryMediaUpload>,
}

/// Normalized method parameter metadata.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryParameter {
    /// Parameter location (`path`, `query`, ...).
    pub location: Option<String>,
    /// Whether parameter is required.
    pub required: bool,
    /// Whether parameter is repeated.
    pub repeated: bool,
    /// Discovery type name.
    pub type_name: Option<String>,
    /// Optional data format.
    pub format: Option<String>,
    /// Optional parameter description.
    pub description: Option<String>,
}

/// Media-upload protocol metadata.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryMediaUpload {
    /// Accepted content types.
    pub accept: Vec<String>,
    /// Optional max upload size.
    pub max_size: Option<String>,
    /// Simple upload path.
    pub simple_path: Option<String>,
    /// Resumable upload path.
    pub resumable_path: Option<String>,
}

/// Normalized schema node.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoverySchema {
    /// Discovery type (`object`, `array`, `string`, ...).
    pub type_name: Option<String>,
    /// Optional format (for example `int64`, `date-time`).
    pub format: Option<String>,
    /// Optional human description.
    pub description: Option<String>,
    /// Required property names.
    pub required: Vec<String>,
    /// Enum value set.
    pub enum_values: Vec<String>,
    /// Object property map.
    pub properties: BTreeMap<String, Self>,
    /// Array item schema.
    pub items: Option<Box<Self>>,
    /// Reference target for `$ref` nodes.
    pub ref_name: Option<String>,
    /// Additional-properties schema.
    pub additional_properties: Option<Box<Self>>,
}

/// Normalize a raw Discovery JSON document into deterministic snapshot types.
///
/// # Errors
///
/// Returns [`DiscoveryError::JsonDecode`] if JSON parsing fails and
/// [`DiscoveryError::SchemaDepthExceeded`] for deeply nested schemas.
pub fn normalize_snapshot_bytes(
    service: &DiscoveryServiceId,
    bytes: &[u8],
    endpoint: DiscoveryEndpointKind,
    source_url: &str,
) -> Result<FetchedDiscoverySnapshot, DiscoveryError> {
    let parsed: RawDiscoveryDocument =
        serde_json::from_slice(bytes).map_err(|source| DiscoveryError::JsonDecode {
            url: source_url.to_string(),
            source,
        })?;

    let mut methods = normalize_methods(&parsed.methods, service, &[]);
    let resources = normalize_resources(&parsed.resources, service, &[]);
    collect_resource_methods(&resources, &mut methods);

    let mut auth_scopes = normalize_scopes(parsed.auth);
    auth_scopes.sort();

    let source_digest = blake3::hash(bytes).to_hex().to_string();
    let snapshot = DiscoverySnapshot {
        service: service.clone(),
        name: normalize_optional(parsed.name),
        title: normalize_optional(parsed.title),
        description: normalize_optional(parsed.description),
        revision: normalize_optional(parsed.revision),
        root_url: normalize_optional(parsed.root_url),
        service_path: normalize_optional(parsed.service_path),
        base_url: normalize_optional(parsed.base_url),
        batch_path: normalize_optional(parsed.batch_path),
        auth_scopes,
        schemas: normalize_schema_map(parsed.schemas, 0)?,
        methods,
        resources,
    };

    Ok(FetchedDiscoverySnapshot {
        snapshot,
        endpoint,
        source_url: source_url.to_string(),
        source_digest,
    })
}

fn normalize_schema_map(
    schemas: BTreeMap<String, RawSchema>,
    depth: usize,
) -> Result<BTreeMap<String, DiscoverySchema>, DiscoveryError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(DiscoveryError::SchemaDepthExceeded {
            max_depth: MAX_SCHEMA_DEPTH,
        });
    }

    let mut out = BTreeMap::new();
    for (name, schema) in schemas {
        out.insert(name, normalize_schema(schema, depth + 1)?);
    }
    Ok(out)
}

fn normalize_schema(schema: RawSchema, depth: usize) -> Result<DiscoverySchema, DiscoveryError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(DiscoveryError::SchemaDepthExceeded {
            max_depth: MAX_SCHEMA_DEPTH,
        });
    }

    let mut required: Vec<String> = schema
        .required
        .into_iter()
        .filter_map(|v| normalize_optional(Some(v)))
        .collect();
    required.sort_unstable();
    required.dedup();

    let mut enum_values: Vec<String> = schema
        .enum_values
        .into_iter()
        .filter_map(|v| normalize_optional(Some(v)))
        .collect();
    enum_values.sort_unstable();
    enum_values.dedup();

    let properties = normalize_schema_map(schema.properties, depth + 1)?;
    let items = schema
        .items
        .map(|value| normalize_schema(*value, depth + 1).map(Box::new))
        .transpose()?;
    let additional_properties = schema
        .additional_properties
        .map(|value| normalize_schema(*value, depth + 1).map(Box::new))
        .transpose()?;

    Ok(DiscoverySchema {
        type_name: normalize_optional(schema.type_name),
        format: normalize_optional(schema.format),
        description: normalize_optional(schema.description),
        required,
        enum_values,
        properties,
        items,
        ref_name: normalize_optional(schema.ref_name),
        additional_properties,
    })
}

fn normalize_resources(
    resources: &BTreeMap<String, RawResource>,
    service: &DiscoveryServiceId,
    parent: &[String],
) -> BTreeMap<String, DiscoveryResource> {
    let mut out = BTreeMap::new();
    for (resource_name, raw_resource) in resources {
        let mut next_parent = parent.to_vec();
        next_parent.push(resource_name.clone());
        let methods = normalize_methods(&raw_resource.methods, service, &next_parent);
        let nested = normalize_resources(&raw_resource.resources, service, &next_parent);
        out.insert(
            resource_name.clone(),
            DiscoveryResource {
                methods,
                resources: nested,
            },
        );
    }
    out
}

fn normalize_methods(
    methods: &BTreeMap<String, RawMethod>,
    service: &DiscoveryServiceId,
    resource_path: &[String],
) -> BTreeMap<String, DiscoveryMethod> {
    let mut out = BTreeMap::new();
    for (method_name, method) in methods {
        let key = method_key(resource_path, method_name);
        let flat_path = normalize_optional(method.flat_path.clone());
        let path = normalize_optional(method.path.clone()).unwrap_or_default();
        let canonical_path = flat_path.clone().unwrap_or_else(|| path.clone());
        let mut scopes: Vec<String> = method
            .scopes
            .clone()
            .into_iter()
            .filter_map(|v| normalize_optional(Some(v)))
            .collect();
        scopes.sort_unstable();
        scopes.dedup();

        let id = normalize_optional(method.id.clone())
            .unwrap_or_else(|| format!("{}.{}", service.api_name, key));
        let http_method = normalize_optional(method.http_method.clone())
            .unwrap_or_else(|| "GET".to_string())
            .to_ascii_uppercase();
        let request_ref = method
            .request
            .as_ref()
            .and_then(RawReference::reference_name);
        let response_ref = method
            .response
            .as_ref()
            .and_then(RawReference::reference_name);

        let mut parameters = BTreeMap::new();
        for (param_name, param) in &method.parameters {
            parameters.insert(
                param_name.clone(),
                DiscoveryParameter {
                    location: normalize_optional(param.location.clone()),
                    required: param.required,
                    repeated: param.repeated,
                    type_name: normalize_optional(param.type_name.clone()),
                    format: normalize_optional(param.format.clone()),
                    description: normalize_optional(param.description.clone()),
                },
            );
        }

        let media_upload = method
            .media_upload
            .as_ref()
            .map(|upload| normalize_media_upload(upload.clone()));
        let supports_media_upload = method.supports_media_upload || media_upload.is_some();

        out.insert(
            key.clone(),
            DiscoveryMethod {
                key,
                id,
                http_method,
                path,
                flat_path,
                canonical_path,
                resource_path: resource_path.to_vec(),
                description: normalize_optional(method.description.clone()),
                scopes,
                request_ref,
                response_ref,
                parameters,
                supports_media_download: method.supports_media_download,
                supports_media_upload,
                media_upload,
            },
        );
    }
    out
}

fn normalize_media_upload(upload: RawMediaUpload) -> DiscoveryMediaUpload {
    let mut accept: Vec<String> = upload
        .accept
        .into_iter()
        .filter_map(|v| normalize_optional(Some(v)))
        .collect();
    accept.sort_unstable();
    accept.dedup();

    let simple_path = upload
        .protocols
        .as_ref()
        .and_then(|protocols| protocols.simple.as_ref())
        .and_then(|simple| normalize_optional(simple.path.clone()));
    let resumable_path = upload
        .protocols
        .as_ref()
        .and_then(|protocols| protocols.resumable.as_ref())
        .and_then(|resumable| normalize_optional(resumable.path.clone()));

    DiscoveryMediaUpload {
        accept,
        max_size: normalize_optional(upload.max_size),
        simple_path,
        resumable_path,
    }
}

fn normalize_scopes(auth: Option<RawAuth>) -> Vec<DiscoveryScope> {
    let mut scopes = Vec::new();
    if let Some(auth) = auth {
        for (id, meta) in auth.oauth2.scopes {
            if let Some(normalized) = normalize_optional(Some(id)) {
                scopes.push(DiscoveryScope {
                    id: normalized,
                    description: normalize_optional(meta.description),
                });
            }
        }
    }
    scopes
}

fn collect_resource_methods(
    resources: &BTreeMap<String, DiscoveryResource>,
    out: &mut BTreeMap<String, DiscoveryMethod>,
) {
    for resource in resources.values() {
        for (key, method) in &resource.methods {
            out.insert(key.clone(), method.clone());
        }
        collect_resource_methods(&resource.resources, out);
    }
}

fn method_key(resource_path: &[String], method_name: &str) -> String {
    if resource_path.is_empty() {
        method_name.to_string()
    } else {
        format!("{}.{}", resource_path.join("."), method_name)
    }
}

fn normalize_component(field: &'static str, value: &str) -> Result<String, DiscoveryError> {
    let candidate = value.trim().to_ascii_lowercase();
    if candidate.is_empty() || !candidate.chars().all(is_allowed_component_char) {
        return Err(DiscoveryError::InvalidComponent {
            field,
            value: value.to_string(),
        });
    }
    Ok(candidate)
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

const fn is_allowed_component_char(ch: char) -> bool {
    ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.')
}

fn trim_trailing_slash(value: &str) -> String {
    value.trim_end_matches('/').to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDiscoveryDocument {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    revision: Option<String>,
    #[serde(default)]
    root_url: Option<String>,
    #[serde(default)]
    service_path: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    batch_path: Option<String>,
    #[serde(default)]
    auth: Option<RawAuth>,
    #[serde(default)]
    schemas: BTreeMap<String, RawSchema>,
    #[serde(default)]
    methods: BTreeMap<String, RawMethod>,
    #[serde(default)]
    resources: BTreeMap<String, RawResource>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RawAuth {
    #[serde(default)]
    oauth2: RawOAuth2,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RawOAuth2 {
    #[serde(default)]
    scopes: BTreeMap<String, RawScopeMeta>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RawScopeMeta {
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawResource {
    #[serde(default)]
    methods: BTreeMap<String, RawMethod>,
    #[serde(default)]
    resources: BTreeMap<String, Self>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMethod {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    flat_path: Option<String>,
    #[serde(default)]
    http_method: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    request: Option<RawReference>,
    #[serde(default)]
    response: Option<RawReference>,
    #[serde(default)]
    parameters: BTreeMap<String, RawParameter>,
    #[serde(default)]
    supports_media_download: bool,
    #[serde(default)]
    supports_media_upload: bool,
    #[serde(default)]
    media_upload: Option<RawMediaUpload>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawParameter {
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    repeated: bool,
    #[serde(default, rename = "type")]
    type_name: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RawReference {
    #[serde(default, rename = "$ref")]
    ref_name: Option<String>,
}

impl RawReference {
    fn reference_name(&self) -> Option<String> {
        normalize_optional(self.ref_name.clone())
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMediaUpload {
    #[serde(default)]
    accept: Vec<String>,
    #[serde(default)]
    max_size: Option<String>,
    #[serde(default)]
    protocols: Option<RawUploadProtocols>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RawUploadProtocols {
    #[serde(default)]
    simple: Option<RawUploadProtocol>,
    #[serde(default)]
    resumable: Option<RawUploadProtocol>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RawUploadProtocol {
    #[serde(default)]
    path: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawSchema {
    #[serde(default, rename = "type")]
    type_name: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    required: Vec<String>,
    #[serde(default, rename = "enum")]
    enum_values: Vec<String>,
    #[serde(default)]
    properties: BTreeMap<String, Self>,
    #[serde(default)]
    items: Option<Box<Self>>,
    #[serde(default, rename = "$ref")]
    ref_name: Option<String>,
    #[serde(default)]
    additional_properties: Option<Box<Self>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const GMAIL_FIXTURE: &str = r#"
{
  "name": "gmail",
  "version": "v1",
  "title": "Gmail API",
  "description": "Workspace mail API",
  "revision": "20260306",
  "rootUrl": "https://gmail.googleapis.com/",
  "servicePath": "gmail/v1/users/",
  "baseUrl": "https://gmail.googleapis.com/gmail/v1/users/",
  "auth": {
    "oauth2": {
      "scopes": {
        "https://www.googleapis.com/auth/gmail.modify": {"description": "Modify mailbox"},
        "https://www.googleapis.com/auth/gmail.readonly": {"description": "Read mailbox"}
      }
    }
  },
  "schemas": {
    "MessageList": {
      "type": "object",
      "properties": {
        "messages": {"type": "array", "items": {"$ref": "Message"}}
      }
    },
    "Message": {
      "type": "object",
      "required": ["id"],
      "properties": {
        "id": {"type": "string"},
        "labelIds": {"type": "array", "items": {"type": "string"}}
      }
    }
  },
  "resources": {
    "users": {
      "resources": {
        "messages": {
          "methods": {
            "list": {
              "id": "gmail.users.messages.list",
              "path": "{userId}/messages",
              "flatPath": "gmail/v1/users/{userId}/messages",
              "httpMethod": "GET",
              "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
              "parameters": {
                "q": {"type": "string", "location": "query"},
                "userId": {"type": "string", "location": "path", "required": true}
              },
              "response": {"$ref": "MessageList"}
            }
          }
        }
      }
    }
  }
}
"#;

    const YOUTUBE_FIXTURE: &str = r#"
{
  "name": "youtube",
  "version": "v3",
  "title": "YouTube Data API",
  "rootUrl": "https://youtube.googleapis.com/",
  "servicePath": "youtube/v3/",
  "methods": {
    "videosList": {
      "id": "youtube.videos.list",
      "path": "videos",
      "httpMethod": "GET",
      "scopes": ["https://www.googleapis.com/auth/youtube.readonly"],
      "parameters": {
        "part": {"type": "string", "location": "query", "required": true}
      },
      "response": {"$ref": "VideoListResponse"}
    }
  },
  "schemas": {
    "VideoListResponse": {
      "type": "object",
      "properties": {
        "items": {"type": "array", "items": {"$ref": "Video"}}
      }
    },
    "Video": {
      "type": "object",
      "properties": {
        "id": {"type": "string"}
      }
    }
  }
}
"#;

    #[test]
    fn alias_registry_supports_tiny_curated_map() {
        let registry = ServiceAliasRegistry::default();
        let resolved = registry.resolve("gcal").expect("resolve alias");
        assert_eq!(resolved.api_name, "calendar");
        assert_eq!(resolved.api_version, "v3");
        assert!(registry.aliases().contains_key("gmail"));
    }

    #[test]
    fn explicit_service_version_resolution_is_supported() {
        let registry = ServiceAliasRegistry::default();
        let resolved = registry
            .resolve("generativelanguage:v1beta")
            .expect("resolve explicit selector");
        assert_eq!(resolved.api_name, "generativelanguage");
        assert_eq!(resolved.api_version, "v1beta");
    }

    #[test]
    fn deterministic_snapshot_storage_key() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid id");
        let key_a = snapshot_storage_key(&service, "abc123");
        let key_b = snapshot_storage_key(&service, "abc123");
        assert_eq!(key_a, key_b);
        assert_eq!(key_a, "google-discovery/gmail/v1/abc123");
    }

    #[test]
    fn candidate_urls_include_standard_and_alternate_patterns() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid id");
        let fetcher = DiscoveryFetcher::new();
        let urls = fetcher.candidate_urls(&service);
        assert_eq!(
            urls[0],
            "https://www.googleapis.com/discovery/v1/apis/gmail/v1/rest"
        );
        assert_eq!(
            urls[1],
            "https://gmail.googleapis.com/$discovery/rest?version=v1"
        );
    }

    #[test]
    fn workspace_fixture_normalizes_with_scopes_and_resource_methods() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid id");
        let result = normalize_snapshot_bytes(
            &service,
            GMAIL_FIXTURE.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize gmail fixture");

        assert_eq!(result.snapshot.service.identity(), "gmail:v1");
        assert_eq!(result.snapshot.auth_scopes.len(), 2);
        assert!(result.snapshot.methods.contains_key("users.messages.list"));
        assert!(result.snapshot.schemas.contains_key("Message"));

        let method = result
            .snapshot
            .methods
            .get("users.messages.list")
            .expect("method exists");
        assert_eq!(method.id, "gmail.users.messages.list");
        assert_eq!(method.canonical_path, "gmail/v1/users/{userId}/messages");
    }

    #[test]
    fn non_workspace_fixture_normalizes_top_level_methods() {
        let service = DiscoveryServiceId::new("youtube", "v3").expect("valid id");
        let result = normalize_snapshot_bytes(
            &service,
            YOUTUBE_FIXTURE.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize youtube fixture");

        assert_eq!(result.snapshot.service.identity(), "youtube:v3");
        assert!(result.snapshot.methods.contains_key("videosList"));
        assert!(result.snapshot.schemas.contains_key("Video"));
    }

    #[test]
    fn normalization_is_deterministic_for_identical_input() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid id");
        let first = normalize_snapshot_bytes(
            &service,
            GMAIL_FIXTURE.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("first normalize");
        let second = normalize_snapshot_bytes(
            &service,
            GMAIL_FIXTURE.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("second normalize");
        assert_eq!(first, second);
    }
}
