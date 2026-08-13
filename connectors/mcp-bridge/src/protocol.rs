//! Pure, bounded protocol core for the dual-era n8n MCP Streamable HTTP
//! adapter.  This module performs no network, process, or credential I/O.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use sha2::{Digest as ShaDigest, Sha256};

pub const CURRENT_PROTOCOL_VERSION: &str = "2026-07-28";
pub const LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";
pub const OLDEST_LEGACY_PROTOCOL_VERSION: &str = "2025-06-18";
pub const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_SSE_LINE_BYTES: usize = 64 * 1024;
pub const MAX_SSE_EVENTS: usize = 256;
pub const MAX_SESSION_ID_BYTES: usize = 256;
pub const MAX_PUBLIC_ID_BYTES: usize = 256;
pub const MAX_TOOL_COUNT: usize = 256;
const MCP_NAME_B64_PREFIX: &str = "=?base64?";
const MCP_NAME_B64_SUFFIX: &str = "?=";

/// Stable, redaction-safe protocol errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolError {
    code: ProtocolErrorCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolErrorCode {
    InvalidVersion,
    UnsupportedVersion,
    InvalidMetadata,
    ReservedMetadataConflict,
    InvalidMethod,
    MissingMcpName,
    UnexpectedMcpName,
    InvalidHeaderPlan,
    InvalidSessionId,
    InvalidInitializeResult,
    ModernCorrectionRequired,
    ResponseTooLarge,
    UnsupportedContentType,
    MalformedResponse,
    ResponseIdMismatch,
    DuplicateResponse,
    MissingResponse,
    InvalidCapabilitySnapshot,
    DuplicateToolName,
    DigestFailure,
}

impl ProtocolError {
    const fn new(code: ProtocolErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(self) -> ProtocolErrorCode {
        self.code
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            ProtocolErrorCode::InvalidVersion => "invalid_version",
            ProtocolErrorCode::UnsupportedVersion => "unsupported_version",
            ProtocolErrorCode::InvalidMetadata => "invalid_metadata",
            ProtocolErrorCode::ReservedMetadataConflict => "reserved_metadata_conflict",
            ProtocolErrorCode::InvalidMethod => "invalid_method",
            ProtocolErrorCode::MissingMcpName => "missing_mcp_name",
            ProtocolErrorCode::UnexpectedMcpName => "unexpected_mcp_name",
            ProtocolErrorCode::InvalidHeaderPlan => "invalid_header_plan",
            ProtocolErrorCode::InvalidSessionId => "invalid_session_id",
            ProtocolErrorCode::InvalidInitializeResult => "invalid_initialize_result",
            ProtocolErrorCode::ModernCorrectionRequired => "modern_correction_required",
            ProtocolErrorCode::ResponseTooLarge => "response_too_large",
            ProtocolErrorCode::UnsupportedContentType => "unsupported_content_type",
            ProtocolErrorCode::MalformedResponse => "malformed_response",
            ProtocolErrorCode::ResponseIdMismatch => "response_id_mismatch",
            ProtocolErrorCode::DuplicateResponse => "duplicate_response",
            ProtocolErrorCode::MissingResponse => "missing_response",
            ProtocolErrorCode::InvalidCapabilitySnapshot => "invalid_capability_snapshot",
            ProtocolErrorCode::DuplicateToolName => "duplicate_tool_name",
            ProtocolErrorCode::DigestFailure => "digest_failure",
        })
    }
}

impl std::error::Error for ProtocolError {}

/// MCP versions accepted by this adapter, ordered by deterministic preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolVersion {
    V20260728,
    V20251125,
    V20250618,
}

impl ProtocolVersion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V20260728 => CURRENT_PROTOCOL_VERSION,
            Self::V20251125 => LEGACY_PROTOCOL_VERSION,
            Self::V20250618 => OLDEST_LEGACY_PROTOCOL_VERSION,
        }
    }

    #[must_use]
    pub const fn era(self) -> ProtocolEra {
        match self {
            Self::V20260728 => ProtocolEra::Modern,
            Self::V20251125 | Self::V20250618 => ProtocolEra::Legacy,
        }
    }

    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        match value {
            CURRENT_PROTOCOL_VERSION => Ok(Self::V20260728),
            LEGACY_PROTOCOL_VERSION => Ok(Self::V20251125),
            OLDEST_LEGACY_PROTOCOL_VERSION => Ok(Self::V20250618),
            _ => Err(ProtocolError::new(ProtocolErrorCode::UnsupportedVersion)),
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for ProtocolVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProtocolVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolEra {
    Modern,
    Legacy,
}

#[must_use]
pub const fn supported_versions() -> [ProtocolVersion; 3] {
    [
        ProtocolVersion::V20260728,
        ProtocolVersion::V20251125,
        ProtocolVersion::V20250618,
    ]
}

/// Select the first locally preferred version also offered by the peer.
pub fn negotiate_version(offered: &[ProtocolVersion]) -> Result<ProtocolVersion, ProtocolError> {
    supported_versions()
        .into_iter()
        .find(|candidate| offered.contains(candidate))
        .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::UnsupportedVersion))
}

/// Safe client identity carried by modern metadata and legacy initialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

impl ClientInfo {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Result<Self, ProtocolError> {
        let info = Self {
            name: name.into(),
            version: version.into(),
        };
        validate_public_id(&info.name)?;
        validate_public_id(&info.version)?;
        Ok(info)
    }
}

/// Coarse, closed client capability projection. Unknown provider capability
/// fields are never accepted into the public protocol core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientCapabilities {
    pub roots: bool,
    pub sampling: bool,
    pub elicitation: bool,
}

impl Serialize for ClientCapabilities {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = Map::new();
        if self.roots {
            map.insert("roots".into(), Value::Object(Map::new()));
        }
        if self.sampling {
            map.insert("sampling".into(), Value::Object(Map::new()));
        }
        if self.elicitation {
            map.insert("elicitation".into(), Value::Object(Map::new()));
        }
        map.serialize(serializer)
    }
}

/// Inject current-era metadata while preserving non-reserved caller keys.
pub fn inject_modern_metadata(
    params: &mut Value,
    client_info: &ClientInfo,
    client_capabilities: ClientCapabilities,
) -> Result<(), ProtocolError> {
    let object = params
        .as_object_mut()
        .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::InvalidMetadata))?;
    let meta = match object.entry("_meta") {
        serde_json::map::Entry::Vacant(entry) => entry.insert(Value::Object(Map::new())),
        serde_json::map::Entry::Occupied(entry) => entry.into_mut(),
    };
    let meta = meta
        .as_object_mut()
        .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::InvalidMetadata))?;
    let reserved = [
        (
            "io.modelcontextprotocol/protocolVersion",
            Value::String(CURRENT_PROTOCOL_VERSION.to_string()),
        ),
        (
            "io.modelcontextprotocol/clientCapabilities",
            serde_json::to_value(client_capabilities)
                .map_err(|_| ProtocolError::new(ProtocolErrorCode::InvalidMetadata))?,
        ),
        (
            "io.modelcontextprotocol/clientInfo",
            serde_json::to_value(client_info)
                .map_err(|_| ProtocolError::new(ProtocolErrorCode::InvalidMetadata))?,
        ),
    ];
    for (key, expected) in reserved {
        if let Some(existing) = meta.get(key) {
            if existing != &expected {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::ReservedMetadataConflict,
                ));
            }
        } else {
            meta.insert(key.to_string(), expected);
        }
    }
    Ok(())
}

/// Typed MCP method names accepted by this adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpMethod {
    Initialize,
    Initialized,
    ServerDiscover,
    ToolsList,
    ToolsCall,
    ResourcesList,
    ResourcesRead,
    PromptsList,
    PromptsGet,
    Ping,
}

impl McpMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::Initialized => "notifications/initialized",
            Self::ServerDiscover => "server/discover",
            Self::ToolsList => "tools/list",
            Self::ToolsCall => "tools/call",
            Self::ResourcesList => "resources/list",
            Self::ResourcesRead => "resources/read",
            Self::PromptsList => "prompts/list",
            Self::PromptsGet => "prompts/get",
            Self::Ping => "ping",
        }
    }

    #[must_use]
    pub const fn requires_name(self) -> bool {
        matches!(
            self,
            Self::ToolsCall | Self::ResourcesRead | Self::PromptsGet
        )
    }
}

/// Header-safe MCP name. The value is encoded when plain HTTP header bytes
/// would trim, reject, or collide with the explicit `=?base64?...?=` sentinel.
#[derive(Clone, PartialEq, Eq)]
pub struct McpNameEncoding {
    value: String,
    encoded: bool,
}

impl McpNameEncoding {
    pub fn encode(name: &str) -> Result<Self, ProtocolError> {
        if name.is_empty() || name.len() > MAX_PUBLIC_ID_BYTES {
            return Err(ProtocolError::new(ProtocolErrorCode::InvalidHeaderPlan));
        }
        let plain_bytes = name
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte));
        let has_edge_whitespace = name
            .bytes()
            .next()
            .is_some_and(|byte| byte == b' ' || byte == b'\t')
            || name
                .bytes()
                .next_back()
                .is_some_and(|byte| byte == b' ' || byte == b'\t');
        let sentinel_shaped =
            name.starts_with(MCP_NAME_B64_PREFIX) && name.ends_with(MCP_NAME_B64_SUFFIX);
        let plain = plain_bytes && !has_edge_whitespace && !sentinel_shaped;
        if plain {
            Ok(Self {
                value: name.to_string(),
                encoded: false,
            })
        } else {
            Ok(Self {
                value: format!(
                    "{MCP_NAME_B64_PREFIX}{}{MCP_NAME_B64_SUFFIX}",
                    base64_encode(name.as_bytes())
                ),
                encoded: true,
            })
        }
    }

    #[must_use]
    pub fn header_value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for McpNameEncoding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpNameEncoding")
            .field("kind", &if self.encoded { "base64" } else { "plain" })
            .field("length", &self.header_value().len())
            .finish()
    }
}

/// Redaction-safe core header plan; the adapter can turn these pairs into HTTP
/// headers without accepting arbitrary header names from the caller.
///
/// The 2026 `x-mcp-header` and `Mcp-Param-*` extension-header mechanism is
/// intentionally not represented here. It remains a transport-integration
/// follow-up; callers must not treat this core plan as complete extension
/// header coverage.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpHeaderPlan {
    protocol_version: ProtocolVersion,
    method: McpMethod,
    name: Option<McpNameEncoding>,
    session_id: Option<SessionId>,
}

impl fmt::Debug for HttpHeaderPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpHeaderPlan")
            .field("protocol_version", &self.protocol_version)
            .field("method", &self.method)
            .field("has_name", &self.name.is_some())
            .field("has_session_id", &self.session_id.is_some())
            .finish()
    }
}

impl HttpHeaderPlan {
    pub fn for_request(
        version: ProtocolVersion,
        method: McpMethod,
        name: Option<&str>,
        session_id: Option<SessionId>,
    ) -> Result<Self, ProtocolError> {
        if version.era() == ProtocolEra::Modern
            && matches!(method, McpMethod::Initialize | McpMethod::Initialized)
        {
            return Err(ProtocolError::new(ProtocolErrorCode::InvalidMethod));
        }
        if version.era() == ProtocolEra::Modern && session_id.is_some() {
            return Err(ProtocolError::new(ProtocolErrorCode::InvalidHeaderPlan));
        }
        let name = if version.era() == ProtocolEra::Modern {
            match (method.requires_name(), name) {
                (true, Some(value)) => Some(McpNameEncoding::encode(value)?),
                (true, None) => return Err(ProtocolError::new(ProtocolErrorCode::MissingMcpName)),
                (false, Some(_)) => {
                    return Err(ProtocolError::new(ProtocolErrorCode::UnexpectedMcpName));
                }
                (false, None) => None,
            }
        } else {
            None
        };
        Ok(Self {
            protocol_version: version,
            method,
            name,
            session_id,
        })
    }

    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    #[must_use]
    pub const fn method(&self) -> McpMethod {
        self.method
    }

    #[must_use]
    pub fn header_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = vec![(
            "MCP-Protocol-Version",
            self.protocol_version.as_str().to_string(),
        )];
        if self.protocol_version.era() == ProtocolEra::Modern {
            pairs.push(("Mcp-Method", self.method.as_str().to_string()));
            if let Some(name) = &self.name {
                pairs.push(("Mcp-Name", name.header_value().to_string()));
            }
        }
        if let Some(session_id) = &self.session_id {
            pairs.push(("Mcp-Session-Id", session_id.as_str().to_string()));
        }
        pairs
    }
}

/// Bounded legacy session identifier.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionId(String);

impl SessionId {
    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        if value.is_empty()
            || value.len() > MAX_SESSION_ID_BYTES
            || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(ProtocolError::new(ProtocolErrorCode::InvalidSessionId));
        }
        Ok(Self(value.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionId(<redacted>)")
    }
}

impl Serialize for SessionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// Legacy initialize request; the notification and session remain explicit.
#[derive(Debug, Clone, Serialize)]
pub struct LegacyInitializeRequest {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: &'static str,
    pub params: LegacyInitializeParams,
}

#[derive(Debug, Clone, Serialize)]
pub struct LegacyInitializeParams {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: ProtocolVersion,
    pub capabilities: ClientCapabilities,
    #[serde(rename = "clientInfo")]
    pub client_info: ClientInfo,
}

pub fn legacy_initialize_request(
    id: u64,
    version: ProtocolVersion,
    client_info: ClientInfo,
    capabilities: ClientCapabilities,
) -> Result<LegacyInitializeRequest, ProtocolError> {
    if version.era() != ProtocolEra::Legacy {
        return Err(ProtocolError::new(ProtocolErrorCode::InvalidVersion));
    }
    Ok(LegacyInitializeRequest {
        jsonrpc: "2.0",
        id,
        method: "initialize",
        params: LegacyInitializeParams {
            protocol_version: version,
            capabilities,
            client_info,
        },
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct InitializedNotification {
    pub jsonrpc: &'static str,
    pub method: &'static str,
    pub params: BTreeMap<String, Value>,
}

#[must_use]
pub const fn legacy_initialized_notification() -> InitializedNotification {
    InitializedNotification {
        jsonrpc: "2.0",
        method: "notifications/initialized",
        params: BTreeMap::new(),
    }
}

/// Coarse server capability flags retained from a legacy initialize result.
/// The provider's capability payload is intentionally never exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct ServerCapabilities {
    pub logging: bool,
    pub prompts: bool,
    pub resources: bool,
    pub tools: bool,
}

impl ServerCapabilities {
    fn from_value(value: &Value) -> Result<Self, ProtocolError> {
        let object = value
            .as_object()
            .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::InvalidInitializeResult))?;
        Ok(Self {
            logging: object.contains_key("logging"),
            prompts: object.contains_key("prompts"),
            resources: object.contains_key("resources"),
            tools: object.contains_key("tools"),
        })
    }
}

/// Validated, bounded projection of a legacy initialize result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyInitializeResult {
    pub protocol_version: ProtocolVersion,
    pub server_name: String,
    pub server_version: String,
    pub capabilities: ServerCapabilities,
}

/// A validated initialize response together with the session binding obtained
/// from its HTTP `Mcp-Session-Id` response header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyInitializeResponse {
    pub result: LegacyInitializeResult,
    pub session: LegacySession,
}

/// Parse only the fields needed to establish a legacy session. Unknown
/// provider fields, descriptions, and payloads are discarded.
pub fn parse_legacy_initialize_result(
    value: &Value,
) -> Result<LegacyInitializeResult, ProtocolError> {
    let object = value
        .as_object()
        .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::InvalidInitializeResult))?;
    let protocol_version = object
        .get("protocolVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::InvalidInitializeResult))
        .and_then(ProtocolVersion::parse)?;
    if protocol_version.era() != ProtocolEra::Legacy {
        return Err(ProtocolError::new(
            ProtocolErrorCode::InvalidInitializeResult,
        ));
    }
    let server_info = object
        .get("serverInfo")
        .and_then(Value::as_object)
        .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::InvalidInitializeResult))?;
    let server_name = server_info
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::InvalidInitializeResult))?;
    let server_version = server_info
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::InvalidInitializeResult))?;
    validate_initialize_text(server_name)?;
    validate_initialize_text(server_version)?;
    let capabilities = ServerCapabilities::from_value(
        object
            .get("capabilities")
            .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::InvalidInitializeResult))?,
    )?;
    Ok(LegacyInitializeResult {
        protocol_version,
        server_name: server_name.to_string(),
        server_version: server_version.to_string(),
        capabilities,
    })
}

/// Validate the complete JSON-RPC initialize envelope and bind its negotiated
/// legacy version to the bounded optional HTTP session identifier.
pub fn parse_legacy_initialize_response(
    value: &Value,
    request_id: u64,
    session_id: Option<&str>,
) -> Result<LegacyInitializeResponse, ProtocolError> {
    let object = value
        .as_object()
        .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::InvalidInitializeResult))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(ProtocolError::new(
            ProtocolErrorCode::InvalidInitializeResult,
        ));
    }
    if object.get("id").and_then(Value::as_u64) != Some(request_id) {
        return Err(ProtocolError::new(
            ProtocolErrorCode::InvalidInitializeResult,
        ));
    }
    let result = parse_legacy_initialize_result(
        object
            .get("result")
            .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::InvalidInitializeResult))?,
    )?;
    let session = LegacySession::from_initialize(&result, session_id)?;
    Ok(LegacyInitializeResponse { result, session })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacySession {
    pub protocol_version: ProtocolVersion,
    pub session_id: Option<SessionId>,
}

impl LegacySession {
    pub fn new(
        protocol_version: ProtocolVersion,
        session_id: Option<&str>,
    ) -> Result<Self, ProtocolError> {
        if protocol_version.era() != ProtocolEra::Legacy {
            return Err(ProtocolError::new(ProtocolErrorCode::InvalidVersion));
        }
        Ok(Self {
            protocol_version,
            session_id: session_id.map(SessionId::parse).transpose()?,
        })
    }

    pub fn from_initialize(
        result: &LegacyInitializeResult,
        session_id: Option<&str>,
    ) -> Result<Self, ProtocolError> {
        Self::new(result.protocol_version, session_id)
    }

    pub fn headers(
        &self,
        method: McpMethod,
        name: Option<&str>,
    ) -> Result<HttpHeaderPlan, ProtocolError> {
        HttpHeaderPlan::for_request(self.protocol_version, method, name, self.session_id.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modern400Kind {
    HeaderMismatch,
    MissingRequiredClientCapability,
    UnsupportedProtocolVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modern400Decision {
    Recognized {
        kind: Modern400Kind,
        supported_versions: Vec<ProtocolVersion>,
        selected_version: Option<ProtocolVersion>,
    },
    LegacyFallback,
}

/// Classify only recognized modern protocol errors. They never trigger legacy
/// fallback; empty/unrecognized 400 responses are the sole safe fallback case.
pub fn classify_modern_400(body: &[u8]) -> Modern400Decision {
    if body.is_empty() || body.len() > MAX_SSE_LINE_BYTES {
        return Modern400Decision::LegacyFallback;
    }
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Modern400Decision::LegacyFallback;
    };
    let code = value
        .pointer("/error/code")
        .and_then(Value::as_i64)
        .or_else(|| value.get("code").and_then(Value::as_i64));
    let kind = match code {
        Some(-32020) => Modern400Kind::HeaderMismatch,
        Some(-32021) => Modern400Kind::MissingRequiredClientCapability,
        Some(-32022) => Modern400Kind::UnsupportedProtocolVersion,
        _ => return Modern400Decision::LegacyFallback,
    };
    let supported_versions = if kind == Modern400Kind::UnsupportedProtocolVersion {
        extract_supported_versions(&value)
    } else {
        Vec::new()
    };
    let selected_version = negotiate_version(&supported_versions).ok();
    Modern400Decision::Recognized {
        kind,
        supported_versions,
        selected_version,
    }
}

fn extract_supported_versions(value: &Value) -> Vec<ProtocolVersion> {
    let candidates = [
        value.pointer("/error/data/supportedVersions"),
        value.pointer("/error/data/supported_versions"),
        value.pointer("/error/data/supported"),
        value.get("supportedVersions"),
    ];
    let Some(array) = candidates.into_iter().flatten().find_map(Value::as_array) else {
        return Vec::new();
    };
    let mut versions: Vec<_> = array
        .iter()
        .filter_map(Value::as_str)
        .filter_map(|value| ProtocolVersion::parse(value).ok())
        .collect();
    versions.sort_by_key(|version| supported_versions().iter().position(|item| item == version));
    versions.dedup();
    versions
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseContentType {
    Json,
    EventStream,
}

impl ResponseContentType {
    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        let media_type = value.split(';').next().unwrap_or("").trim();
        match media_type {
            "application/json" => Ok(Self::Json),
            "text/event-stream" => Ok(Self::EventStream),
            _ => Err(ProtocolError::new(
                ProtocolErrorCode::UnsupportedContentType,
            )),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ParsedRpcResponse {
    pub id: u64,
    pub result: Option<Value>,
    pub error: Option<RpcErrorSummary>,
}

impl fmt::Debug for ParsedRpcResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedRpcResponse")
            .field("id", &self.id)
            .field("has_result", &self.result.is_some())
            .field("error_code", &self.error.as_ref().map(|error| error.code))
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcErrorSummary {
    pub code: i64,
}

/// Dispatch bounded JSON or SSE response parsing and require one exact id.
pub fn parse_response(
    content_type: &str,
    body: &[u8],
    request_id: u64,
) -> Result<ParsedRpcResponse, ProtocolError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(ProtocolError::new(ProtocolErrorCode::ResponseTooLarge));
    }
    match ResponseContentType::parse(content_type)? {
        ResponseContentType::Json => parse_json_response(body, request_id),
        ResponseContentType::EventStream => parse_sse_response(body, request_id),
    }
}

fn parse_json_response(body: &[u8], request_id: u64) -> Result<ParsedRpcResponse, ProtocolError> {
    let value = serde_json::from_slice::<Value>(body)
        .map_err(|_| ProtocolError::new(ProtocolErrorCode::MalformedResponse))?;
    parse_response_value(&value, request_id)
}

fn parse_response_value(
    value: &Value,
    request_id: u64,
) -> Result<ParsedRpcResponse, ProtocolError> {
    let object = value
        .as_object()
        .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::MalformedResponse))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(ProtocolError::new(ProtocolErrorCode::MalformedResponse));
    }
    let id = object
        .get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::MalformedResponse))?;
    if id != request_id {
        return Err(ProtocolError::new(ProtocolErrorCode::ResponseIdMismatch));
    }
    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");
    if has_result == has_error {
        return Err(ProtocolError::new(ProtocolErrorCode::MalformedResponse));
    }
    let error = if has_error {
        let error = object
            .get("error")
            .and_then(Value::as_object)
            .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::MalformedResponse))?;
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::MalformedResponse))?;
        if error.get("message").and_then(Value::as_str).is_none() {
            return Err(ProtocolError::new(ProtocolErrorCode::MalformedResponse));
        }
        Some(RpcErrorSummary { code })
    } else {
        None
    };
    Ok(ParsedRpcResponse {
        id,
        result: object.get("result").cloned(),
        error,
    })
}

fn parse_sse_response(body: &[u8], request_id: u64) -> Result<ParsedRpcResponse, ProtocolError> {
    let mut current_data = String::new();
    let mut response = None;
    let mut events = 0usize;
    for raw_line in body.split_inclusive(|byte| *byte == b'\n') {
        if raw_line.len() > MAX_SSE_LINE_BYTES {
            return Err(ProtocolError::new(ProtocolErrorCode::ResponseTooLarge));
        }
        let line = raw_line.strip_suffix(b"\n").unwrap_or(raw_line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            process_sse_event(&mut current_data, &mut response, request_id)?;
            events += 1;
            if events > MAX_SSE_EVENTS {
                return Err(ProtocolError::new(ProtocolErrorCode::ResponseTooLarge));
            }
            continue;
        }
        if let Some(data) = line.strip_prefix(b"data:") {
            let data = data.strip_prefix(b" ").unwrap_or(data);
            let text = std::str::from_utf8(data)
                .map_err(|_| ProtocolError::new(ProtocolErrorCode::MalformedResponse))?;
            if !current_data.is_empty() {
                current_data.push('\n');
            }
            current_data.push_str(text);
        }
    }
    if !current_data.is_empty() {
        process_sse_event(&mut current_data, &mut response, request_id)?;
    }
    response.ok_or_else(|| ProtocolError::new(ProtocolErrorCode::MissingResponse))
}

fn process_sse_event(
    data: &mut String,
    response: &mut Option<ParsedRpcResponse>,
    request_id: u64,
) -> Result<(), ProtocolError> {
    if data.is_empty() {
        return Ok(());
    }
    let value = serde_json::from_str::<Value>(data)
        .map_err(|_| ProtocolError::new(ProtocolErrorCode::MalformedResponse))?;
    data.clear();
    let object = value
        .as_object()
        .ok_or_else(|| ProtocolError::new(ProtocolErrorCode::MalformedResponse))?;
    if !object.contains_key("id") {
        return Ok(());
    }
    let parsed = parse_response_value(&value, request_id)?;
    if response.is_some() {
        return Err(ProtocolError::new(ProtocolErrorCode::DuplicateResponse));
    }
    *response = Some(parsed);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerId {
    Eec,
    Hetzner,
    Legacy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    OAuth,
    AccessToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolClass {
    Read,
    Write,
    Execution,
    Credential,
    Destructive,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    Approved,
    Blocked,
    Changed,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ToolObservation {
    name: String,
    input_schema_digest: String,
    output_schema_digest: String,
    class: ToolClass,
}

impl ToolObservation {
    pub fn from_schemas(
        name: &str,
        input_schema: &Value,
        output_schema: &Value,
        class: ToolClass,
    ) -> Result<Self, ProtocolError> {
        validate_public_id(name)?;
        Ok(Self {
            name: name.to_string(),
            input_schema_digest: digest_json(input_schema)?,
            output_schema_digest: digest_json(output_schema)?,
            class,
        })
    }

    pub fn from_digests(
        name: &str,
        input_schema_digest: &str,
        output_schema_digest: &str,
        class: ToolClass,
    ) -> Result<Self, ProtocolError> {
        validate_public_id(name)?;
        validate_public_id(input_schema_digest)?;
        validate_public_id(output_schema_digest)?;
        Ok(Self {
            name: name.to_string(),
            input_schema_digest: input_schema_digest.to_string(),
            output_schema_digest: output_schema_digest.to_string(),
            class,
        })
    }
}

impl fmt::Debug for ToolObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolObservation")
            .field("name", &"<redacted>")
            .field("class", &self.class)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCapability {
    pub name: String,
    pub input_schema_digest: String,
    pub output_schema_digest: String,
    pub class: ToolClass,
    pub status: ToolStatus,
}

impl fmt::Debug for ToolCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolCapability")
            .field("name", &"<redacted>")
            .field("class", &self.class)
            .field("status", &self.status)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotMaterial {
    server_id: ServerId,
    n8n_version: String,
    era: ProtocolEra,
    protocol_versions: Vec<ProtocolVersion>,
    auth_mode: AuthMode,
    api_scope_digest: String,
    tools: Vec<ToolCapability>,
}

/// Safe capability discovery projection; no descriptions, schemas, responses,
/// credentials, or auth headers are retained.
#[derive(Clone, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    pub server_id: ServerId,
    pub n8n_version: String,
    pub era: ProtocolEra,
    pub protocol_versions: Vec<ProtocolVersion>,
    pub auth_mode: AuthMode,
    pub api_scope_digest: String,
    pub tools: Vec<ToolCapability>,
    pub snapshot_digest: String,
}

impl fmt::Debug for CapabilitySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilitySnapshot")
            .field("server_id", &self.server_id)
            .field("n8n_version", &self.n8n_version)
            .field("era", &self.era)
            .field("protocol_versions", &self.protocol_versions)
            .field("auth_mode", &self.auth_mode)
            .field("tool_count", &self.tools.len())
            .field("snapshot_digest", &self.snapshot_digest)
            .finish()
    }
}

impl CapabilitySnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn from_observations(
        server_id: ServerId,
        n8n_version: &str,
        era: ProtocolEra,
        protocol_versions: Vec<ProtocolVersion>,
        auth_mode: AuthMode,
        api_scope_digest: &str,
        observations: Vec<ToolObservation>,
        previous: Option<&Self>,
    ) -> Result<Self, ProtocolError> {
        validate_public_id(n8n_version)?;
        validate_public_id(api_scope_digest)?;
        if protocol_versions.is_empty() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::InvalidCapabilitySnapshot,
            ));
        }
        if protocol_versions.iter().any(|version| version.era() != era) {
            return Err(ProtocolError::new(
                ProtocolErrorCode::InvalidCapabilitySnapshot,
            ));
        }
        if observations.len() > MAX_TOOL_COUNT {
            return Err(ProtocolError::new(
                ProtocolErrorCode::InvalidCapabilitySnapshot,
            ));
        }
        let mut protocol_versions = protocol_versions;
        protocol_versions.sort_by_key(|version| {
            supported_versions()
                .iter()
                .position(|item| item == version)
                .unwrap_or(usize::MAX)
        });
        protocol_versions.dedup();
        let mut observations = observations;
        observations.sort_by(|left, right| left.name.cmp(&right.name));
        if observations
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
        {
            return Err(ProtocolError::new(ProtocolErrorCode::DuplicateToolName));
        }
        let tools: Vec<ToolCapability> = observations
            .into_iter()
            .map(|observation| {
                let status = previous
                    .and_then(|snapshot| {
                        snapshot
                            .tools
                            .iter()
                            .find(|tool| tool.name == observation.name)
                    })
                    .map_or_else(
                        || default_tool_status(observation.class),
                        |old| {
                            if old.class == observation.class
                                && old.input_schema_digest == observation.input_schema_digest
                                && old.output_schema_digest == observation.output_schema_digest
                            {
                                old.status
                            } else {
                                ToolStatus::Changed
                            }
                        },
                    );
                ToolCapability {
                    name: observation.name,
                    input_schema_digest: observation.input_schema_digest,
                    output_schema_digest: observation.output_schema_digest,
                    class: observation.class,
                    status,
                }
            })
            .collect();
        let material = SnapshotMaterial {
            server_id,
            n8n_version: n8n_version.to_string(),
            era,
            protocol_versions,
            auth_mode,
            api_scope_digest: api_scope_digest.to_string(),
            tools: tools.clone(),
        };
        let snapshot_digest = digest_serializable(&material)?;
        Ok(Self {
            server_id,
            n8n_version: n8n_version.to_string(),
            era,
            protocol_versions: material.protocol_versions,
            auth_mode,
            api_scope_digest: api_scope_digest.to_string(),
            tools,
            snapshot_digest,
        })
    }

    #[must_use]
    pub fn tool_status(&self, name: &str) -> Option<ToolStatus> {
        self.tools
            .iter()
            .find(|tool| tool.name == name)
            .map(|tool| tool.status)
    }

    /// Approve one observed tool only after an exact reviewed tuple match.
    pub fn approve_tool(
        &mut self,
        name: &str,
        class: ToolClass,
        input_schema_digest: &str,
        output_schema_digest: &str,
    ) -> Result<(), ProtocolError> {
        let Some(tool) = self.tools.iter_mut().find(|tool| tool.name == name) else {
            return Err(ProtocolError::new(
                ProtocolErrorCode::InvalidCapabilitySnapshot,
            ));
        };
        if class == ToolClass::Unknown
            || tool.class == ToolClass::Unknown
            || tool.class != class
            || tool.input_schema_digest != input_schema_digest
            || tool.output_schema_digest != output_schema_digest
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::InvalidCapabilitySnapshot,
            ));
        }
        tool.status = ToolStatus::Approved;
        self.refresh_snapshot_digest()
    }

    /// Return whether a tool is not an exactly approved capability.
    #[must_use]
    pub fn tool_call_is_blocked(&self, name: &str) -> bool {
        self.tools
            .iter()
            .find(|tool| tool.name == name)
            .is_none_or(|tool| {
                tool.class == ToolClass::Unknown || tool.status != ToolStatus::Approved
            })
    }

    #[must_use]
    pub fn write_tool_is_blocked(&self, name: &str) -> bool {
        self.tool_call_is_blocked(name)
    }

    fn refresh_snapshot_digest(&mut self) -> Result<(), ProtocolError> {
        let material = SnapshotMaterial {
            server_id: self.server_id,
            n8n_version: self.n8n_version.clone(),
            era: self.era,
            protocol_versions: self.protocol_versions.clone(),
            auth_mode: self.auth_mode,
            api_scope_digest: self.api_scope_digest.clone(),
            tools: self.tools.clone(),
        };
        self.snapshot_digest = digest_serializable(&material)?;
        Ok(())
    }
}

fn default_tool_status(class: ToolClass) -> ToolStatus {
    if class == ToolClass::Read {
        ToolStatus::Approved
    } else {
        ToolStatus::Blocked
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestTermination {
    Completed,
    Cancelled,
    TimedOut,
    ResponseUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDisposition {
    Allowed,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestDisposition {
    pub termination: RequestTermination,
    pub retry: RetryDisposition,
}

impl RequestDisposition {
    #[must_use]
    pub const fn for_termination(termination: RequestTermination) -> Self {
        let retry = match termination {
            RequestTermination::Completed => RetryDisposition::Allowed,
            RequestTermination::Cancelled
            | RequestTermination::TimedOut
            | RequestTermination::ResponseUnknown => RetryDisposition::Never,
        };
        Self { termination, retry }
    }

    #[must_use]
    pub const fn no_retry(self) -> bool {
        matches!(self.retry, RetryDisposition::Never)
    }
}

fn validate_public_id(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > MAX_PUBLIC_ID_BYTES || value.chars().any(char::is_control)
    {
        return Err(ProtocolError::new(
            ProtocolErrorCode::InvalidCapabilitySnapshot,
        ));
    }
    Ok(())
}

fn validate_initialize_text(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > MAX_PUBLIC_ID_BYTES || value.chars().any(char::is_control)
    {
        return Err(ProtocolError::new(
            ProtocolErrorCode::InvalidInitializeResult,
        ));
    }
    Ok(())
}

fn digest_json(value: &Value) -> Result<String, ProtocolError> {
    Ok(digest_bytes(&canonical_json(value)?))
}

fn digest_serializable<T: Serialize>(value: &T) -> Result<String, ProtocolError> {
    let value = serde_json::to_value(value)
        .map_err(|_| ProtocolError::new(ProtocolErrorCode::DigestFailure))?;
    digest_json(&value)
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, ProtocolError> {
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut ordered = BTreeMap::new();
                for (key, value) in map {
                    ordered.insert(key.clone(), canonical(value));
                }
                Value::Object(ordered.into_iter().collect())
            }
            Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_vec(&canonical(value))
        .map_err(|_| ProtocolError::new(ProtocolErrorCode::DigestFailure))
}

fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(7 + digest.len() * 2);
    encoded.push_str("sha256:");
    encoded.push_str(&hex::encode(digest));
    encoded
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied();
        let third = chunk.get(2).copied();
        output.push(TABLE[(first >> 2) as usize] as char);
        output.push(
            TABLE[((first & 0x03) << 4 | second.map_or(0, |value| value >> 4)) as usize] as char,
        );
        output.push(second.map_or('=', |value| {
            TABLE[((value & 0x0f) << 2 | third.map_or(0, |item| item >> 6)) as usize] as char
        }));
        output.push(third.map_or('=', |value| TABLE[(value & 0x3f) as usize] as char));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn info() -> ClientInfo {
        ClientInfo::new("fcp-mcp-bridge", "0.1.0").unwrap()
    }

    fn observation(name: &str, class: ToolClass) -> ToolObservation {
        ToolObservation::from_schemas(name, &json!({"type": "object"}), &json!({}), class).unwrap()
    }

    #[test]
    fn version_preference_is_modern_then_legacy() {
        assert_eq!(
            negotiate_version(&[ProtocolVersion::V20250618]),
            Ok(ProtocolVersion::V20250618)
        );
        assert_eq!(
            negotiate_version(&[
                ProtocolVersion::V20250618,
                ProtocolVersion::V20260728,
                ProtocolVersion::V20251125
            ]),
            Ok(ProtocolVersion::V20260728)
        );
    }

    #[test]
    fn modern_metadata_preserves_non_reserved_and_rejects_conflict() {
        let mut params = json!({"keep": true, "_meta": {"x-safe": "kept"}});
        inject_modern_metadata(&mut params, &info(), ClientCapabilities::default()).unwrap();
        assert_eq!(params["_meta"]["x-safe"], Value::String("kept".into()));
        assert_eq!(
            params["_meta"]["io.modelcontextprotocol/protocolVersion"],
            CURRENT_PROTOCOL_VERSION
        );

        let mut conflicting = json!({"_meta": {"io.modelcontextprotocol/protocolVersion": "old"}});
        assert_eq!(
            inject_modern_metadata(&mut conflicting, &info(), ClientCapabilities::default())
                .unwrap_err()
                .code(),
            ProtocolErrorCode::ReservedMetadataConflict
        );
    }

    #[test]
    fn mcp_name_plain_base64_and_sentinel_encoding() {
        assert_eq!(
            McpNameEncoding::encode("tool call").unwrap().header_value(),
            "tool call"
        );
        assert_eq!(
            McpNameEncoding::encode("tool\tcall")
                .unwrap()
                .header_value(),
            "tool\tcall"
        );
        assert!(
            McpNameEncoding::encode(" trim")
                .unwrap()
                .header_value()
                .starts_with(MCP_NAME_B64_PREFIX)
        );
        assert!(
            McpNameEncoding::encode("trim ")
                .unwrap()
                .header_value()
                .starts_with(MCP_NAME_B64_PREFIX)
        );
        let sentinel = McpNameEncoding::encode("=?base64?YWJj?=").unwrap();
        assert!(sentinel.header_value().starts_with(MCP_NAME_B64_PREFIX));
        assert!(
            McpNameEncoding::encode("=?base64??=")
                .unwrap()
                .header_value()
                .starts_with(MCP_NAME_B64_PREFIX)
        );
        assert_eq!(
            McpNameEncoding::encode("é").unwrap().header_value(),
            "=?base64?w6k=?="
        );
    }

    #[test]
    fn header_plan_requires_name_only_for_named_methods() {
        assert!(
            HttpHeaderPlan::for_request(
                ProtocolVersion::V20260728,
                McpMethod::ToolsCall,
                None,
                None
            )
            .is_err()
        );
        let plan = HttpHeaderPlan::for_request(
            ProtocolVersion::V20260728,
            McpMethod::ToolsCall,
            Some("tool"),
            None,
        )
        .unwrap();
        assert!(
            plan.header_pairs()
                .iter()
                .any(|(name, _)| *name == "Mcp-Name")
        );
        let modern = HttpHeaderPlan::for_request(
            ProtocolVersion::V20260728,
            McpMethod::ToolsList,
            None,
            None,
        )
        .unwrap();
        assert!(
            modern
                .header_pairs()
                .iter()
                .all(|(name, _)| *name != "Mcp-Session-Id")
        );
        assert!(
            HttpHeaderPlan::for_request(
                ProtocolVersion::V20260728,
                McpMethod::Initialize,
                None,
                None
            )
            .is_err()
        );
        assert!(
            HttpHeaderPlan::for_request(
                ProtocolVersion::V20260728,
                McpMethod::PromptsGet,
                None,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn recognized_modern_400_never_falls_back() {
        let decision = classify_modern_400(br#"{"error":{"code":-32020}}"#);
        assert!(matches!(
            decision,
            Modern400Decision::Recognized {
                kind: Modern400Kind::HeaderMismatch,
                ..
            }
        ));
        let decision = classify_modern_400(br#"{"error":{"code":-32021}}"#);
        assert!(matches!(
            decision,
            Modern400Decision::Recognized {
                kind: Modern400Kind::MissingRequiredClientCapability,
                ..
            }
        ));
    }

    #[test]
    fn unsupported_version_uses_allowlist_selection() {
        let decision = classify_modern_400(
            br#"{"error":{"code":-32022,"data":{"supportedVersions":["2025-06-18","2026-07-28"]}}}"#,
        );
        assert_eq!(
            decision,
            Modern400Decision::Recognized {
                kind: Modern400Kind::UnsupportedProtocolVersion,
                supported_versions: vec![ProtocolVersion::V20260728, ProtocolVersion::V20250618],
                selected_version: Some(ProtocolVersion::V20260728),
            }
        );
    }

    #[test]
    fn empty_or_unknown_400_is_only_legacy_fallback() {
        assert_eq!(classify_modern_400(b""), Modern400Decision::LegacyFallback);
        assert_eq!(
            classify_modern_400(br#"{"error":{"code":-32099}}"#),
            Modern400Decision::LegacyFallback
        );
    }

    #[test]
    fn legacy_initialize_and_session_are_validated() {
        let request = legacy_initialize_request(
            7,
            ProtocolVersion::V20251125,
            info(),
            ClientCapabilities {
                roots: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            legacy_initialize_request(
                7,
                ProtocolVersion::V20260728,
                info(),
                ClientCapabilities::default()
            )
            .is_err()
        );
        let encoded = serde_json::to_value(request).unwrap();
        assert_eq!(encoded["method"], "initialize");
        assert_eq!(
            encoded["params"]["protocolVersion"],
            LEGACY_PROTOCOL_VERSION
        );
        let session = LegacySession::new(ProtocolVersion::V20251125, Some("sid-1")).unwrap();
        assert!(
            session
                .headers(McpMethod::ToolsList, None)
                .unwrap()
                .header_pairs()
                .iter()
                .any(|(name, _)| *name == "Mcp-Session-Id")
        );
        assert!(
            session
                .headers(McpMethod::ToolsCall, Some("tool"))
                .unwrap()
                .header_pairs()
                .iter()
                .all(|(name, _)| *name != "Mcp-Method" && *name != "Mcp-Name")
        );
        assert!(session.headers(McpMethod::ToolsCall, None).is_ok());
        assert!(LegacySession::new(ProtocolVersion::V20260728, None).is_err());
        assert!(SessionId::parse("bad\nvalue").is_err());

        let result = parse_legacy_initialize_result(&json!({
            "protocolVersion": LEGACY_PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "n8n", "version": "1.0"},
            "providerPayload": {"secret": "discarded"}
        }))
        .unwrap();
        assert!(result.capabilities.tools);
        let response = parse_legacy_initialize_response(
            &json!({
                "jsonrpc": "2.0",
                "id": 7,
                "result": {
                    "protocolVersion": LEGACY_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "n8n", "version": "1.0"}
                }
            }),
            7,
            Some("sid-2"),
        )
        .unwrap();
        assert_eq!(
            response.session.session_id.as_ref().unwrap().as_str(),
            "sid-2"
        );
        assert!(
            parse_legacy_initialize_response(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 8,
                    "result": {
                        "protocolVersion": LEGACY_PROTOCOL_VERSION,
                        "capabilities": {},
                        "serverInfo": {"name": "n8n", "version": "1.0"}
                    }
                }),
                7,
                None,
            )
            .is_err()
        );
        assert_eq!(
            LegacySession::from_initialize(&result, Some("sid-2"))
                .unwrap()
                .protocol_version,
            ProtocolVersion::V20251125
        );
        assert!(
            parse_legacy_initialize_result(&json!({
                "protocolVersion": CURRENT_PROTOCOL_VERSION,
                "capabilities": {},
                "serverInfo": {"name": "n8n", "version": "1.0"}
            }))
            .is_err()
        );
    }

    #[test]
    fn legacy_initialized_notification_is_idless() {
        let value = serde_json::to_value(legacy_initialized_notification()).unwrap();
        assert_eq!(value["method"], "notifications/initialized");
        assert!(value.get("id").is_none());
    }

    #[test]
    fn json_response_requires_exact_id() {
        let body = br#"{"jsonrpc":"2.0","id":4,"result":{"ok":true}}"#;
        let parsed = parse_response("application/json; charset=utf-8", body, 4).unwrap();
        assert_eq!(parsed.id, 4);
        assert_eq!(
            parsed
                .result
                .as_ref()
                .and_then(|value| value.get("ok"))
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            parse_response("application/json", body, 5)
                .unwrap_err()
                .code(),
            ProtocolErrorCode::ResponseIdMismatch
        );
    }

    #[test]
    fn multiline_sse_selects_matching_response_and_ignores_events() {
        let body = concat!(
            "event: notice\n",
            "data: {\"method\":\"notifications/progress\"}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\n",
            "data: \"id\":9,\n",
            "data: \"result\":{\"ok\":true}}\n\n",
        )
        .as_bytes();
        let parsed = parse_response("text/event-stream", body, 9).unwrap();
        assert_eq!(parsed.id, 9);
    }

    #[test]
    fn sse_mismatch_duplicate_and_size_are_rejected() {
        let mismatch = b"data: {\"jsonrpc\":\"2.0\",\"id\":8,\"result\":{}}\n\n";
        assert_eq!(
            parse_response("text/event-stream", mismatch, 9)
                .unwrap_err()
                .code(),
            ProtocolErrorCode::ResponseIdMismatch
        );
        let duplicate = b"data: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}\n\n";
        assert_eq!(
            parse_response("text/event-stream", duplicate, 9)
                .unwrap_err()
                .code(),
            ProtocolErrorCode::DuplicateResponse
        );
        assert_eq!(
            parse_response("application/json", &vec![b'x'; MAX_RESPONSE_BYTES + 1], 1)
                .unwrap_err()
                .code(),
            ProtocolErrorCode::ResponseTooLarge
        );
    }

    #[test]
    fn unrelated_sse_without_id_is_not_authoritative() {
        let body = b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\n";
        assert_eq!(
            parse_response("text/event-stream", body, 1)
                .unwrap_err()
                .code(),
            ProtocolErrorCode::MissingResponse
        );
        let malformed = b"data: {not-json}\n\n";
        assert_eq!(
            parse_response("text/event-stream", malformed, 1)
                .unwrap_err()
                .code(),
            ProtocolErrorCode::MalformedResponse
        );
    }

    #[test]
    fn capability_snapshots_are_server_scoped_and_unknown_writes_blocked() {
        let eec = CapabilitySnapshot::from_observations(
            ServerId::Eec,
            "1.0",
            ProtocolEra::Modern,
            vec![ProtocolVersion::V20260728],
            AuthMode::AccessToken,
            "scope-eec",
            vec![
                observation("read", ToolClass::Read),
                observation("new-write", ToolClass::Unknown),
            ],
            None,
        )
        .unwrap();
        let hetzner = CapabilitySnapshot::from_observations(
            ServerId::Hetzner,
            "1.0",
            ProtocolEra::Modern,
            vec![ProtocolVersion::V20260728],
            AuthMode::AccessToken,
            "scope-eec",
            vec![
                observation("read", ToolClass::Read),
                observation("new-write", ToolClass::Unknown),
            ],
            None,
        )
        .unwrap();
        assert_ne!(eec.snapshot_digest, hetzner.snapshot_digest);
        assert!(eec.write_tool_is_blocked("new-write"));
        assert!(!eec.write_tool_is_blocked("read"));
        let duplicate = CapabilitySnapshot::from_observations(
            ServerId::Eec,
            "1.0",
            ProtocolEra::Modern,
            vec![ProtocolVersion::V20260728],
            AuthMode::AccessToken,
            "scope-eec",
            vec![
                observation("read", ToolClass::Read),
                observation("read", ToolClass::Read),
            ],
            None,
        );
        assert_eq!(
            duplicate.unwrap_err().code(),
            ProtocolErrorCode::DuplicateToolName
        );
    }

    fn single_snapshot(name: &str, class: ToolClass) -> CapabilitySnapshot {
        CapabilitySnapshot::from_observations(
            ServerId::Eec,
            "1.0",
            ProtocolEra::Modern,
            vec![ProtocolVersion::V20260728],
            AuthMode::AccessToken,
            "scope",
            vec![observation(name, class)],
            None,
        )
        .unwrap()
    }

    #[test]
    fn exact_approval_allows_every_non_unknown_class() {
        let classes = [
            ToolClass::Read,
            ToolClass::Write,
            ToolClass::Execution,
            ToolClass::Credential,
            ToolClass::Destructive,
        ];
        let observations = classes
            .iter()
            .enumerate()
            .map(|(index, class)| observation(&format!("tool-{index}"), *class))
            .collect();
        let mut snapshot = CapabilitySnapshot::from_observations(
            ServerId::Eec,
            "1.0",
            ProtocolEra::Modern,
            vec![ProtocolVersion::V20260728],
            AuthMode::AccessToken,
            "scope",
            observations,
            None,
        )
        .unwrap();
        let reviewed: Vec<_> = snapshot
            .tools
            .iter()
            .map(|tool| {
                (
                    tool.name.clone(),
                    tool.class,
                    tool.input_schema_digest.clone(),
                    tool.output_schema_digest.clone(),
                )
            })
            .collect();
        let before = snapshot.snapshot_digest.clone();
        for (name, class, input_digest, output_digest) in reviewed {
            snapshot
                .approve_tool(&name, class, &input_digest, &output_digest)
                .unwrap();
            assert_eq!(snapshot.tool_status(&name), Some(ToolStatus::Approved));
            assert!(!snapshot.tool_call_is_blocked(&name));
        }
        assert_ne!(before, snapshot.snapshot_digest);
    }

    #[test]
    fn approval_requires_exact_reviewed_tuple_and_unknown_never_approves() {
        let snapshot = single_snapshot("reviewed", ToolClass::Read);
        let input_digest = snapshot.tools[0].input_schema_digest.clone();
        let output_digest = snapshot.tools[0].output_schema_digest.clone();
        let expected = ProtocolErrorCode::InvalidCapabilitySnapshot;

        let mut wrong_name = snapshot.clone();
        assert_eq!(
            wrong_name
                .approve_tool("other", ToolClass::Read, &input_digest, &output_digest)
                .unwrap_err()
                .code(),
            expected
        );
        let mut wrong_class = snapshot.clone();
        assert_eq!(
            wrong_class
                .approve_tool("reviewed", ToolClass::Write, &input_digest, &output_digest)
                .unwrap_err()
                .code(),
            expected
        );
        let mut wrong_input = snapshot.clone();
        assert_eq!(
            wrong_input
                .approve_tool("reviewed", ToolClass::Read, "wrong-input", &output_digest)
                .unwrap_err()
                .code(),
            expected
        );
        let mut wrong_output = snapshot.clone();
        assert_eq!(
            wrong_output
                .approve_tool("reviewed", ToolClass::Read, &input_digest, "wrong-output")
                .unwrap_err()
                .code(),
            expected
        );

        let mut unknown = single_snapshot("unknown", ToolClass::Unknown);
        let unknown_input = unknown.tools[0].input_schema_digest.clone();
        let unknown_output = unknown.tools[0].output_schema_digest.clone();
        assert_eq!(
            unknown
                .approve_tool(
                    "unknown",
                    ToolClass::Unknown,
                    &unknown_input,
                    &unknown_output
                )
                .unwrap_err()
                .code(),
            expected
        );
        assert!(unknown.tool_call_is_blocked("unknown"));
    }

    #[test]
    fn approval_digest_is_changed_and_deterministic() {
        let mut first = single_snapshot("write", ToolClass::Write);
        let input_digest = first.tools[0].input_schema_digest.clone();
        let output_digest = first.tools[0].output_schema_digest.clone();
        let before = first.snapshot_digest.clone();
        first
            .approve_tool("write", ToolClass::Write, &input_digest, &output_digest)
            .unwrap();

        let mut second = single_snapshot("write", ToolClass::Write);
        second
            .approve_tool("write", ToolClass::Write, &input_digest, &output_digest)
            .unwrap();
        assert_ne!(before, first.snapshot_digest);
        assert_eq!(first.snapshot_digest, second.snapshot_digest);
    }

    #[test]
    fn capability_snapshot_rejects_more_than_maximum_tool_count() {
        let observations = (0..=MAX_TOOL_COUNT)
            .map(|index| observation(&format!("tool-{index}"), ToolClass::Read))
            .collect();
        let error = CapabilitySnapshot::from_observations(
            ServerId::Eec,
            "1.0",
            ProtocolEra::Modern,
            vec![ProtocolVersion::V20260728],
            AuthMode::AccessToken,
            "scope",
            observations,
            None,
        )
        .unwrap_err();
        assert_eq!(error.code(), ProtocolErrorCode::InvalidCapabilitySnapshot);
    }

    #[test]
    fn tool_call_policy_blocks_missing_unknown_changed_and_blocked() {
        let previous = single_snapshot("changed", ToolClass::Read);
        let changed = ToolObservation::from_schemas(
            "changed",
            &json!({"changed": true}),
            &json!({}),
            ToolClass::Read,
        )
        .unwrap();
        let snapshot = CapabilitySnapshot::from_observations(
            ServerId::Eec,
            "1.0",
            ProtocolEra::Modern,
            vec![ProtocolVersion::V20260728],
            AuthMode::AccessToken,
            "scope",
            vec![
                observation("approved", ToolClass::Read),
                observation("blocked", ToolClass::Write),
                observation("unknown", ToolClass::Unknown),
                changed,
            ],
            Some(&previous),
        )
        .unwrap();
        assert!(!snapshot.tool_call_is_blocked("approved"));
        assert!(snapshot.tool_call_is_blocked("blocked"));
        assert!(snapshot.tool_call_is_blocked("unknown"));
        assert!(snapshot.tool_call_is_blocked("changed"));
        assert!(snapshot.tool_call_is_blocked("missing"));
    }

    #[test]
    fn capability_snapshot_debug_remains_redacted() {
        let observation = ToolObservation::from_digests(
            "secret-tool",
            "input-secret",
            "output-secret",
            ToolClass::Write,
        )
        .unwrap();
        let snapshot = CapabilitySnapshot::from_observations(
            ServerId::Eec,
            "1.0",
            ProtocolEra::Modern,
            vec![ProtocolVersion::V20260728],
            AuthMode::AccessToken,
            "scope",
            vec![observation],
            None,
        )
        .unwrap();
        let debug = format!("{snapshot:?}");
        assert!(!debug.contains("secret-tool"));
        assert!(!debug.contains("input-secret"));
        assert!(!debug.contains("output-secret"));
    }

    #[test]
    fn schema_drift_changes_digest_and_status() {
        let first = CapabilitySnapshot::from_observations(
            ServerId::Eec,
            "1.0",
            ProtocolEra::Modern,
            vec![ProtocolVersion::V20260728],
            AuthMode::OAuth,
            "scope",
            vec![observation("read", ToolClass::Read)],
            None,
        )
        .unwrap();
        let changed = ToolObservation::from_schemas(
            "read",
            &json!({"changed": true}),
            &json!({}),
            ToolClass::Read,
        )
        .unwrap();
        let second = CapabilitySnapshot::from_observations(
            ServerId::Eec,
            "1.0",
            ProtocolEra::Modern,
            vec![ProtocolVersion::V20260728],
            AuthMode::OAuth,
            "scope",
            vec![changed],
            Some(&first),
        )
        .unwrap();
        assert_ne!(first.snapshot_digest, second.snapshot_digest);
        assert_eq!(second.tool_status("read"), Some(ToolStatus::Changed));
    }

    #[test]
    fn cancellation_is_never_retry() {
        assert!(RequestDisposition::for_termination(RequestTermination::Cancelled).no_retry());
        assert!(RequestDisposition::for_termination(RequestTermination::TimedOut).no_retry());
        assert!(
            RequestDisposition::for_termination(RequestTermination::ResponseUnknown).no_retry()
        );
        assert!(!RequestDisposition::for_termination(RequestTermination::Completed).no_retry());
    }

    #[test]
    fn public_debug_is_redaction_safe() {
        let session = SessionId::parse("secret-session").unwrap();
        let name = McpNameEncoding::encode("secret-tool").unwrap();
        let observation = observation("secret-tool", ToolClass::Read);
        assert!(!format!("{session:?}").contains("secret-session"));
        assert!(!format!("{name:?}").contains("secret-tool"));
        assert!(!format!("{observation:?}").contains("secret-tool"));
    }
}
