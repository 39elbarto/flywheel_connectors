use serde::{Deserialize, Serialize};

// ── Auth ──

/// Cloudflare authentication mode.
#[derive(Clone, Deserialize)]
#[serde(tag = "mode")]
pub enum CloudflareAuth {
    /// API Token (recommended, scoped permissions).
    #[serde(rename = "api_token")]
    ApiToken { api_token: String },
    /// Global API Key + email (legacy, full account access).
    #[serde(rename = "api_key")]
    ApiKey { api_key: String, email: String },
}

impl std::fmt::Debug for CloudflareAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiToken { .. } => f.debug_struct("ApiToken").field("api_token", &"[REDACTED]").finish(),
            Self::ApiKey { email, .. } => f.debug_struct("ApiKey").field("api_key", &"[REDACTED]").field("email", email).finish(),
        }
    }
}

// ── API envelope ──

/// Standard Cloudflare API v4 response envelope.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CloudflareResponse<T> {
    pub success: bool,
    pub result: Option<T>,
    pub errors: Vec<ApiError>,
    pub messages: Vec<ApiMessage>,
    pub result_info: Option<ResultInfo>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiError {
    pub code: u32,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiMessage {
    pub code: u32,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResultInfo {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub count: Option<u32>,
    pub total_count: Option<u32>,
    pub total_pages: Option<u32>,
}

// ── Zones ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(rename = "type")]
    pub zone_type: Option<String>,
    pub paused: Option<bool>,
    pub development_mode: Option<u32>,
    pub plan: Option<ZonePlan>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZonePlan {
    pub id: String,
    pub name: String,
}

// ── DNS Records ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsRecord {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub content: String,
    pub proxied: Option<bool>,
    pub ttl: Option<u32>,
    pub priority: Option<u16>,
    pub comment: Option<String>,
    pub created_on: Option<String>,
    pub modified_on: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateDnsRecord {
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateDnsRecord {
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

// ── Workers ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Worker {
    pub id: String,
    #[serde(rename = "default_environment")]
    pub default_environment: Option<WorkerEnvironment>,
    pub created_on: Option<String>,
    pub modified_on: Option<String>,
    pub etag: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkerEnvironment {
    pub environment: Option<String>,
    pub created_on: Option<String>,
    pub modified_on: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkerScript {
    pub id: String,
    pub etag: Option<String>,
    pub size: Option<u64>,
    pub modified_on: Option<String>,
}

// ── Pages ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PagesProject {
    pub id: String,
    pub name: String,
    pub subdomain: Option<String>,
    pub created_on: Option<String>,
    pub production_branch: Option<String>,
    pub latest_deployment: Option<PagesDeployment>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PagesDeployment {
    pub id: String,
    pub url: Option<String>,
    pub environment: Option<String>,
    pub created_on: Option<String>,
    pub project_name: Option<String>,
}

// ── KV ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KvNamespace {
    pub id: String,
    pub title: String,
    pub supports_url_encoding: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KvKey {
    pub name: String,
    pub expiration: Option<u64>,
    pub metadata: Option<serde_json::Value>,
}

// ── Verify Token (health check) ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifyToken {
    pub id: String,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_zone() {
        let json = serde_json::json!({
            "id": "zone123",
            "name": "example.com",
            "status": "active",
            "type": "full",
            "paused": false
        });
        let zone: Zone = serde_json::from_value(json).unwrap();
        assert_eq!(zone.id, "zone123");
        assert_eq!(zone.name, "example.com");
        assert_eq!(zone.status, "active");
    }

    #[test]
    fn deserialize_dns_record() {
        let json = serde_json::json!({
            "id": "rec123",
            "type": "A",
            "name": "example.com",
            "content": "93.184.216.34",
            "proxied": true,
            "ttl": 1
        });
        let record: DnsRecord = serde_json::from_value(json).unwrap();
        assert_eq!(record.record_type, "A");
        assert_eq!(record.content, "93.184.216.34");
        assert!(record.proxied.unwrap());
    }

    #[test]
    fn deserialize_worker() {
        let json = serde_json::json!({
            "id": "my-worker",
            "created_on": "2026-01-01T00:00:00Z",
            "modified_on": "2026-01-02T00:00:00Z"
        });
        let worker: Worker = serde_json::from_value(json).unwrap();
        assert_eq!(worker.id, "my-worker");
    }

    #[test]
    fn deserialize_cloudflare_response_zones() {
        let json = serde_json::json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": [{
                "id": "z1",
                "name": "example.com",
                "status": "active"
            }],
            "result_info": {
                "page": 1,
                "per_page": 20,
                "count": 1,
                "total_count": 1,
                "total_pages": 1
            }
        });
        let resp: CloudflareResponse<Vec<Zone>> = serde_json::from_value(json).unwrap();
        assert!(resp.success);
        let zones = resp.result.unwrap();
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].name, "example.com");
    }

    #[test]
    fn deserialize_api_error_response() {
        let json = serde_json::json!({
            "success": false,
            "errors": [{"code": 6003, "message": "Invalid request headers"}],
            "messages": [],
            "result": null
        });
        let resp: CloudflareResponse<serde_json::Value> = serde_json::from_value(json).unwrap();
        assert!(!resp.success);
        assert_eq!(resp.errors.len(), 1);
        assert_eq!(resp.errors[0].code, 6003);
    }

    #[test]
    fn auth_debug_redacts_secrets() {
        let token_auth = CloudflareAuth::ApiToken {
            api_token: "super-secret-token".into(),
        };
        let debug = format!("{token_auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));

        let key_auth = CloudflareAuth::ApiKey {
            api_key: "global-key".into(),
            email: "user@example.com".into(),
        };
        let debug = format!("{key_auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("user@example.com"));
        assert!(!debug.contains("global-key"));
    }

    #[test]
    fn serialize_create_dns_record() {
        let record = CreateDnsRecord {
            record_type: "CNAME".into(),
            name: "www".into(),
            content: "example.com".into(),
            proxied: Some(true),
            ttl: None,
            priority: None,
            comment: Some("CDN entry".into()),
        };
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["type"], "CNAME");
        assert_eq!(json["name"], "www");
        assert!(json.get("ttl").is_none()); // skip_serializing_if works
        assert_eq!(json["comment"], "CDN entry");
    }

    #[test]
    fn deserialize_kv_namespace() {
        let json = serde_json::json!({
            "id": "ns-123",
            "title": "MY_KV",
            "supports_url_encoding": true
        });
        let ns: KvNamespace = serde_json::from_value(json).unwrap();
        assert_eq!(ns.title, "MY_KV");
    }

    #[test]
    fn deserialize_pages_project() {
        let json = serde_json::json!({
            "id": "proj-1",
            "name": "my-site",
            "subdomain": "my-site.pages.dev",
            "production_branch": "main"
        });
        let proj: PagesProject = serde_json::from_value(json).unwrap();
        assert_eq!(proj.name, "my-site");
        assert_eq!(proj.subdomain.unwrap(), "my-site.pages.dev");
    }
}
