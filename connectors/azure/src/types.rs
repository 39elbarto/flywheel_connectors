use serde::{Deserialize, Serialize};

// ── Auth ──

/// Azure service principal authentication.
#[derive(Clone, Deserialize)]
pub struct AzureAuth {
    /// Bearer access token for Azure Resource Manager.
    pub access_token: String,
    /// Azure subscription ID.
    pub subscription_id: String,
}

impl AzureAuth {
    #[must_use]
    pub fn is_secretless(&self) -> bool {
        self.access_token.trim().is_empty()
    }

    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        "bearer_token"
    }
}

impl std::fmt::Debug for AzureAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureAuth")
            .field("access_token", &"[REDACTED]")
            .field("subscription_id", &self.subscription_id)
            .finish()
    }
}

// ── Azure REST API envelope ──

/// Azure REST API error response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AzureErrorResponse {
    pub error: Option<AzureErrorDetail>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AzureErrorDetail {
    pub code: Option<String>,
    pub message: Option<String>,
}

// ── Virtual Machines ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VmListResponse {
    pub value: Vec<VirtualMachine>,
    #[serde(rename = "nextLink")]
    pub next_link: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VirtualMachine {
    pub id: Option<String>,
    pub name: String,
    pub location: String,
    #[serde(rename = "type")]
    pub vm_type: Option<String>,
    pub properties: Option<VmProperties>,
    pub tags: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VmProperties {
    #[serde(rename = "vmId")]
    pub vm_id: Option<String>,
    #[serde(rename = "provisioningState")]
    pub provisioning_state: Option<String>,
    #[serde(rename = "hardwareProfile")]
    pub hardware_profile: Option<HardwareProfile>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HardwareProfile {
    #[serde(rename = "vmSize")]
    pub vm_size: Option<String>,
}

// ── Storage ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContainerListResponse {
    #[serde(rename = "Containers")]
    pub containers: Option<Vec<BlobContainer>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlobContainer {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Properties")]
    pub properties: Option<ContainerProperties>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContainerProperties {
    #[serde(rename = "Last-Modified")]
    pub last_modified: Option<String>,
    #[serde(rename = "Etag")]
    pub etag: Option<String>,
    #[serde(rename = "LeaseStatus")]
    pub lease_status: Option<String>,
}

// ── App Service ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppListResponse {
    pub value: Vec<WebApp>,
    #[serde(rename = "nextLink")]
    pub next_link: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebApp {
    pub id: Option<String>,
    pub name: String,
    pub location: String,
    #[serde(rename = "type")]
    pub app_type: Option<String>,
    pub kind: Option<String>,
    pub properties: Option<WebAppProperties>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebAppProperties {
    pub state: Option<String>,
    #[serde(rename = "defaultHostName")]
    pub default_host_name: Option<String>,
    #[serde(rename = "repositorySiteName")]
    pub repository_site_name: Option<String>,
    pub enabled: Option<bool>,
}

// ── App Service deployment ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeploymentResponse {
    pub id: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub deployment_type: Option<String>,
    pub properties: Option<DeploymentProperties>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeploymentProperties {
    pub status: Option<i32>,
    pub message: Option<String>,
    pub author: Option<String>,
    pub deployer: Option<String>,
    #[serde(rename = "start_time")]
    pub start_time: Option<String>,
    #[serde(rename = "end_time")]
    pub end_time: Option<String>,
    pub active: Option<bool>,
}

// ── Subscription ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Subscription {
    pub id: Option<String>,
    #[serde(rename = "subscriptionId")]
    pub subscription_id: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    pub state: Option<String>,
    #[serde(rename = "tenantId")]
    pub tenant_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = AzureAuth {
            access_token: "super-secret-token-123".into(),
            subscription_id: "sub-123".into(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("sub-123"));
    }

    #[test]
    fn auth_secretless_detects_empty() {
        let auth = AzureAuth {
            access_token: "  ".into(),
            subscription_id: "sub-123".into(),
        };
        assert!(auth.is_secretless());

        let auth2 = AzureAuth {
            access_token: "token".into(),
            subscription_id: "sub-123".into(),
        };
        assert!(!auth2.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let auth = AzureAuth {
            access_token: "t".into(),
            subscription_id: "s".into(),
        };
        assert_eq!(auth.redacted_label(), "bearer_token");
    }

    #[test]
    fn deserialize_virtual_machine() {
        let json = serde_json::json!({
            "name": "my-vm",
            "location": "eastus",
            "type": "Microsoft.Compute/virtualMachines",
            "properties": {
                "vmId": "vm-abc-123",
                "provisioningState": "Succeeded",
                "hardwareProfile": {
                    "vmSize": "Standard_DS1_v2"
                }
            }
        });
        let vm: VirtualMachine = serde_json::from_value(json).unwrap();
        assert_eq!(vm.name, "my-vm");
        assert_eq!(vm.location, "eastus");
        let props = vm.properties.unwrap();
        assert_eq!(props.provisioning_state.unwrap(), "Succeeded");
        assert_eq!(
            props.hardware_profile.unwrap().vm_size.unwrap(),
            "Standard_DS1_v2"
        );
    }

    #[test]
    fn deserialize_vm_list_response() {
        let json = serde_json::json!({
            "value": [
                { "name": "vm1", "location": "eastus" },
                { "name": "vm2", "location": "westus" }
            ],
            "nextLink": null
        });
        let resp: VmListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.value.len(), 2);
        assert_eq!(resp.value[0].name, "vm1");
        assert!(resp.next_link.is_none());
    }

    #[test]
    fn deserialize_blob_container() {
        let json = serde_json::json!({
            "Name": "my-container",
            "Properties": {
                "Last-Modified": "2026-01-01T00:00:00Z",
                "Etag": "0x123",
                "LeaseStatus": "unlocked"
            }
        });
        let container: BlobContainer = serde_json::from_value(json).unwrap();
        assert_eq!(container.name, "my-container");
        let props = container.properties.unwrap();
        assert_eq!(props.lease_status.unwrap(), "unlocked");
    }

    #[test]
    fn deserialize_web_app() {
        let json = serde_json::json!({
            "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Web/sites/myapp",
            "name": "myapp",
            "location": "East US",
            "kind": "app",
            "properties": {
                "state": "Running",
                "defaultHostName": "myapp.azurewebsites.net",
                "enabled": true
            }
        });
        let app: WebApp = serde_json::from_value(json).unwrap();
        assert_eq!(app.name, "myapp");
        assert_eq!(app.kind.unwrap(), "app");
        let props = app.properties.unwrap();
        assert_eq!(props.state.unwrap(), "Running");
        assert_eq!(
            props.default_host_name.unwrap(),
            "myapp.azurewebsites.net"
        );
    }

    #[test]
    fn deserialize_app_list_response() {
        let json = serde_json::json!({
            "value": [
                { "name": "app1", "location": "eastus" },
                { "name": "app2", "location": "westus" }
            ]
        });
        let resp: AppListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.value.len(), 2);
    }

    #[test]
    fn deserialize_subscription() {
        let json = serde_json::json!({
            "id": "/subscriptions/sub-123",
            "subscriptionId": "sub-123",
            "displayName": "My Subscription",
            "state": "Enabled",
            "tenantId": "tenant-abc"
        });
        let sub: Subscription = serde_json::from_value(json).unwrap();
        assert_eq!(sub.subscription_id.unwrap(), "sub-123");
        assert_eq!(sub.display_name.unwrap(), "My Subscription");
        assert_eq!(sub.state.unwrap(), "Enabled");
    }

    #[test]
    fn deserialize_azure_error_response() {
        let json = serde_json::json!({
            "error": {
                "code": "ResourceNotFound",
                "message": "The Resource was not found."
            }
        });
        let resp: AzureErrorResponse = serde_json::from_value(json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code.unwrap(), "ResourceNotFound");
        assert_eq!(err.message.unwrap(), "The Resource was not found.");
    }

    #[test]
    fn deserialize_deployment_response() {
        let json = serde_json::json!({
            "id": "/subscriptions/sub/deployments/d1",
            "name": "d1",
            "type": "Microsoft.Web/sites/deployments",
            "properties": {
                "status": 4,
                "message": "Deployment successful",
                "active": true
            }
        });
        let dep: DeploymentResponse = serde_json::from_value(json).unwrap();
        assert_eq!(dep.name.unwrap(), "d1");
        let props = dep.properties.unwrap();
        assert_eq!(props.status.unwrap(), 4);
        assert!(props.active.unwrap());
    }

    #[test]
    fn vm_with_tags() {
        let json = serde_json::json!({
            "name": "tagged-vm",
            "location": "eastus",
            "tags": {
                "environment": "test",
                "team": "platform"
            }
        });
        let vm: VirtualMachine = serde_json::from_value(json).unwrap();
        let tags = vm.tags.unwrap();
        assert_eq!(tags["environment"], "test");
    }

    #[test]
    fn vm_minimal_fields() {
        let json = serde_json::json!({
            "name": "minimal-vm",
            "location": "westus2"
        });
        let vm: VirtualMachine = serde_json::from_value(json).unwrap();
        assert_eq!(vm.name, "minimal-vm");
        assert!(vm.id.is_none());
        assert!(vm.properties.is_none());
    }

    #[test]
    fn container_list_response() {
        let json = serde_json::json!({
            "Containers": [
                { "Name": "c1" },
                { "Name": "c2" }
            ]
        });
        let resp: ContainerListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.containers.unwrap().len(), 2);
    }
}
