//! Terraform state inspection and resource listing.
//!
//! Parses Terraform state files (v4 format) and provides query methods
//! for resources, outputs, and metadata. All operations are audited.

use serde::{Deserialize, Serialize};

/// A resource in the Terraform state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TerraformResource {
    /// The resource ID (from attributes).
    pub id: String,
    /// The resource type (e.g. `aws_instance`).
    #[serde(rename = "type")]
    pub resource_type: String,
    /// The local name of the resource (e.g. `web`).
    pub name: String,
    /// The provider reference string.
    pub provider: String,
    /// The module path, if the resource lives inside a module.
    pub module: Option<String>,
    /// The full attribute map from the first instance.
    pub attributes: serde_json::Value,
}

/// A fully-qualified resource address (e.g. `module.foo.aws_instance.bar`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ResourceAddress(pub String);

impl ResourceAddress {
    /// Build a resource address from its components.
    #[must_use]
    pub fn from_parts(module: Option<&str>, resource_type: &str, name: &str) -> Self {
        match module {
            Some(m) => Self(format!("{m}.{resource_type}.{name}")),
            None => Self(format!("{resource_type}.{name}")),
        }
    }

    /// Return the address string as a slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ResourceAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A Terraform output value from the state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TerraformOutput {
    /// The output name.
    pub name: String,
    /// The output value.
    pub value: serde_json::Value,
    /// Whether the output is marked sensitive.
    pub sensitive: bool,
    /// Optional type hint string (e.g. `"string"`, `"list"`).
    pub type_hint: Option<String>,
}

/// Metadata from the state file header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateMetadata {
    /// State format version (should be 4).
    pub version: u64,
    /// Terraform CLI version that wrote the state.
    pub terraform_version: String,
    /// Monotonically increasing serial number.
    pub serial: u64,
    /// UUID lineage identifier.
    pub lineage: String,
}

/// An audit event produced by a state inspection operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    /// The operation that was performed.
    pub operation: String,
    /// The resource address involved, if any.
    pub resource_address: Option<String>,
    /// Timestamp of the operation (monotonic counter for determinism).
    pub timestamp: u64,
    /// Additional details about the operation.
    pub details: String,
}

/// Holds parsed Terraform state and provides query methods.
///
/// Every query method records an [`AuditEvent`] in an internal log.
#[derive(Debug, Clone)]
pub struct StateInspector {
    metadata: StateMetadata,
    resources: Vec<TerraformResource>,
    outputs: Vec<TerraformOutput>,
    audit_log: Vec<AuditEvent>,
    audit_counter: u64,
}

impl StateInspector {
    // ---- Construction ----

    /// Parse a Terraform state v4 JSON value into a `StateInspector`.
    ///
    /// # Errors
    /// Returns `Err` if the JSON is not valid Terraform state v4.
    pub fn from_json(state_json: &serde_json::Value) -> Result<Self, String> {
        let version = state_json
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| "missing or invalid 'version' field".to_string())?;

        if version != 4 {
            return Err(format!("unsupported state version: {version}, expected 4"));
        }

        let terraform_version = state_json
            .get("terraform_version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "missing or invalid 'terraform_version' field".to_string())?
            .to_string();

        let serial = state_json
            .get("serial")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| "missing or invalid 'serial' field".to_string())?;

        let lineage = state_json
            .get("lineage")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "missing or invalid 'lineage' field".to_string())?
            .to_string();

        let metadata = StateMetadata {
            version,
            terraform_version,
            serial,
            lineage,
        };

        // Parse resources
        let resources = Self::parse_resources(state_json)?;

        // Parse outputs
        let outputs = Self::parse_outputs(state_json);

        Ok(Self {
            metadata,
            resources,
            outputs,
            audit_log: Vec::new(),
            audit_counter: 0,
        })
    }

    fn parse_resources(state_json: &serde_json::Value) -> Result<Vec<TerraformResource>, String> {
        let resource_array = match state_json.get("resources") {
            Some(serde_json::Value::Array(arr)) => arr,
            Some(serde_json::Value::Null) | None => return Ok(Vec::new()),
            Some(_) => return Err("'resources' field is not an array".to_string()),
        };

        let mut resources = Vec::new();
        for raw in resource_array {
            let resource_type = raw
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            let name = raw
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            let provider = raw
                .get("provider")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            let module = raw
                .get("module")
                .and_then(serde_json::Value::as_str)
                .map(String::from);

            // Extract attributes from the first instance
            let attributes = raw
                .get("instances")
                .and_then(serde_json::Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(|inst| inst.get("attributes"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            // Extract id from attributes
            let id = attributes
                .get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();

            resources.push(TerraformResource {
                id,
                resource_type,
                name,
                provider,
                module,
                attributes,
            });
        }

        Ok(resources)
    }

    fn parse_outputs(state_json: &serde_json::Value) -> Vec<TerraformOutput> {
        let Some(serde_json::Value::Object(outputs_obj)) = state_json.get("outputs") else {
            return Vec::new();
        };

        let mut outputs = Vec::new();
        for (key, val) in outputs_obj {
            let value = val.get("value").cloned().unwrap_or(serde_json::Value::Null);
            let sensitive = val
                .get("sensitive")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let type_hint = val
                .get("type")
                .and_then(serde_json::Value::as_str)
                .map(String::from);

            outputs.push(TerraformOutput {
                name: key.clone(),
                value,
                sensitive,
                type_hint,
            });
        }

        // Sort for deterministic ordering
        outputs.sort_by(|a, b| a.name.cmp(&b.name));
        outputs
    }

    // ---- Audit helpers ----

    fn emit_audit(&mut self, operation: &str, resource_address: Option<&str>, details: &str) {
        let ts = self.audit_counter;
        self.audit_counter += 1;
        self.audit_log.push(AuditEvent {
            operation: operation.to_string(),
            resource_address: resource_address.map(String::from),
            timestamp: ts,
            details: details.to_string(),
        });
    }

    // ---- Query methods ----

    /// List all resources in the state.
    pub fn list_resources(&mut self) -> Vec<&TerraformResource> {
        let count = self.resources.len();
        self.emit_audit("list_resources", None, &format!("listed {count} resources"));
        self.resources.iter().collect()
    }

    /// List resources filtered by type (e.g. `"aws_instance"`).
    pub fn list_resources_by_type(&mut self, resource_type: &str) -> Vec<&TerraformResource> {
        let indices: Vec<usize> = self
            .resources
            .iter()
            .enumerate()
            .filter(|(_, r)| r.resource_type == resource_type)
            .map(|(i, _)| i)
            .collect();
        let count = indices.len();
        self.emit_audit(
            "list_resources_by_type",
            None,
            &format!("type={resource_type}, matched {count}"),
        );
        indices.iter().map(|&i| &self.resources[i]).collect()
    }

    /// List resources filtered by module path (e.g. `"module.network"`).
    pub fn list_resources_by_module(&mut self, module: &str) -> Vec<&TerraformResource> {
        let indices: Vec<usize> = self
            .resources
            .iter()
            .enumerate()
            .filter(|(_, r)| r.module.as_deref() == Some(module))
            .map(|(i, _)| i)
            .collect();
        let count = indices.len();
        self.emit_audit(
            "list_resources_by_module",
            None,
            &format!("module={module}, matched {count}"),
        );
        indices.iter().map(|&i| &self.resources[i]).collect()
    }

    /// Look up a single resource by its full address string.
    ///
    /// The address format is `type.name` or `module.path.type.name`.
    pub fn show_resource(&mut self, address: &str) -> Option<&TerraformResource> {
        let idx = self.resources.iter().position(|r| {
            let addr = ResourceAddress::from_parts(r.module.as_deref(), &r.resource_type, &r.name);
            addr.0 == address
        });
        let found = idx.is_some();
        self.emit_audit(
            "show_resource",
            Some(address),
            if found { "found" } else { "not found" },
        );
        idx.map(|i| &self.resources[i])
    }

    /// Return a slice of all outputs.
    pub fn read_outputs(&mut self) -> &[TerraformOutput] {
        let count = self.outputs.len();
        self.emit_audit("read_outputs", None, &format!("read {count} outputs"));
        &self.outputs
    }

    /// Look up a single output by name.
    pub fn read_output(&mut self, name: &str) -> Option<&TerraformOutput> {
        let idx = self.outputs.iter().position(|o| o.name == name);
        let found = idx.is_some();
        self.emit_audit(
            "read_output",
            None,
            &format!("name={name}, {}", if found { "found" } else { "not found" }),
        );
        idx.map(|i| &self.outputs[i])
    }

    /// Return the state metadata.
    pub fn metadata(&mut self) -> &StateMetadata {
        self.emit_audit("metadata", None, "read state metadata");
        &self.metadata
    }

    /// Drain and return all accumulated audit events, clearing the internal log.
    pub fn drain_audit_events(&mut self) -> Vec<AuditEvent> {
        std::mem::take(&mut self.audit_log)
    }

    /// Return the current number of audit events (without draining).
    #[must_use]
    pub fn audit_event_count(&self) -> usize {
        self.audit_log.len()
    }

    /// Return the number of resources in the state.
    #[must_use]
    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    /// Return the number of outputs in the state.
    #[must_use]
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }
}

// ----------------------------------------------------------------
// Tests
// ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- Test helpers ----

    fn sample_state() -> serde_json::Value {
        json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 42,
            "lineage": "abc-def-123",
            "outputs": {
                "vpc_id": { "value": "vpc-123", "type": "string", "sensitive": false },
                "db_password": { "value": "s3cret", "type": "string", "sensitive": true }
            },
            "resources": [
                {
                    "module": "module.network",
                    "mode": "managed",
                    "type": "aws_vpc",
                    "name": "main",
                    "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
                    "instances": [
                        { "attributes": { "id": "vpc-123", "cidr_block": "10.0.0.0/16" } }
                    ]
                },
                {
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "web",
                    "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
                    "instances": [
                        { "attributes": { "id": "i-abc", "instance_type": "t3.micro" } }
                    ]
                },
                {
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "api",
                    "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
                    "instances": [
                        { "attributes": { "id": "i-def", "instance_type": "t3.small" } }
                    ]
                },
                {
                    "module": "module.network",
                    "mode": "managed",
                    "type": "aws_subnet",
                    "name": "public",
                    "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
                    "instances": [
                        { "attributes": { "id": "subnet-001", "cidr_block": "10.0.1.0/24" } }
                    ]
                }
            ]
        })
    }

    fn empty_state() -> serde_json::Value {
        json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 0,
            "lineage": "empty-lineage",
            "outputs": {},
            "resources": []
        })
    }

    fn minimal_state() -> serde_json::Value {
        json!({
            "version": 4,
            "terraform_version": "1.0.0",
            "serial": 1,
            "lineage": "min-lineage"
        })
    }

    // ================================================================
    // StateInspector::from_json — construction
    // ================================================================

    #[test]
    fn from_json_parses_sample_state() {
        let inspector = StateInspector::from_json(&sample_state()).unwrap();
        assert_eq!(inspector.resource_count(), 4);
        assert_eq!(inspector.output_count(), 2);
    }

    #[test]
    fn from_json_parses_empty_state() {
        let inspector = StateInspector::from_json(&empty_state()).unwrap();
        assert_eq!(inspector.resource_count(), 0);
        assert_eq!(inspector.output_count(), 0);
    }

    #[test]
    fn from_json_parses_minimal_state_no_resources_key() {
        let inspector = StateInspector::from_json(&minimal_state()).unwrap();
        assert_eq!(inspector.resource_count(), 0);
        assert_eq!(inspector.output_count(), 0);
    }

    #[test]
    fn from_json_rejects_wrong_version() {
        let state = json!({
            "version": 3,
            "terraform_version": "0.12.0",
            "serial": 1,
            "lineage": "old"
        });
        let err = StateInspector::from_json(&state).unwrap_err();
        assert!(err.contains("unsupported state version"));
        assert!(err.contains('3'));
    }

    #[test]
    fn from_json_rejects_missing_version() {
        let state = json!({
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x"
        });
        let err = StateInspector::from_json(&state).unwrap_err();
        assert!(err.contains("version"));
    }

    #[test]
    fn from_json_rejects_missing_terraform_version() {
        let state = json!({
            "version": 4,
            "serial": 1,
            "lineage": "x"
        });
        let err = StateInspector::from_json(&state).unwrap_err();
        assert!(err.contains("terraform_version"));
    }

    #[test]
    fn from_json_rejects_missing_serial() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "lineage": "x"
        });
        let err = StateInspector::from_json(&state).unwrap_err();
        assert!(err.contains("serial"));
    }

    #[test]
    fn from_json_rejects_missing_lineage() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1
        });
        let err = StateInspector::from_json(&state).unwrap_err();
        assert!(err.contains("lineage"));
    }

    #[test]
    fn from_json_rejects_non_numeric_version() {
        let state = json!({
            "version": "four",
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x"
        });
        let err = StateInspector::from_json(&state).unwrap_err();
        assert!(err.contains("version"));
    }

    #[test]
    fn from_json_rejects_resources_not_array() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "resources": "not-array"
        });
        let err = StateInspector::from_json(&state).unwrap_err();
        assert!(err.contains("not an array"));
    }

    #[test]
    fn from_json_null_resources_treated_as_empty() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "resources": null
        });
        let inspector = StateInspector::from_json(&state).unwrap();
        assert_eq!(inspector.resource_count(), 0);
    }

    #[test]
    fn from_json_null_outputs_treated_as_empty() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "outputs": null
        });
        let inspector = StateInspector::from_json(&state).unwrap();
        assert_eq!(inspector.output_count(), 0);
    }

    // ================================================================
    // Metadata
    // ================================================================

    #[test]
    fn metadata_returns_correct_version() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        assert_eq!(inspector.metadata().version, 4);
    }

    #[test]
    fn metadata_returns_correct_terraform_version() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        assert_eq!(inspector.metadata().terraform_version, "1.5.0");
    }

    #[test]
    fn metadata_returns_correct_serial() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        assert_eq!(inspector.metadata().serial, 42);
    }

    #[test]
    fn metadata_returns_correct_lineage() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        assert_eq!(inspector.metadata().lineage, "abc-def-123");
    }

    #[test]
    fn metadata_emits_audit_event() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.metadata();
        let events = inspector.drain_audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, "metadata");
    }

    // ================================================================
    // list_resources
    // ================================================================

    #[test]
    fn list_resources_returns_all() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let all = inspector.list_resources();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn list_resources_empty_state() {
        let mut inspector = StateInspector::from_json(&empty_state()).unwrap();
        let all = inspector.list_resources();
        assert!(all.is_empty());
    }

    #[test]
    fn list_resources_emits_audit_event() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.list_resources();
        let events = inspector.drain_audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, "list_resources");
        assert!(events[0].details.contains('4'));
    }

    #[test]
    fn list_resources_preserves_order() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let all = inspector.list_resources();
        assert_eq!(all[0].resource_type, "aws_vpc");
        assert_eq!(all[1].resource_type, "aws_instance");
        assert_eq!(all[1].name, "web");
        assert_eq!(all[2].resource_type, "aws_instance");
        assert_eq!(all[2].name, "api");
        assert_eq!(all[3].resource_type, "aws_subnet");
    }

    // ================================================================
    // list_resources_by_type
    // ================================================================

    #[test]
    fn list_resources_by_type_matches() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let instances = inspector.list_resources_by_type("aws_instance");
        assert_eq!(instances.len(), 2);
    }

    #[test]
    fn list_resources_by_type_single_match() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let vpcs = inspector.list_resources_by_type("aws_vpc");
        assert_eq!(vpcs.len(), 1);
        assert_eq!(vpcs[0].name, "main");
    }

    #[test]
    fn list_resources_by_type_no_match() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let result = inspector.list_resources_by_type("aws_s3_bucket");
        assert!(result.is_empty());
    }

    #[test]
    fn list_resources_by_type_empty_state() {
        let mut inspector = StateInspector::from_json(&empty_state()).unwrap();
        let result = inspector.list_resources_by_type("aws_instance");
        assert!(result.is_empty());
    }

    #[test]
    fn list_resources_by_type_emits_audit_event() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.list_resources_by_type("aws_instance");
        let events = inspector.drain_audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, "list_resources_by_type");
        assert!(events[0].details.contains("aws_instance"));
    }

    #[test]
    fn list_resources_by_type_returns_correct_ids() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let instances = inspector.list_resources_by_type("aws_instance");
        let ids: Vec<&str> = instances.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"i-abc"));
        assert!(ids.contains(&"i-def"));
    }

    // ================================================================
    // list_resources_by_module
    // ================================================================

    #[test]
    fn list_resources_by_module_matches() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let network = inspector.list_resources_by_module("module.network");
        assert_eq!(network.len(), 2);
    }

    #[test]
    fn list_resources_by_module_no_match() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let result = inspector.list_resources_by_module("module.database");
        assert!(result.is_empty());
    }

    #[test]
    fn list_resources_by_module_empty_state() {
        let mut inspector = StateInspector::from_json(&empty_state()).unwrap();
        let result = inspector.list_resources_by_module("module.any");
        assert!(result.is_empty());
    }

    #[test]
    fn list_resources_by_module_emits_audit_event() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.list_resources_by_module("module.network");
        let events = inspector.drain_audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, "list_resources_by_module");
        assert!(events[0].details.contains("module.network"));
    }

    #[test]
    fn list_resources_by_module_returns_correct_types() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let network = inspector.list_resources_by_module("module.network");
        let types: Vec<&str> = network.iter().map(|r| r.resource_type.as_str()).collect();
        assert!(types.contains(&"aws_vpc"));
        assert!(types.contains(&"aws_subnet"));
    }

    // ================================================================
    // show_resource
    // ================================================================

    #[test]
    fn show_resource_root_level() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let r = inspector.show_resource("aws_instance.web").unwrap();
        assert_eq!(r.id, "i-abc");
        assert_eq!(r.resource_type, "aws_instance");
        assert_eq!(r.name, "web");
    }

    #[test]
    fn show_resource_module_scoped() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let r = inspector
            .show_resource("module.network.aws_vpc.main")
            .unwrap();
        assert_eq!(r.id, "vpc-123");
        assert_eq!(r.module, Some("module.network".to_string()));
    }

    #[test]
    fn show_resource_not_found() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        assert!(inspector.show_resource("aws_s3_bucket.data").is_none());
    }

    #[test]
    fn show_resource_empty_state() {
        let mut inspector = StateInspector::from_json(&empty_state()).unwrap();
        assert!(inspector.show_resource("aws_instance.web").is_none());
    }

    #[test]
    fn show_resource_emits_audit_event_found() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.show_resource("aws_instance.web");
        let events = inspector.drain_audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, "show_resource");
        assert_eq!(
            events[0].resource_address,
            Some("aws_instance.web".to_string())
        );
        assert_eq!(events[0].details, "found");
    }

    #[test]
    fn show_resource_emits_audit_event_not_found() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.show_resource("aws_rds.missing");
        let events = inspector.drain_audit_events();
        assert_eq!(events[0].details, "not found");
    }

    #[test]
    fn show_resource_returns_attributes() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let r = inspector.show_resource("aws_instance.web").unwrap();
        assert_eq!(r.attributes["instance_type"], "t3.micro");
    }

    #[test]
    fn show_resource_second_instance_same_type() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let r = inspector.show_resource("aws_instance.api").unwrap();
        assert_eq!(r.id, "i-def");
        assert_eq!(r.attributes["instance_type"], "t3.small");
    }

    // ================================================================
    // read_outputs
    // ================================================================

    #[test]
    fn read_outputs_returns_all() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let outputs = inspector.read_outputs();
        assert_eq!(outputs.len(), 2);
    }

    #[test]
    fn read_outputs_empty_state() {
        let mut inspector = StateInspector::from_json(&empty_state()).unwrap();
        let outputs = inspector.read_outputs();
        assert!(outputs.is_empty());
    }

    #[test]
    fn read_outputs_emits_audit_event() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.read_outputs();
        let events = inspector.drain_audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, "read_outputs");
    }

    #[test]
    fn read_outputs_sorted_by_name() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let outputs = inspector.read_outputs();
        assert_eq!(outputs[0].name, "db_password");
        assert_eq!(outputs[1].name, "vpc_id");
    }

    // ================================================================
    // read_output (single)
    // ================================================================

    #[test]
    fn read_output_found() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let o = inspector.read_output("vpc_id").unwrap();
        assert_eq!(o.value, json!("vpc-123"));
        assert!(!o.sensitive);
    }

    #[test]
    fn read_output_sensitive() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let o = inspector.read_output("db_password").unwrap();
        assert!(o.sensitive);
        assert_eq!(o.value, json!("s3cret"));
    }

    #[test]
    fn read_output_not_found() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        assert!(inspector.read_output("nonexistent").is_none());
    }

    #[test]
    fn read_output_empty_state() {
        let mut inspector = StateInspector::from_json(&empty_state()).unwrap();
        assert!(inspector.read_output("anything").is_none());
    }

    #[test]
    fn read_output_emits_audit_event() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.read_output("vpc_id");
        let events = inspector.drain_audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, "read_output");
        assert!(events[0].details.contains("vpc_id"));
    }

    #[test]
    fn read_output_type_hint_preserved() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let o = inspector.read_output("vpc_id").unwrap();
        assert_eq!(o.type_hint, Some("string".to_string()));
    }

    // ================================================================
    // Audit event mechanics
    // ================================================================

    #[test]
    fn drain_audit_events_clears_log() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.list_resources();
        let _ = inspector.list_resources();
        assert_eq!(inspector.audit_event_count(), 2);
        let events = inspector.drain_audit_events();
        assert_eq!(events.len(), 2);
        assert_eq!(inspector.audit_event_count(), 0);
    }

    #[test]
    fn drain_audit_events_empty_initially() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let events = inspector.drain_audit_events();
        assert!(events.is_empty());
    }

    #[test]
    fn audit_timestamps_monotonically_increase() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.list_resources();
        let _ = inspector.metadata();
        let _ = inspector.read_outputs();
        let events = inspector.drain_audit_events();
        assert_eq!(events[0].timestamp, 0);
        assert_eq!(events[1].timestamp, 1);
        assert_eq!(events[2].timestamp, 2);
    }

    #[test]
    fn audit_counter_continues_after_drain() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.list_resources();
        let _ = inspector.drain_audit_events();
        let _ = inspector.metadata();
        let events = inspector.drain_audit_events();
        assert_eq!(events[0].timestamp, 1);
    }

    #[test]
    fn multiple_operations_produce_multiple_events() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.list_resources();
        let _ = inspector.list_resources_by_type("aws_instance");
        let _ = inspector.list_resources_by_module("module.network");
        let _ = inspector.show_resource("aws_instance.web");
        let _ = inspector.read_outputs();
        let _ = inspector.read_output("vpc_id");
        let _ = inspector.metadata();
        assert_eq!(inspector.audit_event_count(), 7);
    }

    // ================================================================
    // ResourceAddress
    // ================================================================

    #[test]
    fn resource_address_root_level() {
        let addr = ResourceAddress::from_parts(None, "aws_instance", "web");
        assert_eq!(addr.as_str(), "aws_instance.web");
    }

    #[test]
    fn resource_address_module_scoped() {
        let addr = ResourceAddress::from_parts(Some("module.network"), "aws_vpc", "main");
        assert_eq!(addr.as_str(), "module.network.aws_vpc.main");
    }

    #[test]
    fn resource_address_nested_module() {
        let addr =
            ResourceAddress::from_parts(Some("module.env.module.vpc"), "aws_subnet", "private");
        assert_eq!(addr.as_str(), "module.env.module.vpc.aws_subnet.private");
    }

    #[test]
    fn resource_address_display() {
        let addr = ResourceAddress::from_parts(None, "aws_instance", "web");
        assert_eq!(format!("{addr}"), "aws_instance.web");
    }

    #[test]
    fn resource_address_equality() {
        let a = ResourceAddress::from_parts(None, "aws_instance", "web");
        let b = ResourceAddress::from_parts(None, "aws_instance", "web");
        assert_eq!(a, b);
    }

    #[test]
    fn resource_address_inequality() {
        let a = ResourceAddress::from_parts(None, "aws_instance", "web");
        let b = ResourceAddress::from_parts(None, "aws_instance", "api");
        assert_ne!(a, b);
    }

    #[test]
    fn resource_address_serde_roundtrip() {
        let addr = ResourceAddress::from_parts(Some("module.net"), "aws_vpc", "main");
        let json_str = serde_json::to_string(&addr).unwrap();
        let parsed: ResourceAddress = serde_json::from_str(&json_str).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn resource_address_clone() {
        let addr = ResourceAddress::from_parts(None, "aws_instance", "web");
        let cloned = addr.clone();
        drop(addr);
        assert_eq!(cloned.as_str(), "aws_instance.web");
    }

    // ================================================================
    // TerraformResource serde / clone / debug
    // ================================================================

    #[test]
    fn terraform_resource_serde_roundtrip() {
        let r = TerraformResource {
            id: "i-abc".into(),
            resource_type: "aws_instance".into(),
            name: "web".into(),
            provider: "provider[\"aws\"]".into(),
            module: None,
            attributes: json!({"id": "i-abc", "ami": "ami-123"}),
        };
        let json_str = serde_json::to_string(&r).unwrap();
        let parsed: TerraformResource = serde_json::from_str(&json_str).unwrap();
        assert_eq!(r, parsed);
    }

    #[test]
    fn terraform_resource_with_module_serde() {
        let r = TerraformResource {
            id: "vpc-1".into(),
            resource_type: "aws_vpc".into(),
            name: "main".into(),
            provider: "provider[\"aws\"]".into(),
            module: Some("module.network".into()),
            attributes: json!({"id": "vpc-1"}),
        };
        let json_str = serde_json::to_string(&r).unwrap();
        assert!(json_str.contains("module.network"));
        let parsed: TerraformResource = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.module, Some("module.network".to_string()));
    }

    #[test]
    fn terraform_resource_clone() {
        let r = TerraformResource {
            id: "i-1".into(),
            resource_type: "aws_instance".into(),
            name: "web".into(),
            provider: "aws".into(),
            module: None,
            attributes: json!({"id": "i-1"}),
        };
        let cloned = r.clone();
        drop(r);
        assert_eq!(cloned.id, "i-1");
    }

    #[test]
    fn terraform_resource_debug() {
        let r = TerraformResource {
            id: "i-dbg".into(),
            resource_type: "aws_instance".into(),
            name: "debug_test".into(),
            provider: "aws".into(),
            module: None,
            attributes: json!(null),
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("TerraformResource"));
        assert!(dbg.contains("i-dbg"));
    }

    // ================================================================
    // TerraformOutput serde / clone / debug
    // ================================================================

    #[test]
    fn terraform_output_serde_roundtrip() {
        let o = TerraformOutput {
            name: "endpoint".into(),
            value: json!("https://api.example.com"),
            sensitive: false,
            type_hint: Some("string".into()),
        };
        let json_str = serde_json::to_string(&o).unwrap();
        let parsed: TerraformOutput = serde_json::from_str(&json_str).unwrap();
        assert_eq!(o, parsed);
    }

    #[test]
    fn terraform_output_sensitive_serde() {
        let o = TerraformOutput {
            name: "secret".into(),
            value: json!("hunter2"),
            sensitive: true,
            type_hint: None,
        };
        let json_str = serde_json::to_string(&o).unwrap();
        let parsed: TerraformOutput = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.sensitive);
        assert!(parsed.type_hint.is_none());
    }

    #[test]
    fn terraform_output_complex_value() {
        let o = TerraformOutput {
            name: "tags".into(),
            value: json!({"env": "prod", "team": "infra"}),
            sensitive: false,
            type_hint: Some("map".into()),
        };
        let json_str = serde_json::to_string(&o).unwrap();
        let parsed: TerraformOutput = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.value["env"], "prod");
    }

    #[test]
    fn terraform_output_list_value() {
        let o = TerraformOutput {
            name: "subnets".into(),
            value: json!(["subnet-1", "subnet-2", "subnet-3"]),
            sensitive: false,
            type_hint: Some("list".into()),
        };
        let json_str = serde_json::to_string(&o).unwrap();
        let parsed: TerraformOutput = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.value.as_array().unwrap().len(), 3);
    }

    #[test]
    fn terraform_output_clone() {
        let o = TerraformOutput {
            name: "out1".into(),
            value: json!(42),
            sensitive: false,
            type_hint: None,
        };
        let cloned = o.clone();
        drop(o);
        assert_eq!(cloned.name, "out1");
    }

    #[test]
    fn terraform_output_debug() {
        let o = TerraformOutput {
            name: "dbg_out".into(),
            value: json!(null),
            sensitive: false,
            type_hint: None,
        };
        let dbg = format!("{o:?}");
        assert!(dbg.contains("TerraformOutput"));
    }

    // ================================================================
    // StateMetadata serde / clone / debug
    // ================================================================

    #[test]
    fn state_metadata_serde_roundtrip() {
        let m = StateMetadata {
            version: 4,
            terraform_version: "1.5.0".into(),
            serial: 42,
            lineage: "uuid-here".into(),
        };
        let json_str = serde_json::to_string(&m).unwrap();
        let parsed: StateMetadata = serde_json::from_str(&json_str).unwrap();
        assert_eq!(m, parsed);
    }

    #[test]
    fn state_metadata_clone() {
        let m = StateMetadata {
            version: 4,
            terraform_version: "1.5.0".into(),
            serial: 1,
            lineage: "lin".into(),
        };
        let cloned = m.clone();
        drop(m);
        assert_eq!(cloned.version, 4);
    }

    #[test]
    fn state_metadata_debug() {
        let m = StateMetadata {
            version: 4,
            terraform_version: "1.5.0".into(),
            serial: 1,
            lineage: "dbg-lin".into(),
        };
        let dbg = format!("{m:?}");
        assert!(dbg.contains("StateMetadata"));
    }

    // ================================================================
    // AuditEvent serde / clone / debug
    // ================================================================

    #[test]
    fn audit_event_serde_roundtrip() {
        let e = AuditEvent {
            operation: "list_resources".into(),
            resource_address: None,
            timestamp: 0,
            details: "listed 4 resources".into(),
        };
        let json_str = serde_json::to_string(&e).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(e, parsed);
    }

    #[test]
    fn audit_event_with_address_serde() {
        let e = AuditEvent {
            operation: "show_resource".into(),
            resource_address: Some("aws_instance.web".into()),
            timestamp: 5,
            details: "found".into(),
        };
        let json_str = serde_json::to_string(&e).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(
            parsed.resource_address,
            Some("aws_instance.web".to_string())
        );
    }

    #[test]
    fn audit_event_clone() {
        let e = AuditEvent {
            operation: "test".into(),
            resource_address: None,
            timestamp: 0,
            details: "detail".into(),
        };
        let cloned = e.clone();
        drop(e);
        assert_eq!(cloned.operation, "test");
    }

    #[test]
    fn audit_event_debug() {
        let e = AuditEvent {
            operation: "dbg_op".into(),
            resource_address: None,
            timestamp: 0,
            details: "dbg_detail".into(),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("AuditEvent"));
    }

    // ================================================================
    // Edge cases: resources with missing fields
    // ================================================================

    #[test]
    fn resource_with_no_instances() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "resources": [{
                "type": "aws_instance",
                "name": "orphan",
                "provider": "aws",
                "instances": []
            }]
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let all = inspector.list_resources();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "");
        assert_eq!(all[0].attributes, json!(null));
    }

    #[test]
    fn resource_with_missing_instances_key() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "resources": [{
                "type": "aws_instance",
                "name": "no_instances",
                "provider": "aws"
            }]
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let all = inspector.list_resources();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].attributes, json!(null));
    }

    #[test]
    fn resource_with_no_attributes_in_instance() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "resources": [{
                "type": "aws_instance",
                "name": "bare",
                "provider": "aws",
                "instances": [{}]
            }]
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let all = inspector.list_resources();
        assert_eq!(all[0].attributes, json!(null));
    }

    #[test]
    fn resource_with_null_attributes_id() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "resources": [{
                "type": "aws_instance",
                "name": "null_id",
                "provider": "aws",
                "instances": [{ "attributes": { "id": null } }]
            }]
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let all = inspector.list_resources();
        assert_eq!(all[0].id, "");
    }

    // ================================================================
    // Edge cases: multiple resources of same type
    // ================================================================

    #[test]
    fn multiple_resources_same_type_different_names() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "resources": [
                { "type": "aws_s3_bucket", "name": "logs", "provider": "aws", "instances": [{ "attributes": { "id": "logs-bucket" } }] },
                { "type": "aws_s3_bucket", "name": "data", "provider": "aws", "instances": [{ "attributes": { "id": "data-bucket" } }] },
                { "type": "aws_s3_bucket", "name": "backup", "provider": "aws", "instances": [{ "attributes": { "id": "backup-bucket" } }] }
            ]
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let buckets = inspector.list_resources_by_type("aws_s3_bucket");
        assert_eq!(buckets.len(), 3);
    }

    #[test]
    fn show_resource_distinguishes_same_type() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "resources": [
                { "type": "aws_s3_bucket", "name": "logs", "provider": "aws", "instances": [{ "attributes": { "id": "logs-bucket" } }] },
                { "type": "aws_s3_bucket", "name": "data", "provider": "aws", "instances": [{ "attributes": { "id": "data-bucket" } }] }
            ]
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let logs = inspector.show_resource("aws_s3_bucket.logs").unwrap();
        assert_eq!(logs.id, "logs-bucket");
        let data = inspector.show_resource("aws_s3_bucket.data").unwrap();
        assert_eq!(data.id, "data-bucket");
    }

    // ================================================================
    // Edge cases: module-scoped resources
    // ================================================================

    #[test]
    fn module_scoped_resource_not_found_without_prefix() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        // aws_vpc.main lives under module.network, so bare address should not find it
        assert!(inspector.show_resource("aws_vpc.main").is_none());
    }

    #[test]
    fn module_scoped_resource_found_with_prefix() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        assert!(
            inspector
                .show_resource("module.network.aws_vpc.main")
                .is_some()
        );
    }

    #[test]
    fn deeply_nested_module() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "resources": [{
                "module": "module.env.module.vpc",
                "type": "aws_subnet",
                "name": "private",
                "provider": "aws",
                "instances": [{ "attributes": { "id": "subnet-deep" } }]
            }]
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let r = inspector
            .show_resource("module.env.module.vpc.aws_subnet.private")
            .unwrap();
        assert_eq!(r.id, "subnet-deep");
    }

    // ================================================================
    // Edge cases: outputs
    // ================================================================

    #[test]
    fn output_with_null_value() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "outputs": {
                "maybe_null": { "value": null, "sensitive": false }
            }
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let o = inspector.read_output("maybe_null").unwrap();
        assert_eq!(o.value, json!(null));
    }

    #[test]
    fn output_with_no_type_hint() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "outputs": {
                "no_type": { "value": 42, "sensitive": false }
            }
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let o = inspector.read_output("no_type").unwrap();
        assert!(o.type_hint.is_none());
        assert_eq!(o.value, json!(42));
    }

    #[test]
    fn output_missing_sensitive_defaults_false() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "outputs": {
                "no_sens": { "value": "hello" }
            }
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let o = inspector.read_output("no_sens").unwrap();
        assert!(!o.sensitive);
    }

    #[test]
    fn output_missing_value_defaults_null() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "outputs": {
                "no_val": {}
            }
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let o = inspector.read_output("no_val").unwrap();
        assert_eq!(o.value, json!(null));
    }

    #[test]
    fn many_outputs_sorted() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "outputs": {
                "zeta": { "value": "z" },
                "alpha": { "value": "a" },
                "mu": { "value": "m" }
            }
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let outputs = inspector.read_outputs();
        assert_eq!(outputs[0].name, "alpha");
        assert_eq!(outputs[1].name, "mu");
        assert_eq!(outputs[2].name, "zeta");
    }

    // ================================================================
    // StateInspector clone
    // ================================================================

    #[test]
    fn state_inspector_clone_preserves_resources() {
        let inspector = StateInspector::from_json(&sample_state()).unwrap();
        let cloned = inspector.clone();
        assert_eq!(inspector.resource_count(), 4);
        assert_eq!(cloned.resource_count(), 4);
    }

    #[test]
    fn state_inspector_clone_independent_audit() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.list_resources();
        let mut cloned = inspector.clone();
        let _ = cloned.metadata();
        // Original should still have 1 event, clone should have 2
        assert_eq!(inspector.audit_event_count(), 1);
        assert_eq!(cloned.audit_event_count(), 2);
    }

    // ================================================================
    // Large state
    // ================================================================

    #[test]
    fn large_state_many_resources() {
        let resources: Vec<serde_json::Value> = (0..50)
            .map(|i| {
                json!({
                    "type": "aws_instance",
                    "name": format!("server_{i}"),
                    "provider": "aws",
                    "instances": [{ "attributes": { "id": format!("i-{i:04}") } }]
                })
            })
            .collect();
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 100,
            "lineage": "large-state",
            "resources": resources
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        assert_eq!(inspector.resource_count(), 50);
        let all = inspector.list_resources();
        assert_eq!(all.len(), 50);
        let last = inspector.show_resource("aws_instance.server_49").unwrap();
        assert_eq!(last.id, "i-0049");
    }

    #[test]
    fn large_state_many_outputs() {
        let mut outputs = serde_json::Map::new();
        for i in 0..20 {
            outputs.insert(
                format!("output_{i}"),
                json!({ "value": format!("val_{i}"), "sensitive": false, "type": "string" }),
            );
        }
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "many-outputs",
            "outputs": outputs
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        assert_eq!(inspector.output_count(), 20);
        let all = inspector.read_outputs();
        assert_eq!(all.len(), 20);
    }

    // ================================================================
    // Mixed module and root resources
    // ================================================================

    #[test]
    fn mixed_module_and_root_filter_by_module_excludes_root() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let network = inspector.list_resources_by_module("module.network");
        // Only aws_vpc.main and aws_subnet.public are in module.network
        assert_eq!(network.len(), 2);
        for r in &network {
            assert_eq!(r.module, Some("module.network".to_string()));
        }
    }

    #[test]
    fn root_resources_have_no_module() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let r = inspector.show_resource("aws_instance.web").unwrap();
        assert!(r.module.is_none());
    }

    // ================================================================
    // Resource provider field
    // ================================================================

    #[test]
    fn resource_provider_preserved() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let r = inspector.show_resource("aws_instance.web").unwrap();
        assert!(r.provider.contains("hashicorp/aws"));
    }

    #[test]
    fn resource_with_empty_provider() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "resources": [{
                "type": "null_resource",
                "name": "trigger",
                "instances": [{ "attributes": { "id": "nr-1" } }]
            }]
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let r = inspector.show_resource("null_resource.trigger").unwrap();
        assert_eq!(r.provider, "");
    }

    // ================================================================
    // Version 5 rejection
    // ================================================================

    #[test]
    fn rejects_version_5() {
        let state = json!({
            "version": 5,
            "terraform_version": "2.0.0",
            "serial": 1,
            "lineage": "x"
        });
        let err = StateInspector::from_json(&state).unwrap_err();
        assert!(err.contains("unsupported state version"));
        assert!(err.contains('5'));
    }

    // ================================================================
    // Empty string edge cases
    // ================================================================

    #[test]
    fn show_resource_with_empty_string_address() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        assert!(inspector.show_resource("").is_none());
    }

    #[test]
    fn list_resources_by_type_with_empty_string() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let result = inspector.list_resources_by_type("");
        assert!(result.is_empty());
    }

    #[test]
    fn list_resources_by_module_with_empty_string() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let result = inspector.list_resources_by_module("");
        assert!(result.is_empty());
    }

    #[test]
    fn read_output_with_empty_string() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        assert!(inspector.read_output("").is_none());
    }

    // ================================================================
    // Audit event content verification
    // ================================================================

    #[test]
    fn audit_event_list_resources_details_contain_count() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.list_resources();
        let events = inspector.drain_audit_events();
        assert!(events[0].details.contains("listed"));
        assert!(events[0].details.contains('4'));
    }

    #[test]
    fn audit_event_list_by_type_details_contain_type_and_count() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.list_resources_by_type("aws_subnet");
        let events = inspector.drain_audit_events();
        assert!(events[0].details.contains("aws_subnet"));
        assert!(events[0].details.contains('1'));
    }

    #[test]
    fn audit_event_list_by_module_details_contain_module_and_count() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.list_resources_by_module("module.network");
        let events = inspector.drain_audit_events();
        assert!(events[0].details.contains("module.network"));
        assert!(events[0].details.contains('2'));
    }

    #[test]
    fn audit_event_show_resource_has_address() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.show_resource("aws_instance.web");
        let events = inspector.drain_audit_events();
        assert_eq!(
            events[0].resource_address,
            Some("aws_instance.web".to_string())
        );
    }

    #[test]
    fn audit_event_read_outputs_details_contain_count() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.read_outputs();
        let events = inspector.drain_audit_events();
        assert!(events[0].details.contains('2'));
    }

    #[test]
    fn audit_event_read_output_details_contain_name() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.read_output("db_password");
        let events = inspector.drain_audit_events();
        assert!(events[0].details.contains("db_password"));
    }

    #[test]
    fn audit_event_metadata_details() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let _ = inspector.metadata();
        let events = inspector.drain_audit_events();
        assert!(events[0].details.contains("metadata"));
    }

    // ================================================================
    // Resource attributes access
    // ================================================================

    #[test]
    fn resource_attributes_contain_expected_keys() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let r = inspector
            .show_resource("module.network.aws_vpc.main")
            .unwrap();
        assert_eq!(r.attributes["cidr_block"], "10.0.0.0/16");
    }

    #[test]
    fn resource_attributes_nested_object() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "resources": [{
                "type": "aws_instance",
                "name": "complex",
                "provider": "aws",
                "instances": [{
                    "attributes": {
                        "id": "i-complex",
                        "tags": { "Name": "complex", "env": "prod" },
                        "root_block_device": [{ "volume_size": 50 }]
                    }
                }]
            }]
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let r = inspector.show_resource("aws_instance.complex").unwrap();
        assert_eq!(r.attributes["tags"]["Name"], "complex");
        assert_eq!(r.attributes["root_block_device"][0]["volume_size"], 50);
    }

    // ================================================================
    // Idempotency and repeated queries
    // ================================================================

    #[test]
    fn repeated_list_resources_same_result() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let first = inspector.list_resources().len();
        let second = inspector.list_resources().len();
        assert_eq!(first, second);
    }

    #[test]
    fn repeated_show_resource_same_result() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let first = inspector
            .show_resource("aws_instance.web")
            .map(|r| r.id.clone());
        let second = inspector
            .show_resource("aws_instance.web")
            .map(|r| r.id.clone());
        assert_eq!(first, second);
    }

    #[test]
    fn repeated_read_output_same_result() {
        let mut inspector = StateInspector::from_json(&sample_state()).unwrap();
        let first = inspector.read_output("vpc_id").map(|o| o.value.clone());
        let second = inspector.read_output("vpc_id").map(|o| o.value.clone());
        assert_eq!(first, second);
    }

    // ================================================================
    // StateInspector debug
    // ================================================================

    #[test]
    fn state_inspector_debug_output() {
        let inspector = StateInspector::from_json(&sample_state()).unwrap();
        let dbg = format!("{inspector:?}");
        assert!(dbg.contains("StateInspector"));
    }

    // ================================================================
    // Numeric output values
    // ================================================================

    #[test]
    fn output_with_numeric_value() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "outputs": {
                "count": { "value": 7, "type": "number", "sensitive": false }
            }
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let o = inspector.read_output("count").unwrap();
        assert_eq!(o.value, json!(7));
        assert_eq!(o.type_hint, Some("number".to_string()));
    }

    #[test]
    fn output_with_boolean_value() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "outputs": {
                "enabled": { "value": true, "type": "bool", "sensitive": false }
            }
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        let o = inspector.read_output("enabled").unwrap();
        assert_eq!(o.value, json!(true));
    }

    // ================================================================
    // Version 0 rejection
    // ================================================================

    #[test]
    fn rejects_version_0() {
        let state = json!({
            "version": 0,
            "terraform_version": "0.1.0",
            "serial": 0,
            "lineage": "ancient"
        });
        let err = StateInspector::from_json(&state).unwrap_err();
        assert!(err.contains("unsupported"));
    }

    // ================================================================
    // Data sources (mode = "data")
    // ================================================================

    #[test]
    fn data_source_resource_parsed() {
        let state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "resources": [{
                "mode": "data",
                "type": "aws_ami",
                "name": "ubuntu",
                "provider": "aws",
                "instances": [{ "attributes": { "id": "ami-12345" } }]
            }]
        });
        let mut inspector = StateInspector::from_json(&state).unwrap();
        assert_eq!(inspector.resource_count(), 1);
        let r = inspector.show_resource("aws_ami.ubuntu").unwrap();
        assert_eq!(r.id, "ami-12345");
    }

    // ================================================================
    // resource_count / output_count accessors
    // ================================================================

    #[test]
    fn resource_count_no_audit() {
        let inspector = StateInspector::from_json(&sample_state()).unwrap();
        assert_eq!(inspector.resource_count(), 4);
        assert_eq!(inspector.audit_event_count(), 0);
    }

    #[test]
    fn output_count_no_audit() {
        let inspector = StateInspector::from_json(&sample_state()).unwrap();
        assert_eq!(inspector.output_count(), 2);
        assert_eq!(inspector.audit_event_count(), 0);
    }
}
