use std::collections::BTreeMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use fcp_host::{
    LocalMcpProvider, LocalN8nDispatchErrorCode, LocalN8nDispatchRequest, LocalN8nDispatcher,
    LocalN8nDocumentationDepth, LocalN8nGetNodeInput, LocalN8nGetTemplateInput,
    LocalN8nKnowledgeAction, LocalN8nKnowledgeQuery, LocalN8nNodeMode, LocalN8nSearchMode,
    LocalN8nSearchNodesInput, LocalN8nTemplateMode, LocalN8nTool, LocalN8nValidationMode,
    LocalN8nValidationProfile, LocalN8nValidationRun, LocalN8nValidationSubject,
    LocalN8nWorkflowValidationInput, LocalN8nWorkflowValidationOptions,
};
use fcp_manifest::{
    LOCAL_MCP_CATALOG_TOOLS, LOCAL_MCP_METHODS, LOCAL_MCP_PROTOCOL_VERSION, LocalMcpPolicy,
    local_mcp_schema_digest,
};
use serde_json::json;

fn knowledge_request() -> LocalN8nDispatchRequest {
    LocalN8nDispatchRequest::KnowledgeQuery(LocalN8nKnowledgeQuery {
        correlation_id: "dispatch-test".into(),
        action: LocalN8nKnowledgeAction::SearchNodes(LocalN8nSearchNodesInput {
            query: "webhook".into(),
            limit: Some(3),
            mode: Some(LocalN8nSearchMode::Or),
            include_examples: false,
            include_operations: false,
            source: None,
        }),
    })
}

fn provider() -> LocalMcpProvider {
    let expected_digest = local_mcp_schema_digest(&json!({"type": "object"}));
    let expected_catalog = LOCAL_MCP_CATALOG_TOOLS
        .iter()
        .map(|tool| ((*tool).into(), expected_digest.clone()))
        .collect();
    LocalMcpProvider::new(LocalMcpPolicy {
        package_id: "dispatch-test-provider".into(),
        package_version: semver::Version::new(1, 0, 0),
        launcher_path: "/bin/sh".into(),
        launcher_digest: "0".repeat(64),
        runtime_executable: "/usr/bin/dash".into(),
        runtime_executable_digest: "0".repeat(64),
        package_metadata_path: "/usr/share/fcp/package.json".into(),
        package_metadata_digest: "0".repeat(64),
        protocol_version: LOCAL_MCP_PROTOCOL_VERSION.into(),
        fixed_args: Vec::new(),
        fixed_env: BTreeMap::new(),
        allowed_methods: LOCAL_MCP_METHODS
            .iter()
            .map(|method| (*method).into())
            .collect(),
        expected_catalog,
        callable_tools: LOCAL_MCP_CATALOG_TOOLS
            .iter()
            .map(|tool| (*tool).into())
            .collect(),
        max_frame_bytes: 1024,
        max_request_bytes: 1024,
        max_result_bytes: 1024,
        max_sequential_calls: 1,
        startup_timeout_ms: 1000,
        request_timeout_ms: 1000,
        shutdown_timeout_ms: 1000,
        idle_window_ms: 0,
        network_disabled: true,
    })
    .expect("policy shape")
}

#[test]
fn exact_operation_maps_to_closed_internal_tool() {
    assert_eq!(
        knowledge_request().internal_tool(),
        LocalN8nTool::SearchNodes
    );
    let documentation = LocalN8nDispatchRequest::KnowledgeQuery(LocalN8nKnowledgeQuery {
        correlation_id: "dispatch-test".into(),
        action: LocalN8nKnowledgeAction::ToolDocumentation(
            fcp_host::LocalN8nToolDocumentationInput {
                topic: Some("search_nodes".into()),
                depth: LocalN8nDocumentationDepth::Full,
            },
        ),
    });
    assert_eq!(
        documentation.internal_tool(),
        LocalN8nTool::ToolsDocumentation
    );
    let validation = LocalN8nDispatchRequest::ValidationRun(LocalN8nValidationRun {
        correlation_id: "dispatch-test".into(),
        subject: LocalN8nValidationSubject::Workflow(LocalN8nWorkflowValidationInput {
            workflow: json!({"nodes": [], "connections": {}}),
            options: None,
        }),
    });
    assert_eq!(validation.internal_tool(), LocalN8nTool::ValidateWorkflow);
}

#[test]
fn catalog_specific_validation_controls_remain_separate() {
    let node = LocalN8nDispatchRequest::ValidationRun(LocalN8nValidationRun {
        correlation_id: "dispatch-test".into(),
        subject: LocalN8nValidationSubject::Node(fcp_host::LocalN8nNodeValidationInput {
            node_type: "nodes-base.webhook".into(),
            config: json!({}),
            mode: LocalN8nValidationMode::Minimal,
            profile: LocalN8nValidationProfile::Strict,
        }),
    });
    let node_json = serde_json::to_value(node).expect("node dto");
    assert_eq!(node_json["input"]["subject"]["node"]["mode"], "minimal");
    assert_eq!(node_json["input"]["subject"]["node"]["profile"], "strict");

    let workflow = LocalN8nDispatchRequest::ValidationRun(LocalN8nValidationRun {
        correlation_id: "dispatch-test".into(),
        subject: LocalN8nValidationSubject::Workflow(LocalN8nWorkflowValidationInput {
            workflow: json!({"nodes": [], "connections": {}}),
            options: Some(LocalN8nWorkflowValidationOptions {
                validate_nodes: true,
                validate_connections: false,
                validate_expressions: true,
                profile: Some(LocalN8nValidationProfile::Runtime),
            }),
        }),
    });
    let workflow_json = serde_json::to_value(workflow).expect("workflow dto");
    assert_eq!(
        workflow_json["input"]["subject"]["workflow"]["options"]["profile"],
        "runtime"
    );
    assert!(
        workflow_json["input"]["subject"]["workflow"]["options"]
            .get("mode")
            .is_none()
    );
}

#[test]
fn installed_catalog_input_shapes_are_typed() {
    let documentation: LocalN8nDispatchRequest = serde_json::from_value(json!({
        "operation": "n8n.knowledge.query",
        "input": {
            "correlation_id": "dispatch-test",
            "action": {"tool_documentation": {"topic": "overview", "depth": "full"}}
        }
    }))
    .expect("documentation dto");
    let documentation_json = serde_json::to_value(documentation).expect("documentation wire");
    assert_eq!(
        documentation_json["input"]["action"]["tool_documentation"]["topic"],
        "overview"
    );
    assert_eq!(
        documentation_json["input"]["action"]["tool_documentation"]["depth"],
        "full"
    );
    assert!(
        documentation_json["input"]["action"]["tool_documentation"]
            .get("toolName")
            .is_none()
    );

    let templates: LocalN8nDispatchRequest = serde_json::from_value(json!({
        "operation": "n8n.knowledge.query",
        "input": {
            "correlation_id": "dispatch-test",
            "action": {"get_template": {"templateId": 42, "mode": "full"}}
        }
    }))
    .expect("template dto");
    let templates_json = serde_json::to_value(templates).expect("template wire");
    assert_eq!(
        templates_json["input"]["action"]["get_template"]["templateId"],
        42
    );
}

#[test]
fn unknown_fields_and_arbitrary_tool_names_fail_deserialization() {
    let unknown_field = json!({
        "operation": "n8n.knowledge.query",
        "input": {
            "correlation_id": "dispatch-test",
            "action": {"search_nodes": {"query": "x"}},
            "command": "/bin/sh"
        }
    });
    assert!(serde_json::from_value::<LocalN8nDispatchRequest>(unknown_field).is_err());

    let arbitrary_tool = json!({
        "operation": "n8n.knowledge.query",
        "input": {
            "correlation_id": "dispatch-test",
            "action": {"tool_documentation": {"topic": "search_nodes", "depth": "full", "tool": "not-in-catalog"}}
        }
    });
    assert!(serde_json::from_value::<LocalN8nDispatchRequest>(arbitrary_tool).is_err());
}

#[test]
fn oversized_input_is_rejected_before_provider_launch() {
    let dispatcher = LocalN8nDispatcher::with_max_input_bytes(provider(), 1);
    let result = dispatcher.dispatch(knowledge_request(), Arc::new(AtomicBool::new(false)));
    assert_eq!(
        result.expect_err("oversized request").code(),
        LocalN8nDispatchErrorCode::InputTooLarge
    );
}

#[test]
fn catalog_specific_required_fields_fail_before_provider_launch() {
    let dispatcher = LocalN8nDispatcher::new(provider());
    let missing_property_query = LocalN8nDispatchRequest::KnowledgeQuery(LocalN8nKnowledgeQuery {
        correlation_id: "dispatch-test".into(),
        action: LocalN8nKnowledgeAction::GetNode(LocalN8nGetNodeInput {
            node_type: "nodes-base.httpRequest".into(),
            detail: fcp_host::LocalN8nDetail::Standard,
            mode: LocalN8nNodeMode::SearchProperties,
            include_type_info: false,
            include_examples: false,
            from_version: None,
            to_version: None,
            property_query: None,
            max_property_results: None,
        }),
    });
    assert_eq!(
        dispatcher
            .dispatch(missing_property_query, Arc::new(AtomicBool::new(false)),)
            .expect_err("property query is required")
            .code(),
        LocalN8nDispatchErrorCode::InvalidRequest
    );

    let zero_template_id = LocalN8nDispatchRequest::KnowledgeQuery(LocalN8nKnowledgeQuery {
        correlation_id: "dispatch-test".into(),
        action: LocalN8nKnowledgeAction::GetTemplate(LocalN8nGetTemplateInput {
            template_id: 0,
            mode: LocalN8nTemplateMode::Full,
        }),
    });
    assert_eq!(
        dispatcher
            .dispatch(zero_template_id, Arc::new(AtomicBool::new(false)))
            .expect_err("template id must be positive")
            .code(),
        LocalN8nDispatchErrorCode::InvalidRequest
    );
}

#[test]
fn cancellation_delegates_to_existing_provider_boundary() {
    let dispatcher = LocalN8nDispatcher::new(provider());
    let cancelled = Arc::new(AtomicBool::new(true));
    let result = dispatcher.dispatch(knowledge_request(), Arc::clone(&cancelled));
    assert_eq!(
        result.expect_err("cancelled request").code(),
        LocalN8nDispatchErrorCode::Cancelled
    );
    assert!(cancelled.load(Ordering::Acquire));
}
