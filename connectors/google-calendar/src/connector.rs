//! FCP Google Calendar Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::GoogleCalendarClient,
    error::GoogleCalendarError,
    types::{Attendee, Event, EventDateTime},
};

/// FCP Google Calendar Connector.
pub struct GoogleCalendarConnector {
    base: Arc<BaseConnector>,
    client: Option<GoogleCalendarClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl GoogleCalendarConnector {
    /// Create a new Google Calendar connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "google-calendar",
            ))),
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the configuration is invalid or client creation fails.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let token =
            params
                .get("token")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing token in configuration".into(),
                })?;

        let base_url = params.get("base_url").and_then(|v| v.as_str());

        let mut client =
            GoogleCalendarClient::new(token).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("Google Calendar connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:google-calendar-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 100,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle health check.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the health status cannot be determined.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle introspect method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the introspection data fails.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "gcal.list_calendars",
                    "List all calendars for the authenticated user",
                    json!({
                        "type": "object",
                        "properties": {}
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "calendars": { "type": "array", "items": { "type": "object" } }
                        }
                    }),
                    "gcal.calendars.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all calendars accessible by the authenticated user."
                            .into(),
                        common_mistakes: vec![],
                        examples: vec!["{}".into()],
                        related: vec![CapabilityId::from_static("gcal.list_events")],
                    },
                ),
                op_info(
                    "gcal.get_event",
                    "Get a single calendar event by ID",
                    json!({
                        "type": "object",
                        "required": ["calendar_id", "event_id"],
                        "properties": {
                            "calendar_id": { "type": "string", "description": "Calendar ID (use 'primary' for the main calendar)" },
                            "event_id": { "type": "string", "description": "Event ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "event": { "type": "object" } } }),
                    "gcal.events.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve full details of a specific calendar event.".into(),
                        common_mistakes: vec![
                            "Using email address instead of calendar ID".into(),
                        ],
                        examples: vec![
                            r#"{"calendar_id": "primary", "event_id": "abc123def456"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gcal.list_events"),
                            CapabilityId::from_static("gcal.update_event"),
                        ],
                    },
                ),
                op_info(
                    "gcal.list_events",
                    "List events in a calendar with optional time range",
                    json!({
                        "type": "object",
                        "required": ["calendar_id"],
                        "properties": {
                            "calendar_id": { "type": "string", "description": "Calendar ID (use 'primary' for the main calendar)" },
                            "time_min": { "type": "string", "description": "Lower bound (RFC 3339) for event start time" },
                            "time_max": { "type": "string", "description": "Upper bound (RFC 3339) for event end time" },
                            "max_results": { "type": "integer", "description": "Max events to return" },
                            "page_token": { "type": "string", "description": "Pagination token" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "events": { "type": "array" },
                            "next_page_token": { "type": "string" },
                            "summary": { "type": "string" }
                        }
                    }),
                    "gcal.events.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use:
                            "List or search calendar events. Use time_min/time_max for date ranges."
                                .into(),
                        common_mistakes: vec![
                            "Not using RFC 3339 format for time_min/time_max".into(),
                        ],
                        examples: vec![
                            r#"{"calendar_id": "primary", "time_min": "2026-01-01T00:00:00Z", "max_results": 10}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("gcal.get_event")],
                    },
                ),
                op_info(
                    "gcal.create_event",
                    "Create a new calendar event",
                    json!({
                        "type": "object",
                        "required": ["calendar_id", "summary", "start", "end"],
                        "properties": {
                            "calendar_id": { "type": "string", "description": "Calendar ID" },
                            "summary": { "type": "string", "description": "Event title" },
                            "description": { "type": "string", "description": "Event description" },
                            "location": { "type": "string", "description": "Event location" },
                            "start": { "type": "string", "description": "Start time (RFC 3339)" },
                            "end": { "type": "string", "description": "End time (RFC 3339)" },
                            "attendees": { "type": "array", "items": { "type": "object" }, "description": "List of attendee objects with email" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "event": { "type": "object" } } }),
                    "gcal.events.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new event on a calendar. Requires start and end times in RFC 3339 format.".into(),
                        common_mistakes: vec![
                            "Forgetting to specify time zone in the datetime string".into(),
                        ],
                        examples: vec![
                            r#"{"calendar_id": "primary", "summary": "Team Meeting", "start": "2026-01-15T10:00:00-05:00", "end": "2026-01-15T11:00:00-05:00"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gcal.update_event"),
                            CapabilityId::from_static("gcal.quick_add"),
                        ],
                    },
                ),
                op_info(
                    "gcal.update_event",
                    "Update an existing calendar event",
                    json!({
                        "type": "object",
                        "required": ["calendar_id", "event_id"],
                        "properties": {
                            "calendar_id": { "type": "string", "description": "Calendar ID" },
                            "event_id": { "type": "string", "description": "Event ID to update" },
                            "summary": { "type": "string", "description": "New event title" },
                            "description": { "type": "string", "description": "New event description" },
                            "location": { "type": "string", "description": "New event location" },
                            "start": { "type": "string", "description": "New start time (RFC 3339)" },
                            "end": { "type": "string", "description": "New end time (RFC 3339)" },
                            "attendees": { "type": "array", "items": { "type": "object" }, "description": "Updated attendee list" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "event": { "type": "object" } } }),
                    "gcal.events.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Update fields of an existing calendar event. Only specified fields are changed.".into(),
                        common_mistakes: vec![
                            "Not providing the event_id of the existing event".into(),
                        ],
                        examples: vec![
                            r#"{"calendar_id": "primary", "event_id": "abc123", "summary": "Updated Meeting Title"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gcal.get_event"),
                            CapabilityId::from_static("gcal.create_event"),
                        ],
                    },
                ),
                op_info(
                    "gcal.delete_event",
                    "Delete a calendar event",
                    json!({
                        "type": "object",
                        "required": ["calendar_id", "event_id"],
                        "properties": {
                            "calendar_id": { "type": "string", "description": "Calendar ID" },
                            "event_id": { "type": "string", "description": "Event ID to delete" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "status": { "type": "string" } } }),
                    "gcal.events.write",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Permanently delete a calendar event. This cannot be undone."
                            .into(),
                        common_mistakes: vec![
                            "Deleting recurring event instances instead of the series".into(),
                        ],
                        examples: vec![
                            r#"{"calendar_id": "primary", "event_id": "abc123def456"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("gcal.get_event")],
                    },
                ),
                op_info(
                    "gcal.quick_add",
                    "Quick-add an event using natural language text",
                    json!({
                        "type": "object",
                        "required": ["calendar_id", "text"],
                        "properties": {
                            "calendar_id": { "type": "string", "description": "Calendar ID" },
                            "text": { "type": "string", "description": "Natural language event description (e.g., 'Lunch with John tomorrow at noon')" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "event": { "type": "object" } } }),
                    "gcal.events.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Quickly create an event using natural language. Google Calendar parses the text to extract date, time, and title.".into(),
                        common_mistakes: vec![
                            "Using ambiguous dates without specifying the year".into(),
                        ],
                        examples: vec![
                            r#"{"calendar_id": "primary", "text": "Meeting with Alice tomorrow at 3pm"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("gcal.create_event")],
                    },
                ),
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle simulate method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle invoke method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the operation fails or capability verification fails.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "gcal.list_calendars" => self.invoke_list_calendars().await,
            "gcal.get_event" => self.invoke_get_event(input).await,
            "gcal.list_events" => self.invoke_list_events(input).await,
            "gcal.create_event" => self.invoke_create_event(input).await,
            "gcal.update_event" => self.invoke_update_event(input).await,
            "gcal.delete_event" => self.invoke_delete_event(input).await,
            "gcal.quick_add" => self.invoke_quick_add(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_list_calendars(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let result = client
            .list_calendars()
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({ "calendars": result.items }))
    }

    async fn invoke_get_event(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let calendar_id = require_str(&input, "calendar_id")?;
        let event_id = require_str(&input, "event_id")?;

        let event = client
            .get_event(calendar_id, event_id)
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({ "event": event }))
    }

    async fn invoke_list_events(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let calendar_id = require_str(&input, "calendar_id")?;
        let time_min = input.get("time_min").and_then(|v| v.as_str());
        let time_max = input.get("time_max").and_then(|v| v.as_str());
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let page_token = input.get("page_token").and_then(|v| v.as_str());

        let result = client
            .list_events(calendar_id, time_min, time_max, max_results, page_token)
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({
            "events": result.items,
            "next_page_token": result.next_page_token,
            "summary": result.summary
        }))
    }

    async fn invoke_create_event(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let calendar_id = require_str(&input, "calendar_id")?;
        let summary = require_str(&input, "summary")?;
        let start_str = require_str(&input, "start")?;
        let end_str = require_str(&input, "end")?;

        let description = input
            .get("description")
            .and_then(|v| v.as_str())
            .map(String::from);
        let location = input
            .get("location")
            .and_then(|v| v.as_str())
            .map(String::from);

        let attendees: Vec<Attendee> = input
            .get("attendees")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let event = Event {
            id: None,
            status: None,
            summary: Some(summary.to_string()),
            description,
            location,
            start: Some(EventDateTime {
                date_time: Some(start_str.to_string()),
                date: None,
                time_zone: None,
            }),
            end: Some(EventDateTime {
                date_time: Some(end_str.to_string()),
                date: None,
                time_zone: None,
            }),
            creator: None,
            organizer: None,
            attendees,
            html_link: None,
            hangout_link: None,
            recurrence: vec![],
        };

        let created = client
            .create_event(calendar_id, &event)
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({ "event": created }))
    }

    async fn invoke_update_event(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let calendar_id = require_str(&input, "calendar_id")?;
        let event_id = require_str(&input, "event_id")?;

        let summary = input
            .get("summary")
            .and_then(|v| v.as_str())
            .map(String::from);
        let description = input
            .get("description")
            .and_then(|v| v.as_str())
            .map(String::from);
        let location = input
            .get("location")
            .and_then(|v| v.as_str())
            .map(String::from);

        let start = input.get("start").and_then(|v| v.as_str()).map(|s| {
            EventDateTime {
                date_time: Some(s.to_string()),
                date: None,
                time_zone: None,
            }
        });
        let end = input.get("end").and_then(|v| v.as_str()).map(|s| {
            EventDateTime {
                date_time: Some(s.to_string()),
                date: None,
                time_zone: None,
            }
        });

        let attendees: Vec<Attendee> = input
            .get("attendees")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let event = Event {
            id: None,
            status: None,
            summary,
            description,
            location,
            start,
            end,
            creator: None,
            organizer: None,
            attendees,
            html_link: None,
            hangout_link: None,
            recurrence: vec![],
        };

        let updated = client
            .update_event(calendar_id, event_id, &event)
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({ "event": updated }))
    }

    async fn invoke_delete_event(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let calendar_id = require_str(&input, "calendar_id")?;
        let event_id = require_str(&input, "event_id")?;

        client
            .delete_event(calendar_id, event_id)
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({ "status": "deleted" }))
    }

    async fn invoke_quick_add(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let calendar_id = require_str(&input, "calendar_id")?;
        let text = require_str(&input, "text")?;

        let event = client
            .quick_add(calendar_id, text)
            .await
            .map_err(|e: GoogleCalendarError| e.to_fcp_error())?;

        Ok(json!({ "event": event }))
    }

    /// Handle shutdown.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the shutdown process fails.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Google Calendar connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for GoogleCalendarConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

#[allow(clippy::fn_params_excessive_bools)]
fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;

    fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> CapabilityToken {
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[cap])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .unwrap();
        CapabilityToken { raw: cose }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = GoogleCalendarConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gcal.calendars.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = GoogleCalendarConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gcal.list_calendars"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "gcal.list_calendars");

        let result = connector
            .handle_invoke(json!({
                "operation": "gcal.list_calendars",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = GoogleCalendarConnector::new();
        connector.client = Some(
            GoogleCalendarClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gcal.get_event"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "gcal.get_event");

        let result = connector
            .handle_invoke(json!({
                "operation": "gcal.get_event",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("calendar_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = GoogleCalendarConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"gcal.list_calendars"));
        assert!(op_ids.contains(&"gcal.get_event"));
        assert!(op_ids.contains(&"gcal.list_events"));
        assert!(op_ids.contains(&"gcal.create_event"));
        assert!(op_ids.contains(&"gcal.update_event"));
        assert!(op_ids.contains(&"gcal.delete_event"));
        assert!(op_ids.contains(&"gcal.quick_add"));
        assert_eq!(ops.len(), 7);
    }
}
