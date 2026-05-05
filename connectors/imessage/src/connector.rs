//! `BlueBubbles` `iMessage` connector implementation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use chrono::Utc;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, CorrelationId, EventCaps, EventInfo, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, OrderingPolicy, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse, ZoneId,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_sdk::prelude::*;
use rusqlite::{Connection, OpenFlags, params_from_iter};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::client::BlueBubblesClient;
use crate::types::{
    BlueBubblesConfig, BlueBubblesContactsEnrichmentConfig, BlueBubblesReplyContext,
    BlueBubblesSendTarget, BlueBubblesTargetService, BlueBubblesWebhookCoalescingConfig, Message,
    NormalizedBlueBubblesWebhookMessage, QueryParams, SendMediaOptions, SendMessageOptions,
    bluebubbles_webhook_source_dedupe_ids, default_webhook_events,
    normalize_bluebubbles_contact_phone_key, normalize_bluebubbles_message_effect,
    normalize_bluebubbles_tapback_reaction, normalize_bluebubbles_webhook_payload,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_SEND_MESSAGE: &str = "imessage.send_message";
const OP_SEND_MEDIA: &str = "imessage.send_media";
const OP_RESOLVE_SEND_TARGET: &str = "imessage.resolve_send_target";
const OP_CREATE_CHAT: &str = "imessage.create_chat";
const OP_GET_ACTION_AVAILABILITY: &str = "imessage.get_action_availability";
const OP_EDIT_MESSAGE: &str = "imessage.edit_message";
const OP_UNSEND_MESSAGE: &str = "imessage.unsend_message";
const OP_SEND_REACTION: &str = "imessage.send_reaction";
const OP_SET_TYPING: &str = "imessage.set_typing";
const OP_GET_CHATS: &str = "imessage.get_chats";
const OP_GET_CHAT: &str = "imessage.get_chat";
const OP_GET_MESSAGES: &str = "imessage.get_messages";
const OP_SYNC_EVENTS: &str = "imessage.sync_events";
const OP_DOWNLOAD_ATTACHMENT: &str = "imessage.download_attachment";
const OP_MARK_READ: &str = "imessage.mark_read";
const OP_GET_SERVER_INFO: &str = "imessage.get_server_info";
const OP_REGISTER_WEBHOOK: &str = "imessage.register_webhook";
const OP_LIST_WEBHOOKS: &str = "imessage.list_webhooks";
const OP_UNREGISTER_WEBHOOK: &str = "imessage.unregister_webhook";
const OP_INGEST_WEBHOOK_EVENT: &str = "imessage.ingest_webhook_event";
const OP_INGEST_WEBHOOK_REQUEST: &str = "imessage.ingest_webhook_request";

// Capability IDs
const CAP_SEND: &str = "imessage.send";
const CAP_READ: &str = "imessage.read";
const CAP_ADMIN: &str = "imessage.admin";

const DEFAULT_SYNC_CHAT_LIMIT: u64 = 25;
const DEFAULT_SYNC_MESSAGE_LIMIT: u64 = 50;
const WEBHOOK_EVENT_BUFFER_MIN_EVENTS: u32 = 64;
const WEBHOOK_EVENT_BUFFER_MIN_EVENTS_USIZE: usize = 64;
const WEBHOOK_EVENT_BUFFER_MAX_EVENTS: usize = 256;
const WEBHOOK_INGRESS_MAX_BODY_BYTES: usize = 1024 * 1024;
const WEBHOOK_INGRESS_TIMEOUT_MS: u64 = 5_000;
const WEBHOOK_INGRESS_CONCURRENCY_LIMIT: u64 = 64;
const WEBHOOK_INGRESS_RATE_LIMIT_MAX: u64 = 120;
const WEBHOOK_INGRESS_RATE_LIMIT_WINDOW_MS: u64 = 60_000;
const WEBHOOK_AUTH_HEADER: &str = "x-bluebubbles-auth";

#[must_use]
const fn webhook_event_caps() -> EventCaps {
    EventCaps {
        streaming: true,
        replay: true,
        min_buffer_events: WEBHOOK_EVENT_BUFFER_MIN_EVENTS,
        requires_ack: false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BlueBubblesDedupeClaim {
    Claimed,
    Duplicate { matched_id: String },
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
struct BlueBubblesDedupeFile {
    entries: BTreeMap<String, BlueBubblesDedupeEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct BlueBubblesDedupeEntry {
    claimed_at_ms: i64,
    finalized_at_ms: Option<i64>,
}

#[derive(Debug)]
struct BlueBubblesInboundDedupeStore {
    path: Option<PathBuf>,
    ttl: Duration,
    state: Mutex<BlueBubblesDedupeFile>,
}

impl BlueBubblesInboundDedupeStore {
    fn from_config(config: &BlueBubblesConfig) -> FcpResult<Self> {
        let path = config
            .webhook_inbound
            .dedupe_state_path
            .as_ref()
            .map(PathBuf::from);
        let state = match path.as_deref() {
            Some(path) => Self::load_state(path)?,
            None => BlueBubblesDedupeFile::default(),
        };
        Ok(Self {
            path,
            ttl: Duration::from_secs(config.webhook_inbound.dedupe_ttl_seconds),
            state: Mutex::new(state),
        })
    }

    fn load_state(path: &Path) -> FcpResult<BlueBubblesDedupeFile> {
        if !path.exists() {
            return Ok(BlueBubblesDedupeFile::default());
        }

        let bytes = fs::read(path).map_err(|error| FcpError::Internal {
            message: format!(
                "Failed to read BlueBubbles webhook dedupe state '{}': {error}",
                path.display()
            ),
        })?;
        serde_json::from_slice(&bytes).map_err(|error| FcpError::Internal {
            message: format!(
                "Failed to parse BlueBubbles webhook dedupe state '{}': {error}",
                path.display()
            ),
        })
    }

    fn claim(&self, dedupe_ids: &[String]) -> FcpResult<BlueBubblesDedupeClaim> {
        if dedupe_ids.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "BlueBubbles webhook dedupe requires at least one source ID".into(),
            });
        }

        let now_ms = Utc::now().timestamp_millis();
        let (claim, snapshot) = {
            let mut state = self.lock_state()?;
            self.prune_expired_locked(&mut state, now_ms);

            if let Some(matched_id) = dedupe_ids
                .iter()
                .find(|dedupe_id| state.entries.contains_key(dedupe_id.as_str()))
            {
                (
                    BlueBubblesDedupeClaim::Duplicate {
                        matched_id: matched_id.clone(),
                    },
                    state.clone(),
                )
            } else {
                for dedupe_id in dedupe_ids {
                    state.entries.insert(
                        dedupe_id.clone(),
                        BlueBubblesDedupeEntry {
                            claimed_at_ms: now_ms,
                            finalized_at_ms: None,
                        },
                    );
                }
                (BlueBubblesDedupeClaim::Claimed, state.clone())
            }
        };
        self.persist_locked(&snapshot)?;
        Ok(claim)
    }

    fn finalize(&self, dedupe_ids: &[String]) -> FcpResult<()> {
        let now_ms = Utc::now().timestamp_millis();
        let snapshot = {
            let mut state = self.lock_state()?;
            for dedupe_id in dedupe_ids {
                if let Some(entry) = state.entries.get_mut(dedupe_id) {
                    entry.finalized_at_ms = Some(now_ms);
                }
            }
            state.clone()
        };
        self.persist_locked(&snapshot)
    }

    fn release(&self, dedupe_ids: &[String]) -> FcpResult<()> {
        let snapshot = {
            let mut state = self.lock_state()?;
            for dedupe_id in dedupe_ids {
                state.entries.remove(dedupe_id);
            }
            state.clone()
        };
        self.persist_locked(&snapshot)
    }

    #[cfg(test)]
    fn age_claim_for_test(&self, dedupe_id: &str, age_ms: i64) -> FcpResult<()> {
        let snapshot = {
            let mut state = self.lock_state()?;
            let Some(entry) = state.entries.get_mut(dedupe_id) else {
                return Err(FcpError::Internal {
                    message: format!("missing test dedupe id {dedupe_id}"),
                });
            };
            entry.claimed_at_ms = entry.claimed_at_ms.saturating_sub(age_ms);
            state.clone()
        };
        self.persist_locked(&snapshot)
    }

    fn lock_state(&self) -> FcpResult<std::sync::MutexGuard<'_, BlueBubblesDedupeFile>> {
        self.state.lock().map_err(|_| FcpError::Internal {
            message: "BlueBubbles webhook dedupe state lock was poisoned".into(),
        })
    }

    fn prune_expired_locked(&self, state: &mut BlueBubblesDedupeFile, now_ms: i64) {
        let ttl_ms = i64::try_from(self.ttl.as_millis()).unwrap_or(i64::MAX);
        state
            .entries
            .retain(|_, entry| now_ms.saturating_sub(entry.claimed_at_ms) < ttl_ms);
    }

    fn persist_locked(&self, state: &BlueBubblesDedupeFile) -> FcpResult<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };

        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|error| FcpError::Internal {
                message: format!(
                    "Failed to create BlueBubbles webhook dedupe state directory '{}': {error}",
                    parent.display()
                ),
            })?;
        }

        let bytes = serde_json::to_vec_pretty(state).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize BlueBubbles webhook dedupe state: {error}"),
        })?;
        let tmp_path = path.with_extension(format!(
            "{}.tmp",
            path.extension()
                .and_then(|value| value.to_str())
                .unwrap_or("json")
        ));
        fs::write(&tmp_path, bytes).map_err(|error| FcpError::Internal {
            message: format!(
                "Failed to write BlueBubbles webhook dedupe state '{}': {error}",
                tmp_path.display()
            ),
        })?;
        fs::rename(&tmp_path, path).map_err(|error| FcpError::Internal {
            message: format!(
                "Failed to commit BlueBubbles webhook dedupe state '{}': {error}",
                path.display()
            ),
        })?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct BlueBubblesCoalescingBuffer {
    entries: Vec<NormalizedBlueBubblesWebhookMessage>,
    last_seen_ms: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
struct BlueBubblesCoalescingSummary {
    enabled: bool,
    decision: &'static str,
    key: Option<String>,
    emitted_count: usize,
    buffered_count: usize,
    pending_buffer_count: usize,
    truncated_fields: Vec<String>,
}

#[derive(Debug, Clone)]
struct BlueBubblesCoalescingOutcome {
    status: &'static str,
    events: Vec<NormalizedBlueBubblesWebhookMessage>,
    summary: BlueBubblesCoalescingSummary,
}

#[derive(Debug, Default)]
struct BlueBubblesWebhookCoalescer {
    buffers: Mutex<BTreeMap<String, BlueBubblesCoalescingBuffer>>,
}

impl BlueBubblesWebhookCoalescer {
    fn ingest(
        &self,
        config: &BlueBubblesWebhookCoalescingConfig,
        account_id: &str,
        event: NormalizedBlueBubblesWebhookMessage,
        observed_at_ms: i64,
    ) -> FcpResult<BlueBubblesCoalescingOutcome> {
        if !config.enabled {
            return Ok(Self::immediate_outcome(
                false,
                "disabled",
                None,
                event,
                0,
                Vec::new(),
            ));
        }

        let Some((key, key_reason)) = coalescing_key(config, account_id, &event) else {
            return Ok(Self::immediate_outcome(
                true,
                "ineligible_immediate",
                None,
                event,
                self.pending_count()?,
                Vec::new(),
            ));
        };

        let mut buffers = self.lock_buffers()?;
        let mut emitted = Self::flush_expired_locked(config, &mut buffers, observed_at_ms);
        let mut truncated_fields = collect_truncated_fields(&emitted);

        let buffer_count = if let Some(buffer) = buffers.get_mut(&key) {
            buffer.entries.push(event);
            buffer.last_seen_ms = observed_at_ms;
            buffer.entries.len()
        } else {
            if buffers.len() >= config.max_pending_buffers {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: "BlueBubbles webhook coalescing pending buffer limit exceeded".into(),
                });
            }
            buffers.insert(
                key.clone(),
                BlueBubblesCoalescingBuffer {
                    entries: vec![event],
                    last_seen_ms: observed_at_ms,
                },
            );
            1
        };

        let decision = if buffer_count >= config.max_source_messages {
            if let Some(buffer) = buffers.remove(&key) {
                let combined = combine_coalesced_messages(config, buffer.entries);
                truncated_fields.extend(combined.coalescing_truncated_fields.clone());
                emitted.push(combined);
            }
            "max_source_messages_flushed"
        } else if emitted.is_empty() {
            key_reason
        } else {
            "expired_buffers_flushed"
        };

        let pending_buffer_count = buffers.len();
        let current_buffered_count = buffers.get(&key).map_or(0, |buffer| buffer.entries.len());
        drop(buffers);

        truncated_fields.sort();
        truncated_fields.dedup();
        let status = if emitted.is_empty() {
            "buffered"
        } else {
            "accepted"
        };
        let emitted_count = emitted.len();

        Ok(BlueBubblesCoalescingOutcome {
            status,
            events: emitted,
            summary: BlueBubblesCoalescingSummary {
                enabled: true,
                decision,
                key: Some(key),
                emitted_count,
                buffered_count: current_buffered_count,
                pending_buffer_count,
                truncated_fields,
            },
        })
    }

    fn flush_all(
        &self,
        config: &BlueBubblesWebhookCoalescingConfig,
    ) -> FcpResult<BlueBubblesCoalescingOutcome> {
        let drained = {
            let mut buffers = self.lock_buffers()?;
            std::mem::take(&mut *buffers)
        };
        let events = drained
            .into_values()
            .map(|buffer| combine_coalesced_messages(config, buffer.entries))
            .collect::<Vec<_>>();
        let truncated_fields = collect_truncated_fields(&events);
        Ok(BlueBubblesCoalescingOutcome {
            status: "flushed",
            summary: BlueBubblesCoalescingSummary {
                enabled: config.enabled,
                decision: "flush_requested",
                key: None,
                emitted_count: events.len(),
                buffered_count: 0,
                pending_buffer_count: 0,
                truncated_fields,
            },
            events,
        })
    }

    fn drain_for_shutdown(
        &self,
        config: &BlueBubblesWebhookCoalescingConfig,
    ) -> FcpResult<Vec<NormalizedBlueBubblesWebhookMessage>> {
        Ok(self.flush_all(config)?.events)
    }

    fn pending_count(&self) -> FcpResult<usize> {
        Ok(self.lock_buffers()?.len())
    }

    fn lock_buffers(
        &self,
    ) -> FcpResult<std::sync::MutexGuard<'_, BTreeMap<String, BlueBubblesCoalescingBuffer>>> {
        self.buffers.lock().map_err(|_| FcpError::Internal {
            message: "BlueBubbles webhook coalescing state lock was poisoned".into(),
        })
    }

    fn flush_expired_locked(
        config: &BlueBubblesWebhookCoalescingConfig,
        buffers: &mut BTreeMap<String, BlueBubblesCoalescingBuffer>,
        observed_at_ms: i64,
    ) -> Vec<NormalizedBlueBubblesWebhookMessage> {
        let debounce_ms = i64::try_from(config.debounce_ms).unwrap_or(i64::MAX);
        let drained = std::mem::take(buffers);
        let mut retained = BTreeMap::new();
        let mut expired = Vec::new();

        for (key, buffer) in drained {
            let elapsed_ms = observed_at_ms.saturating_sub(buffer.last_seen_ms);
            if elapsed_ms >= debounce_ms {
                expired.push(combine_coalesced_messages(config, buffer.entries));
            } else {
                retained.insert(key, buffer);
            }
        }

        *buffers = retained;
        expired
    }

    fn immediate_outcome(
        enabled: bool,
        decision: &'static str,
        key: Option<String>,
        event: NormalizedBlueBubblesWebhookMessage,
        pending_buffer_count: usize,
        truncated_fields: Vec<String>,
    ) -> BlueBubblesCoalescingOutcome {
        BlueBubblesCoalescingOutcome {
            status: "accepted",
            events: vec![event],
            summary: BlueBubblesCoalescingSummary {
                enabled,
                decision,
                key,
                emitted_count: 1,
                buffered_count: 0,
                pending_buffer_count,
                truncated_fields,
            },
        }
    }
}

fn coalescing_key(
    config: &BlueBubblesWebhookCoalescingConfig,
    account_id: &str,
    event: &NormalizedBlueBubblesWebhookMessage,
) -> Option<(String, &'static str)> {
    if event.is_group || event.is_from_me || event.is_tapback || event.event_type != "new-message" {
        return None;
    }

    if starts_with_immediate_command(config, event.text.as_deref()) {
        return None;
    }

    let account_id = account_id.trim();
    let account_id = if account_id.is_empty() {
        "default"
    } else {
        account_id
    };

    if let (Some(balloon_bundle_id), Some(associated_message_guid)) = (
        event.balloon_bundle_id.as_deref(),
        event.associated_message_guid.as_deref(),
    ) {
        if !balloon_bundle_id.trim().is_empty() && !associated_message_guid.trim().is_empty() {
            return Some((
                format!(
                    "bluebubbles:{account_id}:msg:{}",
                    associated_message_guid.trim()
                ),
                "message_balloon_buffered",
            ));
        }
    }

    let chat_key = event
        .chat_guid
        .as_deref()
        .or(event.chat_identifier.as_deref())?
        .trim();
    let sender_id = event.sender_id.as_deref()?.trim();
    if chat_key.is_empty() || sender_id.is_empty() {
        return None;
    }

    Some((
        format!("bluebubbles:{account_id}:dm:{chat_key}:{sender_id}"),
        "dm_same_sender_buffered",
    ))
}

fn starts_with_immediate_command(
    config: &BlueBubblesWebhookCoalescingConfig,
    text: Option<&str>,
) -> bool {
    let Some(text) = text.map(str::trim).filter(|text| !text.is_empty()) else {
        return false;
    };
    config
        .immediate_command_prefixes
        .iter()
        .any(|prefix| text.starts_with(prefix))
}

fn combine_coalesced_messages(
    config: &BlueBubblesWebhookCoalescingConfig,
    entries: Vec<NormalizedBlueBubblesWebhookMessage>,
) -> NormalizedBlueBubblesWebhookMessage {
    let mut entries = entries;
    if entries.len() <= 1 {
        return entries.pop().expect("coalescing buffer is never empty");
    }

    let mut truncated_fields = Vec::new();
    let mut all_source_ids = Vec::new();
    for entry in &entries {
        push_unique_source_id(&mut all_source_ids, &entry.event_id);
        for source_id in &entry.source_message_ids {
            push_unique_source_id(&mut all_source_ids, source_id);
        }
    }

    let bounded_entries = if entries.len() > config.max_source_messages {
        truncated_fields.push("source_messages".to_string());
        let mut bounded = entries
            .iter()
            .take(config.max_source_messages.saturating_sub(1))
            .cloned()
            .collect::<Vec<_>>();
        if let Some(last) = entries.last().cloned() {
            bounded.push(last);
        }
        bounded
    } else {
        entries.clone()
    };

    let mut first = entries.remove(0);
    let mut seen_texts = Vec::<String>::new();
    let mut text_parts = Vec::new();
    for entry in &bounded_entries {
        let Some(text) = entry
            .text
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
        else {
            continue;
        };
        let normalized = text.to_ascii_lowercase();
        if seen_texts.iter().any(|seen| seen == &normalized) {
            continue;
        }
        seen_texts.push(normalized);
        text_parts.push(text.to_string());
    }
    let mut combined_text = text_parts.join(" ");
    if combined_text.chars().count() > config.max_text_chars {
        truncated_fields.push("text".to_string());
        combined_text = combined_text
            .chars()
            .take(config.max_text_chars)
            .collect::<String>();
        combined_text.push_str("...[truncated]");
    }
    first.text = (!combined_text.is_empty()).then_some(combined_text);

    let mut attachments = bounded_entries
        .iter()
        .flat_map(|entry| entry.attachments.iter().cloned())
        .collect::<Vec<_>>();
    if attachments.len() > config.max_attachments {
        truncated_fields.push("attachments".to_string());
        attachments.truncate(config.max_attachments);
    }
    first.attachments = attachments;

    first.date_created_ms = bounded_entries
        .iter()
        .filter_map(|entry| entry.date_created_ms)
        .max()
        .or(first.date_created_ms);
    first.reply_to_message_guid = bounded_entries
        .iter()
        .find_map(|entry| entry.reply_to_message_guid.clone())
        .or(first.reply_to_message_guid);
    first.reply_context = bounded_entries
        .iter()
        .find_map(|entry| entry.reply_context.clone())
        .or(first.reply_context);
    first.associated_message_guid = bounded_entries
        .iter()
        .find_map(|entry| entry.associated_message_guid.clone())
        .or(first.associated_message_guid);
    first.balloon_bundle_id = None;
    first.coalesced_source_count = Some(all_source_ids.len());
    first.source_message_ids = all_source_ids
        .into_iter()
        .filter(|source_id| source_id != &first.event_id)
        .collect();
    truncated_fields.sort();
    truncated_fields.dedup();
    first.coalescing_truncated_fields = truncated_fields;
    first
}

fn push_unique_source_id(source_ids: &mut Vec<String>, raw_id: &str) {
    let value = raw_id.trim();
    if value.is_empty() || source_ids.iter().any(|existing| existing == value) {
        return;
    }
    source_ids.push(value.to_string());
}

fn collect_truncated_fields(events: &[NormalizedBlueBubblesWebhookMessage]) -> Vec<String> {
    let mut fields = events
        .iter()
        .flat_map(|event| event.coalescing_truncated_fields.iter().cloned())
        .collect::<Vec<_>>();
    fields.sort();
    fields.dedup();
    fields
}

// Doctor types
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        Self { passed, checks }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BlueBubblesReplyContextCacheKey {
    account_id: String,
    chat_key: String,
    reply_id: String,
}

impl BlueBubblesReplyContextCacheKey {
    fn new(account_id: &str, chat_key: &str, reply_id: &str) -> Self {
        Self {
            account_id: normalized_reply_account_id(account_id).to_string(),
            chat_key: chat_key.to_string(),
            reply_id: reply_id.to_string(),
        }
    }
}

#[derive(Debug, Default)]
struct BlueBubblesReplyContextCache {
    entries: Mutex<BTreeMap<BlueBubblesReplyContextCacheKey, BlueBubblesReplyContext>>,
    in_flight: Mutex<BTreeSet<BlueBubblesReplyContextCacheKey>>,
}

impl BlueBubblesReplyContextCache {
    fn get(
        &self,
        key: &BlueBubblesReplyContextCacheKey,
    ) -> FcpResult<Option<BlueBubblesReplyContext>> {
        let entries = self.entries.lock().map_err(|_| FcpError::Internal {
            message: "BlueBubbles reply context cache lock was poisoned".into(),
        })?;
        Ok(entries.get(key).cloned())
    }

    fn insert(
        &self,
        key: BlueBubblesReplyContextCacheKey,
        context: BlueBubblesReplyContext,
    ) -> FcpResult<()> {
        self.entries
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "BlueBubbles reply context cache lock was poisoned".into(),
            })?
            .insert(key, context);
        Ok(())
    }

    fn begin_fetch(&self, key: &BlueBubblesReplyContextCacheKey) -> FcpResult<bool> {
        let mut in_flight = self.in_flight.lock().map_err(|_| FcpError::Internal {
            message: "BlueBubbles reply context in-flight lock was poisoned".into(),
        })?;
        Ok(in_flight.insert(key.clone()))
    }

    fn finish_fetch(&self, key: &BlueBubblesReplyContextCacheKey) -> FcpResult<()> {
        self.in_flight
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "BlueBubbles reply context in-flight lock was poisoned".into(),
            })?
            .remove(key);
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct BlueBubblesReplyContextLookup {
    enabled: bool,
    status: &'static str,
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_id: Option<String>,
    cache_hit: bool,
    fetched: bool,
}

impl BlueBubblesReplyContextLookup {
    const fn disabled(reason: &'static str) -> Self {
        Self {
            enabled: false,
            status: "disabled",
            reason,
            reply_id: None,
            cache_hit: false,
            fetched: false,
        }
    }

    const fn skipped(reason: &'static str, reply_id: Option<String>) -> Self {
        Self {
            enabled: true,
            status: "skipped",
            reason,
            reply_id,
            cache_hit: false,
            fetched: false,
        }
    }

    const fn cache_hit(reply_id: String) -> Self {
        Self {
            enabled: true,
            status: "cache_hit",
            reason: "reply_context_cached",
            reply_id: Some(reply_id),
            cache_hit: true,
            fetched: false,
        }
    }

    const fn fetched(reply_id: String) -> Self {
        Self {
            enabled: true,
            status: "fetched",
            reason: "reply_context_fetched",
            reply_id: Some(reply_id),
            cache_hit: false,
            fetched: true,
        }
    }

    const fn degraded(reason: &'static str, reply_id: Option<String>) -> Self {
        Self {
            enabled: true,
            status: "degraded",
            reason,
            reply_id,
            cache_hit: false,
            fetched: false,
        }
    }
}

fn normalized_reply_account_id(account_id: &str) -> &str {
    let account_id = account_id.trim();
    if account_id.is_empty() {
        "default"
    } else {
        account_id
    }
}

fn canonical_reply_message_id(raw_id: &str, max_chars: usize) -> Result<String, &'static str> {
    let raw_id = raw_id.trim();
    if raw_id.is_empty() {
        return Err("reply_id_missing");
    }

    let id = if let Some(alias) = raw_id.strip_prefix("p:") {
        let Some((part_index, guid)) = alias.split_once('/') else {
            return Err("reply_id_part_alias_malformed");
        };
        if part_index.is_empty() || !part_index.chars().all(|ch| ch.is_ascii_digit()) {
            return Err("reply_id_part_alias_malformed");
        }
        guid.trim()
    } else {
        raw_id
    };

    if id.is_empty() {
        return Err("reply_id_missing");
    }
    if id.chars().count() > max_chars {
        return Err("reply_id_too_long");
    }
    let lower = id.to_ascii_lowercase();
    if id.contains('/')
        || id.contains('\\')
        || id.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || id
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_ascii_whitespace())
    {
        return Err("reply_id_path_unsafe");
    }
    if !id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '+'))
    {
        return Err("reply_id_unsupported_characters");
    }

    Ok(id.to_string())
}

fn reply_context_from_message(message: &Message) -> BlueBubblesReplyContext {
    BlueBubblesReplyContext {
        message_guid: message.guid.clone(),
        text_present: message
            .text
            .as_deref()
            .is_some_and(|text| !text.trim().is_empty()),
        is_from_me: message.is_from_me,
        attachment_count: message.attachments.len(),
        date_created_ms: message.date_created,
    }
}

fn reply_message_scope_matches(event_chat_keys: &[String], message_chat_keys: &[String]) -> bool {
    message_chat_keys.is_empty()
        || event_chat_keys.iter().any(|event_key| {
            message_chat_keys
                .iter()
                .any(|message_key| message_key == event_key)
        })
}

#[derive(Debug, Clone)]
struct BlueBubblesContactNameCacheEntry {
    name: Option<String>,
    expires_at_ms: i64,
}

#[derive(Debug, Clone)]
enum BlueBubblesContactCacheLookup {
    Hit(Option<String>),
    Miss,
}

#[derive(Debug, Default)]
struct BlueBubblesContactsEnrichmentCache {
    entries: Mutex<BTreeMap<String, BlueBubblesContactNameCacheEntry>>,
}

impl BlueBubblesContactsEnrichmentCache {
    fn get(&self, phone_key: &str, now_ms: i64) -> FcpResult<BlueBubblesContactCacheLookup> {
        let mut entries = self.entries.lock().map_err(|_| FcpError::Internal {
            message: "BlueBubbles Contacts enrichment cache lock was poisoned".into(),
        })?;
        let Some(entry) = entries.get(phone_key).cloned() else {
            return Ok(BlueBubblesContactCacheLookup::Miss);
        };
        if entry.expires_at_ms <= now_ms {
            entries.remove(phone_key);
            return Ok(BlueBubblesContactCacheLookup::Miss);
        }
        entries.remove(phone_key);
        entries.insert(phone_key.to_string(), entry.clone());
        drop(entries);
        Ok(BlueBubblesContactCacheLookup::Hit(entry.name))
    }

    fn insert(
        &self,
        phone_key: String,
        name: Option<String>,
        now_ms: i64,
        config: &BlueBubblesContactsEnrichmentConfig,
    ) -> FcpResult<()> {
        let ttl_seconds = if name.is_some() {
            config.positive_cache_ttl_seconds
        } else {
            config.negative_cache_ttl_seconds
        };
        let ttl_ms =
            i64::try_from(Duration::from_secs(ttl_seconds).as_millis()).unwrap_or(i64::MAX);
        let mut entries = self.entries.lock().map_err(|_| FcpError::Internal {
            message: "BlueBubbles Contacts enrichment cache lock was poisoned".into(),
        })?;
        entries.retain(|_, entry| entry.expires_at_ms > now_ms);
        entries.remove(&phone_key);
        entries.insert(
            phone_key,
            BlueBubblesContactNameCacheEntry {
                name,
                expires_at_ms: now_ms.saturating_add(ttl_ms),
            },
        );
        while entries.len() > config.max_cache_entries {
            let Some(oldest_key) = entries.keys().next().cloned() else {
                break;
            };
            entries.remove(&oldest_key);
        }
        drop(entries);
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct BlueBubblesContactsEnrichmentResult {
    enabled: bool,
    status: &'static str,
    reason: &'static str,
    participant_count: usize,
    lookup_count: usize,
    enriched_count: usize,
    cache_hit_count: usize,
    negative_cache_hit_count: usize,
    source_count: usize,
}

impl BlueBubblesContactsEnrichmentResult {
    const fn disabled(reason: &'static str, participant_count: usize) -> Self {
        Self {
            enabled: false,
            status: "disabled",
            reason,
            participant_count,
            lookup_count: 0,
            enriched_count: 0,
            cache_hit_count: 0,
            negative_cache_hit_count: 0,
            source_count: 0,
        }
    }

    const fn skipped(reason: &'static str, participant_count: usize) -> Self {
        Self {
            enabled: true,
            status: "skipped",
            reason,
            participant_count,
            lookup_count: 0,
            enriched_count: 0,
            cache_hit_count: 0,
            negative_cache_hit_count: 0,
            source_count: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    const fn lookup_status(
        status: &'static str,
        reason: &'static str,
        participant_count: usize,
        lookup_count: usize,
        enriched_count: usize,
        cache_hit_count: usize,
        negative_cache_hit_count: usize,
        source_count: usize,
    ) -> Self {
        Self {
            enabled: true,
            status,
            reason,
            participant_count,
            lookup_count,
            enriched_count,
            cache_hit_count,
            negative_cache_hit_count,
            source_count,
        }
    }
}

#[derive(Debug)]
struct BlueBubblesContactsLookup {
    status: &'static str,
    reason: &'static str,
    source_count: usize,
    names: BTreeMap<String, String>,
}

fn contact_lookup_name_for_test_source(
    config: &BlueBubblesContactsEnrichmentConfig,
    phone_keys: &BTreeSet<String>,
) -> Option<BlueBubblesContactsLookup> {
    if config.test_contacts.is_empty() {
        return None;
    }
    let names = phone_keys
        .iter()
        .filter_map(|phone_key| {
            config
                .test_contacts
                .get(phone_key)
                .cloned()
                .map(|name| (phone_key.clone(), name))
        })
        .collect();
    Some(BlueBubblesContactsLookup {
        status: "resolved",
        reason: "test_contacts_configured",
        source_count: 1,
        names,
    })
}

fn discover_contact_database_paths(
    config: &BlueBubblesContactsEnrichmentConfig,
) -> Result<Vec<PathBuf>, &'static str> {
    if !config.database_paths.is_empty() {
        return Ok(config.database_paths.iter().map(PathBuf::from).collect());
    }

    let Some(home_dir) = config
        .home_dir
        .as_deref()
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
    else {
        return Err("home_unavailable");
    };

    let sources_dir = home_dir
        .join("Library")
        .join("Application Support")
        .join("AddressBook")
        .join("Sources");
    let entries = fs::read_dir(sources_dir).map_err(|_| "address_book_sources_unreadable")?;
    Ok(entries
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("AddressBook-v22.abcddb"))
        .filter(|path| path.is_file())
        .collect())
}

fn query_contact_database(
    database_path: &Path,
    phone_keys: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>, rusqlite::Error> {
    if phone_keys.is_empty() {
        return Ok(BTreeMap::new());
    }
    let placeholders = vec!["?"; phone_keys.len()].join(", ");
    let sql = format!(
        "SELECT digits, name \
         FROM ( \
           SELECT \
             CASE \
               WHEN length(raw_digits) = 11 AND substr(raw_digits, 1, 1) = '1' THEN substr(raw_digits, 2) \
               ELSE raw_digits \
             END AS digits, \
             name \
           FROM ( \
             SELECT \
               REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(COALESCE(p.ZFULLNUMBER, ''), ' ', ''), '(', ''), ')', ''), '-', ''), '+', ''), '.', ''), char(10), ''), char(13), '') AS raw_digits, \
             TRIM(CASE \
               WHEN TRIM(COALESCE(r.ZFIRSTNAME, '') || ' ' || COALESCE(r.ZLASTNAME, '')) != '' \
                 THEN TRIM(COALESCE(r.ZFIRSTNAME, '') || ' ' || COALESCE(r.ZLASTNAME, '')) \
               ELSE COALESCE(r.ZORGANIZATION, '') \
             END) AS name \
           FROM ZABCDRECORD r \
           JOIN ZABCDPHONENUMBER p ON p.ZOWNER = r.Z_PK \
           WHERE p.ZFULLNUMBER IS NOT NULL \
           ) \
         ) \
         WHERE digits IN ({placeholders}) AND name != ''"
    );
    let connection = Connection::open_with_flags(database_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(phone_keys.iter()), |row| {
        let digits: String = row.get(0)?;
        let name: String = row.get(1)?;
        Ok((digits, name))
    })?;

    let mut names = BTreeMap::new();
    for row in rows {
        let (digits, name) = row?;
        let Some(phone_key) = normalize_bluebubbles_contact_phone_key(&digits) else {
            continue;
        };
        let name = name.trim();
        if !name.is_empty() {
            names.entry(phone_key).or_insert_with(|| name.to_string());
        }
    }
    Ok(names)
}

/// `BlueBubbles` `iMessage` connector state.
#[derive(Debug)]
struct BlueBubblesState {
    config: BlueBubblesConfig,
    client: BlueBubblesClient,
    runtime: ConnectorRuntime,
    webhook_dedupe: BlueBubblesInboundDedupeStore,
    webhook_coalescer: BlueBubblesWebhookCoalescer,
    webhook_events: Mutex<EventStreamManager>,
    reply_context_cache: BlueBubblesReplyContextCache,
    contacts_enrichment_cache: BlueBubblesContactsEnrichmentCache,
}

impl BlueBubblesState {
    fn from_config(config: BlueBubblesConfig) -> FcpResult<Self> {
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        );
        let client =
            BlueBubblesClient::from_config(&config).map_err(|error| FcpError::Internal {
                message: format!("Failed to create BlueBubbles client: {error}"),
            })?;
        let webhook_dedupe = BlueBubblesInboundDedupeStore::from_config(&config)?;
        let webhook_coalescer = BlueBubblesWebhookCoalescer::default();
        let webhook_events = Mutex::new(EventStreamManager::with_limits(
            webhook_event_caps(),
            BufferLimits::new(
                WEBHOOK_EVENT_BUFFER_MIN_EVENTS_USIZE,
                WEBHOOK_EVENT_BUFFER_MAX_EVENTS,
            ),
        ));
        let reply_context_cache = BlueBubblesReplyContextCache::default();
        let contacts_enrichment_cache = BlueBubblesContactsEnrichmentCache::default();

        Ok(Self {
            config,
            client,
            runtime,
            webhook_dedupe,
            webhook_coalescer,
            webhook_events,
            reply_context_cache,
            contacts_enrichment_cache,
        })
    }

    fn lock_webhook_events(&self) -> FcpResult<std::sync::MutexGuard<'_, EventStreamManager>> {
        self.webhook_events.lock().map_err(|_| FcpError::Internal {
            message: "BlueBubbles webhook event stream lock poisoned".into(),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn enrich_group_participants(
        &self,
        account_id: &str,
        event: &mut NormalizedBlueBubblesWebhookMessage,
    ) -> BlueBubblesContactsEnrichmentResult {
        let participant_count = event.participants.len();
        let chat_keys = event.conversation_keys();
        let normalized_account_id = normalized_reply_account_id(account_id);

        if !self
            .config
            .contacts_enrichment
            .enabled_for(normalized_account_id, &chat_keys)
        {
            return BlueBubblesContactsEnrichmentResult::disabled(
                "config_disabled_for_scope",
                participant_count,
            );
        }
        if !event.is_group {
            return BlueBubblesContactsEnrichmentResult::skipped(
                "not_group_conversation",
                participant_count,
            );
        }
        if event.participants.is_empty() {
            return BlueBubblesContactsEnrichmentResult::skipped(
                "no_participants",
                participant_count,
            );
        }

        let now_ms = Utc::now().timestamp_millis();
        let mut lookup_participants = BTreeMap::<String, Vec<usize>>::new();
        let mut enriched_count = 0;
        let mut cache_hit_count = 0;
        let mut negative_cache_hit_count = 0;

        for (index, participant) in event.participants.iter_mut().enumerate() {
            if participant.is_me
                || participant
                    .display_name
                    .as_deref()
                    .is_some_and(|name| !name.trim().is_empty())
                || participant.address.contains('@')
            {
                continue;
            }

            let Some(phone_key) = normalize_bluebubbles_contact_phone_key(&participant.address)
            else {
                continue;
            };

            match self.contacts_enrichment_cache.get(&phone_key, now_ms) {
                Ok(BlueBubblesContactCacheLookup::Hit(Some(name))) => {
                    participant.display_name = Some(name);
                    participant.contact_name_enriched = true;
                    cache_hit_count += 1;
                    enriched_count += 1;
                }
                Ok(BlueBubblesContactCacheLookup::Hit(None)) => {
                    negative_cache_hit_count += 1;
                }
                Ok(BlueBubblesContactCacheLookup::Miss) => {
                    lookup_participants
                        .entry(phone_key)
                        .or_default()
                        .push(index);
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "BlueBubbles Contacts enrichment cache read failed; preserving participants"
                    );
                    return BlueBubblesContactsEnrichmentResult::lookup_status(
                        "degraded",
                        "cache_read_failed",
                        participant_count,
                        lookup_participants.len(),
                        enriched_count,
                        cache_hit_count,
                        negative_cache_hit_count,
                        0,
                    );
                }
            }
        }

        if lookup_participants.is_empty() {
            let status = if enriched_count > 0 {
                "cache_hit"
            } else {
                "skipped"
            };
            let reason = if enriched_count > 0 {
                "all_names_cached"
            } else {
                "no_lookup_candidates"
            };
            return BlueBubblesContactsEnrichmentResult::lookup_status(
                status,
                reason,
                participant_count,
                0,
                enriched_count,
                cache_hit_count,
                negative_cache_hit_count,
                0,
            );
        }

        let phone_keys = lookup_participants.keys().cloned().collect::<BTreeSet<_>>();
        let lookup = self.lookup_contact_names(&phone_keys);
        let lookup_count = phone_keys.len();
        for phone_key in phone_keys {
            let name = lookup.names.get(&phone_key).cloned();
            if let Err(error) = self.contacts_enrichment_cache.insert(
                phone_key.clone(),
                name.clone(),
                now_ms,
                &self.config.contacts_enrichment,
            ) {
                tracing::warn!(
                    error = %error,
                    "BlueBubbles Contacts enrichment cache write failed"
                );
            }
            let Some(name) = name else {
                continue;
            };
            if let Some(indices) = lookup_participants.get(&phone_key) {
                for index in indices {
                    let Some(participant) = event.participants.get_mut(*index) else {
                        continue;
                    };
                    participant.display_name = Some(name.clone());
                    participant.contact_name_enriched = true;
                    enriched_count += 1;
                }
            }
        }

        let status = if enriched_count > 0 {
            "enriched"
        } else {
            lookup.status
        };
        let reason = if enriched_count > 0 {
            "contacts_resolved"
        } else {
            lookup.reason
        };

        BlueBubblesContactsEnrichmentResult::lookup_status(
            status,
            reason,
            participant_count,
            lookup_count,
            enriched_count,
            cache_hit_count,
            negative_cache_hit_count,
            lookup.source_count,
        )
    }

    fn lookup_contact_names(&self, phone_keys: &BTreeSet<String>) -> BlueBubblesContactsLookup {
        if let Some(lookup) =
            contact_lookup_name_for_test_source(&self.config.contacts_enrichment, phone_keys)
        {
            return lookup;
        }
        if !cfg!(target_os = "macos") && self.config.contacts_enrichment.database_paths.is_empty() {
            return BlueBubblesContactsLookup {
                status: "skipped",
                reason: "platform_unsupported",
                source_count: 0,
                names: BTreeMap::new(),
            };
        }

        let database_paths = match discover_contact_database_paths(&self.config.contacts_enrichment)
        {
            Ok(paths) if !paths.is_empty() => paths,
            Ok(_) => {
                return BlueBubblesContactsLookup {
                    status: "skipped",
                    reason: "no_contacts_database",
                    source_count: 0,
                    names: BTreeMap::new(),
                };
            }
            Err(reason) => {
                return BlueBubblesContactsLookup {
                    status: "skipped",
                    reason,
                    source_count: 0,
                    names: BTreeMap::new(),
                };
            }
        };

        let mut unresolved = phone_keys.clone();
        let mut names = BTreeMap::new();
        let mut query_failed = false;
        for database_path in &database_paths {
            if unresolved.is_empty() {
                break;
            }
            match query_contact_database(database_path, &unresolved) {
                Ok(resolved) => {
                    for (phone_key, name) in resolved {
                        if unresolved.remove(&phone_key) {
                            names.insert(phone_key, name);
                        }
                    }
                }
                Err(error) => {
                    query_failed = true;
                    tracing::warn!(
                        error = %error,
                        database = %database_path.display(),
                        "BlueBubbles Contacts enrichment database query failed"
                    );
                }
            }
        }

        let (status, reason) = if names.is_empty() && query_failed {
            ("degraded", "lookup_failed")
        } else {
            ("resolved", "contacts_query_completed")
        };

        BlueBubblesContactsLookup {
            status,
            reason,
            source_count: database_paths.len(),
            names,
        }
    }

    async fn resolve_reply_context(
        &self,
        account_id: &str,
        event: &mut NormalizedBlueBubblesWebhookMessage,
    ) -> BlueBubblesReplyContextLookup {
        let Some(raw_reply_id) = event.reply_to_message_guid.as_deref() else {
            return BlueBubblesReplyContextLookup::disabled("event_has_no_reply_id");
        };

        let chat_keys = event.conversation_keys();
        let normalized_account_id = normalized_reply_account_id(account_id);
        if !self
            .config
            .reply_context_api_fallback
            .enabled_for(normalized_account_id, &chat_keys)
        {
            return BlueBubblesReplyContextLookup::disabled("config_disabled_for_scope");
        }

        let reply_id = match canonical_reply_message_id(
            raw_reply_id,
            self.config.reply_context_api_fallback.max_reply_id_chars,
        ) {
            Ok(reply_id) => reply_id,
            Err(reason) => return BlueBubblesReplyContextLookup::degraded(reason, None),
        };

        let Some(chat_key) = chat_keys.first() else {
            return BlueBubblesReplyContextLookup::skipped("missing_chat_scope", Some(reply_id));
        };
        let key = BlueBubblesReplyContextCacheKey::new(normalized_account_id, chat_key, &reply_id);

        match self.reply_context_cache.get(&key) {
            Ok(Some(context)) => {
                event.reply_context = Some(context);
                return BlueBubblesReplyContextLookup::cache_hit(reply_id);
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "BlueBubbles reply context cache read failed; degrading to missing context"
                );
                return BlueBubblesReplyContextLookup::degraded(
                    "cache_read_failed",
                    Some(reply_id),
                );
            }
        }

        match self.reply_context_cache.begin_fetch(&key) {
            Ok(true) => {}
            Ok(false) => {
                return BlueBubblesReplyContextLookup::degraded(
                    "concurrent_fetch_in_progress",
                    Some(reply_id),
                );
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "BlueBubbles reply context in-flight mark failed; degrading to missing context"
                );
                return BlueBubblesReplyContextLookup::degraded(
                    "in_flight_lock_failed",
                    Some(reply_id),
                );
            }
        }

        let fetch_result = self
            .client
            .get_message_by_guid(
                &self.runtime,
                &reply_id,
                self.config.reply_context_api_fallback.max_response_bytes,
            )
            .await;
        let finish_result = self.reply_context_cache.finish_fetch(&key);
        if let Err(error) = finish_result {
            tracing::warn!(
                error = %error,
                "BlueBubbles reply context in-flight release failed"
            );
        }

        let message = match fetch_result {
            Ok(message) => message,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "BlueBubbles reply context fetch failed; preserving inbound event without context"
                );
                return BlueBubblesReplyContextLookup::degraded("fetch_failed", Some(reply_id));
            }
        };

        let message_chat_keys = message.conversation_keys();
        if !reply_message_scope_matches(&chat_keys, &message_chat_keys) {
            return BlueBubblesReplyContextLookup::degraded("chat_scope_mismatch", Some(reply_id));
        }

        let context = reply_context_from_message(&message);
        if let Err(error) = self.reply_context_cache.insert(key, context.clone()) {
            tracing::warn!(
                error = %error,
                "BlueBubbles reply context cache insert failed; preserving fetched context on event"
            );
        }
        event.reply_context = Some(context);
        BlueBubblesReplyContextLookup::fetched(reply_id)
    }
}

#[derive(Debug)]
pub struct BlueBubblesConnector {
    base: BaseConnector,
    state: Option<BlueBubblesState>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
    manifest_toml: &'static str,
}

impl BlueBubblesConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self::with_connector_metadata("fcp.imessage", MANIFEST_TOML)
    }

    /// Create a new connector instance with an explicit connector identifier.
    ///
    /// This allows thin wrapper crates to expose the same bridge-backed
    /// implementation under a different connector ID and manifest surface.
    #[must_use]
    pub fn with_connector_id(connector_id: &'static str) -> Self {
        Self::with_connector_metadata(connector_id, MANIFEST_TOML)
    }

    /// Create a connector with explicit connector metadata.
    #[must_use]
    pub fn with_connector_metadata(
        connector_id: &'static str,
        manifest_toml: &'static str,
    ) -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static(connector_id)),
            state: None,
            started_at: Instant::now(),
            verifier: None,
            manifest_toml,
        }
    }

    fn manifest_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.manifest_toml.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
        let capability = match operation {
            OP_SEND_MESSAGE | OP_SEND_MEDIA | OP_CREATE_CHAT | OP_EDIT_MESSAGE
            | OP_UNSEND_MESSAGE | OP_SEND_REACTION | OP_SET_TYPING | OP_MARK_READ => CAP_SEND,
            OP_GET_CHATS
            | OP_GET_CHAT
            | OP_GET_MESSAGES
            | OP_SYNC_EVENTS
            | OP_DOWNLOAD_ATTACHMENT
            | OP_RESOLVE_SEND_TARGET
            | OP_INGEST_WEBHOOK_EVENT
            | OP_INGEST_WEBHOOK_REQUEST => CAP_READ,
            OP_GET_SERVER_INFO
            | OP_GET_ACTION_AVAILABILITY
            | OP_REGISTER_WEBHOOK
            | OP_LIST_WEBHOOKS
            | OP_UNREGISTER_WEBHOOK => CAP_ADMIN,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        Ok(CapabilityId::from_static(capability))
    }

    /// Run connector diagnostics.
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();

        let configured = self.state.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        let client_ok = self.state.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: client_ok,
            message: Some(if client_ok {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        let runtime_ok = self.state.is_some();
        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: runtime_ok,
            message: Some(if runtime_ok {
                "ConnectorRuntime initialized".into()
            } else {
                "Runtime missing".into()
            }),
            critical: true,
        });

        if let Some(state) = &self.state {
            let config = &state.config;
            let scheme = if config.server_url.starts_with("https://") {
                "https"
            } else {
                "http"
            };
            checks.push(DoctorCheck {
                name: "server_url".into(),
                passed: true,
                message: Some(format!("Server URL ({scheme}): {}", config.server_url)),
                critical: false,
            });

            let host_part = config.server_host().unwrap_or_default();
            let host_ok = host_part == "localhost" || host_part == "127.0.0.1";
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: host_ok,
                message: Some(if host_ok {
                    "Server URL is local (localhost or 127.0.0.1)".into()
                } else {
                    format!("Server URL host '{host_part}' is not localhost; ensure trust boundary")
                }),
                critical: false,
            });

            let passcode_ok = !config.server_passcode.is_empty();
            checks.push(DoctorCheck {
                name: "password".into(),
                passed: passcode_ok,
                message: Some(if passcode_ok {
                    "Password is set".into()
                } else {
                    "Password is empty".into()
                }),
                critical: true,
            });

            push_webhook_inbound_doctor_checks(&mut checks, config);
            push_webhook_coalescing_doctor_checks(&mut checks, config);
            push_reply_context_api_fallback_doctor_checks(&mut checks, config);
            push_contacts_enrichment_doctor_checks(&mut checks, config);
        }

        DoctorResult::from_checks(checks)
    }
}

fn push_webhook_inbound_doctor_checks(checks: &mut Vec<DoctorCheck>, config: &BlueBubblesConfig) {
    let inbound = config.webhook_inbound.summary();
    checks.push(DoctorCheck {
        name: "webhook_inbound_policy".into(),
        passed: inbound.allow_from_me
            || inbound.allowed_sender_count > 0
            || inbound.allowed_chat_count > 0,
        message: Some(format!(
            "Inbound policy: allow_from_me={}, allowed_senders={}, allowed_chats={}, groups={}, require_binding={}",
            inbound.allow_from_me,
            inbound.allowed_sender_count,
            inbound.allowed_chat_count,
            inbound.allow_group_chats,
            inbound.require_conversation_binding
        )),
        critical: false,
    });

    checks.push(DoctorCheck {
        name: "webhook_replay_dedupe".into(),
        passed: true,
        message: Some(format!(
            "Replay dedupe TTL={}s, persistence={}",
            inbound.dedupe_ttl_seconds,
            if inbound.persistent_dedupe {
                "file-backed"
            } else {
                "memory-only"
            }
        )),
        critical: false,
    });
}

fn push_webhook_coalescing_doctor_checks(
    checks: &mut Vec<DoctorCheck>,
    config: &BlueBubblesConfig,
) {
    let coalescing = config.webhook_coalescing.summary();
    checks.push(DoctorCheck {
        name: "webhook_dm_coalescing".into(),
        passed: true,
        message: Some(format!(
            "DM coalescing: enabled={}, debounce={}ms, max={}ms, text_cap={}, attachment_cap={}, source_cap={}, pending_cap={}, immediate_prefixes={}",
            coalescing.enabled,
            coalescing.debounce_ms,
            coalescing.max_debounce_ms,
            coalescing.max_text_chars,
            coalescing.max_attachments,
            coalescing.max_source_messages,
            coalescing.max_pending_buffers,
            coalescing.immediate_command_prefix_count
        )),
        critical: false,
    });
}

fn push_reply_context_api_fallback_doctor_checks(
    checks: &mut Vec<DoctorCheck>,
    config: &BlueBubblesConfig,
) {
    let fallback = config.reply_context_api_fallback.summary();
    checks.push(DoctorCheck {
        name: "reply_context_api_fallback".into(),
        passed: true,
        message: Some(format!(
            "Reply-context API fallback: enabled={}, account_overrides={}, chat_overrides={}, id_cap={}, response_cap={} bytes",
            fallback.enabled,
            fallback.account_override_count,
            fallback.chat_override_count,
            fallback.max_reply_id_chars,
            fallback.max_response_bytes
        )),
        critical: false,
    });
}

fn push_contacts_enrichment_doctor_checks(
    checks: &mut Vec<DoctorCheck>,
    config: &BlueBubblesConfig,
) {
    let enrichment = config.contacts_enrichment.summary();
    checks.push(DoctorCheck {
        name: "contacts_participant_enrichment".into(),
        passed: true,
        message: Some(format!(
            "Contacts enrichment: enabled={}, default_enabled={}, account_overrides={}, chat_overrides={}, explicit_databases={}, home_dir_configured={}, test_contacts={}, positive_ttl={}s, negative_ttl={}s, cache_cap={}",
            enrichment.enabled,
            enrichment.default_enabled,
            enrichment.account_override_count,
            enrichment.chat_override_count,
            enrichment.explicit_database_count,
            enrichment.home_dir_configured,
            enrichment.test_contact_count,
            enrichment.positive_cache_ttl_seconds,
            enrichment.negative_cache_ttl_seconds,
            enrichment.max_cache_entries
        )),
        critical: false,
    });
}

impl Default for BlueBubblesConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn optional_string_field(input: &Value, names: &[&str], label: &str) -> FcpResult<Option<String>> {
    for name in names {
        let Some(value) = input.get(*name) else {
            continue;
        };
        let Some(text) = value.as_str() else {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("{label} must be a string"),
            });
        };
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("{label} must not be empty"),
            });
        }
        return Ok(Some(trimmed.to_string()));
    }
    Ok(None)
}

fn optional_u64_field(input: &Value, names: &[&str], label: &str) -> FcpResult<Option<u64>> {
    for name in names {
        let Some(value) = input.get(*name) else {
            continue;
        };
        let Some(number) = value.as_u64() else {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("{label} must be a non-negative integer"),
            });
        };
        return Ok(Some(number));
    }
    Ok(None)
}

fn optional_bool_field(input: &Value, names: &[&str], label: &str) -> FcpResult<Option<bool>> {
    for name in names {
        let Some(value) = input.get(*name) else {
            continue;
        };
        let Some(flag) = value.as_bool() else {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("{label} must be a boolean"),
            });
        };
        return Ok(Some(flag));
    }
    Ok(None)
}

fn parse_send_message_options(input: &Value) -> FcpResult<SendMessageOptions> {
    let reply_to_message_guid = optional_string_field(
        input,
        &[
            "reply_to_message_guid",
            "replyToMessageGuid",
            "selectedMessageGuid",
        ],
        "reply_to_message_guid",
    )?;
    let reply_to_part_index = optional_u64_field(
        input,
        &["reply_to_part_index", "replyToPartIndex", "partIndex"],
        "reply_to_part_index",
    )?;
    let effect_id = optional_string_field(input, &["effect_id", "effectId"], "effect_id")?
        .map(|effect| normalize_bluebubbles_message_effect(&effect).unwrap_or(effect));

    if reply_to_message_guid.is_none() && reply_to_part_index.is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "reply_to_part_index requires reply_to_message_guid".into(),
        });
    }

    Ok(SendMessageOptions {
        reply_to_message_guid,
        reply_to_part_index,
        effect_id,
    })
}

fn parse_send_media_options(input: &Value) -> FcpResult<SendMediaOptions> {
    let reply_to_message_guid = optional_string_field(
        input,
        &[
            "reply_to_message_guid",
            "replyToMessageGuid",
            "selectedMessageGuid",
        ],
        "reply_to_message_guid",
    )?;
    let reply_to_part_index = optional_u64_field(
        input,
        &["reply_to_part_index", "replyToPartIndex", "partIndex"],
        "reply_to_part_index",
    )?;
    if reply_to_message_guid.is_none() && reply_to_part_index.is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "reply_to_part_index requires reply_to_message_guid".into(),
        });
    }

    Ok(SendMediaOptions {
        reply_to_message_guid,
        reply_to_part_index,
        caption: optional_string_field(input, &["caption"], "caption")?,
        filename: optional_string_field(input, &["filename", "name"], "filename")?,
        content_type: optional_string_field(
            input,
            &["content_type", "contentType", "mime_type", "mimeType"],
            "content_type",
        )?,
        as_voice: optional_bool_field(
            input,
            &["as_voice", "asVoice", "is_audio_message", "isAudioMessage"],
            "as_voice",
        )?
        .unwrap_or(false),
    })
}

fn parse_target_service(input: &Value) -> FcpResult<BlueBubblesTargetService> {
    let Some(raw) = optional_string_field(input, &["service"], "service")? else {
        return Ok(BlueBubblesTargetService::Auto);
    };
    match raw.to_ascii_lowercase().as_str() {
        "imessage" => Ok(BlueBubblesTargetService::Imessage),
        "sms" => Ok(BlueBubblesTargetService::Sms),
        "auto" => Ok(BlueBubblesTargetService::Auto),
        _ => Err(FcpError::InvalidRequest {
            code: 1005,
            message: "service must be one of: imessage, sms, auto".into(),
        }),
    }
}

fn parse_send_target(input: &Value) -> FcpResult<BlueBubblesSendTarget> {
    let present = ["chat_guid", "chat_id", "chat_identifier", "handle"]
        .into_iter()
        .filter(|name| input.get(*name).is_some())
        .count();
    if present != 1 {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message:
                "Exactly one target field is required: chat_guid, chat_id, chat_identifier, handle"
                    .into(),
        });
    }

    if let Some(chat_guid) = optional_string_field(input, &["chat_guid"], "chat_guid")? {
        return Ok(BlueBubblesSendTarget::ChatGuid(chat_guid));
    }
    if let Some(chat_id) = optional_u64_field(input, &["chat_id"], "chat_id")? {
        let chat_id = i64::try_from(chat_id).map_err(|_| FcpError::InvalidRequest {
            code: 1005,
            message: "chat_id must fit in a signed 64-bit integer".into(),
        })?;
        return Ok(BlueBubblesSendTarget::ChatId(chat_id));
    }
    if let Some(chat_identifier) =
        optional_string_field(input, &["chat_identifier"], "chat_identifier")?
    {
        return Ok(BlueBubblesSendTarget::ChatIdentifier(chat_identifier));
    }
    let handle = optional_string_field(input, &["handle"], "handle")?.ok_or_else(|| {
        FcpError::InvalidRequest {
            code: 1005,
            message:
                "Exactly one target field is required: chat_guid, chat_id, chat_identifier, handle"
                    .into(),
        }
    })?;
    Ok(BlueBubblesSendTarget::Handle {
        address: handle,
        service: parse_target_service(input)?,
    })
}

/// Build the typed operations catalog.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_SEND_MESSAGE),
            summary: "Send an iMessage".into(),
            description: Some(
                "Sends a text message to a chat via BlueBubbles, choosing an explicit AppleScript or Private API send method from server capabilities. Optional reply/effect fields require known enabled Private API support and fail closed when unavailable.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["chat_guid", "message"],
                "properties": {
                    "chat_guid": {
                        "type": "string",
                        "description": "Target chat GUID (e.g. iMessage;-;+15551234567)"
                    },
                    "message": {
                        "type": "string",
                        "description": "Message text to send"
                    },
                    "reply_to_message_guid": {
                        "type": "string",
                        "description": "Optional message GUID for Private API reply threading"
                    },
                    "reply_to_part_index": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Optional message part index for reply threading; defaults to 0"
                    },
                    "effect_id": {
                        "type": "string",
                        "description": "Optional full Apple effect ID or alias such as slam, confetti, invisible ink, fireworks"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "integer" },
                    "message": { "type": "string" },
                    "data": { "type": "object" },
                    "send_method": { "type": "string", "enum": ["apple-script", "private-api"] },
                    "send_method_decision": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SEND),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to send an iMessage to a contact or group chat".into(),
                common_mistakes: vec![
                    "Chat GUID format is 'iMessage;-;+15551234567' for DMs or 'iMessage;+;chatXXX' for groups".into(),
                    "The BlueBubbles server must be running on a Mac with iMessage signed in".into(),
                    "Plain text sends refresh server info and prefer Private API on macOS 26+ when the bridge reports Private API support".into(),
                    "Reply threading and message effects are not silently downgraded; they require Private API to be known enabled before send".into(),
                ],
                examples: Vec::new(),
                related: vec![
                    CapabilityId::from_static(OP_GET_CHATS),
                    CapabilityId::from_static(OP_RESOLVE_SEND_TARGET),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SEND_MEDIA),
            summary: "Send a local media attachment through BlueBubbles".into(),
            description: Some(
                "Uploads a configured-local-root media file through BlueBubbles multipart attachment send. The connector canonicalizes the local path under media_send.local_roots, enforces file size and MIME bounds before reading, sanitizes multipart filename metadata, and only includes reply threading fields when Private API is known enabled.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["local_path"],
                "oneOf": [
                    { "required": ["chat_guid"] },
                    { "required": ["chat_id"] },
                    { "required": ["chat_identifier"] },
                    { "required": ["handle"] }
                ],
                "properties": {
                    "chat_guid": {
                        "type": "string",
                        "description": "Target chat GUID (e.g. iMessage;-;+15551234567)"
                    },
                    "chat_id": { "type": "integer", "minimum": 0 },
                    "chat_identifier": { "type": "string" },
                    "handle": { "type": "string", "description": "Phone number or email handle to resolve before upload" },
                    "service": {
                        "type": "string",
                        "enum": ["imessage", "sms", "auto"],
                        "description": "Handle service preference; sms preserves explicit SMS intent"
                    },
                    "scan_limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 5000,
                        "description": "Maximum chat records to inspect when resolving non-chat_guid targets"
                    },
                    "local_path": {
                        "type": "string",
                        "description": "Absolute local filesystem path or file:// URL under a configured media_send.local_roots entry"
                    },
                    "filename": {
                        "type": "string",
                        "description": "Optional multipart filename override; sanitized before upload"
                    },
                    "content_type": {
                        "type": "string",
                        "description": "Optional MIME type override; validated against media_send bounds"
                    },
                    "caption": {
                        "type": "string",
                        "description": "Optional caption included in multipart text fields"
                    },
                    "reply_to_message_guid": {
                        "type": "string",
                        "description": "Optional message GUID for Private API reply threading"
                    },
                    "reply_to_part_index": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Optional message part index for reply threading; defaults to 0"
                    },
                    "as_voice": {
                        "type": "boolean",
                        "description": "Send as a BlueBubbles audio message; only mp3/caf media are accepted"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" },
                    "action": { "type": "string" },
                    "chat_guid": { "type": "string" },
                    "message_id": { "type": ["string", "null"] },
                    "filename": { "type": "string" },
                    "content_type": { "type": "string" },
                    "byte_len": { "type": "integer" },
                    "media_send_decision": { "type": "object" },
                    "target_resolution": { "type": "object" },
                    "response": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SEND),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to send a local image, video, audio file, or allowed document through BlueBubbles without granting arbitrary filesystem access".into(),
                common_mistakes: vec![
                    "Configure media_send.local_roots before invoking; uploads outside those roots are rejected".into(),
                    "Do not pass remote URLs; this operation intentionally accepts local files only".into(),
                    "Reply threading fails closed unless BlueBubbles server info proves Private API is enabled".into(),
                ],
                examples: Vec::new(),
                related: vec![
                    CapabilityId::from_static(OP_RESOLVE_SEND_TARGET),
                    CapabilityId::from_static(OP_GET_ACTION_AVAILABILITY),
                    CapabilityId::from_static(OP_DOWNLOAD_ATTACHMENT),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_RESOLVE_SEND_TARGET),
            summary: "Resolve an iMessage send target".into(),
            description: Some(
                "Resolves an explicit chat_guid, chat_id, chat_identifier, or handle target into a chat GUID without sending. Handle lookup preserves iMessage/SMS caller intent and never routes a handle to a group chat only because the handle is a participant.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "oneOf": [
                    { "required": ["chat_guid"] },
                    { "required": ["chat_id"] },
                    { "required": ["chat_identifier"] },
                    { "required": ["handle"] }
                ],
                "properties": {
                    "chat_guid": { "type": "string" },
                    "chat_id": { "type": "integer", "minimum": 0 },
                    "chat_identifier": { "type": "string" },
                    "handle": { "type": "string", "description": "Phone number or email handle to resolve" },
                    "service": {
                        "type": "string",
                        "enum": ["imessage", "sms", "auto"],
                        "description": "Handle service preference; sms preserves explicit SMS intent"
                    },
                    "scan_limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 5000,
                        "description": "Maximum chat records to inspect; default 5000"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "chat_guid": { "type": ["string", "null"] },
                    "target_kind": { "type": "string" },
                    "match_kind": { "type": "string" },
                    "service_preference": { "type": "string" },
                    "scanned_chats": { "type": "integer" },
                    "scanned_pages": { "type": "integer" },
                    "exhausted": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you have a handle, chat_id, or chat_identifier and need a chat_guid before sending".into(),
                common_mistakes: vec![
                    "Do not treat a group participant match as a DM target".into(),
                    "Set service to sms only when the caller explicitly requested SMS".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SEND_MESSAGE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CREATE_CHAT),
            summary: "Create an iMessage DM chat".into(),
            description: Some(
                "Creates a new direct-message chat by sending the initial message through BlueBubbles /api/v1/chat/new. This operation requires known enabled Private API support and fails closed otherwise.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["address", "message"],
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Phone number or email address for the new DM"
                    },
                    "message": {
                        "type": "string",
                        "description": "Initial message body"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "chat_guid": { "type": ["string", "null"] },
                    "message_id": { "type": ["string", "null"] },
                    "send_method": { "type": "string", "enum": ["private-api"] },
                    "send_method_decision": { "type": "object" },
                    "response": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SEND),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When no existing DM chat can be resolved and the caller explicitly wants to start a new iMessage conversation".into(),
                common_mistakes: vec![
                    "This is not a target resolver; it sends the initial message while creating the chat".into(),
                    "Private API must be enabled and known before this operation can run".into(),
                ],
                examples: Vec::new(),
                related: vec![
                    CapabilityId::from_static(OP_RESOLVE_SEND_TARGET),
                    CapabilityId::from_static(OP_SEND_MESSAGE),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_ACTION_AVAILABILITY),
            summary: "Inspect BlueBubbles action availability".into(),
            description: Some(
                "Returns a server-info-derived snapshot for Private API action gates: edit, unsend, tapback reactions, typing indicators, and read receipts. Authentication and rate-limit failures are preserved as errors; other server-info failures produce unavailable action reasons.".into(),
            ),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "server_info_available": { "type": "boolean" },
                    "server_info_error": { "type": ["string", "null"] },
                    "private_api": { "type": ["boolean", "null"] },
                    "helper_connected": { "type": ["boolean", "null"] },
                    "os_version": { "type": ["string", "null"] },
                    "server_version": { "type": ["string", "null"] },
                    "edit": { "type": "object" },
                    "unsend": { "type": "object" },
                    "reaction": { "type": "object" },
                    "typing": { "type": "object" },
                    "mark_read": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_ADMIN),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need deterministic availability reasons before invoking BlueBubbles Private API actions".into(),
                common_mistakes: vec![
                    "Treating static OperationInfo as proof an action is enabled on the local Mac".into(),
                    "Ignoring macOS 26 edit denial; BlueBubbles edit is intentionally unavailable there".into(),
                ],
                examples: vec![r"{}".into()],
                related: vec![
                    CapabilityId::from_static(OP_EDIT_MESSAGE),
                    CapabilityId::from_static(OP_UNSEND_MESSAGE),
                    CapabilityId::from_static(OP_SEND_REACTION),
                    CapabilityId::from_static(OP_SET_TYPING),
                    CapabilityId::from_static(OP_MARK_READ),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_EDIT_MESSAGE),
            summary: "Edit a sent iMessage".into(),
            description: Some(
                "Edits a sent message through BlueBubbles /api/v1/message/{guid}/edit. Requires known enabled Private API, connected helper when reported, and a supported macOS version; macOS 26+ fails closed.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["message_guid", "new_text"],
                "properties": {
                    "message_guid": { "type": "string" },
                    "new_text": { "type": "string" },
                    "part_index": { "type": "integer", "minimum": 0, "default": 0 },
                    "backwards_compatibility_message": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" },
                    "action": { "type": "string" },
                    "response": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SEND),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When the caller explicitly wants to edit a previously sent iMessage by GUID".into(),
                common_mistakes: vec![
                    "Calling edit before checking get_action_availability on macOS 26+ hosts".into(),
                    "Passing a short reply alias instead of the full message GUID".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_ACTION_AVAILABILITY)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_UNSEND_MESSAGE),
            summary: "Unsend a sent iMessage".into(),
            description: Some(
                "Retracts a sent message through BlueBubbles /api/v1/message/{guid}/unsend. Requires known enabled Private API and fails closed when the action cannot be proven available.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["message_guid"],
                "properties": {
                    "message_guid": { "type": "string" },
                    "part_index": { "type": "integer", "minimum": 0, "default": 0 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" },
                    "action": { "type": "string" },
                    "response": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SEND),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When the caller explicitly wants to retract a previously sent iMessage by GUID".into(),
                common_mistakes: vec![
                    "Treating unsend as best effort; FCP fails closed when support is unknown or disabled".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_ACTION_AVAILABILITY)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SEND_REACTION),
            summary: "Send or remove an iMessage tapback".into(),
            description: Some(
                "Adds or removes a BlueBubbles tapback reaction through /api/v1/message/react. Reaction input is normalized to iMessage tapbacks only: love, like, dislike, laugh, emphasize, or question.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["chat_guid", "message_guid", "reaction"],
                "properties": {
                    "chat_guid": { "type": "string" },
                    "message_guid": { "type": "string" },
                    "reaction": { "type": "string" },
                    "remove": { "type": "boolean", "default": false },
                    "part_index": { "type": "integer", "minimum": 0, "default": 0 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" },
                    "reaction": { "type": "string" },
                    "response": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SEND),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When the caller wants to add or remove an iMessage tapback on a specific message".into(),
                common_mistakes: vec![
                    "Passing arbitrary emoji; iMessage tapbacks are limited to six reaction types".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_ACTION_AVAILABILITY)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SET_TYPING),
            summary: "Start or stop an iMessage typing indicator".into(),
            description: Some(
                "Starts or stops a BlueBubbles typing indicator using POST or DELETE /api/v1/chat/{guid}/typing. Requires known enabled Private API and fails closed otherwise.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["chat_guid"],
                "properties": {
                    "chat_guid": { "type": "string" },
                    "typing": { "type": "boolean", "default": true }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" },
                    "typing": { "type": "boolean" },
                    "response": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SEND),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When the caller wants to explicitly show or clear a typing indicator for a chat".into(),
                common_mistakes: vec![
                    "Assuming missing Private API support can be ignored; FCP returns a stable unsupported error".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_ACTION_AVAILABILITY)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_CHATS),
            summary: "List iMessage chats".into(),
            description: Some(
                "Gets a paginated list of iMessage chats from the BlueBubbles server".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "offset": { "type": "integer", "description": "Pagination offset" },
                    "limit": { "type": "integer", "description": "Max results to return" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "total": { "type": "integer" },
                    "offset": { "type": "integer" },
                    "limit": { "type": "integer" },
                    "data": {
                        "type": "array",
                        "items": { "type": "object" }
                    }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to browse or search iMessage conversations".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_MESSAGES)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_CHAT),
            summary: "Get a single iMessage chat".into(),
            description: Some(
                "Gets detailed metadata for one iMessage chat by chat GUID".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["chat_guid"],
                "properties": {
                    "chat_guid": {
                        "type": "string",
                        "description": "Chat GUID to fetch"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "guid": { "type": "string" },
                    "display_name": { "type": "string" },
                    "participants": {
                        "type": "array",
                        "items": { "type": "object" }
                    },
                    "is_group": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need detailed metadata for a specific iMessage chat".into(),
                common_mistakes: vec![
                    "Use get_chats first if you do not already know the chat GUID".into(),
                ],
                examples: Vec::new(),
                related: vec![
                    CapabilityId::from_static(OP_GET_CHATS),
                    CapabilityId::from_static(OP_GET_MESSAGES),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_MESSAGES),
            summary: "Get messages from a chat".into(),
            description: Some(
                "Gets a paginated list of messages from a specific iMessage chat".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["chat_guid"],
                "properties": {
                    "chat_guid": {
                        "type": "string",
                        "description": "Chat GUID to fetch messages from"
                    },
                    "offset": { "type": "integer", "description": "Pagination offset" },
                    "limit": { "type": "integer", "description": "Max results" },
                    "after": { "type": "integer", "description": "Only messages after this timestamp (epoch ms)" },
                    "before": { "type": "integer", "description": "Only messages before this timestamp (epoch ms)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "total": { "type": "integer" },
                    "offset": { "type": "integer" },
                    "limit": { "type": "integer" },
                    "data": {
                        "type": "array",
                        "items": { "type": "object" }
                    }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to read message history from an iMessage chat".into(),
                common_mistakes: vec![
                    "You must specify a valid chat_guid; use get_chats first to discover available chats".into(),
                ],
                examples: Vec::new(),
                related: vec![
                    CapabilityId::from_static(OP_GET_CHATS),
                    CapabilityId::from_static(OP_SEND_MESSAGE),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SYNC_EVENTS),
            summary: "Sync iMessage events".into(),
            description: Some(
                "Polls BlueBubbles for recent messages and returns them as normalized iMessage event records".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "chat_guid": {
                        "type": "string",
                        "description": "Optional chat GUID to scope the sync to one conversation"
                    },
                    "after": {
                        "type": "integer",
                        "description": "Only include messages created after this epoch-ms timestamp"
                    },
                    "before": {
                        "type": "integer",
                        "description": "Only include messages created before this epoch-ms timestamp"
                    },
                    "chat_limit": {
                        "type": "integer",
                        "description": "Maximum chats to scan when chat_guid is omitted"
                    },
                    "message_limit": {
                        "type": "integer",
                        "description": "Maximum messages to fetch per scanned chat"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "events": {
                        "type": "array",
                        "items": { "type": "object" }
                    },
                    "next_after": { "type": "integer" },
                    "synced_chats": { "type": "integer" },
                    "chat_guid": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need a polling-friendly view of new iMessage activity without relying on long-lived streaming".into(),
                common_mistakes: vec![
                    "Use the returned next_after value on the next call to avoid re-reading the same messages".into(),
                    "Set chat_guid when you already know the conversation you want to monitor".into(),
                ],
                examples: vec![
                    r#"{"chat_guid": "chat-guid-1", "after": 1700000000000}"#.into(),
                    r#"{"after": 1700000000000, "chat_limit": 10, "message_limit": 25}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static(OP_GET_CHAT),
                    CapabilityId::from_static(OP_GET_MESSAGES),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_DOWNLOAD_ATTACHMENT),
            summary: "Download an iMessage attachment".into(),
            description: Some(
                "Downloads the binary payload for an attachment referenced by a BlueBubbles message"
                    .into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["attachment_guid"],
                "properties": {
                    "attachment_guid": {
                        "type": "string",
                        "description": "Attachment GUID from a message attachment entry"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "attachment_guid": { "type": "string" },
                    "encoding": { "type": "string" },
                    "data_base64": { "type": "string" },
                    "byte_len": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need the raw contents of an attachment referenced by an iMessage".into(),
                common_mistakes: vec![
                    "Pass the attachment GUID from a message attachment, not the chat GUID".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_MESSAGES)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MARK_READ),
            summary: "Mark a chat as read".into(),
            description: Some(
                "Marks all messages in an iMessage chat as read".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["chat_guid"],
                "properties": {
                    "chat_guid": {
                        "type": "string",
                        "description": "Chat GUID to mark as read"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SEND),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When you want to mark an iMessage conversation as read".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_GET_MESSAGES)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_REGISTER_WEBHOOK),
            summary: "Register a BlueBubbles webhook".into(),
            description: Some(
                "Registers a BlueBubbles callback URL for message webhook events, reusing an existing matching registration by default".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Absolute callback URL. Defaults to the connector webhook_host/webhook_port/webhook_path with password query auth."
                    },
                    "events": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "BlueBubbles event names to register",
                        "default": default_webhook_events()
                    },
                    "skip_if_existing": {
                        "type": "boolean",
                        "description": "When true, list existing webhooks and avoid duplicate registration for the same URL",
                        "default": true
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "registration_status": { "type": "string", "enum": ["existing", "registered"] },
                    "webhook": { "type": "object" },
                    "response": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_ADMIN),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When the host has a supervised BlueBubbles webhook receiver URL and needs the Mac bridge to start delivering message events".into(),
                common_mistakes: vec![
                    "Registering duplicate callback URLs after a restart instead of using skip_if_existing".into(),
                    "Assuming this starts the local HTTP listener; it only registers the remote BlueBubbles callback".into(),
                ],
                examples: vec![
                    r#"{"url": "http://localhost:8645/bluebubbles-webhook"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static(OP_LIST_WEBHOOKS),
                    CapabilityId::from_static(OP_UNREGISTER_WEBHOOK),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_LIST_WEBHOOKS),
            summary: "List BlueBubbles webhooks".into(),
            description: Some("Lists webhook registrations currently configured on the BlueBubbles server".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "webhooks": { "type": "array", "items": { "type": "object" } }
                }
            }),
            capability: CapabilityId::from_static(CAP_ADMIN),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to inspect current BlueBubbles webhook callback registrations before registering or cleaning up".into(),
                common_mistakes: vec![
                    "Assuming the webhook URL is secret-free; BlueBubbles callback auth may be embedded in the URL".into(),
                ],
                examples: vec![r"{}".into()],
                related: vec![CapabilityId::from_static(OP_REGISTER_WEBHOOK)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_UNREGISTER_WEBHOOK),
            summary: "Unregister BlueBubbles webhooks".into(),
            description: Some(
                "Deletes one BlueBubbles webhook by ID or all registrations matching a callback URL".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "webhook_id": {
                        "type": "string",
                        "description": "Specific BlueBubbles webhook ID to delete"
                    },
                    "url": {
                        "type": "string",
                        "description": "Callback URL; all matching registered webhooks with IDs are deleted"
                    }
                },
                "anyOf": [
                    { "required": ["webhook_id"] },
                    { "required": ["url"] }
                ]
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "deleted_count": { "type": "integer" },
                    "deleted": { "type": "array", "items": { "type": "object" } }
                }
            }),
            capability: CapabilityId::from_static(CAP_ADMIN),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When a BlueBubbles callback is no longer valid or duplicate callback registrations need cleanup".into(),
                common_mistakes: vec![
                    "Deleting a webhook before the replacement receiver has been registered and verified".into(),
                ],
                examples: vec![
                    r#"{"webhook_id": "42"}"#.into(),
                    r#"{"url": "http://localhost:8645/bluebubbles-webhook"}"#.into(),
                ],
                related: vec![CapabilityId::from_static(OP_LIST_WEBHOOKS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_INGEST_WEBHOOK_EVENT),
            summary: "Accept and normalize a BlueBubbles webhook event".into(),
            description: Some(
                "Normalizes a host-delivered BlueBubbles webhook payload, applies connector-local sender/conversation policy, optionally enriches accepted group participants from Contacts, optionally resolves scoped reply context, and atomically claims all account-scoped source replay-dedupe keys".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "payload": {
                        "type": "object",
                        "description": "Raw BlueBubbles webhook JSON body"
                    },
                    "event_type": {
                        "type": "string",
                        "description": "Optional event type override when the transport carries it outside the JSON body"
                    },
                    "account_id": {
                        "type": "string",
                        "description": "Optional account namespace for dedupe; defaults to connector webhook_account_id"
                    },
                    "observed_at_ms": {
                        "type": "integer",
                        "description": "Optional host-observed epoch-ms timestamp used for deterministic coalescing tests"
                    },
                    "flush_coalescing": {
                        "type": "boolean",
                        "description": "When true and payload is omitted, drains pending coalesced DM events"
                    }
                },
                "anyOf": [
                    { "required": ["payload"] },
                    { "required": ["flush_coalescing"] }
                ]
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string", "enum": ["accepted", "duplicate", "rejected", "buffered", "flushed"] },
                    "dedupe_id": { "type": "string" },
                    "dedupe_ids": { "type": "array", "items": { "type": "string" } },
                    "duplicate_id": { "type": "string" },
                    "acceptance": { "type": "object" },
                    "policy": { "type": "object" },
                    "coalescing": { "type": "object" },
                    "reply_context_lookup": { "type": "object" },
                    "contacts_enrichment": { "type": "object" },
                    "event": { "type": "object" },
                    "events": { "type": "array", "items": { "type": "object" } },
                    "event_envelopes": { "type": "array", "items": { "type": "object" } }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When a trusted FCP webhook receiver has authenticated a BlueBubbles POST and needs connector-local sender/conversation acceptance, optional privacy-gated Contacts enrichment for group participants, optional reply-context fallback, optional DM split-send coalescing, and duplicate replay suppression".into(),
                common_mistakes: vec![
                    "Leaving webhook_inbound sender/chat policy empty and expecting external senders to be accepted".into(),
                    "Assuming memory-only dedupe survives connector restart; configure webhook_inbound.dedupe_state_path when restart replay suppression is required".into(),
                    "Expecting Contacts participant enrichment to be enabled by default; FCP keeps it opt-in because it reads local Contacts metadata".into(),
                    "Expecting reply-context API fallback to be enabled by default; it is opt-in and scoped by account/chat overrides".into(),
                    "Enabling webhook_coalescing without arranging a host-side flush after debounce_ms; buffered events are emitted on later ingest or explicit flush".into(),
                ],
                examples: vec![
                    r#"{"payload": {"type": "new-message", "data": {"guid": "msg-1", "text": "hello"}}}"#.into(),
                ],
                related: vec![CapabilityId::from_static(OP_SYNC_EVENTS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_INGEST_WEBHOOK_REQUEST),
            summary: "Process a host-forwarded BlueBubbles webhook request".into(),
            description: Some(
                "Validates FCP host request-region metadata, callback auth, route path, method, and body bounds before passing the BlueBubbles POST body into the normalized webhook event pipeline".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["method", "url", "body"],
                "properties": {
                    "method": {
                        "type": "string",
                        "description": "HTTP method observed by the host request region"
                    },
                    "url": {
                        "type": "string",
                        "description": "Full callback URL observed by the host; password query auth is accepted but redacted from outputs"
                    },
                    "headers": {
                        "type": "object",
                        "description": "Optional host-forwarded headers; x-bluebubbles-auth may carry stripped callback auth"
                    },
                    "body": {
                        "type": "object",
                        "description": "Raw BlueBubbles webhook JSON body"
                    },
                    "body_size_bytes": {
                        "type": "integer",
                        "description": "Host-measured request body byte size before connector parsing"
                    },
                    "max_body_bytes": {
                        "type": "integer",
                        "description": "Ingress body limit override for tests or stricter host policy"
                    },
                    "request_region": {
                        "type": "object",
                        "description": "FCP host request-region metadata such as source, cancelled, and deadline_exceeded"
                    },
                    "event_type": {
                        "type": "string",
                        "description": "Optional event type override when the transport carries it outside the JSON body"
                    },
                    "account_id": {
                        "type": "string",
                        "description": "Optional account namespace for dedupe; defaults to connector webhook_account_id"
                    },
                    "observed_at_ms": {
                        "type": "integer",
                        "description": "Optional host-observed epoch-ms timestamp used for deterministic coalescing tests"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "accepted": { "type": "boolean" },
                    "status_code": { "type": "integer" },
                    "reason_code": { "type": "string" },
                    "reason": { "type": "string" },
                    "ingest": { "type": "object" },
                    "request_region": { "type": "object" },
                    "service_layers": { "type": "object" },
                    "logs": { "type": "array", "items": { "type": "object" } },
                    "body_bytes": { "type": "integer" },
                    "tainted": { "type": "boolean" },
                    "clean_shutdown": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When the FCP host or webhook receiver has accepted a raw BlueBubbles POST in a supervised request region and needs connector-local callback auth, body bounds, sender policy, replay dedupe, coalescing, and EventEnvelope fan-out in one route contract".into(),
                common_mistakes: vec![
                    "Passing a URL without the BlueBubbles callback auth query or x-bluebubbles-auth header".into(),
                    "Expecting this operation to open a socket; the host owns the HTTP listener and forwards request-region metadata".into(),
                    "Logging or echoing the callback password; outputs redact query auth and never return the configured password".into(),
                ],
                examples: vec![
                    r#"{"method":"POST","url":"http://localhost:8645/bluebubbles-webhook","headers":{"x-bluebubbles-auth":"[REDACTED]"},"body":{"type":"new-message","data":{"guid":"msg-1","text":"hello"}}}"#.into(),
                ],
                related: vec![CapabilityId::from_static(OP_INGEST_WEBHOOK_EVENT)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_SERVER_INFO),
            summary: "Get BlueBubbles server info".into(),
            description: Some(
                "Gets information about the BlueBubbles server (version, OS, private API status)".into(),
            ),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "os_version": { "type": "string" },
                    "server_version": { "type": "string" },
                    "private_api": { "type": "boolean" },
                    "proxy_service": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_ADMIN),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to check the BlueBubbles server status or capabilities".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

const fn message_event_topic(message: &Message) -> &'static str {
    if message.group_action_type.is_some() {
        "imessage.chat.group_action"
    } else if message.associated_message_type.is_some() {
        "imessage.message.associated"
    } else if message.is_from_me {
        "imessage.message.outbound"
    } else {
        "imessage.message.inbound"
    }
}

fn message_to_sync_event(chat_guid: &str, message: &Message) -> serde_json::Value {
    json!({
        "topic": message_event_topic(message),
        "event_id": message.guid,
        "chat_guid": chat_guid,
        "timestamp_ms": message.date_created,
        "is_from_me": message.is_from_me,
        "thread": message.thread_originator_guid.as_ref().map(|guid| {
            json!({
                "kind": "message_thread",
                "thread_originator_guid": guid,
            })
        }),
        "participant_address": message.handle.as_ref().map(|handle| handle.address.clone()),
        "has_attachments": !message.attachments.is_empty(),
        "message": message,
    })
}

fn webhook_event_stream_key(
    account_id: &str,
    event: &NormalizedBlueBubblesWebhookMessage,
) -> Option<String> {
    let conversation_key = event
        .chat_guid
        .as_deref()
        .or(event.chat_identifier.as_deref())?
        .trim();
    if conversation_key.is_empty() {
        return None;
    }
    let account_id = account_id.trim();
    let account_id = if account_id.is_empty() {
        "default"
    } else {
        account_id
    };
    Some(format!("bluebubbles:{account_id}:chat:{conversation_key}"))
}

fn required_string<'a>(input: &'a Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Missing '{field}' field"),
        })
}

fn optional_string<'a>(input: &'a Value, field: &str) -> Option<&'a str> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn ingress_request_region_bool(input: &Value, field: &str) -> bool {
    input
        .get("request_region")
        .and_then(|region| region.get(field))
        .or_else(|| input.get(field))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn ingress_request_region_string(input: &Value, field: &str, default: &str) -> String {
    input
        .get("request_region")
        .and_then(|region| region.get(field))
        .or_else(|| input.get(field))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map_or_else(|| default.to_string(), str::to_string)
}

fn ingress_u64_field(input: &Value, field: &str, default: u64) -> FcpResult<u64> {
    input.get(field).map_or(Ok(default), |value| {
        value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be a non-negative integer"),
        })
    })
}

fn ingress_usize_field(input: &Value, field: &str, default: usize) -> FcpResult<usize> {
    let default_u64 = u64::try_from(default).map_err(|_| FcpError::InvalidRequest {
        code: 1005,
        message: format!("{field} default is too large for this platform"),
    })?;
    let raw = ingress_u64_field(input, field, default_u64)?;
    usize::try_from(raw).map_err(|_| FcpError::InvalidRequest {
        code: 1005,
        message: format!("{field} is too large for this platform"),
    })
}

fn webhook_ingress_body_size(input: &Value, body: &Value) -> FcpResult<usize> {
    if input.get("body_size_bytes").is_some() {
        return ingress_usize_field(input, "body_size_bytes", 0);
    }
    serde_json::to_vec(body)
        .map(|body| body.len())
        .map_err(|error| FcpError::Internal {
            message: format!("Failed to measure BlueBubbles webhook body: {error}"),
        })
}

fn webhook_ingress_header_value(input: &Value, header_name: &str) -> FcpResult<Option<String>> {
    let Some(headers) = input.get("headers") else {
        return Ok(None);
    };
    let headers = headers
        .as_object()
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "headers must be an object of HTTP header strings".into(),
        })?;
    for (key, value) in headers {
        if key.eq_ignore_ascii_case(header_name) {
            let Some(value) = value.as_str() else {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("header `{key}` must be a string"),
                });
            };
            return Ok(Some(value.trim().to_string()));
        }
    }
    Ok(None)
}

fn redacted_webhook_url(url: &reqwest::Url) -> String {
    let mut redacted = url.clone();
    let query_pairs = url
        .query_pairs()
        .map(|(key, value)| {
            let value = if key.eq_ignore_ascii_case("password") {
                "[REDACTED]".to_string()
            } else {
                value.into_owned()
            };
            (key.into_owned(), value)
        })
        .collect::<Vec<_>>();
    redacted.set_query(None);
    {
        let mut pairs = redacted.query_pairs_mut();
        for (key, value) in query_pairs {
            pairs.append_pair(&key, &value);
        }
    }
    redacted.to_string()
}

fn webhook_ingress_request_region(input: &Value, method: &str, url: &str) -> Value {
    json!({
        "surface": "fcp.webhook.request_region",
        "provider": "bluebubbles",
        "source": ingress_request_region_string(input, "source", "host_forwarded"),
        "method": method,
        "url": url,
        "cancelled": ingress_request_region_bool(input, "cancelled"),
        "deadline_exceeded": ingress_request_region_bool(input, "deadline_exceeded")
    })
}

fn webhook_ingress_service_layers(input: &Value) -> FcpResult<Value> {
    let timeout_ms = ingress_u64_field(input, "timeout_ms", WEBHOOK_INGRESS_TIMEOUT_MS)?;
    let concurrency_limit = ingress_u64_field(
        input,
        "concurrency_limit",
        WEBHOOK_INGRESS_CONCURRENCY_LIMIT,
    )?;
    let rate_limit_max =
        ingress_u64_field(input, "rate_limit_max", WEBHOOK_INGRESS_RATE_LIMIT_MAX)?;
    let rate_limit_window_ms = ingress_u64_field(
        input,
        "rate_limit_window_ms",
        WEBHOOK_INGRESS_RATE_LIMIT_WINDOW_MS,
    )?;

    Ok(json!({
        "builder": "fcp.webhook.ServiceBuilder",
        "host_enforced": true,
        "layers": [
            { "name": "timeout", "timeout_ms": timeout_ms },
            { "name": "concurrency_limit", "max_in_flight": concurrency_limit },
            { "name": "load_shed", "enabled": true },
            {
                "name": "rate_limit",
                "pool": "bluebubbles.webhook",
                "max": rate_limit_max,
                "per_ms": rate_limit_window_ms
            }
        ]
    }))
}

fn webhook_ingress_log(stage: &str, status: &str, reason_code: &str, message: &str) -> Value {
    json!({
        "stage": stage,
        "status": status,
        "reason_code": reason_code,
        "message": message,
    })
}

#[allow(clippy::too_many_arguments)]
fn webhook_ingress_response(
    accepted: bool,
    status_code: u16,
    reason_code: &str,
    reason: &str,
    ingest_result: Option<&Value>,
    request_region: &Value,
    service_layers: &Value,
    logs: &[Value],
    body_bytes: usize,
) -> Value {
    json!({
        "accepted": accepted,
        "status_code": status_code,
        "reason_code": reason_code,
        "reason": reason,
        "ingest": ingest_result,
        "request_region": request_region,
        "service_layers": service_layers,
        "logs": logs,
        "body_bytes": body_bytes,
        "tainted": true,
        "clean_shutdown": true,
    })
}

fn webhook_password_from_url(url: &reqwest::Url) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key.eq_ignore_ascii_case("password"))
        .map(|(_, value)| value.into_owned())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn webhook_password_matches(candidate: &str, expected: &str) -> bool {
    candidate.as_bytes().ct_eq(expected.as_bytes()).into()
}

fn webhook_events_from_input(input: &Value) -> FcpResult<Vec<String>> {
    let Some(values) = input.get("events") else {
        return Ok(default_webhook_events());
    };
    let events = values.as_array().ok_or_else(|| FcpError::InvalidRequest {
        code: 1005,
        message: "events must be an array of non-empty strings".into(),
    })?;
    let events = events
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: "events must contain only non-empty strings".into(),
                })
        })
        .collect::<FcpResult<Vec<_>>>()?;
    if events.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "events must not be empty".into(),
        });
    }
    Ok(events)
}

#[must_use]
pub fn events_info() -> Vec<EventInfo> {
    let schema = json!({
        "type": "object",
        "required": ["event_type", "topic", "event_id", "is_from_me", "is_group"],
        "properties": {
            "event_type": { "type": "string" },
            "topic": { "type": "string" },
            "event_id": { "type": "string" },
            "chat_guid": { "type": "string" },
            "chat_identifier": { "type": "string" },
            "sender_id": { "type": "string" },
            "sender_name": { "type": "string" },
            "text": { "type": "string" },
            "is_from_me": { "type": "boolean" },
            "is_group": { "type": "boolean" },
            "attachments": { "type": "array", "items": { "type": "object" } },
            "participants": { "type": "array", "items": { "type": "object" } },
            "reply_to_message_guid": { "type": "string" },
            "associated_message_guid": { "type": "string" },
            "associated_message_type": { "type": "integer" },
            "balloon_bundle_id": { "type": "string" },
            "is_tapback": { "type": "boolean" }
        }
    });
    [
        "imessage.message.inbound",
        "imessage.message.outbound",
        "imessage.message.updated",
        "imessage.message.tapback",
    ]
    .into_iter()
    .map(|topic| EventInfo {
        topic: topic.to_string(),
        schema: schema.clone(),
        requires_ack: false,
    })
    .collect()
}

fcp_core::impl_fcp_sealed!(BlueBubblesConnector);

#[async_trait]
impl FcpConnector for BlueBubblesConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config = BlueBubblesConfig::from_value(config)?;
        self.state = Some(BlueBubblesState::from_config(config)?);
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: self.manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(webhook_event_caps()),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let mut snapshot = if self.state.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(state) = &self.state else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };

        match state.client.health_check().await {
            Ok(()) => Ok(SelfCheckReport::ok()),
            Err(err) => {
                if err.is_retryable() {
                    Ok(SelfCheckReport::degraded(
                        "self_check_retryable",
                        err.to_string(),
                    ))
                } else {
                    Ok(SelfCheckReport::failed(
                        "self_check_failed",
                        err.to_string(),
                    ))
                }
            }
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let capability = match Self::required_capability(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };

        if self.state.is_none() {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ));
        }

        let Some(verifier) = &self.verifier else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            ));
        };

        if let Err(error) =
            verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if error.error_code() == "FCP-3001" {
                response =
                    response.with_missing_capabilities(vec![capability.as_str().to_string()]);
            }
            return Ok(response);
        }

        Ok(SimulateResponse::allowed(req.id))
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(state) = &self.state {
            let drained = state
                .webhook_coalescer
                .drain_for_shutdown(&state.config.webhook_coalescing)?;
            if !drained.is_empty() {
                tracing::info!(
                    operation = "shutdown",
                    drained_coalesced_events = drained.len(),
                    "drained pending BlueBubbles coalescing buffers during shutdown"
                );
            }
            state.runtime.shutdown();
        }
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: events_info(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(webhook_event_caps()),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        self.base.check_ready()?;
        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
        let mut stream = state.lock_webhook_events()?;
        stream
            .handle_subscribe(&req)
            .map(|outcome| outcome.response)
            .map_err(|error| FcpError::InvalidRequest {
                code: 1005,
                message: error.to_string(),
            })
    }

    async fn unsubscribe(&self, req: UnsubscribeRequest) -> FcpResult<()> {
        self.base.check_ready()?;
        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
        state.lock_webhook_events()?.unsubscribe(&req.topics);
        Ok(())
    }
}

impl BlueBubblesConnector {
    fn record_webhook_event_envelopes(
        &self,
        state: &BlueBubblesState,
        zone_id: &ZoneId,
        correlation_id: Option<&CorrelationId>,
        account_id: &str,
        events: &[NormalizedBlueBubblesWebhookMessage],
    ) -> FcpResult<Vec<EventEnvelope>> {
        let mut envelopes = Vec::with_capacity(events.len());
        for event in events {
            envelopes.push(self.webhook_event_envelope(
                zone_id,
                correlation_id,
                account_id,
                event,
            )?);
        }
        let recorded = {
            let mut stream = state.lock_webhook_events()?;
            envelopes
                .into_iter()
                .map(|envelope| stream.record(envelope))
                .collect()
        };
        Ok(recorded)
    }

    fn webhook_event_envelope(
        &self,
        zone_id: &ZoneId,
        correlation_id: Option<&CorrelationId>,
        account_id: &str,
        event: &NormalizedBlueBubblesWebhookMessage,
    ) -> FcpResult<EventEnvelope> {
        let payload = serde_json::to_value(event).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize BlueBubbles webhook event: {error}"),
        })?;
        let principal = Principal {
            kind: if event.is_from_me {
                "bluebubbles_self".to_string()
            } else {
                "bluebubbles_sender".to_string()
            },
            id: event
                .sender_id
                .clone()
                .or_else(|| event.chat_identifier.clone())
                .or_else(|| event.chat_guid.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            trust: TrustLevel::Untrusted,
            display: event.sender_name.clone(),
        };

        let mut data = EventData::new(
            self.base.id.clone(),
            self.base.instance_id.clone(),
            zone_id.clone(),
            principal,
            payload,
        );
        if let Some(correlation_id) = correlation_id.cloned() {
            data = data.with_correlation_id(correlation_id);
        }

        let mut resource_uris = Vec::new();
        let account_id = account_id.trim();
        if !account_id.is_empty() {
            resource_uris.push(format!("bluebubbles:account:{account_id}"));
        }
        resource_uris.push(format!("imessage:message:{}", event.event_id));
        if let Some(chat_guid) = event.chat_guid.as_deref() {
            resource_uris.push(format!("imessage:chat:{chat_guid}"));
        }
        data = data.with_resource_uris(resource_uris);

        let mut envelope = EventEnvelope::new(event.topic.clone(), data);
        if let Some(stream_key) = webhook_event_stream_key(account_id, event) {
            envelope = envelope
                .with_stream_key(stream_key)
                .with_ordering(OrderingPolicy::PerKey);
        } else {
            envelope = envelope.with_ordering(OrderingPolicy::Unordered);
        }
        if let Some(timestamp) = event
            .date_created_ms
            .and_then(chrono::DateTime::<Utc>::from_timestamp_millis)
        {
            envelope.timestamp = timestamp;
        }
        Ok(envelope)
    }

    #[allow(clippy::too_many_lines)]
    async fn invoke_webhook_event_pipeline(
        &self,
        state: &BlueBubblesState,
        event_zone_id: &ZoneId,
        event_correlation_id: Option<&CorrelationId>,
        input: &Value,
    ) -> FcpResult<Value> {
        let flush_coalescing = input
            .get("flush_coalescing")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if flush_coalescing && input.get("payload").is_none() {
            let outcome = state
                .webhook_coalescer
                .flush_all(&state.config.webhook_coalescing)?;
            let first_event = outcome.events.first().cloned();
            let event_envelopes = self.record_webhook_event_envelopes(
                state,
                event_zone_id,
                event_correlation_id,
                state.config.webhook_account_id.as_str(),
                &outcome.events,
            )?;
            return Ok(json!({
                "status": outcome.status,
                "dedupe_id": null,
                "dedupe_ids": [],
                "duplicate_id": null,
                "acceptance": null,
                "policy": state.config.webhook_inbound.summary(),
                "coalescing": outcome.summary,
                "reply_context_lookup": null,
                "contacts_enrichment": null,
                "event": first_event,
                "events": outcome.events,
                "event_envelopes": event_envelopes,
            }));
        }

        let payload = input
            .get("payload")
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "Missing 'payload' field".into(),
            })?;
        let account_id = optional_string(input, "account_id")
            .unwrap_or(state.config.webhook_account_id.as_str());
        let event_type = optional_string(input, "event_type");
        let mut event = normalize_bluebubbles_webhook_payload(payload, event_type)?;
        let dedupe_ids = bluebubbles_webhook_source_dedupe_ids(account_id, &event);
        let dedupe_id = dedupe_ids
            .first()
            .cloned()
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "BlueBubbles webhook event produced no dedupe IDs".into(),
            })?;
        let acceptance = state.config.webhook_inbound.evaluate(&event);
        let policy = state.config.webhook_inbound.summary();
        let observed_at_ms = input
            .get("observed_at_ms")
            .and_then(Value::as_i64)
            .or(event.date_created_ms)
            .unwrap_or_else(|| Utc::now().timestamp_millis());
        let (status, duplicate_id, coalescing, reply_context_lookup, contacts_enrichment, events) =
            if acceptance.accepted {
                match state.webhook_dedupe.claim(&dedupe_ids)? {
                    BlueBubblesDedupeClaim::Claimed => {
                        if let Err(error) = state.webhook_dedupe.finalize(&dedupe_ids) {
                            let _ = state.webhook_dedupe.release(&dedupe_ids);
                            return Err(error);
                        }
                        let contacts_enrichment =
                            state.enrich_group_participants(account_id, &mut event);
                        let reply_context_lookup =
                            state.resolve_reply_context(account_id, &mut event).await;
                        let outcome = state.webhook_coalescer.ingest(
                            &state.config.webhook_coalescing,
                            account_id,
                            event.clone(),
                            observed_at_ms,
                        )?;
                        (
                            outcome.status,
                            None,
                            Some(outcome.summary),
                            Some(reply_context_lookup),
                            Some(contacts_enrichment),
                            outcome.events,
                        )
                    }
                    BlueBubblesDedupeClaim::Duplicate { matched_id } => {
                        ("duplicate", Some(matched_id), None, None, None, Vec::new())
                    }
                }
            } else {
                ("rejected", None, None, None, None, Vec::new())
            };
        let emitted_event = events.first().cloned();
        let event_envelopes = self.record_webhook_event_envelopes(
            state,
            event_zone_id,
            event_correlation_id,
            account_id,
            &events,
        )?;
        let correlation_id =
            event_correlation_id.map_or_else(|| "none".to_string(), ToString::to_string);
        let chat_guid = event.chat_guid.as_deref().unwrap_or("none").to_string();
        tracing::info!(
            operation = OP_INGEST_WEBHOOK_EVENT,
            correlation_id = %correlation_id,
            event_id = %event.event_id,
            message_guid = %event.event_id,
            chat_guid = %chat_guid,
            dedupe_id = %dedupe_id,
            dedupe_decision = %status,
            duplicate_id = %duplicate_id.as_deref().unwrap_or("none"),
            inbound_acceptance = %acceptance.reason,
            reply_context_status = %reply_context_lookup.as_ref().map_or("none", |lookup| lookup.status),
            reply_context_reason = %reply_context_lookup.as_ref().map_or("none", |lookup| lookup.reason),
            contacts_enrichment_status = %contacts_enrichment.as_ref().map_or("none", |summary| summary.status),
            contacts_enrichment_reason = %contacts_enrichment.as_ref().map_or("none", |summary| summary.reason),
            contacts_enrichment_enriched_count = contacts_enrichment.as_ref().map_or(0, |summary| summary.enriched_count),
            coalescing_decision = %coalescing.as_ref().map_or("none", |summary| summary.decision),
            coalescing_emitted_count = coalescing.as_ref().map_or(0, |summary| summary.emitted_count),
            coalescing_buffered_count = coalescing.as_ref().map_or(0, |summary| summary.buffered_count),
            inbound_policy_allow_from_me = policy.allow_from_me,
            inbound_policy_allowed_sender_count = policy.allowed_sender_count,
            inbound_policy_allowed_chat_count = policy.allowed_chat_count,
            inbound_policy_allow_group_chats = policy.allow_group_chats,
            inbound_policy_persistent_dedupe = policy.persistent_dedupe,
            auth_outcome = "capability_token_verified",
            redaction_decision = "response_excludes_webhook_password",
            "normalized BlueBubbles webhook event"
        );
        Ok(json!({
            "status": status,
            "dedupe_id": dedupe_id,
            "dedupe_ids": dedupe_ids,
            "duplicate_id": duplicate_id,
            "acceptance": acceptance,
            "policy": policy,
            "coalescing": coalescing,
            "reply_context_lookup": reply_context_lookup,
            "contacts_enrichment": contacts_enrichment,
            "event": emitted_event,
            "events": events,
            "event_envelopes": event_envelopes,
        }))
    }

    #[allow(clippy::too_many_lines)]
    async fn invoke_webhook_request_pipeline(
        &self,
        state: &BlueBubblesState,
        event_zone_id: &ZoneId,
        event_correlation_id: Option<&CorrelationId>,
        input: &Value,
    ) -> FcpResult<Value> {
        let method = required_string(input, "method")?;
        let raw_url = required_string(input, "url")?;
        let parsed_url = reqwest::Url::parse(raw_url);
        let redacted_url = parsed_url
            .as_ref()
            .map_or_else(|_| "[invalid-url]".to_string(), redacted_webhook_url);
        let request_region = webhook_ingress_request_region(input, method, &redacted_url);
        let service_layers = webhook_ingress_service_layers(input)?;
        let mut logs = vec![
            webhook_ingress_log(
                "request_region",
                "ok",
                "request_region_attached",
                "FCP request-region metadata attached to BlueBubbles webhook ingress",
            ),
            webhook_ingress_log(
                "service_builder",
                "ok",
                "service_layers_applied",
                "Timeout, concurrency, load-shed, and rate-limit layers are declared for host enforcement",
            ),
        ];

        let body_value = input.get("body").ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "Missing required field: body".into(),
        })?;
        let body_bytes = webhook_ingress_body_size(input, body_value)?;
        let max_body_bytes =
            ingress_usize_field(input, "max_body_bytes", WEBHOOK_INGRESS_MAX_BODY_BYTES)?;

        if ingress_request_region_bool(input, "cancelled") {
            logs.push(webhook_ingress_log(
                "request_region",
                "denied",
                "request_cancelled",
                "Webhook request was cancelled before connector processing",
            ));
            return Ok(webhook_ingress_response(
                false,
                408,
                "request_cancelled",
                "Webhook request was cancelled before connector processing",
                None,
                &request_region,
                &service_layers,
                &logs,
                body_bytes,
            ));
        }

        if ingress_request_region_bool(input, "deadline_exceeded") {
            logs.push(webhook_ingress_log(
                "timeout",
                "denied",
                "request_timeout",
                "Webhook request deadline was exceeded before connector processing",
            ));
            return Ok(webhook_ingress_response(
                false,
                408,
                "request_timeout",
                "Webhook request deadline was exceeded before connector processing",
                None,
                &request_region,
                &service_layers,
                &logs,
                body_bytes,
            ));
        }

        if !method.eq_ignore_ascii_case("POST") {
            logs.push(webhook_ingress_log(
                "admission",
                "denied",
                "method_not_allowed",
                "BlueBubbles webhook ingress accepts POST requests only",
            ));
            return Ok(webhook_ingress_response(
                false,
                405,
                "method_not_allowed",
                "BlueBubbles webhook ingress accepts POST requests only",
                None,
                &request_region,
                &service_layers,
                &logs,
                body_bytes,
            ));
        }

        if body_bytes > max_body_bytes {
            logs.push(webhook_ingress_log(
                "admission",
                "denied",
                "payload_too_large",
                "BlueBubbles webhook body exceeds configured ingress maximum",
            ));
            return Ok(webhook_ingress_response(
                false,
                413,
                "payload_too_large",
                "BlueBubbles webhook body exceeds configured ingress maximum",
                None,
                &request_region,
                &service_layers,
                &logs,
                body_bytes,
            ));
        }

        if !body_value.is_object() {
            logs.push(webhook_ingress_log(
                "parse",
                "denied",
                "malformed_payload",
                "BlueBubbles webhook body must be a JSON object",
            ));
            return Ok(webhook_ingress_response(
                false,
                400,
                "malformed_payload",
                "BlueBubbles webhook body must be a JSON object",
                None,
                &request_region,
                &service_layers,
                &logs,
                body_bytes,
            ));
        }

        let parsed_url = match parsed_url {
            Ok(url) => url,
            Err(error) => {
                logs.push(webhook_ingress_log(
                    "route",
                    "denied",
                    "malformed_url",
                    "BlueBubbles webhook URL must be absolute and parseable",
                ));
                return Ok(webhook_ingress_response(
                    false,
                    400,
                    "malformed_url",
                    &format!("BlueBubbles webhook URL must be absolute and parseable: {error}"),
                    None,
                    &request_region,
                    &service_layers,
                    &logs,
                    body_bytes,
                ));
            }
        };

        if parsed_url.path() != state.config.webhook_path {
            logs.push(webhook_ingress_log(
                "route",
                "denied",
                "path_mismatch",
                "BlueBubbles webhook path does not match configured ingress route",
            ));
            return Ok(webhook_ingress_response(
                false,
                404,
                "path_mismatch",
                "BlueBubbles webhook path does not match configured ingress route",
                None,
                &request_region,
                &service_layers,
                &logs,
                body_bytes,
            ));
        }

        let header_auth = webhook_ingress_header_value(input, WEBHOOK_AUTH_HEADER)?;
        let supplied_auth = webhook_password_from_url(&parsed_url)
            .or_else(|| header_auth.filter(|value| !value.trim().is_empty()));
        let Some(supplied_auth) = supplied_auth else {
            logs.push(webhook_ingress_log(
                "auth",
                "denied",
                "missing_auth",
                "BlueBubbles webhook password was not supplied in the URL or host-forwarded auth header",
            ));
            return Ok(webhook_ingress_response(
                false,
                401,
                "missing_auth",
                "BlueBubbles webhook password was not supplied in the URL or host-forwarded auth header",
                None,
                &request_region,
                &service_layers,
                &logs,
                body_bytes,
            ));
        };

        if !webhook_password_matches(&supplied_auth, &state.config.server_passcode) {
            logs.push(webhook_ingress_log(
                "auth",
                "denied",
                "invalid_auth",
                "BlueBubbles webhook password did not match connector configuration",
            ));
            return Ok(webhook_ingress_response(
                false,
                401,
                "invalid_auth",
                "BlueBubbles webhook password did not match connector configuration",
                None,
                &request_region,
                &service_layers,
                &logs,
                body_bytes,
            ));
        }
        logs.push(webhook_ingress_log(
            "auth",
            "ok",
            "webhook_auth_validated",
            "BlueBubbles webhook callback auth validated before event normalization",
        ));

        let mut ingest_input = serde_json::Map::new();
        ingest_input.insert("payload".into(), body_value.clone());
        for field in ["account_id", "observed_at_ms"] {
            if let Some(value) = input.get(field) {
                ingest_input.insert(field.into(), value.clone());
            }
        }
        let header_event_type = webhook_ingress_header_value(input, "x-bluebubbles-event")?;
        let event_type = optional_string(input, "event_type")
            .map(str::to_string)
            .or(header_event_type);
        if let Some(event_type) = event_type {
            ingest_input.insert("event_type".into(), Value::String(event_type));
        }

        let ingest_result = self
            .invoke_webhook_event_pipeline(
                state,
                event_zone_id,
                event_correlation_id,
                &Value::Object(ingest_input),
            )
            .await?;
        let status = ingest_result
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let (accepted, status_code, reason_code, reason) = match status {
            "accepted" | "flushed" => (
                true,
                200,
                "event_accepted",
                "BlueBubbles webhook event accepted for downstream emission",
            ),
            "buffered" => (
                true,
                202,
                "event_buffered",
                "BlueBubbles webhook event accepted into the coalescing buffer",
            ),
            "duplicate" => (
                false,
                409,
                "replay_suppressed",
                "Duplicate BlueBubbles webhook request suppressed by replay dedupe",
            ),
            "rejected" => (
                false,
                403,
                "policy_rejected",
                "BlueBubbles webhook event rejected by connector-local sender/conversation policy",
            ),
            _ => (
                false,
                500,
                "unexpected_ingest_status",
                "BlueBubbles webhook event returned an unexpected ingest status",
            ),
        };
        logs.push(webhook_ingress_log(
            "emit",
            if accepted { "ok" } else { "denied" },
            reason_code,
            reason,
        ));
        Ok(webhook_ingress_response(
            accepted,
            status_code,
            reason_code,
            reason,
            Some(&ingest_result),
            &request_region,
            &service_layers,
            &logs,
            body_bytes,
        ))
    }

    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        let required_cap = Self::required_capability(operation)?;
        let event_zone_id = req.zone_id.clone();
        let event_correlation_id = req.correlation_id.clone();

        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;

        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
        let runtime = &state.runtime;
        let client = &state.client;

        let output = match operation {
            OP_SEND_MESSAGE => {
                let chat_guid = req
                    .input
                    .get("chat_guid")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'chat_guid' field".into(),
                    })?;
                let message = req
                    .input
                    .get("message")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'message' field".into(),
                    })?;
                let options = parse_send_message_options(&req.input)?;

                let outcome = client
                    .send_message(runtime, chat_guid, message, options)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                let mut output =
                    serde_json::to_value(&outcome.response).map_err(|e| FcpError::Internal {
                        message: format!("Failed to serialize response: {e}"),
                    })?;
                if let Value::Object(ref mut object) = output {
                    object.insert(
                        "send_method".into(),
                        Value::String(outcome.decision.method.clone()),
                    );
                    object.insert(
                        "send_method_decision".into(),
                        serde_json::to_value(&outcome.decision).map_err(|e| {
                            FcpError::Internal {
                                message: format!("Failed to serialize send decision: {e}"),
                            }
                        })?,
                    );
                }
                output
            }
            OP_SEND_MEDIA => {
                let target = parse_send_target(&req.input)?;
                let scan_limit = req
                    .input
                    .get("scan_limit")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(5_000);
                let target_resolution = client
                    .resolve_send_target(runtime, &target, scan_limit)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let chat_guid = target_resolution.chat_guid.clone().ok_or_else(|| {
                    FcpError::InvalidRequest {
                        code: 1004,
                        message: "send_media target did not resolve to a chat_guid".into(),
                    }
                })?;
                let local_path = required_string(&req.input, "local_path")?;
                let options = parse_send_media_options(&req.input)?;
                let outcome = client
                    .send_media(
                        runtime,
                        &chat_guid,
                        local_path,
                        &state.config.media_send,
                        options,
                    )
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "status": "sent",
                    "action": "send_media",
                    "chat_guid": chat_guid,
                    "message_id": outcome.message_id,
                    "filename": outcome.filename,
                    "content_type": outcome.content_type,
                    "byte_len": outcome.byte_len,
                    "media_send_decision": outcome.decision,
                    "target_resolution": target_resolution,
                    "response": outcome.response,
                })
            }
            OP_RESOLVE_SEND_TARGET => {
                let target = parse_send_target(&req.input)?;
                let scan_limit = req
                    .input
                    .get("scan_limit")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(5_000);
                let resolution = client
                    .resolve_send_target(runtime, &target, scan_limit)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&resolution).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize target resolution: {e}"),
                })?
            }
            OP_CREATE_CHAT => {
                let address = req
                    .input
                    .get("address")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'address' field".into(),
                    })?;
                let message = req
                    .input
                    .get("message")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'message' field".into(),
                    })?;
                let outcome = client
                    .create_chat(runtime, address, message)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "chat_guid": outcome.chat_guid,
                    "message_id": outcome.message_id,
                    "send_method": outcome.decision.method,
                    "send_method_decision": outcome.decision,
                    "response": outcome.response,
                })
            }
            OP_GET_ACTION_AVAILABILITY => {
                let availability = client
                    .action_availability(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&availability).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize action availability: {e}"),
                })?
            }
            OP_EDIT_MESSAGE => {
                let message_guid = required_string(&req.input, "message_guid")?;
                let new_text = required_string(&req.input, "new_text")?;
                let part_index =
                    optional_u64_field(&req.input, &["part_index", "partIndex"], "part_index")?
                        .unwrap_or(0);
                let backwards_compatibility_message =
                    optional_string(&req.input, "backwards_compatibility_message");
                let response = client
                    .edit_message(
                        runtime,
                        message_guid,
                        new_text,
                        part_index,
                        backwards_compatibility_message,
                    )
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "status": "edited",
                    "action": "edit",
                    "message_guid": message_guid,
                    "part_index": part_index,
                    "response": response,
                })
            }
            OP_UNSEND_MESSAGE => {
                let message_guid = required_string(&req.input, "message_guid")?;
                let part_index =
                    optional_u64_field(&req.input, &["part_index", "partIndex"], "part_index")?
                        .unwrap_or(0);
                let response = client
                    .unsend_message(runtime, message_guid, part_index)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "status": "unsent",
                    "action": "unsend",
                    "message_guid": message_guid,
                    "part_index": part_index,
                    "response": response,
                })
            }
            OP_SEND_REACTION => {
                let chat_guid = required_string(&req.input, "chat_guid")?;
                let message_guid = required_string(&req.input, "message_guid")?;
                let reaction_input = required_string(&req.input, "reaction")?;
                let remove =
                    optional_bool_field(&req.input, &["remove"], "remove")?.unwrap_or(false);
                let part_index =
                    optional_u64_field(&req.input, &["part_index", "partIndex"], "part_index")?
                        .unwrap_or(0);
                let normalized_reaction = normalize_bluebubbles_tapback_reaction(
                    reaction_input,
                    remove,
                )
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message:
                        "reaction must be one of love, like, dislike, laugh, emphasize, or question"
                            .into(),
                })?;
                let response = client
                    .send_reaction(
                        runtime,
                        chat_guid,
                        message_guid,
                        reaction_input,
                        remove,
                        part_index,
                    )
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "status": "reacted",
                    "action": "reaction",
                    "chat_guid": chat_guid,
                    "message_guid": message_guid,
                    "reaction": normalized_reaction,
                    "part_index": part_index,
                    "response": response,
                })
            }
            OP_SET_TYPING => {
                let chat_guid = required_string(&req.input, "chat_guid")?;
                let typing =
                    optional_bool_field(&req.input, &["typing"], "typing")?.unwrap_or(true);
                let response = client
                    .set_typing(runtime, chat_guid, typing)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "status": if typing { "typing_started" } else { "typing_stopped" },
                    "typing": typing,
                    "response": response,
                })
            }
            OP_GET_CHATS => {
                let offset = req.input.get("offset").and_then(serde_json::Value::as_u64);
                let limit = req.input.get("limit").and_then(serde_json::Value::as_u64);

                let params = QueryParams {
                    offset,
                    limit,
                    ..QueryParams::default()
                };

                let resp = client
                    .get_chats(runtime, &params)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_GET_CHAT => {
                let chat_guid = req
                    .input
                    .get("chat_guid")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'chat_guid' field".into(),
                    })?;

                let resp = client
                    .get_chat(runtime, chat_guid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_GET_MESSAGES => {
                let chat_guid = req
                    .input
                    .get("chat_guid")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'chat_guid' field".into(),
                    })?;
                let offset = req.input.get("offset").and_then(serde_json::Value::as_u64);
                let limit = req.input.get("limit").and_then(serde_json::Value::as_u64);
                let after = req.input.get("after").and_then(serde_json::Value::as_i64);
                let before = req.input.get("before").and_then(serde_json::Value::as_i64);

                let params = QueryParams {
                    offset,
                    limit,
                    after,
                    before,
                    ..QueryParams::default()
                };

                let resp = client
                    .get_messages(runtime, chat_guid, &params)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_SYNC_EVENTS => {
                let requested_chat_guid = req.input.get("chat_guid").and_then(|v| v.as_str());
                let after = req.input.get("after").and_then(serde_json::Value::as_i64);
                let before = req.input.get("before").and_then(serde_json::Value::as_i64);
                let chat_limit = req
                    .input
                    .get("chat_limit")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(DEFAULT_SYNC_CHAT_LIMIT);
                let message_limit = req
                    .input
                    .get("message_limit")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(DEFAULT_SYNC_MESSAGE_LIMIT);

                let chat_guids = if let Some(chat_guid) = requested_chat_guid {
                    vec![chat_guid.to_string()]
                } else {
                    let chat_params = QueryParams {
                        limit: Some(chat_limit),
                        sort: Some("ASC".into()),
                        ..QueryParams::default()
                    };
                    client
                        .get_chats(runtime, &chat_params)
                        .await
                        .map_err(|e| e.to_fcp_error())?
                        .data
                        .into_iter()
                        .map(|chat| chat.guid)
                        .collect::<Vec<_>>()
                };

                let mut next_after = after;
                let mut ordered_events = Vec::new();

                for chat_guid in &chat_guids {
                    let params = QueryParams {
                        limit: Some(message_limit),
                        after,
                        before,
                        sort: Some("ASC".into()),
                        ..QueryParams::default()
                    };

                    let resp = client
                        .get_messages(runtime, chat_guid, &params)
                        .await
                        .map_err(|e| e.to_fcp_error())?;

                    for message in resp.data {
                        if let Some(ts) = message.date_created {
                            next_after = Some(next_after.map_or(ts, |current| current.max(ts)));
                        }

                        let event = message_to_sync_event(chat_guid, &message);
                        ordered_events.push((
                            message.date_created.unwrap_or_default(),
                            message.guid.clone(),
                            event,
                        ));
                    }
                }

                ordered_events
                    .sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

                json!({
                    "events": ordered_events
                        .into_iter()
                        .map(|(_, _, event)| event)
                        .collect::<Vec<_>>(),
                    "next_after": next_after.map(|ts| ts.saturating_add(1)),
                    "synced_chats": chat_guids.len(),
                    "chat_guid": requested_chat_guid,
                })
            }
            OP_DOWNLOAD_ATTACHMENT => {
                let attachment_guid = req
                    .input
                    .get("attachment_guid")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'attachment_guid' field".into(),
                    })?;

                let attachment = client
                    .download_attachment(runtime, attachment_guid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                json!({
                    "attachment_guid": attachment_guid,
                    "encoding": "base64",
                    "data_base64": base64::engine::general_purpose::STANDARD.encode(&attachment),
                    "byte_len": attachment.len(),
                })
            }
            OP_MARK_READ => {
                let chat_guid = req
                    .input
                    .get("chat_guid")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'chat_guid' field".into(),
                    })?;

                client
                    .mark_read(runtime, chat_guid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                json!({ "status": "marked_read" })
            }
            OP_REGISTER_WEBHOOK => {
                let webhook_url = optional_string(&req.input, "url")
                    .map(str::to_string)
                    .map_or_else(|| state.config.webhook_registration_url(), Ok)?;
                let events = webhook_events_from_input(&req.input)?;
                let skip_if_existing = req
                    .input
                    .get("skip_if_existing")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);

                client
                    .register_webhook(runtime, &webhook_url, events, skip_if_existing)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_LIST_WEBHOOKS => {
                let webhooks = client
                    .list_webhooks(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "webhooks": webhooks })
            }
            OP_UNREGISTER_WEBHOOK => {
                let mut deleted = Vec::new();
                if let Some(webhook_id) = optional_string(&req.input, "webhook_id") {
                    let response = client
                        .delete_webhook(runtime, webhook_id)
                        .await
                        .map_err(|e| e.to_fcp_error())?;
                    deleted.push(json!({
                        "webhook_id": webhook_id,
                        "response": response,
                    }));
                } else {
                    let webhook_url = required_string(&req.input, "url")?;
                    let webhooks = client
                        .list_webhooks(runtime)
                        .await
                        .map_err(|e| e.to_fcp_error())?;
                    for webhook in webhooks
                        .into_iter()
                        .filter(|webhook| webhook.url.as_deref() == Some(webhook_url))
                    {
                        if let Some(webhook_id) = webhook.id.as_deref() {
                            let response = client
                                .delete_webhook(runtime, webhook_id)
                                .await
                                .map_err(|e| e.to_fcp_error())?;
                            deleted.push(json!({
                                "webhook_id": webhook_id,
                                "url": webhook.url,
                                "response": response,
                            }));
                        }
                    }
                }
                json!({
                    "deleted_count": deleted.len(),
                    "deleted": deleted,
                })
            }
            OP_INGEST_WEBHOOK_EVENT => {
                self.invoke_webhook_event_pipeline(
                    state,
                    &event_zone_id,
                    event_correlation_id.as_ref(),
                    &req.input,
                )
                .await?
            }
            OP_INGEST_WEBHOOK_REQUEST => {
                self.invoke_webhook_request_pipeline(
                    state,
                    &event_zone_id,
                    event_correlation_id.as_ref(),
                    &req.input,
                )
                .await?
            }
            OP_GET_SERVER_INFO => {
                let info = client
                    .server_info(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                serde_json::to_value(&info).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize server info: {e}"),
                })?
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::{CapabilityConstraints, CorrelationId};
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener as StdTcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_SEND),
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_ADMIN),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn base_invoke(connector_id: &ConnectorId, operation: &'static str) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_1"),
            connector_id: connector_id.clone(),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    fn test_config() -> serde_json::Value {
        json!({
            "password": "test-password-123"
        })
    }

    fn test_config_with_url(server_url: &str) -> serde_json::Value {
        json!({
            "server_url": server_url,
            "password": "test-password-123"
        })
    }

    fn test_config_with_webhook_inbound(dedupe_state_path: Option<&str>) -> serde_json::Value {
        let mut config = test_config();
        config["webhook_inbound"] = json!({
            "allowed_sender_ids": ["+15551234567"],
            "allowed_chat_guids": ["iMessage;-;+15551234567"],
            "dedupe_state_path": dedupe_state_path
        });
        config
    }

    fn test_config_with_webhook_coalescing(extra: &serde_json::Value) -> serde_json::Value {
        let mut config = test_config_with_webhook_inbound(None);
        config["webhook_coalescing"] = json!({
            "enabled": true,
            "debounce_ms": 2500,
            "max_debounce_ms": 2500,
            "max_text_chars": 4000,
            "max_attachments": 20,
            "max_source_messages": 10,
            "max_pending_buffers": 16
        });
        if let Some(extra) = extra.as_object() {
            for (key, value) in extra {
                config["webhook_coalescing"][key] = value.clone();
            }
        }
        config
    }

    fn test_config_with_reply_context(server_url: &str) -> serde_json::Value {
        let mut config = test_config_with_url(server_url);
        config["webhook_inbound"] = json!({
            "allowed_sender_ids": ["+15551234567"],
            "allowed_chat_guids": ["iMessage;-;+15551234567", "iMessage;-;+15557654321"]
        });
        config["reply_context_api_fallback"] = json!({
            "enabled": true,
            "max_reply_id_chars": 128,
            "max_response_bytes": 4096
        });
        config
    }

    fn test_config_with_contacts_enrichment() -> serde_json::Value {
        let mut config = test_config();
        config["webhook_inbound"] = json!({
            "allowed_chat_guids": ["iMessage;+;family"],
            "allow_group_chats": true
        });
        config["contacts_enrichment"] = json!({
            "enabled": true,
            "test_contacts": {
                "+1 (555) 123-4567": "Alice Example"
            },
            "positive_cache_ttl_seconds": 3600,
            "negative_cache_ttl_seconds": 300,
            "max_cache_entries": 16
        });
        config
    }

    fn unique_dedupe_state_path() -> String {
        std::env::temp_dir()
            .join(format!(
                "fcp-imessage-webhook-dedupe-{}.json",
                uuid::Uuid::new_v4()
            ))
            .to_string_lossy()
            .into_owned()
    }

    fn webhook_callback_url(auth_value: &str) -> String {
        format!(
            "http://localhost:8645/bluebubbles-webhook?{}={auth_value}",
            "password"
        )
    }

    async fn invoke_webhook_result(
        connector: &BlueBubblesConnector,
        signing_key: &Ed25519SigningKey,
        input: serde_json::Value,
    ) -> serde_json::Value {
        connector
            .invoke(InvokeRequest {
                input,
                capability_token: generate_valid_token(
                    connector,
                    signing_key,
                    OP_INGEST_WEBHOOK_EVENT,
                ),
                ..base_invoke(connector.id(), OP_INGEST_WEBHOOK_EVENT)
            })
            .await
            .unwrap()
            .result
            .unwrap()
    }

    async fn invoke_webhook_request_result(
        connector: &BlueBubblesConnector,
        signing_key: &Ed25519SigningKey,
        input: serde_json::Value,
    ) -> serde_json::Value {
        connector
            .invoke(InvokeRequest {
                input,
                capability_token: generate_valid_token(
                    connector,
                    signing_key,
                    OP_INGEST_WEBHOOK_REQUEST,
                ),
                ..base_invoke(connector.id(), OP_INGEST_WEBHOOK_REQUEST)
            })
            .await
            .unwrap()
            .result
            .unwrap()
    }

    async fn invoke_operation_result(
        connector: &BlueBubblesConnector,
        signing_key: &Ed25519SigningKey,
        operation: &'static str,
        input: serde_json::Value,
    ) -> serde_json::Value {
        connector
            .invoke(InvokeRequest {
                input,
                capability_token: generate_valid_token(connector, signing_key, operation),
                ..base_invoke(connector.id(), operation)
            })
            .await
            .unwrap()
            .result
            .unwrap()
    }

    fn generate_valid_token(
        connector: &BlueBubblesConnector,
        signing_key: &Ed25519SigningKey,
        op: &str,
    ) -> CapabilityToken {
        let capability = match op {
            OP_SEND_MESSAGE | OP_SEND_MEDIA | OP_CREATE_CHAT | OP_EDIT_MESSAGE
            | OP_UNSEND_MESSAGE | OP_SEND_REACTION | OP_SET_TYPING | OP_MARK_READ => CAP_SEND,
            OP_GET_SERVER_INFO
            | OP_GET_ACTION_AVAILABILITY
            | OP_REGISTER_WEBHOOK
            | OP_LIST_WEBHOOKS
            | OP_UNREGISTER_WEBHOOK => CAP_ADMIN,
            _ => CAP_READ,
        };
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .target_instance(connector.base.instance_id.as_str())
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn handshake_for_signing_key(signing_key: &Ed25519SigningKey) -> HandshakeRequest {
        let mut handshake = base_handshake();
        handshake.host_public_key = signing_key.verifying_key().to_bytes();
        handshake
    }

    #[derive(Clone, Debug)]
    struct LoopbackRequest {
        method: String,
        target: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    impl LoopbackRequest {
        fn json_body(&self) -> Value {
            serde_json::from_slice(&self.body).expect("loopback request body should be valid JSON")
        }
    }

    #[derive(Clone, Debug)]
    struct LoopbackResponse {
        status: u16,
        body: Vec<u8>,
        delay: Duration,
    }

    impl LoopbackResponse {
        fn json(status: u16, body: &Value) -> Self {
            Self {
                status,
                body: body.to_string().into_bytes(),
                delay: Duration::ZERO,
            }
        }

        fn raw_json(status: u16, body: &'static str) -> Self {
            Self {
                status,
                body: body.as_bytes().to_vec(),
                delay: Duration::ZERO,
            }
        }
    }

    struct BlueBubblesLoopback {
        base_url: String,
        requests: Arc<Mutex<Vec<LoopbackRequest>>>,
        logs: Arc<Mutex<Vec<Value>>>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl BlueBubblesLoopback {
        fn spawn(name: &'static str, responses: Vec<LoopbackResponse>) -> Self {
            let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind loopback server");
            let addr = listener.local_addr().expect("loopback server addr");
            let requests = Arc::new(Mutex::new(Vec::new()));
            let logs = Arc::new(Mutex::new(Vec::new()));
            let requests_for_thread = Arc::clone(&requests);
            let logs_for_thread = Arc::clone(&logs);

            let join = thread::spawn(move || {
                for (sequence, response) in responses.into_iter().enumerate() {
                    let (mut stream, _) = listener.accept().expect("accept loopback connection");
                    let request = read_loopback_request(&mut stream);
                    logs_for_thread
                        .lock()
                        .expect("lock loopback logs")
                        .push(json!({
                            "event": "bluebubbles-send-mode-loopback",
                            "server": name,
                            "sequence": sequence,
                            "target": redacted_target(&request.target),
                            "password_redacted": true,
                            "request_body_len": request.body.len(),
                            "response_status": response.status,
                            "response_body_len": response.body.len(),
                        }));
                    requests_for_thread
                        .lock()
                        .expect("lock loopback requests")
                        .push(request);
                    if !response.delay.is_zero() {
                        thread::sleep(response.delay);
                    }
                    let _ = write_loopback_response(&mut stream, &response);
                }
            });

            Self {
                base_url: format!("http://{addr}"),
                requests,
                logs,
                join: Some(join),
            }
        }

        fn uri(&self) -> &str {
            &self.base_url
        }

        fn finish(mut self) -> (Vec<LoopbackRequest>, Vec<Value>) {
            if let Some(join) = self.join.take() {
                join.join().expect("loopback thread should exit");
            }
            let requests = self
                .requests
                .lock()
                .expect("lock loopback requests")
                .clone();
            let logs = self.logs.lock().expect("lock loopback logs").clone();
            (requests, logs)
        }
    }

    fn redacted_target(target: &str) -> String {
        target.replace("test-password-123", "[REDACTED]")
    }

    fn target_has_query_key(target: &str, key: &str) -> bool {
        target.split_once('?').is_some_and(|(_, query)| {
            query
                .split('&')
                .filter_map(|param| param.split_once('='))
                .any(|(name, _)| name == key)
        })
    }

    const fn status_reason(status: u16) -> &'static str {
        match status {
            401 => "Unauthorized",
            403 => "Forbidden",
            409 => "Conflict",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "OK",
        }
    }

    fn read_loopback_request(stream: &mut TcpStream) -> LoopbackRequest {
        let mut buffer = Vec::new();
        let mut scratch = [0_u8; 1024];
        let header_end = loop {
            let read = stream.read(&mut scratch).expect("read loopback request");
            assert!(read > 0, "unexpected EOF before HTTP headers");
            buffer.extend_from_slice(&scratch[..read]);
            if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };

        let header_text =
            std::str::from_utf8(&buffer[..header_end]).expect("HTTP headers are UTF-8");
        let mut lines = header_text.split("\r\n");
        let request_line = lines.next().expect("request line");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().expect("method").to_string();
        let target = parts.next().expect("target").to_string();
        let mut headers = HashMap::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').expect("header separator");
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
        let content_length = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = buffer[header_end..].to_vec();
        while body.len() < content_length {
            let read = stream.read(&mut scratch).expect("read loopback body");
            assert!(read > 0, "unexpected EOF before HTTP body");
            body.extend_from_slice(&scratch[..read]);
        }
        body.truncate(content_length);

        LoopbackRequest {
            method,
            target,
            headers,
            body,
        }
    }

    fn write_loopback_response(
        stream: &mut TcpStream,
        response: &LoopbackResponse,
    ) -> std::io::Result<()> {
        let head = format!(
            "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            response.status,
            status_reason(response.status),
            response.body.len()
        );
        stream.write_all(head.as_bytes())?;
        stream.write_all(&response.body)?;
        stream.flush()
    }

    #[derive(Debug)]
    struct LoopbackHttpResponse {
        status: u16,
        body: Value,
    }

    fn send_loopback_json_post(
        addr: SocketAddr,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> LoopbackHttpResponse {
        let mut stream = TcpStream::connect(addr).expect("connect ingress loopback");
        let mut request = format!(
            "POST {target} HTTP/1.1\r\nhost: {addr}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
            body.len()
        );
        for (name, value) in headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .expect("write ingress request headers");
        stream.write_all(body).expect("write ingress request body");
        stream.flush().expect("flush ingress request");
        stream
            .shutdown(Shutdown::Write)
            .expect("close ingress request write side");

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .expect("read ingress response");
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
            .expect("ingress response header terminator");
        let header_text =
            std::str::from_utf8(&response[..header_end]).expect("response headers are UTF-8");
        let status = header_text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .expect("parse ingress response status");
        let body = serde_json::from_slice(&response[header_end..]).expect("parse response JSON");
        LoopbackHttpResponse { status, body }
    }

    fn webhook_callback_url_for_base(base_url: &str, auth_value: &str) -> String {
        format!("{base_url}/bluebubbles-webhook?{}={auth_value}", "password")
    }

    fn callback_target(callback_url: &str) -> String {
        let url = reqwest::Url::parse(callback_url).expect("callback URL should parse");
        url.query().map_or_else(
            || url.path().to_string(),
            |query| format!("{}?{query}", url.path()),
        )
    }

    async fn drive_ingress_loopback_post(
        listener: &StdTcpListener,
        connector: &BlueBubblesConnector,
        signing_key: &Ed25519SigningKey,
        target: String,
        body: Value,
    ) -> (LoopbackRequest, LoopbackHttpResponse, Value) {
        let addr = listener.local_addr().expect("ingress loopback addr");
        let body_bytes = body.to_string().into_bytes();
        let client = thread::spawn(move || {
            let headers = vec![("x-bluebubbles-event".to_string(), "new-message".to_string())];
            send_loopback_json_post(addr, &target, &headers, &body_bytes)
        });

        let (mut stream, _) = listener.accept().expect("accept FCP ingress loopback POST");
        let request = read_loopback_request(&mut stream);
        let request_body = request.json_body();
        let result = invoke_webhook_request_result(
            connector,
            signing_key,
            json!({
                "method": request.method,
                "url": format!("http://{addr}{}", request.target),
                "headers": request.headers,
                "request_region": {
                    "source": "socket_loopback_harness"
                },
                "account_id": "acct-a",
                "observed_at_ms": 1_700_000_000_000_i64,
                "body": request_body
            }),
        )
        .await;
        let status_code = result["status_code"]
            .as_u64()
            .and_then(|code| u16::try_from(code).ok())
            .unwrap_or(500);
        write_loopback_response(&mut stream, &LoopbackResponse::json(status_code, &result))
            .expect("write FCP ingress response");
        drop(stream);
        let client_response = client.join().expect("ingress client thread should exit");
        (request, client_response, result)
    }

    fn loopback_config(server_url: &str) -> Value {
        json!({
            "server_url": server_url,
            "password": "test-password-123",
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 0,
                "max_delay_ms": 0,
                "jitter_enabled": false
            }
        })
    }

    fn loopback_media_config(server_url: &str, root: &Path, max_bytes: u64) -> Value {
        let mut config = loopback_config(server_url);
        config["media_send"] = json!({
            "local_roots": [root.to_string_lossy()],
            "max_bytes": max_bytes,
            "allowed_mime_types": ["application/pdf", "text/plain"],
            "allowed_mime_prefixes": ["audio/", "image/", "video/"],
            "upload_timeout_ms": 60_000
        });
        config
    }

    fn unique_media_root() -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("fcp-imessage-media-send-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("create media test root");
        root
    }

    #[derive(Debug, Clone, Copy)]
    enum MediaFixtureName {
        Photo,
        Large,
    }

    fn write_media_fixture(root: &Path, name: MediaFixtureName, bytes: &[u8]) -> PathBuf {
        let path = match name {
            MediaFixtureName::Photo => root.join("photo.png"),
            MediaFixtureName::Large => root.join("large.png"),
        };
        fs::write(&path, bytes).expect("write media fixture");
        path
    }

    async fn invoke_against_loopback_with_config(
        config: Value,
        operation: &'static str,
        input: Value,
    ) -> FcpResult<Value> {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(config).await?;
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await?;
        let req = InvokeRequest {
            input,
            capability_token: generate_valid_token(&connector, &signing_key, operation),
            ..base_invoke(connector.id(), operation)
        };
        let response = connector.invoke(req).await?;
        response.result.ok_or_else(|| FcpError::Internal {
            message: "invoke response should include a result".into(),
        })
    }

    async fn invoke_against_loopback(
        server_url: &str,
        operation: &'static str,
        input: Value,
        request_timeout_ms: Option<u64>,
    ) -> FcpResult<Value> {
        let mut config = loopback_config(server_url);
        if let Some(timeout) = request_timeout_ms {
            config["request_timeout_ms"] = json!(timeout);
        }

        invoke_against_loopback_with_config(config, operation, input).await
    }

    async fn invoke_send_against_loopback(
        server_url: &str,
        request_timeout_ms: Option<u64>,
    ) -> FcpResult<Value> {
        invoke_against_loopback(
            server_url,
            OP_SEND_MESSAGE,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "message": "hello from fcp"
            }),
            request_timeout_ms,
        )
        .await
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = BlueBubblesConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = BlueBubblesConnector::new();
        let result = connector.configure(test_config()).await;
        assert!(result.is_ok());
        assert!(connector.state.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_password() {
        let mut connector = BlueBubblesConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = BlueBubblesConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = BlueBubblesConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_zero_request_timeout() {
        let mut connector = BlueBubblesConnector::new();
        let result = connector
            .configure(json!({
                "password": "test-password-123",
                "request_timeout_ms": 0
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_reports_remote_server_host() {
        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_url("https://bluebubbles.example.com"))
            .await
            .unwrap();
        let report = connector.doctor();
        let network_check = report
            .checks
            .iter()
            .find(|check| check.name == "network_constraints")
            .unwrap();
        assert!(!network_check.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = BlueBubblesConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_SEND_MESSAGE),
            ZoneId::work(),
            json!({}),
            generate_valid_token(&connector, &signing_key, OP_SEND_MESSAGE),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_denies_before_configure() {
        let connector = BlueBubblesConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_SEND_MESSAGE),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert_eq!(resp.denial_code, Some(FcpError::NotConfigured.error_code()));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_denies_before_handshake() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_SEND_MESSAGE),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert_eq!(resp.denial_code, Some(FcpError::NotHandshaken.error_code()));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_denies_wrong_operation_token() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_SEND_MESSAGE),
            ZoneId::work(),
            json!({}),
            generate_valid_token(&connector, &signing_key, OP_GET_CHATS),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert_eq!(resp.denial_code.as_deref(), Some("FCP-3003"));
    }

    #[test]
    fn test_introspection_operations() {
        let connector = BlueBubblesConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 21);
        for operation in [
            OP_SEND_MESSAGE,
            OP_SEND_MEDIA,
            OP_RESOLVE_SEND_TARGET,
            OP_CREATE_CHAT,
            OP_GET_ACTION_AVAILABILITY,
            OP_EDIT_MESSAGE,
            OP_UNSEND_MESSAGE,
            OP_SEND_REACTION,
            OP_SET_TYPING,
            OP_GET_CHATS,
            OP_GET_CHAT,
            OP_GET_MESSAGES,
            OP_SYNC_EVENTS,
            OP_DOWNLOAD_ATTACHMENT,
            OP_MARK_READ,
            OP_GET_SERVER_INFO,
            OP_REGISTER_WEBHOOK,
            OP_LIST_WEBHOOKS,
            OP_UNREGISTER_WEBHOOK,
            OP_INGEST_WEBHOOK_EVENT,
            OP_INGEST_WEBHOOK_REQUEST,
        ] {
            assert!(
                intro
                    .operations
                    .iter()
                    .any(|op| op.id.as_str() == operation),
                "missing operation {operation}"
            );
        }
        assert!(
            intro
                .events
                .iter()
                .any(|event| event.topic == "imessage.message.tapback")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "imessage.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = BlueBubblesConnector::new();
        let req = base_invoke(connector.id(), OP_SEND_MESSAGE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_configured_without_handshake_reports_not_handshaken() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let req = base_invoke(connector.id(), OP_SEND_MESSAGE);
        let result = connector.invoke(req).await;
        assert!(matches!(result, Err(FcpError::NotHandshaken)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_chat_guid() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_SEND_MESSAGE);
        req.input = json!({ "message": "hello" }); // missing chat_guid
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_message() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_SEND_MESSAGE);
        req.input = json!({ "chat_guid": "iMessage;-;+15551234567" }); // missing message
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_reply_part_index_requires_reply_guid() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();
        let req = InvokeRequest {
            input: json!({
                "chat_guid": "iMessage;-;+15551234567",
                "message": "hello",
                "reply_to_part_index": 1
            }),
            capability_token: generate_valid_token(&connector, &signing_key, OP_SEND_MESSAGE),
            ..base_invoke(connector.id(), OP_SEND_MESSAGE)
        };
        let result = connector.invoke(req).await;
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_loopback_uses_private_api_for_macos26_when_available() {
        let server = BlueBubblesLoopback::spawn(
            "macos26-private-api",
            vec![
                LoopbackResponse::json(
                    200,
                    &json!({
                        "data": {
                            "os_version": "26.0.1",
                            "server_version": "1.9.0",
                            "private_api": true
                        }
                    }),
                ),
                LoopbackResponse::json(
                    200,
                    &json!({
                        "status": 200,
                        "message": "Message sent!",
                        "data": {
                            "guid": "msg-private-api",
                            "text": "hello from fcp",
                            "is_from_me": true,
                            "attachments": []
                        }
                    }),
                ),
            ],
        );

        let result = invoke_send_against_loopback(server.uri(), None)
            .await
            .expect("send should succeed");
        assert_eq!(result["send_method"], "private-api");
        assert_eq!(
            result["send_method_decision"]["reason"],
            "macos26_private_api_available"
        );
        assert_eq!(result["data"]["guid"], "msg-private-api");

        let (requests, logs) = server.finish();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].target.starts_with("/api/v1/server/info?"));
        assert!(target_has_query_key(&requests[0].target, "password"));
        assert_eq!(
            requests[1].target.split_once('?').map(|(path, _)| path),
            Some("/api/v1/message/text")
        );
        assert!(target_has_query_key(&requests[1].target, "password"));
        let send_body = requests[1].json_body();
        assert_eq!(send_body["method"], "private-api");
        assert_eq!(send_body["chatGuid"], "iMessage;-;+15551234567");
        assert_eq!(send_body["message"], "hello from fcp");
        assert!(
            send_body["tempGuid"]
                .as_str()
                .is_some_and(|guid| !guid.is_empty())
        );
        assert!(
            logs.iter().all(|entry| entry["target"]
                .as_str()
                .is_some_and(|target| !target.contains("test-password-123"))),
            "loopback transcript must redact the passcode"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_loopback_falls_back_to_apple_script_when_private_api_disabled() {
        let server = BlueBubblesLoopback::spawn(
            "macos26-private-api-disabled",
            vec![
                LoopbackResponse::json(
                    200,
                    &json!({
                        "data": {
                            "os_version": "26.0",
                            "server_version": "1.9.0",
                            "private_api": false
                        }
                    }),
                ),
                LoopbackResponse::json(
                    200,
                    &json!({
                        "status": 200,
                        "message": "Message sent!",
                        "data": {
                            "guid": "msg-apple-script",
                            "text": "hello from fcp",
                            "is_from_me": true,
                            "attachments": []
                        }
                    }),
                ),
            ],
        );

        let result = invoke_send_against_loopback(server.uri(), None)
            .await
            .expect("send should succeed");
        assert_eq!(result["send_method"], "apple-script");
        assert_eq!(
            result["send_method_decision"]["reason"],
            "macos26_private_api_disabled_apple_script_fallback"
        );

        let (requests, logs) = server.finish();
        assert_eq!(requests[1].json_body()["method"], "apple-script");
        assert!(
            logs.iter()
                .any(|entry| entry["event"] == "bluebubbles-send-mode-loopback")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_loopback_error_modes_are_deterministic() {
        let auth_failure = BlueBubblesLoopback::spawn(
            "auth-failure",
            vec![
                LoopbackResponse::json(401, &json!({"error": "bad password"})),
                LoopbackResponse::json(401, &json!({"error": "bad password"})),
            ],
        );
        let auth_error = invoke_send_against_loopback(auth_failure.uri(), None)
            .await
            .expect_err("auth failure should be denied");
        assert!(matches!(auth_error, FcpError::Unauthorized { .. }));
        let (_, auth_logs) = auth_failure.finish();
        assert_eq!(auth_logs[0]["response_status"], 401);

        let rate_limit = BlueBubblesLoopback::spawn(
            "rate-limit",
            vec![
                LoopbackResponse::json(
                    200,
                    &json!({
                        "data": {
                            "os_version": "26.0",
                            "server_version": "1.9.0",
                            "private_api": true
                        }
                    }),
                ),
                LoopbackResponse::json(429, &json!({"error": "slow down"})),
            ],
        );
        let rate_error = invoke_send_against_loopback(rate_limit.uri(), None)
            .await
            .expect_err("rate limit should fail after bounded retry budget");
        assert!(matches!(rate_error, FcpError::RateLimited { .. }));
        let (_, rate_logs) = rate_limit.finish();
        assert_eq!(rate_logs[1]["response_status"], 429);

        let malformed = BlueBubblesLoopback::spawn(
            "malformed-send-response",
            vec![
                LoopbackResponse::json(
                    200,
                    &json!({
                        "data": {
                            "os_version": "26.0",
                            "server_version": "1.9.0",
                            "private_api": true
                        }
                    }),
                ),
                LoopbackResponse::raw_json(200, "{not-json"),
            ],
        );
        let malformed_error = invoke_send_against_loopback(malformed.uri(), None)
            .await
            .expect_err("malformed send response should fail closed");
        assert!(malformed_error.to_string().contains("error"));
        let (_, malformed_logs) = malformed.finish();
        assert_eq!(malformed_logs[1]["response_status"], 200);

        let server_info_unavailable = BlueBubblesLoopback::spawn(
            "server-info-unavailable",
            vec![
                LoopbackResponse::json(503, &json!({"error": "server info temporarily down"})),
                LoopbackResponse::json(
                    200,
                    &json!({
                        "status": 200,
                        "message": "Message sent!",
                        "data": {
                            "guid": "msg-timeout-fallback",
                            "text": "hello from fcp",
                            "is_from_me": true,
                            "attachments": []
                        }
                    }),
                ),
            ],
        );
        let unavailable_result = invoke_send_against_loopback(server_info_unavailable.uri(), None)
            .await
            .expect("send should preserve apple-script fallback when server info is unavailable");
        assert_eq!(unavailable_result["send_method"], "apple-script");
        assert_eq!(
            unavailable_result["send_method_decision"]["reason"],
            "server_info_unavailable_apple_script_fallback"
        );
        let (_, unavailable_logs) = server_info_unavailable.finish();
        assert_eq!(unavailable_logs.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_loopback_adds_reply_and_effect_only_with_private_api() {
        let server = BlueBubblesLoopback::spawn(
            "rich-send-private-api",
            vec![
                LoopbackResponse::json(
                    200,
                    &json!({
                        "data": {
                            "os_version": "15.7",
                            "server_version": "1.9.0",
                            "private_api": true
                        }
                    }),
                ),
                LoopbackResponse::json(
                    200,
                    &json!({
                        "status": 200,
                        "message": "Message sent!",
                        "data": {
                            "guid": "msg-rich-send",
                            "text": "reply with confetti",
                            "is_from_me": true,
                            "attachments": []
                        }
                    }),
                ),
            ],
        );

        let result = invoke_against_loopback(
            server.uri(),
            OP_SEND_MESSAGE,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "message": "reply with confetti",
                "reply_to_message_guid": "reply-guid-123",
                "reply_to_part_index": 1,
                "effect_id": "invisible ink"
            }),
            None,
        )
        .await
        .expect("rich send should succeed with Private API");
        assert_eq!(result["send_method"], "private-api");
        assert_eq!(
            result["send_method_decision"]["reason"],
            "rich_send_private_api_available"
        );

        let (requests, logs) = server.finish();
        assert_eq!(requests.len(), 2);
        let send_body = requests[1].json_body();
        assert_eq!(send_body["method"], "private-api");
        assert_eq!(send_body["selectedMessageGuid"], "reply-guid-123");
        assert_eq!(send_body["partIndex"], 1);
        assert_eq!(
            send_body["effectId"],
            "com.apple.MobileSMS.expressivesend.invisibleink"
        );
        assert!(
            logs.iter().all(|entry| entry["target"]
                .as_str()
                .is_some_and(|target| !target.contains("test-password-123"))),
            "rich-send loopback transcript must redact the passcode"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn send_media_loopback_uploads_sanitized_multipart_with_private_api_reply() {
        let root = unique_media_root();
        let media_path = write_media_fixture(&root, MediaFixtureName::Photo, b"fake-png-media");
        let server = BlueBubblesLoopback::spawn(
            "media-private-api",
            vec![
                LoopbackResponse::json(
                    200,
                    &json!({
                        "data": {
                            "os_version": "15.7",
                            "server_version": "1.9.0",
                            "private_api": true
                        }
                    }),
                ),
                LoopbackResponse::json(
                    200,
                    &json!({
                        "data": {
                            "guid": "media-msg-1"
                        }
                    }),
                ),
            ],
        );

        let result = invoke_against_loopback_with_config(
            loopback_media_config(server.uri(), &root, 1024),
            OP_SEND_MEDIA,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "local_path": media_path.to_string_lossy().to_string(),
                "filename": "../bad\"\nname.png",
                "caption": "caption for media",
                "reply_to_message_guid": "reply-guid-123",
                "reply_to_part_index": 2
            }),
        )
        .await
        .expect("media send should succeed with configured root and Private API");
        assert_eq!(result["status"], "sent");
        assert_eq!(result["action"], "send_media");
        assert_eq!(result["message_id"], "media-msg-1");
        assert_eq!(result["filename"], "bad__name.png");
        assert_eq!(result["content_type"], "image/png");
        assert_eq!(result["byte_len"], 14);
        assert_eq!(
            result["media_send_decision"]["request_method"],
            "private-api"
        );
        assert_eq!(
            result["media_send_decision"]["reason"],
            "media_reply_private_api_available"
        );

        let (requests, logs) = server.finish();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[1].target.split_once('?').map(|(path, _)| path),
            Some("/api/v1/message/attachment")
        );
        assert!(target_has_query_key(&requests[1].target, "password"));
        assert!(
            requests[1]
                .headers
                .get("content-type")
                .is_some_and(|value| value.starts_with("multipart/form-data; boundary="))
        );
        let multipart_body = String::from_utf8_lossy(&requests[1].body);
        assert!(multipart_body.contains("name=\"attachment\""));
        assert!(multipart_body.contains("filename=\"bad__name.png\""));
        assert!(multipart_body.contains("name=\"chatGuid\""));
        assert!(multipart_body.contains("iMessage;-;+15551234567"));
        assert!(multipart_body.contains("name=\"method\""));
        assert!(multipart_body.contains("private-api"));
        assert!(multipart_body.contains("name=\"selectedMessageGuid\""));
        assert!(multipart_body.contains("reply-guid-123"));
        assert!(multipart_body.contains("name=\"partIndex\""));
        assert!(multipart_body.contains("\r\n2\r\n"));
        assert!(multipart_body.contains("name=\"caption\""));
        assert!(multipart_body.contains("caption for media"));
        assert!(!multipart_body.contains("test-password-123"));
        assert!(
            logs.iter().all(|entry| entry["target"]
                .as_str()
                .is_some_and(|target| !target.contains("test-password-123"))),
            "media loopback transcript must redact the passcode"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn send_media_loopback_denies_reply_when_private_api_disabled() {
        let root = unique_media_root();
        let media_path = write_media_fixture(&root, MediaFixtureName::Photo, b"fake-png-media");
        let server = BlueBubblesLoopback::spawn(
            "media-private-api-disabled",
            vec![LoopbackResponse::json(
                200,
                &json!({
                    "data": {
                        "os_version": "15.7",
                        "server_version": "1.9.0",
                        "private_api": false
                    }
                }),
            )],
        );

        let error = invoke_against_loopback_with_config(
            loopback_media_config(server.uri(), &root, 1024),
            OP_SEND_MEDIA,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "local_path": media_path.to_string_lossy().to_string(),
                "reply_to_message_guid": "reply-guid-123"
            }),
        )
        .await
        .expect_err("reply media send should fail closed when Private API is disabled");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
        let (requests, _) = server.finish();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].target.starts_with("/api/v1/server/info?"));
    }

    #[fcp_async_core::runtime::test]
    async fn send_media_rejects_unconfigured_outside_and_oversized_before_network() {
        let root = unique_media_root();
        let media_path = write_media_fixture(&root, MediaFixtureName::Photo, b"fake-png-media");
        let no_roots = BlueBubblesLoopback::spawn("media-no-roots", Vec::new());
        let no_roots_error = invoke_against_loopback_with_config(
            loopback_config(no_roots.uri()),
            OP_SEND_MEDIA,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "local_path": media_path.to_string_lossy().to_string()
            }),
        )
        .await
        .expect_err("media send should require configured local roots");
        assert!(matches!(no_roots_error, FcpError::InvalidRequest { .. }));
        let (requests, _) = no_roots.finish();
        assert!(requests.is_empty());

        let allowed_root = unique_media_root();
        let outside_root = unique_media_root();
        let outside_path =
            write_media_fixture(&outside_root, MediaFixtureName::Photo, b"fake-png-media");
        let outside = BlueBubblesLoopback::spawn("media-outside-root", Vec::new());
        let outside_error = invoke_against_loopback_with_config(
            loopback_media_config(outside.uri(), &allowed_root, 1024),
            OP_SEND_MEDIA,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "local_path": outside_path.to_string_lossy().to_string()
            }),
        )
        .await
        .expect_err("media send should reject files outside configured roots");
        assert!(matches!(outside_error, FcpError::InvalidRequest { .. }));
        let (requests, _) = outside.finish();
        assert!(requests.is_empty());

        let small = BlueBubblesLoopback::spawn("media-too-large", Vec::new());
        let too_large_error = invoke_against_loopback_with_config(
            loopback_media_config(small.uri(), &root, 4),
            OP_SEND_MEDIA,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "local_path": write_media_fixture(&root, MediaFixtureName::Large, b"fake-png-media").to_string_lossy().to_string()
            }),
        )
        .await
        .expect_err("media send should reject oversized files before upload");
        assert!(matches!(too_large_error, FcpError::InvalidRequest { .. }));
        let (requests, _) = small.finish();
        assert!(requests.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_loopback_denies_rich_send_when_private_api_disabled_or_unknown() {
        let disabled = BlueBubblesLoopback::spawn(
            "rich-send-private-api-disabled",
            vec![LoopbackResponse::json(
                200,
                &json!({
                    "data": {
                        "os_version": "26.0",
                        "server_version": "1.9.0",
                        "private_api": false
                    }
                }),
            )],
        );
        let disabled_error = invoke_against_loopback(
            disabled.uri(),
            OP_SEND_MESSAGE,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "message": "reply denied",
                "reply_to_message_guid": "reply-guid-123"
            }),
            None,
        )
        .await
        .expect_err("reply threading should fail closed when Private API is disabled");
        assert!(matches!(disabled_error, FcpError::InvalidRequest { .. }));
        let (disabled_requests, _) = disabled.finish();
        assert_eq!(disabled_requests.len(), 1);

        let unknown = BlueBubblesLoopback::spawn(
            "rich-send-private-api-unknown",
            vec![LoopbackResponse::json(
                503,
                &json!({"error": "server info temporarily unavailable"}),
            )],
        );
        let unknown_error = invoke_against_loopback(
            unknown.uri(),
            OP_SEND_MESSAGE,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "message": "effect denied",
                "effect_id": "confetti"
            }),
            None,
        )
        .await
        .expect_err("message effects should fail closed when Private API status is unknown");
        assert!(matches!(unknown_error, FcpError::InvalidRequest { .. }));
        let (unknown_requests, _) = unknown.finish();
        assert_eq!(unknown_requests.len(), 1);

        let auth_failure = BlueBubblesLoopback::spawn(
            "rich-send-server-info-auth-failure",
            vec![LoopbackResponse::json(
                401,
                &json!({"error": "bad password"}),
            )],
        );
        let auth_error = invoke_against_loopback(
            auth_failure.uri(),
            OP_SEND_MESSAGE,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "message": "reply auth denied",
                "reply_to_message_guid": "reply-guid-123"
            }),
            None,
        )
        .await
        .expect_err("server-info auth failure should remain Unauthorized");
        assert!(matches!(auth_error, FcpError::Unauthorized { .. }));
        let (auth_requests, _) = auth_failure.finish();
        assert_eq!(auth_requests.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn resolve_send_target_loopback_preserves_service_intent_and_rejects_group_participant() {
        let service_server = BlueBubblesLoopback::spawn(
            "resolve-target-service-order",
            vec![LoopbackResponse::json(
                200,
                &json!({
                    "data": [
                        {
                            "id": 1,
                            "guid": "iMessage;-;+15551234567",
                            "participants": [{ "address": "+15551234567" }]
                        },
                        {
                            "id": 2,
                            "guid": "SMS;-;+15551234567",
                            "participants": [{ "address": "+15551234567" }]
                        }
                    ]
                }),
            )],
        );
        let sms_result = invoke_against_loopback(
            service_server.uri(),
            OP_RESOLVE_SEND_TARGET,
            json!({
                "handle": "+15551234567",
                "service": "sms"
            }),
            None,
        )
        .await
        .expect("target resolution should succeed");
        assert_eq!(sms_result["chat_guid"], "SMS;-;+15551234567");
        assert_eq!(sms_result["match_kind"], "direct_preferred_service");
        assert_eq!(sms_result["service_preference"], "sms");
        let (service_requests, _) = service_server.finish();
        assert_eq!(service_requests[0].json_body()["with"][0], "participants");

        let group_server = BlueBubblesLoopback::spawn(
            "resolve-target-group-participant-only",
            vec![LoopbackResponse::json(
                200,
                &json!({
                    "data": [
                        {
                            "id": 3,
                            "guid": "iMessage;+;family-group",
                            "participants": [
                                { "address": "+15551234567" },
                                { "address": "+15557654321" }
                            ]
                        }
                    ]
                }),
            )],
        );
        let group_result = invoke_against_loopback(
            group_server.uri(),
            OP_RESOLVE_SEND_TARGET,
            json!({
                "handle": "+15551234567",
                "service": "imessage"
            }),
            None,
        )
        .await
        .expect("target resolution should return deterministic not_found");
        assert!(group_result["chat_guid"].is_null());
        assert_eq!(group_result["match_kind"], "not_found");
        let (group_requests, _) = group_server.finish();
        assert_eq!(group_requests.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn resolve_send_target_loopback_bounds_paginated_chat_queries() {
        let first_page = (0..500)
            .map(|idx| {
                json!({
                    "id": idx,
                    "guid": format!("iMessage;-;+1555000{idx:03}"),
                    "participants": []
                })
            })
            .collect::<Vec<_>>();
        let server = BlueBubblesLoopback::spawn(
            "resolve-target-pagination-bounds",
            vec![
                LoopbackResponse::json(200, &json!({ "data": first_page })),
                LoopbackResponse::json(200, &json!({ "data": [] })),
            ],
        );
        let result = invoke_against_loopback(
            server.uri(),
            OP_RESOLVE_SEND_TARGET,
            json!({
                "chat_id": 9999,
                "scan_limit": 750
            }),
            None,
        )
        .await
        .expect("bounded target resolution should succeed");
        assert!(result["chat_guid"].is_null());
        assert_eq!(result["scanned_chats"], 500);
        assert_eq!(result["scanned_pages"], 2);

        let (requests, _) = server.finish();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].json_body()["limit"], 500);
        assert_eq!(requests[0].json_body()["offset"], 0);
        assert_eq!(requests[1].json_body()["limit"], 250);
        assert_eq!(requests[1].json_body()["offset"], 500);
    }

    #[fcp_async_core::runtime::test]
    async fn create_chat_loopback_requires_private_api_and_uses_chat_new() {
        let server = BlueBubblesLoopback::spawn(
            "create-chat-private-api",
            vec![
                LoopbackResponse::json(
                    200,
                    &json!({
                        "data": {
                            "os_version": "15.7",
                            "server_version": "1.9.0",
                            "private_api": true
                        }
                    }),
                ),
                LoopbackResponse::json(
                    200,
                    &json!({
                        "data": {
                            "chatGuid": "iMessage;-;+15550008888",
                            "messageGuid": "msg-new-chat"
                        }
                    }),
                ),
            ],
        );
        let result = invoke_against_loopback(
            server.uri(),
            OP_CREATE_CHAT,
            json!({
                "address": "+15550008888",
                "message": "hello new chat"
            }),
            None,
        )
        .await
        .expect("create chat should succeed with Private API");
        assert_eq!(result["chat_guid"], "iMessage;-;+15550008888");
        assert_eq!(result["message_id"], "msg-new-chat");
        assert_eq!(result["send_method"], "private-api");

        let (requests, _) = server.finish();
        assert_eq!(
            requests[1].target.split_once('?').map(|(path, _)| path),
            Some("/api/v1/chat/new")
        );
        let create_body = requests[1].json_body();
        assert_eq!(create_body["addresses"][0], "+15550008888");
        assert_eq!(create_body["message"], "hello new chat");

        let disabled = BlueBubblesLoopback::spawn(
            "create-chat-private-api-disabled",
            vec![LoopbackResponse::json(
                200,
                &json!({
                    "data": {
                        "os_version": "15.7",
                        "server_version": "1.9.0",
                        "private_api": false
                    }
                }),
            )],
        );
        let disabled_error = invoke_against_loopback(
            disabled.uri(),
            OP_CREATE_CHAT,
            json!({
                "address": "+15550008888",
                "message": "hello new chat"
            }),
            None,
        )
        .await
        .expect_err("create_chat should fail closed when Private API is disabled");
        assert!(matches!(disabled_error, FcpError::InvalidRequest { .. }));
        let (disabled_requests, _) = disabled.finish();
        assert_eq!(disabled_requests.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn private_api_actions_loopback_edit_unsend_reaction_typing_and_read() {
        let available_info = || {
            LoopbackResponse::json(
                200,
                &json!({
                    "data": {
                        "os_version": "15.7",
                        "server_version": "1.9.0",
                        "private_api": true,
                        "helper_connected": true
                    }
                }),
            )
        };
        let action_ok = || LoopbackResponse::json(200, &json!({ "ok": true }));
        let server = BlueBubblesLoopback::spawn(
            "private-api-actions",
            vec![
                available_info(),
                action_ok(),
                available_info(),
                action_ok(),
                available_info(),
                action_ok(),
                available_info(),
                action_ok(),
                available_info(),
                action_ok(),
                available_info(),
                action_ok(),
            ],
        );

        let edit = invoke_against_loopback(
            server.uri(),
            OP_EDIT_MESSAGE,
            json!({
                "message_guid": "msg-edit",
                "new_text": "edited text",
                "backwards_compatibility_message": "edited fallback",
                "part_index": 2
            }),
            None,
        )
        .await
        .expect("edit should succeed when the action gate is available");
        assert_eq!(edit["status"], "edited");

        let unsend = invoke_against_loopback(
            server.uri(),
            OP_UNSEND_MESSAGE,
            json!({
                "message_guid": "msg-unsend",
                "part_index": 1
            }),
            None,
        )
        .await
        .expect("unsend should succeed when the action gate is available");
        assert_eq!(unsend["status"], "unsent");

        let reaction = invoke_against_loopback(
            server.uri(),
            OP_SEND_REACTION,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "message_guid": "msg-react",
                "reaction": "thumbs up",
                "remove": true,
                "part_index": 3
            }),
            None,
        )
        .await
        .expect("tapback reaction should succeed when the action gate is available");
        assert_eq!(reaction["reaction"], "-like");

        let typing_started = invoke_against_loopback(
            server.uri(),
            OP_SET_TYPING,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "typing": true
            }),
            None,
        )
        .await
        .expect("typing start should succeed when the action gate is available");
        assert_eq!(typing_started["status"], "typing_started");

        let typing_stopped = invoke_against_loopback(
            server.uri(),
            OP_SET_TYPING,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "typing": false
            }),
            None,
        )
        .await
        .expect("typing stop should succeed when the action gate is available");
        assert_eq!(typing_stopped["status"], "typing_stopped");

        let mark_read = invoke_against_loopback(
            server.uri(),
            OP_MARK_READ,
            json!({ "chat_guid": "iMessage;-;+15551234567" }),
            None,
        )
        .await
        .expect("mark_read should succeed when the action gate is available");
        assert_eq!(mark_read["status"], "marked_read");

        let (requests, logs) = server.finish();
        assert_eq!(requests.len(), 12);
        assert_eq!(
            requests[1].target.split_once('?').map(|(path, _)| path),
            Some("/api/v1/message/msg-edit/edit")
        );
        let edit_body = requests[1].json_body();
        assert_eq!(edit_body["editedMessage"], "edited text");
        assert_eq!(
            edit_body["backwardsCompatibilityMessage"],
            "edited fallback"
        );
        assert_eq!(edit_body["partIndex"], 2);

        assert_eq!(
            requests[3].target.split_once('?').map(|(path, _)| path),
            Some("/api/v1/message/msg-unsend/unsend")
        );
        assert_eq!(requests[3].json_body()["partIndex"], 1);

        assert_eq!(
            requests[5].target.split_once('?').map(|(path, _)| path),
            Some("/api/v1/message/react")
        );
        let reaction_body = requests[5].json_body();
        assert_eq!(reaction_body["chatGuid"], "iMessage;-;+15551234567");
        assert_eq!(reaction_body["selectedMessageGuid"], "msg-react");
        assert_eq!(reaction_body["reaction"], "-like");
        assert_eq!(reaction_body["partIndex"], 3);

        assert_eq!(requests[7].method, "POST");
        assert_eq!(
            requests[7].target.split_once('?').map(|(path, _)| path),
            Some("/api/v1/chat/iMessage;-;+15551234567/typing")
        );
        assert_eq!(requests[9].method, "DELETE");
        assert_eq!(
            requests[9].target.split_once('?').map(|(path, _)| path),
            Some("/api/v1/chat/iMessage;-;+15551234567/typing")
        );
        assert_eq!(
            requests[11].target.split_once('?').map(|(path, _)| path),
            Some("/api/v1/chat/iMessage;-;+15551234567/read")
        );
        assert!(
            logs.iter().all(|entry| entry["target"]
                .as_str()
                .is_some_and(|target| !target.contains("test-password-123"))),
            "private action loopback transcript must redact the passcode"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn private_api_actions_fail_closed_when_disabled_unknown_or_macos26_edit() {
        let disabled = BlueBubblesLoopback::spawn(
            "private-actions-disabled",
            vec![LoopbackResponse::json(
                200,
                &json!({
                    "data": {
                        "os_version": "15.7",
                        "server_version": "1.9.0",
                        "private_api": false,
                        "helper_connected": true
                    }
                }),
            )],
        );
        let disabled_error = invoke_against_loopback(
            disabled.uri(),
            OP_SEND_REACTION,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "message_guid": "msg-react",
                "reaction": "like"
            }),
            None,
        )
        .await
        .expect_err("reaction should fail closed when Private API is disabled");
        assert!(matches!(disabled_error, FcpError::InvalidRequest { .. }));
        let (disabled_requests, _) = disabled.finish();
        assert_eq!(disabled_requests.len(), 1);

        let unknown = BlueBubblesLoopback::spawn(
            "private-actions-server-info-unknown",
            vec![LoopbackResponse::json(
                503,
                &json!({"error": "server info temporarily unavailable"}),
            )],
        );
        let unknown_error = invoke_against_loopback(
            unknown.uri(),
            OP_SET_TYPING,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "typing": true
            }),
            None,
        )
        .await
        .expect_err("typing should fail closed when server info is unavailable");
        assert!(matches!(unknown_error, FcpError::InvalidRequest { .. }));
        let (unknown_requests, _) = unknown.finish();
        assert_eq!(unknown_requests.len(), 1);

        let macos26 = BlueBubblesLoopback::spawn(
            "private-actions-macos26-edit",
            vec![LoopbackResponse::json(
                200,
                &json!({
                    "data": {
                        "os_version": "26.0",
                        "server_version": "1.9.0",
                        "private_api": true,
                        "helper_connected": true
                    }
                }),
            )],
        );
        let macos26_error = invoke_against_loopback(
            macos26.uri(),
            OP_EDIT_MESSAGE,
            json!({
                "message_guid": "msg-edit",
                "new_text": "edited text"
            }),
            None,
        )
        .await
        .expect_err("edit should fail closed on macOS 26+");
        assert!(matches!(macos26_error, FcpError::InvalidRequest { .. }));
        let (macos26_requests, _) = macos26.finish();
        assert_eq!(macos26_requests.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn get_action_availability_loopback_reports_dynamic_status() {
        let server = BlueBubblesLoopback::spawn(
            "private-actions-availability",
            vec![LoopbackResponse::json(
                200,
                &json!({
                    "data": {
                        "os_version": "26.0",
                        "server_version": "1.9.0",
                        "private_api": true,
                        "helper_connected": true
                    }
                }),
            )],
        );
        let result =
            invoke_against_loopback(server.uri(), OP_GET_ACTION_AVAILABILITY, json!({}), None)
                .await
                .expect("availability should return a dynamic status object");
        assert_eq!(result["server_info_available"], true);
        assert_eq!(result["private_api"], true);
        assert_eq!(result["helper_connected"], true);
        assert_eq!(result["edit"]["supported"], false);
        assert_eq!(result["edit"]["reason"], "macos26_edit_unsupported");
        assert_eq!(result["unsend"]["supported"], true);
        assert_eq!(result["typing"]["reason"], "private_api_supported");
        let (requests, _) = server.finish();
        assert_eq!(requests.len(), 1);
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 21);
    }

    #[test]
    fn test_manifest_operations_match_catalog_for_imessage_and_bluebubbles() {
        const BLUEBUBBLES_MANIFEST_TOML: &str = include_str!("../../bluebubbles/manifest.toml");
        let manifests = [
            ("imessage", MANIFEST_TOML),
            ("bluebubbles", BLUEBUBBLES_MANIFEST_TOML),
        ];

        for op in operations_info() {
            let suffix = op.id.as_str().strip_prefix("imessage.").unwrap();
            let section = format!("[provides.operations.{suffix}]");
            for (name, manifest) in manifests {
                assert!(
                    manifest.contains(&section),
                    "{name} manifest is missing {section}"
                );
            }
        }
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_send_message_is_risky() {
        let ops = operations_info();
        let send = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SEND_MESSAGE)
            .unwrap();
        assert_eq!(send.safety_tier, SafetyTier::Risky);
        assert_eq!(send.idempotency, IdempotencyClass::None);
        assert_eq!(send.capability, CapabilityId::from_static(CAP_SEND));
        assert!(send.input_schema["properties"]["reply_to_message_guid"].is_object());
        assert!(send.input_schema["properties"]["reply_to_part_index"].is_object());
        assert!(send.input_schema["properties"]["effect_id"].is_object());
    }

    #[test]
    fn test_send_media_is_bounded_risky_send_operation() {
        let ops = operations_info();
        let send_media = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SEND_MEDIA)
            .unwrap();
        assert_eq!(send_media.capability, CapabilityId::from_static(CAP_SEND));
        assert_eq!(send_media.safety_tier, SafetyTier::Risky);
        assert_eq!(send_media.idempotency, IdempotencyClass::None);
        assert!(send_media.input_schema["properties"]["local_path"].is_object());
        assert!(send_media.input_schema["properties"]["content_type"].is_object());
        assert!(send_media.input_schema["properties"]["reply_to_message_guid"].is_object());
        assert!(
            send_media
                .ai_hints
                .common_mistakes
                .iter()
                .any(|hint| hint.contains("media_send.local_roots"))
        );
    }

    #[test]
    fn test_rich_send_parity_operations_are_explicitly_cataloged() {
        let ops = operations_info();
        let resolve = ops
            .iter()
            .find(|op| op.id.as_str() == OP_RESOLVE_SEND_TARGET)
            .unwrap();
        assert_eq!(resolve.capability, CapabilityId::from_static(CAP_READ));
        assert_eq!(resolve.safety_tier, SafetyTier::Safe);
        assert!(resolve.input_schema["properties"]["service"].is_object());

        let create = ops
            .iter()
            .find(|op| op.id.as_str() == OP_CREATE_CHAT)
            .unwrap();
        assert_eq!(create.capability, CapabilityId::from_static(CAP_SEND));
        assert_eq!(create.safety_tier, SafetyTier::Risky);
        assert_eq!(create.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_private_api_action_operations_are_explicitly_cataloged() {
        let ops = operations_info();
        let expected = [
            (
                OP_GET_ACTION_AVAILABILITY,
                CAP_ADMIN,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
            ),
            (
                OP_EDIT_MESSAGE,
                CAP_SEND,
                SafetyTier::Risky,
                IdempotencyClass::None,
            ),
            (
                OP_UNSEND_MESSAGE,
                CAP_SEND,
                SafetyTier::Dangerous,
                IdempotencyClass::None,
            ),
            (
                OP_SEND_REACTION,
                CAP_SEND,
                SafetyTier::Risky,
                IdempotencyClass::BestEffort,
            ),
            (
                OP_SET_TYPING,
                CAP_SEND,
                SafetyTier::Safe,
                IdempotencyClass::BestEffort,
            ),
        ];

        for (operation_id, capability, safety_tier, idempotency) in expected {
            let op = ops
                .iter()
                .find(|op| op.id.as_str() == operation_id)
                .unwrap();
            assert_eq!(op.capability.as_str(), capability);
            assert_eq!(op.safety_tier, safety_tier);
            assert_eq!(op.idempotency, idempotency);
        }
    }

    #[test]
    fn test_get_chats_is_safe() {
        let ops = operations_info();
        let chats = ops
            .iter()
            .find(|op| op.id.as_str() == OP_GET_CHATS)
            .unwrap();
        assert_eq!(chats.safety_tier, SafetyTier::Safe);
        assert_eq!(chats.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_download_attachment_is_safe() {
        let ops = operations_info();
        let download = ops
            .iter()
            .find(|op| op.id.as_str() == OP_DOWNLOAD_ATTACHMENT)
            .unwrap();
        assert_eq!(download.safety_tier, SafetyTier::Safe);
        assert_eq!(download.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_sync_events_is_safe() {
        let ops = operations_info();
        let sync = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SYNC_EVENTS)
            .unwrap();
        assert_eq!(sync.safety_tier, SafetyTier::Safe);
        assert_eq!(sync.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_mark_read_is_best_effort() {
        let ops = operations_info();
        let mark = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MARK_READ)
            .unwrap();
        assert_eq!(mark.safety_tier, SafetyTier::Safe);
        assert_eq!(mark.idempotency, IdempotencyClass::BestEffort);
    }

    #[test]
    fn test_webhook_register_is_risky_best_effort() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_REGISTER_WEBHOOK)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.idempotency, IdempotencyClass::BestEffort);
    }

    #[test]
    fn test_webhook_operations_pin_catalog_contract_and_redaction() {
        let ops = operations_info();
        let expected = [
            (
                OP_REGISTER_WEBHOOK,
                CAP_ADMIN,
                SafetyTier::Risky,
                IdempotencyClass::BestEffort,
            ),
            (
                OP_LIST_WEBHOOKS,
                CAP_ADMIN,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
            ),
            (
                OP_UNREGISTER_WEBHOOK,
                CAP_ADMIN,
                SafetyTier::Risky,
                IdempotencyClass::BestEffort,
            ),
            (
                OP_INGEST_WEBHOOK_EVENT,
                CAP_READ,
                SafetyTier::Safe,
                IdempotencyClass::BestEffort,
            ),
            (
                OP_INGEST_WEBHOOK_REQUEST,
                CAP_READ,
                SafetyTier::Safe,
                IdempotencyClass::BestEffort,
            ),
        ];

        for (operation_id, capability, safety_tier, idempotency) in expected {
            let op = ops
                .iter()
                .find(|op| op.id.as_str() == operation_id)
                .unwrap();
            assert_eq!(op.capability.as_str(), capability);
            assert_eq!(op.safety_tier, safety_tier);
            assert_eq!(op.idempotency, idempotency);
            assert!(
                op.ai_hints
                    .examples
                    .iter()
                    .all(|example| !example.contains(&format!("{}=", "password"))),
                "{operation_id} examples must not leak callback auth query strings"
            );
        }

        let config = BlueBubblesConfig::from_value(json!({
            "password": "test-password-123"
        }))
        .unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("test-password-123"));
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let connector = BlueBubblesConnector::new();
        let hash1 = connector.manifest_hash();
        let hash2 = connector.manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_webhook_streaming_caps_advertised() {
        let connector = BlueBubblesConnector::new();
        let intro = connector.introspect();
        let caps = intro.event_caps.as_ref().unwrap();
        assert!(caps.streaming);
        assert!(caps.replay);
        assert_eq!(caps.min_buffer_events, WEBHOOK_EVENT_BUFFER_MIN_EVENTS);
        assert!(!caps.requires_ack);
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let req = ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1000,
            drain: false,
            reason: Some("test".into()),
        };
        let result = connector.shutdown(req).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_default_impl() {
        let connector = BlueBubblesConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.imessage");
    }

    #[test]
    fn test_custom_connector_id() {
        let connector = BlueBubblesConnector::with_connector_id("fcp.bluebubbles");
        assert_eq!(connector.id().as_str(), "fcp.bluebubbles");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_get_messages_missing_chat_guid() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_GET_MESSAGES);
        req.input = json!({ "limit": 10 }); // missing chat_guid
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_mark_read_missing_chat_guid() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_MARK_READ);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_get_chat_missing_chat_guid() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_GET_CHAT);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_download_attachment_missing_attachment_guid() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_DOWNLOAD_ATTACHMENT);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_sync_events_single_chat() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/chat/chat-guid-1/message"))
            .and(query_param("password", "test-password-123"))
            .and(query_param("after", "1700000000000"))
            .and(query_param("limit", "10"))
            .and(query_param("sort", "ASC"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 10,
                "data": [
                    {
                        "guid": "msg-001",
                        "text": "hello from bridge",
                        "date_created": 1_700_000_000_100_i64,
                        "is_from_me": false,
                        "handle": {
                            "address": "+15551234567",
                            "display_name": "Alice"
                        },
                        "thread_originator_guid": "root-1",
                        "attachments": []
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_url(&mock_server.uri()))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut handshake = base_handshake();
        handshake.host_public_key = verifying_key.to_bytes();
        connector.handshake(handshake).await.unwrap();

        let req = InvokeRequest {
            input: json!({
                "chat_guid": "chat-guid-1",
                "after": 1_700_000_000_000_i64,
                "message_limit": 10
            }),
            capability_token: generate_valid_token(&connector, &signing_key, OP_SYNC_EVENTS),
            ..base_invoke(connector.id(), OP_SYNC_EVENTS)
        };

        let response = connector.invoke(req).await.unwrap();
        let result = response.result.as_ref().unwrap();
        let events = result["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["topic"], "imessage.message.inbound");
        assert_eq!(events[0]["chat_guid"], "chat-guid-1");
        assert_eq!(events[0]["thread"]["thread_originator_guid"], "root-1");
        assert_eq!(result["next_after"], 1_700_000_000_101_i64);
        assert_eq!(result["synced_chats"], 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_dedupes_replay() {
        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_webhook_inbound(None))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let input = json!({
            "account_id": "acct-a",
            "payload": {
                "type": "new-message",
                "data": {
                    "guid": "msg-1",
                    "text": "hello",
                    "handle": { "address": "+15551234567" },
                    "chats": [{ "guid": "iMessage;-;+15551234567" }],
                    "attachments": [{ "guid": "att-1", "mimeType": "image/png" }],
                    "isFromMe": false
                }
            }
        });
        let req = InvokeRequest {
            input: input.clone(),
            capability_token: generate_valid_token(
                &connector,
                &signing_key,
                OP_INGEST_WEBHOOK_EVENT,
            ),
            correlation_id: Some(CorrelationId::new()),
            ..base_invoke(connector.id(), OP_INGEST_WEBHOOK_EVENT)
        };
        let first = connector.invoke(req).await.unwrap();
        let first_result = first.result.as_ref().unwrap();
        assert_eq!(first_result["status"], "accepted");
        assert_eq!(first_result["dedupe_id"], "acct-a:msg-1");
        assert_eq!(first_result["dedupe_ids"], json!(["acct-a:msg-1"]));
        assert_eq!(first_result["acceptance"]["reason"], "sender_allowed");
        assert_eq!(first_result["policy"]["allowed_sender_count"], 1);
        assert_eq!(first_result["event"]["event_type"], "new-message");
        assert_eq!(first_result["event"]["event_id"], "msg-1");
        assert_eq!(
            first_result["event"]["chat_guid"],
            "iMessage;-;+15551234567"
        );
        assert_eq!(first_result["event"]["sender_id"], "+15551234567");
        assert_eq!(first_result["event"]["topic"], "imessage.message.inbound");
        assert_eq!(first_result["event"]["is_from_me"], false);
        assert_eq!(first_result["event"]["is_group"], false);
        assert_eq!(first_result["event"]["attachments"][0]["guid"], "att-1");
        assert_eq!(
            first_result["event"]["attachments"][0]["mime_type"],
            "image/png"
        );
        let envelopes = first_result["event_envelopes"].as_array().unwrap();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0]["topic"], "imessage.message.inbound");
        assert_eq!(envelopes[0]["seq"], 0);
        assert_eq!(envelopes[0]["cursor"], "0");
        assert_eq!(
            envelopes[0]["stream_key"],
            "bluebubbles:acct-a:chat:iMessage;-;+15551234567"
        );
        assert_eq!(envelopes[0]["ordering"], "per_key");
        assert_eq!(envelopes[0]["data"]["zone_id"], "z:work");
        assert_eq!(envelopes[0]["data"]["payload"]["event_id"], "msg-1");
        assert!(envelopes[0]["data"]["correlation_id"].as_str().is_some());

        let subscribe = connector
            .subscribe(SubscribeRequest {
                r#type: "subscribe".into(),
                id: RequestId::new("sub_1"),
                topics: vec!["imessage.message.inbound".to_string()],
                since: None,
                max_events_per_sec: None,
                batch_ms: None,
                window_size: None,
                capability_token: None,
            })
            .await
            .unwrap();
        assert_eq!(
            subscribe.result.confirmed_topics,
            vec!["imessage.message.inbound".to_string()]
        );
        assert!(subscribe.result.replay_supported);
        assert_eq!(
            subscribe.result.cursors.get("imessage.message.inbound"),
            Some(&"0".to_string())
        );

        let req = InvokeRequest {
            input,
            capability_token: generate_valid_token(
                &connector,
                &signing_key,
                OP_INGEST_WEBHOOK_EVENT,
            ),
            ..base_invoke(connector.id(), OP_INGEST_WEBHOOK_EVENT)
        };
        let second = connector.invoke(req).await.unwrap();
        let second_result = second.result.as_ref().unwrap();
        assert_eq!(second_result["status"], "duplicate");
        assert_eq!(second_result["duplicate_id"], "acct-a:msg-1");
        assert_eq!(second_result["event_envelopes"], json!([]));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_request_authenticates_and_fans_out() {
        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_webhook_inbound(None))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let input = json!({
            "method": "POST",
            "url": webhook_callback_url("test-password-123"),
            "headers": { "x-bluebubbles-event": "new-message" },
            "request_region": { "source": "loopback_harness" },
            "account_id": "acct-a",
            "observed_at_ms": 1_700_000_000_000_i64,
            "body": {
                "type": "new-message",
                "data": {
                    "guid": "msg-request-1",
                    "text": "hello",
                    "handle": { "address": "+15551234567" },
                    "chats": [{ "guid": "iMessage;-;+15551234567" }],
                    "isFromMe": false
                }
            }
        });
        let first = invoke_webhook_request_result(&connector, &signing_key, input.clone()).await;
        assert_eq!(first["accepted"], true);
        assert_eq!(first["status_code"], 200);
        assert_eq!(first["reason_code"], "event_accepted");
        assert_eq!(first["ingest"]["status"], "accepted");
        assert_eq!(first["ingest"]["event"]["event_id"], "msg-request-1");
        assert_eq!(
            first["ingest"]["event_envelopes"][0]["topic"],
            "imessage.message.inbound"
        );
        assert_eq!(
            first["request_region"]["surface"],
            "fcp.webhook.request_region"
        );
        assert_eq!(first["request_region"]["source"], "loopback_harness");
        assert_eq!(
            first["service_layers"]["builder"],
            "fcp.webhook.ServiceBuilder"
        );
        assert_eq!(first["service_layers"]["host_enforced"], true);
        assert!(
            !first["request_region"]["url"]
                .as_str()
                .unwrap()
                .contains("test-password-123")
        );
        assert!(
            first["logs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|log| log["reason_code"] == "webhook_auth_validated")
        );

        let second = invoke_webhook_request_result(&connector, &signing_key, input).await;
        assert_eq!(second["accepted"], false);
        assert_eq!(second["status_code"], 409);
        assert_eq!(second["reason_code"], "replay_suppressed");
        assert_eq!(second["ingest"]["status"], "duplicate");
        assert_eq!(second["ingest"]["event_envelopes"], json!([]));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_request_rejects_auth_and_oversized_body() {
        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_webhook_inbound(None))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let body = json!({
            "type": "new-message",
            "data": {
                "guid": "msg-auth-fail",
                "handle": { "address": "+15551234567" },
                "chats": [{ "guid": "iMessage;-;+15551234567" }],
                "isFromMe": false
            }
        });
        let invalid_auth = invoke_webhook_request_result(
            &connector,
            &signing_key,
            json!({
                "method": "POST",
                "url": webhook_callback_url("wrong"),
                "body": body.clone()
            }),
        )
        .await;
        assert_eq!(invalid_auth["accepted"], false);
        assert_eq!(invalid_auth["status_code"], 401);
        assert_eq!(invalid_auth["reason_code"], "invalid_auth");
        assert!(invalid_auth["ingest"].is_null());

        let oversized = invoke_webhook_request_result(
            &connector,
            &signing_key,
            json!({
                "method": "POST",
                "url": webhook_callback_url("test-password-123"),
                "body": body,
                "body_size_bytes": 2048,
                "max_body_bytes": 64
            }),
        )
        .await;
        assert_eq!(oversized["accepted"], false);
        assert_eq!(oversized["status_code"], 413);
        assert_eq!(oversized["reason_code"], "payload_too_large");
        assert!(oversized["ingest"].is_null());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_request_respects_request_region_cancellation() {
        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_webhook_inbound(None))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let input = json!({
            "method": "POST",
            "url": webhook_callback_url("test-password-123"),
            "headers": { "x-bluebubbles-event": "new-message" },
            "account_id": "acct-a",
            "body": {
                "type": "new-message",
                "data": {
                    "guid": "msg-cancellable-request",
                    "text": "held by request region",
                    "handle": { "address": "+15551234567" },
                    "chats": [{ "guid": "iMessage;-;+15551234567" }],
                    "isFromMe": false
                }
            }
        });

        let mut cancelled_input = input.clone();
        cancelled_input["request_region"] = json!({ "cancelled": true });
        let cancelled =
            invoke_webhook_request_result(&connector, &signing_key, cancelled_input).await;
        assert_eq!(cancelled["accepted"], false);
        assert_eq!(cancelled["status_code"], 408);
        assert_eq!(cancelled["reason_code"], "request_cancelled");
        assert!(cancelled["ingest"].is_null());

        let mut deadline_input = input.clone();
        deadline_input["request_region"] = json!({ "deadline_exceeded": true });
        let deadline =
            invoke_webhook_request_result(&connector, &signing_key, deadline_input).await;
        assert_eq!(deadline["accepted"], false);
        assert_eq!(deadline["status_code"], 408);
        assert_eq!(deadline["reason_code"], "request_timeout");
        assert!(deadline["ingest"].is_null());

        let accepted = invoke_webhook_request_result(&connector, &signing_key, input).await;
        assert_eq!(accepted["accepted"], true);
        assert_eq!(accepted["reason_code"], "event_accepted");
        assert_eq!(
            accepted["ingest"]["dedupe_id"],
            "acct-a:msg-cancellable-request"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_request_persists_replay_dedupe_across_restart() {
        let dedupe_path = unique_dedupe_state_path();
        let input = json!({
            "method": "POST",
            "url": webhook_callback_url("test-password-123"),
            "headers": { "x-bluebubbles-event": "new-message" },
            "account_id": "acct-a",
            "body": {
                "type": "new-message",
                "data": {
                    "guid": "msg-request-persistent",
                    "handle": { "address": "+15551234567" },
                    "chats": [{ "guid": "iMessage;-;+15551234567" }],
                    "isFromMe": false
                }
            }
        });

        for (expected_status_code, expected_reason_code) in
            [(200, "event_accepted"), (409, "replay_suppressed")]
        {
            let mut connector = BlueBubblesConnector::new();
            connector
                .configure(test_config_with_webhook_inbound(Some(&dedupe_path)))
                .await
                .unwrap();
            let signing_key = Ed25519SigningKey::generate();
            connector
                .handshake(handshake_for_signing_key(&signing_key))
                .await
                .unwrap();
            let response =
                invoke_webhook_request_result(&connector, &signing_key, input.clone()).await;
            assert_eq!(response["status_code"], expected_status_code);
            assert_eq!(response["reason_code"], expected_reason_code);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_request_policy_rejection_never_emits() {
        let mut connector = BlueBubblesConnector::new();
        connector.configure(test_config()).await.unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let rejected = invoke_webhook_request_result(
            &connector,
            &signing_key,
            json!({
                "method": "POST",
                "url": webhook_callback_url("test-password-123"),
                "headers": { "x-bluebubbles-event": "new-message" },
                "body": {
                    "data": {
                        "guid": "msg-policy-reject",
                        "text": "untrusted",
                        "handle": { "address": "+15551234567" },
                        "chats": [{ "guid": "iMessage;-;+15551234567" }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;
        assert_eq!(rejected["accepted"], false);
        assert_eq!(rejected["status_code"], 403);
        assert_eq!(rejected["reason_code"], "policy_rejected");
        assert_eq!(rejected["ingest"]["status"], "rejected");
        assert_eq!(
            rejected["ingest"]["acceptance"]["reason"],
            "conversation_not_bound"
        );
        assert_eq!(rejected["ingest"]["event_envelopes"], json!([]));
    }

    #[fcp_async_core::runtime::test]
    async fn no_mock_bluebubbles_ingress_loopback_registers_callback_and_exercises_actions() {
        let ingress_listener =
            StdTcpListener::bind("127.0.0.1:0").expect("bind FCP ingress loopback");
        let ingress_base = format!(
            "http://{}",
            ingress_listener
                .local_addr()
                .expect("FCP ingress loopback addr")
        );
        let callback_url = webhook_callback_url_for_base(&ingress_base, "test-password-123");
        let callback_target = callback_target(&callback_url);

        let media_root = unique_media_root();
        let media_path =
            write_media_fixture(&media_root, MediaFixtureName::Photo, b"loopback-media");
        let server_info = || {
            LoopbackResponse::json(
                200,
                &json!({
                    "data": {
                        "os_version": "15.7",
                        "server_version": "1.9.0",
                        "private_api": true,
                        "helper_connected": true
                    }
                }),
            )
        };
        let action_ok = || LoopbackResponse::json(200, &json!({ "ok": true }));
        let bluebubbles = BlueBubblesLoopback::spawn(
            "ingress-loopback-e2e",
            vec![
                LoopbackResponse::json(
                    200,
                    &json!({
                        "data": {
                            "id": "webhook-1",
                            "url": callback_url
                        }
                    }),
                ),
                server_info(),
                action_ok(),
                server_info(),
                LoopbackResponse::json(200, &json!({ "data": { "guid": "media-loopback-1" } })),
                server_info(),
                action_ok(),
                server_info(),
                action_ok(),
            ],
        );

        let mut config = loopback_media_config(bluebubbles.uri(), &media_root, 1024);
        config["webhook_inbound"] = json!({
            "allowed_sender_ids": ["+15551234567"],
            "allowed_chat_guids": ["iMessage;-;+15551234567"]
        });

        let mut connector = BlueBubblesConnector::new();
        connector.configure(config).await.unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let registration = invoke_operation_result(
            &connector,
            &signing_key,
            OP_REGISTER_WEBHOOK,
            json!({
                "url": callback_url,
                "events": ["new-message"],
                "skip_if_existing": false
            }),
        )
        .await;
        assert_eq!(registration["registration_status"], "registered");

        let unauthorized_body = json!({
            "type": "new-message",
            "data": {
                "guid": "msg-loopback-unauthorized",
                "text": "blocked",
                "handle": { "address": "+15557654321" },
                "chats": [{ "guid": "iMessage;-;+15557654321" }],
                "isFromMe": false
            }
        });
        let (unauthorized_request, unauthorized_http, unauthorized_result) =
            drive_ingress_loopback_post(
                &ingress_listener,
                &connector,
                &signing_key,
                callback_target.clone(),
                unauthorized_body,
            )
            .await;
        assert_eq!(unauthorized_http.status, 403);
        assert_eq!(unauthorized_http.body["reason_code"], "policy_rejected");
        assert_eq!(unauthorized_result["ingest"]["event_envelopes"], json!([]));

        let authorized_body = json!({
            "type": "new-message",
            "data": {
                "guid": "msg-loopback-authorized",
                "text": "authorized",
                "handle": { "address": "+15551234567" },
                "chats": [{ "guid": "iMessage;-;+15551234567" }],
                "isFromMe": false,
                "attachments": [{ "guid": "att-loopback-1", "mimeType": "image/png" }]
            }
        });
        let (authorized_request, authorized_http, authorized_result) = drive_ingress_loopback_post(
            &ingress_listener,
            &connector,
            &signing_key,
            callback_target.clone(),
            authorized_body.clone(),
        )
        .await;
        assert_eq!(authorized_http.status, 200);
        assert_eq!(authorized_http.body["reason_code"], "event_accepted");
        assert_eq!(
            authorized_result["ingest"]["event_envelopes"][0]["topic"],
            "imessage.message.inbound"
        );

        let (duplicate_request, duplicate_http, duplicate_result) = drive_ingress_loopback_post(
            &ingress_listener,
            &connector,
            &signing_key,
            callback_target,
            authorized_body,
        )
        .await;
        assert_eq!(duplicate_http.status, 409);
        assert_eq!(duplicate_http.body["reason_code"], "replay_suppressed");
        assert_eq!(duplicate_result["ingest"]["event_envelopes"], json!([]));

        let reaction = invoke_operation_result(
            &connector,
            &signing_key,
            OP_SEND_REACTION,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "message_guid": "msg-loopback-authorized",
                "reaction": "like"
            }),
        )
        .await;
        assert_eq!(reaction["status"], "reacted");

        let media = invoke_operation_result(
            &connector,
            &signing_key,
            OP_SEND_MEDIA,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "local_path": media_path.to_string_lossy().to_string(),
                "caption": "loopback media"
            }),
        )
        .await;
        assert_eq!(media["status"], "sent");
        assert_eq!(media["message_id"], "media-loopback-1");

        let typing = invoke_operation_result(
            &connector,
            &signing_key,
            OP_SET_TYPING,
            json!({
                "chat_guid": "iMessage;-;+15551234567",
                "typing": true
            }),
        )
        .await;
        assert_eq!(typing["status"], "typing_started");

        let mark_read = invoke_operation_result(
            &connector,
            &signing_key,
            OP_MARK_READ,
            json!({
                "chat_guid": "iMessage;-;+15551234567"
            }),
        )
        .await;
        assert_eq!(mark_read["status"], "marked_read");

        let (server_requests, server_logs) = bluebubbles.finish();
        assert_eq!(server_requests.len(), 9);
        assert_eq!(
            server_requests[0]
                .target
                .split_once('?')
                .map(|(path, _)| path),
            Some("/api/v1/webhook")
        );
        assert_eq!(server_requests[0].json_body()["url"], callback_url);
        assert_eq!(
            server_requests[2]
                .target
                .split_once('?')
                .map(|(path, _)| path),
            Some("/api/v1/message/react")
        );
        assert_eq!(
            server_requests[4]
                .target
                .split_once('?')
                .map(|(path, _)| path),
            Some("/api/v1/message/attachment")
        );
        assert_eq!(
            server_requests[6]
                .target
                .split_once('?')
                .map(|(path, _)| path),
            Some("/api/v1/chat/iMessage;-;+15551234567/typing")
        );
        assert_eq!(
            server_requests[8]
                .target
                .split_once('?')
                .map(|(path, _)| path),
            Some("/api/v1/chat/iMessage;-;+15551234567/read")
        );

        let transcript = json!({
            "event": "bluebubbles-ingress-loopback-e2e",
            "registration_status": registration["registration_status"],
            "ingress_requests": [
                {
                    "target": redacted_target(&unauthorized_request.target),
                    "status": unauthorized_http.status,
                    "reason_code": unauthorized_http.body["reason_code"]
                },
                {
                    "target": redacted_target(&authorized_request.target),
                    "status": authorized_http.status,
                    "reason_code": authorized_http.body["reason_code"]
                },
                {
                    "target": redacted_target(&duplicate_request.target),
                    "status": duplicate_http.status,
                    "reason_code": duplicate_http.body["reason_code"]
                }
            ],
            "outbound_request_count": server_requests.len(),
            "server_logs": server_logs
        });
        let transcript_text = serde_json::to_string(&transcript).unwrap();
        assert!(transcript_text.contains("bluebubbles-ingress-loopback-e2e"));
        assert!(!transcript_text.contains("test-password-123"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_rejects_unbound_sender_without_claiming() {
        let dedupe_path = unique_dedupe_state_path();
        let input = json!({
            "account_id": "acct-a",
            "payload": {
                "type": "new-message",
                "data": {
                    "guid": "msg-unbound",
                    "text": "hello",
                    "handle": { "address": "+15551234567" },
                    "chats": [{ "guid": "iMessage;-;+15551234567" }],
                    "isFromMe": false
                }
            }
        });

        let mut rejecting = BlueBubblesConnector::new();
        rejecting
            .configure(json!({
                "password": "test-password-123",
                "webhook_inbound": {
                    "dedupe_state_path": dedupe_path.clone()
                }
            }))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        rejecting
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();
        let rejected = rejecting
            .invoke(InvokeRequest {
                input: input.clone(),
                capability_token: generate_valid_token(
                    &rejecting,
                    &signing_key,
                    OP_INGEST_WEBHOOK_EVENT,
                ),
                ..base_invoke(rejecting.id(), OP_INGEST_WEBHOOK_EVENT)
            })
            .await
            .unwrap();
        let rejected_result = rejected.result.as_ref().unwrap();
        assert_eq!(rejected_result["status"], "rejected");
        assert_eq!(
            rejected_result["acceptance"]["reason"],
            "conversation_not_bound"
        );

        let mut accepting = BlueBubblesConnector::new();
        accepting
            .configure(test_config_with_webhook_inbound(Some(&dedupe_path)))
            .await
            .unwrap();
        accepting
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();
        let accepted = accepting
            .invoke(InvokeRequest {
                input,
                capability_token: generate_valid_token(
                    &accepting,
                    &signing_key,
                    OP_INGEST_WEBHOOK_EVENT,
                ),
                ..base_invoke(accepting.id(), OP_INGEST_WEBHOOK_EVENT)
            })
            .await
            .unwrap();
        assert_eq!(accepted.result.as_ref().unwrap()["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_persists_replay_dedupe_across_restart() {
        let dedupe_path = unique_dedupe_state_path();
        let input = json!({
            "account_id": "acct-a",
            "payload": {
                "type": "new-message",
                "data": {
                    "guid": "msg-persistent",
                    "handle": { "address": "+15551234567" },
                    "chats": [{ "guid": "iMessage;-;+15551234567" }],
                    "isFromMe": false
                }
            }
        });

        for expected_status in ["accepted", "duplicate"] {
            let mut connector = BlueBubblesConnector::new();
            connector
                .configure(test_config_with_webhook_inbound(Some(&dedupe_path)))
                .await
                .unwrap();
            let signing_key = Ed25519SigningKey::generate();
            connector
                .handshake(handshake_for_signing_key(&signing_key))
                .await
                .unwrap();
            let response = connector
                .invoke(InvokeRequest {
                    input: input.clone(),
                    capability_token: generate_valid_token(
                        &connector,
                        &signing_key,
                        OP_INGEST_WEBHOOK_EVENT,
                    ),
                    ..base_invoke(connector.id(), OP_INGEST_WEBHOOK_EVENT)
                })
                .await
                .unwrap();
            assert_eq!(response.result.as_ref().unwrap()["status"], expected_status);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_claims_secondary_source_ids() {
        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_webhook_inbound(None))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let coalesced = json!({
            "account_id": "acct-a",
            "payload": {
                "type": "new-message",
                "data": {
                    "guid": "msg-primary",
                    "handle": { "address": "+15551234567" },
                    "chats": [{ "guid": "iMessage;-;+15551234567" }],
                    "coalescedMessageIds": ["msg-secondary"],
                    "isFromMe": false
                }
            }
        });
        let response = connector
            .invoke(InvokeRequest {
                input: coalesced,
                capability_token: generate_valid_token(
                    &connector,
                    &signing_key,
                    OP_INGEST_WEBHOOK_EVENT,
                ),
                ..base_invoke(connector.id(), OP_INGEST_WEBHOOK_EVENT)
            })
            .await
            .unwrap();
        assert_eq!(response.result.as_ref().unwrap()["status"], "accepted");
        assert_eq!(
            response.result.as_ref().unwrap()["dedupe_ids"],
            json!(["acct-a:msg-primary", "acct-a:msg-secondary"])
        );

        let secondary = json!({
            "account_id": "acct-a",
            "payload": {
                "type": "new-message",
                "data": {
                    "guid": "msg-secondary",
                    "handle": { "address": "+15551234567" },
                    "chats": [{ "guid": "iMessage;-;+15551234567" }],
                    "isFromMe": false
                }
            }
        });
        let replay = connector
            .invoke(InvokeRequest {
                input: secondary,
                capability_token: generate_valid_token(
                    &connector,
                    &signing_key,
                    OP_INGEST_WEBHOOK_EVENT,
                ),
                ..base_invoke(connector.id(), OP_INGEST_WEBHOOK_EVENT)
            })
            .await
            .unwrap();
        assert_eq!(replay.result.as_ref().unwrap()["status"], "duplicate");
        assert_eq!(
            replay.result.as_ref().unwrap()["duplicate_id"],
            "acct-a:msg-secondary"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_contacts_disabled_by_default() {
        let mut config = test_config();
        config["webhook_inbound"] = json!({
            "allowed_chat_guids": ["iMessage;+;family"],
            "allow_group_chats": true
        });

        let mut connector = BlueBubblesConnector::new();
        connector.configure(config).await.unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let result = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-contacts-disabled",
                        "chats": [{
                            "guid": "iMessage;+;family",
                            "participants": [
                                { "address": "+1 (555) 123-4567" },
                                { "address": "me@example.com", "isMe": true },
                                { "address": "+15557654321", "displayName": "Bob" }
                            ]
                        }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;

        assert_eq!(result["status"], "accepted");
        assert_eq!(result["contacts_enrichment"]["status"], "disabled");
        assert_eq!(
            result["contacts_enrichment"]["reason"],
            "config_disabled_for_scope"
        );
        assert!(result["event"]["participants"][0]["display_name"].is_null());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_enriches_group_participants_from_contacts_cache() {
        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_contacts_enrichment())
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let first = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-contacts-1",
                        "chats": [{
                            "guid": "iMessage;+;family",
                            "participants": [
                                { "address": "+1 (555) 123-4567" },
                                { "address": "me@example.com", "displayName": "Me", "isMe": true },
                                { "address": "+15557654321", "displayName": "Bob" }
                            ]
                        }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;

        assert_eq!(first["status"], "accepted");
        assert_eq!(first["contacts_enrichment"]["status"], "enriched");
        assert_eq!(first["contacts_enrichment"]["lookup_count"], 1);
        assert_eq!(first["contacts_enrichment"]["enriched_count"], 1);
        assert_eq!(
            first["event"]["participants"][0]["display_name"],
            "Alice Example"
        );
        assert_eq!(
            first["event"]["participants"][0]["contact_name_enriched"],
            true
        );
        assert!(
            !serde_json::to_string(&first["contacts_enrichment"])
                .unwrap()
                .contains("Alice Example")
        );

        let second = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-contacts-2",
                        "chats": [{
                            "guid": "iMessage;+;family",
                            "participants": [
                                { "address": "555.123.4567" },
                                { "address": "me@example.com", "displayName": "Me", "isMe": true },
                                { "address": "+15557654321", "displayName": "Bob" }
                            ]
                        }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;

        assert_eq!(second["status"], "accepted");
        assert_eq!(second["contacts_enrichment"]["status"], "cache_hit");
        assert_eq!(second["contacts_enrichment"]["cache_hit_count"], 1);
        assert_eq!(
            second["event"]["participants"][0]["display_name"],
            "Alice Example"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_contacts_run_only_after_policy_acceptance() {
        let mut config = test_config_with_contacts_enrichment();
        config["webhook_inbound"] = json!({
            "allowed_chat_guids": ["iMessage;+;other-family"],
            "allow_group_chats": true
        });

        let mut connector = BlueBubblesConnector::new();
        connector.configure(config).await.unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let result = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-contacts-rejected",
                        "chats": [{
                            "guid": "iMessage;+;family",
                            "participants": [
                                { "address": "+1 (555) 123-4567" },
                                { "address": "me@example.com", "isMe": true },
                                { "address": "+15557654321" }
                            ]
                        }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;

        assert_eq!(result["status"], "rejected");
        assert_eq!(result["acceptance"]["reason"], "conversation_not_bound");
        assert!(result["contacts_enrichment"].is_null());
        assert!(result["event"].is_null());
    }

    #[test]
    fn canonical_reply_message_id_accepts_part_alias_and_rejects_path_inputs() {
        assert_eq!(
            canonical_reply_message_id(" p:0/root-1 ", 128).unwrap(),
            "root-1"
        );
        assert_eq!(
            canonical_reply_message_id("message.GUID-1:+", 128).unwrap(),
            "message.GUID-1:+"
        );
        assert_eq!(
            canonical_reply_message_id("p:x/root-1", 128).unwrap_err(),
            "reply_id_part_alias_malformed"
        );
        assert_eq!(
            canonical_reply_message_id("../root-1", 128).unwrap_err(),
            "reply_id_path_unsafe"
        );
        assert_eq!(
            canonical_reply_message_id("root/1", 128).unwrap_err(),
            "reply_id_path_unsafe"
        );
    }

    #[test]
    fn contacts_database_lookup_normalizes_us_phone_numbers() {
        let db_path = std::env::temp_dir().join(format!(
            "fcp-imessage-contacts-{}.abcddb",
            uuid::Uuid::new_v4()
        ));
        let connection = Connection::open(&db_path).unwrap();
        connection
            .execute_batch(
                "
                CREATE TABLE ZABCDRECORD (
                    Z_PK INTEGER PRIMARY KEY,
                    ZFIRSTNAME TEXT,
                    ZLASTNAME TEXT,
                    ZORGANIZATION TEXT
                );
                CREATE TABLE ZABCDPHONENUMBER (
                    ZOWNER INTEGER,
                    ZFULLNUMBER TEXT
                );
                INSERT INTO ZABCDRECORD (Z_PK, ZFIRSTNAME, ZLASTNAME, ZORGANIZATION)
                    VALUES (1, 'Alice', 'Example', '');
                INSERT INTO ZABCDPHONENUMBER (ZOWNER, ZFULLNUMBER)
                    VALUES (1, '+1 (555) 123-4567');
                ",
            )
            .unwrap();
        drop(connection);

        let keys = BTreeSet::from(["5551234567".to_string()]);
        let names = query_contact_database(&db_path, &keys).unwrap();
        assert_eq!(
            names.get("5551234567").map(String::as_str),
            Some("Alice Example")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_fetches_and_caches_reply_context() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/message/root-1"))
            .and(query_param("password", "test-password-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "guid": "root-1",
                    "text": "secret reply body",
                    "date_created": 1_700_000_000_000_i64,
                    "is_from_me": true,
                    "chatGuid": "iMessage;-;+15551234567",
                    "handle": { "address": "+15551234567", "display_name": "Alice" },
                    "attachments": [{ "guid": "reply-att-1" }]
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_reply_context(&mock_server.uri()))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let first = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-reply-1",
                        "text": "new message",
                        "threadOriginatorGuid": "p:0/root-1",
                        "handle": { "address": "+15551234567" },
                        "chats": [{ "guid": "iMessage;-;+15551234567" }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;
        assert_eq!(first["status"], "accepted");
        assert_eq!(first["reply_context_lookup"]["status"], "fetched");
        assert_eq!(first["reply_context_lookup"]["reply_id"], "root-1");
        assert_eq!(first["event"]["reply_to_message_guid"], "p:0/root-1");
        assert_eq!(first["event"]["reply_context"]["message_guid"], "root-1");
        assert_eq!(first["event"]["reply_context"]["text_present"], true);
        assert_eq!(first["event"]["reply_context"]["attachment_count"], 1);
        assert!(
            !serde_json::to_string(&first)
                .unwrap()
                .contains("secret reply body")
        );

        let second = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-reply-2",
                        "threadOriginatorGuid": "root-1",
                        "handle": { "address": "+15551234567" },
                        "chats": [{ "guid": "iMessage;-;+15551234567" }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;
        assert_eq!(second["reply_context_lookup"]["status"], "cache_hit");
        assert_eq!(second["event"]["reply_context"]["message_guid"], "root-1");
        mock_server.verify().await;
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_coalesces_concurrent_reply_context_fetches() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/message/root-1"))
            .and(query_param("password", "test-password-123"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(100))
                    .set_body_json(json!({
                        "data": {
                            "guid": "root-1",
                            "text": "secret reply body",
                            "is_from_me": true,
                            "chatGuid": "iMessage;-;+15551234567",
                            "attachments": []
                        }
                    })),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_reply_context(&mock_server.uri()))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();
        let connector = Arc::new(connector);
        let signing_key = Arc::new(signing_key);

        let first_connector = Arc::clone(&connector);
        let first_signing_key = Arc::clone(&signing_key);
        let first_task = fcp_async_core::task::spawn(async move {
            invoke_webhook_result(
                &first_connector,
                &first_signing_key,
                json!({
                    "account_id": "acct-a",
                    "payload": {
                        "type": "new-message",
                        "data": {
                            "guid": "msg-concurrent-1",
                            "threadOriginatorGuid": "root-1",
                            "handle": { "address": "+15551234567" },
                            "chats": [{ "guid": "iMessage;-;+15551234567" }],
                            "isFromMe": false
                        }
                    }
                }),
            )
            .await
        });

        let second_connector = Arc::clone(&connector);
        let second_signing_key = Arc::clone(&signing_key);
        let second_task = fcp_async_core::task::spawn(async move {
            invoke_webhook_result(
                &second_connector,
                &second_signing_key,
                json!({
                    "account_id": "acct-a",
                    "payload": {
                        "type": "new-message",
                        "data": {
                            "guid": "msg-concurrent-2",
                            "threadOriginatorGuid": "root-1",
                            "handle": { "address": "+15551234567" },
                            "chats": [{ "guid": "iMessage;-;+15551234567" }],
                            "isFromMe": false
                        }
                    }
                }),
            )
            .await
        });

        let first = first_task.await.unwrap();
        let second = second_task.await.unwrap();
        let results = [&first, &second];
        let fetched = results
            .iter()
            .find(|result| result["reply_context_lookup"]["status"].as_str() == Some("fetched"))
            .expect("one concurrent event should fetch reply context");
        let degraded = results
            .iter()
            .find(|result| result["reply_context_lookup"]["status"].as_str() == Some("degraded"))
            .expect("one concurrent event should coalesce behind the in-flight fetch");

        assert_eq!(fetched["event"]["reply_context"]["message_guid"], "root-1");
        assert_eq!(
            degraded["reply_context_lookup"]["reason"],
            "concurrent_fetch_in_progress"
        );
        assert!(degraded["event"]["reply_context"].is_null());
        for result in results {
            assert!(
                !serde_json::to_string(result)
                    .unwrap()
                    .contains("secret reply body")
            );
        }
        mock_server.verify().await;
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_rejects_cross_chat_reply_context() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/message/root-1"))
            .and(query_param("password", "test-password-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "guid": "root-1",
                    "text": "secret reply body",
                    "is_from_me": false,
                    "chatGuid": "iMessage;-;+15551234567",
                    "attachments": []
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_reply_context(&mock_server.uri()))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let result = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-wrong-chat",
                        "threadOriginatorGuid": "root-1",
                        "handle": { "address": "+15551234567" },
                        "chats": [{ "guid": "iMessage;-;+15557654321" }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;

        assert_eq!(result["status"], "accepted");
        assert_eq!(result["reply_context_lookup"]["status"], "degraded");
        assert_eq!(
            result["reply_context_lookup"]["reason"],
            "chat_scope_mismatch"
        );
        assert!(result["event"]["reply_context"].is_null());
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("secret reply body")
        );
        mock_server.verify().await;
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_coalesces_same_sender_dm_on_flush() {
        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_webhook_coalescing(&json!({})))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let first = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "observed_at_ms": 1_000_i64,
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-split-1",
                        "text": "Dump",
                        "dateCreated": 1_000_i64,
                        "handle": { "address": "+15551234567" },
                        "chats": [{ "guid": "iMessage;-;+15551234567" }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;
        assert_eq!(first["status"], "buffered");
        assert!(first["event"].is_null());
        assert_eq!(first["event_envelopes"], json!([]));
        assert_eq!(first["coalescing"]["buffered_count"], 1);

        let second = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "observed_at_ms": 1_700_i64,
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-split-2",
                        "text": "https://example.test/report",
                        "dateCreated": 1_700_i64,
                        "handle": { "address": "+15551234567" },
                        "chats": [{ "guid": "iMessage;-;+15551234567" }],
                        "attachments": [{ "guid": "att-url", "mimeType": "image/png" }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;
        assert_eq!(second["status"], "buffered");
        assert_eq!(second["coalescing"]["buffered_count"], 2);

        let flushed = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({ "flush_coalescing": true }),
        )
        .await;
        assert_eq!(flushed["status"], "flushed");
        assert_eq!(flushed["coalescing"]["emitted_count"], 1);
        assert_eq!(flushed["events"].as_array().unwrap().len(), 1);
        let envelopes = flushed["event_envelopes"].as_array().unwrap();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0]["topic"], "imessage.message.inbound");
        assert_eq!(envelopes[0]["data"]["payload"]["coalesced_source_count"], 2);
        let event = &flushed["event"];
        assert_eq!(event["event_id"], "msg-split-1");
        assert_eq!(event["text"], "Dump https://example.test/report");
        assert_eq!(event["attachments"][0]["guid"], "att-url");
        assert_eq!(event["source_message_ids"], json!(["msg-split-2"]));
        assert_eq!(event["coalesced_source_count"], 2);

        let replay = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-split-2",
                        "handle": { "address": "+15551234567" },
                        "chats": [{ "guid": "iMessage;-;+15551234567" }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;
        assert_eq!(replay["status"], "duplicate");
        assert_eq!(replay["duplicate_id"], "acct-a:msg-split-2");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_keeps_groups_and_commands_immediate() {
        let mut config = test_config_with_webhook_coalescing(&json!({
            "immediate_command_prefixes": ["/"]
        }));
        config["webhook_inbound"] = json!({
            "allowed_sender_ids": ["+15551234567"],
            "allowed_chat_guids": ["iMessage;-;+15551234567", "iMessage;+;group-chat"],
            "allow_group_chats": true
        });

        let mut connector = BlueBubblesConnector::new();
        connector.configure(config).await.unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let group = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-group",
                        "text": "group message",
                        "handle": { "address": "+15551234567" },
                        "chats": [{ "guid": "iMessage;+;group-chat" }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;
        assert_eq!(group["status"], "accepted");
        assert_eq!(group["event"]["event_id"], "msg-group");
        assert_eq!(group["coalescing"]["decision"], "ineligible_immediate");

        let command = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-command",
                        "text": "/now",
                        "handle": { "address": "+15551234567" },
                        "chats": [{ "guid": "iMessage;-;+15551234567" }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;
        assert_eq!(command["status"], "accepted");
        assert_eq!(command["event"]["event_id"], "msg-command");

        let flushed = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({ "flush_coalescing": true }),
        )
        .await;
        assert_eq!(flushed["events"].as_array().unwrap().len(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_rejection_never_buffers() {
        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(json!({
                "password": "test-password-123",
                "webhook_coalescing": {
                    "enabled": true,
                    "debounce_ms": 2500,
                    "max_debounce_ms": 2500
                }
            }))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let rejected = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-rejected",
                        "text": "do not buffer",
                        "handle": { "address": "+15551234567" },
                        "chats": [{ "guid": "iMessage;-;+15551234567" }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;
        assert_eq!(rejected["status"], "rejected");
        assert_eq!(rejected["acceptance"]["reason"], "conversation_not_bound");

        let flushed = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({ "flush_coalescing": true }),
        )
        .await;
        assert_eq!(flushed["events"].as_array().unwrap().len(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_separates_account_chat_and_sender() {
        let mut config = test_config_with_webhook_coalescing(&json!({}));
        config["webhook_inbound"] = json!({
            "allowed_sender_ids": ["+15551234567", "+15557654321"],
            "allowed_chat_guids": ["iMessage;-;+15551234567", "iMessage;-;+15557654321"]
        });

        let mut connector = BlueBubblesConnector::new();
        connector.configure(config).await.unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let cases = [
            (
                "acct-a",
                "msg-account-a",
                "+15551234567",
                "iMessage;-;+15551234567",
            ),
            (
                "acct-b",
                "msg-account-b",
                "+15551234567",
                "iMessage;-;+15551234567",
            ),
            (
                "acct-a",
                "msg-sender-b",
                "+15557654321",
                "iMessage;-;+15551234567",
            ),
            (
                "acct-a",
                "msg-chat-b",
                "+15551234567",
                "iMessage;-;+15557654321",
            ),
        ];

        for (account_id, guid, sender, chat_guid) in cases {
            let buffered = invoke_webhook_result(
                &connector,
                &signing_key,
                json!({
                    "account_id": account_id,
                    "observed_at_ms": 1_000_i64,
                    "payload": {
                        "type": "new-message",
                        "data": {
                            "guid": guid,
                            "text": guid,
                            "handle": { "address": sender },
                            "chats": [{ "guid": chat_guid }],
                            "isFromMe": false
                        }
                    }
                }),
            )
            .await;
            assert_eq!(buffered["status"], "buffered");
        }

        let flushed = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({ "flush_coalescing": true }),
        )
        .await;
        let mut event_ids = flushed["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["event_id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        event_ids.sort();
        assert_eq!(
            event_ids,
            vec![
                "msg-account-a",
                "msg-account-b",
                "msg-chat-b",
                "msg-sender-b"
            ]
        );
        assert!(flushed["events"].as_array().unwrap().iter().all(|event| {
            event["coalesced_source_count"].is_null() && event["source_message_ids"].is_null()
        }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_rejects_over_limit_pending_buffers() {
        let mut config = test_config_with_webhook_coalescing(&json!({
            "max_pending_buffers": 1
        }));
        config["webhook_inbound"] = json!({
            "allowed_sender_ids": ["+15551234567", "+15557654321"],
            "allowed_chat_guids": ["iMessage;-;+15551234567", "iMessage;-;+15557654321"]
        });

        let mut connector = BlueBubblesConnector::new();
        connector.configure(config).await.unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let first = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-buffer-1",
                        "text": "first",
                        "handle": { "address": "+15551234567" },
                        "chats": [{ "guid": "iMessage;-;+15551234567" }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;
        assert_eq!(first["status"], "buffered");

        let error = connector
            .invoke(InvokeRequest {
                input: json!({
                    "account_id": "acct-a",
                    "payload": {
                        "type": "new-message",
                        "data": {
                            "guid": "msg-buffer-2",
                            "text": "second",
                            "handle": { "address": "+15557654321" },
                            "chats": [{ "guid": "iMessage;-;+15557654321" }],
                            "isFromMe": false
                        }
                    }
                }),
                capability_token: generate_valid_token(
                    &connector,
                    &signing_key,
                    OP_INGEST_WEBHOOK_EVENT,
                ),
                ..base_invoke(connector.id(), OP_INGEST_WEBHOOK_EVENT)
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            FcpError::InvalidRequest { ref message, .. }
                if message.contains("pending buffer limit exceeded")
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_flushes_stale_buffer_before_new_dm() {
        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_webhook_coalescing(&json!({})))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let first = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "observed_at_ms": 1_000_i64,
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-stale-1",
                        "text": "first",
                        "handle": { "address": "+15551234567" },
                        "chats": [{ "guid": "iMessage;-;+15551234567" }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;
        assert_eq!(first["status"], "buffered");

        let second = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "observed_at_ms": 4_000_i64,
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-stale-2",
                        "text": "second",
                        "handle": { "address": "+15551234567" },
                        "chats": [{ "guid": "iMessage;-;+15551234567" }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;
        assert_eq!(second["status"], "accepted");
        assert_eq!(second["event"]["event_id"], "msg-stale-1");
        assert_eq!(second["coalescing"]["pending_buffer_count"], 1);

        let flushed = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({ "flush_coalescing": true }),
        )
        .await;
        assert_eq!(flushed["event"]["event_id"], "msg-stale-2");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_flushes_on_source_cap_and_marks_truncation() {
        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_webhook_coalescing(&json!({
                "max_text_chars": 8,
                "max_attachments": 1,
                "max_source_messages": 2
            })))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let first = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "observed_at_ms": 1_000_i64,
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-cap-1",
                        "text": "abcdefghij",
                        "handle": { "address": "+15551234567" },
                        "chats": [{ "guid": "iMessage;-;+15551234567" }],
                        "attachments": [{ "guid": "att-1" }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;
        assert_eq!(first["status"], "buffered");

        let second = invoke_webhook_result(
            &connector,
            &signing_key,
            json!({
                "account_id": "acct-a",
                "observed_at_ms": 1_100_i64,
                "payload": {
                    "type": "new-message",
                    "data": {
                        "guid": "msg-cap-2",
                        "text": "klmnop",
                        "handle": { "address": "+15551234567" },
                        "chats": [{ "guid": "iMessage;-;+15551234567" }],
                        "attachments": [{ "guid": "att-2" }],
                        "isFromMe": false
                    }
                }
            }),
        )
        .await;
        assert_eq!(second["status"], "accepted");
        assert_eq!(second["event"]["text"], "abcdefgh...[truncated]");
        assert_eq!(second["event"]["attachments"].as_array().unwrap().len(), 1);
        assert_eq!(
            second["event"]["coalescing_truncated_fields"],
            json!(["attachments", "text"])
        );
        assert_eq!(second["event"]["source_message_ids"], json!(["msg-cap-2"]));
    }

    #[test]
    fn webhook_dedupe_store_release_and_ttl_allow_reclaim() {
        let config = BlueBubblesConfig::from_value(json!({
            "password": "test-password-123",
            "webhook_inbound": {
                "dedupe_ttl_seconds": 60
            }
        }))
        .unwrap();
        let store = BlueBubblesInboundDedupeStore::from_config(&config).unwrap();
        let ids = vec!["acct-a:msg-release".to_string()];

        assert_eq!(store.claim(&ids).unwrap(), BlueBubblesDedupeClaim::Claimed);
        assert!(matches!(
            store.claim(&ids).unwrap(),
            BlueBubblesDedupeClaim::Duplicate { .. }
        ));
        store.release(&ids).unwrap();
        assert_eq!(store.claim(&ids).unwrap(), BlueBubblesDedupeClaim::Claimed);

        store
            .age_claim_for_test("acct-a:msg-release", 61_000)
            .unwrap();
        assert_eq!(store.claim(&ids).unwrap(), BlueBubblesDedupeClaim::Claimed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_list_and_unregister_webhooks_by_url() {
        let mock_server = MockServer::start().await;
        let callback_url = "http://localhost:8645/bluebubbles-webhook";

        Mock::given(method("GET"))
            .and(path("/api/v1/webhook"))
            .and(query_param("password", "test-password-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [{
                    "id": "wh-1",
                    "url": callback_url,
                    "events": ["new-message", "updated-message"]
                }]
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/webhook/wh-1"))
            .and(query_param("password", "test-password-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": 200,
                "message": "deleted"
            })))
            .mount(&mock_server)
            .await;

        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_url(&mock_server.uri()))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();

        let req = InvokeRequest {
            capability_token: generate_valid_token(&connector, &signing_key, OP_LIST_WEBHOOKS),
            ..base_invoke(connector.id(), OP_LIST_WEBHOOKS)
        };
        let response = connector.invoke(req).await.unwrap();
        let result = response.result.as_ref().unwrap();
        assert_eq!(result["webhooks"][0]["id"], "wh-1");
        assert_eq!(result["webhooks"][0]["url"], callback_url);
        assert_eq!(
            result["webhooks"][0]["events"],
            json!(["new-message", "updated-message"])
        );

        let req = InvokeRequest {
            input: json!({ "url": callback_url }),
            capability_token: generate_valid_token(&connector, &signing_key, OP_UNREGISTER_WEBHOOK),
            ..base_invoke(connector.id(), OP_UNREGISTER_WEBHOOK)
        };
        let response = connector.invoke(req).await.unwrap();
        let result = response.result.as_ref().unwrap();
        assert_eq!(result["deleted_count"], 1);
        assert_eq!(result["deleted"][0]["webhook_id"], "wh-1");
        assert_eq!(result["deleted"][0]["response"]["message"], "deleted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_register_webhook_posts_when_no_existing_match() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/webhook"))
            .and(query_param("password", "test-password-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": []
            })))
            .mount(&mock_server)
            .await;
        let callback_url = format!(
            "{}?{}={}",
            "http://localhost:8645/bluebubbles-webhook", "password", "test-password-123"
        );

        Mock::given(method("POST"))
            .and(path("/api/v1/webhook"))
            .and(query_param("password", "test-password-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": 200,
                "message": "registered",
                "data": {
                    "id": "wh-1",
                    "url": callback_url.clone(),
                    "events": ["new-message", "updated-message"]
                }
            })))
            .mount(&mock_server)
            .await;

        let mut connector = BlueBubblesConnector::new();
        connector
            .configure(test_config_with_url(&mock_server.uri()))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_for_signing_key(&signing_key))
            .await
            .unwrap();
        let req = InvokeRequest {
            input: json!({
                "url": callback_url
            }),
            capability_token: generate_valid_token(&connector, &signing_key, OP_REGISTER_WEBHOOK),
            ..base_invoke(connector.id(), OP_REGISTER_WEBHOOK)
        };

        let response = connector.invoke(req).await.unwrap();
        let result = response.result.as_ref().unwrap();
        assert_eq!(result["registration_status"], "registered");
        assert_eq!(result["response"]["data"]["id"], "wh-1");
    }
}
