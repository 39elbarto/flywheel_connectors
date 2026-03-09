//! Twilio REST API client.
//!
//! Twilio uses Basic auth (account_sid:auth_token) and JSON POST bodies.
//! Base URL: `https://api.twilio.com/2010-04-01/Accounts/{account_sid}`

use std::fmt::Write;
use std::time::Duration;

use base64::Engine;
use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode, header};
use tracing::{debug, warn};

use crate::{
    error::{TwilioError, TwilioResult},
    types::{
        ApiErrorResponse, CallListResponse, ConversationListResponse,
        ConversationMessageListResponse, ConversationParticipant, MediaListResponse,
        MessageListResponse, PhoneNumberListResponse, RecordingListResponse, TwilioAccount,
        TwilioCall, TwilioConversation, TwilioMediaResource, TwilioMessage, TwilioVerification,
        TwimlTemplate, TwilioVideoRoom, VerificationCheck, VideoParticipantListResponse,
        VideoRecordingListResponse, VideoRoomListResponse, WhatsAppMessage,
    },
};

/// Default Twilio API base URL prefix.
pub const DEFAULT_API_BASE: &str = "https://api.twilio.com/2010-04-01/Accounts";

/// Default Twilio Conversations API base URL.
pub const DEFAULT_CONVERSATIONS_BASE: &str = "https://conversations.twilio.com/v1";

/// Default Twilio Verify API base URL.
pub const DEFAULT_VERIFY_BASE: &str = "https://verify.twilio.com/v2";

/// Default Twilio Video API base URL.
pub const DEFAULT_VIDEO_BASE: &str = "https://video.twilio.com/v1";

/// Authentication mode for the Twilio client.
#[derive(Clone)]
pub enum TwilioAuth {
    /// Direct credentials: account SID + auth token (Basic auth).
    Token {
        account_sid: String,
        auth_token: String,
    },
    /// Secretless credential injection via egress proxy.
    CredentialId {
        account_sid: String,
        credential_id: CredentialId,
    },
}

impl std::fmt::Debug for TwilioAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token { account_sid, .. } => f
                .debug_struct("Token")
                .field("account_sid", account_sid)
                .field("auth_token", &"[REDACTED]")
                .finish(),
            Self::CredentialId {
                account_sid,
                credential_id,
            } => f
                .debug_struct("CredentialId")
                .field("account_sid", account_sid)
                .field("credential_id", credential_id)
                .finish(),
        }
    }
}

impl TwilioAuth {
    /// Human-readable label with secrets redacted.
    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::Token { .. } => "token",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    /// Whether this auth mode is secretless (no raw credentials held).
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }

    /// Get the account SID regardless of auth mode.
    #[must_use]
    pub fn account_sid(&self) -> &str {
        match self {
            Self::Token { account_sid, .. } | Self::CredentialId { account_sid, .. } => account_sid,
        }
    }
}

/// Twilio REST API client.
pub struct TwilioClient {
    http: Client,
    auth: TwilioAuth,
    base_url: String,
    conversations_base_url: String,
    verify_base_url: String,
    video_base_url: String,
    account_sid: String,
    max_retries: u32,
}

impl std::fmt::Debug for TwilioClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwilioClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("conversations_base_url", &self.conversations_base_url)
            .field("verify_base_url", &self.verify_base_url)
            .field("video_base_url", &self.video_base_url)
            .field("account_sid", &self.account_sid)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

impl TwilioClient {
    /// Create a new Twilio client with account SID and auth token.
    pub fn new(account_sid: &str, auth_token: &str) -> TwilioResult<Self> {
        Self::new_with_auth(TwilioAuth::Token {
            account_sid: account_sid.to_string(),
            auth_token: auth_token.to_string(),
        })
    }

    /// Create a new Twilio client with the specified auth mode.
    pub fn new_with_auth(auth: TwilioAuth) -> TwilioResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());

        match &auth {
            TwilioAuth::Token {
                account_sid,
                auth_token,
            } => {
                let credentials = base64::engine::general_purpose::STANDARD
                    .encode(format!("{account_sid}:{auth_token}"));
                headers.insert(
                    header::AUTHORIZATION,
                    format!("Basic {credentials}").parse().unwrap(),
                );
            }
            TwilioAuth::CredentialId { credential_id, .. } => {
                headers.insert(
                    "X-FCP-Credential-ID",
                    credential_id.to_string().parse().unwrap(),
                );
            }
        }

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-twilio/0.1.0")
            .build()
            .map_err(TwilioError::Http)?;

        let sid = auth.account_sid().to_string();
        let base_url = format!("{DEFAULT_API_BASE}/{sid}");
        let conversations_base_url = DEFAULT_CONVERSATIONS_BASE.to_string();
        let verify_base_url = DEFAULT_VERIFY_BASE.to_string();
        let video_base_url = DEFAULT_VIDEO_BASE.to_string();

        Ok(Self {
            http,
            auth,
            base_url,
            conversations_base_url,
            verify_base_url,
            video_base_url,
            account_sid: sid,
            max_retries: 2,
        })
    }

    /// Lightweight connectivity probe for self-check.
    pub async fn health_check(&self) -> TwilioResult<TwilioAccount> {
        self.get_account().await
    }

    /// Set a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
    }

    /// Set a custom Conversations API base URL (for testing).
    #[must_use]
    pub fn with_conversations_base_url(mut self, url: &str) -> Self {
        self.conversations_base_url = url.to_string();
        self
    }

    /// Set a custom Video API base URL (for testing).
    #[must_use]
    pub fn with_video_base_url(mut self, url: &str) -> Self {
        self.video_base_url = url.to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub const fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Get the account SID.
    #[must_use]
    pub fn account_sid(&self) -> &str {
        &self.account_sid
    }

    // ── Messaging operations ─────────────────────────────────────

    /// Send an SMS or MMS message.
    pub async fn send_message(
        &self,
        to: &str,
        from: &str,
        body: &str,
        media_url: Option<&[String]>,
        status_callback: Option<&str>,
    ) -> TwilioResult<TwilioMessage> {
        let url = format!("{}/Messages.json", self.base_url);
        let mut payload = serde_json::json!({
            "To": to,
            "From": from,
            "Body": body,
        });
        if let Some(urls) = media_url {
            payload["MediaUrl"] = serde_json::json!(urls);
        }
        if let Some(cb) = status_callback {
            payload["StatusCallback"] = serde_json::Value::String(cb.to_string());
        }
        let data = self.post_json(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a message by SID.
    pub async fn get_message(&self, message_sid: &str) -> TwilioResult<TwilioMessage> {
        let url = format!("{}/Messages/{message_sid}.json", self.base_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List messages with optional filters.
    pub async fn list_messages(
        &self,
        to: Option<&str>,
        from: Option<&str>,
        date_sent: Option<&str>,
        page_size: Option<u32>,
        page: Option<u32>,
    ) -> TwilioResult<MessageListResponse> {
        let base_url = format!("{}/Messages.json", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = to {
            params.push(("To", v.to_string()));
        }
        if let Some(v) = from {
            params.push(("From", v.to_string()));
        }
        if let Some(v) = date_sent {
            params.push(("DateSent", v.to_string()));
        }
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        if let Some(v) = page {
            params.push(("Page", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Voice operations ─────────────────────────────────────────

    /// Create (initiate) a voice call.
    pub async fn create_call(
        &self,
        to: &str,
        from: &str,
        url: &str,
        status_callback: Option<&str>,
        timeout: Option<u32>,
        record: Option<bool>,
    ) -> TwilioResult<TwilioCall> {
        let api_url = format!("{}/Calls.json", self.base_url);
        let mut payload = serde_json::json!({
            "To": to,
            "From": from,
            "Url": url,
        });
        if let Some(cb) = status_callback {
            payload["StatusCallback"] = serde_json::Value::String(cb.to_string());
        }
        if let Some(t) = timeout {
            payload["Timeout"] = serde_json::Value::Number(t.into());
        }
        if let Some(r) = record {
            payload["Record"] = serde_json::Value::Bool(r);
        }
        let data = self.post_json(&api_url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a call by SID.
    pub async fn get_call(&self, call_sid: &str) -> TwilioResult<TwilioCall> {
        let url = format!("{}/Calls/{call_sid}.json", self.base_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Hangup (end) a call by updating its status to "completed".
    pub async fn hangup_call(&self, call_sid: &str) -> TwilioResult<TwilioCall> {
        let url = format!("{}/Calls/{call_sid}.json", self.base_url);
        let payload = serde_json::json!({ "Status": "completed" });
        let data = self.post_json(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List calls with optional filters.
    pub async fn list_calls(
        &self,
        to: Option<&str>,
        from: Option<&str>,
        status: Option<&str>,
        start_time: Option<&str>,
        end_time: Option<&str>,
        page_size: Option<u32>,
        page: Option<u32>,
    ) -> TwilioResult<CallListResponse> {
        let base_url = format!("{}/Calls.json", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = to {
            params.push(("To", v.to_string()));
        }
        if let Some(v) = from {
            params.push(("From", v.to_string()));
        }
        if let Some(v) = status {
            params.push(("Status", v.to_string()));
        }
        if let Some(v) = start_time {
            params.push(("StartTime", v.to_string()));
        }
        if let Some(v) = end_time {
            params.push(("EndTime", v.to_string()));
        }
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        if let Some(v) = page {
            params.push(("Page", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Generate TwiML XML from a safe template.
    ///
    /// This is a local operation; no API call is made.
    #[must_use]
    pub fn generate_twiml(
        template: &TwimlTemplate,
        message: Option<&str>,
        url: Option<&str>,
        voice: Option<&str>,
        language: Option<&str>,
        digits: Option<&str>,
        number: Option<&str>,
        length: Option<u32>,
        reason: Option<&str>,
    ) -> String {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Response>\n");

        match template {
            TwimlTemplate::Say => {
                let msg = Self::escape_xml(message.unwrap_or("Hello from FCP."));
                let v = voice.unwrap_or("alice");
                let lang = language.unwrap_or("en-US");
                let _ = writeln!(xml, "  <Say voice=\"{v}\" language=\"{lang}\">{msg}</Say>");
            }
            TwimlTemplate::Play => {
                let u = Self::escape_xml(url.unwrap_or(""));
                let _ = writeln!(xml, "  <Play>{u}</Play>");
            }
            TwimlTemplate::Gather => {
                let prompt = Self::escape_xml(message.unwrap_or("Please enter your selection."));
                let v = voice.unwrap_or("alice");
                let lang = language.unwrap_or("en-US");
                let num_digits = digits.unwrap_or("1");
                let _ = write!(xml, "  <Gather numDigits=\"{num_digits}\">\n    <Say voice=\"{v}\" language=\"{lang}\">{prompt}</Say>\n  </Gather>\n");
            }
            TwimlTemplate::Dial => {
                let num = Self::escape_xml(number.unwrap_or(""));
                let _ = writeln!(xml, "  <Dial>{num}</Dial>");
            }
            TwimlTemplate::Pause => {
                let len = length.unwrap_or(1);
                let _ = writeln!(xml, "  <Pause length=\"{len}\"/>");
            }
            TwimlTemplate::Reject => {
                let r = reason.unwrap_or("rejected");
                let _ = writeln!(xml, "  <Reject reason=\"{r}\"/>");
            }
            TwimlTemplate::Hangup => {
                xml.push_str("  <Hangup/>\n");
            }
        }

        xml.push_str("</Response>");
        xml
    }

    /// Escape XML special characters.
    fn escape_xml(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    // ── Recording operations ─────────────────────────────────────

    /// List recordings with optional filters.
    pub async fn list_recordings(
        &self,
        call_sid: Option<&str>,
        date_created: Option<&str>,
        page_size: Option<u32>,
    ) -> TwilioResult<RecordingListResponse> {
        let base_url = format!("{}/Recordings.json", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = call_sid {
            params.push(("CallSid", v.to_string()));
        }
        if let Some(v) = date_created {
            params.push(("DateCreated", v.to_string()));
        }
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Download a recording, returning the base64-encoded audio data and content type.
    pub async fn download_recording(
        &self,
        recording_sid: &str,
        format: Option<&str>,
    ) -> TwilioResult<(String, String)> {
        let ext = format.unwrap_or("mp3");
        let url = format!("{}/Recordings/{recording_sid}.{ext}", self.base_url);
        let data = self.get_bytes(&url).await?;
        let content_type = if ext == "wav" {
            "audio/wav"
        } else {
            "audio/mpeg"
        };
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        Ok((b64, content_type.to_string()))
    }

    /// Download media attached to a message, returning base64-encoded data and content type.
    pub async fn download_media(
        &self,
        message_sid: &str,
        media_sid: &str,
    ) -> TwilioResult<(String, String)> {
        let url = format!("{}/Messages/{message_sid}/Media/{media_sid}", self.base_url);
        let data = self.get_bytes(&url).await?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        Ok((b64, "application/octet-stream".to_string()))
    }

    // ── Media operations ─────────────────────────────────────────

    /// List media resources attached to a message.
    pub async fn list_media(
        &self,
        message_sid: &str,
        page_size: Option<u32>,
        page: Option<u32>,
    ) -> TwilioResult<MediaListResponse> {
        let base_url = format!("{}/Messages/{message_sid}/Media.json", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        if let Some(v) = page {
            params.push(("Page", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a specific media resource by SID.
    pub async fn get_media(
        &self,
        message_sid: &str,
        media_sid: &str,
    ) -> TwilioResult<TwilioMediaResource> {
        let url = format!(
            "{}/Messages/{message_sid}/Media/{media_sid}.json",
            self.base_url
        );
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── WhatsApp operations ──────────────────────────────────────

    /// Send a freeform WhatsApp message.
    ///
    /// Uses the same Messages API as SMS but with `whatsapp:` prefix on numbers.
    pub async fn whatsapp_send(
        &self,
        to: &str,
        from: &str,
        body: &str,
        media_url: Option<&[String]>,
        status_callback: Option<&str>,
    ) -> TwilioResult<WhatsAppMessage> {
        let url = format!("{}/Messages.json", self.base_url);
        let wa_to = ensure_whatsapp_prefix(to);
        let wa_from = ensure_whatsapp_prefix(from);
        let mut payload = serde_json::json!({
            "To": wa_to,
            "From": wa_from,
            "Body": body,
        });
        if let Some(urls) = media_url {
            payload["MediaUrl"] = serde_json::json!(urls);
        }
        if let Some(cb) = status_callback {
            payload["StatusCallback"] = serde_json::Value::String(cb.to_string());
        }
        let data = self.post_json(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Send a template-based WhatsApp message.
    ///
    /// Uses `ContentSid` to reference pre-approved templates with optional
    /// `ContentVariables` for variable substitution.
    pub async fn whatsapp_send_template(
        &self,
        to: &str,
        from: &str,
        content_sid: &str,
        content_variables: Option<&serde_json::Value>,
        status_callback: Option<&str>,
    ) -> TwilioResult<WhatsAppMessage> {
        let url = format!("{}/Messages.json", self.base_url);
        let wa_to = ensure_whatsapp_prefix(to);
        let wa_from = ensure_whatsapp_prefix(from);
        let mut payload = serde_json::json!({
            "To": wa_to,
            "From": wa_from,
            "ContentSid": content_sid,
        });
        if let Some(vars) = content_variables {
            payload["ContentVariables"] = serde_json::Value::String(vars.to_string());
        }
        if let Some(cb) = status_callback {
            payload["StatusCallback"] = serde_json::Value::String(cb.to_string());
        }
        let data = self.post_json(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a WhatsApp message by SID.
    pub async fn whatsapp_get(&self, message_sid: &str) -> TwilioResult<WhatsAppMessage> {
        let url = format!("{}/Messages/{message_sid}.json", self.base_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List WhatsApp messages by filtering on the `whatsapp:` prefix.
    pub async fn whatsapp_list(
        &self,
        to: Option<&str>,
        from: Option<&str>,
        date_sent: Option<&str>,
        page_size: Option<u32>,
        page: Option<u32>,
    ) -> TwilioResult<MessageListResponse> {
        let base_url = format!("{}/Messages.json", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = to {
            params.push(("To", ensure_whatsapp_prefix(v)));
        }
        if let Some(v) = from {
            params.push(("From", ensure_whatsapp_prefix(v)));
        }
        if let Some(v) = date_sent {
            params.push(("DateSent", v.to_string()));
        }
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        if let Some(v) = page {
            params.push(("Page", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Account operations ───────────────────────────────────────

    /// Get account details.
    pub async fn get_account(&self) -> TwilioResult<TwilioAccount> {
        let url = format!("{}.json", self.base_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List phone numbers on the account.
    pub async fn list_phone_numbers(
        &self,
        phone_number: Option<&str>,
        page_size: Option<u32>,
    ) -> TwilioResult<PhoneNumberListResponse> {
        let base_url = format!("{}/IncomingPhoneNumbers.json", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = phone_number {
            params.push(("PhoneNumber", v.to_string()));
        }
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Conversations API ──────────────────────────────────────

    /// Create a new conversation.
    pub async fn create_conversation(
        &self,
        friendly_name: Option<&str>,
        unique_name: Option<&str>,
    ) -> TwilioResult<TwilioConversation> {
        let url = format!("{}/Conversations", self.conversations_base_url);
        let mut payload = serde_json::json!({});
        if let Some(name) = friendly_name {
            payload["FriendlyName"] = serde_json::Value::String(name.to_string());
        }
        if let Some(name) = unique_name {
            payload["UniqueName"] = serde_json::Value::String(name.to_string());
        }
        let data = self.post_json(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a conversation by SID.
    pub async fn get_conversation(
        &self,
        conversation_sid: &str,
    ) -> TwilioResult<TwilioConversation> {
        let url = format!(
            "{}/Conversations/{conversation_sid}",
            self.conversations_base_url
        );
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List conversations with optional pagination.
    pub async fn list_conversations(
        &self,
        page_size: Option<u32>,
    ) -> TwilioResult<ConversationListResponse> {
        let base_url = format!("{}/Conversations", self.conversations_base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Add a participant to a conversation.
    pub async fn add_participant(
        &self,
        conversation_sid: &str,
        identity: Option<&str>,
        messaging_address: Option<&str>,
        messaging_proxy_address: Option<&str>,
    ) -> TwilioResult<ConversationParticipant> {
        let url = format!(
            "{}/Conversations/{conversation_sid}/Participants",
            self.conversations_base_url
        );
        let mut payload = serde_json::json!({});
        if let Some(id) = identity {
            payload["Identity"] = serde_json::Value::String(id.to_string());
        }
        if let Some(addr) = messaging_address {
            payload["MessagingBinding.Address"] =
                serde_json::Value::String(addr.to_string());
        }
        if let Some(proxy) = messaging_proxy_address {
            payload["MessagingBinding.ProxyAddress"] =
                serde_json::Value::String(proxy.to_string());
        }
        let data = self.post_json(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Remove a participant from a conversation.
    pub async fn remove_participant(
        &self,
        conversation_sid: &str,
        participant_sid: &str,
    ) -> TwilioResult<()> {
        let url = format!(
            "{}/Conversations/{conversation_sid}/Participants/{participant_sid}",
            self.conversations_base_url
        );
        self.delete(&url).await
    }

    /// Send a message into a conversation.
    pub async fn send_conversation_message(
        &self,
        conversation_sid: &str,
        author: Option<&str>,
        body: &str,
    ) -> TwilioResult<serde_json::Value> {
        let url = format!(
            "{}/Conversations/{conversation_sid}/Messages",
            self.conversations_base_url
        );
        let mut payload = serde_json::json!({
            "Body": body,
        });
        if let Some(a) = author {
            payload["Author"] = serde_json::Value::String(a.to_string());
        }
        self.post_json(&url, &payload).await
    }

    /// List messages in a conversation.
    pub async fn list_conversation_messages(
        &self,
        conversation_sid: &str,
        page_size: Option<u32>,
        order: Option<&str>,
    ) -> TwilioResult<ConversationMessageListResponse> {
        let base_url = format!(
            "{}/Conversations/{conversation_sid}/Messages",
            self.conversations_base_url
        );
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        if let Some(v) = order {
            params.push(("Order", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Verify API ─────────────────────────────────────────────

    /// Send a verification code (create a verification).
    pub async fn send_verification(
        &self,
        service_sid: &str,
        to: &str,
        channel: &str,
    ) -> TwilioResult<TwilioVerification> {
        let url = format!(
            "{}/Services/{service_sid}/Verifications",
            self.verify_base_url
        );
        let payload = serde_json::json!({
            "To": to,
            "Channel": channel,
        });
        let data = self.post_json(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Check a verification code.
    pub async fn check_verification(
        &self,
        service_sid: &str,
        to: &str,
        code: &str,
    ) -> TwilioResult<VerificationCheck> {
        let url = format!(
            "{}/Services/{service_sid}/VerificationCheck",
            self.verify_base_url
        );
        let payload = serde_json::json!({
            "To": to,
            "Code": code,
        });
        let data = self.post_json(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Cancel a pending verification.
    pub async fn cancel_verification(
        &self,
        service_sid: &str,
        verification_sid: &str,
    ) -> TwilioResult<TwilioVerification> {
        let url = format!(
            "{}/Services/{service_sid}/Verifications/{verification_sid}",
            self.verify_base_url
        );
        let payload = serde_json::json!({
            "Status": "canceled",
        });
        let data = self.post_json(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Video API ──────────────────────────────────────────────────

    /// Create a video room.
    pub async fn create_video_room(
        &self,
        unique_name: Option<&str>,
        room_type: Option<&str>,
        max_participants: Option<u32>,
    ) -> TwilioResult<TwilioVideoRoom> {
        let url = format!("{}/Rooms", self.video_base_url);
        let mut payload = serde_json::json!({});
        if let Some(name) = unique_name {
            payload["UniqueName"] = serde_json::Value::String(name.to_string());
        }
        if let Some(rt) = room_type {
            payload["Type"] = serde_json::Value::String(rt.to_string());
        }
        if let Some(mp) = max_participants {
            payload["MaxParticipants"] = serde_json::Value::Number(mp.into());
        }
        let data = self.post_json(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a video room by SID or unique name.
    pub async fn get_video_room(&self, room_sid: &str) -> TwilioResult<TwilioVideoRoom> {
        let url = format!("{}/Rooms/{room_sid}", self.video_base_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List video rooms.
    pub async fn list_video_rooms(
        &self,
        status: Option<&str>,
        page_size: Option<u32>,
    ) -> TwilioResult<VideoRoomListResponse> {
        let base_url = format!("{}/Rooms", self.video_base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(s) = status {
            params.push(("Status", s.to_string()));
        }
        if let Some(ps) = page_size {
            params.push(("PageSize", ps.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// End a video room (set status to completed).
    pub async fn end_video_room(&self, room_sid: &str) -> TwilioResult<TwilioVideoRoom> {
        let url = format!("{}/Rooms/{room_sid}", self.video_base_url);
        let payload = serde_json::json!({
            "Status": "completed",
        });
        let data = self.post_json(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List participants in a video room.
    pub async fn list_video_participants(
        &self,
        room_sid: &str,
        status: Option<&str>,
    ) -> TwilioResult<VideoParticipantListResponse> {
        let base_url = format!("{}/Rooms/{room_sid}/Participants", self.video_base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(s) = status {
            params.push(("Status", s.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List recordings for a video room.
    pub async fn list_video_recordings(
        &self,
        room_sid: &str,
    ) -> TwilioResult<VideoRecordingListResponse> {
        let url = format!("{}/Rooms/{room_sid}/Recordings", self.video_base_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── HTTP helpers ─────────────────────────────────────────────

    async fn get(&self, url: &str) -> TwilioResult<serde_json::Value> {
        self.execute(|| self.http.get(url)).await
    }

    async fn get_with_params(
        &self,
        base_url: &str,
        params: &[(&str, String)],
    ) -> TwilioResult<serde_json::Value> {
        let mut url = base_url.to_string();
        if !params.is_empty() {
            url.push('?');
            for (i, (key, value)) in params.iter().enumerate() {
                if i > 0 {
                    url.push('&');
                }
                let encoded = percent_encoding::utf8_percent_encode(
                    value,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                let _ = write!(url, "{key}={encoded}");
            }
        }
        self.execute(|| self.http.get(&url)).await
    }

    async fn get_bytes(&self, url: &str) -> TwilioResult<Vec<u8>> {
        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = Duration::from_millis(500 * u64::from(attempt));
                debug!(attempt, delay_ms = delay.as_millis(), "retrying request");
                fcp_async_core::time::sleep(delay).await;
            }

            let result = self.http.get(url).send().await;

            match result {
                Ok(response) => {
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        if attempt < self.max_retries {
                            let wait = retry_result
                                .unwrap_or(Duration::from_millis(500 * u64::from(attempt + 1)));
                            warn!(attempt, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(TwilioError::RateLimited {
                            retry_after_ms: retry_result.map_or(60_000, |d| d.as_millis() as u64),
                        });
                    }

                    let status = response.status();
                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        return Err(TwilioError::Unauthorized);
                    }
                    if status == StatusCode::NOT_FOUND {
                        return Err(TwilioError::NotFound {
                            resource: url.to_string(),
                        });
                    }
                    if !status.is_success() {
                        let body = response.text().await.unwrap_or_default();
                        return Err(TwilioError::Api {
                            message: format!("HTTP {status}: {body}"),
                            status_code: Some(status.as_u16()),
                            error_code: None,
                        });
                    }

                    let bytes = response.bytes().await.map_err(TwilioError::Http)?;
                    return Ok(bytes.to_vec());
                }
                Err(e) => {
                    if attempt < self.max_retries {
                        warn!(attempt, error = %e, "request failed, will retry");
                        last_err = Some(TwilioError::Http(e));
                        continue;
                    }
                    return Err(TwilioError::Http(e));
                }
            }
        }

        Err(last_err.unwrap_or(TwilioError::Api {
            message: "Max retries exceeded".into(),
            status_code: None,
            error_code: None,
        }))
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> TwilioResult<serde_json::Value> {
        self.execute(|| self.http.post(url).json(body)).await
    }

    async fn delete(&self, url: &str) -> TwilioResult<()> {
        let resp = self.execute(|| self.http.delete(url)).await;
        match resp {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> TwilioResult<serde_json::Value> {
        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = Duration::from_millis(500 * u64::from(attempt));
                debug!(attempt, delay_ms = delay.as_millis(), "retrying request");
                fcp_async_core::time::sleep(delay).await;
            }

            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        if attempt < self.max_retries {
                            let wait = retry_result
                                .unwrap_or(Duration::from_millis(500 * u64::from(attempt + 1)));
                            warn!(attempt, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(TwilioError::RateLimited {
                            retry_after_ms: retry_result.map_or(60_000, |d| d.as_millis() as u64),
                        });
                    }

                    let status = response.status();

                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        return Err(TwilioError::Unauthorized);
                    }

                    if status == StatusCode::NOT_FOUND {
                        let body = response.text().await.unwrap_or_default();
                        return Err(TwilioError::NotFound { resource: body });
                    }

                    if status.is_server_error() {
                        let body = response.text().await.unwrap_or_default();
                        let err = TwilioError::Api {
                            message: format!("Server error {status}: {body}"),
                            status_code: Some(status.as_u16()),
                            error_code: None,
                        };
                        if attempt < self.max_retries {
                            warn!(attempt, status = %status, "server error, will retry");
                            last_err = Some(err);
                            continue;
                        }
                        return Err(err);
                    }

                    if !status.is_success() {
                        let body = response.text().await.unwrap_or_default();
                        let api_err: Option<ApiErrorResponse> = serde_json::from_str(&body).ok();
                        let (message, error_code) = api_err
                            .as_ref()
                            .map(|e| {
                                (
                                    e.message.clone().unwrap_or(format!("HTTP {status}")),
                                    e.code.map(|c| c.to_string()),
                                )
                            })
                            .unwrap_or((format!("HTTP {status}: {body}"), None));
                        return Err(TwilioError::Api {
                            message,
                            status_code: Some(status.as_u16()),
                            error_code,
                        });
                    }

                    let body = response.text().await.map_err(TwilioError::Http)?;
                    let data: serde_json::Value = serde_json::from_str(&body)?;
                    return Ok(data);
                }
                Err(e) => {
                    if attempt < self.max_retries {
                        warn!(attempt, error = %e, "request failed, will retry");
                        last_err = Some(TwilioError::Http(e));
                        continue;
                    }
                    return Err(TwilioError::Http(e));
                }
            }
        }

        Err(last_err.unwrap_or(TwilioError::Api {
            message: "Max retries exceeded".into(),
            status_code: None,
            error_code: None,
        }))
    }

    #[allow(clippy::option_option)]
    fn check_rate_limit(response: &Response) -> Option<Option<Duration>> {
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs);
            Some(retry_after)
        } else {
            None
        }
    }
}

/// Ensure a phone number has the `whatsapp:` prefix.
fn ensure_whatsapp_prefix(number: &str) -> String {
    if number.starts_with("whatsapp:") {
        number.to_string()
    } else {
        format!("whatsapp:{number}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    fn test_client(base_url: &str) -> TwilioClient {
        TwilioClient::new("ACtest123", "test_auth_token")
            .unwrap()
            .with_base_url(base_url)
            .with_retry_config(0)
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("POST"))
            .and(path("/2010-04-01/Accounts/ACtest123/Messages.json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "sid": "SMtest123",
                "status": "queued",
                "to": "+15551234567",
                "from": "+15559876543",
                "body": "Hello from FCP!",
                "date_created": "2026-03-01T00:00:00Z"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let msg = client
            .send_message(
                "+15551234567",
                "+15559876543",
                "Hello from FCP!",
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(msg.sid, "SMtest123");
        assert_eq!(msg.status, "queued");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_message() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123/Messages/SMabc.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sid": "SMabc",
                "status": "delivered",
                "to": "+15551234567",
                "from": "+15559876543",
                "body": "Test message",
                "date_created": "2026-03-01T00:00:00Z",
                "num_media": "0"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let msg = client.get_message("SMabc").await.unwrap();
        assert_eq!(msg.sid, "SMabc");
        assert_eq!(msg.status, "delivered");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_messages() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123/Messages.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "messages": [
                    { "sid": "SM1", "status": "delivered", "to": "+1", "from": "+2" },
                    { "sid": "SM2", "status": "sent", "to": "+3", "from": "+4" }
                ],
                "next_page_uri": null
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client
            .list_messages(None, None, None, Some(20), None)
            .await
            .unwrap();
        assert_eq!(result.messages.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_call() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("POST"))
            .and(path("/2010-04-01/Accounts/ACtest123/Calls.json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "sid": "CAtest",
                "status": "queued",
                "to": "+15551234567",
                "from": "+15559876543",
                "date_created": "2026-03-01T00:00:00Z"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let call = client
            .create_call(
                "+15551234567",
                "+15559876543",
                "https://example.com/twiml",
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(call.sid, "CAtest");
        assert_eq!(call.status, "queued");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_call() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123/Calls/CAxyz.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sid": "CAxyz",
                "status": "completed",
                "to": "+15551234567",
                "from": "+15559876543",
                "duration": "42",
                "date_created": "2026-03-01T00:00:00Z",
                "price": "-0.0100"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let call = client.get_call("CAxyz").await.unwrap();
        assert_eq!(call.sid, "CAxyz");
        assert_eq!(call.duration.as_deref(), Some("42"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_hangup_call() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("POST"))
            .and(path(
                "/2010-04-01/Accounts/ACtest123/Calls/CAactive.json",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sid": "CAactive",
                "status": "completed",
                "to": "+15551234567",
                "from": "+15559876543",
                "duration": "120",
                "date_created": "2026-03-01T00:00:00Z"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let call = client.hangup_call("CAactive").await.unwrap();
        assert_eq!(call.sid, "CAactive");
        assert_eq!(call.status, "completed");
        assert_eq!(call.duration.as_deref(), Some("120"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_calls() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123/Calls.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "calls": [
                    { "sid": "CA1", "status": "completed", "to": "+1", "from": "+2", "duration": "30" },
                    { "sid": "CA2", "status": "in-progress", "to": "+3", "from": "+4" }
                ],
                "next_page_uri": null
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client
            .list_calls(None, None, None, None, None, Some(20), None)
            .await
            .unwrap();
        assert_eq!(result.calls.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_calls_with_filters() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123/Calls.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "calls": [
                    { "sid": "CA1", "status": "completed", "to": "+15551234567", "from": "+2" }
                ],
                "next_page_uri": "/next"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client
            .list_calls(
                Some("+15551234567"),
                None,
                Some("completed"),
                None,
                None,
                Some(10),
                Some(0),
            )
            .await
            .unwrap();
        assert_eq!(result.calls.len(), 1);
        assert_eq!(result.next_page_uri.as_deref(), Some("/next"));
    }

    #[test]
    fn test_generate_twiml_say() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Say,
            Some("Hello world"),
            None,
            Some("alice"),
            Some("en-US"),
            None,
            None,
            None,
            None,
        );
        assert!(xml.contains("<Response>"));
        assert!(xml.contains("</Response>"));
        assert!(xml.contains("<Say"));
        assert!(xml.contains("voice=\"alice\""));
        assert!(xml.contains("language=\"en-US\""));
        assert!(xml.contains("Hello world"));
    }

    #[test]
    fn test_generate_twiml_say_defaults() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Say,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(xml.contains("voice=\"alice\""));
        assert!(xml.contains("language=\"en-US\""));
        assert!(xml.contains("Hello from FCP."));
    }

    #[test]
    fn test_generate_twiml_play() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Play,
            None,
            Some("https://example.com/audio.mp3"),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(xml.contains("<Play>https://example.com/audio.mp3</Play>"));
    }

    #[test]
    fn test_generate_twiml_gather() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Gather,
            Some("Press 1 for help"),
            None,
            None,
            None,
            Some("1"),
            None,
            None,
            None,
        );
        assert!(xml.contains("<Gather numDigits=\"1\">"));
        assert!(xml.contains("Press 1 for help"));
        assert!(xml.contains("</Gather>"));
    }

    #[test]
    fn test_generate_twiml_dial() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Dial,
            None,
            None,
            None,
            None,
            None,
            Some("+15551234567"),
            None,
            None,
        );
        assert!(xml.contains("<Dial>+15551234567</Dial>"));
    }

    #[test]
    fn test_generate_twiml_pause() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Pause,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(5),
            None,
        );
        assert!(xml.contains("<Pause length=\"5\"/>"));
    }

    #[test]
    fn test_generate_twiml_pause_default_length() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Pause,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(xml.contains("<Pause length=\"1\"/>"));
    }

    #[test]
    fn test_generate_twiml_reject() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Reject,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some("busy"),
        );
        assert!(xml.contains("<Reject reason=\"busy\"/>"));
    }

    #[test]
    fn test_generate_twiml_reject_default_reason() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Reject,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(xml.contains("<Reject reason=\"rejected\"/>"));
    }

    #[test]
    fn test_generate_twiml_hangup() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Hangup,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(xml.contains("<Hangup/>"));
    }

    #[test]
    fn test_generate_twiml_xml_escaping() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Say,
            Some("Hello <world> & \"friends\""),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(xml.contains("Hello &lt;world&gt; &amp; &quot;friends&quot;"));
        assert!(!xml.contains("<world>"));
    }

    #[test]
    fn test_generate_twiml_has_xml_declaration() {
        let xml = TwilioClient::generate_twiml(
            &TwimlTemplate::Say,
            Some("Hi"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    }

    #[test]
    fn test_escape_xml() {
        assert_eq!(TwilioClient::escape_xml("hello"), "hello");
        assert_eq!(TwilioClient::escape_xml("<>"), "&lt;&gt;");
        assert_eq!(TwilioClient::escape_xml("a&b"), "a&amp;b");
        assert_eq!(TwilioClient::escape_xml("\"x\""), "&quot;x&quot;");
        assert_eq!(TwilioClient::escape_xml("it's"), "it&apos;s");
        assert_eq!(
            TwilioClient::escape_xml("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&apos;xss&apos;)&lt;/script&gt;"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_account() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sid": "ACtest123",
                "friendly_name": "Test Account",
                "status": "active",
                "type": "Full"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let account = client.get_account().await.unwrap();
        assert_eq!(account.sid, "ACtest123");
        assert_eq!(account.friendly_name.as_deref(), Some("Test Account"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_phone_numbers() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path(
                "/2010-04-01/Accounts/ACtest123/IncomingPhoneNumbers.json",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "incoming_phone_numbers": [
                    { "sid": "PN1", "phone_number": "+15551234567", "friendly_name": "Main" }
                ],
                "next_page_uri": null
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.list_phone_numbers(None, None).await.unwrap();
        assert_eq!(result.incoming_phone_numbers.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123.json"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.get_account().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TwilioError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path(
                "/2010-04-01/Accounts/ACtest123/Messages/SMmissing.json",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "code": 20404,
                "message": "The requested resource was not found"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.get_message("SMmissing").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TwilioError::NotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123.json"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.get_account().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TwilioError::RateLimited { .. }
        ));
    }

    #[test]
    fn test_error_is_retryable() {
        let err = TwilioError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = TwilioError::Unauthorized;
        assert!(!err.is_retryable());

        let err = TwilioError::Api {
            message: "Server error".into(),
            status_code: Some(500),
            error_code: None,
        };
        assert!(err.is_retryable());

        let err = TwilioError::NotFound {
            resource: "message".into(),
        };
        assert!(!err.is_retryable());
    }

    // ── TwilioAuth tests ────────────────────────────────────────────────

    #[test]
    fn auth_token_redacted_label() {
        let auth = TwilioAuth::Token {
            account_sid: "ACtest".into(),
            auth_token: "secret123".into(),
        };
        assert_eq!(auth.redacted_label(), "token");
    }

    #[test]
    fn auth_credential_id_redacted_label() {
        let auth = TwilioAuth::CredentialId {
            account_sid: "ACtest".into(),
            credential_id: CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
        };
        assert_eq!(auth.redacted_label(), "credential_id");
    }

    #[test]
    fn auth_token_is_not_secretless() {
        let auth = TwilioAuth::Token {
            account_sid: "ACtest".into(),
            auth_token: "token".into(),
        };
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        let auth = TwilioAuth::CredentialId {
            account_sid: "ACtest".into(),
            credential_id: CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
        };
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_account_sid_from_token() {
        let auth = TwilioAuth::Token {
            account_sid: "ACabc123".into(),
            auth_token: "tok".into(),
        };
        assert_eq!(auth.account_sid(), "ACabc123");
    }

    #[test]
    fn auth_account_sid_from_credential_id() {
        let auth = TwilioAuth::CredentialId {
            account_sid: "ACxyz789".into(),
            credential_id: CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
        };
        assert_eq!(auth.account_sid(), "ACxyz789");
    }

    #[test]
    fn auth_token_debug_redacts_auth_token() {
        let auth = TwilioAuth::Token {
            account_sid: "ACdebug".into(),
            auth_token: "super_secret_should_not_appear".into(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("ACdebug"), "debug: {debug}");
        assert!(debug.contains("[REDACTED]"), "debug: {debug}");
        assert!(
            !debug.contains("super_secret_should_not_appear"),
            "debug: {debug}"
        );
    }

    #[test]
    fn auth_credential_id_debug_shows_id() {
        let cid = uuid::Uuid::new_v4();
        let auth = TwilioAuth::CredentialId {
            account_sid: "ACdebug2".into(),
            credential_id: CredentialId::parse(&cid.to_string()).unwrap(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("ACdebug2"), "debug: {debug}");
        assert!(debug.contains("CredentialId"), "debug: {debug}");
    }

    #[test]
    fn auth_clone_token() {
        let original = TwilioAuth::Token {
            account_sid: "ACclone".into(),
            auth_token: "tok_clone".into(),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.account_sid(), "ACclone");
        assert_eq!(cloned.redacted_label(), "token");
    }

    #[test]
    fn auth_clone_credential_id() {
        let original = TwilioAuth::CredentialId {
            account_sid: "ACclone2".into(),
            credential_id: CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.account_sid(), "ACclone2");
        assert!(cloned.is_secretless());
    }

    // ── TwilioClient construction tests ─────────────────────────────────

    #[test]
    fn client_new_builds_with_default_base_url() {
        let client = TwilioClient::new("ACtest123", "auth_tok").unwrap();
        assert_eq!(client.account_sid(), "ACtest123");
    }

    #[test]
    fn client_with_base_url_overrides() {
        let client = TwilioClient::new("ACtest123", "tok")
            .unwrap()
            .with_base_url("http://localhost:8888");
        assert_eq!(client.account_sid(), "ACtest123");
        let debug = format!("{client:?}");
        assert!(debug.contains("http://localhost:8888"), "debug: {debug}");
    }

    #[test]
    fn client_with_retry_config() {
        let client = TwilioClient::new("ACtest", "tok")
            .unwrap()
            .with_retry_config(5);
        let debug = format!("{client:?}");
        assert!(debug.contains("max_retries: 5"), "debug: {debug}");
    }

    #[test]
    fn client_debug_format_contains_key_fields() {
        let client = TwilioClient::new("ACfmt", "tok")
            .unwrap()
            .with_base_url("http://test.local")
            .with_retry_config(3);
        let debug = format!("{client:?}");
        assert!(debug.contains("TwilioClient"), "debug: {debug}");
        assert!(debug.contains("ACfmt"), "debug: {debug}");
        assert!(debug.contains("http://test.local"), "debug: {debug}");
        assert!(debug.contains("max_retries: 3"), "debug: {debug}");
    }

    #[test]
    fn client_new_with_auth_token_mode() {
        let client = TwilioClient::new_with_auth(TwilioAuth::Token {
            account_sid: "ACnew".into(),
            auth_token: "tok_new".into(),
        })
        .unwrap();
        assert_eq!(client.account_sid(), "ACnew");
    }

    #[test]
    fn client_new_with_auth_credential_id_mode() {
        let cid = CredentialId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        let client = TwilioClient::new_with_auth(TwilioAuth::CredentialId {
            account_sid: "ACcred".into(),
            credential_id: cid,
        })
        .unwrap();
        assert_eq!(client.account_sid(), "ACcred");
    }

    #[test]
    fn client_default_retry_is_two() {
        let client = TwilioClient::new("ACtest", "tok").unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("max_retries: 2"), "debug: {debug}");
    }

    #[test]
    fn client_base_url_includes_account_sid() {
        let client = TwilioClient::new("ACurl123", "tok").unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("ACurl123"), "debug: {debug}");
        // The base URL should contain the default API base + account SID
        let expected_url = format!("{DEFAULT_API_BASE}/ACurl123");
        assert!(debug.contains(&expected_url), "debug: {debug}");
    }

    // ── Default API base constant ───────────────────────────────────────

    #[test]
    fn default_api_base_is_twilio() {
        assert!(DEFAULT_API_BASE.contains("api.twilio.com"));
        assert!(DEFAULT_API_BASE.contains("2010-04-01"));
        assert!(DEFAULT_API_BASE.contains("Accounts"));
    }

    // ── Wiremock edge case tests ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_list_recordings() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123/Recordings.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "recordings": [
                    {"sid": "RE1", "duration": "30"},
                    {"sid": "RE2", "duration": "60"}
                ],
                "next_page_uri": null
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.list_recordings(None, None, None).await.unwrap();
        assert_eq!(result.recordings.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_forbidden_returns_unauthorized() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123.json"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.get_account().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TwilioError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_api_error_with_error_body() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123/Messages.json"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "code": 21211,
                "message": "Invalid 'To' Phone Number"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.list_messages(None, None, None, None, None).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TwilioError::Api {
                message,
                status_code,
                error_code,
            } => {
                assert_eq!(message, "Invalid 'To' Phone Number");
                assert_eq!(status_code, Some(400));
                assert_eq!(error_code, Some("21211".to_string()));
            }
            e => panic!("Expected Api error, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_server_error_no_retry() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123.json"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.get_account().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TwilioError::Api {
                status_code,
                message,
                ..
            } => {
                assert_eq!(status_code, Some(503));
                assert!(message.contains("503"), "msg: {message}");
            }
            e => panic!("Expected Api error, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_with_media_url() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("POST"))
            .and(path("/2010-04-01/Accounts/ACtest123/Messages.json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "sid": "SMmedia",
                "status": "queued",
                "to": "+15551111111",
                "from": "+15552222222",
                "body": "With media",
                "num_media": "1"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let media = vec!["https://example.com/image.png".to_string()];
        let msg = client
            .send_message(
                "+15551111111",
                "+15552222222",
                "With media",
                Some(&media),
                None,
            )
            .await
            .unwrap();
        assert_eq!(msg.sid, "SMmedia");
        assert_eq!(msg.num_media.as_deref(), Some("1"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_with_callback() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("POST"))
            .and(path("/2010-04-01/Accounts/ACtest123/Messages.json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "sid": "SMcb",
                "status": "queued",
                "to": "+15551111111",
                "from": "+15552222222",
                "body": "With callback"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let msg = client
            .send_message(
                "+15551111111",
                "+15552222222",
                "With callback",
                None,
                Some("https://example.com/callback"),
            )
            .await
            .unwrap();
        assert_eq!(msg.sid, "SMcb");
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_call_with_all_options() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("POST"))
            .and(path("/2010-04-01/Accounts/ACtest123/Calls.json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "sid": "CAfull",
                "status": "queued",
                "to": "+15551111111",
                "from": "+15552222222"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let call = client
            .create_call(
                "+15551111111",
                "+15552222222",
                "https://example.com/twiml",
                Some("https://example.com/status"),
                Some(30),
                Some(true),
            )
            .await
            .unwrap();
        assert_eq!(call.sid, "CAfull");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_messages_with_filters() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123/Messages.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "messages": [{"sid": "SMfiltered"}],
                "next_page_uri": null
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client
            .list_messages(
                Some("+15551111111"),
                Some("+15552222222"),
                Some("2026-03-01"),
                Some(10),
                Some(0),
            )
            .await
            .unwrap();
        assert_eq!(result.messages.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_phone_numbers_with_filter() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path(
                "/2010-04-01/Accounts/ACtest123/IncomingPhoneNumbers.json",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "incoming_phone_numbers": [
                    {"sid": "PNfiltered", "phone_number": "+15551234567"}
                ],
                "next_page_uri": null
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client
            .list_phone_numbers(Some("+15551234567"), Some(10))
            .await
            .unwrap();
        assert_eq!(result.incoming_phone_numbers.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_recordings_with_filters() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123/Recordings.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "recordings": [{"sid": "REfiltered"}],
                "next_page_uri": null
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client
            .list_recordings(Some("CA123"), Some("2026-03-01"), Some(5))
            .await
            .unwrap();
        assert_eq!(result.recordings.len(), 1);
    }

    // ── Media operations tests ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_list_media() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path(
                "/2010-04-01/Accounts/ACtest123/Messages/SMabc/Media.json",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "media_list": [
                    {
                        "sid": "ME001",
                        "account_sid": "ACtest123",
                        "parent_sid": "SMabc",
                        "content_type": "image/jpeg",
                        "date_created": "2026-03-01T00:00:00Z"
                    },
                    {
                        "sid": "ME002",
                        "account_sid": "ACtest123",
                        "parent_sid": "SMabc",
                        "content_type": "image/png",
                        "date_created": "2026-03-01T00:01:00Z"
                    }
                ],
                "next_page_uri": null
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.list_media("SMabc", None, None).await.unwrap();
        assert_eq!(result.media_list.len(), 2);
        assert!(result.next_page_uri.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_media_with_pagination() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path(
                "/2010-04-01/Accounts/ACtest123/Messages/SMabc/Media.json",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "media_list": [
                    {"sid": "ME001", "content_type": "image/jpeg"}
                ],
                "next_page_uri": "/2010-04-01/Accounts/ACtest123/Messages/SMabc/Media.json?Page=1"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.list_media("SMabc", Some(1), Some(0)).await.unwrap();
        assert_eq!(result.media_list.len(), 1);
        assert!(result.next_page_uri.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_media_empty() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path(
                "/2010-04-01/Accounts/ACtest123/Messages/SMnomedia/Media.json",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "media_list": [],
                "next_page_uri": null
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.list_media("SMnomedia", None, None).await.unwrap();
        assert!(result.media_list.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_media() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path(
                "/2010-04-01/Accounts/ACtest123/Messages/SMabc/Media/ME001.json",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sid": "ME001",
                "account_sid": "ACtest123",
                "parent_sid": "SMabc",
                "content_type": "image/jpeg",
                "date_created": "2026-03-01T00:00:00Z",
                "date_updated": "2026-03-01T00:00:01Z",
                "uri": "/2010-04-01/Accounts/ACtest123/Messages/SMabc/Media/ME001.json"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let media = client.get_media("SMabc", "ME001").await.unwrap();
        assert_eq!(media.sid, "ME001");
        assert_eq!(media.content_type.as_deref(), Some("image/jpeg"));
        assert_eq!(media.parent_sid.as_deref(), Some("SMabc"));
        assert_eq!(media.account_sid.as_deref(), Some("ACtest123"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_media_not_found() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path(
                "/2010-04-01/Accounts/ACtest123/Messages/SMabc/Media/MEmissing.json",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "code": 20404,
                "message": "The requested resource was not found"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.get_media("SMabc", "MEmissing").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TwilioError::NotFound { .. }));
    }
}
