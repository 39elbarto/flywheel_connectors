//! Twilio API types.

use serde::{Deserialize, Serialize};

/// A Twilio SMS/MMS message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwilioMessage {
    pub sid: String,
    pub status: String,
    pub to: String,
    pub from: String,
    pub body: Option<String>,
    pub date_created: Option<String>,
    pub date_updated: Option<String>,
    pub date_sent: Option<String>,
    pub price: Option<String>,
    pub price_unit: Option<String>,
    pub num_media: Option<String>,
    pub num_segments: Option<String>,
    pub direction: Option<String>,
    pub uri: Option<String>,
}

/// A Twilio voice call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwilioCall {
    pub sid: String,
    pub status: String,
    pub to: String,
    pub from: String,
    pub duration: Option<String>,
    pub date_created: Option<String>,
    pub date_updated: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub price: Option<String>,
    pub price_unit: Option<String>,
    pub direction: Option<String>,
    pub uri: Option<String>,
}

/// A Twilio recording.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwilioRecording {
    pub sid: String,
    pub call_sid: Option<String>,
    pub duration: Option<String>,
    pub date_created: Option<String>,
    pub date_updated: Option<String>,
    pub status: Option<String>,
    pub channels: Option<u32>,
    pub source: Option<String>,
    pub uri: Option<String>,
}

/// A Twilio account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwilioAccount {
    pub sid: String,
    pub friendly_name: Option<String>,
    pub status: Option<String>,
    #[serde(rename = "type")]
    pub account_type: Option<String>,
    pub date_created: Option<String>,
    pub date_updated: Option<String>,
}

/// A Twilio phone number.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhoneNumber {
    pub sid: Option<String>,
    pub phone_number: Option<String>,
    pub friendly_name: Option<String>,
    pub capabilities: Option<PhoneNumberCapabilities>,
    pub date_created: Option<String>,
    pub date_updated: Option<String>,
    pub status: Option<String>,
}

/// Phone number capabilities (SMS, MMS, voice, fax).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhoneNumberCapabilities {
    pub sms: Option<bool>,
    pub mms: Option<bool>,
    pub voice: Option<bool>,
    pub fax: Option<bool>,
}

/// Twilio list response wrapper for messages.
#[derive(Debug, Clone, Deserialize)]
pub struct MessageListResponse {
    pub messages: Vec<serde_json::Value>,
    pub next_page_uri: Option<String>,
}

/// Twilio list response wrapper for recordings.
#[derive(Debug, Clone, Deserialize)]
pub struct RecordingListResponse {
    pub recordings: Vec<serde_json::Value>,
    pub next_page_uri: Option<String>,
}

/// Twilio list response wrapper for incoming phone numbers.
#[derive(Debug, Clone, Deserialize)]
pub struct PhoneNumberListResponse {
    pub incoming_phone_numbers: Vec<serde_json::Value>,
    pub next_page_uri: Option<String>,
}

/// Twilio API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub code: Option<u32>,
    pub message: Option<String>,
    pub status: Option<u16>,
    pub more_info: Option<String>,
}
