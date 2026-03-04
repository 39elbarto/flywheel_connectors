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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn twilio_message_serde() {
        let msg = TwilioMessage {
            sid: "SM123".into(),
            status: "delivered".into(),
            to: "+15551234567".into(),
            from: "+15559876543".into(),
            body: Some("Hello!".into()),
            date_created: Some("2026-03-01T00:00:00Z".into()),
            date_updated: None,
            date_sent: None,
            price: Some("-0.0075".into()),
            price_unit: Some("USD".into()),
            num_media: Some("0".into()),
            num_segments: Some("1".into()),
            direction: Some("outbound-api".into()),
            uri: None,
        };
        let json_str = serde_json::to_string(&msg).unwrap();
        let back: TwilioMessage = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.sid, "SM123");
        assert_eq!(back.status, "delivered");
    }

    #[test]
    fn twilio_call_serde() {
        let call = TwilioCall {
            sid: "CA123".into(),
            status: "completed".into(),
            to: "+15551234567".into(),
            from: "+15559876543".into(),
            duration: Some("120".into()),
            date_created: None,
            date_updated: None,
            start_time: None,
            end_time: None,
            price: Some("-0.02".into()),
            price_unit: Some("USD".into()),
            direction: Some("outbound-dial".into()),
            uri: None,
        };
        let json_str = serde_json::to_string(&call).unwrap();
        let back: TwilioCall = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.sid, "CA123");
        assert_eq!(back.duration.as_deref(), Some("120"));
    }

    #[test]
    fn twilio_recording_serde() {
        let rec = TwilioRecording {
            sid: "RE123".into(),
            call_sid: Some("CA123".into()),
            duration: Some("60".into()),
            date_created: None,
            date_updated: None,
            status: Some("completed".into()),
            channels: Some(1),
            source: Some("RecordVerb".into()),
            uri: None,
        };
        let json_str = serde_json::to_string(&rec).unwrap();
        let back: TwilioRecording = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.channels, Some(1));
    }

    #[test]
    fn twilio_account_type_rename() {
        let acct = TwilioAccount {
            sid: "AC123".into(),
            friendly_name: Some("My Account".into()),
            status: Some("active".into()),
            account_type: Some("Full".into()),
            date_created: None,
            date_updated: None,
        };
        let json_str = serde_json::to_string(&acct).unwrap();
        assert!(json_str.contains("\"type\":\"Full\""));
        let back: TwilioAccount = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.account_type.as_deref(), Some("Full"));
    }

    #[test]
    fn phone_number_capabilities() {
        let pn = PhoneNumber {
            sid: Some("PN123".into()),
            phone_number: Some("+15551234567".into()),
            friendly_name: Some("My Number".into()),
            capabilities: Some(PhoneNumberCapabilities {
                sms: Some(true),
                mms: Some(true),
                voice: Some(true),
                fax: Some(false),
            }),
            date_created: None,
            date_updated: None,
            status: None,
        };
        let json_str = serde_json::to_string(&pn).unwrap();
        let back: PhoneNumber = serde_json::from_str(&json_str).unwrap();
        let caps = back.capabilities.unwrap();
        assert!(caps.sms.unwrap());
        assert!(!caps.fax.unwrap());
    }

    #[test]
    fn message_list_response_serde() {
        let json = json!({
            "messages": [{"sid": "SM1"}],
            "next_page_uri": "/2010-04-01/Accounts/AC/Messages?Page=1"
        });
        let resp: MessageListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.messages.len(), 1);
        assert!(resp.next_page_uri.is_some());
    }

    #[test]
    fn recording_list_response_serde() {
        let json = json!({"recordings": [], "next_page_uri": null});
        let resp: RecordingListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.recordings.is_empty());
        assert!(resp.next_page_uri.is_none());
    }

    #[test]
    fn phone_number_list_response_serde() {
        let json = json!({"incoming_phone_numbers": [{"sid": "PN1"}]});
        let resp: PhoneNumberListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.incoming_phone_numbers.len(), 1);
    }

    #[test]
    fn api_error_response_serde() {
        let json = json!({
            "code": 20003,
            "message": "Authentication Error",
            "status": 401,
            "more_info": "https://www.twilio.com/docs/errors/20003"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.code, Some(20003));
        assert_eq!(err.status, Some(401));
    }
}
