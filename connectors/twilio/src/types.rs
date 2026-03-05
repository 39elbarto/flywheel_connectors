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

    // ── TwilioMessage tests ──────────────────────────────────────────────

    #[test]
    fn twilio_message_roundtrip_full() {
        let msg = TwilioMessage {
            sid: "SM123".into(),
            status: "delivered".into(),
            to: "+15551234567".into(),
            from: "+15559876543".into(),
            body: Some("Hello!".into()),
            date_created: Some("2026-03-01T00:00:00Z".into()),
            date_updated: Some("2026-03-01T00:01:00Z".into()),
            date_sent: Some("2026-03-01T00:00:30Z".into()),
            price: Some("-0.0075".into()),
            price_unit: Some("USD".into()),
            num_media: Some("0".into()),
            num_segments: Some("1".into()),
            direction: Some("outbound-api".into()),
            uri: Some("/2010-04-01/Accounts/AC/Messages/SM123.json".into()),
        };
        let json_str = serde_json::to_string(&msg).unwrap();
        let back: TwilioMessage = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.sid, "SM123");
        assert_eq!(back.status, "delivered");
        assert_eq!(back.to, "+15551234567");
        assert_eq!(back.from, "+15559876543");
        assert_eq!(back.body.as_deref(), Some("Hello!"));
        assert_eq!(back.date_created.as_deref(), Some("2026-03-01T00:00:00Z"));
        assert_eq!(back.date_updated.as_deref(), Some("2026-03-01T00:01:00Z"));
        assert_eq!(back.date_sent.as_deref(), Some("2026-03-01T00:00:30Z"));
        assert_eq!(back.price.as_deref(), Some("-0.0075"));
        assert_eq!(back.price_unit.as_deref(), Some("USD"));
        assert_eq!(back.num_media.as_deref(), Some("0"));
        assert_eq!(back.num_segments.as_deref(), Some("1"));
        assert_eq!(back.direction.as_deref(), Some("outbound-api"));
        assert!(back.uri.is_some());
    }

    #[test]
    fn twilio_message_missing_optional_fields() {
        let json = json!({
            "sid": "SM999",
            "status": "queued",
            "to": "+1",
            "from": "+2"
        });
        let msg: TwilioMessage = serde_json::from_value(json).unwrap();
        assert_eq!(msg.sid, "SM999");
        assert!(msg.body.is_none());
        assert!(msg.date_created.is_none());
        assert!(msg.date_updated.is_none());
        assert!(msg.date_sent.is_none());
        assert!(msg.price.is_none());
        assert!(msg.price_unit.is_none());
        assert!(msg.num_media.is_none());
        assert!(msg.num_segments.is_none());
        assert!(msg.direction.is_none());
        assert!(msg.uri.is_none());
    }

    #[test]
    fn twilio_message_null_optional_fields() {
        let json = json!({
            "sid": "SM1",
            "status": "sent",
            "to": "+1",
            "from": "+2",
            "body": null,
            "price": null,
            "direction": null
        });
        let msg: TwilioMessage = serde_json::from_value(json).unwrap();
        assert!(msg.body.is_none());
        assert!(msg.price.is_none());
        assert!(msg.direction.is_none());
    }

    #[test]
    fn twilio_message_clone() {
        let msg = TwilioMessage {
            sid: "SM1".into(),
            status: "sent".into(),
            to: "+1".into(),
            from: "+2".into(),
            body: Some("hi".into()),
            date_created: None,
            date_updated: None,
            date_sent: None,
            price: None,
            price_unit: None,
            num_media: None,
            num_segments: None,
            direction: None,
            uri: None,
        };
        let cloned = msg.clone();
        assert_eq!(cloned.sid, msg.sid);
        assert_eq!(cloned.body, msg.body);
    }

    #[test]
    fn twilio_message_debug() {
        let msg = TwilioMessage {
            sid: "SM_DBG".into(),
            status: "sent".into(),
            to: "+1".into(),
            from: "+2".into(),
            body: None,
            date_created: None,
            date_updated: None,
            date_sent: None,
            price: None,
            price_unit: None,
            num_media: None,
            num_segments: None,
            direction: None,
            uri: None,
        };
        let debug = format!("{msg:?}");
        assert!(debug.contains("SM_DBG"));
        assert!(debug.contains("TwilioMessage"));
    }

    #[test]
    fn twilio_message_serializes_null_optionals() {
        let msg = TwilioMessage {
            sid: "SM1".into(),
            status: "sent".into(),
            to: "+1".into(),
            from: "+2".into(),
            body: None,
            date_created: None,
            date_updated: None,
            date_sent: None,
            price: None,
            price_unit: None,
            num_media: None,
            num_segments: None,
            direction: None,
            uri: None,
        };
        let json_str = serde_json::to_string(&msg).unwrap();
        // Without skip_serializing_if, None fields should serialize as null
        assert!(
            json_str.contains("\"body\":null"),
            "body should be null in JSON: {json_str}"
        );
    }

    #[test]
    fn twilio_message_deserialize_missing_required_field_fails() {
        // Missing "status" should fail
        let json = json!({
            "sid": "SM1",
            "to": "+1",
            "from": "+2"
        });
        let result = serde_json::from_value::<TwilioMessage>(json);
        assert!(result.is_err());
    }

    // ── TwilioCall tests ─────────────────────────────────────────────────

    #[test]
    fn twilio_call_roundtrip_full() {
        let call = TwilioCall {
            sid: "CA123".into(),
            status: "completed".into(),
            to: "+15551234567".into(),
            from: "+15559876543".into(),
            duration: Some("120".into()),
            date_created: Some("2026-03-01T00:00:00Z".into()),
            date_updated: Some("2026-03-01T00:02:00Z".into()),
            start_time: Some("2026-03-01T00:00:00Z".into()),
            end_time: Some("2026-03-01T00:02:00Z".into()),
            price: Some("-0.02".into()),
            price_unit: Some("USD".into()),
            direction: Some("outbound-dial".into()),
            uri: Some("/2010-04-01/Accounts/AC/Calls/CA123.json".into()),
        };
        let json_str = serde_json::to_string(&call).unwrap();
        let back: TwilioCall = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.sid, "CA123");
        assert_eq!(back.duration.as_deref(), Some("120"));
        assert_eq!(back.start_time.as_deref(), Some("2026-03-01T00:00:00Z"));
        assert_eq!(back.end_time.as_deref(), Some("2026-03-01T00:02:00Z"));
        assert!(back.uri.is_some());
    }

    #[test]
    fn twilio_call_missing_optional_fields() {
        let json = json!({
            "sid": "CA1",
            "status": "ringing",
            "to": "+1",
            "from": "+2"
        });
        let call: TwilioCall = serde_json::from_value(json).unwrap();
        assert_eq!(call.sid, "CA1");
        assert!(call.duration.is_none());
        assert!(call.date_created.is_none());
        assert!(call.start_time.is_none());
        assert!(call.end_time.is_none());
        assert!(call.price.is_none());
        assert!(call.price_unit.is_none());
        assert!(call.direction.is_none());
        assert!(call.uri.is_none());
    }

    #[test]
    fn twilio_call_clone_and_debug() {
        let call = TwilioCall {
            sid: "CADBG".into(),
            status: "in-progress".into(),
            to: "+1".into(),
            from: "+2".into(),
            duration: None,
            date_created: None,
            date_updated: None,
            start_time: None,
            end_time: None,
            price: None,
            price_unit: None,
            direction: None,
            uri: None,
        };
        let cloned = call.clone();
        assert_eq!(cloned.sid, "CADBG");
        let debug = format!("{call:?}");
        assert!(debug.contains("CADBG"));
        assert!(debug.contains("TwilioCall"));
    }

    #[test]
    fn twilio_call_deserialize_missing_required_fails() {
        let json = json!({
            "sid": "CA1",
            "to": "+1",
            "from": "+2"
            // missing "status"
        });
        assert!(serde_json::from_value::<TwilioCall>(json).is_err());
    }

    // ── TwilioRecording tests ────────────────────────────────────────────

    #[test]
    fn twilio_recording_roundtrip_full() {
        let rec = TwilioRecording {
            sid: "RE123".into(),
            call_sid: Some("CA123".into()),
            duration: Some("60".into()),
            date_created: Some("2026-03-01T00:00:00Z".into()),
            date_updated: Some("2026-03-01T00:01:00Z".into()),
            status: Some("completed".into()),
            channels: Some(2),
            source: Some("RecordVerb".into()),
            uri: Some("/2010-04-01/Accounts/AC/Recordings/RE123.json".into()),
        };
        let json_str = serde_json::to_string(&rec).unwrap();
        let back: TwilioRecording = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.sid, "RE123");
        assert_eq!(back.call_sid.as_deref(), Some("CA123"));
        assert_eq!(back.channels, Some(2));
        assert_eq!(back.source.as_deref(), Some("RecordVerb"));
        assert!(back.uri.is_some());
    }

    #[test]
    fn twilio_recording_minimal() {
        let json = json!({"sid": "RE1"});
        let rec: TwilioRecording = serde_json::from_value(json).unwrap();
        assert_eq!(rec.sid, "RE1");
        assert!(rec.call_sid.is_none());
        assert!(rec.duration.is_none());
        assert!(rec.status.is_none());
        assert!(rec.channels.is_none());
        assert!(rec.source.is_none());
        assert!(rec.uri.is_none());
    }

    #[test]
    fn twilio_recording_channels_zero() {
        let json = json!({"sid": "RE2", "channels": 0});
        let rec: TwilioRecording = serde_json::from_value(json).unwrap();
        assert_eq!(rec.channels, Some(0));
    }

    #[test]
    fn twilio_recording_clone_and_debug() {
        let rec = TwilioRecording {
            sid: "REDBG".into(),
            call_sid: None,
            duration: None,
            date_created: None,
            date_updated: None,
            status: None,
            channels: None,
            source: None,
            uri: None,
        };
        let cloned = rec.clone();
        assert_eq!(cloned.sid, "REDBG");
        let debug = format!("{rec:?}");
        assert!(debug.contains("REDBG"));
    }

    #[test]
    fn twilio_recording_missing_sid_fails() {
        let json = json!({"call_sid": "CA1", "duration": "30"});
        assert!(serde_json::from_value::<TwilioRecording>(json).is_err());
    }

    // ── TwilioAccount tests ──────────────────────────────────────────────

    #[test]
    fn twilio_account_type_rename_roundtrip() {
        let acct = TwilioAccount {
            sid: "AC123".into(),
            friendly_name: Some("My Account".into()),
            status: Some("active".into()),
            account_type: Some("Full".into()),
            date_created: Some("2020-01-01T00:00:00Z".into()),
            date_updated: Some("2026-03-01T00:00:00Z".into()),
        };
        let json_str = serde_json::to_string(&acct).unwrap();
        // serde rename: account_type -> "type" in JSON
        assert!(json_str.contains("\"type\":\"Full\""), "JSON: {json_str}");
        assert!(
            !json_str.contains("\"account_type\""),
            "JSON should use 'type' not 'account_type': {json_str}"
        );
        let back: TwilioAccount = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.account_type.as_deref(), Some("Full"));
    }

    #[test]
    fn twilio_account_from_json_with_type_field() {
        let json = json!({
            "sid": "AC1",
            "type": "Trial"
        });
        let acct: TwilioAccount = serde_json::from_value(json).unwrap();
        assert_eq!(acct.account_type.as_deref(), Some("Trial"));
    }

    #[test]
    fn twilio_account_minimal() {
        let json = json!({"sid": "AC1"});
        let acct: TwilioAccount = serde_json::from_value(json).unwrap();
        assert_eq!(acct.sid, "AC1");
        assert!(acct.friendly_name.is_none());
        assert!(acct.status.is_none());
        assert!(acct.account_type.is_none());
        assert!(acct.date_created.is_none());
        assert!(acct.date_updated.is_none());
    }

    #[test]
    fn twilio_account_clone_and_debug() {
        let acct = TwilioAccount {
            sid: "ACDBG".into(),
            friendly_name: None,
            status: None,
            account_type: None,
            date_created: None,
            date_updated: None,
        };
        let cloned = acct.clone();
        assert_eq!(cloned.sid, "ACDBG");
        let debug = format!("{acct:?}");
        assert!(debug.contains("ACDBG"));
        assert!(debug.contains("TwilioAccount"));
    }

    #[test]
    fn twilio_account_missing_sid_fails() {
        let json = json!({"friendly_name": "Test"});
        assert!(serde_json::from_value::<TwilioAccount>(json).is_err());
    }

    // ── PhoneNumber tests ────────────────────────────────────────────────

    #[test]
    fn phone_number_full_roundtrip() {
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
            date_created: Some("2026-01-01T00:00:00Z".into()),
            date_updated: Some("2026-03-01T00:00:00Z".into()),
            status: Some("in-use".into()),
        };
        let json_str = serde_json::to_string(&pn).unwrap();
        let back: PhoneNumber = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.sid.as_deref(), Some("PN123"));
        assert_eq!(back.phone_number.as_deref(), Some("+15551234567"));
        let caps = back.capabilities.unwrap();
        assert!(caps.sms.unwrap());
        assert!(caps.mms.unwrap());
        assert!(caps.voice.unwrap());
        assert!(!caps.fax.unwrap());
    }

    #[test]
    fn phone_number_all_none() {
        let json = json!({});
        let pn: PhoneNumber = serde_json::from_value(json).unwrap();
        assert!(pn.sid.is_none());
        assert!(pn.phone_number.is_none());
        assert!(pn.friendly_name.is_none());
        assert!(pn.capabilities.is_none());
        assert!(pn.date_created.is_none());
        assert!(pn.date_updated.is_none());
        assert!(pn.status.is_none());
    }

    #[test]
    fn phone_number_clone_and_debug() {
        let pn = PhoneNumber {
            sid: Some("PNDBG".into()),
            phone_number: None,
            friendly_name: None,
            capabilities: None,
            date_created: None,
            date_updated: None,
            status: None,
        };
        let cloned = pn.clone();
        assert_eq!(cloned.sid, pn.sid);
        let debug = format!("{pn:?}");
        assert!(debug.contains("PNDBG"));
    }

    // ── PhoneNumberCapabilities tests ────────────────────────────────────

    #[test]
    fn capabilities_all_true() {
        let caps = PhoneNumberCapabilities {
            sms: Some(true),
            mms: Some(true),
            voice: Some(true),
            fax: Some(true),
        };
        let json_str = serde_json::to_string(&caps).unwrap();
        let back: PhoneNumberCapabilities = serde_json::from_str(&json_str).unwrap();
        assert!(back.sms.unwrap());
        assert!(back.mms.unwrap());
        assert!(back.voice.unwrap());
        assert!(back.fax.unwrap());
    }

    #[test]
    fn capabilities_all_false() {
        let caps = PhoneNumberCapabilities {
            sms: Some(false),
            mms: Some(false),
            voice: Some(false),
            fax: Some(false),
        };
        let json_str = serde_json::to_string(&caps).unwrap();
        let back: PhoneNumberCapabilities = serde_json::from_str(&json_str).unwrap();
        assert!(!back.sms.unwrap());
        assert!(!back.mms.unwrap());
        assert!(!back.voice.unwrap());
        assert!(!back.fax.unwrap());
    }

    #[test]
    fn capabilities_all_none() {
        let json = json!({});
        let caps: PhoneNumberCapabilities = serde_json::from_value(json).unwrap();
        assert!(caps.sms.is_none());
        assert!(caps.mms.is_none());
        assert!(caps.voice.is_none());
        assert!(caps.fax.is_none());
    }

    #[test]
    fn capabilities_partial() {
        let json = json!({"sms": true, "voice": false});
        let caps: PhoneNumberCapabilities = serde_json::from_value(json).unwrap();
        assert_eq!(caps.sms, Some(true));
        assert!(caps.mms.is_none());
        assert_eq!(caps.voice, Some(false));
        assert!(caps.fax.is_none());
    }

    #[test]
    fn capabilities_clone_and_debug() {
        let caps = PhoneNumberCapabilities {
            sms: Some(true),
            mms: None,
            voice: Some(false),
            fax: None,
        };
        let cloned = caps.clone();
        assert_eq!(cloned.sms, caps.sms);
        assert_eq!(cloned.voice, caps.voice);
        let debug = format!("{caps:?}");
        assert!(debug.contains("PhoneNumberCapabilities"));
    }

    // ── MessageListResponse tests ────────────────────────────────────────

    #[test]
    fn message_list_response_with_pagination() {
        let json = json!({
            "messages": [{"sid": "SM1"}, {"sid": "SM2"}],
            "next_page_uri": "/2010-04-01/Accounts/AC/Messages?Page=1"
        });
        let resp: MessageListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.messages.len(), 2);
        assert_eq!(
            resp.next_page_uri.as_deref(),
            Some("/2010-04-01/Accounts/AC/Messages?Page=1")
        );
    }

    #[test]
    fn message_list_response_no_pagination() {
        let json = json!({
            "messages": [{"sid": "SM1"}],
            "next_page_uri": null
        });
        let resp: MessageListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.messages.len(), 1);
        assert!(resp.next_page_uri.is_none());
    }

    #[test]
    fn message_list_response_empty() {
        let json = json!({"messages": []});
        let resp: MessageListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.messages.is_empty());
        assert!(resp.next_page_uri.is_none());
    }

    #[test]
    fn message_list_response_clone_and_debug() {
        let json = json!({"messages": [], "next_page_uri": null});
        let resp: MessageListResponse = serde_json::from_value(json).unwrap();
        let cloned = resp.clone();
        assert_eq!(cloned.messages.len(), resp.messages.len());
        let debug = format!("{resp:?}");
        assert!(debug.contains("MessageListResponse"));
    }

    // ── RecordingListResponse tests ──────────────────────────────────────

    #[test]
    fn recording_list_response_with_data() {
        let json = json!({
            "recordings": [{"sid": "RE1"}, {"sid": "RE2"}, {"sid": "RE3"}],
            "next_page_uri": "/next"
        });
        let resp: RecordingListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.recordings.len(), 3);
        assert_eq!(resp.next_page_uri.as_deref(), Some("/next"));
    }

    #[test]
    fn recording_list_response_empty() {
        let json = json!({"recordings": [], "next_page_uri": null});
        let resp: RecordingListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.recordings.is_empty());
        assert!(resp.next_page_uri.is_none());
    }

    #[test]
    fn recording_list_response_clone_and_debug() {
        let json = json!({"recordings": [{"sid": "RE1"}], "next_page_uri": null});
        let resp: RecordingListResponse = serde_json::from_value(json).unwrap();
        let cloned = resp.clone();
        assert_eq!(cloned.recordings.len(), 1);
        let debug = format!("{resp:?}");
        assert!(debug.contains("RecordingListResponse"));
    }

    // ── PhoneNumberListResponse tests ────────────────────────────────────

    #[test]
    fn phone_number_list_response_with_data() {
        let json = json!({
            "incoming_phone_numbers": [
                {"sid": "PN1", "phone_number": "+15551234567"},
                {"sid": "PN2"}
            ],
            "next_page_uri": null
        });
        let resp: PhoneNumberListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.incoming_phone_numbers.len(), 2);
        assert!(resp.next_page_uri.is_none());
    }

    #[test]
    fn phone_number_list_response_empty() {
        let json = json!({"incoming_phone_numbers": []});
        let resp: PhoneNumberListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.incoming_phone_numbers.is_empty());
    }

    #[test]
    fn phone_number_list_response_clone_and_debug() {
        let json = json!({"incoming_phone_numbers": [], "next_page_uri": null});
        let resp: PhoneNumberListResponse = serde_json::from_value(json).unwrap();
        let cloned = resp.clone();
        assert_eq!(cloned.incoming_phone_numbers.len(), 0);
        let debug = format!("{resp:?}");
        assert!(debug.contains("PhoneNumberListResponse"));
    }

    // ── ApiErrorResponse tests ───────────────────────────────────────────

    #[test]
    fn api_error_response_full() {
        let json = json!({
            "code": 20003,
            "message": "Authentication Error",
            "status": 401,
            "more_info": "https://www.twilio.com/docs/errors/20003"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.code, Some(20003));
        assert_eq!(err.message.as_deref(), Some("Authentication Error"));
        assert_eq!(err.status, Some(401));
        assert_eq!(
            err.more_info.as_deref(),
            Some("https://www.twilio.com/docs/errors/20003")
        );
    }

    #[test]
    fn api_error_response_minimal() {
        let json = json!({});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(err.code.is_none());
        assert!(err.message.is_none());
        assert!(err.status.is_none());
        assert!(err.more_info.is_none());
    }

    #[test]
    fn api_error_response_partial() {
        let json = json!({"code": 21211, "message": "Invalid 'To' Phone Number"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.code, Some(21211));
        assert_eq!(err.message.as_deref(), Some("Invalid 'To' Phone Number"));
        assert!(err.status.is_none());
        assert!(err.more_info.is_none());
    }

    #[test]
    fn api_error_response_clone_and_debug() {
        let json = json!({"code": 20003, "status": 401});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let cloned = err.clone();
        assert_eq!(cloned.code, err.code);
        assert_eq!(cloned.status, err.status);
        let debug = format!("{err:?}");
        assert!(debug.contains("ApiErrorResponse"));
        assert!(debug.contains("20003"));
    }

    // ── Cross-type deserialization edge cases ────────────────────────────

    #[test]
    fn message_from_api_json_with_extra_fields() {
        // Twilio API may include extra fields not in our struct
        let json = json!({
            "sid": "SM1",
            "status": "sent",
            "to": "+1",
            "from": "+2",
            "account_sid": "AC123",
            "api_version": "2010-04-01",
            "messaging_service_sid": null,
            "error_code": null,
            "error_message": null
        });
        // serde default deny_unknown_fields is off, so this should work
        let msg: TwilioMessage = serde_json::from_value(json).unwrap();
        assert_eq!(msg.sid, "SM1");
    }

    #[test]
    fn call_from_api_json_with_extra_fields() {
        let json = json!({
            "sid": "CA1",
            "status": "completed",
            "to": "+1",
            "from": "+2",
            "account_sid": "AC123",
            "forwarded_from": null,
            "caller_name": null
        });
        let call: TwilioCall = serde_json::from_value(json).unwrap();
        assert_eq!(call.sid, "CA1");
    }

    #[test]
    fn recording_from_api_json_with_extra_fields() {
        let json = json!({
            "sid": "RE1",
            "account_sid": "AC123",
            "api_version": "2010-04-01",
            "encryption_details": null
        });
        let rec: TwilioRecording = serde_json::from_value(json).unwrap();
        assert_eq!(rec.sid, "RE1");
    }

    // ── Serialization preserves null for None optional fields ────────────

    #[test]
    fn call_serializes_none_as_null() {
        let call = TwilioCall {
            sid: "CA1".into(),
            status: "queued".into(),
            to: "+1".into(),
            from: "+2".into(),
            duration: None,
            date_created: None,
            date_updated: None,
            start_time: None,
            end_time: None,
            price: None,
            price_unit: None,
            direction: None,
            uri: None,
        };
        let json_str = serde_json::to_string(&call).unwrap();
        // Without skip_serializing_if, None fields serialize as null
        assert!(json_str.contains("\"duration\":null"), "JSON: {json_str}");
        assert!(json_str.contains("\"price\":null"), "JSON: {json_str}");
    }

    #[test]
    fn recording_serializes_none_channels_as_null() {
        let rec = TwilioRecording {
            sid: "RE1".into(),
            call_sid: None,
            duration: None,
            date_created: None,
            date_updated: None,
            status: None,
            channels: None,
            source: None,
            uri: None,
        };
        let json_str = serde_json::to_string(&rec).unwrap();
        assert!(json_str.contains("\"channels\":null"), "JSON: {json_str}");
    }

    // ── Value roundtrip through serde_json::Value ────────────────────────

    #[test]
    fn message_value_roundtrip() {
        let msg = TwilioMessage {
            sid: "SMRT".into(),
            status: "delivered".into(),
            to: "+15551111111".into(),
            from: "+15552222222".into(),
            body: Some("roundtrip".into()),
            date_created: None,
            date_updated: None,
            date_sent: None,
            price: None,
            price_unit: None,
            num_media: None,
            num_segments: None,
            direction: None,
            uri: None,
        };
        let value = serde_json::to_value(&msg).unwrap();
        assert_eq!(value["sid"], "SMRT");
        assert_eq!(value["body"], "roundtrip");
        let back: TwilioMessage = serde_json::from_value(value).unwrap();
        assert_eq!(back.sid, "SMRT");
        assert_eq!(back.body.as_deref(), Some("roundtrip"));
    }

    #[test]
    fn account_value_roundtrip_type_rename() {
        let acct = TwilioAccount {
            sid: "ACRT".into(),
            friendly_name: Some("Test".into()),
            status: Some("active".into()),
            account_type: Some("Full".into()),
            date_created: None,
            date_updated: None,
        };
        let value = serde_json::to_value(&acct).unwrap();
        // "type" key in JSON, not "account_type"
        assert_eq!(value["type"], "Full");
        assert!(value.get("account_type").is_none());
        let back: TwilioAccount = serde_json::from_value(value).unwrap();
        assert_eq!(back.account_type.as_deref(), Some("Full"));
    }

    #[test]
    fn capabilities_value_roundtrip() {
        let caps = PhoneNumberCapabilities {
            sms: Some(true),
            mms: Some(false),
            voice: None,
            fax: Some(true),
        };
        let value = serde_json::to_value(&caps).unwrap();
        assert_eq!(value["sms"], true);
        assert_eq!(value["mms"], false);
        assert!(value["voice"].is_null());
        assert_eq!(value["fax"], true);
        let back: PhoneNumberCapabilities = serde_json::from_value(value).unwrap();
        assert_eq!(back.sms, Some(true));
        assert_eq!(back.mms, Some(false));
        assert!(back.voice.is_none());
        assert_eq!(back.fax, Some(true));
    }

    // ── Empty strings are valid values ───────────────────────────────────

    #[test]
    fn message_with_empty_body() {
        let json = json!({
            "sid": "SM1",
            "status": "sent",
            "to": "+1",
            "from": "+2",
            "body": ""
        });
        let msg: TwilioMessage = serde_json::from_value(json).unwrap();
        assert_eq!(msg.body.as_deref(), Some(""));
    }

    #[test]
    fn account_with_empty_friendly_name() {
        let json = json!({
            "sid": "AC1",
            "friendly_name": ""
        });
        let acct: TwilioAccount = serde_json::from_value(json).unwrap();
        assert_eq!(acct.friendly_name.as_deref(), Some(""));
    }

    // ── MessageListResponse does NOT impl Serialize ──────────────────────

    #[test]
    fn message_list_response_missing_required_field_fails() {
        // "messages" is required
        let json = json!({"next_page_uri": null});
        assert!(serde_json::from_value::<MessageListResponse>(json).is_err());
    }

    #[test]
    fn recording_list_response_missing_required_field_fails() {
        let json = json!({"next_page_uri": "/next"});
        assert!(serde_json::from_value::<RecordingListResponse>(json).is_err());
    }

    #[test]
    fn phone_number_list_response_missing_required_field_fails() {
        let json = json!({"next_page_uri": null});
        assert!(serde_json::from_value::<PhoneNumberListResponse>(json).is_err());
    }
}
