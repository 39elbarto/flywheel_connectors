//! Stripe API types.

use serde::{Deserialize, Serialize};

/// A Stripe customer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Customer {
    pub id: String,
    pub object: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub created: Option<i64>,
    pub livemode: Option<bool>,
}

/// A Stripe payment intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentIntent {
    pub id: String,
    pub object: String,
    pub amount: i64,
    pub currency: String,
    pub status: String,
    pub customer: Option<String>,
    pub created: Option<i64>,
}

/// A Stripe refund.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refund {
    pub id: String,
    pub object: String,
    pub amount: i64,
    pub currency: String,
    pub status: String,
    pub payment_intent: Option<String>,
    pub created: Option<i64>,
}

/// A Stripe subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub object: String,
    pub status: String,
    pub customer: Option<String>,
    pub current_period_start: Option<i64>,
    pub current_period_end: Option<i64>,
    pub created: Option<i64>,
}

/// A Stripe invoice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub id: String,
    pub object: String,
    pub amount_due: Option<i64>,
    pub currency: Option<String>,
    pub status: Option<String>,
    pub customer: Option<String>,
    pub created: Option<i64>,
}

/// A Stripe deleted resource response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedResource {
    pub id: String,
    pub object: String,
    pub deleted: bool,
}

/// A Stripe balance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    pub object: String,
    pub available: Vec<BalanceAmount>,
    pub pending: Vec<BalanceAmount>,
    pub livemode: Option<bool>,
}

/// Amount in a balance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceAmount {
    pub amount: i64,
    pub currency: String,
}

/// Stripe list response.
#[derive(Debug, Clone, Deserialize)]
pub struct ListResponse {
    pub object: String,
    pub data: Vec<serde_json::Value>,
    pub has_more: bool,
    pub url: Option<String>,
}

/// Stripe API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub error: Option<ApiErrorDetail>,
}

/// Stripe error detail.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetail {
    pub message: Option<String>,
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub code: Option<String>,
}

/// Stripe webhook event envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeWebhookEvent {
    pub id: String,
    pub object: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub created: i64,
    pub livemode: Option<bool>,
    pub data: StripeWebhookEventData,
}

/// Stripe webhook event payload wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeWebhookEventData {
    pub object: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn customer_serde() {
        let cust = Customer {
            id: "cus_123".to_string(),
            object: "customer".to_string(),
            email: Some("alice@example.com".to_string()),
            name: Some("Alice".to_string()),
            created: Some(1_700_000_000),
            livemode: Some(false),
        };
        let json = serde_json::to_string(&cust).unwrap();
        let back: Customer = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "cus_123");
    }

    #[test]
    fn payment_intent_serde() {
        let pi = PaymentIntent {
            id: "pi_123".to_string(),
            object: "payment_intent".to_string(),
            amount: 2000,
            currency: "usd".to_string(),
            status: "succeeded".to_string(),
            customer: Some("cus_123".to_string()),
            created: Some(1_700_000_000),
        };
        let json = serde_json::to_string(&pi).unwrap();
        let back: PaymentIntent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.amount, 2000);
        assert_eq!(back.status, "succeeded");
    }

    #[test]
    fn refund_serde() {
        let refund = Refund {
            id: "re_123".to_string(),
            object: "refund".to_string(),
            amount: 500,
            currency: "usd".to_string(),
            status: "succeeded".to_string(),
            payment_intent: Some("pi_123".to_string()),
            created: None,
        };
        let json = serde_json::to_string(&refund).unwrap();
        let back: Refund = serde_json::from_str(&json).unwrap();
        assert_eq!(back.amount, 500);
    }

    #[test]
    fn subscription_serde() {
        let sub = Subscription {
            id: "sub_123".to_string(),
            object: "subscription".to_string(),
            status: "active".to_string(),
            customer: Some("cus_123".to_string()),
            current_period_start: Some(1_700_000_000),
            current_period_end: Some(1_702_592_000),
            created: None,
        };
        let json = serde_json::to_string(&sub).unwrap();
        let back: Subscription = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, "active");
    }

    #[test]
    fn invoice_serde() {
        let inv = Invoice {
            id: "in_123".to_string(),
            object: "invoice".to_string(),
            amount_due: Some(5000),
            currency: Some("usd".to_string()),
            status: Some("paid".to_string()),
            customer: Some("cus_123".to_string()),
            created: None,
        };
        let json = serde_json::to_string(&inv).unwrap();
        let back: Invoice = serde_json::from_str(&json).unwrap();
        assert_eq!(back.amount_due, Some(5000));
    }

    #[test]
    fn deleted_resource_serde() {
        let del = DeletedResource {
            id: "cus_123".to_string(),
            object: "customer".to_string(),
            deleted: true,
        };
        let json = serde_json::to_string(&del).unwrap();
        let back: DeletedResource = serde_json::from_str(&json).unwrap();
        assert!(back.deleted);
    }

    #[test]
    fn balance_serde() {
        let bal = Balance {
            object: "balance".to_string(),
            available: vec![BalanceAmount {
                amount: 10000,
                currency: "usd".to_string(),
            }],
            pending: vec![],
            livemode: Some(false),
        };
        let json = serde_json::to_string(&bal).unwrap();
        let back: Balance = serde_json::from_str(&json).unwrap();
        assert_eq!(back.available.len(), 1);
        assert_eq!(back.available[0].amount, 10000);
    }

    #[test]
    fn list_response_serde() {
        let json = json!({"object": "list", "data": [{"id": "cus_1"}], "has_more": true, "url": "/v1/customers"});
        let resp: ListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.has_more);
        assert_eq!(resp.data.len(), 1);
    }

    #[test]
    fn api_error_response_serde() {
        let json = json!({"error": {"message": "No such customer", "type": "invalid_request_error", "code": "resource_missing"}});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let detail = err.error.unwrap();
        assert_eq!(detail.code.as_deref(), Some("resource_missing"));
    }

    #[test]
    fn webhook_event_serde() {
        let event = StripeWebhookEvent {
            id: "evt_123".to_string(),
            object: "event".to_string(),
            event_type: "customer.created".to_string(),
            created: 1_700_000_000,
            livemode: Some(false),
            data: StripeWebhookEventData {
                object: json!({"id": "cus_123"}),
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"customer.created\""));
        let back: StripeWebhookEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_type, "customer.created");
    }

    // --- Customer additional tests ---

    #[test]
    fn customer_missing_optional_fields() {
        let json = json!({
            "id": "cus_minimal",
            "object": "customer"
        });
        let cust: Customer = serde_json::from_value(json).unwrap();
        assert_eq!(cust.id, "cus_minimal");
        assert_eq!(cust.object, "customer");
        assert!(cust.email.is_none());
        assert!(cust.name.is_none());
        assert!(cust.created.is_none());
        assert!(cust.livemode.is_none());
    }

    #[test]
    fn customer_clone() {
        let cust = Customer {
            id: "cus_clone".into(),
            object: "customer".into(),
            email: Some("clone@test.com".into()),
            name: Some("Clone Test".into()),
            created: Some(1_700_000_000),
            livemode: Some(true),
        };
        let cloned = cust.clone();
        assert_eq!(cust.id, "cus_clone");
        assert_eq!(cloned.id, "cus_clone");
        assert_eq!(cloned.email.as_deref(), Some("clone@test.com"));
        assert_eq!(cloned.name.as_deref(), Some("Clone Test"));
        assert_eq!(cloned.created, Some(1_700_000_000));
        assert_eq!(cloned.livemode, Some(true));
    }

    #[test]
    fn customer_debug() {
        let cust = Customer {
            id: "cus_dbg".into(),
            object: "customer".into(),
            email: None,
            name: None,
            created: None,
            livemode: None,
        };
        let dbg = format!("{cust:?}");
        assert!(dbg.contains("Customer"));
        assert!(dbg.contains("cus_dbg"));
    }

    #[test]
    fn customer_roundtrip() {
        let original = Customer {
            id: "cus_rt".into(),
            object: "customer".into(),
            email: Some("rt@test.com".into()),
            name: Some("Roundtrip".into()),
            created: Some(1_700_000_000),
            livemode: Some(false),
        };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: Customer = serde_json::from_str(&serialized).unwrap();
        let reserialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(serialized, reserialized);
    }

    // --- PaymentIntent additional tests ---

    #[test]
    fn payment_intent_without_customer() {
        let json = json!({
            "id": "pi_noc",
            "object": "payment_intent",
            "amount": 1500,
            "currency": "eur",
            "status": "requires_payment_method"
        });
        let pi: PaymentIntent = serde_json::from_value(json).unwrap();
        assert!(pi.customer.is_none());
        assert!(pi.created.is_none());
        assert_eq!(pi.amount, 1500);
        assert_eq!(pi.currency, "eur");
        assert_eq!(pi.status, "requires_payment_method");
    }

    #[test]
    fn payment_intent_clone() {
        let pi = PaymentIntent {
            id: "pi_cl".into(),
            object: "payment_intent".into(),
            amount: 9999,
            currency: "gbp".into(),
            status: "processing".into(),
            customer: Some("cus_x".into()),
            created: Some(1_700_000_000),
        };
        let cloned = pi.clone();
        assert_eq!(pi.id, "pi_cl");
        assert_eq!(cloned.id, "pi_cl");
        assert_eq!(cloned.amount, 9999);
        assert_eq!(cloned.currency, "gbp");
        assert_eq!(cloned.customer.as_deref(), Some("cus_x"));
    }

    // --- Refund additional tests ---

    #[test]
    fn refund_without_payment_intent_and_created() {
        let json = json!({
            "id": "re_min",
            "object": "refund",
            "amount": 200,
            "currency": "usd",
            "status": "pending"
        });
        let refund: Refund = serde_json::from_value(json).unwrap();
        assert!(refund.payment_intent.is_none());
        assert!(refund.created.is_none());
        assert_eq!(refund.amount, 200);
        assert_eq!(refund.status, "pending");
    }

    // --- Subscription additional tests ---

    #[test]
    fn subscription_all_none_optionals() {
        let json = json!({
            "id": "sub_min",
            "object": "subscription",
            "status": "trialing"
        });
        let sub: Subscription = serde_json::from_value(json).unwrap();
        assert_eq!(sub.id, "sub_min");
        assert_eq!(sub.status, "trialing");
        assert!(sub.customer.is_none());
        assert!(sub.current_period_start.is_none());
        assert!(sub.current_period_end.is_none());
        assert!(sub.created.is_none());
    }

    // --- Invoice additional tests ---

    #[test]
    fn invoice_all_none_optionals() {
        let json = json!({
            "id": "in_min",
            "object": "invoice"
        });
        let inv: Invoice = serde_json::from_value(json).unwrap();
        assert_eq!(inv.id, "in_min");
        assert_eq!(inv.object, "invoice");
        assert!(inv.amount_due.is_none());
        assert!(inv.currency.is_none());
        assert!(inv.status.is_none());
        assert!(inv.customer.is_none());
        assert!(inv.created.is_none());
    }

    // --- DeletedResource additional tests ---

    #[test]
    fn deleted_resource_with_deleted_false() {
        let del = DeletedResource {
            id: "cus_notdel".into(),
            object: "customer".into(),
            deleted: false,
        };
        let json = serde_json::to_string(&del).unwrap();
        let back: DeletedResource = serde_json::from_str(&json).unwrap();
        assert!(!back.deleted);
    }

    #[test]
    fn deleted_resource_clone() {
        let del = DeletedResource {
            id: "cus_del_cl".into(),
            object: "customer".into(),
            deleted: true,
        };
        let cloned = del.clone();
        assert_eq!(del.id, "cus_del_cl");
        assert_eq!(cloned.id, "cus_del_cl");
        assert!(cloned.deleted);
    }

    // --- Balance additional tests ---

    #[test]
    fn balance_multiple_currencies() {
        let bal = Balance {
            object: "balance".into(),
            available: vec![
                BalanceAmount {
                    amount: 10000,
                    currency: "usd".into(),
                },
                BalanceAmount {
                    amount: 5000,
                    currency: "eur".into(),
                },
                BalanceAmount {
                    amount: 8000,
                    currency: "gbp".into(),
                },
            ],
            pending: vec![
                BalanceAmount {
                    amount: 200,
                    currency: "usd".into(),
                },
                BalanceAmount {
                    amount: 100,
                    currency: "eur".into(),
                },
            ],
            livemode: Some(true),
        };
        let json = serde_json::to_string(&bal).unwrap();
        let back: Balance = serde_json::from_str(&json).unwrap();
        assert_eq!(back.available.len(), 3);
        assert_eq!(back.pending.len(), 2);
        assert_eq!(back.available[1].currency, "eur");
        assert_eq!(back.pending[0].amount, 200);
        assert_eq!(back.livemode, Some(true));
    }

    #[test]
    fn balance_empty_available_and_pending() {
        let bal = Balance {
            object: "balance".into(),
            available: vec![],
            pending: vec![],
            livemode: None,
        };
        let json = serde_json::to_string(&bal).unwrap();
        let back: Balance = serde_json::from_str(&json).unwrap();
        assert!(back.available.is_empty());
        assert!(back.pending.is_empty());
        assert!(back.livemode.is_none());
    }

    // --- BalanceAmount additional tests ---

    #[test]
    fn balance_amount_clone() {
        let amt = BalanceAmount {
            amount: 42,
            currency: "jpy".into(),
        };
        let cloned = amt.clone();
        assert_eq!(amt.amount, 42);
        assert_eq!(cloned.amount, 42);
        assert_eq!(cloned.currency, "jpy");
    }

    #[test]
    fn balance_amount_debug() {
        let amt = BalanceAmount {
            amount: 999,
            currency: "chf".into(),
        };
        let dbg = format!("{amt:?}");
        assert!(dbg.contains("BalanceAmount"));
        assert!(dbg.contains("999"));
        assert!(dbg.contains("chf"));
    }

    // --- ListResponse additional tests ---

    #[test]
    fn list_response_empty_data_no_more() {
        let json = json!({
            "object": "list",
            "data": [],
            "has_more": false
        });
        let resp: ListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.data.is_empty());
        assert!(!resp.has_more);
        assert!(resp.url.is_none());
    }

    #[test]
    fn list_response_without_url() {
        let json = json!({
            "object": "list",
            "data": [{"id": "pi_1"}],
            "has_more": false
        });
        let resp: ListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.url.is_none());
        assert_eq!(resp.data.len(), 1);
    }

    // --- ApiErrorResponse additional tests ---

    #[test]
    fn api_error_response_with_none_error() {
        let json = json!({});
        let resp: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(resp.error.is_none());
    }

    // --- ApiErrorDetail additional tests ---

    #[test]
    fn api_error_detail_all_none_fields() {
        let json = json!({});
        let detail: ApiErrorDetail = serde_json::from_value(json).unwrap();
        assert!(detail.message.is_none());
        assert!(detail.error_type.is_none());
        assert!(detail.code.is_none());
    }

    #[test]
    fn api_error_detail_clone() {
        let json = json!({
            "message": "expired card",
            "type": "card_error",
            "code": "expired_card"
        });
        let detail: ApiErrorDetail = serde_json::from_value(json).unwrap();
        let cloned = detail.clone();
        assert_eq!(detail.message.as_deref(), Some("expired card"));
        assert_eq!(cloned.message.as_deref(), Some("expired card"));
        assert_eq!(cloned.error_type.as_deref(), Some("card_error"));
        assert_eq!(cloned.code.as_deref(), Some("expired_card"));
    }

    #[test]
    fn api_error_detail_debug() {
        let json = json!({"message": "test_msg", "type": "api_error"});
        let detail: ApiErrorDetail = serde_json::from_value(json).unwrap();
        let dbg = format!("{detail:?}");
        assert!(dbg.contains("ApiErrorDetail"));
        assert!(dbg.contains("test_msg"));
        assert!(dbg.contains("api_error"));
    }

    // --- StripeWebhookEvent roundtrip ---

    #[test]
    fn webhook_event_roundtrip() {
        let event = StripeWebhookEvent {
            id: "evt_rt".into(),
            object: "event".into(),
            event_type: "payment_intent.succeeded".into(),
            created: 1_700_000_000,
            livemode: Some(true),
            data: StripeWebhookEventData {
                object: json!({"id": "pi_123", "amount": 5000}),
            },
        };
        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: StripeWebhookEvent = serde_json::from_str(&serialized).unwrap();
        let reserialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(serialized, reserialized);
        assert_eq!(deserialized.event_type, "payment_intent.succeeded");
        assert_eq!(deserialized.livemode, Some(true));
    }

    // --- StripeWebhookEventData clone ---

    #[test]
    fn webhook_event_data_clone() {
        let data = StripeWebhookEventData {
            object: json!({"id": "cus_clone", "balance": 0}),
        };
        let cloned = data.clone();
        assert_eq!(data.object["id"], "cus_clone");
        assert_eq!(cloned.object["id"], "cus_clone");
        assert_eq!(cloned.object["balance"], 0);
    }

    // --- Multiple items in list context ---

    #[test]
    fn list_response_multiple_customers() {
        let json = json!({
            "object": "list",
            "data": [
                {"id": "cus_1", "object": "customer", "email": "a@b.com"},
                {"id": "cus_2", "object": "customer", "email": "c@d.com"},
                {"id": "cus_3", "object": "customer"}
            ],
            "has_more": true,
            "url": "/v1/customers"
        });
        let resp: ListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.data.len(), 3);
        assert!(resp.has_more);
        assert_eq!(resp.url.as_deref(), Some("/v1/customers"));

        // Each item can be deserialized as a Customer
        for item in &resp.data {
            let cust: Customer = serde_json::from_value(item.clone()).unwrap();
            assert!(cust.id.starts_with("cus_"));
        }
    }

    #[test]
    fn list_response_multiple_payment_intents() {
        let json = json!({
            "object": "list",
            "data": [
                {
                    "id": "pi_a",
                    "object": "payment_intent",
                    "amount": 1000,
                    "currency": "usd",
                    "status": "succeeded"
                },
                {
                    "id": "pi_b",
                    "object": "payment_intent",
                    "amount": 2500,
                    "currency": "eur",
                    "status": "requires_capture"
                }
            ],
            "has_more": false
        });
        let resp: ListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.data.len(), 2);
        assert!(!resp.has_more);

        let pi_a: PaymentIntent = serde_json::from_value(resp.data[0].clone()).unwrap();
        assert_eq!(pi_a.amount, 1000);
        assert_eq!(pi_a.currency, "usd");

        let pi_b: PaymentIntent = serde_json::from_value(resp.data[1].clone()).unwrap();
        assert_eq!(pi_b.amount, 2500);
        assert_eq!(pi_b.status, "requires_capture");
    }
}
