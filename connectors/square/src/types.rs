//! Square API types.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Money type
// ─────────────────────────────────────────────────────────────────────────────

/// Money amount with currency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Money {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Payment types
// ─────────────────────────────────────────────────────────────────────────────

/// Paginated list of payments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentList {
    #[serde(default)]
    pub payments: Vec<Payment>,
    pub cursor: Option<String>,
}

/// A single payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_money: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_money: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_url: Option<String>,
}

/// Response wrapping a single payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResponse {
    pub payment: Option<Payment>,
}

/// Request to create a payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePaymentRequest {
    pub source_id: String,
    pub idempotency_key: String,
    pub amount_money: Money,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Request to refund a payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundPaymentRequest {
    pub idempotency_key: String,
    pub payment_id: String,
    pub amount_money: Money,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Response wrapping a refund.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    pub refund: Option<Refund>,
}

/// A payment refund.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refund {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_money: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Order types
// ─────────────────────────────────────────────────────────────────────────────

/// Search orders response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderList {
    #[serde(default)]
    pub orders: Vec<Order>,
    pub cursor: Option<String>,
}

/// A single order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_money: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub line_items: Vec<OrderLineItem>,
}

/// An order line item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderLineItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_price_money: Option<Money>,
}

/// Response wrapping a single order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderResponse {
    pub order: Option<Order>,
}

/// Request to create an order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOrderRequest {
    pub order: OrderInput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// Order input for creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderInput {
    pub location_id: String,
    #[serde(default)]
    pub line_items: Vec<OrderLineItemInput>,
}

/// Line item input for order creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderLineItemInput {
    pub name: String,
    pub quantity: String,
    pub base_price_money: Money,
}

// ─────────────────────────────────────────────────────────────────────────────
// Catalog types
// ─────────────────────────────────────────────────────────────────────────────

/// Catalog list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogList {
    #[serde(default)]
    pub objects: Vec<CatalogObject>,
    pub cursor: Option<String>,
}

/// A catalog object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogObject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_deleted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_data: Option<serde_json::Value>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Customer types
// ─────────────────────────────────────────────────────────────────────────────

/// Paginated list of customers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerList {
    #[serde(default)]
    pub customers: Vec<Customer>,
    pub cursor: Option<String>,
}

/// A single customer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Customer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Response wrapping a single customer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerResponse {
    pub customer: Option<Customer>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Location types
// ─────────────────────────────────────────────────────────────────────────────

/// List of locations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationList {
    #[serde(default)]
    pub locations: Vec<Location>,
}

/// A single location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub business_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// API error types
// ─────────────────────────────────────────────────────────────────────────────

/// Square API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(default)]
    pub errors: Vec<ApiError>,
}

/// A single Square API error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub category: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn money_serialization() {
        let money = Money {
            amount: Some(1000),
            currency: Some("USD".into()),
        };
        let json = serde_json::to_value(&money).unwrap();
        assert_eq!(json["amount"], 1000);
        assert_eq!(json["currency"], "USD");
    }

    #[test]
    fn payment_list_deserialization() {
        let json = serde_json::json!({
            "payments": [{
                "id": "pay_123",
                "status": "COMPLETED",
                "amount_money": { "amount": 1000, "currency": "USD" },
                "source_type": "CARD",
                "location_id": "loc_abc",
                "created_at": "2026-03-21T10:00:00Z"
            }],
            "cursor": "next_cursor"
        });
        let list: PaymentList = serde_json::from_value(json).unwrap();
        assert_eq!(list.payments.len(), 1);
        assert_eq!(list.payments[0].id.as_deref(), Some("pay_123"));
        assert_eq!(list.cursor.as_deref(), Some("next_cursor"));
    }

    #[test]
    fn payment_response_deserialization() {
        let json = serde_json::json!({
            "payment": {
                "id": "pay_456",
                "status": "COMPLETED",
                "amount_money": { "amount": 2500, "currency": "USD" }
            }
        });
        let resp: PaymentResponse = serde_json::from_value(json).unwrap();
        assert!(resp.payment.is_some());
    }

    #[test]
    fn create_payment_request() {
        let req = CreatePaymentRequest {
            source_id: "nonce_abc".into(),
            idempotency_key: "key_123".into(),
            amount_money: Money {
                amount: Some(500),
                currency: Some("USD".into()),
            },
            location_id: Some("loc_abc".into()),
            customer_id: None,
            note: Some("Test payment".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["source_id"], "nonce_abc");
        assert_eq!(json["amount_money"]["amount"], 500);
    }

    #[test]
    fn refund_request_serialization() {
        let req = RefundPaymentRequest {
            idempotency_key: "refund_key_1".into(),
            payment_id: "pay_123".into(),
            amount_money: Money {
                amount: Some(500),
                currency: Some("USD".into()),
            },
            reason: Some("Customer request".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["payment_id"], "pay_123");
    }

    #[test]
    fn order_list_deserialization() {
        let json = serde_json::json!({
            "orders": [{
                "id": "order_abc",
                "location_id": "loc_123",
                "state": "COMPLETED",
                "total_money": { "amount": 3000, "currency": "USD" },
                "line_items": [{
                    "uid": "item_1",
                    "name": "Widget",
                    "quantity": "2",
                    "base_price_money": { "amount": 1500, "currency": "USD" }
                }]
            }]
        });
        let list: OrderList = serde_json::from_value(json).unwrap();
        assert_eq!(list.orders.len(), 1);
        assert_eq!(list.orders[0].line_items.len(), 1);
    }

    #[test]
    fn create_order_request() {
        let req = CreateOrderRequest {
            order: OrderInput {
                location_id: "loc_123".into(),
                line_items: vec![OrderLineItemInput {
                    name: "Coffee".into(),
                    quantity: "1".into(),
                    base_price_money: Money {
                        amount: Some(450),
                        currency: Some("USD".into()),
                    },
                }],
            },
            idempotency_key: Some("order_key_1".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["order"]["location_id"], "loc_123");
    }

    #[test]
    fn catalog_list_deserialization() {
        let json = serde_json::json!({
            "objects": [{
                "id": "cat_item_1",
                "type": "ITEM",
                "version": 1,
                "is_deleted": false
            }],
            "cursor": "next"
        });
        let list: CatalogList = serde_json::from_value(json).unwrap();
        assert_eq!(list.objects.len(), 1);
        assert_eq!(list.objects[0].object_type.as_deref(), Some("ITEM"));
    }

    #[test]
    fn customer_list_deserialization() {
        let json = serde_json::json!({
            "customers": [{
                "id": "cust_1",
                "given_name": "Jane",
                "family_name": "Doe",
                "email_address": "jane@example.com"
            }]
        });
        let list: CustomerList = serde_json::from_value(json).unwrap();
        assert_eq!(list.customers.len(), 1);
        assert_eq!(list.customers[0].given_name.as_deref(), Some("Jane"));
    }

    #[test]
    fn customer_response_deserialization() {
        let json = serde_json::json!({
            "customer": {
                "id": "cust_2",
                "given_name": "John",
                "email_address": "john@example.com"
            }
        });
        let resp: CustomerResponse = serde_json::from_value(json).unwrap();
        assert!(resp.customer.is_some());
    }

    #[test]
    fn location_list_deserialization() {
        let json = serde_json::json!({
            "locations": [{
                "id": "loc_1",
                "name": "Main Store",
                "status": "ACTIVE",
                "country": "US",
                "currency": "USD"
            }]
        });
        let list: LocationList = serde_json::from_value(json).unwrap();
        assert_eq!(list.locations.len(), 1);
        assert_eq!(list.locations[0].name.as_deref(), Some("Main Store"));
    }

    #[test]
    fn api_error_deserialization() {
        let json = serde_json::json!({
            "errors": [{
                "category": "INVALID_REQUEST_ERROR",
                "code": "MISSING_REQUIRED_PARAMETER",
                "detail": "Missing required parameter: source_id",
                "field": "source_id"
            }]
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.errors.len(), 1);
        assert_eq!(err.errors[0].code, "MISSING_REQUIRED_PARAMETER");
    }

    #[test]
    fn empty_payment_list() {
        let json = serde_json::json!({});
        let list: PaymentList = serde_json::from_value(json).unwrap();
        assert!(list.payments.is_empty());
        assert!(list.cursor.is_none());
    }

    #[test]
    fn refund_response_deserialization() {
        let json = serde_json::json!({
            "refund": {
                "id": "ref_123",
                "status": "COMPLETED",
                "amount_money": { "amount": 500, "currency": "USD" },
                "payment_id": "pay_123"
            }
        });
        let resp: RefundResponse = serde_json::from_value(json).unwrap();
        assert!(resp.refund.is_some());
    }
}
