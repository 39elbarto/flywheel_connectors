//! Plaid API types.

use serde::{Deserialize, Serialize};

/// A Plaid account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub account_id: String,
    pub balances: AccountBalances,
    pub mask: Option<String>,
    pub name: String,
    pub official_name: Option<String>,
    pub subtype: Option<String>,
    #[serde(rename = "type")]
    pub account_type: Option<String>,
}

/// Account balance details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountBalances {
    pub available: Option<f64>,
    pub current: Option<f64>,
    pub limit: Option<f64>,
    pub iso_currency_code: Option<String>,
    pub unofficial_currency_code: Option<String>,
}

/// A Plaid transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub transaction_id: String,
    pub account_id: String,
    pub amount: f64,
    pub iso_currency_code: Option<String>,
    pub date: String,
    pub name: String,
    pub merchant_name: Option<String>,
    pub pending: bool,
    pub category: Option<Vec<String>>,
    pub category_id: Option<String>,
    pub authorized_date: Option<String>,
}

/// A Plaid investment holding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Holding {
    pub account_id: String,
    pub security_id: String,
    pub quantity: f64,
    pub institution_price: f64,
    pub institution_value: f64,
    pub cost_basis: Option<f64>,
    pub iso_currency_code: Option<String>,
}

/// A Plaid security.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Security {
    pub security_id: String,
    pub name: Option<String>,
    pub ticker_symbol: Option<String>,
    #[serde(rename = "type")]
    pub security_type: Option<String>,
    pub close_price: Option<f64>,
    pub iso_currency_code: Option<String>,
    pub isin: Option<String>,
    pub cusip: Option<String>,
}

/// A Plaid liability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Liability {
    pub account_id: Option<String>,
    #[serde(rename = "type")]
    pub liability_type: Option<String>,
}

/// Credit card liability details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditLiability {
    pub account_id: Option<String>,
    pub is_overdue: Option<bool>,
    pub last_payment_amount: Option<f64>,
    pub last_statement_balance: Option<f64>,
    pub minimum_payment_amount: Option<f64>,
    pub next_payment_due_date: Option<String>,
}

/// Student loan liability details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StudentLoanLiability {
    pub account_id: Option<String>,
    pub disbursement_dates: Option<Vec<String>>,
    pub interest_rate_percentage: Option<f64>,
    pub loan_name: Option<String>,
    pub origination_principal_amount: Option<f64>,
    pub outstanding_interest_amount: Option<f64>,
}

/// Liabilities container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiabilitiesResponse {
    pub credit: Option<Vec<serde_json::Value>>,
    pub mortgage: Option<Vec<serde_json::Value>>,
    pub student: Option<Vec<serde_json::Value>>,
}

/// A Plaid item (linked institution).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaidItem {
    pub item_id: String,
    pub institution_id: Option<String>,
    pub available_products: Option<Vec<String>>,
    pub billed_products: Option<Vec<String>>,
    pub consent_expiration_time: Option<String>,
}

/// Link token creation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkTokenResponse {
    pub link_token: String,
    pub expiration: String,
    pub request_id: Option<String>,
}

/// Access token exchange response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenResponse {
    pub access_token: String,
    pub item_id: String,
    pub request_id: Option<String>,
}

/// Auth numbers response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthNumbers {
    pub ach: Option<Vec<serde_json::Value>>,
    pub eft: Option<Vec<serde_json::Value>>,
    pub international: Option<Vec<serde_json::Value>>,
    pub bacs: Option<Vec<serde_json::Value>>,
}

/// Transactions sync response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionsSyncResponse {
    pub added: Vec<Transaction>,
    pub modified: Vec<Transaction>,
    pub removed: Vec<RemovedTransaction>,
    pub next_cursor: String,
    pub has_more: bool,
}

/// A removed transaction reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovedTransaction {
    pub transaction_id: String,
}

/// Plaid API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct PlaidApiError {
    pub error_type: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub display_message: Option<String>,
    pub request_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- Account ----

    #[test]
    fn account_serde_roundtrip() {
        let json = json!({
            "account_id": "acc_123",
            "balances": {
                "available": 100.50,
                "current": 200.75,
                "limit": null,
                "iso_currency_code": "USD",
                "unofficial_currency_code": null
            },
            "mask": "1234",
            "name": "Checking",
            "official_name": "Premier Checking",
            "subtype": "checking",
            "type": "depository"
        });
        let account: Account = serde_json::from_value(json).unwrap();
        assert_eq!(account.account_id, "acc_123");
        assert_eq!(account.balances.available, Some(100.50));
        assert_eq!(account.account_type, Some("depository".into()));

        let serialized = serde_json::to_value(&account).unwrap();
        assert_eq!(serialized["type"], "depository");
    }

    #[test]
    fn account_optional_fields_null() {
        let json = json!({
            "account_id": "acc_456",
            "balances": {
                "available": null,
                "current": null,
                "limit": null,
                "iso_currency_code": null,
                "unofficial_currency_code": null
            },
            "mask": null,
            "name": "Savings",
            "official_name": null,
            "subtype": null,
            "type": null
        });
        let account: Account = serde_json::from_value(json).unwrap();
        assert!(account.balances.available.is_none());
        assert!(account.mask.is_none());
        assert!(account.account_type.is_none());
    }

    // ---- Transaction ----

    #[test]
    fn transaction_serde_roundtrip() {
        let json = json!({
            "transaction_id": "txn_001",
            "account_id": "acc_123",
            "amount": -42.50,
            "iso_currency_code": "USD",
            "date": "2026-03-01",
            "name": "Coffee Shop",
            "merchant_name": "Blue Bottle",
            "pending": false,
            "category": ["Food and Drink", "Coffee"],
            "category_id": "13005",
            "authorized_date": "2026-02-28"
        });
        let txn: Transaction = serde_json::from_value(json).unwrap();
        assert_eq!(txn.transaction_id, "txn_001");
        assert_eq!(txn.amount, -42.50);
        assert!(!txn.pending);
        assert_eq!(txn.category.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn transaction_minimal_fields() {
        let json = json!({
            "transaction_id": "txn_002",
            "account_id": "acc_456",
            "amount": 10.0,
            "date": "2026-03-02",
            "name": "Transfer",
            "pending": true,
            "iso_currency_code": null,
            "merchant_name": null,
            "category": null,
            "category_id": null,
            "authorized_date": null
        });
        let txn: Transaction = serde_json::from_value(json).unwrap();
        assert!(txn.pending);
        assert!(txn.merchant_name.is_none());
        assert!(txn.category.is_none());
    }

    // ---- Holding ----

    #[test]
    fn holding_serde_roundtrip() {
        let json = json!({
            "account_id": "acc_inv",
            "security_id": "sec_001",
            "quantity": 10.0,
            "institution_price": 150.25,
            "institution_value": 1502.50,
            "cost_basis": 1400.00,
            "iso_currency_code": "USD"
        });
        let holding: Holding = serde_json::from_value(json).unwrap();
        assert_eq!(holding.quantity, 10.0);
        assert_eq!(holding.cost_basis, Some(1400.00));
    }

    // ---- Security ----

    #[test]
    fn security_type_field_renamed() {
        let json = json!({
            "security_id": "sec_001",
            "name": "Apple Inc.",
            "ticker_symbol": "AAPL",
            "type": "equity",
            "close_price": 175.50,
            "iso_currency_code": "USD",
            "isin": "US0378331005",
            "cusip": "037833100"
        });
        let sec: Security = serde_json::from_value(json).unwrap();
        assert_eq!(sec.security_type, Some("equity".into()));
        assert_eq!(sec.ticker_symbol, Some("AAPL".into()));

        let serialized = serde_json::to_value(&sec).unwrap();
        assert_eq!(serialized["type"], "equity");
    }

    // ---- Liability ----

    #[test]
    fn liability_type_field_renamed() {
        let json = json!({
            "account_id": "acc_loan",
            "type": "credit"
        });
        let liab: Liability = serde_json::from_value(json).unwrap();
        assert_eq!(liab.liability_type, Some("credit".into()));
    }

    // ---- CreditLiability ----

    #[test]
    fn credit_liability_optional_fields() {
        let json = json!({
            "account_id": "acc_cc",
            "is_overdue": true,
            "last_payment_amount": 500.00,
            "last_statement_balance": 1200.00,
            "minimum_payment_amount": 25.00,
            "next_payment_due_date": "2026-04-01"
        });
        let cl: CreditLiability = serde_json::from_value(json).unwrap();
        assert_eq!(cl.is_overdue, Some(true));
        assert_eq!(cl.minimum_payment_amount, Some(25.00));
    }

    // ---- StudentLoanLiability ----

    #[test]
    fn student_loan_serde() {
        let json = json!({
            "account_id": "acc_loan",
            "disbursement_dates": ["2020-09-01", "2021-01-15"],
            "interest_rate_percentage": 4.5,
            "loan_name": "Federal Subsidized",
            "origination_principal_amount": 25000.0,
            "outstanding_interest_amount": 500.0
        });
        let sl: StudentLoanLiability = serde_json::from_value(json).unwrap();
        assert_eq!(sl.disbursement_dates.as_ref().unwrap().len(), 2);
        assert_eq!(sl.interest_rate_percentage, Some(4.5));
    }

    // ---- LiabilitiesResponse ----

    #[test]
    fn liabilities_response_empty() {
        let json = json!({
            "credit": null,
            "mortgage": null,
            "student": null
        });
        let resp: LiabilitiesResponse = serde_json::from_value(json).unwrap();
        assert!(resp.credit.is_none());
        assert!(resp.mortgage.is_none());
        assert!(resp.student.is_none());
    }

    // ---- PlaidItem ----

    #[test]
    fn plaid_item_serde() {
        let json = json!({
            "item_id": "item_001",
            "institution_id": "ins_1",
            "available_products": ["transactions", "auth"],
            "billed_products": ["transactions"],
            "consent_expiration_time": "2027-01-01T00:00:00Z"
        });
        let item: PlaidItem = serde_json::from_value(json).unwrap();
        assert_eq!(item.item_id, "item_001");
        assert_eq!(item.available_products.as_ref().unwrap().len(), 2);
    }

    // ---- LinkTokenResponse ----

    #[test]
    fn link_token_response_serde() {
        let json = json!({
            "link_token": "link-sandbox-abc",
            "expiration": "2026-03-02T00:00:00Z",
            "request_id": "req_001"
        });
        let resp: LinkTokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.link_token, "link-sandbox-abc");
    }

    // ---- AccessTokenResponse ----

    #[test]
    fn access_token_response_serde() {
        let json = json!({
            "access_token": "access-sandbox-xyz",
            "item_id": "item_001",
            "request_id": "req_002"
        });
        let resp: AccessTokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.access_token, "access-sandbox-xyz");
    }

    // ---- TransactionsSyncResponse ----

    #[test]
    fn transactions_sync_response_serde() {
        let json = json!({
            "added": [{
                "transaction_id": "txn_new",
                "account_id": "acc_1",
                "amount": 15.0,
                "date": "2026-03-01",
                "name": "Grocery",
                "pending": false,
                "iso_currency_code": "USD",
                "merchant_name": null,
                "category": null,
                "category_id": null,
                "authorized_date": null
            }],
            "modified": [],
            "removed": [{"transaction_id": "txn_old"}],
            "next_cursor": "cursor_abc",
            "has_more": false
        });
        let resp: TransactionsSyncResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.added.len(), 1);
        assert!(resp.modified.is_empty());
        assert_eq!(resp.removed.len(), 1);
        assert_eq!(resp.removed[0].transaction_id, "txn_old");
        assert!(!resp.has_more);
    }

    // ---- PlaidApiError ----

    #[test]
    fn plaid_api_error_serde() {
        let json = json!({
            "error_type": "INVALID_INPUT",
            "error_code": "INVALID_ACCESS_TOKEN",
            "error_message": "The access token is invalid",
            "display_message": "Please reconnect your account",
            "request_id": "req_err"
        });
        let err: PlaidApiError = serde_json::from_value(json).unwrap();
        assert_eq!(err.error_type, Some("INVALID_INPUT".into()));
        assert_eq!(err.error_code, Some("INVALID_ACCESS_TOKEN".into()));
    }

    #[test]
    fn plaid_api_error_all_null() {
        let json = json!({});
        let err: PlaidApiError = serde_json::from_value(json).unwrap();
        assert!(err.error_type.is_none());
        assert!(err.error_message.is_none());
        assert!(err.request_id.is_none());
    }

    // ---- AuthNumbers ----

    #[test]
    fn auth_numbers_serde() {
        let json = json!({
            "ach": [{"account": "acc_1"}],
            "eft": null,
            "international": null,
            "bacs": null
        });
        let auth: AuthNumbers = serde_json::from_value(json).unwrap();
        assert_eq!(auth.ach.as_ref().unwrap().len(), 1);
        assert!(auth.eft.is_none());
    }

    // ---- Account edge cases ----

    #[test]
    fn account_clone() {
        let account = Account {
            account_id: "acc_clone".into(),
            balances: AccountBalances {
                available: Some(500.0),
                current: Some(600.0),
                limit: None,
                iso_currency_code: Some("EUR".into()),
                unofficial_currency_code: None,
            },
            mask: Some("9999".into()),
            name: "Cloned Account".into(),
            official_name: None,
            subtype: Some("savings".into()),
            account_type: Some("depository".into()),
        };
        let cloned = account.clone();
        assert_eq!(cloned.account_id, "acc_clone");
        assert_eq!(cloned.balances.available, Some(500.0));
        assert_eq!(cloned.mask, Some("9999".into()));
        assert_eq!(account.account_id, "acc_clone");
    }

    #[test]
    fn account_debug_format() {
        let account = Account {
            account_id: "acc_dbg".into(),
            balances: AccountBalances {
                available: None,
                current: None,
                limit: None,
                iso_currency_code: None,
                unofficial_currency_code: None,
            },
            mask: None,
            name: "Debug Test".into(),
            official_name: None,
            subtype: None,
            account_type: None,
        };
        let debug = format!("{account:?}");
        assert!(debug.contains("acc_dbg"));
        assert!(debug.contains("Debug Test"));
    }

    #[test]
    fn account_roundtrip_preserves_type_rename() {
        let account = Account {
            account_id: "acc_rt".into(),
            balances: AccountBalances {
                available: Some(1.0),
                current: Some(2.0),
                limit: Some(3.0),
                iso_currency_code: Some("GBP".into()),
                unofficial_currency_code: Some("CRYPTO".into()),
            },
            mask: Some("0001".into()),
            name: "Roundtrip".into(),
            official_name: Some("Official Roundtrip".into()),
            subtype: Some("checking".into()),
            account_type: Some("depository".into()),
        };
        let serialized = serde_json::to_value(&account).unwrap();
        // The field should serialize as "type", not "account_type"
        assert!(serialized.get("type").is_some());
        assert!(serialized.get("account_type").is_none());

        // Deserialize back and verify
        let deserialized: Account = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized.account_type, Some("depository".into()));
        assert_eq!(
            deserialized.balances.unofficial_currency_code,
            Some("CRYPTO".into())
        );
    }

    #[test]
    fn account_missing_optional_fields_omitted_in_json() {
        let json = json!({
            "account_id": "acc_missing",
            "balances": {
                "available": null,
                "current": null,
                "limit": null,
                "iso_currency_code": null,
                "unofficial_currency_code": null
            },
            "name": "Minimal"
        });
        // mask, official_name, subtype, type are missing (not null, actually absent)
        let account: Account = serde_json::from_value(json).unwrap();
        assert!(account.mask.is_none());
        assert!(account.official_name.is_none());
        assert!(account.subtype.is_none());
        assert!(account.account_type.is_none());
    }

    #[test]
    fn account_balances_all_present() {
        let json = json!({
            "available": 1000.50,
            "current": 1200.75,
            "limit": 5000.00,
            "iso_currency_code": "CAD",
            "unofficial_currency_code": "BTC"
        });
        let balances: AccountBalances = serde_json::from_value(json).unwrap();
        assert_eq!(balances.available, Some(1000.50));
        assert_eq!(balances.current, Some(1200.75));
        assert_eq!(balances.limit, Some(5000.00));
        assert_eq!(balances.iso_currency_code, Some("CAD".into()));
        assert_eq!(balances.unofficial_currency_code, Some("BTC".into()));
    }

    #[test]
    fn account_balances_clone() {
        let balances = AccountBalances {
            available: Some(42.0),
            current: Some(100.0),
            limit: None,
            iso_currency_code: Some("USD".into()),
            unofficial_currency_code: None,
        };
        let cloned = balances.clone();
        assert_eq!(cloned.available, balances.available);
        assert_eq!(cloned.iso_currency_code, balances.iso_currency_code);
    }

    // ---- Transaction edge cases ----

    #[test]
    fn transaction_negative_amount() {
        let json = json!({
            "transaction_id": "txn_neg",
            "account_id": "acc_1",
            "amount": -999.99,
            "iso_currency_code": "USD",
            "date": "2026-01-01",
            "name": "Refund",
            "merchant_name": null,
            "pending": false,
            "category": null,
            "category_id": null,
            "authorized_date": null
        });
        let txn: Transaction = serde_json::from_value(json).unwrap();
        assert_eq!(txn.amount, -999.99);
    }

    #[test]
    fn transaction_zero_amount() {
        let json = json!({
            "transaction_id": "txn_zero",
            "account_id": "acc_1",
            "amount": 0.0,
            "iso_currency_code": null,
            "date": "2026-02-15",
            "name": "Zero Dollar Auth",
            "merchant_name": null,
            "pending": true,
            "category": null,
            "category_id": null,
            "authorized_date": null
        });
        let txn: Transaction = serde_json::from_value(json).unwrap();
        assert_eq!(txn.amount, 0.0);
        assert!(txn.pending);
    }

    #[test]
    fn transaction_empty_category_vec() {
        let json = json!({
            "transaction_id": "txn_empty_cat",
            "account_id": "acc_1",
            "amount": 5.0,
            "iso_currency_code": "USD",
            "date": "2026-03-01",
            "name": "Uncategorized",
            "merchant_name": null,
            "pending": false,
            "category": [],
            "category_id": null,
            "authorized_date": null
        });
        let txn: Transaction = serde_json::from_value(json).unwrap();
        assert!(txn.category.as_ref().unwrap().is_empty());
    }

    #[test]
    fn transaction_clone() {
        let txn = Transaction {
            transaction_id: "txn_c".into(),
            account_id: "acc_c".into(),
            amount: 12.34,
            iso_currency_code: Some("USD".into()),
            date: "2026-03-04".into(),
            name: "Clone Test".into(),
            merchant_name: Some("Merchant".into()),
            pending: false,
            category: Some(vec!["Food".into()]),
            category_id: Some("13000".into()),
            authorized_date: Some("2026-03-03".into()),
        };
        let cloned = txn.clone();
        assert_eq!(cloned.transaction_id, "txn_c");
        assert_eq!(cloned.category.as_ref().unwrap()[0], "Food");
        assert_eq!(txn.transaction_id, "txn_c");
    }

    #[test]
    fn transaction_debug() {
        let txn = Transaction {
            transaction_id: "txn_d".into(),
            account_id: "acc_d".into(),
            amount: 1.0,
            iso_currency_code: None,
            date: "2026-01-01".into(),
            name: "DebugTxn".into(),
            merchant_name: None,
            pending: true,
            category: None,
            category_id: None,
            authorized_date: None,
        };
        let debug = format!("{txn:?}");
        assert!(debug.contains("DebugTxn"));
        assert!(debug.contains("txn_d"));
    }

    #[test]
    fn transaction_roundtrip_serialization() {
        let txn = Transaction {
            transaction_id: "txn_rt".into(),
            account_id: "acc_rt".into(),
            amount: 55.55,
            iso_currency_code: Some("EUR".into()),
            date: "2026-06-15".into(),
            name: "Roundtrip Txn".into(),
            merchant_name: Some("Shop".into()),
            pending: false,
            category: Some(vec!["Shopping".into(), "Clothing".into()]),
            category_id: Some("19000".into()),
            authorized_date: Some("2026-06-14".into()),
        };
        let json_val = serde_json::to_value(&txn).unwrap();
        let deserialized: Transaction = serde_json::from_value(json_val).unwrap();
        assert_eq!(deserialized.transaction_id, "txn_rt");
        assert_eq!(deserialized.amount, 55.55);
        assert_eq!(deserialized.category.as_ref().unwrap().len(), 2);
    }

    // ---- Holding edge cases ----

    #[test]
    fn holding_no_cost_basis() {
        let json = json!({
            "account_id": "acc_h",
            "security_id": "sec_h",
            "quantity": 0.5,
            "institution_price": 50000.0,
            "institution_value": 25000.0,
            "cost_basis": null,
            "iso_currency_code": null
        });
        let h: Holding = serde_json::from_value(json).unwrap();
        assert!(h.cost_basis.is_none());
        assert!(h.iso_currency_code.is_none());
        assert_eq!(h.quantity, 0.5);
    }

    #[test]
    fn holding_clone_and_debug() {
        let holding = Holding {
            account_id: "acc_hcd".into(),
            security_id: "sec_hcd".into(),
            quantity: 100.0,
            institution_price: 10.0,
            institution_value: 1000.0,
            cost_basis: Some(950.0),
            iso_currency_code: Some("USD".into()),
        };
        let cloned = holding.clone();
        assert_eq!(cloned.institution_value, 1000.0);

        let debug = format!("{holding:?}");
        assert!(debug.contains("acc_hcd"));
    }

    #[test]
    fn holding_roundtrip() {
        let holding = Holding {
            account_id: "acc_hrt".into(),
            security_id: "sec_hrt".into(),
            quantity: 42.0,
            institution_price: 123.45,
            institution_value: 5184.90,
            cost_basis: Some(5000.0),
            iso_currency_code: Some("USD".into()),
        };
        let json_val = serde_json::to_value(&holding).unwrap();
        let back: Holding = serde_json::from_value(json_val).unwrap();
        assert_eq!(back.security_id, "sec_hrt");
        assert_eq!(back.cost_basis, Some(5000.0));
    }

    // ---- Security edge cases ----

    #[test]
    fn security_all_none_optionals() {
        let json = json!({
            "security_id": "sec_none",
            "name": null,
            "ticker_symbol": null,
            "type": null,
            "close_price": null,
            "iso_currency_code": null,
            "isin": null,
            "cusip": null
        });
        let sec: Security = serde_json::from_value(json).unwrap();
        assert_eq!(sec.security_id, "sec_none");
        assert!(sec.name.is_none());
        assert!(sec.ticker_symbol.is_none());
        assert!(sec.security_type.is_none());
        assert!(sec.close_price.is_none());
        assert!(sec.isin.is_none());
        assert!(sec.cusip.is_none());
    }

    #[test]
    fn security_clone_debug() {
        let sec = Security {
            security_id: "sec_cd".into(),
            name: Some("Tesla".into()),
            ticker_symbol: Some("TSLA".into()),
            security_type: Some("equity".into()),
            close_price: Some(250.0),
            iso_currency_code: Some("USD".into()),
            isin: None,
            cusip: None,
        };
        let cloned = sec.clone();
        assert_eq!(cloned.name, Some("Tesla".into()));

        let debug = format!("{sec:?}");
        assert!(debug.contains("TSLA"));
    }

    #[test]
    fn security_roundtrip_type_rename() {
        let sec = Security {
            security_id: "sec_rt".into(),
            name: Some("Bond Fund".into()),
            ticker_symbol: Some("BND".into()),
            security_type: Some("fixed income".into()),
            close_price: Some(80.0),
            iso_currency_code: Some("USD".into()),
            isin: Some("US12345".into()),
            cusip: Some("12345".into()),
        };
        let val = serde_json::to_value(&sec).unwrap();
        assert_eq!(val["type"], "fixed income");
        assert!(val.get("security_type").is_none());

        let back: Security = serde_json::from_value(val).unwrap();
        assert_eq!(back.security_type, Some("fixed income".into()));
    }

    #[test]
    fn security_missing_optional_fields() {
        // Fields absent (not null)
        let json = json!({
            "security_id": "sec_missing"
        });
        let sec: Security = serde_json::from_value(json).unwrap();
        assert_eq!(sec.security_id, "sec_missing");
        assert!(sec.name.is_none());
    }

    // ---- Liability edge cases ----

    #[test]
    fn liability_all_none() {
        let json = json!({});
        let liab: Liability = serde_json::from_value(json).unwrap();
        assert!(liab.account_id.is_none());
        assert!(liab.liability_type.is_none());
    }

    #[test]
    fn liability_roundtrip_type_rename() {
        let liab = Liability {
            account_id: Some("acc_liab".into()),
            liability_type: Some("student".into()),
        };
        let val = serde_json::to_value(&liab).unwrap();
        assert_eq!(val["type"], "student");
        assert!(val.get("liability_type").is_none());

        let back: Liability = serde_json::from_value(val).unwrap();
        assert_eq!(back.liability_type, Some("student".into()));
    }

    #[test]
    fn liability_clone_debug() {
        let liab = Liability {
            account_id: Some("acc_l".into()),
            liability_type: Some("credit".into()),
        };
        let cloned = liab.clone();
        assert_eq!(cloned.account_id, Some("acc_l".into()));
        let debug = format!("{liab:?}");
        assert!(debug.contains("credit"));
    }

    // ---- CreditLiability edge cases ----

    #[test]
    fn credit_liability_all_none() {
        let json = json!({});
        let cl: CreditLiability = serde_json::from_value(json).unwrap();
        assert!(cl.account_id.is_none());
        assert!(cl.is_overdue.is_none());
        assert!(cl.last_payment_amount.is_none());
        assert!(cl.last_statement_balance.is_none());
        assert!(cl.minimum_payment_amount.is_none());
        assert!(cl.next_payment_due_date.is_none());
    }

    #[test]
    fn credit_liability_not_overdue() {
        let json = json!({
            "account_id": "acc_cc2",
            "is_overdue": false,
            "last_payment_amount": 100.0,
            "last_statement_balance": 0.0,
            "minimum_payment_amount": 0.0,
            "next_payment_due_date": "2026-05-01"
        });
        let cl: CreditLiability = serde_json::from_value(json).unwrap();
        assert_eq!(cl.is_overdue, Some(false));
        assert_eq!(cl.last_statement_balance, Some(0.0));
    }

    #[test]
    fn credit_liability_clone_debug() {
        let cl = CreditLiability {
            account_id: Some("acc_cc3".into()),
            is_overdue: Some(true),
            last_payment_amount: Some(50.0),
            last_statement_balance: Some(1500.0),
            minimum_payment_amount: Some(35.0),
            next_payment_due_date: Some("2026-04-15".into()),
        };
        let cloned = cl.clone();
        assert_eq!(cloned.last_payment_amount, Some(50.0));
        let debug = format!("{cl:?}");
        assert!(debug.contains("1500"));
    }

    #[test]
    fn credit_liability_roundtrip() {
        let cl = CreditLiability {
            account_id: Some("acc_rt_cc".into()),
            is_overdue: Some(false),
            last_payment_amount: Some(200.0),
            last_statement_balance: Some(800.0),
            minimum_payment_amount: Some(25.0),
            next_payment_due_date: Some("2026-07-01".into()),
        };
        let val = serde_json::to_value(&cl).unwrap();
        let back: CreditLiability = serde_json::from_value(val).unwrap();
        assert_eq!(back.account_id, Some("acc_rt_cc".into()));
        assert_eq!(back.last_statement_balance, Some(800.0));
    }

    // ---- StudentLoanLiability edge cases ----

    #[test]
    fn student_loan_all_none() {
        let json = json!({});
        let sl: StudentLoanLiability = serde_json::from_value(json).unwrap();
        assert!(sl.account_id.is_none());
        assert!(sl.disbursement_dates.is_none());
        assert!(sl.interest_rate_percentage.is_none());
        assert!(sl.loan_name.is_none());
        assert!(sl.origination_principal_amount.is_none());
        assert!(sl.outstanding_interest_amount.is_none());
    }

    #[test]
    fn student_loan_empty_disbursement_dates() {
        let json = json!({
            "account_id": "acc_sl2",
            "disbursement_dates": [],
            "interest_rate_percentage": 0.0,
            "loan_name": "Zero Interest",
            "origination_principal_amount": 10000.0,
            "outstanding_interest_amount": 0.0
        });
        let sl: StudentLoanLiability = serde_json::from_value(json).unwrap();
        assert!(sl.disbursement_dates.as_ref().unwrap().is_empty());
        assert_eq!(sl.interest_rate_percentage, Some(0.0));
    }

    #[test]
    fn student_loan_clone_debug() {
        let sl = StudentLoanLiability {
            account_id: Some("acc_sl3".into()),
            disbursement_dates: Some(vec!["2020-01-01".into()]),
            interest_rate_percentage: Some(3.5),
            loan_name: Some("Private Loan".into()),
            origination_principal_amount: Some(50000.0),
            outstanding_interest_amount: Some(1200.0),
        };
        let cloned = sl.clone();
        assert_eq!(cloned.loan_name, Some("Private Loan".into()));
        let debug = format!("{sl:?}");
        assert!(debug.contains("50000"));
    }

    #[test]
    fn student_loan_roundtrip() {
        let sl = StudentLoanLiability {
            account_id: Some("acc_sl_rt".into()),
            disbursement_dates: Some(vec!["2019-08-15".into(), "2020-01-10".into()]),
            interest_rate_percentage: Some(5.25),
            loan_name: Some("Federal Unsubsidized".into()),
            origination_principal_amount: Some(30000.0),
            outstanding_interest_amount: Some(750.0),
        };
        let val = serde_json::to_value(&sl).unwrap();
        let back: StudentLoanLiability = serde_json::from_value(val).unwrap();
        assert_eq!(back.disbursement_dates.as_ref().unwrap().len(), 2);
        assert_eq!(back.interest_rate_percentage, Some(5.25));
    }

    // ---- LiabilitiesResponse edge cases ----

    #[test]
    fn liabilities_response_all_populated() {
        let json = json!({
            "credit": [{"account_id": "cc1"}],
            "mortgage": [{"account_id": "mtg1"}, {"account_id": "mtg2"}],
            "student": [{"account_id": "sl1"}]
        });
        let resp: LiabilitiesResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.credit.as_ref().unwrap().len(), 1);
        assert_eq!(resp.mortgage.as_ref().unwrap().len(), 2);
        assert_eq!(resp.student.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn liabilities_response_empty_arrays() {
        let json = json!({
            "credit": [],
            "mortgage": [],
            "student": []
        });
        let resp: LiabilitiesResponse = serde_json::from_value(json).unwrap();
        assert!(resp.credit.as_ref().unwrap().is_empty());
        assert!(resp.mortgage.as_ref().unwrap().is_empty());
        assert!(resp.student.as_ref().unwrap().is_empty());
    }

    #[test]
    fn liabilities_response_clone_debug() {
        let resp = LiabilitiesResponse {
            credit: Some(vec![json!({"id": "c1"})]),
            mortgage: None,
            student: None,
        };
        let cloned = resp.clone();
        assert_eq!(cloned.credit.as_ref().unwrap().len(), 1);
        let debug = format!("{resp:?}");
        assert!(debug.contains("LiabilitiesResponse"));
    }

    // ---- PlaidItem edge cases ----

    #[test]
    fn plaid_item_all_none_optionals() {
        let json = json!({
            "item_id": "item_minimal"
        });
        let item: PlaidItem = serde_json::from_value(json).unwrap();
        assert_eq!(item.item_id, "item_minimal");
        assert!(item.institution_id.is_none());
        assert!(item.available_products.is_none());
        assert!(item.billed_products.is_none());
        assert!(item.consent_expiration_time.is_none());
    }

    #[test]
    fn plaid_item_empty_product_arrays() {
        let json = json!({
            "item_id": "item_empty",
            "institution_id": "ins_1",
            "available_products": [],
            "billed_products": [],
            "consent_expiration_time": null
        });
        let item: PlaidItem = serde_json::from_value(json).unwrap();
        assert!(item.available_products.as_ref().unwrap().is_empty());
        assert!(item.billed_products.as_ref().unwrap().is_empty());
    }

    #[test]
    fn plaid_item_clone_debug() {
        let item = PlaidItem {
            item_id: "item_cd".into(),
            institution_id: Some("ins_5".into()),
            available_products: Some(vec!["auth".into(), "transactions".into()]),
            billed_products: Some(vec!["transactions".into()]),
            consent_expiration_time: Some("2027-06-01T00:00:00Z".into()),
        };
        let cloned = item.clone();
        assert_eq!(cloned.item_id, "item_cd");
        assert_eq!(cloned.available_products.as_ref().unwrap().len(), 2);

        let debug = format!("{item:?}");
        assert!(debug.contains("item_cd"));
        assert!(debug.contains("ins_5"));
    }

    #[test]
    fn plaid_item_roundtrip() {
        let item = PlaidItem {
            item_id: "item_rt".into(),
            institution_id: Some("ins_9".into()),
            available_products: Some(vec!["balance".into()]),
            billed_products: Some(vec!["auth".into()]),
            consent_expiration_time: Some("2028-01-01T00:00:00Z".into()),
        };
        let val = serde_json::to_value(&item).unwrap();
        let back: PlaidItem = serde_json::from_value(val).unwrap();
        assert_eq!(back.item_id, "item_rt");
        assert_eq!(
            back.consent_expiration_time,
            Some("2028-01-01T00:00:00Z".into())
        );
    }

    // ---- LinkTokenResponse edge cases ----

    #[test]
    fn link_token_response_no_request_id() {
        let json = json!({
            "link_token": "link-sandbox-no-req",
            "expiration": "2026-12-31T23:59:59Z"
        });
        let resp: LinkTokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.link_token, "link-sandbox-no-req");
        assert!(resp.request_id.is_none());
    }

    #[test]
    fn link_token_response_clone_debug() {
        let resp = LinkTokenResponse {
            link_token: "link-sandbox-cd".into(),
            expiration: "2026-06-01T00:00:00Z".into(),
            request_id: Some("req_cd".into()),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.link_token, "link-sandbox-cd");
        let debug = format!("{resp:?}");
        assert!(debug.contains("link-sandbox-cd"));
    }

    #[test]
    fn link_token_response_roundtrip() {
        let resp = LinkTokenResponse {
            link_token: "link-sandbox-rt".into(),
            expiration: "2026-09-01T12:00:00Z".into(),
            request_id: Some("req_rt".into()),
        };
        let val = serde_json::to_value(&resp).unwrap();
        let back: LinkTokenResponse = serde_json::from_value(val).unwrap();
        assert_eq!(back.link_token, "link-sandbox-rt");
        assert_eq!(back.request_id, Some("req_rt".into()));
    }

    // ---- AccessTokenResponse edge cases ----

    #[test]
    fn access_token_response_no_request_id() {
        let json = json!({
            "access_token": "access-sandbox-no-req",
            "item_id": "item_no_req"
        });
        let resp: AccessTokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.access_token, "access-sandbox-no-req");
        assert!(resp.request_id.is_none());
    }

    #[test]
    fn access_token_response_clone_debug() {
        let resp = AccessTokenResponse {
            access_token: "access-sandbox-cd".into(),
            item_id: "item_cd".into(),
            request_id: Some("req_cd".into()),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.access_token, "access-sandbox-cd");
        let debug = format!("{resp:?}");
        assert!(debug.contains("access-sandbox-cd"));
    }

    #[test]
    fn access_token_response_roundtrip() {
        let resp = AccessTokenResponse {
            access_token: "access-sandbox-rt".into(),
            item_id: "item_rt".into(),
            request_id: Some("req_rt".into()),
        };
        let val = serde_json::to_value(&resp).unwrap();
        let back: AccessTokenResponse = serde_json::from_value(val).unwrap();
        assert_eq!(back.access_token, "access-sandbox-rt");
        assert_eq!(back.item_id, "item_rt");
    }

    // ---- AuthNumbers edge cases ----

    #[test]
    fn auth_numbers_all_none() {
        let json = json!({});
        let auth: AuthNumbers = serde_json::from_value(json).unwrap();
        assert!(auth.ach.is_none());
        assert!(auth.eft.is_none());
        assert!(auth.international.is_none());
        assert!(auth.bacs.is_none());
    }

    #[test]
    fn auth_numbers_all_populated() {
        let json = json!({
            "ach": [{"account_id": "a1", "routing": "011401533"}],
            "eft": [{"account_id": "a2"}],
            "international": [{"account_id": "a3", "iban": "GB123"}],
            "bacs": [{"account_id": "a4", "sort_code": "12-34-56"}]
        });
        let auth: AuthNumbers = serde_json::from_value(json).unwrap();
        assert_eq!(auth.ach.as_ref().unwrap().len(), 1);
        assert_eq!(auth.eft.as_ref().unwrap().len(), 1);
        assert_eq!(auth.international.as_ref().unwrap().len(), 1);
        assert_eq!(auth.bacs.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn auth_numbers_empty_arrays() {
        let json = json!({
            "ach": [],
            "eft": [],
            "international": [],
            "bacs": []
        });
        let auth: AuthNumbers = serde_json::from_value(json).unwrap();
        assert!(auth.ach.as_ref().unwrap().is_empty());
        assert!(auth.eft.as_ref().unwrap().is_empty());
    }

    #[test]
    fn auth_numbers_clone_debug() {
        let auth = AuthNumbers {
            ach: Some(vec![json!({"routing": "011401533"})]),
            eft: None,
            international: None,
            bacs: None,
        };
        let cloned = auth.clone();
        assert_eq!(cloned.ach.as_ref().unwrap().len(), 1);
        let debug = format!("{auth:?}");
        assert!(debug.contains("011401533"));
    }

    // ---- TransactionsSyncResponse edge cases ----

    #[test]
    fn transactions_sync_response_all_empty() {
        let json = json!({
            "added": [],
            "modified": [],
            "removed": [],
            "next_cursor": "",
            "has_more": false
        });
        let resp: TransactionsSyncResponse = serde_json::from_value(json).unwrap();
        assert!(resp.added.is_empty());
        assert!(resp.modified.is_empty());
        assert!(resp.removed.is_empty());
        assert!(resp.next_cursor.is_empty());
    }

    #[test]
    fn transactions_sync_response_has_more_true() {
        let json = json!({
            "added": [],
            "modified": [],
            "removed": [],
            "next_cursor": "cursor_page2",
            "has_more": true
        });
        let resp: TransactionsSyncResponse = serde_json::from_value(json).unwrap();
        assert!(resp.has_more);
        assert_eq!(resp.next_cursor, "cursor_page2");
    }

    #[test]
    fn transactions_sync_response_with_modified() {
        let json = json!({
            "added": [],
            "modified": [{
                "transaction_id": "txn_mod",
                "account_id": "acc_m",
                "amount": 99.99,
                "iso_currency_code": "USD",
                "date": "2026-03-01",
                "name": "Modified Purchase",
                "merchant_name": "Updated Merchant",
                "pending": false,
                "category": ["Shops"],
                "category_id": "19000",
                "authorized_date": "2026-02-28"
            }],
            "removed": [],
            "next_cursor": "cursor_mod",
            "has_more": false
        });
        let resp: TransactionsSyncResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.modified.len(), 1);
        assert_eq!(resp.modified[0].name, "Modified Purchase");
    }

    #[test]
    fn transactions_sync_response_clone_debug() {
        let resp = TransactionsSyncResponse {
            added: vec![],
            modified: vec![],
            removed: vec![RemovedTransaction {
                transaction_id: "txn_rm".into(),
            }],
            next_cursor: "cursor_cd".into(),
            has_more: false,
        };
        let cloned = resp.clone();
        assert_eq!(cloned.removed.len(), 1);
        let debug = format!("{resp:?}");
        assert!(debug.contains("cursor_cd"));
    }

    // ---- RemovedTransaction edge cases ----

    #[test]
    fn removed_transaction_serde() {
        let json = json!({"transaction_id": "txn_removed_1"});
        let rt: RemovedTransaction = serde_json::from_value(json).unwrap();
        assert_eq!(rt.transaction_id, "txn_removed_1");
    }

    #[test]
    fn removed_transaction_roundtrip() {
        let rt = RemovedTransaction {
            transaction_id: "txn_rm_rt".into(),
        };
        let val = serde_json::to_value(&rt).unwrap();
        let back: RemovedTransaction = serde_json::from_value(val).unwrap();
        assert_eq!(back.transaction_id, "txn_rm_rt");
    }

    #[test]
    fn removed_transaction_clone_debug() {
        let rt = RemovedTransaction {
            transaction_id: "txn_rm_cd".into(),
        };
        let cloned = rt.clone();
        assert_eq!(cloned.transaction_id, "txn_rm_cd");
        let debug = format!("{rt:?}");
        assert!(debug.contains("txn_rm_cd"));
    }

    // ---- PlaidApiError edge cases ----

    #[test]
    fn plaid_api_error_partial_fields() {
        let json = json!({
            "error_type": "API_ERROR",
            "error_message": "internal server error"
        });
        let err: PlaidApiError = serde_json::from_value(json).unwrap();
        assert_eq!(err.error_type, Some("API_ERROR".into()));
        assert!(err.error_code.is_none());
        assert_eq!(err.error_message, Some("internal server error".into()));
        assert!(err.display_message.is_none());
        assert!(err.request_id.is_none());
    }

    #[test]
    fn plaid_api_error_debug() {
        let err = PlaidApiError {
            error_type: Some("RATE_LIMIT_EXCEEDED".into()),
            error_code: Some("ACCOUNTS_LIMIT".into()),
            error_message: Some("too many requests".into()),
            display_message: Some("Please slow down".into()),
            request_id: Some("req_dbg".into()),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("RATE_LIMIT_EXCEEDED"));
        assert!(debug.contains("ACCOUNTS_LIMIT"));
        assert!(debug.contains("req_dbg"));
    }

    #[test]
    fn plaid_api_error_clone() {
        let err = PlaidApiError {
            error_type: Some("INVALID_INPUT".into()),
            error_code: Some("MISSING_FIELDS".into()),
            error_message: Some("Missing required fields".into()),
            display_message: Some("Please fill in all fields".into()),
            request_id: Some("req_clone".into()),
        };
        let cloned = err.clone();
        assert_eq!(cloned.error_type, err.error_type);
        assert_eq!(cloned.error_code, err.error_code);
        assert_eq!(cloned.error_message, err.error_message);
        assert_eq!(cloned.display_message, err.display_message);
        assert_eq!(cloned.request_id, err.request_id);
    }

    // ---- Deserialization failure cases ----

    #[test]
    fn account_missing_required_field_fails() {
        // account_id is required
        let json = json!({
            "balances": {
                "available": null,
                "current": null,
                "limit": null,
                "iso_currency_code": null,
                "unofficial_currency_code": null
            },
            "name": "No ID"
        });
        let result = serde_json::from_value::<Account>(json);
        assert!(result.is_err());
    }

    #[test]
    fn account_missing_name_fails() {
        let json = json!({
            "account_id": "acc_no_name",
            "balances": {
                "available": null,
                "current": null,
                "limit": null,
                "iso_currency_code": null,
                "unofficial_currency_code": null
            }
        });
        let result = serde_json::from_value::<Account>(json);
        assert!(result.is_err());
    }

    #[test]
    fn account_missing_balances_fails() {
        let json = json!({
            "account_id": "acc_no_bal",
            "name": "No Balances"
        });
        let result = serde_json::from_value::<Account>(json);
        assert!(result.is_err());
    }

    #[test]
    fn transaction_missing_required_fields_fails() {
        let json = json!({
            "transaction_id": "txn_missing"
            // missing account_id, amount, date, name, pending
        });
        let result = serde_json::from_value::<Transaction>(json);
        assert!(result.is_err());
    }

    #[test]
    fn holding_missing_required_fields_fails() {
        let json = json!({
            "account_id": "acc_h"
            // missing security_id, quantity, institution_price, institution_value
        });
        let result = serde_json::from_value::<Holding>(json);
        assert!(result.is_err());
    }

    #[test]
    fn link_token_response_missing_required_fails() {
        let json = json!({
            "link_token": "link-sandbox-abc"
            // missing expiration
        });
        let result = serde_json::from_value::<LinkTokenResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn access_token_response_missing_required_fails() {
        let json = json!({
            "access_token": "access-sandbox-abc"
            // missing item_id
        });
        let result = serde_json::from_value::<AccessTokenResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn transactions_sync_missing_required_fails() {
        let json = json!({
            "added": [],
            "modified": []
            // missing removed, next_cursor, has_more
        });
        let result = serde_json::from_value::<TransactionsSyncResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn removed_transaction_missing_id_fails() {
        let json = json!({});
        let result = serde_json::from_value::<RemovedTransaction>(json);
        assert!(result.is_err());
    }

    // ---- Wrong type deserialization ----

    #[test]
    fn account_wrong_type_for_amount() {
        let json = json!({
            "account_id": "acc_wt",
            "balances": {
                "available": "not_a_number",
                "current": null,
                "limit": null,
                "iso_currency_code": null,
                "unofficial_currency_code": null
            },
            "name": "Wrong Type"
        });
        let result = serde_json::from_value::<Account>(json);
        assert!(result.is_err());
    }

    #[test]
    fn transaction_wrong_type_for_pending() {
        let json = json!({
            "transaction_id": "txn_wt",
            "account_id": "acc_1",
            "amount": 10.0,
            "iso_currency_code": null,
            "date": "2026-03-01",
            "name": "Wrong Type",
            "merchant_name": null,
            "pending": "not_a_bool",
            "category": null,
            "category_id": null,
            "authorized_date": null
        });
        let result = serde_json::from_value::<Transaction>(json);
        assert!(result.is_err());
    }
}
