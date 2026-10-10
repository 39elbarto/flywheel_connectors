//! FCP Host - Node Gateway/Orchestrator for the Flywheel Connector Protocol
//!
//! This crate implements the host/orchestrator that:
//! - Supervises connector binaries in sandboxes
//! - Exposes an agent-facing API (local or mesh-facing)
//! - Delegates enforcement decisions to the `MeshNode` + policy engine
//! - Manages lifecycle (install/verify, configure, health, restart)
//!
//! Based on FCP Specification Section 10 (Gateway Architecture) and
//! bead `flywheel_connectors-oip0`.

#![deny(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod admin_state;
mod agent_api;
mod batch;
mod budget;
mod cancellation;
mod credentials;
mod cutover;
mod deployment_mode;
mod discovery;
mod doctor;
mod emergency_revocation;
mod enforcement;
mod error;
// Retained-but-unwired: composite host-health framework
// (`HealthAggregator`, `CompositeHealthStatus`, tri-state `HealthState`,
// merge/rollup logic across connector / mesh / resource / named-component
// inputs). Production `/rpc/health` at `crates/fcp-host/src/bin/fcp-host.rs`
// `health_handler` instead builds a flat `HostHealthResponse` directly from
// `state.registry.list()` and `ConnectorHealth` (from fcp-kernel); the
// composite shape here was the prototype that did not get adopted when the
// host binary landed. Module is intentionally retained — its 77 unit tests
// pin the target shape for a future composite-health redesign and the
// types are the natural starting point if `/rpc/health` ever needs to
// surface mesh or resource subsystems alongside connectors. Same pattern
// as `enforcement::EnforcementPipeline` (br-ike8x diagnosis). Visibility
// stays private (no `pub use health::*`) so the module cannot accidentally
// be picked up by external callers expecting it to drive production
// health responses.
#[allow(dead_code)]
mod health;
#[cfg(target_os = "linux")]
mod inherited_egress;
mod invoke_audit;
mod local_mcp;
mod migration_linux;
#[cfg(target_os = "macos")]
mod migration_macos;
mod n8n_approval;
mod n8n_dispatch;
pub mod n8n_release_read;
mod network_policy;
mod output_capture;
mod owned_invocation;
mod progress;
mod redaction;
mod resilience;
mod resource_ledger;
mod resume_handshake;
mod rollout;
mod supervisor;
mod supply_chain;
mod tailnet_evidence;

pub use admin_state::*;
pub use agent_api::*;
pub use batch::*;
pub use budget::*;
pub use cancellation::*;
pub use credentials::*;
pub use cutover::*;
pub use deployment_mode::*;
pub use discovery::*;
pub use doctor::*;
pub use emergency_revocation::*;
pub use enforcement::*;
pub use error::*;
#[cfg(target_os = "linux")]
pub use inherited_egress::*;
pub use invoke_audit::*;
pub use local_mcp::*;
pub use migration_linux::*;
#[cfg(target_os = "macos")]
pub use migration_macos::*;
pub use n8n_approval::{
    N8nApprovalInputBinding, N8nApprovalIssueRequest, N8nApprovalServer, N8nLifecycleOperation,
    build_unsigned_n8n_approval_token, canonical_approval_token_bytes,
    n8n_official_mcp_approval_constraints, n8n_runtime_approval_verifying_key,
    n8n_typed_approval_plan_digest,
};
pub use n8n_dispatch::*;
pub use network_policy::*;
pub use output_capture::*;
pub use owned_invocation::*;
pub use progress::*;
pub use redaction::*;
pub use resilience::*;
pub use resource_ledger::*;
pub use resume_handshake::*;
pub use rollout::*;
pub use supervisor::*;
pub use supply_chain::*;
pub use tailnet_evidence::*;

// Duplicate keys must not acquire authority through serde_json's last-value
// semantics. The parser's normal recursion limit remains enabled. This helper
// is private at the crate root so sibling consumers share it without export.
fn credential_metadata_unique_json(bytes: &[u8]) -> Result<serde_json::Value, &'static str> {
    use std::fmt;

    use serde::Deserialize;
    use serde_json::Value;

    struct Unique(Value);
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Unique;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("unique-key JSON")
                }
                fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Unique, E> {
                    Ok(Unique(Value::Bool(v)))
                }
                fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Unique, E> {
                    serde_json::Number::from_f64(v)
                        .map(|v| Unique(Value::Number(v)))
                        .ok_or_else(|| E::custom("invalid number"))
                }
                fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Unique, E> {
                    Ok(Unique(Value::String(v.into())))
                }
                fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                    Ok(Unique(Value::Null))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<Unique, A::Error> {
                    let mut values = Vec::new();
                    while let Some(Unique(value)) = seq.next_element()? {
                        values.push(value);
                    }
                    Ok(Unique(Value::Array(values)))
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Unique, A::Error> {
                    let mut values = serde_json::Map::new();
                    while let Some(key) = map.next_key::<String>()? {
                        if values.contains_key(&key) {
                            return Err(serde::de::Error::custom("duplicate key"));
                        }
                        let Unique(value) = map.next_value()?;
                        values.insert(key, value);
                    }
                    Ok(Unique(Value::Object(values)))
                }
            }
            deserializer.deserialize_any(Visitor)
        }
    }
    serde_json::from_slice::<Unique>(bytes)
        .map(|value| value.0)
        .map_err(|_| "credential_metadata_response_denied")
}
