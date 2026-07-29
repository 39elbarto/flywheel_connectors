//! Runtime mirror for the cutover TLA+ model.
//!
//! This module is intentionally small: the operational host logic still lives in
//! `deployment_mode`, while this file gives model-alignment tests a stable Rust
//! discriminant surface for `specs/tla/cutover.tla`.

use std::fmt;

/// TLA+ invariant clause names mirrored by Rust assertion messages.
pub const CUTOVER_TLA_INVARIANT_CLAUSES: &[&str] = &[
    "Safety_no_v1_only_and_v2_default",
    "Liveness_shadow_resolves_in_one_step",
    "Recoverability_v1_path_exists",
];

/// Runtime states for the V1 host-first to V2 mesh-native cutover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CutoverState {
    /// Legacy host-first operation only.
    V1Only,
    /// V2 is running in shadow alongside V1.
    V2Shadow,
    /// V2 is the default dispatch path, with fallback still available.
    V2Default,
    /// Operator-triggered fallback to V1 after a V2 issue.
    V1Fallback,
    /// V2 is committed as the permanent default.
    V2Permanent,
}

impl CutoverState {
    /// All states in the same order as `specs/tla/cutover.tla`.
    pub const ALL: [Self; 5] = [
        Self::V1Only,
        Self::V2Shadow,
        Self::V2Default,
        Self::V1Fallback,
        Self::V2Permanent,
    ];

    /// Stable TLA+ label for this state.
    #[must_use]
    pub const fn tla_name(self) -> &'static str {
        match self {
            Self::V1Only => "V1Only",
            Self::V2Shadow => "V2Shadow",
            Self::V2Default => "V2Default",
            Self::V1Fallback => "V1Fallback",
            Self::V2Permanent => "V2Permanent",
        }
    }
}

/// Operator actions in the TLA+ cutover model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CutoverAction {
    /// Enable the V2 shadow path from V1 or fallback.
    EnableShadow,
    /// Promote V2 shadow to the default path.
    PromoteV2Default,
    /// Roll back from V2 shadow/default to the fallback state.
    TriggerFallback,
    /// Commit V2 as permanent after operator validation.
    CommitPermanent,
    /// Recover from fallback to V1-only operation.
    RecoverV1,
    /// Break-glass recovery from permanent V2 to V1-only operation.
    EmergencyRecoverV1,
}

impl CutoverAction {
    /// All operator actions in the same order as `specs/tla/cutover.tla`.
    pub const ALL: [Self; 6] = [
        Self::EnableShadow,
        Self::PromoteV2Default,
        Self::TriggerFallback,
        Self::CommitPermanent,
        Self::RecoverV1,
        Self::EmergencyRecoverV1,
    ];

    /// Stable TLA+ label for this action.
    #[must_use]
    pub const fn tla_name(self) -> &'static str {
        match self {
            Self::EnableShadow => "EnableShadow",
            Self::PromoteV2Default => "PromoteV2Default",
            Self::TriggerFallback => "TriggerFallback",
            Self::CommitPermanent => "CommitPermanent",
            Self::RecoverV1 => "RecoverV1",
            Self::EmergencyRecoverV1 => "EmergencyRecoverV1",
        }
    }
}

/// Runtime snapshot used by assertion hooks and alignment tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CutoverRuntimeSnapshot {
    /// Current cutover state.
    pub state: CutoverState,
    /// Whether the runtime reports V1-only operation.
    pub v1_only_active: bool,
    /// Whether the runtime reports V2-default operation.
    pub v2_default_active: bool,
    /// Number of consecutive shadow steps observed in the bounded model.
    pub shadow_steps: u8,
    /// Whether the operator has a bounded path back to V1-only operation.
    pub rollback_path_to_v1: bool,
}

impl CutoverRuntimeSnapshot {
    /// Build the canonical abstract snapshot for a cutover state.
    #[must_use]
    pub const fn from_state(state: CutoverState) -> Self {
        Self {
            state,
            v1_only_active: matches!(state, CutoverState::V1Only),
            v2_default_active: matches!(state, CutoverState::V2Default | CutoverState::V2Permanent),
            shadow_steps: if matches!(state, CutoverState::V2Shadow) {
                1
            } else {
                0
            },
            rollback_path_to_v1: true,
        }
    }
}

/// Error returned when a TLA+ state or action label is not part of the Rust
/// cutover state-machine mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownCutoverLabel {
    label: String,
}

impl UnknownCutoverLabel {
    #[must_use]
    fn new(label: &str) -> Self {
        Self {
            label: label.to_owned(),
        }
    }
}

impl fmt::Display for UnknownCutoverLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown cutover label `{}`", self.label)
    }
}

impl std::error::Error for UnknownCutoverLabel {}

impl TryFrom<&str> for CutoverState {
    type Error = UnknownCutoverLabel;

    fn try_from(label: &str) -> Result<Self, Self::Error> {
        match label {
            "V1Only" => Ok(Self::V1Only),
            "V2Shadow" => Ok(Self::V2Shadow),
            "V2Default" => Ok(Self::V2Default),
            "V1Fallback" => Ok(Self::V1Fallback),
            "V2Permanent" => Ok(Self::V2Permanent),
            other => Err(UnknownCutoverLabel::new(other)),
        }
    }
}

impl TryFrom<&str> for CutoverAction {
    type Error = UnknownCutoverLabel;

    fn try_from(label: &str) -> Result<Self, Self::Error> {
        match label {
            "EnableShadow" => Ok(Self::EnableShadow),
            "PromoteV2Default" => Ok(Self::PromoteV2Default),
            "TriggerFallback" => Ok(Self::TriggerFallback),
            "CommitPermanent" => Ok(Self::CommitPermanent),
            "RecoverV1" => Ok(Self::RecoverV1),
            "EmergencyRecoverV1" => Ok(Self::EmergencyRecoverV1),
            other => Err(UnknownCutoverLabel::new(other)),
        }
    }
}

/// Assert the Rust-side abstract cutover invariants that mirror TLA+ clauses.
///
/// # Panics
///
/// Panics if a snapshot violates one of the TLA+ invariant clauses.
pub fn assert_cutover_invariants(snapshot: &CutoverRuntimeSnapshot) {
    assert!(
        !(snapshot.v1_only_active && snapshot.v2_default_active),
        "TLA_INVARIANT:Safety_no_v1_only_and_v2_default"
    );
    assert!(
        snapshot.shadow_steps <= 1,
        "TLA_INVARIANT:Liveness_shadow_resolves_in_one_step"
    );
    assert!(
        snapshot.rollback_path_to_v1,
        "TLA_INVARIANT:Recoverability_v1_path_exists"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_tla_labels_round_trip() {
        for state in CutoverState::ALL {
            assert_eq!(
                CutoverState::try_from(state.tla_name()).expect("known state"),
                state
            );
        }
    }

    #[test]
    fn action_tla_labels_round_trip() {
        for action in CutoverAction::ALL {
            assert_eq!(
                CutoverAction::try_from(action.tla_name()).expect("known action"),
                action
            );
        }
    }

    #[test]
    fn canonical_snapshots_satisfy_invariants() {
        for state in CutoverState::ALL {
            let snapshot = CutoverRuntimeSnapshot::from_state(state);
            assert_cutover_invariants(&snapshot);
        }
    }
}
