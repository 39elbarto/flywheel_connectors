//! FCP2 Mesh Session State Machine.
//!
//! This module builds on `fcp-protocol` primitives to provide a stateful
//! session object (`MeshSession`).

use fcp_protocol::session::{
    MeshSessionId, ReplayWindow, SessionCryptoSuite, SessionDirection, SessionKeys,
    SessionReplayPolicy, TransportLimits, compute_session_mac, verify_session_mac,
};
use fcp_tailscale::NodeId;

/// Session state for a peer connection.
///
/// Represents an established session with a peer, including
/// cryptographic keys, anti-replay state, and rekey tracking.
#[derive(Debug)]
pub struct MeshSession {
    /// Unique session identifier.
    pub session_id: MeshSessionId,
    /// Peer node ID.
    pub peer_id: NodeId,
    /// Negotiated crypto suite.
    pub suite: SessionCryptoSuite,
    /// Session keys.
    pub keys: SessionKeys,
    /// Negotiated transport limits.
    pub transport_limits: TransportLimits,
    /// Whether we are the initiator.
    pub is_initiator: bool,

    // Anti-replay state
    /// Next sequence number to send.
    send_seq: u64,
    /// Replay window for received sequences.
    recv_window: ReplayWindow,

    // Rekey tracking
    /// Total frames sent on this session.
    frames_sent: u64,
    /// Total bytes sent on this session.
    bytes_sent: u64,
    /// Timestamp when session was established (seconds since epoch).
    established_at: u64,
    /// Replay policy for this session.
    replay_policy: SessionReplayPolicy,
}

impl MeshSession {
    /// Create a new session.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: MeshSessionId,
        peer_id: NodeId,
        suite: SessionCryptoSuite,
        keys: SessionKeys,
        transport_limits: TransportLimits,
        is_initiator: bool,
        established_at: u64,
        replay_policy: SessionReplayPolicy,
    ) -> Self {
        Self {
            session_id,
            peer_id,
            suite,
            keys,
            transport_limits,
            is_initiator,
            send_seq: 0,
            recv_window: ReplayWindow::new(replay_policy.max_reorder_window),
            frames_sent: 0,
            bytes_sent: 0,
            established_at,
            replay_policy,
        }
    }

    /// Check if session needs rekeying.
    #[must_use]
    pub const fn needs_rekey(&self, current_time: u64) -> bool {
        self.frames_sent >= self.replay_policy.rekey_after_frames
            || self.bytes_sent >= self.replay_policy.rekey_after_bytes
            || (current_time.saturating_sub(self.established_at))
                >= self.replay_policy.rekey_after_seconds
    }

    /// Get next send sequence and increment.
    pub const fn next_send_seq(&mut self) -> u64 {
        self.send_seq += 1;
        self.send_seq
    }

    /// Check received sequence for replay and update window.
    pub fn check_recv_seq(&mut self, seq: u64) -> bool {
        self.recv_window.check_and_update(seq)
    }

    /// Get MAC key for sending.
    #[must_use]
    pub const fn send_mac_key(&self) -> &[u8; 32] {
        self.keys.mac_key(if self.is_initiator {
            SessionDirection::InitiatorToResponder
        } else {
            SessionDirection::ResponderToInitiator
        })
    }

    /// Get MAC key for receiving.
    #[must_use]
    pub const fn recv_mac_key(&self) -> &[u8; 32] {
        self.keys.mac_key(if self.is_initiator {
            SessionDirection::ResponderToInitiator
        } else {
            SessionDirection::InitiatorToResponder
        })
    }

    /// Direction for MAC computation (sending).
    #[must_use]
    pub const fn send_direction(&self) -> SessionDirection {
        if self.is_initiator {
            SessionDirection::InitiatorToResponder
        } else {
            SessionDirection::ResponderToInitiator
        }
    }

    /// Direction for MAC computation (receiving).
    #[must_use]
    pub const fn recv_direction(&self) -> SessionDirection {
        if self.is_initiator {
            SessionDirection::ResponderToInitiator
        } else {
            SessionDirection::InitiatorToResponder
        }
    }

    /// Compute MAC for an outgoing frame and update counters.
    ///
    /// Returns (`sequence_number`, mac).
    ///
    /// # Panics
    /// Panics if MAC computation fails due to an invalid key length.
    pub fn mac_outgoing(&mut self, frame_bytes: &[u8]) -> (u64, [u8; 16]) {
        let seq = self.next_send_seq();
        let mac = compute_session_mac(
            self.suite,
            self.send_mac_key(),
            &self.session_id,
            self.send_direction(),
            seq,
            frame_bytes,
        )
        .expect("MAC computation failed (invalid key length?)");

        self.frames_sent += 1;
        self.bytes_sent += frame_bytes.len() as u64;
        (seq, mac)
    }

    /// Verify MAC for an incoming frame and check replay.
    ///
    /// SECURITY NOTE: MAC is verified BEFORE updating the replay window.
    /// This prevents a `DoS` attack where an attacker burns sequence numbers
    /// by sending garbage frames that fail MAC verification.
    #[must_use]
    pub fn verify_incoming(&mut self, seq: u64, frame_bytes: &[u8], tag: &[u8; 16]) -> bool {
        // Quick bounds check
        if seq == 0 {
            return false;
        }

        // Anti-DoS: Check if seq is astronomically far ahead (window jumping)
        // ReplayWindow logic handles this but we can check here too if needed.
        // For now rely on ReplayWindow logic which we call AFTER mac check?
        // No, we should check if it's plausible before spending CPU on MAC?
        // But verifying MAC first is safer against window corruption?
        // Actually, verifying MAC first is critical. But if seq is huge, it might be a valid future packet?
        // ReplayWindow doesn't expose "is_plausible" easily.
        // Let's verify MAC first.

        let valid_mac = verify_session_mac(
            self.suite,
            self.recv_mac_key(),
            &self.session_id,
            self.recv_direction(),
            seq,
            frame_bytes,
            tag,
        )
        .is_ok();

        if !valid_mac {
            return false;
        }

        // Only update replay window after MAC verification succeeds
        self.check_recv_seq(seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_session(is_initiator: bool, replay_policy: SessionReplayPolicy) -> MeshSession {
        let keys = SessionKeys {
            k_mac_i2r: [1u8; 32],
            k_mac_r2i: [2u8; 32],
            k_ctx: [3u8; 32],
        };
        MeshSession::new(
            MeshSessionId([7u8; 16]),
            NodeId::new("node-test"),
            SessionCryptoSuite::Suite1,
            keys,
            TransportLimits::default(),
            is_initiator,
            1_000,
            replay_policy,
        )
    }

    #[test]
    fn mac_outgoing_triggers_rekey_after_threshold() {
        let replay_policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: 1,
            rekey_after_seconds: u64::MAX,
            rekey_after_bytes: u64::MAX,
        };
        let mut session = build_session(true, replay_policy);
        assert!(!session.needs_rekey(1_000));

        let _ = session.mac_outgoing(b"frame");
        assert!(session.needs_rekey(1_000));
    }

    #[test]
    fn verify_incoming_accepts_valid_mac_and_rejects_replay() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let frame = b"payload";
        let seq = 1;

        let tag = compute_session_mac(
            SessionCryptoSuite::Suite1,
            session.recv_mac_key(),
            &session.session_id,
            session.recv_direction(),
            seq,
            frame,
        )
        .expect("mac");

        assert!(session.verify_incoming(seq, frame, &tag));
        // Replays should be rejected by replay window.
        assert!(!session.verify_incoming(seq, frame, &tag));
    }

    #[test]
    fn verify_incoming_rejects_bad_mac() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let frame = b"payload";
        let seq = 1;

        let bad_tag = compute_session_mac(
            SessionCryptoSuite::Suite1,
            session.send_mac_key(),
            &session.session_id,
            session.send_direction(),
            seq,
            frame,
        )
        .expect("mac");

        assert!(!session.verify_incoming(seq, frame, &bad_tag));
    }
}
