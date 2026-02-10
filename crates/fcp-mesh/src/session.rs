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
    ///
    /// # Panics
    /// Panics if sequence number overflows `u64::MAX`. This prevents nonce reuse.
    pub fn next_send_seq(&mut self) -> u64 {
        assert_ne!(
            self.send_seq,
            u64::MAX,
            "FCP session sequence number overflow: nonce reuse prevention"
        );
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

    #[test]
    fn needs_rekey_time_based() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: u64::MAX,
            rekey_after_seconds: 3600,
            rekey_after_bytes: u64::MAX,
        };
        let session = build_session(true, policy);

        // Established at t=1000, rekey after 3600s
        assert!(!session.needs_rekey(1_000)); // t=0 elapsed
        assert!(!session.needs_rekey(4_599)); // 3599s elapsed
        assert!(session.needs_rekey(4_600)); // 3600s elapsed (exact threshold)
        assert!(session.needs_rekey(5_000)); // well past threshold
    }

    #[test]
    fn needs_rekey_bytes_based() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: u64::MAX,
            rekey_after_seconds: u64::MAX,
            rekey_after_bytes: 100,
        };
        let mut session = build_session(true, policy);

        assert!(!session.needs_rekey(1_000));

        // Send frames totaling >=100 bytes
        for _ in 0..10 {
            let _ = session.mac_outgoing(b"0123456789"); // 10 bytes each
        }
        // 10 frames * 10 bytes = 100 bytes
        assert!(session.needs_rekey(1_000));
    }

    #[test]
    fn needs_rekey_not_triggered_just_below_all_thresholds() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: 10,
            rekey_after_seconds: 3600,
            rekey_after_bytes: 1000,
        };
        let mut session = build_session(true, policy);

        // Send 9 frames of 100 bytes each (900 bytes total, 9 frames)
        for _ in 0..9 {
            let _ = session.mac_outgoing(&[0u8; 100]);
        }

        // 9 frames < 10, 900 bytes < 1000, 0s < 3600s
        assert!(!session.needs_rekey(1_000));
    }

    #[test]
    fn next_send_seq_starts_at_one_and_increments() {
        let mut session = build_session(true, SessionReplayPolicy::default());

        assert_eq!(session.next_send_seq(), 1);
        assert_eq!(session.next_send_seq(), 2);
        assert_eq!(session.next_send_seq(), 3);
    }

    #[test]
    fn verify_incoming_rejects_seq_zero() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let frame = b"payload";

        // Compute a valid MAC for seq=0
        let tag = compute_session_mac(
            SessionCryptoSuite::Suite1,
            session.recv_mac_key(),
            &session.session_id,
            session.recv_direction(),
            0,
            frame,
        )
        .expect("mac");

        // Should reject: seq=0 is explicitly forbidden
        assert!(!session.verify_incoming(0, frame, &tag));
    }

    #[test]
    fn mac_direction_initiator_uses_i2r_send_r2i_recv() {
        let session = build_session(true, SessionReplayPolicy::default());

        assert!(matches!(
            session.send_direction(),
            SessionDirection::InitiatorToResponder
        ));
        assert!(matches!(
            session.recv_direction(),
            SessionDirection::ResponderToInitiator
        ));
        // Send key should use I2R key material
        assert_eq!(session.send_mac_key(), &[1u8; 32]); // k_mac_i2r
        assert_eq!(session.recv_mac_key(), &[2u8; 32]); // k_mac_r2i
    }

    #[test]
    fn mac_direction_responder_uses_r2i_send_i2r_recv() {
        let session = build_session(false, SessionReplayPolicy::default());

        assert!(matches!(
            session.send_direction(),
            SessionDirection::ResponderToInitiator
        ));
        assert!(matches!(
            session.recv_direction(),
            SessionDirection::InitiatorToResponder
        ));
        // Responder sends with R2I, receives with I2R
        assert_eq!(session.send_mac_key(), &[2u8; 32]); // k_mac_r2i
        assert_eq!(session.recv_mac_key(), &[1u8; 32]); // k_mac_i2r
    }

    #[test]
    fn peer_session_symmetry_initiator_to_responder() {
        let keys = SessionKeys {
            k_mac_i2r: [1u8; 32],
            k_mac_r2i: [2u8; 32],
            k_ctx: [3u8; 32],
        };
        let session_id = MeshSessionId([7u8; 16]);
        let policy = SessionReplayPolicy::default();

        let mut initiator = MeshSession::new(
            session_id,
            NodeId::new("responder"),
            SessionCryptoSuite::Suite1,
            keys.clone(),
            TransportLimits::default(),
            true,
            1_000,
            policy.clone(),
        );
        let mut responder = MeshSession::new(
            session_id,
            NodeId::new("initiator"),
            SessionCryptoSuite::Suite1,
            keys,
            TransportLimits::default(),
            false,
            1_000,
            policy,
        );

        // Initiator sends a frame
        let frame = b"hello from initiator";
        let (seq, tag) = initiator.mac_outgoing(frame);

        // Responder should accept it
        assert!(responder.verify_incoming(seq, frame, &tag));

        // Responder sends a frame
        let frame2 = b"hello from responder";
        let (seq2, tag2) = responder.mac_outgoing(frame2);

        // Initiator should accept it
        assert!(initiator.verify_incoming(seq2, frame2, &tag2));
    }

    #[test]
    fn multiple_frames_increment_counters_correctly() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: u64::MAX,
            rekey_after_seconds: u64::MAX,
            rekey_after_bytes: u64::MAX,
        };
        let mut session = build_session(true, policy);

        // Send 5 frames of varying sizes
        let _ = session.mac_outgoing(b"a"); // 1 byte
        let _ = session.mac_outgoing(b"bb"); // 2 bytes
        let _ = session.mac_outgoing(b"ccc"); // 3 bytes
        let _ = session.mac_outgoing(b"dddd"); // 4 bytes
        let _ = session.mac_outgoing(b"eeeee"); // 5 bytes

        // frames_sent = 5, bytes_sent = 1+2+3+4+5 = 15
        // send_seq = 5 (next will be 6)
        assert_eq!(session.next_send_seq(), 6);
    }

    #[test]
    fn out_of_order_reception_within_window() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let frame = b"payload";

        // Generate MACs for seqs 1, 2, 3
        let tags: Vec<_> = (1..=3u64)
            .map(|seq| {
                let tag = compute_session_mac(
                    SessionCryptoSuite::Suite1,
                    session.recv_mac_key(),
                    &session.session_id,
                    session.recv_direction(),
                    seq,
                    frame,
                )
                .expect("mac");
                (seq, tag)
            })
            .collect();

        // Receive out of order: 2, 3, 1
        assert!(session.verify_incoming(tags[1].0, frame, &tags[1].1)); // seq=2
        assert!(session.verify_incoming(tags[2].0, frame, &tags[2].1)); // seq=3
        assert!(session.verify_incoming(tags[0].0, frame, &tags[0].1)); // seq=1

        // All should be rejected on replay
        assert!(!session.verify_incoming(tags[0].0, frame, &tags[0].1));
        assert!(!session.verify_incoming(tags[1].0, frame, &tags[1].1));
        assert!(!session.verify_incoming(tags[2].0, frame, &tags[2].1));
    }

    #[test]
    fn tampered_frame_rejected_even_with_valid_seq() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let frame = b"original";
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

        // Tamper with the frame content
        assert!(!session.verify_incoming(seq, b"tampered", &tag));
    }
}
