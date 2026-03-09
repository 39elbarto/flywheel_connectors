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

    // ── Batch: rekey trigger combinations ──

    #[test]
    fn needs_rekey_frames_exact_threshold() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: 3,
            rekey_after_seconds: u64::MAX,
            rekey_after_bytes: u64::MAX,
        };
        let mut session = build_session(true, policy);

        let _ = session.mac_outgoing(b"a");
        let _ = session.mac_outgoing(b"b");
        assert!(!session.needs_rekey(1_000)); // 2 frames < 3
        let _ = session.mac_outgoing(b"c");
        assert!(session.needs_rekey(1_000)); // 3 frames >= 3
    }

    #[test]
    fn needs_rekey_time_saturating_sub() {
        // Test that established_at > current_time doesn't panic (saturating sub)
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: u64::MAX,
            rekey_after_seconds: 3600,
            rekey_after_bytes: u64::MAX,
        };
        // established_at = 5000, current_time = 1000 (in the past somehow)
        let session = build_session(true, policy);
        // Should not need rekey since elapsed would be 0 (saturating)
        assert!(!session.needs_rekey(500));
    }

    // ── Batch: session construction ──

    #[test]
    fn session_initial_state() {
        let policy = SessionReplayPolicy::default();
        let session = build_session(true, policy);

        assert_eq!(session.session_id, MeshSessionId([7u8; 16]));
        assert!(session.is_initiator);
        assert!(!session.needs_rekey(1_000));
    }

    #[test]
    fn session_debug_format() {
        let session = build_session(true, SessionReplayPolicy::default());
        let debug = format!("{session:?}");
        assert!(debug.contains("MeshSession"));
    }

    // ── Batch: MAC symmetry with Suite2 ──

    #[test]
    fn suite2_symmetry() {
        let keys = SessionKeys {
            k_mac_i2r: [10u8; 32],
            k_mac_r2i: [20u8; 32],
            k_ctx: [30u8; 32],
        };
        let session_id = MeshSessionId([42u8; 16]);
        let policy = SessionReplayPolicy::default();

        let mut initiator = MeshSession::new(
            session_id,
            NodeId::new("peer-r"),
            SessionCryptoSuite::Suite2,
            keys.clone(),
            TransportLimits::default(),
            true,
            2_000,
            policy.clone(),
        );
        let mut responder = MeshSession::new(
            session_id,
            NodeId::new("peer-i"),
            SessionCryptoSuite::Suite2,
            keys,
            TransportLimits::default(),
            false,
            2_000,
            policy,
        );

        let frame = b"suite2 test frame";
        let (seq, tag) = initiator.mac_outgoing(frame);
        assert!(responder.verify_incoming(seq, frame, &tag));
    }

    // ── Batch: empty frame ──

    #[test]
    fn mac_outgoing_empty_frame() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let (seq, _tag) = session.mac_outgoing(b"");
        assert_eq!(seq, 1);
    }

    // ── Batch: large sequence gaps ──

    #[test]
    fn verify_incoming_large_seq_gap_behind_window_rejected() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: u64::MAX,
            rekey_after_seconds: u64::MAX,
            rekey_after_bytes: u64::MAX,
        };
        let mut session = build_session(true, policy);
        let frame = b"data";

        // Jump to seq=500
        let tag = compute_session_mac(
            SessionCryptoSuite::Suite1,
            session.recv_mac_key(),
            &session.session_id,
            session.recv_direction(),
            500,
            frame,
        )
        .expect("mac");
        assert!(session.verify_incoming(500, frame, &tag));

        // seq=1 is now 499 behind the window head (500), which exceeds
        // the max_reorder_window of 128, so it should be rejected
        let tag1 = compute_session_mac(
            SessionCryptoSuite::Suite1,
            session.recv_mac_key(),
            &session.session_id,
            session.recv_direction(),
            1,
            frame,
        )
        .expect("mac");
        assert!(!session.verify_incoming(1, frame, &tag1));
    }

    #[test]
    fn verify_incoming_within_reorder_window_accepted() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: u64::MAX,
            rekey_after_seconds: u64::MAX,
            rekey_after_bytes: u64::MAX,
        };
        let mut session = build_session(true, policy);
        let frame = b"data";

        // Receive seq=100 first
        let tag100 = compute_session_mac(
            SessionCryptoSuite::Suite1,
            session.recv_mac_key(),
            &session.session_id,
            session.recv_direction(),
            100,
            frame,
        )
        .expect("mac");
        assert!(session.verify_incoming(100, frame, &tag100));

        // seq=50 is 50 behind the window head (100), within window of 128
        let tag50 = compute_session_mac(
            SessionCryptoSuite::Suite1,
            session.recv_mac_key(),
            &session.session_id,
            session.recv_direction(),
            50,
            frame,
        )
        .expect("mac");
        assert!(session.verify_incoming(50, frame, &tag50));
    }

    // ── Batch: cross-session isolation ──

    #[test]
    fn different_sessions_reject_cross_mac() {
        let keys = SessionKeys {
            k_mac_i2r: [1u8; 32],
            k_mac_r2i: [2u8; 32],
            k_ctx: [3u8; 32],
        };
        let policy = SessionReplayPolicy::default();

        let mut session_a = MeshSession::new(
            MeshSessionId([1u8; 16]),
            NodeId::new("peer"),
            SessionCryptoSuite::Suite1,
            keys.clone(),
            TransportLimits::default(),
            true,
            1_000,
            policy.clone(),
        );
        let mut session_b = MeshSession::new(
            MeshSessionId([2u8; 16]), // Different session ID
            NodeId::new("peer"),
            SessionCryptoSuite::Suite1,
            keys,
            TransportLimits::default(),
            false,
            1_000,
            policy,
        );

        let frame = b"payload";
        let (seq, tag) = session_a.mac_outgoing(frame);
        // Should fail because session_b has different session_id
        assert!(!session_b.verify_incoming(seq, frame, &tag));
    }

    // ── Batch: construction and field access ──

    #[test]
    fn session_responder_initial_state() {
        let session = build_session(false, SessionReplayPolicy::default());
        assert!(!session.is_initiator);
        assert_eq!(session.session_id, MeshSessionId([7u8; 16]));
    }

    #[test]
    fn session_established_at_stored() {
        let keys = SessionKeys {
            k_mac_i2r: [1u8; 32],
            k_mac_r2i: [2u8; 32],
            k_ctx: [3u8; 32],
        };
        let session = MeshSession::new(
            MeshSessionId([0u8; 16]),
            NodeId::new("peer"),
            SessionCryptoSuite::Suite1,
            keys,
            TransportLimits::default(),
            true,
            42_000,
            SessionReplayPolicy::default(),
        );
        // established_at=42000, rekey_after_seconds=86400
        // at t=42000 elapsed=0
        assert!(!session.needs_rekey(42_000));
        // at t=42000+86400=128400
        assert!(session.needs_rekey(128_400));
    }

    #[test]
    fn session_peer_id_stored() {
        let keys = SessionKeys {
            k_mac_i2r: [1u8; 32],
            k_mac_r2i: [2u8; 32],
            k_ctx: [3u8; 32],
        };
        let session = MeshSession::new(
            MeshSessionId([0u8; 16]),
            NodeId::new("my-peer-node"),
            SessionCryptoSuite::Suite1,
            keys,
            TransportLimits::default(),
            true,
            1_000,
            SessionReplayPolicy::default(),
        );
        assert_eq!(session.peer_id.as_str(), "my-peer-node");
    }

    #[test]
    fn session_suite_stored() {
        let keys = SessionKeys {
            k_mac_i2r: [1u8; 32],
            k_mac_r2i: [2u8; 32],
            k_ctx: [3u8; 32],
        };
        let session = MeshSession::new(
            MeshSessionId([0u8; 16]),
            NodeId::new("peer"),
            SessionCryptoSuite::Suite2,
            keys,
            TransportLimits::default(),
            true,
            1_000,
            SessionReplayPolicy::default(),
        );
        assert_eq!(session.suite, SessionCryptoSuite::Suite2);
    }

    #[test]
    fn session_transport_limits_stored() {
        let keys = SessionKeys {
            k_mac_i2r: [1u8; 32],
            k_mac_r2i: [2u8; 32],
            k_ctx: [3u8; 32],
        };
        let limits = TransportLimits {
            max_datagram_bytes: 512,
        };
        let session = MeshSession::new(
            MeshSessionId([0u8; 16]),
            NodeId::new("peer"),
            SessionCryptoSuite::Suite1,
            keys,
            limits,
            true,
            1_000,
            SessionReplayPolicy::default(),
        );
        assert_eq!(session.transport_limits.max_datagram_bytes, 512);
    }

    // ── Batch: sequence number edge cases ──

    #[test]
    fn next_send_seq_many_increments() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        for expected in 1..=100 {
            assert_eq!(session.next_send_seq(), expected);
        }
    }

    #[test]
    #[should_panic(expected = "nonce reuse prevention")]
    fn next_send_seq_overflow_panics() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        // Force send_seq to u64::MAX
        session.send_seq = u64::MAX;
        let _ = session.next_send_seq();
    }

    #[test]
    fn send_seq_near_max_still_works() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        session.send_seq = u64::MAX - 2;
        assert_eq!(session.next_send_seq(), u64::MAX - 1);
    }

    // ── Batch: rekey combinations ──

    #[test]
    fn needs_rekey_all_thresholds_at_once() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: 1,
            rekey_after_seconds: 1,
            rekey_after_bytes: 1,
        };
        let mut session = build_session(true, policy);
        let _ = session.mac_outgoing(b"x");
        // All three conditions met simultaneously
        assert!(session.needs_rekey(1_001));
    }

    #[test]
    fn needs_rekey_frames_only() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: 2,
            rekey_after_seconds: u64::MAX,
            rekey_after_bytes: u64::MAX,
        };
        let mut session = build_session(true, policy);
        let _ = session.mac_outgoing(b"a");
        assert!(!session.needs_rekey(1_000));
        let _ = session.mac_outgoing(b"b");
        assert!(session.needs_rekey(1_000));
    }

    #[test]
    fn needs_rekey_bytes_exact_threshold() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: u64::MAX,
            rekey_after_seconds: u64::MAX,
            rekey_after_bytes: 5,
        };
        let mut session = build_session(true, policy);
        let _ = session.mac_outgoing(b"abcd"); // 4 bytes
        assert!(!session.needs_rekey(1_000));
        let _ = session.mac_outgoing(b"e"); // 5th byte
        assert!(session.needs_rekey(1_000));
    }

    #[test]
    fn needs_rekey_time_exact_boundary() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: u64::MAX,
            rekey_after_seconds: 100,
            rekey_after_bytes: u64::MAX,
        };
        let session = build_session(true, policy);
        // established_at = 1000
        assert!(!session.needs_rekey(1_099)); // 99s elapsed
        assert!(session.needs_rekey(1_100)); // 100s elapsed
    }

    #[test]
    fn needs_rekey_zero_second_threshold() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: u64::MAX,
            rekey_after_seconds: 0,
            rekey_after_bytes: u64::MAX,
        };
        let session = build_session(true, policy);
        // Any time >= established_at triggers rekey since 0 seconds required
        assert!(session.needs_rekey(1_000));
    }

    #[test]
    fn needs_rekey_false_fresh_session() {
        let session = build_session(true, SessionReplayPolicy::default());
        // Default policy: 1B frames, 86400s, 1TB bytes
        assert!(!session.needs_rekey(1_000));
    }

    // ── Batch: MAC direction symmetry ──

    #[test]
    fn initiator_send_key_differs_from_recv_key() {
        let session = build_session(true, SessionReplayPolicy::default());
        assert_ne!(session.send_mac_key(), session.recv_mac_key());
    }

    #[test]
    fn responder_send_key_differs_from_recv_key() {
        let session = build_session(false, SessionReplayPolicy::default());
        assert_ne!(session.send_mac_key(), session.recv_mac_key());
    }

    #[test]
    fn initiator_send_key_equals_responder_recv_key() {
        let init = build_session(true, SessionReplayPolicy::default());
        let resp = build_session(false, SessionReplayPolicy::default());
        assert_eq!(init.send_mac_key(), resp.recv_mac_key());
        assert_eq!(init.recv_mac_key(), resp.send_mac_key());
    }

    #[test]
    fn initiator_send_direction_is_i2r() {
        let session = build_session(true, SessionReplayPolicy::default());
        assert_eq!(
            session.send_direction(),
            SessionDirection::InitiatorToResponder
        );
    }

    #[test]
    fn responder_send_direction_is_r2i() {
        let session = build_session(false, SessionReplayPolicy::default());
        assert_eq!(
            session.send_direction(),
            SessionDirection::ResponderToInitiator
        );
    }

    #[test]
    fn initiator_recv_direction_is_r2i() {
        let session = build_session(true, SessionReplayPolicy::default());
        assert_eq!(
            session.recv_direction(),
            SessionDirection::ResponderToInitiator
        );
    }

    #[test]
    fn responder_recv_direction_is_i2r() {
        let session = build_session(false, SessionReplayPolicy::default());
        assert_eq!(
            session.recv_direction(),
            SessionDirection::InitiatorToResponder
        );
    }

    // ── Batch: MAC outgoing ──

    #[test]
    fn mac_outgoing_seq_starts_at_one() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let (seq, _) = session.mac_outgoing(b"frame");
        assert_eq!(seq, 1);
    }

    #[test]
    fn mac_outgoing_seq_increments() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let (s1, _) = session.mac_outgoing(b"a");
        let (s2, _) = session.mac_outgoing(b"b");
        let (s3, _) = session.mac_outgoing(b"c");
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(s3, 3);
    }

    #[test]
    fn mac_outgoing_different_frames_different_macs() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let (_, mac1) = session.mac_outgoing(b"frame-a");
        let (_, mac2) = session.mac_outgoing(b"frame-b");
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn mac_outgoing_same_frame_different_seq_different_mac() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let (_, mac1) = session.mac_outgoing(b"same");
        let (_, mac2) = session.mac_outgoing(b"same");
        // Different seq numbers should produce different MACs
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn mac_outgoing_updates_frames_sent() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: 5,
            rekey_after_seconds: u64::MAX,
            rekey_after_bytes: u64::MAX,
        };
        let mut session = build_session(true, policy);
        for _ in 0..4 {
            let _ = session.mac_outgoing(b"x");
        }
        assert!(!session.needs_rekey(1_000));
        let _ = session.mac_outgoing(b"x");
        assert!(session.needs_rekey(1_000));
    }

    #[test]
    fn mac_outgoing_updates_bytes_sent() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: u64::MAX,
            rekey_after_seconds: u64::MAX,
            rekey_after_bytes: 20,
        };
        let mut session = build_session(true, policy);
        let _ = session.mac_outgoing(b"1234567890"); // 10 bytes
        assert!(!session.needs_rekey(1_000));
        let _ = session.mac_outgoing(b"1234567890"); // 20 bytes total
        assert!(session.needs_rekey(1_000));
    }

    #[test]
    fn mac_outgoing_large_frame() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let large = vec![0xAAu8; 65536];
        let (seq, mac) = session.mac_outgoing(&large);
        assert_eq!(seq, 1);
        assert_ne!(mac, [0u8; 16]);
    }

    // ── Batch: verify_incoming edge cases ──

    #[test]
    fn verify_incoming_sequential_acceptance() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let frame = b"data";

        for seq in 1..=10u64 {
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
        }
    }

    #[test]
    fn verify_incoming_rejects_all_zero_tag() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        assert!(!session.verify_incoming(1, b"frame", &[0u8; 16]));
    }

    #[test]
    fn verify_incoming_rejects_all_ff_tag() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        assert!(!session.verify_incoming(1, b"frame", &[0xFFu8; 16]));
    }

    #[test]
    fn verify_incoming_empty_frame_valid() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let frame = b"";
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
    }

    #[test]
    fn verify_incoming_wrong_seq_rejected() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let frame = b"data";
        let tag = compute_session_mac(
            SessionCryptoSuite::Suite1,
            session.recv_mac_key(),
            &session.session_id,
            session.recv_direction(),
            5,
            frame,
        )
        .expect("mac");
        // Tag computed for seq=5 but provided as seq=6
        assert!(!session.verify_incoming(6, frame, &tag));
    }

    #[test]
    fn verify_incoming_does_not_advance_window_on_bad_mac() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let frame = b"data";

        // Try with bad MAC for seq=1 — should NOT advance window
        assert!(!session.verify_incoming(1, frame, &[0u8; 16]));

        // Now try with valid MAC for seq=1 — should still work
        let tag = compute_session_mac(
            SessionCryptoSuite::Suite1,
            session.recv_mac_key(),
            &session.session_id,
            session.recv_direction(),
            1,
            frame,
        )
        .expect("mac");
        assert!(session.verify_incoming(1, frame, &tag));
    }

    // ── Batch: replay window behavior ──

    #[test]
    fn check_recv_seq_accepts_first_then_rejects() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        assert!(session.check_recv_seq(1));
        assert!(!session.check_recv_seq(1));
    }

    #[test]
    fn check_recv_seq_accepts_ascending() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        for seq in 1..=50 {
            assert!(session.check_recv_seq(seq));
        }
    }

    #[test]
    fn check_recv_seq_out_of_order_within_window() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: u64::MAX,
            rekey_after_seconds: u64::MAX,
            rekey_after_bytes: u64::MAX,
        };
        let mut session = build_session(true, policy);
        assert!(session.check_recv_seq(5));
        assert!(session.check_recv_seq(3));
        assert!(session.check_recv_seq(4));
        assert!(session.check_recv_seq(1));
        assert!(session.check_recv_seq(2));
    }

    #[test]
    fn check_recv_seq_rejects_behind_window() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 10,
            rekey_after_frames: u64::MAX,
            rekey_after_seconds: u64::MAX,
            rekey_after_bytes: u64::MAX,
        };
        let mut session = build_session(true, policy);
        // Move window forward
        assert!(session.check_recv_seq(100));
        // seq=1 is 99 behind, window is only 10
        assert!(!session.check_recv_seq(1));
    }

    // ── Batch: cross-suite rejection ──

    #[test]
    fn cross_suite_mac_rejected() {
        let keys = SessionKeys {
            k_mac_i2r: [1u8; 32],
            k_mac_r2i: [2u8; 32],
            k_ctx: [3u8; 32],
        };
        let policy = SessionReplayPolicy::default();
        let session_id = MeshSessionId([7u8; 16]);

        // Compute MAC with Suite1
        let tag = compute_session_mac(
            SessionCryptoSuite::Suite1,
            &keys.k_mac_r2i,
            &session_id,
            SessionDirection::ResponderToInitiator,
            1,
            b"data",
        )
        .expect("mac");

        // Verify with Suite2 session
        let mut session = MeshSession::new(
            session_id,
            NodeId::new("peer"),
            SessionCryptoSuite::Suite2,
            keys,
            TransportLimits::default(),
            true,
            1_000,
            policy,
        );
        assert!(!session.verify_incoming(1, b"data", &tag));
    }

    // ── Batch: bidirectional communication ──

    #[test]
    fn bidirectional_multi_frame_exchange() {
        let keys = SessionKeys {
            k_mac_i2r: [10u8; 32],
            k_mac_r2i: [20u8; 32],
            k_ctx: [30u8; 32],
        };
        let session_id = MeshSessionId([99u8; 16]);
        let policy = SessionReplayPolicy::default();

        let mut init = MeshSession::new(
            session_id,
            NodeId::new("resp"),
            SessionCryptoSuite::Suite1,
            keys.clone(),
            TransportLimits::default(),
            true,
            1_000,
            policy.clone(),
        );
        let mut resp = MeshSession::new(
            session_id,
            NodeId::new("init"),
            SessionCryptoSuite::Suite1,
            keys,
            TransportLimits::default(),
            false,
            1_000,
            policy,
        );

        // Multiple rounds of communication
        for i in 0..5 {
            let msg = format!("init-msg-{i}");
            let (seq, tag) = init.mac_outgoing(msg.as_bytes());
            assert!(resp.verify_incoming(seq, msg.as_bytes(), &tag));

            let reply = format!("resp-msg-{i}");
            let (seq2, tag2) = resp.mac_outgoing(reply.as_bytes());
            assert!(init.verify_incoming(seq2, reply.as_bytes(), &tag2));
        }
    }

    #[test]
    fn suite2_bidirectional_multi_frame() {
        let keys = SessionKeys {
            k_mac_i2r: [50u8; 32],
            k_mac_r2i: [60u8; 32],
            k_ctx: [70u8; 32],
        };
        let session_id = MeshSessionId([88u8; 16]);
        let policy = SessionReplayPolicy::default();

        let mut init = MeshSession::new(
            session_id,
            NodeId::new("r"),
            SessionCryptoSuite::Suite2,
            keys.clone(),
            TransportLimits::default(),
            true,
            2_000,
            policy.clone(),
        );
        let mut resp = MeshSession::new(
            session_id,
            NodeId::new("i"),
            SessionCryptoSuite::Suite2,
            keys,
            TransportLimits::default(),
            false,
            2_000,
            policy,
        );

        let (seq, tag) = init.mac_outgoing(b"hello");
        assert!(resp.verify_incoming(seq, b"hello", &tag));
        let (seq2, tag2) = resp.mac_outgoing(b"world");
        assert!(init.verify_incoming(seq2, b"world", &tag2));
    }

    // ── Batch: replay policy cloning ──

    #[test]
    fn session_replay_policy_default_values() {
        let policy = SessionReplayPolicy::default();
        assert_eq!(policy.max_reorder_window, 128);
        assert_eq!(policy.rekey_after_frames, 1_000_000_000);
        assert_eq!(policy.rekey_after_seconds, 86_400);
        assert_eq!(policy.rekey_after_bytes, 1_099_511_627_776);
    }

    #[test]
    fn session_replay_policy_copy() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 64,
            rekey_after_frames: 500,
            rekey_after_seconds: 300,
            rekey_after_bytes: 1000,
        };
        let copy = policy;
        assert_eq!(copy.max_reorder_window, 64);
        assert_eq!(copy.rekey_after_frames, 500);
        assert_eq!(copy.rekey_after_seconds, 300);
        assert_eq!(copy.rekey_after_bytes, 1000);
    }

    // ── Batch: different key material ──

    #[test]
    fn different_keys_reject_mac() {
        let keys_a = SessionKeys {
            k_mac_i2r: [1u8; 32],
            k_mac_r2i: [2u8; 32],
            k_ctx: [3u8; 32],
        };
        let keys_b = SessionKeys {
            k_mac_i2r: [4u8; 32],
            k_mac_r2i: [5u8; 32],
            k_ctx: [6u8; 32],
        };
        let session_id = MeshSessionId([7u8; 16]);
        let policy = SessionReplayPolicy::default();

        let mut sender = MeshSession::new(
            session_id,
            NodeId::new("peer"),
            SessionCryptoSuite::Suite1,
            keys_a,
            TransportLimits::default(),
            true,
            1_000,
            policy.clone(),
        );
        let mut receiver = MeshSession::new(
            session_id,
            NodeId::new("peer"),
            SessionCryptoSuite::Suite1,
            keys_b,
            TransportLimits::default(),
            false,
            1_000,
            policy,
        );

        let (seq, tag) = sender.mac_outgoing(b"secret");
        assert!(!receiver.verify_incoming(seq, b"secret", &tag));
    }

    // ── Batch: session_id all zeros ──

    #[test]
    fn session_with_zero_id() {
        let keys = SessionKeys {
            k_mac_i2r: [1u8; 32],
            k_mac_r2i: [2u8; 32],
            k_ctx: [3u8; 32],
        };
        let session_id = MeshSessionId([0u8; 16]);
        let policy = SessionReplayPolicy::default();

        let mut init = MeshSession::new(
            session_id,
            NodeId::new("resp"),
            SessionCryptoSuite::Suite1,
            keys.clone(),
            TransportLimits::default(),
            true,
            0,
            policy.clone(),
        );
        let mut resp = MeshSession::new(
            session_id,
            NodeId::new("init"),
            SessionCryptoSuite::Suite1,
            keys,
            TransportLimits::default(),
            false,
            0,
            policy,
        );

        let (seq, tag) = init.mac_outgoing(b"msg");
        assert!(resp.verify_incoming(seq, b"msg", &tag));
    }

    // ── Batch: established_at edge cases ──

    #[test]
    fn session_established_at_zero() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: u64::MAX,
            rekey_after_seconds: 100,
            rekey_after_bytes: u64::MAX,
        };
        let keys = SessionKeys {
            k_mac_i2r: [1u8; 32],
            k_mac_r2i: [2u8; 32],
            k_ctx: [3u8; 32],
        };
        let session = MeshSession::new(
            MeshSessionId([0u8; 16]),
            NodeId::new("peer"),
            SessionCryptoSuite::Suite1,
            keys,
            TransportLimits::default(),
            true,
            0,
            policy,
        );
        // at t=99 elapsed=99 < 100
        assert!(!session.needs_rekey(99));
        // at t=100 elapsed=100 >= 100
        assert!(session.needs_rekey(100));
    }

    #[test]
    fn session_established_at_max() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: u64::MAX,
            rekey_after_seconds: 100,
            rekey_after_bytes: u64::MAX,
        };
        let keys = SessionKeys {
            k_mac_i2r: [1u8; 32],
            k_mac_r2i: [2u8; 32],
            k_ctx: [3u8; 32],
        };
        let session = MeshSession::new(
            MeshSessionId([0u8; 16]),
            NodeId::new("peer"),
            SessionCryptoSuite::Suite1,
            keys,
            TransportLimits::default(),
            true,
            u64::MAX,
            policy,
        );
        // saturating_sub(u64::MAX, u64::MAX) = 0 < 100
        assert!(!session.needs_rekey(u64::MAX));
    }

    // ── Batch: Debug formatting ──

    #[test]
    fn session_debug_contains_peer_id() {
        let session = build_session(true, SessionReplayPolicy::default());
        let debug = format!("{session:?}");
        assert!(debug.contains("node-test"));
    }

    #[test]
    fn session_debug_contains_suite() {
        let session = build_session(true, SessionReplayPolicy::default());
        let debug = format!("{session:?}");
        assert!(debug.contains("Suite1"));
    }

    #[test]
    fn session_debug_contains_is_initiator() {
        let session = build_session(true, SessionReplayPolicy::default());
        let debug = format!("{session:?}");
        assert!(debug.contains("is_initiator: true"));
    }

    // ── Batch: mac_outgoing bytes accounting ──

    #[test]
    fn mac_outgoing_zero_length_frame_zero_bytes() {
        let policy = SessionReplayPolicy {
            max_reorder_window: 128,
            rekey_after_frames: u64::MAX,
            rekey_after_seconds: u64::MAX,
            rekey_after_bytes: 1, // even 1 byte triggers
        };
        let mut session = build_session(true, policy);
        let _ = session.mac_outgoing(b""); // 0 bytes
        // 0 bytes < 1 threshold
        assert!(!session.needs_rekey(1_000));
        let _ = session.mac_outgoing(b"x"); // 1 byte
        assert!(session.needs_rekey(1_000));
    }

    // ── Batch: consecutive replay rejections ──

    #[test]
    fn replay_rejected_multiple_times() {
        let mut session = build_session(true, SessionReplayPolicy::default());
        let frame = b"data";
        let tag = compute_session_mac(
            SessionCryptoSuite::Suite1,
            session.recv_mac_key(),
            &session.session_id,
            session.recv_direction(),
            1,
            frame,
        )
        .expect("mac");

        assert!(session.verify_incoming(1, frame, &tag));
        // Replay many times
        for _ in 0..5 {
            assert!(!session.verify_incoming(1, frame, &tag));
        }
    }

    // ── Batch: MeshSessionId ──

    #[test]
    fn mesh_session_id_equality() {
        let a = MeshSessionId([1u8; 16]);
        let b = MeshSessionId([1u8; 16]);
        let c = MeshSessionId([2u8; 16]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn mesh_session_id_copy() {
        let a = MeshSessionId([5u8; 16]);
        let b = a;
        assert_eq!(a, b);
    }

    // ── Batch: SessionKeys ──

    #[test]
    fn session_keys_fields_independent() {
        let keys = SessionKeys {
            k_mac_i2r: [1u8; 32],
            k_mac_r2i: [2u8; 32],
            k_ctx: [3u8; 32],
        };
        assert_ne!(keys.k_mac_i2r, keys.k_mac_r2i);
        assert_ne!(keys.k_mac_r2i, keys.k_ctx);
        assert_ne!(keys.k_mac_i2r, keys.k_ctx);
    }

    #[test]
    fn session_keys_mac_key_direction() {
        let keys = SessionKeys {
            k_mac_i2r: [1u8; 32],
            k_mac_r2i: [2u8; 32],
            k_ctx: [3u8; 32],
        };
        assert_eq!(
            keys.mac_key(SessionDirection::InitiatorToResponder),
            &[1u8; 32]
        );
        assert_eq!(
            keys.mac_key(SessionDirection::ResponderToInitiator),
            &[2u8; 32]
        );
    }

    // ── Batch: Transport limits ──

    #[test]
    fn transport_limits_default() {
        let limits = TransportLimits::default();
        assert!(limits.max_datagram_bytes > 0);
    }

    #[test]
    fn transport_limits_custom() {
        let limits = TransportLimits {
            max_datagram_bytes: 1024,
        };
        assert_eq!(limits.max_datagram_bytes, 1024);
    }

    // ── Batch: SessionCryptoSuite ──

    #[test]
    fn session_crypto_suite_copy() {
        let suite = SessionCryptoSuite::Suite1;
        let copy = suite;
        assert_eq!(suite, copy);
    }

    #[test]
    fn session_crypto_suite_ne() {
        assert_ne!(SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2);
    }
}
