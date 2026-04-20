# GEMINI_LANE4_BOOTSTRAP.md — Lane 4 Review: Bootstrap & Key Derivation Ceremonies

## Initial Plan

1. **Read `AGENTS.md` and `README.md`** (Completed)
2. **Study the codebase architecture** (In Progress)
    - [ ] Trace `fcp-bootstrap` workflow from entry point (`lib.rs` -> `workflow.rs`).
    - [ ] Analyze genesis ceremony (`genesis.rs`) and owner key derivation.
    - [ ] Review hardware/soft token lifecycle (`hardware_token.rs`, `soft_token.rs`).
    - [ ] Inspect threshold signing (FROST) support (`ceremony.rs`).
    - [ ] Verify Shamir secret sharing implementation (`fcp-core/src/secret.rs`).
3. **Execute focused lane review**
    - [ ] Entropy source verification (OsRng usage).
    - [ ] BIP39/Recovery phrase validation and zeroization.
    - [ ] Key derivation separation.
    - [ ] Multi-phase state machine crash-recovery analysis.
    - [ ] Atomic file write patterns (fsync).
    - [ ] Hardware token secure-erasure semantics.
    - [ ] FROST aggregate signature validation.
    - [ ] Shamir GF(2^8) correctness and oracle-attack resistance.
    - [ ] NTP drift handling.
    - [ ] ZoneKeyManifest HPKE sealing and public key freshness.
4. **Fix bugs and document findings.**

## Findings

(Pending review)
