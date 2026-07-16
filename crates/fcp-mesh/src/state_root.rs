//! Vector-commitment layer for connector state roots (br-angoc.17.1).
//!
//! A zone commits to the vector of its connector state slots and later
//! proves that slot `i` holds a specific value without shipping the whole
//! vector. Two schemes are available through
//! [`fcp_crypto::vector_commit`]: KZG (constant-size proof, trusted setup)
//! and IPA (log-size proof, transparent). A zone selects one via
//! [`StateRootScheme`]; a proof produced under one scheme does not verify
//! under the other (a cross-tier verifier returns
//! [`VcError::SchemeMismatch`] and the holder re-proves).
//!
//! # Failure-injection fallback
//!
//! If a state-root commitment fails to decode (a corrupted byte on the
//! wire), verification returns [`VcError::BadCommit`]. Callers fall back to
//! the per-slot [`MerkleTree`] proofs carried alongside the commitment and
//! emit an audit alert — the vector commitment is an availability/size
//! optimization layered over an always-present Merkle root, never the sole
//! integrity anchor.
//!
//! # Observability
//!
//! - `INFO` per commit: `{scheme, n_slots, commit_hash}`.
//! - Per-verify debug on `fcp.mesh.state_root`:
//!   `{scheme, n_slots, proof_size_bytes, verify_us}`.

use std::sync::Arc;
use std::time::Instant;

use fcp_crypto::vector_commit::{
    IpaVectorCommitment, KzgVectorCommitment, SlotValue, VcError, VcScheme, VectorCommitmentScheme,
    kzg::KzgSrs,
};
use serde::{Deserialize, Serialize};

/// Which vector-commitment scheme a zone uses for its state root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StateRootScheme {
    /// KZG10 over BLS12-381 (constant-size proof; requires trusted setup).
    Kzg,
    /// Bulletproofs IPA over ristretto255 (log-size proof; transparent).
    Ipa,
}

impl StateRootScheme {
    /// The underlying crypto scheme tag.
    #[must_use]
    pub const fn vc_scheme(self) -> VcScheme {
        match self {
            Self::Kzg => VcScheme::Kzg,
            Self::Ipa => VcScheme::Ipa,
        }
    }
}

/// Enum-dispatched scheme instance (the [`VectorCommitmentScheme`] trait has
/// scheme-specific associated types, so it cannot be trait-objected).
#[derive(Debug, Clone)]
enum SchemeImpl {
    Kzg(KzgVectorCommitment),
    Ipa(IpaVectorCommitment),
}

/// A committer bound to one scheme and a fixed power-of-two domain.
#[derive(Debug, Clone)]
pub struct StateRootCommitter {
    inner: SchemeImpl,
    domain: usize,
}

/// A serializable state-root commitment plus its Merkle-fallback root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRootCommitment {
    /// Scheme that produced `commitment`.
    pub scheme: StateRootScheme,
    /// Number of slots committed.
    pub n_slots: u64,
    /// Serialized vector commitment (scheme-specific).
    #[serde(with = "serde_bytes")]
    pub commitment: Vec<u8>,
    /// BLAKE3 hash of `commitment` (stable id for logging / dedup).
    pub commit_hash: [u8; 32],
    /// Always-present per-slot Merkle root: the integrity anchor the
    /// vector commitment is layered over and the fallback verification path.
    pub merkle_root: [u8; 32],
}

/// A serializable inclusion proof for one slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRootInclusionProof {
    /// Scheme the proof was produced under.
    pub scheme: StateRootScheme,
    /// The proven slot index.
    pub index: u64,
    /// Serialized scheme-specific proof.
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}

impl StateRootCommitter {
    /// Build a KZG committer over `domain` slots using `srs`.
    ///
    /// # Errors
    ///
    /// Propagates [`VcError`] from [`KzgVectorCommitment::new`].
    pub fn kzg(srs: Arc<KzgSrs>, domain: usize) -> Result<Self, VcError> {
        Ok(Self {
            inner: SchemeImpl::Kzg(KzgVectorCommitment::new(srs, domain)?),
            domain,
        })
    }

    /// Build a transparent IPA committer over `domain` slots (no setup).
    ///
    /// # Errors
    ///
    /// Propagates [`VcError`] from [`IpaVectorCommitment::new`].
    pub fn ipa(domain: usize) -> Result<Self, VcError> {
        Ok(Self {
            inner: SchemeImpl::Ipa(IpaVectorCommitment::new(domain)?),
            domain,
        })
    }

    /// The scheme in use.
    #[must_use]
    pub const fn scheme(&self) -> StateRootScheme {
        match self.inner {
            SchemeImpl::Kzg(_) => StateRootScheme::Kzg,
            SchemeImpl::Ipa(_) => StateRootScheme::Ipa,
        }
    }

    /// The committed domain size.
    #[must_use]
    pub const fn domain_size(&self) -> usize {
        self.domain
    }

    /// Commit to a vector of slot values, producing the scheme commitment,
    /// the fallback Merkle root, and a stable commit hash.
    ///
    /// # Errors
    ///
    /// [`VcError::LengthMismatch`] if `slots.len()` != the domain size.
    pub fn commit(&self, slots: &[SlotValue]) -> Result<StateRootCommitment, VcError> {
        let commitment = match &self.inner {
            SchemeImpl::Kzg(vc) => vc.commit(slots)?.to_bytes().to_vec(),
            SchemeImpl::Ipa(vc) => vc.commit(slots)?.to_bytes().to_vec(),
        };
        let commit_hash = *blake3::hash(&commitment).as_bytes();
        let merkle_root = MerkleTree::new(slots).root();

        tracing::info!(
            target: "fcp.mesh.state_root",
            scheme = self.scheme().vc_scheme().as_str(),
            n_slots = slots.len(),
            commit_hash = %hex::encode(commit_hash),
            "committed connector state root",
        );

        Ok(StateRootCommitment {
            scheme: self.scheme(),
            n_slots: slots.len() as u64,
            commitment,
            commit_hash,
            merkle_root,
        })
    }

    /// Produce an inclusion proof that slot `index` holds `slots[index]`.
    ///
    /// # Errors
    ///
    /// [`VcError::LengthMismatch`] or [`VcError::IndexOutOfRange`].
    pub fn open(
        &self,
        slots: &[SlotValue],
        index: usize,
    ) -> Result<StateRootInclusionProof, VcError> {
        let proof = match &self.inner {
            SchemeImpl::Kzg(vc) => vc.open(slots, index)?.to_bytes().to_vec(),
            SchemeImpl::Ipa(vc) => {
                let p = vc.open(slots, index)?;
                let mut buf = Vec::new();
                ciborium::into_writer(&p, &mut buf).map_err(|_| VcError::BadProof {
                    scheme: VcScheme::Ipa,
                })?;
                buf
            }
        };
        Ok(StateRootInclusionProof {
            scheme: self.scheme(),
            index: index as u64,
            proof,
        })
    }

    /// Verify an inclusion proof for slot `index` = `value` against a
    /// commitment.
    ///
    /// # Errors
    ///
    /// - [`VcError::SchemeMismatch`] if the commitment/proof scheme differs
    ///   from this verifier's scheme (the cross-tier rejection).
    /// - [`VcError::BadCommit`] / [`VcError::BadProof`] on a corrupted
    ///   commitment or proof (the fallback trigger).
    /// - [`VcError::VerificationFailed`] on an invalid proof.
    pub fn verify(
        &self,
        commitment: &StateRootCommitment,
        index: usize,
        value: &SlotValue,
        proof: &StateRootInclusionProof,
    ) -> Result<(), VcError> {
        let my_scheme = self.scheme().vc_scheme();
        if commitment.scheme != self.scheme() {
            return Err(VcError::SchemeMismatch {
                proof_scheme: commitment.scheme.vc_scheme(),
                verifier_scheme: my_scheme,
            });
        }
        if proof.scheme != self.scheme() {
            return Err(VcError::SchemeMismatch {
                proof_scheme: proof.scheme.vc_scheme(),
                verifier_scheme: my_scheme,
            });
        }

        let started = Instant::now();
        let proof_size = proof.proof.len();
        let result = match &self.inner {
            SchemeImpl::Kzg(vc) => {
                use fcp_crypto::vector_commit::kzg::{KzgCommitment, KzgProof};
                let c = KzgCommitment::from_bytes(&commitment.commitment)?;
                let p = KzgProof::from_bytes(&proof.proof)?;
                vc.verify(&c, index, value, &p)
            }
            SchemeImpl::Ipa(vc) => {
                use fcp_crypto::vector_commit::ipa::{IpaCommitment, IpaProof};
                let c = IpaCommitment::from_bytes(&commitment.commitment)?;
                let p: IpaProof =
                    ciborium::from_reader(&proof.proof[..]).map_err(|_| VcError::BadProof {
                        scheme: VcScheme::Ipa,
                    })?;
                vc.verify(&c, index, value, &p)
            }
        };

        let verify_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        tracing::debug!(
            target: "fcp.mesh.state_root",
            scheme = my_scheme.as_str(),
            n_slots = commitment.n_slots,
            proof_size_bytes = proof_size,
            verify_us,
            accepted = result.is_ok(),
            "verified state-root inclusion proof",
        );
        result
    }
}

/// A binary BLAKE3 Merkle tree over slot values — the always-present
/// fallback when a vector commitment fails to decode.
///
/// Leaves are `H(0x00 ‖ slot)`; internal nodes are `H(0x01 ‖ left ‖ right)`.
/// An odd level duplicates its last node (standard "promote" rule).
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// `levels[0]` = leaves, `levels[last]` = `[root]`.
    levels: Vec<Vec<[u8; 32]>>,
}

fn hash_leaf(slot: &SlotValue) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[0x00]);
    h.update(slot);
    *h.finalize().as_bytes()
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[0x01]);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

impl MerkleTree {
    /// Build a Merkle tree over `slots`. An empty input yields the
    /// all-zero root.
    #[must_use]
    pub fn new(slots: &[SlotValue]) -> Self {
        if slots.is_empty() {
            return Self {
                levels: vec![vec![[0u8; 32]]],
            };
        }
        let mut current: Vec<[u8; 32]> = slots.iter().map(hash_leaf).collect();
        let mut levels = vec![current.clone()];
        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i < current.len() {
                let left = current[i];
                let right = if i + 1 < current.len() {
                    current[i + 1]
                } else {
                    current[i]
                };
                next.push(hash_node(&left, &right));
                i += 2;
            }
            levels.push(next.clone());
            current = next;
        }
        Self { levels }
    }

    /// The Merkle root. Returns the all-zero hash for a tree with no levels
    /// (unreachable via [`new`](Self::new), which always builds ≥ 1 level).
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|level| level.last())
            .copied()
            .unwrap_or([0u8; 32])
    }

    /// Produce an inclusion proof (sibling path) for `index`.
    #[must_use]
    pub fn prove(&self, index: usize) -> MerkleProof {
        let mut siblings = Vec::with_capacity(self.levels.len());
        let mut idx = index;
        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            let sib = if idx % 2 == 0 {
                if idx + 1 < level.len() {
                    level[idx + 1]
                } else {
                    level[idx] // promoted duplicate
                }
            } else {
                level[idx - 1]
            };
            siblings.push((idx % 2 == 1, sib));
            idx /= 2;
        }
        MerkleProof {
            index: index as u64,
            siblings,
        }
    }

    /// Verify a Merkle inclusion proof for `value` at the proof's index
    /// against `root`.
    #[must_use]
    pub fn verify(root: &[u8; 32], value: &SlotValue, proof: &MerkleProof) -> bool {
        let mut acc = hash_leaf(value);
        for (sibling_is_left, sib) in &proof.siblings {
            acc = if *sibling_is_left {
                hash_node(sib, &acc)
            } else {
                hash_node(&acc, sib)
            };
        }
        &acc == root
    }
}

/// A Merkle inclusion proof: the sibling hashes from leaf to root, each
/// flagged with whether the sibling sits on the left.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The proven leaf index.
    pub index: u64,
    /// `(sibling_is_left, sibling_hash)` bottom-up.
    pub siblings: Vec<(bool, [u8; 32])>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slots(n: usize) -> Vec<SlotValue> {
        (0..n)
            .map(|i| *blake3::hash(&(i as u64).to_le_bytes()).as_bytes())
            .collect()
    }

    fn kzg_committer(n: usize) -> StateRootCommitter {
        let srs = Arc::new(KzgSrs::insecure_deterministic(n, b"state-root-test"));
        StateRootCommitter::kzg(srs, n).unwrap()
    }

    #[test]
    fn kzg_state_root_roundtrip() {
        let n = 256usize;
        let committer = kzg_committer(n);
        let values = slots(n);
        let commitment = committer.commit(&values).unwrap();
        assert_eq!(commitment.scheme, StateRootScheme::Kzg);

        let proof = committer.open(&values, 42).unwrap();
        committer
            .verify(&commitment, 42, &values[42], &proof)
            .unwrap();
    }

    #[test]
    fn ipa_state_root_roundtrip() {
        let n = 256usize;
        let committer = StateRootCommitter::ipa(n).unwrap();
        let values = slots(n);
        let commitment = committer.commit(&values).unwrap();
        let proof = committer.open(&values, 99).unwrap();
        committer
            .verify(&commitment, 99, &values[99], &proof)
            .unwrap();
    }

    #[test]
    fn cross_scheme_verify_is_rejected() {
        let n = 64usize;
        let kzg = kzg_committer(n);
        let ipa = StateRootCommitter::ipa(n).unwrap();
        let values = slots(n);

        let kzg_commit = kzg.commit(&values).unwrap();
        let kzg_proof = kzg.open(&values, 7).unwrap();

        // An IPA-only verifier rejects a KZG commitment/proof outright.
        let err = ipa
            .verify(&kzg_commit, 7, &values[7], &kzg_proof)
            .unwrap_err();
        assert_eq!(
            err,
            VcError::SchemeMismatch {
                proof_scheme: VcScheme::Kzg,
                verifier_scheme: VcScheme::Ipa,
            }
        );

        // Re-proving under IPA (shared slot bytes) verifies.
        let ipa_commit = ipa.commit(&values).unwrap();
        let ipa_proof = ipa.open(&values, 7).unwrap();
        ipa.verify(&ipa_commit, 7, &values[7], &ipa_proof).unwrap();
    }

    #[test]
    fn corrupted_commitment_triggers_bad_commit_and_merkle_fallback() {
        let n = 128usize;
        let committer = kzg_committer(n);
        let values = slots(n);
        let mut commitment = committer.commit(&values).unwrap();
        let proof = committer.open(&values, 13).unwrap();

        // Corrupt a commitment byte: verification returns BadCommit.
        commitment.commitment[0] ^= 0xFF;
        let err = committer
            .verify(&commitment, 13, &values[13], &proof)
            .unwrap_err();
        assert_eq!(
            err,
            VcError::BadCommit {
                scheme: VcScheme::Kzg
            }
        );

        // Fallback: the per-slot Merkle proof still verifies against the
        // always-present merkle_root.
        let tree = MerkleTree::new(&values);
        assert_eq!(tree.root(), commitment.merkle_root);
        let mproof = tree.prove(13);
        assert!(MerkleTree::verify(
            &commitment.merkle_root,
            &values[13],
            &mproof
        ));
        // ...and a wrong value fails the fallback path too.
        let mut bad = values[13];
        bad[0] ^= 0x01;
        assert!(!MerkleTree::verify(&commitment.merkle_root, &bad, &mproof));
    }

    #[test]
    fn merkle_tree_all_indices_verify() {
        let n = 100usize; // deliberately not a power of two
        let values = slots(n);
        let tree = MerkleTree::new(&values);
        let root = tree.root();
        for (i, value) in values.iter().enumerate() {
            let p = tree.prove(i);
            assert!(MerkleTree::verify(&root, value, &p), "index {i}");
        }
    }

    #[test]
    fn state_root_commitment_serde_roundtrip() {
        let n = 64usize;
        let committer = StateRootCommitter::ipa(n).unwrap();
        let values = slots(n);
        let commitment = committer.commit(&values).unwrap();
        let proof = committer.open(&values, 5).unwrap();

        let mut cbuf = Vec::new();
        ciborium::into_writer(&commitment, &mut cbuf).unwrap();
        let c2: StateRootCommitment = ciborium::from_reader(&cbuf[..]).unwrap();
        let mut pbuf = Vec::new();
        ciborium::into_writer(&proof, &mut pbuf).unwrap();
        let p2: StateRootInclusionProof = ciborium::from_reader(&pbuf[..]).unwrap();

        committer.verify(&c2, 5, &values[5], &p2).unwrap();
    }
}
