namespace Fcp.Audit.HashChain

/--
Minimal hash-link carrier used by the repository audit-chain proof.

`canonicalId` models the domain-separated BLAKE3 digest that
`AuditEntry::computed_id` recomputes from the canonical payload. The Lean model
does not claim cryptographic collision resistance; the collision-resistance
theorem takes that property as an explicit assumption.
-/
structure AuditEntry where
  id : Nat
  prev : Option Nat
  seq : Nat
  deriving DecidableEq, Repr

def canonicalId (entry : AuditEntry) : Nat :=
  entry.id

def Genesis (entry : AuditEntry) : Prop :=
  entry.seq = 0 ∧ entry.prev = none

def Extends (parent child : AuditEntry) : Prop :=
  child.prev = some (canonicalId parent) ∧ child.seq = parent.seq + 1

def Tampered (parent child : AuditEntry) : Prop :=
  child.prev ≠ some (canonicalId parent)

theorem chain_tamper_evident
    (parent child : AuditEntry)
    (h : Tampered parent child) :
    Not (Extends parent child) := by
  intro proof
  exact h proof.left

theorem chain_matching_hash_extends
    (parent child : AuditEntry)
    (hPrev : child.prev = some (canonicalId parent))
    (hSeq : child.seq = parent.seq + 1) :
    Extends parent child := by
  exact And.intro hPrev hSeq

theorem extension_preserves_prior_hash_link
    (parent child : AuditEntry)
    (h : Extends parent child) :
    child.prev = some (canonicalId parent) := by
  exact h.left

theorem extension_sequence_strictly_increases
    (parent child : AuditEntry)
    (h : Extends parent child) :
    parent.seq < child.seq := by
  rw [h.right]
  exact Nat.lt_succ_self parent.seq

theorem no_retroactive_insertion
    (parent child : AuditEntry)
    (h : Extends parent child) :
    ¬ child.seq ≤ parent.seq := by
  intro retro
  exact Nat.not_lt_of_ge retro (extension_sequence_strictly_increases parent child h)

theorem hash_chain_collision_resistance_assumption_unique
    (collisionResistant :
      ∀ {left right : AuditEntry}, canonicalId left = canonicalId right -> left = right)
    {parent left right : AuditEntry}
    (_leftExtends : Extends parent left)
    (_rightExtends : Extends parent right)
    (sameHash : canonicalId left = canonicalId right) :
    left = right := by
  exact collisionResistant sameHash

end Fcp.Audit.HashChain
