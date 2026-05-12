namespace Fcp.Audit.HashChain

/--
TODO: replace the `Nat` hash model with the repository audit-chain witness
format and connect each link to the signed receipt digest.
-/
structure ChainLink where
  previousHash : Nat
  currentHash : Nat
  deriving DecidableEq, Repr

def Extends (parent child : ChainLink) : Prop :=
  child.previousHash = parent.currentHash

def Tampered (parent child : ChainLink) : Prop :=
  Not (child.previousHash = parent.currentHash)

theorem chain_tamper_evident
    (parent child : ChainLink)
    (h : Tampered parent child) :
    Not (Extends parent child) := by
  intro proof
  exact h proof

theorem chain_matching_hash_extends
    (parent child : ChainLink)
    (h : child.previousHash = parent.currentHash) :
    Extends parent child :=
  h

end Fcp.Audit.HashChain
