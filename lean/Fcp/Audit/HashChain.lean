namespace Fcp.Audit.HashChain

structure ChainHead where
  expectedHash : Nat
  observedHash : Nat
  deriving DecidableEq, Repr

def verify_chain (head : ChainHead) : Except String Unit :=
  if head.expectedHash = head.observedHash then
    Except.ok ()
  else
    Except.error "hash-chain-tamper-evident"

theorem chain_tamper_evident
    (head : ChainHead)
    (hTampered : head.expectedHash ≠ head.observedHash) :
    Exists (fun msg => verify_chain head = Except.error msg) := by
  exists "hash-chain-tamper-evident"
  simp [verify_chain, hTampered]

theorem matching_head_verifies
    (hash : Nat) :
    verify_chain { expectedHash := hash, observedHash := hash } = Except.ok () := by
  simp [verify_chain]

end Fcp.Audit.HashChain
