namespace Fcp.Invariants.Audit

def linkHash (parentHash payloadHash : Nat) : Nat :=
  parentHash * 16777619 + payloadHash

structure AuditEntry where
  parentHash : Nat
  payloadHash : Nat
  headHash : Nat
  deriving DecidableEq, Repr

def ValidExtension (parentHash : Nat) (entry : AuditEntry) : Prop :=
  entry.parentHash = parentHash /\ entry.headHash = linkHash parentHash entry.payloadHash

def NoLinkCollisionAt (parentHash : Nat) : Prop :=
  forall {leftPayload rightPayload : Nat},
    linkHash parentHash leftPayload = linkHash parentHash rightPayload ->
      leftPayload = rightPayload

theorem same_parent_payload_extension_unique
    {parentHash : Nat}
    {left right : AuditEntry}
    (leftValid : ValidExtension parentHash left)
    (rightValid : ValidExtension parentHash right)
    (samePayload : left.payloadHash = right.payloadHash) :
    left.headHash = right.headHash := by
  calc
    left.headHash = linkHash parentHash left.payloadHash := leftValid.right
    _ = linkHash parentHash right.payloadHash := by rw [samePayload]
    _ = right.headHash := Eq.symm rightValid.right

theorem audit_chain_hash_link_fork_resistance
    {parentHash : Nat}
    {left right : AuditEntry}
    (leftValid : ValidExtension parentHash left)
    (rightValid : ValidExtension parentHash right)
    (noCollision : NoLinkCollisionAt parentHash)
    (sameHead : left.headHash = right.headHash) :
    left.payloadHash = right.payloadHash := by
  apply noCollision
  calc
    linkHash parentHash left.payloadHash = left.headHash := Eq.symm leftValid.right
    _ = right.headHash := sameHead
    _ = linkHash parentHash right.payloadHash := rightValid.right

end Fcp.Invariants.Audit
