namespace Fcp.Invariants.Zone

structure ZoneLabel where
  integrity : Nat
  confidentiality : Nat
  deriving DecidableEq, Repr

def merge (left right : ZoneLabel) : ZoneLabel :=
  {
    integrity := Nat.min left.integrity right.integrity,
    confidentiality := Nat.max left.confidentiality right.confidentiality
  }

theorem merge_integrity_le_left
    (left right : ZoneLabel) :
    (merge left right).integrity <= left.integrity :=
  Nat.min_le_left left.integrity right.integrity

theorem merge_integrity_le_right
    (left right : ZoneLabel) :
    (merge left right).integrity <= right.integrity :=
  Nat.min_le_right left.integrity right.integrity

theorem left_confidentiality_le_merge
    (left right : ZoneLabel) :
    left.confidentiality <= (merge left right).confidentiality :=
  Nat.le_max_left left.confidentiality right.confidentiality

theorem right_confidentiality_le_merge
    (left right : ZoneLabel) :
    right.confidentiality <= (merge left right).confidentiality :=
  Nat.le_max_right left.confidentiality right.confidentiality

theorem merge_preserves_integrity_and_confidentiality
    (left right : ZoneLabel) :
    (merge left right).integrity <= left.integrity /\
      (merge left right).integrity <= right.integrity /\
      left.confidentiality <= (merge left right).confidentiality /\
      right.confidentiality <= (merge left right).confidentiality := by
  exact And.intro (merge_integrity_le_left left right)
    (And.intro (merge_integrity_le_right left right)
      (And.intro (left_confidentiality_le_merge left right)
        (right_confidentiality_le_merge left right)))

end Fcp.Invariants.Zone
