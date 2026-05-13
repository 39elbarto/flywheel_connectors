namespace Fcp.Mesh.CrdtMerge

structure ConnectorStateRoot where
  version : Nat
  deriving DecidableEq, Repr

def merge (left right : ConnectorStateRoot) : ConnectorStateRoot :=
  { version := Nat.max left.version right.version }

theorem merge_idempotent
    (root : ConnectorStateRoot) :
    merge root root = root := by
  cases root
  simp [merge]

theorem merge_commutative
    (left right : ConnectorStateRoot) :
    merge left right = merge right left := by
  cases left
  cases right
  simp [merge, Nat.max_comm]

theorem merge_associative
    (left middle right : ConnectorStateRoot) :
    merge (merge left middle) right = merge left (merge middle right) := by
  cases left
  cases middle
  cases right
  simp [merge, Nat.max_assoc]

theorem crdt_merge_lattice_laws :
    (forall root, merge root root = root) /\
      (forall left right, merge left right = merge right left) /\
      (forall left middle right,
        merge (merge left middle) right = merge left (merge middle right)) := by
  exact And.intro merge_idempotent
    (And.intro merge_commutative merge_associative)

end Fcp.Mesh.CrdtMerge
