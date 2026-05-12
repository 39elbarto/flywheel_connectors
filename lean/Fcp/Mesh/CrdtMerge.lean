namespace Fcp.Mesh.CrdtMerge

/--
TODO: lift this idempotent root model to the mesh connector-state CRDT with
hybrid-logical-clock tie breaks and revocation-vector tombstones.
-/
structure CrdtRoot where
  version : Nat
  deriving DecidableEq, Repr

def merge (left right : CrdtRoot) : CrdtRoot :=
  { version := Nat.max left.version right.version }

theorem crdt_merge_lattice_laws
    (root : CrdtRoot) :
    merge root root = root := by
  cases root
  simp [merge]

theorem crdt_merge_left_observed
    (left right : CrdtRoot) :
    left.version <= (merge left right).version :=
  Nat.le_max_left left.version right.version

end Fcp.Mesh.CrdtMerge
