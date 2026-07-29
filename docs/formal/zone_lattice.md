# Zone Lattice Proof

`lean/Fcp/Zone/Lattice.lean` models the current zone-flow obligation for the
formal verification gate. The model uses natural-number zone levels: larger
levels are more restrictive, and a flow is admitted only when the target level
is no more restrictive than the source level.

The central theorem is `zone_lattice_sound`: if `zone_check` returns `pass` for
an operation, there is no reachable leak whose target is more restrictive than
the source. Supporting lemmas cover join upper bounds, transitive capability
transport, silent-downgrade rejection, self-loop safety, and the witness shape
for a two-hop capability proof.

This is intentionally a compact proof model rather than an extraction of the
Rust host. The conformance alignment test pins the theorem names and the
runtime boundary (`verify_live_request` plus `allowed_zones`) so README proof
claims cannot drift silently from either side.
