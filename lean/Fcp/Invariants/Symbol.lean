namespace Fcp.Invariants.Symbol

structure Reconstruction where
  sourceSymbols : Nat
  receivedSymbols : Nat
  deriving DecidableEq, Repr

def CanDecode (run : Reconstruction) : Prop :=
  run.sourceSymbols <= run.receivedSymbols

def ReconstructionCorrect (run : Reconstruction) : Prop :=
  run.sourceSymbols <= run.receivedSymbols

theorem insufficient_symbols_not_decodable
    {run : Reconstruction}
    (h : run.receivedSymbols < run.sourceSymbols) :
    Not (CanDecode run) := by
  intro canDecode
  exact Nat.not_lt_of_ge canDecode h

theorem extra_repair_symbols_preserve_decode
    {sourceSymbols receivedSymbols extraSymbols : Nat}
    (h : sourceSymbols <= receivedSymbols) :
    sourceSymbols <= receivedSymbols + extraSymbols :=
  Nat.le_trans h (Nat.le_add_right receivedSymbols extraSymbols)

theorem symbol_fungibility_reconstruction_guarantee
    {run : Reconstruction}
    (h : CanDecode run) :
    ReconstructionCorrect run :=
  h

end Fcp.Invariants.Symbol
