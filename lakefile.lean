import Lake
open Lake DSL

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @
    "5e932f97dd25535344f80f9dd8da3aab83df0fe6"

package flywheel_connectors_formal where
  leanOptions := #[
    { name := `autoImplicit, value := false }
  ]

@[default_target]
lean_lib Fcp where
  srcDir := "lean"
