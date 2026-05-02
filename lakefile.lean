import Lake
open Lake DSL

package flywheel_connectors_formal where
  leanOptions := #[
    { name := `autoImplicit, value := false }
  ]

@[default_target]
lean_lib Fcp where
  srcDir := "lean"
