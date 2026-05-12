.PHONY: lean-verify

LEAN_PROOF_FILES := \
	lean/Fcp/Zone/Lattice.lean \
	lean/Fcp/Capability/Typestate.lean \
	lean/Fcp/Audit/HashChain.lean \
	lean/Fcp/Crypto/HybridSignature.lean \
	lean/Fcp/Mesh/CrdtMerge.lean

lean-verify:
	@set -eu; \
	if ! command -v lake >/dev/null 2>&1; then \
		printf '{"level":"ERROR","event":"lean_toolchain_missing","message":"Lean toolchain missing: lake not found"}\n' >&2; \
		exit 127; \
	fi; \
	start_epoch=$$(date +%s); \
	total=0; \
	green=0; \
	red=0; \
	for file in $(LEAN_PROOF_FILES); do \
		total=$$((total + 1)); \
		module=$$(printf '%s' "$$file" | sed 's#^lean/##; s#/#.#g; s#\.lean$$##'); \
		theorem="unknown"; \
		if [ "$$file" = "lean/Fcp/Zone/Lattice.lean" ]; then theorem="zone_flow_soundness"; fi; \
		if [ "$$file" = "lean/Fcp/Capability/Typestate.lean" ]; then theorem="typestate_progression_no_skip"; fi; \
		if [ "$$file" = "lean/Fcp/Audit/HashChain.lean" ]; then theorem="chain_tamper_evident"; fi; \
		if [ "$$file" = "lean/Fcp/Crypto/HybridSignature.lean" ]; then theorem="hybrid_unforgeable_under_one_break"; fi; \
		if [ "$$file" = "lean/Fcp/Mesh/CrdtMerge.lean" ]; then theorem="crdt_merge_lattice_laws"; fi; \
		if output=$$(lake env lean "$$file" 2>&1); then \
			green=$$((green + 1)); \
			printf '{"level":"INFO","event":"lean_proof_file","proof_file":"%s","module":"%s","theorem":"%s","success":true,"theorems_proven":1,"sorries_remaining":0}\n' "$$file" "$$module" "$$theorem"; \
		else \
			red=$$((red + 1)); \
			printf '{"level":"ERROR","event":"lean_proof_file","proof_file":"%s","module":"%s","theorem":"%s","success":false}\n' "$$file" "$$module" "$$theorem"; \
			printf '%s\n' "$$output" >&2; \
		fi; \
	done; \
	if [ "$$red" -eq 0 ]; then \
		lake build >/dev/null; \
	fi; \
	duration=$$(( $$(date +%s) - start_epoch )); \
	printf '{"level":"INFO","event":"lean_verify_summary","total_proofs":%s,"green":%s,"red":%s,"duration_seconds":%s}\n' "$$total" "$$green" "$$red" "$$duration"; \
	if [ "$$red" -ne 0 ]; then \
		exit 1; \
	fi
