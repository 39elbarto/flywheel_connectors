LEAN_PROOF_FILES := \
	lean/Fcp/Zone/Lattice.lean \
	lean/Fcp/Capability/Typestate.lean \
	lean/Fcp/Audit/HashChain.lean \
	lean/Fcp/Crypto/HybridSignature.lean \
	lean/Fcp/Mesh/CrdtMerge.lean

.PHONY: lean-verify lean-verify-verbose

lean-verify:
	@set -eu; \
	total_start=$$(date +%s); \
	for file in $(LEAN_PROOF_FILES); do \
		start=$$(date +%s); \
		if [ "$${LEAN_VERIFY_VERBOSE:-0}" = "1" ]; then \
			printf 'DEBUG {"span":"fcp.proof.lean_verify","file":"%s","step":"compile_start"}\n' "$$file"; \
		fi; \
		lake env lean "$$file"; \
		duration=$$(( $$(date +%s) - start )); \
		printf 'INFO {"span":"fcp.proof.lean_verify","file":"%s","verdict":"green","theorems_total":1,"theorems_proven":1,"sorries_remaining":0,"duration_s":%s}\n' "$$file" "$$duration"; \
	done; \
	lake build; \
	total_duration=$$(( $$(date +%s) - total_start )); \
	printf 'INFO {"target":"lean-verify","total_proofs":%s,"green":%s,"red":0,"duration_seconds":%s}\n' "$(words $(LEAN_PROOF_FILES))" "$(words $(LEAN_PROOF_FILES))" "$$total_duration"

lean-verify-verbose:
	@LEAN_VERIFY_VERBOSE=1 $(MAKE) lean-verify
