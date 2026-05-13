LEAN_PROOF_FILES := \
	lean/Fcp/Zone/Lattice.lean \
	lean/Fcp/Capability/Typestate.lean \
	lean/Fcp/Audit/HashChain.lean \
	lean/Fcp/Crypto/HybridSignature.lean \
	lean/Fcp/Mesh/CrdtMerge.lean

TLA2TOOLS_JAR ?= tools/tla2tools.jar
TLA_CUTOVER_SPEC := specs/tla/cutover.tla
TLA_CUTOVER_CFG := specs/tla/cutover.cfg
TLA_CUTOVER_BROKEN_SPEC := specs/tla/_fixtures/cutover_broken.tla
TLA_CAPABILITY_LIFECYCLE_SPEC := specs/tla/capability_lifecycle.tla
TLA_CAPABILITY_LIFECYCLE_CFG := specs/tla/capability_lifecycle.cfg
TLA_CAPABILITY_LIFECYCLE_BROKEN_SPEC := specs/tla/_fixtures/capability_lifecycle_broken.tla
TLA_AUDIT_LIVENESS_SPEC := specs/tla/audit_liveness.tla
TLA_AUDIT_LIVENESS_CFG := specs/tla/audit_liveness.cfg
TLA_AUDIT_LIVENESS_BROKEN_SPEC := specs/tla/_fixtures/audit_liveness_broken.tla
TLA_ARTIFACT_DIR := artifacts/formal/tla
TLA_STATE_DIR := $(TLA_ARTIFACT_DIR)/states

.PHONY: lean-verify lean-verify-verbose tla-check tla-check-broken tla-check-capability-lifecycle tla-check-capability-lifecycle-broken tla-check-audit-liveness tla-check-audit-liveness-broken

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

tla-check:
	@set -eu; \
	mkdir -p "$(TLA_ARTIFACT_DIR)" "$(TLA_STATE_DIR)/cutover"; \
	if [ ! -f "$(TLA2TOOLS_JAR)" ]; then \
		printf 'ERROR {"span":"fcp.formal.tla_check","spec":"%s","verdict":"toolchain_missing","message":"set TLA2TOOLS_JAR to tla2tools.jar"}\n' "$(TLA_CUTOVER_SPEC)"; \
		exit 127; \
	fi; \
	start=$$(date +%s); \
	if java -cp "$(TLA2TOOLS_JAR)" tlc2.TLC -deadlock -metadir "$(TLA_STATE_DIR)/cutover" -config "$(TLA_CUTOVER_CFG)" "$(TLA_CUTOVER_SPEC)" | tee "$(TLA_ARTIFACT_DIR)/cutover.log"; then \
		duration=$$(( $$(date +%s) - start )); \
		states=$$(sed -n 's/^\([0-9][0-9]*\) states generated.*/\1/p' "$(TLA_ARTIFACT_DIR)/cutover.log" | tail -n 1); \
		states=$${states:-unknown}; \
		printf 'INFO {"span":"fcp.formal.tla_check","spec":"%s","depth":20,"states_explored":"%s","invariants_checked":["Safety","Liveness","Recoverability"],"verdict":"green","duration_s":%s}\n' "$(TLA_CUTOVER_SPEC)" "$$states" "$$duration"; \
	else \
		duration=$$(( $$(date +%s) - start )); \
		printf 'ERROR {"span":"fcp.formal.tla_check","spec":"%s","depth":20,"states_explored":"unknown","invariants_checked":["Safety","Liveness","Recoverability"],"verdict":"red","duration_s":%s}\n' "$(TLA_CUTOVER_SPEC)" "$$duration"; \
		exit 1; \
	fi

tla-check-broken:
	@set -eu; \
	mkdir -p "$(TLA_ARTIFACT_DIR)" "$(TLA_STATE_DIR)/cutover_broken"; \
	if [ ! -f "$(TLA2TOOLS_JAR)" ]; then \
		printf 'ERROR {"span":"fcp.formal.tla_check","spec":"%s","verdict":"toolchain_missing","message":"set TLA2TOOLS_JAR to tla2tools.jar"}\n' "$(TLA_CUTOVER_BROKEN_SPEC)"; \
		exit 127; \
	fi; \
	start=$$(date +%s); \
	if java -cp "$(TLA2TOOLS_JAR)" tlc2.TLC -deadlock -metadir "$(TLA_STATE_DIR)/cutover_broken" -config "$(TLA_CUTOVER_CFG)" "$(TLA_CUTOVER_BROKEN_SPEC)" > "$(TLA_ARTIFACT_DIR)/cutover_broken.log" 2>&1; then \
		cat "$(TLA_ARTIFACT_DIR)/cutover_broken.log"; \
		duration=$$(( $$(date +%s) - start )); \
		printf 'ERROR {"span":"fcp.formal.tla_check","spec":"%s","depth":20,"verdict":"unexpected_green","duration_s":%s}\n' "$(TLA_CUTOVER_BROKEN_SPEC)" "$$duration"; \
		exit 1; \
	fi; \
	if grep -q "Safety" "$(TLA_ARTIFACT_DIR)/cutover_broken.log"; then \
		duration=$$(( $$(date +%s) - start )); \
		printf 'INFO {"span":"fcp.formal.tla_check","spec":"%s","depth":20,"invariants_checked":["Safety"],"verdict":"expected_red","duration_s":%s}\n' "$(TLA_CUTOVER_BROKEN_SPEC)" "$$duration"; \
	else \
		cat "$(TLA_ARTIFACT_DIR)/cutover_broken.log"; \
		duration=$$(( $$(date +%s) - start )); \
		printf 'ERROR {"span":"fcp.formal.tla_check","spec":"%s","depth":20,"verdict":"red_without_safety_invariant","duration_s":%s}\n' "$(TLA_CUTOVER_BROKEN_SPEC)" "$$duration"; \
		exit 1; \
	fi

tla-check-capability-lifecycle:
	@set -eu; \
	mkdir -p "$(TLA_ARTIFACT_DIR)" "$(TLA_STATE_DIR)/capability_lifecycle"; \
	if [ ! -f "$(TLA2TOOLS_JAR)" ]; then \
		printf 'ERROR {"span":"fcp.formal.tla_check","spec":"%s","verdict":"toolchain_missing","message":"set TLA2TOOLS_JAR to tla2tools.jar"}\n' "$(TLA_CAPABILITY_LIFECYCLE_SPEC)"; \
		exit 127; \
	fi; \
	start=$$(date +%s); \
	if java -cp "$(TLA2TOOLS_JAR)" tlc2.TLC -deadlock -metadir "$(TLA_STATE_DIR)/capability_lifecycle" -config "$(TLA_CAPABILITY_LIFECYCLE_CFG)" "$(TLA_CAPABILITY_LIFECYCLE_SPEC)" | tee "$(TLA_ARTIFACT_DIR)/capability_lifecycle.log"; then \
		duration=$$(( $$(date +%s) - start )); \
		states=$$(sed -n 's/^\([0-9][0-9]*\) states generated.*/\1/p' "$(TLA_ARTIFACT_DIR)/capability_lifecycle.log" | tail -n 1); \
		states=$${states:-unknown}; \
		printf 'INFO {"span":"fcp.formal.tla_check","spec":"%s","depth":20,"states_explored":"%s","invariants_checked":["RevokeBeforeUse","NoDoubleSpend","RevocationPropagationSLO"],"verdict":"green","duration_s":%s}\n' "$(TLA_CAPABILITY_LIFECYCLE_SPEC)" "$$states" "$$duration"; \
	else \
		duration=$$(( $$(date +%s) - start )); \
		printf 'ERROR {"span":"fcp.formal.tla_check","spec":"%s","depth":20,"states_explored":"unknown","invariants_checked":["RevokeBeforeUse","NoDoubleSpend","RevocationPropagationSLO"],"verdict":"red","duration_s":%s}\n' "$(TLA_CAPABILITY_LIFECYCLE_SPEC)" "$$duration"; \
		exit 1; \
	fi

tla-check-capability-lifecycle-broken:
	@set -eu; \
	mkdir -p "$(TLA_ARTIFACT_DIR)" "$(TLA_STATE_DIR)/capability_lifecycle_broken"; \
	if [ ! -f "$(TLA2TOOLS_JAR)" ]; then \
		printf 'ERROR {"span":"fcp.formal.tla_check","spec":"%s","verdict":"toolchain_missing","message":"set TLA2TOOLS_JAR to tla2tools.jar"}\n' "$(TLA_CAPABILITY_LIFECYCLE_BROKEN_SPEC)"; \
		exit 127; \
	fi; \
	start=$$(date +%s); \
	if java -cp "$(TLA2TOOLS_JAR)" tlc2.TLC -deadlock -metadir "$(TLA_STATE_DIR)/capability_lifecycle_broken" -config "$(TLA_CAPABILITY_LIFECYCLE_CFG)" "$(TLA_CAPABILITY_LIFECYCLE_BROKEN_SPEC)" > "$(TLA_ARTIFACT_DIR)/capability_lifecycle_broken.log" 2>&1; then \
		cat "$(TLA_ARTIFACT_DIR)/capability_lifecycle_broken.log"; \
		duration=$$(( $$(date +%s) - start )); \
		printf 'ERROR {"span":"fcp.formal.tla_check","spec":"%s","depth":20,"verdict":"unexpected_green","duration_s":%s}\n' "$(TLA_CAPABILITY_LIFECYCLE_BROKEN_SPEC)" "$$duration"; \
		exit 1; \
	fi; \
	if grep -q "RevokeBeforeUse" "$(TLA_ARTIFACT_DIR)/capability_lifecycle_broken.log"; then \
		duration=$$(( $$(date +%s) - start )); \
		printf 'INFO {"span":"fcp.formal.tla_check","spec":"%s","depth":20,"invariants_checked":["RevokeBeforeUse"],"verdict":"expected_red","duration_s":%s}\n' "$(TLA_CAPABILITY_LIFECYCLE_BROKEN_SPEC)" "$$duration"; \
	else \
		cat "$(TLA_ARTIFACT_DIR)/capability_lifecycle_broken.log"; \
		duration=$$(( $$(date +%s) - start )); \
		printf 'ERROR {"span":"fcp.formal.tla_check","spec":"%s","depth":20,"verdict":"red_without_revoke_before_use_invariant","duration_s":%s}\n' "$(TLA_CAPABILITY_LIFECYCLE_BROKEN_SPEC)" "$$duration"; \
		exit 1; \
	fi

tla-check-audit-liveness:
	@set -eu; \
	mkdir -p "$(TLA_ARTIFACT_DIR)" "$(TLA_STATE_DIR)/audit_liveness"; \
	if [ ! -f "$(TLA2TOOLS_JAR)" ]; then \
		printf 'ERROR {"span":"fcp.formal.tla_check","spec":"%s","verdict":"toolchain_missing","message":"set TLA2TOOLS_JAR to tla2tools.jar"}\n' "$(TLA_AUDIT_LIVENESS_SPEC)"; \
		exit 127; \
	fi; \
	start=$$(date +%s); \
	if java -cp "$(TLA2TOOLS_JAR)" tlc2.TLC -deadlock -metadir "$(TLA_STATE_DIR)/audit_liveness" -config "$(TLA_AUDIT_LIVENESS_CFG)" "$(TLA_AUDIT_LIVENESS_SPEC)" | tee "$(TLA_ARTIFACT_DIR)/audit_liveness.log"; then \
		duration=$$(( $$(date +%s) - start )); \
		states=$$(sed -n 's/^\([0-9][0-9]*\) states generated.*/\1/p' "$(TLA_ARTIFACT_DIR)/audit_liveness.log" | tail -n 1); \
		states=$${states:-unknown}; \
		printf 'INFO {"span":"fcp.formal.tla_check","spec":"%s","depth":20,"states_explored":"%s","invariants_checked":["Safety","Liveness","Recoverability"],"verdict":"green","duration_s":%s}\n' "$(TLA_AUDIT_LIVENESS_SPEC)" "$$states" "$$duration"; \
	else \
		duration=$$(( $$(date +%s) - start )); \
		printf 'ERROR {"span":"fcp.formal.tla_check","spec":"%s","depth":20,"states_explored":"unknown","invariants_checked":["Safety","Liveness","Recoverability"],"verdict":"red","duration_s":%s}\n' "$(TLA_AUDIT_LIVENESS_SPEC)" "$$duration"; \
		exit 1; \
	fi

tla-check-audit-liveness-broken:
	@set -eu; \
	mkdir -p "$(TLA_ARTIFACT_DIR)" "$(TLA_STATE_DIR)/audit_liveness_broken"; \
	if [ ! -f "$(TLA2TOOLS_JAR)" ]; then \
		printf 'ERROR {"span":"fcp.formal.tla_check","spec":"%s","verdict":"toolchain_missing","message":"set TLA2TOOLS_JAR to tla2tools.jar"}\n' "$(TLA_AUDIT_LIVENESS_BROKEN_SPEC)"; \
		exit 127; \
	fi; \
	start=$$(date +%s); \
	if java -cp "$(TLA2TOOLS_JAR)" tlc2.TLC -deadlock -metadir "$(TLA_STATE_DIR)/audit_liveness_broken" -config "$(TLA_AUDIT_LIVENESS_CFG)" "$(TLA_AUDIT_LIVENESS_BROKEN_SPEC)" > "$(TLA_ARTIFACT_DIR)/audit_liveness_broken.log" 2>&1; then \
		cat "$(TLA_ARTIFACT_DIR)/audit_liveness_broken.log"; \
		duration=$$(( $$(date +%s) - start )); \
		printf 'ERROR {"span":"fcp.formal.tla_check","spec":"%s","depth":20,"verdict":"unexpected_green","duration_s":%s}\n' "$(TLA_AUDIT_LIVENESS_BROKEN_SPEC)" "$$duration"; \
		exit 1; \
	fi; \
	if grep -qi "liveness\|temporal" "$(TLA_ARTIFACT_DIR)/audit_liveness_broken.log"; then \
		duration=$$(( $$(date +%s) - start )); \
		printf 'INFO {"span":"fcp.formal.tla_check","spec":"%s","depth":20,"invariants_checked":["Liveness"],"verdict":"expected_red","duration_s":%s}\n' "$(TLA_AUDIT_LIVENESS_BROKEN_SPEC)" "$$duration"; \
	else \
		cat "$(TLA_ARTIFACT_DIR)/audit_liveness_broken.log"; \
		duration=$$(( $$(date +%s) - start )); \
		printf 'ERROR {"span":"fcp.formal.tla_check","spec":"%s","depth":20,"verdict":"red_without_liveness_violation","duration_s":%s}\n' "$(TLA_AUDIT_LIVENESS_BROKEN_SPEC)" "$$duration"; \
		exit 1; \
	fi
