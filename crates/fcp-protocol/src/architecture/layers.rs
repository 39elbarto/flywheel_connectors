//! Seven-layer FCP architecture map.
//!
//! The constants in this module are intentionally data-only. Conformance tests
//! consume them with `cargo metadata` so new core crates cannot drift outside
//! the documented layering contract.

/// A numbered architecture layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer {
    /// Layer 1: crypto, hardware, encoding, and runtime substrate.
    CryptoHardware = 1,
    /// Layer 2: state identity, commit evidence, and mesh freshness.
    StateCommit = 2,
    /// Layer 3: anti-entropy, manifests, policy, and persisted state.
    AntiEntropy = 3,
    /// Layer 4: protocol, consensus, sandboxing, and mesh coordination.
    Consensus = 4,
    /// Layer 5: verifiable computation and connector runtime surfaces.
    VerifiableComputation = 5,
    /// Layer 6: audit, anomaly, and query surfaces.
    AuditAnomaly = 6,
    /// Layer 7: operator, test, host, and connector surfaces.
    OperatorSurface = 7,
}

impl Layer {
    /// Return the numeric layer identifier.
    #[must_use]
    pub const fn number(self) -> u8 {
        self as u8
    }

    /// Return the stable operator-facing layer name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CryptoHardware => "crypto_hardware",
            Self::StateCommit => "state_commit",
            Self::AntiEntropy => "anti_entropy",
            Self::Consensus => "consensus",
            Self::VerifiableComputation => "verifiable_computation",
            Self::AuditAnomaly => "audit_anomaly",
            Self::OperatorSurface => "operator_surface",
        }
    }
}

/// Reference to a crate or crate class that belongs to a layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CrateRef {
    /// A concrete workspace crate package name.
    Named(&'static str),
    /// A package that lives under this workspace-relative path prefix.
    WorkspacePathPrefix(&'static str),
    /// A planned crate named by architecture acceptance but not present yet.
    Planned(&'static str),
}

impl CrateRef {
    /// Return the named crate when this is a named or planned reference.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        match self {
            Self::Named(name) | Self::Planned(name) => Some(name),
            Self::WorkspacePathPrefix(_) => None,
        }
    }

    /// Return true when this reference matches a workspace package.
    #[must_use]
    pub fn matches(self, package_name: &str, workspace_relative_manifest_path: &str) -> bool {
        match self {
            Self::Named(name) => package_name == name,
            Self::WorkspacePathPrefix(prefix) => {
                workspace_relative_manifest_path.starts_with(prefix)
            }
            Self::Planned(_) => false,
        }
    }
}

/// Non-crate components that are assigned to architecture layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerComponent {
    /// Component name.
    pub name: &'static str,
    /// Layer assignment.
    pub layer: Layer,
    /// Owning crate or artifact.
    pub owner: &'static str,
}

/// Integration-glue narrative item with documented consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegrationGlueNarrative {
    /// Narrative item.
    pub item: &'static str,
    /// Producer or substrate.
    pub producer: &'static str,
    /// Documented consuming crates, tests, or operator surfaces.
    pub consumers: &'static [&'static str],
}

/// Workspace crate layer assignments.
pub const LAYERS: &[(Layer, &[CrateRef])] = &[
    (
        Layer::CryptoHardware,
        &[
            CrateRef::Named("fcp-async-core"),
            CrateRef::Named("fcp-async-core-macros"),
            CrateRef::Named("fcp-auth-schema"),
            CrateRef::Named("fcp-cbor"),
            CrateRef::Named("fcp-crypto"),
            CrateRef::Named("fcp-crypto-hw"),
            CrateRef::Named("fcp-crypto-pq"),
            CrateRef::Planned("fcp-hpke"),
        ],
    ),
    (
        Layer::StateCommit,
        &[
            CrateRef::Named("fcp-core"),
            CrateRef::Named("fcp-evidence"),
            CrateRef::Named("fcp-prelude"),
            CrateRef::Named("fcp-tailscale"),
            CrateRef::Named("fcp-telemetry"),
        ],
    ),
    (
        Layer::AntiEntropy,
        &[
            CrateRef::Named("fcp-kernel"),
            CrateRef::Named("fcp-manifest"),
            CrateRef::Named("fcp-policy"),
            CrateRef::Named("fcp-raptorq"),
            CrateRef::Named("fcp-ratelimit"),
            CrateRef::Named("fcp-store"),
        ],
    ),
    (
        Layer::Consensus,
        &[
            CrateRef::Named("fcp-mesh"),
            CrateRef::Named("fcp-protocol"),
            CrateRef::Named("fcp-provider-auth"),
            CrateRef::Named("fcp-sandbox"),
            CrateRef::Named("fcp-voice-call"),
        ],
    ),
    (
        Layer::VerifiableComputation,
        &[
            CrateRef::Named("fcp-bootstrap"),
            CrateRef::Named("fcp-google-discovery"),
            CrateRef::Named("fcp-oauth"),
            CrateRef::Named("fcp-openai-compat"),
            CrateRef::Named("fcp-registry"),
            CrateRef::Named("fcp-sdk"),
            CrateRef::Named("fcp-streaming"),
            CrateRef::Named("fcp-webhook"),
        ],
    ),
    (
        Layer::AuditAnomaly,
        &[CrateRef::Named("fcp-audit"), CrateRef::Named("fcp-graphql")],
    ),
    (
        Layer::OperatorSurface,
        &[
            CrateRef::Named("br-tools"),
            CrateRef::Named("fcp-bench"),
            CrateRef::Named("fcp-chaos"),
            CrateRef::Named("fcp-conformance"),
            CrateRef::Named("fcp-e2e"),
            CrateRef::Named("fcp-host"),
            CrateRef::Named("fcp-testkit"),
            CrateRef::Named("fwc"),
            CrateRef::WorkspacePathPrefix("connectors/"),
        ],
    ),
];

/// Non-crate layer components named by the Phase U integration contract.
pub const LAYER_COMPONENTS: &[LayerComponent] = &[
    LayerComponent {
        name: "LiveTruthResolver",
        layer: Layer::OperatorSurface,
        owner: "fwc::truth",
    },
    LayerComponent {
        name: "ConformalScore",
        layer: Layer::OperatorSurface,
        owner: "fcp-audit::conformal",
    },
];

/// Documented integration-glue consumers for the five cross-layer narratives.
pub const INTEGRATION_GLUE_NARRATIVES: &[IntegrationGlueNarrative] = &[
    IntegrationGlueNarrative {
        item: "HLC",
        producer: "state_commit",
        consumers: &[
            "fcp-store",
            "fcp-mesh",
            "fcp-audit",
            "fcp-conformance::state_commit_linearizability_property",
        ],
    },
    IntegrationGlueNarrative {
        item: "KZG/IPA vector commits",
        producer: "state_commit",
        consumers: &[
            "fcp-store",
            "fcp-core::ConnectorStateRoot",
            "fcp-conformance::vector_commit_scheme_policy_match",
        ],
    },
    IntegrationGlueNarrative {
        item: "BLS+FROST+VSS",
        producer: "consensus",
        consumers: &[
            "fcp-mesh",
            "fcp-crypto",
            "fcp-crypto-pq",
            "fcp-conformance::capability_consume_always_fenced",
        ],
    },
    IntegrationGlueNarrative {
        item: "audit chain",
        producer: "audit_anomaly",
        consumers: &[
            "fcp-audit",
            "fcp-host::invoke_audit",
            "fwc::audit",
            "fcp-conformance::master_reachability_artifact_completeness",
        ],
    },
    IntegrationGlueNarrative {
        item: "Datalog policy",
        producer: "anti_entropy",
        consumers: &[
            "fcp-policy",
            "fcp-host::zone_policies",
            "fcp-sdk::contract",
            "fwc::capability_replay",
        ],
    },
];

/// Find every layer reference matching a workspace package.
#[must_use]
pub fn matching_layers(package_name: &str, workspace_relative_manifest_path: &str) -> Vec<Layer> {
    LAYERS
        .iter()
        .filter_map(|(layer, crate_refs)| {
            crate_refs
                .iter()
                .any(|crate_ref| crate_ref.matches(package_name, workspace_relative_manifest_path))
                .then_some(*layer)
        })
        .collect()
}

/// Resolve a workspace package to its single layer.
#[must_use]
pub fn layer_for_crate(
    package_name: &str,
    workspace_relative_manifest_path: &str,
) -> Option<Layer> {
    let mut matches = matching_layers(package_name, workspace_relative_manifest_path);
    (matches.len() == 1).then(|| matches.remove(0))
}
