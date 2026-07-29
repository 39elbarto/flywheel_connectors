//! Build-time architecture metadata shared by conformance checks.

pub mod layers;

pub use layers::{
    CrateRef, INTEGRATION_GLUE_NARRATIVES, IntegrationGlueNarrative, LAYER_COMPONENTS, LAYERS,
    Layer, LayerComponent,
};
