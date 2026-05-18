// Batch-4 graduation expects a connector-local no-live-provider test target.
// The IRC integration suite already uses a real loopback TCP IRC fixture with
// no mocked connector boundary, so keep this target as the explicit local
// non-mock entry point instead of duplicating that fixture.
include!("integration.rs");
