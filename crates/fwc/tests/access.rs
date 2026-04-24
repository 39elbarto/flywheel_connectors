use chrono::{Duration as ChronoDuration, Utc};
use fwc::access_cmd::{
    AccessAttachArgs, AccessBundle, AccessBundleStore, AccessGrant, BundleStatus, GrantScope,
    attach_bundle_with_store,
};
use tempfile::TempDir;

#[test]
fn forged_handle_errors() {
    let tempdir = TempDir::new().unwrap();
    let store = AccessBundleStore::new(tempdir.path().join("access").join("bundles"));
    let args = AccessAttachArgs::new("bnd-forged");

    let err = attach_bundle_with_store(&args, &store).unwrap_err();

    assert_eq!(err, "unknown bundle handle: bnd-forged");
}

#[test]
fn stored_bundle_is_loaded_verbatim() {
    let tempdir = TempDir::new().unwrap();
    let store = AccessBundleStore::new(tempdir.path().join("access").join("bundles"));
    let expires_at = Utc::now() + ChronoDuration::minutes(30);
    let persisted = AccessBundle::new("bnd-real")
        .with_grant(AccessGrant::new(
            "grt-real",
            "github",
            "repo.read",
            GrantScope::Operation,
            expires_at,
        ))
        .with_status(BundleStatus::Partial)
        .with_receipt("stored-receipt")
        .with_justification("saved bundle");
    store.save(&persisted).unwrap();

    let loaded = attach_bundle_with_store(&AccessAttachArgs::new("bnd-real"), &store).unwrap();

    assert_eq!(loaded.handle, "bnd-real");
    assert_eq!(loaded.status, BundleStatus::Partial);
    assert_eq!(loaded.receipt.as_deref(), Some("stored-receipt"));
    assert_eq!(loaded.justification.as_deref(), Some("saved bundle"));
    assert_eq!(loaded.grants.len(), 1);
    assert_eq!(loaded.grants[0].handle, "grt-real");
    assert_eq!(loaded.grants[0].connector, "github");
    assert_eq!(loaded.grants[0].operation, "repo.read");
    assert_eq!(loaded.grants[0].scope, GrantScope::Operation);
}
