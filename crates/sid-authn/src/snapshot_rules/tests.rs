use super::*;
use crate::test_support::key_manager;

// The owner domain a snapshot keys history keys by is the one the history
// evaluator uses, so exported keys are found for their owner.
#[test]
fn the_owner_domain_is_the_evaluators() {
    let (installation, owner) = (OrgId::generate(), ProfileId::generate());
    assert_eq!(
        AuthnSnapshotRules.history_owner_domain(installation, owner),
        crate::password_history::owner_domain(installation.as_bytes(), owner)
    );
}

// A sealed setup names the key version it is sealed under, read without
// opening it; a value sealed for another context or not sealed at all is
// refused.
#[tokio::test]
async fn a_sealed_setup_names_its_key_version() {
    let keys = key_manager();
    let context = crate::instance_secret::context(InstanceSecret::OpaqueServerSetup);
    let sealed = crate::sealed_secret::seal(keys.as_ref(), &context, b"opaque server setup")
        .await
        .unwrap();
    let version = AuthnSnapshotRules
        .opaque_setup_key_version(&sealed)
        .unwrap();
    assert_eq!(version, keys.current_key_version());

    let other = crate::sealed_secret::seal(keys.as_ref(), "other context", b"setup")
        .await
        .unwrap();
    assert!(AuthnSnapshotRules.opaque_setup_key_version(&other).is_err());
    assert!(
        AuthnSnapshotRules
            .opaque_setup_key_version(b"plain setup")
            .is_err()
    );
}
