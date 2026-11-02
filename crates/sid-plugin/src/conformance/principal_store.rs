// SPDX-License-Identifier: AGPL-3.0-only
//! [`PrincipalStore`] scenarios: a sign-in principal routes to the one
//! account holding it, under the key it is held by, for any account type.
//! Every scenario works on accounts and values it created, so a harness may
//! run them concurrently against one shared database.

use std::fmt::Debug;

use async_trait::async_trait;
use sid_core::models::PrincipalType;

use crate::PrincipalStore;

/// A sign-in principal as the caller presents it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInPrincipal {
    pub principal_type: PrincipalType,
    /// The normalized value.
    pub value: String,
    /// The key revision it is held under.
    pub key_revision: Option<i64>,
}

/// What a backend's harness supplies to the scenarios.
#[async_trait]
pub trait PrincipalHarness: Send + Sync {
    /// The account type the backend routes principals to.
    type Owner: Clone + PartialEq + Debug + Send + Sync + 'static;

    fn store(&self) -> &dyn PrincipalStore<Owner = Self::Owner>;

    /// A new account the store accepts as an owner.
    async fn owner(&self) -> Self::Owner;

    /// A new email principal `owner` signs in with.
    async fn hold(&self, owner: &Self::Owner) -> SignInPrincipal;

    /// `owner` gives `principal` up.
    async fn release(&self, owner: &Self::Owner, principal: &SignInPrincipal);
}

async fn resolve<H: PrincipalHarness>(h: &H, p: &SignInPrincipal) -> Option<H::Owner> {
    h.store()
        .resolve_sign_in_principal(p.principal_type, &p.value, p.key_revision)
        .await
        .unwrap()
}

/// A held principal routes to its holder, and each holder's principal to
/// that holder only.
pub async fn held_principal_resolves_its_owner<H: PrincipalHarness>(h: &H) {
    let (first, second) = (h.owner().await, h.owner().await);
    let (a, b) = (h.hold(&first).await, h.hold(&second).await);
    assert_eq!(resolve(h, &a).await, Some(first));
    assert_eq!(resolve(h, &b).await, Some(second));
}

/// A value nobody holds routes nobody.
pub async fn unknown_principal_resolves_nobody<H: PrincipalHarness>(h: &H) {
    let owner = h.owner().await;
    let held = h.hold(&owner).await;
    let unknown = SignInPrincipal {
        value: format!("unknown.{}", held.value),
        ..held
    };
    assert_eq!(resolve(h, &unknown).await, None);
}

/// The same value under another principal type is another principal.
pub async fn other_type_resolves_nobody<H: PrincipalHarness>(h: &H) {
    let owner = h.owner().await;
    let held = h.hold(&owner).await;
    let as_username = SignInPrincipal {
        principal_type: PrincipalType::Username,
        ..held
    };
    assert_eq!(resolve(h, &as_username).await, None);
}

/// A key of another revision routes nobody: an address established under
/// other rules does not sign in under the current ones.
pub async fn other_key_revision_resolves_nobody<H: PrincipalHarness>(h: &H) {
    let owner = h.owner().await;
    let held = h.hold(&owner).await;
    let other = SignInPrincipal {
        key_revision: Some(held.key_revision.map_or(1, |r| r + 1)),
        ..held.clone()
    };
    assert_eq!(resolve(h, &other).await, None);
    let unkeyed = SignInPrincipal {
        key_revision: None,
        ..held.clone()
    };
    if held.key_revision.is_some() {
        assert_eq!(resolve(h, &unkeyed).await, None);
    }
}

/// A principal its holder gave up routes nobody.
pub async fn released_principal_resolves_nobody<H: PrincipalHarness>(h: &H) {
    let owner = h.owner().await;
    let held = h.hold(&owner).await;
    h.release(&owner, &held).await;
    assert_eq!(resolve(h, &held).await, None);
}
