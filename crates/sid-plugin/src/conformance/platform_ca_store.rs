// SPDX-License-Identifier: AGPL-3.0-only
//! [`PlatformCaStore`] scenarios: what every store of the admitted platform
//! CA set owes its caller. Each scenario needs a store that holds no set
//! yet.

use sid_core::models::{AuditEntry, MutationContext};

use crate::platform_ca::{
    AnchorStatus, Applied, GenerationStatus, HeldAnchors, IssuerStatus, PlatformCa,
    PlatformCaError, PlatformCaSet, PlatformCaState, PlatformCaStore, StatusRefusal,
};

const NOW: i64 = 1_800_000_000;

fn ca(generation: u32, state: PlatformCaState, overlap_end: Option<i64>) -> PlatformCa {
    PlatformCa {
        generation,
        certificate: vec![generation as u8; 32],
        state,
        overlap_end,
        // A store takes authenticated status apart from the set.
        crl: None,
    }
}

/// No status held of an anchor: none of its CRLs was ever recorded.
fn unknown() -> AnchorStatus {
    AnchorStatus::default()
}

fn status(generation: u32, number: u64, next_update: i64, revoked: &[&[u8]]) -> GenerationStatus {
    GenerationStatus {
        generation,
        number,
        next_update,
        revoked: revoked.iter().map(|serial| serial.to_vec()).collect(),
    }
}

fn set(revision: u64, generations: Vec<PlatformCa>) -> PlatformCaSet {
    PlatformCaSet {
        revision,
        generations,
        issued_at: NOW,
        next_update: NOW + 3600,
    }
}

/// The store under test, each write carrying the scenarios' audit entry.
struct Audited<'a>(&'a dyn PlatformCaStore);

fn audit() -> MutationContext {
    AuditEntry::system("conformance", "platform_ca").into()
}

impl Audited<'_> {
    async fn apply_platform_cas(&self, set: &PlatformCaSet) -> Result<Applied, PlatformCaError> {
        self.0.apply_platform_cas(set, audit()).await
    }

    async fn record_platform_ca_status(
        &self,
        status: &[GenerationStatus],
    ) -> Result<(), PlatformCaError> {
        self.0.record_platform_ca_status(status, audit()).await
    }

    async fn held_platform_cas(&self, now: i64) -> Result<HeldAnchors, PlatformCaError> {
        self.0.held_platform_cas(now).await
    }
}

async fn anchors(store: &Audited<'_>, now: i64) -> Vec<Vec<u8>> {
    store.held_platform_cas(now).await.unwrap().anchors
}

/// Active and in-overlap generations anchor paths; an ended overlap and a
/// withdrawn generation do not. The answer names the held revision and stops
/// being current at the first overlap end among its anchors, before the
/// set's refresh time: a cached copy cannot outlive either.
pub async fn anchors_follow_the_published_states(backend: &dyn PlatformCaStore) {
    let store = &Audited(backend);
    store
        .apply_platform_cas(&set(
            1,
            vec![
                ca(4, PlatformCaState::Active, None),
                ca(3, PlatformCaState::VerificationOnly, Some(NOW + 60)),
                ca(2, PlatformCaState::VerificationOnly, Some(NOW - 1)),
                ca(1, PlatformCaState::Withdrawn, None),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(
        store.held_platform_cas(NOW).await.unwrap(),
        HeldAnchors {
            revision: 1,
            anchors: vec![vec![4u8; 32], vec![3u8; 32]],
            status: vec![unknown(), unknown()],
            until: NOW + 60,
            renew_at: NOW + 1800,
        }
    );
    // Past that overlap the set's refresh time bounds the answer.
    assert_eq!(
        store.held_platform_cas(NOW + 61).await.unwrap(),
        HeldAnchors {
            revision: 1,
            anchors: vec![vec![4u8; 32]],
            status: vec![unknown()],
            until: NOW + 3600,
            renew_at: NOW + 1800,
        }
    );
}

/// Nothing is answered before a set arrives, nor from a set past its refresh
/// time: stale states are not current evidence.
pub async fn no_anchor_without_current_evidence(backend: &dyn PlatformCaStore) {
    let store = &Audited(backend);
    assert!(matches!(
        store.held_platform_cas(NOW).await,
        Err(PlatformCaError::NotProvisioned)
    ));
    store
        .apply_platform_cas(&set(1, vec![ca(1, PlatformCaState::Active, None)]))
        .await
        .unwrap();
    assert!(matches!(
        store.held_platform_cas(NOW + 3601).await,
        Err(PlatformCaError::Stale)
    ));
}

/// An older set arriving after a newer one changes nothing; a withdrawal is
/// kept even when a later set at a higher revision lists the generation as
/// active again, as an older copy replayed under a new revision would.
pub async fn what_is_held_only_narrows(backend: &dyn PlatformCaStore) {
    let store = &Audited(backend);
    store
        .apply_platform_cas(&set(5, vec![ca(1, PlatformCaState::Withdrawn, None)]))
        .await
        .unwrap();
    assert_eq!(
        store
            .apply_platform_cas(&set(4, vec![ca(1, PlatformCaState::Active, None)]))
            .await
            .unwrap(),
        Applied::Stale
    );
    assert_eq!(
        store
            .apply_platform_cas(&set(6, vec![ca(1, PlatformCaState::Active, None)]))
            .await
            .unwrap(),
        Applied::Current
    );
    assert!(anchors(store, NOW).await.is_empty());
}

/// A generation the held revision does not list anchors nothing, whatever
/// state an earlier revision left it in: only the held revision's
/// generations are answered.
pub async fn only_the_held_revision_anchors(backend: &dyn PlatformCaStore) {
    let store = &Audited(backend);
    store
        .apply_platform_cas(&set(
            1,
            vec![
                ca(1, PlatformCaState::Active, None),
                ca(2, PlatformCaState::Active, None),
            ],
        ))
        .await
        .unwrap();
    store
        .apply_platform_cas(&set(2, vec![ca(2, PlatformCaState::Active, None)]))
        .await
        .unwrap();
    assert_eq!(anchors(store, NOW).await, vec![vec![2u8; 32]]);
}

/// An anchor's status is what its generation's CRLs said: a certificate it
/// revoked is refused, one it did not is relied on while the CRL is within
/// its time, and nothing is relied on without a CRL or past its next update.
pub async fn an_anchor_answers_for_the_cas_it_issued(backend: &dyn PlatformCaStore) {
    let store = &Audited(backend);
    store
        .apply_platform_cas(&set(1, vec![ca(1, PlatformCaState::Active, None)]))
        .await
        .unwrap();
    let held = store.held_platform_cas(NOW).await.unwrap();
    assert_eq!(
        held.status[0].admits(&[7], NOW),
        Err(StatusRefusal::Unavailable),
        "no CRL was ever held"
    );
    store
        .record_platform_ca_status(&[status(1, 10, NOW + 3600, &[&[7]])])
        .await
        .unwrap();
    let held = store.held_platform_cas(NOW).await.unwrap();
    assert_eq!(
        held.status[0].admits(&[7], NOW),
        Err(StatusRefusal::Revoked)
    );
    assert_eq!(held.status[0].admits(&[8], NOW), Ok(()));
    assert_eq!(held.status[0].admits(&[8], NOW + 3600), Ok(()));
    assert_eq!(
        held.status[0].admits(&[8], NOW + 3601),
        Err(StatusRefusal::Unavailable),
        "past the CRL's next update it is no evidence"
    );
}

/// An older CRL replayed after a newer one, or a newer CRL that no longer
/// lists a serial, does not bring a revoked CA certificate back: a lower
/// number changes nothing, and a revocation seen once stays.
pub async fn a_revocation_seen_once_stays(backend: &dyn PlatformCaStore) {
    let store = &Audited(backend);
    store
        .apply_platform_cas(&set(1, vec![ca(1, PlatformCaState::Active, None)]))
        .await
        .unwrap();
    store
        .record_platform_ca_status(&[status(1, 10, NOW + 3600, &[&[7]])])
        .await
        .unwrap();
    // An older CRL, valid for longer and listing nothing.
    store
        .record_platform_ca_status(&[status(1, 9, NOW + 7200, &[])])
        .await
        .unwrap();
    let held = store.held_platform_cas(NOW).await.unwrap();
    assert_eq!(held.status[0].until, Some(NOW + 3600));
    assert_eq!(
        held.status[0].admits(&[7], NOW),
        Err(StatusRefusal::Revoked)
    );
    // A newer CRL that omits the serial and revokes another.
    store
        .record_platform_ca_status(&[status(1, 11, NOW + 7200, &[&[8]])])
        .await
        .unwrap();
    let held = store.held_platform_cas(NOW).await.unwrap();
    assert_eq!(held.status[0].until, Some(NOW + 7200));
    for serial in [[7u8], [8]] {
        assert_eq!(
            held.status[0].admits(&serial, NOW),
            Err(StatusRefusal::Revoked)
        );
    }
    assert_eq!(held.status[0].admits(&[9], NOW), Ok(()));
    // The same CRL recorded again changes nothing.
    store
        .record_platform_ca_status(&[status(1, 11, NOW + 7200, &[&[8]])])
        .await
        .unwrap();
    assert_eq!(store.held_platform_cas(NOW).await.unwrap(), held);
}

/// One generation's CRL says nothing of another's certificates: each anchor
/// answers from its own generation's status.
pub async fn status_is_per_generation(backend: &dyn PlatformCaStore) {
    let store = &Audited(backend);
    store
        .apply_platform_cas(&set(
            1,
            vec![
                ca(2, PlatformCaState::Active, None),
                ca(1, PlatformCaState::VerificationOnly, Some(NOW + 600)),
            ],
        ))
        .await
        .unwrap();
    store
        .record_platform_ca_status(&[status(2, 5, NOW + 3600, &[&[7]])])
        .await
        .unwrap();
    let held = store.held_platform_cas(NOW).await.unwrap();
    // Newest generation first.
    assert_eq!(
        held.status[0].admits(&[7], NOW),
        Err(StatusRefusal::Revoked)
    );
    assert_eq!(
        held.status[1].admits(&[7], NOW),
        Err(StatusRefusal::Unavailable)
    );
}

fn issuer_crl(issuer: u8, number: u64, next_update: i64, revoked: &[&[u8]]) -> IssuerStatus {
    IssuerStatus {
        issuer: [issuer; 32],
        number,
        next_update,
        revoked: revoked.iter().map(|serial| serial.to_vec()).collect(),
    }
}

/// Nothing held of an issuer shows nothing of what it issued; a held CRL
/// admits an unlisted serial until its next update and no longer, and
/// refuses a listed one. Bug prevented: absence of status read as good
/// status, or a CRL past its time still relied on.
pub async fn issuer_status_is_evidence_only_in_its_time(backend: &dyn PlatformCaStore) {
    let unknown = backend.held_issuer_status(&[1; 32]).await.unwrap();
    assert_eq!(unknown.admits(&[7], NOW), Err(StatusRefusal::Unavailable));

    backend
        .record_issuer_status(&issuer_crl(1, 5, NOW + 3600, &[&[9]]), audit())
        .await
        .unwrap();
    let held = backend.held_issuer_status(&[1; 32]).await.unwrap();
    assert_eq!(held.until, Some(NOW + 3600));
    assert_eq!(held.admits(&[7], NOW + 3600), Ok(()));
    assert_eq!(
        held.admits(&[7], NOW + 3601),
        Err(StatusRefusal::Unavailable)
    );
    assert_eq!(held.admits(&[9], NOW), Err(StatusRefusal::Revoked));
    // Another issuer's status says nothing of this one's serials.
    assert_eq!(
        backend.held_issuer_status(&[2; 32]).await.unwrap(),
        AnchorStatus::default()
    );
}

/// What is held of an issuer only narrows: an older CRL does not shorten or
/// replace the held evidence but its revocations are kept, and a newer CRL
/// that omits a serial seen revoked does not bring it back. Bug prevented:
/// a replayed or rolled-back CRL restoring a revoked certificate.
pub async fn an_issuers_revocation_seen_once_stays(backend: &dyn PlatformCaStore) {
    let record = |crl: IssuerStatus| async move {
        backend.record_issuer_status(&crl, audit()).await.unwrap();
    };
    record(issuer_crl(1, 5, NOW + 3600, &[&[9]])).await;
    // An older number: its end is not taken, its revocation is.
    record(issuer_crl(1, 4, NOW + 9000, &[&[8]])).await;
    let held = backend.held_issuer_status(&[1; 32]).await.unwrap();
    assert_eq!(held.until, Some(NOW + 3600));
    assert_eq!(held.admits(&[8], NOW), Err(StatusRefusal::Revoked));
    assert_eq!(held.admits(&[9], NOW), Err(StatusRefusal::Revoked));

    // A newer number listing nothing extends the evidence only.
    record(issuer_crl(1, 6, NOW + 7200, &[])).await;
    let held = backend.held_issuer_status(&[1; 32]).await.unwrap();
    assert_eq!(held.until, Some(NOW + 7200));
    assert_eq!(held.admits(&[9], NOW), Err(StatusRefusal::Revoked));
    assert_eq!(held.admits(&[7], NOW), Ok(()));
    // The same CRL again changes nothing.
    record(issuer_crl(1, 6, NOW + 7200, &[])).await;
    assert_eq!(backend.held_issuer_status(&[1; 32]).await.unwrap(), held);
}

/// Recorders of one issuer's CRLs at once leave the highest number and
/// every revocation, whichever commits last. A store that refuses a
/// concurrent writer is asked again.
pub async fn concurrent_issuer_status_keeps_the_newest(backend: &dyn PlatformCaStore) {
    let newer = issuer_crl(1, 6, NOW + 7200, &[&[9]]);
    let older = issuer_crl(1, 5, NOW + 3600, &[&[8]]);
    let (a, b) = tokio::join!(
        backend.record_issuer_status(&newer, audit()),
        backend.record_issuer_status(&older, audit())
    );
    if a.is_err() {
        backend.record_issuer_status(&newer, audit()).await.unwrap();
    }
    if b.is_err() {
        backend.record_issuer_status(&older, audit()).await.unwrap();
    }
    let held = backend.held_issuer_status(&[1; 32]).await.unwrap();
    assert_eq!(held.until, Some(NOW + 7200));
    assert_eq!(held.revoked, vec![vec![8u8], vec![9u8]]);
}

/// A move carries everything the source held, as it held it: the target
/// answers as the source did, keeps a generation the held revision no longer
/// lists withdrawn when a later set lists it active again, and keeps every
/// revocation. Moving the same archive again writes nothing, and a store
/// holding other state refuses a move. `target` holds nothing yet.
pub async fn a_move_keeps_every_narrowing(
    source: &dyn PlatformCaStore,
    target: &dyn PlatformCaStore,
) {
    let (from, to) = (&Audited(source), &Audited(target));
    assert!(from.0.export_platform_cas().await.unwrap().is_empty());
    from.apply_platform_cas(&set(
        1,
        vec![
            ca(1, PlatformCaState::Withdrawn, None),
            ca(2, PlatformCaState::Active, None),
        ],
    ))
    .await
    .unwrap();
    // The held revision no longer lists the withdrawn generation.
    from.apply_platform_cas(&set(
        2,
        vec![
            ca(3, PlatformCaState::Active, None),
            ca(2, PlatformCaState::VerificationOnly, Some(NOW + 600)),
        ],
    ))
    .await
    .unwrap();
    from.record_platform_ca_status(&[status(3, 5, NOW + 3600, &[&[9], &[7]])])
        .await
        .unwrap();
    from.0
        .record_issuer_status(&issuer_crl(4, 2, NOW + 3600, &[&[5]]), audit())
        .await
        .unwrap();
    let archive = from.0.export_platform_cas().await.unwrap();
    assert_eq!(archive.generations.len(), 3);
    assert_eq!(archive.issuers.len(), 1);

    assert!(to.0.import_platform_cas(&archive, audit()).await.unwrap());
    assert_eq!(to.0.export_platform_cas().await.unwrap(), archive);
    assert_eq!(
        to.held_platform_cas(NOW).await.unwrap(),
        from.held_platform_cas(NOW).await.unwrap()
    );
    assert_eq!(
        to.0.held_issuer_status(&[4; 32])
            .await
            .unwrap()
            .admits(&[5], NOW),
        Err(StatusRefusal::Revoked)
    );
    // A resumed move finds it held.
    assert!(!to.0.import_platform_cas(&archive, audit()).await.unwrap());

    // The withdrawal moved with it: listed active again, it anchors nothing.
    to.apply_platform_cas(&set(
        3,
        vec![
            ca(3, PlatformCaState::Active, None),
            ca(1, PlatformCaState::Active, None),
        ],
    ))
    .await
    .unwrap();
    assert_eq!(anchors(to, NOW).await, vec![vec![3u8; 32]]);
    let held = to.held_platform_cas(NOW).await.unwrap();
    assert_eq!(
        held.status[0].admits(&[7], NOW),
        Err(StatusRefusal::Revoked)
    );

    // The source holds its own state: another archive is refused whole.
    let mut other = archive.clone();
    other.issuers.clear();
    assert!(matches!(
        from.0.import_platform_cas(&other, audit()).await,
        Err(PlatformCaError::Occupied)
    ));
    assert_eq!(from.0.export_platform_cas().await.unwrap(), archive);
}

/// A generation number keeps the certificate it was first published with:
/// a set carrying another one is refused whole, its revision included.
pub async fn a_generation_keeps_its_certificate(backend: &dyn PlatformCaStore) {
    let store = &Audited(backend);
    store
        .apply_platform_cas(&set(1, vec![ca(1, PlatformCaState::Active, None)]))
        .await
        .unwrap();
    let mut other = ca(1, PlatformCaState::Active, None);
    other.certificate = vec![9; 32];
    assert!(matches!(
        store
            .apply_platform_cas(&set(2, vec![ca(5, PlatformCaState::Active, None), other]))
            .await,
        Err(PlatformCaError::Conflict(1))
    ));
    let held = store.held_platform_cas(NOW).await.unwrap();
    assert_eq!(held.revision, 1);
    assert_eq!(held.anchors, vec![vec![1u8; 32]]);
}

/// Two replicas applying different revisions at once settle on the newer
/// set and the narrower state, whichever commits last. A store that refuses
/// a concurrent writer is asked again, as the caller's refresh would.
pub async fn concurrent_applies_never_widen(backend: &dyn PlatformCaStore) {
    let store = &Audited(backend);
    store
        .apply_platform_cas(&set(1, vec![ca(1, PlatformCaState::Active, None)]))
        .await
        .unwrap();
    let newer = set(3, vec![ca(1, PlatformCaState::Withdrawn, None)]);
    let older = set(2, vec![ca(1, PlatformCaState::Active, None)]);
    let (a, b) = tokio::join!(
        store.apply_platform_cas(&newer),
        store.apply_platform_cas(&older)
    );
    if a.is_err() {
        store.apply_platform_cas(&newer).await.unwrap();
    }
    if b.is_err() {
        store.apply_platform_cas(&older).await.unwrap();
    }
    let held = store.held_platform_cas(NOW).await.unwrap();
    assert_eq!(held.revision, 3);
    assert!(held.anchors.is_empty());
}

/// An older set racing a newer one never leaves its generations behind: the
/// held generations are those of the held revision, so an older overlap end
/// or a generation only the older set lists is never kept beside the newer
/// revision.
pub async fn an_older_set_racing_a_newer_one_leaves_nothing(backend: &dyn PlatformCaStore) {
    let store = &Audited(backend);
    store
        .apply_platform_cas(&set(
            1,
            vec![ca(1, PlatformCaState::VerificationOnly, Some(NOW + 600))],
        ))
        .await
        .unwrap();
    let newer = set(
        3,
        vec![ca(1, PlatformCaState::VerificationOnly, Some(NOW + 60))],
    );
    let older = set(
        2,
        vec![
            ca(1, PlatformCaState::VerificationOnly, Some(NOW + 600)),
            ca(7, PlatformCaState::Active, None),
        ],
    );
    let (a, b) = tokio::join!(
        store.apply_platform_cas(&older),
        store.apply_platform_cas(&newer)
    );
    if a.is_err() {
        store.apply_platform_cas(&older).await.unwrap();
    }
    if b.is_err() {
        store.apply_platform_cas(&newer).await.unwrap();
    }
    assert!(
        anchors(store, NOW + 120).await.is_empty(),
        "an older set widened the held revision"
    );
}
