// SPDX-License-Identifier: AGPL-3.0-only
//! Acceptance of a presented Binding Passport by its recipient.
//!
//! In plain words: a certificate proves nothing by itself, since anyone can
//! write one. A recipient accepts a passport only when it can follow the
//! signatures from that passport up to an authority the recipient itself
//! admitted, when every authority on the way was allowed to sign what it
//! signed, and when the passport was issued for this very recipient.
//!
//! This module VERIFIES: the complete path to a trust anchor the caller
//! supplies, with every authority, name, path-length, critical-extension and
//! validity constraint of RFC 5280 §6.1, then the SID purposes along the
//! path, the source organization's scope and the passport's recipient.
//!
//! What it leaves to its caller:
//! - which anchors are admitted, and whether that set is current;
//! - revocation and status of the path's certificates;
//! - that the passport's holder is present (the presentation's proof);
//! - whether this recipient admits such an identity at all.
//!
//! The signatures of a path are checked by a [`PathPolicy`]. [`Classical`]
//! checks ECDSA P-256 signatures and gives a classical verdict only. A
//! composition that requires further signatures on the same certificates
//! supplies its own policy and gets the same admission rules, without a
//! second copy of them and without first requiring the classical verdict.

use std::time::SystemTime;

use der::Decode;
use structured_asn1::Parser;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::path::{self, RejectionReason, Validation, Verified};

use crate::binding_passport::{Passport, PassportError, PassportProfile};
use crate::organization_scope::check_organization_scope;
use crate::purpose::{Issued, IssuerRole, PurposeProfile};

/// `ecdsa-with-SHA256` (RFC 5758 §3.2).
const ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/// Why a presented certificate was not accepted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    /// A certificate is not a DER X.509 certificate.
    #[error("not a DER certificate: {0}")]
    Encoding(String),
    /// The caller supplied no anchor this purpose may end at.
    #[error("no trust anchor")]
    NoAnchor,
    /// A trust anchor's own certificate does not allow this path: its
    /// validity, authority status, key usage, path length or key.
    #[error("the trust anchor is {0}")]
    Anchor(&'static str),
    /// The path to every anchor failed a constraint (RFC 5280 §6.1); the
    /// reason given is the last anchor's.
    #[error("the path does not validate: {0}")]
    Rejected(String),
    /// The path names a subject outside an authority's name constraints.
    #[error("a name is outside an authority's name constraints")]
    NameConstraints,
    /// The certificate is not a Binding Passport of the profile.
    #[error(transparent)]
    Passport(#[from] PassportError),
    /// The passport is for another recipient organization.
    #[error("the passport is for another recipient organization")]
    Recipient,
    /// A certificate on the path holds no SID role permitting what it issued.
    #[error("{0}")]
    Purpose(&'static str),
    /// An authority target cannot issue below its path: its key usage, or no
    /// room left by the path lengths above it.
    #[error("the authority is not usable as an issuer: {0}")]
    Target(&'static str),
}

/// How the signatures of one path are verified to one anchor: the
/// cryptographic policy of a verifier. The admission rules around it are the
/// same for every policy.
pub trait PathPolicy {
    /// Validate `path` (the target first, then its issuers) to `anchor` at
    /// `moment` (seconds since the epoch) under RFC 5280 §6.1 and this
    /// policy's signature requirements. `Err` refuses this anchor; the
    /// caller goes on to the next one.
    fn validate<'a>(
        &self,
        path: &[&'a structured_pkix::Certificate<'a>],
        anchor: &'a structured_pkix::Certificate<'a>,
        moment: i64,
        memory: &Memory,
    ) -> Result<(), PathError>;
}

/// The refusal a rejected or unfinished path validation is reported as.
pub fn refusal(outcome: &Validation<'_>) -> Result<(), PathError> {
    match outcome {
        Validation::Accepted(_) => Ok(()),
        Validation::Rejected(rejection) => Err(match rejection.reason {
            RejectionReason::NameConstraints { .. } => PathError::NameConstraints,
            ref reason => PathError::Rejected(format!("{reason:?}")),
        }),
        Validation::Incomplete(bound) => Err(PathError::Rejected(format!("incomplete: {bound:?}"))),
    }
}

/// The classical policy: every certificate of the path is signed with ECDSA
/// P-256 over SHA-256. Further signatures a certificate may carry are not
/// looked at, so this is a classical verdict and no statement about them.
#[derive(Debug, Clone, Copy, Default)]
pub struct Classical;

impl PathPolicy for Classical {
    fn validate<'a>(
        &self,
        path: &[&'a structured_pkix::Certificate<'a>],
        anchor: &'a structured_pkix::Certificate<'a>,
        moment: i64,
        memory: &Memory,
    ) -> Result<(), PathError> {
        let context = path::ValidationContext {
            execution: memory,
            interval: path::Interval::at(moment),
            policy: path::Policy::default(),
            bounds: path::ValidationBounds::default(),
            verifier: &EcdsaP256,
            watch: &(),
            recognizer: &(),
        };
        let outcome = path::validate(path, path::Anchor::from_certificate(anchor), &context)
            .map_err(|e| PathError::Rejected(format!("{e:?}")))?;
        refusal(&outcome)
    }
}

/// ECDSA P-256 with SHA-256 over the signed bytes; any other algorithm is
/// unsupported, which path processing treats as an unverified signature.
pub struct EcdsaP256;

impl path::Verify for EcdsaP256 {
    type Error = core::convert::Infallible;

    fn verify(
        &self,
        algorithm: &structured_pkix::algorithm::AlgorithmIdentifier<'_>,
        key: path::WorkingKey<'_>,
        signed: &[u8],
        signature: structured_pkix::signature::SignatureValue<'_>,
        _execution: &Memory,
    ) -> Result<Verified, Self::Error> {
        use p256::ecdsa::signature::Verifier;
        use p256::pkcs8::DecodePublicKey;
        if algorithm.algorithm().as_bytes() != ECDSA_WITH_SHA256 {
            return Ok(Verified::Unsupported);
        }
        let Ok(key) = p256::ecdsa::VerifyingKey::from_public_key_der(key.key().as_bytes()) else {
            return Ok(Verified::Unsupported);
        };
        let Some(signature) = signature
            .octets()
            .and_then(|bytes| p256::ecdsa::DerSignature::from_bytes(bytes).ok())
        else {
            return Ok(Verified::No);
        };
        Ok(if key.verify(signed, &signature).is_ok() {
            Verified::Yes
        } else {
            Verified::No
        })
    }
}

/// A path validated to one of the admitted anchors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPath {
    /// The anchor the path ends at (DER).
    pub anchor: Vec<u8>,
    /// The authorities between the certificate and the anchor (DER), the
    /// certificate's issuer first.
    pub issuers: Vec<Vec<u8>>,
}

/// A passport accepted on its path, and the moment the acceptance stops
/// holding by the certificates alone: the earliest end of validity among the
/// passport, the authorities of its path and the anchor. Status and the
/// anchor set's own currency bound a reuse further; they are the caller's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedPassport {
    pub passport: Passport,
    pub until: SystemTime,
    /// The path it was accepted on, for the caller's status checks.
    pub path: ValidatedPath,
}

impl AcceptedPassport {
    /// What the passport certifies, by who issued it: a Personal Binding
    /// (no source organization) or a Corporate one.
    pub fn issued(&self) -> Issued {
        issued_as(&self.passport)
    }
}

fn issued_as(passport: &Passport) -> Issued {
    match passport.source_org {
        None => Issued::PersonalPassport,
        Some(_) => Issued::CorporatePassport,
    }
}

/// Verify and accept the passport `certificate` (DER) for the recipient
/// organization `recipient` at `at`: `chain` holds the authorities above it,
/// its issuer first, and may go on to the certificate of the anchor it
/// reaches and above it, which are then not part of the path (RFC 5280
/// §6.1). `anchors` are the certificates the caller admits for this purpose.
#[allow(clippy::too_many_arguments)]
pub fn accept_passport(
    policy: &impl PathPolicy,
    profile: &PassportProfile,
    purposes: &PurposeProfile,
    certificate: &[u8],
    chain: &[Vec<u8>],
    anchors: &[Vec<u8>],
    recipient: uuid::Uuid,
    at: SystemTime,
) -> Result<AcceptedPassport, PathError> {
    let path = validate_path(policy, certificate, chain, anchors, at)?;
    let leaf = read(certificate)?;
    let passport = Passport::read(profile, &leaf)?;
    admit_roles(purposes, &path, issued_as(&passport), passport.source_org)?;
    if passport.recipient_org != recipient {
        return Err(PathError::Recipient);
    }
    let mut until = not_after(&leaf);
    for der in path.issuers.iter().chain(std::iter::once(&path.anchor)) {
        until = until.min(not_after(&read(der)?));
    }
    Ok(AcceptedPassport {
        passport,
        until,
        path,
    })
}

/// Verify and accept the organization authority `certificate` (DER) of
/// `organization` at `at` on a path to one of `anchors`: the same path
/// validation and SID roles as a passport's, and the organization's exact
/// scope. The path is returned for the caller's status checks.
pub fn accept_organization_ca(
    policy: &impl PathPolicy,
    purposes: &PurposeProfile,
    certificate: &[u8],
    chain: &[Vec<u8>],
    anchors: &[Vec<u8>],
    organization: uuid::Uuid,
    at: SystemTime,
) -> Result<ValidatedPath, PathError> {
    let path = validate_path(policy, certificate, chain, anchors, at)?;
    let issued = read(certificate)?;
    if roles(purposes, &issued)? != [IssuerRole::OrganizationCa] {
        return Err(PathError::Purpose(
            "an organization's authority holds exactly the organization purpose",
        ));
    }
    admit_roles(
        purposes,
        &path,
        Issued::Ca(IssuerRole::OrganizationCa),
        Some(organization),
    )?;
    check_organization_scope(&issued, organization).map_err(|_| {
        PathError::Purpose("the organization's authority is not scoped to its organization")
    })?;
    Ok(path)
}

/// Verify `certificate` (DER) at `at` on a path to one of `anchors` (RFC
/// 5280 §6.1 with the anchor's own certificate constraints, under
/// `policy`): `chain` holds the authorities above it, its issuer first, and
/// may go on to the anchor's certificate and above it (a Root for
/// continuity), which are then not part of the path.
pub fn validate_path(
    policy: &impl PathPolicy,
    certificate: &[u8],
    chain: &[Vec<u8>],
    anchors: &[Vec<u8>],
    at: SystemTime,
) -> Result<ValidatedPath, PathError> {
    if anchors.is_empty() {
        return Err(PathError::NoAnchor);
    }
    // Bounds far above the few certificates of a SID chain.
    let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 24, 1 << 26)));
    let parser = Parser::der(memory.clone());
    let parse = |der| {
        structured_pkix::Certificate::read(&parser, der, 0)
            .map_err(|e| PathError::Encoding(e.to_string()))
    };
    let leaf = parse(certificate)?;
    let authorities = chain
        .iter()
        .map(|der| parse(der))
        .collect::<Result<Vec<_>, _>>()?;
    let trusted = anchors
        .iter()
        .map(|der| parse(der))
        .collect::<Result<Vec<_>, _>>()?;
    let moment = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .ok_or_else(|| PathError::Rejected("a time outside the certificates'".into()))?;

    let mut refused = PathError::NoAnchor;
    for anchor in &trusted {
        // The anchor's own certificate, when presented, closes the path: it
        // and what was presented above it (a Root for continuity) are not
        // part of it.
        let mut path: Vec<&structured_pkix::Certificate<'_>> = vec![&leaf];
        path.extend(
            authorities
                .iter()
                .take_while(|authority| authority.as_bytes() != anchor.as_bytes()),
        );
        let checked = admit_anchor(anchor.as_bytes(), path.len() - 1, at)
            .and_then(|()| policy.validate(&path, anchor, moment, &memory));
        match checked {
            Ok(()) => {
                let validated = ValidatedPath {
                    anchor: anchor.as_bytes().to_vec(),
                    issuers: path[1..].iter().map(|c| c.as_bytes().to_vec()).collect(),
                };
                admit_ca_target(certificate, &validated)?;
                return Ok(validated);
            }
            Err(e) => refused = e,
        }
    }
    Err(refused)
}

fn read(der: &[u8]) -> Result<x509_cert::Certificate, PathError> {
    x509_cert::Certificate::from_der(der).map_err(|e| PathError::Encoding(e.to_string()))
}

fn not_after(certificate: &x509_cert::Certificate) -> SystemTime {
    certificate
        .tbs_certificate()
        .validity()
        .not_after
        .to_system_time()
}

fn roles(
    purposes: &PurposeProfile,
    certificate: &x509_cert::Certificate,
) -> Result<Vec<IssuerRole>, PathError> {
    purposes
        .issuer_roles(certificate)
        .map_err(|_| PathError::Purpose("a SID purpose of another allocation"))
}

/// The SID roles along a validated path: the anchor is a platform
/// intermediate, each authority below it holds a role its parent may issue,
/// and the last one may issue `issued`, all by [`IssuerRole::may_issue`]. An
/// organization's authority on the path is scoped exactly to `source_org`,
/// which path processing does not require of a name constraint it merely
/// finds. Path processing applies none of this; an extra purpose on a child
/// cannot enlarge what its parent may issue.
fn admit_roles(
    purposes: &PurposeProfile,
    path: &ValidatedPath,
    issued: Issued,
    source_org: Option<uuid::Uuid>,
) -> Result<(), PathError> {
    let anchor = read(&path.anchor)?;
    if !roles(purposes, &anchor)?.contains(&IssuerRole::PlatformIntermediate) {
        return Err(PathError::Purpose(
            "the trust point is not a platform intermediate",
        ));
    }
    let mut parent = IssuerRole::PlatformIntermediate;
    // From the anchor down: the issuers are listed the certificate's first.
    for der in path.issuers.iter().rev() {
        let authority = read(der)?;
        let held = roles(purposes, &authority)?;
        let [role] = held.as_slice() else {
            return Err(PathError::Purpose(
                "an authority holds exactly one SID role",
            ));
        };
        if !parent.may_issue(Issued::Ca(*role)) {
            return Err(PathError::Purpose(
                "an authority holds a role its issuer may not issue",
            ));
        }
        if *role == IssuerRole::OrganizationCa {
            let organization = source_org.ok_or(PathError::Purpose(
                "an organization's authority issues only for its organization",
            ))?;
            check_organization_scope(&authority, organization).map_err(|_| {
                PathError::Purpose(
                    "the organization's authority is not scoped to the source organization",
                )
            })?;
        }
        parent = *role;
    }
    if parent.may_issue(issued) {
        Ok(())
    } else {
        Err(PathError::Purpose(
            "the certificate's issuer may not issue it",
        ))
    }
}

/// A target that is itself an authority, imported to issue further: RFC 5280
/// §6.1 path processing counts only the intermediates above the target
/// (§6.1.4 (l)) and checks `keyCertSign` only on them (§6.1.4 (n)), so the
/// target's own level and key usage are held here. Every authority above it,
/// the anchor included, leaves room for one more authority below its
/// intermediates (§4.2.1.9), and the target signs certificates (§4.2.1.3). A
/// leaf target passes untouched.
fn admit_ca_target(target: &[u8], path: &ValidatedPath) -> Result<(), PathError> {
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
    let constraints = |certificate: &x509_cert::Certificate| {
        certificate
            .tbs_certificate()
            .get_extension::<BasicConstraints>()
            .map_err(|e| PathError::Encoding(e.to_string()))
            .map(|found| found.map(|(_, c)| c))
    };
    let target = read(target)?;
    if !constraints(&target)?.is_some_and(|c| c.ca) {
        return Ok(());
    }
    let signs_certificates = target
        .tbs_certificate()
        .get_extension::<KeyUsage>()
        .map_err(|e| PathError::Encoding(e.to_string()))?
        .is_some_and(|(_, usage)| usage.key_cert_sign());
    if !signs_certificates {
        return Err(PathError::Target(
            "an authority not allowed to sign certificates",
        ));
    }
    // The issuers are listed the target's own first: issuer j has j
    // intermediates below it, and the target one more.
    let authorities = path.issuers.iter().chain(core::iter::once(&path.anchor));
    for (below, der) in authorities.enumerate() {
        let limit = constraints(&read(der)?)?.and_then(|c| c.path_len_constraint);
        if limit.is_some_and(|limit| usize::from(limit) < below + 1) {
            return Err(PathError::Target(
                "an authority's path length leaves no room for the authority",
            ));
        }
    }
    Ok(())
}

/// The anchor's own certificate allows a path with `below` authority
/// certificates under it at `at`. RFC 5280 §6.1 applies none of an anchor
/// certificate's extensions, but a platform intermediate used as the trust
/// point keeps its validity, authority status, `keyCertSign` and path length.
fn admit_anchor(der: &[u8], below: usize, at: SystemTime) -> Result<(), PathError> {
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
    let anchor = read(der)?;
    let tbs = anchor.tbs_certificate();
    let validity = tbs.validity();
    if at < validity.not_before.to_system_time() || at > validity.not_after.to_system_time() {
        return Err(PathError::Anchor("not valid at that time"));
    }
    let constraints = tbs
        .get_extension::<BasicConstraints>()
        .map_err(|e| PathError::Encoding(e.to_string()))?
        .map(|(_, c)| c)
        .filter(|c| c.ca)
        .ok_or(PathError::Anchor("not an authority"))?;
    let signs_certificates = tbs
        .get_extension::<KeyUsage>()
        .map_err(|e| PathError::Encoding(e.to_string()))?
        .is_some_and(|(_, usage)| usage.key_cert_sign());
    if !signs_certificates {
        return Err(PathError::Anchor("not allowed to sign certificates"));
    }
    if constraints
        .path_len_constraint
        .is_some_and(|limit| below > usize::from(limit))
    {
        return Err(PathError::Anchor("limited to a shorter path"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
