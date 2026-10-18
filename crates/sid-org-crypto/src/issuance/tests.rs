use super::*;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sid_keys::{SigningKeyId, SoftwareP256Signer};
use uuid::Uuid;
use x509_cert::der::{Decode, Encode};
use x509_parser::prelude::{FromDer, X509Certificate};

const YEAR: Duration = Duration::from_secs(365 * 24 * 3600);

fn signer() -> SoftwareP256Signer {
    SoftwareP256Signer::generate(SigningKeyId(Uuid::now_v7()))
        .unwrap()
        .0
}

fn request(subject: &str, key: &dyn CaSigner, years: u32, path_len: Option<u8>) -> CaRequest {
    CaRequest {
        subject: Name::from_str(subject).unwrap(),
        public_key: key.public_key().clone(),
        serial_number: SerialNumber::from(42u32),
        validity: Validity::from_now(YEAR * years).unwrap(),
        path_len,
        extensions: Vec::new(),
    }
}

async fn root(signer: &dyn CaSigner, path_len: Option<u8>) -> Certificate {
    issue_ca_certificate(
        Issuer::SelfIssued(signer),
        request("CN=Root,O=Example", signer, 10, path_len),
    )
    .await
    .unwrap()
}

/// The certificate's signature verifies under `issuer`'s key over its exact TBS.
fn verifies_under(certificate: &Certificate, issuer: &dyn CaSigner) -> bool {
    let key = VerifyingKey::from_public_key_der(&issuer.public_key().to_der().unwrap()).unwrap();
    let Ok(signature) = Signature::from_der(certificate.signature().raw_bytes()) else {
        return false;
    };
    let tbs = certificate.tbs_certificate().to_der().unwrap();
    key.verify(&tbs, &signature).is_ok()
}

/// Counts the signatures it is asked for, to show a refusal never signs.
struct Counting {
    inner: SoftwareP256Signer,
    calls: AtomicUsize,
}

#[async_trait]
impl CaSigner for Counting {
    fn key_id(&self) -> SigningKeyId {
        self.inner.key_id()
    }
    fn signature_algorithm(&self) -> &AlgorithmIdentifierOwned {
        self.inner.signature_algorithm()
    }
    fn public_key(&self) -> &SubjectPublicKeyInfoOwned {
        self.inner.public_key()
    }
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(message).await
    }
}

fn counting() -> Counting {
    Counting {
        inner: signer(),
        calls: AtomicUsize::new(0),
    }
}

// A self-issued root is signed with the key it certifies.
#[tokio::test]
async fn self_issued_root_verifies_under_its_own_key() {
    let key = signer();
    let root = root(&key, Some(1)).await;
    assert!(verifies_under(&root, &key));
    assert_eq!(
        root.tbs_certificate().issuer(),
        root.tbs_certificate().subject()
    );
}

// A subordinate CA is signed by its issuer, names it and verifies under its key.
#[tokio::test]
async fn subordinate_verifies_under_its_issuer() {
    let root_key = signer();
    let root = root(&root_key, Some(1)).await;
    let sub_key = signer();
    let sub = issue_ca_certificate(
        Issuer::Ca {
            certificate: &root,
            signer: &root_key,
        },
        request("CN=Intermediate,O=Example", &sub_key, 5, Some(0)),
    )
    .await
    .unwrap();
    assert!(verifies_under(&sub, &root_key));
    assert!(!verifies_under(&sub, &sub_key));
    assert_eq!(
        sub.tbs_certificate().issuer(),
        root.tbs_certificate().subject()
    );
}

// The CA profile as an independent parser reads it: v3; critical basic
// constraints with the path length; critical keyCertSign, cRLSign and
// digitalSignature; the authority key id is the issuer's subject key id; both
// signature algorithm fields are the signer's (RFC 5280 §4.1.1.2).
#[tokio::test]
async fn certificate_carries_the_ca_profile() {
    let root_key = signer();
    let root = root(&root_key, Some(1)).await;
    let sub_key = signer();
    let sub = issue_ca_certificate(
        Issuer::Ca {
            certificate: &root,
            signer: &root_key,
        },
        request("CN=Intermediate,O=Example", &sub_key, 5, Some(0)),
    )
    .await
    .unwrap();
    let root_der = root.to_der().unwrap();
    let sub_der = sub.to_der().unwrap();
    let (_, parsed_root) = X509Certificate::from_der(&root_der).unwrap();
    let (_, parsed) = X509Certificate::from_der(&sub_der).unwrap();

    assert_eq!(parsed.version().0, 2, "v3");
    let constraints = parsed.basic_constraints().unwrap().unwrap();
    assert!(constraints.critical);
    assert!(constraints.value.ca);
    assert_eq!(constraints.value.path_len_constraint, Some(0));
    let usage = parsed.key_usage().unwrap().unwrap();
    assert!(usage.critical);
    assert!(
        usage.value.key_cert_sign() && usage.value.crl_sign() && usage.value.digital_signature()
    );
    assert!(!usage.value.key_encipherment());

    let root_ski = parsed_root
        .extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(k) => Some(k.0.to_vec()),
            _ => None,
        })
        .unwrap();
    let aki = parsed
        .extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(a) => {
                a.key_identifier.as_ref().map(|k| k.0.to_vec())
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(aki, root_ski);

    let ecdsa_with_sha256 = "1.2.840.10045.4.3.2";
    assert_eq!(
        parsed.signature_algorithm.algorithm.to_id_string(),
        ecdsa_with_sha256
    );
    assert_eq!(
        parsed.tbs_certificate.signature.algorithm.to_id_string(),
        ecdsa_with_sha256
    );
    assert!(parsed.signature_algorithm.parameters.is_none());
}

// A signer whose key is not the issuing certificate's is refused before signing.
#[tokio::test]
async fn another_key_cannot_sign_for_the_issuer() {
    let root_key = signer();
    let root = root(&root_key, Some(1)).await;
    let impostor = counting();
    let sub_key = signer();
    let refused = issue_ca_certificate(
        Issuer::Ca {
            certificate: &root,
            signer: &impostor,
        },
        request("CN=Intermediate", &sub_key, 5, Some(0)),
    )
    .await;
    assert!(matches!(refused, Err(IssuanceError::WrongKey)));
    assert_eq!(impostor.calls.load(Ordering::SeqCst), 0);
}

// Self-issuance certifies the signer's own key: a request for another key is refused.
#[tokio::test]
async fn self_issuance_of_another_key_is_refused() {
    let key = counting();
    let other = signer();
    let refused = issue_ca_certificate(
        Issuer::SelfIssued(&key),
        request("CN=Root", &other, 10, None),
    )
    .await;
    assert!(matches!(refused, Err(IssuanceError::WrongKey)));
    assert_eq!(key.calls.load(Ordering::SeqCst), 0);
}

// RFC 5280 §4.2.1.9: below a CA of path length 0 no CA may be issued.
#[tokio::test]
async fn path_length_zero_issues_no_ca() {
    let root_key = counting();
    let root = root(&root_key, Some(0)).await;
    root_key.calls.store(0, Ordering::SeqCst);
    let refused = issue_ca_certificate(
        Issuer::Ca {
            certificate: &root,
            signer: &root_key,
        },
        request("CN=Intermediate", &signer(), 5, Some(0)),
    )
    .await;
    assert!(matches!(refused, Err(IssuanceError::PathLength)));
    assert_eq!(root_key.calls.load(Ordering::SeqCst), 0);
}

// Below a CA of path length 1 a CA has path length 0: an unlimited or longer
// one is refused, 0 is issued.
#[tokio::test]
async fn subordinate_path_length_is_bounded_by_the_issuer() {
    let root_key = signer();
    let root = root(&root_key, Some(1)).await;
    for path_len in [None, Some(1)] {
        let refused = issue_ca_certificate(
            Issuer::Ca {
                certificate: &root,
                signer: &root_key,
            },
            request("CN=Intermediate", &signer(), 5, path_len),
        )
        .await;
        assert!(
            matches!(refused, Err(IssuanceError::PathLength)),
            "{path_len:?}"
        );
    }
    issue_ca_certificate(
        Issuer::Ca {
            certificate: &root,
            signer: &root_key,
        },
        request("CN=Intermediate", &signer(), 5, Some(0)),
    )
    .await
    .unwrap();
}

// A subordinate cannot outlive its issuer.
#[tokio::test]
async fn validity_beyond_the_issuer_is_refused() {
    let root_key = counting();
    let root = root(&root_key, Some(1)).await;
    root_key.calls.store(0, Ordering::SeqCst);
    let refused = issue_ca_certificate(
        Issuer::Ca {
            certificate: &root,
            signer: &root_key,
        },
        request("CN=Intermediate", &signer(), 11, Some(0)),
    )
    .await;
    assert!(matches!(refused, Err(IssuanceError::Validity)));
    assert_eq!(root_key.calls.load(Ordering::SeqCst), 0);
}

/// A certificate the CA profile would never produce: no extensions at all.
struct Bare(Name);

impl BuilderProfile for Bare {
    fn get_issuer(&self, subject: &Name) -> Name {
        subject.clone()
    }
    fn get_subject(&self) -> Name {
        self.0.clone()
    }
    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(Vec::new())
    }
}

// A certificate that is not a CA (no basic constraints) cannot issue a CA,
// even with its own key.
#[tokio::test]
async fn non_ca_certificate_cannot_issue() {
    let key = counting();
    let mut builder = CertificateBuilder::new(
        Bare(Name::from_str("CN=Leaf").unwrap()),
        SerialNumber::from(7u32),
        Validity::from_now(YEAR * 10).unwrap(),
        key.public_key().clone(),
    )
    .unwrap();
    let signer_key = SignerKey(&key);
    let tbs = builder.finalize(&signer_key).unwrap();
    let signature = BitString::from_bytes(&key.sign(&tbs).await.unwrap()).unwrap();
    let leaf = builder.assemble(signature, &signer_key).unwrap();
    key.calls.store(0, Ordering::SeqCst);

    let refused = issue_ca_certificate(
        Issuer::Ca {
            certificate: &leaf,
            signer: &key,
        },
        request("CN=Intermediate", &signer(), 5, Some(0)),
    )
    .await;
    assert!(matches!(refused, Err(IssuanceError::IssuerNotCa)));
    assert_eq!(key.calls.load(Ordering::SeqCst), 0);
}

// A signer failure is the issuance's failure, never a certificate.
#[tokio::test]
async fn signer_failure_issues_nothing() {
    struct Failing(SoftwareP256Signer);
    #[async_trait]
    impl CaSigner for Failing {
        fn key_id(&self) -> SigningKeyId {
            self.0.key_id()
        }
        fn signature_algorithm(&self) -> &AlgorithmIdentifierOwned {
            self.0.signature_algorithm()
        }
        fn public_key(&self) -> &SubjectPublicKeyInfoOwned {
            self.0.public_key()
        }
        async fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, SigningError> {
            Err(SigningError::Unavailable(self.0.key_id()))
        }
    }
    let key = Failing(signer());
    let refused =
        issue_ca_certificate(Issuer::SelfIssued(&key), request("CN=Root", &key, 10, None)).await;
    assert!(matches!(
        refused,
        Err(IssuanceError::Signing(SigningError::Unavailable(_)))
    ));
}

// RFC 5280 §4.2: an extension appears at most once. A caller extension that
// repeats one of the profile's (here basic constraints) or another caller
// extension is refused before signing.
#[tokio::test]
async fn duplicate_extensions_are_refused() {
    let key = counting();
    let name = Name::from_str("CN=Root").unwrap();
    let constraints = BasicConstraints {
        ca: true,
        path_len_constraint: None,
    }
    .to_extension(&name, &[])
    .unwrap();
    let mut repeats_profile = request("CN=Root", &key, 10, None);
    repeats_profile.extensions.push(constraints);
    let refused = issue_ca_certificate(Issuer::SelfIssued(&key), repeats_profile).await;
    assert!(matches!(refused, Err(IssuanceError::DuplicateExtension(_))));

    let custom = Extension {
        extn_id: x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1"),
        critical: false,
        extn_value: x509_cert::der::asn1::OctetString::new(vec![0x05, 0x00]).unwrap(),
    };
    let mut repeats_caller = request("CN=Root", &key, 10, None);
    repeats_caller.extensions.extend([custom.clone(), custom]);
    let refused = issue_ca_certificate(Issuer::SelfIssued(&key), repeats_caller).await;
    assert!(matches!(refused, Err(IssuanceError::DuplicateExtension(_))));
    assert_eq!(key.calls.load(Ordering::SeqCst), 0);
}

// A validity that ends before it begins is refused, self-issued or not, even
// when both ends lie inside the issuer's validity.
#[tokio::test]
async fn reversed_validity_is_refused() {
    let key = counting();
    let mut reversed = request("CN=Root", &key, 10, None);
    std::mem::swap(
        &mut reversed.validity.not_before,
        &mut reversed.validity.not_after,
    );
    let refused = issue_ca_certificate(Issuer::SelfIssued(&key), reversed).await;
    assert!(matches!(refused, Err(IssuanceError::ReversedValidity)));

    let root_key = signer();
    let root = root(&root_key, Some(1)).await;
    let sub_key = signer();
    let mut reversed = request("CN=Intermediate", &sub_key, 5, Some(0));
    reversed.validity.not_before = Validity::<x509_cert::certificate::Rfc5280>::from_now(YEAR * 2)
        .unwrap()
        .not_after;
    reversed.validity.not_after = Validity::<x509_cert::certificate::Rfc5280>::from_now(YEAR)
        .unwrap()
        .not_after;
    let refused = issue_ca_certificate(
        Issuer::Ca {
            certificate: &root,
            signer: &root_key,
        },
        reversed,
    )
    .await;
    assert!(matches!(refused, Err(IssuanceError::ReversedValidity)));
    assert_eq!(key.calls.load(Ordering::SeqCst), 0);
}

// RFC 5280 §4.1.2.6: a CA certificate has a non-empty subject.
#[tokio::test]
async fn empty_subject_is_refused() {
    let key = counting();
    let mut unnamed = request("CN=Root", &key, 10, None);
    unnamed.subject = Name::default();
    let refused = issue_ca_certificate(Issuer::SelfIssued(&key), unnamed).await;
    assert!(matches!(refused, Err(IssuanceError::EmptySubject)));
    assert_eq!(key.calls.load(Ordering::SeqCst), 0);
}

// An issuing CA certifying a CA of its own name is a replacement signed by the
// CA it replaces; SID admits replacements only from the parent, so this is
// refused (and is not a path-length exemption, RFC 5280 §6.1.4 (l)).
#[tokio::test]
async fn same_name_replacement_under_the_old_ca_is_refused() {
    let root_key = counting();
    let root = root(&root_key, Some(0)).await;
    root_key.calls.store(0, Ordering::SeqCst);
    let replacement = signer();
    let refused = issue_ca_certificate(
        Issuer::Ca {
            certificate: &root,
            signer: &root_key,
        },
        request("CN=Root,O=Example", &replacement, 5, Some(0)),
    )
    .await;
    assert!(matches!(refused, Err(IssuanceError::SameSubjectAsIssuer)));
    assert_eq!(root_key.calls.load(Ordering::SeqCst), 0);
}

// Preparing fixes the TBS without signing; the signed certificate carries
// exactly those bytes, so a signature computed from them before signing (an
// alternative signature) covers the issued certificate's fields.
#[tokio::test]
async fn prepared_tbs_is_the_signed_tbs() {
    let key = counting();
    let prepared =
        prepare_ca_certificate(Issuer::SelfIssued(&key), request("CN=Root", &key, 10, None))
            .unwrap();
    assert_eq!(key.calls.load(Ordering::SeqCst), 0);
    let tbs = prepared.tbs_der().to_vec();
    let certificate = prepared.sign().await.unwrap();
    assert_eq!(key.calls.load(Ordering::SeqCst), 1);
    assert_eq!(certificate.tbs_certificate().to_der().unwrap(), tbs);
    assert!(verifies_under(&certificate, &key.inner));
}

// The certificate round-trips through DER unchanged.
#[tokio::test]
async fn certificate_der_round_trips() {
    let key = signer();
    let root = root(&key, None).await;
    let der = root.to_der().unwrap();
    assert_eq!(Certificate::from_der(&der).unwrap(), root);
}
