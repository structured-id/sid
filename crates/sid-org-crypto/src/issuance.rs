// SPDX-License-Identifier: AGPL-3.0-only
//! CA certificate issuance through a key-bound signer.
//!
//! The certificate is encoded by RustCrypto `x509-cert`; the issuer's
//! [`CaSigner`] signs the exact DER `TBSCertificate` the builder produces, so a
//! key held outside this process (hardware, external custody) issues the same
//! way as a software key. Every check on the issuer happens before signing: a
//! refused request never reaches the signer.

use sid_keys::{CaSigner, SigningError};
use thiserror::Error;
use x509_cert::Certificate;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{AsyncBuilder, CertificateBuilder};
use x509_cert::der::asn1::BitString;
use x509_cert::der::asn1::{Any, ObjectIdentifier};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::{Encode, Tag, Tagged};
use x509_cert::ext::pkix::constraints::PolicyConstraints;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
    SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef,
};
use x509_cert::time::Validity;

/// Who signs the certificate.
pub enum Issuer<'a> {
    /// The certificate is signed with the key it certifies: the root of a
    /// perimeter. Its subject is also its issuer.
    SelfIssued(&'a dyn CaSigner),
    /// An issuing CA: its certificate and the signer of the key it certifies.
    Ca {
        certificate: &'a Certificate,
        signer: &'a dyn CaSigner,
    },
}

/// The CA certificate requested.
pub struct CaRequest {
    pub subject: Name,
    pub public_key: SubjectPublicKeyInfoOwned,
    pub serial_number: SerialNumber,
    pub validity: Validity,
    /// `pathLenConstraint`: how many CA certificates may follow this one;
    /// `None` leaves it unlimited (RFC 5280 §4.2.1.9).
    pub path_len: Option<u8>,
    /// Further extensions, added after the CA profile's own.
    pub extensions: Vec<Extension>,
}

/// Why a CA certificate was not issued.
#[derive(Debug, Error)]
pub enum IssuanceError {
    /// The signer does not hold the key the issuing certificate (or, when
    /// self-issued, the request) certifies.
    #[error("the signer's key is not the issuer's key")]
    WrongKey,
    /// The issuing certificate is not a CA allowed to sign certificates.
    #[error("the issuing certificate is not a certificate-signing CA")]
    IssuerNotCa,
    /// The issuing CA's path length allows no CA below it, or not one with
    /// the requested path length.
    #[error("the issuing CA's path length does not allow this CA")]
    PathLength,
    /// The requested validity is not within the issuing certificate's.
    #[error("the requested validity exceeds the issuer's")]
    Validity,
    /// The requested validity ends before it begins.
    #[error("the requested validity ends before it begins")]
    ReversedValidity,
    /// A CA certificate needs a subject (RFC 5280 §4.1.2.6).
    #[error("a CA certificate needs a non-empty subject")]
    EmptySubject,
    /// A relative distinguished name holds at least one attribute
    /// (RFC 5280 §4.1.2.4).
    #[error("the subject has an empty relative distinguished name")]
    EmptyRelativeName,
    /// A naming attribute's value is empty, longer than its upper bound, or
    /// not of its type's syntax (RFC 5280 Appendix A.1).
    #[error("the subject's {0} value is not a valid value of that attribute")]
    InvalidAttributeValue(ObjectIdentifier),
    /// The issuing CA would certify a subject of its own name: a replacement
    /// signed by the CA it replaces, which SID never accepts as delegation.
    #[error("an issuing CA cannot certify a CA of its own name")]
    SameSubjectAsIssuer,
    /// One extension would appear twice (RFC 5280 §4.2).
    #[error("extension {0} would appear more than once")]
    DuplicateExtension(x509_cert::der::asn1::ObjectIdentifier),
    /// A serial number is a positive integer (RFC 5280 §4.1.2.2).
    #[error("the serial number is not positive")]
    NonPositiveSerial,
    /// The issuing certificate constrains names; issuance does not evaluate
    /// name constraints, so it refuses rather than sign outside them.
    #[error("the issuing certificate carries name constraints")]
    NameConstrainedIssuer,
    /// The request or the issuing certificate carries policy constraints; the
    /// profile issues no certificate policies, so the path would not validate.
    #[error("policy constraints are not issued under this profile")]
    PolicyConstrained,
    /// An extension of the issuing certificate does not decode.
    #[error("malformed issuing certificate: {0}")]
    MalformedIssuer(String),
    /// Certificate encoding failed.
    #[error("certificate encoding: {0}")]
    Encoding(String),
    /// The signer refused or failed.
    #[error(transparent)]
    Signing(#[from] SigningError),
}

/// Issues the CA certificate `request` under `issuer`.
pub async fn issue_ca_certificate(
    issuer: Issuer<'_>,
    request: CaRequest,
) -> Result<Certificate, IssuanceError> {
    prepare_ca_certificate(issuer, request)?.sign().await
}

/// A CA certificate with every field final and not yet signed.
pub struct PreparedCertificate<'a> {
    builder: CertificateBuilder<CaProfile>,
    tbs: Vec<u8>,
    signer: &'a dyn CaSigner,
}

impl PreparedCertificate<'_> {
    /// The exact DER `TBSCertificate` the issuer's signature will cover; the
    /// fields are final.
    pub fn tbs_der(&self) -> &[u8] {
        &self.tbs
    }

    /// Signs the prepared `TBSCertificate` with the issuer's signer.
    pub async fn sign(self) -> Result<Certificate, IssuanceError> {
        let signature = self.signer.sign(&self.tbs).await?;
        let signature = BitString::from_bytes(&signature)
            .map_err(|e| IssuanceError::Encoding(e.to_string()))?;
        self.builder
            .assemble(signature, &SignerKey(self.signer))
            .map_err(|e| IssuanceError::Encoding(e.to_string()))
    }
}

/// Checks `request` under `issuer` and fixes every field of the certificate;
/// nothing is signed. The same checks as [`issue_ca_certificate`] apply.
pub fn prepare_ca_certificate<'a>(
    issuer: Issuer<'a>,
    request: CaRequest,
) -> Result<PreparedCertificate<'a>, IssuanceError> {
    admit_request(&request)?;
    let (signer, issuer_name, issuer_key_id) = match issuer {
        Issuer::SelfIssued(signer) => {
            if signer.public_key() != &request.public_key {
                return Err(IssuanceError::WrongKey);
            }
            (signer, request.subject.clone(), None)
        }
        Issuer::Ca {
            certificate,
            signer,
        } => {
            let tbs = certificate.tbs_certificate();
            if signer.public_key() != tbs.subject_public_key_info() {
                return Err(IssuanceError::WrongKey);
            }
            // A CA of the issuer's own name signed by the issuer is a
            // replacement certified by the key it replaces: SID admits a
            // replacement only from the parent, so this is no rollover path
            // (and RFC 5280 §6.1.4 (l)'s self-issued exemption never applies).
            if same_name(&request.subject, tbs.subject()) {
                return Err(IssuanceError::SameSubjectAsIssuer);
            }
            admit_issuer(certificate, &request)?;
            let key_id = tbs
                .get_extension::<SubjectKeyIdentifier>()
                .map_err(|e| IssuanceError::MalformedIssuer(e.to_string()))?
                .map(|(_, ski)| ski);
            (signer, tbs.subject().clone(), key_id)
        }
    };

    let profile = CaProfile {
        subject: request.subject,
        issuer: issuer_name,
        path_len: request.path_len,
        issuer_key_id,
        extensions: request.extensions,
    };
    let mut builder = CertificateBuilder::new(
        profile,
        request.serial_number,
        request.validity,
        request.public_key,
    )
    .map_err(|e| IssuanceError::Encoding(e.to_string()))?;
    // Finalized once: the builder appends the profile's extensions here.
    let tbs = builder
        .finalize(&SignerKey(signer))
        .map_err(|e| IssuanceError::Encoding(e.to_string()))?;
    Ok(PreparedCertificate {
        builder,
        tbs,
        signer,
    })
}

/// The request itself is a conforming CA certificate: a subject (RFC 5280
/// §4.1.2.6), a validity that does not end before it begins, and no extension
/// twice, neither among the caller's nor against the profile's (RFC 5280 §4.2).
fn admit_request(request: &CaRequest) -> Result<(), IssuanceError> {
    if request.subject.is_empty() {
        return Err(IssuanceError::EmptySubject);
    }
    if request.subject.iter_rdn().any(|rdn| rdn.is_empty()) {
        return Err(IssuanceError::EmptyRelativeName);
    }
    check_attribute_values(&request.subject)?;
    // RFC 5280 §4.1.2.2: positive, so neither zero nor a negative encoding.
    // `as_bytes` is the signed DER content (a positive value with its high
    // bit set carries the 0x00 sign octet), so a leading 1 bit is negative.
    let serial = request.serial_number.as_bytes();
    if serial.iter().all(|b| *b == 0) || serial.first().is_some_and(|b| b & 0x80 != 0) {
        return Err(IssuanceError::NonPositiveSerial);
    }
    if request.validity.not_after.to_unix_duration()
        < request.validity.not_before.to_unix_duration()
    {
        return Err(IssuanceError::ReversedValidity);
    }
    let mut seen = vec![
        BasicConstraints::OID,
        KeyUsage::OID,
        SubjectKeyIdentifier::OID,
        AuthorityKeyIdentifier::OID,
    ];
    for extension in &request.extensions {
        // RFC 5280 §6.1.4 (i): requireExplicitPolicy makes every following
        // certificate need an acceptable policy, which this profile never
        // issues (§4.2.1.11).
        if extension.extn_id == PolicyConstraints::OID {
            return Err(IssuanceError::PolicyConstrained);
        }
        if seen.contains(&extension.extn_id) {
            return Err(IssuanceError::DuplicateExtension(extension.extn_id));
        }
        seen.push(extension.extn_id);
    }
    Ok(())
}

/// Two names name the same entity under RFC 5280 §7.1: per RDN, the same
/// attribute types; string values compared after the LDAP string preparation
/// of RFC 4518 §2 with the case folding of RFC 3454 B.2, whatever their string
/// type; other values, and strings preparation prohibits, by their DER.
fn same_name(a: &Name, b: &Name) -> bool {
    normalized(a) == normalized(b)
}

fn normalized(name: &Name) -> Vec<Vec<(ObjectIdentifier, Vec<u8>)>> {
    name.iter_rdn()
        .map(|rdn| {
            let mut attributes: Vec<_> = rdn
                .iter()
                .map(|atv| (atv.oid, normalized_value(&atv.value)))
                .collect();
            attributes.sort();
            attributes
        })
        .collect()
}

fn normalized_value(value: &Any) -> Vec<u8> {
    match string_value(value).as_deref().and_then(prepared) {
        Some(text) => {
            let mut out = vec![1];
            out.extend(text.into_bytes());
            out
        }
        // A non-string value, bytes that are not text in their string type,
        // or a string preparation prohibits: compared exactly.
        None => {
            let mut out = vec![0];
            out.extend(value.to_der().unwrap_or_default());
            out
        }
    }
}

/// The text of a string value: UTF-8 and the ASCII types as stored, BMPString
/// as UTF-16BE (X.680 §41). A TeletexString is read as text only when it is
/// valid UTF-8. A UniversalString never gets here: `der` does not decode it.
fn string_value(value: &Any) -> Option<String> {
    let bytes = value.value();
    match value.tag() {
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String | Tag::TeletexString => {
            core::str::from_utf8(bytes).ok().map(str::to_owned)
        }
        Tag::BmpString => {
            let (units, rest) = bytes.as_chunks::<2>();
            if !rest.is_empty() {
                return None;
            }
            char::decode_utf16(units.iter().map(|unit| u16::from_be_bytes(*unit)))
                .collect::<Result<String, _>>()
                .ok()
        }
        _ => None,
    }
}

/// RFC 4518 §2 string preparation of a stored value for `caseIgnoreMatch`:
/// map (§2.2, with RFC 3454 B.2 case folding as RFC 5280 §7.1 requires),
/// normalize to NFKC (§2.3), prohibit (§2.4; `None` when a prohibited code
/// point remains), ignore bidi (§2.5), and compress insignificant spaces
/// (§2.6.1). The repertoire is Unicode 3.2 (RFC 4518 §1.2): a code point
/// unassigned there (RFC 3454 A.1) fails preparation before it is mapped.
/// The tables RFC 3454 fixes (A.1, B.2, C.3-C.5, C.8) come from `stringprep`;
/// NFKC of Unicode 3.2 text is the same under later Unicode versions
/// (Unicode normalization stability).
fn prepared(text: &str) -> Option<String> {
    use icu_properties::props::GeneralCategory;
    use stringprep::tables;
    if text.chars().any(tables::unassigned_code_point) {
        return None;
    }
    let categories = icu_properties::CodePointMapData::<GeneralCategory>::new();
    let mut mapped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            // U+180E was a space separator (Zs) in Unicode 3.2, the version
            // §2.2 is defined over; later versions class it as Cf.
            '\u{9}'..='\u{d}' | '\u{85}' | '\u{180e}' => mapped.push(' '),
            '\u{ad}'
            | '\u{1806}'
            | '\u{34f}'
            | '\u{180b}'..='\u{180d}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{fffc}'
            | '\u{200b}' => {}
            _ => match categories.get(c) {
                GeneralCategory::Control | GeneralCategory::Format => {}
                GeneralCategory::SpaceSeparator
                | GeneralCategory::LineSeparator
                | GeneralCategory::ParagraphSeparator => mapped.push(' '),
                // RFC 3454 B.2: case folding for use with NFKC.
                _ => mapped.extend(tables::case_fold_for_nfkc(c)),
            },
        }
    }
    let prepared = icu_normalizer::ComposingNormalizer::new_nfkc().normalize(&mapped);
    let prohibited = |c: char| {
        tables::unassigned_code_point(c)
            || tables::private_use(c)
            || tables::non_character_code_point(c)
            || tables::surrogate_code(c)
            || tables::change_display_properties_or_deprecated(c)
            || c == '\u{fffd}'
    };
    if prepared.chars().any(prohibited) {
        return None;
    }
    // RFC 4518 §2.6.1: a space is U+0020 followed by no combining mark; one
    // that carries a mark is part of its word and is kept.
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut chars = prepared.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ' ' && !chars.peek().is_some_and(|&next| combining_mark(next)) {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(c);
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    Some(words.join(" "))
}

/// RFC 4518 Appendix A, the combining marks (Mn, Mc, Me of Unicode 3.2), which
/// the RFC makes definitive; later Unicode versions reclassify some of them.
const COMBINING_MARKS: &[(u32, u32)] = &[
    (0x0300, 0x034F),
    (0x0360, 0x036F),
    (0x0483, 0x0486),
    (0x0488, 0x0489),
    (0x0591, 0x05A1),
    (0x05A3, 0x05B9),
    (0x05BB, 0x05BC),
    (0x05BF, 0x05BF),
    (0x05C1, 0x05C2),
    (0x05C4, 0x05C4),
    (0x064B, 0x0655),
    (0x0670, 0x0670),
    (0x06D6, 0x06DC),
    (0x06DE, 0x06E4),
    (0x06E7, 0x06E8),
    (0x06EA, 0x06ED),
    (0x0711, 0x0711),
    (0x0730, 0x074A),
    (0x07A6, 0x07B0),
    (0x0901, 0x0903),
    (0x093C, 0x093C),
    (0x093E, 0x094F),
    (0x0951, 0x0954),
    (0x0962, 0x0963),
    (0x0981, 0x0983),
    (0x09BC, 0x09BC),
    (0x09BE, 0x09C4),
    (0x09C7, 0x09C8),
    (0x09CB, 0x09CD),
    (0x09D7, 0x09D7),
    (0x09E2, 0x09E3),
    (0x0A02, 0x0A02),
    (0x0A3C, 0x0A3C),
    (0x0A3E, 0x0A42),
    (0x0A47, 0x0A48),
    (0x0A4B, 0x0A4D),
    (0x0A70, 0x0A71),
    (0x0A81, 0x0A83),
    (0x0ABC, 0x0ABC),
    (0x0ABE, 0x0AC5),
    (0x0AC7, 0x0AC9),
    (0x0ACB, 0x0ACD),
    (0x0B01, 0x0B03),
    (0x0B3C, 0x0B3C),
    (0x0B3E, 0x0B43),
    (0x0B47, 0x0B48),
    (0x0B4B, 0x0B4D),
    (0x0B56, 0x0B57),
    (0x0B82, 0x0B82),
    (0x0BBE, 0x0BC2),
    (0x0BC6, 0x0BC8),
    (0x0BCA, 0x0BCD),
    (0x0BD7, 0x0BD7),
    (0x0C01, 0x0C03),
    (0x0C3E, 0x0C44),
    (0x0C46, 0x0C48),
    (0x0C4A, 0x0C4D),
    (0x0C55, 0x0C56),
    (0x0C82, 0x0C83),
    (0x0CBE, 0x0CC4),
    (0x0CC6, 0x0CC8),
    (0x0CCA, 0x0CCD),
    (0x0CD5, 0x0CD6),
    (0x0D02, 0x0D03),
    (0x0D3E, 0x0D43),
    (0x0D46, 0x0D48),
    (0x0D4A, 0x0D4D),
    (0x0D57, 0x0D57),
    (0x0D82, 0x0D83),
    (0x0DCA, 0x0DCA),
    (0x0DCF, 0x0DD4),
    (0x0DD6, 0x0DD6),
    (0x0DD8, 0x0DDF),
    (0x0DF2, 0x0DF3),
    (0x0E31, 0x0E31),
    (0x0E34, 0x0E3A),
    (0x0E47, 0x0E4E),
    (0x0EB1, 0x0EB1),
    (0x0EB4, 0x0EB9),
    (0x0EBB, 0x0EBC),
    (0x0EC8, 0x0ECD),
    (0x0F18, 0x0F19),
    (0x0F35, 0x0F35),
    (0x0F37, 0x0F37),
    (0x0F39, 0x0F39),
    (0x0F3E, 0x0F3F),
    (0x0F71, 0x0F84),
    (0x0F86, 0x0F87),
    (0x0F90, 0x0F97),
    (0x0F99, 0x0FBC),
    (0x0FC6, 0x0FC6),
    (0x102C, 0x1032),
    (0x1036, 0x1039),
    (0x1056, 0x1059),
    (0x1712, 0x1714),
    (0x1732, 0x1734),
    (0x1752, 0x1753),
    (0x1772, 0x1773),
    (0x17B4, 0x17D3),
    (0x180B, 0x180D),
    (0x18A9, 0x18A9),
    (0x20D0, 0x20EA),
    (0x302A, 0x302F),
    (0x3099, 0x309A),
    (0xFB1E, 0xFB1E),
    (0xFE00, 0xFE0F),
    (0xFE20, 0xFE23),
    (0x1D165, 0x1D169),
    (0x1D16D, 0x1D172),
    (0x1D17B, 0x1D182),
    (0x1D185, 0x1D18B),
    (0x1D1AA, 0x1D1AD),
];

fn combining_mark(c: char) -> bool {
    let c = u32::from(c);
    COMBINING_MARKS
        .binary_search_by(|&(first, last)| {
            if last < c {
                core::cmp::Ordering::Less
            } else if first > c {
                core::cmp::Ordering::Greater
            } else {
                core::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Every value of `name` is a valid value of its attribute (RFC 5280
/// Appendix A.1): a string is never empty, the standard naming attributes stay
/// within their upper bounds, and a country is two PrintableString letters.
fn check_attribute_values(name: &Name) -> Result<(), IssuanceError> {
    for atv in name.iter_rdn().flat_map(|rdn| rdn.iter()) {
        let invalid = || IssuanceError::InvalidAttributeValue(atv.oid);
        let tag = atv.value.tag();
        let string = matches!(
            tag,
            Tag::Utf8String
                | Tag::PrintableString
                | Tag::Ia5String
                | Tag::TeletexString
                | Tag::BmpString
        );
        if !string {
            continue;
        }
        let bytes = atv.value.value();
        if bytes.is_empty() {
            return Err(invalid());
        }
        // RFC 5280 Appendix A.1 / X.680 §41: PrintableString's repertoire.
        if tag == Tag::PrintableString
            && !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(b))
        {
            return Err(invalid());
        }
        // Characters, as SIZE counts them; bytes when the value is not text.
        let length = string_value(&atv.value).map_or(bytes.len(), |text| text.chars().count());
        match upper_bound(&atv.oid) {
            Bound::Exactly(n) if tag != Tag::PrintableString || length != n => {
                return Err(invalid());
            }
            Bound::AtMost(n) if length > n => return Err(invalid()),
            _ => {}
        }
    }
    Ok(())
}

enum Bound {
    Exactly(usize),
    AtMost(usize),
    None,
}

/// The upper bounds RFC 5280 Appendix A.1 gives the naming attributes.
fn upper_bound(oid: &ObjectIdentifier) -> Bound {
    const UB_NAME: usize = 32768;
    let at = |arc: u32| ObjectIdentifier::new_unwrap("2.5.4").push_arc(arc).ok();
    let is = |arc: u32| at(arc).as_ref() == Some(oid);
    if is(6) {
        // id-at-countryName: PrintableString (SIZE (2)).
        Bound::Exactly(2)
    } else if is(3) || is(10) || is(11) || is(12) || is(5) {
        // common name, organization, organizational unit, title, serial number.
        Bound::AtMost(64)
    } else if is(7) || is(8) || is(65) {
        // locality, state or province, pseudonym.
        Bound::AtMost(128)
    } else if is(4) || is(41) || is(42) || is(43) || is(44) {
        // surname, name, given name, initials, generation qualifier.
        Bound::AtMost(UB_NAME)
    } else if *oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1") {
        // emailAddress: IA5String (SIZE (1..ub-emailaddress-length)).
        Bound::AtMost(255)
    } else {
        Bound::None
    }
}

/// The issuing certificate may sign this CA: it is a CA with `keyCertSign`,
/// its path length leaves room for the request (RFC 5280 §4.2.1.9), and the
/// request's validity lies within its own.
fn admit_issuer(certificate: &Certificate, request: &CaRequest) -> Result<(), IssuanceError> {
    let tbs = certificate.tbs_certificate();
    let malformed = |e: x509_cert::der::Error| IssuanceError::MalformedIssuer(e.to_string());
    // Its subject becomes the issuer name of what it signs, which must be a
    // non-empty distinguished name of non-empty RDNs (RFC 5280 §4.1.2.4).
    if tbs.subject().is_empty()
        || tbs.subject().iter_rdn().any(|rdn| rdn.is_empty())
        || check_attribute_values(tbs.subject()).is_err()
    {
        return Err(IssuanceError::MalformedIssuer(
            "the issuing certificate's subject is not a distinguished name".into(),
        ));
    }
    let constraints = tbs
        .get_extension::<BasicConstraints>()
        .map_err(malformed)?
        .map(|(_, c)| c)
        .filter(|c| c.ca)
        .ok_or(IssuanceError::IssuerNotCa)?;
    // Key usage is required, not only checked when present: a CA whose key
    // signs certificates MUST carry it (RFC 5280 §4.2.1.3), and every issuer
    // here is a SID CA of this profile, never a CA from outside the hierarchy.
    let signs_certificates = tbs
        .get_extension::<KeyUsage>()
        .map_err(malformed)?
        .is_some_and(|(_, usage)| usage.key_cert_sign());
    if !signs_certificates {
        return Err(IssuanceError::IssuerNotCa);
    }
    // Name constraints restrict every subsequent name (RFC 5280 §4.2.1.10);
    // they are not evaluated here, so a constrained issuer signs nothing.
    if tbs
        .get_extension::<x509_cert::ext::pkix::constraints::name::NameConstraints>()
        .map_err(malformed)?
        .is_some()
    {
        return Err(IssuanceError::NameConstrainedIssuer);
    }
    // The same for policy constraints: the subordinate this profile signs has
    // no certificate policies (RFC 5280 §4.2.1.11).
    if tbs
        .get_extension::<PolicyConstraints>()
        .map_err(malformed)?
        .is_some()
    {
        return Err(IssuanceError::PolicyConstrained);
    }
    if let Some(issuer_len) = constraints.path_len_constraint {
        // A CA below a CA of path length n has at most n - 1, and is limited.
        let allowed = issuer_len.checked_sub(1).ok_or(IssuanceError::PathLength)?;
        match request.path_len {
            Some(len) if len <= allowed => {}
            _ => return Err(IssuanceError::PathLength),
        }
    }
    let within = |t: &x509_cert::time::Time| {
        let t = t.to_unix_duration();
        tbs.validity().not_before.to_unix_duration() <= t
            && t <= tbs.validity().not_after.to_unix_duration()
    };
    if !within(&request.validity.not_before) || !within(&request.validity.not_after) {
        return Err(IssuanceError::Validity);
    }
    Ok(())
}

/// The SID CA profile: subject and issuer, and the extensions of a CA
/// certificate (RFC 5280 §4.2.1.1, §4.2.1.2, §4.2.1.3, §4.2.1.9).
struct CaProfile {
    subject: Name,
    issuer: Name,
    path_len: Option<u8>,
    issuer_key_id: Option<SubjectKeyIdentifier>,
    extensions: Vec<Extension>,
}

impl BuilderProfile for CaProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let subject = tbs.subject();
        let mut extensions: Vec<Extension> = Vec::new();
        let constraints = BasicConstraints {
            ca: true,
            path_len_constraint: self.path_len,
        };
        extensions.push(constraints.to_extension(subject, &extensions)?);
        let usage =
            KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign | KeyUsages::DigitalSignature);
        extensions.push(usage.to_extension(subject, &extensions)?);
        let ski = SubjectKeyIdentifier::try_from(spk)?;
        extensions.push(ski.to_extension(subject, &extensions)?);
        // RFC 5280 §4.2.1.1: the issuer's subject key identifier; a self-issued
        // certificate's is its own key's.
        let issuer_ski = match &self.issuer_key_id {
            Some(ski) => ski.clone(),
            None => SubjectKeyIdentifier::try_from(issuer_spk)?,
        };
        let aki = AuthorityKeyIdentifier {
            key_identifier: Some(issuer_ski.0),
            ..Default::default()
        };
        extensions.push(aki.to_extension(subject, &extensions)?);
        extensions.extend(self.extensions.iter().cloned());
        Ok(extensions)
    }
}

/// The issuer's signer as the builder sees it: its public key and its complete
/// signature algorithm. The builder takes both from here, so the certificate's
/// `signature` and `signatureAlgorithm` fields are the signer's.
struct SignerKey<'a>(&'a dyn CaSigner);

#[derive(Clone)]
struct ReportedKey(SubjectPublicKeyInfoOwned);

impl EncodePublicKey for ReportedKey {
    fn to_public_key_der(&self) -> x509_cert::spki::Result<x509_cert::der::Document> {
        Ok(x509_cert::der::Document::encode_msg(&self.0)?)
    }
}

impl signature::Keypair for SignerKey<'_> {
    type VerifyingKey = ReportedKey;

    fn verifying_key(&self) -> ReportedKey {
        ReportedKey(self.0.public_key().clone())
    }
}

impl DynSignatureAlgorithmIdentifier for SignerKey<'_> {
    fn signature_algorithm_identifier(&self) -> x509_cert::spki::Result<AlgorithmIdentifierOwned> {
        Ok(self.0.signature_algorithm().clone())
    }
}

#[cfg(test)]
mod tests;
