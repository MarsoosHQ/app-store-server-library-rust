//! What checking Apple's certificate chains and OCSP responses needs from X.509: the bytes a
//! signature covers, exactly as received; ECDSA verification over the P-256 and P-384 keys
//! with SHA-256 or SHA-384 that Apple signs with (and nothing else); and the extensions the
//! checks read.

use der::asn1::ObjectIdentifier;
use der::{Decode, Encode, Header, Reader, SliceReader, Tag};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256, Sha384};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;
use x509_cert::Certificate;

pub(crate) const ECDSA_WITH_SHA_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
pub(crate) const ECDSA_WITH_SHA_384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP_256_R_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP_384_R_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
pub(crate) const ID_AD_OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");

/// A certificate, with the DER it was read from (its signature covers part of those bytes).
pub(crate) struct Cert<'a> {
    pub der: &'a [u8],
    pub cert: Certificate,
}

impl<'a> Cert<'a> {
    pub fn parse(der: &'a [u8]) -> der::Result<Self> {
        Ok(Self {
            der,
            cert: Certificate::from_der(der)?,
        })
    }

    /// Whether `issuer` issued this certificate: it names `issuer`'s subject as its issuer,
    /// its outer and inner signature algorithms are the same, and the signature verifies
    /// with `issuer`'s key.
    pub fn signed_by(&self, issuer: &Cert<'_>) -> bool {
        let tbs = self.cert.tbs_certificate();
        if tbs.issuer() != issuer.cert.tbs_certificate().subject() || tbs.signature() != self.cert.signature_algorithm()
        {
            return false;
        }

        let (Ok(signed), Some(signature)) = (signed_part(self.der), self.cert.signature().as_bytes()) else {
            return false;
        };
        verify_signature(
            issuer
                .cert
                .tbs_certificate()
                .subject_public_key_info(),
            self.cert.signature_algorithm(),
            signed,
            signature,
        )
    }

    /// Whether the certificate is within its validity dates at `time` (Unix seconds).
    pub fn valid_at(&self, time: u64) -> bool {
        let validity = self.cert.tbs_certificate().validity();
        let not_before = validity
            .not_before
            .to_unix_duration()
            .as_secs();
        let not_after = validity
            .not_after
            .to_unix_duration()
            .as_secs();
        not_before <= time && time <= not_after
    }

    /// Whether the certificate has an extension with this OID, whatever its value.
    pub fn has_extension(&self, oid: &ObjectIdentifier) -> bool {
        self.extensions()
            .any(|ext| ext.extn_id == *oid)
    }

    /// Whether the certificate has a critical extension that isn't one of `checked`: RFC 5280
    /// refuses a certificate whose critical extensions the verifier doesn't process.
    pub fn has_unchecked_critical_extension(&self, checked: &[ObjectIdentifier]) -> bool {
        self.extensions()
            .any(|ext| ext.critical && !checked.contains(&ext.extn_id))
    }

    /// The OCSP responders the Authority Information Access extension names. None when the
    /// extension is missing, repeated or unreadable.
    pub fn ocsp_urls(&self) -> Vec<String> {
        let Ok(Some((_, access))) = self
            .cert
            .tbs_certificate()
            .get_extension::<AuthorityInfoAccessSyntax>()
        else {
            return Vec::new();
        };

        access
            .0
            .iter()
            .filter(|description| description.access_method == ID_AD_OCSP)
            .filter_map(|description| match &description.access_location {
                GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
                _ => None,
            })
            .collect()
    }

    /// The subject's public key, as the BIT STRING's value (no tag, length or unused-bits
    /// byte): what OCSP's key hashes cover.
    pub fn public_key_bytes(&self) -> &[u8] {
        self.cert
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .raw_bytes()
    }

    /// The subject's distinguished name, DER-encoded: what OCSP's name hashes cover.
    pub fn subject_der(&self) -> der::Result<Vec<u8>> {
        self.cert
            .tbs_certificate()
            .subject()
            .to_der()
    }

    fn extensions(&self) -> impl Iterator<Item = &x509_cert::ext::Extension> {
        self.cert
            .tbs_certificate()
            .extensions()
            .into_iter()
            .flatten()
    }
}

/// The raw first element of a DER SEQUENCE: a certificate's tbsCertificate, an OCSP
/// response's tbsResponseData. Signatures cover these bytes exactly as received.
pub(crate) fn signed_part(der: &[u8]) -> der::Result<&[u8]> {
    let mut reader = SliceReader::new(der)?;
    let header = Header::decode(&mut reader)?;
    header.tag().assert_eq(Tag::Sequence)?;
    reader.tlv_bytes()
}

/// Whether `signature` (DER, as X.509 and OCSP carry it) over `message` was made by `key`
/// with `algorithm`. Only ECDSA with SHA-256 or SHA-384 by a P-256 or P-384 key passes: what
/// Apple's chains and OCSP responders use. Anything else is refused.
pub(crate) fn verify_signature(
    key: &SubjectPublicKeyInfoOwned,
    algorithm: &AlgorithmIdentifierOwned,
    message: &[u8],
    signature: &[u8],
) -> bool {
    // ecdsa-with-SHA* identifiers carry no parameters (RFC 5758 section 3.2).
    if algorithm.parameters.is_some() || key.algorithm.oid != ID_EC_PUBLIC_KEY {
        return false;
    }

    let digest = match algorithm.oid {
        ECDSA_WITH_SHA_256 => Sha256::digest(message).to_vec(),
        ECDSA_WITH_SHA_384 => Sha384::digest(message).to_vec(),
        _ => return false,
    };
    let Some(point) = key.subject_public_key.as_bytes() else {
        return false;
    };
    let curve = key
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| {
            parameters
                .decode_as::<ObjectIdentifier>()
                .ok()
        });

    match curve {
        Some(SECP_256_R_1) => {
            let (Ok(key), Ok(signature)) = (
                p256::ecdsa::VerifyingKey::from_sec1_bytes(point),
                p256::ecdsa::Signature::from_der(signature),
            ) else {
                return false;
            };
            key.verify_prehash(&digest, &signature)
                .is_ok()
        }
        Some(SECP_384_R_1) => {
            let (Ok(key), Ok(signature)) = (
                p384::ecdsa::VerifyingKey::from_sec1_bytes(point),
                p384::ecdsa::Signature::from_der(signature),
            ) else {
                return false;
            };
            key.verify_prehash(&digest, &signature)
                .is_ok()
        }
        _ => false,
    }
}
