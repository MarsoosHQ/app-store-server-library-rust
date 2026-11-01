//! Verifies the certificate chain Apple signs App Store data with, as Apple's own libraries
//! verify it: the leaf (Apple's receipt signer), issued by the intermediate (Apple Worldwide
//! Developer Relations), issued by one of the trusted roots. With online checks, both
//! certificates' revocation status is asked of their issuer's OCSP responder (see
//! [`crate::ocsp`]), and a chain that verified is remembered for 15 minutes.
//!
//! Apple's chains are always these three certificates, so this checks exactly that shape
//! instead of building paths: the names linking each certificate to its issuer; every
//! signature (ECDSA with SHA-256 or SHA-384, the outer and inner algorithms the same); the
//! validity dates at the effective time; that both issuers are CAs (basic constraints, room in
//! any path length, and key usage, when present, that includes keyCertSign); that the leaf
//! isn't a CA and may sign (digitalSignature, when key usage is present); that no critical
//! extension goes unchecked; and Apple's OIDs on the leaf and the intermediate. The third
//! certificate a JWS carries isn't used: the root must be one of the trusted ones.
//!
//! Strict checks, on unless turned off, add the rules OpenSSL's `X509_STRICT` adds, which
//! Apple's libraries set by default: every certificate is version 3 and names its issuer and
//! subject; a CA's basic constraints are critical, and it has key usage and a subject key
//! identifier; only a CA may have a path length or keyCertSign; and the leaf and the
//! intermediate name their issuer's key (an authority key identifier). Apple's chains meet
//! them; its test certificates don't, so its tests turn them off.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use der::asn1::ObjectIdentifier;
use der::Encode;
use thiserror::Error;
use x509_cert::certificate::Version;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier};

use crate::ocsp::{self, OcspFetcher};
use crate::x509::Cert;

#[derive(Error, Debug, PartialEq)]
pub enum ChainVerifierError {
    #[error("VerificationFailure: [{0}]")]
    VerificationFailure(ChainVerificationFailureReason),

    #[error("InternalError: [{0}]")]
    InternalError(String),

    #[error("InternalDecodeError: [{0}]")]
    InternalDecodeError(#[from] base64::DecodeError),
}

#[derive(Error, Debug, PartialEq)]
pub enum ChainVerificationFailureReason {
    #[error("InvalidAppIdentifier")]
    InvalidAppIdentifier,

    /// A certificate or a trusted root couldn't be read, or there are no trusted roots.
    #[error("InvalidCertificate")]
    InvalidCertificate,

    #[error("InvalidChainLength")]
    InvalidChainLength,

    /// The chain doesn't verify: an issuer, a signature, a date, a CA or key-usage rule, a
    /// critical extension left unchecked, or Apple's OIDs.
    #[error("InvalidChain")]
    InvalidChain,

    /// An OCSP responder answered, but not that the certificate is good (revoked, unknown,
    /// not signed by the issuer or its delegate, or stale), or none was named to ask.
    #[error("RevocationCheckFailed")]
    RevocationCheckFailed,

    /// An OCSP responder couldn't be reached, or didn't answer 200: try again later.
    #[error("RetryableVerificationFailure")]
    RetryableVerificationFailure,
}

/// Apple's receipt-signing OID, expected on the leaf certificate.
const APPLE_RECEIPT_SIGNER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113635.100.6.11.1");
/// Apple's WWDR OID, expected on the intermediate certificate.
const APPLE_WWDR_INTERMEDIATE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113635.100.6.2.1");

/// The extensions a chain's certificates may mark critical: those checked here.
const CHECKED_CRITICAL: [ObjectIdentifier; 3] = [
    ObjectIdentifier::new_unwrap("2.5.29.19"), // basic constraints
    ObjectIdentifier::new_unwrap("2.5.29.15"), // key usage
    ObjectIdentifier::new_unwrap("2.5.29.37"), // extended key usage
];

/// There are unlikely to be more than a couple of keys at once.
const MAXIMUM_CACHE_SIZE: usize = 32;
/// 15 minutes, in seconds.
const CACHE_TIME_LIMIT: u64 = 15 * 60;

#[derive(PartialEq, Eq, Hash)]
struct CacheKey {
    leaf: Vec<u8>,
    intermediate: Vec<u8>,
}

struct CacheValue {
    expiration_time: u64,
    public_key: Vec<u8>,
}

/// Verifies Apple's certificate chains.
pub struct ChainVerifier {
    root_certificates: Vec<Vec<u8>>,
    strict_checks: bool,
    verified_public_key_cache: Mutex<HashMap<CacheKey, CacheValue>>,
}

impl ChainVerifier {
    /// Creates a verifier trusting the given DER-encoded root certificates, with strict checks.
    pub fn new(root_certificates: Vec<Vec<u8>>) -> Self {
        Self {
            root_certificates,
            strict_checks: true,
            verified_public_key_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Turns the strict checks (see the module's documentation) on or off. They're on by
    /// default, as in Apple's libraries; turn them off only for test certificates, which have
    /// no key identifiers.
    pub fn with_strict_checks(mut self, enabled: bool) -> Self {
        self.strict_checks = enabled;
        self
    }

    /// Verifies the chain and returns the leaf's DER-encoded SubjectPublicKeyInfo.
    ///
    /// # Arguments
    /// * `leaf` - DER-encoded leaf certificate
    /// * `intermediate` - DER-encoded intermediate certificate
    /// * `effective_date` - Unix seconds at which the certificates must be valid; now when
    ///   `None`
    /// * `ocsp` - With a fetcher, online checks: both certificates' revocation status is
    ///   checked with their issuer's OCSP responder, and a verified chain's key is cached for
    ///   15 minutes, as Apple's libraries do. Without one, no revocation check is made.
    pub fn verify(
        &self,
        leaf: &[u8],
        intermediate: &[u8],
        effective_date: Option<u64>,
        ocsp: Option<&dyn OcspFetcher>,
    ) -> Result<Vec<u8>, ChainVerifierError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.verify_at(leaf, intermediate, effective_date, ocsp, now)
    }

    /// [`ChainVerifier::verify`], with the current time injected. Exposed for deterministic
    /// testing of cache expiry and OCSP freshness.
    pub fn verify_at(
        &self,
        leaf: &[u8],
        intermediate: &[u8],
        effective_date: Option<u64>,
        ocsp: Option<&dyn OcspFetcher>,
        now: u64,
    ) -> Result<Vec<u8>, ChainVerifierError> {
        if ocsp.is_some() {
            if let Some(cached) = self.cached_public_key(leaf, intermediate, now) {
                return Ok(cached);
            }
        }

        let public_key = self.verify_without_caching(leaf, intermediate, effective_date.unwrap_or(now), ocsp, now)?;

        if ocsp.is_some() {
            self.store_public_key(leaf, intermediate, &public_key, now);
        }
        Ok(public_key)
    }

    /// Number of entries currently held. Exposed for testing.
    pub fn cache_len(&self) -> usize {
        self.verified_public_key_cache
            .lock()
            .map(|c| c.len())
            .unwrap_or(0)
    }

    fn verify_without_caching(
        &self,
        leaf: &[u8],
        intermediate: &[u8],
        effective_date: u64,
        ocsp: Option<&dyn OcspFetcher>,
        now: u64,
    ) -> Result<Vec<u8>, ChainVerifierError> {
        if self.root_certificates.is_empty() {
            return Err(failure(ChainVerificationFailureReason::InvalidCertificate));
        }
        let roots = self
            .root_certificates
            .iter()
            .map(|der| parse(der))
            .collect::<Result<Vec<_>, _>>()?;
        let leaf = parse(leaf)?;
        let intermediate = parse(intermediate)?;

        let root = roots
            .iter()
            .find(|root| intermediate.signed_by(root))
            .ok_or_else(|| failure(ChainVerificationFailureReason::InvalidChain))?;
        let chain = [&leaf, &intermediate, root];
        let holds = leaf.signed_by(&intermediate)
            && chain
                .iter()
                .all(|cert| cert.valid_at(effective_date))
            && chain
                .iter()
                .all(|cert| !cert.has_unchecked_critical_extension(&CHECKED_CRITICAL))
            && is_ca(root, 1)
            && is_ca(&intermediate, 0)
            && is_signer(&leaf)
            && leaf.has_extension(&APPLE_RECEIPT_SIGNER_OID)
            && intermediate.has_extension(&APPLE_WWDR_INTERMEDIATE_OID)
            && (!self.strict_checks
                || (meets_strict_rules(&leaf, false, true)
                    && meets_strict_rules(&intermediate, true, true)
                    && meets_strict_rules(root, true, false)));
        if !holds {
            return Err(failure(ChainVerificationFailureReason::InvalidChain));
        }

        if let Some(fetcher) = ocsp {
            ocsp::check(fetcher, &intermediate, root, now)?;
            ocsp::check(fetcher, &leaf, &intermediate, now)?;
        }

        leaf.cert
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|_| failure(ChainVerificationFailureReason::InvalidCertificate))
    }

    fn cached_public_key(&self, leaf: &[u8], intermediate: &[u8], now: u64) -> Option<Vec<u8>> {
        let key = CacheKey {
            leaf: leaf.to_vec(),
            intermediate: intermediate.to_vec(),
        };
        let cache = self
            .verified_public_key_cache
            .lock()
            .ok()?;
        let value = cache.get(&key)?;
        if value.expiration_time > now {
            Some(value.public_key.clone())
        } else {
            None
        }
    }

    fn store_public_key(&self, leaf: &[u8], intermediate: &[u8], public_key: &[u8], now: u64) {
        let Ok(mut cache) = self.verified_public_key_cache.lock() else {
            return;
        };

        cache.insert(
            CacheKey {
                leaf: leaf.to_vec(),
                intermediate: intermediate.to_vec(),
            },
            CacheValue {
                expiration_time: now + CACHE_TIME_LIMIT,
                public_key: public_key.to_vec(),
            },
        );

        if cache.len() > MAXIMUM_CACHE_SIZE {
            cache.retain(|_, v| v.expiration_time > now);
        }
    }
}

#[cfg(test)]
mod tests;

fn failure(reason: ChainVerificationFailureReason) -> ChainVerifierError {
    ChainVerifierError::VerificationFailure(reason)
}

fn parse(der: &[u8]) -> Result<Cert<'_>, ChainVerifierError> {
    Cert::parse(der).map_err(|_| failure(ChainVerificationFailureReason::InvalidCertificate))
}

/// Whether `cert` may issue certificates with `below` more CAs under it: basic constraints say
/// it's a CA with room for them, and its key usage, when present, includes keyCertSign.
fn is_ca(cert: &Cert<'_>, below: u8) -> bool {
    let tbs = cert.cert.tbs_certificate();
    let ca = matches!(
        tbs.get_extension::<BasicConstraints>(),
        Ok(Some((_, constraints))) if constraints.ca && constraints.path_len_constraint.is_none_or(|room| room >= below)
    );
    let signs_certificates = match tbs.get_extension::<KeyUsage>() {
        Ok(None) => true,
        Ok(Some((_, usage))) => usage.key_cert_sign(),
        Err(_) => false,
    };
    ca && signs_certificates
}

/// Whether the leaf is an end entity that may sign: not a CA, and its key usage, when
/// present, includes digitalSignature.
fn is_signer(cert: &Cert<'_>) -> bool {
    let tbs = cert.cert.tbs_certificate();
    let end_entity = match tbs.get_extension::<BasicConstraints>() {
        Ok(None) => true,
        Ok(Some((_, constraints))) => !constraints.ca,
        Err(_) => false,
    };
    let signs = match tbs.get_extension::<KeyUsage>() {
        Ok(None) => true,
        Ok(Some((_, usage))) => usage.digital_signature(),
        Err(_) => false,
    };
    end_entity && signs
}

/// Whether `cert` meets the strict rules (see the module's documentation), as a CA or not, and
/// as a certificate that names its issuer's key or not (the root doesn't need to).
fn meets_strict_rules(cert: &Cert<'_>, ca: bool, names_issuer_key: bool) -> bool {
    let tbs = cert.cert.tbs_certificate();
    let (Ok(constraints), Ok(usage), Ok(subject_key), Ok(authority_key)) = (
        tbs.get_extension::<BasicConstraints>(),
        tbs.get_extension::<KeyUsage>(),
        tbs.get_extension::<SubjectKeyIdentifier>(),
        tbs.get_extension::<AuthorityKeyIdentifier>(),
    ) else {
        return false;
    };
    let signs_certificates = usage
        .as_ref()
        .is_some_and(|(_, usage)| usage.key_cert_sign());
    let path_length = constraints
        .as_ref()
        .is_some_and(|(_, c)| c.path_len_constraint.is_some());

    let named = !tbs.issuer().is_empty() && !tbs.subject().is_empty();
    let as_ca = if ca {
        constraints
            .as_ref()
            .is_some_and(|(critical, _)| *critical)
            && usage.is_some()
            && subject_key.is_some()
    } else {
        !path_length && !signs_certificates
    };
    let issuer_key = !names_issuer_key || authority_key.is_some_and(|(_, id)| id.key_identifier.is_some());

    tbs.version() == Version::V3 && named && as_ca && issuer_key
}
