//! Revocation checks for Apple's certificate chains, made as Apple's own libraries make them
//! (RFC 6960). For each certificate, an OCSP request (a CertID hashed with SHA-256) goes to
//! each responder its Authority Information Access names, and the answer must say the
//! certificate is good. An answer counts only when:
//!
//! - it's signed by the certificate's issuer, or by a responder the issuer delegated to
//!   (issued by it, valid now, with the OCSP signing extended key usage), found by key hash
//!   or by name among the issuer and the certificates the answer carries;
//! - its signature verifies (ECDSA with SHA-256 or SHA-384);
//! - it holds a response about this certificate (its CertID, recomputed with whatever hash the
//!   responder used) that says good and is fresh: `thisUpdate` no later than now and
//!   `nextUpdate` no earlier, each give or take 60 seconds.
//!
//! A responder that can't be reached, or answers HTTP other than 200, is a retryable failure.
//! The crate does no networking itself: an [`OcspFetcher`] posts the request, so the caller
//! chooses the HTTP client and how it waits.

use der::asn1::{BitString, GeneralizedTime, Null, ObjectIdentifier, OctetString};
use der::{Choice, Decode, Encode, Enumerated, Sequence};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::Certificate;

use crate::chain_verifier::{ChainVerificationFailureReason, ChainVerifierError};
use crate::x509::{self, Cert};

/// Posts an OCSP request for the chain verifier, and answers the response.
pub trait OcspFetcher: Send + Sync {
    /// POSTs `request` (DER) to `url` with `Content-Type: application/ocsp-request`, and
    /// answers the body of a `200` response. Anything else (no connection, a timeout, another
    /// status) is an error, which makes the verification a retryable failure.
    fn fetch(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, OcspFetchError>;
}

/// The responder couldn't be reached, or didn't answer `200`.
#[derive(thiserror::Error, Debug)]
#[error("OCSP responder unavailable: {0}")]
pub struct OcspFetchError(pub String);

/// Clock skew allowed when checking a response's dates, in seconds.
const MAX_SKEW: u64 = 60;

pub(crate) const ID_PKIX_OCSP_BASIC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");
pub(crate) const ID_KP_OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");
pub(crate) const ID_SHA_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
pub(crate) const ID_SHA_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_SHA_384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const ID_SHA_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// The extensions a delegated responder's certificate may mark critical: those checked here.
const RESPONDER_CHECKED_CRITICAL: [ObjectIdentifier; 3] = [
    ObjectIdentifier::new_unwrap("2.5.29.19"), // basic constraints
    ObjectIdentifier::new_unwrap("2.5.29.15"), // key usage
    ObjectIdentifier::new_unwrap("2.5.29.37"), // extended key usage
];

/// Asks `cert`'s OCSP responders whether `issuer`'s certificate `cert` is good, at `now`
/// (Unix seconds). Ok once one says so; a retryable failure when a responder can't be
/// reached; otherwise a failed revocation check.
pub(crate) fn check(
    fetcher: &dyn OcspFetcher,
    cert: &Cert<'_>,
    issuer: &Cert<'_>,
    now: u64,
) -> Result<(), ChainVerifierError> {
    let request = request_for(cert, issuer).map_err(|_| failure(ChainVerificationFailureReason::InvalidCertificate))?;

    for url in cert.ocsp_urls() {
        let body = fetcher
            .fetch(&url, &request)
            .map_err(|_| failure(ChainVerificationFailureReason::RetryableVerificationFailure))?;
        if says_good(&body, cert, issuer, now)? {
            return Ok(());
        }
    }
    Err(failure(
        ChainVerificationFailureReason::RevocationCheckFailed,
    ))
}

fn failure(reason: ChainVerificationFailureReason) -> ChainVerifierError {
    ChainVerifierError::VerificationFailure(reason)
}

fn failed() -> ChainVerifierError {
    failure(ChainVerificationFailureReason::RevocationCheckFailed)
}

/// The DER OCSP request for `cert`: one CertID, hashed with SHA-256.
pub(crate) fn request_for(cert: &Cert<'_>, issuer: &Cert<'_>) -> der::Result<Vec<u8>> {
    let id = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA_256,
            parameters: None,
        },
        issuer_name_hash: OctetString::new(Sha256::digest(issuer.subject_der()?).to_vec())?,
        issuer_key_hash: OctetString::new(Sha256::digest(issuer.public_key_bytes()).to_vec())?,
        serial_number: cert
            .cert
            .tbs_certificate()
            .serial_number()
            .clone(),
    };
    OcspRequest {
        tbs_request: TbsRequest {
            request_list: vec![Request { req_cert: id }],
        },
    }
    .to_der()
}

/// Whether this OCSP response says `cert` is good. A response that isn't `successful` says
/// nothing (the next responder is asked); one that can't be trusted is a failure.
fn says_good(body: &[u8], cert: &Cert<'_>, issuer: &Cert<'_>, now: u64) -> Result<bool, ChainVerifierError> {
    let response = OcspResponse::from_der(body).map_err(|_| failed())?;
    if response.response_status != OcspResponseStatus::Successful {
        return Ok(false);
    }

    let bytes = response
        .response_bytes
        .ok_or_else(failed)?;
    if bytes.response_type != ID_PKIX_OCSP_BASIC {
        return Err(failed());
    }
    let basic_der = bytes.response.as_bytes();
    let basic = BasicOcspResponse::from_der(basic_der).map_err(|_| failed())?;
    let signed = x509::signed_part(basic_der).map_err(|_| failed())?;

    // Who signed it: the issuer, or a responder among the certificates it carries.
    let carried: Vec<Vec<u8>> = basic
        .certs
        .iter()
        .flatten()
        .map(Encode::to_der)
        .collect::<der::Result<_>>()
        .map_err(|_| failed())?;
    let carried: Vec<Cert<'_>> = carried
        .iter()
        .map(|der| Cert::parse(der))
        .collect::<der::Result<_>>()
        .map_err(|_| failed())?;
    let responder_id = &basic.tbs_response_data.responder_id;
    let signer = std::iter::once(issuer)
        .chain(carried.iter())
        .find(|candidate| identifies(responder_id, candidate))
        .ok_or_else(failed)?;
    if signer.der != issuer.der && !delegated_by(signer, issuer, now) {
        return Err(failed());
    }

    let Some(signature) = basic.signature.as_bytes() else {
        return Err(failed());
    };
    if !x509::verify_signature(
        signer
            .cert
            .tbs_certificate()
            .subject_public_key_info(),
        &basic.signature_algorithm,
        signed,
        signature,
    ) {
        return Err(failed());
    }

    Ok(basic
        .tbs_response_data
        .responses
        .iter()
        .any(|single| is_about(&single.cert_id, cert, issuer) && is_good_and_fresh(single, now)))
}

/// Whether the responder ID names this certificate: the SHA-1 of its public key, or its subject.
fn identifies(id: &ResponderId, candidate: &Cert<'_>) -> bool {
    match id {
        ResponderId::ByKey(hash) => hash.as_bytes() == Sha1::digest(candidate.public_key_bytes()).as_slice(),
        ResponderId::ByName(name) => {
            name == candidate
                .cert
                .tbs_certificate()
                .subject()
        }
    }
}

/// Whether `issuer` delegated its OCSP responses to `responder`: it issued the responder's
/// certificate, which is valid now, has the OCSP signing extended key usage, and has no
/// critical extension left unchecked.
fn delegated_by(responder: &Cert<'_>, issuer: &Cert<'_>, now: u64) -> bool {
    let signs_ocsp = matches!(
        responder.cert.tbs_certificate().get_extension::<ExtendedKeyUsage>(),
        Ok(Some((_, usage))) if usage.0.contains(&ID_KP_OCSP_SIGNING)
    );

    signs_ocsp
        && responder.signed_by(issuer)
        && responder.valid_at(now)
        && !responder.has_unchecked_critical_extension(&RESPONDER_CHECKED_CRITICAL)
}

/// Whether a response's CertID is this certificate's, recomputed with the response's hash.
fn is_about(id: &CertId, cert: &Cert<'_>, issuer: &Cert<'_>) -> bool {
    let Ok(name) = issuer.subject_der() else {
        return false;
    };
    let Some(name_hash) = hash(&id.hash_algorithm, &name) else {
        return false;
    };
    let Some(key_hash) = hash(&id.hash_algorithm, issuer.public_key_bytes()) else {
        return false;
    };

    id.serial_number
        == *cert
            .cert
            .tbs_certificate()
            .serial_number()
        && id.issuer_name_hash.as_bytes() == name_hash.as_slice()
        && id.issuer_key_hash.as_bytes() == key_hash.as_slice()
}

/// `data` hashed with a CertID's algorithm: SHA-1, SHA-256, SHA-384 or SHA-512, with absent
/// or NULL parameters. None for anything else.
fn hash(algorithm: &AlgorithmIdentifierOwned, data: &[u8]) -> Option<Vec<u8>> {
    let null_or_absent = algorithm
        .parameters
        .as_ref()
        .is_none_or(|parameters| parameters.decode_as::<Null>().is_ok());
    if !null_or_absent {
        return None;
    }

    Some(match algorithm.oid {
        ID_SHA_1 => Sha1::digest(data).to_vec(),
        ID_SHA_256 => Sha256::digest(data).to_vec(),
        ID_SHA_384 => Sha384::digest(data).to_vec(),
        ID_SHA_512 => Sha512::digest(data).to_vec(),
        _ => return None,
    })
}

/// Good, and fresh at `now`: issued no later than now and valid until no earlier, each give
/// or take `MAX_SKEW`. A response with no `nextUpdate` isn't fresh.
fn is_good_and_fresh(single: &SingleResponse, now: u64) -> bool {
    let this_update = single
        .this_update
        .to_unix_duration()
        .as_secs();
    let next_update = single
        .next_update
        .map(|t| t.to_unix_duration().as_secs());

    matches!(single.cert_status, CertStatus::Good(_))
        && this_update <= now.saturating_add(MAX_SKEW)
        && next_update.is_some_and(|next| next.saturating_add(MAX_SKEW) >= now)
}

// RFC 6960's structures (its module's tags are EXPLICIT unless marked otherwise), as far as
// a request and a basic response need them.

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct CertId {
    pub hash_algorithm: AlgorithmIdentifierOwned,
    pub issuer_name_hash: OctetString,
    pub issuer_key_hash: OctetString,
    pub serial_number: SerialNumber,
}

/// A request with one CertID, and none of the optional parts.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct OcspRequest {
    pub tbs_request: TbsRequest,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct TbsRequest {
    pub request_list: Vec<Request>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct Request {
    pub req_cert: CertId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Enumerated)]
#[repr(u32)]
pub(crate) enum OcspResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct OcspResponse {
    pub response_status: OcspResponseStatus,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub response_bytes: Option<ResponseBytes>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct ResponseBytes {
    pub response_type: ObjectIdentifier,
    pub response: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct BasicOcspResponse {
    pub tbs_response_data: ResponseData,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub certs: Option<Vec<Certificate>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct ResponseData {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", default = "Default::default")]
    pub version: x509_cert::certificate::Version,
    pub responder_id: ResponderId,
    pub produced_at: GeneralizedTime,
    pub responses: Vec<SingleResponse>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub response_extensions: Option<Extensions>,
}

#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub(crate) enum ResponderId {
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    ByName(Name),
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    ByKey(OctetString),
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct SingleResponse {
    pub cert_id: CertId,
    pub cert_status: CertStatus,
    pub this_update: GeneralizedTime,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub next_update: Option<GeneralizedTime>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub single_extensions: Option<Extensions>,
}

#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub(crate) enum CertStatus {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Good(Null),
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Revoked(RevokedInfo),
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    Unknown(Null),
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct RevokedInfo {
    pub revocation_time: GeneralizedTime,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub revocation_reason: Option<CrlReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Enumerated)]
#[repr(u32)]
pub(crate) enum CrlReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}
