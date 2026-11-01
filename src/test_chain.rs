//! Certificate chains and OCSP responders for the tests, built as Apple's own tests build them
//! (`test_x509_verification.py`): a root, an intermediate with Apple's WWDR OID that names the
//! root's OCSP responder, and a leaf with Apple's receipt-signing OID that names the
//! intermediate's, with a responder that answers about either.

use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use const_oid::AssociatedOid;
use der::asn1::{AnyRef, BitString, GeneralizedTime, Ia5String, Null, ObjectIdentifier, OctetString, UtcTime};
use der::{Any, Decode, Encode, Sequence};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AccessDescription, AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
    KeyUsages, SubjectKeyIdentifier,
};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

use crate::ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspFetchError, OcspFetcher, OcspRequest, OcspResponse, OcspResponseStatus,
    ResponderId, ResponseBytes, ResponseData, RevokedInfo, SingleResponse, ID_KP_OCSP_SIGNING, ID_PKIX_OCSP_BASIC,
    ID_SHA_1,
};
use crate::x509::{self, Cert, ECDSA_WITH_SHA_256, ID_AD_OCSP};

/// When the tests run, in Unix seconds: certificates are valid from a day before to a year after.
pub const NOW: u64 = 1_800_000_000;
pub const DAY: u64 = 86_400;

/// The responder the leaf names: the intermediate's.
pub const LEAF_OCSP_URL: &str = "http://ocsp.example.com/intermediate";
/// The responder the intermediate names: the root's.
pub const INTERMEDIATE_OCSP_URL: &str = "http://ocsp.example.com/root";

pub const RECEIPT_SIGNER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113635.100.6.11.1");
pub const WWDR_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113635.100.6.2.1");
pub const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

/// A P-256 key, the same for the same seed.
pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

/// The root's, the intermediate's and the leaf's keys.
pub fn keys() -> (SigningKey, SigningKey, SigningKey) {
    (key(1), key(2), key(3))
}

/// What a chain's certificates carry besides their names and keys.
pub struct Shape {
    pub root: Vec<Extension>,
    pub intermediate: Vec<Extension>,
    pub leaf: Vec<Extension>,
}

impl Shape {
    /// As Apple's tests build them: basic constraints, Apple's OIDs and the OCSP responders.
    pub fn apple_test() -> Self {
        Self {
            root: vec![ca(None)],
            intermediate: vec![ca(None), apple_oid(WWDR_OID), ocsp_access(INTERMEDIATE_OCSP_URL)],
            leaf: vec![end_entity(), apple_oid(RECEIPT_SIGNER_OID), ocsp_access(LEAF_OCSP_URL)],
        }
    }

    /// As Apple's real chains are, so the strict checks pass: key usage and key identifiers too.
    pub fn strict() -> Self {
        let (root, intermediate, leaf) = keys();

        Self {
            root: vec![ca(None), signs_certificates(), subject_key_id(&root)],
            intermediate: vec![
                ca(Some(0)),
                signs_certificates(),
                subject_key_id(&intermediate),
                authority_key_id(&root),
                apple_oid(WWDR_OID),
                ocsp_access(INTERMEDIATE_OCSP_URL),
            ],
            leaf: vec![
                end_entity(),
                key_usage(KeyUsage(KeyUsages::DigitalSignature.into())),
                subject_key_id(&leaf),
                authority_key_id(&intermediate),
                apple_oid(RECEIPT_SIGNER_OID),
                ocsp_access(LEAF_OCSP_URL),
            ],
        }
    }
}

/// A root, an intermediate and a leaf, DER-encoded, with their keys.
pub struct Chain {
    pub now: u64,
    pub root_key: SigningKey,
    pub intermediate_key: SigningKey,
    pub leaf_key: SigningKey,
    pub root: Vec<u8>,
    pub intermediate: Vec<u8>,
    pub leaf: Vec<u8>,
}

impl Chain {
    pub fn new() -> Self {
        Self::shaped(Shape::apple_test())
    }

    pub fn shaped(shape: Shape) -> Self {
        Self::shaped_at(shape, NOW)
    }

    /// A chain whose certificates are valid from a day before `now` to a year after.
    pub fn shaped_at(shape: Shape, now: u64) -> Self {
        let (root_key, intermediate_key, leaf_key) = keys();
        let root_name = Name::from_str("CN=Root").unwrap();
        let intermediate_name = Name::from_str("CN=Intermediate").unwrap();

        let root = certificate("CN=Root", &root_name, &root_key, &root_key, shape.root, now);
        let intermediate = certificate(
            "CN=Intermediate",
            &root_name,
            &intermediate_key,
            &root_key,
            shape.intermediate,
            now,
        );
        let leaf = certificate(
            "CN=Leaf",
            &intermediate_name,
            &leaf_key,
            &intermediate_key,
            shape.leaf,
            now,
        );

        Self {
            now,
            root_key,
            intermediate_key,
            leaf_key,
            root,
            intermediate,
            leaf,
        }
    }

    /// The leaf's SubjectPublicKeyInfo, DER-encoded: what a verified chain answers.
    pub fn leaf_public_key(&self) -> Vec<u8> {
        public_key(&self.leaf_key)
            .to_der()
            .unwrap()
    }
}

/// A certificate for `key`'s public key, named `subject` (`CN=…`) and issued by `issuer` with
/// `issuer_key`, valid from a day before `now` to a year after, with these extensions.
pub fn certificate(
    subject: &str,
    issuer: &Name,
    key: &SigningKey,
    issuer_key: &SigningKey,
    extensions: Vec<Extension>,
    now: u64,
) -> Vec<u8> {
    static SERIAL: AtomicU32 = AtomicU32::new(1);

    let profile = Profile {
        subject: Name::from_str(subject).unwrap(),
        issuer: issuer.clone(),
    };
    let serial = SerialNumber::from(SERIAL.fetch_add(1, Ordering::Relaxed));
    let validity = Validity::new(time(now - DAY), time(now + 365 * DAY));
    let mut builder = CertificateBuilder::new(profile, serial, validity, public_key(key)).unwrap();
    for extension in extensions {
        builder
            .add_extension(extension)
            .unwrap();
    }

    builder
        .build::<_, DerSignature>(issuer_key)
        .unwrap()
        .to_der()
        .unwrap()
}

/// `certificate` (signed with ECDSA and SHA-256) with its tbsCertificate's signature algorithm
/// changed to `inner`, signed again by `issuer_key`: the signature verifies, but the outer and
/// inner algorithms differ unless `inner` is SHA-256's.
pub fn with_inner_algorithm(certificate: &[u8], issuer_key: &SigningKey, inner: ObjectIdentifier) -> Vec<u8> {
    #[derive(Sequence)]
    struct Signed<'a> {
        tbs: AnyRef<'a>,
        algorithm: AlgorithmIdentifierOwned,
        signature: BitString,
    }

    let sha_256 = AlgorithmIdentifierOwned {
        oid: ECDSA_WITH_SHA_256,
        parameters: None,
    }
    .to_der()
    .unwrap();
    let changed = AlgorithmIdentifierOwned {
        oid: inner,
        parameters: None,
    }
    .to_der()
    .unwrap();
    let mut tbs = x509::signed_part(certificate)
        .unwrap()
        .to_vec();
    let at = tbs
        .windows(sha_256.len())
        .position(|window| window == sha_256.as_slice())
        .unwrap();
    tbs.splice(at..at + sha_256.len(), changed);

    let signature: DerSignature = issuer_key.sign(&tbs);
    Signed {
        tbs: AnyRef::from_der(&tbs).unwrap(),
        algorithm: AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA_256,
            parameters: None,
        },
        signature: BitString::from_bytes(signature.as_bytes()).unwrap(),
    }
    .to_der()
    .unwrap()
}

struct Profile {
    subject: Name,
    issuer: Name,
}

impl BuilderProfile for Profile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(Vec::new())
    }
}

fn public_key(key: &SigningKey) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap()
}

fn time(unix: u64) -> Time {
    Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(unix)).unwrap())
}

fn generalized(unix: u64) -> GeneralizedTime {
    GeneralizedTime::from_unix_duration(Duration::from_secs(unix)).unwrap()
}

pub fn extension<T: Encode>(oid: ObjectIdentifier, critical: bool, value: &T) -> Extension {
    Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(value.to_der().unwrap()).unwrap(),
    }
}

/// Critical basic constraints for a CA, with this path length.
pub fn ca(path_length: Option<u8>) -> Extension {
    extension(
        BasicConstraints::OID,
        true,
        &BasicConstraints {
            ca: true,
            path_len_constraint: path_length,
        },
    )
}

/// Critical basic constraints for an end entity.
pub fn end_entity() -> Extension {
    extension(
        BasicConstraints::OID,
        true,
        &BasicConstraints {
            ca: false,
            path_len_constraint: None,
        },
    )
}

/// Critical key usage.
pub fn key_usage(usage: KeyUsage) -> Extension {
    extension(KeyUsage::OID, true, &usage)
}

pub fn signs_certificates() -> Extension {
    key_usage(KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign))
}

/// One of Apple's marker extensions, as Apple's tests write them (a NULL value).
pub fn apple_oid(oid: ObjectIdentifier) -> Extension {
    extension(oid, false, &Null)
}

pub fn ocsp_access(url: &str) -> Extension {
    let description = AccessDescription {
        access_method: ID_AD_OCSP,
        access_location: GeneralName::UniformResourceIdentifier(Ia5String::new(url).unwrap()),
    };
    extension(
        AuthorityInfoAccessSyntax::OID,
        false,
        &AuthorityInfoAccessSyntax(vec![description]),
    )
}

pub fn extended_key_usage(usages: &[ObjectIdentifier]) -> Extension {
    extension(
        ExtendedKeyUsage::OID,
        false,
        &ExtendedKeyUsage(usages.to_vec()),
    )
}

fn key_id(key: &SigningKey) -> OctetString {
    OctetString::new(
        Sha1::digest(
            public_key(key)
                .subject_public_key
                .raw_bytes(),
        )
        .to_vec(),
    )
    .unwrap()
}

pub fn subject_key_id(key: &SigningKey) -> Extension {
    extension(
        SubjectKeyIdentifier::OID,
        false,
        &SubjectKeyIdentifier(key_id(key)),
    )
}

pub fn authority_key_id(issuer_key: &SigningKey) -> Extension {
    let id = AuthorityKeyIdentifier {
        key_identifier: Some(key_id(issuer_key)),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };
    extension(AuthorityKeyIdentifier::OID, false, &id)
}

/// How a response names its signer.
#[derive(Clone, Copy)]
pub enum By {
    KeyHash,
    Name,
}

/// Who signs a response.
#[derive(Clone)]
pub enum SignedBy {
    /// The certificate's issuer.
    Issuer,
    /// A responder the issuer delegated to, with these extended key usages.
    Delegate(Vec<ObjectIdentifier>),
    /// A responder with OCSP signing that someone other than the issuer issued.
    Stranger,
    /// A key other than the issuer's, though the response names the issuer.
    WrongKey,
}

/// Stands in for the OCSP responders, as Apple's tests mock `requests.post`: answers about
/// whichever of the chain's certificates it's asked about, and notes each URL it was asked at.
pub struct Responder<'a> {
    pub chain: &'a Chain,
    pub reachable: bool,
    pub response_status: OcspResponseStatus,
    pub by: By,
    pub signed_by: SignedBy,
    pub status: CertStatus,
    /// The hash the answer's CertID is made with.
    pub hash: ObjectIdentifier,
    /// Answers about another serial number.
    pub other_serial: bool,
    pub this_update: u64,
    pub next_update: Option<u64>,
    pub asked: Mutex<Vec<String>>,
}

impl<'a> Responder<'a> {
    /// A responder that answers good, signed by the issuer, valid for the next hour.
    pub fn new(chain: &'a Chain) -> Self {
        Self {
            chain,
            reachable: true,
            response_status: OcspResponseStatus::Successful,
            by: By::KeyHash,
            signed_by: SignedBy::Issuer,
            status: CertStatus::Good(Null),
            hash: crate::ocsp::ID_SHA_256,
            other_serial: false,
            this_update: chain.now - 60,
            next_update: Some(chain.now + 3_600),
            asked: Mutex::new(Vec::new()),
        }
    }

    pub fn revoked(chain: &'a Chain) -> Self {
        let info = RevokedInfo {
            revocation_time: generalized(chain.now - DAY),
            revocation_reason: None,
        };
        Self {
            status: CertStatus::Revoked(info),
            ..Self::new(chain)
        }
    }

    /// The URLs it was asked at, in order.
    pub fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }

    fn answer(&self, cert: &Cert<'_>, issuer: &Cert<'_>, issuer_key: &SigningKey) -> Vec<u8> {
        if self.response_status != OcspResponseStatus::Successful {
            return OcspResponse {
                response_status: self.response_status,
                response_bytes: None,
            }
            .to_der()
            .unwrap();
        }

        let issuer_name = issuer.cert.tbs_certificate().subject();
        let delegate = |usages: &[ObjectIdentifier], issued_by: &SigningKey| {
            let extensions = vec![end_entity(), extended_key_usage(usages)];
            certificate(
                "CN=Delegated OCSP Signer",
                issuer_name,
                &key(8),
                issued_by,
                extensions,
                self.chain.now,
            )
        };
        let (signer_der, signer_key, carried) = match &self.signed_by {
            SignedBy::Issuer => (issuer.der.to_vec(), issuer_key.clone(), false),
            SignedBy::WrongKey => (issuer.der.to_vec(), key(9), false),
            SignedBy::Delegate(usages) => (delegate(usages, issuer_key), key(8), true),
            SignedBy::Stranger => (delegate(&[ID_KP_OCSP_SIGNING], &key(7)), key(8), true),
        };
        let signer = Cert::parse(&signer_der).unwrap();

        let responder_id = match self.by {
            By::KeyHash => {
                ResponderId::ByKey(OctetString::new(Sha1::digest(signer.public_key_bytes()).to_vec()).unwrap())
            }
            By::Name => ResponderId::ByName(
                signer
                    .cert
                    .tbs_certificate()
                    .subject()
                    .clone(),
            ),
        };
        let mut cert_id = cert_id(cert, issuer, self.hash);
        if self.other_serial {
            cert_id.serial_number = SerialNumber::from(999_999u32);
        }
        let single = SingleResponse {
            cert_id,
            cert_status: self.status.clone(),
            this_update: generalized(self.this_update),
            next_update: self.next_update.map(generalized),
            single_extensions: None,
        };
        let data = ResponseData {
            version: Default::default(),
            responder_id,
            produced_at: generalized(self.chain.now),
            responses: vec![single],
            response_extensions: None,
        };

        let signature: DerSignature = signer_key.sign(&data.to_der().unwrap());
        let basic = BasicOcspResponse {
            tbs_response_data: data,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA_256,
                parameters: None,
            },
            signature: BitString::from_bytes(signature.as_bytes()).unwrap(),
            certs: carried.then(|| vec![signer.cert.clone()]),
        };
        let bytes = ResponseBytes {
            response_type: ID_PKIX_OCSP_BASIC,
            response: OctetString::new(basic.to_der().unwrap()).unwrap(),
        };
        OcspResponse {
            response_status: self.response_status,
            response_bytes: Some(bytes),
        }
        .to_der()
        .unwrap()
    }
}

impl OcspFetcher for Responder<'_> {
    fn fetch(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, OcspFetchError> {
        self.asked
            .lock()
            .unwrap()
            .push(url.to_string());
        if !self.reachable {
            return Err(OcspFetchError("connection refused".into()));
        }

        let request = OcspRequest::from_der(request).unwrap();
        let asked_about = &request.tbs_request.request_list[0]
            .req_cert
            .serial_number;
        let leaf = Cert::parse(&self.chain.leaf).unwrap();
        let intermediate = Cert::parse(&self.chain.intermediate).unwrap();
        let root = Cert::parse(&self.chain.root).unwrap();

        if asked_about
            == leaf
                .cert
                .tbs_certificate()
                .serial_number()
        {
            Ok(self.answer(&leaf, &intermediate, &self.chain.intermediate_key))
        } else {
            Ok(self.answer(&intermediate, &root, &self.chain.root_key))
        }
    }
}

/// A CertID for `cert`, made with `hash` (SHA-1, with NULL parameters as OpenSSL writes them,
/// or SHA-256, without).
fn cert_id(cert: &Cert<'_>, issuer: &Cert<'_>, hash: ObjectIdentifier) -> CertId {
    let name = issuer.subject_der().unwrap();
    let (name_hash, key_hash, parameters) = if hash == ID_SHA_1 {
        (
            Sha1::digest(&name).to_vec(),
            Sha1::digest(issuer.public_key_bytes()).to_vec(),
            Some(Any::from(Null)),
        )
    } else {
        (
            Sha256::digest(&name).to_vec(),
            Sha256::digest(issuer.public_key_bytes()).to_vec(),
            None,
        )
    };

    CertId {
        hash_algorithm: AlgorithmIdentifierOwned { oid: hash, parameters },
        issuer_name_hash: OctetString::new(name_hash).unwrap(),
        issuer_key_hash: OctetString::new(key_hash).unwrap(),
        serial_number: cert
            .cert
            .tbs_certificate()
            .serial_number()
            .clone(),
    }
}

/// Answers the same body to every request.
pub struct Answers(pub &'static [u8]);

impl OcspFetcher for Answers {
    fn fetch(&self, _url: &str, _request: &[u8]) -> Result<Vec<u8>, OcspFetchError> {
        Ok(self.0.to_vec())
    }
}
