#![cfg(any(feature = "rust_crypto", feature = "aws_lc", feature = "ring"))]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use app_store_server_library::chain_verifier::ChainVerificationFailureReason::{InvalidCertificate, InvalidChain};
use app_store_server_library::chain_verifier::{ChainVerifier, ChainVerifierError};
use app_store_server_library::ocsp::{OcspFetchError, OcspFetcher};
use base64::engine::general_purpose::STANDARD;
use base64::{DecodeError, Engine};
use common::*;

extern crate base64;

/// A verifier for Apple's test certificates, which have no key identifiers: strict checks are
/// off, as in Apple's own tests.
fn test_verifier(root_certificates: Vec<Vec<u8>>) -> ChainVerifier {
    ChainVerifier::new(root_certificates).with_strict_checks(false)
}

#[test]
fn test_valid_chain_without_ocsp() -> Result<(), ChainVerifierError> {
    let root = ROOT_CA_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let leaf = LEAF_CERT_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let intermediate = INTERMEDIATE_CA_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();

    let verifier = test_verifier(vec![root]);
    let public_key = verifier.verify(&leaf, &intermediate, Some(EFFECTIVE_DATE), None)?;
    assert_eq!(
        LEAF_CERT_PUBLIC_KEY_BASE64_ENCODED
            .as_der_bytes()
            .unwrap(),
        public_key
    );
    Ok(())
}

#[test]
fn test_valid_chain_invalid_intermediate_oid_without_ocsp() -> Result<(), ChainVerifierError> {
    let root = ROOT_CA_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let leaf = LEAF_CERT_FOR_INTERMEDIATE_CA_INVALID_OID_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let intermediate = INTERMEDIATE_CA_INVALID_OID_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();

    let verifier = test_verifier(vec![root]);
    let public_key = verifier.verify(&leaf, &intermediate, Some(EFFECTIVE_DATE), None);

    assert_eq!(
        public_key.expect_err("Expect error"),
        ChainVerifierError::VerificationFailure(InvalidChain)
    );
    Ok(())
}

#[test]
fn test_valid_chain_invalid_leaf_oid_without_ocsp() -> Result<(), ChainVerifierError> {
    let root = ROOT_CA_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let leaf = LEAF_CERT_INVALID_OID_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let intermediate = INTERMEDIATE_CA_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();

    let verifier = test_verifier(vec![root]);
    let public_key = verifier.verify(&leaf, &intermediate, Some(EFFECTIVE_DATE), None);

    assert_eq!(
        public_key.expect_err("Expect error"),
        ChainVerifierError::VerificationFailure(InvalidChain)
    );

    Ok(())
}

#[test]
fn test_invalid_base64_in_certificate_list() -> Result<(), ChainVerifierError> {
    assert_eq!(
        "abc"
            .as_der_bytes()
            .expect_err("Expect Error"),
        DecodeError::InvalidPadding
    );
    Ok(())
}

#[test]
fn test_invalid_data_in_certificate_list() -> Result<(), ChainVerifierError> {
    let root = ROOT_CA_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let leaf = STANDARD
        .encode("abc")
        .as_der_bytes()
        .unwrap();
    let intermediate = INTERMEDIATE_CA_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();

    let verifier = test_verifier(vec![root]);
    let public_key = verifier.verify(&leaf, &intermediate, Some(EFFECTIVE_DATE), None);

    assert_eq!(
        public_key.expect_err("Expect error"),
        ChainVerifierError::VerificationFailure(InvalidCertificate)
    );
    Ok(())
}

#[test]
fn test_malformed_root_cert() -> Result<(), ChainVerifierError> {
    let malformed_root = STANDARD
        .encode("abc")
        .as_der_bytes()
        .unwrap();
    let leaf = LEAF_CERT_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let intermediate = INTERMEDIATE_CA_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();

    let verifier = ChainVerifier::new(vec![malformed_root]);
    let public_key = verifier.verify(&leaf, &intermediate, Some(EFFECTIVE_DATE), None);
    assert_eq!(
        public_key.expect_err("Expect error"),
        ChainVerifierError::VerificationFailure(InvalidCertificate)
    );
    Ok(())
}

#[test]
fn test_chain_different_than_root_certificate() -> Result<(), ChainVerifierError> {
    let real_root = REAL_APPLE_ROOT_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let leaf = LEAF_CERT_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let intermediate = INTERMEDIATE_CA_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();

    let verifier = test_verifier(vec![real_root]);
    let public_key = verifier.verify(&leaf, &intermediate, Some(EFFECTIVE_DATE), None);

    assert_eq!(
        public_key.expect_err("Expect error"),
        ChainVerifierError::VerificationFailure(InvalidChain)
    );
    Ok(())
}

#[test]
fn test_valid_expired_chain() -> Result<(), ChainVerifierError> {
    let root = ROOT_CA_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let leaf = LEAF_CERT_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let intermediate = INTERMEDIATE_CA_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();

    let verifier = test_verifier(vec![root]);
    let public_key = verifier.verify(&leaf, &intermediate, Some(2280946846), None);

    assert_eq!(
        public_key.expect_err("Expect error"),
        ChainVerifierError::VerificationFailure(InvalidChain)
    );
    Ok(())
}

#[test]
fn test_empty_root_certificates() -> Result<(), ChainVerifierError> {
    let leaf = LEAF_CERT_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let intermediate = INTERMEDIATE_CA_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();

    let verifier = test_verifier(Vec::new());
    let public_key = verifier.verify(&leaf, &intermediate, Some(EFFECTIVE_DATE), None);

    assert_eq!(
        public_key.expect_err("Expect error"),
        ChainVerifierError::VerificationFailure(InvalidCertificate)
    );
    Ok(())
}

#[test]
fn test_strict_checks_refuse_the_test_certificates() -> Result<(), ChainVerifierError> {
    let root = ROOT_CA_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let leaf = LEAF_CERT_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let intermediate = INTERMEDIATE_CA_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();

    let verifier = ChainVerifier::new(vec![root]);
    let public_key = verifier.verify(&leaf, &intermediate, Some(EFFECTIVE_DATE), None);

    assert_eq!(
        public_key.expect_err("Expect error"),
        ChainVerifierError::VerificationFailure(InvalidChain)
    );
    Ok(())
}

#[test]
fn test_apple_chain_is_valid() -> Result<(), ChainVerifierError> {
    let root = REAL_APPLE_ROOT_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let leaf = REAL_APPLE_SIGNING_CERTIFICATE_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let intermediate = REAL_APPLE_INTERMEDIATE_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();

    let verifier = ChainVerifier::new(vec![root]);
    let _public_key = verifier.verify(&leaf, &intermediate, Some(EFFECTIVE_DATE), None)?;
    Ok(())
}

#[test]
fn test_apple_chain_is_valid_multi_root() -> Result<(), ChainVerifierError> {
    let leaf = REAL_APPLE_SIGNING_CERTIFICATE_BASE64_ENCODED.as_der_bytes()?;
    let intermediate = REAL_APPLE_INTERMEDIATE_BASE64_ENCODED.as_der_bytes()?;

    let multi_root: Vec<_> = REAL_APPLE_MULTI_ROOT_BASE64_ENCODED
        .into_iter()
        .map(|str| str.as_der_bytes().unwrap())
        .collect();

    let verifier = ChainVerifier::new(multi_root);
    let _public_key = verifier.verify(&leaf, &intermediate, Some(EFFECTIVE_DATE), None)?;
    Ok(())
}

/// Asks Apple's real OCSP responders about Apple's real chain, with strict checks, as Apple's
/// `test_apple_chain_is_valid_with_ocsp_and_strict` does. It needs the network and the real
/// leaf to be valid today (until October 2027), so it runs only when asked:
/// `cargo test --features rust_crypto --test chain_verifier -- --ignored`.
#[test]
#[ignore = "asks Apple's OCSP responders over the network"]
fn test_apple_chain_is_valid_with_ocsp_and_strict() -> Result<(), ChainVerifierError> {
    let root = REAL_APPLE_ROOT_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let leaf = REAL_APPLE_SIGNING_CERTIFICATE_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();
    let intermediate = REAL_APPLE_INTERMEDIATE_BASE64_ENCODED
        .as_der_bytes()
        .unwrap();

    let verifier = ChainVerifier::new(vec![root]);
    let public_key = verifier.verify(&leaf, &intermediate, None, Some(&PlainHttp))?;

    assert!(!public_key.is_empty());
    assert_eq!(verifier.cache_len(), 1);
    Ok(())
}

/// Posts OCSP requests over plain HTTP/1.0, as Apple's responders are reached: enough for the
/// live test, without an HTTP client.
struct PlainHttp;

impl OcspFetcher for PlainHttp {
    fn fetch(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, OcspFetchError> {
        let fail = |what: &str| OcspFetchError(format!("{url}: {what}"));
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| fail("not http"))?;
        let (host, path) = rest
            .split_once('/')
            .unwrap_or((rest, ""));

        let mut stream = TcpStream::connect((host, 80)).map_err(|e| fail(&e.to_string()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| fail(&e.to_string()))?;
        let head = format!(
            "POST /{path} HTTP/1.0\r\nHost: {host}\r\nContent-Type: application/ocsp-request\r\nContent-Length: {}\r\n\r\n",
            request.len()
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|_| stream.write_all(request))
            .map_err(|e| fail(&e.to_string()))?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| fail(&e.to_string()))?;
        let split = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| fail("no body"))?;
        if !response.starts_with(b"HTTP/1.0 200") && !response.starts_with(b"HTTP/1.1 200") {
            return Err(fail("not 200"));
        }
        Ok(response[split + 4..].to_vec())
    }
}
