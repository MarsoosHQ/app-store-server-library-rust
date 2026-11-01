//! The chain verifier on chains and OCSP responders built for the tests: Apple's own cases
//! (`test_x509_verification.py`), and the ones its library handles without a test.

use std::str::FromStr;

use const_oid::AssociatedOid;
use der::asn1::{Null, ObjectIdentifier};
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, KeyUsages};
use x509_cert::name::Name;
use ChainVerificationFailureReason::{
    InvalidCertificate, InvalidChain, RetryableVerificationFailure, RevocationCheckFailed,
};

use super::*;
use crate::ocsp::{CertStatus, OcspResponseStatus, ID_KP_OCSP_SIGNING, ID_SHA_1};
use crate::test_chain::*;
use crate::x509::{ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384};

fn verify(chain: &Chain, ocsp: Option<&dyn OcspFetcher>) -> Result<Vec<u8>, ChainVerifierError> {
    verify_at(chain, NOW, ocsp)
}

/// Verifies `chain` with strict checks off, as Apple's tests do for the chains they build.
fn verify_at(chain: &Chain, now: u64, ocsp: Option<&dyn OcspFetcher>) -> Result<Vec<u8>, ChainVerifierError> {
    ChainVerifier::new(vec![chain.root.clone()])
        .with_strict_checks(false)
        .verify_at(&chain.leaf, &chain.intermediate, None, ocsp, now)
}

fn refused(reason: ChainVerificationFailureReason) -> Result<Vec<u8>, ChainVerifierError> {
    Err(failure(reason))
}

#[test]
fn verifies_a_chain_shaped_like_apples() {
    let chain = Chain::new();

    assert_eq!(verify(&chain, None), Ok(chain.leaf_public_key()));
}

#[test]
fn refuses_no_trusted_roots() {
    let chain = Chain::new();
    let verifier = ChainVerifier::new(Vec::new());

    let result = verifier.verify_at(&chain.leaf, &chain.intermediate, None, None, NOW);

    assert_eq!(result, refused(InvalidCertificate));
}

#[test]
fn refuses_certificates_outside_their_dates() {
    let chain = Chain::new();
    let verifier = ChainVerifier::new(vec![chain.root.clone()]).with_strict_checks(false);

    for date in [NOW - 2 * DAY, NOW + 366 * DAY] {
        let result = verifier.verify_at(&chain.leaf, &chain.intermediate, Some(date), None, NOW);

        assert_eq!(result, refused(InvalidChain));
    }
}

#[test]
fn refuses_a_leaf_the_intermediate_did_not_sign() {
    let mut chain = Chain::new();
    let (_, _, leaf_key) = keys();
    let intermediate = Name::from_str("CN=Intermediate").unwrap();
    chain.leaf = certificate(
        "CN=Leaf",
        &intermediate,
        &leaf_key,
        &key(7),
        Shape::apple_test().leaf,
        NOW,
    );

    assert_eq!(verify(&chain, None), refused(InvalidChain));
}

#[test]
fn refuses_a_certificate_whose_two_signature_algorithms_differ() {
    let mut chain = Chain::new();
    let leaf = chain.leaf.clone();

    chain.leaf = with_inner_algorithm(&leaf, &chain.intermediate_key, ECDSA_WITH_SHA_256);
    assert_eq!(verify(&chain, None), Ok(chain.leaf_public_key()));

    chain.leaf = with_inner_algorithm(&leaf, &chain.intermediate_key, ECDSA_WITH_SHA_384);
    assert_eq!(verify(&chain, None), refused(InvalidChain));
}

#[test]
fn refuses_an_intermediate_that_may_not_sign_certificates() {
    let mut shape = Shape::apple_test();
    shape
        .intermediate
        .push(key_usage(KeyUsage(KeyUsages::DigitalSignature.into())));

    assert_eq!(verify(&Chain::shaped(shape), None), refused(InvalidChain));
}

#[test]
fn refuses_a_root_with_no_room_for_the_intermediate() {
    let mut shape = Shape::apple_test();
    shape.root[0] = ca(Some(0));

    assert_eq!(verify(&Chain::shaped(shape), None), refused(InvalidChain));
}

#[test]
fn refuses_a_leaf_that_is_a_ca() {
    let mut shape = Shape::apple_test();
    shape.leaf[0] = ca(None);

    assert_eq!(verify(&Chain::shaped(shape), None), refused(InvalidChain));
}

#[test]
fn refuses_a_leaf_that_may_not_sign() {
    let mut shape = Shape::apple_test();
    shape
        .leaf
        .push(key_usage(KeyUsage(KeyUsages::KeyEncipherment.into())));

    assert_eq!(verify(&Chain::shaped(shape), None), refused(InvalidChain));
}

#[test]
fn refuses_a_critical_extension_it_does_not_check() {
    let mut shape = Shape::apple_test();
    shape.leaf.push(extension(
        ObjectIdentifier::new_unwrap("1.2.3.4"),
        true,
        &Null,
    ));

    assert_eq!(verify(&Chain::shaped(shape), None), refused(InvalidChain));
}

#[test]
fn refuses_a_chain_without_apples_oids() {
    let mut shape = Shape::apple_test();
    shape
        .leaf
        .retain(|ext| ext.extn_id != RECEIPT_SIGNER_OID);
    assert_eq!(verify(&Chain::shaped(shape), None), refused(InvalidChain));

    let mut shape = Shape::apple_test();
    shape
        .intermediate
        .retain(|ext| ext.extn_id != WWDR_OID);
    assert_eq!(verify(&Chain::shaped(shape), None), refused(InvalidChain));
}

#[test]
fn strict_checks_pass_a_chain_shaped_like_apples_real_ones() {
    let chain = Chain::shaped(Shape::strict());
    let verifier = ChainVerifier::new(vec![chain.root.clone()]);

    let result = verifier.verify_at(&chain.leaf, &chain.intermediate, None, None, NOW);

    assert_eq!(result, Ok(chain.leaf_public_key()));
}

#[test]
fn strict_checks_refuse_what_openssls_strict_mode_refuses() {
    let not_critical = extension(
        BasicConstraints::OID,
        false,
        &BasicConstraints {
            ca: true,
            path_len_constraint: None,
        },
    );
    let breaks: [fn(&mut Shape); 6] = [
        // Apple's test chains: no key usage or key identifiers.
        |shape| *shape = Shape::apple_test(),
        // A CA without key usage.
        |shape| {
            shape
                .root
                .retain(|ext| ext.extn_id != KeyUsage::OID)
        },
        // A CA without a subject key identifier.
        |shape| {
            shape
                .intermediate
                .retain(|ext| ext.extn_id != SubjectKeyIdentifier::OID)
        },
        // A leaf without an authority key identifier.
        |shape| {
            shape
                .leaf
                .retain(|ext| ext.extn_id != AuthorityKeyIdentifier::OID)
        },
        // A leaf with a path length.
        |shape| {
            shape.leaf[0] = extension(
                BasicConstraints::OID,
                true,
                &BasicConstraints {
                    ca: false,
                    path_len_constraint: Some(0),
                },
            )
        },
        // A leaf that may sign certificates.
        |shape| {
            shape.leaf[1] = key_usage(KeyUsage(
                KeyUsages::DigitalSignature | KeyUsages::KeyCertSign,
            ))
        },
    ];

    let mut shapes: Vec<Shape> = breaks
        .iter()
        .map(|change| {
            let mut shape = Shape::strict();
            change(&mut shape);
            shape
        })
        .collect();
    // A CA whose basic constraints aren't critical.
    let mut shape = Shape::strict();
    shape.root[0] = not_critical;
    shapes.push(shape);

    for shape in shapes {
        let chain = Chain::shaped(shape);
        let strict = ChainVerifier::new(vec![chain.root.clone()]);

        let result = strict.verify_at(&chain.leaf, &chain.intermediate, None, None, NOW);

        assert_eq!(result, refused(InvalidChain));
        assert_eq!(verify(&chain, None), Ok(chain.leaf_public_key()));
    }
}

#[test]
fn ocsp_responder_identified_by_key_hash() {
    let chain = Chain::new();
    let responder = Responder::new(&chain);

    assert_eq!(
        verify(&chain, Some(&responder)),
        Ok(chain.leaf_public_key())
    );
    assert_eq!(responder.asked(), [INTERMEDIATE_OCSP_URL, LEAF_OCSP_URL]);
}

#[test]
fn ocsp_responder_identified_by_name() {
    let chain = Chain::new();
    let responder = Responder {
        by: By::Name,
        ..Responder::new(&chain)
    };

    assert_eq!(
        verify(&chain, Some(&responder)),
        Ok(chain.leaf_public_key())
    );
    assert_eq!(responder.asked(), [INTERMEDIATE_OCSP_URL, LEAF_OCSP_URL]);
}

#[test]
fn ocsp_delegated_signer_identified_by_key_hash() {
    let chain = Chain::new();
    let signed_by = SignedBy::Delegate(vec![ID_KP_OCSP_SIGNING]);
    let responder = Responder {
        signed_by,
        ..Responder::new(&chain)
    };

    assert_eq!(
        verify(&chain, Some(&responder)),
        Ok(chain.leaf_public_key())
    );
}

#[test]
fn ocsp_delegated_signer_identified_by_name() {
    let chain = Chain::new();
    let signed_by = SignedBy::Delegate(vec![ID_KP_OCSP_SIGNING]);
    let responder = Responder {
        by: By::Name,
        signed_by,
        ..Responder::new(&chain)
    };

    assert_eq!(
        verify(&chain, Some(&responder)),
        Ok(chain.leaf_public_key())
    );
}

#[test]
fn ocsp_delegated_signer_without_ocsp_signing_usage() {
    let chain = Chain::new();
    let signed_by = SignedBy::Delegate(vec![SERVER_AUTH]);
    let responder = Responder {
        signed_by,
        ..Responder::new(&chain)
    };

    assert_eq!(
        verify(&chain, Some(&responder)),
        refused(RevocationCheckFailed)
    );
}

#[test]
fn ocsp_delegated_signer_the_issuer_did_not_issue() {
    let chain = Chain::new();
    let responder = Responder {
        signed_by: SignedBy::Stranger,
        ..Responder::new(&chain)
    };

    assert_eq!(
        verify(&chain, Some(&responder)),
        refused(RevocationCheckFailed)
    );
}

#[test]
fn ocsp_response_not_signed_by_the_responder_it_names() {
    let chain = Chain::new();
    let responder = Responder {
        signed_by: SignedBy::WrongKey,
        ..Responder::new(&chain)
    };

    assert_eq!(
        verify(&chain, Some(&responder)),
        refused(RevocationCheckFailed)
    );
}

#[test]
fn ocsp_revoked_certificate() {
    let chain = Chain::new();
    let responder = Responder::revoked(&chain);

    assert_eq!(
        verify(&chain, Some(&responder)),
        refused(RevocationCheckFailed)
    );
}

#[test]
fn ocsp_unknown_certificate() {
    let chain = Chain::new();
    let responder = Responder {
        status: CertStatus::Unknown(Null),
        ..Responder::new(&chain)
    };

    assert_eq!(
        verify(&chain, Some(&responder)),
        refused(RevocationCheckFailed)
    );
}

#[test]
fn ocsp_response_about_another_certificate() {
    let chain = Chain::new();
    let responder = Responder {
        other_serial: true,
        ..Responder::new(&chain)
    };

    assert_eq!(
        verify(&chain, Some(&responder)),
        refused(RevocationCheckFailed)
    );
}

#[test]
fn ocsp_response_with_a_sha_1_cert_id() {
    let chain = Chain::new();
    let responder = Responder {
        hash: ID_SHA_1,
        ..Responder::new(&chain)
    };

    assert_eq!(
        verify(&chain, Some(&responder)),
        Ok(chain.leaf_public_key())
    );
}

#[test]
fn ocsp_response_dates_allow_a_minute_of_skew() {
    let chain = Chain::new();
    let cases = [
        (NOW + 60, Some(NOW + 3_600), true),
        (NOW + 61, Some(NOW + 3_600), false),
        (NOW - 3_600, Some(NOW - 60), true),
        (NOW - 3_600, Some(NOW - 61), false),
        (NOW - 60, None, false),
    ];

    for (this_update, next_update, good) in cases {
        let responder = Responder {
            this_update,
            next_update,
            ..Responder::new(&chain)
        };

        let result = verify(&chain, Some(&responder));

        let expected = if good {
            Ok(chain.leaf_public_key())
        } else {
            refused(RevocationCheckFailed)
        };
        assert_eq!(
            result, expected,
            "thisUpdate {this_update}, nextUpdate {next_update:?}"
        );
    }
}

#[test]
fn ocsp_unsuccessful_response_status() {
    let chain = Chain::new();
    let response_status = OcspResponseStatus::TryLater;
    let responder = Responder {
        response_status,
        ..Responder::new(&chain)
    };

    assert_eq!(
        verify(&chain, Some(&responder)),
        refused(RevocationCheckFailed)
    );
    assert_eq!(responder.asked(), [INTERMEDIATE_OCSP_URL]);
}

#[test]
fn ocsp_unreadable_response() {
    let chain = Chain::new();

    assert_eq!(
        verify(&chain, Some(&Answers(b"garbage"))),
        refused(RevocationCheckFailed)
    );
}

#[test]
fn ocsp_certificate_without_a_responder() {
    let mut shape = Shape::apple_test();
    shape
        .leaf
        .retain(|ext| ext.extn_id != AuthorityInfoAccessSyntax::OID);
    let chain = Chain::shaped(shape);
    let responder = Responder::new(&chain);

    assert_eq!(
        verify(&chain, Some(&responder)),
        refused(RevocationCheckFailed)
    );
    assert_eq!(responder.asked(), [INTERMEDIATE_OCSP_URL]);
}

#[test]
fn ocsp_network_failure_is_retryable() {
    let chain = Chain::new();
    let responder = Responder {
        reachable: false,
        ..Responder::new(&chain)
    };

    assert_eq!(
        verify(&chain, Some(&responder)),
        refused(RetryableVerificationFailure)
    );
    assert_eq!(responder.asked(), [INTERMEDIATE_OCSP_URL]);
}

#[test]
fn ocsp_response_caching_has_expiration() {
    let chain = Chain::new();
    let responder = Responder::new(&chain);
    let verifier = ChainVerifier::new(vec![chain.root.clone()]).with_strict_checks(false);
    let check = |now| {
        verifier.verify_at(
            &chain.leaf,
            &chain.intermediate,
            None,
            Some(&responder),
            now,
        )
    };

    for now in [NOW, NOW + 1, NOW + 899] {
        assert_eq!(check(now), Ok(chain.leaf_public_key()));
        assert_eq!(responder.asked().len(), 2);
    }

    assert_eq!(check(NOW + 900), Ok(chain.leaf_public_key()));
    assert_eq!(responder.asked().len(), 4);
}

#[test]
fn ocsp_response_caching_with_different_chain() {
    let (first, second) = (Chain::new(), Chain::new());
    let (first_responder, second_responder) = (Responder::new(&first), Responder::new(&second));
    let verifier = ChainVerifier::new(vec![first.root.clone()]).with_strict_checks(false);

    verifier
        .verify_at(
            &first.leaf,
            &first.intermediate,
            None,
            Some(&first_responder),
            NOW,
        )
        .unwrap();
    verifier
        .verify_at(
            &second.leaf,
            &second.intermediate,
            None,
            Some(&second_responder),
            NOW,
        )
        .unwrap();

    assert_eq!(first_responder.asked().len(), 2);
    assert_eq!(second_responder.asked().len(), 2);
    assert_eq!(verifier.cache_len(), 2);
}

#[test]
fn offline_checks_are_not_cached() {
    let chain = Chain::new();
    let verifier = ChainVerifier::new(vec![chain.root.clone()]).with_strict_checks(false);

    verifier
        .verify_at(&chain.leaf, &chain.intermediate, None, None, NOW)
        .unwrap();

    assert_eq!(verifier.cache_len(), 0);
}

#[test]
fn ocsp_response_caching_evicts_expired_entries() {
    let verifier = ChainVerifier::new(Vec::new());
    for i in 0..MAXIMUM_CACHE_SIZE {
        verifier.store_public_key(
            format!("leaf{i}").as_bytes(),
            b"intermediate",
            format!("key{i}").as_bytes(),
            NOW,
        );
    }
    assert_eq!(verifier.cache_len(), MAXIMUM_CACHE_SIZE);

    verifier.store_public_key(b"leaf", b"intermediate", b"key", NOW + 1);
    assert_eq!(verifier.cache_len(), MAXIMUM_CACHE_SIZE + 1);

    verifier.store_public_key(b"newLeaf", b"intermediate", b"newKey", NOW + 900);
    assert_eq!(verifier.cache_len(), 2);
    assert_eq!(
        verifier.cached_public_key(b"leaf", b"intermediate", NOW + 900),
        Some(b"key".to_vec())
    );
    assert_eq!(
        verifier.cached_public_key(b"newLeaf", b"intermediate", NOW + 900),
        Some(b"newKey".to_vec())
    );
    assert_eq!(
        verifier.cached_public_key(b"leaf0", b"intermediate", NOW + 900),
        None
    );
}
