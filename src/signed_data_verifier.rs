use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::{DecodeError, Engine};
use serde::de::DeserializeOwned;

use crate::chain_verifier::{ChainVerificationFailureReason, ChainVerifier, ChainVerifierError};
use crate::crypto::{jws, CryptoProvider};
use crate::models::app_store_environment::Environment;
use crate::models::app_transaction::AppTransaction;
use crate::models::decoded_realtime_request_body::DecodedRealtimeRequestBody;
use crate::models::decoded_signed_data::DecodedSignedData;
use crate::models::jws_renewal_info_decoded_payload::JWSRenewalInfoDecodedPayload;
use crate::models::jws_transaction_decoded_payload::JWSTransactionDecodedPayload;
use crate::models::response_body_v2_decoded_payload::ResponseBodyV2DecodedPayload;
use crate::ocsp::OcspFetcher;

#[derive(thiserror::Error, Debug)]
pub enum SignedDataVerifierError {
    #[error("VerificationFailure")]
    VerificationFailure,

    #[error("InvalidAppIdentifier")]
    InvalidAppIdentifier,

    #[error("InvalidEnvironment")]
    InvalidEnvironment,

    #[error("InvalidAppAppleId")]
    InvalidAppAppleId,

    #[error("InternalChainVerifierError")]
    InternalChainVerifierError(#[from] ChainVerifierError),

    #[error("InternalDecodeError: [{0}]")]
    InternalDecodeError(#[from] DecodeError),

    #[error("InternalDeserializationError: [{0}]")]
    InternalDeserializationError(#[from] serde_json::Error),

    #[error("InternalJWSError: [{0}]")]
    InternalJWSError(#[from] crate::crypto::jws::JwsError),
}

impl SignedDataVerifierError {
    /// Whether trying again later may succeed: an OCSP responder couldn't be reached during
    /// online checks, so the data's certificates couldn't be checked yet.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::InternalChainVerifierError(ChainVerifierError::VerificationFailure(
                ChainVerificationFailureReason::RetryableVerificationFailure
            ))
        )
    }
}

const EXPECTED_CHAIN_LENGTH: usize = 3;

///A verifier and decoder class designed to decode signed data from the App Store.
pub struct SignedDataVerifier {
    environment: Environment,
    bundle_id: String,
    app_apple_id: Option<i64>,
    online_checks: Option<Arc<dyn OcspFetcher>>,
    chain_verifier: ChainVerifier,
}

impl SignedDataVerifier {
    /// Creates a new `SignedDataVerifier` instance with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `root_certificates` - A vector of DER-encoded root certificates used for verification.
    /// * `environment` - The environment (e.g., `Environment::PRODUCTION` or `Environment::SANDBOX`).
    /// * `bundle_id` - The bundle ID associated with the application.
    /// * `app_apple_id` - An optional Apple ID associated with the application. Required when
    ///   `environment` is `Environment::Production`.
    /// * `online_checks` - With an OCSP fetcher, online checks, as Apple's libraries make them:
    ///   the certificates must be valid now (rather than when the data was signed), Apple's
    ///   OCSP responders are asked whether they've been revoked, and a verified chain's key is
    ///   remembered for 15 minutes. `None` checks the chain offline, at the data's signed date.
    ///
    /// # Returns
    ///
    /// - `Ok(SignedDataVerifier)` on success.
    /// - `Err(SignedDataVerifierError::InvalidAppAppleId)` if `environment` is
    ///   `Environment::Production` and `app_apple_id` is `None`.
    pub fn new(
        root_certificates: Vec<Vec<u8>>,
        environment: Environment,
        bundle_id: String,
        app_apple_id: Option<i64>,
        online_checks: Option<Arc<dyn OcspFetcher>>,
    ) -> Result<Self, SignedDataVerifierError> {
        if environment == Environment::Production && app_apple_id.is_none() {
            return Err(SignedDataVerifierError::InvalidAppAppleId);
        }

        Ok(SignedDataVerifier {
            environment,
            bundle_id,
            app_apple_id,
            online_checks,
            chain_verifier: ChainVerifier::new(root_certificates),
        })
    }

    /// Turns the certificate chain's strict checks on or off: see
    /// [`ChainVerifier::with_strict_checks`]. They're on by default.
    pub fn with_strict_checks(mut self, enabled: bool) -> Self {
        self.chain_verifier = self
            .chain_verifier
            .with_strict_checks(enabled);
        self
    }
}

impl SignedDataVerifier {
    /// Verifies and decodes a signedRenewalInfo obtained from the App Store Server API, an App Store Server Notification, or from a device
    /// See [JWSRenewalInfo](https://developer.apple.com/documentation/appstoreserverapi/jwsrenewalinfo)
    ///
    /// # Arguments
    ///
    /// * `signed_renewal_info` - The signed renewal info string to verify and decode.
    ///
    /// # Returns
    ///
    /// - `Ok(JWSRenewalInfoDecodedPayload)` if verification and decoding are successful.
    /// - `Err(SignedDataVerifierError)` if verification or decoding fails, with error details.
    pub fn verify_and_decode_renewal_info(
        &self,
        signed_renewal_info: &str,
    ) -> Result<JWSRenewalInfoDecodedPayload, SignedDataVerifierError> {
        let decoded_renewal_info: JWSRenewalInfoDecodedPayload = self.decode_signed_object(signed_renewal_info)?;

        if decoded_renewal_info
            .environment
            .as_ref()
            != Some(&self.environment)
        {
            return Err(SignedDataVerifierError::InvalidEnvironment);
        }

        Ok(decoded_renewal_info)
    }

    ///  Verifies and decodes a signedTransaction obtained from the App Store Server API, an App Store Server Notification, or from a device
    ///  See [JWSTransaction](https://developer.apple.com/documentation/appstoreserverapi/jwstransaction)
    ///
    /// # Arguments
    ///
    /// * `signed_transaction` - The signed transaction string to verify and decode.
    ///
    /// # Returns
    ///
    /// - `Ok(JWSTransactionDecodedPayload)` if verification and decoding are successful.
    /// - `Err(SignedDataVerifierError)` if verification or decoding fails, with error details.
    pub fn verify_and_decode_signed_transaction(
        &self,
        signed_transaction: &str,
    ) -> Result<JWSTransactionDecodedPayload, SignedDataVerifierError> {
        let decoded_signed_tx: JWSTransactionDecodedPayload = self.decode_signed_object(signed_transaction)?;

        if decoded_signed_tx.bundle_id.as_ref() != Some(&self.bundle_id) {
            return Err(SignedDataVerifierError::InvalidAppIdentifier);
        }

        if decoded_signed_tx.environment.as_ref() != Some(&self.environment) {
            return Err(SignedDataVerifierError::InvalidEnvironment);
        }

        Ok(decoded_signed_tx)
    }

    ///  Verifies and decodes an App Store Server Notification signedPayload
    ///  See [signedPayload](https://developer.apple.com/documentation/appstoreservernotifications/signedpayload)
    ///
    /// # Arguments
    ///
    /// * `signed_payload` - The signed notification string to verify and decode.
    ///
    /// # Returns
    ///
    /// - `Ok(ResponseBodyV2DecodedPayload)` if verification and decoding are successful.
    /// - `Err(SignedDataVerifierError)` if verification or decoding fails, with error details.
    pub fn verify_and_decode_notification(
        &self,
        signed_payload: &str,
    ) -> Result<ResponseBodyV2DecodedPayload, SignedDataVerifierError> {
        let decoded_signed_notification: ResponseBodyV2DecodedPayload = self.decode_signed_object(signed_payload)?;

        let bundle_id;
        let app_apple_id;
        let environment;

        if let Some(data) = &decoded_signed_notification.data {
            bundle_id = data.bundle_id.clone();
            app_apple_id = data.app_apple_id;
            environment = data.environment.clone();
        } else if let Some(summary) = &decoded_signed_notification.summary {
            bundle_id = summary.bundle_id.clone();
            app_apple_id = summary.app_apple_id;
            environment = summary.environment.clone();
        } else if let Some(external_purchase_token) = &decoded_signed_notification.external_purchase_token {
            bundle_id = external_purchase_token
                .bundle_id
                .clone();
            app_apple_id = external_purchase_token.app_apple_id;

            if let Some(external_purchase_id) = &external_purchase_token.external_purchase_id {
                if external_purchase_id.starts_with("SANDBOX") {
                    environment = Some(Environment::Sandbox)
                } else {
                    environment = Some(Environment::Production)
                }
            } else {
                environment = Some(Environment::Production)
            }
        } else if let Some(app_data) = &decoded_signed_notification.app_data {
            bundle_id = app_data.bundle_id.clone();
            app_apple_id = app_data.app_apple_id;
            environment = app_data.environment.clone();
        } else {
            bundle_id = None;
            app_apple_id = None;
            environment = None;
        }

        self.verify_notification_app_identifier_and_environment(bundle_id, app_apple_id, environment)?;

        Ok(decoded_signed_notification)
    }

    fn verify_notification_app_identifier_and_environment(
        &self,
        bundle_id: Option<String>,
        app_apple_id: Option<i64>,
        environment: Option<Environment>,
    ) -> Result<(), SignedDataVerifierError> {
        if self.environment == Environment::LocalTesting {
            return Ok(());
        }

        if bundle_id.as_deref() != Some(self.bundle_id.as_str())
            || (self.environment == Environment::Production && self.app_apple_id != app_apple_id)
        {
            return Err(SignedDataVerifierError::InvalidAppIdentifier);
        }

        if environment.as_ref() != Some(&self.environment) {
            return Err(SignedDataVerifierError::InvalidEnvironment);
        }

        Ok(())
    }

    ///Verifies and decodes a signed AppTransaction
    ///See [AppTransaction](https://developer.apple.com/documentation/storekit/apptransaction)
    ///
    /// # Arguments
    ///
    /// * `signed_app_transaction` - The signed app transaction string to verify and decode.
    ///
    /// # Returns
    ///
    /// - `Ok(AppTransaction)` if verification and decoding are successful.
    /// - `Err(SignedDataVerifierError)` if verification or decoding fails, with error details.
    pub fn verify_and_decode_app_transaction(
        &self,
        signed_app_transaction: &str,
    ) -> Result<AppTransaction, SignedDataVerifierError> {
        let decoded_app_transaction: AppTransaction = self.decode_signed_object(signed_app_transaction)?;

        if decoded_app_transaction
            .bundle_id
            .as_ref()
            != Some(&self.bundle_id)
            || (self.environment == Environment::Production
                && self.app_apple_id != decoded_app_transaction.app_apple_id)
        {
            return Err(SignedDataVerifierError::InvalidAppIdentifier);
        }

        if decoded_app_transaction
            .receipt_type
            .as_ref()
            != Some(&self.environment)
        {
            return Err(SignedDataVerifierError::InvalidEnvironment);
        }

        Ok(decoded_app_transaction)
    }

    ///Verifies and decodes a realtime request the App Store sends to your Get Retention Message endpoint.
    ///
    /// # Arguments
    ///
    /// * `signed_payload` - The payload the App Store server sends to your server.
    ///
    /// # Returns
    ///
    /// - `Ok(DecodedRealtimeRequestBody)` if verification and decoding are successful.
    /// - `Err(SignedDataVerifierError)` if verification or decoding fails, with error details.
    pub fn verify_and_decode_realtime_request(
        &self,
        signed_payload: &str,
    ) -> Result<DecodedRealtimeRequestBody, SignedDataVerifierError> {
        let decoded_realtime_request: DecodedRealtimeRequestBody = self.decode_signed_object(signed_payload)?;

        if self.environment == Environment::Production
            && self.app_apple_id != Some(decoded_realtime_request.app_apple_id)
        {
            return Err(SignedDataVerifierError::InvalidAppIdentifier);
        }

        if self.environment != decoded_realtime_request.environment {
            return Err(SignedDataVerifierError::InvalidEnvironment);
        }

        Ok(decoded_realtime_request)
    }

    /// Private method used for decoding a signed object (internal use).
    fn decode_signed_object<T: DeserializeOwned + DecodedSignedData>(
        &self,
        signed_obj: &str,
    ) -> Result<T, SignedDataVerifierError> {
        // Data is not signed by the App Store, and verification should be skipped.
        // The environment MUST be checked in the public method calling this.
        if self.environment == Environment::Xcode || self.environment == Environment::LocalTesting {
            let _ = jws::decode_header(signed_obj)?;
            return Ok(jws::decode_payload(signed_obj)?);
        }

        let header = jws::decode_header(signed_obj)?;

        if header.alg.as_deref() != Some("ES256") {
            return Err(SignedDataVerifierError::VerificationFailure);
        }

        let Some(x5c) = header.x5c else {
            return Err(SignedDataVerifierError::VerificationFailure);
        };

        if x5c.len() != EXPECTED_CHAIN_LENGTH {
            return Err(SignedDataVerifierError::InternalChainVerifierError(
                ChainVerifierError::VerificationFailure(ChainVerificationFailureReason::InvalidChainLength),
            ));
        }

        let chain: Vec<Vec<u8>> = x5c
            .iter()
            .map(|c| STANDARD.decode(c))
            .collect::<Result<_, DecodeError>>()?;

        let decoded_body: T = jws::decode_payload(signed_obj)?;

        // Online, the certificates must be valid now; offline, when the data was signed (now
        // when it carries no date).
        let effective_date = match self.online_checks {
            Some(_) => None,
            None => decoded_body
                .signed_date_optional()
                .map(|date| date.timestamp() as u64),
        };

        let spki = self.chain_verifier.verify(
            &chain[0],
            &chain[1],
            effective_date,
            self.online_checks.as_deref(),
        )?;

        let signature_bytes = jws::decode_signature_bytes(signed_obj)?;
        let raw: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| SignedDataVerifierError::VerificationFailure)?;

        let provider = CryptoProvider::default_provider();
        let public_key = provider
            .p256_signing
            .public_key(&spki)
            .map_err(|_| SignedDataVerifierError::VerificationFailure)?;

        let signing_input = jws::signing_input(signed_obj)?;
        public_key
            .is_valid_signature(&raw, signing_input.as_bytes())
            .map_err(|_| SignedDataVerifierError::VerificationFailure)?;

        Ok(decoded_body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_verifier::ChainVerificationFailureReason::InvalidChainLength;

    #[test]
    fn test_invalid_chain_length() {
        // The length check happens before any signature verification, so a
        // minimal unsigned JWS with a 4-element x5c is enough to exercise it
        // through the public API.
        let header = jws::b64url_encode(br#"{"alg":"ES256","x5c":["YQ","YQ","YQ","YQ"]}"#);
        let payload = jws::b64url_encode(b"{}");
        let signature = jws::b64url_encode(b"sig");
        let jws_token = format!("{header}.{payload}.{signature}");

        let verifier = SignedDataVerifier::new(
            vec![Vec::new()],
            Environment::Production,
            "com.example".into(),
            Some(1234),
            None,
        )
        .expect("valid config");

        let result = verifier.verify_and_decode_app_transaction(&jws_token);

        assert!(matches!(
            result.expect_err("expect error"),
            SignedDataVerifierError::InternalChainVerifierError(ChainVerifierError::VerificationFailure(
                InvalidChainLength
            ))
        ));
    }

    /// Online checks through the verifier: the chain's responders are asked, and the
    /// certificates must be valid now rather than when the data was signed.
    #[cfg(any(feature = "rust_crypto", feature = "aws_lc", feature = "ring"))]
    mod online {
        use std::time::{SystemTime, UNIX_EPOCH};

        use p256::ecdsa::signature::Signer;

        use super::*;
        use crate::chain_verifier::ChainVerificationFailureReason::{InvalidChain, RevocationCheckFailed};
        use crate::test_chain::{Chain, Responder, Shape, INTERMEDIATE_OCSP_URL, LEAF_OCSP_URL};

        fn now() -> u64 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        }

        /// A chain whose certificates are valid from a day ago, for as long as the test runs.
        fn chain() -> &'static Chain {
            Box::leak(Box::new(Chain::shaped_at(Shape::apple_test(), now())))
        }

        /// A transaction signed by the chain's leaf on `signed_date` (Unix seconds).
        fn transaction(chain: &Chain, signed_date: u64) -> String {
            let x5c = [&chain.leaf, &chain.intermediate, &chain.root].map(|der| STANDARD.encode(der));
            let header = serde_json::json!({ "alg": "ES256", "x5c": x5c });
            let payload = serde_json::json!({
                "bundleId": "com.example",
                "environment": "Production",
                "signedDate": signed_date * 1000,
            });
            let input = format!(
                "{}.{}",
                jws::b64url_encode(header.to_string().as_bytes()),
                jws::b64url_encode(payload.to_string().as_bytes())
            );

            let signature: p256::ecdsa::Signature = chain.leaf_key.sign(input.as_bytes());
            format!("{input}.{}", jws::b64url_encode(&signature.to_bytes()))
        }

        fn verifier(chain: &Chain, online_checks: Option<Arc<dyn OcspFetcher>>) -> SignedDataVerifier {
            SignedDataVerifier::new(
                vec![chain.root.clone()],
                Environment::Production,
                "com.example".into(),
                Some(1234),
                online_checks,
            )
            .unwrap()
            .with_strict_checks(false)
        }

        fn chain_failure(reason: ChainVerificationFailureReason) -> SignedDataVerifierError {
            SignedDataVerifierError::InternalChainVerifierError(ChainVerifierError::VerificationFailure(reason))
        }

        #[test]
        fn online_checks_ask_the_responders_and_use_the_time_now() {
            let chain = chain();
            let responder = Arc::new(Responder::new(chain));
            // Signed before the certificates were issued: only valid now.
            let signed_long_ago = transaction(chain, now() - 30 * 86_400);

            let result =
                verifier(chain, Some(responder.clone())).verify_and_decode_signed_transaction(&signed_long_ago);

            assert!(result.is_ok(), "{result:?}");
            assert_eq!(responder.asked(), [INTERMEDIATE_OCSP_URL, LEAF_OCSP_URL]);
        }

        #[test]
        fn offline_checks_use_the_signed_date() {
            let chain = chain();

            let signed_long_ago = transaction(chain, now() - 30 * 86_400);
            let error = verifier(chain, None)
                .verify_and_decode_signed_transaction(&signed_long_ago)
                .unwrap_err();
            assert_eq!(error.to_string(), chain_failure(InvalidChain).to_string());

            let signed_now = transaction(chain, now());
            let result = verifier(chain, None).verify_and_decode_signed_transaction(&signed_now);
            assert!(result.is_ok(), "{result:?}");
        }

        #[test]
        fn an_unreachable_responder_is_retryable() {
            let chain = chain();
            let responder = Arc::new(Responder {
                reachable: false,
                ..Responder::new(chain)
            });

            let error = verifier(chain, Some(responder))
                .verify_and_decode_signed_transaction(&transaction(chain, now()))
                .unwrap_err();

            assert!(error.is_retryable(), "{error:?}");
        }

        #[test]
        fn a_revoked_certificate_is_not_retryable() {
            let chain = chain();
            let responder = Arc::new(Responder::revoked(chain));

            let error = verifier(chain, Some(responder))
                .verify_and_decode_signed_transaction(&transaction(chain, now()))
                .unwrap_err();

            assert!(!error.is_retryable());
            assert_eq!(
                error.to_string(),
                chain_failure(RevocationCheckFailed).to_string()
            );
        }
    }
}
