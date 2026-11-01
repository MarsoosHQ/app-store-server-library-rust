# Changelog

All notable changes to this project are documented in this file.

## [7.0.0]

MarsoosHQ's fork. Certificate chains are checked the way Apple's own libraries check them, and online checks ask Apple's OCSP responders again.

### Added

- **OCSP revocation checks** during online checks, as Apple's libraries make them (RFC 6960). The intermediate and the leaf are each checked with the responders named in their Authority Information Access. An answer counts only when all of these hold:
  - it's signed by the certificate's issuer, or by a responder the issuer delegated to (with the OCSP signing extended key usage);
  - it's about this certificate;
  - it says the certificate is good;
  - it's fresh, give or take 60 seconds.

  The crate does no networking: the caller supplies an `OcspFetcher` (the new `ocsp` module).
- `SignedDataVerifierError::is_retryable()`: an OCSP responder couldn't be reached.
- **Strict checks**, on by default, as in Apple's libraries (OpenSSL's `X509_STRICT`):
  - every certificate is version 3, with non-empty names;
  - a CA has critical basic constraints, key usage and a subject key identifier;
  - the leaf and the intermediate have an authority key identifier;
  - only a CA has a path length or keyCertSign.

  `ChainVerifier::with_strict_checks` and `SignedDataVerifier::with_strict_checks` turn them off, for test certificates.
- The failure reasons `InvalidChain`, `RevocationCheckFailed` and `RetryableVerificationFailure`.

### Changed

- **Breaking:** `SignedDataVerifier::new` takes `online_checks: Option<Arc<dyn OcspFetcher>>` instead of `enable_online_checks: bool`. Online checks require the certificates to be valid now, ask the OCSP responders, and remember a verified chain for 15 minutes.
- **Breaking:** `ChainVerifier::verify` and `verify_at` take `ocsp: Option<&dyn OcspFetcher>` instead of a `bool`.
- This crate now verifies certificate chains itself, on RustCrypto (`x509-cert`, `p256`, `p384`), instead of through `x509-validator`. That holds whichever backend signs and verifies the JWS. The checks follow Apple's:
  - the names and signatures that link the chain (ECDSA with SHA-256 or SHA-384, the outer and inner algorithms the same);
  - validity dates;
  - CA basic constraints, key usage and path lengths;
  - a leaf that may sign and isn't a CA;
  - no critical extension left unchecked;
  - Apple's OIDs.
- A chain that doesn't verify now fails with `InvalidChain`. `InvalidCertificate` now means a certificate that can't be read, or no trusted roots.

### Removed

- The `x509-validator` dependency.
- The `chain/verify_cached` benchmark: caching needs online checks, and online checks need an OCSP responder.

## [6.0.1]

### Added

- `NotificationTypeV2::raw_value()`, returning the string Apple sends in `notificationType`.

### Changed

- Updated `x509-validator` to 0.3.1.
- Updated dependencies: `aws-lc-rs`, `serde_with`, `uuid`, `reqwest` and `thiserror`.

### Removed

- The unused `serde_repr` dependency.

## [6.0.0]

A major release that restructures the crate to mirror the Swift reference library, makes the crypto backend pluggable, and updates the models to the latest Apple API versions.

### Supported API versions

| API | 4.3.0 | 6.0.0 |
|-----|-------|-------|
| App Store Server API | 1.19 | 1.21 |
| Retention Messaging API | 1.3 | 1.5 |
| Advanced Commerce API | 1.2 | 1.2 |

### Added

- **Pluggable crypto backends.** Every cryptographic operation now goes through a `CryptoProvider`, backed by one of three mutually interchangeable implementations selected by crate feature:
  - `aws_lc` — [aws-lc-rs](https://github.com/aws/aws-lc-rs) (fastest)
  - `ring` — [ring](https://github.com/briansmith/ring)
  - `rust_crypto` — pure Rust 

- `IntroductoryOfferEligibilitySignatureCreator` for signing introductory offer eligibility JWS.
- Explicit reqwest TLS backend features, `reqwest-tls-rustls` and `reqwest-tls-native`. Enabling the reqwest transport without a TLS backend is now a compile error rather than a runtime connection failure.

### Changed

Breaking changes are listed in the migration table below.

- Certificate chain verification is delegated to the [`x509-validator`](https://github.com/namecare/x509-validator) crate.
- Module layout, API client method names, and model naming now follow the Swift library.
- API responses with no body are handled correctly by status code.

### Removed

- **The `ocsp` feature.** Online certificate revocation checking is no longer part of this crate; chain verification moved to `x509-validator`.
- The `primitives` module (renamed to `models`) and the `api_client::api` module tree.

## [4.3.0] and earlier

See the [release history](https://github.com/namecare/app-store-server-library-rust/releases).