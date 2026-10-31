//! The provider that implements certval's verification interfaces against Security.framework.

use crate::algorithm::{digest_algorithm, message_algorithm, KeyKind};
use crate::key::{create_public_key, key_data};
use certval::{
    PathValidationStatus, PkiEnvironment, VerifySignatureDigest, VerifySignatureMessage,
};
use der::asn1::BitString;
use log::debug;
use security_framework_sys::key::Algorithm;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

/// The `OSStatus` Security.framework reports when it checked a signature and found it invalid
/// (`errSecVerifyFailed`). Every other error is a refusal to check, not a verdict.
const ERR_SEC_VERIFY_FAILED: isize = -67808;

/// A [`certval`] crypto provider backed by Security.framework.
///
/// The value holds no state: each verification imports the issuer's key, verifies, and releases
/// the key. Importing a public key is an in-process call with no session behind it, so there is
/// no round trip for a cache to save. The same value can be registered in both roles:
///
/// ```no_run
/// # use certval::PkiEnvironment;
/// # use certval_security_framework::SecurityFrameworkCrypto;
/// # let mut pe = PkiEnvironment::default();
/// pe.add_verify_signature_message_callback(SecurityFrameworkCrypto::new());
/// pe.add_verify_signature_digest_callback(SecurityFrameworkCrypto::new());
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct SecurityFrameworkCrypto {
    _private: (),
}

impl SecurityFrameworkCrypto {
    /// Returns a provider.
    pub fn new() -> Self {
        SecurityFrameworkCrypto { _private: () }
    }

    /// Reports whether ML-DSA signatures will be verified by CryptoKit: true only when the crate
    /// was built with the `pqc` feature and the running OS is macOS or iOS 26 or later.
    pub fn ml_dsa_available() -> bool {
        #[cfg(feature = "pqc")]
        {
            crate::mldsa::available()
        }
        #[cfg(not(feature = "pqc"))]
        {
            false
        }
    }

    /// Verifies `data` against `signature` with `algorithm`, reporting the outcome in the terms
    /// certval's interfaces are defined in.
    fn verify_with(
        &self,
        spki: &SubjectPublicKeyInfoOwned,
        kind: KeyKind,
        algorithm: Algorithm,
        data: &[u8],
        signature: &[u8],
    ) -> certval::Result<()> {
        let Some((key_bytes, key_type)) = key_data(spki, kind) else {
            return Err(certval::Error::Unrecognized);
        };
        let Some(key) = create_public_key(key_bytes, key_type) else {
            return Err(certval::Error::Unrecognized);
        };

        match key.verify_signature(algorithm, data, signature) {
            // Security.framework verified the signature.
            Ok(true) => Ok(()),

            // Security.framework reached a verdict and it was negative. The environment treats
            // this as final and consults no other implementation.
            Ok(false) => Err(certval::Error::PathValidation(
                PathValidationStatus::SignatureVerificationFailure,
            )),
            Err(e) if e.code() == ERR_SEC_VERIFY_FAILED => Err(certval::Error::PathValidation(
                PathValidationStatus::SignatureVerificationFailure,
            )),

            // Any other error is Security.framework declining the request (a digest of the wrong
            // length, or a key it cannot use with the algorithm) rather than judging the
            // signature, so another implementation answers.
            Err(e) => {
                debug!("Security.framework could not verify a signature: {e}");
                Err(certval::Error::Unrecognized)
            }
        }
    }
}

impl VerifySignatureMessage for SecurityFrameworkCrypto {
    fn verify_signature_message(
        &self,
        _pe: &PkiEnvironment,
        message_to_verify: &[u8],
        signature: &BitString,
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> certval::Result<()> {
        #[cfg(feature = "pqc")]
        if let Some(parameter_set) = crate::mldsa::parameter_set(signature_alg) {
            use crate::mldsa::Verdict;
            let signature = signature.as_bytes().ok_or(certval::Error::ParseError)?;
            return match crate::mldsa::verify(
                parameter_set,
                signature_alg,
                spki,
                message_to_verify,
                signature,
            ) {
                Verdict::Valid => Ok(()),
                Verdict::Invalid => Err(certval::Error::PathValidation(
                    PathValidationStatus::SignatureVerificationFailure,
                )),
                Verdict::Declined => Err(certval::Error::Unrecognized),
            };
        }

        let Some((algorithm, kind)) = message_algorithm(signature_alg) else {
            return Err(certval::Error::Unrecognized);
        };
        let signature = signature.as_bytes().ok_or(certval::Error::ParseError)?;
        self.verify_with(spki, kind, algorithm, message_to_verify, signature)
    }
}

impl VerifySignatureDigest for SecurityFrameworkCrypto {
    fn verify_signature_digest(
        &self,
        _pe: &PkiEnvironment,
        hash_to_verify: &[u8],
        signature: &BitString,
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> certval::Result<()> {
        let Some((algorithm, kind)) = digest_algorithm(signature_alg) else {
            return Err(certval::Error::Unrecognized);
        };
        let signature = signature.as_bytes().ok_or(certval::Error::ParseError)?;
        self.verify_with(spki, kind, algorithm, hash_to_verify, signature)
    }
}
