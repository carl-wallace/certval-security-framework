//! ML-DSA verification through CryptoKit, by way of the Swift shim in `swift/MLDSAShim.swift`.
//!
//! CryptoKit offers ML-DSA-65 and ML-DSA-87 from macOS and iOS 26. ML-DSA-44 is not among them, and
//! neither is SLH-DSA, so those are declined here and software answers them.

use const_oid::db::fips204::{ID_ML_DSA_65, ID_ML_DSA_87};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

extern "C" {
    fn certval_sf_mldsa_available() -> i32;
    fn certval_sf_mldsa_verify(
        parameter_set: i32,
        key: *const u8,
        key_len: usize,
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
    ) -> i32;
}

/// What CryptoKit made of an ML-DSA signature.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Verdict {
    Valid,
    Invalid,
    /// CryptoKit refused the key, or the running OS has no ML-DSA.
    Declined,
}

/// Returns whether the running OS has CryptoKit's ML-DSA.
pub(crate) fn available() -> bool {
    // SAFETY: the function takes no arguments and only checks the OS version.
    unsafe { certval_sf_mldsa_available() == 1 }
}

/// Returns the CryptoKit parameter set for a pure ML-DSA signature algorithm, or `None` when
/// CryptoKit has no such parameter set. RFC 9881 requires the parameters to be absent.
pub(crate) fn parameter_set(alg: &AlgorithmIdentifierOwned) -> Option<i32> {
    if alg.parameters.is_some() {
        return None;
    }
    match alg.oid {
        ID_ML_DSA_65 => Some(65),
        ID_ML_DSA_87 => Some(87),
        _ => None,
    }
}

/// Verifies `signature` over `message` with the ML-DSA key in `spki`, which must be identified by
/// the same object identifier as the signature and carry no parameters.
pub(crate) fn verify(
    parameter_set: i32,
    signature_alg: &AlgorithmIdentifierOwned,
    spki: &SubjectPublicKeyInfoOwned,
    message: &[u8],
    signature: &[u8],
) -> Verdict {
    if spki.algorithm.oid != signature_alg.oid || spki.algorithm.parameters.is_some() {
        return Verdict::Declined;
    }
    let Some(key) = spki.subject_public_key.as_bytes() else {
        return Verdict::Declined;
    };
    // SAFETY: each pointer and length pair describes a slice that is live for the call, and the
    // shim copies the bytes before returning.
    let result = unsafe {
        certval_sf_mldsa_verify(
            parameter_set,
            key.as_ptr(),
            key.len(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
        )
    };
    match result {
        1 => Verdict::Valid,
        0 => Verdict::Invalid,
        _ => Verdict::Declined,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use const_oid::db::fips204::ID_ML_DSA_44;
    use der::asn1::Any;

    fn plain(oid: const_oid::ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
    }

    #[test]
    fn only_the_parameter_sets_cryptokit_offers() {
        assert_eq!(parameter_set(&plain(ID_ML_DSA_65)), Some(65));
        assert_eq!(parameter_set(&plain(ID_ML_DSA_87)), Some(87));
        assert_eq!(parameter_set(&plain(ID_ML_DSA_44)), None);
    }

    #[test]
    fn parameters_are_not_recognized() {
        let alg = AlgorithmIdentifierOwned {
            oid: ID_ML_DSA_65,
            parameters: Some(Any::null()),
        };
        assert_eq!(parameter_set(&alg), None);
    }

    #[test]
    fn a_garbage_key_is_declined_not_judged() {
        let alg = plain(ID_ML_DSA_65);
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: alg.clone(),
            subject_public_key: der::asn1::BitString::from_bytes(&[0u8; 10]).unwrap(),
        };
        assert_eq!(verify(65, &alg, &spki, b"m", &[0u8; 10]), Verdict::Declined);
    }
}
