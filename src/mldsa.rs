//! ML-DSA through CryptoKit, by way of the Swift shim in `swift/MLDSAShim.swift`: verification, and
//! under the `cms` feature, signing with a key held in memory or in the Secure Enclave.
//!
//! CryptoKit offers ML-DSA-65 and ML-DSA-87 from macOS and iOS 26. ML-DSA-44 is not among them, and
//! neither is SLH-DSA, so those are declined here and software answers them. Signing is stateless:
//! a private key crosses as its seed or its Secure Enclave `dataRepresentation` on each call.

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
    #[cfg(feature = "cms")]
    fn certval_sf_mldsa_sign(
        parameter_set: i32,
        key_kind: i32,
        key: *const u8,
        key_len: usize,
        public_key: *const u8,
        public_key_len: usize,
        message: *const u8,
        message_len: usize,
        signature_out: *mut u8,
        signature_capacity: usize,
        signature_len: *mut usize,
    ) -> i32;
    #[cfg(feature = "cms")]
    fn certval_sf_mldsa_secure_enclave_generate(
        parameter_set: i32,
        data_out: *mut u8,
        data_capacity: usize,
        data_len: *mut usize,
        public_out: *mut u8,
        public_capacity: usize,
        public_len: *mut usize,
    ) -> i32;
    #[cfg(feature = "cms")]
    fn certval_sf_mldsa_seed_public_key(
        parameter_set: i32,
        seed: *const u8,
        seed_len: usize,
        public_out: *mut u8,
        public_capacity: usize,
        public_len: *mut usize,
    ) -> i32;
    #[cfg(feature = "cms")]
    fn certval_sf_mldsa_secure_enclave_public_key(
        parameter_set: i32,
        data: *const u8,
        data_len: usize,
        public_out: *mut u8,
        public_capacity: usize,
        public_len: *mut usize,
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

/// Room for any ML-DSA-65 or ML-DSA-87 signature (4627 octets).
#[cfg(feature = "cms")]
const MAX_SIGNATURE_LEN: usize = 4627;

/// Room for any ML-DSA-65 or ML-DSA-87 public key (2592 octets).
#[cfg(feature = "cms")]
const MAX_PUBLIC_KEY_LEN: usize = 2592;

/// Room for a Secure Enclave key's `dataRepresentation`, an opaque blob of a few hundred octets.
#[cfg(feature = "cms")]
const MAX_SECURE_ENCLAVE_DATA_LEN: usize = 8192;

/// A private ML-DSA key as the shim takes it.
#[cfg(feature = "cms")]
pub(crate) enum PrivateKey<'a> {
    /// A key held in memory: its seed, and the raw public key it must generate.
    Seed {
        seed: &'a [u8],
        public_key: &'a [u8],
    },
    /// A Secure Enclave key's `dataRepresentation`.
    SecureEnclave(&'a [u8]),
}

/// Signs `message` with pure ML-DSA and an empty context string, returning the signature.
#[cfg(feature = "cms")]
pub(crate) fn sign(
    parameter_set: i32,
    key: PrivateKey<'_>,
    message: &[u8],
) -> certval_cms::Result<Vec<u8>> {
    use certval_cms::Error;
    let (kind, key, public_key): (i32, &[u8], &[u8]) = match key {
        PrivateKey::Seed { seed, public_key } => (0, seed, public_key),
        PrivateKey::SecureEnclave(data) => (1, data, &[]),
    };
    let mut signature = vec![0u8; MAX_SIGNATURE_LEN];
    let mut signature_len = 0usize;
    // SAFETY: each pointer and length pair describes a slice live for the call; the shim writes at
    // most the capacity given into the signature and its length into `signature_len`.
    let result = unsafe {
        certval_sf_mldsa_sign(
            parameter_set,
            kind,
            key.as_ptr(),
            key.len(),
            public_key.as_ptr(),
            public_key.len(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
            &mut signature_len,
        )
    };
    match result {
        1 => {
            signature.truncate(signature_len);
            Ok(signature)
        }
        -2 => Err(Error::Unrecognized),
        _ => Err(Error::Crypto(String::from("CryptoKit could not sign"))),
    }
}

/// Generates an ML-DSA key in the Secure Enclave and returns its `dataRepresentation` and raw
/// public key.
#[cfg(feature = "cms")]
pub(crate) fn generate_in_secure_enclave(
    parameter_set: i32,
) -> certval_cms::Result<(Vec<u8>, Vec<u8>)> {
    use certval_cms::Error;
    let mut data = vec![0u8; MAX_SECURE_ENCLAVE_DATA_LEN];
    let mut data_len = 0usize;
    let mut public_key = vec![0u8; MAX_PUBLIC_KEY_LEN];
    let mut public_len = 0usize;
    // SAFETY: each output is a buffer of the capacity given, and each length a live usize.
    let result = unsafe {
        certval_sf_mldsa_secure_enclave_generate(
            parameter_set,
            data.as_mut_ptr(),
            data.len(),
            &mut data_len,
            public_key.as_mut_ptr(),
            public_key.len(),
            &mut public_len,
        )
    };
    match result {
        1 => {
            data.truncate(data_len);
            public_key.truncate(public_len);
            Ok((data, public_key))
        }
        -1 | -2 => Err(Error::Unrecognized),
        _ => Err(Error::Crypto(String::from(
            "the Secure Enclave could not generate an ML-DSA key",
        ))),
    }
}

/// The raw public key of the Secure Enclave ML-DSA key whose `dataRepresentation` is `data`, or
/// `None` when the Secure Enclave refuses it, e.g. a key of another device.
#[cfg(feature = "cms")]
pub(crate) fn secure_enclave_public_key(parameter_set: i32, data: &[u8]) -> Option<Vec<u8>> {
    let mut public_key = vec![0u8; MAX_PUBLIC_KEY_LEN];
    let mut public_len = 0usize;
    // SAFETY: as for generation.
    let result = unsafe {
        certval_sf_mldsa_secure_enclave_public_key(
            parameter_set,
            data.as_ptr(),
            data.len(),
            public_key.as_mut_ptr(),
            public_key.len(),
            &mut public_len,
        )
    };
    (result == 1).then(|| {
        public_key.truncate(public_len);
        public_key
    })
}

/// The raw public key of the ML-DSA key `seed` generates, or `None` when CryptoKit refuses it.
#[cfg(feature = "cms")]
pub(crate) fn seed_public_key(parameter_set: i32, seed: &[u8]) -> Option<Vec<u8>> {
    let mut public_key = vec![0u8; MAX_PUBLIC_KEY_LEN];
    let mut public_len = 0usize;
    // SAFETY: as for the Secure Enclave public key.
    let result = unsafe {
        certval_sf_mldsa_seed_public_key(
            parameter_set,
            seed.as_ptr(),
            seed.len(),
            public_key.as_mut_ptr(),
            public_key.len(),
            &mut public_len,
        )
    };
    (result == 1).then(|| {
        public_key.truncate(public_len);
        public_key
    })
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
