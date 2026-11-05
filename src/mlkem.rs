//! ML-KEM through CryptoKit, by way of the Swift shim in `swift/MLKEMShim.swift`, for CMS
//! KEMRecipientInfo.
//!
//! CryptoKit offers ML-KEM-768 and ML-KEM-1024 from macOS and iOS 26, for keys held in memory and
//! in the Secure Enclave. ML-KEM-512 is not among them, so it is declined and software answers it.
//! Each call is stateless: a private key crosses as its seed or its Secure Enclave
//! `dataRepresentation`. The shared secret does not cross at all; HKDF runs in CryptoKit, and what
//! comes back is the key-encryption key.

use certval_cms::{Error, KdfAlgorithm, Result};
use const_oid::db::fips203::{ID_ALG_ML_KEM_1024, ID_ALG_ML_KEM_768};
use const_oid::ObjectIdentifier;
use zeroize::Zeroizing;

extern "C" {
    fn certval_sf_mlkem_available() -> i32;
    fn certval_sf_secure_enclave_available() -> i32;
    fn certval_sf_mlkem_secure_enclave_generate(
        parameter_set: i32,
        data_out: *mut u8,
        data_capacity: usize,
        data_len: *mut usize,
        public_out: *mut u8,
        public_capacity: usize,
        public_len: *mut usize,
    ) -> i32;
    fn certval_sf_mlkem_secure_enclave_public_key(
        parameter_set: i32,
        data: *const u8,
        data_len: usize,
        public_out: *mut u8,
        public_capacity: usize,
        public_len: *mut usize,
    ) -> i32;
    fn certval_sf_mlkem_encapsulate(
        parameter_set: i32,
        key: *const u8,
        key_len: usize,
        hash: i32,
        info: *const u8,
        info_len: usize,
        ciphertext_out: *mut u8,
        ciphertext_capacity: usize,
        ciphertext_len: *mut usize,
        kek_out: *mut u8,
        kek_len: usize,
    ) -> i32;
    fn certval_sf_mlkem_decapsulate(
        parameter_set: i32,
        key_kind: i32,
        key: *const u8,
        key_len: usize,
        public_key: *const u8,
        public_key_len: usize,
        ciphertext: *const u8,
        ciphertext_len: usize,
        hash: i32,
        info: *const u8,
        info_len: usize,
        kek_out: *mut u8,
        kek_len: usize,
    ) -> i32;
}

/// Room for any ML-KEM-768 or ML-KEM-1024 public key (1568 octets) or ciphertext (1568 octets).
const MAX_KEM_LEN: usize = 1568;

/// Room for a Secure Enclave key's `dataRepresentation`, an opaque blob of a few hundred octets.
const MAX_SECURE_ENCLAVE_DATA_LEN: usize = 8192;

/// Returns whether the running OS has CryptoKit's ML-KEM.
pub(crate) fn available() -> bool {
    // SAFETY: the function takes no arguments and only checks the OS version.
    unsafe { certval_sf_mlkem_available() == 1 }
}

/// Returns whether the device has a Secure Enclave CryptoKit can use.
pub(crate) fn secure_enclave_available() -> bool {
    // SAFETY: the function takes no arguments.
    unsafe { certval_sf_secure_enclave_available() == 1 }
}

/// The CryptoKit parameter set for an ML-KEM key identified by `oid`, or `None` when CryptoKit has
/// no such parameter set.
pub(crate) fn parameter_set(oid: ObjectIdentifier) -> Option<i32> {
    match oid {
        ID_ALG_ML_KEM_768 => Some(768),
        ID_ALG_ML_KEM_1024 => Some(1024),
        _ => None,
    }
}

/// The hash the shim's HKDF takes for `kdf`, or `Unrecognized` for a KDF it does not offer.
fn hash(kdf: KdfAlgorithm) -> Result<i32> {
    match kdf {
        KdfAlgorithm::HkdfSha256 => Ok(256),
        KdfAlgorithm::HkdfSha384 => Ok(384),
        KdfAlgorithm::HkdfSha512 => Ok(512),
        _ => Err(Error::Unrecognized),
    }
}

/// A private ML-KEM key as the shim takes it.
pub(crate) enum PrivateKey<'a> {
    /// A key held in memory: its seed, and the raw public key it must generate.
    Seed {
        seed: &'a [u8],
        public_key: &'a [u8],
    },
    /// A Secure Enclave key's `dataRepresentation`.
    SecureEnclave(&'a [u8]),
}

/// Encapsulates to the raw public key `key` and returns the ciphertext and the key-encryption key
/// HKDF derives from the shared secret with `info`.
pub(crate) fn encapsulate(
    parameter_set: i32,
    key: &[u8],
    kdf: KdfAlgorithm,
    info: &[u8],
    kek_len: usize,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let hash = hash(kdf)?;
    let mut ciphertext = vec![0u8; MAX_KEM_LEN];
    let mut ciphertext_len = 0usize;
    let mut kek = Zeroizing::new(vec![0u8; kek_len]);
    // SAFETY: each pointer and length pair describes a slice live for the call; the shim writes at
    // most the capacity given into each output and its length into `ciphertext_len`.
    let result = unsafe {
        certval_sf_mlkem_encapsulate(
            parameter_set,
            key.as_ptr(),
            key.len(),
            hash,
            info.as_ptr(),
            info.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            &mut ciphertext_len,
            kek.as_mut_ptr(),
            kek.len(),
        )
    };
    match result {
        1 => {
            ciphertext.truncate(ciphertext_len);
            Ok((ciphertext, kek))
        }
        // The key is refused, or the OS has no ML-KEM: another implementation may take it.
        -1 | -2 => Err(Error::Unrecognized),
        _ => Err(Error::Crypto(String::from(
            "CryptoKit could not encapsulate",
        ))),
    }
}

/// Decapsulates `ciphertext` with `key` and returns the key-encryption key HKDF derives from the
/// shared secret with `info`.
pub(crate) fn decapsulate(
    parameter_set: i32,
    key: PrivateKey<'_>,
    ciphertext: &[u8],
    kdf: KdfAlgorithm,
    info: &[u8],
    kek_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let (kind, key, public_key): (i32, &[u8], &[u8]) = match key {
        PrivateKey::Seed { seed, public_key } => (0, seed, public_key),
        PrivateKey::SecureEnclave(data) => (1, data, &[]),
    };
    let hash = hash(kdf)?;
    let mut kek = Zeroizing::new(vec![0u8; kek_len]);
    // SAFETY: as for encapsulation; the shim writes exactly `kek_len` octets of key-encryption key.
    let result = unsafe {
        certval_sf_mlkem_decapsulate(
            parameter_set,
            kind,
            key.as_ptr(),
            key.len(),
            public_key.as_ptr(),
            public_key.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            hash,
            info.as_ptr(),
            info.len(),
            kek.as_mut_ptr(),
            kek.len(),
        )
    };
    match result {
        1 => Ok(kek),
        -2 => Err(Error::Unrecognized),
        _ => Err(Error::Crypto(String::from(
            "CryptoKit could not decapsulate",
        ))),
    }
}

/// Generates an ML-KEM key in the Secure Enclave and returns its `dataRepresentation` and raw
/// public key.
pub(crate) fn generate_in_secure_enclave(parameter_set: i32) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut data = vec![0u8; MAX_SECURE_ENCLAVE_DATA_LEN];
    let mut data_len = 0usize;
    let mut public_key = vec![0u8; MAX_KEM_LEN];
    let mut public_len = 0usize;
    // SAFETY: each output is a buffer of the capacity given, and each length a live usize.
    let result = unsafe {
        certval_sf_mlkem_secure_enclave_generate(
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
            "the Secure Enclave could not generate an ML-KEM key",
        ))),
    }
}

/// The raw public key of the Secure Enclave ML-KEM key whose `dataRepresentation` is `data`, or
/// `None` when the Secure Enclave refuses it, e.g. a key of another device.
pub(crate) fn secure_enclave_public_key(parameter_set: i32, data: &[u8]) -> Option<Vec<u8>> {
    let mut public_key = vec![0u8; MAX_KEM_LEN];
    let mut public_len = 0usize;
    // SAFETY: as for generation.
    let result = unsafe {
        certval_sf_mlkem_secure_enclave_public_key(
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

#[cfg(test)]
mod tests {
    use super::*;
    use const_oid::db::fips203::ID_ALG_ML_KEM_512;

    #[test]
    fn only_the_parameter_sets_cryptokit_offers() {
        assert_eq!(parameter_set(ID_ALG_ML_KEM_768), Some(768));
        assert_eq!(parameter_set(ID_ALG_ML_KEM_1024), Some(1024));
        assert_eq!(parameter_set(ID_ALG_ML_KEM_512), None);
    }

    #[test]
    fn a_garbage_public_key_is_declined() {
        assert!(matches!(
            encapsulate(768, &[0u8; 10], KdfAlgorithm::HkdfSha256, b"info", 32),
            Err(Error::Unrecognized)
        ));
    }
}
