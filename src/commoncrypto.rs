//! CommonCrypto, Apple's C interface to corecrypto, the cryptographic module Security.framework is
//! built on: message digests, and, under the `cms` feature, AES-CBC and AES key wrap (RFC 3394).

use std::ffi::c_void;

/// A digest CommonCrypto computes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Digest {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Digest {
    pub(crate) fn len(self) -> usize {
        match self {
            Digest::Sha1 => 20,
            Digest::Sha224 => 28,
            Digest::Sha256 => 32,
            Digest::Sha384 => 48,
            Digest::Sha512 => 64,
        }
    }
}

type DigestFn = unsafe extern "C" fn(data: *const c_void, len: u32, md: *mut u8) -> *mut u8;

extern "C" {
    fn CC_SHA1(data: *const c_void, len: u32, md: *mut u8) -> *mut u8;
    fn CC_SHA224(data: *const c_void, len: u32, md: *mut u8) -> *mut u8;
    fn CC_SHA256(data: *const c_void, len: u32, md: *mut u8) -> *mut u8;
    fn CC_SHA384(data: *const c_void, len: u32, md: *mut u8) -> *mut u8;
    fn CC_SHA512(data: *const c_void, len: u32, md: *mut u8) -> *mut u8;
}

/// The digest of `data`, or `None` for input longer than the one-shot functions take.
pub(crate) fn digest(digest: Digest, data: &[u8]) -> Option<Vec<u8>> {
    let len = u32::try_from(data.len()).ok()?;
    let function: DigestFn = match digest {
        Digest::Sha1 => CC_SHA1,
        Digest::Sha224 => CC_SHA224,
        Digest::Sha256 => CC_SHA256,
        Digest::Sha384 => CC_SHA384,
        Digest::Sha512 => CC_SHA512,
    };
    let mut md = vec![0u8; digest.len()];
    // SAFETY: `data` is live for `len` octets, and `md` holds the digest's length, which is all the
    // function writes.
    unsafe { function(data.as_ptr().cast(), len, md.as_mut_ptr()) };
    Some(md)
}

#[cfg(feature = "cms")]
pub(crate) use cipher::{aes_cbc, aes_key_unwrap, aes_key_wrap, Direction};

#[cfg(feature = "cms")]
mod cipher {
    use super::*;
    use std::ffi::c_int;

    const K_CC_SUCCESS: c_int = 0;
    const K_CC_ENCRYPT: u32 = 0;
    const K_CC_DECRYPT: u32 = 1;
    const K_CC_ALGORITHM_AES: u32 = 0;
    const K_CC_OPTION_PKCS7_PADDING: u32 = 1;
    const K_CC_WRAP_AES: u32 = 1;
    const AES_BLOCK: usize = 16;

    extern "C" {
        #[allow(clippy::too_many_arguments)]
        fn CCCrypt(
            op: u32,
            alg: u32,
            options: u32,
            key: *const c_void,
            key_length: usize,
            iv: *const c_void,
            data_in: *const c_void,
            data_in_length: usize,
            data_out: *mut c_void,
            data_out_available: usize,
            data_out_moved: *mut usize,
        ) -> c_int;

        static CCrfc3394_iv: *const u8;
        static CCrfc3394_ivLen: usize;

        #[allow(clippy::too_many_arguments)]
        fn CCSymmetricKeyWrap(
            algorithm: u32,
            iv: *const u8,
            iv_len: usize,
            kek: *const u8,
            kek_len: usize,
            raw_key: *const u8,
            raw_key_len: usize,
            wrapped_key: *mut u8,
            wrapped_key_len: *mut usize,
        ) -> c_int;

        #[allow(clippy::too_many_arguments)]
        fn CCSymmetricKeyUnwrap(
            algorithm: u32,
            iv: *const u8,
            iv_len: usize,
            kek: *const u8,
            kek_len: usize,
            wrapped_key: *const u8,
            wrapped_key_len: usize,
            raw_key: *mut u8,
            raw_key_len: *mut usize,
        ) -> c_int;
    }

    /// Whether CBC encrypts or decrypts.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum Direction {
        Encrypt,
        Decrypt,
    }

    /// AES-CBC with PKCS #7 padding, which CommonCrypto adds on encryption and this function
    /// checks and removes on decryption: CommonCrypto's own unpadding strips a trailing count
    /// without checking the padding octets or that the input is whole blocks, so it never fails.
    /// `None` if CommonCrypto refuses or, on decryption, if the input is empty or not whole blocks
    /// or the padding is malformed.
    pub(crate) fn aes_cbc(
        direction: Direction,
        key: &[u8],
        iv: &[u8],
        input: &[u8],
    ) -> Option<Vec<u8>> {
        if iv.len() != AES_BLOCK {
            return None;
        }
        let (op, options) = match direction {
            Direction::Encrypt => (K_CC_ENCRYPT, K_CC_OPTION_PKCS7_PADDING),
            Direction::Decrypt => {
                if input.is_empty() || !input.len().is_multiple_of(AES_BLOCK) {
                    return None;
                }
                (K_CC_DECRYPT, 0)
            }
        };
        let mut output = vec![0u8; input.len() + AES_BLOCK];
        let mut moved = 0usize;
        // SAFETY: every buffer is live with the length passed, and CommonCrypto writes at most
        // `output.len()` octets, reporting how many in `moved`.
        let status = unsafe {
            CCCrypt(
                op,
                K_CC_ALGORITHM_AES,
                options,
                key.as_ptr().cast(),
                key.len(),
                iv.as_ptr().cast(),
                input.as_ptr().cast(),
                input.len(),
                output.as_mut_ptr().cast(),
                output.len(),
                &mut moved,
            )
        };
        if status != K_CC_SUCCESS {
            return None;
        }
        output.truncate(moved);
        if direction == Direction::Decrypt {
            let unpadded = unpadded_len(&output)?;
            output.truncate(unpadded);
        }
        Some(output)
    }

    /// The length of `padded` without its PKCS #7 padding: the last octet is the count, 1 to the
    /// block length, and every one of that many trailing octets is the count. `None` otherwise.
    fn unpadded_len(padded: &[u8]) -> Option<usize> {
        let count = usize::from(*padded.last()?);
        if count == 0 || count > AES_BLOCK || count > padded.len() {
            return None;
        }
        let (content, padding) = padded.split_at(padded.len() - count);
        padding
            .iter()
            .all(|&octet| usize::from(octet) == count)
            .then_some(content.len())
    }

    /// Wraps `key` under `kek` with AES key wrap (RFC 3394).
    pub(crate) fn aes_key_wrap(kek: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        let mut wrapped = vec![0u8; key.len() + 8];
        let mut wrapped_len = wrapped.len();
        // SAFETY: every buffer is live with the length passed; the RFC 3394 IV is CommonCrypto's
        // own constant.
        let status = unsafe {
            CCSymmetricKeyWrap(
                K_CC_WRAP_AES,
                CCrfc3394_iv,
                CCrfc3394_ivLen,
                kek.as_ptr(),
                kek.len(),
                key.as_ptr(),
                key.len(),
                wrapped.as_mut_ptr(),
                &mut wrapped_len,
            )
        };
        if status != K_CC_SUCCESS {
            return None;
        }
        wrapped.truncate(wrapped_len);
        Some(wrapped)
    }

    /// Unwraps `wrapped` under `kek` with AES key wrap (RFC 3394). `None` on an integrity failure,
    /// which is what a wrong key-encryption key produces.
    pub(crate) fn aes_key_unwrap(kek: &[u8], wrapped: &[u8]) -> Option<Vec<u8>> {
        let mut key = vec![0u8; wrapped.len().checked_sub(8)?];
        let mut key_len = key.len();
        // SAFETY: as for wrapping.
        let status = unsafe {
            CCSymmetricKeyUnwrap(
                K_CC_WRAP_AES,
                CCrfc3394_iv,
                CCrfc3394_ivLen,
                kek.as_ptr(),
                kek.len(),
                wrapped.as_ptr(),
                wrapped.len(),
                key.as_mut_ptr(),
                &mut key_len,
            )
        };
        if status != K_CC_SUCCESS {
            return None;
        }
        key.truncate(key_len);
        Some(key)
    }
}
