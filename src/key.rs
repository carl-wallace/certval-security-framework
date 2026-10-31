//! Turning a `SubjectPublicKeyInfo` into a Security.framework public key.
//!
//! `SecKeyCreateWithData` takes the key in the form the `subjectPublicKey` `BIT STRING` already
//! holds: a PKCS #1 `RSAPublicKey` for RSA, and an uncompressed X9.63 point for elliptic curve
//! keys. What it does not take is the curve. Security.framework infers the curve from the length
//! of the point, so a point on any other 256-bit curve would be read as a P-256 point. The named
//! curve in the algorithm parameters is therefore checked here, before the platform sees the key.
//!
//! This is the one module in the crate that calls Security.framework directly, because the
//! `security-framework` crate wraps key generation but not key import.

use crate::algorithm::KeyKind;
use certval::{
    PKIXALG_EC_PUBLIC_KEY, PKIXALG_RSASSA_PSS, PKIXALG_RSA_ENCRYPTION, PKIXALG_SECP256R1,
    PKIXALG_SECP384R1, PKIXALG_SECP521R1,
};
use const_oid::ObjectIdentifier;
use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::{CFError, CFErrorRef};
use core_foundation::string::CFString;
use log::debug;
use security_framework::key::SecKey;
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyClassPublic, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeyTypeRSA,
};
use security_framework_sys::key::SecKeyCreateWithData;
use spki::SubjectPublicKeyInfoOwned;

/// The key type a `SecKeyCreateWithData` call is made with.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum PlatformKeyType {
    Rsa,
    Ec,
}

/// Returns the bytes and key type to import `spki` with, or `None` when the key is not one
/// Security.framework can be relied on to interpret.
///
/// An RSA key for a PKCS #1 v1.5 signature must be identified as `rsaEncryption`: RFC 4055
/// restricts a key identified as `id-RSASSA-PSS` to PSS, and certval's software verifier rejects
/// the combination, so it is declined here and software gives that verdict. An RSA key for a PSS
/// signature is accepted under either identifier, since the key material is the same
/// `RSAPublicKey` in both. An elliptic curve key must name P-256, P-384 or P-521 and carry an
/// uncompressed point of the length that curve implies.
pub(crate) fn key_data(
    spki: &SubjectPublicKeyInfoOwned,
    kind: KeyKind,
) -> Option<(&[u8], PlatformKeyType)> {
    let bits = spki.subject_public_key.as_bytes()?;
    match kind {
        KeyKind::Rsa => {
            if spki.algorithm.oid != PKIXALG_RSA_ENCRYPTION {
                return None;
            }
            Some((bits, PlatformKeyType::Rsa))
        }
        KeyKind::RsaPss => {
            if spki.algorithm.oid != PKIXALG_RSA_ENCRYPTION
                && spki.algorithm.oid != PKIXALG_RSASSA_PSS
            {
                return None;
            }
            Some((bits, PlatformKeyType::Rsa))
        }
        KeyKind::Ec => {
            if spki.algorithm.oid != PKIXALG_EC_PUBLIC_KEY {
                return None;
            }
            let curve = spki
                .algorithm
                .parameters
                .as_ref()?
                .decode_as::<ObjectIdentifier>()
                .ok()?;
            let point_len = match curve {
                PKIXALG_SECP256R1 => 65,
                PKIXALG_SECP384R1 => 97,
                PKIXALG_SECP521R1 => 133,
                _ => return None,
            };
            if bits.len() != point_len || bits[0] != 0x04 {
                return None;
            }
            Some((bits, PlatformKeyType::Ec))
        }
    }
}

/// Creates a public `SecKey` from `data`, or `None` when the platform refuses it.
pub(crate) fn create_public_key(data: &[u8], key_type: PlatformKeyType) -> Option<SecKey> {
    // SAFETY: the attribute names and values are immutable constants exported by
    // Security.framework, so taking them under the get rule neither leaks nor frees them.
    let attributes = unsafe {
        let type_value = match key_type {
            PlatformKeyType::Rsa => kSecAttrKeyTypeRSA,
            PlatformKeyType::Ec => kSecAttrKeyTypeECSECPrimeRandom,
        };
        CFDictionary::<CFString, CFType>::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(type_value).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyClass),
                CFString::wrap_under_get_rule(kSecAttrKeyClassPublic).as_CFType(),
            ),
        ])
    };
    let data = CFData::from_buffer(data);

    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: both arguments are live CF objects owned by this frame, and `error` is a valid
    // out-pointer. A non-null key and a non-null error are each returned under the create rule,
    // so each is wrapped exactly once.
    unsafe {
        let key = SecKeyCreateWithData(
            data.as_concrete_TypeRef(),
            attributes.as_concrete_TypeRef(),
            &mut error,
        );
        if !error.is_null() {
            let error = CFError::wrap_under_create_rule(error);
            debug!("Security.framework declined to import a public key: {error}");
        }
        if key.is_null() {
            return None;
        }
        Some(SecKey::wrap_under_create_rule(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::{Any, BitString};
    use spki::AlgorithmIdentifierOwned;

    fn ec_spki(curve: ObjectIdentifier, point: &[u8]) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: PKIXALG_EC_PUBLIC_KEY,
                parameters: Some(Any::encode_from(&curve).unwrap()),
            },
            subject_public_key: BitString::from_bytes(point).unwrap(),
        }
    }

    fn uncompressed(len: usize) -> Vec<u8> {
        let mut point = vec![0x11u8; len];
        point[0] = 0x04;
        point
    }

    #[test]
    fn each_supported_curve_needs_its_own_point_length() {
        for (curve, len) in [
            (PKIXALG_SECP256R1, 65),
            (PKIXALG_SECP384R1, 97),
            (PKIXALG_SECP521R1, 133),
        ] {
            let ok = ec_spki(curve, &uncompressed(len));
            assert!(key_data(&ok, KeyKind::Ec).is_some(), "{curve}");
            let short = ec_spki(curve, &uncompressed(len - 2));
            assert!(key_data(&short, KeyKind::Ec).is_none(), "{curve}");
        }
    }

    #[test]
    fn a_256_bit_point_on_another_curve_is_declined() {
        // brainpoolP256r1. The point is the same length as a P-256 point, which is exactly what
        // Security.framework would mistake for one.
        let brainpool = ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.7");
        let spki = ec_spki(brainpool, &uncompressed(65));
        assert!(key_data(&spki, KeyKind::Ec).is_none());
    }

    #[test]
    fn a_compressed_point_is_declined() {
        let mut point = uncompressed(65);
        point[0] = 0x02;
        assert!(key_data(&ec_spki(PKIXALG_SECP256R1, &point), KeyKind::Ec).is_none());
    }

    #[test]
    fn key_kind_must_match_the_key_algorithm() {
        let ec = ec_spki(PKIXALG_SECP256R1, &uncompressed(65));
        assert!(key_data(&ec, KeyKind::Rsa).is_none());
    }

    #[test]
    fn a_pss_key_verifies_only_pss() {
        let pss_key = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: PKIXALG_RSASSA_PSS,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&[0x30, 0x00]).unwrap(),
        };
        assert!(key_data(&pss_key, KeyKind::Rsa).is_none());
        assert!(key_data(&pss_key, KeyKind::RsaPss).is_some());
    }

    #[test]
    fn garbage_is_refused_by_the_platform() {
        assert!(create_public_key(&[0x30, 0x03, 0x02, 0x01, 0x00], PlatformKeyType::Rsa).is_none());
        assert!(create_public_key(&uncompressed(65), PlatformKeyType::Ec).is_none());
    }
}
