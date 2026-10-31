//! Translation from the algorithm identifiers certval presents to the `SecKeyAlgorithm` constants
//! Security.framework understands.
//!
//! certval separates verification into two interfaces: one that is handed a message and hashes it,
//! and one that is handed a digest that has already been calculated. Security.framework draws the
//! same line, in that `...SignatureMessage...` algorithms hash the data themselves while
//! `...SignatureDigest...` algorithms operate on a digest, so each interface maps onto its own
//! family of constants.

use certval::{
    PKIXALG_ECDSA_WITH_SHA224, PKIXALG_ECDSA_WITH_SHA256, PKIXALG_ECDSA_WITH_SHA384,
    PKIXALG_ECDSA_WITH_SHA512, PKIXALG_MGF1, PKIXALG_RSASSA_PSS, PKIXALG_SHA224,
    PKIXALG_SHA224_WITH_RSA_ENCRYPTION, PKIXALG_SHA256, PKIXALG_SHA256_WITH_RSA_ENCRYPTION,
    PKIXALG_SHA384, PKIXALG_SHA384_WITH_RSA_ENCRYPTION, PKIXALG_SHA512,
    PKIXALG_SHA512_WITH_RSA_ENCRYPTION,
};
use der::{Decode, Encode};
use security_framework_sys::key::Algorithm;
use spki::AlgorithmIdentifierOwned;

/// The shape of public key a signature algorithm implies, which determines how the key is
/// imported.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum KeyKind {
    /// An RSA key used for PKCS #1 v1.5, imported as a PKCS #1 `RSAPublicKey`.
    Rsa,
    /// An RSA key used for RSASSA-PSS, imported the same way. Kept apart from [`KeyKind::Rsa`]
    /// because a key identified as `id-RSASSA-PSS` may verify only PSS signatures.
    RsaPss,
    /// An elliptic curve key, imported as an uncompressed X9.63 point.
    Ec,
}

/// The SHA-2 hash a signature algorithm is built on. SHA-1 is absent because certval defines no
/// SHA-1 signature algorithm for the provider to be handed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Hash {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn from_oid(oid: &const_oid::ObjectIdentifier) -> Option<Self> {
        match *oid {
            PKIXALG_SHA224 => Some(Hash::Sha224),
            PKIXALG_SHA256 => Some(Hash::Sha256),
            PKIXALG_SHA384 => Some(Hash::Sha384),
            PKIXALG_SHA512 => Some(Hash::Sha512),
            _ => None,
        }
    }

    fn len(self) -> u32 {
        match self {
            Hash::Sha224 => 28,
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }
}

/// Returns the algorithm that verifies a signature over a message, hashing the message inside
/// Security.framework, together with the kind of key it needs.
pub(crate) fn message_algorithm(alg: &AlgorithmIdentifierOwned) -> Option<(Algorithm, KeyKind)> {
    use Algorithm as A;
    match alg.oid {
        PKIXALG_SHA224_WITH_RSA_ENCRYPTION => {
            Some((A::RSASignatureMessagePKCS1v15SHA224, KeyKind::Rsa))
        }
        PKIXALG_SHA256_WITH_RSA_ENCRYPTION => {
            Some((A::RSASignatureMessagePKCS1v15SHA256, KeyKind::Rsa))
        }
        PKIXALG_SHA384_WITH_RSA_ENCRYPTION => {
            Some((A::RSASignatureMessagePKCS1v15SHA384, KeyKind::Rsa))
        }
        PKIXALG_SHA512_WITH_RSA_ENCRYPTION => {
            Some((A::RSASignatureMessagePKCS1v15SHA512, KeyKind::Rsa))
        }

        PKIXALG_ECDSA_WITH_SHA224 => Some((A::ECDSASignatureMessageX962SHA224, KeyKind::Ec)),
        PKIXALG_ECDSA_WITH_SHA256 => Some((A::ECDSASignatureMessageX962SHA256, KeyKind::Ec)),
        PKIXALG_ECDSA_WITH_SHA384 => Some((A::ECDSASignatureMessageX962SHA384, KeyKind::Ec)),
        PKIXALG_ECDSA_WITH_SHA512 => Some((A::ECDSASignatureMessageX962SHA512, KeyKind::Ec)),

        PKIXALG_RSASSA_PSS => {
            let algorithm = match pss_hash(alg)? {
                Hash::Sha224 => A::RSASignatureMessagePSSSHA224,
                Hash::Sha256 => A::RSASignatureMessagePSSSHA256,
                Hash::Sha384 => A::RSASignatureMessagePSSSHA384,
                Hash::Sha512 => A::RSASignatureMessagePSSSHA512,
            };
            Some((algorithm, KeyKind::RsaPss))
        }

        _ => None,
    }
}

/// Returns the algorithm that verifies a signature over an already-calculated digest, together
/// with the kind of key it needs.
///
/// The PKCS #1 v1.5 digest algorithms take the bare digest and build the `DigestInfo` themselves,
/// so unlike `CKM_RSA_PKCS` nothing needs wrapping before the call.
pub(crate) fn digest_algorithm(alg: &AlgorithmIdentifierOwned) -> Option<(Algorithm, KeyKind)> {
    use Algorithm as A;
    match alg.oid {
        PKIXALG_SHA224_WITH_RSA_ENCRYPTION => {
            Some((A::RSASignatureDigestPKCS1v15SHA224, KeyKind::Rsa))
        }
        PKIXALG_SHA256_WITH_RSA_ENCRYPTION => {
            Some((A::RSASignatureDigestPKCS1v15SHA256, KeyKind::Rsa))
        }
        PKIXALG_SHA384_WITH_RSA_ENCRYPTION => {
            Some((A::RSASignatureDigestPKCS1v15SHA384, KeyKind::Rsa))
        }
        PKIXALG_SHA512_WITH_RSA_ENCRYPTION => {
            Some((A::RSASignatureDigestPKCS1v15SHA512, KeyKind::Rsa))
        }

        PKIXALG_ECDSA_WITH_SHA224 => Some((A::ECDSASignatureDigestX962SHA224, KeyKind::Ec)),
        PKIXALG_ECDSA_WITH_SHA256 => Some((A::ECDSASignatureDigestX962SHA256, KeyKind::Ec)),
        PKIXALG_ECDSA_WITH_SHA384 => Some((A::ECDSASignatureDigestX962SHA384, KeyKind::Ec)),
        PKIXALG_ECDSA_WITH_SHA512 => Some((A::ECDSASignatureDigestX962SHA512, KeyKind::Ec)),

        PKIXALG_RSASSA_PSS => {
            let algorithm = match pss_hash(alg)? {
                Hash::Sha224 => A::RSASignatureDigestPSSSHA224,
                Hash::Sha256 => A::RSASignatureDigestPSSSHA256,
                Hash::Sha384 => A::RSASignatureDigestPSSSHA384,
                Hash::Sha512 => A::RSASignatureDigestPSSSHA512,
            };
            Some((algorithm, KeyKind::RsaPss))
        }

        _ => None,
    }
}

/// Returns the hash of an RSASSA-PSS algorithm identifier whose parameters Security.framework can
/// honor.
///
/// The PSS algorithms take no parameters: each fixes MGF1 over the same hash as the message and a
/// salt as long as the hash. A parameter block naming anything else describes a signature these
/// algorithms would misjudge, so it is declined and software answers instead. RFC 4055 defaults
/// every field to its SHA-1 form, so a block that omits the hash, the mask generation function or
/// the salt length is declined too.
fn pss_hash(alg: &AlgorithmIdentifierOwned) -> Option<Hash> {
    let encoded = alg.parameters.as_ref()?.to_der().ok()?;
    let pss = RsaPssParams::from_der(&encoded).ok()?;

    let hash = Hash::from_oid(&pss.hash?.oid)?;

    let mask_gen = pss.mask_gen?;
    if mask_gen.oid != PKIXALG_MGF1 {
        return None;
    }
    let mgf_hash = mask_gen
        .parameters
        .as_ref()?
        .decode_as::<AlgorithmIdentifierOwned>()
        .ok()?;
    if Hash::from_oid(&mgf_hash.oid)? != hash {
        return None;
    }

    if pss.salt_len? != hash.len() {
        return None;
    }
    if pss.trailer_field.unwrap_or(1) != 1 {
        return None;
    }

    Some(hash)
}

/// The parameter block carried by an RSASSA-PSS algorithm identifier.
#[derive(der::Sequence)]
struct RsaPssParams {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    hash: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    mask_gen: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    salt_len: Option<u32>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    trailer_field: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::Any;

    fn hash_alg(oid: const_oid::ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: Some(Any::null()),
        }
    }

    fn pss(
        hash: Option<const_oid::ObjectIdentifier>,
        mgf_hash: Option<const_oid::ObjectIdentifier>,
        salt_len: Option<u32>,
    ) -> AlgorithmIdentifierOwned {
        let params = RsaPssParams {
            hash: hash.map(hash_alg),
            mask_gen: mgf_hash.map(|h| AlgorithmIdentifierOwned {
                oid: PKIXALG_MGF1,
                parameters: Some(Any::encode_from(&hash_alg(h)).unwrap()),
            }),
            salt_len,
            trailer_field: None,
        };
        AlgorithmIdentifierOwned {
            oid: PKIXALG_RSASSA_PSS,
            parameters: Some(Any::encode_from(&params).unwrap()),
        }
    }

    fn plain(oid: const_oid::ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
    }

    #[test]
    fn every_supported_oid_has_both_forms() {
        for oid in [
            PKIXALG_SHA224_WITH_RSA_ENCRYPTION,
            PKIXALG_SHA256_WITH_RSA_ENCRYPTION,
            PKIXALG_SHA384_WITH_RSA_ENCRYPTION,
            PKIXALG_SHA512_WITH_RSA_ENCRYPTION,
            PKIXALG_ECDSA_WITH_SHA224,
            PKIXALG_ECDSA_WITH_SHA256,
            PKIXALG_ECDSA_WITH_SHA384,
            PKIXALG_ECDSA_WITH_SHA512,
        ] {
            assert!(message_algorithm(&plain(oid)).is_some(), "{oid}");
            assert!(digest_algorithm(&plain(oid)).is_some(), "{oid}");
        }
    }

    #[test]
    fn key_kind_follows_the_signature_family() {
        let (_, kind) = message_algorithm(&plain(PKIXALG_SHA256_WITH_RSA_ENCRYPTION)).unwrap();
        assert_eq!(kind, KeyKind::Rsa);
        let (_, kind) = message_algorithm(&plain(PKIXALG_ECDSA_WITH_SHA384)).unwrap();
        assert_eq!(kind, KeyKind::Ec);
    }

    #[test]
    fn unknown_algorithm_is_declined() {
        let ml_dsa_44 = const_oid::db::fips204::ID_ML_DSA_44;
        assert!(message_algorithm(&plain(ml_dsa_44)).is_none());
        assert!(digest_algorithm(&plain(ml_dsa_44)).is_none());
    }

    #[test]
    fn pss_with_matching_parameters_is_accepted() {
        for (hash, salt) in [
            (PKIXALG_SHA224, 28),
            (PKIXALG_SHA256, 32),
            (PKIXALG_SHA384, 48),
            (PKIXALG_SHA512, 64),
        ] {
            let alg = pss(Some(hash), Some(hash), Some(salt));
            assert!(message_algorithm(&alg).is_some(), "{hash}");
            assert!(digest_algorithm(&alg).is_some(), "{hash}");
        }
    }

    #[test]
    fn pss_salt_other_than_the_hash_length_is_declined() {
        let alg = pss(Some(PKIXALG_SHA256), Some(PKIXALG_SHA256), Some(20));
        assert!(message_algorithm(&alg).is_none());
        assert!(digest_algorithm(&alg).is_none());
    }

    #[test]
    fn pss_mgf_hash_other_than_the_message_hash_is_declined() {
        let alg = pss(Some(PKIXALG_SHA256), Some(PKIXALG_SHA384), Some(32));
        assert!(message_algorithm(&alg).is_none());
    }

    #[test]
    fn pss_with_defaulted_fields_is_declined() {
        assert!(message_algorithm(&pss(None, Some(PKIXALG_SHA256), Some(32))).is_none());
        assert!(message_algorithm(&pss(Some(PKIXALG_SHA256), None, Some(32))).is_none());
        assert!(
            message_algorithm(&pss(Some(PKIXALG_SHA256), Some(PKIXALG_SHA256), None)).is_none()
        );
        assert!(message_algorithm(&plain(PKIXALG_RSASSA_PSS)).is_none());
    }
}
