//! Key management for cms's own recipient builders, through Security.framework and CommonCrypto:
//! [`SecurityFrameworkKeyEncryptor`] for `KeyTransRecipientInfoBuilder`, and
//! [`SecurityFrameworkKeyAgreement`] and [`SecurityFrameworkKeyWrap`] for
//! `KeyAgreeRecipientInfoBuilder`. These implement cms's traits directly, so a caller using cms's
//! builders without a certval-cms `CmsEnvironment` can have the platform perform the operation.
//!
//! The random number generator cms's builders pass is not used: Security.framework draws the RSA
//! padding and the ephemeral key from its own generator.

use certval_cms::{
    Error as CmsError, KeyAgreementAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm,
};
use cms::builder::{self, KeyAgreement, KeyAgreementOutput};
use cms::enveloped_data::OriginatorPublicKey;
use const_oid::{DynAssociatedOid, ObjectIdentifier};
use der::asn1::BitString;
use log::debug;
use rsa::traits::RandomizedEncryptor;
use spki::{AlgorithmIdentifierOwned, DynAssociatedAlgorithmIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;

use crate::cms::{ecdh_x963, rsa_encrypt};
use crate::commoncrypto::aes_key_wrap;

/// A certval-cms error as a cms builder error, which holds only a message.
fn builder_error(e: CmsError) -> builder::Error {
    match e {
        CmsError::Asn1(e) => builder::Error::Asn1(e),
        e => builder::Error::Builder(e.to_string()),
    }
}

/// RSA key transport to one recipient's key, by Security.framework, for cms's
/// `KeyTransRecipientInfoBuilder`: RSAES-PKCS1-v1_5 or RSAES-OAEP, as the [`KeyTransportAlgorithm`]
/// given says.
#[derive(Clone, Debug)]
pub struct SecurityFrameworkKeyEncryptor {
    spki: SubjectPublicKeyInfoOwned,
    alg: KeyTransportAlgorithm,
}

impl SecurityFrameworkKeyEncryptor {
    /// Key transport with `alg` to the RSA key in `spki`.
    pub fn new(spki: SubjectPublicKeyInfoOwned, alg: KeyTransportAlgorithm) -> Self {
        Self { spki, alg }
    }

    /// Key transport with `alg` to the RSA key in `cert`.
    pub fn from_certificate(cert: &Certificate, alg: KeyTransportAlgorithm) -> Self {
        Self::new(
            cert.tbs_certificate().subject_public_key_info().clone(),
            alg,
        )
    }
}

impl RandomizedEncryptor for SecurityFrameworkKeyEncryptor {
    fn encrypt_with_rng<R: rsa::rand_core::TryCryptoRng + ?Sized>(
        &self,
        _rng: &mut R,
        msg: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        rsa_encrypt(self.alg, &self.spki, msg).map_err(|e| {
            debug!(
                "Security.framework key transport with {:?} failed: {e}",
                self.alg
            );
            rsa::Error::Internal
        })
    }
}

impl DynAssociatedAlgorithmIdentifier for SecurityFrameworkKeyEncryptor {
    fn algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        // Only encoding the OAEP parameters can fail.
        self.alg.algorithm_identifier().map_err(|e| match e {
            CmsError::Asn1(e) => spki::Error::Asn1(e),
            _ => spki::Error::Asn1(der::ErrorKind::Failed.into()),
        })
    }
}

/// Ephemeral-static ECDH with one recipient's key on P-256, P-384 or P-521, and the X9.63 KDF, by
/// Security.framework in one call, for cms's `KeyAgreeRecipientInfoBuilder`. The
/// [`KeyAgreementAlgorithm`] given identifies the scheme and the KDF's hash.
#[derive(Clone, Debug)]
pub struct SecurityFrameworkKeyAgreement {
    spki: SubjectPublicKeyInfoOwned,
    alg: KeyAgreementAlgorithm,
}

impl SecurityFrameworkKeyAgreement {
    /// Key agreement with `alg` with the EC key in `spki`.
    pub fn new(spki: SubjectPublicKeyInfoOwned, alg: KeyAgreementAlgorithm) -> Self {
        Self { spki, alg }
    }

    /// Key agreement with `alg` with the EC key in `cert`.
    pub fn from_certificate(cert: &Certificate, alg: KeyAgreementAlgorithm) -> Self {
        Self::new(
            cert.tbs_certificate().subject_public_key_info().clone(),
            alg,
        )
    }
}

impl DynAssociatedOid for SecurityFrameworkKeyAgreement {
    fn oid(&self) -> ObjectIdentifier {
        self.alg.oid()
    }
}

impl<R: ?Sized> KeyAgreement<R> for SecurityFrameworkKeyAgreement {
    fn agree(
        &self,
        shared_info: &[u8],
        kek_size: usize,
        _rng: &mut R,
    ) -> builder::Result<KeyAgreementOutput> {
        let (ephemeral_public_key, key_encryption_key) =
            ecdh_x963(self.alg, &self.spki, shared_info, kek_size).map_err(builder_error)?;
        Ok(KeyAgreementOutput {
            // RFC 5753, section 3.1.1: the ephemeral key is on the recipient's curve, which the
            // algorithm identifier names.
            originator_key: OriginatorPublicKey {
                algorithm: self.spki.algorithm.clone(),
                public_key: BitString::from_bytes(&ephemeral_public_key)?,
            },
            key_encryption_key,
        })
    }
}

/// AES key wrap (RFC 3394) by CommonCrypto, for cms's `KeyAgreeRecipientInfoBuilder`.
#[derive(Clone, Copy, Debug)]
pub struct SecurityFrameworkKeyWrap {
    wrap: KeyWrapAlgorithm,
}

impl SecurityFrameworkKeyWrap {
    /// Key wrap with `wrap`.
    pub fn new(wrap: KeyWrapAlgorithm) -> Self {
        Self { wrap }
    }
}

impl builder::KeyWrapAlgorithm for SecurityFrameworkKeyWrap {
    fn algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
        self.wrap.algorithm_identifier()
    }

    fn kek_size(&self) -> usize {
        self.wrap.kek_len()
    }

    fn try_wrap(&self, kek: &[u8], key: &[u8]) -> builder::Result<Vec<u8>> {
        // CommonCrypto takes the key size from the key-encryption key, so one of another size
        // would wrap under another algorithm than the one identified.
        if kek.len() != self.wrap.kek_len() {
            return Err(builder::Error::Builder(format!(
                "a {}-octet key-encryption key for {:?}",
                kek.len(),
                self.wrap
            )));
        }
        aes_key_wrap(kek, key)
            .ok_or_else(|| builder::Error::Builder(String::from("key wrap failed")))
    }
}
