//! ML-KEM and ML-DSA for CMS through CryptoKit, under the `cms` and `pqc` features: encryption to
//! an ML-KEM recipient by [`SecurityFrameworkCrypto`], [`CryptoKitRecipientKey`], which decrypts
//! with an ML-KEM key held in memory or in the Secure Enclave, and [`CryptoKitSigningKey`], which
//! signs with an ML-DSA key held in either.
//!
//! CryptoKit performs the encapsulation or decapsulation and the HKDF over the
//! `CMSORIforKEMOtherInfo`, so the shared secret stays in CryptoKit; the key-encryption key it
//! returns is used by CommonCrypto's AES key wrap, as for key agreement. ML-KEM-768 and ML-KEM-1024
//! are offered, on macOS and iOS 26 and later; ML-KEM-512, which CryptoKit lacks, is declined, and an
//! older OS declines both.

use certval_cms::{
    kem_other_info, CmsEnvironment, EncryptKem, Error, KdfAlgorithm, KemOutput, KeyWrapAlgorithm,
    RecipientCredential, Result, SeedOrExpandedKey, SigningCredential,
};
use der::Decode;
use log::trace;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;
use zeroize::Zeroizing;

use crate::commoncrypto::{aes_key_unwrap, aes_key_wrap};
use crate::mldsa;
use crate::mlkem::{self, PrivateKey};
use crate::SecurityFrameworkCrypto;

/// The parameter set of an ML-KEM key, which RFC 9935 requires to carry no parameters, or
/// `Unrecognized` for any other key and for ML-KEM-512.
fn parameter_set(spki: &SubjectPublicKeyInfoOwned) -> Result<i32> {
    if spki.algorithm.parameters.is_some() {
        return Err(Error::Unrecognized);
    }
    mlkem::parameter_set(spki.algorithm.oid).ok_or(Error::Unrecognized)
}

fn public_key(spki: &SubjectPublicKeyInfoOwned) -> Result<&[u8]> {
    spki.subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::InvalidInput(String::from("an ML-KEM public key of unused bits")))
}

impl EncryptKem for SecurityFrameworkCrypto {
    /// ML-KEM-768 or ML-KEM-1024 with HKDF-SHA256, -SHA384 or -SHA512: the encapsulation and HKDF
    /// by CryptoKit, the key wrap by CommonCrypto.
    fn encrypt_kem(
        &self,
        _env: &CmsEnvironment,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        cek: &[u8],
    ) -> Result<KemOutput> {
        let parameter_set = parameter_set(spki)?;
        let info = kem_other_info(wrap, ukm)?;
        let (kem_ct, kek) =
            mlkem::encapsulate(parameter_set, public_key(spki)?, kdf, &info, wrap.kek_len())?;
        let encrypted_key = aes_key_wrap(&kek, cek)
            .ok_or_else(|| Error::Crypto(String::from("key wrap failed")))?;
        trace!("CryptoKit encapsulated to ML-KEM-{parameter_set} with {kdf:?} and {wrap:?}");
        Ok(KemOutput {
            kem_ct,
            encrypted_key,
        })
    }
}

/// How a [`CryptoKitRecipientKey`] holds its private key.
enum Key {
    /// The 64-octet seed of a key held in memory.
    Seed(Zeroizing<Vec<u8>>),
    /// The `dataRepresentation` of a Secure Enclave key, which only this device's Secure Enclave
    /// can use.
    SecureEnclave(Vec<u8>),
}

/// A [`RecipientCredential`] whose private key is a CryptoKit ML-KEM-768 or ML-KEM-1024 key, held in
/// memory or in the Secure Enclave, decrypting KEMRecipientInfo: the decapsulation and HKDF by
/// CryptoKit, then CommonCrypto's key unwrap. It declines the other recipient types.
///
/// The key is passed to CryptoKit on each decryption, as its seed or its Secure Enclave
/// `dataRepresentation`, so nothing is held on the Swift side between calls. A Secure Enclave key
/// whose access control requires user presence asks for it at each decryption.
///
/// It holds private key material, so it implements neither `Debug` nor `Clone`.
pub struct CryptoKitRecipientKey {
    certificate: Certificate,
    parameter_set: i32,
    key: Key,
}

impl CryptoKitRecipientKey {
    /// A credential for an RFC 9935 ML-KEM private key in PKCS #8, in the `seed` or `both` form,
    /// identified by `certificate`. CryptoKit takes the seed, so a key in the `expandedKey` form
    /// alone cannot be used and is refused. The key must be the one `certificate` contains.
    pub fn from_pkcs8_der(certificate: Certificate, der: &[u8]) -> Result<Self> {
        let invalid = |e: &str| Error::InvalidInput(format!("an ML-KEM PKCS #8 key: {e}"));
        let spki = certificate.tbs_certificate().subject_public_key_info();
        let parameter_set = parameter_set(spki)?;
        let info = pkcs8::PrivateKeyInfoRef::from_der(der).map_err(|e| invalid(&e.to_string()))?;
        if info.algorithm.oid != spki.algorithm.oid {
            return Err(invalid("not the type of key the certificate contains"));
        }
        let seed = match SeedOrExpandedKey::from_der(info.private_key.as_bytes())? {
            SeedOrExpandedKey::Seed(seed) => seed,
            SeedOrExpandedKey::Both(both) => both.seed,
            SeedOrExpandedKey::ExpandedKey(_) => {
                return Err(invalid(
                    "only the expanded key, and CryptoKit takes the seed",
                ));
            }
        };
        let credential = Self {
            certificate,
            parameter_set,
            key: Key::Seed(Zeroizing::new(seed.as_bytes().to_vec())),
        };
        credential.check_against_certificate()?;
        Ok(credential)
    }

    /// A credential for the Secure Enclave ML-KEM key whose `dataRepresentation` is
    /// `data_representation`, e.g. one an app made with CryptoKit's
    /// `SecureEnclave.MLKEM768.PrivateKey`, identified by `certificate`. The key must be the one
    /// `certificate` contains, and must be this device's.
    pub fn from_secure_enclave(
        certificate: Certificate,
        data_representation: Vec<u8>,
    ) -> Result<Self> {
        let spki = certificate.tbs_certificate().subject_public_key_info();
        let parameter_set = parameter_set(spki)?;
        let public = mlkem::secure_enclave_public_key(parameter_set, &data_representation)
            .ok_or_else(|| {
                Error::InvalidInput(String::from(
                    "the Secure Enclave refused the key, e.g. one of another device",
                ))
            })?;
        if public != public_key(spki)? {
            return Err(Error::InvalidInput(String::from(
                "a Secure Enclave key that is not the one the certificate contains",
            )));
        }
        Ok(Self {
            certificate,
            parameter_set,
            key: Key::SecureEnclave(data_representation),
        })
    }

    /// Generates an ML-KEM key in the Secure Enclave, of the parameter set `algorithm` identifies
    /// (ML-KEM-768 or ML-KEM-1024), usable after first unlock on this device only, without user
    /// presence. Returns its `dataRepresentation`, for [`from_secure_enclave`](Self::from_secure_enclave)
    /// once a certificate is issued, and its public key, for the certificate.
    pub fn generate_in_secure_enclave(
        algorithm: const_oid::ObjectIdentifier,
    ) -> Result<(Vec<u8>, SubjectPublicKeyInfoOwned)> {
        let parameter_set = mlkem::parameter_set(algorithm).ok_or(Error::Unrecognized)?;
        let (data, public) = mlkem::generate_in_secure_enclave(parameter_set)?;
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: spki::AlgorithmIdentifierOwned {
                oid: algorithm,
                parameters: None,
            },
            subject_public_key: der::asn1::BitString::from_bytes(&public)?,
        };
        Ok((data, spki))
    }

    fn private_key(&self) -> PrivateKey<'_> {
        match &self.key {
            Key::Seed(seed) => PrivateKey::Seed {
                seed,
                public_key: self
                    .certificate
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes(),
            },
            Key::SecureEnclave(data) => PrivateKey::SecureEnclave(data),
        }
    }

    /// Whether the seed generates the certificate's key: an encapsulation to the certificate's
    /// key that the seed decapsulates to the same key-encryption key.
    fn check_against_certificate(&self) -> Result<()> {
        let spki = self.certificate.tbs_certificate().subject_public_key_info();
        let mismatch = || {
            Error::InvalidInput(String::from(
                "an ML-KEM key that is not the one the certificate contains",
            ))
        };
        let info = b"certval-security-framework key check";
        let (ct, expected) = mlkem::encapsulate(
            self.parameter_set,
            public_key(spki)?,
            KdfAlgorithm::HkdfSha256,
            info,
            32,
        )?;
        let kek = mlkem::decapsulate(
            self.parameter_set,
            self.private_key(),
            &ct,
            KdfAlgorithm::HkdfSha256,
            info,
            32,
        )
        .map_err(|_| mismatch())?;
        if kek != expected {
            return Err(mismatch());
        }
        Ok(())
    }
}

impl RecipientCredential for CryptoKitRecipientKey {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn decrypt_kem(
        &self,
        _env: &CmsEnvironment,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        kem_ct: &[u8],
        ukm: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let info = kem_other_info(wrap, ukm)?;
        let kek = mlkem::decapsulate(
            self.parameter_set,
            self.private_key(),
            kem_ct,
            kdf,
            &info,
            wrap.kek_len(),
        )?;
        let cek = aes_key_unwrap(&kek, encrypted_key)
            .ok_or_else(|| Error::Crypto(String::from("key unwrap failed")))?;
        trace!(
            "CryptoKit decapsulated with ML-KEM-{} and {kdf:?} and {wrap:?}",
            self.parameter_set
        );
        Ok(Zeroizing::new(cek))
    }
}

/// The parameter set of an ML-DSA key, which RFC 9881 requires to carry no parameters, or
/// `Unrecognized` for any other key and for ML-DSA-44.
fn ml_dsa_parameter_set(spki: &SubjectPublicKeyInfoOwned) -> Result<i32> {
    mldsa::parameter_set(&spki.algorithm).ok_or(Error::Unrecognized)
}

/// A [`SigningCredential`] whose private key is a CryptoKit ML-DSA-65 or ML-DSA-87 key, held in
/// memory or in the Secure Enclave, signing SignedData with pure ML-DSA and an empty context
/// string (RFC 9882). It declines every other signature algorithm.
///
/// The key is passed to CryptoKit on each signature, as its seed or its Secure Enclave
/// `dataRepresentation`, so nothing is held on the Swift side between calls. A Secure Enclave key
/// whose access control requires user presence asks for it at each signature.
///
/// It holds private key material, so it implements neither `Debug` nor `Clone`.
pub struct CryptoKitSigningKey {
    certificate: Certificate,
    parameter_set: i32,
    key: Key,
}

impl CryptoKitSigningKey {
    /// A credential for an RFC 9881 ML-DSA private key in PKCS #8, in the `seed` or `both` form,
    /// identified by `certificate`. CryptoKit takes the seed, so a key in the `expandedKey` form
    /// alone cannot be used and is refused. The key must be the one `certificate` contains.
    pub fn from_pkcs8_der(certificate: Certificate, der: &[u8]) -> Result<Self> {
        let invalid = |e: &str| Error::InvalidInput(format!("an ML-DSA PKCS #8 key: {e}"));
        let spki = certificate.tbs_certificate().subject_public_key_info();
        let parameter_set = ml_dsa_parameter_set(spki)?;
        let info = pkcs8::PrivateKeyInfoRef::from_der(der).map_err(|e| invalid(&e.to_string()))?;
        if info.algorithm.oid != spki.algorithm.oid {
            return Err(invalid("not the type of key the certificate contains"));
        }
        let seed = match SeedOrExpandedKey::from_der(info.private_key.as_bytes())? {
            SeedOrExpandedKey::Seed(seed) => seed,
            SeedOrExpandedKey::Both(both) => both.seed,
            SeedOrExpandedKey::ExpandedKey(_) => {
                return Err(invalid(
                    "only the expanded key, and CryptoKit takes the seed",
                ));
            }
        };
        let credential = Self {
            certificate,
            parameter_set,
            key: Key::Seed(Zeroizing::new(seed.as_bytes().to_vec())),
        };
        credential.check_against_certificate()?;
        Ok(credential)
    }

    /// A credential for the Secure Enclave ML-DSA key whose `dataRepresentation` is
    /// `data_representation`, e.g. one an app made with CryptoKit's
    /// `SecureEnclave.MLDSA65.PrivateKey`, identified by `certificate`. The key must be the one
    /// `certificate` contains, and must be this device's.
    pub fn from_secure_enclave(
        certificate: Certificate,
        data_representation: Vec<u8>,
    ) -> Result<Self> {
        let spki = certificate.tbs_certificate().subject_public_key_info();
        let parameter_set = ml_dsa_parameter_set(spki)?;
        let public = mldsa::secure_enclave_public_key(parameter_set, &data_representation)
            .ok_or_else(|| {
                Error::InvalidInput(String::from(
                    "the Secure Enclave refused the key, e.g. one of another device",
                ))
            })?;
        if public != public_key(spki)? {
            return Err(Error::InvalidInput(String::from(
                "a Secure Enclave key that is not the one the certificate contains",
            )));
        }
        Ok(Self {
            certificate,
            parameter_set,
            key: Key::SecureEnclave(data_representation),
        })
    }

    /// Generates an ML-DSA key in the Secure Enclave, of the parameter set `algorithm` identifies
    /// (ML-DSA-65 or ML-DSA-87), usable after first unlock on this device only, without user
    /// presence. Returns its `dataRepresentation`, for [`from_secure_enclave`](Self::from_secure_enclave)
    /// once a certificate is issued, and its public key, for the certificate.
    pub fn generate_in_secure_enclave(
        algorithm: const_oid::ObjectIdentifier,
    ) -> Result<(Vec<u8>, SubjectPublicKeyInfoOwned)> {
        let algorithm = spki::AlgorithmIdentifierOwned {
            oid: algorithm,
            parameters: None,
        };
        let parameter_set = mldsa::parameter_set(&algorithm).ok_or(Error::Unrecognized)?;
        let (data, public) = mldsa::generate_in_secure_enclave(parameter_set)?;
        let spki = SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key: der::asn1::BitString::from_bytes(&public)?,
        };
        Ok((data, spki))
    }

    fn private_key(&self) -> mldsa::PrivateKey<'_> {
        match &self.key {
            Key::Seed(seed) => mldsa::PrivateKey::Seed {
                seed,
                public_key: self
                    .certificate
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes(),
            },
            Key::SecureEnclave(data) => mldsa::PrivateKey::SecureEnclave(data),
        }
    }

    /// Whether the seed generates the certificate's key: a signature by the seed that the
    /// certificate's key verifies.
    fn check_against_certificate(&self) -> Result<()> {
        let spki = self.certificate.tbs_certificate().subject_public_key_info();
        let mismatch = || {
            Error::InvalidInput(String::from(
                "an ML-DSA key that is not the one the certificate contains",
            ))
        };
        let message = b"certval-security-framework key check";
        let signature =
            mldsa::sign(self.parameter_set, self.private_key(), message).map_err(|_| mismatch())?;
        match mldsa::verify(
            self.parameter_set,
            &spki.algorithm,
            spki,
            message,
            &signature,
        ) {
            mldsa::Verdict::Valid => Ok(()),
            _ => Err(mismatch()),
        }
    }
}

impl SigningCredential for CryptoKitSigningKey {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn sign_message(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        if mldsa::parameter_set(alg) != Some(self.parameter_set) {
            return Err(Error::Unrecognized);
        }
        let signature = mldsa::sign(self.parameter_set, self.private_key(), message)?;
        trace!("CryptoKit signed with ML-DSA-{}", self.parameter_set);
        Ok(signature)
    }
}
