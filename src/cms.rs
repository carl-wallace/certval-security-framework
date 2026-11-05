//! The provider's implementations of certval-cms's interfaces, under the `cms` feature: AES-CBC
//! content encryption and decryption by CommonCrypto; RSA key transport and ECDH key agreement by
//! Security.framework; recipient and signing credentials over Security.framework keys; and
//! [`KeychainIdentities`], which finds both among the keychain's identities.
//!
//! Key agreement is done as Security.framework does it, ECDH and the X9.63 KDF in one call
//! (`SecKeyCopyKeyExchangeResult`), so the shared secret never leaves the framework; the key-encryption
//! key is then used by CommonCrypto's AES key wrap. AES-GCM, which CommonCrypto does not offer, and
//! KEMs are declined, and the environment passes them to the next implementation registered.

use std::sync::Arc;

use certval_cms::{
    content_decryption_parameters, ecc_cms_shared_info, recipient_matches, CmsEnvironment,
    ContentEncryptionAlgorithm, ContentEncryptionOutput, ContentParameters, DecryptContent,
    EncryptContent, EncryptKeyAgreement, EncryptKeyTransport, Error, KeyAgreeOutput,
    KeyAgreementAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm, RecipientCredential,
    RecipientCredentialSource, Result, SharedRecipientCredential, SharedSigningCredential,
    SigningCredential, SigningCredentialLookup, SigningCredentialSource,
};
use cms::enveloped_data::RecipientIdentifier;
use const_oid::db::rfc5912::{
    ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1,
};
use der::{asn1::Any, Decode, Encode, Tag};
use log::{debug, trace};
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework::key::{GenerateKeyOptions, KeyType, SecKey};
use security_framework::random::SecRandom;
use security_framework_sys::key::Algorithm;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;
use zeroize::Zeroizing;

use crate::algorithm::{message_algorithm, KeyKind};
use crate::commoncrypto::{aes_cbc, aes_key_unwrap, aes_key_wrap, Direction};
use crate::key::{create_private_key, create_public_key, key_data, PlatformKeyType};
use crate::SecurityFrameworkCrypto;

/// Length in octets of an AES-CBC IV.
const CBC_IV_LEN: usize = 16;

fn content_decryption_failed() -> Error {
    Error::Crypto(String::from("content decryption failed"))
}

fn random(len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; len]);
    SecRandom::default()
        .copy_bytes(&mut buf)
        .map_err(|e| Error::Crypto(format!("random number generator: {e}")))?;
    Ok(buf)
}

/// The CBC algorithm `alg` is, or `None` for anything else, GCM included.
fn cbc(alg: ContentEncryptionAlgorithm) -> Option<ContentEncryptionAlgorithm> {
    match alg {
        ContentEncryptionAlgorithm::Aes128Cbc
        | ContentEncryptionAlgorithm::Aes192Cbc
        | ContentEncryptionAlgorithm::Aes256Cbc => Some(alg),
        _ => None,
    }
}

impl EncryptContent for SecurityFrameworkCrypto {
    /// AES-CBC by CommonCrypto, with the key and IV from Security.framework's random number
    /// generator. AES-GCM is declined.
    fn encrypt_content(
        &self,
        _env: &CmsEnvironment,
        alg: ContentEncryptionAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<ContentEncryptionOutput> {
        let Some(alg) = cbc(alg) else {
            return Err(Error::Unrecognized);
        };
        if aad.is_some() {
            return Err(Error::InvalidInput(String::from(
                "associated data given for an algorithm that does not authenticate",
            )));
        }
        let key = random(alg.key_len())?;
        let iv = random(CBC_IV_LEN)?;
        let ciphertext = aes_cbc(Direction::Encrypt, &key, &iv, plaintext)
            .ok_or_else(|| Error::Crypto(String::from("content encryption failed")))?;
        trace!("CommonCrypto encrypted content with {alg:?}");
        Ok(ContentEncryptionOutput {
            ciphertext,
            key,
            algorithm: AlgorithmIdentifierOwned {
                oid: alg.oid(),
                parameters: Some(Any::new(Tag::OctetString, iv.as_slice())?),
            },
            tag: None,
        })
    }
}

impl DecryptContent for SecurityFrameworkCrypto {
    /// AES-CBC by CommonCrypto. AES-GCM is declined.
    fn decrypt_content(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        // GCM, which CommonCrypto lacks, is declined before anything is checked.
        if ContentEncryptionAlgorithm::from_oid(alg.oid)
            .and_then(cbc)
            .is_none()
        {
            return Err(Error::Unrecognized);
        }
        let (content_alg, parameters) = content_decryption_parameters(alg, key, aad, tag)?;
        let ContentParameters::Cbc { iv } = parameters else {
            return Err(Error::Unrecognized);
        };
        let plaintext = aes_cbc(Direction::Decrypt, key, &iv, ciphertext)
            .ok_or_else(content_decryption_failed)?;
        trace!("CommonCrypto decrypted content with {content_alg:?}");
        Ok(Zeroizing::new(plaintext))
    }
}

/// Security.framework's algorithm for a key transport algorithm. Its OAEP algorithms use MGF1 with
/// the same hash and an empty label, as RFC 4055 does.
fn key_transport_algorithm(alg: KeyTransportAlgorithm) -> Result<Algorithm> {
    match alg {
        KeyTransportAlgorithm::RsaPkcs1v15 => Ok(Algorithm::RSAEncryptionPKCS1),
        KeyTransportAlgorithm::RsaOaepSha1 => Ok(Algorithm::RSAEncryptionOAEPSHA1),
        KeyTransportAlgorithm::RsaOaepSha256 => Ok(Algorithm::RSAEncryptionOAEPSHA256),
        KeyTransportAlgorithm::RsaOaepSha384 => Ok(Algorithm::RSAEncryptionOAEPSHA384),
        KeyTransportAlgorithm::RsaOaepSha512 => Ok(Algorithm::RSAEncryptionOAEPSHA512),
        _ => Err(Error::Unrecognized),
    }
}

/// Security.framework's algorithm for a key agreement scheme: ECDH, then the X9.63 KDF with the
/// scheme's hash.
fn key_agreement_algorithm(alg: KeyAgreementAlgorithm) -> Result<Algorithm> {
    match alg {
        KeyAgreementAlgorithm::EcdhSha256 => Ok(Algorithm::ECDHKeyExchangeStandardX963SHA256),
        KeyAgreementAlgorithm::EcdhSha384 => Ok(Algorithm::ECDHKeyExchangeStandardX963SHA384),
        KeyAgreementAlgorithm::EcdhSha512 => Ok(Algorithm::ECDHKeyExchangeStandardX963SHA512),
        _ => Err(Error::Unrecognized),
    }
}

/// The size in bits of the curve an EC public key is on, for generating an ephemeral key on it.
fn curve_bits(spki: &SubjectPublicKeyInfoOwned) -> Option<u32> {
    let curve =
        const_oid::ObjectIdentifier::from_der(&spki.algorithm.parameters.as_ref()?.to_der().ok()?)
            .ok()?;
    match curve {
        SECP_256_R_1 => Some(256),
        SECP_384_R_1 => Some(384),
        SECP_521_R_1 => Some(521),
        _ => None,
    }
}

impl EncryptKeyTransport for SecurityFrameworkCrypto {
    /// RSA key transport by Security.framework, to an `rsaEncryption` key.
    fn encrypt_key_transport(
        &self,
        _env: &CmsEnvironment,
        alg: KeyTransportAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        cek: &[u8],
    ) -> Result<Vec<u8>> {
        let algorithm = key_transport_algorithm(alg)?;
        let Some((data, key_type)) = key_data(spki, KeyKind::Rsa) else {
            return Err(Error::Unrecognized);
        };
        let key = create_public_key(data, key_type).ok_or(Error::Unrecognized)?;
        let encrypted = key.encrypt_data(algorithm, cek).map_err(|e| {
            debug!("Security.framework declined key transport: {e}");
            Error::Unrecognized
        })?;
        trace!("Security.framework performed key transport with {alg:?}");
        Ok(encrypted)
    }
}

impl EncryptKeyAgreement for SecurityFrameworkCrypto {
    /// Ephemeral-static ECDH on P-256, P-384 or P-521: the ephemeral key generated by
    /// Security.framework, the ECDH and X9.63 KDF by Security.framework in one call, and the key
    /// wrap by CommonCrypto.
    fn encrypt_key_agreement(
        &self,
        _env: &CmsEnvironment,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        cek: &[u8],
    ) -> Result<KeyAgreeOutput> {
        if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
            return Err(Error::Unrecognized);
        }
        let algorithm = key_agreement_algorithm(alg)?;
        let bits = curve_bits(spki).ok_or(Error::Unrecognized)?;
        let Some((data, key_type)) = key_data(spki, KeyKind::Ec) else {
            return Err(Error::Unrecognized);
        };
        let recipient = create_public_key(data, key_type).ok_or(Error::Unrecognized)?;

        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(bits);
        let ephemeral = SecKey::new(&options).map_err(|e| {
            debug!("Security.framework could not generate an ephemeral key: {e}");
            Error::Unrecognized
        })?;
        let ephemeral_public_key = ephemeral
            .public_key()
            .and_then(|k| k.external_representation())
            .ok_or_else(|| Error::Crypto(String::from("no ephemeral public key")))?
            .to_vec();

        let shared_info = ecc_cms_shared_info(wrap, ukm)?;
        let kek = Zeroizing::new(
            ephemeral
                .key_exchange(algorithm, &recipient, wrap.kek_len(), Some(&shared_info))
                .map_err(|e| {
                    debug!("Security.framework declined key agreement: {e}");
                    Error::Unrecognized
                })?,
        );
        let encrypted_key = aes_key_wrap(&kek, cek)
            .ok_or_else(|| Error::Crypto(String::from("key wrap failed")))?;
        trace!("Security.framework performed key agreement with {alg:?} and {wrap:?}");
        Ok(KeyAgreeOutput {
            ephemeral_public_key,
            encrypted_key,
        })
    }
}

/// The algorithm of the key a certificate certifies.
fn key_algorithm(certificate: &Certificate) -> const_oid::ObjectIdentifier {
    certificate
        .tbs_certificate()
        .subject_public_key_info()
        .algorithm
        .oid
}

/// A [`RecipientCredential`] whose private key is a Security.framework key, e.g. a keychain
/// identity's or one in the Secure Enclave: RSA key transport, by `SecKeyCreateDecryptedData`, and
/// ECDH key agreement, by `SecKeyCopyKeyExchangeResult` with the X9.63 KDF, then CommonCrypto's
/// key unwrap.
pub struct SecurityFrameworkRecipientKey {
    certificate: Certificate,
    key: SecKey,
}

impl SecurityFrameworkRecipientKey {
    /// A credential for `key`, a private key, identified by `certificate`.
    pub fn new(certificate: Certificate, key: SecKey) -> Self {
        Self { certificate, key }
    }
}

impl RecipientCredential for SecurityFrameworkRecipientKey {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn decrypt_key_transport(
        &self,
        _env: &CmsEnvironment,
        alg: KeyTransportAlgorithm,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if key_algorithm(&self.certificate) != RSA_ENCRYPTION {
            return Err(Error::Unrecognized);
        }
        let algorithm = key_transport_algorithm(alg)?;
        let cek = self
            .key
            .decrypt_data(algorithm, encrypted_key)
            .map_err(|e| {
                debug!("Security.framework could not decrypt a key transport: {e}");
                Error::Crypto(String::from("key transport failed"))
            })?;
        trace!("Security.framework decrypted a key transport with {alg:?}");
        Ok(Zeroizing::new(cek))
    }

    fn decrypt_key_agreement(
        &self,
        _env: &CmsEnvironment,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        originator: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if key_algorithm(&self.certificate) != ID_EC_PUBLIC_KEY {
            return Err(Error::Unrecognized);
        }
        let algorithm = key_agreement_algorithm(alg)?;
        // The originator's ephemeral key is on the recipient's curve; RFC 5753 does not require its
        // algorithm identifier to name the curve, so the point is imported as it stands, and
        // Security.framework infers the curve from its length.
        let point = originator.subject_public_key.raw_bytes();
        let originator = create_public_key(point, PlatformKeyType::Ec)
            .ok_or_else(|| Error::Crypto(String::from("key agreement failed")))?;
        let shared_info = ecc_cms_shared_info(wrap, ukm)?;
        let kek = Zeroizing::new(
            self.key
                .key_exchange(algorithm, &originator, wrap.kek_len(), Some(&shared_info))
                .map_err(|e| {
                    debug!("Security.framework could not perform key agreement: {e}");
                    Error::Crypto(String::from("key agreement failed"))
                })?,
        );
        let cek = aes_key_unwrap(&kek, encrypted_key)
            .ok_or_else(|| Error::Crypto(String::from("key unwrap failed")))?;
        trace!("Security.framework decrypted a key agreement with {alg:?} and {wrap:?}");
        Ok(Zeroizing::new(cek))
    }
}

/// A [`SigningCredential`] whose private key is a Security.framework key, signing SignedData with
/// RSA PKCS #1 v1.5 or RSASSA-PSS (salt the length of the hash), or ECDSA, by
/// `SecKeyCreateSignature`, which hashes the message itself.
pub struct SecurityFrameworkSigningKey {
    certificate: Certificate,
    key: SecKey,
}

impl SecurityFrameworkSigningKey {
    /// A credential for `key`, a private key, identified by `certificate`.
    pub fn new(certificate: Certificate, key: SecKey) -> Self {
        Self { certificate, key }
    }
}

impl SigningCredential for SecurityFrameworkSigningKey {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn sign_message(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let Some((algorithm, kind)) = message_algorithm(alg) else {
            return Err(Error::Unrecognized);
        };
        let key_alg = key_algorithm(&self.certificate);
        let fits = match kind {
            KeyKind::Rsa | KeyKind::RsaPss => key_alg == RSA_ENCRYPTION,
            KeyKind::Ec => key_alg == ID_EC_PUBLIC_KEY,
        };
        if !fits {
            return Err(Error::Unrecognized);
        }
        let signature = self.key.create_signature(algorithm, message).map_err(|e| {
            debug!("Security.framework could not sign: {e}");
            Error::Crypto(String::from("signing failed"))
        })?;
        trace!("Security.framework signed with {}", alg.oid);
        Ok(signature)
    }
}

/// The identities in the keychains the process can search, each a certificate and its private
/// key, as a source of both recipient and signing credentials. A keychain holds many keys; the one
/// a recipient identifier names is found by its certificate's issuer and serial number or subject
/// key identifier, and signing keys by any [`SigningCredentialLookup`].
#[derive(Clone, Copy, Debug, Default)]
pub struct KeychainIdentities {
    _private: (),
}

impl KeychainIdentities {
    /// A source over the keychain's identities.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every identity whose certificate `matches`, as its certificate and private key.
    fn find(&self, matches: impl Fn(&Certificate) -> bool) -> Result<Vec<(Certificate, SecKey)>> {
        let results = match ItemSearchOptions::new()
            .class(ItemClass::identity())
            .load_refs(true)
            .limit(Limit::All)
            .search()
        {
            Ok(results) => results,
            Err(e) => {
                // errSecItemNotFound: there are no identities at all.
                if e.code() == -25300 {
                    return Ok(vec![]);
                }
                return Err(Error::Crypto(format!("searching the keychain: {e}")));
            }
        };
        let mut found = vec![];
        for result in results {
            let SearchResult::Ref(Reference::Identity(identity)) = result else {
                continue;
            };
            let Ok(sec_certificate) = identity.certificate() else {
                continue;
            };
            let Ok(certificate) = Certificate::from_der(&sec_certificate.to_der()) else {
                continue;
            };
            if !matches(&certificate) {
                continue;
            }
            let key = identity
                .private_key()
                .map_err(|e| Error::Crypto(format!("reading an identity's private key: {e}")))?;
            found.push((certificate, key));
        }
        Ok(found)
    }

    /// The certificate of every identity in the keychains the process can search, i.e. every
    /// certificate with a private key, for a caller to list or choose among. A credential for one
    /// is found through either source interface, by its identifier.
    pub fn certificates(&self) -> Result<Vec<Certificate>> {
        Ok(self.find(|_| true)?.into_iter().map(|(c, _)| c).collect())
    }
}

impl RecipientCredentialSource for KeychainIdentities {
    fn find_recipient_credential(
        &self,
        _env: &CmsEnvironment,
        rid: &RecipientIdentifier,
    ) -> Result<Option<SharedRecipientCredential>> {
        Ok(self
            .find(|c| recipient_matches(rid, c))?
            .into_iter()
            .next()
            .map(|(certificate, key)| {
                Arc::new(SecurityFrameworkRecipientKey::new(certificate, key))
                    as SharedRecipientCredential
            }))
    }
}

impl SigningCredentialSource for KeychainIdentities {
    fn find_signing_credentials(
        &self,
        _env: &CmsEnvironment,
        lookup: SigningCredentialLookup<'_>,
    ) -> Result<Vec<SharedSigningCredential>> {
        Ok(self
            .find(|c| lookup.matches(c))?
            .into_iter()
            .map(|(certificate, key)| {
                Arc::new(SecurityFrameworkSigningKey::new(certificate, key))
                    as SharedSigningCredential
            })
            .collect())
    }
}

/// Credentials for an RSA or elliptic curve key imported into Security.framework from PKCS #8, for
/// a key held in software that should be used through Security.framework, e.g. for testing. The
/// key is created in memory and not added to a keychain. It must be the key `certificate`
/// contains, and an elliptic curve key must be on P-256, P-384 or P-521.
pub fn import_pkcs8(
    certificate: Certificate,
    pkcs8: &[u8],
) -> Result<(SecurityFrameworkRecipientKey, SecurityFrameworkSigningKey)> {
    let invalid = |e: &str| Error::InvalidInput(format!("a PKCS #8 key to import: {e}"));
    let info = pkcs8::PrivateKeyInfoRef::from_der(pkcs8).map_err(|e| invalid(&e.to_string()))?;
    let spki = certificate.tbs_certificate().subject_public_key_info();
    if info.algorithm.oid != spki.algorithm.oid {
        return Err(invalid("not the type of key the certificate contains"));
    }
    let private_key = info.private_key.as_bytes();
    // The point is the certificate's, for an elliptic curve key.
    let (data, key_type, point) = match spki.algorithm.oid {
        // The PKCS #8 privateKey of an RSA key is the PKCS #1 RSAPrivateKey Security.framework takes.
        RSA_ENCRYPTION => (
            Zeroizing::new(private_key.to_vec()),
            PlatformKeyType::Rsa,
            None,
        ),
        ID_EC_PUBLIC_KEY => {
            let (point, _) = key_data(spki, KeyKind::Ec)
                .ok_or_else(|| invalid("not a key on P-256, P-384 or P-521"))?;
            let scalar = sec1::EcPrivateKey::from_der(private_key)
                .map_err(|e| invalid(&e.to_string()))?
                .private_key;
            // Security.framework takes the point followed by the scalar, at the curve's length.
            let scalar_len = (point.len() - 1) / 2;
            if scalar.len() > scalar_len {
                return Err(invalid("a private scalar longer than the curve's"));
            }
            let mut data = Zeroizing::new(Vec::with_capacity(point.len() + scalar_len));
            data.extend_from_slice(point);
            data.resize(point.len() + scalar_len - scalar.len(), 0);
            data.extend_from_slice(scalar);
            (data, PlatformKeyType::Ec, Some(point))
        }
        _ => return Err(Error::Unrecognized),
    };
    let key = create_private_key(&data, key_type)
        .ok_or_else(|| invalid("Security.framework did not accept the key"))?;
    let matches = match point {
        // An RSA private key holds its modulus and public exponent, from which Security.framework
        // derives the public key.
        None => key
            .public_key()
            .and_then(|public| public.external_representation())
            .is_some_and(|public| spki.subject_public_key.as_bytes() == Some(public.bytes())),
        // An elliptic curve key's point was taken from the certificate, and Security.framework does
        // not check it against the scalar, so the pair is checked by a signature the certificate's
        // key verifies.
        Some(point) => {
            let algorithm = Algorithm::ECDSASignatureMessageX962SHA256;
            let message = b"certval-security-framework import_pkcs8";
            let signature = key
                .create_signature(algorithm, message)
                .map_err(|e| invalid(&format!("Security.framework could not sign: {e}")))?;
            create_public_key(point, key_type).is_some_and(|public| {
                public
                    .verify_signature(algorithm, message, &signature)
                    .unwrap_or(false)
            })
        }
    };
    if !matches {
        return Err(invalid("not the key the certificate contains"));
    }
    Ok((
        SecurityFrameworkRecipientKey::new(certificate.clone(), key.clone()),
        SecurityFrameworkSigningKey::new(certificate, key),
    ))
}
