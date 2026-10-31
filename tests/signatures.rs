//! Verifies signatures made by an independent implementation, through both interfaces, and checks
//! every verdict against certval's software verifier.
//!
//! The elliptic curve signatures come from RustCrypto with fixed private scalars, so they are the
//! same on every run. RSA has no deterministic key generation in reach, so the RSA keys are
//! generated in memory by Security.framework itself; the software verifier is then what keeps those
//! tests from being circular, because it reads the same `SubjectPublicKeyInfo` and must agree.

#![cfg(target_vendor = "apple")]

use certval::{
    verify_signature_digest_rust_crypto, verify_signature_message_rust_crypto, Error,
    PathValidationStatus, PkiEnvironment, VerifySignatureDigest, VerifySignatureMessage,
    PKIXALG_ECDSA_WITH_SHA256, PKIXALG_ECDSA_WITH_SHA384, PKIXALG_ECDSA_WITH_SHA512,
    PKIXALG_EC_PUBLIC_KEY, PKIXALG_MGF1, PKIXALG_RSASSA_PSS, PKIXALG_RSA_ENCRYPTION,
    PKIXALG_SECP256R1, PKIXALG_SECP384R1, PKIXALG_SECP521R1, PKIXALG_SHA256,
    PKIXALG_SHA256_WITH_RSA_ENCRYPTION, PKIXALG_SHA384, PKIXALG_SHA384_WITH_RSA_ENCRYPTION,
};
use certval_security_framework::SecurityFrameworkCrypto;
use const_oid::ObjectIdentifier;
use der::asn1::{Any, BitString};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey};
use sha2::Digest;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

const MESSAGE: &[u8] = b"a to-be-signed structure stands in here";

/// One signature together with what is needed to check it.
struct Case {
    spki: SubjectPublicKeyInfoOwned,
    alg: AlgorithmIdentifierOwned,
    signature: Vec<u8>,
    digest: Vec<u8>,
}

fn pe() -> PkiEnvironment {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe
}

fn bits(bytes: &[u8]) -> BitString {
    BitString::from_bytes(bytes).unwrap()
}

fn plain(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    }
}

fn ec_spki(curve: ObjectIdentifier, point: &[u8]) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: PKIXALG_EC_PUBLIC_KEY,
            parameters: Some(Any::encode_from(&curve).unwrap()),
        },
        subject_public_key: bits(point),
    }
}

macro_rules! ec_case {
    ($curve:ident, $curve_oid:expr, $sig_oid:expr, $digest:ty, $scalar:expr) => {{
        use signature::hazmat::PrehashSigner;
        let key = $curve::ecdsa::SigningKey::from_slice(&$scalar).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let digest = <$digest>::digest(MESSAGE).to_vec();
        let signature: $curve::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
        Case {
            spki: ec_spki($curve_oid, point.as_bytes()),
            alg: plain($sig_oid),
            signature: signature.to_der().as_bytes().to_vec(),
            digest,
        }
    }};
}

fn ec_cases() -> Vec<(&'static str, Case)> {
    vec![
        (
            "P-256",
            ec_case!(
                p256,
                PKIXALG_SECP256R1,
                PKIXALG_ECDSA_WITH_SHA256,
                sha2::Sha256,
                [0x11u8; 32]
            ),
        ),
        (
            "P-384",
            ec_case!(
                p384,
                PKIXALG_SECP384R1,
                PKIXALG_ECDSA_WITH_SHA384,
                sha2::Sha384,
                [0x22u8; 48]
            ),
        ),
        (
            "P-521",
            ec_case!(
                p521,
                PKIXALG_SECP521R1,
                PKIXALG_ECDSA_WITH_SHA512,
                sha2::Sha512,
                {
                    // A P-521 scalar is 521 bits, so the top byte holds a single bit.
                    let mut s = [0x33u8; 66];
                    s[0] = 0x01;
                    s
                }
            ),
        ),
    ]
}

/// Generates an RSA key in memory, never in a keychain, and returns its public half as an SPKI
/// under `rsaEncryption` along with the private key for signing.
fn rsa_key(size: u32) -> (SecKey, SubjectPublicKeyInfoOwned) {
    let mut options = GenerateKeyOptions::default();
    options.set_key_type(KeyType::rsa()).set_size_in_bits(size);
    let private = SecKey::new(&options).unwrap();
    let public = private.public_key().unwrap();
    let pkcs1 = public.external_representation().unwrap();
    let spki = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: PKIXALG_RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        },
        subject_public_key: bits(pkcs1.bytes()),
    };
    (private, spki)
}

fn pss_alg(hash: ObjectIdentifier, salt_len: u32) -> AlgorithmIdentifierOwned {
    #[derive(der::Sequence)]
    struct Params {
        #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
        hash: AlgorithmIdentifierOwned,
        #[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
        mask_gen: AlgorithmIdentifierOwned,
        #[asn1(context_specific = "2", tag_mode = "EXPLICIT")]
        salt_len: u32,
    }
    let hash_alg = AlgorithmIdentifierOwned {
        oid: hash,
        parameters: Some(Any::null()),
    };
    let params = Params {
        hash: hash_alg.clone(),
        mask_gen: AlgorithmIdentifierOwned {
            oid: PKIXALG_MGF1,
            parameters: Some(Any::encode_from(&hash_alg).unwrap()),
        },
        salt_len,
    };
    AlgorithmIdentifierOwned {
        oid: PKIXALG_RSASSA_PSS,
        parameters: Some(Any::encode_from(&params).unwrap()),
    }
}

fn rsa_cases() -> Vec<(&'static str, Case)> {
    let (key, spki) = rsa_key(2048);
    let (key3072, spki3072) = rsa_key(3072);
    let sign = |key: &SecKey, algorithm| key.create_signature(algorithm, MESSAGE).unwrap();
    vec![
        (
            "RSA-2048 PKCS #1 SHA-256",
            Case {
                spki: spki.clone(),
                alg: plain(PKIXALG_SHA256_WITH_RSA_ENCRYPTION),
                signature: sign(&key, Algorithm::RSASignatureMessagePKCS1v15SHA256),
                digest: sha2::Sha256::digest(MESSAGE).to_vec(),
            },
        ),
        (
            "RSA-3072 PKCS #1 SHA-384",
            Case {
                spki: spki3072.clone(),
                alg: plain(PKIXALG_SHA384_WITH_RSA_ENCRYPTION),
                signature: sign(&key3072, Algorithm::RSASignatureMessagePKCS1v15SHA384),
                digest: sha2::Sha384::digest(MESSAGE).to_vec(),
            },
        ),
        (
            "RSA-2048 PSS SHA-256",
            Case {
                spki: spki.clone(),
                alg: pss_alg(PKIXALG_SHA256, 32),
                signature: sign(&key, Algorithm::RSASignatureMessagePSSSHA256),
                digest: sha2::Sha256::digest(MESSAGE).to_vec(),
            },
        ),
        (
            "RSA-3072 PSS SHA-384",
            Case {
                spki: spki3072,
                alg: pss_alg(PKIXALG_SHA384, 48),
                signature: sign(&key3072, Algorithm::RSASignatureMessagePSSSHA384),
                digest: sha2::Sha384::digest(MESSAGE).to_vec(),
            },
        ),
    ]
}

fn all_cases() -> Vec<(&'static str, Case)> {
    let mut cases = ec_cases();
    cases.extend(rsa_cases());
    cases
}

fn is_rejection(result: &certval::Result<()>) -> bool {
    matches!(
        result,
        Err(Error::PathValidation(
            PathValidationStatus::SignatureVerificationFailure
        ))
    )
}

#[test]
fn good_signatures_verify_through_both_interfaces() {
    let pe = pe();
    let crypto = SecurityFrameworkCrypto::new();
    for (name, case) in all_cases() {
        let signature = bits(&case.signature);

        let platform =
            crypto.verify_signature_message(&pe, MESSAGE, &signature, &case.alg, &case.spki);
        assert!(platform.is_ok(), "{name}, message: {platform:?}");
        let software =
            verify_signature_message_rust_crypto(&pe, MESSAGE, &signature, &case.alg, &case.spki);
        assert!(
            software.is_ok(),
            "{name}, software disagrees on the message: {software:?}"
        );

        let platform =
            crypto.verify_signature_digest(&pe, &case.digest, &signature, &case.alg, &case.spki);
        assert!(platform.is_ok(), "{name}, digest: {platform:?}");
    }
}

#[test]
fn a_changed_message_is_a_verdict_not_a_refusal() {
    let pe = pe();
    let crypto = SecurityFrameworkCrypto::new();
    let other = b"a different to-be-signed structure";
    for (name, case) in all_cases() {
        let signature = bits(&case.signature);
        let platform =
            crypto.verify_signature_message(&pe, other, &signature, &case.alg, &case.spki);
        assert!(is_rejection(&platform), "{name}: {platform:?}");
        let software =
            verify_signature_message_rust_crypto(&pe, other, &signature, &case.alg, &case.spki);
        assert!(
            software.is_err(),
            "{name}: software accepted a changed message"
        );
    }
}

#[test]
fn a_changed_signature_is_a_verdict_not_a_refusal() {
    let pe = pe();
    let crypto = SecurityFrameworkCrypto::new();
    for (name, case) in all_cases() {
        let mut tampered = case.signature.clone();
        // The last byte is inside the signature value for every encoding here: the low byte of `s`
        // for a DER ECDSA signature, and the low byte of the integer for RSA.
        *tampered.last_mut().unwrap() ^= 0x01;
        let signature = bits(&tampered);

        let platform =
            crypto.verify_signature_message(&pe, MESSAGE, &signature, &case.alg, &case.spki);
        assert!(is_rejection(&platform), "{name}, message: {platform:?}");

        let platform =
            crypto.verify_signature_digest(&pe, &case.digest, &signature, &case.alg, &case.spki);
        assert!(is_rejection(&platform), "{name}, digest: {platform:?}");
    }
}

#[test]
fn a_signature_under_another_key_is_a_verdict() {
    let pe = pe();
    let crypto = SecurityFrameworkCrypto::new();
    let cases = ec_cases();
    let (_, p256) = &cases[0];
    let other = ec_case!(
        p256,
        PKIXALG_SECP256R1,
        PKIXALG_ECDSA_WITH_SHA256,
        sha2::Sha256,
        [0x44u8; 32]
    );
    let result = crypto.verify_signature_message(
        &pe,
        MESSAGE,
        &bits(&p256.signature),
        &p256.alg,
        &other.spki,
    );
    assert!(is_rejection(&result), "{result:?}");
}

#[test]
fn a_digest_of_the_wrong_length_is_declined() {
    let pe = pe();
    let crypto = SecurityFrameworkCrypto::new();
    for (name, case) in rsa_cases() {
        let short = &case.digest[..case.digest.len() - 1];
        let result = crypto.verify_signature_digest(
            &pe,
            short,
            &bits(&case.signature),
            &case.alg,
            &case.spki,
        );
        assert!(result.is_err(), "{name}: accepted a truncated digest");
    }
}

#[test]
fn a_pss_salt_the_platform_cannot_honor_is_left_to_software() {
    let pe = pe();
    let crypto = SecurityFrameworkCrypto::new();
    let (key, spki) = rsa_key(2048);
    let signature = key
        .create_signature(Algorithm::RSASignatureMessagePSSSHA256, MESSAGE)
        .unwrap();
    // The signature was made with a 32-byte salt, so naming 20 describes a different signature.
    // Security.framework cannot be told the salt length, so the provider must not answer.
    let alg = pss_alg(PKIXALG_SHA256, 20);
    let result = crypto.verify_signature_message(&pe, MESSAGE, &bits(&signature), &alg, &spki);
    assert!(matches!(result, Err(Error::Unrecognized)), "{result:?}");
}

#[test]
fn a_pkcs1_signature_under_a_pss_key_is_left_to_software() {
    let pe = pe();
    let crypto = SecurityFrameworkCrypto::new();
    let (key, mut spki) = rsa_key(2048);
    spki.algorithm = plain(PKIXALG_RSASSA_PSS);
    let signature = key
        .create_signature(Algorithm::RSASignatureMessagePKCS1v15SHA256, MESSAGE)
        .unwrap();
    let alg = plain(PKIXALG_SHA256_WITH_RSA_ENCRYPTION);

    let result = crypto.verify_signature_message(&pe, MESSAGE, &bits(&signature), &alg, &spki);
    assert!(matches!(result, Err(Error::Unrecognized)), "{result:?}");

    // And software, which then answers, rejects it.
    let software =
        verify_signature_message_rust_crypto(&pe, MESSAGE, &bits(&signature), &alg, &spki);
    assert!(is_rejection(&software), "{software:?}");
}

#[test]
fn registered_first_it_answers_and_software_agrees() {
    let mut pe = PkiEnvironment::default();
    pe.add_verify_signature_message_callback(SecurityFrameworkCrypto::new());
    pe.add_verify_signature_digest_callback(SecurityFrameworkCrypto::new());
    pe.populate_5280_pki_environment();

    for (name, case) in all_cases() {
        let signature = bits(&case.signature);
        assert!(
            pe.verify_signature_message(&pe, MESSAGE, &signature, &case.alg, &case.spki)
                .is_ok(),
            "{name}"
        );
        // certval's software digest verifier covers RSA, so for the RSA cases this also checks the
        // platform's digest verdict against software.
        if verify_signature_digest_rust_crypto(&pe, &case.digest, &signature, &case.alg, &case.spki)
            .is_ok()
        {
            assert!(
                pe.verify_signature_digest(&pe, &case.digest, &signature, &case.alg, &case.spki)
                    .is_ok(),
                "{name}"
            );
        }
    }
}
