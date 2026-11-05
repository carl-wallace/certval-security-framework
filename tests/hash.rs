//! CommonCrypto's digests, through `CalculateHash`, agree with RustCrypto's for every algorithm the
//! provider takes, over inputs of several lengths, and other algorithms are declined.

#![cfg(target_vendor = "apple")]

use certval::{CalculateHash, PkiEnvironment};
use certval_security_framework::SecurityFrameworkCrypto;
use const_oid::db::rfc5912::{ID_MD_5, ID_SHA_1, ID_SHA_224, ID_SHA_256, ID_SHA_384, ID_SHA_512};
use sha2::Digest;
use spki::AlgorithmIdentifierOwned;

fn alg(oid: const_oid::ObjectIdentifier) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    }
}

#[test]
fn commoncrypto_digests_agree_with_rustcrypto() {
    let pe = PkiEnvironment::default();
    let crypto = SecurityFrameworkCrypto::new();
    for len in [0usize, 1, 55, 56, 64, 127, 128, 1000, 65537] {
        let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        let cases: [(_, Vec<u8>); 5] = [
            (ID_SHA_1, sha1::Sha1::digest(&data).to_vec()),
            (ID_SHA_224, sha2::Sha224::digest(&data).to_vec()),
            (ID_SHA_256, sha2::Sha256::digest(&data).to_vec()),
            (ID_SHA_384, sha2::Sha384::digest(&data).to_vec()),
            (ID_SHA_512, sha2::Sha512::digest(&data).to_vec()),
        ];
        for (oid, expected) in cases {
            assert_eq!(
                crypto.calculate_hash(&pe, &alg(oid), &data).unwrap(),
                expected,
                "{oid} over {len} octets"
            );
        }
    }
    assert!(matches!(
        crypto.calculate_hash(&pe, &alg(ID_MD_5), b"x"),
        Err(certval::Error::Unrecognized)
    ));
}
