//! Security.framework crypto provider for [`certval`].
//!
//! [`certval`] performs signature verification through callbacks registered on a
//! [`PkiEnvironment`](certval::PkiEnvironment). This crate supplies an implementation of those
//! callbacks that routes the work to Apple's Security.framework (`SecKeyCreateWithData` and
//! `SecKeyVerifySignature`), so certification path validation on macOS and iOS can be performed
//! with the operating system's cryptographic module rather than the in-process software
//! implementation.
//!
//! The crate is empty on targets other than Apple's, so a workspace that builds for several
//! platforms can depend on it unconditionally and register it only where it exists.
//!
//! ```no_run
//! # #[cfg(target_vendor = "apple")]
//! # {
//! use certval::PkiEnvironment;
//! use certval_security_framework::SecurityFrameworkCrypto;
//!
//! let mut pe = PkiEnvironment::default();
//!
//! // Registering before populate_5280_pki_environment puts Security.framework ahead of the
//! // software implementations, so it is consulted first and software answers only what it
//! // declined.
//! pe.add_verify_signature_message_callback(SecurityFrameworkCrypto::new());
//! pe.add_verify_signature_digest_callback(SecurityFrameworkCrypto::new());
//!
//! pe.populate_5280_pki_environment();
//! # }
//! ```
//!
//! # Registration is additive
//!
//! [`PkiEnvironment`](certval::PkiEnvironment) consults registered implementations in order and
//! stops at the first verdict. The provider reports a rejection only when Security.framework judged
//! the signature invalid; anything else it declines, and a declined verification falls through to
//! the next implementation. A caller who requires that every verification reach Security.framework
//! must make the registration exclusive by clearing the software callbacks first:
//!
//! ```no_run
//! # #[cfg(target_vendor = "apple")]
//! # {
//! # use certval::PkiEnvironment;
//! # use certval_security_framework::SecurityFrameworkCrypto;
//! # let mut pe = PkiEnvironment::default();
//! pe.populate_5280_pki_environment();
//! pe.clear_verify_signature_message_callbacks();
//! pe.clear_verify_signature_digest_callbacks();
//! pe.add_verify_signature_message_callback(SecurityFrameworkCrypto::new());
//! pe.add_verify_signature_digest_callback(SecurityFrameworkCrypto::new());
//! # }
//! ```
//!
//! # ML-DSA
//!
//! With the `pqc` feature, ML-DSA-65 and ML-DSA-87 signatures are verified by CryptoKit on macOS
//! and iOS 26 and later, through a small Swift shim that the build compiles (so the feature needs
//! Xcode's Swift toolchain). CryptoKit has no ML-DSA-44 and no SLH-DSA, and an older OS has no
//! ML-DSA at all; those are declined and software answers them. The same feature enables
//! certval's software ML-DSA and SLH-DSA, so with it on, every post-quantum signature has an
//! answer. [`SecurityFrameworkCrypto::ml_dsa_available`] reports whether CryptoKit's ML-DSA is
//! present. With the `cms` feature as well, `CryptoKitSigningKey` signs SignedData with an
//! ML-DSA-65 or ML-DSA-87 key held in memory or in the Secure Enclave.
//!
//! # ML-KEM
//!
//! With the `cms` and `pqc` features, ML-KEM-768 and ML-KEM-1024 KEMRecipientInfo are performed by
//! CryptoKit through the same shim: [`SecurityFrameworkCrypto`] encrypts to an ML-KEM recipient, and
//! `CryptoKitRecipientKey` decrypts with a key held in memory or in the Secure Enclave. The
//! shared secret stays in CryptoKit. ML-KEM-512, which CryptoKit lacks, is declined.
//! [`SecurityFrameworkCrypto::ml_kem_available`] and
//! [`SecurityFrameworkCrypto::secure_enclave_available`] report what the device offers.
//!
//! # Hashing
//!
//! Security.framework offers no digest function, so [`CalculateHash`](certval::CalculateHash) is
//! implemented with CommonCrypto, its companion interface over the same module, corecrypto: SHA-1,
//! SHA-224, SHA-256, SHA-384 and SHA-512. The message interface hashes inside Security.framework
//! too: `SecKeyVerifySignature` hashes the message itself with a `...Message...` algorithm.

#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(target_vendor = "apple")]
mod algorithm;
#[cfg(all(target_vendor = "apple", feature = "cms"))]
mod cms;
#[cfg(target_vendor = "apple")]
#[allow(unsafe_code)]
mod commoncrypto;
#[cfg(all(target_vendor = "apple", feature = "cms", feature = "pqc"))]
mod cryptokit;
#[cfg(target_vendor = "apple")]
#[allow(unsafe_code)]
mod key;
#[cfg(all(target_vendor = "apple", feature = "pqc"))]
#[allow(unsafe_code)]
mod mldsa;
#[cfg(all(target_vendor = "apple", feature = "cms", feature = "pqc"))]
#[allow(unsafe_code)]
mod mlkem;
#[cfg(target_vendor = "apple")]
mod provider;

#[cfg(all(target_vendor = "apple", feature = "cms"))]
pub use cms::{
    import_pkcs8, KeychainIdentities, SecurityFrameworkRecipientKey, SecurityFrameworkSigningKey,
};
#[cfg(all(target_vendor = "apple", feature = "cms", feature = "pqc"))]
pub use cryptokit::{CryptoKitRecipientKey, CryptoKitSigningKey};
#[cfg(target_vendor = "apple")]
pub use provider::SecurityFrameworkCrypto;
