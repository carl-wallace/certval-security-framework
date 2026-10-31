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
//! present.
//!
//! # Hashing
//!
//! The provider implements verification only. Security.framework offers no digest function, so
//! [`CalculateHash`](certval::CalculateHash) stays with whatever else is registered. The message
//! interface is unaffected: `SecKeyVerifySignature` hashes the message itself with a
//! `...Message...` algorithm, so the hash a signature covers is computed inside the platform module.

#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(target_vendor = "apple")]
mod algorithm;
#[cfg(target_vendor = "apple")]
#[allow(unsafe_code)]
mod key;
#[cfg(all(target_vendor = "apple", feature = "pqc"))]
#[allow(unsafe_code)]
mod mldsa;
#[cfg(target_vendor = "apple")]
mod provider;

#[cfg(target_vendor = "apple")]
pub use provider::SecurityFrameworkCrypto;
