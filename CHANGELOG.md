# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

## Unreleased

`CalculateHash`, by CommonCrypto: SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512. A `cms` feature
implements certval-cms's AES-CBC content encryption and decryption (CommonCrypto), RSA key transport
and ECDH key agreement with the X9.63 KDF (Security.framework), with `SecurityFrameworkRecipientKey`
and `SecurityFrameworkSigningKey` decrypting and signing with Security.framework keys and
`KeychainIdentities` finding them in the keychain, and listing them with `certificates()`.
`import_pkcs8` makes both credentials for a PKCS #8 RSA or EC key, checked against its certificate.
With `cms` and `pqc`, ML-KEM-768 and ML-KEM-1024 by CryptoKit: `SecurityFrameworkCrypto` encrypts to
ML-KEM recipients, and `CryptoKitRecipientKey` decrypts with a key held as a seed or in the Secure
Enclave, with the encapsulation, decapsulation and HKDF inside CryptoKit. `CryptoKitSigningKey` signs
with ML-DSA-65 and ML-DSA-87 by CryptoKit, with a key held as a seed or in the Secure Enclave.

## [0.1.0-rc.1] - 2026-10-31

Initial release. Verifies RSA PKCS #1 v1.5, RSASSA-PSS and ECDSA (P-256/384/521) certificate
signatures through Security.framework on macOS and iOS, through both of certval's verification
interfaces. The `pqc` feature adds ML-DSA-65 and ML-DSA-87 through CryptoKit on macOS and iOS 26 and
later, by way of a Swift shim, and enables certval's software ML-DSA and SLH-DSA for the rest.
MSRV 1.89.
