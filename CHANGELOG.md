# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

## [0.1.0-rc.1] - 2026-10-31

Initial release. Verifies RSA PKCS #1 v1.5, RSASSA-PSS and ECDSA (P-256/384/521) certificate
signatures through Security.framework on macOS and iOS, through both of certval's verification
interfaces. The `pqc` feature adds ML-DSA-65 and ML-DSA-87 through CryptoKit on macOS and iOS 26 and
later, by way of a Swift shim, and enables certval's software ML-DSA and SLH-DSA for the rest.
MSRV 1.88.
