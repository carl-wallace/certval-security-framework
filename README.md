# certval-security-framework

A Security.framework crypto provider for [certval](https://github.com/carl-wallace/rust-pki). It
supplies implementations of the signature verification callbacks that a `PkiEnvironment` dispatches
through, so certification path validation on macOS and iOS can be performed with Apple's platform
cryptography rather than the in-process software implementation.

The crate is empty on targets other than Apple's, so a workspace that builds for several platforms
can depend on it unconditionally and register the provider only where it exists.

```rust
use certval::PkiEnvironment;
use certval_security_framework::SecurityFrameworkCrypto;

let mut pe = PkiEnvironment::default();

// Registering before populate_5280_pki_environment puts Security.framework ahead of the software
// implementations, so it is consulted first and software answers only what it declined.
pe.add_verify_signature_message_callback(SecurityFrameworkCrypto::new());
pe.add_verify_signature_digest_callback(SecurityFrameworkCrypto::new());

pe.populate_5280_pki_environment();
```

The provider holds no state. Each verification imports the issuer's key with `SecKeyCreateWithData`,
verifies with `SecKeyVerifySignature`, and releases the key; an import is an in-process call, so
there is nothing for a key cache to save.

## Registration is additive

`PkiEnvironment` consults registered implementations in order and stops at the first verdict. The
provider reports a rejection only when Security.framework judged the signature invalid
(`errSecVerifyFailed`); anything else it declines, and a declined verification falls through to the
next implementation. That lets the platform answer for the algorithms it offers while software
covers the rest.

It also means registering the provider does not by itself guarantee that every verification reaches
Security.framework. A caller who requires that must make the registration exclusive:

```rust
pe.populate_5280_pki_environment();
pe.clear_verify_signature_message_callbacks();
pe.clear_verify_signature_digest_callbacks();
pe.add_verify_signature_message_callback(SecurityFrameworkCrypto::new());
pe.add_verify_signature_digest_callback(SecurityFrameworkCrypto::new());
```

## Algorithm coverage

| Signature algorithm | Message interface | Digest interface |
|---|---|---|
| RSA PKCS #1 v1.5, SHA-224/256/384/512 | `RSASignatureMessagePKCS1v15SHA*` | `RSASignatureDigestPKCS1v15SHA*` |
| RSASSA-PSS, SHA-224/256/384/512 | `RSASignatureMessagePSSSHA*` | `RSASignatureDigestPSSSHA*` |
| ECDSA on P-256/384/521, SHA-224/256/384/512 | `ECDSASignatureMessageX962SHA*` | `ECDSASignatureDigestX962SHA*` |
| ML-DSA-65/87, with `pqc`, OS 26 or later | CryptoKit `MLDSA65`/`MLDSA87` | not applicable |

Anything else is declined, and software answers it. Three cases are declined deliberately:

- **RSASSA-PSS with parameters Security.framework cannot express.** Its PSS algorithms fix MGF1 over
  the message hash and a salt as long as the hash. A parameter block naming another mask, another
  salt length, or relying on RFC 4055's SHA-1 defaults describes a signature those algorithms would
  misjudge.
- **An elliptic curve key on any curve but P-256, P-384 or P-521.** `SecKeyCreateWithData` infers the
  curve from the length of the point, so a point on another 256-bit curve would be read as a P-256
  point. The named curve is checked before the platform sees the key.
- **A PKCS #1 v1.5 signature under a key identified as `id-RSASSA-PSS`.** RFC 4055 restricts such a
  key to PSS, and certval's software verifier rejects the combination, so it gives that verdict.

### ML-DSA

With the `pqc` feature, ML-DSA-65 and ML-DSA-87 are verified by CryptoKit on macOS and iOS 26 and
later. Security.framework's C interface has no ML-DSA and CryptoKit is Swift-only, so the feature
compiles a small Swift shim (`swift/MLDSAShim.swift`) in `build.rs`, which needs Xcode's Swift
toolchain and a 26 SDK. Without the feature, nothing Swift is built.

CryptoKit has no ML-DSA-44 and no SLH-DSA, and an OS older than 26 has no ML-DSA at all. Those are
declined, and software answers them: the same feature enables certval's software ML-DSA and SLH-DSA,
so with it on, every post-quantum signature has an answer. `SecurityFrameworkCrypto::ml_dsa_available()`
reports whether CryptoKit's ML-DSA is in use. As with the other algorithms, a key must be identified
by the same object identifier as its signature, and an identifier carrying parameters (which RFC 9881
forbids) is declined.

## Hashing

The provider implements verification only. Security.framework offers no digest function, so
`CalculateHash` stays with whatever else is registered. The message interface is unaffected: a
`...Message...` algorithm hashes the message inside the platform.

## Testing

`cargo test` runs the unit tests and the signature tests with no setup. The signature tests verify
ECDSA signatures made by RustCrypto with fixed keys, and RSA and RSASSA-PSS signatures from keys
Security.framework generates in memory (never in a keychain), and check every verdict against certval's
software verifier. Each good signature is also checked with a changed message and with a changed
signature, which must be **rejections**, not refusals.

The collection tests verify certificates through the provider and compare against software. No
certificates are carried in this repository; the collections are named by environment variables, and
a test whose collection is not set reports that and passes.

| Variable | Meaning |
|---|---|
| `CERTVAL_SF_RSA_CERTS` | directory of RSA-signed certificates |
| `CERTVAL_SF_ECDSA_CERTS` | directory of ECDSA-signed certificates |
| `CERTVAL_SF_PSS_CERTS` | directory of RSASSA-PSS-signed certificates |
| `CERTVAL_SF_MLDSA_CERTS` | directories of ML-DSA-signed certificates, separated as `PATH` is; CryptoKit must answer 65 and 87 when available, and nothing else |

```sh
export EX=../rust-pki/certval/tests/examples
export CERTVAL_SF_RSA_CERTS=$EX/PKITS_data_2048/certs
export CERTVAL_SF_ECDSA_CERTS=$EX/PKITS_data_p256/certs
export CERTVAL_SF_PSS_CERTS=$EX/rsapss
export CERTVAL_SF_MLDSA_CERTS=$EX/pkits_ml_dsa_44/certs:$EX/pkits_ml_dsa_65/certs:$EX/pkits_ml_dsa_87/certs

cargo test --features pqc -- --nocapture
```

The assertion in each case is **agreement**, not success, and `--nocapture` prints how many
verifications the platform answered itself. The `pqc` feature builds the CryptoKit shim and gives the
ML-DSA collections a software verdict to compare against.

## Status

Run on macOS 26.6 (Apple silicon) against rust-pki's PKITS collections: Security.framework answered
all 389 RSA and 388 ECDSA verifications that software accepted, with no disagreements in either
interface. With `pqc`, CryptoKit answered 391 of the 394 ML-DSA-65 and ML-DSA-87 verifications
software accepted in each collection, with no disagreements; the other 3 in each are signed with
ML-DSA-44, which CryptoKit lacks, and went to software. ML-DSA-44 went entirely to software. Builds for iOS; not yet run there. Not yet published to
crates.io.

Whether Apple's corecrypto validation covers a given OS release is a question for NIST's CMVP list,
not for this crate.

certval is consumed from crates.io. A commented `[patch.crates-io]` line in `Cargo.toml` redirects
the dependency to a local checkout for developing both crates together.

## License

Apache-2.0 OR MIT.
