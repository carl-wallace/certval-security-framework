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

Security.framework offers no digest function, so `CalculateHash` is implemented with CommonCrypto,
its companion C interface over the same module, corecrypto: SHA-1, SHA-224, SHA-256, SHA-384 and
SHA-512. The message interface hashes inside Security.framework too: a `...Message...` algorithm
hashes the message itself.

## CMS

With the `cms` feature, `SecurityFrameworkCrypto` also implements
[certval-cms](https://github.com/carl-wallace/certval-cms)'s content encryption and decryption, key
transport and key agreement, and Security.framework keys serve as credentials:
`SecurityFrameworkRecipientKey` decrypts, `SecurityFrameworkSigningKey` signs, and
`KeychainIdentities` finds both among the keychain's identities and those on smart cards
CryptoTokenKit presents (a CAC or PIV card): a decryption key by the recipient identifier a message
contains, and signing keys by signer identifier, email address or subject, and `certificates()`
lists them. `import_pkcs8` makes both credentials for an RSA or EC key held as
PKCS #8, created in memory and not added to a keychain.

With `cms` and `pqc`, ML-KEM is performed by CryptoKit, through the same Swift shim as ML-DSA:
`SecurityFrameworkCrypto` encrypts to ML-KEM-768 and ML-KEM-1024 recipients, and
`CryptoKitRecipientKey` decrypts with an ML-KEM key held in memory (from an RFC 9935 PKCS #8 key in
the `seed` or `both` form; CryptoKit takes the seed, so `expandedKey` alone is refused) or in the
Secure Enclave (from its `dataRepresentation`, e.g. one an app made with CryptoKit's
`SecureEnclave.MLKEM768.PrivateKey`). `CryptoKitRecipientKey::generate_in_secure_enclave` makes a
Secure Enclave key and returns its public key, to be certified. Each constructor checks the key
against the certificate. The shim is stateless: the seed or `dataRepresentation` is passed on every
call. CryptoKit performs the encapsulation or decapsulation and the HKDF, so the shared secret never
leaves it; the key-encryption key it returns is used by CommonCrypto's AES key wrap.
`SecurityFrameworkCrypto::ml_kem_available` and `secure_enclave_available` report what the running
device offers. A Secure Enclave key whose access control requires user presence asks for it at each
decryption. CryptoKit ML-KEM keys are not keychain identities, so `KeychainIdentities` does not find
them.

With `cms` and `pqc`, `CryptoKitSigningKey` signs with an ML-DSA-65 or ML-DSA-87 key in the same way:
held in memory (from an RFC 9881 PKCS #8 key in the `seed` or `both` form; `expandedKey` alone is
refused) or in the Secure Enclave (from its `dataRepresentation`, e.g. one made with CryptoKit's
`SecureEnclave.MLDSA65.PrivateKey`), with `generate_in_secure_enclave` to make one. Signatures are
pure ML-DSA with an empty context string, as RFC 9882 requires. Each constructor checks the key
against the certificate, and the shim is stateless, as for ML-KEM. ML-DSA-44, which CryptoKit does
not offer, is declined. Like the ML-KEM keys, these are not keychain identities.

A key with no certificate yet, e.g. one signing its own certificate request, is certval-cms's
`SigningKey`: `SecurityFrameworkKey` for an RSA or EC `SecKey` (`import_pkcs8_key` makes one from a
PKCS #8 key; an EC key must carry its public key, which Security.framework does not derive), and
`CryptoKitKey` for ML-DSA-65 and ML-DSA-87, held as a seed, whose public key CryptoKit derives, or in
the Secure Enclave.

| Operation | Coverage |
|---|---|
| Content encryption and decryption | AES-128/192/256-CBC, by CommonCrypto; AES-GCM, which CommonCrypto does not offer, is declined |
| Key transport | RSAES-PKCS1-v1_5, RSAES-OAEP with SHA-1/256/384/512, by `SecKeyCreateEncryptedData` and `SecKeyCreateDecryptedData` |
| Key agreement | ephemeral-static ECDH on P-256, P-384 and P-521 with the X9.63 KDF (SHA-256/384/512), by `SecKeyCopyKeyExchangeResult`, then CommonCrypto's AES key wrap |
| Signing | RSA PKCS #1 v1.5 and RSASSA-PSS, and ECDSA, by `SecKeyCreateSignature`; ML-DSA-65 and ML-DSA-87, by CryptoKit on macOS and iOS 26 and later, with `pqc`; ML-DSA-44 is declined |
| KEM | ML-KEM-768 and ML-KEM-1024 with HKDF-SHA256/384/512 (RFC 9629), by CryptoKit on macOS and iOS 26 and later, with `pqc`; ML-KEM-512, which CryptoKit does not offer, is declined, and without `pqc` or on an older OS, every KEM |

Security.framework performs ECDH and the X9.63 KDF in one call, so the shared secret never leaves
it, in either direction. An originator's ephemeral point in compressed form is refused, where
software and AWS-LC accept it; RFC 5753 makes compressed points a MAY, and OpenSSL sends
uncompressed ones.

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

With `cms` and `pqc`, the CMS tests also cross ML-KEM-768 and ML-KEM-1024 with software in both
directions, for every KDF and wrap, with keys held in memory and, where the device has a Secure
Enclave, keys generated there for the test. They also sign with ML-DSA-65 and ML-DSA-87 keys held as
seeds and, where the device has a Secure Enclave, generated there, and verify each signature with
software and with this provider alone. A process that cannot reach the Secure Enclave (e.g. one in a
restrictive sandbox), for which CryptoKit's
[`SecureEnclave.isAvailable`](https://developer.apple.com/documentation/cryptokit/secureenclave/isavailable)
is false, reports those tests as skipped when they are run with `--nocapture`.

## Status

Run on macOS 26.6 (Apple silicon) against rust-pki's PKITS collections: Security.framework answered
all 389 RSA and 388 ECDSA verifications that software accepted, with no disagreements in either
interface. With `pqc`, CryptoKit answered all 390 ML-DSA-65 and ML-DSA-87 verifications software
accepted in each collection (macOS 26.6.2, 2026-11-06), with no disagreements, and ML-DSA-44 went
entirely to software. On an iPhone with iOS 18.3.1 (2026-11-06), Security.framework signed with an
ECDSA P-256 key it generated and verified the signature, crossed with software, and CryptoKit's ML-KEM
and ML-DSA reported themselves unavailable, as an OS older than 26 should, rather than failing. On an
iPhone with iOS 26.5 (2026-11-06), with keys generated in the Secure Enclave and keys held as seeds,
CryptoKit decrypted ML-KEM-768 and ML-KEM-1024 messages software encrypted, and signed with ML-DSA-65
and ML-DSA-87, verified by software and by CryptoKit.

Whether Apple's corecrypto validation covers a given OS release is a question for NIST's CMVP list,
not for this crate.

With the `cms` feature, on macOS 26.6, every CMS test passes, crossed with certval-cms's software in
both directions, and the keychain is searched. With `cms` and `pqc`, on macOS 26.6.2 (Apple
silicon), the ML-KEM decryption and ML-DSA signing tests pass for keys in memory and in the Secure
Enclave.

certval-cms is not on crates.io yet, so `Cargo.toml`'s `[patch.crates-io]` takes it from a
neighboring checkout (`../certval-cms`), and CI checks it out there. Both go when it publishes, and
this crate cannot publish before it does.

certval is consumed from crates.io. A commented `[patch.crates-io]` line in `Cargo.toml` redirects
the dependency to a local checkout for developing both crates together.

## License

Apache-2.0 OR MIT.
