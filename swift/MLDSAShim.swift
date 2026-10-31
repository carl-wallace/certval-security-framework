// ML-DSA verification through CryptoKit, exposed to Rust as C functions.
//
// CryptoKit is a Swift-only API, so this is the one piece of the crate written in Swift. It is
// compiled into a static library by build.rs when the `pqc` feature is enabled, and called from
// src/mldsa.rs. Only public data crosses the boundary.

import CryptoKit
import Foundation

/// Returns 1 when the running OS has CryptoKit's ML-DSA (macOS and iOS 26 and later), 0 otherwise.
@_cdecl("certval_sf_mldsa_available")
public func certval_sf_mldsa_available() -> Int32 {
    if #available(macOS 26.0, iOS 26.0, *) {
        return 1
    }
    return 0
}

/// Verifies a pure ML-DSA signature with an empty context string, which is what a certificate
/// signature uses.
///
/// `parameterSet` is 65 or 87. `key` is the raw public key, as carried in the
/// `subjectPublicKey` of a `SubjectPublicKeyInfo`.
///
/// Returns 1 for a valid signature, 0 for one that is not, -1 when the key is refused or the
/// parameter set is not one CryptoKit offers, and -2 when the running OS has no ML-DSA.
@_cdecl("certval_sf_mldsa_verify")
public func certval_sf_mldsa_verify(
    _ parameterSet: Int32,
    _ key: UnsafePointer<UInt8>,
    _ keyLen: Int,
    _ message: UnsafePointer<UInt8>,
    _ messageLen: Int,
    _ signature: UnsafePointer<UInt8>,
    _ signatureLen: Int
) -> Int32 {
    guard #available(macOS 26.0, iOS 26.0, *) else {
        return -2
    }

    let keyData = Data(bytes: key, count: keyLen)
    let messageData = Data(bytes: message, count: messageLen)
    let signatureData = Data(bytes: signature, count: signatureLen)

    do {
        let valid: Bool
        switch parameterSet {
        case 65:
            let publicKey = try MLDSA65.PublicKey(rawRepresentation: keyData)
            valid = publicKey.isValidSignature(signatureData, for: messageData)
        case 87:
            let publicKey = try MLDSA87.PublicKey(rawRepresentation: keyData)
            valid = publicKey.isValidSignature(signatureData, for: messageData)
        default:
            return -1
        }
        return valid ? 1 : 0
    } catch {
        return -1
    }
}
