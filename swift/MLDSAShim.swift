// ML-DSA through CryptoKit, exposed to Rust as C functions: verification, and signing with a key
// held in memory or in the Secure Enclave.
//
// CryptoKit is a Swift-only API, so this and MLKEMShim.swift are the pieces of the crate written in
// Swift. They are compiled into a static library by build.rs when the `pqc` feature is enabled,
// and called from src/mldsa.rs. Verification passes only public data. Signing is stateless, as
// ML-KEM's decapsulation is: a private key crosses on each call, as the seed of a key held in
// memory or the `dataRepresentation` of a Secure Enclave key, which only this device's Secure
// Enclave can use.

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

/// Copies `data` into `out`, whose capacity is `capacity`, and its length into `outLen`.
private func copyOut(
    _ data: Data, _ out: UnsafeMutablePointer<UInt8>, _ capacity: Int,
    _ outLen: UnsafeMutablePointer<Int>
) -> Bool {
    guard data.count <= capacity else {
        return false
    }
    data.copyBytes(to: out, count: data.count)
    outLen.pointee = data.count
    return true
}

/// Signs `message` with pure ML-DSA and an empty context string, as a certificate or CMS signature
/// is made, and writes the signature.
///
/// `parameterSet` is 65 or 87. `keyKind` is 0 for a key held in memory, `key` being its 32-octet
/// seed and `publicKey` the raw public key it must generate, or 1 for a Secure Enclave key, `key`
/// being its `dataRepresentation` (`publicKey` is then unused).
///
/// Returns 1 for a signature, 0 when signing failed, -1 when the key is refused or the parameter
/// set is not one CryptoKit offers, -2 when the running OS has no ML-DSA, and -3 when the output
/// buffer is too small.
@_cdecl("certval_sf_mldsa_sign")
public func certval_sf_mldsa_sign(
    _ parameterSet: Int32,
    _ keyKind: Int32,
    _ key: UnsafePointer<UInt8>, _ keyLen: Int,
    _ publicKey: UnsafePointer<UInt8>, _ publicKeyLen: Int,
    _ message: UnsafePointer<UInt8>, _ messageLen: Int,
    _ signatureOut: UnsafeMutablePointer<UInt8>, _ signatureCapacity: Int,
    _ signatureLen: UnsafeMutablePointer<Int>
) -> Int32 {
    guard #available(macOS 26.0, iOS 26.0, *) else {
        return -2
    }
    // A seed is read in place from the caller's buffer, which the caller zeroizes; a copy into
    // Data would be freed without being wiped. A Secure Enclave key's data representation is
    // the enclave's wrapped form, not the key, and is copied.
    let seed = UnsafeRawBufferPointer(start: key, count: keyLen)
    let publicData = Data(bytes: publicKey, count: publicKeyLen)
    let messageData = Data(bytes: message, count: messageLen)
    let signature: Data
    do {
        switch (parameterSet, keyKind) {
        case (65, 0):
            let privateKey = try MLDSA65.PrivateKey(
                seedRepresentation: seed,
                publicKey: try MLDSA65.PublicKey(rawRepresentation: publicData))
            signature = try privateKey.signature(for: messageData)
        case (87, 0):
            let privateKey = try MLDSA87.PrivateKey(
                seedRepresentation: seed,
                publicKey: try MLDSA87.PublicKey(rawRepresentation: publicData))
            signature = try privateKey.signature(for: messageData)
        case (65, 1):
            signature = try SecureEnclave.MLDSA65.PrivateKey(
                dataRepresentation: Data(bytes: key, count: keyLen)
            ).signature(for: messageData)
        case (87, 1):
            signature = try SecureEnclave.MLDSA87.PrivateKey(
                dataRepresentation: Data(bytes: key, count: keyLen)
            ).signature(for: messageData)
        default:
            return -1
        }
    } catch {
        return 0
    }
    return copyOut(signature, signatureOut, signatureCapacity, signatureLen) ? 1 : -3
}

/// Generates an ML-DSA key in the Secure Enclave, with the default access control (usable after
/// first unlock, on this device only, without user presence), and writes its
/// `dataRepresentation` and raw public key.
///
/// `parameterSet` is 65 or 87.
@_cdecl("certval_sf_mldsa_secure_enclave_generate")
public func certval_sf_mldsa_secure_enclave_generate(
    _ parameterSet: Int32,
    _ dataOut: UnsafeMutablePointer<UInt8>, _ dataCapacity: Int,
    _ dataLen: UnsafeMutablePointer<Int>,
    _ publicOut: UnsafeMutablePointer<UInt8>, _ publicCapacity: Int,
    _ publicLen: UnsafeMutablePointer<Int>
) -> Int32 {
    guard #available(macOS 26.0, iOS 26.0, *) else {
        return -2
    }
    guard SecureEnclave.isAvailable else {
        return -1
    }
    do {
        let data: Data
        let publicKey: Data
        switch parameterSet {
        case 65:
            let key = try SecureEnclave.MLDSA65.PrivateKey()
            (data, publicKey) = (key.dataRepresentation, key.publicKey.rawRepresentation)
        case 87:
            let key = try SecureEnclave.MLDSA87.PrivateKey()
            (data, publicKey) = (key.dataRepresentation, key.publicKey.rawRepresentation)
        default:
            return -1
        }
        guard copyOut(data, dataOut, dataCapacity, dataLen),
            copyOut(publicKey, publicOut, publicCapacity, publicLen)
        else {
            return -3
        }
        return 1
    } catch {
        return 0
    }
}

/// Writes the raw public key of the Secure Enclave ML-DSA key whose `dataRepresentation` is `data`.
@_cdecl("certval_sf_mldsa_secure_enclave_public_key")
public func certval_sf_mldsa_secure_enclave_public_key(
    _ parameterSet: Int32,
    _ data: UnsafePointer<UInt8>, _ dataLength: Int,
    _ publicOut: UnsafeMutablePointer<UInt8>, _ publicCapacity: Int,
    _ publicLen: UnsafeMutablePointer<Int>
) -> Int32 {
    guard #available(macOS 26.0, iOS 26.0, *) else {
        return -2
    }
    let representation = Data(bytes: data, count: dataLength)
    do {
        let publicKey: Data
        switch parameterSet {
        case 65:
            publicKey = try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: representation)
                .publicKey.rawRepresentation
        case 87:
            publicKey = try SecureEnclave.MLDSA87.PrivateKey(dataRepresentation: representation)
                .publicKey.rawRepresentation
        default:
            return -1
        }
        return copyOut(publicKey, publicOut, publicCapacity, publicLen) ? 1 : -3
    } catch {
        return -1
    }
}

/// Writes the raw public key of the ML-DSA key the 32-octet seed `seed` generates, for a key held
/// in memory that has no certificate to take its public key from.
@_cdecl("certval_sf_mldsa_seed_public_key")
public func certval_sf_mldsa_seed_public_key(
    _ parameterSet: Int32,
    _ seed: UnsafePointer<UInt8>, _ seedLen: Int,
    _ publicOut: UnsafeMutablePointer<UInt8>, _ publicCapacity: Int,
    _ publicLen: UnsafeMutablePointer<Int>
) -> Int32 {
    guard #available(macOS 26.0, iOS 26.0, *) else {
        return -2
    }
    // Read in place, as in signing: a copy into Data would be freed without being wiped.
    let seed = UnsafeRawBufferPointer(start: seed, count: seedLen)
    do {
        let publicKey: Data
        switch parameterSet {
        case 65:
            publicKey = try MLDSA65.PrivateKey(seedRepresentation: seed, publicKey: nil)
                .publicKey.rawRepresentation
        case 87:
            publicKey = try MLDSA87.PrivateKey(seedRepresentation: seed, publicKey: nil)
                .publicKey.rawRepresentation
        default:
            return -1
        }
        return copyOut(publicKey, publicOut, publicCapacity, publicLen) ? 1 : -3
    } catch {
        return -1
    }
}
