// ML-KEM through CryptoKit, exposed to Rust as C functions, for CMS KEMRecipientInfo.
//
// Compiled with MLDSAShim.swift by build.rs when the `pqc` feature is enabled, and called from
// src/mlkem.rs. Every function is stateless: a private key crosses the boundary as its
// representation on each call, either the seed of a key held in memory or the
// `dataRepresentation` of a Secure Enclave key, which only this device's Secure Enclave can use.
//
// The shared secret never crosses it. Encapsulation and decapsulation both run HKDF (RFC 9629's
// KDF, with no salt and the CMSORIforKEMOtherInfo as its info) inside CryptoKit and return the
// key-encryption key, which the caller uses for AES key wrap.
//
// Return codes: 1 success, 0 a cryptographic failure (e.g. decapsulation failed), -1 a key,
// parameter set or hash CryptoKit does not offer or refuses, -2 the running OS has no ML-KEM, and
// -3 an output buffer too small.

import CryptoKit
import Foundation

/// Returns 1 when the running OS has CryptoKit's ML-KEM (macOS and iOS 26 and later), 0 otherwise.
@_cdecl("certval_sf_mlkem_available")
public func certval_sf_mlkem_available() -> Int32 {
    if #available(macOS 26.0, iOS 26.0, *) {
        return 1
    }
    return 0
}

/// Returns 1 when the device has a Secure Enclave that CryptoKit can use, 0 otherwise.
@_cdecl("certval_sf_secure_enclave_available")
public func certval_sf_secure_enclave_available() -> Int32 {
    return SecureEnclave.isAvailable ? 1 : 0
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

/// The key-encryption key HKDF derives from `secret`, with the hash `hash` names (256, 384 or 512).
@available(macOS 26.0, iOS 26.0, *)
private func hkdfKek(_ secret: SymmetricKey, _ hash: Int32, _ info: Data, _ kekLen: Int) -> SymmetricKey? {
    switch hash {
    case 256:
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: secret, salt: Data(), info: info, outputByteCount: kekLen)
    case 384:
        return HKDF<SHA384>.deriveKey(
            inputKeyMaterial: secret, salt: Data(), info: info, outputByteCount: kekLen)
    case 512:
        return HKDF<SHA512>.deriveKey(
            inputKeyMaterial: secret, salt: Data(), info: info, outputByteCount: kekLen)
    default:
        return nil
    }
}

private func writeKey(_ key: SymmetricKey, _ out: UnsafeMutablePointer<UInt8>, _ len: Int) {
    key.withUnsafeBytes { bytes in
        out.update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: len)
    }
}

/// Generates an ML-KEM key in the Secure Enclave, with the default access control (usable after
/// first unlock, on this device only, without user presence), and writes its
/// `dataRepresentation` and raw public key.
///
/// `parameterSet` is 768 or 1024.
@_cdecl("certval_sf_mlkem_secure_enclave_generate")
public func certval_sf_mlkem_secure_enclave_generate(
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
        case 768:
            let key = try SecureEnclave.MLKEM768.PrivateKey()
            (data, publicKey) = (key.dataRepresentation, key.publicKey.rawRepresentation)
        case 1024:
            let key = try SecureEnclave.MLKEM1024.PrivateKey()
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

/// Writes the raw public key of the Secure Enclave ML-KEM key whose `dataRepresentation` is `data`.
@_cdecl("certval_sf_mlkem_secure_enclave_public_key")
public func certval_sf_mlkem_secure_enclave_public_key(
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
        case 768:
            publicKey = try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: representation)
                .publicKey.rawRepresentation
        case 1024:
            publicKey = try SecureEnclave.MLKEM1024.PrivateKey(dataRepresentation: representation)
                .publicKey.rawRepresentation
        default:
            return -1
        }
        return copyOut(publicKey, publicOut, publicCapacity, publicLen) ? 1 : -3
    } catch {
        return -1
    }
}

/// Encapsulates to the raw ML-KEM public key `key` and derives the key-encryption key from the
/// shared secret. Writes the ciphertext and `kekLen` octets of key-encryption key.
@_cdecl("certval_sf_mlkem_encapsulate")
public func certval_sf_mlkem_encapsulate(
    _ parameterSet: Int32,
    _ key: UnsafePointer<UInt8>, _ keyLen: Int,
    _ hash: Int32,
    _ info: UnsafePointer<UInt8>, _ infoLen: Int,
    _ ciphertextOut: UnsafeMutablePointer<UInt8>, _ ciphertextCapacity: Int,
    _ ciphertextLen: UnsafeMutablePointer<Int>,
    _ kekOut: UnsafeMutablePointer<UInt8>, _ kekLen: Int
) -> Int32 {
    guard #available(macOS 26.0, iOS 26.0, *) else {
        return -2
    }
    let keyData = Data(bytes: key, count: keyLen)
    let infoData = Data(bytes: info, count: infoLen)
    let result: KEM.EncapsulationResult
    do {
        switch parameterSet {
        case 768:
            result = try MLKEM768.PublicKey(rawRepresentation: keyData).encapsulate()
        case 1024:
            result = try MLKEM1024.PublicKey(rawRepresentation: keyData).encapsulate()
        default:
            return -1
        }
    } catch {
        return -1
    }
    guard let kek = hkdfKek(result.sharedSecret, hash, infoData, kekLen) else {
        return -1
    }
    guard copyOut(result.encapsulated, ciphertextOut, ciphertextCapacity, ciphertextLen) else {
        return -3
    }
    writeKey(kek, kekOut, kekLen)
    return 1
}

/// Decapsulates `ciphertext` with a private key and derives the key-encryption key from the shared
/// secret, writing `kekLen` octets of it.
///
/// `keyKind` is 0 for a key held in memory, `key` being its 64-octet seed and `publicKey` the raw
/// public key it must generate, or 1 for a Secure Enclave key, `key` being its
/// `dataRepresentation` (`publicKey` is then unused).
@_cdecl("certval_sf_mlkem_decapsulate")
public func certval_sf_mlkem_decapsulate(
    _ parameterSet: Int32,
    _ keyKind: Int32,
    _ key: UnsafePointer<UInt8>, _ keyLen: Int,
    _ publicKey: UnsafePointer<UInt8>, _ publicKeyLen: Int,
    _ ciphertext: UnsafePointer<UInt8>, _ ciphertextLen: Int,
    _ hash: Int32,
    _ info: UnsafePointer<UInt8>, _ infoLen: Int,
    _ kekOut: UnsafeMutablePointer<UInt8>, _ kekLen: Int
) -> Int32 {
    guard #available(macOS 26.0, iOS 26.0, *) else {
        return -2
    }
    // A seed is read in place from the caller's buffer, which the caller zeroizes; a copy into
    // Data would be freed without being wiped. A Secure Enclave key's data representation is
    // the enclave's wrapped form, not the key, and is copied.
    let seed = UnsafeRawBufferPointer(start: key, count: keyLen)
    let publicData = Data(bytes: publicKey, count: publicKeyLen)
    let ciphertextData = Data(bytes: ciphertext, count: ciphertextLen)
    let infoData = Data(bytes: info, count: infoLen)
    let secret: SymmetricKey
    do {
        switch (parameterSet, keyKind) {
        case (768, 0):
            let key = try MLKEM768.PrivateKey(
                seedRepresentation: seed,
                publicKey: try MLKEM768.PublicKey(rawRepresentation: publicData))
            secret = try key.decapsulate(ciphertextData)
        case (1024, 0):
            let key = try MLKEM1024.PrivateKey(
                seedRepresentation: seed,
                publicKey: try MLKEM1024.PublicKey(rawRepresentation: publicData))
            secret = try key.decapsulate(ciphertextData)
        case (768, 1):
            secret = try SecureEnclave.MLKEM768.PrivateKey(
                dataRepresentation: Data(bytes: key, count: keyLen)
            ).decapsulate(ciphertextData)
        case (1024, 1):
            secret = try SecureEnclave.MLKEM1024.PrivateKey(
                dataRepresentation: Data(bytes: key, count: keyLen)
            ).decapsulate(ciphertextData)
        default:
            return -1
        }
    } catch {
        return 0
    }
    guard let kek = hkdfKek(secret, hash, infoData, kekLen) else {
        return -1
    }
    writeKey(kek, kekOut, kekLen)
    return 1
}
