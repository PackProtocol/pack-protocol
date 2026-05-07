import Foundation
import CPackProtocolFFI

public struct SealedSenderResult: Sendable {
    public let senderUuid: String
    public let plaintext: Data
}

public enum PackSealedSender {

    public static func encrypt(
        senderIdentity: UnsafeMutablePointer<IdentityKeyPair>,
        senderCertificate: Data,
        recipientKey: Data,
        innerMessage: Data,
        currentTime: UInt64
    ) throws -> Data {
        guard recipientKey.count == 32 else {
            throw PackProtocolError.encryptFailed
        }

        var outBuf = [UInt8](repeating: 0, count: innerMessage.count + 1024)
        var outLen: Int = 0

        let result = senderCertificate.withUnsafeBytes { certPtr in
            recipientKey.withUnsafeBytes { rkPtr in
                innerMessage.withUnsafeBytes { msgPtr in
                    pack_sealed_sender_encrypt_msg(
                        senderIdentity,
                        certPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        senderCertificate.count,
                        rkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        currentTime,
                        msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        innerMessage.count,
                        &outBuf, outBuf.count, &outLen
                    )
                }
            }
        }

        guard result == OK else {
            throw PackProtocolError.encryptFailed
        }

        return Data(outBuf[0..<outLen])
    }

    public static func decrypt(
        ourIdentity: UnsafeMutablePointer<IdentityKeyPair>,
        ciphertext: Data,
        trustRoot: Data,
        currentTime: UInt64
    ) throws -> SealedSenderResult {
        guard trustRoot.count == 32 else {
            throw PackProtocolError.decryptFailed
        }

        var uuidBuf = [UInt8](repeating: 0, count: 256)
        var uuidLen: Int = 0
        var msgBuf = [UInt8](repeating: 0, count: ciphertext.count + 512)
        var msgLen: Int = 0

        let result = ciphertext.withUnsafeBytes { ctPtr in
            trustRoot.withUnsafeBytes { trPtr in
                pack_sealed_sender_decrypt_msg(
                    ourIdentity,
                    ctPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    ciphertext.count,
                    trPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    currentTime,
                    &uuidBuf, uuidBuf.count, &uuidLen,
                    &msgBuf, msgBuf.count, &msgLen
                )
            }
        }

        guard result == OK else {
            throw PackProtocolError.decryptFailed
        }

        let senderUuid = String(bytes: uuidBuf[0..<uuidLen], encoding: .utf8) ?? ""

        return SealedSenderResult(
            senderUuid: senderUuid,
            plaintext: Data(msgBuf[0..<msgLen])
        )
    }
}
