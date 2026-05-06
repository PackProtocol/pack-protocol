import Foundation
import CPackProtocolFFI

public final class PackSession {
    private var handle: UnsafeMutableRawPointer?

    private init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    deinit {
        if let handle = handle {
            pack_session_destroy(handle)
        }
    }

    public struct InitiateResult {
        public let session: PackSession
        public let preKeyMessage: Data
    }

    public struct RespondResult {
        public let session: PackSession
        public let plaintext: Data
    }

    public static func initiate(
        ourName: String,
        ourDeviceId: UInt32,
        ourIdentity: UnsafeMutablePointer<IdentityKeyPair>,
        registrationId: UInt32,
        remoteName: String,
        remoteDeviceId: UInt32,
        bundle: UnsafeMutablePointer<PreKeyBundle>,
        firstMessage: Data
    ) throws -> InitiateResult {
        var sessionPtr: UnsafeMutableRawPointer?
        var msgBuf = [UInt8](repeating: 0, count: 4096)
        var msgLen: Int = 0

        let result = ourName.withCString { ourNamePtr in
            remoteName.withCString { remoteNamePtr in
                firstMessage.withUnsafeBytes { msgPtr in
                    pack_session_initiate(
                        ourNamePtr, ourName.utf8.count,
                        ourDeviceId,
                        ourIdentity,
                        registrationId,
                        remoteNamePtr, remoteName.utf8.count,
                        remoteDeviceId,
                        bundle,
                        msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        firstMessage.count,
                        &sessionPtr,
                        &msgBuf, msgBuf.count, &msgLen
                    )
                }
            }
        }

        guard result == OK, let ptr = sessionPtr else {
            throw PackProtocolError.sessionInitFailed
        }

        return InitiateResult(
            session: PackSession(handle: ptr),
            preKeyMessage: Data(msgBuf[0..<msgLen])
        )
    }

    public func encrypt(_ plaintext: Data) throws -> Data {
        guard let handle = handle else {
            throw PackProtocolError.invalidHandle
        }

        var outBuf = [UInt8](repeating: 0, count: plaintext.count + 512)
        var outLen: Int = 0

        let result = plaintext.withUnsafeBytes { ptPtr in
            pack_session_encrypt_msg(
                handle,
                ptPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                plaintext.count,
                &outBuf, outBuf.count, &outLen
            )
        }

        guard result == OK else {
            throw PackProtocolError.encryptFailed
        }

        return Data(outBuf[0..<outLen])
    }

    public func decrypt(_ ciphertext: Data) throws -> Data {
        guard let handle = handle else {
            throw PackProtocolError.invalidHandle
        }

        var outBuf = [UInt8](repeating: 0, count: ciphertext.count + 512)
        var outLen: Int = 0

        let result = ciphertext.withUnsafeBytes { ctPtr in
            pack_session_decrypt_msg(
                handle,
                ctPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                ciphertext.count,
                &outBuf, outBuf.count, &outLen
            )
        }

        guard result == OK else {
            throw PackProtocolError.decryptFailed
        }

        return Data(outBuf[0..<outLen])
    }
}

public enum PackProtocolError: Error {
    case sessionInitFailed
    case invalidHandle
    case encryptFailed
    case decryptFailed
    case groupCreateFailed
}
