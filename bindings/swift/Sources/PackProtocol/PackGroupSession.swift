import Foundation
import CPackProtocolFFI

public final class PackGroupSession: @unchecked Sendable {
    private nonisolated(unsafe) var handle: UnsafeMutableRawPointer?

    private init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    deinit {
        if let handle = handle {
            pack_group_session_destroy(handle)
        }
    }

    public struct CreateSenderResult: Sendable {
        public let session: PackGroupSession
        public let distributionMessage: Data
    }

    public static func createSender(distributionId: String) throws -> CreateSenderResult {
        var sessionPtr: UnsafeMutableRawPointer?
        var distBuf = [UInt8](repeating: 0, count: 4096)
        var distLen: Int = 0

        let result = distributionId.withCString { distIdPtr in
            pack_group_session_create_sender(
                distIdPtr, distributionId.utf8.count,
                &sessionPtr,
                &distBuf, distBuf.count, &distLen
            )
        }

        guard result == OK, let ptr = sessionPtr else {
            throw PackProtocolError.groupCreateFailed
        }

        return CreateSenderResult(
            session: PackGroupSession(handle: ptr),
            distributionMessage: Data(distBuf[0..<distLen])
        )
    }

    public static func createReceiver(
        distributionId: String,
        distributionMessage: Data
    ) throws -> PackGroupSession {
        var sessionPtr: UnsafeMutableRawPointer?

        let result = distributionId.withCString { distIdPtr in
            distributionMessage.withUnsafeBytes { msgPtr in
                pack_group_session_create_receiver(
                    distIdPtr, distributionId.utf8.count,
                    msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    distributionMessage.count,
                    &sessionPtr
                )
            }
        }

        guard result == OK, let ptr = sessionPtr else {
            throw PackProtocolError.groupCreateFailed
        }

        return PackGroupSession(handle: ptr)
    }

    public func encrypt(_ plaintext: Data) throws -> Data {
        guard let handle = handle else {
            throw PackProtocolError.invalidHandle
        }

        var outBuf = [UInt8](repeating: 0, count: plaintext.count + 512)
        var outLen: Int = 0

        let result = plaintext.withUnsafeBytes { ptPtr in
            pack_group_session_encrypt(
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
            pack_group_session_decrypt(
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
