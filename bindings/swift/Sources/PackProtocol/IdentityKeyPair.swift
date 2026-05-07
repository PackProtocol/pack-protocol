import Foundation
import CPackProtocolFFI

public final class IdentityKeyPair: @unchecked Sendable {
    private nonisolated(unsafe) var handle: UnsafeMutablePointer<CPackProtocolFFI.IdentityKeyPair>?

    public init() {
        var ptr: UnsafeMutablePointer<CPackProtocolFFI.IdentityKeyPair>?
        let result = pack_identity_key_pair_generate(&ptr)
        precondition(result == OK, "Failed to generate identity key pair")
        self.handle = ptr
    }

    deinit {
        if let handle = handle {
            pack_identity_key_pair_destroy(handle)
        }
    }

    public var publicKey: Data {
        var buf = [UInt8](repeating: 0, count: 32)
        var len: Int = 0
        pack_identity_key_pair_get_public(handle, &buf, buf.count, &len)
        return Data(buf[0..<len])
    }

    public func sign(_ message: Data) -> Data {
        var sigBuf = [UInt8](repeating: 0, count: 64)
        var sigLen: Int = 0
        message.withUnsafeBytes { msgPtr in
            pack_identity_key_pair_sign(
                handle,
                msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                message.count,
                &sigBuf,
                sigBuf.count,
                &sigLen
            )
        }
        return Data(sigBuf[0..<sigLen])
    }
}
