import Foundation
import CPackProtocolFFI

public struct PackFingerprint {
    public static func generate(
        localIdentifier: Data,
        localKey: Data,
        remoteIdentifier: Data,
        remoteKey: Data
    ) -> String {
        var handle: UnsafeMutablePointer<CPackProtocolFFI.Fingerprint>?

        localIdentifier.withUnsafeBytes { localIdPtr in
            localKey.withUnsafeBytes { localKeyPtr in
                remoteIdentifier.withUnsafeBytes { remoteIdPtr in
                    remoteKey.withUnsafeBytes { remoteKeyPtr in
                        var localKeyObj: UnsafeMutablePointer<CPackProtocolFFI.IdentityKey>?
                        pack_identity_key_from_bytes(
                            localKeyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            localKey.count,
                            &localKeyObj
                        )
                        var remoteKeyObj: UnsafeMutablePointer<CPackProtocolFFI.IdentityKey>?
                        pack_identity_key_from_bytes(
                            remoteKeyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            remoteKey.count,
                            &remoteKeyObj
                        )

                        pack_fingerprint_generate(
                            localIdPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            localIdentifier.count,
                            localKeyObj,
                            remoteIdPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            remoteIdentifier.count,
                            remoteKeyObj,
                            &handle
                        )

                        pack_identity_key_destroy(localKeyObj)
                        pack_identity_key_destroy(remoteKeyObj)
                    }
                }
            }
        }

        guard let fp = handle else { return "" }
        defer { pack_fingerprint_destroy(fp) }

        var buf = [UInt8](repeating: 0, count: 60)
        var len: Int = 0
        pack_fingerprint_display(fp, &buf, buf.count, &len)
        return String(bytes: buf[0..<len], encoding: .utf8) ?? ""
    }
}
