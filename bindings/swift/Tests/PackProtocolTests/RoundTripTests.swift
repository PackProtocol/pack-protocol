// RoundTripTests.swift
//
// NOTE: These tests call through to the C FFI library (CPackProtocolFFI), so the
// native shared library must be built before running them. Build the Rust
// crate in crates/pack-protocol-ffi first (e.g. `cargo build -p pack-protocol-ffi`).

import XCTest
import Foundation
import CPackProtocolFFI
@testable import PackProtocol

final class RoundTripTests: XCTestCase {

    // MARK: - IdentityKeyPair

    func testIdentityKeyPairPublicKeyLength() {
        let keyPair = IdentityKeyPair()
        let publicKey = keyPair.publicKey
        XCTAssertEqual(publicKey.count, 32, "Public key should be 32 bytes (Curve25519)")
    }

    // MARK: - Fingerprint display string

    func testFingerprintDisplayStringIs60Digits() {
        let alice = IdentityKeyPair()
        let bob   = IdentityKeyPair()

        let localId  = Data("+14151111111".utf8)
        let remoteId = Data("+14152222222".utf8)

        let display = PackFingerprint.generate(
            localIdentifier: localId,
            localKey: alice.publicKey,
            remoteIdentifier: remoteId,
            remoteKey: bob.publicKey
        )

        XCTAssertEqual(display.count, 60,
                       "Fingerprint display string should be exactly 60 characters")
        XCTAssertTrue(display.allSatisfy(\.isNumber),
                      "Fingerprint display string should contain only digits")
    }

    // MARK: - Scannable fingerprint round-trip

    func testScannableFingerprintRoundTrip() {
        let alice = IdentityKeyPair()
        let bob   = IdentityKeyPair()

        let localId  = Data("+14151111111".utf8)
        let remoteId = Data("+14152222222".utf8)

        // Generate a fingerprint from Alice's perspective.
        let aliceFingerprint = generateFingerprintHandle(
            localIdentifier: localId,
            localKey: alice.publicKey,
            remoteIdentifier: remoteId,
            remoteKey: bob.publicKey
        )
        XCTAssertNotNil(aliceFingerprint, "Alice fingerprint handle should not be nil")

        // Generate the matching fingerprint from Bob's perspective (swapped).
        let bobFingerprint = generateFingerprintHandle(
            localIdentifier: remoteId,
            localKey: bob.publicKey,
            remoteIdentifier: localId,
            remoteKey: alice.publicKey
        )
        XCTAssertNotNil(bobFingerprint, "Bob fingerprint handle should not be nil")

        // Get scannable bytes from both sides.
        let aliceScannable = scannableBytes(from: aliceFingerprint!)
        let bobScannable   = scannableBytes(from: bobFingerprint!)

        XCTAssertFalse(aliceScannable.isEmpty, "Alice scannable bytes should not be empty")
        XCTAssertFalse(bobScannable.isEmpty, "Bob scannable bytes should not be empty")

        // Verify that Bob's scannable bytes match Alice's expectation.
        var match: Bool = false
        let result = aliceScannable.withUnsafeBytes { oursPtr in
            bobScannable.withUnsafeBytes { theirsPtr in
                pack_scannable_fingerprint_verify(
                    oursPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    aliceScannable.count,
                    theirsPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    bobScannable.count,
                    &match
                )
            }
        }
        XCTAssertEqual(result, OK, "Scannable fingerprint verification should succeed")
        XCTAssertTrue(match, "Matching scannable fingerprints should verify as equal")

        pack_fingerprint_destroy(aliceFingerprint)
        pack_fingerprint_destroy(bobFingerprint)
    }

    // MARK: - Helpers

    /// Creates a raw `Fingerprint` handle via the C FFI so we can access
    /// scannable bytes directly (the Swift wrapper only exposes the display
    /// string today).
    private func generateFingerprintHandle(
        localIdentifier: Data,
        localKey: Data,
        remoteIdentifier: Data,
        remoteKey: Data
    ) -> UnsafeMutablePointer<Fingerprint>? {
        var handle: UnsafeMutablePointer<Fingerprint>?

        localIdentifier.withUnsafeBytes { localIdPtr in
            localKey.withUnsafeBytes { localKeyPtr in
                remoteIdentifier.withUnsafeBytes { remoteIdPtr in
                    remoteKey.withUnsafeBytes { remoteKeyPtr in
                        var localKeyObj: UnsafeMutablePointer<IdentityKey>?
                        pack_identity_key_from_bytes(
                            localKeyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            localKey.count,
                            &localKeyObj
                        )
                        var remoteKeyObj: UnsafeMutablePointer<IdentityKey>?
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

        return handle
    }

    /// Extracts the scannable fingerprint bytes from a raw `Fingerprint` handle.
    private func scannableBytes(
        from handle: UnsafeMutablePointer<Fingerprint>
    ) -> Data {
        var buf = [UInt8](repeating: 0, count: 256)
        var len: Int = 0
        pack_fingerprint_scannable_bytes(handle, &buf, buf.count, &len)
        return Data(buf[0..<len])
    }
}
