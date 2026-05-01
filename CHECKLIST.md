# Pack Protocol Implementation Checklist

## Phase 1: Project Setup
- [x] Initialize Cargo workspace (`Cargo.toml`)
- [x] Create `pack-protocol` crate skeleton
- [x] Create `pack-protocol-ffi` crate skeleton
- [x] Create `pack-protocol-jni` crate skeleton
- [x] Add workspace dependencies
- [x] Set up `#![forbid(unsafe_code)]` in `pack-protocol`
- [x] Initialize git repo

## Phase 2: Crypto Foundation
- [x] `crypto/mod.rs` — module structure
- [x] `crypto/curve.rs` — X25519 key generation and DH
- [x] `crypto/curve.rs` — XEdDSA sign/verify
- [x] `crypto/kdf.rs` — HKDF-SHA256 (RFC 5869)
- [x] `crypto/aead.rs` — AES-256-GCM encrypt/decrypt
- [x] `crypto/hmac.rs` — HMAC-SHA256
- [x] `keys.rs` — PublicKey, PrivateKey with Zeroize
- [x] `keys.rs` — IdentityKeyPair
- [x] `keys.rs` — SignedPreKey, OneTimePreKey, PreKeyBundle
- [x] `errors.rs` — error types
- [x] Tests: RFC 5869 HKDF test vectors
- [x] Tests: X25519 known-answer vectors
- [x] Tests: XEdDSA test vectors from spec
- [x] Tests: AES-GCM round-trip

## Phase 3: X3DH Key Agreement
- [x] `x3dh.rs` — initiator protocol (spec §3.3)
- [x] `x3dh.rs` — responder protocol (spec §3.4)
- [x] Tests: both sides derive same shared secret
- [x] Tests: with and without one-time pre-key
- [x] Tests: signature verification failure rejects bundle
- [x] Tests: X3DH spec structural verification (DH symmetry, HKDF params, AD format)

## Phase 4: Double Ratchet
- [x] `chain.rs` — KDF_RK root key derivation (spec §2.2)
- [x] `chain.rs` — KDF_CK chain key derivation (spec §2.3)
- [x] `ratchet.rs` — RatchetState structure (spec §3.1)
- [x] `ratchet.rs` — ratchet_encrypt (spec §3.3)
- [x] `ratchet.rs` — ratchet_decrypt (spec §3.4)
- [x] `ratchet.rs` — DH ratchet step (spec §3.5)
- [x] `ratchet.rs` — skipped message key storage and lookup
- [x] `ratchet.rs` — MAX_SKIP enforcement
- [x] `ratchet.rs` — initialization from X3DH (spec §3.2)
- [x] Tests: simple send/receive
- [x] Tests: ping-pong (alternating directions)
- [x] Tests: out-of-order delivery
- [x] Tests: lost messages
- [x] Tests: DH ratchet advancement on direction change
- [x] Tests: MAX_SKIP limit enforcement
- [x] Tests: Double Ratchet KDF spec verification (HMAC constants, HKDF params)

## Phase 5: Session Layer
- [x] `store.rs` — IdentityKeyStore trait
- [x] `store.rs` — PreKeyStore trait
- [x] `store.rs` — SignedPreKeyStore trait
- [x] `store.rs` — SessionStore trait
- [x] `store.rs` — SenderKeyStore trait
- [x] `store.rs` — ProtocolStore combined trait
- [x] `session.rs` — SessionState
- [x] `session.rs` — SessionRecord (current + previous states)
- [x] `session.rs` — SessionCipher encrypt
- [x] `session.rs` — SessionCipher decrypt (PreKeyPackMessage)
- [x] `session.rs` — SessionCipher decrypt (PackMessage)
- [x] `session.rs` — simultaneous initiation handling
- [x] `message.rs` — PackMessage structure + serialization
- [x] `message.rs` — PreKeyPackMessage structure + serialization
- [x] `message.rs` — CiphertextMessage enum
- [x] `proto/` — protobuf definitions (derived from spec)
- [x] In-memory store implementation (for testing)
- [x] Tests: full X3DH -> Double Ratchet -> message exchange flow
- [x] Tests: simultaneous initiation
- [x] Tests: session renegotiation

## Phase 6: Sealed Sender
- [x] `sealed_sender.rs` — SenderCertificate structure
- [x] `sealed_sender.rs` — ServerCertificate structure
- [x] `sealed_sender.rs` — certificate validation
- [x] `sealed_sender.rs` — sealed sender encrypt
- [x] `sealed_sender.rs` — sealed sender decrypt
- [x] Tests: round-trip encrypt/decrypt
- [x] Tests: expired certificate rejection
- [x] Tests: invalid signature rejection

## Phase 7: Group Messaging
- [x] `group.rs` — SenderKeyDistributionMessage
- [x] `group.rs` — GroupCipher encrypt
- [x] `group.rs` — GroupCipher decrypt
- [x] `group.rs` — chain key ratchet for groups
- [x] Tests: group key distribution flow
- [x] Tests: group encrypt/decrypt round-trip
- [x] Tests: out-of-order group messages

## Phase 8: Fingerprints
- [x] `fingerprint.rs` — displayable fingerprint generation
- [x] `fingerprint.rs` — scannable fingerprint generation
- [x] `fingerprint.rs` — scannable fingerprint verification
- [x] Tests: fingerprint generation determinism
- [x] Tests: scannable fingerprint round-trip

## Phase 9: C FFI
- [x] `pack-protocol-ffi/handles.rs` — opaque handle pattern
- [x] `pack-protocol-ffi/error.rs` — error code mapping
- [x] `pack-protocol-ffi/identity_ffi.rs` — identity key FFI functions
- [x] `pack-protocol-ffi/session_ffi.rs` — session cipher FFI functions (callback-based store)
- [x] `pack-protocol-ffi/sealed_sender_ffi.rs` — sealed sender FFI functions
- [x] `pack-protocol-ffi/group_ffi.rs` — group cipher FFI functions
- [x] `cbindgen.toml` — configure header generation
- [x] Generate `pack_protocol.h`
- [x] `bindings/cpp/` — C++ RAII wrapper
- [x] `bindings/cpp/CMakeLists.txt`
- [x] Tests: C/C++ link and round-trip

## Phase 10: Mobile Bindings
- [x] `pack-protocol-jni/` — JNI entry points
- [x] `pack-protocol-jni/convert.rs` — JNI type conversion
- [x] `bindings/kotlin/` — Kotlin wrapper classes
- [x] `bindings/kotlin/build.gradle.kts`
- [x] `bindings/swift/Package.swift`
- [x] `bindings/swift/` — Swift wrapper classes
- [x] `xtask/` — build automation
- [x] `cargo xtask build-ios` — xcframework build
- [x] `cargo xtask build-android` — NDK cross-compile + .aar
- [x] `cargo xtask generate-headers` — cbindgen automation
- [x] Tests: Swift round-trip
- [x] Tests: Kotlin round-trip

## Phase 11: Sesame (Multi-Device)
- [x] `sesame.rs` — device address types
- [x] `sesame.rs` — encrypt for all devices
- [x] `sesame.rs` — receive and route to correct session
- [x] Tests: multi-device send/receive
- [x] Tests: new device session establishment
- [x] Tests: stale device handling

## Phase 12: Hardening
- [x] Fuzz target: protobuf deserialization
- [x] Fuzz target: ratchet_decrypt with malformed input
- [x] Fuzz target: sealed sender decrypt with malformed envelope
- [x] Property tests: encrypt-then-decrypt identity
- [x] Property tests: ratchet state consistency
- [x] Property tests: skipped key bounds
- [x] Cross-language interop tests
- [x] Constant-time comparison audit (verify `subtle` usage)
- [x] Zeroize audit (verify all secret material is cleared)
- [x] Dependency license audit (`cargo tree` — no GPL)
- [x] Security audit preparation documentation
