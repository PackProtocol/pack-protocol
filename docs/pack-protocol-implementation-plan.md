# Pack Protocol Clean-Room Implementation Plan

**Date:** 2026-04-29
**Status:** Proposed
**License Target:** TBD (non-GPL)

---

## 1. Motivation

This project currently depends on libsignal, which is licensed under GPLv3. The GPLv3 requires that any software linking against it must also be released under GPLv3-compatible terms, which is incompatible with our licensing goals.

To remove this obligation, we will build a clean-room implementation of the Pack Protocol from the publicly available cryptographic specifications. 

---

## 2. Clean-Room Implementation Methodology

### 2.1 What "Clean-Room" Means

A clean-room implementation is one built exclusively from public specifications, academic papers, and RFCs — without reading, referencing, or copying any existing GPL-licensed source code. This is a well-established legal strategy for producing interoperable software without inheriting the original work's license obligations.

### 2.2 Source Specifications

All implementation work will be derived solely from these publicly available documents:

| Specification | Source |
|---|---|
| X3DH Key Agreement Protocol | signal.org/docs/specifications/x3dh |
| Double Ratchet Algorithm | signal.org/docs/specifications/doubleratchet |
| Sesame Algorithm | signal.org/docs/specifications/sesame |
| XEdDSA and VXEdDSA | signal.org/docs/specifications/xeddsa |
| Sealed Sender | Publicly documented by Signal |
| HKDF (RFC 5869) | tools.ietf.org/html/rfc5869 |
| X25519 (RFC 7748) | tools.ietf.org/html/rfc7748 |
| Ed25519 (RFC 8032) | tools.ietf.org/html/rfc8032 |
| AES-GCM (NIST SP 800-38D) | NIST publication |

### 2.3 Clean-Room Rules

The following rules **must** be followed by all contributors:

1. **Do not read libsignal source code.** This includes the Rust, Java, Swift, and C implementations published by Signal Foundation under GPLv3.
2. **Do not read code derived from libsignal.** This includes forks, ports, or wrappers that are themselves GPL-licensed.
3. **Do not copy data structures, variable names, function signatures, or code organization from libsignal.** Structural similarity that arises naturally from implementing the same spec is acceptable, but deliberate copying is not.
4. **Do not reference libsignal commit history, issues, or pull requests** for implementation guidance.
5. **Do reference the public specifications freely.** The protocol specifications are published for the purpose of enabling interoperable implementations and are not themselves GPL-licensed.
6. **Do reference RFCs and academic papers freely.** The underlying cryptographic primitives are standardized and well-documented.
7. **Do use MIT/Apache-2.0/BSD-licensed crates** for cryptographic primitives. These are independent implementations of standardized algorithms, not derived from libsignal.

### 2.4 Documentation Trail

Every module should include a comment at the top of the file citing which specification section it implements. For example:

```rust
// Implements: Signal Double Ratchet Algorithm, Sections 2.4 and 3.1
// Source: https://signal.org/docs/specifications/doubleratchet/
```

This creates an auditable trail showing that the implementation derives from the public spec, not from GPL source code.

---

## 3. Legal Risk Assessment

### 3.1 Low Risk: Protocol Specifications Are Public

The Pack Protocol specifications are published openly and are not themselves covered by the GPLv3. They describe algorithms at a mathematical level. Implementing a published algorithm from its specification is not copyright infringement — copyright protects expression (code), not ideas (algorithms).

**Precedent:** Clean-room implementations have been upheld in cases like *Sega v. Accolade* and *Lotus v. Borland*. The practice is standard in the software industry.

### 3.2 Low Risk: Cryptographic Primitives Are Standardized

The underlying cryptographic operations (X25519, Ed25519, AES-GCM, HKDF, HMAC-SHA256) are NIST/IETF standards with multiple independent implementations. The Rust crates we will use (`x25519-dalek`, `ed25519-dalek`, `aes-gcm`, `hkdf`, etc.) are independently written, permissively licensed, and widely used. They are not derived from libsignal.

### 3.3 Medium Risk: Structural Similarity

Any two implementations of the same protocol will share structural similarities — similar function names, similar data structures, similar control flow. This is an inherent consequence of implementing the same specification and is generally not considered copyright infringement.

**However**, if the structural similarity is so detailed that it suggests copying rather than independent derivation, it could raise questions. Mitigations:

- Use Rust-idiomatic naming conventions and patterns.
- Make independent design decisions about error handling, state management, serialization, and API surface.
- Maintain the documentation trail showing derivation from specs.

### 3.4 Medium Risk: Wire Format Compatibility

For interoperability, our wire format must match what the protocol specification describes. Protobuf schemas that define a wire format are functional — they define interoperability, not creative expression — so implementing them from the specification is defensible.

- Define protobuf messages from the specification's description of the wire format.
- If the specification does not fully document the wire format, derive it from the protocol behavior described in the spec.

### 3.5 Low Risk: Test Vector Sharing

The specifications include test vectors (known inputs and expected outputs) for validating implementations. Using these test vectors does not create a GPL obligation, as they are part of the public specification, not part of the GPL-licensed code.

### 3.6 Risk Summary

| Area | Risk Level | Mitigation |
|---|---|---|
| Implementing from public specs | Low | Well-established legal practice |
| Using permissive crypto crates | Low | Independent implementations of standards |
| Structural similarity | Medium | Idiomatic Rust style, independent design decisions, documentation trail |
| Wire format compatibility | Medium | Derive from spec descriptions only |
| Test vectors from specs | Low | Part of public specification |
| Accidental code viewing by contributor | Medium | Clear contributor guidelines, code review for anomalies |

### 3.7 Recommendations

1. **Contributor agreement.** All contributors should acknowledge they have not read libsignal source code before contributing.
2. **Code review.** Review contributions to ensure they are derived from public specifications and not from any GPL-licensed implementation.
3. **Legal review.** Before shipping, have a lawyer review the implementation for GPL compliance. This document is not legal advice.
4. **Dependency audit.** Before every release, audit the full dependency tree (`cargo tree`) for any GPL-licensed transitive dependencies.

---

## 4. Architecture

### 4.1 Workspace Structure

```
pack-protocol/
├── Cargo.toml                     # Workspace root
├── LICENSE                        # TBD — non-GPL license
│
├── crates/
│   ├── pack-protocol/               # Pure protocol logic, #![forbid(unsafe_code)]
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── crypto/            # Wrappers around crypto crates
│   │       │   ├── mod.rs
│   │       │   ├── curve.rs       # X25519 + XEdDSA
│   │       │   ├── aead.rs        # AES-256-GCM
│   │       │   ├── kdf.rs         # HKDF-SHA256
│   │       │   └── hmac.rs        # HMAC-SHA256
│   │       ├── keys.rs            # Key types with Zeroize
│   │       ├── identity.rs        # Identity keys
│   │       ├── x3dh.rs            # X3DH key agreement
│   │       ├── ratchet.rs         # Double Ratchet state machine
│   │       ├── chain.rs           # Symmetric chain key derivation
│   │       ├── session.rs         # Session state, SessionCipher
│   │       ├── message.rs         # Wire format types
│   │       ├── sealed_sender.rs   # Sealed Sender envelope
│   │       ├── sesame.rs          # Multi-device session management
│   │       ├── group.rs           # Sender Keys for group messaging
│   │       ├── fingerprint.rs     # Safety number generation
│   │       ├── store.rs           # Async trait definitions for storage
│   │       ├── errors.rs          # Error types
│   │       └── proto/             # Protobuf wire format (via prost)
│   │           ├── mod.rs
│   │           └── wire.rs
│   │
│   ├── pack-protocol-ffi/                # C-ABI FFI (staticlib + cdylib)
│   │   ├── cbindgen.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── handles.rs         # Opaque handle pattern
│   │       ├── error.rs           # FFI error codes
│   │       ├── identity_ffi.rs
│   │       ├── session_ffi.rs
│   │       ├── sealed_sender_ffi.rs
│   │       └── group_ffi.rs
│   │
│   └── pack-protocol-jni/                # JNI bindings for Android
│       └── src/
│           ├── lib.rs
│           ├── convert.rs         # JNI <-> Rust type conversion
│           ├── identity_jni.rs
│           ├── session_jni.rs
│           └── sealed_sender_jni.rs
│
├── bindings/
│   ├── swift/                     # Swift Package (iOS + macOS)
│   │   ├── Package.swift
│   │   └── Sources/PackProtocol/
│   │       ├── PackProtocol.swift
│   │       ├── Identity.swift
│   │       ├── Session.swift
│   │       ├── SealedSender.swift
│   │       └── Store.swift
│   │
│   ├── kotlin/                    # Kotlin/Android library
│   │   ├── build.gradle.kts
│   │   └── src/main/kotlin/org/packprotocol/
│   │       ├── IdentityKey.kt
│   │       ├── SessionCipher.kt
│   │       ├── SealedSenderCipher.kt
│   │       └── ProtocolStore.kt
│   │
│   └── cpp/                       # C++ RAII wrapper
│       ├── CMakeLists.txt
│       ├── include/pack_protocol.hpp
│       └── src/signal_protocol.cpp
│
├── tests/
│   ├── vectors/                   # Spec test vector JSON files
│   ├── integration/               # End-to-end Rust tests
│   └── interop/                   # Cross-language round-trip tests
│
└── xtask/                         # Build automation
    └── src/main.rs                # cargo xtask build-ios, build-android, etc.
```

### 4.2 Platform Build Targets

| Platform | Output | Build Method | Consumed By |
|---|---|---|---|
| iOS | `.xcframework` (static) | `cargo` → `lipo` → `xcodebuild -create-xcframework` | Swift Package |
| macOS | `.xcframework` (static) | Same as iOS | Swift Package |
| Android | `.so` for 4 ABIs | `cargo-ndk` | Kotlin via JNI `System.loadLibrary` |
| Linux | `.so` + `.a` | `cargo build` | C/C++ via CMake |
| Windows | `.dll` + `.lib` | `cargo build` | C/C++ via CMake |

Android ABIs: `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`
iOS slices: `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`

---

## 5. Protocol-to-Implementation Mapping

This section traces each public specification through to the code modules that implement it, documenting which spec sections govern which behavior, and the algorithmic steps the code must follow.

### 5.1 XEdDSA Signatures

**Spec:** signal.org/docs/specifications/xeddsa
**Implements in:** `crypto/curve.rs`

XEdDSA allows a Curve25519 key pair (normally used only for Diffie-Hellman) to also produce and verify Ed25519-compatible signatures. This is needed because the protocol uses a single long-term key pair for both DH and signing.

**Spec algorithm for signing (XEdDSA, Section 2):**
1. Convert the Curve25519 private scalar `a` to an Ed25519 signing key
2. Compute the nonce deterministically: `r = SHA-512(a || M || Z)` where `Z` is 64 bytes of random
3. Compute `R = r * B` (base point multiplication)
4. Compute `S = r + SHA-512(R || A || M) * a` (mod group order)
5. Return signature `(R, S)`

**Spec algorithm for verification (XEdDSA, Section 2):**
1. Convert the Curve25519 public key `u` to an Ed25519 public key `A`
2. Verify the Ed25519 signature `(R, S)` against `A` and message `M` using standard Ed25519 verification

**Code functions:**
- `fn xeddsa_sign(key: &IdentityKeyPair, message: &[u8]) -> Signature`
- `fn xeddsa_verify(public: &PublicKey, message: &[u8], signature: &Signature) -> Result<()>`

**Validation:** Verify against the XEdDSA test vectors in the spec appendix.

---

### 5.2 Cryptographic Primitives

**Specs:** RFC 7748 (X25519), RFC 5869 (HKDF), NIST SP 800-38D (AES-GCM)
**Implements in:** `crypto/curve.rs`, `crypto/kdf.rs`, `crypto/aead.rs`, `crypto/hmac.rs`

These are thin wrappers around permissively-licensed crates, providing a stable internal API so the crypto backend can be swapped without touching protocol logic.

**X25519 DH (RFC 7748, Section 5):**
- Key generation: generate a 32-byte random scalar, clamp bits per the RFC, compute public key as `scalar * basepoint`
- DH: `shared_secret = our_scalar * their_public_point`
- Code: `fn generate_keypair() -> KeyPair`, `fn dh(our_secret, their_public) -> SharedSecret`

**HKDF (RFC 5869, Sections 2.2-2.3):**
- Extract: `PRK = HMAC-SHA256(salt, IKM)`
- Expand: iterate `HMAC-SHA256(PRK, T(i-1) || info || i)` to produce output key material of desired length
- Code: `fn hkdf_derive(ikm, salt, info, output_len) -> Vec<u8>`
- Validation: RFC 5869 Appendix A test vectors

**AES-256-GCM (NIST SP 800-38D):**
- Authenticated encryption with associated data
- Code: `fn encrypt(key, nonce, plaintext, ad) -> Vec<u8>`, `fn decrypt(key, nonce, ciphertext, ad) -> Result<Vec<u8>>`

**HMAC-SHA256 (RFC 2104):**
- Used by the Double Ratchet for chain key derivation (KDF_CK)
- Code: `fn hmac(key, data) -> [u8; 32]`

---

### 5.3 Key Types

**Spec:** X3DH Sections 2.1-2.4 define the key types used in the protocol
**Implements in:** `keys.rs`, `identity.rs`

The X3DH specification defines these key types and their roles:

| Spec Term | Spec Section | Code Type | Role |
|---|---|---|---|
| IK (Identity Key) | X3DH §2.1 | `IdentityKeyPair` | Long-term key, never changes. Used for both DH and XEdDSA signing. |
| SPK (Signed Pre-Key) | X3DH §2.2 | `SignedPreKey` | Medium-term key, rotated periodically (e.g., weekly). Signed by IK via XEdDSA. |
| OPK (One-Time Pre-Key) | X3DH §2.3 | `OneTimePreKey` | Single-use. Server stores a batch; each is consumed by one session initiation. |
| EK (Ephemeral Key) | X3DH §2.4 | `EphemeralKeyPair` | Generated fresh per session initiation. Never stored long-term. |

**Pre-Key Bundle** (X3DH §3.2): What the server stores and provides to initiators:
- Identity public key (IK)
- Signed pre-key public + signature + ID
- One-time pre-key public + ID (optional, may be exhausted)
- Any additional application-layer fields (e.g., device identifiers) are implementation decisions, not specified by X3DH

All private key material implements `Zeroize + ZeroizeOnDrop` to clear memory on deallocation.

---

### 5.4 X3DH Key Agreement

**Spec:** signal.org/docs/specifications/x3dh
**Implements in:** `x3dh.rs`

X3DH establishes a shared secret between two parties, even when the responder is offline, by using pre-published keys.

**Initiator protocol (X3DH §3.3):**

| Step | Spec Operation | Code |
|---|---|---|
| 1 | Fetch Bob's pre-key bundle from the server | Input: `PreKeyBundle` |
| 2 | Verify `Sig(IK_B, Encode(SPK_B))` using XEdDSA | `xeddsa_verify(bundle.identity_key, bundle.signed_pre_key)` |
| 3 | Abort if signature verification fails | Return error |
| 4 | Generate ephemeral key pair EK_A | `generate_keypair()` |
| 5 | `DH1 = DH(IK_A, SPK_B)` | `dh(our_identity.private, their_signed_prekey)` |
| 6 | `DH2 = DH(EK_A, IK_B)` | `dh(ephemeral.private, their_identity)` |
| 7 | `DH3 = DH(EK_A, SPK_B)` | `dh(ephemeral.private, their_signed_prekey)` |
| 8 | If OPK present: `DH4 = DH(EK_A, OPK_B)` | `dh(ephemeral.private, their_one_time_prekey)` |
| 9 | `SK = HKDF(F \|\| DH1 \|\| DH2 \|\| DH3 [\|\| DH4])` | `hkdf_derive(...)` with `salt = 0...0`, `info = "X3DH"`, `F = 0xFF * 32` |
| 10 | `AD = Encode(IK_A) \|\| Encode(IK_B)` | Concatenate 32-byte public keys |
| 11 | Send initial message with IK_A, EK_A, pre-key IDs | Construct `PreKeySignalMessage` |

**Responder protocol (X3DH §3.4):**

| Step | Spec Operation | Code |
|---|---|---|
| 1 | Receive PreKeySignalMessage | Input: `PreKeySignalMessage` |
| 2 | `DH1 = DH(SPK_B, IK_A)` | `dh(our_signed_prekey.private, their_identity)` |
| 3 | `DH2 = DH(IK_B, EK_A)` | `dh(our_identity.private, their_ephemeral)` |
| 4 | `DH3 = DH(SPK_B, EK_A)` | `dh(our_signed_prekey.private, their_ephemeral)` |
| 5 | If OPK was used: `DH4 = DH(OPK_B, EK_A)` | `dh(our_one_time_prekey.private, their_ephemeral)` |
| 6 | `SK = HKDF(F \|\| DH1 \|\| DH2 \|\| DH3 [\|\| DH4])` | Same HKDF parameters as initiator |
| 7 | Delete one-time pre-key (if used) | `prekey_store.remove(opk_id)` |
| 8 | Initialize Double Ratchet with SK | `ratchet_init_responder(sk, our_signed_prekey)` |

**Security properties from spec §4:**
- Forward secrecy (compromise of IK does not reveal past session keys)
- Deniability (no cryptographic proof of who participated)
- Replay protection (one-time pre-keys ensure unique sessions)

---

### 5.5 Double Ratchet Algorithm

**Spec:** signal.org/docs/specifications/doubleratchet
**Implements in:** `ratchet.rs`, `chain.rs`

The Double Ratchet provides forward secrecy and break-in recovery by combining a DH ratchet (for new key material) with a symmetric-key ratchet (for per-message keys).

**Ratchet state (Spec §3.1):**

| Spec Variable | Code Field | Description |
|---|---|---|
| DHs | `dh_sending` | Our current DH ratchet key pair |
| DHr | `dh_receiving` | Their current DH ratchet public key |
| RK | `root_key` | 32-byte root key, advances on DH ratchet step |
| CKs | `sending_chain.chain_key` | Sending chain key |
| CKr | `receiving_chain.chain_key` | Receiving chain key |
| Ns | `send_count` | Message counter for sending chain |
| Nr | `recv_count` | Message counter for receiving chain |
| PN | `prev_send_count` | Message count of previous sending chain |
| MKSKIPPED | `skipped_keys` | Map of skipped-over message keys |

**KDF_RK — Root key derivation (Spec §2.2):**
```
(new_root_key, new_chain_key) = HKDF(rk, dh_output)
```
- `salt` = current root key
- `ikm` = DH output
- `info` = application-specific constant
- Output: 64 bytes, split into new root key (first 32) and new chain key (last 32)
- Code in: `chain.rs` → `fn kdf_rk(root_key, dh_output) -> (RootKey, ChainKey)`

**KDF_CK — Chain key derivation (Spec §2.3):**
```
new_chain_key = HMAC-SHA256(ck, 0x02)
message_key   = HMAC-SHA256(ck, 0x01)
```
- Input: current chain key
- Output: next chain key + message key for encryption/decryption
- Code in: `chain.rs` → `fn kdf_ck(chain_key) -> (ChainKey, MessageKey)`

**Encrypt (Spec §3.3):**

| Step | Spec Operation | Code |
|---|---|---|
| 1 | `(CKs, mk) = KDF_CK(CKs)` | `kdf_ck(&mut state.sending_chain)` |
| 2 | Construct header: `HEADER(DHs, PN, Ns)` | `MessageHeader { ratchet_key, prev_counter, counter }` |
| 3 | `Ns = Ns + 1` | `state.send_count += 1` |
| 4 | `ciphertext = ENCRYPT(mk, plaintext, CONCAT(AD, header))` | `aead_encrypt(mk, plaintext, ad \|\| header_bytes)` |
| 5 | Return `(header, ciphertext)` | Return `(MessageHeader, Vec<u8>)` |

**Decrypt (Spec §3.4):**

| Step | Spec Operation | Code |
|---|---|---|
| 1 | If `header.dh != DHr`: perform DH ratchet step | Check `header.ratchet_key != state.dh_receiving` |
| 2 | Try `MKSKIPPED` for this `(header.dh, header.n)` | Lookup in `state.skipped_keys` |
| 3 | If found: decrypt with skipped key, remove from map, return | Early return path |
| 4 | Skip message keys up to `header.n` | Loop: `kdf_ck` for each skipped index, store in `skipped_keys` |
| 5 | Enforce `MAX_SKIP` limit | Error if too many keys would be skipped |
| 6 | `(CKr, mk) = KDF_CK(CKr)` | `kdf_ck(&mut state.receiving_chain)` |
| 7 | `Nr = Nr + 1` | `state.recv_count += 1` |
| 8 | `plaintext = DECRYPT(mk, ciphertext, CONCAT(AD, header))` | `aead_decrypt(mk, ciphertext, ad \|\| header_bytes)` |

**DH Ratchet step (Spec §3.5 — triggered on direction change):**

| Step | Spec Operation | Code |
|---|---|---|
| 1 | `PN = Ns` | `state.prev_send_count = state.send_count` |
| 2 | `Ns = 0`, `Nr = 0` | Reset counters |
| 3 | `DHr = header.dh` | `state.dh_receiving = header.ratchet_key` |
| 4 | Skip any remaining message keys in current receiving chain | Store in `skipped_keys` |
| 5 | `(RK, CKr) = KDF_RK(RK, DH(DHs, DHr))` | `kdf_rk(root_key, dh(dh_sending, dh_receiving))` |
| 6 | `DHs = GENERATE_DH()` | `state.dh_sending = generate_keypair()` |
| 7 | `(RK, CKs) = KDF_RK(RK, DH(DHs, DHr))` | `kdf_rk(root_key, dh(dh_sending, dh_receiving))` |

**Initialization from X3DH (Spec §3.2):**

Initiator (Alice):
1. `RK, CKs = KDF_RK(SK, DH(DHs, SPK_B))` — where `SK` is the X3DH output and `SPK_B` serves as Bob's initial ratchet public key
2. `DHr = SPK_B`

Responder (Bob):
1. `DHs = SPK_B` (signed pre-key pair becomes Bob's initial ratchet key pair)
2. `RK = SK`
3. No sending chain yet — it is created on first encrypt (which triggers a DH ratchet step)

---

### 5.6 Session Management

**Spec:** Implied by the protocol flow; no standalone spec section
**Implements in:** `session.rs`, `message.rs`

**SessionRecord:** Holds a current `SessionState` plus a bounded history of previous states (max count TBD). Previous states are needed for:
- Simultaneous initiation: both parties send `PreKeySignalMessage` before receiving the other's. A deterministic tie-breaking rule (TBD — e.g., compare public keys lexicographically) selects the active session; the other is archived.
- Renegotiation: a new `PreKeySignalMessage` may arrive mid-session.

**SessionCipher:** High-level encrypt/decrypt API that:
1. Loads the session from the `SessionStore`
2. On encrypt: uses the current session's ratchet state; outputs a `SignalMessage` or `PreKeySignalMessage`
3. On decrypt: tries the current session first, then iterates previous sessions if the current one fails (for out-of-order messages from a previous session)
4. Stores updated session state back to the `SessionStore`

**Message types (derived from spec descriptions):**
- `SignalMessage` — version byte + serialized header (ratchet key, counter, prev counter) + ciphertext + MAC (format and length TBD — the spec uses AEAD which provides its own authentication tag; any additional outer MAC is an implementation decision)
- `PreKeySignalMessage` — version byte + pre-key ID (optional) + signed pre-key ID + base key (Alice's ephemeral) + identity key (Alice's) + inner `SignalMessage`
- `SenderKeyMessage` — for group messaging (see §5.9)

Serialization uses protobuf via `prost`. Message definitions are derived from the protocol spec descriptions, not from any existing implementation's `.proto` files.

---

### 5.7 Sealed Sender

**Spec:** Publicly documented by Signal (blog post and protocol description)
**Implements in:** `sealed_sender.rs`

Sealed Sender hides the sender's identity from the server. The server can route the message (it knows the recipient) but cannot see who sent it.

**Sender Certificate structure:**
- Sender UUID
- Sender device ID
- Sender identity public key
- Expiration timestamp
- Server certificate (the server's signing key)
- Server's signature over the above fields

**Encrypt protocol:**

| Step | Operation | Code |
|---|---|---|
| 1 | Generate ephemeral key pair `E` | `generate_keypair()` |
| 2 | `shared = DH(E, recipient_identity_key)` | `dh(ephemeral.private, recipient_identity)` |
| 3 | Derive `enc_key, mac_key` from `shared` via HKDF | `hkdf_derive(shared, ...)` |
| 4 | `encrypted_static = ENCRYPT(enc_key, sender_certificate)` | Sender identity + cert encrypted |
| 5 | `encrypted_message = ENCRYPT(enc_key, inner_ciphertext_message)` | The actual Signal/PreKey message |
| 6 | `mac = HMAC(mac_key, E.public \|\| encrypted_static \|\| encrypted_message)` | Integrity tag |
| 7 | Output: version + `E.public` + `encrypted_static` + `encrypted_message` + `mac` | `SealedSenderMessage` |

**Decrypt protocol:**

| Step | Operation | Code |
|---|---|---|
| 1 | Parse version, ephemeral public key, encrypted_static, encrypted_message, mac | Deserialize `SealedSenderMessage` |
| 2 | `shared = DH(our_identity, ephemeral_public)` | `dh(our_identity.private, ephemeral)` |
| 3 | Derive `enc_key, mac_key` from `shared` via HKDF | Same derivation as sender |
| 4 | Verify `mac` | `hmac_verify(mac_key, ...)` |
| 5 | Decrypt `encrypted_static` to recover sender certificate | `aead_decrypt(enc_key, encrypted_static)` |
| 6 | Validate sender certificate: check signature, check expiration against current time | `verify_certificate(cert, trust_root, now)` |
| 7 | Decrypt `encrypted_message` to recover inner ciphertext message | `aead_decrypt(enc_key, encrypted_message)` |
| 8 | Decrypt inner message using normal session decrypt | `session_cipher.decrypt(inner_message)` |

---

### 5.8 Sender Keys (Group Messaging)

**Spec:** Described in Signal's Sender Keys documentation
**Implements in:** `group.rs`

Sender Keys optimize group messaging: instead of encrypting N times (once per group member), the sender encrypts once. Each group member has a symmetric "sender key" that all other members know.

**Key distribution protocol:**
1. Sender generates a `SenderKeyDistributionMessage` containing:
   - Key ID (u32)
   - Iteration counter (u32)
   - Chain key (32 bytes) — for symmetric ratchet
   - Signing public key — for message authentication
2. This message is sent 1:1 to each group member via a normal pairwise session (encrypted with the Double Ratchet)
3. Each recipient stores the sender key in their `SenderKeyStore`

**Group encrypt:**

| Step | Operation |
|---|---|
| 1 | Derive message key from chain key using a symmetric ratchet (KDF constants TBD — this is an implementation decision for the group layer) |
| 2 | Advance chain key |
| 3 | Encrypt plaintext with message key using AES-256-GCM |
| 4 | Sign the message (key_id + iteration + ciphertext) with the sender's signing key |
| 5 | Increment iteration counter |

**Group decrypt:**

| Step | Operation |
|---|---|
| 1 | Look up the sender's key by `(group_id, sender_address)` in `SenderKeyStore` |
| 2 | Verify the signature against the sender's stored signing public key |
| 3 | Advance the sender's chain key to the message's iteration (may need to skip ahead) |
| 4 | Derive message key and decrypt ciphertext |

---

### 5.9 Sesame (Multi-Device)

**Spec:** signal.org/docs/specifications/sesame
**Implements in:** `sesame.rs`

Sesame handles the problem of users with multiple devices. When Alice sends a message to Bob, she must encrypt it separately for each of Bob's devices, since each device has its own identity key and session state.

**Protocol flow (Sesame §3):**

| Step | Operation | Code |
|---|---|---|
| 1 | Query server for recipient's device list | Application-layer call, returns list of `DeviceAddress` |
| 2 | For each device: check if a session exists | `session_store.load_session(address)` |
| 3 | If no session: fetch pre-key bundle, run X3DH | `x3dh_initiate(...)` + `ratchet_init_initiator(...)` |
| 4 | Encrypt message for each device using its session | `session_cipher.encrypt(plaintext)` per device |
| 5 | Send all encrypted copies to the server for fan-out | Application-layer call |

**Receiving side:**
1. Server delivers the copy addressed to this specific device
2. Normal session decrypt (may be a `PreKeySignalMessage` if this is a new session)

**Device management considerations:**
- Stale devices: if a device hasn't been seen in a configured period, stop encrypting for it
- New devices: when the server reports a new device for a contact, establish a session before the next message
- Own devices: the sender also encrypts to their own other devices (for message sync)

---

### 5.10 Safety Numbers (Fingerprints)

**Spec:** Described in Signal's safety number specification
**Implements in:** `fingerprint.rs`

Safety numbers allow two users to verify that they are communicating with each other's real identity keys (detecting MITM attacks).

**Displayable fingerprint generation:**

The spec describes an iterated hash approach for generating displayable fingerprints:

| Step | Operation |
|---|---|
| 1 | For each party: compute `hash = SHA-512(version \|\| identity_key \|\| stable_identifier)` iterated N times (iteration count TBD) |
| 2 | Encode a portion of the final hash as a numeric string (digit count and grouping TBD) |
| 3 | The displayable fingerprint is the concatenation of both parties' numeric strings |

The specific iteration count, digit length, and grouping format are implementation decisions that affect the security level (collision resistance) and usability (readability). These will be determined during implementation.

**Scannable fingerprint:**
- A protobuf-serialized structure containing version + both fingerprint hashes
- Used with QR codes for in-person verification
- The verifier checks that the scanned fingerprint matches their locally computed one (with local/remote swapped)

---

### 5.11 Storage Traits

**Spec:** Not specified — this is an implementation concern
**Implements in:** `store.rs`

The protocol specs define what state must be persisted but not how. Our implementation defines async traits that consumers implement with their platform's storage backend (SQLite, Core Data, Room, etc.).

| Trait | What it Stores | Spec Requirement |
|---|---|---|
| `IdentityKeyStore` | Local identity key pair, remote identity keys, trust decisions | X3DH §2.1: "IK is a long-term key" — must be persisted permanently |
| `PreKeyStore` | One-time pre-keys | X3DH §2.3: must be deletable after use |
| `SignedPreKeyStore` | Signed pre-keys with signatures and timestamps | X3DH §2.2: rotated periodically, old ones kept briefly for in-flight messages |
| `SessionStore` | Session records (ratchet state per remote address) | Double Ratchet §3.1: entire ratchet state must survive app restart |
| `SenderKeyStore` | Sender keys for group sessions | Sender Keys: stored per (group_id, sender_address) |
| `ProtocolStore` | Combined super-trait | Convenience for functions needing multiple stores |

---

## 6. FFI Design

### 6.1 C FFI Pattern

All functions follow a consistent pattern:
- Return `i32` error code (0 = success)
- Output via out-pointers
- Opaque handles for Rust objects (boxed, leaked, reclaimed on `_destroy`)
- Caller owns memory returned via out-pointers and must call corresponding `_destroy`

```c
// Example C API surface
int32_t signal_identity_key_pair_generate(SignalIdentityKeyPair **out);
int32_t signal_identity_key_pair_destroy(SignalIdentityKeyPair *handle);

int32_t signal_session_cipher_encrypt(
    const SignalSessionCipher *cipher,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t **out_ciphertext,
    size_t *out_ciphertext_len
);
```

Header generated automatically by `cbindgen`.

### 6.2 Swift Bindings

Swift Package wrapping the C static library via a module map. Swift classes manage handle lifetime with `deinit` calling `_destroy`. Errors are bridged to Swift `Error` types.

### 6.3 Kotlin/JNI Bindings

JNI functions in Rust (`pack-protocol-jni` crate) map to Kotlin `external fun` declarations. The native library is loaded via `System.loadLibrary("signal_jni")`.

### 6.4 C++ Bindings

Thin RAII wrapper using `std::unique_ptr` with custom deleters. Built with CMake, links against the static or dynamic C library.

---

## 7. Dependencies

All runtime dependencies must be permissively licensed (MIT, Apache-2.0, or BSD).

| Crate | License | Purpose |
|---|---|---|
| `x25519-dalek` | BSD-3-Clause | X25519 Diffie-Hellman |
| `ed25519-dalek` | BSD-3-Clause | Ed25519 signatures |
| `curve25519-dalek` | BSD-3-Clause | Curve arithmetic |
| `aes-gcm` | MIT/Apache-2.0 | AEAD encryption |
| `hkdf` | MIT/Apache-2.0 | Key derivation |
| `hmac` | MIT/Apache-2.0 | MAC computation |
| `sha2` | MIT/Apache-2.0 | SHA-256/512 |
| `rand` | MIT/Apache-2.0 | Randomness |
| `zeroize` | MIT/Apache-2.0 | Secret material cleanup |
| `prost` | Apache-2.0 | Protobuf serialization |
| `thiserror` | MIT/Apache-2.0 | Error derive macro |
| `subtle` | BSD-3-Clause | Constant-time comparisons |
| `jni` | MIT/Apache-2.0 | JNI bindings (pack-protocol-jni only) |

Before every release, run `cargo tree` and audit for any GPL-licensed transitive dependencies.

---

## 8. Testing Strategy

### 8.1 Unit Tests

Every module has `#[cfg(test)]` tests:
- **Crypto primitives:** Known-answer test vectors from RFCs
- **X3DH:** Both sides derive the same shared secret, with and without one-time pre-keys
- **Double Ratchet:** Ping-pong, out-of-order delivery, lost messages, skipped key limits
- **Sealed Sender:** Round-trip, expired certificate rejection, invalid signature rejection
- **Fingerprints:** Known-answer tests for displayable fingerprint generation

### 8.2 Spec Test Vectors

Test vectors from the X3DH and Double Ratchet specification appendices, stored as JSON in `tests/vectors/`, loaded and verified by integration tests.

### 8.3 End-to-End Integration Tests

Full protocol flows: key generation → bundle publication → X3DH → Double Ratchet session → bidirectional message exchange.

### 8.4 Cross-Language Interop Tests

Messages encrypted via one binding decrypted via another (Rust ↔ C++ ↔ Swift ↔ Kotlin).

### 8.5 Fuzz Testing

`cargo-fuzz` targets for protobuf deserialization and ratchet decryption with malformed inputs.

### 8.6 Property-Based Testing

`proptest` to verify invariants: ratchet consistency across arbitrary message sequences, skipped key bounds, encrypt-then-decrypt identity.

---

## 9. Implementation Phases

| Phase | Scope | Estimated Timeline |
|---|---|---|
| **1. Crypto Foundation** | `crypto/*`, `keys.rs`, `errors.rs` + known-answer tests | Week 1 |
| **2. X3DH** | `x3dh.rs`, protobuf wire types for PreKeySignalMessage | Week 2 |
| **3. Double Ratchet** | `chain.rs`, `ratchet.rs` + spec test vectors | Week 2-3 |
| **4. Session Layer** | `store.rs` traits, `session.rs`, `message.rs`, in-memory store | Week 3 |
| **5. Advanced Features** | `sealed_sender.rs`, `group.rs`, `fingerprint.rs` | Week 4 |
| **6. C FFI** | `pack-protocol-ffi` crate, `cbindgen`, C++ wrapper | Week 5 |
| **7. Mobile Bindings** | `pack-protocol-jni`, Swift Package, Kotlin wrapper, `xtask` build scripts | Week 5-6 |
| **8. Multi-Device** | `sesame.rs` | Week 6-7 |
| **9. Hardening** | Fuzz testing, property tests, interop tests, constant-time audit, zeroize audit | Week 7-8 |

---

## 10. Security Considerations

- **No `unsafe` in protocol code.** `pack-protocol` compiles with `#![forbid(unsafe_code)]`. All `unsafe` is confined to `pack-protocol-ffi` and `pack-protocol-jni`.
- **Zeroize all secrets.** Every type holding key material derives `Zeroize + ZeroizeOnDrop`.
- **Constant-time comparisons.** MAC and signature verification uses the `subtle` crate to prevent timing attacks.
- **Bounded skipped keys.** The Double Ratchet limits stored skipped message keys (default 1000) to prevent memory exhaustion attacks.
- **Certificate expiration.** Sealed Sender validates sender certificate expiration to prevent replay with stale certificates.
- **Security audit.** A professional cryptographic audit is strongly recommended before production deployment. This document and the implementation are not a substitute for expert review.
