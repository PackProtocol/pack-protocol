# pack-protocol

A Rust implementation of an end-to-end encrypted messaging protocol based on the published [blogs](https://signal.org/blog/spqr/) of the Signal Protocol. Provides the cryptographic layer for secure 1:1 and group messaging — key agreement, session management, message encryption, sender anonymity, and identity verification.

## What this is

pack-protocol is a library, not an application. It implements:

- **X3DH** (Extended Triple Diffie-Hellman) — asynchronous key agreement for establishing 1:1 sessions without both parties being online
- **Double Ratchet** — forward-secure symmetric key ratcheting for 1:1 sessions with out-of-order message handling
- **Sender Keys** — efficient group encryption where each member maintains a single ratcheting key
- **Sealed Sender** — encrypts sender identity so the relay server cannot determine who sent a message
- **Safety Numbers** — fingerprint generation and QR verification for out-of-band identity confirmation

All cryptographic operations use constant-time primitives where applicable. The crate enforces `#![forbid(unsafe_code)]`.

## What this is not

- Not a messaging application or UI framework
- Not a server or network transport — no sockets, no HTTP, no gRPC
- Not a storage layer — session persistence is the caller's responsibility
- Not a wire protocol — serialization formats are provided, but framing and delivery are outside scope
- Not a key server — pre-key bundle distribution and storage must be handled by your infrastructure

## Crate structure

| Crate | Purpose |
|---|---|
| `pack-protocol` | Core library. All cryptography, key management, and session logic. Pure Rust, no system library requirements. |
| `pack-protocol-ffi` | C-compatible FFI bindings for native integration. |
| `pack-protocol-swift` | Swift bindings for iOS/macOS. |
| `pack-protocol-jni` | JNI bindings for Android/JVM. |

### Protocol layers

1. **Crypto foundation** (`crypto/`) — X25519 DH, XEdDSA signatures, AES-256-GCM, HKDF, HMAC
2. **Key agreement** (`x3dh.rs`, `pqxdh.rs`) — Session establishment between two parties
3. **Double Ratchet** (`ratchet.rs`, `chain.rs`) — Per-message forward secrecy within a session
4. **Sessions** (`session.rs`) — Ratchet state management, serialization, multi-session fallback
5. **Group encryption** (`group.rs`) — Sender Key distribution and message encryption
6. **Sealed sender** (`sealed_sender.rs`) — Metadata-hiding envelope
7. **Fingerprints** (`fingerprint.rs`) — Safety number generation and verification
8. **High-level API** (`api.rs`) — `PackSession`, `PackGroupSession`, `PackSealedSender`, `PackFingerprint`

## API overview

The public API is in `pack_protocol::api`. Four types cover the full protocol surface:

### `PackSession`

Manages a 1:1 encrypted session between two devices.

```rust
// Initiator creates session and encrypts first message
let (session, pre_key_message) = PackSession::initiate(
    our_name, our_device_id, &our_identity, registration_id,
    remote_name, remote_device_id, &their_bundle, &first_message,
)?;

// Responder receives the first message and establishes their side
let (session, plaintext) = PackSession::respond(
    our_name, our_device_id, &our_identity, registration_id,
    remote_name, remote_device_id, &signed_pre_key, one_time_pre_key,
    &pre_key_message_bytes,
)?;

// Subsequent messages
let ciphertext = session.encrypt(plaintext)?;
let plaintext = session.decrypt(ciphertext)?;
```

### `PackGroupSession`

Sender Key-based group encryption. Each group member creates a sender session and distributes the key material to other members.

```rust
// Sender creates a group session and distribution message
let (sender_session, skdm) = PackGroupSession::create_sender(distribution_id)?;

// Receivers process the distribution message
let receiver_session = PackGroupSession::from_distribution(distribution_id, skdm.as_bytes())?;

// Encrypt (sender) and decrypt (receiver)
let ciphertext = sender_session.encrypt_for_send(plaintext)?;
let plaintext = receiver_session.decrypt(ciphertext)?;
```

### `PackSealedSender`

Wraps 1:1 or group messages in a sealed sender envelope that hides the sender's identity from the relay server.

```rust
// Encrypt a group message for multiple recipients
let sealed_blobs = PackSealedSender::encrypt_message(
    &mut group_session, &sender_identity, &raw_cert,
    &recipients, plaintext, timestamp,
)?;

// Decrypt — reveals sender identity and inner ciphertext
let envelope = PackSealedSender::decrypt_message(
    &our_identity, &ciphertext, &trust_root, timestamp,
)?;
let plaintext = envelope.decrypt(&mut group_session)?;

// Distribute sender key to a new contact (first message, no existing session)
let (session, sealed) = PackSealedSender::distribute_sender_key_new(
    our_name, our_device_id, &our_identity, registration_id,
    remote_name, remote_device_id, &their_bundle,
    &raw_cert, &skdm, timestamp,
)?;
```

### `PackFingerprint`

Generates safety numbers for out-of-band identity verification.

```rust
let fingerprint = PackFingerprint::generate(
    local_id, &local_identity_key,
    remote_id, &remote_identity_key,
)?;
// Display as numeric code or verify a scanned QR payload
```

## Security properties

- **Forward secrecy** — compromising long-term keys does not reveal past messages
- **Break-in recovery** — sessions self-heal after a compromise through ratchet advancement
- **Deniability** — no cryptographic proof that a specific party sent a message
- **Sender anonymity** — sealed sender hides the sender's identity from the server
- **Constant-time operations** — key comparisons and HMAC verification use `subtle::ConstantTimeEq`
- **Key zeroization** — private keys, root keys, and chain keys implement `ZeroizeOnDrop`
- **Small-subgroup rejection** — DH outputs are checked for all-zero results

## Cryptographic dependencies

| Primitive | Crate | Use |
|---|---|---|
| X25519 | `x25519-dalek` | ECDH key agreement |
| XEdDSA | `ed25519-dalek` + `curve25519-dalek` | Signatures from Curve25519 keys |
| AES-256-GCM | `aes-gcm` | Symmetric message encryption |
| HKDF-SHA-256 | `hkdf`, `sha2` | Key derivation |
| HMAC-SHA-256 | `hmac`, `sha2` | Message authentication, chain key advancement |
| ML-KEM-768 | `ml-kem` | Post-quantum key encapsulation (PQXDH) |

All dependencies are pure Rust with no system library requirements.

## Building

```sh
cargo build
cargo test
```

Requires Rust 1.70+.

### Fuzz testing

```sh
cd fuzz
cargo +nightly fuzz run fuzz_message_deserialize
cargo +nightly fuzz run fuzz_ratchet_decrypt
cargo +nightly fuzz run fuzz_sealed_sender_decrypt
cargo +nightly fuzz run fuzz_sender_key_message
cargo +nightly fuzz run fuzz_pqxdh
```

## Platform bindings

The core library is pure Rust with no platform dependencies. FFI crates produce:

- **C/C++** — static library via `pack-protocol-ffi`
- **Swift/iOS** — framework via `pack-protocol-swift`
- **Android/Kotlin** — JNI library via `pack-protocol-jni`

## Test coverage

~250 tests covering protocol correctness, security properties (forward secrecy, replay rejection, identity key validation, MAC verification), cross-language interoperability, and edge cases (out-of-order messages, skipped keys, re-registration, concurrent sessions).

## FAQ

**Why Rust?**
Memory safety without a garbage collector. Cryptographic libraries are high-value targets for memory corruption exploits — buffer overflows, use-after-free, double-free. Rust eliminates these classes of bugs at compile time. The `ZeroizeOnDrop` trait provides deterministic secret cleanup, and `#![forbid(unsafe_code)]` on the core crate means zero unsafe blocks in the cryptographic logic. The modern Rust cryptography ecosystem (`RustCrypto`, `dalek`) is mature and audited.

**Why not use libsignal directly?**
This started with an attempt to integrate the Signal library into an iOS app. When that hit roadblocks, it grew into a larger question: how far can this go? Pack Protocol became an experiment: could AI-assisted development produce a working, correct implementation of modern E2EE protocols? The answer turned out to be yes — with human direction, code review, and cross-platform interop testing against independent implementations.

**What about post-quantum?**
The codebase includes PQXDH (hybrid X25519 + ML-KEM-768) key agreement at the cryptographic layer. It is not yet integrated into the end-to-end message flow. When complete, PQXDH will replace X3DH as the default key agreement — not as an optional mode, but as the only path. Every session will be quantum-resistant transparently.

**Has this been audited?**
No. The library has not undergone a formal third-party security audit. The test suite covers protocol correctness and security properties, and fuzz targets exercise parsing and decryption paths, but independent review should precede use in production systems.

**How is this different from Signal?**
This is a clean-room implementation based on the published specifications and blog posts of the Signal Protocol. It is not a fork of libsignal, does not share code with Signal, and is not affiliated with Signal Foundation. The protocol design follows the same cryptographic approach — X3DH, Double Ratchet, Sender Keys, Sealed Sender — but the implementation, API, and licensing are independent.

## Security

This library implements security-critical cryptographic protocols. It has not yet undergone a formal third-party security audit. Use in production systems should be preceded by independent review.

If you discover a security vulnerability, please report it privately rather than opening a public issue.

## License

AGPL-3.0. See [LICENSE](LICENSE) for the full text.

Commercial licensing is available for organizations that require terms other than AGPL. Contact [Finn Devs](mailto:hello@finndevs.com) for details.
