# Security Audit Preparation

## Project Overview

Clean-room implementation of the Pack Protocol in Rust, built from public cryptographic specifications only. The core crate uses `#![forbid(unsafe_code)]`.

## Specification Sources

| Component | Specification |
|-----------|--------------|
| X3DH | X3DH key agreement specification |
| Double Ratchet | Double Ratchet Algorithm specification |
| Sealed Sender | Noise Protocol Framework (NK pattern) |
| Sender Keys | Sender Keys group messaging specification |
| XEdDSA | XEdDSA signature specification |

## Crate Structure

- `pack-protocol` — all protocol logic, `#![forbid(unsafe_code)]`, no I/O
- `pack-protocol-ffi` — C FFI layer (contains `unsafe` for FFI boundary)
- `pack-protocol-jni` — JNI layer for Android (contains `unsafe` for JNI boundary)

## Cryptographic Primitives

| Primitive | Implementation | Crate |
|-----------|---------------|-------|
| X25519 DH | `x25519-dalek` | `crypto/curve.rs` |
| Ed25519 / XEdDSA | `curve25519-dalek` (manual) | `crypto/curve.rs` |
| AES-256-GCM | `aes-gcm` | `crypto/aead.rs` |
| HMAC-SHA256 | `hmac` + `sha2` | `crypto/hmac.rs` |
| HKDF-SHA256 | `hkdf` + `sha2` | `crypto/kdf.rs` |
| SHA-512 | `sha2` | `fingerprint.rs` |
| Constant-time comparison | `subtle` | `crypto/curve.rs`, `fingerprint.rs` |

## Secret Material Handling

- All private keys use `Zeroize` + `ZeroizeOnDrop` via the `zeroize` crate
- `PrivateKey` struct wraps `[u8; 32]` with `#[derive(Zeroize, ZeroizeOnDrop)]`
- `IdentityKeyPair` derives `ZeroizeOnDrop`
- Chain keys and message keys implement `Zeroize`
- Root keys implement `Zeroize`

## Areas Requiring Focused Review

### 1. XEdDSA Implementation (`crypto/curve.rs`)
Custom XEdDSA signing/verification using `curve25519-dalek` internals. Converts between Montgomery and Edwards forms. This is the most complex cryptographic code and the highest-risk area.

### 2. Double Ratchet State Machine (`ratchet.rs`)
- DH ratchet step correctness
- Skipped message key management (MAX_SKIP = 1000)
- State serialization/deserialization for persistent storage
- Nonce derivation from message keys

### 3. X3DH Key Agreement (`x3dh.rs`)
- DH computation ordering (DH1-DH4)
- Associated data construction (IK_A || IK_B)
- Shared secret derivation via HKDF

### 4. Session Layer (`session.rs`)
- Associated data consistency between initiator and responder
- Session record serialization format
- Simultaneous initiation resolution
- Previous session state fallback during decryption

### 5. Sealed Sender (`sealed_sender.rs`)
- Certificate chain validation
- Ephemeral key generation and static key encapsulation
- Sender identity concealment guarantees

### 6. FFI Boundary (`pack-protocol-ffi/`)
- Handle lifetime management (box_raw / destroy pattern)
- Null pointer checks on all FFI inputs
- Error propagation across FFI boundary
- No secret material leaked through return values

### 7. Serialization (`ratchet.rs`, `session.rs`, `message.rs`)
- Binary format parsing (potential for out-of-bounds reads)
- Length-prefix validation
- Round-trip correctness (fuzz targets exist)

## Test Coverage Summary

- 101 unit and integration tests in `pack-protocol`
- 4 fuzz targets in `fuzz/`:
  - `fuzz_message_deserialize` — protobuf message parsing
  - `fuzz_ratchet_decrypt` — ratchet decrypt with arbitrary input
  - `fuzz_sealed_sender_decrypt` — sealed sender envelope parsing
  - `fuzz_sender_key_message` — sender key message parsing
- Integration tests cover full X3DH -> Double Ratchet -> session store -> message exchange flow
- Property tests for encrypt/decrypt identity and MAX_SKIP enforcement

## Dependency Audit

All dependencies are permissively licensed (MIT/Apache-2.0). No GPL dependencies.

Run `cargo tree` for the full dependency graph. Key dependencies:
- `x25519-dalek` 2.x (BSD-3)
- `curve25519-dalek` 4.x (BSD-3)
- `aes-gcm` 0.10 (MIT/Apache-2.0)
- `hkdf` 0.12 (MIT/Apache-2.0)
- `sha2` 0.10 (MIT/Apache-2.0)
- `hmac` 0.12 (MIT/Apache-2.0)
- `zeroize` 1.x (MIT/Apache-2.0)
- `subtle` 2.x (BSD-3)
- `prost` 0.13 (Apache-2.0)

## Build Reproducibility

- No C/C++ dependencies in `pack-protocol`
- Protobuf compilation uses `protox` (pure Rust parser) + `prost-build`
- No system library requirements for the core crate
- `Cargo.lock` is committed for reproducible builds

## Known Limitations

- No formal verification of cryptographic operations
- XEdDSA implementation has not been independently audited
- Fuzz testing has been set up but not run for extended periods
- No timing side-channel analysis has been performed (relies on `subtle` and `curve25519-dalek` for constant-time guarantees)
