// Implements: X25519 Diffie-Hellman (RFC 7748 Section 5) and XEdDSA (XEdDSA specification, Section 2)
// X25519 provides DH key agreement. XEdDSA allows an X25519 key to produce Ed25519-compatible signatures.

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{Result, PackError};

#[derive(Clone, Zeroize)]
pub struct PublicKey {
    bytes: [u8; 32],
}

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Create a PublicKey from bytes, rejecting the all-zeros key (the identity
    /// point on Curve25519, which always produces a zero DH output).
    pub fn from_bytes_validated(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0u8; 32] {
            return Err(PackError::InvalidKey(
                "rejected all-zeros public key (identity point)".into(),
            ));
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn to_x25519(&self) -> X25519Public {
        X25519Public::from(self.bytes)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for PublicKey {}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({:?})", &self.bytes[..4])
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    bytes: [u8; 32],
}

impl PrivateKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Create a PrivateKey from bytes with X25519 clamping applied.
    /// Clears bottom 3 bits, clears top bit, sets second-to-top bit,
    /// ensuring the result is always a valid X25519 scalar.
    pub fn from_bytes_clamped(mut bytes: [u8; 32]) -> Self {
        bytes[0] &= 248;   // clear bottom 3 bits
        bytes[31] &= 127;  // clear top bit
        bytes[31] |= 64;   // set second-to-top bit
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn to_static_secret(&self) -> StaticSecret {
        StaticSecret::from(self.bytes)
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes }
    }
}

/// A key pair containing both a public and private key.
/// The contained `PrivateKey` implements `ZeroizeOnDrop`, so private key
/// material is automatically zeroized when the `KeyPair` is dropped.
#[derive(Clone)]
pub struct KeyPair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519Public::from(&secret);

        KeyPair {
            public: PublicKey::from_bytes(*public.as_bytes()),
            private: PrivateKey::from_bytes(secret.to_bytes()),
        }
    }
}

/// Perform X25519 Diffie-Hellman key agreement.
/// RFC 7748 Section 5: shared_secret = our_scalar * their_public_point
///
/// Returns an error if the shared secret is all zeros, which indicates a
/// small-subgroup attack (the remote public key is a low-order point).
pub fn dh(our_private: &PrivateKey, their_public: &PublicKey) -> Result<[u8; 32]> {
    let secret = our_private.to_static_secret();
    let public = their_public.to_x25519();
    let shared = *secret.diffie_hellman(&public).as_bytes();
    if shared == [0u8; 32] {
        return Err(PackError::InvalidKey(
            "DH shared secret is all zeros (small-subgroup attack)".into(),
        ));
    }
    Ok(shared)
}

/// XEdDSA signing: produce an Ed25519-compatible signature using an X25519 private key.
///
/// Per the XEdDSA spec (Section 2), implemented directly with curve25519-dalek primitives:
/// 1. Clamp the X25519 private scalar
/// 2. Compute Ed25519 public point A = a*B
/// 3. If A has odd sign bit, negate the scalar (so sign bit is always 0)
/// 4. Derive a hedged nonce r = SHA-512(Z || a || message) mod L  (Z = 64 random bytes)
/// 5. Compute R = r*B
/// 6. Compute S = r + SHA-512(R || A || message) * a mod L
/// 7. Signature is (R, S)
pub fn xeddsa_sign(private: &PrivateKey, message: &[u8]) -> [u8; 64] {
    use curve25519_dalek::scalar::clamp_integer;
    use sha2::{Sha512, Digest};

    // Step 1: clamp
    let clamped = clamp_integer(*private.as_bytes());
    let mut a = curve25519_dalek::Scalar::from_bytes_mod_order(clamped);

    // Step 2: compute public point
    let big_a = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &a;
    let big_a_compressed = big_a.compress();
    let mut a_bytes = *big_a_compressed.as_bytes();

    // Step 3: negate if sign bit is odd
    if a_bytes[31] >> 7 == 1 {
        a = -a;
        let new_a = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &a;
        a_bytes = *new_a.compress().as_bytes();
    }

    // Step 4: hedged nonce r = SHA-512(Z || a || message) mod L
    // Per XEdDSA spec Section 2.1: random bytes provide fault-attack protection,
    // while the scalar and message provide nonce-reuse protection.
    let r = {
        use rand::RngCore;
        let mut random_bytes = [0u8; 64];
        OsRng.fill_bytes(&mut random_bytes);

        let mut h = Sha512::new();
        h.update(&random_bytes);
        h.update(&a.to_bytes());
        h.update(message);
        let hash = h.finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hash);
        curve25519_dalek::Scalar::from_bytes_mod_order_wide(&wide)
    };

    // Step 5: R = r * B
    let big_r = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &r;
    let r_bytes = big_r.compress();

    // Step 6: S = r + SHA-512(R || A || message) * a
    let k = {
        let mut h = Sha512::new();
        h.update(r_bytes.as_bytes());
        h.update(&a_bytes);
        h.update(message);
        let hash = h.finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hash);
        curve25519_dalek::Scalar::from_bytes_mod_order_wide(&wide)
    };
    let s = r + k * a;

    // Step 7: signature = (R || S)
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(r_bytes.as_bytes());
    sig[32..].copy_from_slice(&s.to_bytes());
    sig
}

/// XEdDSA verification: verify an Ed25519-compatible signature against an X25519 public key.
///
/// Per the XEdDSA spec (Section 2):
/// 1. Convert X25519 public key (Montgomery u-coordinate) to Ed25519 public key (Edwards y)
/// 2. Try both possible sign bits (the Montgomery form loses sign information)
/// 3. Verify the Ed25519 signature
pub fn xeddsa_verify(public: &PublicKey, message: &[u8], signature: &[u8; 64]) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let sig = Signature::from_bytes(signature);
    let montgomery = curve25519_dalek::montgomery::MontgomeryPoint(*public.as_bytes());

    // During signing, the sign bit was forced to 0, so try sign=0 first
    for sign in [0u8, 1u8] {
        if let Some(edwards) = montgomery.to_edwards(sign) {
            let compressed = edwards.compress();
            if let Ok(vk) = VerifyingKey::from_bytes(compressed.as_bytes()) {
                if vk.verify(message, &sig).is_ok() {
                    return Ok(());
                }
            }
        }
    }

    Err(PackError::InvalidSignature)
}

pub fn ed25519_verify_raw(public_bytes: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let sig = Signature::from_bytes(signature);
    let vk = VerifyingKey::from_bytes(public_bytes)
        .map_err(|_| PackError::InvalidKey("invalid ed25519 public key".into()))?;
    vk.verify(message, &sig)
        .map_err(|_| PackError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate();
        assert_ne!(kp.public.as_bytes(), &[0u8; 32]);
        assert_ne!(kp.private.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_dh_shared_secret() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let shared_a = dh(&alice.private, &bob.public).unwrap();
        let shared_b = dh(&bob.private, &alice.public).unwrap();

        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn test_dh_different_keys_different_secrets() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let charlie = KeyPair::generate();

        let shared_ab = dh(&alice.private, &bob.public).unwrap();
        let shared_ac = dh(&alice.private, &charlie.public).unwrap();

        assert_ne!(shared_ab, shared_ac);
    }

    #[test]
    fn test_dh_zero_public_key_rejected() {
        let kp = KeyPair::generate();
        let zero_pub = PublicKey::from_bytes([0u8; 32]);
        let result = dh(&kp.private, &zero_pub);
        assert!(result.is_err(), "DH with all-zeros public key must fail");
    }

    #[test]
    fn test_public_key_from_bytes_validated_rejects_zero() {
        let result = PublicKey::from_bytes_validated([0u8; 32]);
        assert!(result.is_err(), "from_bytes_validated must reject all-zeros key");
    }

    #[test]
    fn test_public_key_from_bytes_validated_accepts_normal() {
        let kp = KeyPair::generate();
        let result = PublicKey::from_bytes_validated(*kp.public.as_bytes());
        assert!(result.is_ok());
    }

    #[test]
    fn test_private_key_clamping() {
        let raw = [0xFF; 32];
        let clamped = PrivateKey::from_bytes_clamped(raw);
        let b = clamped.as_bytes();
        assert_eq!(b[0] & 0x07, 0);
        assert_eq!(b[31] & 0x80, 0);
        assert_eq!(b[31] & 0x40, 0x40);
    }

    #[test]
    fn test_xeddsa_sign_verify() {
        let kp = KeyPair::generate();
        let message = b"test message for xeddsa";

        let signature = xeddsa_sign(&kp.private, message);
        let result = xeddsa_verify(&kp.public, message, &signature);
        assert!(result.is_ok(), "signature verification should succeed: {:?}", result);
    }

    #[test]
    fn test_xeddsa_wrong_message_fails() {
        let kp = KeyPair::generate();
        let signature = xeddsa_sign(&kp.private, b"correct message");
        assert!(xeddsa_verify(&kp.public, b"wrong message", &signature).is_err());
    }

    #[test]
    fn test_xeddsa_wrong_key_fails() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let signature = xeddsa_sign(&kp1.private, b"test message");
        assert!(xeddsa_verify(&kp2.public, b"test message", &signature).is_err());
    }

    #[test]
    fn test_xeddsa_empty_message() {
        let kp = KeyPair::generate();
        let signature = xeddsa_sign(&kp.private, b"");
        assert!(xeddsa_verify(&kp.public, b"", &signature).is_ok());
    }

    #[test]
    fn test_xeddsa_large_message() {
        let kp = KeyPair::generate();
        let message = vec![0xABu8; 10000];
        let signature = xeddsa_sign(&kp.private, &message);
        assert!(xeddsa_verify(&kp.public, &message, &signature).is_ok());
    }

    #[test]
    fn test_xeddsa_many_keys() {
        for _ in 0..100 {
            let kp = KeyPair::generate();
            let message = b"sign bit stress test";
            let signature = xeddsa_sign(&kp.private, message);
            assert!(
                xeddsa_verify(&kp.public, message, &signature).is_ok(),
                "XEdDSA sign/verify must work for all key pairs"
            );
        }
    }

    #[test]
    fn test_public_key_constant_time_eq() {
        let kp1 = KeyPair::generate();
        let same = PublicKey::from_bytes(*kp1.public.as_bytes());
        let kp2 = KeyPair::generate();

        assert_eq!(kp1.public, same);
        assert_ne!(kp1.public, kp2.public);
    }

}
