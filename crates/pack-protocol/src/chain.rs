// Implements: Symmetric chain key derivation functions KDF_RK and KDF_CK
// Source: https://signal.org/docs/specifications/doubleratchet/ Sections 2.2-2.3

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::kdf;
use crate::crypto::hmac;
use crate::errors::Result;

/// A 32-byte root key that advances on each DH ratchet step.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey {
    bytes: [u8; 32],
}

impl RootKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// A 32-byte chain key used to derive message keys.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey {
    bytes: [u8; 32],
}

impl ChainKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// A 32-byte message key used for a single message's AEAD encryption.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey {
    bytes: [u8; 32],
}

impl MessageKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// KDF_RK: Root key derivation (spec §2.2).
///
/// Takes the current root key and a DH output, produces a new root key and a new chain key.
/// Uses HKDF with the root key as salt and the DH output as input keying material.
///
/// Output: 64 bytes split into (new_root_key[0..32], new_chain_key[32..64])
pub fn kdf_rk(root_key: &RootKey, dh_output: &[u8; 32]) -> Result<(RootKey, ChainKey)> {
    let (rk_bytes, ck_bytes) = kdf::hkdf_derive_pair(dh_output, root_key.as_bytes(), b"DoubleRatchet")?;
    Ok((RootKey::from_bytes(rk_bytes), ChainKey::from_bytes(ck_bytes)))
}

/// KDF_CK: Chain key derivation (spec §2.3).
///
/// Takes the current chain key and produces the next chain key and a message key.
/// Uses HMAC-SHA256 with single-byte inputs as the KDF.
///
/// message_key = HMAC-SHA256(ck, 0x01)
/// new_chain_key = HMAC-SHA256(ck, 0x02)
pub fn kdf_ck(chain_key: &ChainKey) -> (ChainKey, MessageKey) {
    let mk_bytes = hmac::hmac_sha256(chain_key.as_bytes(), &[0x01]);
    let new_ck_bytes = hmac::hmac_sha256(chain_key.as_bytes(), &[0x02]);
    (ChainKey::from_bytes(new_ck_bytes), MessageKey::from_bytes(mk_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_rk_produces_different_outputs() {
        let rk = RootKey::from_bytes([0x42; 32]);
        let dh1 = [0x01; 32];
        let dh2 = [0x02; 32];

        let (new_rk1, ck1) = kdf_rk(&rk, &dh1).unwrap();
        let (new_rk2, ck2) = kdf_rk(&rk, &dh2).unwrap();

        // Different DH outputs should produce different keys
        assert_ne!(new_rk1.as_bytes(), new_rk2.as_bytes());
        assert_ne!(ck1.as_bytes(), ck2.as_bytes());
    }

    #[test]
    fn test_kdf_rk_deterministic() {
        let rk = RootKey::from_bytes([0x42; 32]);
        let dh = [0xAB; 32];

        let (rk1, ck1) = kdf_rk(&rk, &dh).unwrap();
        let (rk2, ck2) = kdf_rk(&rk, &dh).unwrap();

        assert_eq!(rk1.as_bytes(), rk2.as_bytes());
        assert_eq!(ck1.as_bytes(), ck2.as_bytes());
    }

    #[test]
    fn test_kdf_rk_root_and_chain_differ() {
        let rk = RootKey::from_bytes([0x42; 32]);
        let dh = [0xAB; 32];

        let (new_rk, ck) = kdf_rk(&rk, &dh).unwrap();
        assert_ne!(new_rk.as_bytes(), ck.as_bytes());
    }

    #[test]
    fn test_kdf_ck_produces_different_outputs() {
        let ck = ChainKey::from_bytes([0x42; 32]);
        let (new_ck, mk) = kdf_ck(&ck);

        // Chain key and message key should differ
        assert_ne!(new_ck.as_bytes(), mk.as_bytes());
        // New chain key should differ from original
        assert_ne!(new_ck.as_bytes(), ck.as_bytes());
    }

    #[test]
    fn test_kdf_ck_deterministic() {
        let ck = ChainKey::from_bytes([0x42; 32]);
        let (ck1, mk1) = kdf_ck(&ck);
        let (ck2, mk2) = kdf_ck(&ck);

        assert_eq!(ck1.as_bytes(), ck2.as_bytes());
        assert_eq!(mk1.as_bytes(), mk2.as_bytes());
    }

    #[test]
    fn test_kdf_ck_spec_constants() {
        // Spec §2.3: KDF_CK uses HMAC with single-byte constants
        // message_key = HMAC(ck, 0x01), new_chain_key = HMAC(ck, 0x02)
        let ck = ChainKey::from_bytes([0x42; 32]);
        let (new_ck, mk) = kdf_ck(&ck);

        // Verify against direct HMAC computation
        let expected_mk = crate::crypto::hmac::hmac_sha256(ck.as_bytes(), &[0x01]);
        let expected_ck = crate::crypto::hmac::hmac_sha256(ck.as_bytes(), &[0x02]);
        assert_eq!(*mk.as_bytes(), expected_mk);
        assert_eq!(*new_ck.as_bytes(), expected_ck);
    }

    #[test]
    fn test_kdf_rk_spec_hkdf_params() {
        // Spec §2.2: KDF_RK uses HKDF with root_key as salt, DH output as IKM,
        // info="DoubleRatchet", output=64 bytes split into new_rk + chain_key
        let rk = RootKey::from_bytes([0x42; 32]);
        let dh = [0xAB; 32];

        let (new_rk, ck) = kdf_rk(&rk, &dh).unwrap();

        // Verify against direct HKDF computation
        let raw = crate::crypto::kdf::hkdf_derive(&dh, rk.as_bytes(), b"DoubleRatchet", 64).unwrap();
        let mut expected_rk = [0u8; 32];
        let mut expected_ck = [0u8; 32];
        expected_rk.copy_from_slice(&raw[..32]);
        expected_ck.copy_from_slice(&raw[32..]);
        assert_eq!(*new_rk.as_bytes(), expected_rk);
        assert_eq!(*ck.as_bytes(), expected_ck);
    }

    #[test]
    fn test_kdf_ck_chain_advances() {
        let ck0 = ChainKey::from_bytes([0x42; 32]);
        let (ck1, mk1) = kdf_ck(&ck0);
        let (ck2, mk2) = kdf_ck(&ck1);
        let (ck3, mk3) = kdf_ck(&ck2);

        // Each step should produce unique keys
        assert_ne!(mk1.as_bytes(), mk2.as_bytes());
        assert_ne!(mk2.as_bytes(), mk3.as_bytes());
        assert_ne!(ck1.as_bytes(), ck2.as_bytes());
        assert_ne!(ck2.as_bytes(), ck3.as_bytes());
    }

}
