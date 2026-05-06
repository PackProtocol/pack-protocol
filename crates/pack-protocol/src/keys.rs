// Implements: Key types defined by X3DH specification Sections 2.1-2.4
// and PQXDH post-quantum key types (signal.org/docs/specifications/pqxdh/)
// ML-KEM per FIPS 203

use crate::crypto::curve::{self, KeyPair, PublicKey, PrivateKey};
use crate::errors::Result;

/// Long-term identity key pair (X3DH §2.1).
/// Used for both X25519 DH and XEdDSA signing.
/// The private key never leaves the device.
pub struct IdentityKeyPair {
    pub public: IdentityKey,
    private: PrivateKey,
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        let kp = KeyPair::generate();
        Self {
            public: IdentityKey(kp.public.clone()),
            private: kp.private.clone(),
        }
    }

    pub fn from_keys(public: IdentityKey, private: PrivateKey) -> Self {
        Self { public, private }
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private
    }

    /// Sign a message using XEdDSA.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        curve::xeddsa_sign(&self.private, message)
    }
}

/// The public half of an identity key.
#[derive(Clone, Debug)]
pub struct IdentityKey(PublicKey);

impl IdentityKey {
    pub fn from_public_key(key: PublicKey) -> Self {
        Self(key)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        Ok(Self(PublicKey::from_bytes_validated(bytes)?))
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Verify an XEdDSA signature.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        curve::xeddsa_verify(&self.0, message, signature)
    }
}

impl PartialEq for IdentityKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for IdentityKey {}

/// Signed pre-key (X3DH §2.2).
/// Medium-term key pair signed by the identity key via XEdDSA.
/// Rotated periodically (rotation interval is an implementation decision).
pub struct SignedPreKey {
    pub id: u32,
    pub key_pair: KeyPair,
    pub signature: [u8; 64],
    pub timestamp: u64,
}

impl SignedPreKey {
    /// Generate a new signed pre-key, signing the public key with the identity key.
    pub fn generate(id: u32, identity: &IdentityKeyPair, timestamp: u64) -> Self {
        let key_pair = KeyPair::generate();
        let signature = identity.sign(key_pair.public.as_bytes());
        Self {
            id,
            key_pair,
            signature,
            timestamp,
        }
    }

    /// Verify this signed pre-key's signature against the given identity key.
    pub fn verify_signature(&self, identity: &IdentityKey) -> Result<()> {
        identity.verify(self.key_pair.public.as_bytes(), &self.signature)
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.key_pair.public
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.key_pair.private
    }
}

/// One-time pre-key (X3DH §2.3).
/// Single-use key that is deleted after being consumed during session establishment.
pub struct OneTimePreKey {
    pub id: u32,
    pub key_pair: KeyPair,
}

impl OneTimePreKey {
    pub fn generate(id: u32) -> Self {
        Self {
            id,
            key_pair: KeyPair::generate(),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.key_pair.public
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.key_pair.private
    }
}

/// Pre-key bundle published to the server (X3DH §3.2).
/// Contains everything a remote party needs to initiate X3DH.
pub struct PreKeyBundle {
    pub identity_key: IdentityKey,
    pub signed_pre_key_id: u32,
    pub signed_pre_key: PublicKey,
    pub signed_pre_key_signature: [u8; 64],
    pub signed_pre_key_timestamp: u64,
    pub one_time_pre_key_id: Option<u32>,
    pub one_time_pre_key: Option<PublicKey>,
}

impl PreKeyBundle {
    /// Verify the signed pre-key signature in this bundle.
    pub fn verify_signed_pre_key(&self) -> Result<()> {
        self.identity_key.verify(
            self.signed_pre_key.as_bytes(),
            &self.signed_pre_key_signature,
        )
    }

    /// Check that the signed pre-key is not older than `max_age_secs` relative to `now_secs`.
    /// Both values are seconds since the UNIX epoch.
    pub fn check_signed_pre_key_age(&self, now_secs: u64, max_age_secs: u64) -> Result<()> {
        if now_secs.saturating_sub(self.signed_pre_key_timestamp) > max_age_secs {
            return Err(crate::errors::PackError::InvalidMessage(
                "signed pre-key has expired".into(),
            ));
        }
        Ok(())
    }
}

/// Post-quantum signed pre-key using ML-KEM-768 (FIPS 203).
/// Signed by the identity key via XEdDSA, analogous to SignedPreKey for X25519.
pub struct PQPreKey {
    pub id: u32,
    pub decapsulation_key: ml_kem::ml_kem_768::DecapsulationKey,
    pub encapsulation_key: ml_kem::ml_kem_768::EncapsulationKey,
    pub signature: [u8; 64],
    pub timestamp: u64,
}

impl PQPreKey {
    pub fn generate(id: u32, identity: &IdentityKeyPair, timestamp: u64) -> Self {
        use ml_kem::kem::KeyExport;
        use rand::RngCore;

        let mut seed_bytes = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut seed_bytes);
        let seed = ml_kem::Seed::from(seed_bytes);

        let dk = ml_kem::ml_kem_768::DecapsulationKey::from_seed(seed);
        let ek = dk.encapsulation_key().clone();

        let ek_bytes = ek.to_bytes();
        let signature = identity.sign(ek_bytes.as_ref());

        Self {
            id,
            decapsulation_key: dk,
            encapsulation_key: ek,
            signature,
            timestamp,
        }
    }

    pub fn verify_signature(&self, identity: &IdentityKey) -> Result<()> {
        use ml_kem::kem::KeyExport;
        let ek_bytes = self.encapsulation_key.to_bytes();
        identity.verify(ek_bytes.as_ref(), &self.signature)
    }

    pub fn encapsulation_key_bytes(&self) -> Vec<u8> {
        use ml_kem::kem::KeyExport;
        self.encapsulation_key.to_bytes().to_vec()
    }

    pub fn decapsulation_key_bytes(&self) -> Vec<u8> {
        use ml_kem::kem::KeyExport;
        self.decapsulation_key.to_bytes().to_vec()
    }
}

/// Pre-key bundle extended with a post-quantum KEM key for PQXDH.
pub struct PQPreKeyBundle {
    pub identity_key: IdentityKey,
    pub signed_pre_key_id: u32,
    pub signed_pre_key: PublicKey,
    pub signed_pre_key_signature: [u8; 64],
    pub signed_pre_key_timestamp: u64,
    pub one_time_pre_key_id: Option<u32>,
    pub one_time_pre_key: Option<PublicKey>,
    pub pq_pre_key_id: u32,
    pub pq_pre_key: ml_kem::ml_kem_768::EncapsulationKey,
    pub pq_pre_key_signature: [u8; 64],
}

impl PQPreKeyBundle {
    pub fn verify_signed_pre_key(&self) -> Result<()> {
        self.identity_key.verify(
            self.signed_pre_key.as_bytes(),
            &self.signed_pre_key_signature,
        )
    }

    pub fn verify_pq_pre_key(&self) -> Result<()> {
        use ml_kem::kem::KeyExport;
        let ek_bytes = self.pq_pre_key.to_bytes();
        self.identity_key.verify(ek_bytes.as_ref(), &self.pq_pre_key_signature)
    }

    pub fn check_signed_pre_key_age(&self, now_secs: u64, max_age_secs: u64) -> Result<()> {
        if now_secs.saturating_sub(self.signed_pre_key_timestamp) > max_age_secs {
            return Err(crate::errors::PackError::InvalidMessage(
                "signed pre-key has expired".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_key_pair_generation() {
        let ikp = IdentityKeyPair::generate();
        assert_ne!(ikp.public.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_identity_sign_verify() {
        let ikp = IdentityKeyPair::generate();
        let message = b"test identity signing";

        let sig = ikp.sign(message);
        assert!(ikp.public.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_signed_pre_key_generation_and_verification() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(1, &identity, 1000);

        assert_eq!(spk.id, 1);
        assert_eq!(spk.timestamp, 1000);
        assert!(spk.verify_signature(&identity.public).is_ok());
    }

    #[test]
    fn test_signed_pre_key_wrong_identity_fails() {
        let identity1 = IdentityKeyPair::generate();
        let identity2 = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(1, &identity1, 1000);

        assert!(spk.verify_signature(&identity2.public).is_err());
    }

    #[test]
    fn test_one_time_pre_key_generation() {
        let opk = OneTimePreKey::generate(42);
        assert_eq!(opk.id, 42);
        assert_ne!(opk.public_key().as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_pre_key_bundle_verify() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(1, &identity, 1000);
        let opk = OneTimePreKey::generate(100);

        let bundle = PreKeyBundle {
            identity_key: identity.public.clone(),
            signed_pre_key_id: spk.id,
            signed_pre_key: spk.key_pair.public.clone(),
            signed_pre_key_signature: spk.signature,
            signed_pre_key_timestamp: spk.timestamp,
            one_time_pre_key_id: Some(opk.id),
            one_time_pre_key: Some(opk.key_pair.public.clone()),
        };

        assert!(bundle.verify_signed_pre_key().is_ok());
    }

    #[test]
    fn test_pre_key_bundle_no_one_time_key() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(1, &identity, 1000);

        let bundle = PreKeyBundle {
            identity_key: identity.public.clone(),
            signed_pre_key_id: spk.id,
            signed_pre_key: spk.key_pair.public.clone(),
            signed_pre_key_signature: spk.signature,
            signed_pre_key_timestamp: spk.timestamp,
            one_time_pre_key_id: None,
            one_time_pre_key: None,
        };

        assert!(bundle.verify_signed_pre_key().is_ok());
    }

    #[test]
    fn test_identity_key_equality() {
        let ikp = IdentityKeyPair::generate();
        let clone = IdentityKey::from_bytes(*ikp.public.as_bytes()).unwrap();

        assert_eq!(ikp.public, clone);
    }
}
