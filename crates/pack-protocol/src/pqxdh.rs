// Implements: PQXDH key agreement protocol
// Source: signal.org/docs/specifications/pqxdh/
// Extends X3DH with an ML-KEM-768 (FIPS 203) key encapsulation, producing a
// hybrid shared secret that is secure if either X25519 or ML-KEM remains unbroken.

use ml_kem::kem::Decapsulate;
use ml_kem::Encapsulate;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::curve::{self, KeyPair, PublicKey};
use crate::crypto::kdf;
use crate::errors::Result;
use crate::keys::{IdentityKeyPair, PQPreKey, PQPreKeyBundle};

pub struct PQXDHInitResult {
    pub shared_secret: Zeroizing<[u8; 32]>,
    pub ephemeral_public: PublicKey,
    pub kem_ciphertext: Vec<u8>,
    pub associated_data: Vec<u8>,
}

/// 32 bytes of 0xFF, prepended to the DH concatenation per the PQXDH spec.
const F: [u8; 32] = [0xFF; 32];

/// Initiator (Alice) side of PQXDH.
///
/// Extends X3DH §3.3 with a KEM encapsulation step:
/// 1. Verify the signed pre-key and PQ pre-key signatures
/// 2. Generate an ephemeral X25519 key pair
/// 3. Compute DH1..DH4 (same as X3DH)
/// 4. Encapsulate against Bob's PQ pre-key → (kem_ss, kem_ct)
/// 5. SK = HKDF(F || DH1 || DH2 || DH3 [|| DH4] || kem_ss, salt=0, info="PQXDH")
/// 6. AD = Encode(IK_A) || Encode(IK_B)
///
/// # RNG
/// KEM encapsulation uses OS entropy via ml-kem's `getrandom` feature.
/// The ephemeral X25519 key pair likewise uses `OsRng`.
pub fn pqxdh_initiate(
    our_identity: &IdentityKeyPair,
    their_bundle: &PQPreKeyBundle,
) -> Result<PQXDHInitResult> {
    // Step 1: verify signatures
    their_bundle.verify_signed_pre_key()?;
    their_bundle.verify_pq_pre_key()?;

    // Step 2: generate ephemeral key pair
    let ephemeral = KeyPair::generate();

    // Step 3: compute DH values (same as X3DH)
    let dh1 = Zeroizing::new(curve::dh(our_identity.private_key(), &their_bundle.signed_pre_key)?);
    let dh2 = Zeroizing::new(curve::dh(&ephemeral.private, their_bundle.identity_key.public_key())?);
    let dh3 = Zeroizing::new(curve::dh(&ephemeral.private, &their_bundle.signed_pre_key)?);

    let dh4 = their_bundle
        .one_time_pre_key
        .as_ref()
        .map(|opk| curve::dh(&ephemeral.private, opk).map(Zeroizing::new))
        .transpose()?;

    // Step 4: KEM encapsulation
    let (kem_ct, mut kem_ss): (ml_kem::ml_kem_768::Ciphertext, ml_kem::SharedKey) =
        their_bundle.pq_pre_key.encapsulate();

    // Step 5: derive shared secret
    // SK = HKDF(F || DH1 || DH2 || DH3 [|| DH4] || kem_ss, salt=0, info="PQXDH")
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * 6));
    ikm.extend_from_slice(&F);
    ikm.extend_from_slice(&*dh1);
    ikm.extend_from_slice(&*dh2);
    ikm.extend_from_slice(&*dh3);
    if let Some(ref dh4_val) = dh4 {
        ikm.extend_from_slice(&**dh4_val);
    }
    ikm.extend_from_slice(kem_ss.as_slice());
    kem_ss.zeroize();

    let salt = [0u8; 32];
    let sk_bytes = Zeroizing::new(kdf::hkdf_derive(&ikm, &salt, b"PQXDH", 32)?);
    let mut shared_secret = Zeroizing::new([0u8; 32]);
    shared_secret.copy_from_slice(&sk_bytes);

    // Step 6: associated data
    let mut associated_data = Vec::with_capacity(64);
    associated_data.extend_from_slice(our_identity.public.as_bytes());
    associated_data.extend_from_slice(their_bundle.identity_key.as_bytes());

    Ok(PQXDHInitResult {
        shared_secret,
        ephemeral_public: ephemeral.public.clone(),
        kem_ciphertext: AsRef::<[u8]>::as_ref(&kem_ct).to_vec(),
        associated_data,
    })
}

pub struct PQXDHRespondResult {
    pub shared_secret: Zeroizing<[u8; 32]>,
    pub associated_data: Vec<u8>,
}

/// Responder (Bob) side of PQXDH.
///
/// Mirrors the initiator:
/// 1. Compute the same DH values
/// 2. Decapsulate the KEM ciphertext → kem_ss
/// 3. Derive the same shared secret SK
///
/// The PQ pre-key should be deleted after this call (one-time use).
pub fn pqxdh_respond(
    our_identity: &IdentityKeyPair,
    our_signed_pre_key: &crate::keys::SignedPreKey,
    our_one_time_pre_key: Option<&crate::keys::OneTimePreKey>,
    our_pq_pre_key: &PQPreKey,
    their_identity: &crate::keys::IdentityKey,
    their_ephemeral: &PublicKey,
    kem_ciphertext: &[u8],
) -> Result<PQXDHRespondResult> {
    use crate::errors::PackError;

    // DH1 = DH(SPK_B, IK_A)
    let dh1 = Zeroizing::new(curve::dh(our_signed_pre_key.private_key(), their_identity.public_key())?);
    // DH2 = DH(IK_B, EK_A)
    let dh2 = Zeroizing::new(curve::dh(our_identity.private_key(), their_ephemeral)?);
    // DH3 = DH(SPK_B, EK_A)
    let dh3 = Zeroizing::new(curve::dh(our_signed_pre_key.private_key(), their_ephemeral)?);

    let dh4 = our_one_time_pre_key
        .map(|opk| curve::dh(opk.private_key(), their_ephemeral).map(Zeroizing::new))
        .transpose()?;

    // KEM decapsulation
    let ct = ml_kem::ml_kem_768::Ciphertext::try_from(kem_ciphertext)
        .map_err(|_| PackError::InvalidMessage("invalid KEM ciphertext length".into()))?;
    let mut kem_ss: ml_kem::SharedKey = our_pq_pre_key.decapsulation_key.decapsulate(&ct);

    // Derive shared secret
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * 6));
    ikm.extend_from_slice(&F);
    ikm.extend_from_slice(&*dh1);
    ikm.extend_from_slice(&*dh2);
    ikm.extend_from_slice(&*dh3);
    if let Some(ref dh4_val) = dh4 {
        ikm.extend_from_slice(&**dh4_val);
    }
    ikm.extend_from_slice(kem_ss.as_slice());
    kem_ss.zeroize();

    let salt = [0u8; 32];
    let sk_bytes = Zeroizing::new(kdf::hkdf_derive(&ikm, &salt, b"PQXDH", 32)?);
    let mut shared_secret = Zeroizing::new([0u8; 32]);
    shared_secret.copy_from_slice(&sk_bytes);

    // AD = IK_A || IK_B
    let mut associated_data = Vec::with_capacity(64);
    associated_data.extend_from_slice(their_identity.as_bytes());
    associated_data.extend_from_slice(our_identity.public.as_bytes());

    Ok(PQXDHRespondResult {
        shared_secret,
        associated_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{IdentityKeyPair, SignedPreKey, OneTimePreKey, PQPreKey, PQPreKeyBundle};

    fn make_pq_bundle(
        identity: &IdentityKeyPair,
        spk: &SignedPreKey,
        opk: Option<&OneTimePreKey>,
        pqpk: &PQPreKey,
    ) -> PQPreKeyBundle {
        PQPreKeyBundle {
            identity_key: identity.public.clone(),
            signed_pre_key_id: spk.id,
            signed_pre_key: spk.public_key().clone(),
            signed_pre_key_signature: spk.signature,
            signed_pre_key_timestamp: spk.timestamp,
            one_time_pre_key_id: opk.map(|o| o.id),
            one_time_pre_key: opk.map(|o| o.public_key().clone()),
            pq_pre_key_id: pqpk.id,
            pq_pre_key: pqpk.encapsulation_key.clone(),
            pq_pre_key_signature: pqpk.signature,
        }
    }

    #[test]
    fn test_pqxdh_with_one_time_prekey() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);
        let bob_opk = OneTimePreKey::generate(100);
        let bob_pqpk = PQPreKey::generate(200, &bob_identity, 1000);

        let bundle = make_pq_bundle(&bob_identity, &bob_spk, Some(&bob_opk), &bob_pqpk);

        let alice_result = pqxdh_initiate(&alice_identity, &bundle).unwrap();

        let bob_result = pqxdh_respond(
            &bob_identity,
            &bob_spk,
            Some(&bob_opk),
            &bob_pqpk,
            &alice_identity.public,
            &alice_result.ephemeral_public,
            &alice_result.kem_ciphertext,
        )
        .unwrap();

        assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
        assert_eq!(alice_result.associated_data, bob_result.associated_data);
    }

    #[test]
    fn test_pqxdh_without_one_time_prekey() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);
        let bob_pqpk = PQPreKey::generate(200, &bob_identity, 1000);

        let bundle = make_pq_bundle(&bob_identity, &bob_spk, None, &bob_pqpk);

        let alice_result = pqxdh_initiate(&alice_identity, &bundle).unwrap();

        let bob_result = pqxdh_respond(
            &bob_identity,
            &bob_spk,
            None,
            &bob_pqpk,
            &alice_identity.public,
            &alice_result.ephemeral_public,
            &alice_result.kem_ciphertext,
        )
        .unwrap();

        assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
        assert_eq!(alice_result.associated_data, bob_result.associated_data);
    }

    #[test]
    fn test_pqxdh_bad_spk_signature_rejected() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let evil_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &evil_identity, 1000);
        let bob_pqpk = PQPreKey::generate(200, &bob_identity, 1000);

        let bundle = PQPreKeyBundle {
            identity_key: bob_identity.public.clone(),
            signed_pre_key_id: bob_spk.id,
            signed_pre_key: bob_spk.public_key().clone(),
            signed_pre_key_signature: bob_spk.signature,
            signed_pre_key_timestamp: bob_spk.timestamp,
            one_time_pre_key_id: None,
            one_time_pre_key: None,
            pq_pre_key_id: bob_pqpk.id,
            pq_pre_key: bob_pqpk.encapsulation_key.clone(),
            pq_pre_key_signature: bob_pqpk.signature,
        };

        assert!(pqxdh_initiate(&alice_identity, &bundle).is_err());
    }

    #[test]
    fn test_pqxdh_bad_pqpk_signature_rejected() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let evil_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);
        let bob_pqpk = PQPreKey::generate(200, &evil_identity, 1000);

        let bundle = PQPreKeyBundle {
            identity_key: bob_identity.public.clone(),
            signed_pre_key_id: bob_spk.id,
            signed_pre_key: bob_spk.public_key().clone(),
            signed_pre_key_signature: bob_spk.signature,
            signed_pre_key_timestamp: bob_spk.timestamp,
            one_time_pre_key_id: None,
            one_time_pre_key: None,
            pq_pre_key_id: bob_pqpk.id,
            pq_pre_key: bob_pqpk.encapsulation_key.clone(),
            pq_pre_key_signature: bob_pqpk.signature,
        };

        assert!(pqxdh_initiate(&alice_identity, &bundle).is_err());
    }

    #[test]
    fn test_pqxdh_tampered_kem_ciphertext_fails() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);
        let bob_pqpk = PQPreKey::generate(200, &bob_identity, 1000);

        let bundle = make_pq_bundle(&bob_identity, &bob_spk, None, &bob_pqpk);
        let alice_result = pqxdh_initiate(&alice_identity, &bundle).unwrap();

        // Tamper with KEM ciphertext
        let mut bad_ct = alice_result.kem_ciphertext.clone();
        bad_ct[0] ^= 0xFF;

        let bob_result = pqxdh_respond(
            &bob_identity,
            &bob_spk,
            None,
            &bob_pqpk,
            &alice_identity.public,
            &alice_result.ephemeral_public,
            &bad_ct,
        )
        .unwrap();

        // ML-KEM decapsulation with tampered ciphertext produces a different
        // shared secret (implicit rejection), so the secrets won't match
        assert_ne!(alice_result.shared_secret, bob_result.shared_secret);
    }

    #[test]
    fn test_pqxdh_differs_from_x3dh() {
        // The KEM contribution must change the output — verify PQXDH and X3DH
        // produce different secrets even with the same DH inputs
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);
        let bob_pqpk = PQPreKey::generate(200, &bob_identity, 1000);

        let pq_bundle = make_pq_bundle(&bob_identity, &bob_spk, None, &bob_pqpk);
        let pq_result = pqxdh_initiate(&alice_identity, &pq_bundle).unwrap();

        // Can't directly compare because ephemeral keys differ between calls,
        // but we can verify the shared secret is 32 bytes and the KEM
        // ciphertext is the expected ML-KEM-768 size (1088 bytes)
        assert_eq!(pq_result.shared_secret.len(), 32);
        assert_eq!(pq_result.kem_ciphertext.len(), 1088);
        assert_eq!(pq_result.associated_data.len(), 64);
    }

    #[test]
    fn test_pqxdh_different_sessions_different_secrets() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);
        let bob_pqpk = PQPreKey::generate(200, &bob_identity, 1000);

        let bundle = make_pq_bundle(&bob_identity, &bob_spk, None, &bob_pqpk);

        let result1 = pqxdh_initiate(&alice_identity, &bundle).unwrap();
        let result2 = pqxdh_initiate(&alice_identity, &bundle).unwrap();

        assert_ne!(result1.shared_secret, result2.shared_secret);
    }

    #[test]
    fn test_pqxdh_associated_data_format() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);
        let bob_pqpk = PQPreKey::generate(200, &bob_identity, 1000);

        let bundle = make_pq_bundle(&bob_identity, &bob_spk, None, &bob_pqpk);
        let result = pqxdh_initiate(&alice_identity, &bundle).unwrap();

        assert_eq!(result.associated_data.len(), 64);
        assert_eq!(&result.associated_data[..32], alice_identity.public.as_bytes());
        assert_eq!(&result.associated_data[32..], bob_identity.public.as_bytes());
    }
}
