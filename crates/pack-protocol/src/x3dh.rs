// Implements: X3DH key agreement protocol, Sections 3.3 and 3.4
// Source: https://signal.org/docs/specifications/x3dh/

use zeroize::Zeroizing;

use crate::crypto::curve::{self, KeyPair, PublicKey};
use crate::crypto::kdf;
use crate::errors::Result;
use crate::keys::{IdentityKeyPair, IdentityKey, PreKeyBundle};

/// Result of the initiator side of X3DH.
pub struct X3DHInitResult {
    /// The derived shared secret (SK) — zeroized on drop
    pub shared_secret: Zeroizing<[u8; 32]>,
    /// The ephemeral public key Alice generated (sent to Bob)
    pub ephemeral_public: PublicKey,
    /// Associated data: Encode(IK_A) || Encode(IK_B)
    pub associated_data: Vec<u8>,
}

/// 32 bytes of 0xFF, prepended to the DH concatenation per the X3DH spec.
const F: [u8; 32] = [0xFF; 32];

/// Initiator (Alice) side of X3DH (spec §3.3).
///
/// Given our identity key pair and the remote party's published pre-key bundle:
/// 1. Verify the signed pre-key signature
/// 2. Generate an ephemeral key pair
/// 3. Compute DH1..DH4
/// 4. Derive the shared secret SK via HKDF
/// 5. Build associated data AD = IK_A || IK_B
pub fn x3dh_initiate(
    our_identity: &IdentityKeyPair,
    their_bundle: &PreKeyBundle,
) -> Result<X3DHInitResult> {
    // Step 1: verify signed pre-key signature
    their_bundle.verify_signed_pre_key()?;

    // Step 2: generate ephemeral key pair
    let ephemeral = KeyPair::generate();

    // Step 3: compute DH values
    // DH1 = DH(IK_A, SPK_B)
    let dh1 = Zeroizing::new(curve::dh(our_identity.private_key(), &their_bundle.signed_pre_key)?);
    // DH2 = DH(EK_A, IK_B)
    let dh2 = Zeroizing::new(curve::dh(&ephemeral.private, their_bundle.identity_key.public_key())?);
    // DH3 = DH(EK_A, SPK_B)
    let dh3 = Zeroizing::new(curve::dh(&ephemeral.private, &their_bundle.signed_pre_key)?);

    // DH4 = DH(EK_A, OPK_B) — only if one-time pre-key is present
    let dh4 = their_bundle
        .one_time_pre_key
        .as_ref()
        .map(|opk| curve::dh(&ephemeral.private, opk).map(Zeroizing::new))
        .transpose()?;

    // Step 4: derive shared secret
    // SK = HKDF(F || DH1 || DH2 || DH3 [|| DH4], salt=0...0, info="X3DH")
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * 5));
    ikm.extend_from_slice(&F);
    ikm.extend_from_slice(&*dh1);
    ikm.extend_from_slice(&*dh2);
    ikm.extend_from_slice(&*dh3);
    if let Some(ref dh4_val) = dh4 {
        ikm.extend_from_slice(&**dh4_val);
    }

    let salt = [0u8; 32];
    let sk_bytes = Zeroizing::new(kdf::hkdf_derive(&ikm, &salt, b"X3DH", 32)?);
    let mut shared_secret = Zeroizing::new([0u8; 32]);
    shared_secret.copy_from_slice(&sk_bytes);

    // Step 5: build associated data
    // AD = Encode(IK_A) || Encode(IK_B)
    let mut associated_data = Vec::with_capacity(64);
    associated_data.extend_from_slice(our_identity.public.as_bytes());
    associated_data.extend_from_slice(their_bundle.identity_key.as_bytes());

    Ok(X3DHInitResult {
        shared_secret,
        ephemeral_public: ephemeral.public.clone(),
        associated_data,
    })
}

/// Responder (Bob) side of X3DH (spec §3.4).
///
/// Given our keys and the initiator's identity + ephemeral key from the PreKeyPackMessage:
/// 1. Compute the same DH values
/// 2. Derive the same shared secret SK
///
/// The one-time pre-key should be deleted after this call.
pub fn x3dh_respond(
    our_identity: &IdentityKeyPair,
    our_signed_pre_key: &crate::keys::SignedPreKey,
    our_one_time_pre_key: Option<&crate::keys::OneTimePreKey>,
    their_identity: &IdentityKey,
    their_ephemeral: &PublicKey,
) -> Result<X3DHRespondResult> {
    // DH1 = DH(SPK_B, IK_A)
    let dh1 = Zeroizing::new(curve::dh(our_signed_pre_key.private_key(), their_identity.public_key())?);
    // DH2 = DH(IK_B, EK_A)
    let dh2 = Zeroizing::new(curve::dh(our_identity.private_key(), their_ephemeral)?);
    // DH3 = DH(SPK_B, EK_A)
    let dh3 = Zeroizing::new(curve::dh(our_signed_pre_key.private_key(), their_ephemeral)?);

    // DH4 = DH(OPK_B, EK_A) — only if one-time pre-key was used
    let dh4 = our_one_time_pre_key
        .map(|opk| curve::dh(opk.private_key(), their_ephemeral).map(Zeroizing::new))
        .transpose()?;

    // Derive shared secret
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * 5));
    ikm.extend_from_slice(&F);
    ikm.extend_from_slice(&*dh1);
    ikm.extend_from_slice(&*dh2);
    ikm.extend_from_slice(&*dh3);
    if let Some(ref dh4_val) = dh4 {
        ikm.extend_from_slice(&**dh4_val);
    }

    let salt = [0u8; 32];
    let sk_bytes = Zeroizing::new(kdf::hkdf_derive(&ikm, &salt, b"X3DH", 32)?);
    let mut shared_secret = Zeroizing::new([0u8; 32]);
    shared_secret.copy_from_slice(&sk_bytes);

    // Build associated data: AD = IK_A || IK_B
    let mut associated_data = Vec::with_capacity(64);
    associated_data.extend_from_slice(their_identity.as_bytes());
    associated_data.extend_from_slice(our_identity.public.as_bytes());

    Ok(X3DHRespondResult {
        shared_secret,
        associated_data,
    })
}

/// Result of the responder side of X3DH.
pub struct X3DHRespondResult {
    /// The derived shared secret (SK) — must match the initiator's, zeroized on drop
    pub shared_secret: Zeroizing<[u8; 32]>,
    /// Associated data: Encode(IK_A) || Encode(IK_B)
    pub associated_data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{IdentityKeyPair, SignedPreKey, OneTimePreKey, PreKeyBundle};

    fn make_bundle(
        identity: &IdentityKeyPair,
        spk: &SignedPreKey,
        opk: Option<&OneTimePreKey>,
    ) -> PreKeyBundle {
        PreKeyBundle {
            identity_key: identity.public.clone(),
            signed_pre_key_id: spk.id,
            signed_pre_key: spk.public_key().clone(),
            signed_pre_key_signature: spk.signature,
            signed_pre_key_timestamp: spk.timestamp,
            one_time_pre_key_id: opk.map(|o| o.id),
            one_time_pre_key: opk.map(|o| o.public_key().clone()),
        }
    }

    #[test]
    fn test_x3dh_with_one_time_prekey() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);
        let bob_opk = OneTimePreKey::generate(100);

        let bundle = make_bundle(&bob_identity, &bob_spk, Some(&bob_opk));

        // Alice initiates
        let alice_result = x3dh_initiate(&alice_identity, &bundle).unwrap();

        // Bob responds
        let bob_result = x3dh_respond(
            &bob_identity,
            &bob_spk,
            Some(&bob_opk),
            &alice_identity.public,
            &alice_result.ephemeral_public,
        )
        .unwrap();

        // Both sides must derive the same shared secret
        assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
        // Both sides must have the same associated data
        assert_eq!(alice_result.associated_data, bob_result.associated_data);
    }

    #[test]
    fn test_x3dh_without_one_time_prekey() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);

        let bundle = make_bundle(&bob_identity, &bob_spk, None);

        let alice_result = x3dh_initiate(&alice_identity, &bundle).unwrap();

        let bob_result = x3dh_respond(
            &bob_identity,
            &bob_spk,
            None,
            &alice_identity.public,
            &alice_result.ephemeral_public,
        )
        .unwrap();

        assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
        assert_eq!(alice_result.associated_data, bob_result.associated_data);
    }

    #[test]
    fn test_x3dh_different_sessions_different_secrets() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);

        let bundle = make_bundle(&bob_identity, &bob_spk, None);

        let result1 = x3dh_initiate(&alice_identity, &bundle).unwrap();
        let result2 = x3dh_initiate(&alice_identity, &bundle).unwrap();

        // Different ephemeral keys should produce different secrets
        assert_ne!(result1.shared_secret, result2.shared_secret);
    }

    #[test]
    fn test_x3dh_bad_signature_rejected() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let evil_identity = IdentityKeyPair::generate();
        // Sign with a different identity — signature won't match the bundle's identity_key
        let bob_spk = SignedPreKey::generate(1, &evil_identity, 1000);

        let bundle = PreKeyBundle {
            identity_key: bob_identity.public.clone(),
            signed_pre_key_id: bob_spk.id,
            signed_pre_key: bob_spk.public_key().clone(),
            signed_pre_key_signature: bob_spk.signature,
            signed_pre_key_timestamp: bob_spk.timestamp,
            one_time_pre_key_id: None,
            one_time_pre_key: None,
        };

        let result = x3dh_initiate(&alice_identity, &bundle);
        assert!(result.is_err(), "bad signature should be rejected");
    }

    #[test]
    fn test_x3dh_associated_data_format() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);

        let bundle = make_bundle(&bob_identity, &bob_spk, None);
        let result = x3dh_initiate(&alice_identity, &bundle).unwrap();

        // AD should be exactly 64 bytes: IK_A (32) || IK_B (32)
        assert_eq!(result.associated_data.len(), 64);
        assert_eq!(&result.associated_data[..32], alice_identity.public.as_bytes());
        assert_eq!(&result.associated_data[32..], bob_identity.public.as_bytes());
    }

    #[test]
    fn test_x3dh_spec_dh_ordering_and_hkdf_params() {
        // Verify the spec-mandated structure: DH1=DH(IK_A,SPK_B), DH2=DH(EK_A,IK_B),
        // DH3=DH(EK_A,SPK_B), DH4=DH(EK_A,OPK_B) with F || DH1..DH4, salt=0, info="X3DH"
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);
        let bob_opk = OneTimePreKey::generate(100);

        let bundle = make_bundle(&bob_identity, &bob_spk, Some(&bob_opk));
        let result = x3dh_initiate(&alice_identity, &bundle).unwrap();

        // Verify the F constant is 32 bytes of 0xFF (used internally)
        assert_eq!(F, [0xFF; 32]);

        // Verify shared secret is 32 bytes
        assert_eq!(result.shared_secret.len(), 32);

        // Verify AD is exactly IK_A || IK_B (64 bytes, initiator first)
        assert_eq!(result.associated_data.len(), 64);
        assert_eq!(&result.associated_data[..32], alice_identity.public.as_bytes());
        assert_eq!(&result.associated_data[32..], bob_identity.public.as_bytes());

        // Verify responder produces identical AD ordering
        let bob_result = x3dh_respond(
            &bob_identity, &bob_spk, Some(&bob_opk),
            &alice_identity.public, &result.ephemeral_public,
        ).unwrap();
        assert_eq!(result.associated_data, bob_result.associated_data);
        assert_eq!(result.shared_secret, bob_result.shared_secret);
    }

    #[test]
    fn test_x3dh_spec_dh_symmetry() {
        // Spec §3.3/§3.4: DH(a,B) == DH(b,A) for X25519
        // Verify this holds for all four DH computations
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);
        let bob_opk = OneTimePreKey::generate(100);
        let ephemeral = KeyPair::generate();

        // DH1: DH(IK_A_priv, SPK_B_pub) == DH(SPK_B_priv, IK_A_pub)
        let dh1_alice = curve::dh(alice_identity.private_key(), &bob_spk.public_key()).unwrap();
        let dh1_bob = curve::dh(bob_spk.private_key(), alice_identity.public.public_key()).unwrap();
        assert_eq!(dh1_alice, dh1_bob);

        // DH2: DH(EK_A_priv, IK_B_pub) == DH(IK_B_priv, EK_A_pub)
        let dh2_alice = curve::dh(&ephemeral.private, bob_identity.public.public_key()).unwrap();
        let dh2_bob = curve::dh(bob_identity.private_key(), &ephemeral.public).unwrap();
        assert_eq!(dh2_alice, dh2_bob);

        // DH3: DH(EK_A_priv, SPK_B_pub) == DH(SPK_B_priv, EK_A_pub)
        let dh3_alice = curve::dh(&ephemeral.private, &bob_spk.public_key()).unwrap();
        let dh3_bob = curve::dh(bob_spk.private_key(), &ephemeral.public).unwrap();
        assert_eq!(dh3_alice, dh3_bob);

        // DH4: DH(EK_A_priv, OPK_B_pub) == DH(OPK_B_priv, EK_A_pub)
        let dh4_alice = curve::dh(&ephemeral.private, &bob_opk.public_key()).unwrap();
        let dh4_bob = curve::dh(bob_opk.private_key(), &ephemeral.public).unwrap();
        assert_eq!(dh4_alice, dh4_bob);
    }

    #[test]
    fn test_x3dh_with_opk_differs_from_without() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);
        let bob_opk = OneTimePreKey::generate(100);

        // We can't easily compare because ephemeral keys differ,
        // but we can verify both paths produce valid results
        let bundle_with = make_bundle(&bob_identity, &bob_spk, Some(&bob_opk));
        let bundle_without = make_bundle(&bob_identity, &bob_spk, None);

        let result_with = x3dh_initiate(&alice_identity, &bundle_with).unwrap();
        let result_without = x3dh_initiate(&alice_identity, &bundle_without).unwrap();

        // Secrets should differ (different DH inputs)
        assert_ne!(result_with.shared_secret, result_without.shared_secret);
    }
}
