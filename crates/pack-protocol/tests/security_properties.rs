// Construction Trace Tests for pack-protocol
//
// Each test encodes a mathematical formula from a published specification,
// computes the expected output from first principles using raw cryptographic
// primitives, and verifies the library's higher-level functions produce
// identical results.
//
// Sources cited per theorem:
//   RFC 7748 §6.1      — X25519 Diffie-Hellman
//   RFC 4231            — HMAC-SHA256
//   RFC 5869 Appendix A — HKDF-SHA256
//   NIST SP 800-38D     — AES-256-GCM
//   Double Ratchet §2.2 — KDF_CK, KDF_RK
//   X3DH §3.3           — Shared secret derivation
//   PQXDH spec          — Hybrid post-quantum binding
//   XEdDSA §2           — Montgomery-to-Edwards signatures

use pack_protocol::crypto::curve::{
    dh, xeddsa_sign, xeddsa_verify, KeyPair, PrivateKey, PublicKey,
};
use pack_protocol::crypto::kdf::hkdf_derive;
use pack_protocol::crypto::hmac::hmac_sha256;
use pack_protocol::crypto::aead;
use pack_protocol::chain::{kdf_ck, kdf_rk, ChainKey, RootKey};

use std::collections::HashSet;

// ============================================================================
// PART I: Primitive Verification — RFC/NIST Known-Answer Vectors
//
// These tests contain NO implementation-derived values. Every expected output
// is copied verbatim from a published standard. If a test fails, the primitive
// does not conform to its specification.
// ============================================================================

/// Theorem 1: X25519 Diffie-Hellman (RFC 7748 §6.1)
///
/// Given:
///   a  = 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
///   A  = 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
///   b  = 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
///   B  = de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
///
/// Then:
///   X25519(a, B) = X25519(b, A) = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
///
/// This proves scalar multiplication, RFC-mandated clamping, and DH commutativity.
#[test]
fn theorem_1_x25519_rfc7748_section_6_1() {
    let a: [u8; 32] = hex::decode(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ).unwrap().try_into().unwrap();

    let big_a: [u8; 32] = hex::decode(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    ).unwrap().try_into().unwrap();

    let b: [u8; 32] = hex::decode(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ).unwrap().try_into().unwrap();

    let big_b: [u8; 32] = hex::decode(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    ).unwrap().try_into().unwrap();

    let expected: [u8; 32] = hex::decode(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    ).unwrap().try_into().unwrap();

    // X25519(a, B)
    let shared_ab = dh(&PrivateKey::from_bytes(a), &PublicKey::from_bytes(big_b)).unwrap();
    assert_eq!(shared_ab, expected, "X25519(a, B) ≠ RFC 7748 §6.1 expected value");

    // X25519(b, A) — commutativity
    let shared_ba = dh(&PrivateKey::from_bytes(b), &PublicKey::from_bytes(big_a)).unwrap();
    assert_eq!(shared_ba, expected, "X25519(b, A) ≠ RFC 7748 §6.1 expected value");

    assert_eq!(shared_ab, shared_ba, "DH commutativity violated: X25519(a,B) ≠ X25519(b,A)");
}

/// Theorem 2: HMAC-SHA256 (RFC 4231 Test Cases 1 and 2)
///
/// Test Case 1:
///   Key  = 0x0b repeated 20 times
///   Data = "Hi There" (ASCII)
///   HMAC = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
///
/// Test Case 2:
///   Key  = "Jefe" (ASCII)
///   Data = "what do ya want for nothing?" (ASCII)
///   HMAC = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
#[test]
fn theorem_2_hmac_sha256_rfc4231() {
    // Test Case 1
    let result1 = hmac_sha256(&[0x0bu8; 20], b"Hi There");
    let expected1: [u8; 32] = hex::decode(
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    ).unwrap().try_into().unwrap();
    assert_eq!(result1, expected1, "HMAC-SHA256 ≠ RFC 4231 Test Case 1");

    // Test Case 2
    let result2 = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    let expected2: [u8; 32] = hex::decode(
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    ).unwrap().try_into().unwrap();
    assert_eq!(result2, expected2, "HMAC-SHA256 ≠ RFC 4231 Test Case 2");
}

/// Theorem 3: HKDF-SHA256 (RFC 5869 Appendix A, Test Cases 1 and 3)
///
/// Extract-then-Expand per RFC 5869 §2.2-2.3:
///   PRK = HMAC-SHA256(salt, IKM)
///   T(0) = empty
///   T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
///   OKM  = T(1) || T(2) || ... truncated to L bytes
///
/// Test Case 1 (L=42):
///   IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
///   salt = 0x000102030405060708090a0b0c
///   info = 0xf0f1f2f3f4f5f6f7f8f9
///   OKM  = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
///          34007208d5b887185865
///
/// Test Case 3 (L=42, empty salt and info):
///   IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
///   OKM  = 8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d
///          9d201395faa4b61a96c8
#[test]
fn theorem_3_hkdf_sha256_rfc5869() {
    // Test Case 1
    let ikm1 = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt1 = hex::decode("000102030405060708090a0b0c").unwrap();
    let info1 = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let expected1 = hex::decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865",
    ).unwrap();
    let okm1 = hkdf_derive(&ikm1, &salt1, &info1, 42).unwrap();
    assert_eq!(okm1, expected1, "HKDF ≠ RFC 5869 Test Case 1");

    // Test Case 3 — empty salt and info
    let ikm3 = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let expected3 = hex::decode(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
         9d201395faa4b61a96c8",
    ).unwrap();
    let okm3 = hkdf_derive(&ikm3, b"", b"", 42).unwrap();
    assert_eq!(okm3, expected3, "HKDF ≠ RFC 5869 Test Case 3 (empty salt/info)");
}

/// Theorem 4: AES-256-GCM (NIST SP 800-38D)
///
/// Test Case 13 (empty plaintext, Key=0^32, IV=0^12):
///   CT  = (empty)
///   Tag = 530f8afbc74536b9a963b4f1c4cb738b
///   Output = Tag alone (16 bytes)
///
/// Test Case 14 (PT=0^16, Key=0^32, IV=0^12):
///   CT  = cea7403d4d606b6e074ec5d3baf39d18
///   Tag = d0d1c8a799996bf0265b98b5d48ab919
///   Output = CT||Tag (32 bytes)
#[test]
fn theorem_4_aes256gcm_nist_sp800_38d() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];

    // Test Case 13: empty plaintext
    let ct_empty = aead::encrypt(&key, &nonce, b"", b"").unwrap();
    let expected_tag = hex::decode("530f8afbc74536b9a963b4f1c4cb738b").unwrap();
    assert_eq!(ct_empty, expected_tag,
        "AES-256-GCM(K=0,IV=0,PT=∅) ≠ NIST SP 800-38D Test Case 13");

    // Test Case 14: 16-byte zero plaintext
    let ct_16 = aead::encrypt(&key, &nonce, &[0u8; 16], b"").unwrap();
    let expected_ct_tag = hex::decode(
        "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
    ).unwrap();
    assert_eq!(ct_16, expected_ct_tag,
        "AES-256-GCM(K=0,IV=0,PT=0^16) ≠ NIST SP 800-38D Test Case 14");

    // Decryption must recover the plaintext
    let pt_recovered = aead::decrypt(&key, &nonce, &ct_16, b"").unwrap();
    assert_eq!(pt_recovered, vec![0u8; 16],
        "AES-256-GCM decryption must be the inverse of encryption");
}

// ============================================================================
// PART II: Construction Trace — Protocol Formula Verification
//
// These tests fix known inputs, compute expected outputs using the raw
// primitives proven correct in Part I, and verify that the protocol's
// higher-level functions produce identical results.
//
// If a test fails, the protocol function does not implement the spec formula.
// ============================================================================

/// Theorem 5: KDF_CK (Double Ratchet §2.2)
///
/// The symmetric-ratchet key derivation function is defined as:
///   MK  = HMAC-SHA256(CK, 0x01)     — message key
///   CK' = HMAC-SHA256(CK, 0x02)     — next chain key
///
/// We fix two distinct chain keys, compute the expected outputs by calling
/// HMAC-SHA256 directly, and verify kdf_ck matches for both.
#[test]
fn theorem_5_kdf_ck_double_ratchet_section_2_2() {
    for &ck_bytes in &[[0x42u8; 32], [0xABu8; 32], [0x01u8; 32]] {
        let ck = ChainKey::from_bytes(ck_bytes);

        let expected_mk = hmac_sha256(&ck_bytes, &[0x01]);
        let expected_next_ck = hmac_sha256(&ck_bytes, &[0x02]);

        let (next_ck, mk) = kdf_ck(&ck);

        assert_eq!(mk.as_bytes(), &expected_mk,
            "KDF_CK: MK ≠ HMAC(CK, 0x01) for CK={:02x?}", &ck_bytes[..4]);
        assert_eq!(next_ck.as_bytes(), &expected_next_ck,
            "KDF_CK: CK' ≠ HMAC(CK, 0x02) for CK={:02x?}", &ck_bytes[..4]);

        // MK and CK' must differ (0x01 ≠ 0x02 → different HMAC outputs)
        assert_ne!(mk.as_bytes(), next_ck.as_bytes(),
            "KDF_CK: MK must differ from CK' (different HMAC inputs)");
    }
}

/// Theorem 6: KDF_RK (Double Ratchet §2.2)
///
/// The DH-ratchet key derivation function is defined as:
///   output = HKDF-SHA256(salt=RK, ikm=dh_output, info="DoubleRatchet", L=64)
///   RK'    = output[0..32]
///   CK     = output[32..64]
///
/// We fix root key and DH output, compute HKDF directly, and verify kdf_rk matches.
#[test]
fn theorem_6_kdf_rk_double_ratchet_section_2_2() {
    let rk_bytes = [0x42u8; 32];
    let dh_output = [0x37u8; 32];
    let rk = RootKey::from_bytes(rk_bytes);

    let hkdf_out = hkdf_derive(&dh_output, &rk_bytes, b"DoubleRatchet", 64).unwrap();
    let expected_rk: [u8; 32] = hkdf_out[..32].try_into().unwrap();
    let expected_ck: [u8; 32] = hkdf_out[32..64].try_into().unwrap();

    let (new_rk, new_ck) = kdf_rk(&rk, &dh_output).unwrap();

    assert_eq!(new_rk.as_bytes(), &expected_rk,
        "KDF_RK: RK' ≠ HKDF(salt=RK, ikm=DH, info=\"DoubleRatchet\")[0..32]");
    assert_eq!(new_ck.as_bytes(), &expected_ck,
        "KDF_RK: CK ≠ HKDF(salt=RK, ikm=DH, info=\"DoubleRatchet\")[32..64]");

    // Second input pair to rule out hardcoding
    let rk2 = RootKey::from_bytes([0xBB; 32]);
    let dh2 = [0xCC; 32];
    let hkdf_out2 = hkdf_derive(&dh2, &[0xBB; 32], b"DoubleRatchet", 64).unwrap();
    let (new_rk2, new_ck2) = kdf_rk(&rk2, &dh2).unwrap();
    assert_eq!(new_rk2.as_bytes(), &<[u8; 32]>::try_from(&hkdf_out2[..32]).unwrap());
    assert_eq!(new_ck2.as_bytes(), &<[u8; 32]>::try_from(&hkdf_out2[32..64]).unwrap());
}

/// Theorem 7: Full Ratchet Construction Trace
///
/// End-to-end verification of the Double Ratchet key derivation chain:
///
///   DH_output ──► KDF_RK(RK, DH) ──► (RK', CK)
///                                        │
///                                        ▼
///                                   KDF_CK(CK) ──► (CK₁, MK₀)
///                                        │
///                                        ▼
///                                   KDF_CK(CK₁) ──► (CK₂, MK₁)
///
/// Every intermediate value is verified against raw HKDF/HMAC computation.
#[test]
fn theorem_7_full_ratchet_construction_trace() {
    let rk = [0x42u8; 32];
    let dh_out = [0x37u8; 32];

    // Step 1: KDF_RK — HKDF(salt=RK, ikm=DH, info="DoubleRatchet", 64)
    let hkdf_out = hkdf_derive(&dh_out, &rk, b"DoubleRatchet", 64).unwrap();
    let expected_rk1: [u8; 32] = hkdf_out[..32].try_into().unwrap();
    let expected_ck0: [u8; 32] = hkdf_out[32..64].try_into().unwrap();

    let (rk1, ck0) = kdf_rk(&RootKey::from_bytes(rk), &dh_out).unwrap();
    assert_eq!(rk1.as_bytes(), &expected_rk1);
    assert_eq!(ck0.as_bytes(), &expected_ck0);

    // Step 2: First KDF_CK — MK₀ = HMAC(CK₀, 0x01), CK₁ = HMAC(CK₀, 0x02)
    let expected_mk0 = hmac_sha256(&expected_ck0, &[0x01]);
    let expected_ck1 = hmac_sha256(&expected_ck0, &[0x02]);

    let (ck1, mk0) = kdf_ck(&ck0);
    assert_eq!(mk0.as_bytes(), &expected_mk0);
    assert_eq!(ck1.as_bytes(), &expected_ck1);

    // Step 3: Second KDF_CK — MK₁ = HMAC(CK₁, 0x01), CK₂ = HMAC(CK₁, 0x02)
    let expected_mk1 = hmac_sha256(&expected_ck1, &[0x01]);
    let expected_ck2 = hmac_sha256(&expected_ck1, &[0x02]);

    let (ck2, mk1) = kdf_ck(&ck1);
    assert_eq!(mk1.as_bytes(), &expected_mk1);
    assert_eq!(ck2.as_bytes(), &expected_ck2);

    // All derived keys must be distinct
    let all_keys: Vec<&[u8; 32]> = vec![
        &expected_rk1, &expected_ck0, &expected_mk0,
        &expected_ck1, &expected_mk1, &expected_ck2,
    ];
    let unique: HashSet<&[u8; 32]> = all_keys.iter().copied().collect();
    assert_eq!(unique.len(), all_keys.len(),
        "All intermediate keys in the ratchet trace must be distinct");
}

/// Theorem 8: X3DH Shared Secret Formula (X3DH §3.3)
///
/// The X3DH shared secret derivation is:
///   IKM = F || DH1 || DH2 || DH3 [|| DH4]
///   SK  = HKDF(IKM, salt=0x00^32, info="X3DH", L=32)
///
/// where F = 0xFF^32 (padding for transcript-binding)
///
/// DH components (§3.3):
///   DH1 = DH(IK_A, SPK_B)     — mutual authentication
///   DH2 = DH(EK_A, IK_B)      — forward secrecy
///   DH3 = DH(EK_A, SPK_B)     — key freshness
///   DH4 = DH(EK_A, OPK_B)     — optional, one-time key
///
/// This test verifies the formula's structural properties using simulated
/// DH outputs. DH correctness itself is proven by Theorem 1.
#[test]
fn theorem_8_x3dh_shared_secret_formula() {
    let dh1 = [0x11u8; 32];
    let dh2 = [0x22u8; 32];
    let dh3 = [0x33u8; 32];
    let dh4 = [0x44u8; 32];
    let f = [0xFFu8; 32];
    let salt = [0x00u8; 32];

    // Full formula with OPK
    let mut ikm = Vec::with_capacity(160);
    ikm.extend_from_slice(&f);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    ikm.extend_from_slice(&dh4);
    let sk = hkdf_derive(&ikm, &salt, b"X3DH", 32).unwrap();
    assert_eq!(sk.len(), 32, "X3DH SK must be exactly 32 bytes");

    // Without OPK (3 DH components) — must produce different SK
    let mut ikm_no_opk = Vec::with_capacity(128);
    ikm_no_opk.extend_from_slice(&f);
    ikm_no_opk.extend_from_slice(&dh1);
    ikm_no_opk.extend_from_slice(&dh2);
    ikm_no_opk.extend_from_slice(&dh3);
    let sk_no_opk = hkdf_derive(&ikm_no_opk, &salt, b"X3DH", 32).unwrap();
    assert_ne!(sk, sk_no_opk, "OPK (DH4) must be load-bearing in X3DH IKM");

    // Each DH component is load-bearing
    for i in 0..4 {
        let mut ikm_zeroed = ikm.clone();
        let offset = 32 + i * 32;
        ikm_zeroed[offset..offset + 32].fill(0x00);
        let sk_zeroed = hkdf_derive(&ikm_zeroed, &salt, b"X3DH", 32).unwrap();
        assert_ne!(sk, sk_zeroed,
            "DH{} must be load-bearing: zeroing it must change SK", i + 1);
    }

    // F padding is load-bearing
    let mut ikm_no_f = ikm.clone();
    ikm_no_f[..32].fill(0x00);
    let sk_no_f = hkdf_derive(&ikm_no_f, &salt, b"X3DH", 32).unwrap();
    assert_ne!(sk, sk_no_f, "F (0xFF padding) must be load-bearing in IKM");

    // Domain separation: info="X3DH" vs info="PQXDH"
    let sk_pqxdh = hkdf_derive(&ikm, &salt, b"PQXDH", 32).unwrap();
    assert_ne!(sk, sk_pqxdh, "X3DH/PQXDH domain separation must hold via info string");

    // Determinism: same inputs → same SK
    let sk_again = hkdf_derive(&ikm, &salt, b"X3DH", 32).unwrap();
    assert_eq!(sk, sk_again, "X3DH SK derivation must be deterministic");
}

/// Theorem 9: PQXDH Hybrid Binding (PQXDH spec)
///
/// The PQXDH shared secret extends X3DH with a KEM shared secret:
///   IKM = F || DH1 || DH2 || DH3 [|| DH4] || kem_ss
///   SK  = HKDF(IKM, salt=0x00^32, info="PQXDH", L=32)
///
/// The KEM shared secret (from ML-KEM-768 / FIPS 203) is concatenated after
/// the DH components. If the KEM is broken (kem_ss known to attacker), security
/// falls back to classical DH. If DH is broken, security falls back to KEM.
///
/// This test verifies the hybrid binding: both DH and KEM components must
/// independently affect the derived SK.
#[test]
fn theorem_9_pqxdh_hybrid_binding() {
    let dh1 = [0x11u8; 32];
    let dh2 = [0x22u8; 32];
    let dh3 = [0x33u8; 32];
    let dh4 = [0x44u8; 32];
    let kem_ss = [0x55u8; 32];
    let f = [0xFFu8; 32];
    let salt = [0x00u8; 32];

    // Full PQXDH formula
    let mut ikm = Vec::with_capacity(192);
    ikm.extend_from_slice(&f);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    ikm.extend_from_slice(&dh4);
    ikm.extend_from_slice(&kem_ss);
    let sk = hkdf_derive(&ikm, &salt, b"PQXDH", 32).unwrap();
    assert_eq!(sk.len(), 32);

    // KEM shared secret is load-bearing (hybrid binding proof)
    let mut ikm_no_kem = Vec::with_capacity(160);
    ikm_no_kem.extend_from_slice(&f);
    ikm_no_kem.extend_from_slice(&dh1);
    ikm_no_kem.extend_from_slice(&dh2);
    ikm_no_kem.extend_from_slice(&dh3);
    ikm_no_kem.extend_from_slice(&dh4);
    let sk_no_kem = hkdf_derive(&ikm_no_kem, &salt, b"PQXDH", 32).unwrap();
    assert_ne!(sk, sk_no_kem,
        "ML-KEM shared secret must be load-bearing (removing it changes SK)");

    // Wrong KEM shared secret → different SK
    let mut ikm_wrong_kem = ikm.clone();
    ikm_wrong_kem[160..192].fill(0xAA);
    let sk_wrong_kem = hkdf_derive(&ikm_wrong_kem, &salt, b"PQXDH", 32).unwrap();
    assert_ne!(sk, sk_wrong_kem,
        "Corrupted KEM shared secret must produce different SK");

    // DH components still load-bearing (classical security preserved)
    for i in 0..4 {
        let mut ikm_mod = ikm.clone();
        let offset = 32 + i * 32;
        ikm_mod[offset..offset + 32].fill(0x00);
        let sk_mod = hkdf_derive(&ikm_mod, &salt, b"PQXDH", 32).unwrap();
        assert_ne!(sk, sk_mod,
            "DH{} must remain load-bearing in PQXDH even with KEM present", i + 1);
    }

    // Domain separation from X3DH
    let sk_x3dh = hkdf_derive(&ikm, &salt, b"X3DH", 32).unwrap();
    assert_ne!(sk, sk_x3dh, "PQXDH/X3DH domain separation must hold");
}

// ============================================================================
// PART III: Security Property Proofs
//
// These tests verify structural properties that the cryptographic literature
// requires for security: signature unforgeability, chain uniqueness, root key
// evolution, and HKDF domain separation.
// ============================================================================

/// Theorem 10: XEdDSA Signature Properties (XEdDSA §2)
///
/// XEdDSA converts an X25519 private key to an Ed25519-compatible signing key:
///   1. Clamp the X25519 scalar a
///   2. Compute Ed25519 public point A = a·B (force sign bit = 0)
///   3. Hedged nonce: r = SHA-512(Z || a || M) mod ℓ, where Z = 64 random bytes
///   4. R = r·B, S = r + SHA-512(R || A || M)·a mod ℓ
///   5. Signature = (R, S)
///
/// Properties verified:
///   (a) ∀ (sk, pk, M): Verify(pk, M, Sign(sk, M)) = OK         — completeness
///   (b) Sign(sk, M) ≠ Sign(sk, M) w.h.p.                       — hedged nonces
///   (c) Verify(pk', M, Sign(sk, M)) = Err for pk' ≠ pk         — unforgeability
///   (d) Verify(pk, M', Sign(sk, M)) = Err for M' ≠ M           — integrity
#[test]
fn theorem_10_xeddsa_properties() {
    let kp = KeyPair::generate();
    let m = b"XEdDSA construction trace verification";

    // (a) Completeness
    let sig1 = xeddsa_sign(&kp.private, m);
    assert!(xeddsa_verify(&kp.public, m, &sig1).is_ok(),
        "XEdDSA completeness: valid signature must verify");

    // (b) Hedged nonces — two signatures on same (key, message) must differ
    // This is NOT non-deterministic signing; it's hedged (Z || a || M) per §2.1.
    // The random Z provides fault-attack resistance.
    let sig2 = xeddsa_sign(&kp.private, m);
    assert_ne!(sig1, sig2,
        "XEdDSA hedged nonces: Sign(sk, M) must produce different signatures each call");
    assert!(xeddsa_verify(&kp.public, m, &sig2).is_ok(),
        "XEdDSA: second hedged signature must also verify");

    // (c) Unforgeability — wrong public key rejects
    let kp2 = KeyPair::generate();
    assert!(xeddsa_verify(&kp2.public, m, &sig1).is_err(),
        "XEdDSA unforgeability: signature must not verify under wrong public key");

    // (d) Integrity — wrong message rejects
    assert!(xeddsa_verify(&kp.public, b"wrong message", &sig1).is_err(),
        "XEdDSA integrity: signature must not verify for tampered message");
}

/// Theorem 10b: XEdDSA Completeness Across Key Space
///
/// The Montgomery-to-Edwards conversion in XEdDSA must work for all X25519
/// key pairs. Roughly half of keys will have sign bit = 1 (requiring negation
/// per §2 step 3). We verify 200 random keys to exercise both code paths.
#[test]
fn theorem_10b_xeddsa_completeness_all_keys() {
    let message = b"sign bit coverage test";
    for _ in 0..200 {
        let kp = KeyPair::generate();
        let sig = xeddsa_sign(&kp.private, message);
        assert!(xeddsa_verify(&kp.public, message, &sig).is_ok(),
            "XEdDSA must work for all X25519 key pairs (sign bit coverage)");
    }
}

/// Theorem 11: Chain Key Forward Secrecy (Double Ratchet §2.2)
///
/// The symmetric ratchet CK_n = HMAC(CK_{n-1}, 0x02) must satisfy:
///   (a) All chain keys CK_0, CK_1, ..., CK_N are distinct (no cycles)
///   (b) All message keys MK_0, MK_1, ..., MK_N are distinct (AES-GCM nonce safety)
///   (c) The chain is deterministic: same CK_0 → same sequence
///
/// One-wayness (cannot compute CK_{n-1} from CK_n) is a cryptographic assumption
/// on HMAC-SHA256 and cannot be tested — it follows from SHA-256 preimage resistance.
#[test]
fn theorem_11_chain_forward_secrecy() {
    let ck0 = ChainKey::from_bytes([0x42u8; 32]);

    let mut chain_keys = Vec::with_capacity(101);
    let mut message_keys = Vec::with_capacity(100);
    chain_keys.push(*ck0.as_bytes());

    let mut ck = ck0;
    for _ in 0..100 {
        let (next_ck, mk) = kdf_ck(&ck);
        chain_keys.push(*next_ck.as_bytes());
        message_keys.push(*mk.as_bytes());
        ck = next_ck;
    }

    // (a) All chain keys unique
    let unique_cks: HashSet<[u8; 32]> = chain_keys.iter().copied().collect();
    assert_eq!(unique_cks.len(), 101,
        "100-step chain produced {} unique chain keys, expected 101", unique_cks.len());

    // (b) All message keys unique
    let unique_mks: HashSet<[u8; 32]> = message_keys.iter().copied().collect();
    assert_eq!(unique_mks.len(), 100,
        "100-step chain produced {} unique message keys, expected 100", unique_mks.len());

    // (c) Determinism
    let ck0_again = ChainKey::from_bytes([0x42u8; 32]);
    let mut ck_verify = ck0_again;
    for i in 0..100 {
        let (next, mk) = kdf_ck(&ck_verify);
        assert_eq!(next.as_bytes(), &chain_keys[i + 1],
            "Chain key determinism violated at step {}", i);
        assert_eq!(mk.as_bytes(), &message_keys[i],
            "Message key determinism violated at step {}", i);
        ck_verify = next;
    }
}

/// Theorem 12: Root Key Evolution (Double Ratchet §2.2)
///
/// Each DH ratchet step feeds a fresh DH output into KDF_RK.
///
///   (RK', CK) = KDF_RK(RK, dh_output)
///
/// Properties:
///   (a) Different DH outputs → different (RK', CK) pairs
///   (b) 50 successive root keys are all distinct (no fixed points or cycles)
///   (c) Same input → same output (determinism)
#[test]
fn theorem_12_root_key_evolution() {
    let rk0 = RootKey::from_bytes([0x42u8; 32]);

    // (a) Different DH outputs → different derived keys
    let (rk_a, ck_a) = kdf_rk(&rk0, &[0xAA; 32]).unwrap();
    let (rk_b, ck_b) = kdf_rk(&rk0, &[0xBB; 32]).unwrap();
    assert_ne!(rk_a.as_bytes(), rk_b.as_bytes(),
        "Different DH outputs must produce different root keys");
    assert_ne!(ck_a.as_bytes(), ck_b.as_bytes(),
        "Different DH outputs must produce different chain keys");

    // (b) 50 successive ratchet steps with varying DH outputs — all unique
    let mut root_keys = Vec::with_capacity(51);
    root_keys.push([0x42u8; 32]);
    let mut rk = rk0;
    for i in 0u8..50 {
        let mut dh_out = [0u8; 32];
        dh_out[0] = i;
        dh_out[1] = i.wrapping_mul(7).wrapping_add(13);
        dh_out[31] = i ^ 0xAA;
        let (new_rk, _) = kdf_rk(&rk, &dh_out).unwrap();
        root_keys.push(*new_rk.as_bytes());
        rk = new_rk;
    }
    let unique_rks: HashSet<[u8; 32]> = root_keys.iter().copied().collect();
    assert_eq!(unique_rks.len(), 51,
        "50-step root key evolution produced {} unique keys, expected 51", unique_rks.len());

    // (c) Determinism
    let (rk_det, ck_det) = kdf_rk(&RootKey::from_bytes([0x42u8; 32]), &[0xAA; 32]).unwrap();
    assert_eq!(rk_det.as_bytes(), rk_a.as_bytes());
    assert_eq!(ck_det.as_bytes(), ck_a.as_bytes());
}

/// Theorem 13: HKDF Domain Separation (RFC 5869 §3.2)
///
/// HKDF's info parameter provides domain separation. Two derivations with
/// the same IKM and salt but different info strings must produce independent
/// (unrelated) outputs. This is critical because:
///   - X3DH uses info="X3DH"
///   - PQXDH uses info="PQXDH"
///   - Double Ratchet uses info="DoubleRatchet"
///
/// If domain separation fails, a compromise in one protocol context
/// would leak keys in another.
#[test]
fn theorem_13_hkdf_domain_separation() {
    let ikm = [0x42u8; 32];
    let salt = [0x00u8; 32];

    let domains = [
        b"X3DH" as &[u8],
        b"PQXDH",
        b"DoubleRatchet",
        b"",
        b"SomeOtherContext",
    ];

    let outputs: Vec<Vec<u8>> = domains
        .iter()
        .map(|info| hkdf_derive(&ikm, &salt, info, 32).unwrap())
        .collect();

    // All outputs must be pairwise distinct
    for i in 0..outputs.len() {
        for j in (i + 1)..outputs.len() {
            assert_ne!(outputs[i], outputs[j],
                "HKDF domain separation failed: info={:?} and info={:?} produced same output",
                std::str::from_utf8(domains[i]).unwrap_or("?"),
                std::str::from_utf8(domains[j]).unwrap_or("?"));
        }
    }
}

/// Theorem 14: X25519 Small Subgroup Rejection
///
/// RFC 7748 §6.1: Implementations SHOULD reject the all-zeros public key
/// because it is the identity point on Curve25519. DH with the identity
/// point always produces the all-zeros shared secret regardless of the
/// private key, enabling a trivial key-recovery attack.
///
/// Our implementation must reject this.
#[test]
fn theorem_14_x25519_small_subgroup_rejection() {
    let kp = KeyPair::generate();

    // All-zeros public key is the identity point
    let zero_pk = PublicKey::from_bytes([0u8; 32]);
    let result = dh(&kp.private, &zero_pk);
    assert!(result.is_err(),
        "DH with all-zeros public key (identity point) must be rejected");

    // Validated constructor must also reject
    let validated = PublicKey::from_bytes_validated([0u8; 32]);
    assert!(validated.is_err(),
        "from_bytes_validated must reject the all-zeros key");
}

/// Theorem 15: AES-256-GCM Authentication (NIST SP 800-38D §7)
///
/// AES-GCM provides authenticated encryption. The authentication tag binds
/// the ciphertext to the associated data. Modification of either must cause
/// decryption to fail.
///
/// Properties:
///   (a) Wrong key → decryption fails
///   (b) Tampered ciphertext → decryption fails
///   (c) Wrong associated data → decryption fails
///   (d) Wrong nonce → decryption fails
#[test]
fn theorem_15_aes256gcm_authentication() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let pt = b"authenticated plaintext";
    let ad = b"associated data";

    let ct = aead::encrypt(&key, &nonce, pt, ad).unwrap();

    // (a) Wrong key
    let wrong_key = [0x43u8; 32];
    assert!(aead::decrypt(&wrong_key, &nonce, &ct, ad).is_err(),
        "AES-GCM must reject decryption with wrong key");

    // (b) Tampered ciphertext
    let mut ct_tampered = ct.clone();
    ct_tampered[0] ^= 0xFF;
    assert!(aead::decrypt(&key, &nonce, &ct_tampered, ad).is_err(),
        "AES-GCM must reject tampered ciphertext");

    // (c) Wrong associated data
    assert!(aead::decrypt(&key, &nonce, &ct, b"wrong ad").is_err(),
        "AES-GCM must reject mismatched associated data");

    // (d) Wrong nonce
    let wrong_nonce = [0x02u8; 12];
    assert!(aead::decrypt(&key, &wrong_nonce, &ct, ad).is_err(),
        "AES-GCM must reject decryption with wrong nonce");
}
