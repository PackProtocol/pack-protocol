#![no_main]
use libfuzzer_sys::fuzz_target;
use pack_protocol::crypto::curve::KeyPair;
use pack_protocol::keys::{IdentityKeyPair, PQPreKey, PQPreKeyBundle, SignedPreKey};
use pack_protocol::pqxdh;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let strategy = data[0] % 4;
    let fuzz_data = &data[1..];

    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    let bob_spk = SignedPreKey::generate(1, &bob, 1000);
    let bob_pqpk = PQPreKey::generate(200, &bob, 1000);

    match strategy {
        0 => {
            // Fuzz: corrupted KEM ciphertext on the responder side
            // ML-KEM-768 ciphertext is 1088 bytes — fuzz it
            let bundle = PQPreKeyBundle {
                identity_key: bob.public.clone(),
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

            let init_result = match pqxdh::pqxdh_initiate(&alice, &bundle) {
                Ok(r) => r,
                Err(_) => return,
            };

            // Corrupt the KEM ciphertext with fuzz data
            let mut bad_ct = init_result.kem_ciphertext.clone();
            for (i, &byte) in fuzz_data.iter().enumerate() {
                if i < bad_ct.len() {
                    bad_ct[i] ^= byte;
                }
            }

            // ML-KEM implicit rejection: this should succeed but produce wrong shared secret
            let _ = pqxdh::pqxdh_respond(
                &bob,
                &bob_spk,
                None,
                &bob_pqpk,
                &alice.public,
                &init_result.ephemeral_public,
                &bad_ct,
            );
        }
        1 => {
            // Fuzz: wrong-length KEM ciphertext (should be rejected cleanly)
            let _ = pqxdh::pqxdh_respond(
                &bob,
                &bob_spk,
                None,
                &bob_pqpk,
                &alice.public,
                &KeyPair::generate().public,
                fuzz_data,
            );
        }
        2 => {
            // Fuzz: corrupted SPK signature in bundle (should fail signature verification)
            if fuzz_data.len() < 64 {
                return;
            }
            let mut bad_sig = [0u8; 64];
            bad_sig.copy_from_slice(&fuzz_data[..64]);
            let bundle = PQPreKeyBundle {
                identity_key: bob.public.clone(),
                signed_pre_key_id: bob_spk.id,
                signed_pre_key: bob_spk.public_key().clone(),
                signed_pre_key_signature: bad_sig,
                signed_pre_key_timestamp: bob_spk.timestamp,
                one_time_pre_key_id: None,
                one_time_pre_key: None,
                pq_pre_key_id: bob_pqpk.id,
                pq_pre_key: bob_pqpk.encapsulation_key.clone(),
                pq_pre_key_signature: bob_pqpk.signature,
            };
            let _ = pqxdh::pqxdh_initiate(&alice, &bundle);
        }
        3 => {
            // Fuzz: corrupted PQ pre-key signature (should fail PQ signature verification)
            if fuzz_data.len() < 64 {
                return;
            }
            let mut bad_sig = [0u8; 64];
            bad_sig.copy_from_slice(&fuzz_data[..64]);
            let bundle = PQPreKeyBundle {
                identity_key: bob.public.clone(),
                signed_pre_key_id: bob_spk.id,
                signed_pre_key: bob_spk.public_key().clone(),
                signed_pre_key_signature: bob_spk.signature,
                signed_pre_key_timestamp: bob_spk.timestamp,
                one_time_pre_key_id: None,
                one_time_pre_key: None,
                pq_pre_key_id: bob_pqpk.id,
                pq_pre_key: bob_pqpk.encapsulation_key.clone(),
                pq_pre_key_signature: bad_sig,
            };
            let _ = pqxdh::pqxdh_initiate(&alice, &bundle);
        }
        _ => {}
    }
});
