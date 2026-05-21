#![no_main]
use libfuzzer_sys::fuzz_target;
use pack_protocol::crypto::curve::{self, KeyPair, PublicKey};
use pack_protocol::keys::IdentityKeyPair;
use pack_protocol::sealed_sender::{
    self, SenderCertificate, ServerCertificate,
};

fn build_valid_envelope(
    alice: &IdentityKeyPair,
    bob: &IdentityKeyPair,
    server_kp: &KeyPair,
) -> Vec<u8> {
    let server_cert = ServerCertificate {
        key: server_kp.public.clone(),
        id: 1,
    };
    let mut cert = SenderCertificate {
        sender_uuid: "alice".to_string(),
        sender_device_id: 1,
        sender_identity: alice.public.clone(),
        expiration: 9999,
        server_certificate: server_cert,
        signature: Vec::new(),
    };
    let content = cert.serialize_content();
    cert.signature = curve::xeddsa_sign(&server_kp.private, &content).to_vec();

    sealed_sender::sealed_sender_encrypt(alice, &cert, &bob.public, b"fuzz payload", 1000)
        .unwrap()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    let server_kp = KeyPair::generate();

    let valid_envelope = build_valid_envelope(&alice, &bob, &server_kp);

    let strategy = data[0] % 4;
    let fuzz_data = &data[1..];

    match strategy {
        0 => {
            // Fuzz: completely random bytes as sealed sender input
            let _ = sealed_sender::sealed_sender_decrypt(&bob, fuzz_data, &server_kp.public, 1000);
        }
        1 => {
            // Fuzz: valid envelope with corrupted bytes (preserving version + ephemeral)
            let mut corrupted = valid_envelope.clone();
            for (i, &byte) in fuzz_data.iter().enumerate() {
                let target = 33 + (i % corrupted.len().saturating_sub(33).max(1));
                if target < corrupted.len() {
                    corrupted[target] ^= byte;
                }
            }
            let _ = sealed_sender::sealed_sender_decrypt(&bob, &corrupted, &server_kp.public, 1000);
        }
        2 => {
            // Fuzz: valid envelope, wrong trust root
            if fuzz_data.len() >= 32 {
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&fuzz_data[..32]);
                if let Ok(fake_trust) = PublicKey::from_bytes_validated(key_bytes) {
                    let _ = sealed_sender::sealed_sender_decrypt(
                        &bob,
                        &valid_envelope,
                        &fake_trust,
                        1000,
                    );
                }
            }
        }
        3 => {
            // Fuzz: valid envelope, wrong recipient identity
            let eve = IdentityKeyPair::generate();
            let _ = sealed_sender::sealed_sender_decrypt(
                &eve,
                &valid_envelope,
                &server_kp.public,
                1000,
            );
            // Also try fuzzed time (expired cert scenarios)
            if fuzz_data.len() >= 8 {
                let time = u64::from_be_bytes([
                    fuzz_data[0], fuzz_data[1], fuzz_data[2], fuzz_data[3],
                    fuzz_data[4], fuzz_data[5], fuzz_data[6], fuzz_data[7],
                ]);
                let _ = sealed_sender::sealed_sender_decrypt(
                    &bob,
                    &valid_envelope,
                    &server_kp.public,
                    time,
                );
            }
        }
        _ => {}
    }
});
