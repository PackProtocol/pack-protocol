#![no_main]
use libfuzzer_sys::fuzz_target;
use pack_protocol::crypto::curve::KeyPair;
use pack_protocol::ratchet::{self, MessageHeader};
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let shared_secret = Zeroizing::new([0x42u8; 32]);
    let bob_kp = KeyPair::generate();
    let bob_pub = bob_kp.public.clone();

    let mut alice = match ratchet::ratchet_init_initiator(
        shared_secret.clone(),
        &bob_pub,
    ) {
        Ok(a) => a,
        Err(_) => return,
    };
    let mut bob = ratchet::ratchet_init_responder(shared_secret, bob_kp);

    let ad = b"fuzz-ad";

    // Alice encrypts a real message so Bob has valid receiving state
    let (header, ciphertext) = match ratchet::ratchet_encrypt(&mut alice, b"hello bob", ad) {
        Ok(r) => r,
        Err(_) => return,
    };

    // Bob decrypts the real message to initialize his ratchet
    let _ = ratchet::ratchet_decrypt(&mut bob, &header, &ciphertext, ad);

    // Now Bob replies so Alice has receiving state too
    let (header2, ciphertext2) = match ratchet::ratchet_encrypt(&mut bob, b"hello alice", ad) {
        Ok(r) => r,
        Err(_) => return,
    };
    let _ = ratchet::ratchet_decrypt(&mut alice, &header2, &ciphertext2, ad);

    // Strategy byte determines what we fuzz
    let strategy = data[0] % 4;
    let fuzz_data = &data[1..];

    match strategy {
        0 => {
            // Fuzz: random header bytes + valid-length ciphertext
            if fuzz_data.len() < 40 {
                return;
            }
            if let Ok(bad_header) = MessageHeader::from_bytes(&fuzz_data[..40]) {
                let _ = ratchet::ratchet_decrypt(&mut bob, &bad_header, &fuzz_data[40..], ad);
            }
        }
        1 => {
            // Fuzz: valid header, corrupted ciphertext
            let (good_header, good_ct) = match ratchet::ratchet_encrypt(&mut alice, b"real msg", ad) {
                Ok(r) => r,
                Err(_) => return,
            };
            let mut bad_ct = good_ct;
            for (i, byte) in fuzz_data.iter().enumerate() {
                if i < bad_ct.len() {
                    bad_ct[i] ^= byte;
                }
            }
            let _ = ratchet::ratchet_decrypt(&mut bob, &good_header, &bad_ct, ad);
        }
        2 => {
            // Fuzz: valid header, wrong AD
            let (good_header, good_ct) = match ratchet::ratchet_encrypt(&mut alice, b"real msg", ad) {
                Ok(r) => r,
                Err(_) => return,
            };
            let _ = ratchet::ratchet_decrypt(&mut bob, &good_header, &good_ct, fuzz_data);
        }
        3 => {
            // Fuzz: out-of-order messages with random skips
            if fuzz_data.is_empty() {
                return;
            }
            let count = (fuzz_data[0] % 10) as usize + 1;
            let mut messages = Vec::new();
            for _ in 0..count {
                match ratchet::ratchet_encrypt(&mut alice, b"msg", ad) {
                    Ok(m) => messages.push(m),
                    Err(_) => return,
                }
            }
            // Deliver in fuzz-determined order
            for i in fuzz_data.iter().take(count) {
                let idx = (*i as usize) % messages.len();
                let (ref h, ref c) = messages[idx];
                let _ = ratchet::ratchet_decrypt(&mut bob, h, c, ad);
            }
        }
        _ => {}
    }
});
