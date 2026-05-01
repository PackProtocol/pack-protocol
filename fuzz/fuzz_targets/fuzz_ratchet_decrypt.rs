#![no_main]
use libfuzzer_sys::fuzz_target;
use pack_protocol::crypto::curve::KeyPair;
use pack_protocol::ratchet::{self, MessageHeader};

fuzz_target!(|data: &[u8]| {
    if data.len() < 40 {
        return;
    }
    let header = match MessageHeader::from_bytes(&data[..40]) {
        Ok(h) => h,
        Err(_) => return,
    };
    let ciphertext = &data[40..];
    let ad = b"fuzz";

    let shared_secret = [0x42u8; 32];
    let bob_kp = KeyPair::generate();
    let mut bob = ratchet::ratchet_init_responder(shared_secret, bob_kp);

    let _ = ratchet::ratchet_decrypt(&mut bob, &header, ciphertext, ad);
});
