#![no_main]
use libfuzzer_sys::fuzz_target;
use pack_protocol::crypto::curve::PublicKey;
use pack_protocol::keys::IdentityKeyPair;
use pack_protocol::sealed_sender;

fuzz_target!(|data: &[u8]| {
    let identity = IdentityKeyPair::generate();
    let trust_root = PublicKey::from_bytes([0xAA; 32]);
    let _ = sealed_sender::sealed_sender_decrypt(&identity, data, &trust_root, 1000);
});
