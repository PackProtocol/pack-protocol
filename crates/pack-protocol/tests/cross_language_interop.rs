// Cross-language interoperability tests
//
// These tests verify that serialization formats are stable and can be consumed
// by any language binding (C, C++, Kotlin/JNI, Swift). They use fixed byte
// sequences to detect accidental format changes.

use zeroize::Zeroizing;

use pack_protocol::keys::{IdentityKeyPair, IdentityKey};
use pack_protocol::crypto::curve::{KeyPair, PublicKey};
use pack_protocol::ratchet::{self, MessageHeader, RatchetState};
use pack_protocol::session::{SessionState, SessionRecord};
use pack_protocol::fingerprint;
use pack_protocol::message::{PackMessage, PreKeyPackMessage};

#[test]
fn test_message_header_wire_format_stability() {
    let ratchet_key = PublicKey::from_bytes([0xAA; 32]);
    let header = MessageHeader {
        ratchet_key,
        prev_chain_length: 42,
        message_number: 7,
    };

    let bytes = header.to_bytes();
    assert_eq!(bytes.len(), 40);
    assert_eq!(&bytes[..32], &[0xAA; 32]);
    assert_eq!(&bytes[32..36], &42u32.to_be_bytes());
    assert_eq!(&bytes[36..40], &7u32.to_be_bytes());

    let restored = MessageHeader::from_bytes(&bytes).unwrap();
    assert_eq!(restored.ratchet_key, header.ratchet_key);
    assert_eq!(restored.prev_chain_length, 42);
    assert_eq!(restored.message_number, 7);
}

#[test]
fn test_pack_message_wire_format_roundtrip() {
    let ratchet_key = PublicKey::from_bytes([0xBB; 32]);
    let header = MessageHeader {
        ratchet_key,
        prev_chain_length: 10,
        message_number: 3,
    };
    let ciphertext = vec![0xCC; 64];
    let msg = PackMessage::new(header, ciphertext.clone());

    let bytes = msg.serialize();
    let restored = PackMessage::deserialize(&bytes).unwrap();

    assert_eq!(restored.header.ratchet_key, msg.header.ratchet_key);
    assert_eq!(restored.header.prev_chain_length, 10);
    assert_eq!(restored.header.message_number, 3);
    assert_eq!(restored.ciphertext, ciphertext);
}

#[test]
fn test_pre_key_pack_message_wire_format_roundtrip() {
    let identity = IdentityKeyPair::generate();
    let base_key = KeyPair::generate().public;
    let ratchet_key = KeyPair::generate().public;

    let header = MessageHeader {
        ratchet_key,
        prev_chain_length: 0,
        message_number: 0,
    };
    let inner = PackMessage::new(header, vec![0xDD; 48]);

    let msg = PreKeyPackMessage::new(
        1,
        Some(100),
        base_key.clone(),
        identity.public.clone(),
        inner,
    );

    let bytes = msg.serialize();
    let restored = PreKeyPackMessage::deserialize(&bytes).unwrap();

    assert_eq!(restored.signed_pre_key_id, 1);
    assert_eq!(restored.pre_key_id, Some(100));
    assert_eq!(restored.base_key, base_key);
    assert_eq!(restored.identity_key, identity.public);
}

#[test]
fn test_session_state_serialization_format_stability() {
    let kp = KeyPair::generate();
    let ratchet = ratchet::ratchet_init_responder(Zeroizing::new([0x42; 32]), kp);
    let local_id = IdentityKeyPair::generate();
    let remote_id = IdentityKeyPair::generate();

    let state = SessionState {
        ratchet,
        local_identity: local_id.public.clone(),
        remote_identity: remote_id.public.clone(),
        alice_base_key: None,
        is_initiator: false,
    };

    let bytes = state.to_bytes();
    let restored = SessionState::from_bytes(&bytes).unwrap();

    assert_eq!(restored.local_identity, local_id.public);
    assert_eq!(restored.remote_identity, remote_id.public);
    assert!(restored.alice_base_key.is_none());
    assert!(!restored.is_initiator);

    // With base key and initiator flag
    let base = KeyPair::generate().public;
    let kp2 = KeyPair::generate();
    let ratchet2 = ratchet::ratchet_init_responder(Zeroizing::new([0x43; 32]), kp2);
    let state2 = SessionState {
        ratchet: ratchet2,
        local_identity: local_id.public.clone(),
        remote_identity: remote_id.public.clone(),
        alice_base_key: Some(base.clone()),
        is_initiator: true,
    };

    let bytes2 = state2.to_bytes();
    let restored2 = SessionState::from_bytes(&bytes2).unwrap();

    assert_eq!(restored2.alice_base_key.unwrap(), base);
    assert!(restored2.is_initiator);
}

#[test]
fn test_session_record_serialization_with_previous_states() {
    let local_id = IdentityKeyPair::generate();
    let remote_id = IdentityKeyPair::generate();

    let mut record = SessionRecord::new();
    for i in 0u8..3 {
        let kp = KeyPair::generate();
        let ratchet = ratchet::ratchet_init_responder(Zeroizing::new([i; 32]), kp);
        let state = SessionState {
            ratchet,
            local_identity: local_id.public.clone(),
            remote_identity: remote_id.public.clone(),
            alice_base_key: None,
            is_initiator: false,
        };
        record.archive_current_and_set(state);
    }

    assert!(record.current.is_some());
    assert_eq!(record.previous.len(), 2);

    let bytes = record.to_bytes();
    let restored = SessionRecord::from_bytes_stored(&bytes).unwrap();

    assert!(restored.current.is_some());
    assert_eq!(restored.previous.len(), 2);
}

#[test]
fn test_fingerprint_determinism_across_invocations() {
    let key_a = IdentityKey::from_bytes([0x11; 32]).unwrap();
    let key_b = IdentityKey::from_bytes([0x22; 32]).unwrap();

    let fp1 = fingerprint::generate_fingerprint(
        b"alice", &key_a, b"bob", &key_b,
    );
    let fp2 = fingerprint::generate_fingerprint(
        b"alice", &key_a, b"bob", &key_b,
    );

    assert_eq!(fp1.displayable.display(), fp2.displayable.display());
    assert_eq!(fp1.displayable.display().len(), 60);
    assert!(fp1.displayable.display().chars().all(|c: char| c.is_ascii_digit()));
}

#[test]
fn test_ratchet_state_serialization_preserves_skipped_keys() {
    let bob_kp = KeyPair::generate();
    let bob_pub = bob_kp.public.clone();
    let shared_secret = [0x42; 32];

    let mut alice = ratchet::ratchet_init_initiator(Zeroizing::new(shared_secret), &bob_pub).unwrap();
    let mut bob = ratchet::ratchet_init_responder(Zeroizing::new(shared_secret), bob_kp);
    let ad = b"interop-test";

    // Alice sends 3 messages
    let (h1, ct1) = ratchet::ratchet_encrypt(&mut alice, b"msg1", ad).unwrap();
    let (h2, ct2) = ratchet::ratchet_encrypt(&mut alice, b"msg2", ad).unwrap();
    let (h3, ct3) = ratchet::ratchet_encrypt(&mut alice, b"msg3", ad).unwrap();

    // Bob receives msg3 first (creating skipped keys for msg1 and msg2)
    let pt3 = ratchet::ratchet_decrypt(&mut bob, &h3, &ct3, ad).unwrap();
    assert_eq!(pt3, b"msg3");

    // Serialize/deserialize Bob's state (has skipped keys)
    let bob_bytes = bob.to_bytes();
    let mut bob_restored = RatchetState::from_bytes(&bob_bytes).unwrap();

    // Bob should still be able to decrypt the skipped messages
    let pt1 = ratchet::ratchet_decrypt(&mut bob_restored, &h1, &ct1, ad).unwrap();
    assert_eq!(pt1, b"msg1");
    let pt2 = ratchet::ratchet_decrypt(&mut bob_restored, &h2, &ct2, ad).unwrap();
    assert_eq!(pt2, b"msg2");
}
